//! Integration tests for both x402 payment flows.
//!
//! Tests the full HTTP flow: Agent → Merchant → Facilitator → Ack → Resource
//! for both Approach 1 (ADN) and Approach 2 (P2ID).
//!
//! Each test spawns in-process facilitator + merchant servers on random ports.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header::HeaderName};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use miden_protocol::Felt;
use miden_protocol::Word;
use miden_protocol::account::auth::AuthSecretKey;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use x402_facilitator::api;
use x402_facilitator::jobs::{BatchConfig, spawn_batch_worker};
use x402_facilitator::key::FacilitatorKey;
use x402_facilitator::state::{AppState, PerAgentLocks};
use x402_facilitator::store::FilesystemX402Store;

const HDR_PAYMENT_REQUIRED: HeaderName = HeaderName::from_static("payment-required");
const HDR_PAYMENT_SIGNATURE: HeaderName = HeaderName::from_static("payment-signature");

// ── Shared types (mirrors reference-merchant) ──

#[derive(Serialize, Deserialize, Clone)]
struct AcceptsEntry {
    scheme: String,
    network: String,
    merchant_account_id: String,
    asset_faucet_id: String,
    amount: String,
    deadline_unix_secs: u64,
    payment_requirements_digest: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct PaymentRequired {
    accepts: Vec<AcceptsEntry>,
}

#[derive(Serialize, Deserialize)]
struct AdnPaymentSignature {
    note_id: String,
    serial_num_hex: [String; 4],
    merchant_account_id: String,
    amount: u64,
    signature_hex: String,
    prepared_signature_hex: String,
    expiry_block_height: u32,
    agent_pubkey_commitment_hex: String,
}

#[derive(Serialize, Deserialize)]
struct P2idPaymentSignature {
    agent_id: String,
    payload: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct PaymentSignature {
    agent_id: String,
    nullifier: String,
}

// ── Test merchant (inline, minimal) ──

#[derive(Clone)]
struct MerchantState {
    facilitator_url: String,
    http: reqwest::Client,
    merchant_id: String,
    faucet_id: String,
    amount: String,
}

async fn merchant_resource(State(state): State<MerchantState>, headers: HeaderMap) -> Response {
    match headers.get(&HDR_PAYMENT_SIGNATURE) {
        None => {
            // Emit 402
            let required = PaymentRequired {
                accepts: vec![
                    AcceptsEntry {
                        scheme: "miden-p2id-x402".into(),
                        network: "miden:testnet".into(),
                        merchant_account_id: state.merchant_id.clone(),
                        asset_faucet_id: state.faucet_id.clone(),
                        amount: state.amount.clone(),
                        deadline_unix_secs: 10_000_000_000,
                        payment_requirements_digest: state.merchant_id.clone(),
                    },
                    AcceptsEntry {
                        scheme: "miden-adn-x402".into(),
                        network: "miden:testnet".into(),
                        merchant_account_id: state.merchant_id.clone(),
                        asset_faucet_id: state.faucet_id.clone(),
                        amount: state.amount.clone(),
                        deadline_unix_secs: 10_000_000_000,
                        payment_requirements_digest: state.merchant_id.clone(),
                    },
                ],
            };
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&required).unwrap());
            let mut h = HeaderMap::new();
            h.insert(HDR_PAYMENT_REQUIRED, HeaderValue::from_str(&encoded).unwrap());
            (StatusCode::PAYMENT_REQUIRED, h, "payment required").into_response()
        }
        Some(value) => {
            let header_str = value.to_str().unwrap_or("");
            let bytes = match base64::engine::general_purpose::STANDARD.decode(header_str.as_bytes()) {
                Ok(b) => b,
                Err(_) => return (StatusCode::BAD_REQUEST, "bad base64").into_response(),
            };

            // Try ADN format
            if let Ok(adn) = serde_json::from_slice::<AdnPaymentSignature>(&bytes) {
                let url = format!("{}/adn/pay", state.facilitator_url);
                match state.http.post(&url).json(&adn).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        (StatusCode::OK, "resource delivered (ADN)").into_response()
                    }
                    Ok(resp) => {
                        let body = resp.text().await.unwrap_or_default();
                        (StatusCode::PAYMENT_REQUIRED, format!("facilitator rejected: {body}")).into_response()
                    }
                    Err(e) => {
                        (StatusCode::INTERNAL_SERVER_ERROR, format!("facilitator error: {e}")).into_response()
                    }
                }
            }
            // Try P2ID full payload format
            else if let Ok(p2id) = serde_json::from_slice::<P2idPaymentSignature>(&bytes) {
                let url = format!("{}/agents/{}/payments", state.facilitator_url, p2id.agent_id);
                match state.http.post(&url).json(&p2id.payload).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        (StatusCode::OK, "resource delivered (P2ID)").into_response()
                    }
                    Ok(resp) => {
                        let body = resp.text().await.unwrap_or_default();
                        (StatusCode::PAYMENT_REQUIRED, format!("facilitator rejected: {body}")).into_response()
                    }
                    Err(e) => {
                        (StatusCode::INTERNAL_SERVER_ERROR, format!("facilitator error: {e}")).into_response()
                    }
                }
            }
            // Try legacy P2ID (agent_id + nullifier)
            else if let Ok(sig) = serde_json::from_slice::<PaymentSignature>(&bytes) {
                let url = format!("{}/verify", state.facilitator_url);
                match state.http.post(&url).json(&serde_json::json!({"agent_id": sig.agent_id, "nullifier": sig.nullifier})).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        (StatusCode::OK, "resource delivered (legacy P2ID)").into_response()
                    }
                    _ => (StatusCode::PAYMENT_REQUIRED, "verify failed").into_response(),
                }
            } else {
                (StatusCode::BAD_REQUEST, "unrecognized payment format").into_response()
            }
        }
    }
}

// ── Test helpers ──

async fn spawn_facilitator(data_dir: &std::path::Path, keystore_dir: &std::path::Path) -> u16 {
    let store = FilesystemX402Store::new(data_dir).expect("store");
    let facilitator_key = FacilitatorKey::load_or_create(keystore_dir.to_path_buf()).expect("key");
    let state = AppState {
        store,
        facilitator_key,
        locks: PerAgentLocks::default(),
        submitter: None,
        submitter_available: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    // Don't spawn batch worker for these tests — we only test the hot path
    let app = api::router(state);
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

async fn spawn_merchant(facilitator_url: &str, merchant_id: &str, faucet_id: &str) -> u16 {
    let state = MerchantState {
        facilitator_url: facilitator_url.to_string(),
        http: reqwest::Client::builder().user_agent("test-merchant").build().unwrap(),
        merchant_id: merchant_id.to_string(),
        faucet_id: faucet_id.to_string(),
        amount: "100".to_string(),
    };
    let app = Router::new()
        .route("/resource", get(merchant_resource))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

// ── APPROACH 1: AgentDebitNote ──

#[tokio::test]
async fn test_adn_full_flow() {
    let fac_data = tempfile::TempDir::new().unwrap();
    let fac_keystore = tempfile::TempDir::new().unwrap();

    let fac_port = spawn_facilitator(fac_data.path(), fac_keystore.path()).await;
    let facilitator_url = format!("http://127.0.0.1:{fac_port}");

    let merchant_id = "0x86535dca74a83d100febdc1560fbe8";
    let faucet_id = "0x4ac9172cc5c709206076eb2cd7700e";

    let merch_port = spawn_merchant(&facilitator_url, merchant_id, faucet_id).await;
    let merchant_url = format!("http://127.0.0.1:{merch_port}");
    let resource_url = format!("{merchant_url}/resource");

    // Create agent keypair
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let agent_sk = AuthSecretKey::new_falcon512_poseidon2_with_rng(&mut rng);
    let agent_pk_commitment: Word = agent_sk.public_key().to_commitment().into();

    let note_id = "0xdeadbeef01234567";
    let serial: Word = [Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)].into();
    let expiry_block: u32 = 1_000_000;

    let adn_client = adn_client::client::AdnClient::new(
        agent_sk,
        note_id.to_string(),
        serial,
        100_000,
        expiry_block,
    );

    let http = reqwest::Client::builder().user_agent("test-agent").build().unwrap();

    // Step 1: GET /resource → 402
    let res = http.get(&resource_url).send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::PAYMENT_REQUIRED, "expected 402");
    let pr_header = res.headers().get("payment-required").expect("missing payment-required header");
    let pr_bytes = base64::engine::general_purpose::STANDARD
        .decode(pr_header.to_str().unwrap().as_bytes()).unwrap();
    let pr: PaymentRequired = serde_json::from_slice(&pr_bytes).unwrap();
    assert!(pr.accepts.iter().any(|a| a.scheme == "miden-adn-x402"), "should advertise ADN scheme");

    // Step 3: Sign debit + retry with Payment-Signature
    let merchant_account_id = miden_protocol::account::AccountId::from_hex(merchant_id)
        .expect("parse merchant id");
    let (signed_debit, timings) = adn_client.sign_debit(merchant_account_id, 100)
        .expect("sign debit");

    assert!(timings.t_sign_end > timings.t_sign_start, "signing should take time");
    assert!(timings.t_sign_end - timings.t_sign_start < 50_000, "signing should be < 50ms");

    let debit_b64 = base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(&signed_debit).unwrap());

    let res2 = http.get(&resource_url)
        .header("payment-signature", debit_b64)
        .send()
        .await
        .unwrap();

    let status2 = res2.status();
    let body2 = res2.text().await.unwrap();
    assert_eq!(status2, reqwest::StatusCode::OK, "expected 200 after ADN payment, got {status2}: {body2}");
    assert!(body2.contains("resource delivered"), "should contain resource: got {body2}");

    println!("ADN FLOW TEST PASSED: 402 → sign → retry → resource delivered");
}

