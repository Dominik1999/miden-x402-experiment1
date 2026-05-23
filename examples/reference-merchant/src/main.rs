//! Minimal x402 merchant paywall.
//!
//! Single endpoint `GET /resource`:
//!   - No `PAYMENT-SIGNATURE` header  ⇒  402 with a `PAYMENT-REQUIRED`
//!     header carrying a base64 JSON describing the merchant's accepts
//!     entry (merchant id, faucet, amount, deadline, requirements digest).
//!   - With `PAYMENT-SIGNATURE` header ⇒  call the facilitator's
//!     `/verify` endpoint with the bound `(agent_id, nullifier)`. If
//!     the facilitator says `valid: true`, serve the resource and
//!     include a `PAYMENT-RESPONSE` header.
//!
//! Configured by environment:
//!   - `MERCHANT_HTTP_PORT`              default 7001
//!   - `MERCHANT_ACCOUNT_ID`             string echoed into 402
//!   - `MERCHANT_ASSET_FAUCET_ID`        string echoed into 402
//!   - `MERCHANT_PRICE_AMOUNT`           string echoed into 402
//!   - `MERCHANT_DEADLINE_UNIX_SECS`     u64, default 1e10
//!   - `MERCHANT_RESOURCE_BODY`          string, default "resource payload"
//!   - `FACILITATOR_URL`                 e.g. http://localhost:7002
//!   - `RUST_LOG`                        tracing filter

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header::HeaderName, HeaderValue},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::Engine;
use serde::{Deserialize, Serialize};

const HDR_PAYMENT_REQUIRED: HeaderName = HeaderName::from_static("payment-required");
const HDR_PAYMENT_SIGNATURE: HeaderName = HeaderName::from_static("payment-signature");
const HDR_PAYMENT_RESPONSE: HeaderName = HeaderName::from_static("payment-response");

#[derive(Clone)]
struct AppState {
    facilitator_url: String,
    http: reqwest::Client,
    cfg: Arc<MerchantConfig>,
}

#[derive(Clone, Debug)]
struct MerchantConfig {
    account_id: String,
    asset_faucet_id: String,
    amount: String,
    deadline_unix_secs: u64,
    resource_body: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AcceptsEntry {
    scheme: String,
    network: String,
    merchant_account_id: String,
    asset_faucet_id: String,
    amount: String,
    deadline_unix_secs: u64,
    payment_requirements_digest: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct PaymentRequired {
    accepts: Vec<AcceptsEntry>,
}

/// P2ID-style payment: the full AgenticPayload from the agent.
/// The merchant relays this to the facilitator's POST /agents/{id}/payments.
#[derive(Serialize, Deserialize, Debug)]
struct P2idPaymentSignature {
    agent_id: String,
    payload: serde_json::Value, // the full AgenticPayload JSON
}

/// Legacy P2ID format (agent_id + nullifier only, for backward compat).
#[derive(Serialize, Deserialize, Debug)]
struct PaymentSignature {
    agent_id: String,
    nullifier: String,
}

/// ADN-style payment signature (variant B). Contains the full signed debit.
#[derive(Serialize, Deserialize, Debug)]
struct AdnPaymentSignature {
    note_id: String,
    serial_num_hex: [String; 4],
    merchant_account_id: String,
    amount: u64,
    signature_hex: String,
    prepared_signature_hex: String,
    expiry_block_height: u32,
    agent_pubkey_commitment_hex: String,
    /// Hex-encoded serialized Note (for chain-finality settlement).
    #[serde(default)]
    note_data_hex: Option<String>,
}

/// Facilitator ack for ADN payments.
#[derive(Serialize, Deserialize, Debug)]
struct AdnFacilitatorAck {
    accepted_at_unix_micros: u64,
    facilitator_ack_signature: String,
    facilitator_pubkey_commitment: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct FacilitatorVerifyResp {
    valid: bool,
    status: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PaymentResponse {
    agent_id: String,
    nullifier: String,
    status: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let port: u16 = std::env::var("MERCHANT_HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7001);
    let facilitator_url =
        std::env::var("FACILITATOR_URL").unwrap_or_else(|_| "http://localhost:7002".into());
    let cfg = MerchantConfig {
        account_id: std::env::var("MERCHANT_ACCOUNT_ID").unwrap_or_else(|_| "0xmerchant1".into()),
        asset_faucet_id: std::env::var("MERCHANT_ASSET_FAUCET_ID")
            .unwrap_or_else(|_| "0xfaucet1".into()),
        amount: std::env::var("MERCHANT_PRICE_AMOUNT").unwrap_or_else(|_| "100".into()),
        deadline_unix_secs: std::env::var("MERCHANT_DEADLINE_UNIX_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000_000_000),
        resource_body: std::env::var("MERCHANT_RESOURCE_BODY")
            .unwrap_or_else(|_| "resource payload".into()),
    };

    let state = AppState {
        facilitator_url,
        http: reqwest::Client::builder()
            .user_agent("reference-merchant/0.1")
            .build()?,
        cfg: Arc::new(cfg),
    };

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/resource", get(get_resource))
        .with_state(state);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "reference-merchant listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn get_resource(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match headers.get(&HDR_PAYMENT_SIGNATURE) {
        None => emit_402(&state),
        Some(value) => {
            let header_str = match value.to_str() {
                Ok(s) => s,
                Err(_) => return bad_request("PAYMENT-SIGNATURE not utf8"),
            };
            let bytes = match base64::engine::general_purpose::STANDARD.decode(header_str.as_bytes()) {
                Ok(b) => b,
                Err(e) => return bad_request(&format!("PAYMENT-SIGNATURE not base64: {e}")),
            };

            // Try P2ID full payload format first (has "agent_id" + "payload"),
            // then ADN format (has "note_id"), then legacy P2ID (agent_id + nullifier).
            if let Ok(p2id_full) = serde_json::from_slice::<P2idPaymentSignature>(&bytes) {
                // P2ID scheme (new flow): relay full payload to facilitator
                match call_facilitator_p2id_relay(&state, &p2id_full).await {
                    Ok(ack) => {
                        let pr = PaymentResponse {
                            agent_id: p2id_full.agent_id.clone(),
                            nullifier: ack.get("reserved_nullifiers")
                                .and_then(|v| v.as_array())
                                .and_then(|a| a.first())
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                            status: "accepted".to_string(),
                        };
                        let pr_encoded = base64::engine::general_purpose::STANDARD
                            .encode(serde_json::to_vec(&pr).expect("serialize"));
                        let mut headers = HeaderMap::new();
                        headers.insert(HDR_PAYMENT_RESPONSE, HeaderValue::from_str(&pr_encoded).unwrap());
                        (StatusCode::OK, headers, state.cfg.resource_body.clone()).into_response()
                    }
                    Err(e) => payment_required_again(&state, format!("P2ID relay failed: {e}")),
                }
            } else if let Ok(adn_sig) = serde_json::from_slice::<AdnPaymentSignature>(&bytes) {
                // ADN scheme: relay to facilitator /adn/pay
                match call_facilitator_adn_pay(&state, &adn_sig).await {
                    Ok(_ack) => {
                        let pr = PaymentResponse {
                            agent_id: adn_sig.note_id.clone(),
                            nullifier: adn_sig.note_id,
                            status: "accepted".to_string(),
                        };
                        let pr_encoded = base64::engine::general_purpose::STANDARD
                            .encode(serde_json::to_vec(&pr).expect("serialize"));
                        let mut headers = HeaderMap::new();
                        headers.insert(HDR_PAYMENT_RESPONSE, HeaderValue::from_str(&pr_encoded).unwrap());
                        (StatusCode::OK, headers, state.cfg.resource_body.clone()).into_response()
                    }
                    Err(e) => payment_required_again(&state, format!("ADN verify failed: {e}")),
                }
            } else if let Ok(sig) = serde_json::from_slice::<PaymentSignature>(&bytes) {
                // Legacy P2ID: agent_id + nullifier → call facilitator /verify
                match call_facilitator_verify(&state, &sig).await {
                    Ok(resp) if resp.valid => emit_resource(&state, &sig, &resp.status),
                    Ok(resp) => payment_required_again(&state, format!("invalid: status={}", resp.status)),
                    Err(e) => internal(&format!("facilitator verify failed: {e}")),
                }
            } else {
                bad_request("PAYMENT-SIGNATURE: unrecognized format")
            }
        }
    }
}

fn emit_402(state: &AppState) -> Response {
    let required = PaymentRequired {
        accepts: vec![
            AcceptsEntry {
                scheme: "miden-p2id-x402".into(),
                network: "miden:testnet".into(),
                merchant_account_id: state.cfg.account_id.clone(),
                asset_faucet_id: state.cfg.asset_faucet_id.clone(),
                amount: state.cfg.amount.clone(),
                deadline_unix_secs: state.cfg.deadline_unix_secs,
                payment_requirements_digest: state.cfg.account_id.clone(),
            },
            AcceptsEntry {
                scheme: "miden-adn-x402".into(),
                network: "miden:testnet".into(),
                merchant_account_id: state.cfg.account_id.clone(),
                asset_faucet_id: state.cfg.asset_faucet_id.clone(),
                amount: state.cfg.amount.clone(),
                deadline_unix_secs: state.cfg.deadline_unix_secs,
                payment_requirements_digest: state.cfg.account_id.clone(),
            },
        ],
    };
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(&required).expect("serialize PaymentRequired"));
    let mut headers = HeaderMap::new();
    headers.insert(
        HDR_PAYMENT_REQUIRED,
        HeaderValue::from_str(&encoded).unwrap(),
    );
    (StatusCode::PAYMENT_REQUIRED, headers, Json(required)).into_response()
}

fn payment_required_again(state: &AppState, why: String) -> Response {
    tracing::warn!(reason = %why, "rejecting PAYMENT-SIGNATURE; re-issuing 402");
    let resp = emit_402(state);
    resp
}

fn emit_resource(state: &AppState, sig: &PaymentSignature, status: &str) -> Response {
    let pr = PaymentResponse {
        agent_id: sig.agent_id.clone(),
        nullifier: sig.nullifier.clone(),
        status: status.to_string(),
    };
    let pr_encoded = base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(&pr).expect("serialize PaymentResponse"));
    let mut headers = HeaderMap::new();
    headers.insert(
        HDR_PAYMENT_RESPONSE,
        HeaderValue::from_str(&pr_encoded).unwrap(),
    );
    (StatusCode::OK, headers, state.cfg.resource_body.clone()).into_response()
}

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, msg.to_string()).into_response()
}
fn internal(msg: &str) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, msg.to_string()).into_response()
}

fn decode_payment_signature(value: &str) -> anyhow::Result<PaymentSignature> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(value.as_bytes())?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Relay the full P2ID AgenticPayload to the facilitator.
async fn call_facilitator_p2id_relay(
    state: &AppState,
    p2id: &P2idPaymentSignature,
) -> anyhow::Result<serde_json::Value> {
    let url = format!(
        "{}/agents/{}/payments",
        state.facilitator_url.trim_end_matches('/'),
        p2id.agent_id
    );
    let res = state
        .http
        .post(url)
        .json(&p2id.payload)
        .send()
        .await?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        anyhow::bail!("facilitator returned {status}: {body}");
    }
    Ok(res.json().await?)
}

/// Relay the ADN signed debit to the facilitator's /adn/pay endpoint.
async fn call_facilitator_adn_pay(
    state: &AppState,
    sig: &AdnPaymentSignature,
) -> anyhow::Result<AdnFacilitatorAck> {
    let url = format!("{}/adn/pay", state.facilitator_url.trim_end_matches('/'));
    let res = state
        .http
        .post(url)
        .json(sig)
        .send()
        .await?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        anyhow::bail!("facilitator /adn/pay returned {status}: {body}");
    }
    Ok(res.json().await?)
}

async fn call_facilitator_verify(
    state: &AppState,
    sig: &PaymentSignature,
) -> anyhow::Result<FacilitatorVerifyResp> {
    let url = format!("{}/verify", state.facilitator_url.trim_end_matches('/'));
    let res = state
        .http
        .post(url)
        .json(&serde_json::json!({
            "agent_id": sig.agent_id,
            "nullifier": sig.nullifier,
        }))
        .send()
        .await?;
    if !res.status().is_success() {
        anyhow::bail!("facilitator returned {}", res.status());
    }
    Ok(res.json().await?)
}
