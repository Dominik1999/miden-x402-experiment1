//! AgentDebitNote payment endpoints.
//!
//! POST /adn/pay — hot path: verify agent's Falcon signature, ack immediately.
//! Settlement (consuming the note, proving, submitting) is async.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{Json, extract::State, http::StatusCode};
use miden_protocol::Hasher;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::crypto::dsa::falcon512_poseidon2::Signature as FalconSignature;
use miden_protocol::utils::serde::Deserializable;
use serde::{Deserialize, Serialize};

use agent_debit_note::message::debit_message;
use crate::error::{FacilitatorError, Result};
use crate::state::AppState;

/// Request body for POST /adn/pay.
#[derive(Debug, Clone, Deserialize)]
pub struct AdnPayRequest {
    pub note_id: String,
    pub serial_num_hex: [String; 4],
    pub merchant_account_id: String,
    pub amount: u64,
    pub signature_hex: String,
    pub prepared_signature_hex: String,
    pub expiry_block_height: u32,
    pub agent_pubkey_commitment_hex: String,
}

/// Response body for POST /adn/pay.
#[derive(Debug, Clone, Serialize)]
pub struct AdnPayResponse {
    pub accepted_at_unix_micros: u64,
    pub facilitator_ack_signature: String,
    pub facilitator_pubkey_commitment: String,
    /// Present when synchronous settlement succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_num: Option<u32>,
}

/// POST /adn/pay — verify agent's signature and ack.
///
/// Hot path: no proving, no chain interaction. ~1ms server-side.
/// Settlement happens asynchronously in the background.
pub async fn pay(
    State(state): State<AppState>,
    Json(req): Json<AdnPayRequest>,
) -> Result<(StatusCode, Json<AdnPayResponse>)> {
    let now = now_micros();

    // ── 1. Parse inputs ──
    let serial_num = parse_serial_hex(&req.serial_num_hex)?;
    let merchant_id = AccountId::from_hex(&req.merchant_account_id)
        .map_err(|e| FacilitatorError::Malformed(format!("merchant_account_id: {e}")))?;

    // ── 2. Parse and verify the agent's Falcon signature ──
    let sig_bytes = decode_hex(&req.signature_hex)?;
    let falcon_sig = FalconSignature::read_from_bytes(&sig_bytes)
        .map_err(|e| FacilitatorError::InvalidSignature(format!("Falcon decode: {e}")))?;

    // Compute the expected message
    let message = debit_message(serial_num, merchant_id, req.amount);

    // Verify the signature against the inline public key
    let inline_pk = falcon_sig.public_key();
    if !falcon_sig.verify(message, inline_pk) {
        return Err(FacilitatorError::InvalidSignature(
            "Falcon signature failed to verify against debit message".into(),
        ));
    }

    // Cross-check: the inline pubkey's commitment must match what the agent claims
    let expected_commitment_hex = crate::key::word_to_hex(inline_pk.to_commitment());
    let claimed_commitment = req.agent_pubkey_commitment_hex.trim_start_matches("0x");
    let expected_trimmed = expected_commitment_hex.trim_start_matches("0x");
    if expected_trimmed != claimed_commitment {
        return Err(FacilitatorError::InvalidSignature(format!(
            "pubkey commitment mismatch: sig has {expected_trimmed}, claimed {claimed_commitment}"
        )));
    }

    // ── 3. TODO: check note is on-chain and has sufficient balance ──
    // ── 4. TODO: check expiry gap (current_block + min_gap < expiry_block) ──
    // ── 5. TODO: mandate enforcement ──
    // ── 6. TODO: reserve debit (prevent double-spend of same serial+amount) ──

    // ── 7. Sign facilitator ack ──
    let ack_msg = ack_message(now, &req.note_id, &req.merchant_account_id, req.amount)?;
    let ack_signature = state.facilitator_key.sign_word_hex(ack_msg)?;

    tracing::info!(
        note_id = %req.note_id,
        merchant = %req.merchant_account_id,
        amount = req.amount,
        "ADN payment acked"
    );

    // ── 8. Synchronous settlement (if submitter is configured) ──
    let (tx_id, block_num) = if let Some(submitter) = &state.submitter {
        let note_bytes = decode_hex(&req.prepared_signature_hex)?; // placeholder: real note bytes TBD
        let mut note_args = [0u8; 32];
        // Pack serial_num felts into note_args
        for (i, h) in req.serial_num_hex.iter().enumerate() {
            let s = h.trim_start_matches("0x");
            let val = u64::from_str_radix(s, 16)
                .map_err(|e| FacilitatorError::Malformed(format!("serial_num[{i}]: {e}")))?;
            note_args[i * 8..(i + 1) * 8].copy_from_slice(&val.to_be_bytes());
        }
        let prepared_sig_bytes = decode_hex(&req.prepared_signature_hex)?;
        match submitter.consume_adn_note(note_bytes, note_args, prepared_sig_bytes).await {
            Ok((tid, bn)) => {
                tracing::info!(tx_id = %tid, block_num = bn, "ADN sync settlement succeeded");
                (Some(tid), Some(bn))
            }
            Err(e) => {
                tracing::warn!(error = %e, "ADN sync settlement failed, returning ack only");
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    Ok((
        StatusCode::OK,
        Json(AdnPayResponse {
            accepted_at_unix_micros: now,
            facilitator_ack_signature: ack_signature,
            facilitator_pubkey_commitment: state.facilitator_key.commitment_hex(),
            tx_id,
            block_num,
        }),
    ))
}

fn parse_serial_hex(hex_arr: &[String; 4]) -> Result<Word> {
    let mut felts = [miden_protocol::Felt::ZERO; 4];
    for (i, h) in hex_arr.iter().enumerate() {
        let s = h.trim_start_matches("0x");
        let val = u64::from_str_radix(s, 16)
            .map_err(|e| FacilitatorError::Malformed(format!("serial_num[{i}]: {e}")))?;
        felts[i] = miden_protocol::Felt::new(val);
    }
    Ok(felts.into())
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim_start_matches("0x");
    hex::decode(s).map_err(|e| FacilitatorError::Malformed(format!("hex: {e}")))
}

fn ack_message(
    accepted_at: u64,
    note_id: &str,
    merchant_id: &str,
    amount: u64,
) -> Result<Word> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&accepted_at.to_be_bytes());
    buf.extend_from_slice(note_id.as_bytes());
    buf.extend_from_slice(merchant_id.as_bytes());
    buf.extend_from_slice(&amount.to_be_bytes());
    Ok(Hasher::hash(&buf))
}

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}
