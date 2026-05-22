//! `AdnClient` — agent-side client for AgentDebitNote payments.
//!
//! Matches the Base x402 flow: the agent only talks to the merchant.
//! Step 1: GET /resource → 402 with payment requirements
//! Step 3: GET /resource + Payment-Signature header with signed debit
//! The merchant relays to the facilitator internally.

use std::time::{SystemTime, UNIX_EPOCH};

use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::utils::serde::Serializable;

use agent_debit_note::message::debit_message;

use crate::types::*;

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

fn word_to_hex_array(w: Word) -> [String; 4] {
    [
        format!("0x{:016x}", w[0].as_canonical_u64()),
        format!("0x{:016x}", w[1].as_canonical_u64()),
        format!("0x{:016x}", w[2].as_canonical_u64()),
        format!("0x{:016x}", w[3].as_canonical_u64()),
    ]
}

/// Agent-side client for AgentDebitNote payments.
///
/// The agent only signs; it does not prove, execute kernels, or talk to
/// the facilitator. All communication goes through the merchant.
pub struct AdnClient {
    agent_sk: AuthSecretKey,
    note_id: String,
    note_serial: Word,
    balance: u64,
    expiry_block: u32,
    agent_pubkey_commitment: Word,
    note_data_hex: Option<String>,
}

impl AdnClient {
    pub fn new(
        agent_sk: AuthSecretKey,
        note_id: String,
        note_serial: Word,
        balance: u64,
        expiry_block: u32,
    ) -> Self {
        let agent_pubkey_commitment: Word = agent_sk.public_key().to_commitment().into();
        Self {
            agent_sk,
            note_id,
            note_serial,
            balance,
            expiry_block,
            note_data_hex: None,
            agent_pubkey_commitment,
        }
    }

    /// Set the serialized note data (hex). Included in payment requests
    /// so the facilitator can consume the note for chain-finality settlement.
    pub fn set_note_data_hex(&mut self, hex: String) {
        self.note_data_hex = Some(hex);
    }

    pub fn note_id(&self) -> &str {
        &self.note_id
    }

    pub fn balance(&self) -> u64 {
        self.balance
    }

    /// Sign a debit authorization for the given merchant and amount.
    /// Returns a `SignedDebit` that the agent embeds in the Payment-Signature
    /// header when retrying the merchant request.
    pub fn sign_debit(
        &self,
        merchant: AccountId,
        amount: u64,
    ) -> Result<(SignedDebit, AdnPayTimings), AdnPayError> {
        let mut timings = AdnPayTimings {
            t_pay_start: now_micros(),
            ..Default::default()
        };

        if amount > self.balance {
            return Err(AdnPayError::InsufficientBalance {
                requested: amount,
                available: self.balance,
            });
        }

        timings.t_sign_start = now_micros();
        let message = debit_message(self.note_serial, merchant, amount);
        let signature = self.agent_sk.sign(message);
        // Extract raw Falcon signature bytes (without the Signature enum wrapper)
        let falcon_sig = match &signature {
            miden_protocol::account::auth::Signature::Falcon512Poseidon2(inner) => inner.to_bytes(),
            _ => panic!("expected Falcon512Poseidon2 signature"),
        };
        let prepared_sig = signature.to_prepared_signature(message);
        timings.t_sign_end = now_micros();

        let debit = SignedDebit {
            note_id: self.note_id.clone(),
            serial_num_hex: word_to_hex_array(self.note_serial),
            merchant_account_id: merchant.to_hex(),
            amount,
            signature_hex: format!("0x{}", hex::encode(&falcon_sig)),
            prepared_signature_hex: format!(
                "0x{}",
                hex::encode(
                    prepared_sig
                        .iter()
                        .flat_map(|f| f.as_canonical_u64().to_le_bytes())
                        .collect::<Vec<u8>>()
                )
            ),
            expiry_block_height: self.expiry_block,
            agent_pubkey_commitment_hex: format!(
                "0x{}",
                hex::encode(self.agent_pubkey_commitment.to_bytes())
            ),
            note_data_hex: self.note_data_hex.clone(),
        };

        Ok((debit, timings))
    }

    /// Update local state after the facilitator reports successful settlement.
    pub fn update_remainder(&mut self, remainder: &RemainderInfo) {
        self.note_id = remainder.note_id.clone();
        self.balance = remainder.balance;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdnPayError {
    #[error("insufficient balance: requested {requested}, available {available}")]
    InsufficientBalance { requested: u64, available: u64 },
}
