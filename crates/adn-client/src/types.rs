//! Wire types for the AgentDebitNote x402 payment flow.

use serde::{Deserialize, Serialize};

/// Agent → Facilitator: request to debit the AgentDebitNote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDebit {
    /// Hex note ID of the current AgentDebitNote.
    pub note_id: String,
    /// Serial number of the current note (4 hex felts).
    pub serial_num_hex: [String; 4],
    /// Merchant's Miden account ID (hex).
    pub merchant_account_id: String,
    /// Debit amount.
    pub amount: u64,
    /// Hex-encoded Falcon signature bytes over debit_message(serial, merchant, amount).
    pub signature_hex: String,
    /// Hex-encoded prepared signature (for advice stack injection during proving).
    pub prepared_signature_hex: String,
    /// Expiry block height of the AgentDebitNote.
    pub expiry_block_height: u32,
    /// Agent's public key commitment (hex Word) — for facilitator to verify.
    pub agent_pubkey_commitment_hex: String,
    /// Hex-encoded serialized Note (for chain-finality settlement).
    /// Included on first payment or when facilitator needs note data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note_data_hex: Option<String>,
}

/// Facilitator → Agent: ack that the debit is accepted.
/// The facilitator has verified the signature and will settle asynchronously.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayAck {
    /// Unix timestamp (micros) when the facilitator accepted the debit.
    pub accepted_at_unix_micros: u64,
    /// Facilitator's Falcon signature over (accepted_at, note_id, merchant, amount).
    /// The merchant can verify this to confirm the facilitator vouches for the payment.
    pub facilitator_ack_signature: String,
    /// Facilitator's public key commitment (hex) for ack verification.
    pub facilitator_pubkey_commitment: String,
}

/// Facilitator → Agent (async, after settlement): remainder note info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemainderInfo {
    /// New note ID after consumption.
    pub note_id: String,
    /// Serial number of the remainder note.
    pub serial_num_hex: [String; 4],
    /// Remaining balance.
    pub balance: u64,
    /// On-chain tx ID of the consumption transaction.
    pub tx_id: String,
    /// Block number where the tx was included.
    pub block_num: u32,
}

/// Per-payment timing breakdown (for benchmarking).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdnPayTimings {
    pub t_pay_start: u64,
    pub t_sign_start: u64,
    pub t_sign_end: u64,
    pub t_send_facilitator: u64,
    pub t_ack_received: u64,
}
