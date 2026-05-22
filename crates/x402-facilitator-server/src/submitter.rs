//! Facilitator-side Miden integration.
//!
//! The underlying `miden_client::Client` is not `Send` (it holds a
//! `Box<dyn OnNoteReceived>` and a non-Send future inside its sync
//! plumbing), which is incompatible with our `AppState` getting cloned
//! into multi-threaded tokio spawn tasks. Wrap it in a "submitter
//! actor": a dedicated single-threaded `tokio::task::LocalSet` thread
//! owns the client and consumes `Command` messages from an mpsc
//! channel. The rest of the server holds only a cheap, `Send + Sync`
//! [`SubmitterHandle`] that sends commands and awaits responses via
//! oneshot channels.
//!
//! Commands implemented in v1:
//!   - `Sync`              — `client.sync_state()`; returns block_num
//!   - `AddAccountBytes`   — load a serialized `Account` into the store
//!
//! Future commands (Phase 1B-3 follow-up):
//!   - `RebuildAndSubmit`  — reconstruct a `TransactionRequest` from
//!                           x402_context + signature, execute, prove,
//!                           submit via the Miden network.

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use guardian_shared::SignatureScheme;
use miden_client::builder::ClientBuilder;
use miden_client::keystore::FilesystemKeyStore;
use miden_client::rpc::{Endpoint, GrpcClient};
use miden_client::transaction::{TransactionRequest, TransactionRequestBuilder};
use miden_client::{Client as MidenSdkClient, ClientError};
use miden_client_sqlite_store::ClientBuilderSqliteExt;
use miden_protocol::{Felt, Word};
use miden_protocol::account::{Account, AccountId};
use miden_protocol::note::Note;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use tokio::sync::{mpsc, oneshot};

use crate::error::{FacilitatorError, Result};

#[derive(Debug)]
enum Command {
    Sync(oneshot::Sender<std::result::Result<u32, String>>),
    AddAccountBytes {
        bytes: Vec<u8>,
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
    /// Consume an AgentDebitNote synchronously: import note, build tx,
    /// prove, submit, wait for block inclusion. Returns (tx_id, block_num).
    ConsumeAdnNote {
        note_bytes: Vec<u8>,
        note_args: [u8; 32],
        prepared_sig_bytes: Vec<u8>,
        reply: oneshot::Sender<std::result::Result<(String, u32), String>>,
    },
    /// Rebuild a `TransactionRequest` from `request_bytes`, inject the
    /// `(pubkey_commitment, message, signature)` triple into its
    /// advice map, then prove + submit via the miden-client. Returns
    /// the resulting tx id as a hex string.
    RebuildAndSubmit {
        account_id: AccountId,
        request_bytes: Vec<u8>,
        scheme: SignatureScheme,
        pubkey_commitment: Word,
        message: Word,
        signature_hex: String,
        /// Only needed for ECDSA; ignored for Falcon.
        pubkey_hex: Option<String>,
        reply: oneshot::Sender<std::result::Result<String, String>>,
    },
}

/// Cheap, `Send + Sync` handle to the submitter actor. Cloneable.
#[derive(Debug, Clone)]
pub struct SubmitterHandle {
    tx: mpsc::Sender<Command>,
}

impl SubmitterHandle {
    pub async fn sync(&self) -> Result<u32> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(Command::Sync(reply_tx))
            .await
            .map_err(|_| FacilitatorError::Internal("submitter actor stopped".into()))?;
        let res = reply_rx
            .await
            .map_err(|_| FacilitatorError::Internal("submitter actor dropped reply".into()))?;
        res.map_err(FacilitatorError::Internal)
    }

    pub async fn add_account_bytes(&self, bytes: Vec<u8>) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(Command::AddAccountBytes {
                bytes,
                reply: reply_tx,
            })
            .await
            .map_err(|_| FacilitatorError::Internal("submitter actor stopped".into()))?;
        let res = reply_rx
            .await
            .map_err(|_| FacilitatorError::Internal("submitter actor dropped reply".into()))?;
        res.map_err(FacilitatorError::Internal)
    }

    /// Consume an AgentDebitNote synchronously: import note, build tx,
    /// prove, submit, and wait for block inclusion. Returns (tx_id, block_num).
    pub async fn consume_adn_note(
        &self,
        note_bytes: Vec<u8>,
        note_args: [u8; 32],
        prepared_sig_bytes: Vec<u8>,
    ) -> Result<(String, u32)> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(Command::ConsumeAdnNote {
                note_bytes,
                note_args,
                prepared_sig_bytes,
                reply: reply_tx,
            })
            .await
            .map_err(|_| FacilitatorError::Internal("submitter actor stopped".into()))?;
        let res = reply_rx
            .await
            .map_err(|_| FacilitatorError::Internal("submitter actor dropped reply".into()))?;
        res.map_err(FacilitatorError::Internal)
    }

    /// Rebuild a serialized `TransactionRequest`, inject the agent's
    /// signature into the advice map, prove + submit. Returns the
    /// resulting on-chain tx id.
    #[allow(clippy::too_many_arguments)]
    pub async fn rebuild_and_submit(
        &self,
        account_id: AccountId,
        request_bytes: Vec<u8>,
        scheme: SignatureScheme,
        pubkey_commitment: Word,
        message: Word,
        signature_hex: String,
        pubkey_hex: Option<String>,
    ) -> Result<String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(Command::RebuildAndSubmit {
                account_id,
                request_bytes,
                scheme,
                pubkey_commitment,
                message,
                signature_hex,
                pubkey_hex,
                reply: reply_tx,
            })
            .await
            .map_err(|_| FacilitatorError::Internal("submitter actor stopped".into()))?;
        let res = reply_rx
            .await
            .map_err(|_| FacilitatorError::Internal("submitter actor dropped reply".into()))?;
        res.map_err(FacilitatorError::Internal)
    }
}

/// Spawn a dedicated OS thread running a tokio current-thread runtime
/// that owns the `MidenSdkClient` and processes `Command` messages.
/// Returns a `SubmitterHandle` for the caller.
pub fn spawn_submitter_actor(
    rpc_endpoint: String,
    data_dir: PathBuf,
    timeout_ms: u64,
) -> SubmitterHandle {
    let (tx, mut rx) = mpsc::channel::<Command>(64);
    let handle = SubmitterHandle { tx };

    thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!(error = %e, "submitter actor: failed to build current-thread runtime");
                return;
            }
        };

        runtime.block_on(async move {
            let mut client = match build_client(&rpc_endpoint, &data_dir, timeout_ms).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "submitter actor: failed to build miden-client; actor exiting");
                    return;
                }
            };
            tracing::info!("submitter actor: miden-client built, ready");

            while let Some(cmd) = rx.recv().await {
                match cmd {
                    Command::Sync(reply) => {
                        let res = client
                            .sync_state()
                            .await
                            .map(|s| s.block_num.as_u32())
                            .map_err(|e: ClientError| format!("sync: {e}"));
                        let _ = reply.send(res);
                    }
                    Command::AddAccountBytes { bytes, reply } => {
                        let res = match Account::read_from_bytes(&bytes) {
                            Err(e) => Err(format!("Account decode: {e}")),
                            Ok(account) => client
                                .add_account(&account, false)
                                .await
                                .map_err(|e| format!("add_account: {e}")),
                        };
                        let _ = reply.send(res);
                    }
                    Command::ConsumeAdnNote {
                        note_bytes,
                        note_args,
                        prepared_sig_bytes,
                        reply,
                    } => {
                        let res = consume_adn_note_inner(
                            &mut client,
                            &note_bytes,
                            &note_args,
                            &prepared_sig_bytes,
                        )
                        .await;
                        let _ = reply.send(res);
                    }
                    Command::RebuildAndSubmit {
                        account_id,
                        request_bytes,
                        scheme,
                        pubkey_commitment,
                        message,
                        signature_hex,
                        pubkey_hex,
                        reply,
                    } => {
                        let res = rebuild_and_submit_inner(
                            &mut client,
                            account_id,
                            &request_bytes,
                            scheme,
                            pubkey_commitment,
                            message,
                            &signature_hex,
                            pubkey_hex.as_deref(),
                        )
                        .await;
                        let _ = reply.send(res);
                    }
                }
            }
            tracing::info!("submitter actor: channel closed; exiting");
        });
    });

    handle
}

#[allow(clippy::too_many_arguments)]
async fn rebuild_and_submit_inner(
    client: &mut MidenSdkClient<FilesystemKeyStore>,
    account_id: AccountId,
    request_bytes: &[u8],
    scheme: SignatureScheme,
    pubkey_commitment: Word,
    message: Word,
    signature_hex: &str,
    pubkey_hex: Option<&str>,
) -> std::result::Result<String, String> {
    let mut request = TransactionRequest::read_from_bytes(request_bytes)
        .map_err(|e| format!("request decode: {e}"))?;
    // Parse the signature into a typed AccountSignature and stage it
    // into the request's advice map at the executor-expected key.
    let parsed = scheme
        .parse_signature_hex(signature_hex)
        .map_err(|e| format!("parse signature: {e}"))?;
    let (advice_key, advice_vals) = scheme
        .build_signature_advice_entry(pubkey_commitment, message, &parsed, pubkey_hex)
        .map_err(|e| format!("build advice: {e}"))?;
    request
        .advice_map_mut()
        .insert(advice_key, advice_vals);
    // Sync first so on-chain state is current; otherwise the
    // re-execution may diverge from what the agent saw.
    client
        .sync_state()
        .await
        .map_err(|e: ClientError| format!("sync_state: {e}"))?;
    let tx_id = client
        .submit_new_transaction(account_id, request)
        .await
        .map_err(|e| format!("submit_new_transaction: {e}"))?;
    Ok(format!("{tx_id}"))
}

/// Consume an AgentDebitNote: deserialize the note, build a consume tx
/// with the agent's prepared Falcon signature on the advice stack,
/// prove + submit, sync to confirm block inclusion.
async fn consume_adn_note_inner(
    client: &mut MidenSdkClient<FilesystemKeyStore>,
    note_bytes: &[u8],
    note_args_bytes: &[u8; 32],
    prepared_sig_bytes: &[u8],
) -> std::result::Result<(String, u32), String> {
    // 1. Deserialize the Note
    let note = Note::read_from_bytes(note_bytes)
        .map_err(|e| format!("Note decode: {e}"))?;

    // 2. Parse note_args: 4 felts packed as 4 x u64 big-endian
    let note_args_word: Word = {
        let mut felts = [Felt::ZERO; 4];
        for i in 0..4 {
            let bytes: [u8; 8] = note_args_bytes[i * 8..(i + 1) * 8]
                .try_into()
                .map_err(|_| "note_args slice error".to_string())?;
            felts[i] = Felt::new(u64::from_be_bytes(bytes));
        }
        felts.into()
    };

    // 3. Parse prepared signature into Felts for advice stack
    let prepared_sig_felts: Vec<Felt> = prepared_sig_bytes
        .chunks_exact(8)
        .map(|chunk| {
            let bytes: [u8; 8] = chunk.try_into().unwrap();
            Felt::new(u64::from_le_bytes(bytes))
        })
        .collect();

    // 4. Compute the advice map key for the Falcon signature.
    //    The MASM note script looks up the sig at key = merge(AGENT_PK, MESSAGE).
    //    We need to compute both the message and the agent's PK from the note storage.
    //
    //    Message = merge(serial_num, note_args_word) — same as debit_message()
    //    Agent PK = first 4 felts of note storage
    let serial_num = note.recipient().serial_num();
    let message = miden_protocol::Hasher::merge(&[serial_num.into(), note_args_word.into()]);
    let agent_pk: Word = {
        let storage_elements = note.recipient().storage().to_elements();
        if storage_elements.len() >= 4 {
            [storage_elements[0], storage_elements[1],
             storage_elements[2], storage_elements[3]].into()
        } else {
            return Err("note storage too short for agent_pk".into());
        }
    };
    let sig_key: Word = miden_protocol::Hasher::merge(&[agent_pk, message]);

    // 5. Import the note into the client's store so the executor can
    //    find the note and its script during execution.
    use miden_protocol::note::{NoteFile, NoteDetails};
    let note_details = NoteDetails::new(
        note.assets().clone(),
        note.recipient().clone(),
    );
    let note_file = NoteFile::NoteDetails {
        details: note_details,
        after_block_num: 0u32.into(),
        tag: None,
    };
    client
        .import_notes(&[note_file])
        .await
        .map_err(|e| format!("import_notes: {e}"))?;

    let request = TransactionRequestBuilder::new()
        .input_notes([(note, Some(note_args_word))])
        .extend_advice_map([(sig_key, prepared_sig_felts.as_slice())])
        .build()
        .map_err(|e| format!("build consume request: {e}"))?;

    // 6. Sync state to get current chain state
    client
        .sync_state()
        .await
        .map_err(|e: ClientError| format!("sync_state before submit: {e}"))?;

    // 6. Get the facilitator's account ID from env or use first account in store
    let consumer_account_id = if let Ok(hex) = std::env::var("FACILITATOR_ACCOUNT_ID") {
        AccountId::from_hex(&hex)
            .map_err(|e| format!("FACILITATOR_ACCOUNT_ID parse: {e}"))?
    } else {
        // Fallback: try to get any account from the store
        return Err("FACILITATOR_ACCOUNT_ID not set — cannot consume note".into());
    };

    // 7. Submit: proves locally + submits to Miden node
    let tx_id = client
        .submit_new_transaction(consumer_account_id, request)
        .await
        .map_err(|e| format!("submit_new_transaction: {e}"))?;

    // 8. Sync again to confirm block inclusion
    let sync_result = client
        .sync_state()
        .await
        .map_err(|e: ClientError| format!("sync_state after submit: {e}"))?;

    let block_num = sync_result.block_num.as_u32();
    tracing::info!(%tx_id, block_num, "ADN note consumed and confirmed on-chain");

    Ok((format!("{tx_id}"), block_num))
}

async fn build_client(
    rpc_endpoint: &str,
    data_dir: &PathBuf,
    timeout_ms: u64,
) -> Result<MidenSdkClient<FilesystemKeyStore>> {
    std::fs::create_dir_all(data_dir)
        .map_err(|e| FacilitatorError::Internal(format!("data dir: {e}")))?;
    let endpoint = Endpoint::try_from(rpc_endpoint)
        .map_err(|e| FacilitatorError::Internal(format!("endpoint {rpc_endpoint}: {e}")))?;
    let rpc_client = Arc::new(GrpcClient::new(&endpoint, timeout_ms));
    let keystore = Arc::new(
        FilesystemKeyStore::new(data_dir.join("facilitator-keystore"))
            .map_err(|e| FacilitatorError::Internal(format!("keystore: {e}")))?,
    );
    let store_path = data_dir.join("facilitator-store.sqlite3");
    ClientBuilder::new()
        .rpc(rpc_client)
        .sqlite_store(store_path)
        .authenticator(keystore)
        .in_debug_mode(false.into())
        .build()
        .await
        .map_err(|e| FacilitatorError::Internal(format!("client build: {e}")))
}
