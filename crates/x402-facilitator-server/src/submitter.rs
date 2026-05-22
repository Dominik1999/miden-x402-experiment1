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
use miden_client::transaction::TransactionRequest;
use miden_client::{Client as MidenSdkClient, ClientError};
use miden_client_sqlite_store::ClientBuilderSqliteExt;
use miden_protocol::Word;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::utils::serde::Deserializable;
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
                    Command::ConsumeAdnNote { reply, .. } => {
                        // TODO: implement full note consumption
                        // 1. Deserialize Note from note_bytes
                        // 2. Import into client store
                        // 3. Build TransactionRequest with input_notes + note_args
                        // 4. Add prepared sig to advice stack
                        // 5. client.submit_new_transaction()
                        // 6. client.sync_state() to confirm
                        let _ = reply.send(Err(
                            "ConsumeAdnNote: not yet implemented - settlement requires full note integration".into(),
                        ));
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
