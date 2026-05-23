//! x402 facilitator binary entry point.

use std::path::PathBuf;
use std::sync::Arc;

use std::sync::atomic::AtomicBool;

use x402_facilitator::{
    api,
    jobs::{self, BatchConfig},
    key::FacilitatorKey,
    state::{AppState, PerAgentLocks},
    store::FilesystemX402Store,
    submitter::spawn_submitter_actor,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let data_dir: PathBuf = std::env::var("FACILITATOR_DATA_DIR")
        .unwrap_or_else(|_| "./.x402-data".to_string())
        .into();
    let keystore_dir: PathBuf = std::env::var("FACILITATOR_KEYSTORE_PATH")
        .unwrap_or_else(|_| {
            data_dir
                .join("keystore")
                .to_string_lossy()
                .into_owned()
        })
        .into();
    let port: u16 = std::env::var("FACILITATOR_HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7002);

    let store = FilesystemX402Store::new(data_dir.clone())?;
    let facilitator_key = FacilitatorKey::load_or_create(keystore_dir.clone())?;
    let locks = PerAgentLocks::default();

    // Optional: connect to a Miden RPC endpoint so we can prove + submit.
    let submitter_available = Arc::new(AtomicBool::new(false));
    let submitter = match std::env::var("MIDEN_RPC_ENDPOINT") {
        Ok(endpoint) => {
            tracing::info!(%endpoint, "spawning submitter actor");
            let timeout: u64 = std::env::var("MIDEN_RPC_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(20_000);
            let submitter_dir = data_dir.join("submitter");
            let handle = spawn_submitter_actor(endpoint, submitter_dir, timeout);
            // Import facilitator account BEFORE sync (so sync discovers it)
            if let Ok(snap_path) = std::env::var("FACILITATOR_ACCOUNT_SNAPSHOT") {
                match std::fs::read_to_string(&snap_path) {
                    Ok(b64) => {
                        use base64::Engine;
                        match base64::engine::general_purpose::STANDARD.decode(b64.trim().as_bytes()) {
                            Ok(bytes) => match handle.add_account_bytes(bytes).await {
                                Ok(()) => tracing::info!("facilitator account imported into submitter"),
                                Err(e) => tracing::warn!(error = %e, "failed to import facilitator account"),
                            },
                            Err(e) => tracing::warn!(error = %e, "failed to decode facilitator snapshot b64"),
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, path = %snap_path, "failed to read facilitator snapshot"),
                }
            }
            // Import ADN note BEFORE sync (so sync authenticates it)
            if let Ok(note_path) = std::env::var("ADN_NOTE_SNAPSHOT") {
                match std::fs::read_to_string(&note_path) {
                    Ok(b64) => {
                        use base64::Engine;
                        match base64::engine::general_purpose::STANDARD.decode(b64.trim().as_bytes()) {
                            Ok(bytes) => match handle.import_note_bytes(bytes).await {
                                Ok(()) => tracing::info!("ADN note imported into submitter (pre-sync)"),
                                Err(e) => tracing::warn!(error = %e, "failed to import ADN note"),
                            },
                            Err(e) => tracing::warn!(error = %e, "failed to decode ADN note b64"),
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, path = %note_path, "failed to read ADN note snapshot"),
                }
            }
            // Sync AFTER importing account + note (so note gets authenticated)
            match handle.sync().await {
                Ok(block_num) => {
                    tracing::info!(block_num, "submitter actor synced at startup");
                    submitter_available.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "submitter actor sync failed at startup; continuing");
                }
            }
            Some(handle)
        }
        Err(_) => None,
    };

    let state = AppState {
        store,
        facilitator_key,
        locks,
        submitter,
        submitter_available,
    };

    let batch_cfg = BatchConfig::from_env();
    jobs::spawn_batch_worker(state.clone(), batch_cfg);

    let app = api::router(state.clone());
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(
        %addr,
        data_dir = %data_dir.display(),
        keystore_dir = %keystore_dir.display(),
        facilitator_pubkey_commitment = %state.facilitator_key.commitment_hex(),
        "x402-facilitator-server listening"
    );
    axum::serve(listener, app).await?;
    Ok(())
}
