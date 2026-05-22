//! One-shot Miden testnet setup for the x402 demo.
//!
//! Brings up the on-chain state the bench expects:
//!   1. Deploys a fungible faucet ("X402TEST" token).
//!   2. Deploys `--agents N` agent wallet accounts (each with a fresh Falcon key).
//!   3. Mints one note from the faucet to each agent.
//!   4. Waits for the notes to become consumable, then consumes them.
//!   5. Saves everything the bench needs into `--out-dir`:
//!        - `setup.toml`           — bench config + IDs
//!        - `faucet_id.txt`        — bech32 faucet id (testnet)
//!        - `agents/<i>/account_id.txt`
//!        - `agents/<i>/account_snapshot.b64`  — base64 `Account::write_to_bytes`
//!        - `agents/<i>/hot_key.bin`           — Falcon `SecretKey::write_to_bytes`
//!        - `keystore/`            — miden-client filesystem keystore (shared)
//!        - `store.sqlite3`        — miden-client store
//!
//! Setup is idempotent up to disk: a fresh run wipes `--out-dir`
//! first so it's safe to re-run.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use base64::Engine;
use clap::Parser;
use miden_client::account::component::{AuthControlled, BasicFungibleFaucet, BasicWallet};
use miden_client::account::{AccountBuilder, AccountStorageMode, AccountType};
use miden_client::address::NetworkId;
use miden_client::asset::{FungibleAsset, TokenSymbol};
use miden_client::auth::{AuthSchemeId, AuthSecretKey, AuthSingleSig};
use miden_client::builder::ClientBuilder;
use miden_client::keystore::{FilesystemKeyStore, Keystore};
use miden_client::note::NoteType;
use miden_client::rpc::{Endpoint, GrpcClient};
use miden_client::transaction::TransactionRequestBuilder;
use miden_client::{Client, Felt};
use miden_client_sqlite_store::ClientBuilderSqliteExt;
use guardian_shared::SignatureScheme as GuardianSignatureScheme;
use miden_client::{ClientError, transaction::TransactionExecutorError};
use miden_confidential_contracts::multisig_guardian::{
    MultisigGuardianBuilder, MultisigGuardianConfig,
};
use miden_protocol::Word;
use miden_protocol::note::{Note, NoteAssets, NoteMetadata, NoteRecipient, NoteStorage, NoteTag};
use miden_protocol::transaction::TransactionSummary;
use miden_protocol::utils::serde::{Deserializable, Serializable};
use miden_standards::code_builder::CodeBuilder;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
#[command(about = "One-shot Miden testnet setup for the x402 bench")]
struct Args {
    /// RPC endpoint for the Miden node.
    #[arg(long, default_value = "https://rpc.testnet.miden.io")]
    rpc_endpoint: String,

    /// Number of agent accounts to provision.
    #[arg(long, default_value_t = 1)]
    agents: usize,

    /// Amount of test tokens to mint per agent.
    #[arg(long, default_value_t = 1_000_000u64)]
    mint_amount: u64,

    /// Output directory; will be created if missing. NOTE: contents are
    /// *not* wiped — re-running against an existing dir reuses the
    /// existing miden-client store.
    #[arg(long, default_value = "./testnet-state")]
    out_dir: PathBuf,

    /// How many seconds to wait for consumable notes per agent before giving up.
    #[arg(long, default_value_t = 120u64)]
    consumable_wait_secs: u64,

    /// Also create an AgentDebitNote on-chain for the ADN x402 variant.
    /// The note will hold --adn-amount tokens from the first agent.
    #[arg(long)]
    adn: bool,

    /// Amount of tokens to put into the AgentDebitNote.
    #[arg(long, default_value_t = 100_000u64)]
    adn_amount: u64,

    /// Expiry block height for the AgentDebitNote (blocks from current).
    #[arg(long, default_value_t = 100_000u32)]
    adn_expiry_blocks: u32,

    /// Facilitator URL to fetch its pubkey for the AgentDebitNote co-sig storage.
    /// The facilitator must be running before setup-testnet.
    #[arg(long)]
    adn_facilitator_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SetupReport {
    rpc_endpoint: String,
    faucet_id_bech32: String,
    faucet_id_hex: String,
    merchant_id_bech32: String,
    merchant_id_hex: String,
    agent_count: usize,
    agents: Vec<AgentRecord>,
    mint_amount: u64,
    /// AgentDebitNote fields (populated when --adn flag is used)
    #[serde(default)]
    adn_note_id: Option<String>,
    #[serde(default)]
    adn_serial_num_hex: Option<[String; 4]>,
    #[serde(default)]
    adn_balance: Option<u64>,
    #[serde(default)]
    adn_expiry_block: Option<u32>,
    /// Hex-encoded serialized Note for async settlement.
    #[serde(default)]
    adn_note_data_hex: Option<String>,
    /// Facilitator account for note consumption.
    #[serde(default)]
    facilitator_account_id_hex: Option<String>,
    #[serde(default)]
    facilitator_account_snapshot_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AgentRecord {
    index: usize,
    account_id_bech32: String,
    account_id_hex: String,
    /// Path to the base64-encoded `Account` snapshot.
    snapshot_path: String,
    /// Path to the Falcon `SecretKey::write_to_bytes` blob.
    hot_key_path: String,
    commitment_hex: String,
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
    let args = Args::parse();
    std::fs::create_dir_all(&args.out_dir)?;
    tracing::info!(?args, "setup-testnet starting");

    let (mut client, keystore) = build_client(&args).await?;
    client
        .sync_state()
        .await
        .context("initial sync_state failed")?;

    // ─── 1. Deploy faucet ───
    let faucet_init_seed = rand_seed_32(&mut client);
    let faucet_key = AuthSecretKey::new_falcon512_poseidon2_with_rng(client.rng());
    let symbol = TokenSymbol::new("XTEST")
        .map_err(|e| anyhow::anyhow!("TokenSymbol: {e:?}"))?;
    let max_supply = Felt::new(1_000_000_000);
    let faucet = AccountBuilder::new(faucet_init_seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthSingleSig::new(
            faucet_key.public_key().to_commitment().into(),
            AuthSchemeId::Falcon512Poseidon2,
        ))
        .with_component(
            BasicFungibleFaucet::new(symbol, 6, max_supply)
                .map_err(|e| anyhow::anyhow!("BasicFungibleFaucet: {e:?}"))?,
        )
        .with_component(AuthControlled::allow_all())
        .build()
        .map_err(|e| anyhow::anyhow!("faucet build: {e:?}"))?;
    client
        .add_account(&faucet, false)
        .await
        .context("add faucet account")?;
    keystore
        .add_key(&faucet_key, faucet.id())
        .await
        .map_err(|e| anyhow::anyhow!("faucet keystore add: {e:?}"))?;
    let faucet_id = faucet.id();
    let faucet_bech32 = faucet_id.to_bech32(NetworkId::Testnet);
    tracing::info!(faucet_id = %faucet_bech32, "faucet deployed locally");

    client.sync_state().await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // ─── 1b. Deploy a placeholder merchant account ───
    // The bench's reference-merchant verifies payments by nullifier
    // lookup on the facilitator, but the on-chain tx still needs a
    // real-looking `recipient` `AccountId`. Deploying a public
    // BasicWallet here gives us a stable merchant id for the run.
    let merchant_init_seed = rand_seed_32(&mut client);
    let merchant_key = AuthSecretKey::new_falcon512_poseidon2_with_rng(client.rng());
    let merchant = AccountBuilder::new(merchant_init_seed)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthSingleSig::new(
            merchant_key.public_key().to_commitment().into(),
            AuthSchemeId::Falcon512Poseidon2,
        ))
        .with_component(BasicWallet)
        .build()
        .map_err(|e| anyhow::anyhow!("merchant build: {e:?}"))?;
    client
        .add_account(&merchant, false)
        .await
        .context("add merchant account")?;
    keystore
        .add_key(&merchant_key, merchant.id())
        .await
        .map_err(|e| anyhow::anyhow!("merchant keystore add: {e:?}"))?;
    let merchant_id_bech32 = merchant.id().to_bech32(NetworkId::Testnet);
    let merchant_id_hex = merchant.id().to_hex();
    tracing::info!(%merchant_id_bech32, "merchant deployed locally");

    // ─── 1c. Deploy a facilitator wallet account ───
    // The facilitator needs its own on-chain account to consume
    // AgentDebitNotes (the note script adds assets to the consumer's
    // vault, so the consumer needs a BasicWallet component).
    let facilitator_init_seed = rand_seed_32(&mut client);
    let facilitator_key_for_account = AuthSecretKey::new_falcon512_poseidon2_with_rng(client.rng());
    let facilitator_account = AccountBuilder::new(facilitator_init_seed)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthSingleSig::new(
            facilitator_key_for_account.public_key().to_commitment().into(),
            AuthSchemeId::Falcon512Poseidon2,
        ))
        .with_component(BasicWallet)
        .build()
        .map_err(|e| anyhow::anyhow!("facilitator build: {e:?}"))?;
    client
        .add_account(&facilitator_account, false)
        .await
        .context("add facilitator account")?;
    keystore
        .add_key(&facilitator_key_for_account, facilitator_account.id())
        .await
        .map_err(|e| anyhow::anyhow!("facilitator keystore add: {e:?}"))?;
    let facilitator_account_id_hex = facilitator_account.id().to_hex();
    tracing::info!(facilitator_id = %facilitator_account_id_hex, "facilitator account deployed locally");

    // ─── 2. Deploy agents (MultisigGuardian, threshold=1, guardian disabled) ───
    //
    // The auth flow on `MultisigGuardian` surfaces the
    // `TransactionSummary` via the executor's `Unauthorized` error
    // variant when no signature is configured — which is exactly what
    // the design's sign-without-prove pattern needs. The simpler
    // `BasicWallet + AuthSingleSig` path actively signs during
    // execution and fails with `UnknownPublicKey` if the key isn't
    // in the keystore.
    //
    // We disable the guardian co-sig for the agent payment flow: a
    // single-signer agent only needs its own hot-key signature per
    // payment, matching DESIGN.md's per-payment surface.
    let mut agents = Vec::new();
    for i in 0..args.agents {
        tracing::info!(i, "deploying agent account (multisig-guardian, threshold=1)");
        let init_seed = rand_seed_32(&mut client);
        let key = AuthSecretKey::new_falcon512_poseidon2_with_rng(client.rng());
        let signer_commitment: Word = key.public_key().to_commitment().into();
        let cfg = MultisigGuardianConfig::new(
            1,
            vec![signer_commitment],
            // guardian_commitment unused when guardian_enabled = false.
            Word::default(),
        )
        .with_guardian_enabled(false)
        .with_storage_mode(AccountStorageMode::Public);
        let account = MultisigGuardianBuilder::new(cfg)
            .with_seed(init_seed)
            .with_storage_mode(AccountStorageMode::Public)
            .build()
            .map_err(|e| anyhow::anyhow!("agent {i} build: {e:?}"))?;
        client
            .add_account(&account, false)
            .await
            .context("add agent account")?;
        keystore
            .add_key(&key, account.id())
            .await
            .map_err(|e| anyhow::anyhow!("agent {i} keystore add: {e:?}"))?;
        agents.push((i, account, key));
    }
    client.sync_state().await?;

    // ─── 3. Mint one note from faucet to each agent ───
    for (i, account, _key) in &agents {
        let asset = FungibleAsset::new(faucet_id, args.mint_amount)
            .map_err(|e| anyhow::anyhow!("FungibleAsset: {e:?}"))?;
        let req = TransactionRequestBuilder::new()
            .build_mint_fungible_asset(asset, account.id(), NoteType::Public, client.rng())
            .map_err(|e| anyhow::anyhow!("mint tx build: {e:?}"))?;
        let tx_id = client
            .submit_new_transaction(faucet_id, req)
            .await
            .with_context(|| format!("mint to agent {i}"))?;
        tracing::info!(i, %tx_id, "mint submitted");
    }

    // ─── 4. Wait for consumable, then consume per agent ───
    //
    // Agents use the MultisigGuardian auth component, which DOES NOT
    // auto-sign during execution. We have to drive the sign-then-inject
    // dance manually here too (the same dance the bench's facilitator
    // does for payments).
    for (i, account, key) in &agents {
        let agent_id = account.id();
        let sk = match key {
            AuthSecretKey::Falcon512Poseidon2(sk) => sk.clone(),
            _ => anyhow::bail!("agent {i} expects a Falcon SecretKey"),
        };
        let signer_commitment: Word = sk.public_key().to_commitment().into();

        let deadline = std::time::Instant::now()
            + Duration::from_secs(args.consumable_wait_secs);
        loop {
            client.sync_state().await?;
            let consumable = client
                .get_consumable_notes(Some(agent_id))
                .await
                .with_context(|| format!("get_consumable_notes agent {i}"))?;
            if consumable.is_empty() {
                if std::time::Instant::now() > deadline {
                    anyhow::bail!("agent {i} never saw consumable notes within deadline");
                }
                tracing::info!(i, "no consumable notes yet; waiting…");
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
            tracing::info!(i, count = consumable.len(), "consuming notes");
            let notes = consumable
                .into_iter()
                .map(|(note, _)| note.try_into())
                .collect::<Result<Vec<_>, _>>()
                .context("note conversion")?;
            let req = TransactionRequestBuilder::new()
                .build_consume_notes(notes)
                .map_err(|e| anyhow::anyhow!("consume tx build: {e:?}"))?;

            // First execution to surface the TransactionSummary via Unauthorized.
            let summary = execute_for_summary(&mut client, agent_id, req.clone())
                .await
                .with_context(|| format!("agent {i} execute_for_summary"))?;
            let message = summary.to_commitment();
            // Sign the summary commitment.
            let sig = sk.sign(message);
            let sig_hex = format!("0x{}", hex::encode(sig.to_bytes()));
            // Build the advice entry and inject it into the request.
            let parsed = GuardianSignatureScheme::Falcon
                .parse_signature_hex(&sig_hex)
                .map_err(|e| anyhow::anyhow!("parse_signature_hex: {e}"))?;
            let (advice_key, advice_vals) = GuardianSignatureScheme::Falcon
                .build_signature_advice_entry(signer_commitment, message, &parsed, None)
                .map_err(|e| anyhow::anyhow!("build_signature_advice_entry: {e}"))?;
            let mut signed_req = req;
            signed_req.advice_map_mut().insert(advice_key, advice_vals);
            let tx_id = client
                .submit_new_transaction(agent_id, signed_req)
                .await
                .with_context(|| format!("agent {i} consume submit"))?;
            tracing::info!(i, %tx_id, "consume submitted (multisig sign+inject path)");
            // Wait for the consume tx to land before we serialize the account snapshot.
            tokio::time::sleep(Duration::from_secs(6)).await;
            client.sync_state().await?;
            break;
        }
    }

    // ─── 4b. (Optional) Create AgentDebitNote on-chain ───
    let mut adn_info: Option<(String, Word, u64, u32)> = None;
    if args.adn && !agents.is_empty() {
        tracing::info!("creating AgentDebitNote on-chain");
        let (_i, account, key) = &agents[0];
        let agent_id = account.id();
        let sk = match key {
            AuthSecretKey::Falcon512Poseidon2(sk) => sk.clone(),
            _ => anyhow::bail!("agent 0 expects Falcon key for ADN"),
        };
        let agent_pk_commitment: Word = sk.public_key().to_commitment().into();

        // Get current block for expiry computation
        client.sync_state().await?;
        // Use a fixed high expiry for now (the actual block number doesn't matter for benchmarks)
        let expiry_block = args.adn_expiry_blocks;

        // Compile the AgentDebitNote MASM script
        let adn_masm = agent_debit_note::note::AGENT_DEBIT_NOTE_MASM;
        let adn_script = CodeBuilder::default()
            .compile_note_script(adn_masm)
            .map_err(|e| anyhow::anyhow!("compile ADN script: {e}"))?;

        // Build the note
        let adn_asset = FungibleAsset::new(faucet_id, args.adn_amount)
            .map_err(|e| anyhow::anyhow!("ADN asset: {e:?}"))?;
        let _merchant_for_storage = merchant.id();
        let user_id = agent_id; // user = agent's own account for reclaim

        // Fetch facilitator pubkey for co-signature storage
        let facilitator_pk_commitment: Word = if let Some(ref fac_url) = args.adn_facilitator_url {
            let health_url = format!("{}/healthz", fac_url.trim_end_matches('/'));
            let http_client = reqwest::Client::new();
            let resp: serde_json::Value = http_client.get(&health_url)
                .send().await
                .map_err(|e| anyhow::anyhow!("facilitator healthz: {e}"))?
                .json().await
                .map_err(|e| anyhow::anyhow!("facilitator healthz json: {e}"))?;
            let pk_hex = resp.get("facilitator_pubkey_commitment")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("facilitator healthz missing facilitator_pubkey_commitment"))?;
            let pk_bytes = hex::decode(pk_hex.trim_start_matches("0x"))
                .map_err(|e| anyhow::anyhow!("facilitator pk hex: {e}"))?;
            let pk = miden_protocol::Word::read_from_bytes(&pk_bytes)
                .map_err(|e| anyhow::anyhow!("facilitator pk decode: {e}"))?;
            tracing::info!(facilitator_pk = %pk_hex, "fetched facilitator pubkey");
            pk
        } else {
            tracing::warn!("no --adn-facilitator-url; using zero facilitator pubkey (tests only)");
            Word::default()
        };

        // 11-item storage: [agent_pk(4), facilitator_pk(4), user_suffix, user_prefix, expiry]
        let adn_storage = NoteStorage::new(vec![
            agent_pk_commitment[0],
            agent_pk_commitment[1],
            agent_pk_commitment[2],
            agent_pk_commitment[3],
            facilitator_pk_commitment[0],
            facilitator_pk_commitment[1],
            facilitator_pk_commitment[2],
            facilitator_pk_commitment[3],
            user_id.suffix(),
            user_id.prefix().as_felt(),
            Felt::new(expiry_block as u64),
        ])
        .map_err(|e| anyhow::anyhow!("ADN storage: {e}"))?;

        let adn_serial = {
            let mut s = [0u8; 32];
            client.rng().fill_bytes(&mut s);
            Word::from([
                Felt::new(u64::from_le_bytes(s[0..8].try_into().unwrap())),
                Felt::new(u64::from_le_bytes(s[8..16].try_into().unwrap())),
                Felt::new(u64::from_le_bytes(s[16..24].try_into().unwrap())),
                Felt::new(u64::from_le_bytes(s[24..32].try_into().unwrap())),
            ])
        };

        let adn_metadata = NoteMetadata::new(agent_id, NoteType::Public)
            .with_tag(NoteTag::new(0));
        let adn_vault = NoteAssets::new(vec![miden_protocol::asset::Asset::Fungible(adn_asset)])
            .map_err(|e| anyhow::anyhow!("ADN vault: {e}"))?;
        let adn_recipient = NoteRecipient::new(adn_serial, adn_script, adn_storage);
        let adn_note = Note::new(adn_vault, adn_metadata, adn_recipient);
        let adn_note_id = adn_note.id();

        tracing::info!(%adn_note_id, "ADN note built, submitting tx");

        // Build a transaction that outputs the AgentDebitNote.
        // The agent's account creates the note, moving assets from its vault.
        // This uses the MultisigGuardian sign-inject flow (same as consume).
        let signer_commitment: Word = sk.public_key().to_commitment().into();
        let req = TransactionRequestBuilder::new()
            .own_output_notes(vec![adn_note.clone()])
            .build()
            .map_err(|e| anyhow::anyhow!("ADN tx request: {e}"))?;

        let summary = execute_for_summary(&mut client, agent_id, req.clone())
            .await
            .context("ADN execute_for_summary")?;
        let message = summary.to_commitment();
        let sig = sk.sign(message);
        let sig_hex = format!("0x{}", hex::encode(sig.to_bytes()));
        let parsed = GuardianSignatureScheme::Falcon
            .parse_signature_hex(&sig_hex)
            .map_err(|e| anyhow::anyhow!("ADN parse sig: {e}"))?;
        let (advice_key, advice_vals) = GuardianSignatureScheme::Falcon
            .build_signature_advice_entry(signer_commitment, message, &parsed, None)
            .map_err(|e| anyhow::anyhow!("ADN advice entry: {e}"))?;
        let mut signed_req = req;
        signed_req.advice_map_mut().insert(advice_key, advice_vals);
        let tx_id = client
            .submit_new_transaction(agent_id, signed_req)
            .await
            .context("ADN submit")?;
        tracing::info!(%tx_id, "ADN note submitted");

        // Wait for inclusion
        tokio::time::sleep(Duration::from_secs(6)).await;
        client.sync_state().await?;

        // Serialize the note for async settlement
        let adn_note_bytes = adn_note.to_bytes();
        let adn_note_data_hex = format!("0x{}", hex::encode(&adn_note_bytes));

        adn_info = Some((
            format!("0x{}", hex::encode(adn_note_id.to_bytes())),
            adn_serial,
            args.adn_amount,
            expiry_block,
            adn_note_data_hex,
        ));

        tracing::info!("ADN note created on-chain");
    }

    // ─── 5. Snapshot + save ───
    let agents_dir = args.out_dir.join("agents");
    std::fs::create_dir_all(&agents_dir)?;
    let mut report_agents = Vec::new();
    for (i, _account_at_deploy, key) in &agents {
        let agent_dir = agents_dir.join(format!("{i:04}"));
        std::fs::create_dir_all(&agent_dir)?;
        // Re-fetch the latest account from the client store (post-consume).
        let agent_at_deploy = &agents[*i].1;
        let id = agent_at_deploy.id();
        let updated = client
            .get_account(id)
            .await
            .context("re-fetch agent account after consume")?
            .ok_or_else(|| anyhow::anyhow!("agent {i} missing from store"))?;
        let snap_bytes = updated.to_bytes();
        let snap_b64 = base64::engine::general_purpose::STANDARD.encode(&snap_bytes);
        let snap_path = agent_dir.join("account_snapshot.b64");
        std::fs::write(&snap_path, &snap_b64)?;
        let key_bytes = match key {
            AuthSecretKey::Falcon512Poseidon2(sk) => sk.to_bytes(),
            _ => anyhow::bail!("agent {i} used non-Falcon key (unexpected)"),
        };
        let hot_key_path = agent_dir.join("hot_key.bin");
        std::fs::write(&hot_key_path, &key_bytes)?;
        std::fs::write(
            agent_dir.join("account_id.txt"),
            id.to_bech32(NetworkId::Testnet),
        )?;
        let commitment_hex = format!(
            "0x{}",
            hex::encode(updated.to_commitment().to_bytes())
        );
        report_agents.push(AgentRecord {
            index: *i,
            account_id_bech32: id.to_bech32(NetworkId::Testnet),
            account_id_hex: id.to_hex(),
            snapshot_path: relative(&args.out_dir, &snap_path),
            hot_key_path: relative(&args.out_dir, &hot_key_path),
            commitment_hex,
        });
        tracing::info!(i, "snapshot saved");
    }

    let (adn_note_id, adn_serial_hex, adn_balance, adn_expiry, adn_note_data_hex) = match &adn_info {
        Some((id, serial, balance, expiry, note_data)) => (
            Some(id.clone()),
            Some([
                format!("0x{:016x}", serial[0].as_canonical_u64()),
                format!("0x{:016x}", serial[1].as_canonical_u64()),
                format!("0x{:016x}", serial[2].as_canonical_u64()),
                format!("0x{:016x}", serial[3].as_canonical_u64()),
            ]),
            Some(*balance),
            Some(*expiry),
            Some(note_data.clone()),
        ),
        None => (None, None, None, None, None),
    };

    // Save facilitator account snapshot
    let fac_snap_path = args.out_dir.join("facilitator_account.b64");
    let fac_snap_b64 = base64::engine::general_purpose::STANDARD
        .encode(facilitator_account.to_bytes());
    std::fs::write(&fac_snap_path, &fac_snap_b64)?;
    tracing::info!("facilitator account snapshot saved");

    let report = SetupReport {
        rpc_endpoint: args.rpc_endpoint.clone(),
        faucet_id_bech32: faucet_bech32,
        faucet_id_hex: faucet_id.to_hex(),
        merchant_id_bech32,
        merchant_id_hex,
        agent_count: agents.len(),
        agents: report_agents,
        mint_amount: args.mint_amount,
        adn_note_id,
        adn_serial_num_hex: adn_serial_hex,
        adn_balance,
        adn_expiry_block: adn_expiry,
        adn_note_data_hex,
        facilitator_account_id_hex: Some(facilitator_account_id_hex),
        facilitator_account_snapshot_path: Some(
            relative(&args.out_dir, &fac_snap_path),
        ),
    };
    let toml_path = args.out_dir.join("setup.toml");
    std::fs::write(&toml_path, toml::to_string_pretty(&report)?)?;
    std::fs::write(args.out_dir.join("faucet_id.txt"), &report.faucet_id_bech32)?;

    tracing::info!(report_path = %toml_path.display(), "setup complete");
    Ok(())
}

async fn build_client(
    args: &Args,
) -> anyhow::Result<(Client<FilesystemKeyStore>, Arc<FilesystemKeyStore>)> {
    let endpoint = Endpoint::try_from(args.rpc_endpoint.as_str())
        .map_err(|e| anyhow::anyhow!("endpoint: {e:?}"))?;
    let rpc = Arc::new(GrpcClient::new(&endpoint, 20_000));
    let keystore = Arc::new(
        FilesystemKeyStore::new(args.out_dir.join("keystore"))
            .map_err(|e| anyhow::anyhow!("keystore: {e:?}"))?,
    );
    let store = args.out_dir.join("store.sqlite3");
    let client = ClientBuilder::new()
        .rpc(rpc)
        .sqlite_store(store)
        .authenticator(keystore.clone())
        .in_debug_mode(false.into())
        .build()
        .await
        .context("client build")?;
    Ok((client, keystore))
}

async fn execute_for_summary(
    client: &mut Client<FilesystemKeyStore>,
    account_id: miden_protocol::account::AccountId,
    request: miden_client::transaction::TransactionRequest,
) -> anyhow::Result<TransactionSummary> {
    match client.execute_transaction(account_id, request).await {
        Ok(_) => anyhow::bail!("expected Unauthorized error carrying summary"),
        Err(ClientError::TransactionExecutorError(TransactionExecutorError::Unauthorized(
            summary,
        ))) => Ok(*summary),
        Err(other) => Err(anyhow::anyhow!("execute: {other} | debug: {other:?}")),
    }
}

fn rand_seed_32<KS>(client: &mut Client<KS>) -> [u8; 32]
where
    KS: Keystore + 'static,
{
    let mut seed = [0u8; 32];
    client.rng().fill_bytes(&mut seed);
    seed
}

fn relative(base: &Path, p: &Path) -> String {
    p.strip_prefix(base)
        .map(|q| q.to_string_lossy().into_owned())
        .unwrap_or_else(|_| p.to_string_lossy().into_owned())
}
