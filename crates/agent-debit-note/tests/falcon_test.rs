//! Minimal test: can a note script verify a Falcon signature?
//! Uses a fixed key in the advice map (no merge computation needed).

use std::collections::BTreeMap;
use miden_protocol::{Felt, Word};
use miden_protocol::vm::AdviceInputs;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::*;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};

/// Note script that:
/// 1. Takes NOTE_ARGS = MESSAGE (the word that was signed)
/// 2. Reads PUB_KEY from note storage (4 items)
/// 3. Uses MESSAGE as key to adv.push_mapval to get the signature
/// 4. Calls falcon512_poseidon2::verify
/// 5. Adds assets to vault (to pass epilogue)
const FALCON_TEST_MASM: &str = r#"
use miden::protocol::active_note
use miden::core::crypto::dsa::falcon512_poseidon2
use miden::core::sys
use miden::standards::wallets::basic->wallet

const STORAGE_PTR=100

@note_script
pub proc main
    # NOTE_ARGS = MESSAGE (the signed word)
    # => [MESSAGE]

    # Load storage (4 items = agent pubkey commitment)
    push.STORAGE_PTR exec.active_note::get_storage
    # => [num_items, dest_ptr, MESSAGE]
    # num_items is on top, dest_ptr is next
    # Actually checking the API: outputs [num_storage_items, dest_ptr]
    # So top = num_storage_items. We want to check it = 4 then drop dest_ptr
    eq.4 assert.err="expected 4 storage items"
    # => [dest_ptr, MESSAGE]
    drop
    # => [MESSAGE]

    # Load PUB_KEY from storage as a word
    padw push.STORAGE_PTR mem_loadw_le
    # => [PUB_KEY, MESSAGE]

    # falcon512_poseidon2::verify expects:
    #   OS: [PUB_KEY, MESSAGE]
    #   AS: signature data (pre-populated via advice_inputs.stack)
    exec.falcon512_poseidon2::verify
    # => []

    exec.wallet::add_assets_to_account
    exec.sys::truncate_stack
end
"#;

#[tokio::test]
async fn test_falcon_verify_in_note_script() -> anyhow::Result<()> {
    // Create agent keypair
    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(12345);
    let agent_sk = AuthSecretKey::new_falcon512_poseidon2_with_rng(&mut rng);
    let agent_pk = agent_sk.public_key();
    let pk_commitment: Word = agent_pk.to_commitment().into();

    // A known message
    let message: Word = [Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)].into();

    // Sign it
    let signature = agent_sk.sign(message);
    let prepared_sig = signature.to_prepared_signature(message);
    println!("prepared_sig len = {}", prepared_sig.len());

    // Pre-populate the advice STACK with the prepared signature.
    // falcon512_poseidon2::verify reads directly from the advice stack.
    let advice_inputs = AdviceInputs::default()
        .with_stack(prepared_sig);

    // Compile the note script
    let note_script = CodeBuilder::default().compile_note_script(FALCON_TEST_MASM)?;

    // Build the note with pk_commitment as storage
    let mut builder = MockChain::builder();
    let consumer = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = builder.add_existing_basic_faucet(Auth::IncrNonce, "TEST", 1_000_000, None)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?;
    let serial_num: Word = [Felt::new(99), Felt::new(99), Felt::new(99), Felt::new(99)].into();

    // Storage = just the 4 pk commitment felts
    let storage = NoteStorage::new(vec![
        pk_commitment[0],
        pk_commitment[1],
        pk_commitment[2],
        pk_commitment[3],
    ])?;

    let metadata = NoteMetadata::new(consumer.id(), NoteType::Public).with_tag(NoteTag::new(0));
    let vault = NoteAssets::new(vec![Asset::Fungible(asset)])?;
    let recipient = NoteRecipient::new(serial_num, note_script.clone(), storage);
    let note = Note::new(vault, metadata, recipient);
    let note_id = note.id();

    builder.add_output_note(RawOutputNote::Full(note));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Pass MESSAGE as note_args
    let mut note_args = BTreeMap::new();
    note_args.insert(note_id, message);

    let tx_context = mock_chain
        .build_tx_context(consumer.id(), &[note_id], &[])?
        .extend_note_args(note_args)
        .add_note_script(note_script)
        .extend_advice_inputs(advice_inputs)
        .build()?;

    let _executed_tx = tx_context.execute().await?;
    println!("FALCON VERIFICATION IN NOTE SCRIPT SUCCEEDED!");

    Ok(())
}
