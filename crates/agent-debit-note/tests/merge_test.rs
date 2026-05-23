//! Test: does MASM poseidon2::merge match Rust Hasher::merge?
//! Strategy: Put the Rust-computed merge result in the advice map.
//! MASM computes merge, then uses the result as a key to adv.push_mapval.
//! If the key matches, adv.push_mapval succeeds. If not, it panics.

use std::collections::BTreeMap;
use miden_protocol::{Felt, Hasher, Word};
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::*;
use miden_protocol::transaction::RawOutputNote;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};

const MERGE_VERIFY_MASM: &str = r#"
use miden::core::crypto::hashes::poseidon2
use miden::core::sys
use miden::standards::wallets::basic->wallet

@note_script
pub proc main
    # NOTE_ARGS = [a0, a1, a2, a3] = Word A

    # Push Word B = [5, 6, 7, 8] below A
    push.8 push.7 push.6 push.5
    # => [5, 6, 7, 8, a0, a1, a2, a3]

    swapw
    # => [a0, a1, a2, a3, 5, 6, 7, 8]
    # merge(top=A, second=B)

    exec.poseidon2::merge
    # => [RESULT]

    # Use RESULT as a key to adv.push_mapval.
    # If the Rust-side put a value at this key, it succeeds.
    # If the key doesn't match, it panics.
    adv.push_mapval
    # => [RESULT]
    # AS => [some_value]

    # Success! Clean up.
    adv_push.1 drop  # consume the advice stack value
    dropw            # drop RESULT

    # Add assets to vault (prevent epilogue asset error)
    exec.wallet::add_assets_to_account

    exec.sys::truncate_stack
end
"#;

#[tokio::test]
async fn test_merge_key_matches() -> anyhow::Result<()> {
    let word_a: Word = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();
    let word_b: Word = [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)].into();

    // Rust-side merge
    let rust_merge: Word = Hasher::merge(&[word_a.into(), word_b.into()]).into();
    println!("Rust merge(A, B) = {:?}", rust_merge);

    // Put a dummy value at this key in the advice map
    let dummy_value = vec![Felt::new(42)];

    let note_script = CodeBuilder::default().compile_note_script(MERGE_VERIFY_MASM)?;

    let mut builder = MockChain::builder();
    let consumer = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = builder.add_existing_basic_faucet(Auth::IncrNonce, "TEST", 1_000_000, None)?;

    let asset = FungibleAsset::new(faucet.id(), 100)?;
    let serial_num: Word = [Felt::new(99), Felt::new(99), Felt::new(99), Felt::new(99)].into();
    let storage = NoteStorage::new(vec![])?;
    let metadata = NoteMetadata::new(consumer.id(), NoteType::Public).with_tag(NoteTag::new(0));
    let vault = NoteAssets::new(vec![Asset::Fungible(asset)])?;
    let recipient = NoteRecipient::new(serial_num, note_script.clone(), storage);
    let note = Note::new(vault, metadata, recipient);
    let note_id = note.id();

    builder.add_output_note(RawOutputNote::Full(note));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let mut note_args = BTreeMap::new();
    note_args.insert(note_id, word_a);

    let tx_context = mock_chain
        .build_tx_context(consumer.id(), &[note_id], &[])?
        .extend_note_args(note_args)
        .add_note_script(note_script)
        .extend_advice_map([(rust_merge, dummy_value)])
        .build()?;

    let _executed_tx = tx_context.execute().await?;
    println!("SUCCESS: MASM merge output matches Rust merge output!");

    Ok(())
}
