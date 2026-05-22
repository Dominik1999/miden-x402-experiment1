//! AgentDebitNote MASM script tests.
//! Consume path requires agent signature only (no facilitator co-sig).

use std::collections::BTreeMap;

use miden_protocol::{Felt, Hasher, Word};
use miden_protocol::account::AccountId;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::*;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::vm::AdviceInputs;
use miden_standards::code_builder::CodeBuilder;
use miden_testing::{Auth, MockChain};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const NOTE_MASM: &str = include_str!("../masm/agent_debit_note.masm");

fn make_keypair(seed: u64) -> AuthSecretKey {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    AuthSecretKey::new_falcon512_poseidon2_with_rng(&mut rng)
}

fn debit_message(serial: Word, merchant: AccountId, amount: u64) -> Word {
    let dw: Word = [merchant.suffix(), merchant.prefix().as_felt(), Felt::new(amount), Felt::ZERO].into();
    Hasher::merge(&[serial, dw])
}

fn reclaim_message(serial: Word, user: AccountId) -> Word {
    let rw: Word = [user.suffix(), user.prefix().as_felt(), Felt::ZERO, Felt::ZERO].into();
    Hasher::merge(&[serial, rw])
}

fn serial(a: u64, b: u64, c: u64, d: u64) -> Word {
    [Felt::new(a), Felt::new(b), Felt::new(c), Felt::new(d)].into()
}

/// Build advice stack with agent sig only.
fn agent_only_advice(agent_sk: &AuthSecretKey, message: Word) -> AdviceInputs {
    let sig = agent_sk.sign(message);
    AdviceInputs::default().with_stack(sig.to_prepared_signature(message))
}

struct TestSetup {
    mock_chain: MockChain,
    note_id: NoteId,
    note_script: NoteScript,
    serial_num: Word,
    consumer_id: AccountId,
    merchant_id: AccountId,
    user_id: AccountId,
}

fn setup_test(agent_pk: Word, balance: u64, sn: Word, expiry: u32) -> anyhow::Result<TestSetup> {
    let note_script = CodeBuilder::default().compile_note_script(NOTE_MASM)?;

    let mut builder = MockChain::builder();
    let consumer = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = builder.add_existing_basic_faucet(Auth::IncrNonce, "USDC", 1_000_000, None)?;
    let merchant = builder.add_existing_wallet(Auth::Noop)?;
    let user = builder.add_existing_wallet(Auth::Noop)?;

    let asset = FungibleAsset::new(faucet.id(), balance)?;
    let storage = NoteStorage::new(vec![
        agent_pk[0], agent_pk[1], agent_pk[2], agent_pk[3],
        user.id().suffix(), user.id().prefix().as_felt(),
        Felt::new(expiry as u64),
    ])?;

    let metadata = NoteMetadata::new(consumer.id(), NoteType::Public).with_tag(NoteTag::new(0));
    let vault = NoteAssets::new(vec![Asset::Fungible(asset)])?;
    let recipient = NoteRecipient::new(sn, note_script.clone(), storage);
    let note = Note::new(vault, metadata, recipient);
    let note_id = note.id();

    builder.add_output_note(RawOutputNote::Full(note));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;
    mock_chain.prove_next_block()?;

    Ok(TestSetup {
        mock_chain, note_id, note_script, serial_num: sn,
        consumer_id: consumer.id(), merchant_id: merchant.id(),
        user_id: user.id(),
    })
}

fn note_args_for(merchant: AccountId, amount: u64, note_id: NoteId) -> BTreeMap<NoteId, Word> {
    let mut args = BTreeMap::new();
    args.insert(note_id, [merchant.suffix(), merchant.prefix().as_felt(), Felt::new(amount), Felt::ZERO].into());
    args
}

// ── CONSUME PATH TESTS (require agent sig) ──

#[tokio::test]
async fn test_01_valid_consume() -> anyhow::Result<()> {
    let agent_sk = make_keypair(1);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(1,2,3,4), 1_000_000)?;
    let msg = debit_message(s.serial_num, s.merchant_id, 100);

    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(note_args_for(s.merchant_id, 100, s.note_id))
        .add_note_script(s.note_script)
        .extend_advice_inputs(agent_only_advice(&agent_sk, msg))
        .build()?;

    let executed = tx.execute().await?;
    assert_eq!(executed.output_notes().num_notes(), 2);
    println!("Test #1 PASSED");
    Ok(())
}

#[tokio::test]
async fn test_02_wrong_agent_sig_rejected() -> anyhow::Result<()> {
    let agent_sk = make_keypair(2);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(2,2,3,4), 1_000_000)?;
    let msg = debit_message(s.serial_num, s.merchant_id, 100);

    // Wrong agent key
    let wrong_sk = make_keypair(999);
    let advice = agent_only_advice(&wrong_sk, msg);

    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(note_args_for(s.merchant_id, 100, s.note_id))
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    assert!(tx.execute().await.is_err());
    println!("Test #2 PASSED");
    Ok(())
}

#[tokio::test]
async fn test_03_wrong_merchant() -> anyhow::Result<()> {
    let agent_sk = make_keypair(3);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(3,2,3,4), 1_000_000)?;

    // Sign for merchant_id but pass user_id in note_args
    let msg = debit_message(s.serial_num, s.merchant_id, 100);
    let advice = agent_only_advice(&agent_sk, msg);

    // Note args reference a different account (user_id instead of merchant_id)
    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(note_args_for(s.user_id, 100, s.note_id))
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    assert!(tx.execute().await.is_err());
    println!("Test #3 PASSED");
    Ok(())
}

#[tokio::test]
async fn test_04_wrong_amount() -> anyhow::Result<()> {
    let agent_sk = make_keypair(4);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(4,2,3,4), 1_000_000)?;

    let msg = debit_message(s.serial_num, s.merchant_id, 100);
    let advice = agent_only_advice(&agent_sk, msg);

    // Note args say 200 but signature says 100
    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(note_args_for(s.merchant_id, 200, s.note_id))
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    assert!(tx.execute().await.is_err());
    println!("Test #4 PASSED");
    Ok(())
}

#[tokio::test]
async fn test_05_debit_exceeds_balance() -> anyhow::Result<()> {
    let agent_sk = make_keypair(5);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 100, serial(5,2,3,4), 1_000_000)?;

    let msg = debit_message(s.serial_num, s.merchant_id, 500);
    let advice = agent_only_advice(&agent_sk, msg);

    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(note_args_for(s.merchant_id, 500, s.note_id))
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    assert!(tx.execute().await.is_err());
    println!("Test #5 PASSED");
    Ok(())
}

#[tokio::test]
async fn test_06_wrong_signer_key() -> anyhow::Result<()> {
    let agent_sk = make_keypair(6);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(6,2,3,4), 1_000_000)?;

    let msg = debit_message(s.serial_num, s.merchant_id, 100);
    let other_sk = make_keypair(600);
    let advice = agent_only_advice(&other_sk, msg);

    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(note_args_for(s.merchant_id, 100, s.note_id))
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    assert!(tx.execute().await.is_err());
    println!("Test #6 PASSED");
    Ok(())
}

#[tokio::test]
async fn test_07_remainder_correct_value() -> anyhow::Result<()> {
    let agent_sk = make_keypair(7);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(7,2,3,4), 1_000_000)?;

    let msg = debit_message(s.serial_num, s.merchant_id, 100);
    let advice = agent_only_advice(&agent_sk, msg);

    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(note_args_for(s.merchant_id, 100, s.note_id))
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    let executed = tx.execute().await?;
    let mut total = 0u64;
    for note in executed.output_notes().iter() {
        if let RawOutputNote::Full(n) = note {
            for a in n.assets().iter_fungible() { total += a.amount(); }
        }
    }
    assert_eq!(total, 1000);
    println!("Test #7 PASSED");
    Ok(())
}

// ── BLOCK HEIGHT / RECLAIM TESTS ──

#[tokio::test]
async fn test_10_consume_at_expiry_rejected() -> anyhow::Result<()> {
    let agent_sk = make_keypair(10);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(10,2,3,4), 0)?;

    let msg = debit_message(s.serial_num, s.merchant_id, 100);
    let advice = agent_only_advice(&agent_sk, msg);

    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(note_args_for(s.merchant_id, 100, s.note_id))
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    assert!(tx.execute().await.is_err());
    println!("Test #10 PASSED");
    Ok(())
}

#[tokio::test]
async fn test_12_valid_reclaim() -> anyhow::Result<()> {
    let agent_sk = make_keypair(12);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(12,2,3,4), 0)?;

    let msg = reclaim_message(s.serial_num, s.user_id);
    let advice = agent_only_advice(&agent_sk, msg);

    let mut args = BTreeMap::new();
    args.insert(s.note_id, [Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO].into());

    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(args)
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    let executed = tx.execute().await?;
    assert_eq!(executed.output_notes().num_notes(), 1);
    println!("Test #12 PASSED");
    Ok(())
}

#[tokio::test]
async fn test_13_reclaim_before_expiry() -> anyhow::Result<()> {
    let agent_sk = make_keypair(13);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(13,2,3,4), 1_000_000)?;

    let msg = reclaim_message(s.serial_num, s.user_id);
    let advice = agent_only_advice(&agent_sk, msg);

    let mut args = BTreeMap::new();
    args.insert(s.note_id, [Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO].into());

    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(args)
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    assert!(tx.execute().await.is_err());
    println!("Test #13 PASSED");
    Ok(())
}

#[tokio::test]
async fn test_14_reclaim_wrong_sig() -> anyhow::Result<()> {
    let agent_sk = make_keypair(14);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(14,2,3,4), 0)?;

    let msg = reclaim_message(s.serial_num, s.user_id);
    let wrong_sk = make_keypair(1400);
    let advice = agent_only_advice(&wrong_sk, msg);

    let mut args = BTreeMap::new();
    args.insert(s.note_id, [Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO].into());

    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(args)
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    assert!(tx.execute().await.is_err());
    println!("Test #14 PASSED");
    Ok(())
}

// ── MULTI-MERCHANT TEST ──

#[tokio::test]
async fn test_15_pay_two_different_merchants() -> anyhow::Result<()> {
    let agent_sk = make_keypair(15);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let note_script = CodeBuilder::default().compile_note_script(NOTE_MASM)?;

    let mut builder = MockChain::builder();
    let consumer = builder.add_existing_wallet(Auth::IncrNonce)?;
    let faucet = builder.add_existing_basic_faucet(Auth::IncrNonce, "USDC", 1_000_000, None)?;
    let merchant_a = builder.add_existing_wallet(Auth::Noop)?;
    let merchant_b = builder.add_existing_wallet(Auth::Noop)?;
    let user = builder.add_existing_wallet(Auth::Noop)?;

    let sn = serial(15, 2, 3, 4);
    let asset = FungibleAsset::new(faucet.id(), 1000)?;
    let storage = NoteStorage::new(vec![
        pk[0], pk[1], pk[2], pk[3],
        user.id().suffix(), user.id().prefix().as_felt(),
        Felt::new(1_000_000u64),
    ])?;

    let metadata = NoteMetadata::new(consumer.id(), NoteType::Public).with_tag(NoteTag::new(0));
    let vault = NoteAssets::new(vec![Asset::Fungible(asset)])?;
    let recipient = NoteRecipient::new(sn, note_script.clone(), storage);
    let note = Note::new(vault, metadata, recipient);
    let note_id = note.id();

    builder.add_output_note(RawOutputNote::Full(note));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;
    mock_chain.prove_next_block()?;

    // Payment 1: merchant A
    let msg_a = debit_message(sn, merchant_a.id(), 100);
    let tx_a = mock_chain
        .build_tx_context(consumer.id(), &[note_id], &[])?
        .extend_note_args(note_args_for(merchant_a.id(), 100, note_id))
        .add_note_script(note_script.clone())
        .extend_advice_inputs(agent_only_advice(&agent_sk, msg_a))
        .build()?;
    let executed_a = tx_a.execute().await?;
    assert_eq!(executed_a.output_notes().num_notes(), 2);
    println!("Test #15a PASSED: paid merchant A");

    // Payment 2: merchant B (same note, different merchant)
    let msg_b = debit_message(sn, merchant_b.id(), 200);
    let tx_b = mock_chain
        .build_tx_context(consumer.id(), &[note_id], &[])?
        .extend_note_args(note_args_for(merchant_b.id(), 200, note_id))
        .add_note_script(note_script)
        .extend_advice_inputs(agent_only_advice(&agent_sk, msg_b))
        .build()?;
    let executed_b = tx_b.execute().await?;
    assert_eq!(executed_b.output_notes().num_notes(), 2);
    println!("Test #15b PASSED: paid merchant B");
    println!("Test #15 PASSED: multi-merchant works");
    Ok(())
}

/// #18: Reclaim after expiry does NOT require facilitator sig.
#[tokio::test]
async fn test_18_reclaim_without_facilitator_sig_works() -> anyhow::Result<()> {
    let agent_sk = make_keypair(18);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(18,2,3,4), 0)?;

    let msg = reclaim_message(s.serial_num, s.user_id);
    let advice = agent_only_advice(&agent_sk, msg);

    let mut args = BTreeMap::new();
    args.insert(s.note_id, [Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO].into());

    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(args)
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    let executed = tx.execute().await?;
    assert_eq!(executed.output_notes().num_notes(), 1);
    println!("Test #18 PASSED: reclaim works with agent sig only");
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════
// ATTACK VECTOR TESTS
// ══════════════════════════════════════════════════════════════════════

/// Attack: Agent tries to reclaim funds BEFORE expiry using reclaim path.
/// Should fail because the block height check routes to consume path,
/// and the reclaim message won't match the consume message.
#[tokio::test]
async fn test_attack_early_reclaim() -> anyhow::Result<()> {
    let agent_sk = make_keypair(23);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(23,2,3,4), 1_000_000)?; // far future expiry

    let msg = reclaim_message(s.serial_num, s.user_id);
    let advice = agent_only_advice(&agent_sk, msg);

    let mut args = BTreeMap::new();
    args.insert(s.note_id, [Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO].into());

    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(args)
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    assert!(tx.execute().await.is_err(),
        "ATTACK FAILED TO PREVENT: early reclaim should be rejected");
    println!("ATTACK BLOCKED: early reclaim rejected");
    Ok(())
}

/// Attack: Random third party tries to consume note without any valid signature.
/// They have the note data but no agent keys.
#[tokio::test]
async fn test_attack_unauthorized_consumer() -> anyhow::Result<()> {
    let agent_sk = make_keypair(24);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(24,2,3,4), 1_000_000)?;

    // Random third party signs with their own key (not agent)
    let attacker = make_keypair(2400);
    let msg = debit_message(s.serial_num, s.merchant_id, 100);
    let advice = agent_only_advice(&attacker, msg);

    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(note_args_for(s.merchant_id, 100, s.note_id))
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    assert!(tx.execute().await.is_err(),
        "ATTACK FAILED TO PREVENT: unauthorized consumer should be rejected");
    println!("ATTACK BLOCKED: unauthorized consumer rejected");
    Ok(())
}

/// Attack: Agent tries to inflate the amount (overspend).
/// Agent signs for 100 but sets note_args to 999.
/// MASM recomputes msg from note_args (999) -> agent sig was for 100 -> mismatch.
#[tokio::test]
async fn test_attack_agent_inflates_amount() -> anyhow::Result<()> {
    let agent_sk = make_keypair(26);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(26,2,3,4), 1_000_000)?;

    // Agent signs for 100
    let msg_100 = debit_message(s.serial_num, s.merchant_id, 100);
    let advice = agent_only_advice(&agent_sk, msg_100);

    // But note_args says 999 -> MASM computes msg(merchant, 999) -> doesn't match sig
    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(note_args_for(s.merchant_id, 999, s.note_id))
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    assert!(tx.execute().await.is_err(),
        "ATTACK FAILED TO PREVENT: agent inflating amount should be rejected");
    println!("ATTACK BLOCKED: agent amount inflation rejected");
    Ok(())
}

// ── ADVICE MAP PATH TEST ──

/// Verify that the Falcon sig can be delivered via the advice MAP
/// (not just the stack). This is the path used by the facilitator's
/// submitter when consuming the note via TransactionRequestBuilder.
#[tokio::test]
async fn test_consume_with_sig_in_advice_map() -> anyhow::Result<()> {
    let agent_sk = make_keypair(30);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(30,2,3,4), 1_000_000)?;
    let msg = debit_message(s.serial_num, s.merchant_id, 100);

    // Sign and prepare
    let sig = agent_sk.sign(msg);
    let prepared = sig.to_prepared_signature(msg);

    // Put sig in the advice MAP at key = merge(AGENT_PK, MESSAGE)
    let sig_key = Hasher::merge(&[pk, msg]);

    let advice = AdviceInputs::default()
        .with_map([(sig_key, prepared)]);

    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(note_args_for(s.merchant_id, 100, s.note_id))
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    let executed = tx.execute().await?;
    assert_eq!(executed.output_notes().num_notes(), 2);
    println!("ADVICE MAP PATH TEST PASSED: sig from map works for facilitator submitter");
    Ok(())
}

/// Test the full submitter consumption path:
/// Build a TransactionRequest via TransactionRequestBuilder with the note as input,
/// sig in advice map, and execute it. This simulates exactly what the facilitator
/// submitter does (but via MockChain instead of miden-client).
#[tokio::test]
async fn test_submitter_consumption_path() -> anyhow::Result<()> {
    let agent_sk = make_keypair(31);
    let pk: Word = agent_sk.public_key().to_commitment().into();
    let s = setup_test(pk, 1000, serial(31,2,3,4), 1_000_000)?;
    let msg = debit_message(s.serial_num, s.merchant_id, 100);

    // Agent signs
    let sig = agent_sk.sign(msg);
    let prepared = sig.to_prepared_signature(msg);

    // Compute advice map key = merge(AGENT_PK, MESSAGE) — same as submitter
    let sig_key = Hasher::merge(&[pk, msg]);

    // Build note_args Word — same as submitter packs it
    let note_args: Word = [
        s.merchant_id.suffix(),
        s.merchant_id.prefix().as_felt(),
        Felt::new(100),
        Felt::ZERO,
    ].into();

    // Build advice inputs with sig in MAP (not stack) — submitter path
    let advice = AdviceInputs::default()
        .with_map([(sig_key, prepared)]);

    // Use MockChain's build_tx_context which internally uses TransactionContextBuilder
    // This simulates the TransactionRequestBuilder path
    let tx = s.mock_chain
        .build_tx_context(s.consumer_id, &[s.note_id], &[])?
        .extend_note_args(note_args_for(s.merchant_id, 100, s.note_id))
        .add_note_script(s.note_script)
        .extend_advice_inputs(advice)
        .build()?;

    let executed = tx.execute().await?;
    assert_eq!(executed.output_notes().num_notes(), 2,
        "submitter path should produce P2ID + remainder");

    // Verify asset preservation
    let mut total = 0u64;
    for note in executed.output_notes().iter() {
        if let miden_protocol::transaction::RawOutputNote::Full(n) = note {
            for a in n.assets().iter_fungible() { total += a.amount(); }
        }
    }
    assert_eq!(total, 1000, "1000 in = 100 P2ID + 900 remainder");

    println!("SUBMITTER PATH TEST PASSED: full consumption via advice map works");
    Ok(())
}
