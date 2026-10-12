//! Header-context rules: lock time, and the version and signature script length rules that
//! change at the Toccata fork.

use kaspa_consensus_core::{
    constants::LOCK_TIME_THRESHOLD,
    errors::tx::TxRuleError,
    hashing::sighash_type::SIG_HASH_ALL,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{Transaction, TransactionInput},
};
use node_gate::{
    GateParams, Stage,
    header::{self, LockTimeArg, LockTimeType},
    wallet::TestKey,
};

use crate::common::*;

fn in_header_context(gate: &GateParams, tx: &Transaction) -> Result<(), TxRuleError> {
    header::validate_tx_in_header_context_with_args(&gate.params, tx, gate.block_daa_score, gate.past_median_time)
}

fn with_lock_time(lock_time: u64, sequences: &[u64]) -> Transaction {
    let inputs = sequences
        .iter()
        .enumerate()
        .map(|(i, sequence)| TransactionInput::new_with_compute_budget(outpoint(1, i as u32), vec![], *sequence, 0))
        .collect();
    Transaction::new(1, inputs, vec![pay(2, KAS)], lock_time, SUBNETWORK_ID_NATIVE, 0, vec![])
}

#[test]
fn lock_time_kinds() {
    assert_eq!(header::get_lock_time_type(&with_lock_time(0, &[0])), LockTimeType::Finalized);
    assert_eq!(header::get_lock_time_type(&with_lock_time(1, &[0])), LockTimeType::DaaScore);
    assert_eq!(header::get_lock_time_type(&with_lock_time(LOCK_TIME_THRESHOLD - 1, &[0])), LockTimeType::DaaScore);
    assert_eq!(header::get_lock_time_type(&with_lock_time(LOCK_TIME_THRESHOLD, &[0])), LockTimeType::Time);
}

#[test]
fn lock_time_by_daa_score() {
    let gate = node();
    let now = gate.block_daa_score;
    // Reached: the lock time is below the block's DAA score.
    assert_eq!(in_header_context(&gate, &with_lock_time(now - 1, &[0])), Ok(()));
    // Not reached, and an input that is not final.
    assert_eq!(in_header_context(&gate, &with_lock_time(now, &[0])), Err(TxRuleError::NotFinalized(0)));
    assert_eq!(in_header_context(&gate, &with_lock_time(now, &[u64::MAX, u64::MAX - 1])), Err(TxRuleError::NotFinalized(1)));
    // Not reached, but every sequence is maximal.
    assert_eq!(in_header_context(&gate, &with_lock_time(now, &[u64::MAX, u64::MAX])), Ok(()));
}

#[test]
fn lock_time_by_median_time() {
    let gate = node();
    let median_time = gate.past_median_time;
    assert!(median_time > LOCK_TIME_THRESHOLD);
    assert_eq!(in_header_context(&gate, &with_lock_time(median_time - 1, &[0])), Ok(()));
    assert_eq!(in_header_context(&gate, &with_lock_time(median_time, &[0])), Err(TxRuleError::NotFinalized(0)));
    // The time value is not compared with the DAA score: a later median time releases it.
    let later = gate.clone().with_past_median_time(median_time + 1);
    assert_eq!(in_header_context(&later, &with_lock_time(median_time, &[0])), Ok(()));
}

#[test]
fn the_lock_time_argument_decides_not_the_field_alone() {
    let tx = with_lock_time(500, &[0]);
    assert_eq!(header::check_tx_is_finalized(&tx, LockTimeArg::Finalized), Ok(()));
    assert_eq!(header::check_tx_is_finalized(&tx, LockTimeArg::DaaScore(501)), Ok(()));
    assert_eq!(header::check_tx_is_finalized(&tx, LockTimeArg::DaaScore(500)), Err(TxRuleError::NotFinalized(0)));
    assert_eq!(header::check_tx_is_finalized(&tx, LockTimeArg::MedianTime(500)), Err(TxRuleError::NotFinalized(0)));
}

#[test]
fn version_by_fork_side() {
    let before = node_before_toccata();
    let after = node();
    assert!(!before.toccata_active());

    let v0 = plain_spend_v0(&after).tx;
    let v1 = plain_spend(&after).tx;
    assert_eq!(in_header_context(&before, &v0), Ok(()));
    assert_eq!(in_header_context(&before, &v1), Err(TxRuleError::UnknownTxVersion(1)));
    assert_eq!(in_header_context(&after, &v0), Ok(()));
    assert_eq!(in_header_context(&after, &v1), Ok(()));

    // The activation score itself is already the new side.
    let at_activation = before.clone().with_daa_score(before.block_daa_score + 1);
    assert_eq!(in_header_context(&at_activation, &v1), Ok(()));

    // Version 2 is refused on both sides (the in-isolation rule refuses it earlier).
    let v2 = Transaction::new(2, vec![input_v1(1, 0)], vec![pay(2, KAS)], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    assert_eq!(header::check_transaction_version(&after.params, &v2, after.block_daa_score), Err(TxRuleError::UnknownTxVersion(2)));
    assert_eq!(header::check_transaction_version(&before.params, &v2, before.block_daa_score), Err(TxRuleError::UnknownTxVersion(2)));
}

#[test]
fn signature_script_length_by_fork_side() {
    let before = node_before_toccata();
    let after = node();
    let with_script = |len: usize| {
        let mut input = input_v0(1, 1);
        input.signature_script = vec![0; len];
        tx_v0(vec![input], vec![pay(2, KAS)])
    };

    assert_eq!(in_header_context(&before, &with_script(10_000)), Ok(()));
    assert_eq!(in_header_context(&before, &with_script(10_001)), Err(TxRuleError::TooBigSignatureScript(0, 10_000)));
    assert_eq!(in_header_context(&after, &with_script(10_001)), Ok(()));
    assert_eq!(in_header_context(&after, &with_script(250_000)), Ok(()));
    assert_eq!(in_header_context(&after, &with_script(250_001)), Err(TxRuleError::TooBigSignatureScript(0, 250_000)));
}

#[test]
fn lock_time_is_checked_before_version_and_length() {
    let before = node_before_toccata();
    let mut tx = with_lock_time(before.block_daa_score, &[0]);
    tx.inputs[0].signature_script = vec![0; 10_001];
    // Not final, version 1 before the fork, and a long signature script.
    assert_eq!(in_header_context(&before, &tx), Err(TxRuleError::NotFinalized(0)));
    tx.lock_time = 0;
    assert_eq!(in_header_context(&before, &tx), Err(TxRuleError::UnknownTxVersion(1)));
}

#[test]
fn the_gate_compares_a_time_lock_with_its_past_median_time() {
    let gate = node();
    let owner = TestKey::from_seed(OWNER);
    let with_lock_time = |lock_time: u64| {
        let mut spend = plain_spend(&gate);
        spend.tx.lock_time = lock_time;
        spend.tx.finalize();
        spend.sign_p2pk(0, &owner, SIG_HASH_ALL);
        spend.commit_storage_mass(&gate);
        spend
    };
    let reached = with_lock_time(gate.past_median_time - 1);
    assert!(submit(&gate, &reached).verdict.accepted);
    assert!(in_block(&gate, &reached).verdict.accepted);
    let waiting = with_lock_time(gate.past_median_time);
    assert_eq!(submit(&gate, &waiting).consensus_error, Some(TxRuleError::NotFinalized(0)));
    assert_eq!(in_block(&gate, &waiting).consensus_error, Some(TxRuleError::NotFinalized(0)));
}

#[test]
fn in_a_block_the_blocks_own_daa_score_decides_the_fork_side() {
    // A block from just before the fork, judged from a point of view after it.
    let activation = node().params.toccata_activation.daa_score();
    let mut gate = GateParams::testnet10().with_daa_score(activation + 100_000);
    gate.block_daa_score = activation - 1;
    assert!(!gate.toccata_active());
    assert!(!gate.engine_flags().covenants_enabled);

    let v1 = plain_spend(&gate);
    v1.commit_storage_mass(&gate);
    assert_eq!(in_block(&gate, &v1).consensus_error, Some(TxRuleError::UnknownTxVersion(1)));

    let v0 = plain_spend_v0(&gate);
    v0.commit_storage_mass(&gate);
    let evaluation = in_block(&gate, &v0);
    assert!(evaluation.verdict.accepted);
    assert!(!evaluation.verdict.toccata_active);
    // The old engine: signature operations counted, script units not metered.
    let run = &evaluation.committed_runs[0];
    assert_eq!((run.used_script_units, run.used_sig_ops), (0, 1));
}

#[test]
fn the_gate_names_the_stage_and_the_rule() {
    let gate = node();
    let mut locked = plain_spend(&gate);
    locked.tx.lock_time = gate.block_daa_score;
    let evaluation = submit(&gate, &locked);
    let refusal = evaluation.verdict.consensus_refusal.expect("not final");
    assert_eq!((refusal.stage, refusal.rule.as_str()), (Stage::HeaderContext, "check_tx_is_finalized"));
    assert_eq!(evaluation.consensus_error, Some(TxRuleError::NotFinalized(0)));

    // Before the fork a version 1 transaction stops here, in both modes.
    let before = node_before_toccata();
    let spend = plain_spend(&before);
    for evaluation in [submit(&before, &spend), in_block(&before, &spend)] {
        let refusal = evaluation.verdict.consensus_refusal.expect("unknown version");
        assert_eq!((refusal.stage, refusal.rule.as_str()), (Stage::HeaderContext, "check_transaction_version"));
        assert_eq!(evaluation.consensus_error, Some(TxRuleError::UnknownTxVersion(1)));
    }

    let mut long = plain_spend_v0(&before);
    long.tx.inputs[0].signature_script = vec![0; 10_001];
    let evaluation = in_block(&before, &long);
    let refusal = evaluation.verdict.consensus_refusal.expect("signature script too long");
    assert_eq!(
        (refusal.stage, refusal.rule.as_str()),
        (Stage::HeaderContext, "check_transaction_signature_scripts_in_header_context")
    );
}
