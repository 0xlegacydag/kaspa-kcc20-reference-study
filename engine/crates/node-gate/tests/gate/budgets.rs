//! Compute budgets: what an input needs, the smallest budget that covers it, and the
//! failure one unit below.

use kaspa_consensus_core::{
    errors::tx::TxRuleError,
    hashing::sighash_type::SIG_HASH_ALL,
    mass::{ComputeBudget, ScriptUnits, SigopCount, free_script_units_per_input},
    tx::{ComputeCommit, CovenantBinding},
};
use kaspa_hashes::Hash;
use kaspa_txscript_errors::{CovenantsError, TxScriptError};
use node_gate::{
    budget::{self, BudgetError},
    wallet::{self, TestKey},
};

use crate::common::*;

const OP_NOP: u8 = 0x61;
const OP_CHECKSIG: u8 = 0xac;

fn with_budget(spend: &Spend, budget: u16) -> Spend {
    let mut spend = spend.clone();
    spend.tx.inputs[0].compute_commit = ComputeBudget(budget).into();
    spend
}

#[test]
fn the_units_a_commitment_allows() {
    assert_eq!(free_script_units_per_input(), ScriptUnits(9_999));
    let allowed = |commit: ComputeCommit| commit.allowed_script_units().0;
    assert_eq!(allowed(ComputeBudget(0).into()), 9_999);
    assert_eq!(allowed(ComputeBudget(1).into()), 19_999);
    assert_eq!(allowed(ComputeBudget(10).into()), 109_999);
    assert_eq!(allowed(ComputeBudget(u16::MAX).into()), 655_359_999);
    assert_eq!(allowed(SigopCount(0).into()), 9_999);
    assert_eq!(allowed(SigopCount(1).into()), 109_999);
    assert_eq!(allowed(SigopCount(u8::MAX).into()), 25_509_999);
}

#[test]
fn the_smallest_budget_covering_a_number_of_units() {
    let covering = |units: u64| ComputeBudget::checked_covering_script_units(ScriptUnits(units)).map(|budget| budget.0);
    assert_eq!(covering(0), Some(0));
    assert_eq!(covering(9_999), Some(0));
    assert_eq!(covering(10_000), Some(1));
    assert_eq!(covering(19_999), Some(1));
    assert_eq!(covering(20_000), Some(2));
    assert_eq!(covering(100_001), Some(10));
    assert_eq!(covering(109_999), Some(10));
    assert_eq!(covering(110_000), Some(11));
    assert_eq!(covering(655_359_999), Some(u16::MAX));
    assert_eq!(covering(655_360_000), None);
}

#[test]
fn a_pay_to_pubkey_spend_needs_budget_ten() {
    let gate = node();
    let spend = plain_spend(&gate);

    let measured = budget::measure_inputs(&gate, &spend.tx, &spend.entries, false).unwrap();
    assert_eq!(measured[0].result, Ok(()));
    assert_eq!(measured[0].used_script_units, 100_001);
    assert_eq!((measured[0].script_units_limit, measured[0].sig_op_limit), (Some(u64::MAX), None));
    assert_eq!(measured[0].covering_budget(), Some(ComputeBudget(10)));

    // One unit less: the signature check alone is one script unit too many.
    let under = submit(&gate, &with_budget(&spend, 9));
    assert_eq!(
        under.consensus_error,
        Some(TxRuleError::SignatureInvalid(TxScriptError::ExceededCommittedScriptUnits { used: 100_000, limit: 99_999 }))
    );
    assert_eq!(under.committed_runs[0].used_script_units, 0);
    // The measuring run of the same evaluation shows what it would take.
    assert_eq!(under.verdict.inputs[0].minimal_budget, Some(10));
    assert_eq!(under.verdict.inputs[0].measured.as_ref().unwrap().used_script_units, 100_001);

    // The exact budget passes.
    assert!(submit(&gate, &with_budget(&spend, 10)).verdict.accepted);
}

#[test]
fn every_budget_below_ten_fails_the_same_way() {
    let gate = node();
    let spend = plain_spend(&gate);
    for budget in 0..=9u16 {
        let runs = budget::run_committed_inputs(&gate, &with_budget(&spend, budget).tx, &spend.entries, false).unwrap();
        let limit = budget as u64 * 10_000 + 9_999;
        assert_eq!(runs[0].result, Err(TxScriptError::ExceededCommittedScriptUnits { used: 100_000, limit }), "budget {budget}");
    }
    for budget in [10u16, 11, 500, u16::MAX] {
        let runs = budget::run_committed_inputs(&gate, &with_budget(&spend, budget).tx, &spend.entries, false).unwrap();
        assert_eq!((runs[0].result.clone(), runs[0].used_script_units), (Ok(()), 100_001), "budget {budget}");
    }
}

#[test]
fn a_larger_script_pushes_the_need_over_the_next_unit() {
    let gate = node();
    let owner = TestKey::from_seed(OWNER);
    // No-ops, then <key> OpCheckSig. The wrapper costs 2 * length + 33, the check 100,001.
    let spend_with_redeem_len = |len: usize| {
        let mut redeem_script = vec![OP_NOP; len - 34];
        redeem_script.extend_from_slice(&wallet::push_data(&owner.schnorr_public_key()));
        redeem_script.push(OP_CHECKSIG);
        assert_eq!(redeem_script.len(), len);
        let mut spend = p2sh_spend(&gate, &redeem_script, &[], 0);
        let signature = owner.schnorr_signature(&spend.populated(), 0, SIG_HASH_ALL);
        spend.tx.inputs[0].signature_script = wallet::p2sh_signature_script(&wallet::push_data(&signature), &redeem_script);
        spend
    };

    // 2 * 4982 + 33 + 100,001 = 109,998: budget 10 (109,999 allowed) is enough.
    let mut fits = spend_with_redeem_len(4_982);
    let measurements = budget::commit_minimal_budgets(&gate, &mut fits.tx, &fits.entries).unwrap();
    assert_eq!((measurements[0].run.used_script_units, measurements[0].budget), (109_998, ComputeBudget(10)));

    // One byte more: 110,000 units, budget 11.
    let mut over = spend_with_redeem_len(4_983);
    let measurements = budget::commit_minimal_budgets(&gate, &mut over.tx, &over.entries).unwrap();
    assert_eq!((measurements[0].run.used_script_units, measurements[0].budget), (110_000, ComputeBudget(11)));
    assert_eq!(over.tx.inputs[0].compute_commit, ComputeBudget(11).into());
    assert_eq!(budget::run_committed_inputs(&gate, &over.tx, &over.entries, false).unwrap()[0].result, Ok(()));
    // With budget 10 the last unit is missing: the `true` pushed by the signature check.
    let under = budget::run_committed_inputs(&gate, &with_budget(&over, 10).tx, &over.entries, true).unwrap();
    assert_eq!(under[0].result, Err(TxScriptError::ExceededCommittedScriptUnits { used: 110_000, limit: 109_999 }));
    assert_eq!(under[0].used_script_units, 109_999);
}

#[test]
fn minimal_budgets_are_committed_per_input_after_signing() {
    let gate = node();
    let owner = TestKey::from_seed(OWNER);
    // Input 0: pay-to-pubkey. Input 1: a pay-to-script-hash coin whose script is `OpTrue`.
    let redeem_script = [0x51];
    let entries = vec![
        coin(&gate, 10 * KAS, owner.p2pk_script_public_key()),
        coin(&gate, 5 * KAS, wallet::p2sh_script_public_key(&redeem_script)),
    ];
    let mut second = input_v1(0xb1, 0);
    second.signature_script = wallet::p2sh_signature_script(&[], &redeem_script);
    let mut spend = Spend::new(tx_v1(vec![input_v1(0xa1, 0), second], vec![pay(RECEIVER, 15 * KAS - PLAIN_FEE)]), entries);
    spend.sign_p2pk(0, &owner, SIG_HASH_ALL);
    let id_before = spend.tx.id();
    let signature_scripts: Vec<Vec<u8>> = spend.tx.inputs.iter().map(|input| input.signature_script.clone()).collect();

    // With budgets of zero the first input cannot pay for its signature check.
    let unfunded = submit(&gate, &spend);
    assert_eq!(unfunded.first_script_error(), Some(&TxScriptError::ExceededCommittedScriptUnits { used: 100_000, limit: 9_999 }));

    let measurements = budget::commit_minimal_budgets(&gate, &mut spend.tx, &spend.entries).unwrap();
    assert_eq!(measurements.iter().map(|m| (m.run.used_script_units, m.budget.0)).collect::<Vec<_>>(), vec![(100_001, 10), (35, 0)]);
    assert_eq!(
        spend.tx.inputs.iter().map(|input| input.compute_commit).collect::<Vec<_>>(),
        vec![ComputeBudget(10).into(), ComputeBudget(0).into()]
    );
    // Neither the id nor the signature scripts changed, and the signature still verifies.
    assert_eq!(spend.tx.id(), id_before);
    assert_eq!(spend.tx.inputs.iter().map(|input| input.signature_script.clone()).collect::<Vec<_>>(), signature_scripts);

    let funded = submit(&gate, &spend);
    assert!(funded.verdict.accepted, "{:?}", funded.verdict.first_refusal);
    assert_eq!(funded.committed_runs.iter().map(|run| run.used_script_units).collect::<Vec<_>>(), vec![100_001, 35]);
    // 100 grams of compute mass per committed unit: ten units for the whole transaction.
    assert_eq!(funded.verdict.masses.unwrap().compute_mass, 94 + (54 + 66) + (54 + 2) + 52 + 360 + 1_000);
}

#[test]
fn a_failing_input_fails_the_same_way_under_its_measured_budget() {
    let gate = node();
    let mut spend = plain_spend(&gate);
    spend.sign_p2pk(0, &TestKey::from_seed(9), SIG_HASH_ALL);
    let measurements = budget::commit_minimal_budgets(&gate, &mut spend.tx, &spend.entries).unwrap();
    assert_eq!(measurements[0].run.result, Err(TxScriptError::EvalFalse));
    assert_eq!((measurements[0].run.used_script_units, measurements[0].budget), (100_000, ComputeBudget(10)));
    let rerun = budget::run_committed_inputs(&gate, &spend.tx, &spend.entries, false).unwrap();
    assert_eq!(rerun[0].result, Err(TxScriptError::EvalFalse));
}

#[test]
fn one_input_under_a_chosen_limit() {
    let gate = node();
    let spend = plain_spend(&gate);
    let run = |limit: u64| budget::run_input(&gate, &spend.tx, &spend.entries, 0, ScriptUnits(limit), true).unwrap();
    // The check costs 100,000 units and its result one more.
    assert_eq!(run(100_001).result, Ok(()));
    let short = run(100_000);
    assert_eq!(short.result, Err(TxScriptError::ExceededCommittedScriptUnits { used: 100_001, limit: 100_000 }));
    assert_eq!(short.used_script_units, 100_000);
    assert_eq!(run(99_999).result, Err(TxScriptError::ExceededCommittedScriptUnits { used: 100_000, limit: 99_999 }));
}

#[test]
fn what_cannot_be_measured() {
    let gate = node();
    let spend = plain_spend(&gate);
    assert_eq!(budget::measure_inputs(&gate, &spend.tx, &[], false), Err(BudgetError::EntryCountMismatch { inputs: 1, entries: 0 }));

    let mut bound = spend.clone();
    bound.tx.outputs[0].covenant = Some(CovenantBinding::new(3, Hash::from_bytes([9; 32])));
    bound.tx.finalize();
    assert_eq!(
        budget::measure_inputs(&gate, &bound.tx, &bound.entries, false),
        Err(BudgetError::Covenants(TxRuleError::CovenantsError(CovenantsError::AuthInputOutOfBounds(0, 3))))
    );

    // Version 0 signatures cover the signature operation counts: nothing to rewrite.
    let mut v0 = plain_spend_v0(&gate);
    assert_eq!(budget::commit_minimal_budgets(&gate, &mut v0.tx, &v0.entries), Err(BudgetError::NotVersionOne(0)));
    // Measuring a version 0 transaction is fine.
    assert_eq!(budget::measure_inputs(&gate, &v0.tx, &v0.entries, false).unwrap()[0].used_script_units, 100_001);
}

/// The price of a signature check is `mass_per_sig_op` of the network parameters
/// (rusty-kaspa a41a333
/// consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs:172). It
/// is 1000 grams on every network, the number `EngineFlags::default()` carries too, so
/// only a changed parameter can show where the price is read from.
#[test]
fn the_price_of_a_signature_check_comes_from_the_parameters() {
    let mut half_price = node();
    half_price.params.mass_per_sig_op = 500;
    assert_eq!(half_price.engine_flags().sigop_script_units.0, 50_000);
    let spend = plain_spend(&half_price);

    let measured = budget::measure_inputs(&half_price, &spend.tx, &spend.entries, false).unwrap();
    assert_eq!((measured[0].result.clone(), measured[0].used_script_units), (Ok(()), 50_001));
    assert_eq!(measured[0].covering_budget(), Some(ComputeBudget(5)));

    // A budget of five allows 59,999 units, a budget of four 49,999.
    assert!(submit(&half_price, &with_budget(&spend, 5)).verdict.consensus_accepted);
    let four = budget::run_committed_inputs(&half_price, &with_budget(&spend, 4).tx, &spend.entries, false).unwrap();
    assert_eq!(four[0].result, Err(TxScriptError::ExceededCommittedScriptUnits { used: 50_000, limit: 49_999 }));

    // At the real price the budget of five is far too small.
    let real_price = node();
    let five = budget::run_committed_inputs(&real_price, &with_budget(&spend, 5).tx, &spend.entries, false).unwrap();
    assert_eq!(five[0].result, Err(TxScriptError::ExceededCommittedScriptUnits { used: 100_000, limit: 59_999 }));
}

/// Before Toccata the engine meters no script units and allows an input the signature
/// operations it commits to, whatever limit it is handed (rusty-kaspa a41a333
/// crypto/txscript/src/lib.rs:542-546). The measuring run is not bound by that commitment,
/// it counts signature operations, and no budget is read off it.
#[test]
fn before_toccata_measuring_counts_signature_operations_and_gives_no_budget() {
    let before = node_before_toccata();
    let owner = TestKey::from_seed(OWNER);
    // A version 0 signature covers the committed count, so the spend is signed after the
    // count is set.
    let committing = |sig_op_count: u8| {
        let mut spend = plain_spend_v0(&before);
        spend.tx.inputs[0].compute_commit = SigopCount(sig_op_count).into();
        spend.tx.finalize();
        spend.sign_p2pk(0, &owner, SIG_HASH_ALL);
        spend
    };

    // One committed operation: accepted. Both runs name the limit the engine applied.
    let one = submit(&before, &committing(1));
    assert!(one.verdict.consensus_accepted);
    let (committed, measured) = (&one.committed_runs[0], &one.measured_runs[0]);
    assert_eq!((committed.script_units_limit, committed.sig_op_limit), (None, Some(1)));
    assert_eq!((measured.script_units_limit, measured.sig_op_limit), (None, Some(u8::MAX)));
    assert_eq!((measured.result.clone(), measured.used_script_units, measured.used_sig_ops), (Ok(()), 0, 1));
    // No script unit was metered: zero is not the budget of this input.
    assert_eq!(measured.covering_budget(), None);
    let record = &one.verdict.inputs[0];
    assert_eq!(record.minimal_budget, None);
    assert_eq!((record.committed.script_units_limit, record.committed.sig_op_limit), (None, Some(1)));
    assert_eq!(record.measured.as_ref().map(|measured| (measured.sig_op_limit, measured.used_sig_ops)), Some((Some(u8::MAX), 1)));

    // No committed operation: a node refuses. The measuring run is not stopped by the
    // commitment and shows that one operation is needed. The signature was made for a
    // commitment of zero and still verifies there: only the meter sees another count.
    let none = submit(&before, &committing(0));
    assert_eq!(none.consensus_error, Some(TxRuleError::SignatureInvalid(TxScriptError::ExceededSigOpLimit(0))));
    let committed = &none.committed_runs[0];
    assert_eq!((committed.result.clone(), committed.sig_op_limit), (Err(TxScriptError::ExceededSigOpLimit(0)), Some(0)));
    let measured = &none.measured_runs[0];
    assert_eq!((measured.result.clone(), measured.used_sig_ops, measured.sig_op_limit), (Ok(()), 1, Some(u8::MAX)));
    assert_eq!(none.verdict.inputs[0].minimal_budget, None);

    // A signature that is wrong stays wrong without a limit.
    let mut forged = committing(1);
    forged.sign_p2pk(0, &TestKey::from_seed(9), SIG_HASH_ALL);
    let measured = budget::measure_inputs(&before, &forged.tx, &forged.entries, false).unwrap();
    assert_eq!(measured[0].result, Err(TxScriptError::EvalFalse));

    // Budgets cannot be measured or committed on this side of the fork.
    let spend = committing(1);
    assert_eq!(budget::minimal_budgets(&before, &spend.tx, &spend.entries), Err(BudgetError::BeforeToccata));
    let mut v1 = plain_spend(&before);
    assert_eq!(budget::commit_minimal_budgets(&before, &mut v1.tx, &v1.entries), Err(BudgetError::BeforeToccata));

    // After the fork the same kind of input is metered and needs ten units.
    let after = node();
    let spend = plain_spend_v0(&after);
    let measured = budget::measure_inputs(&after, &spend.tx, &spend.entries, false).unwrap();
    assert_eq!((measured[0].script_units_limit, measured[0].sig_op_limit), (Some(u64::MAX), None));
    assert_eq!(measured[0].covering_budget(), Some(ComputeBudget(10)));
}
