//! UTXO-context rules: one transaction that trips exactly each rule, one neighbour that
//! passes; and the two ways the storage mass commitment is treated.

use kaspa_consensus_core::{
    constants::MAX_SOMPI,
    errors::tx::TxRuleError,
    hashing::{covenant_id::covenant_id, sighash_type::SIG_HASH_ALL},
    subnets::SUBNETWORK_ID_COINBASE,
    tx::{CovenantBinding, Transaction, TransactionInput, TransactionOutput, UtxoEntry},
};
use kaspa_hashes::Hash;
use kaspa_txscript_errors::{CovenantsError, TxScriptError};
use node_gate::{
    GateParams, Stage, mass,
    utxo::{self, TxValidationFlags},
    wallet::TestKey,
};

use crate::common::*;

/// A spend of one pay-to-pubkey coin of `amount` to outputs of `values`, signed.
fn spend_of(gate: &GateParams, amount: u64, values: &[u64]) -> Spend {
    let owner = TestKey::from_seed(OWNER);
    let entries = vec![coin(gate, amount, owner.p2pk_script_public_key())];
    let outputs = values.iter().map(|value| pay(RECEIVER, *value)).collect();
    let mut spend = Spend::new(tx_v1(vec![input_v1(0xa1, 10)], outputs), entries);
    spend.sign_p2pk(0, &owner, SIG_HASH_ALL);
    spend
}

fn refusal_of(evaluation: &node_gate::Evaluation) -> (Stage, String) {
    let refusal = evaluation.verdict.consensus_refusal.clone().expect("a consensus refusal");
    (refusal.stage, refusal.rule)
}

#[test]
fn the_plain_spend_passes_in_both_modes() {
    let gate = node();
    let spend = plain_spend(&gate);
    let submitted = submit(&gate, &spend);
    assert!(submitted.verdict.consensus_accepted);
    assert_eq!(submitted.verdict.stage_reached, Stage::Accepted);
    assert_eq!(submitted.verdict.fee, Some(PLAIN_FEE));

    // In a block the commitment must already be right.
    spend.commit_storage_mass(&gate);
    let mined = in_block(&gate, &spend);
    assert!(mined.verdict.accepted);
    assert_eq!(mined.verdict.fee, Some(PLAIN_FEE));
}

#[test]
fn missing_coins() {
    let gate = node();
    let mut spend = plain_spend(&gate);
    spend.entries.clear();
    for evaluation in [submit(&gate, &spend), in_block(&gate, &spend)] {
        assert_eq!(evaluation.consensus_error, Some(TxRuleError::MissingTxOutpoints));
        assert_eq!(refusal_of(&evaluation), (Stage::UtxoPopulation, "validate_transaction_in_utxo_context".to_string()));
        assert!(evaluation.verdict.inputs.is_empty());
    }
}

#[test]
fn coinbase_maturity() {
    let gate = node();
    let maturity = gate.params.coinbase_maturity();
    assert_eq!(maturity, 1000);
    let with_coinbase_age = |age: u64| {
        let mut spend = plain_spend(&gate);
        spend.entries[0].is_coinbase = true;
        spend.entries[0].block_daa_score = gate.pov_daa_score - age;
        spend
    };

    let young = with_coinbase_age(maturity - 1);
    let evaluation = submit(&gate, &young);
    assert_eq!(
        evaluation.consensus_error,
        Some(TxRuleError::ImmatureCoinbaseSpend(0, outpoint(0xa1, 0), gate.pov_daa_score - 999, gate.pov_daa_score, 1000))
    );
    assert_eq!(refusal_of(&evaluation), (Stage::UtxoContext, "check_transaction_coinbase_maturity".to_string()));

    assert!(submit(&gate, &with_coinbase_age(maturity)).verdict.consensus_accepted);

    // The same young coin, not marked coinbase, is spendable.
    let mut ordinary = with_coinbase_age(maturity - 1);
    ordinary.entries[0].is_coinbase = false;
    assert!(submit(&gate, &ordinary).verdict.consensus_accepted);
}

#[test]
fn input_amount_too_high() {
    let gate = node();
    let too_high = spend_of(&gate, MAX_SOMPI + 1, &[MAX_SOMPI - PLAIN_FEE]);
    for evaluation in [submit(&gate, &too_high), in_block(&gate, &too_high)] {
        assert_eq!(evaluation.consensus_error, Some(TxRuleError::InputAmountTooHigh));
        assert_eq!(refusal_of(&evaluation), (Stage::UtxoContext, "check_transaction_input_amounts".to_string()));
    }
    assert!(submit(&gate, &spend_of(&gate, MAX_SOMPI, &[MAX_SOMPI - PLAIN_FEE])).verdict.consensus_accepted);
}

#[test]
fn input_amount_overflow() {
    let gate = node();
    // The running total must still be valid when the addition overflows: a small coin
    // first, then one that fills 64 bits.
    let owner = TestKey::from_seed(OWNER);
    let entries = vec![coin(&gate, 1, owner.p2pk_script_public_key()), coin(&gate, u64::MAX, owner.p2pk_script_public_key())];
    let spend = Spend::new(tx_v1(vec![input_v1(0xa1, 10), input_v1(0xa2, 10)], vec![pay(RECEIVER, KAS)]), entries);

    let populated = spend.populated();
    assert_eq!(utxo::check_transaction_input_amounts(&populated), Err(TxRuleError::InputAmountOverflow));
    assert_eq!(in_block(&gate, &spend).consensus_error, Some(TxRuleError::InputAmountOverflow));
    // On submission a node calculates the storage mass first. Such coins cannot exist, so
    // the gate does not feed them to the calculator; the amounts rule then refuses.
    let submitted = node_gate::evaluate(&gate, &spend.tx, &spend.entries, node_gate::GateOptions::submit());
    assert_eq!(submitted.consensus_error, Some(TxRuleError::InputAmountOverflow));
    assert_eq!(submitted.verdict.harness_error, None);

    // In the other order the first coin alone is already above the maximum.
    let reversed = Spend::new(spend.tx.clone(), vec![spend.entries[1].clone(), spend.entries[0].clone()]);
    assert_eq!(utxo::check_transaction_input_amounts(&reversed.populated()), Err(TxRuleError::InputAmountTooHigh));
}

#[test]
fn outputs_worth_more_than_inputs() {
    let gate = node();
    let over = spend_of(&gate, 10 * KAS, &[6 * KAS, 4 * KAS + 1]);
    let evaluation = submit(&gate, &over);
    assert_eq!(evaluation.consensus_error, Some(TxRuleError::SpendTooHigh(10 * KAS + 1, 10 * KAS)));
    assert_eq!(refusal_of(&evaluation), (Stage::UtxoContext, "check_transaction_output_values".to_string()));
    assert_eq!(evaluation.verdict.fee, None);

    // A zero fee is fine for consensus. The mempool is another matter.
    let exact = submit(&gate, &spend_of(&gate, 10 * KAS, &[6 * KAS, 4 * KAS]));
    assert!(exact.verdict.consensus_accepted);
    assert_eq!(exact.verdict.fee, Some(0));
    assert!(!exact.verdict.accepted);
}

#[test]
fn mass_commitment_in_a_block_must_be_exact() {
    let gate = node();
    let spend = plain_spend(&gate);
    let calculated = mass::calculated_storage_mass(&gate.params, &spend.tx, &spend.entries).unwrap().unwrap();
    // 10^12 / 999,000,000 - 10^12 / 1,000,000,000 = 1001 - 1000.
    assert_eq!(calculated, 1);

    for wrong in [0, 2, 500_000] {
        spend.tx.set_storage_mass(wrong);
        let evaluation = in_block(&gate, &spend);
        assert_eq!(evaluation.consensus_error, Some(TxRuleError::WrongMass(1, wrong)));
        assert_eq!(refusal_of(&evaluation), (Stage::UtxoContext, "check_mass_commitment".to_string()));
        assert_eq!(spend.tx.storage_mass(), wrong, "block mode must not touch the commitment");
    }
    spend.tx.set_storage_mass(1);
    assert!(in_block(&gate, &spend).verdict.accepted);
}

#[test]
fn mass_commitment_on_submission_is_overwritten() {
    let gate = node();
    let spend = plain_spend(&gate);
    spend.tx.set_storage_mass(123_456);
    let evaluation = submit(&gate, &spend);
    assert!(evaluation.verdict.accepted);
    assert_eq!(spend.tx.storage_mass(), 1);
    let masses = evaluation.verdict.masses.expect("masses");
    assert_eq!((masses.calculated_storage_mass, masses.committed_storage_mass), (Some(1), 1));
}

/// With the real parameters the storage mass of a transaction that passed the
/// in-isolation rules always fits in 64 bits: at most 1000 outputs, each at most
/// 10^12 * 101^2 (a 10,000-byte script has plurality 101). The rule is exercised with a
/// storage mass parameter large enough to overflow.
#[test]
fn incomputable_mass() {
    let mut gate = node();
    gate.params.storage_mass_parameter = u64::MAX;
    let two_outputs = spend_of(&gate, 10 * KAS, &[1, 1]);
    assert_eq!(mass::calculated_storage_mass(&gate.params, &two_outputs.tx, &two_outputs.entries), Ok(None));

    let mined = in_block(&gate, &two_outputs);
    assert_eq!(mined.consensus_error, Some(TxRuleError::MassIncomputable));
    assert_eq!(refusal_of(&mined), (Stage::UtxoContext, "check_mass_commitment".to_string()));

    let submitted = submit(&gate, &two_outputs);
    assert_eq!(submitted.consensus_error, Some(TxRuleError::MassIncomputable));
    assert_eq!(refusal_of(&submitted), (Stage::StorageMass, "validate_mempool_transaction_in_utxo_context".to_string()));

    // One such output is computable.
    let one_output = spend_of(&gate, 10 * KAS, &[1]);
    assert!(mass::calculated_storage_mass(&gate.params, &one_output.tx, &one_output.entries).unwrap().is_some());

    // The bound claimed above, with the real parameter.
    let real = node();
    let worst_output_term = real.params.storage_mass_parameter as u128 * 101 * 101;
    assert!(worst_output_term * (real.params.max_tx_outputs as u128) < u64::MAX as u128);
}

#[test]
fn sequence_lock() {
    let gate = node();
    let with_sequence = |sequence: u64| {
        let owner = TestKey::from_seed(OWNER);
        let mut spend = plain_spend(&gate);
        spend.tx.inputs[0].sequence = sequence;
        spend.sign_p2pk(0, &owner, SIG_HASH_ALL);
        spend
    };

    // The coin is COIN_AGE old: a relative lock of COIN_AGE has just passed, one more has not.
    assert!(submit(&gate, &with_sequence(COIN_AGE)).verdict.consensus_accepted);
    let locked = submit(&gate, &with_sequence(COIN_AGE + 1));
    assert_eq!(locked.consensus_error, Some(TxRuleError::SequenceLockConditionsAreNotMet));
    assert_eq!(refusal_of(&locked), (Stage::UtxoContext, "check_sequence_lock".to_string()));

    // Bit 63 disables the lock, whatever the low bits say.
    assert!(submit(&gate, &with_sequence((1 << 63) | 0xffff_ffff)).verdict.consensus_accepted);
    // Only the low 32 bits count as the lock.
    assert!(submit(&gate, &with_sequence(1 << 32)).verdict.consensus_accepted);
}

#[test]
fn covenant_binding_names_a_missing_input() {
    let gate = node();
    let mut spend = plain_spend(&gate);
    spend.tx.outputs[0].covenant = Some(CovenantBinding::new(5, Hash::from_bytes([9; 32])));
    spend.tx.finalize();
    let evaluation = submit(&gate, &spend);
    assert_eq!(evaluation.consensus_error, Some(TxRuleError::CovenantsError(CovenantsError::AuthInputOutOfBounds(0, 5))));
    assert_eq!(refusal_of(&evaluation), (Stage::UtxoContext, "check_covenant_info".to_string()));
    // Without a covenant context no script can be run.
    assert!(evaluation.verdict.inputs.is_empty());
}

#[test]
fn covenant_binding_of_a_new_covenant_must_carry_the_derived_id() {
    let gate = node();
    let owner = TestKey::from_seed(OWNER);
    let bound_spend = |id_of: &dyn Fn(&TransactionOutput) -> Hash| {
        let mut spend = plain_spend(&gate);
        let id = id_of(&spend.tx.outputs[0]);
        spend.tx.outputs[0].covenant = Some(CovenantBinding::new(0, id));
        spend.tx.finalize();
        spend.sign_p2pk(0, &owner, SIG_HASH_ALL);
        spend
    };

    let arbitrary = Hash::from_bytes([9; 32]);
    let wrong = submit(&gate, &bound_spend(&|_| arbitrary));
    assert_eq!(wrong.consensus_error, Some(TxRuleError::CovenantsError(CovenantsError::WrongGenesisCovenantId(0, arbitrary))));
    assert_eq!(refusal_of(&wrong), (Stage::UtxoContext, "check_covenant_info".to_string()));

    let derived = submit(&gate, &bound_spend(&|output| covenant_id(outpoint(0xa1, 0), [(0u32, output)].into_iter())));
    assert!(derived.verdict.consensus_accepted);
}

#[test]
fn covenant_binding_that_continues_the_coins_covenant() {
    let gate = node();
    let owner = TestKey::from_seed(OWNER);
    let id = Hash::from_bytes([7; 32]);
    let mut spend = plain_spend(&gate);
    spend.entries[0].covenant_id = Some(id);
    spend.tx.outputs[0].covenant = Some(CovenantBinding::new(0, id));
    spend.tx.finalize();
    spend.sign_p2pk(0, &owner, SIG_HASH_ALL);
    let evaluation = submit(&gate, &spend);
    assert!(evaluation.verdict.consensus_accepted);
    assert!(evaluation.verdict.inputs[0].spent_has_covenant_id);

    // A coin with a covenant id and no continuing output is accepted as well: the node
    // leaves that to the coin's script.
    let mut dropped = plain_spend(&gate);
    dropped.entries[0].covenant_id = Some(id);
    assert!(submit(&gate, &dropped).verdict.consensus_accepted);
}

#[test]
fn covenant_bindings_are_not_looked_at_before_toccata() {
    let before = node_before_toccata();
    let mut spend = plain_spend(&before);
    spend.tx.outputs[0].covenant = Some(CovenantBinding::new(5, Hash::from_bytes([9; 32])));
    spend.tx.finalize();
    assert!(utxo::check_covenant_info(&before, &spend.populated(), before.block_daa_score).is_ok());
    assert!(utxo::check_covenant_info(&node(), &spend.populated(), node().block_daa_score).is_err());
}

#[test]
fn script_failure_is_wrapped_by_signature_script_emptiness() {
    let gate = node();
    let mut unsigned = plain_spend(&gate);
    unsigned.tx.inputs[0].signature_script.clear();
    let evaluation = submit(&gate, &unsigned);
    assert_eq!(evaluation.consensus_error, Some(TxRuleError::SignatureEmpty(TxScriptError::InvalidStackOperation(2, 1))));
    assert_eq!(refusal_of(&evaluation), (Stage::Scripts, "check_scripts".to_string()));
    assert_eq!(evaluation.verdict.consensus_refusal.unwrap().input, Some(0));

    let mut wrong = plain_spend(&gate);
    wrong.sign_p2pk(0, &TestKey::from_seed(9), SIG_HASH_ALL);
    let evaluation = submit(&gate, &wrong);
    assert_eq!(evaluation.consensus_error, Some(TxRuleError::SignatureInvalid(TxScriptError::EvalFalse)));
    assert_eq!(evaluation.verdict.stage_reached, Stage::Scripts);
}

#[test]
fn the_first_failing_input_answers_and_every_input_is_recorded() {
    let gate = node();
    let owner = TestKey::from_seed(OWNER);
    let entries: Vec<UtxoEntry> = (0..3).map(|_| coin(&gate, 10 * KAS, owner.p2pk_script_public_key())).collect();
    let tx = tx_v1(vec![input_v1(0xa1, 10), input_v1(0xa2, 10), input_v1(0xa3, 10)], vec![pay(RECEIVER, 30 * KAS - PLAIN_FEE)]);
    let mut spend = Spend::new(tx, entries);
    spend.sign_p2pk(0, &owner, SIG_HASH_ALL);
    spend.sign_p2pk(1, &TestKey::from_seed(9), SIG_HASH_ALL);
    // Input 2 stays unsigned.

    let evaluation = submit(&gate, &spend);
    assert_eq!(evaluation.consensus_error, Some(TxRuleError::SignatureInvalid(TxScriptError::EvalFalse)));
    assert_eq!(evaluation.verdict.consensus_refusal.as_ref().unwrap().input, Some(1));
    let results: Vec<Result<(), TxScriptError>> = evaluation.committed_runs.iter().map(|run| run.result.clone()).collect();
    assert_eq!(results, vec![Ok(()), Err(TxScriptError::EvalFalse), Err(TxScriptError::InvalidStackOperation(2, 1))]);
    assert_eq!(evaluation.verdict.inputs.len(), 3);
}

#[test]
fn skipping_script_checks_skips_only_them() {
    let gate = node();
    let mut unsigned = plain_spend(&gate);
    unsigned.tx.inputs[0].signature_script.clear();
    unsigned.commit_storage_mass(&gate);
    let populated = unsigned.populated();
    assert_eq!(
        utxo::validate_populated_transaction_and_get_fee(&gate, &populated, TxValidationFlags::SkipScriptChecks),
        Ok(PLAIN_FEE)
    );
    assert!(utxo::validate_populated_transaction_and_get_fee(&gate, &populated, TxValidationFlags::Full).is_err());

    // Skipping the mass check accepts a wrong commitment; the full check does not.
    let signed = plain_spend(&gate);
    signed.tx.set_storage_mass(77);
    let populated = signed.populated();
    assert_eq!(utxo::validate_populated_transaction_and_get_fee(&gate, &populated, TxValidationFlags::SkipMassCheck), Ok(PLAIN_FEE));
    assert_eq!(
        utxo::validate_populated_transaction_and_get_fee(&gate, &populated, TxValidationFlags::Full),
        Err(TxRuleError::WrongMass(1, 77))
    );
}

#[test]
fn rules_run_in_the_node_order() {
    let gate = node();
    // Immature coinbase, outputs above inputs, a failing sequence lock, no signature.
    let mut spend = spend_of(&gate, 10 * KAS, &[11 * KAS]);
    spend.entries[0].is_coinbase = true;
    spend.entries[0].block_daa_score = gate.pov_daa_score - 1;
    spend.tx.inputs[0].sequence = 5;
    spend.tx.inputs[0].signature_script.clear();
    assert!(matches!(submit(&gate, &spend).consensus_error, Some(TxRuleError::ImmatureCoinbaseSpend(..))));

    spend.entries[0].is_coinbase = false;
    assert_eq!(submit(&gate, &spend).consensus_error, Some(TxRuleError::SpendTooHigh(11 * KAS, 10 * KAS)));

    spend.tx.outputs[0].value = 9 * KAS;
    spend.tx.finalize();
    assert_eq!(submit(&gate, &spend).consensus_error, Some(TxRuleError::SequenceLockConditionsAreNotMet));

    spend.tx.inputs[0].sequence = 0;
    spend.tx.finalize();
    assert!(matches!(submit(&gate, &spend).consensus_error, Some(TxRuleError::SignatureEmpty(_))));
}

/// Inside a block the two DAA scores of the gate differ: the rules of the fork are those
/// of the containing block, coinbase maturity is judged from the point of view of the
/// block that merges it (rusty-kaspa a41a333
/// consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs:46, 81-97).
#[test]
fn coinbase_maturity_is_judged_from_the_point_of_view_score() {
    let mut gate = node();
    gate.block_daa_score = gate.pov_daa_score - 50;
    let maturity = gate.params.coinbase_maturity();
    let with_coinbase_age = |age: u64| {
        let mut spend = plain_spend(&gate);
        spend.entries[0].is_coinbase = true;
        spend.entries[0].block_daa_score = gate.pov_daa_score - age;
        spend.commit_storage_mass(&gate);
        spend
    };

    // Exactly mature from the point of view; from the block's own score it would be
    // fifty scores short.
    assert!(in_block(&gate, &with_coinbase_age(maturity)).verdict.accepted);
    // One score younger: refused, and the error carries the point of view score.
    let young = in_block(&gate, &with_coinbase_age(maturity - 1));
    assert_eq!(
        young.consensus_error,
        Some(TxRuleError::ImmatureCoinbaseSpend(
            0,
            outpoint(0xa1, 0),
            gate.pov_daa_score - maturity + 1,
            gate.pov_daa_score,
            maturity
        ))
    );
}

/// A node never puts a coinbase through the rules of ordinary spends: the virtual
/// processor skips the first transaction of a block (rusty-kaspa a41a333
/// consensus/src/pipeline/virtual_processor/utxo_validation.rs:117-121, 326, 348) and a
/// coinbase in any other place is refused as a second coinbase
/// (consensus/src/pipeline/body_processor/body_validation_in_isolation.rs:46-56). In block
/// mode the gate answers for the transaction rules a coinbase does go through and says
/// that the rest is not a question it can answer.
#[test]
fn a_coinbase_in_a_block_is_not_judged_by_the_rules_of_ordinary_spends() {
    let gate = node();
    let coinbase = |inputs: Vec<TransactionInput>| {
        Transaction::new(0, inputs, vec![pay(RECEIVER, 50 * KAS)], 0, SUBNETWORK_ID_COINBASE, 0, vec![])
    };
    let in_a_block = |tx: &Transaction| node_gate::evaluate(&gate, tx, &[], node_gate::GateOptions::block());

    // A well formed coinbase: no refusal by the amounts rule, although its output is
    // worth more than its (absent) inputs.
    let well_formed = in_a_block(&coinbase(vec![]));
    assert_eq!((well_formed.consensus_error.clone(), well_formed.block_mass_error.clone()), (None, None));
    assert!(!well_formed.verdict.accepted, "no answer is not an acceptance");
    assert_eq!(well_formed.verdict.stage_reached, Stage::Harness);
    let reason = well_formed.verdict.harness_error.clone().expect("the gate says it cannot answer");
    assert!(reason.contains("coinbase") && reason.contains("block rules"), "{reason}");

    // The transaction rules a node does apply to a coinbase still answer.
    let with_input = in_a_block(&coinbase(vec![input_v0(1, 0)]));
    assert_eq!(with_input.consensus_error, Some(TxRuleError::CoinbaseHasInputs(1)));
    assert_eq!((with_input.verdict.stage_reached, with_input.verdict.harness_error.clone()), (Stage::Isolation, None));
    let committed = coinbase(vec![]);
    committed.set_storage_mass(1);
    assert_eq!(in_a_block(&committed).consensus_error, Some(TxRuleError::CoinbaseNonZeroMassCommitment));

    // Submitted to a mempool, a coinbase does go through the rules of ordinary spends
    // (utxo_validation.rs:442-490 makes no exception) and fails the amounts rule.
    let submitted = node_gate::evaluate(&gate, &coinbase(vec![]), &[], node_gate::GateOptions::submit());
    assert_eq!(submitted.consensus_error, Some(TxRuleError::SpendTooHigh(50 * KAS, 0)));
    assert_eq!(submitted.verdict.harness_error, None);
}
