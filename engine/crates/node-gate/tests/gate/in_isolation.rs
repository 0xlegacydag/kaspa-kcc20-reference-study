//! Every in-isolation rule: one transaction that trips exactly it, one neighbour that
//! passes. The neighbours differ from the tripping transaction in the one value the rule
//! looks at.

use kaspa_consensus_core::{
    constants::MAX_SOMPI,
    errors::tx::TxRuleError,
    subnets::{SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_NATIVE, SubnetworkId},
    tx::{CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutput},
};
use kaspa_hashes::Hash;
use node_gate::{Stage, isolation};

use crate::common::*;

fn in_isolation(tx: &Transaction) -> Result<(), TxRuleError> {
    isolation::validate_tx_in_isolation(&node().params, tx)
}

/// A user lane id: four namespace bytes, sixteen zero bytes.
fn user_lane() -> SubnetworkId {
    let mut bytes = [0u8; 20];
    bytes[..4].copy_from_slice(&[1, 2, 3, 4]);
    SubnetworkId::from_bytes(bytes)
}

fn script_of_len(len: usize) -> ScriptPublicKey {
    ScriptPublicKey::from_vec(0, vec![0x51; len])
}

fn coinbase(inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>) -> Transaction {
    Transaction::new(0, inputs, outputs, 0, SUBNETWORK_ID_COINBASE, 0, vec![])
}

#[test]
fn the_plain_spend_passes() {
    assert_eq!(in_isolation(&plain_spend(&node()).tx), Ok(()));
    assert_eq!(in_isolation(&plain_spend_v0(&node()).tx), Ok(()));
}

#[test]
fn no_inputs() {
    assert_eq!(in_isolation(&tx_v1(vec![], vec![pay(2, KAS)])), Err(TxRuleError::NoTxInputs));
    assert_eq!(in_isolation(&tx_v1(vec![input_v1(1, 0)], vec![pay(2, KAS)])), Ok(()));
}

#[test]
fn too_many_inputs() {
    let inputs = |n: u32| (0..n).map(|i| TransactionInput::new_with_compute_budget(outpoint(1, i), vec![], 0, 0)).collect::<Vec<_>>();
    assert_eq!(in_isolation(&tx_v1(inputs(1001), vec![pay(2, KAS)])), Err(TxRuleError::TooManyInputs(1001, 1000)));
    assert_eq!(in_isolation(&tx_v1(inputs(1000), vec![pay(2, KAS)])), Ok(()));
}

#[test]
fn signature_script_above_the_larger_fork_value() {
    let with_script = |len: usize| {
        let mut input = input_v1(1, 0);
        input.signature_script = vec![0; len];
        tx_v1(vec![input], vec![pay(2, KAS)])
    };
    assert_eq!(in_isolation(&with_script(250_001)), Err(TxRuleError::TooBigSignatureScript(0, 250_000)));
    assert_eq!(in_isolation(&with_script(250_000)), Ok(()));
}

#[test]
fn too_many_outputs_reports_the_input_limit() {
    let outputs = |n: usize| (0..n).map(|_| pay(2, 1_000)).collect::<Vec<_>>();
    // The second field is `max_tx_inputs`, as upstream writes it; both limits are 1000.
    assert_eq!(in_isolation(&tx_v1(vec![input_v1(1, 0)], outputs(1001))), Err(TxRuleError::TooManyOutputs(1001, 1000)));
    assert_eq!(in_isolation(&tx_v1(vec![input_v1(1, 0)], outputs(1000))), Ok(()));
}

#[test]
fn output_script_too_long() {
    let with_output = |len: usize| tx_v1(vec![input_v1(1, 0)], vec![pay(2, KAS), TransactionOutput::new(KAS, script_of_len(len))]);
    assert_eq!(in_isolation(&with_output(10_001)), Err(TxRuleError::TooBigScriptPublicKey(1, 10_000)));
    assert_eq!(in_isolation(&with_output(10_000)), Ok(()));
}

#[test]
fn coinbase_rules() {
    let output = |len: usize| TransactionOutput::new(KAS, script_of_len(len));

    assert_eq!(in_isolation(&coinbase(vec![], vec![output(34)])), Ok(()));
    assert_eq!(in_isolation(&coinbase(vec![input_v0(1, 0)], vec![output(34)])), Err(TxRuleError::CoinbaseHasInputs(1)));

    let committed = coinbase(vec![], vec![output(34)]);
    committed.set_storage_mass(1);
    assert_eq!(in_isolation(&committed), Err(TxRuleError::CoinbaseNonZeroMassCommitment));

    // ghostdag_k is 124 at ten blocks per second: at most 126 outputs.
    let outputs = |n: usize| (0..n).map(|_| output(34)).collect::<Vec<_>>();
    assert_eq!(in_isolation(&coinbase(vec![], outputs(127))), Err(TxRuleError::CoinbaseTooManyOutputs(127, 126)));
    assert_eq!(in_isolation(&coinbase(vec![], outputs(126))), Ok(()));

    assert_eq!(in_isolation(&coinbase(vec![], vec![output(34), output(151)])), Err(TxRuleError::CoinbaseScriptPublicKeyTooLong(1)));
    assert_eq!(in_isolation(&coinbase(vec![], vec![output(34), output(150)])), Ok(()));
}

#[test]
fn output_value_ranges() {
    let with_values = |values: &[u64]| tx_v1(vec![input_v1(1, 0)], values.iter().map(|value| pay(2, *value)).collect());

    assert_eq!(in_isolation(&with_values(&[KAS, 0])), Err(TxRuleError::TxOutZero(1)));
    assert_eq!(in_isolation(&with_values(&[KAS, 1])), Ok(()));

    assert_eq!(in_isolation(&with_values(&[MAX_SOMPI + 1])), Err(TxRuleError::TxOutTooHigh(0)));
    assert_eq!(in_isolation(&with_values(&[MAX_SOMPI])), Ok(()));

    assert_eq!(in_isolation(&with_values(&[MAX_SOMPI, 1])), Err(TxRuleError::TotalTxOutTooHigh));
    assert_eq!(in_isolation(&with_values(&[MAX_SOMPI - 1, 1])), Ok(()));
}

/// `OutputsValueOverflow` cannot be produced: the running total is at most `MAX_SOMPI`
/// when the next value (itself at most `MAX_SOMPI`) is added, and twice `MAX_SOMPI` is
/// far below 2^64. The largest sum the rule can see ends in `TotalTxOutTooHigh`.
#[test]
fn output_value_overflow_is_unreachable() {
    assert!(MAX_SOMPI.checked_add(MAX_SOMPI).is_some());
    let tx = tx_v1(vec![input_v1(1, 0)], vec![pay(2, MAX_SOMPI), pay(2, MAX_SOMPI)]);
    assert_eq!(in_isolation(&tx), Err(TxRuleError::TotalTxOutTooHigh));
}

#[test]
fn duplicate_inputs() {
    let input = |index: u32| TransactionInput::new_with_compute_budget(outpoint(1, index), vec![], 0, 0);
    assert_eq!(in_isolation(&tx_v1(vec![input(0), input(1), input(0)], vec![pay(2, KAS)])), Err(TxRuleError::TxDuplicateInputs));
    assert_eq!(in_isolation(&tx_v1(vec![input(0), input(1), input(2)], vec![pay(2, KAS)])), Ok(()));
}

#[test]
fn gas() {
    let v0_with_gas = Transaction::new(0, vec![input_v0(1, 1)], vec![pay(2, KAS)], 0, SUBNETWORK_ID_NATIVE, 1, vec![]);
    assert_eq!(in_isolation(&v0_with_gas), Err(TxRuleError::TxHasGas("gas is only allowed for Toccata-or-newer tx versions")));

    let native_with_gas = Transaction::new(1, vec![input_v1(1, 0)], vec![pay(2, KAS)], 0, SUBNETWORK_ID_NATIVE, 1, vec![]);
    assert_eq!(in_isolation(&native_with_gas), Err(TxRuleError::TxHasGas("native / system subnetworks must use zero gas")));

    let lane_with_gas = Transaction::new(1, vec![input_v1(1, 0)], vec![pay(2, KAS)], 0, user_lane(), 1, vec![]);
    assert_eq!(in_isolation(&lane_with_gas), Ok(()));
}

#[test]
fn subnetwork() {
    let on = |version: u16, id: SubnetworkId| {
        let input = if version == 0 { input_v0(1, 1) } else { input_v1(1, 0) };
        Transaction::new(version, vec![input], vec![pay(2, KAS)], 0, id, 0, vec![])
    };
    let mut odd_tail = [0u8; 20];
    odd_tail[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
    let odd_tail = SubnetworkId::from_bytes(odd_tail);

    // Reserved system ids other than native and coinbase.
    for first_byte in [2u8, 3, 255] {
        let id = SubnetworkId::from_byte(first_byte);
        assert_eq!(in_isolation(&on(1, id)), Err(TxRuleError::SubnetworksDisabled(id)));
    }
    // A user lane needs version 1.
    assert_eq!(in_isolation(&on(0, user_lane())), Err(TxRuleError::SubnetworksDisabled(user_lane())));
    assert_eq!(in_isolation(&on(1, user_lane())), Ok(()));
    // Any other shape.
    assert_eq!(in_isolation(&on(1, odd_tail)), Err(TxRuleError::SubnetworksDisabled(odd_tail)));
    assert_eq!(in_isolation(&on(1, SUBNETWORK_ID_NATIVE)), Ok(()));
}

#[test]
fn version() {
    let with_version =
        |version: u16| Transaction::new(version, vec![input_v1(1, 0)], vec![pay(2, KAS)], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    assert_eq!(in_isolation(&with_version(2)), Err(TxRuleError::UnknownTxVersion(2)));
    assert_eq!(in_isolation(&with_version(1)), Ok(()));
}

#[test]
fn version_specific_fields() {
    // Version 1 with a signature operation count.
    assert_eq!(in_isolation(&tx_v1(vec![input_v1(1, 0), input_v0(2, 1)], vec![pay(2, KAS)])), Err(TxRuleError::SigopCountInV1(1, 1)));
    // Version 0 with a compute budget.
    assert_eq!(
        in_isolation(&tx_v0(vec![input_v0(1, 1), input_v1(2, 10)], vec![pay(2, KAS)])),
        Err(TxRuleError::ComputeBudgetInV0(1, 10))
    );

    // Version 0 with a covenant binding; the same output is fine in version 1.
    let bound =
        TransactionOutput::with_covenant(KAS, pay(2, KAS).script_public_key, Some(CovenantBinding::new(0, Hash::from_bytes([9; 32]))));
    assert_eq!(in_isolation(&tx_v0(vec![input_v0(1, 1)], vec![pay(2, KAS), bound.clone()])), Err(TxRuleError::CovenantBindingInV0(1)));
    assert_eq!(in_isolation(&tx_v1(vec![input_v1(1, 0)], vec![pay(2, KAS), bound])), Ok(()));
}

#[test]
fn the_first_rule_in_node_order_answers() {
    // Zero output value and duplicate inputs and gas: the output values are checked first.
    let input = |index: u32| TransactionInput::new_with_compute_budget(outpoint(1, index), vec![], 0, 0);
    let tx = Transaction::new(1, vec![input(0), input(0)], vec![pay(2, 0)], 0, SUBNETWORK_ID_NATIVE, 7, vec![]);
    assert_eq!(in_isolation(&tx), Err(TxRuleError::TxOutZero(0)));
    // Counts are checked before values.
    assert_eq!(in_isolation(&tx_v1(vec![], vec![pay(2, 0)])), Err(TxRuleError::NoTxInputs));
}

#[test]
fn the_gate_names_the_stage_and_the_rule() {
    let gate = node();
    let cases: Vec<(Transaction, &str)> = vec![
        (tx_v1(vec![], vec![pay(2, KAS)]), "check_transaction_inputs_count"),
        (tx_v1(vec![input_v1(1, 0)], vec![pay(2, 0)]), "check_transaction_output_value_ranges"),
        (
            tx_v1(vec![input_v1(1, 0), TransactionInput::new_with_compute_budget(outpoint(1, 0), vec![], 0, 0)], vec![pay(2, KAS)]),
            "check_duplicate_transaction_inputs",
        ),
        (Transaction::new(1, vec![input_v1(1, 0)], vec![pay(2, KAS)], 0, SUBNETWORK_ID_NATIVE, 1, vec![]), "check_gas"),
        (
            Transaction::new(1, vec![input_v1(1, 0)], vec![pay(2, KAS)], 0, SubnetworkId::from_byte(2), 0, vec![]),
            "check_transaction_subnetwork",
        ),
        (
            Transaction::new(2, vec![input_v1(1, 0)], vec![pay(2, KAS)], 0, SUBNETWORK_ID_NATIVE, 0, vec![]),
            "check_transaction_version",
        ),
        (tx_v1(vec![input_v0(1, 1)], vec![pay(2, KAS)]), "check_tx_version_specific_fields"),
    ];
    for (tx, rule) in cases {
        let entries = tx.inputs.iter().map(|_| coin(&gate, 10 * KAS, pay(1, 1).script_public_key)).collect();
        let evaluation = in_block(&gate, &Spend::new(tx, entries));
        let refusal = evaluation.verdict.consensus_refusal.expect("refused in isolation");
        assert_eq!((refusal.stage, refusal.rule.as_str()), (Stage::Isolation, rule));
        assert_eq!(evaluation.verdict.stage_reached, Stage::Isolation);
        assert!(!evaluation.verdict.accepted);
    }
}

/// The input count and the output count have their own limits. Both are 1000 on every
/// network, so only changed parameters can show which limit a count is compared with:
/// here ten inputs and fifteen outputs, as in upstream's own test (rusty-kaspa a41a333
/// consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs:238-250).
#[test]
fn the_two_count_limits_are_told_apart() {
    let mut params = node().params;
    params.max_tx_inputs = 10;
    params.max_tx_outputs = 15;
    let with_counts = |inputs: u32, outputs: usize| {
        tx_v1(
            (0..inputs).map(|i| TransactionInput::new_with_compute_budget(outpoint(1, i), vec![], 0, 0)).collect(),
            (0..outputs).map(|_| pay(2, 1_000)).collect(),
        )
    };
    let validate = |tx: &Transaction| isolation::validate_tx_in_isolation(&params, tx);

    // Fifteen outputs pass although the input limit is ten; the sixteenth is refused, and
    // the error carries the input limit, as upstream writes it (line 72).
    assert_eq!(validate(&with_counts(1, 15)), Ok(()));
    assert_eq!(validate(&with_counts(1, 16)), Err(TxRuleError::TooManyOutputs(16, 10)));
    // Ten inputs pass and the eleventh is refused although the output limit is fifteen.
    assert_eq!(validate(&with_counts(10, 1)), Ok(()));
    assert_eq!(validate(&with_counts(11, 1)), Err(TxRuleError::TooManyInputs(11, 10)));
}
