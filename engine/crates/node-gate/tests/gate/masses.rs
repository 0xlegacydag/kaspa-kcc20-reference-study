//! Sizes and masses: numbers worked out from the formulas, checked against the node's own
//! calculator.

use kaspa_consensus_core::{
    constants::STORAGE_MASS_PARAMETER,
    errors::tx::TxRuleError,
    mass::{UtxoCell, calc_storage_mass},
    tx::{CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutput, UtxoEntry},
};
use kaspa_hashes::Hash;
use node_gate::{
    GateParams,
    mass::{self, StorageMassInputError},
    wallet::{self, TestKey},
};

use crate::common::*;

/// The covenant id used for bound coins. Any 32 bytes do: the mass does not look at it.
fn id() -> Hash {
    Hash::from_bytes([0xc0; 32])
}

/// A 35-byte pay-to-script-hash script.
fn p2sh() -> ScriptPublicKey {
    wallet::p2sh_script_public_key(&[0x51])
}

/// A 34-byte pay-to-pubkey script.
fn p2pk() -> ScriptPublicKey {
    TestKey::from_seed(1).p2pk_script_public_key()
}

fn covenant_coin(gate: &GateParams, amount: u64) -> UtxoEntry {
    let mut entry = coin(gate, amount, p2sh());
    entry.covenant_id = Some(id());
    entry
}

fn covenant_output(value: u64, authorizing_input: u16) -> TransactionOutput {
    TransactionOutput::with_covenant(value, p2sh(), Some(CovenantBinding::new(authorizing_input, id())))
}

fn storage_mass(gate: &GateParams, tx: &Transaction, entries: &[UtxoEntry]) -> u64 {
    mass::calculated_storage_mass(&gate.params, tx, entries).expect("coins a node could hold").expect("a computable mass")
}

#[test]
fn plurality() {
    let gate = node();
    // 63 fixed bytes + script (+ 32 for a covenant id), in units of 100 bytes, rounded up.
    assert_eq!(mass::input_pluralities(&[coin(&gate, 1, p2pk()), coin(&gate, 1, p2sh()), covenant_coin(&gate, 1)]), vec![1, 1, 2]);
    let outputs = vec![
        TransactionOutput::new(1, p2pk()),
        TransactionOutput::new(1, p2sh()),
        covenant_output(1, 0),
        TransactionOutput::new(1, ScriptPublicKey::from_vec(0, vec![0x51; 37])),
        TransactionOutput::new(1, ScriptPublicKey::from_vec(0, vec![0x51; 38])),
        TransactionOutput::with_covenant(1, ScriptPublicKey::from_vec(0, vec![0x51; 5]), Some(CovenantBinding::new(0, id()))),
        TransactionOutput::with_covenant(1, ScriptPublicKey::from_vec(0, vec![0x51; 6]), Some(CovenantBinding::new(0, id()))),
    ];
    assert_eq!(mass::output_pluralities(&tx_v1(vec![input_v1(1, 0)], outputs)), vec![1, 1, 2, 1, 2, 1, 2]);
}

/// One covenant coin of 1000 sompi to one covenant coin of 1000 sompi, 35-byte scripts.
#[test]
fn one_covenant_coin_in_one_out() {
    let gate = node();
    let entries = vec![covenant_coin(&gate, 1_000)];
    let tx = tx_v1(vec![input_v1(1, 0)], vec![covenant_output(1_000, 0)]);
    // Pluralities 2 and 2: the relaxed formula, 4 * 10^12 / 1000 on both sides.
    assert_eq!(storage_mass(&gate, &tx, &entries), 0);

    // Size 235 + L, compute 605 + L + 100 * B, transient 940 + 4 * L.
    let masses = mass::calculate_transaction_non_contextual_masses(&gate.params, &tx).unwrap();
    assert_eq!((mass::estimated_size(&tx), masses.compute_mass, masses.transient_mass), (235, 605, 940));

    let mut bigger = tx.clone();
    bigger.inputs[0].signature_script = vec![0; 1_000];
    bigger.inputs[0].compute_commit = kaspa_consensus_core::mass::ComputeBudget(7).into();
    let masses = mass::calculate_transaction_non_contextual_masses(&gate.params, &bigger).unwrap();
    assert_eq!((mass::estimated_size(&bigger), masses.compute_mass, masses.transient_mass), (1_235, 605 + 1_000 + 700, 940 + 4_000));
}

/// The same coin paying a fee out of itself: 1000 in, 900 out.
#[test]
fn the_coin_pays_its_own_fee() {
    let gate = node();
    let entries = vec![covenant_coin(&gate, 1_000)];
    let tx = tx_v1(vec![input_v1(1, 0)], vec![covenant_output(900, 0)]);
    // 4 * 10^12 / 900 - 4 * 10^12 / 1000 = 4,444,444,444 - 4,000,000,000.
    assert_eq!(storage_mass(&gate, &tx, &entries), 444_444_444);
}

/// The 1000-sompi covenant coin again, with an ordinary fee input and change.
#[test]
fn the_coin_with_a_fee_input_and_change() {
    let gate = node();
    let entries = vec![covenant_coin(&gate, 1_000), coin(&gate, 100_000_000, p2pk())];
    let tx = tx_v1(vec![input_v1(1, 0), input_v1(2, 10)], vec![covenant_output(1_000, 0), TransactionOutput::new(99_990_000, p2pk())]);
    // Not relaxed (plurality 3 on both sides): 4,000,010,001 - 3 * (10^12 / 33,333,666).
    assert_eq!(storage_mass(&gate, &tx, &entries), 3_999_920_004);
}

/// A covenant coin created from one wallet coin of 10 KAS, fee 0.01 KAS.
#[test]
fn one_wallet_coin_in_token_coin_and_change_out() {
    let gate = node();
    let entries = vec![coin(&gate, 10 * KAS, p2pk())];
    let with_token_output = |token: TransactionOutput| {
        let change = 10 * KAS - token.value - 1_000_000;
        tx_v1(vec![input_v1(1, 10)], vec![token, TransactionOutput::new(change, p2pk())])
    };

    let rows = [
        (covenant_output(1_000, 0), 4_000_000_001u64),
        (TransactionOutput::new(1_000, p2sh()), 1_000_000_001),
        (covenant_output(8_000_000, 0), 500_009),
        (covenant_output(8_000_200, 0), 499_996),
    ];
    for (token, expected) in rows {
        assert_eq!(storage_mass(&gate, &with_token_output(token.clone()), &entries), expected, "token output of {}", token.value);
    }
}

/// A covenant coin moved with a separate fee payer.
#[test]
fn token_coin_and_fee_payer_in_token_coin_and_change_out() {
    let gate = node();
    let transfer = |token_value: u64, fee_payer: u64, fee: u64| {
        let entries = vec![covenant_coin(&gate, token_value), coin(&gate, fee_payer, p2pk())];
        let tx = tx_v1(
            vec![input_v1(1, 0), input_v1(2, 10)],
            vec![covenant_output(token_value, 0), TransactionOutput::new(fee_payer - fee, p2pk())],
        );
        storage_mass(&gate, &tx, &entries)
    };
    assert_eq!(transfer(1_000, 10 * KAS, 1_000_000), 3_999_992_004);
    assert_eq!(transfer(20_000_000, KAS, 600_000), 135_060);
    assert_eq!(transfer(KAS, 10 * KAS, 600_000), 32_819);
}

/// One covenant coin in, one out, nothing else.
#[test]
fn one_covenant_coin_in_one_out_paying_its_fee() {
    let gate = node();
    let entries = vec![covenant_coin(&gate, KAS)];
    let tx = tx_v1(vec![input_v1(1, 0)], vec![covenant_output(KAS - 600_000, 0)]);
    assert_eq!(storage_mass(&gate, &tx, &entries), 241);
}

/// The smallest output value whose own term stays within a limit. The input is so large
/// that it gives no credit.
#[test]
fn smallest_output_value_under_a_limit() {
    let term = |plurality: u64, value: u64| {
        let inputs = [UtxoCell::new(1, 2 * STORAGE_MASS_PARAMETER)];
        calc_storage_mass(false, inputs.into_iter(), [UtxoCell::new(plurality, value)].into_iter(), STORAGE_MASS_PARAMETER).unwrap()
    };
    // Without a covenant binding (plurality 1): block limit 500,000 and the old standard cap 100,000.
    assert!(term(1, 1_999_996) > 500_000 && term(1, 1_999_997) <= 500_000);
    assert!(term(1, 9_999_900) > 100_000 && term(1, 9_999_901) <= 100_000);
    // With a covenant binding (plurality 2) the term is four times larger.
    assert!(term(2, 7_999_984) > 500_000 && term(2, 7_999_985) <= 500_000);
    assert!(term(2, 39_999_600) > 100_000 && term(2, 39_999_601) <= 100_000);
    assert_eq!(term(2, 1_000), 4_000_000_000);
    assert_eq!(term(1, 1_000), 1_000_000_000);
}

/// Version 0, one pay-to-pubkey input with a 66-byte signature script and one signature
/// operation, two pay-to-pubkey outputs: the transaction the mempool uses as its average.
#[test]
fn the_everyday_version_0_transaction() {
    let gate = node();
    let mut input = input_v0(1, 1);
    input.signature_script = vec![0; 66];
    let tx = tx_v0(vec![input], vec![pay(2, KAS), pay(3, KAS)]);
    let masses = mass::calculate_transaction_non_contextual_masses(&gate.params, &tx).unwrap();
    // 316 bytes; 316 + 10 * 2 * 36 + 1000.
    assert_eq!((mass::estimated_size(&tx), masses.compute_mass, masses.transient_mass), (316, 2_036, 1_264));
}

/// Version 1: a pay-to-script-hash covenant input with a signature script of S bytes and a
/// pay-to-pubkey fee input, a covenant output and change.
#[test]
fn a_covenant_spend_with_a_fee_payer() {
    let gate = node();
    let with = |script_len: usize, budgets: (u16, u16)| {
        let mut token = input_v1(1, budgets.0);
        token.signature_script = vec![0; script_len];
        let mut payer = input_v1(2, budgets.1);
        payer.signature_script = vec![0; 66];
        tx_v1(vec![token, payer], vec![covenant_output(KAS, 0), pay(2, KAS)])
    };
    let tx = with(0, (0, 0));
    let masses = mass::calculate_transaction_non_contextual_masses(&gate.params, &tx).unwrap();
    assert_eq!((mass::estimated_size(&tx), masses.compute_mass), (407, 1_137));

    let tx = with(1_000, (10, 10));
    let masses = mass::calculate_transaction_non_contextual_masses(&gate.params, &tx).unwrap();
    assert_eq!((mass::estimated_size(&tx), masses.compute_mass, masses.transient_mass), (1_407, 4_137, 5_628));
}

#[test]
fn the_committed_budget_is_charged_used_or_not() {
    let gate = node();
    let spend = plain_spend(&gate);
    let base = mass::calculate_transaction_non_contextual_masses(&gate.params, &spend.tx).unwrap();
    // 94 + (54 + 66) + 52 bytes; one 34-byte output script; budget 10.
    assert_eq!((mass::estimated_size(&spend.tx), base.compute_mass, base.transient_mass), (266, 266 + 360 + 1_000, 1_064));

    let mut generous = spend.clone();
    generous.tx.inputs[0].compute_commit = kaspa_consensus_core::mass::ComputeBudget(500).into();
    let masses = mass::calculate_transaction_non_contextual_masses(&gate.params, &generous.tx).unwrap();
    assert_eq!(masses.compute_mass, base.compute_mass + 100 * 490);
    // The engine uses the same 100,001 units either way.
    assert_eq!(submit(&gate, &generous).committed_runs[0].used_script_units, 100_001);
}

#[test]
fn the_calculators_are_guarded() {
    let gate = node();
    // A compute commitment of the wrong kind would make the mass calculator panic.
    let mixed = tx_v1(vec![input_v0(1, 1)], vec![pay(2, KAS)]);
    assert_eq!(mass::calculate_transaction_non_contextual_masses(&gate.params, &mixed), Err(TxRuleError::SigopCountInV1(0, 1)));
    let mixed = tx_v0(vec![input_v1(1, 3)], vec![pay(2, KAS)]);
    assert_eq!(mass::calculate_transaction_non_contextual_masses(&gate.params, &mixed), Err(TxRuleError::ComputeBudgetInV0(0, 3)));
    // This guard reports the output limit itself, unlike the in-isolation rule.
    let outputs = (0..1001).map(|_| pay(2, 1_000)).collect();
    assert_eq!(
        mass::validate_transaction_for_non_contextual_masses(&gate.params, &tx_v1(vec![input_v1(1, 0)], outputs)),
        Err(TxRuleError::TooManyOutputs(1001, 1000))
    );

    let outputs = (0..1000).map(|_| pay(2, 1_000)).collect();
    assert_eq!(mass::validate_transaction_for_non_contextual_masses(&gate.params, &tx_v1(vec![input_v1(1, 0)], outputs)), Ok(()));
    let inputs = |n: u32| (0..n).map(|i| TransactionInput::new_with_compute_budget(outpoint(1, i), vec![], 0, 0)).collect::<Vec<_>>();
    assert_eq!(
        mass::validate_transaction_for_non_contextual_masses(&gate.params, &tx_v1(inputs(1001), vec![pay(2, KAS)])),
        Err(TxRuleError::TooManyInputs(1001, 1000))
    );
    assert_eq!(mass::validate_transaction_for_non_contextual_masses(&gate.params, &tx_v1(inputs(1000), vec![pay(2, KAS)])), Ok(()));

    // The storage mass calculator divides by amounts and values.
    let tx = tx_v1(vec![input_v1(1, 0)], vec![pay(2, KAS), pay(3, KAS)]);
    let calc = |entries: &[UtxoEntry], tx: &Transaction| mass::calculated_storage_mass(&gate.params, tx, entries);
    assert_eq!(calc(&[coin(&gate, 0, p2pk())], &tx), Err(StorageMassInputError::ZeroInputAmount(0)));
    assert_eq!(calc(&[], &tx), Err(StorageMassInputError::EntryCountMismatch { inputs: 1, entries: 0 }));
    assert_eq!(calc(&[], &tx_v1(vec![], vec![pay(2, KAS)])), Err(StorageMassInputError::NoInputs));
    let zero_output = tx_v1(vec![input_v1(1, 0)], vec![pay(2, KAS), pay(3, 0)]);
    assert_eq!(calc(&[coin(&gate, KAS, p2pk())], &zero_output), Err(StorageMassInputError::ZeroOutputValue(1)));
    let two_inputs = tx_v1(vec![input_v1(1, 0), input_v1(2, 0)], vec![pay(2, KAS), pay(3, KAS)]);
    assert_eq!(
        calc(&[coin(&gate, u64::MAX, p2pk()), coin(&gate, 1, p2pk())], &two_inputs),
        Err(StorageMassInputError::InputAmountsOverflow)
    );
    let long_script = coin(&gate, KAS, ScriptPublicKey::from_vec(0, vec![0x51; 10_001]));
    assert_eq!(calc(&[long_script], &tx), Err(StorageMassInputError::OversizedInputScript(0, 10_001, 10_000)));
    assert!(calc(&[coin(&gate, 3 * KAS, p2pk())], &tx).unwrap().is_some());
}
