//! The step-by-step walk of `gate::evaluate` against the node's own sequence of calls.
//!
//! `gate::evaluate` re-arranges the consensus validation so that it can report the stage,
//! the fee and every input's run. The node's sequence is three calls in a row
//! (rusty-kaspa a41a333 consensus/src/pipeline/virtual_processor/processor.rs:1216-1233,
//! utxo_validation.rs:366-414 and 442-490). `node_answer` below makes those calls with the
//! ported functions and nothing else; the walk must give the same stage, the same error
//! and the same fee for every transaction, in both modes, on both sides of the fork, also
//! when several rules are broken at once and the order decides which one answers.
//!
//! The first test does that for a fixed sequence of three thousand transactions with
//! one to three things changed in each. The others pin which DAA score each rule reads
//! when a block is merged by a later block, and the rule order inside a block.

use kaspa_consensus_core::{
    config::params::Params,
    constants::{LOCK_TIME_THRESHOLD, MAX_SOMPI},
    errors::tx::TxRuleError,
    hashing::sighash_type::SIG_HASH_ALL,
    mass::{ComputeBudget, SigopCount},
    subnets::{SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_NATIVE, SubnetworkId},
    tx::{
        ComputeCommit, CovenantBinding, PopulatedTransaction, Transaction, TransactionInput,
        TransactionOutpoint, TransactionOutput, UtxoEntry,
    },
};
use kaspa_hashes::Hash;
use kaspa_txscript_errors::{CovenantsError, TxScriptError};
use node_gate::{
    GateOptions, GateParams, Mode, Stage, block, gate, header, isolation, mass,
    utxo::{self, TxValidationFlags},
    wallet::{TestKey, p2sh_script_public_key, p2sh_signature_script},
};

/// Sompi per KAS.
const KAS: u64 = 100_000_000;
/// How many DAA scores before the point of view the test coins were created.
const COIN_AGE: u64 = 10_000;
/// The fee of the unchanged transaction, in sompi.
const FEE: u64 = 1_000_000;

/// The consensus answer of a node, from the ported functions in the node's order.
#[derive(Debug, PartialEq)]
struct NodeAnswer {
    stage: Stage,
    error: Option<TxRuleError>,
    block_limit_broken: bool,
    fee: Option<u64>,
}

impl NodeAnswer {
    fn refused(stage: Stage, error: TxRuleError) -> Self {
        Self {
            stage,
            error: Some(error),
            block_limit_broken: false,
            fee: None,
        }
    }
}

/// What a node answers for `tx` spending `entries`.
///
/// Block mode: body_validation_in_isolation.rs:17-27 (isolation, then block mass),
/// body_validation_in_context.rs:30-46 (header context at the block's own DAA score),
/// utxo_validation.rs:366-414 (coins, then the UTXO-context validation in full).
/// Submit mode: processor.rs:1216-1233 (isolation, header context at the virtual DAA
/// score), utxo_validation.rs:442-490 (coins, storage mass calculated and written, then
/// the UTXO-context validation without the commitment check).
///
/// The only addition is the split of the last call in two, with and without the script
/// checks, to learn whether a refusal came from the scripts.
fn node_answer(
    gate: &GateParams,
    mode: Mode,
    tx: &Transaction,
    entries: &[UtxoEntry],
) -> NodeAnswer {
    let params: &Params = &gate.params;
    if let Err(error) = isolation::validate_tx_in_isolation(params, tx) {
        return NodeAnswer::refused(Stage::Isolation, error);
    }
    if mode == Mode::Block && block::check_block_mass(gate, tx).is_err() {
        return NodeAnswer {
            stage: Stage::BlockMass,
            error: None,
            block_limit_broken: true,
            fee: None,
        };
    }
    let header_daa_score = match mode {
        Mode::Submit => gate.pov_daa_score,
        Mode::Block => gate.block_daa_score,
    };
    if let Err(error) = header::validate_tx_in_header_context_with_args(
        params,
        tx,
        header_daa_score,
        gate.past_median_time,
    ) {
        return NodeAnswer::refused(Stage::HeaderContext, error);
    }
    if entries.len() < tx.inputs.len() {
        return NodeAnswer::refused(Stage::UtxoPopulation, TxRuleError::MissingTxOutpoints);
    }
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let flags = match mode {
        Mode::Submit => {
            match gate.mass_calculator().calc_contextual_masses(&populated) {
                Some(masses) => tx.set_storage_mass(masses.storage_mass),
                None => {
                    return NodeAnswer::refused(Stage::StorageMass, TxRuleError::MassIncomputable);
                }
            }
            TxValidationFlags::SkipMassCheck
        }
        Mode::Block => TxValidationFlags::Full,
    };
    // On submission the commitment was written a moment ago, so the commitment check in
    // this first call cannot refuse.
    if let Err(error) = utxo::validate_populated_transaction_and_get_fee(
        gate,
        &populated,
        TxValidationFlags::SkipScriptChecks,
    ) {
        return NodeAnswer::refused(Stage::UtxoContext, error);
    }
    match utxo::validate_populated_transaction_and_get_fee(gate, &populated, flags) {
        Ok(fee) => NodeAnswer {
            stage: Stage::Accepted,
            error: None,
            block_limit_broken: false,
            fee: Some(fee),
        },
        Err(error) => NodeAnswer::refused(Stage::Scripts, error),
    }
}

/// Puts the same question to the walk and to `node_answer` and compares. The two get
/// separate copies of the transaction, because both write the storage mass field.
fn compare(
    gate: &GateParams,
    mode: Mode,
    tx: &Transaction,
    entries: &[UtxoEntry],
    context: &str,
) -> NodeAnswer {
    compare_with(
        gate,
        GateOptions {
            mode,
            ..GateOptions::submit()
        },
        tx,
        entries,
        context,
    )
}

/// `compare` with the options of the walk chosen by the caller. Measuring and locating
/// add runs of the engine and must not change the answer.
fn compare_with(
    gate: &GateParams,
    options: GateOptions,
    tx: &Transaction,
    entries: &[UtxoEntry],
    context: &str,
) -> NodeAnswer {
    let mode = options.mode;
    let expected = node_answer(gate, mode, &tx.clone(), entries);
    let evaluation = gate::evaluate(gate, &tx.clone(), entries, options);
    assert_eq!(evaluation.verdict.harness_error, None, "{context}");
    assert_eq!(
        evaluation.verdict.stage_reached, expected.stage,
        "{context}"
    );
    assert_eq!(evaluation.consensus_error, expected.error, "{context}");
    assert_eq!(
        evaluation.block_mass_error.is_some(),
        expected.block_limit_broken,
        "{context}"
    );
    assert_eq!(
        evaluation.verdict.consensus_accepted,
        expected.stage == Stage::Accepted,
        "{context}"
    );
    if expected.stage == Stage::Accepted {
        assert_eq!(evaluation.verdict.fee, expected.fee, "{context}");
    }
    if mode == Mode::Block {
        assert_eq!(
            evaluation.accepted(),
            expected.stage == Stage::Accepted,
            "{context}"
        );
    }
    if expected.stage == Stage::Scripts {
        let refused = evaluation
            .verdict
            .consensus_refusal
            .as_ref()
            .unwrap()
            .input
            .unwrap();
        assert!(
            evaluation.committed_runs[..refused]
                .iter()
                .all(|run| run.is_ok()),
            "{context}"
        );
        assert!(!evaluation.committed_runs[refused].is_ok(), "{context}");
    }
    expected
}

/// A fixed sequence of numbers (xorshift64*). Not random: the same seed gives the same
/// transactions on every run.
struct Sequence(u64);

impl Sequence {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn one_in(&mut self, n: u64) -> bool {
        self.below(n) == 0
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }
}

fn outpoint(tag: u8) -> TransactionOutpoint {
    TransactionOutpoint::new(Hash::from_bytes([tag; 32]), 0)
}

/// The key that owns the coin of input `i`.
fn owner(i: usize) -> TestKey {
    TestKey::from_seed(10 + i as u8)
}

/// Signs every input with the key of its coin.
fn sign(tx: &mut Transaction, entries: &[UtxoEntry]) {
    let scripts: Vec<Vec<u8>> = {
        let populated = PopulatedTransaction::new(tx, entries.to_vec());
        (0..tx.inputs.len())
            .map(|i| owner(i).p2pk_signature_script(&populated, i, SIG_HASH_ALL))
            .collect()
    };
    for (input, script) in tx.inputs.iter_mut().zip(scripts) {
        input.signature_script = script;
    }
}

/// One generated question.
struct Question {
    gate: GateParams,
    mode: Mode,
    tx: Transaction,
    entries: Vec<UtxoEntry>,
    /// What was changed, for the failure message.
    changes: Vec<&'static str>,
}

/// An ordinary transaction - one to three pay-to-pubkey coins of 10 KAS each, one to three
/// outputs, valid for its side of the fork - with one to three things changed. Coins
/// with a zero amount and amounts whose sum overflows are left out: no node holds them
/// and the gate declines the question.
fn question(sequence: &mut Sequence) -> Question {
    let mut changes: Vec<&'static str> = Vec::new();
    let testnet = GateParams::testnet10();
    let activation = testnet.params.toccata_activation.daa_score();
    let mode = if sequence.one_in(2) {
        Mode::Submit
    } else {
        Mode::Block
    };

    let mut gate = match sequence.below(4) {
        0 => testnet.with_daa_score(activation - 1),
        1 => testnet.with_daa_score(activation),
        _ => testnet,
    };
    if mode == Mode::Block && sequence.one_in(3) {
        // The containing block is merged by a later one: maturity and the sequence lock
        // are judged from the later score, the fork side from the block's own.
        gate.pov_daa_score += sequence.pick(&[1, 7, 2 * COIN_AGE]);
        changes.push("merged by a later block");
    }
    let toccata = gate.toccata_active();
    let header_daa_score = if mode == Mode::Submit {
        gate.pov_daa_score
    } else {
        gate.block_daa_score
    };

    let mut version: u16 = if toccata { 1 } else { 0 };
    if sequence.one_in(8) {
        version = sequence.pick(&[0, 1, 2]);
        changes.push("version");
    }

    let input_count = 1 + sequence.below(3) as usize;
    let mut entries: Vec<UtxoEntry> = (0..input_count)
        .map(|i| {
            UtxoEntry::new(
                10 * KAS,
                owner(i).p2pk_script_public_key(),
                gate.pov_daa_score - COIN_AGE,
                false,
                None,
            )
        })
        .collect();
    let mut inputs: Vec<TransactionInput> = (0..input_count)
        .map(|i| {
            if version == 0 {
                TransactionInput::new(outpoint(0xa0 + i as u8), vec![], 0, 1)
            } else {
                TransactionInput::new_with_compute_budget(outpoint(0xa0 + i as u8), vec![], 0, 10)
            }
        })
        .collect();

    // Changes to the inputs and their coins.
    let maturity = gate.params.coinbase_maturity();
    for i in 0..input_count {
        if sequence.one_in(10) {
            inputs[i].compute_commit = sequence.pick(&[
                ComputeCommit::SigopCount(SigopCount(0)),
                ComputeCommit::SigopCount(SigopCount(1)),
                ComputeCommit::SigopCount(SigopCount(2)),
                ComputeCommit::ComputeBudget(ComputeBudget(0)),
                ComputeCommit::ComputeBudget(ComputeBudget(9)),
                ComputeCommit::ComputeBudget(ComputeBudget(10)),
                ComputeCommit::ComputeBudget(ComputeBudget(11)),
            ]);
            changes.push("compute commitment");
        }
        if sequence.one_in(8) {
            inputs[i].sequence = sequence.pick(&[
                1,
                COIN_AGE,
                COIN_AGE + 1,
                u64::MAX,
                (1 << 63) | (COIN_AGE + 1),
                1 << 32,
            ]);
            changes.push("sequence");
        }
        if sequence.one_in(12) {
            entries[i].is_coinbase = true;
            entries[i].block_daa_score =
                gate.pov_daa_score - sequence.pick(&[maturity - 1, maturity, maturity + 1]);
            changes.push("coinbase coin");
        }
        if sequence.one_in(25) {
            entries[i].amount = MAX_SOMPI + 1;
            changes.push("coin above the maximum");
        }
        if sequence.one_in(25) {
            entries[i].covenant_id = Some(Hash::from_bytes([0xc0 + i as u8; 32]));
            changes.push("coin with a covenant id");
        }
    }
    if input_count > 1 && sequence.one_in(25) {
        inputs[1].previous_outpoint = inputs[0].previous_outpoint;
        changes.push("duplicate input");
    }

    // Outputs: the coins minus the fee, split evenly.
    let total_in: u64 = entries.iter().map(|entry| entry.amount).sum();
    let output_count = 1 + sequence.below(3);
    let share = (total_in.min(MAX_SOMPI) - FEE) / output_count;
    let mut outputs: Vec<TransactionOutput> = (0..output_count)
        .map(|i| {
            TransactionOutput::new(
                share,
                TestKey::from_seed(50 + i as u8).p2pk_script_public_key(),
            )
        })
        .collect();
    if sequence.one_in(15) {
        outputs[0].value = sequence.pick(&[0, MAX_SOMPI + 1, share + FEE + 1, share + 2 * KAS]);
        changes.push("output value");
    }
    if version >= 1 && sequence.one_in(12) {
        outputs[0].covenant = Some(match sequence.below(3) {
            0 => CovenantBinding::new(9, Hash::from_bytes([9; 32])),
            1 => CovenantBinding::new(0, Hash::from_bytes([9; 32])),
            _ => CovenantBinding::new(
                0,
                entries[0]
                    .covenant_id
                    .unwrap_or(Hash::from_bytes([0xc0; 32])),
            ),
        });
        changes.push("covenant binding");
    }
    if version == 0 && sequence.one_in(40) {
        outputs[0].covenant = Some(CovenantBinding::new(0, Hash::from_bytes([9; 32])));
        changes.push("covenant binding in version 0");
    }

    // Transaction fields.
    let mut lock_time = 0;
    if sequence.one_in(8) {
        let past_median_time = gate.past_median_time;
        lock_time = sequence.pick(&[
            header_daa_score - 1,
            header_daa_score,
            header_daa_score + 1,
            LOCK_TIME_THRESHOLD - 1,
            LOCK_TIME_THRESHOLD,
            past_median_time - 1,
            past_median_time,
            past_median_time + 1,
        ]);
        changes.push("lock time");
    }
    let mut subnetwork_id = SUBNETWORK_ID_NATIVE;
    if sequence.one_in(15) {
        let mut user_lane = [0u8; 20];
        user_lane[..4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        subnetwork_id = sequence.pick(&[
            SubnetworkId::from_bytes(user_lane),
            SubnetworkId::from_byte(3),
            SUBNETWORK_ID_COINBASE,
        ]);
        changes.push("subnetwork");
    }
    let mut gas = 0;
    if sequence.one_in(15) {
        gas = 1;
        changes.push("gas");
    }

    let mut tx = Transaction::new(
        version,
        inputs,
        outputs,
        lock_time,
        subnetwork_id,
        gas,
        vec![],
    );
    sign(&mut tx, &entries);

    // Changes after signing.
    if sequence.one_in(10) {
        let i = sequence.below(input_count as u64) as usize;
        match sequence.below(3) {
            0 => tx.inputs[i].signature_script.clear(),
            1 => tx.inputs[i].signature_script.push(0x61),
            _ => {
                let populated = PopulatedTransaction::new(&tx, entries.clone());
                let script =
                    TestKey::from_seed(99).p2pk_signature_script(&populated, i, SIG_HASH_ALL);
                tx.inputs[i].signature_script = script;
            }
        }
        changes.push("signature script");
    }

    // In a block the transaction carries the calculated storage mass, unless changed.
    if mode == Mode::Block && isolation::validate_tx_in_isolation(&gate.params, &tx).is_ok() {
        let calculated = mass::calculated_storage_mass(&gate.params, &tx, &entries)
            .unwrap()
            .unwrap();
        tx.set_storage_mass(calculated);
        if sequence.one_in(12) {
            tx.set_storage_mass(calculated + 1);
            changes.push("storage mass commitment");
        }
    }
    if sequence.one_in(20) {
        entries.pop();
        changes.push("missing coin");
    }
    tx.finalize();

    Question {
        gate,
        mode,
        tx,
        entries,
        changes,
    }
}

#[test]
fn the_walk_gives_the_node_answer_for_a_fixed_sequence_of_changed_transactions() {
    let mut sequence = Sequence(0x0123_4567_89ab_cdef);
    let mut reached: std::collections::BTreeMap<Stage, usize> = std::collections::BTreeMap::new();
    let mut errors: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for case in 0..3_000 {
        let question = question(&mut sequence);
        let context = format!(
            "case {case}: {:?} at DAA {}/{}, changed: {:?}",
            question.mode,
            question.gate.pov_daa_score,
            question.gate.block_daa_score,
            question.changes
        );
        // Every fourth question with measuring and locating, the others without.
        let thorough = case % 4 == 0;
        let options = GateOptions {
            mode: question.mode,
            measure_budgets: thorough,
            locate_stops: thorough,
            ..GateOptions::submit()
        };
        let answer = compare_with(
            &question.gate,
            options,
            &question.tx,
            &question.entries,
            &context,
        );
        *reached.entry(answer.stage).or_default() += 1;
        if let Some(error) = &answer.error {
            let text = format!("{error:?}");
            errors.insert(
                text.split(['(', ' '])
                    .next()
                    .unwrap_or_default()
                    .to_string(),
            );
        }
    }

    // The sequence reaches every stage of both modes and most rules.
    for stage in [
        Stage::Isolation,
        Stage::HeaderContext,
        Stage::UtxoPopulation,
        Stage::UtxoContext,
        Stage::Scripts,
        Stage::Accepted,
    ] {
        assert!(
            reached.get(&stage).copied().unwrap_or(0) >= 50,
            "{stage:?}: {reached:?}"
        );
    }
    for rule in [
        "TxOutZero",
        "TxOutTooHigh",
        "TxDuplicateInputs",
        "TxHasGas",
        "SubnetworksDisabled",
        "UnknownTxVersion",
        "SigopCountInV1",
        "ComputeBudgetInV0",
        "CovenantBindingInV0",
        "CoinbaseHasInputs",
        "NotFinalized",
        "MissingTxOutpoints",
        "ImmatureCoinbaseSpend",
        "InputAmountTooHigh",
        "SpendTooHigh",
        "WrongMass",
        "SequenceLockConditionsAreNotMet",
        "CovenantsError",
        "SignatureInvalid",
        "SignatureEmpty",
    ] {
        assert!(
            errors.contains(rule),
            "{rule} was never the answer: {errors:?}"
        );
    }
}

/// A plain version 1 spend of one pay-to-pubkey coin, unsigned.
fn plain(gate: &GateParams) -> (Transaction, Vec<UtxoEntry>) {
    let entries = vec![UtxoEntry::new(
        10 * KAS,
        owner(0).p2pk_script_public_key(),
        gate.pov_daa_score - COIN_AGE,
        false,
        None,
    )];
    let input = TransactionInput::new_with_compute_budget(outpoint(0xa0), vec![], 0, 10);
    let output = TransactionOutput::new(
        10 * KAS - FEE,
        TestKey::from_seed(50).p2pk_script_public_key(),
    );
    (
        Transaction::new(
            1,
            vec![input],
            vec![output],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        ),
        entries,
    )
}

fn commit_storage_mass(gate: &GateParams, tx: &Transaction, entries: &[UtxoEntry]) {
    tx.set_storage_mass(
        mass::calculated_storage_mass(&gate.params, tx, entries)
            .unwrap()
            .unwrap(),
    );
}

/// tx_validation_in_utxo_context.rs:46-62: inside a block the rules answer in this order:
/// maturity, amounts, mass commitment, sequence lock, covenant bindings, scripts.
#[test]
fn rules_inside_a_block_answer_in_the_node_order() {
    let gate = GateParams::testnet10();
    let block = |tx: &Transaction, entries: &[UtxoEntry]| {
        compare(&gate, Mode::Block, tx, entries, "rule order").error
    };

    // Everything wrong at once: a young coinbase coin, outputs above the coin, a wrong
    // commitment, a relative lock not yet passed, a binding with a made-up id, no signature.
    // The rules are then put right one at a time, in the node order.
    let (mut tx, mut entries) = plain(&gate);
    entries[0].is_coinbase = true;
    entries[0].block_daa_score = gate.pov_daa_score - 1;
    tx.outputs[0].value = 11 * KAS;
    tx.inputs[0].sequence = 5;
    tx.outputs[0].covenant = Some(CovenantBinding::new(0, Hash::from_bytes([9; 32])));
    tx.finalize();
    tx.set_storage_mass(77);
    assert!(matches!(
        block(&tx, &entries),
        Some(TxRuleError::ImmatureCoinbaseSpend(..))
    ));

    entries[0].is_coinbase = false;
    assert_eq!(
        block(&tx, &entries),
        Some(TxRuleError::SpendTooHigh(11 * KAS, 10 * KAS))
    );

    tx.outputs[0].value = 10 * KAS - FEE;
    tx.finalize();
    let calculated = mass::calculated_storage_mass(&gate.params, &tx, &entries)
        .unwrap()
        .unwrap();
    assert_eq!(
        block(&tx, &entries),
        Some(TxRuleError::WrongMass(calculated, 77))
    );

    tx.set_storage_mass(calculated);
    assert_eq!(
        block(&tx, &entries),
        Some(TxRuleError::SequenceLockConditionsAreNotMet)
    );

    tx.inputs[0].sequence = 0;
    tx.finalize();
    assert_eq!(
        block(&tx, &entries),
        Some(TxRuleError::CovenantsError(
            CovenantsError::WrongGenesisCovenantId(0, Hash::from_bytes([9; 32]))
        ))
    );

    // Without the binding the output takes one storage unit instead of two
    // (consensus/core/src/mass/mod.rs:83-100), so the commitment made for the bound
    // output is wrong again: the mass rule answers before the scripts are looked at.
    tx.outputs[0].covenant = None;
    tx.finalize();
    let unbound = mass::calculated_storage_mass(&gate.params, &tx, &entries)
        .unwrap()
        .unwrap();
    assert_eq!((calculated, unbound), (3_004, 1));
    assert_eq!(
        block(&tx, &entries),
        Some(TxRuleError::WrongMass(unbound, calculated))
    );

    tx.set_storage_mass(unbound);
    let unsigned = block(&tx, &entries);
    assert!(
        matches!(unsigned, Some(TxRuleError::SignatureEmpty(_))),
        "{unsigned:?}"
    );

    sign(&mut tx, &entries);
    assert_eq!(block(&tx, &entries), None);
}

/// A block merged by a later block: coinbase maturity and the sequence lock are judged
/// from the merging block's DAA score (tx_validation_in_utxo_context.rs:46, 53), not
/// from the score of the block that contains the transaction.
#[test]
fn maturity_and_sequence_lock_read_the_point_of_view_score() {
    let mut gate = GateParams::testnet10();
    gate.block_daa_score = gate.pov_daa_score - 50;
    let maturity = gate.params.coinbase_maturity();
    let consensus = |tx: &Transaction, entries: &[UtxoEntry]| {
        commit_storage_mass(&gate, tx, entries);
        compare(&gate, Mode::Block, tx, entries, "point of view").error
    };

    // A coinbase coin exactly mature from the point of view; from the block's own score
    // it would be fifty scores short.
    let (mut tx, mut entries) = plain(&gate);
    entries[0].is_coinbase = true;
    entries[0].block_daa_score = gate.pov_daa_score - maturity;
    sign(&mut tx, &entries);
    assert_eq!(consensus(&tx, &entries), None);
    // One score younger: refused, and the error carries the point of view score.
    entries[0].block_daa_score += 1;
    sign(&mut tx, &entries);
    assert_eq!(
        consensus(&tx, &entries),
        Some(TxRuleError::ImmatureCoinbaseSpend(
            0,
            outpoint(0xa0),
            gate.pov_daa_score - maturity + 1,
            gate.pov_daa_score,
            maturity
        ))
    );

    // A relative lock that has just passed from the point of view.
    let (mut tx, entries) = plain(&gate);
    tx.inputs[0].sequence = COIN_AGE;
    sign(&mut tx, &entries);
    assert_eq!(consensus(&tx, &entries), None);
    tx.inputs[0].sequence = COIN_AGE + 1;
    sign(&mut tx, &entries);
    assert_eq!(
        consensus(&tx, &entries),
        Some(TxRuleError::SequenceLockConditionsAreNotMet)
    );
}

/// The fork side of the script engine is the containing block's
/// (tx_validation_in_utxo_context.rs:171 reads `block_daa_score`), also when the block is
/// merged after activation. `OpCat` is disabled before Toccata and works after it.
#[test]
fn the_engine_flags_follow_the_containing_block_exactly_at_activation() {
    let testnet = GateParams::testnet10();
    let activation = testnet.params.toccata_activation.daa_score();
    // push "a", push "b", OpCat, push "ab", OpEqual
    let redeem_script = [0x01, 0x61, 0x01, 0x62, 0x7e, 0x02, 0x61, 0x62, 0x87];
    let spend = |gate: &GateParams| {
        // A version 0 transaction is valid on both sides of the fork.
        let entries = vec![UtxoEntry::new(
            10 * KAS,
            p2sh_script_public_key(&redeem_script),
            gate.pov_daa_score - COIN_AGE,
            false,
            None,
        )];
        let input = TransactionInput::new(
            outpoint(0xb0),
            p2sh_signature_script(&[], &redeem_script),
            0,
            0,
        );
        let output = TransactionOutput::new(
            10 * KAS - FEE,
            TestKey::from_seed(50).p2pk_script_public_key(),
        );
        let tx = Transaction::new(
            0,
            vec![input],
            vec![output],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        );
        commit_storage_mass(gate, &tx, &entries);
        (tx, entries)
    };
    let disabled = |error: Option<TxRuleError>| {
        matches!(
            error,
            Some(TxRuleError::SignatureInvalid(
                TxScriptError::OpcodeDisabled(_)
            ))
        )
    };

    for mode in [Mode::Submit, Mode::Block] {
        let before = testnet.clone().with_daa_score(activation - 1);
        let (tx, entries) = spend(&before);
        assert!(disabled(
            compare(&before, mode, &tx, &entries, "one score before activation").error
        ));

        let at = testnet.clone().with_daa_score(activation);
        let (tx, entries) = spend(&at);
        assert_eq!(
            compare(&at, mode, &tx, &entries, "at activation").error,
            None
        );
    }

    // Contained in the last block before activation, merged a hundred scores later.
    let mut merged_later = testnet.clone().with_daa_score(activation - 1);
    merged_later.pov_daa_score = activation + 100;
    let (tx, entries) = spend(&merged_later);
    assert!(disabled(
        compare(
            &merged_later,
            Mode::Block,
            &tx,
            &entries,
            "merged after activation"
        )
        .error
    ));
}

/// The covenant context the scripts see is built by the engine crate itself
/// (`CovenantsContext::from_tx`, crypto/txscript/src/covenants.rs:101-163); the port only
/// decides by the fork whether it is built at all (tx_validation_in_utxo_context.rs:177-183).
/// Three shapes from upstream's own tests (covenants.rs:289-305, 307-317, 357-389): a new
/// covenant leaves the context empty, a made-up id is refused, a continued one fills it.
#[test]
fn covenant_info_follows_the_fork_and_carries_the_engine_context() {
    let after = GateParams::testnet10();
    let before = after
        .clone()
        .with_daa_score(after.params.toccata_activation.daa_score() - 1);
    let carried = Hash::from_bytes([0xc7; 32]);
    let bound = |tx: &mut Transaction, id: Hash| {
        let script_public_key = tx.outputs[0].script_public_key.clone();
        tx.outputs = vec![
            TransactionOutput::with_covenant(
                4 * KAS,
                script_public_key.clone(),
                Some(CovenantBinding::new(0, id)),
            ),
            TransactionOutput::with_covenant(
                5 * KAS,
                script_public_key,
                Some(CovenantBinding::new(0, id)),
            ),
        ];
        tx.finalize();
    };

    // A new covenant with the id derived from the outpoint and the two outputs.
    let (mut tx, entries) = plain(&after);
    bound(&mut tx, carried);
    let derived = kaspa_consensus_core::hashing::covenant_id::covenant_id(
        tx.inputs[0].previous_outpoint,
        tx.outputs
            .iter()
            .enumerate()
            .map(|(i, output)| (i as u32, output)),
    );
    bound(&mut tx, derived);
    let populated = PopulatedTransaction::new(&tx, entries.clone());
    let context = utxo::check_covenant_info(&after, &populated, after.block_daa_score).unwrap();
    assert!(context.input_ctxs.is_empty() && context.shared_ctxs.is_empty());

    // The same outputs with an id that is not the derived one.
    bound(&mut tx, carried);
    let populated = PopulatedTransaction::new(&tx, entries.clone());
    assert_eq!(
        utxo::check_covenant_info(&after, &populated, after.block_daa_score).err(),
        Some(TxRuleError::CovenantsError(
            CovenantsError::WrongGenesisCovenantId(0, carried)
        ))
    );
    // Before Toccata nothing is looked at and the context is empty.
    let context = utxo::check_covenant_info(&before, &populated, before.block_daa_score).unwrap();
    assert!(context.input_ctxs.is_empty() && context.shared_ctxs.is_empty());
    // The score that is passed decides, not the scores of the gate.
    assert!(utxo::check_covenant_info(&before, &populated, after.block_daa_score).is_err());

    // The coin carries the id: a continuation. Both outputs are the input's own and the
    // covenant's.
    let mut continued = entries.clone();
    continued[0].covenant_id = Some(carried);
    let populated = PopulatedTransaction::new(&tx, continued);
    let context = utxo::check_covenant_info(&after, &populated, after.block_daa_score).unwrap();
    assert_eq!(context.input_ctxs.len(), 1);
    assert_eq!(context.input_ctxs[&0].auth_outputs, vec![0, 1]);
    assert_eq!(context.shared_ctxs.len(), 1);
    assert_eq!(context.shared_ctxs[&carried].input_indices, vec![0]);
    assert_eq!(context.shared_ctxs[&carried].output_indices, vec![0, 1]);
}

/// The price of a signature check is the `mass_per_sig_op` of the network parameters
/// (tx_validation_in_utxo_context.rs:172). It is 1000 grams on every network, the same
/// number `EngineFlags::default()` carries, so only a changed parameter can show where
/// the price is read from.
#[test]
fn the_price_of_a_signature_check_comes_from_the_parameters() {
    let exceeded = |used: u64, limit: u64| {
        Some(TxRuleError::SignatureInvalid(
            TxScriptError::ExceededCommittedScriptUnits { used, limit },
        ))
    };

    let mut half_price = GateParams::testnet10();
    half_price.params.mass_per_sig_op = 500;
    assert_eq!(half_price.engine_flags().sigop_script_units.0, 50_000);
    let (mut tx, entries) = plain(&half_price);
    sign(&mut tx, &entries);

    // A budget of five allows 59,999 units: enough for one check at 50,000.
    tx.inputs[0].compute_commit = ComputeBudget(5).into();
    assert_eq!(
        compare(
            &half_price,
            Mode::Submit,
            &tx,
            &entries,
            "half price, budget 5"
        )
        .stage,
        Stage::Accepted
    );
    // A budget of four allows 49,999.
    tx.inputs[0].compute_commit = ComputeBudget(4).into();
    assert_eq!(
        compare(
            &half_price,
            Mode::Submit,
            &tx,
            &entries,
            "half price, budget 4"
        )
        .error,
        exceeded(50_000, 49_999)
    );

    // At the real price the budget of five is far too small.
    let real_price = GateParams::testnet10();
    tx.inputs[0].compute_commit = ComputeBudget(5).into();
    assert_eq!(
        compare(
            &real_price,
            Mode::Submit,
            &tx,
            &entries,
            "real price, budget 5"
        )
        .error,
        exceeded(100_000, 59_999)
    );
}

/// A coin created by a transaction that is still in the mempool carries the DAA score
/// `u64::MAX` (rusty-kaspa a41a333 consensus/core/src/constants.rs:54-56,
/// mining/src/mempool/model/utxo_set.rs:46). The sequence lock casts it to a signed
/// number (tx_validation_in_utxo_context.rs:153), which makes it -1: a relative lock on
/// such a coin is measured from before the first block. The port keeps that.
#[test]
fn the_sequence_lock_of_a_coin_that_is_not_in_a_block_yet() {
    let gate = GateParams::testnet10();
    let lock = |sequence: u64| {
        let (mut tx, mut entries) = plain(&gate);
        entries[0].block_daa_score = u64::MAX;
        tx.inputs[0].sequence = sequence;
        utxo::check_sequence_lock(&PopulatedTransaction::new(&tx, entries), gate.pov_daa_score)
    };
    assert_eq!(lock(0), Ok(()));
    assert_eq!(lock(1_000), Ok(()));
    // -1 + lock - 1 >= point of view, from a lock of point of view + 2 on. The low 32
    // bits hold the lock and the testnet score fits in them.
    assert!(gate.pov_daa_score + 2 <= u32::MAX as u64);
    assert_eq!(lock(gate.pov_daa_score + 1), Ok(()));
    assert_eq!(
        lock(gate.pov_daa_score + 2),
        Err(TxRuleError::SequenceLockConditionsAreNotMet)
    );

    // The whole walk for such a coin, as when a transaction spends the output of another
    // one that is still in the mempool: the consensus rules accept it.
    let (mut tx, mut entries) = plain(&gate);
    entries[0].block_daa_score = u64::MAX;
    sign(&mut tx, &entries);
    assert_eq!(
        compare(
            &gate,
            Mode::Submit,
            &tx,
            &entries,
            "coin of a pooled transaction"
        )
        .stage,
        Stage::Accepted
    );
}

/// Before Toccata the engine does not meter script units at all, and the limit it holds
/// an input to is the committed signature operation count whatever limit it is handed
/// (rusty-kaspa a41a333 crypto/txscript/src/lib.rs:542-546). A run that is to measure
/// the input must not be stopped by that commitment, and a budget cannot be read off it.
/// The gate therefore hands the engine, for the run "without a limit", a copy of the input
/// that commits to the largest count, and reads no budget off a run that metered no script
/// unit: the measuring run is not stopped by the commitment, and the verdict carries no
/// `minimal_budget`.
#[test]
fn before_toccata_the_measuring_run_measures_no_budget() {
    let testnet = GateParams::testnet10();
    let gate = testnet
        .clone()
        .with_daa_score(testnet.params.toccata_activation.daa_score() - 1);
    let spend = |sig_op_count: u8| {
        let entries = vec![UtxoEntry::new(
            10 * KAS,
            owner(0).p2pk_script_public_key(),
            gate.pov_daa_score - COIN_AGE,
            false,
            None,
        )];
        let input = TransactionInput::new(outpoint(0xa0), vec![], 0, sig_op_count);
        let output = TransactionOutput::new(
            10 * KAS - FEE,
            TestKey::from_seed(50).p2pk_script_public_key(),
        );
        let mut tx = Transaction::new(
            0,
            vec![input],
            vec![output],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        );
        sign(&mut tx, &entries);
        gate::evaluate(&gate, &tx, &entries, GateOptions::submit())
    };

    // One signature check, one committed operation: accepted. No script unit was
    // metered, so no budget is known; zero would be wrong after the fork, where the
    // same input needs ten units.
    let committed_one = spend(1);
    assert!(committed_one.verdict.consensus_accepted);
    assert_eq!(committed_one.measured_runs[0].used_script_units, 0);
    let reported_budget = committed_one.verdict.inputs[0].minimal_budget;

    // No committed operation: the node refuses, and the run that is meant to measure
    // the input without a limit should not be stopped by that same limit.
    let committed_none = spend(0);
    assert_eq!(
        committed_none.committed_runs[0].result,
        Err(TxScriptError::ExceededSigOpLimit(0))
    );
    let measuring_run = committed_none.measured_runs[0].result.clone();

    assert_eq!((reported_budget, measuring_run), (None, Ok(())));

    // What the runs say instead of a script-unit limit: the signature operation count
    // the engine applied, and the count the input needs.
    let committed = &committed_none.committed_runs[0];
    let measured = &committed_none.measured_runs[0];
    assert_eq!(
        (committed.script_units_limit, committed.sig_op_limit),
        (None, Some(0))
    );
    assert_eq!(
        (
            measured.script_units_limit,
            measured.sig_op_limit,
            measured.used_sig_ops
        ),
        (None, Some(u8::MAX), 1)
    );
    assert_eq!(committed_none.verdict.inputs[0].minimal_budget, None);
}
