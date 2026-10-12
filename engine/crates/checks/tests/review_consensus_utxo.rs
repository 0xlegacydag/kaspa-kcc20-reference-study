//! Upstream's own unit tests of the UTXO-context rules and of the script loop, re-run
//! against the ports in `node_gate::utxo`, against `node_gate::engine::ScriptRunner` and
//! against `gate::evaluate`.
//!
//! What is upstream's: every transaction, every byte vector, the key of the budget tests
//! and every expected result of the tests that keep upstream's names. They are taken from
//! rusty-kaspa, revision a41a333,
//! consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs:229-1140
//! (ISC License, Copyright (c) 2022-2024 Kaspa developers); the lines of each test are
//! given at the test.
//!
//! Two of upstream's transactions come with signatures that were not made for a test:
//! upstream's file names, in a comment, the id of the transaction each was taken from
//! (lines 595 and 675). They are called the mainnet transactions here and are run, as
//! upstream runs them, under the mainnet parameters. That makes them a check of the whole
//! path - sighash, engine flags, limits - that a transaction signed inside a test cannot
//! give. They are upstream's test vectors, read offline from upstream's source. Nothing
//! here is sent anywhere: every test validates in memory.
//!
//! What is not upstream's:
//!
//! * the signing: upstream signs with `kaspa_consensus_core::sign::sign`, whose Schnorr
//!   signatures use auxiliary randomness; here the same steps are done without it
//!   (`sign_all_inputs`), so that the bytes repeat;
//! * the key of `test_sign`: upstream draws a random key; here the key is fixed;
//! * the assertions about the place a run stopped at and about the units it used, an
//!   error pinned where upstream asserts no more than a failure (said at the place), the
//!   questions put to `gate::evaluate`, and the two tests `the_gate_accepts_the_mainnet_*`,
//!   which reuse upstream's two transactions.
//!
//! Upstream runs transactions with more than one input on a thread pool. The gate runs
//! the inputs in order. In every upstream case all failing inputs fail alike, so the
//! expected error is the same.

use std::str::FromStr;

use kaspa_consensus_core::{
    config::params::{ForkActivation, MAINNET_PARAMS},
    errors::tx::TxRuleError,
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    mass::{
        ComputeBudget, GRAMS_PER_COMPUTE_BUDGET_UNIT, SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT,
        SigopCount, free_script_units_per_input,
    },
    subnets::SubnetworkId,
    tx::{
        ComputeCommit, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId,
        TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
    },
};
use kaspa_txscript::{
    EngineCtx, EngineFlags, SigCacheKey,
    caches::Cache,
    covenants::CovenantsContext,
    opcodes::codes::{OpCheckSig, OpCheckSigVerify, OpDrop, OpDup},
    script_builder::ScriptBuilder,
    standard::{pay_to_script_hash_script, pay_to_script_hash_signature_script},
};
use kaspa_txscript_errors::TxScriptError;
use node_gate::{
    GateOptions, GateParams, ScriptKind, ScriptRun, ScriptRunner, Stage, StopPoint,
    engine::OpcodeStop,
    gate, mass,
    policy::Priority,
    utxo::{self, TxValidationFlags},
};
use secp256k1::{Keypair, Message, SECP256K1};

/// `assert!(matches!(..))` that prints the value on failure.
macro_rules! assert_matches {
    ($value:expr, $pattern:pat $(if $guard:expr)? $(,)?) => {{
        let value = $value;
        assert!(
            matches!(value, $pattern $(if $guard)?),
            "{:?} does not match {}",
            value,
            stringify!($pattern)
        );
    }};
}

fn hex(text: &str) -> Vec<u8> {
    let mut bytes = vec![0u8; text.len() / 2];
    faster_hex::hex_decode(text.as_bytes(), &mut bytes).expect("an even number of hex digits");
    bytes
}

fn native() -> SubnetworkId {
    SubnetworkId::from_bytes([0; 20])
}

/// Mainnet at DAA score zero: before Toccata, the side of the fork upstream's
/// `TransactionValidator::new_for_tests` is on (its activation is `never`, mod.rs:84).
fn mainnet_before_toccata() -> GateParams {
    GateParams {
        params: MAINNET_PARAMS.clone(),
        pov_daa_score: 0,
        block_daa_score: 0,
        past_median_time: 0,
    }
}

/// Mainnet with Toccata active from the start, at DAA score zero
/// (tx_validation_in_utxo_context.rs:351-363).
fn mainnet_always_toccata() -> GateParams {
    let mut params = MAINNET_PARAMS.clone();
    params.toccata_activation = ForkActivation::always();
    GateParams {
        params,
        pov_daa_score: 0,
        block_daa_score: 0,
        past_median_time: 0,
    }
}

/// tx_validation_in_utxo_context.rs:261-267.
fn duplicate_input(tx: &Transaction, entries: &[UtxoEntry]) -> (Transaction, Vec<UtxoEntry>) {
    let mut tx2 = tx.clone();
    let mut entries2 = entries.to_owned();
    tx2.inputs.push(tx2.inputs.last().unwrap().clone());
    entries2.push(entries2.last().unwrap().clone());
    (tx2, entries2)
}

/// The steps of `kaspa_consensus_core::sign::sign` (rusty-kaspa a41a333
/// consensus/core/src/sign.rs:83-103) without auxiliary randomness: every input gets the
/// compute commitment of one signature check and a signature script of one push,
/// `OpData65 <64-byte Schnorr signature> <SIG_HASH_ALL>`.
fn sign_all_inputs(tx: &mut Transaction, entries: &[UtxoEntry], key: &Keypair) {
    let commitment: ComputeCommit =
        if ComputeCommit::version_expects_compute_budget_field(tx.version) {
            ComputeBudget(10).into()
        } else {
            SigopCount(1).into()
        };
    for input in tx.inputs.iter_mut() {
        input.compute_commit = commitment;
    }
    let mut signature_scripts = Vec::with_capacity(tx.inputs.len());
    {
        let populated = PopulatedTransaction::new(tx, entries.to_vec());
        let reused_values = SigHashReusedValuesUnsync::new();
        for i in 0..tx.inputs.len() {
            let sig_hash = calc_schnorr_signature_hash(&populated, i, SIG_HASH_ALL, &reused_values);
            let message = Message::from_digest(sig_hash.as_bytes());
            let signature = SECP256K1.sign_schnorr_no_aux_rand(&message, key);
            let mut script = vec![65u8];
            script.extend_from_slice(signature.as_ref());
            script.push(SIG_HASH_ALL.to_u8());
            signature_scripts.push(script);
        }
    }
    for (input, script) in tx.inputs.iter_mut().zip(signature_scripts) {
        input.signature_script = script;
    }
}

/// The key of upstream's budget tests (tx_validation_in_utxo_context.rs:365, 441).
fn key_of_sevens() -> Keypair {
    Keypair::from_seckey_slice(SECP256K1, &[7u8; 32]).unwrap()
}

/// The runs of `ScriptRunner` under the committed limits, with the given flags and an
/// empty covenant context, turned into the node's answer: the first failure, wrapped the
/// way `map_script_err` wraps it.
fn runner_answer(
    tx: &Transaction,
    entries: &[UtxoEntry],
    flags: EngineFlags,
) -> (Result<(), TxRuleError>, Vec<ScriptRun>) {
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let covenants = CovenantsContext::default();
    let runs = ScriptRunner::new(&populated, &covenants, flags).run_all_committed(true);
    let answer = match runs
        .iter()
        .find_map(|run| run.error().map(|error| (run.input_index, error.clone())))
    {
        Some((input, error)) => Err(utxo::map_script_err(error, &tx.inputs[input])),
        None => Ok(()),
    };
    (answer, runs)
}

/// The script verdict of the ported node loop (`utxo::check_scripts`) for a gate before
/// Toccata, checked against the runner on the way. Returns the answer and the runs.
fn check_scripts(
    gate: &GateParams,
    tx: &Transaction,
    entries: &[UtxoEntry],
) -> (Result<(), TxRuleError>, Vec<ScriptRun>) {
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let ported = utxo::check_scripts(
        gate,
        &populated,
        CovenantsContext::default(),
        gate.block_daa_score,
    );
    let (by_runner, runs) = runner_answer(tx, entries, gate.engine_flags());
    assert_eq!(
        ported, by_runner,
        "the ported script loop and the runner disagree"
    );
    (ported, runs)
}

fn opcode_stop(
    script: ScriptKind,
    op_index: usize,
    byte_offset: usize,
    opcode: u8,
    name: &str,
    executed: bool,
) -> Option<StopPoint> {
    Some(StopPoint::Opcode(OpcodeStop {
        script,
        op_index,
        byte_offset,
        opcode,
        opcode_name: Some(name.to_string()),
        executed,
    }))
}

/// tx_validation_in_utxo_context.rs:269-315. Inputs whose script exceeds the free
/// per-input allowance but fits in one compute-budget unit.
fn build_parallel_push_budget_test_tx(num_inputs: usize) -> (Transaction, Vec<UtxoEntry>) {
    let covenant_flags = EngineFlags {
        covenants_enabled: true,
        ..Default::default()
    };
    let signature_prefix = ScriptBuilder::with_flags(covenant_flags)
        .add_data(&vec![1u8; SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT as usize])
        .unwrap()
        .drain();
    let redeem_script = ScriptBuilder::with_flags(covenant_flags)
        .add_op(OpDup)
        .unwrap()
        .add_op(OpDrop)
        .unwrap()
        .drain();
    let script_public_key = pay_to_script_hash_script(&redeem_script);
    let outputs = vec![TransactionOutput {
        value: 1,
        script_public_key: ScriptPublicKey::from_vec(0, vec![0x51]),
        covenant: None,
    }];

    let inputs: Vec<TransactionInput> = (0..num_inputs)
        .map(|i| TransactionInput {
            previous_outpoint: TransactionOutpoint {
                transaction_id: TransactionId::from_bytes([(i as u8).wrapping_add(1); 32]),
                index: 0,
            },
            signature_script: pay_to_script_hash_signature_script(
                redeem_script.clone(),
                signature_prefix.clone(),
            )
            .expect("the script is canonical"),
            sequence: 0,
            compute_commit: ComputeCommit::ComputeBudget(1.into()),
        })
        .collect();

    let entries: Vec<UtxoEntry> = (0..num_inputs)
        .map(|_| UtxoEntry {
            amount: 1,
            script_public_key: script_public_key.clone(),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        })
        .collect();

    (
        Transaction::new(1, inputs, outputs, 0, SubnetworkId::default(), 0, vec![]),
        entries,
    )
}

/// tx_validation_in_utxo_context.rs:317-346.
#[test]
fn check_scripts_parallel_budget_behavior() {
    let sig_cache: Cache<SigCacheKey, bool> = Cache::new(10_000);
    let flags = EngineFlags {
        covenants_enabled: true,
        ..Default::default()
    };
    let sequential = |tx: &Transaction, entries: &[UtxoEntry]| {
        let populated = PopulatedTransaction::new(tx, entries.to_vec());
        let reused_values = SigHashReusedValuesUnsync::new();
        let ported = utxo::check_scripts_sequential(
            &populated,
            EngineCtx::new(&sig_cache).with_reused(&reused_values),
            flags,
        );
        let (by_runner, runs) = runner_answer(tx, entries, flags);
        assert_eq!(
            ported, by_runner,
            "the ported script loop and the runner disagree"
        );
        (ported, runs)
    };

    // (a) One input alone is over budget when compute_budget=0 (allowed units per input = 9999).
    let (mut tx, entries) = build_parallel_push_budget_test_tx(2);
    tx.inputs[0].compute_commit = ComputeBudget(0).into();
    let (result, runs) = sequential(&tx, &entries);
    let free = free_script_units_per_input().0;
    assert_matches!(
        result,
        Err(TxRuleError::SignatureInvalid(
            TxScriptError::ExceededCommittedScriptUnits { limit, .. }
        )) if limit == free
    );
    // The charge that does not fit is the copy made by OpDup, the first opcode of the
    // redeem script; the second input, with a budget of one unit, passes.
    assert_eq!(
        runs[0].stop,
        opcode_stop(ScriptKind::RedeemScript, 0, 0, OpDup, "OpDup", true)
    );
    assert_eq!(runs[1].result, Ok(()));

    // (b) A few inputs together are all independently under budget and should pass.
    let (mut tx, entries) = build_parallel_push_budget_test_tx(3);
    tx.inputs
        .iter_mut()
        .for_each(|input| input.compute_commit = ComputeBudget(1).into());
    sequential(&tx, &entries).0.expect("should succeed");

    // (c) Everything is ok with a larger per-input budget as well.
    let (mut tx, entries) = build_parallel_push_budget_test_tx(3);
    tx.inputs
        .iter_mut()
        .for_each(|input| input.compute_commit = ComputeBudget(10).into());
    let (result, runs) = sequential(&tx, &entries);
    result.expect("should succeed");
    // The need does not depend on the budget: every input used the same units as under
    // a budget of one, which is more than the free allowance and at most one unit.
    for run in &runs {
        assert!(
            run.used_script_units > free_script_units_per_input().0,
            "{}",
            run.used_script_units
        );
        assert!(
            run.used_script_units
                <= ComputeCommit::ComputeBudget(1.into())
                    .allowed_script_units()
                    .0
        );
        assert_eq!(run.covering_budget(), Some(ComputeBudget(1)));
    }

    // The node's flags for a network with Toccata active are the flags of this test.
    let (tx, entries) = build_parallel_push_budget_test_tx(2);
    let gate = mainnet_always_toccata();
    assert!(gate.engine_flags().covenants_enabled);
    assert_eq!(
        gate.engine_flags().sigop_script_units.0,
        flags.sigop_script_units.0
    );
    let populated = PopulatedTransaction::new(&tx, entries.clone());
    assert_eq!(
        utxo::check_scripts(&gate, &populated, CovenantsContext::default(), 0),
        Ok(())
    );
}

/// The script of upstream's two budget tests: two signature checks of one signature.
fn two_sigops_script(key: &Keypair, verify_first: bool) -> Vec<u8> {
    let (x_only_pubkey, _) = key.x_only_public_key();
    let builder = &mut ScriptBuilder::new();
    builder
        .add_op(OpDup)
        .unwrap()
        .add_data(&x_only_pubkey.serialize())
        .unwrap();
    if verify_first {
        builder.add_op(OpCheckSigVerify).unwrap();
    } else {
        builder.add_op(OpCheckSig).unwrap().add_op(OpDrop).unwrap();
    }
    builder
        .add_data(&x_only_pubkey.serialize())
        .unwrap()
        .add_op(OpCheckSig)
        .unwrap()
        .drain()
}

/// tx_validation_in_utxo_context.rs:348-430.
#[test]
fn validate_populated_transaction_sigop_budget_enforced_for_v0_and_v1_with_covenants_enabled() {
    let gate = mainnet_always_toccata();
    let schnorr_key = key_of_sevens();
    // OpDup <key> OpCheckSig OpDrop <key> OpCheckSig
    let script = two_sigops_script(&schnorr_key, false);
    assert_eq!(script.len(), 70);

    for version in [0u16, 1u16] {
        let sig_op_count = if version == 0 { 1 } else { 0 };
        let compute_budget = if version == 1 {
            (gate.params.mass_per_sig_op / GRAMS_PER_COMPUTE_BUDGET_UNIT) as u16
        } else {
            0
        };

        let input = TransactionInput {
            previous_outpoint: TransactionOutpoint {
                transaction_id: TransactionId::from_bytes([version as u8 + 1; 32]),
                index: 0,
            },
            signature_script: vec![],
            sequence: 0,
            compute_commit: if ComputeCommit::version_expects_compute_budget_field(version) {
                ComputeCommit::ComputeBudget(compute_budget.into())
            } else {
                ComputeCommit::SigopCount(sig_op_count.into())
            },
        };
        let output = TransactionOutput {
            value: 1,
            script_public_key: ScriptPublicKey::from_vec(0, vec![0x51]),
            covenant: None,
        };
        let mut tx = Transaction::new(
            version,
            vec![input],
            vec![output],
            0,
            SubnetworkId::default(),
            0,
            vec![],
        );
        let entries = vec![UtxoEntry {
            amount: 1,
            script_public_key: ScriptPublicKey::from_vec(0, script.clone()),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        }];
        sign_all_inputs(&mut tx, &entries, &schnorr_key);

        // Verify that signing didn't change the sig_op_count and compute_budget values.
        assert_eq!(
            tx.inputs[0].compute_commit.sig_op_count().unwrap_or(0),
            sig_op_count
        );
        assert_eq!(
            tx.inputs[0].compute_commit.compute_budget().unwrap_or(0),
            compute_budget
        );

        let populated = PopulatedTransaction::new(&tx, entries.clone());
        let result = utxo::validate_populated_transaction_and_get_fee(
            &gate,
            &populated,
            TxValidationFlags::SkipMassCheck,
        );
        assert_matches!(
            &result,
            Err(TxRuleError::SignatureInvalid(
                TxScriptError::ExceededCommittedScriptUnits { .. }
            ))
        );

        // Both commitments allow 109,999 units. The script is 35 bytes longer than a
        // standard one (3,500 units up front); the first check costs 100,000, the second
        // does not fit. It is opcode 5 of the script public key, at byte 69.
        let (by_runner, runs) = runner_answer(&tx, &entries, gate.engine_flags());
        assert_eq!(
            by_runner.as_ref().err(),
            result.as_ref().err(),
            "tx version {version}"
        );
        assert_eq!(runs[0].script_units_limit, Some(109_999));
        assert_eq!(runs[0].used_sig_ops, 1);
        assert_eq!(
            runs[0].stop,
            opcode_stop(
                ScriptKind::ScriptPublicKey,
                5,
                69,
                OpCheckSig,
                "OpCheckSig",
                true
            )
        );

        // The walk of the gate stops at the scripts with the same error.
        let evaluation = gate::evaluate(&gate, &tx, &entries, GateOptions::submit());
        assert_eq!(evaluation.verdict.harness_error, None);
        assert_eq!(evaluation.verdict.stage_reached, Stage::Scripts);
        assert_eq!(
            evaluation.consensus_error.as_ref(),
            result.as_ref().err(),
            "tx version {version}"
        );
    }
}

/// tx_validation_in_utxo_context.rs:432-502. A version 0 input committing one signature
/// operation: two checks exceed the count before Toccata, and fit after it when a check
/// is priced at 5,000 script units.
#[test]
fn check_scripts_v0_sigop_count_input_fails_by_default_and_succeeds_with_5000_sigop_script_units() {
    let sig_cache: Cache<SigCacheKey, bool> = Cache::new(10_000);
    let schnorr_key = key_of_sevens();
    // OpDup <key> OpCheckSigVerify <key> OpCheckSig
    let script = two_sigops_script(&schnorr_key, true);

    let mut tx = Transaction::new(
        0,
        vec![TransactionInput {
            previous_outpoint: TransactionOutpoint {
                transaction_id: TransactionId::from_bytes([11u8; 32]),
                index: 0,
            },
            signature_script: vec![],
            sequence: 0,
            compute_commit: ComputeCommit::SigopCount(1.into()),
        }],
        vec![TransactionOutput {
            value: 1,
            script_public_key: ScriptPublicKey::from_vec(0, vec![0x51]),
            covenant: None,
        }],
        0,
        SubnetworkId::default(),
        0,
        vec![],
    );
    let entries = vec![UtxoEntry {
        amount: 1,
        script_public_key: ScriptPublicKey::from_vec(0, script),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    }];
    sign_all_inputs(&mut tx, &entries, &schnorr_key);
    assert_eq!(tx.version, 0);
    assert_eq!(tx.inputs[0].compute_commit.sig_op_count().unwrap_or(0), 1);

    let run_with = |flags: EngineFlags| {
        let populated = PopulatedTransaction::new(&tx, entries.clone());
        let reused_values = SigHashReusedValuesUnsync::new();
        let ported = utxo::check_scripts_sequential(
            &populated,
            EngineCtx::new(&sig_cache).with_reused(&reused_values),
            flags,
        );
        let (by_runner, runs) = runner_answer(&tx, &entries, flags);
        assert_eq!(
            ported, by_runner,
            "the ported script loop and the runner disagree"
        );
        (ported, runs)
    };

    let (result, runs) = run_with(EngineFlags::default());
    assert_eq!(
        result,
        Err(TxRuleError::SignatureInvalid(
            TxScriptError::ExceededSigOpLimit(1)
        ))
    );
    // The second check, opcode 4 of the script public key at byte 68, is the one refused.
    assert_eq!(
        runs[0].stop,
        opcode_stop(
            ScriptKind::ScriptPublicKey,
            4,
            68,
            OpCheckSig,
            "OpCheckSig",
            true
        )
    );
    assert_eq!((runs[0].used_sig_ops, runs[0].used_script_units), (1, 0));

    let (result, runs) = run_with(EngineFlags {
        covenants_enabled: true,
        sigop_script_units: 5_000.into(),
    });
    assert_eq!(result, Ok(()));
    assert_eq!(runs[0].used_sig_ops, 2);
}

/// The mainnet transaction of `check_signature_test` and `check_incorrect_signature_test`:
/// one Schnorr pay-to-pubkey coin spent to two outputs. With `spend_own_coin` the spent coin
/// carries the key the signature was made for; without it, the key of the other output.
fn mainnet_p2pk_spend(spend_own_coin: bool) -> (Transaction, Vec<UtxoEntry>) {
    let prev_tx_id =
        TransactionId::from_str("746915c8dfc5e1550eacbe1d87625a105750cf1a65aaddd1baa60f8bcf7e953c")
            .unwrap();
    let signature_script = hex(concat!(
        "4176cf2ee56b3eed1e8da083851f41cae11532fc70a63ca1ca9f17bc9a4c2fd3d",
        "cdf60df1c1a57465f0d112995a6f289511c8e0a79c806fb79165544a439d11c0201",
    ));
    let script_pub_key_1 =
        hex("20e1d5835e09f3c3dad209debcb7b3bf3fb0e0d9642471f5db36c9ea58338b06beac");
    let script_pub_key_2 =
        hex("200749c89953b463d1e186a16a941f9354fa3fff313c391149e47961b95dd4df28ac");

    let tx = Transaction::new(
        0,
        vec![TransactionInput {
            previous_outpoint: TransactionOutpoint {
                transaction_id: prev_tx_id,
                index: 1,
            },
            signature_script,
            sequence: 0,
            compute_commit: ComputeCommit::SigopCount(1.into()),
        }],
        vec![
            TransactionOutput {
                value: 10360487799,
                script_public_key: ScriptPublicKey::from_vec(0, script_pub_key_2.clone()),
                covenant: None,
            },
            TransactionOutput {
                value: 10518958752,
                script_public_key: ScriptPublicKey::from_vec(0, script_pub_key_1.clone()),
                covenant: None,
            },
        ],
        0,
        native(),
        0,
        vec![],
    );
    let spent = if spend_own_coin {
        script_pub_key_1
    } else {
        script_pub_key_2
    };
    let entries = vec![UtxoEntry {
        amount: 20879456551,
        script_public_key: ScriptPublicKey::from_vec(0, spent),
        block_daa_score: 32022768,
        is_coinbase: false,
        covenant_id: None,
    }];
    (tx, entries)
}

/// tx_validation_in_utxo_context.rs:504-577.
#[test]
fn check_signature_test() {
    let gate = mainnet_before_toccata();
    let (tx, entries) = mainnet_p2pk_spend(true);
    let (result, runs) = check_scripts(&gate, &tx, &entries);
    result.expect("Signature check failed");
    assert_eq!((runs[0].used_sig_ops, runs[0].stop.clone()), (1, None));

    // Test a tx with 2 inputs to cover parallelism split points in inner script checking code.
    // Duplicated sigs should fail due to wrong sighash.
    let (tx2, entries2) = duplicate_input(&tx, &entries);
    let (result, runs) = check_scripts(&gate, &tx2, &entries2);
    assert_eq!(
        result,
        Err(TxRuleError::SignatureInvalid(TxScriptError::EvalFalse))
    );
    // A well formed signature over another message: the check pushes false and the
    // script ends with it.
    assert_eq!(runs[0].stop, Some(StopPoint::FinalStack));
    assert_eq!(runs[1].stop, Some(StopPoint::FinalStack));
}

/// tx_validation_in_utxo_context.rs:579-657.
#[test]
fn check_incorrect_signature_test() {
    let gate = mainnet_before_toccata();
    let (tx, entries) = mainnet_p2pk_spend(false);
    let (result, _) = check_scripts(&gate, &tx, &entries);
    assert!(result.is_err(), "Expecting signature check to fail");
    // Upstream asserts no more than a failure. The engine's answer is pinned here: the
    // signature is well formed and made for another key.
    assert_eq!(
        result,
        Err(TxRuleError::SignatureInvalid(TxScriptError::EvalFalse))
    );

    let (tx2, entries2) = duplicate_input(&tx, &entries);
    check_scripts(&gate, &tx2, &entries2)
        .0
        .expect_err("Expecting signature check to fail");
}

/// The whole walk of the gate for the pay-to-pubkey transaction of upstream's signature
/// tests, at a DAA score a little after its coin was created (mainnet, before Toccata).
#[test]
fn the_gate_accepts_the_mainnet_pay_to_pubkey_transaction() {
    let (tx, entries) = mainnet_p2pk_spend(true);
    let gate = mainnet_before_toccata().with_daa_score(entries[0].block_daa_score + 1_000);
    assert!(!gate.toccata_active());

    let submitted = gate::evaluate(&gate, &tx, &entries, GateOptions::submit());
    assert_eq!(submitted.verdict.harness_error, None);
    assert_eq!(submitted.consensus_error, None);
    assert_eq!(submitted.verdict.stage_reached, Stage::Accepted);
    assert_eq!(submitted.verdict.fee, Some(10_000));
    assert_eq!(submitted.committed_runs[0].used_sig_ops, 1);
    // The transaction rebuilt here has the id that upstream's comment names (line 595).
    assert_eq!(
        tx.id().to_string(),
        "3f582463d73c77d93f278b7bf649bd890e75fe9bb8a1edd7a6854df1a2a2bfc1"
    );
    // Its fee is 10,000 sompi. A node of this revision relays it when it comes from a
    // peer before Toccata, under the prior fee rule.
    let relayed = gate::evaluate(
        &gate,
        &tx,
        &entries,
        GateOptions {
            priority: Priority::Low,
            ..GateOptions::submit()
        },
    );
    assert!(relayed.accepted(), "{:?}", relayed.verdict.first_refusal);

    // In a block the commitment must be the calculated storage mass. On submission the
    // gate wrote it into the transaction; it is calculated again here.
    let storage_mass = mass::calculated_storage_mass(&gate.params, &tx, &entries)
        .unwrap()
        .unwrap();
    // 10^12 / 10360487799 + 10^12 / 10518958752 - 10^12 / 20879456551 = 96 + 95 - 47.
    assert_eq!(storage_mass, 144);
    tx.set_storage_mass(storage_mass);
    let mined = gate::evaluate(&gate, &tx, &entries, GateOptions::block());
    assert_eq!(mined.consensus_error, None);
    assert!(mined.accepted());

    // A commitment of zero is refused by the rules of this revision.
    tx.set_storage_mass(0);
    let mined = gate::evaluate(&gate, &tx, &entries, GateOptions::block());
    assert_eq!(mined.consensus_error, Some(TxRuleError::WrongMass(144, 0)));

    // The wrong coin: the walk stops at the scripts.
    let (tx, entries) = mainnet_p2pk_spend(false);
    let submitted = gate::evaluate(&gate, &tx, &entries, GateOptions::submit());
    assert_eq!(submitted.verdict.stage_reached, Stage::Scripts);
    assert_eq!(
        submitted.consensus_error,
        Some(TxRuleError::SignatureInvalid(TxScriptError::EvalFalse))
    );
}

/// The redeem script of the mainnet multisig transaction: 2 of 4 Schnorr keys.
/// `Op2 <key> <key> <key> <key> Op4 OpCheckMultiSig`, 135 bytes.
const MULTISIG_REDEEM_SCRIPT: &str = concat!(
    "5220ecdd9ec9f2c53ed8e5a170cc88354e133299022da55e1e8bd3c61d8b9dcb",
    "d7df2068f191b6aca3d9d8cfa2edb0c44a10fc87dc36b62e1d02228257ccdf97",
    "9b1fce20b1503ef14aa6773ba3a1f012dbea2992e181766c35c5bc17465b5f57",
    "807540bf2006e161ced6b77c11b9a317080a899121a9c6df30a76490402f9a3b",
    "7e18bce97b54ae",
);

/// The two signatures of the mainnet multisig transaction, each as a push of 65 bytes.
const MULTISIG_FIRST_SIGNATURE: &str = concat!(
    "41ca6f8d104b47ca8ab133d98b3794b49f00ec5d2dce8253e78de035dfbc8f40",
    "a2fefa3086c3a181d9f1755a8f4ada4f8a4b8982b361853c8020009e1a752deb",
    "ce01",
);
const MULTISIG_SECOND_SIGNATURE: &str = concat!(
    "41fdb58c2c25fcfe37d427967c34700f92e9eb1df0f2f9ff366444d92357ff35",
    "a270ee5445287031e4c0f72acda20876ccf918de1039a41e9b5f83b3737223f9",
    "9501",
);

/// The mainnet transaction of the four multisig tests, with the given signature script
/// (tx_validation_in_utxo_context.rs:675-726).
fn mainnet_multisig_spend(signature_script: Vec<u8>) -> (Transaction, Vec<UtxoEntry>) {
    let prev_tx_id =
        TransactionId::from_str("63020db736215f8b1105a9281f7bcbb6473d965ecc45bb2fb5da59bd35e6ff84")
            .unwrap();
    let script_pub_key_1 =
        hex("aa2071b6c2c604a8830a1484ba469e845c37bb0af32f044bc8fd0c892c8878419e8587");
    let script_pub_key_2 =
        hex("206c376f9da440494e18b283803698ed13249af93be3e99f58f42d7d82744d3d15ac");

    let tx = Transaction::new(
        0,
        vec![TransactionInput {
            previous_outpoint: TransactionOutpoint {
                transaction_id: prev_tx_id,
                index: 0,
            },
            signature_script,
            sequence: 0,
            compute_commit: ComputeCommit::SigopCount(4.into()),
        }],
        vec![
            TransactionOutput {
                value: 10000000000000,
                script_public_key: ScriptPublicKey::from_vec(0, script_pub_key_2),
                covenant: None,
            },
            TransactionOutput {
                value: 2792999990000,
                script_public_key: ScriptPublicKey::from_vec(0, script_pub_key_1.clone()),
                covenant: None,
            },
        ],
        0,
        native(),
        0,
        vec![],
    );
    let entries = vec![UtxoEntry {
        amount: 12793000000000,
        script_public_key: ScriptPublicKey::from_vec(0, script_pub_key_1),
        block_daa_score: 36151168,
        is_coinbase: false,
        covenant_id: None,
    }];
    (tx, entries)
}

/// The signature script of the multisig spend: the two signature pushes, then
/// `OpPushData1 0x87 <redeem script>`.
fn multisig_signature_script(first: &str, second: &str) -> Vec<u8> {
    hex(&format!("{first}{second}4c87{MULTISIG_REDEEM_SCRIPT}"))
}

/// Where a failed multisig stops: `OpCheckMultiSig`, the seventh opcode of the redeem
/// script and its last byte.
fn multisig_stop() -> Option<StopPoint> {
    opcode_stop(
        ScriptKind::RedeemScript,
        6,
        134,
        0xae,
        "OpCheckMultiSig",
        true,
    )
}

/// tx_validation_in_utxo_context.rs:659-738.
#[test]
fn check_multi_signature_test() {
    let gate = mainnet_before_toccata();
    let signature_script =
        multisig_signature_script(MULTISIG_FIRST_SIGNATURE, MULTISIG_SECOND_SIGNATURE);
    assert_eq!(signature_script.len(), 269);
    let (tx, entries) = mainnet_multisig_spend(signature_script);
    let (result, runs) = check_scripts(&gate, &tx, &entries);
    result.expect("Signature check failed");
    // The engine charges one signature operation per check it makes, not per key
    // (crypto/txscript/src/lib.rs:832-874, 898). Four checks are made here, which is the
    // count the transaction commits to.
    assert_eq!(runs[0].used_sig_ops, 4);

    // Duplicated sigs should fail due to wrong sighash.
    let (tx2, entries2) = duplicate_input(&tx, &entries);
    let (result, runs) = check_scripts(&gate, &tx2, &entries2);
    assert_eq!(
        result,
        Err(TxRuleError::SignatureInvalid(TxScriptError::NullFail))
    );
    assert_eq!(runs[0].stop, multisig_stop());
    assert_eq!(runs[1].stop, multisig_stop());
}

/// tx_validation_in_utxo_context.rs:740-821. One hex digit of the second signature is
/// changed.
#[test]
fn check_last_sig_incorrect_multi_signature_test() {
    let gate = mainnet_before_toccata();
    let second = MULTISIG_SECOND_SIGNATURE.replace("ff35a270", "ff3da270");
    assert_ne!(second, MULTISIG_SECOND_SIGNATURE);
    let (tx, entries) =
        mainnet_multisig_spend(multisig_signature_script(MULTISIG_FIRST_SIGNATURE, &second));
    let (result, runs) = check_scripts(&gate, &tx, &entries);
    assert_eq!(
        result,
        Err(TxRuleError::SignatureInvalid(TxScriptError::NullFail))
    );
    assert_eq!(runs[0].stop, multisig_stop());

    let (tx2, entries2) = duplicate_input(&tx, &entries);
    assert_eq!(
        check_scripts(&gate, &tx2, &entries2).0,
        Err(TxRuleError::SignatureInvalid(TxScriptError::NullFail))
    );
}

/// tx_validation_in_utxo_context.rs:823-904. One hex digit of the first signature is
/// changed.
#[test]
fn check_first_sig_incorrect_multi_signature_test() {
    let gate = mainnet_before_toccata();
    let first = MULTISIG_FIRST_SIGNATURE.replace("8f40a2fe", "8f41a2fe");
    assert_ne!(first, MULTISIG_FIRST_SIGNATURE);
    let (tx, entries) =
        mainnet_multisig_spend(multisig_signature_script(&first, MULTISIG_SECOND_SIGNATURE));
    let (result, runs) = check_scripts(&gate, &tx, &entries);
    assert_eq!(
        result,
        Err(TxRuleError::SignatureInvalid(TxScriptError::NullFail))
    );
    assert_eq!(runs[0].stop, multisig_stop());

    let (tx2, entries2) = duplicate_input(&tx, &entries);
    assert_eq!(
        check_scripts(&gate, &tx2, &entries2).0,
        Err(TxRuleError::SignatureInvalid(TxScriptError::NullFail))
    );
}

/// tx_validation_in_utxo_context.rs:906-987. Two empty signatures.
#[test]
fn check_empty_incorrect_multi_signature_test() {
    let gate = mainnet_before_toccata();
    let signature_script = hex(&format!("00004c87{MULTISIG_REDEEM_SCRIPT}"));
    assert_eq!(signature_script.len(), 139);
    let (tx, entries) = mainnet_multisig_spend(signature_script);
    let (result, runs) = check_scripts(&gate, &tx, &entries);
    assert_eq!(
        result,
        Err(TxRuleError::SignatureInvalid(TxScriptError::EvalFalse))
    );
    // Empty signatures make the multisig push false without an error: the redeem script
    // runs to its end and the final stack is false.
    assert_eq!(runs[0].stop, Some(StopPoint::FinalStack));

    let (tx2, entries2) = duplicate_input(&tx, &entries);
    assert_eq!(
        check_scripts(&gate, &tx2, &entries2).0,
        Err(TxRuleError::SignatureInvalid(TxScriptError::EvalFalse))
    );
}

/// The whole walk of the gate for the multisig transaction of upstream's multisig tests
/// (mainnet, before Toccata).
#[test]
fn the_gate_accepts_the_mainnet_multisig_transaction() {
    let (tx, entries) = mainnet_multisig_spend(multisig_signature_script(
        MULTISIG_FIRST_SIGNATURE,
        MULTISIG_SECOND_SIGNATURE,
    ));
    let gate = mainnet_before_toccata().with_daa_score(entries[0].block_daa_score + 1_000);

    let submitted = gate::evaluate(&gate, &tx, &entries, GateOptions::submit());
    assert_eq!(submitted.verdict.harness_error, None);
    assert_eq!(submitted.consensus_error, None);
    assert_eq!(submitted.verdict.stage_reached, Stage::Accepted);
    assert_eq!(submitted.verdict.fee, Some(10_000));

    // The transaction rebuilt here has the id that upstream's comment names (line 675).
    assert_eq!(
        tx.id().to_string(),
        "d839d29b549469d0f9a23e51febe68d4084967a6a477868b511a5a8d88c5ae06"
    );
    let relayed = gate::evaluate(
        &gate,
        &tx,
        &entries,
        GateOptions {
            priority: Priority::Low,
            ..GateOptions::submit()
        },
    );
    assert!(relayed.accepted(), "{:?}", relayed.verdict.first_refusal);

    // A committed count of three instead of four. The signatures of a version 0
    // transaction cover the count (consensus/core/src/hashing/sighash.rs:260-270), so
    // they no longer verify: the first signature is tried against three keys, which
    // uses the three operations exactly, and the multisig fails with NullFail before
    // the count can run out.
    let (mut tx, entries) = mainnet_multisig_spend(multisig_signature_script(
        MULTISIG_FIRST_SIGNATURE,
        MULTISIG_SECOND_SIGNATURE,
    ));
    tx.inputs[0].compute_commit = ComputeCommit::SigopCount(3.into());
    tx.finalize();
    let submitted = gate::evaluate(&gate, &tx, &entries, GateOptions::submit());
    assert_eq!(
        submitted.consensus_error,
        Some(TxRuleError::SignatureInvalid(TxScriptError::NullFail))
    );
    assert_eq!(submitted.committed_runs[0].used_sig_ops, 3);
    assert_eq!(submitted.committed_runs[0].stop, multisig_stop());

    // With two operations the third check is the one refused.
    tx.inputs[0].compute_commit = ComputeCommit::SigopCount(2.into());
    tx.finalize();
    let submitted = gate::evaluate(&gate, &tx, &entries, GateOptions::submit());
    assert_eq!(
        submitted.consensus_error,
        Some(TxRuleError::SignatureInvalid(
            TxScriptError::ExceededSigOpLimit(2)
        ))
    );
    assert_eq!(submitted.committed_runs[0].stop, multisig_stop());
}

/// tx_validation_in_utxo_context.rs:989-1057. The script itself is valid, but the
/// signature script is not push only.
#[test]
fn check_non_push_only_script_sig_test() {
    let gate = mainnet_before_toccata();
    let prev_tx_id =
        TransactionId::from_str("1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let signature_script = hex("5175"); // OP_TRUE OP_DROP
    let script_pub_key_1 = hex("51"); // OP_TRUE

    let tx = Transaction::new(
        0,
        vec![TransactionInput {
            previous_outpoint: TransactionOutpoint {
                transaction_id: prev_tx_id,
                index: 0,
            },
            signature_script,
            sequence: 0,
            compute_commit: ComputeCommit::SigopCount(4.into()),
        }],
        vec![TransactionOutput {
            value: 2792999990000,
            script_public_key: ScriptPublicKey::from_vec(0, script_pub_key_1.clone()),
            covenant: None,
        }],
        0,
        native(),
        0,
        vec![],
    );
    let entries = vec![UtxoEntry {
        amount: 12793000000000,
        script_public_key: ScriptPublicKey::from_vec(0, script_pub_key_1),
        block_daa_score: 36151168,
        is_coinbase: false,
        covenant_id: None,
    }];

    let (result, runs) = check_scripts(&gate, &tx, &entries);
    assert_eq!(
        result,
        Err(TxRuleError::SignatureInvalid(
            TxScriptError::SignatureScriptNotPushOnly
        ))
    );
    // OpDrop, the second opcode of the signature script, is refused before it runs.
    assert_eq!(
        runs[0].stop,
        opcode_stop(ScriptKind::SignatureScript, 1, 1, OpDrop, "OpDrop", false)
    );

    let (tx2, entries2) = duplicate_input(&tx, &entries);
    assert_eq!(
        check_scripts(&gate, &tx2, &entries2).0,
        Err(TxRuleError::SignatureInvalid(
            TxScriptError::SignatureScriptNotPushOnly
        ))
    );
}

/// tx_validation_in_utxo_context.rs:1059-1139, with a fixed key in place of a random one.
/// Three pay-to-pubkey coins of one key, a time lock and a subnetwork id that is not
/// native: only the scripts are asked.
#[test]
fn test_sign() {
    let gate = mainnet_before_toccata();
    let schnorr_key = Keypair::from_seckey_slice(SECP256K1, &[0x42u8; 32]).unwrap();
    let (public_key, _) = schnorr_key.x_only_public_key();
    let script_pub_key: Vec<u8> = std::iter::once(0x20)
        .chain(public_key.serialize())
        .chain(std::iter::once(0xac))
        .collect();

    let prev_tx_id =
        TransactionId::from_str("880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3")
            .unwrap();
    let input = |index: u32, sequence: u64| TransactionInput {
        previous_outpoint: TransactionOutpoint {
            transaction_id: prev_tx_id,
            index,
        },
        signature_script: vec![],
        sequence,
        compute_commit: ComputeCommit::SigopCount(0.into()),
    };
    let output = || TransactionOutput {
        value: 300,
        script_public_key: ScriptPublicKey::from_vec(0, script_pub_key.clone()),
        covenant: None,
    };
    let mut tx = Transaction::new(
        0,
        vec![input(0, 0), input(1, 1), input(2, 2)],
        vec![output(), output()],
        1615462089000,
        SubnetworkId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        0,
        vec![],
    );
    let entry = |amount: u64| UtxoEntry {
        amount,
        script_public_key: ScriptPublicKey::from_vec(0, script_pub_key.clone()),
        block_daa_score: 0,
        is_coinbase: false,
        covenant_id: None,
    };
    let entries = vec![entry(100), entry(200), entry(300)];
    sign_all_inputs(&mut tx, &entries, &schnorr_key);

    let (result, runs) = check_scripts(&gate, &tx, &entries);
    assert_eq!(result, Ok(()));
    assert_eq!(runs.len(), 3);

    // Every signature covers its own outpoint, amount and sequence number: after
    // exchanging the signature scripts of the first two inputs neither verifies.
    let first = tx.inputs[0].signature_script.clone();
    tx.inputs[0].signature_script = std::mem::replace(&mut tx.inputs[1].signature_script, first);
    let (result, runs) = check_scripts(&gate, &tx, &entries);
    assert_eq!(
        result,
        Err(TxRuleError::SignatureInvalid(TxScriptError::EvalFalse))
    );
    let verdicts: Vec<bool> = runs.iter().map(ScriptRun::is_ok).collect();
    assert_eq!(verdicts, vec![false, false, true]);
}
