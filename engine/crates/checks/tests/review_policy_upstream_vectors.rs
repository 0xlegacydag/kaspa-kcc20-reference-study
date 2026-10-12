//! Review of the mempool policy port: upstream's own unit tests, replayed against it.
//!
//! Source of every transaction, mass, fee and expected result of the `upstream_test_*`
//! tests: rusty-kaspa a41a333 mining/src/mempool/check_transaction_standard.rs:206-682
//! and mining/src/mempool/check_transaction_limits.rs:69-195 (the constants, the helpers
//! and the six tests of the two test modules; ISC License, Copyright (c) 2022-2024 Kaspa
//! developers). Upstream runs them against its `Mempool`, which cannot be built here
//! (`kaspa-mining` is not a dependency). The same inputs go to the ported functions of
//! `node_gate::policy` and the same answers are required. The upstream errors carry the
//! transaction id and the ported ones do not; everything else is compared field by field.
//!
//! Not upstream's:
//!
//! * the helpers that stand in for upstream's address and `Mempool`
//!   (`pay_to_pubkey_of_ones`, `standard_in_context`, `params_of_the_limit_tests`), the
//!   port's refusal expected where upstream only asks whether a transaction is standard,
//!   and the assertions on literal numbers that pin what upstream's expressions and
//!   constants come to;
//! * the first and the last score of the relaxation window, marked at the end of
//!   `upstream_test_standard_transaction_mass_cap`;
//! * every test below the line "Several refusals in one transaction": those put several
//!   refusals into one transaction and require `gate::evaluate` to name the one a node
//!   reaches first (mining/src/mempool/validate_and_insert_transaction.rs:26-36, 73-77).

use kaspa_consensus_core::{
    config::params::{DEFAULT_LANES_PER_BLOCK_LIMIT, ForkActivation, Params},
    constants::{
        MAX_SCRIPT_PUBLIC_KEY_VERSION, MAX_TX_IN_SEQUENCE_NUM, SOMPI_PER_KASPA,
        TRANSIENT_BYTE_TO_MASS_FACTOR, TX_VERSION,
    },
    errors::tx::TxRuleError,
    hashing::sighash_type::SIG_HASH_ALL,
    mass::{BlockLaneLimits, BlockMassLimits, ComputeBudget, NonContextualMasses, SigopCount},
    network::NetworkType,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        ComputeCommit, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput,
        TransactionOutpoint, TransactionOutput, UtxoEntry,
    },
};
use kaspa_hashes::Hash;
use kaspa_txscript::{
    opcodes::codes::{OpCheckSig, OpData32, OpReturn, OpTrue},
    script_class::ScriptClass,
};
use node_gate::{
    Evaluation, GateOptions, GateParams, Stage, evaluate, mass,
    policy::{self, PolicyRefusal, PolicyRule, Priority},
    wallet::TestKey,
};

/// What upstream's tests get from
/// `pay_to_address_script(&Address::new(_, Version::PubKey, &[1u8; 32]))`: version 0,
/// `OpData32 <32 bytes> OpCheckSig` (crypto/txscript/src/standard.rs:19-23, 42-49). The
/// address prefix does not enter the script.
fn pay_to_pubkey_of_ones() -> ScriptPublicKey {
    let mut script = vec![OpData32];
    script.extend_from_slice(&[1u8; 32]);
    script.push(OpCheckSig);
    let script_public_key = ScriptPublicKey::from_vec(MAX_SCRIPT_PUBLIC_KEY_VERSION, script);
    assert_eq!(
        ScriptClass::from_script(&script_public_key),
        ScriptClass::PubKey
    );
    script_public_key
}

/// A version 0 script public key that is one opcode long.
fn one_opcode(opcode: u8) -> ScriptPublicKey {
    ScriptPublicKey::from_vec(MAX_SCRIPT_PUBLIC_KEY_VERSION, vec![opcode])
}

const RELAY_FEE_TEST_MASS: u64 = 500_000;

/// check_transaction_standard.rs:207-209.
const fn default_minimum_relay_fee_for_mass(mass: u64) -> u64 {
    mass * policy::DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE / 1000
}

/// check_transaction_standard.rs:211-269, `test_calc_min_required_tx_relay_fee`.
#[test]
fn upstream_test_calc_min_required_tx_relay_fee() {
    // (name, mass, relay fee in sompi per kilogram, wanted fee)
    let tests = [
        ("250 bytes with relay fee of 3", 250, 3, 3),
        (
            "100 bytes with default minimum relay fee",
            100,
            policy::DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE,
            default_minimum_relay_fee_for_mass(100),
        ),
        (
            "large relay fee test mass with default minimum relay fee",
            RELAY_FEE_TEST_MASS,
            policy::DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE,
            default_minimum_relay_fee_for_mass(RELAY_FEE_TEST_MASS),
        ),
        ("1500 bytes with 5000 relay fee", 1500, 5000, 7500),
        ("1500 bytes with 3000 relay fee", 1500, 3000, 4500),
        ("782 bytes with 5000 relay fee", 782, 5000, 3910),
        ("782 bytes with 3000 relay fee", 782, 3000, 2346),
        ("782 bytes with 2550 relay fee", 782, 2550, 1994),
    ];
    for (name, mass, relay_fee, want) in tests {
        assert_eq!(
            policy::minimum_required_transaction_relay_fee(mass, relay_fee),
            want,
            "{name}"
        );
    }
    // The two constants the daemon's configuration is built from (config.rs:23, 28).
    assert_eq!(policy::DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE, 100_000);
    assert_eq!(policy::LEGACY_MINIMUM_RELAY_TRANSACTION_FEE, 1_000);
}

/// check_transaction_standard.rs:271-406, `test_check_transaction_standard_in_isolation`.
#[test]
fn upstream_test_check_transaction_standard_in_isolation() {
    let dummy_prev_out = TransactionOutpoint::new(Hash::from_u64_word(1), 1);
    let dummy_tx_input =
        TransactionInput::new(dummy_prev_out, vec![0u8; 65], MAX_TX_IN_SEQUENCE_NUM, 1);
    let dummy_tx_out = TransactionOutput::new(SOMPI_PER_KASPA, pay_to_pubkey_of_ones());
    let tx = |version: u16, output: TransactionOutput| {
        Transaction::new(
            version,
            vec![dummy_tx_input.clone()],
            vec![output],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        )
    };

    // (name, transaction, standard, the refusal of the port when not standard)
    let tests = [
        (
            "Typical pay-to-pubkey transaction",
            tx(TX_VERSION, dummy_tx_out.clone()),
            true,
            None,
        ),
        (
            // check_transaction_standard_in_isolation does not check version
            "Transaction version above allowed",
            tx(TX_VERSION + 2, dummy_tx_out.clone()),
            true,
            None,
        ),
        (
            "Valid but non standard public key script",
            tx(
                TX_VERSION,
                TransactionOutput::new(SOMPI_PER_KASPA, one_opcode(OpTrue)),
            ),
            false,
            Some(PolicyRefusal::OutputScriptClass { output: 0 }),
        ),
        (
            "Null-data transaction",
            tx(
                TX_VERSION,
                TransactionOutput::new(SOMPI_PER_KASPA, one_opcode(OpReturn)),
            ),
            false,
            Some(PolicyRefusal::OutputScriptClass { output: 0 }),
        ),
    ];

    let masses = NonContextualMasses::new(1000, 1000);
    for (name, tx, is_standard, refusal) in tests {
        for net in NetworkType::iter() {
            let params: Params = net.into();
            let result = policy::check_transaction_standard_in_isolation(&params, &tx, masses, 0);
            assert_eq!(
                result.is_ok(),
                is_standard,
                "failed for test '{name}' on {net:?}: {result:?}"
            );
            assert_eq!(result.err(), refusal, "test '{name}' on {net:?}");
        }
    }
}

/// The transaction of upstream's `new_mtx` (check_transaction_standard.rs:428-447): one
/// input with an empty signature script, one output of 1 KAS, and a coin of 2 KAS, both
/// locked by `script_public_key`.
fn context_transaction(script_public_key: &ScriptPublicKey) -> (Transaction, Vec<UtxoEntry>) {
    let prev_out = TransactionOutpoint::new(Hash::from_u64_word(1), 1);
    let input = TransactionInput::new(prev_out, vec![], MAX_TX_IN_SEQUENCE_NUM, 1);
    let tx = Transaction::new(
        TX_VERSION,
        vec![input],
        vec![TransactionOutput::new(
            SOMPI_PER_KASPA,
            script_public_key.clone(),
        )],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let entries = vec![UtxoEntry::new(
        2 * SOMPI_PER_KASPA,
        script_public_key.clone(),
        0,
        false,
        None,
    )];
    (tx, entries)
}

/// `Mempool::check_transaction_standard_in_context` on upstream's `new_mtx`.
fn standard_in_context(
    params: &Params,
    script_public_key: &ScriptPublicKey,
    masses: NonContextualMasses,
    fee: u64,
    priority: Priority,
    virtual_daa_score: u64,
) -> Result<(), PolicyRefusal> {
    let (tx, entries) = context_transaction(script_public_key);
    policy::check_transaction_standard_in_context(
        params,
        &tx,
        &entries,
        masses,
        tx.storage_mass(),
        fee,
        priority,
        virtual_daa_score,
    )
}

/// check_transaction_standard.rs:408-526, `test_check_transaction_standard_in_context`,
/// the part on simnet parameters.
#[test]
fn upstream_test_check_transaction_standard_in_context_on_simnet() {
    let standard = pay_to_pubkey_of_ones();
    let non_standard = one_opcode(OpTrue);

    let params: Params = NetworkType::Simnet.into();
    assert_ne!(
        params.toccata_activation,
        ForkActivation::never(),
        "this test requires post-activation cofactors"
    );
    let cofactors = params.mempool_block_mass_cofactors().after();
    let transient = |bytes: u64| bytes * TRANSIENT_BYTE_TO_MASS_FACTOR;
    let normalized_transient =
        |bytes: u64| NonContextualMasses::new(0, transient(bytes)).normalized_transient(&cofactors);

    let bytes = 5_000;
    let compute = normalized_transient(bytes);
    let boundary_fee = default_minimum_relay_fee_for_mass(compute);
    let insufficient_fee = boundary_fee - 1;
    // What the upstream expressions come to: half of four grams per byte.
    assert_eq!((compute, boundary_fee), (10_000, 1_000_000));

    let run = |script_public_key: &ScriptPublicKey, masses: NonContextualMasses, fee: u64| {
        standard_in_context(&params, script_public_key, masses, fee, Priority::High, 0)
    };

    assert_eq!(
        run(
            &standard,
            NonContextualMasses::new(compute, transient(bytes)),
            boundary_fee
        ),
        Ok(()),
        "standard input with exactly sufficient relay fee"
    );
    assert_eq!(
        run(
            &non_standard,
            NonContextualMasses::new(1_000, 1_000),
            policy::DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE
        ),
        Err(PolicyRefusal::InputScriptClass { input: 0 }),
        "non-standard input script class"
    );
    assert_eq!(
        run(
            &standard,
            NonContextualMasses::new(compute, transient(bytes - 1)),
            insufficient_fee
        ),
        Err(PolicyRefusal::InsufficientComputeFee {
            fee: insufficient_fee,
            minimum_fee: boundary_fee,
            compute_mass: compute
        }),
        "compute mass triggers insufficient relay fee"
    );
    assert_eq!(
        run(
            &standard,
            NonContextualMasses::new(compute - 1, transient(bytes)),
            insufficient_fee
        ),
        Err(PolicyRefusal::InsufficientTransientFee {
            fee: insufficient_fee,
            minimum_fee: boundary_fee,
            normalized_transient_mass: compute
        }),
        "transient mass triggers insufficient relay fee"
    );
}

/// check_transaction_standard.rs:528-590, the part of the same test with mainnet
/// parameters and a Toccata activation at DAA score 10.
///
/// Upstream builds the configuration from the unchanged mainnet parameters and hands the
/// activation to the mempool separately. Here the activation is written into the
/// parameters, which is where the port reads it. Nothing else the port reads changes: the
/// blocks per second do not depend on the activation, and `raw_post` of the cofactors is
/// the post-activation value whatever the activation score.
#[test]
fn upstream_test_check_transaction_standard_in_context_around_the_activation() {
    let unchanged: Params = NetworkType::Mainnet.into();
    let mut params = unchanged.clone();
    params.toccata_activation = ForkActivation::new(10);
    let toccata_daa_activation = params.toccata_activation.daa_score();
    assert_eq!(params.bps(), unchanged.bps());
    assert_eq!(
        params.mempool_block_mass_cofactors().raw_post().transient,
        unchanged
            .mempool_block_mass_cofactors()
            .raw_post()
            .transient
    );
    let cofactors = params.mempool_block_mass_cofactors().raw_post();

    let compute_mass = 1_000;
    let legacy_minimum_fee = policy::LEGACY_MINIMUM_RELAY_TRANSACTION_FEE;
    let insufficient_legacy_fee = legacy_minimum_fee - 1;
    let masses = NonContextualMasses::new(compute_mass, compute_mass * 4);
    let normalized_transient_mass = masses.normalized_transient(&cofactors);
    assert!(normalized_transient_mass > compute_mass);
    let new_minimum_fee = default_minimum_relay_fee_for_mass(normalized_transient_mass);
    assert_eq!(
        (normalized_transient_mass, new_minimum_fee),
        (2_000, 200_000)
    );

    let script_public_key = pay_to_pubkey_of_ones();
    let run = |fee: u64, priority: Priority, virtual_daa_score: u64| {
        standard_in_context(
            &params,
            &script_public_key,
            masses,
            fee,
            priority,
            virtual_daa_score,
        )
    };
    let transient_refusal = Err(PolicyRefusal::InsufficientTransientFee {
        fee: legacy_minimum_fee,
        minimum_fee: new_minimum_fee,
        normalized_transient_mass,
    });

    assert_eq!(
        run(
            legacy_minimum_fee,
            Priority::Low,
            toccata_daa_activation - 1
        ),
        Ok(())
    );
    assert_eq!(
        run(
            insufficient_legacy_fee,
            Priority::Low,
            toccata_daa_activation - 1
        ),
        Err(PolicyRefusal::InsufficientComputeFee {
            fee: insufficient_legacy_fee,
            minimum_fee: legacy_minimum_fee,
            compute_mass
        })
    );
    assert_eq!(
        run(legacy_minimum_fee, Priority::Low, toccata_daa_activation),
        transient_refusal
    );
    assert_eq!(
        run(
            legacy_minimum_fee,
            Priority::High,
            toccata_daa_activation - 1
        ),
        transient_refusal
    );
    assert_eq!(
        run(legacy_minimum_fee, Priority::High, toccata_daa_activation),
        transient_refusal
    );
}

/// check_transaction_standard.rs:593-682, `test_standard_transaction_mass_cap`.
#[test]
fn upstream_test_standard_transaction_mass_cap() {
    // Toccata score far enough out that the relaxation window (30 min * bps) starts at a
    // positive score.
    let mut params: Params = NetworkType::Mainnet.into();
    params.toccata_activation = ForkActivation::new(1_000_000);
    let cap = policy::MAXIMUM_STANDARD_TRANSACTION_MASS_PRE_TOCCATA;
    assert_eq!(cap, 100_000);
    assert_eq!(policy::STANDARD_MASS_RELAXATION_WINDOW_SECONDS, 30 * 60);

    let spk = pay_to_pubkey_of_ones();

    // 0 is before the relaxation window opens; one score below activation is inside it.
    let before_window = 0;
    let in_window = params.toccata_activation.daa_score() - 1;
    let over = cap + 1;

    // Non-contextual (compute/transient) dimensions, checked in isolation.
    let input = TransactionInput::new(
        TransactionOutpoint::new(Hash::from_u64_word(1), 0),
        vec![],
        MAX_TX_IN_SEQUENCE_NUM,
        0,
    );
    let tx = Transaction::new(
        TX_VERSION,
        vec![input],
        vec![TransactionOutput::new(SOMPI_PER_KASPA, spk.clone())],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let in_isolation = |compute: u64, transient: u64, virtual_daa_score: u64| {
        policy::check_transaction_standard_in_isolation(
            &params,
            &tx,
            NonContextualMasses::new(compute, transient),
            virtual_daa_score,
        )
    };

    assert_eq!(
        in_isolation(over, 1_000, before_window),
        Err(PolicyRefusal::StandardComputeMass { mass: over, cap })
    );
    assert_eq!(in_isolation(over, 1_000, in_window), Ok(()));

    assert_eq!(
        in_isolation(1_000, over, before_window),
        Err(PolicyRefusal::StandardTransientMass { mass: over, cap })
    );
    assert_eq!(in_isolation(1_000, over, in_window), Ok(()));

    // A transaction at the cap is standard even before the window.
    assert_eq!(in_isolation(cap, cap, before_window), Ok(()));

    // Contextual storage dimension, checked in context.
    let entries = vec![UtxoEntry::new(
        2 * SOMPI_PER_KASPA,
        spk.clone(),
        0,
        false,
        None,
    )];
    tx.set_storage_mass(over);
    let in_context = |virtual_daa_score: u64| {
        policy::check_transaction_standard_in_context(
            &params,
            &tx,
            &entries,
            NonContextualMasses::new(1_000, 1_000),
            tx.storage_mass(),
            SOMPI_PER_KASPA,
            Priority::High,
            virtual_daa_score,
        )
    };
    assert_eq!(
        in_context(before_window),
        Err(PolicyRefusal::StandardStorageMass { mass: over, cap })
    );
    // Within the window the storage cap is lifted; the well-funded, standard tx is accepted.
    assert_eq!(in_context(in_window), Ok(()));

    // Not in upstream's test: the first and the last score of the window. Thirty minutes
    // at ten blocks per second are 18,000 scores.
    let opens = 1_000_000 - 18_000;
    assert_eq!(
        policy::standard_transaction_mass_cap(&params, opens - 1),
        Some(cap)
    );
    assert_eq!(policy::standard_transaction_mass_cap(&params, opens), None);
    // `early_by` leaves `never` and `always` alone (config/params.rs:66-71).
    params.toccata_activation = ForkActivation::never();
    assert_eq!(
        policy::standard_transaction_mass_cap(&params, u64::MAX - 1),
        Some(cap)
    );
    params.toccata_activation = ForkActivation::always();
    assert_eq!(policy::standard_transaction_mass_cap(&params, 0), None);
}

const LIMITS: BlockMassLimits = BlockMassLimits {
    compute: 100,
    storage: 200,
    transient: 300,
};
const GAS_PER_LANE: u64 = 7;

/// The parameters that give the port the mempool configuration of upstream's limit tests
/// (check_transaction_limits.rs:89-97): limits that never fork, and a lane limit of 7.
fn params_of_the_limit_tests() -> Params {
    let mut params: Params = NetworkType::Mainnet.into();
    params.toccata_activation = ForkActivation::never();
    params.prior_block_mass_limits = LIMITS;
    params.block_lane_limits = BlockLaneLimits {
        lanes_per_block: DEFAULT_LANES_PER_BLOCK_LIMIT,
        gas_per_lane: GAS_PER_LANE,
    };
    let limits = params.mempool_block_mass_limits().get(0);
    assert_eq!(
        (limits.compute, limits.storage, limits.transient),
        (100, 200, 300)
    );
    params
}

/// The transaction of check_transaction_limits.rs:99-110 with the given gas.
fn limits_transaction(gas: u64) -> Transaction {
    let script_public_key = ScriptPublicKey::from_vec(0, vec![0x51]);
    let outpoint = TransactionOutpoint::new(Hash::from_u64_word(1), 0);
    let input = TransactionInput::new(outpoint, vec![], MAX_TX_IN_SEQUENCE_NUM, 0);
    let output = TransactionOutput::new(SOMPI_PER_KASPA, script_public_key);
    Transaction::new(
        TX_VERSION,
        vec![input],
        vec![output],
        0,
        SUBNETWORK_ID_NATIVE,
        gas,
        vec![],
    )
}

/// check_transaction_limits.rs:123-166, `test_validate_transaction_limits_in_isolation`.
#[test]
fn upstream_test_validate_transaction_limits_in_isolation() {
    let params = params_of_the_limit_tests();
    // (name, gas, compute mass, transient mass, expected)
    let tests = [
        (
            "non-contextual values at limits",
            GAS_PER_LANE,
            LIMITS.compute,
            LIMITS.transient,
            Ok(()),
        ),
        (
            "transaction gas exceeds the per-lane limit",
            GAS_PER_LANE + 1,
            1,
            1,
            Err(PolicyRefusal::Gas {
                gas: GAS_PER_LANE + 1,
                limit: GAS_PER_LANE,
            }),
        ),
        (
            "transaction compute mass exceeds the block limit",
            0,
            LIMITS.compute + 1,
            1,
            Err(PolicyRefusal::ComputeMass {
                mass: LIMITS.compute + 1,
                limit: LIMITS.compute,
            }),
        ),
        (
            "transaction transient byte size exceeds the block limit",
            0,
            1,
            LIMITS.transient + 1,
            Err(PolicyRefusal::TransientMass {
                mass: LIMITS.transient + 1,
                limit: LIMITS.transient,
            }),
        ),
    ];
    for (name, gas, compute_mass, transient_mass, expected) in tests {
        let result = policy::validate_transaction_limits_in_isolation(
            &params,
            &limits_transaction(gas),
            NonContextualMasses::new(compute_mass, transient_mass),
            0,
        );
        assert_eq!(result, expected, "failed for test '{name}'");
    }
}

/// check_transaction_limits.rs:168-195, `test_validate_transaction_limits_in_context`.
#[test]
fn upstream_test_validate_transaction_limits_in_context() {
    let params = params_of_the_limit_tests();
    let tests = [
        ("contextual storage value at limit", LIMITS.storage, Ok(())),
        (
            "transaction storage mass exceeds the block limit",
            LIMITS.storage + 1,
            Err(PolicyRefusal::StorageMass {
                mass: LIMITS.storage + 1,
                limit: LIMITS.storage,
            }),
        ),
    ];
    for (name, storage_mass, expected) in tests {
        let tx = limits_transaction(0);
        tx.set_storage_mass(storage_mass);
        let result = policy::validate_transaction_limits_in_context(&params, tx.storage_mass(), 0);
        assert_eq!(result, expected, "failed for test '{name}'");
    }
}

// ---------------------------------------------------------------------------------------
// Several refusals in one transaction: which one a node reaches first
// ---------------------------------------------------------------------------------------

const KAS: u64 = SOMPI_PER_KASPA;

/// A transaction and the coins it spends.
struct Spend {
    tx: Transaction,
    entries: Vec<UtxoEntry>,
}

impl Spend {
    /// Signs every input as a spend of a pay-to-pubkey coin of the key of seed 1.
    fn sign(&mut self) {
        let key = TestKey::from_seed(1);
        for index in 0..self.tx.inputs.len() {
            let populated = PopulatedTransaction::new(&self.tx, self.entries.clone());
            let script = key.p2pk_signature_script(&populated, index, SIG_HASH_ALL);
            self.tx.inputs[index].signature_script = script;
        }
    }
}

/// One pay-to-pubkey coin of 10 KAS to one pay-to-pubkey output, fee 0.01 KAS, version 1,
/// compute budget 10, signed. A default node takes it.
fn plain_spend(node: &GateParams) -> Spend {
    let key = TestKey::from_seed(1);
    let coin = UtxoEntry::new(
        10 * KAS,
        key.p2pk_script_public_key(),
        node.pov_daa_score - 10_000,
        false,
        None,
    );
    let outpoint = TransactionOutpoint::new(Hash::from_bytes([0xa1; 32]), 0);
    let input = TransactionInput::new_with_compute_budget(outpoint, vec![], 0, 10);
    let output = TransactionOutput::new(
        10 * KAS - 1_000_000,
        TestKey::from_seed(2).p2pk_script_public_key(),
    );
    let tx = Transaction::new(
        1,
        vec![input],
        vec![output],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let mut spend = Spend {
        tx,
        entries: vec![coin],
    };
    spend.sign();
    spend
}

/// Submits the spend to the gate and holds the gate's first mempool refusal against a
/// second path: the four functions ported under their upstream names, chained the way a
/// node chains them (validate_and_insert_transaction.rs:32-33, 76-77). `gate::evaluate`
/// does not call those four; it walks the single rules in the order of two lists.
fn submit(node: &GateParams, spend: &Spend) -> Evaluation {
    let evaluation = evaluate(node, &spend.tx, &spend.entries, GateOptions::submit());
    let params = &node.params;
    let daa = node.pov_daa_score;
    let Ok(masses) = mass::calculate_transaction_non_contextual_masses(params, &spend.tx) else {
        return evaluation;
    };
    let before = policy::validate_transaction_limits_in_isolation(params, &spend.tx, masses, daa)
        .and_then(|()| {
            policy::check_transaction_standard_in_isolation(params, &spend.tx, masses, daa)
        });
    match before {
        Err(refusal) => assert_eq!(evaluation.policy_refusal, Some(refusal)),
        Ok(()) if evaluation.verdict.consensus_accepted => {
            // The gate has written the calculated storage mass into the transaction.
            let storage_mass = spend.tx.storage_mass();
            let fee = evaluation
                .verdict
                .fee
                .expect("an accepted transaction has a fee");
            let after = policy::validate_transaction_limits_in_context(params, storage_mass, daa)
                .and_then(|()| {
                    policy::check_transaction_standard_in_context(
                        params,
                        &spend.tx,
                        &spend.entries,
                        masses,
                        storage_mass,
                        fee,
                        Priority::High,
                        daa,
                    )
                });
            assert_eq!(evaluation.policy_refusal, after.err());
        }
        // The consensus validation refused: a node does not get to the later rules.
        Ok(()) => {}
    }
    evaluation
}

fn refused_rules(evaluation: &Evaluation) -> Vec<PolicyRule> {
    let report = evaluation.verdict.policy.as_ref().expect("submit mode");
    report.refusals().map(|(rule, _)| rule).collect()
}

fn first_refusal(evaluation: &Evaluation) -> (Stage, String) {
    let first = evaluation
        .verdict
        .first_refusal
        .as_ref()
        .expect("a refused transaction");
    (first.stage, first.rule.clone())
}

#[test]
fn the_plain_spend_of_these_tests_is_accepted() {
    let node = GateParams::testnet10();
    let evaluation = submit(&node, &plain_spend(&node));
    assert!(
        evaluation.verdict.accepted,
        "{:?}",
        evaluation.verdict.first_refusal
    );
}

/// validate_and_insert_transaction.rs:30 comes before :32: a transaction whose masses
/// cannot be calculated is refused for that, whatever its gas.
#[test]
fn the_sanity_checks_before_the_masses_answer_before_the_gas_limit() {
    let node = GateParams::testnet10();
    let mut spend = plain_spend(&node);
    // A signature operation count in a version 1 transaction, and gas above the lane limit.
    spend.tx.inputs[0].compute_commit = ComputeCommit::SigopCount(SigopCount(1));
    spend.tx.gas = node.params.block_lane_limits.gas_per_lane + 1;
    spend.tx.finalize();

    let evaluation = submit(&node, &spend);
    assert_eq!(
        first_refusal(&evaluation),
        (
            Stage::PreMass,
            "validate_transaction_for_non_contextual_masses".to_string()
        )
    );
    assert_eq!(
        evaluation.pre_mass_error,
        Some(TxRuleError::SigopCountInV1(0, 1))
    );
    // The gas rule is still listed as one more reason.
    assert_eq!(refused_rules(&evaluation), vec![PolicyRule::GasLimit]);
}

/// validate_and_insert_transaction.rs:32-33 come before the consensus validation: a
/// transaction over the compute limit never reaches the in-isolation rules.
#[test]
fn a_block_fit_limit_answers_before_the_rules_in_isolation() {
    let node = GateParams::testnet10();
    let mut spend = plain_spend(&node);
    // The same outpoint twice, and budgets that add up to 600,000 grams.
    spend.tx.inputs.push(spend.tx.inputs[0].clone());
    spend.entries.push(spend.entries[0].clone());
    for input in &mut spend.tx.inputs {
        input.compute_commit = ComputeBudget(3_000).into();
    }
    spend.tx.finalize();
    spend.sign();

    let evaluation = submit(&node, &spend);
    assert_eq!(
        first_refusal(&evaluation),
        (
            Stage::MempoolBeforeConsensus,
            "check_compute_mass_limit".to_string()
        )
    );
    assert!(matches!(
        evaluation.policy_refusal,
        Some(PolicyRefusal::ComputeMass { limit: 500_000, .. })
    ));
    assert_eq!(
        evaluation.consensus_error,
        Some(TxRuleError::TxDuplicateInputs)
    );
    assert_eq!(evaluation.verdict.stage_reached, Stage::Isolation);
}

/// check_transaction_limits.rs:19-30: gas, then compute mass, then transient mass; and
/// all three before the standardness of the outputs
/// (validate_and_insert_transaction.rs:32-33).
#[test]
fn gas_answers_before_the_masses_and_the_masses_before_the_outputs() {
    let node = GateParams::testnet10();
    let build = |gas: u64, budget: u16, payload: usize| {
        let mut spend = plain_spend(&node);
        spend.tx.gas = gas;
        spend.tx.inputs[0].compute_commit = ComputeBudget(budget).into();
        spend.tx.outputs[0].script_public_key = one_opcode(OpTrue);
        spend.tx.payload = vec![0; payload];
        spend.tx.finalize();
        spend.sign();
        spend
    };
    let lane_limit = node.params.block_lane_limits.gas_per_lane;

    // The plain spend is 266 bytes; with a one-byte output script it is 233. With 250,000
    // bytes of payload the transient mass is above 1,000,000; a budget of 5,000 is 500,000
    // grams of compute mass by itself.
    let all = submit(&node, &build(lane_limit + 1, 5_000, 250_000));
    assert_eq!(first_refusal(&all).1, "check_gas_limit");
    assert_eq!(
        refused_rules(&all)[..4],
        [
            PolicyRule::GasLimit,
            PolicyRule::ComputeMassLimit,
            PolicyRule::TransientMassLimit,
            PolicyRule::OutputScriptsStandard
        ]
    );

    let without_gas = submit(&node, &build(0, 5_000, 250_000));
    assert_eq!(first_refusal(&without_gas).1, "check_compute_mass_limit");

    let bulky = submit(&node, &build(0, 10, 250_000));
    assert_eq!(first_refusal(&bulky).1, "check_transient_mass_limit");
    assert_eq!(
        bulky.policy_refusal,
        Some(PolicyRefusal::TransientMass {
            mass: 4 * (233 + 250_000),
            limit: 1_000_000
        })
    );

    let odd_output_only = submit(&node, &build(0, 10, 0));
    assert_eq!(
        first_refusal(&odd_output_only),
        (
            Stage::MempoolBeforeConsensus,
            "check_output_scripts_standard".to_string()
        )
    );
}

/// validate_and_insert_transaction.rs:76 comes before :77, and inside
/// `check_transaction_standard_in_context` the spent scripts come before the fee
/// (check_transaction_standard.rs:105-157).
#[test]
fn after_consensus_the_storage_limit_answers_first_then_the_coins_then_the_fee() {
    let node = GateParams::testnet10();
    // A coin anyone can spend, a second output of `small` sompi and no fee.
    let build = |small: u64| {
        let coin = UtxoEntry::new(
            10 * KAS,
            one_opcode(OpTrue),
            node.pov_daa_score - 10_000,
            false,
            None,
        );
        let outpoint = TransactionOutpoint::new(Hash::from_bytes([0xc1; 32]), 0);
        let input = TransactionInput::new_with_compute_budget(outpoint, vec![], 0, 0);
        let receiver = TestKey::from_seed(2).p2pk_script_public_key();
        let outputs = vec![
            TransactionOutput::new(10 * KAS - small, receiver.clone()),
            TransactionOutput::new(small, receiver),
        ];
        Spend {
            tx: Transaction::new(1, vec![input], outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]),
            entries: vec![coin],
        }
    };

    let with_dust = submit(&node, &build(1_000));
    assert!(with_dust.verdict.consensus_accepted);
    assert_eq!(
        first_refusal(&with_dust),
        (
            Stage::MempoolAfterConsensus,
            "check_storage_mass_limit".to_string()
        )
    );
    assert_eq!(
        refused_rules(&with_dust),
        vec![
            PolicyRule::StorageMassLimit,
            PolicyRule::InputScriptsStandard,
            PolicyRule::MinimumRelayFee
        ]
    );

    // Without the dust the coin's script class is the first objection, not the fee.
    let without_dust = submit(&node, &build(5 * KAS));
    assert_eq!(
        first_refusal(&without_dust),
        (
            Stage::MempoolAfterConsensus,
            "check_input_scripts_standard".to_string()
        )
    );
    assert_eq!(
        refused_rules(&without_dust),
        vec![
            PolicyRule::InputScriptsStandard,
            PolicyRule::MinimumRelayFee
        ]
    );
}

/// A failing script is a consensus refusal and comes before every rule of
/// validate_and_insert_transaction.rs:76-77, also when the storage mass is far too high.
#[test]
fn a_failing_script_answers_before_the_storage_limit() {
    let node = GateParams::testnet10();
    let mut spend = plain_spend(&node);
    spend.tx.outputs[0].value = 9 * KAS;
    spend.tx.outputs.push(TransactionOutput::new(
        1_000,
        TestKey::from_seed(3).p2pk_script_public_key(),
    ));
    spend.tx.finalize();
    spend.sign();
    // Flip one bit of the signature.
    spend.tx.inputs[0].signature_script[10] ^= 1;

    let evaluation = submit(&node, &spend);
    assert_eq!(
        first_refusal(&evaluation),
        (Stage::Scripts, "check_scripts".to_string())
    );
    assert_eq!(
        refused_rules(&evaluation),
        vec![PolicyRule::StorageMassLimit]
    );
}

/// Before the standard mass cap is lifted, a transaction above a block limit is above the
/// cap as well. The limit is the node's answer: validate_and_insert_transaction.rs:32
/// comes before :33 and :76 before :77.
#[test]
fn before_the_relaxation_a_block_limit_answers_before_the_standard_cap() {
    let testnet = GateParams::testnet10();
    let activation = testnet.params.toccata_activation.daa_score();
    // One DAA score before the cap is lifted; Toccata is not active, so version 0.
    let node = testnet.with_daa_score(activation - 18_001);
    assert_eq!(
        policy::standard_transaction_mass_cap(&node.params, node.pov_daa_score),
        Some(100_000)
    );
    let key = TestKey::from_seed(1);
    let coin = UtxoEntry::new(
        10 * KAS,
        key.p2pk_script_public_key(),
        node.pov_daa_score - 10_000,
        false,
        None,
    );
    let receiver = TestKey::from_seed(2).p2pk_script_public_key();
    let input = |tag: u8, sig_op_count: u8| {
        let outpoint = TransactionOutpoint::new(Hash::from_bytes([tag; 32]), 0);
        TransactionInput::new(outpoint, vec![], 0, sig_op_count)
    };

    // Storage: a second output of 1,000 sompi. 10^12 / 1,000 grams against a limit of
    // 500,000 and a cap of 100,000.
    let tx = Transaction::new(
        0,
        vec![input(0xa1, 1)],
        vec![
            TransactionOutput::new(9 * KAS, receiver.clone()),
            TransactionOutput::new(1_000, receiver.clone()),
        ],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let mut spend = Spend {
        tx,
        entries: vec![coin.clone()],
    };
    spend.sign();
    let evaluation = submit(&node, &spend);
    assert!(
        evaluation.verdict.consensus_accepted,
        "{:?}",
        evaluation.verdict.consensus_refusal
    );
    assert_eq!(
        first_refusal(&evaluation),
        (
            Stage::MempoolAfterConsensus,
            "check_storage_mass_limit".to_string()
        )
    );
    assert_eq!(
        refused_rules(&evaluation),
        vec![
            PolicyRule::StorageMassLimit,
            PolicyRule::StandardStorageMassCap
        ]
    );

    // Compute: two inputs committing 255 signature operations each, 510,000 grams.
    let tx = Transaction::new(
        0,
        vec![input(0xa1, 255), input(0xa2, 255)],
        vec![TransactionOutput::new(19 * KAS, receiver)],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );
    let mut spend = Spend {
        tx,
        entries: vec![coin.clone(), coin],
    };
    spend.sign();
    let evaluation = submit(&node, &spend);
    assert_eq!(
        first_refusal(&evaluation),
        (
            Stage::MempoolBeforeConsensus,
            "check_compute_mass_limit".to_string()
        )
    );
    assert_eq!(
        refused_rules(&evaluation),
        vec![
            PolicyRule::ComputeMassLimit,
            PolicyRule::StandardComputeMassCap
        ]
    );
}
