//! Mempool policy: every rule tripped alone, with a neighbour that passes.

use kaspa_consensus_core::{
    constants::MAX_SOMPI,
    hashing::sighash_type::SIG_HASH_ALL,
    mass::NonContextualMasses,
    subnets::SubnetworkId,
    tx::{CovenantBinding, ScriptPublicKey, Transaction, TransactionOutput},
};
use kaspa_hashes::Hash;
use node_gate::{
    GateParams, Stage, mass,
    policy::{self, PolicyRefusal, PolicyRule, Priority},
    verdict::PolicyOutcome,
    wallet::{self, TestKey},
};

use crate::common::*;

const OP_FALSE: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_IF: u8 = 0x63;
const OP_ENDIF: u8 = 0x68;
const OP_CHECKSIG: u8 = 0xac;

/// The DAA score at which the standard mass cap is lifted on testnet-10: thirty minutes
/// (18,000 blocks at ten per second) before Toccata activation.
fn relaxation_score(gate: &GateParams) -> u64 {
    gate.params.toccata_activation.daa_score() - 18_000
}

/// `plain_spend` with its output value changed so that the fee is `fee`, signed again.
fn plain_spend_with_fee(gate: &GateParams, fee: u64) -> Spend {
    let mut spend = plain_spend(gate);
    spend.tx.outputs[0].value = 10 * KAS - fee;
    spend.tx.finalize();
    spend.sign_p2pk(0, &TestKey::from_seed(OWNER), SIG_HASH_ALL);
    spend
}

fn outcome(evaluation: &node_gate::Evaluation, rule: PolicyRule) -> PolicyOutcome {
    evaluation.verdict.policy.as_ref().expect("submit mode").outcome(rule).expect("every rule is listed").clone()
}

/// Asserts that exactly `rule` refused, with `refusal`, and that it is the node's answer.
fn assert_only(evaluation: &node_gate::Evaluation, rule: PolicyRule, refusal: PolicyRefusal) {
    let report = evaluation.verdict.policy.as_ref().expect("submit mode");
    let refused: Vec<(PolicyRule, PolicyRefusal)> = report.refusals().map(|(rule, refusal)| (rule, refusal.clone())).collect();
    assert_eq!(refused, vec![(rule, refusal.clone())]);
    assert_eq!(evaluation.policy_refusal, Some(refusal));
    assert!(!evaluation.verdict.accepted);
    assert!(!report.accepted);
}

#[test]
fn the_plain_spend_passes_every_rule() {
    let gate = node();
    let evaluation = submit(&gate, &plain_spend(&gate));
    assert!(evaluation.verdict.accepted);
    let report = evaluation.verdict.policy.expect("submit mode");
    assert!(report.accepted);
    assert_eq!(report.checks.len(), 10);
    assert!(report.checks.iter().all(|check| check.outcome == PolicyOutcome::Passed));
    assert_eq!(report.standard_mass_cap, None);
    // compute 1,626; transient 1,064, normalized to 532; fee floor 100 sompi per gram.
    assert_eq!((report.normalized_transient_mass, report.fee_mass, report.minimum_fee), (Some(532), Some(1_626), Some(162_600)));
    assert_eq!(report.p2sh_sig_ops, vec![None]);
}

#[test]
fn gas_limit() {
    let gate = node();
    let mut lane = [0u8; 20];
    lane[..4].copy_from_slice(&[1, 2, 3, 4]);
    let with_gas = |gas: u64| {
        let mut spend = plain_spend(&gate);
        spend.tx.subnetwork_id = SubnetworkId::from_bytes(lane);
        spend.tx.gas = gas;
        spend.tx.finalize();
        spend.sign_p2pk(0, &TestKey::from_seed(OWNER), SIG_HASH_ALL);
        spend
    };
    let over = submit(&gate, &with_gas(1_000_000_001));
    assert_only(&over, PolicyRule::GasLimit, PolicyRefusal::Gas { gas: 1_000_000_001, limit: 1_000_000_000 });
    assert_eq!(over.verdict.first_refusal.as_ref().unwrap().stage, Stage::MempoolBeforeConsensus);
    // Consensus has no objection to the transaction itself.
    assert!(over.verdict.consensus_accepted);

    assert!(submit(&gate, &with_gas(1_000_000_000)).verdict.accepted);
}

#[test]
fn compute_mass_limit() {
    let gate = node();
    // compute mass of the plain spend is 626 + 100 * budget.
    let with_budget = |budget: u16, fee: u64| {
        let mut spend = plain_spend_with_fee(&gate, fee);
        spend.tx.inputs[0].compute_commit = kaspa_consensus_core::mass::ComputeBudget(budget).into();
        spend
    };
    let over = submit(&gate, &with_budget(4_994, 60_000_000));
    assert_only(&over, PolicyRule::ComputeMassLimit, PolicyRefusal::ComputeMass { mass: 500_026, limit: 500_000 });
    assert_eq!(over.verdict.first_refusal.as_ref().unwrap().rule, "check_compute_mass_limit");

    assert!(submit(&gate, &with_budget(4_993, 60_000_000)).verdict.accepted);
}

#[test]
fn transient_mass_limit() {
    let gate = node();
    // 266 bytes without a payload; transient mass is four times the size.
    let with_payload = |len: usize, fee: u64| {
        let mut spend = plain_spend_with_fee(&gate, fee);
        spend.tx.payload = vec![0; len];
        spend.tx.finalize();
        spend.sign_p2pk(0, &TestKey::from_seed(OWNER), SIG_HASH_ALL);
        spend
    };
    let over = submit(&gate, &with_payload(249_735, 60_000_000));
    assert_only(&over, PolicyRule::TransientMassLimit, PolicyRefusal::TransientMass { mass: 1_000_004, limit: 1_000_000 });
    assert!(submit(&gate, &with_payload(249_734, 60_000_000)).verdict.accepted);

    // For one day after activation the mempool still applies the old limit of 500,000,
    // although a block may already carry more.
    let activation = gate.params.toccata_activation.daa_score();
    let early = gate.clone().with_daa_score(activation + 863_999);
    let masses = NonContextualMasses::new(1_000, 500_004);
    assert_eq!(
        policy::check_transient_mass_limit(&early.params, masses, early.pov_daa_score),
        Err(PolicyRefusal::TransientMass { mass: 500_004, limit: 500_000 })
    );
    assert_eq!(policy::check_transient_mass_limit(&early.params, masses, activation + 864_000), Ok(()));
    assert_eq!(early.params.block_mass_limits().get(early.pov_daa_score).transient, 1_000_000);
}

#[test]
fn standard_mass_caps_before_the_relaxation() {
    let gate = node();
    let lifted_at = relaxation_score(&gate);
    assert_eq!(policy::standard_transaction_mass_cap(&gate.params, lifted_at - 1), Some(100_000));
    assert_eq!(policy::standard_transaction_mass_cap(&gate.params, lifted_at), None);
    assert_eq!(policy::standard_transaction_mass_cap(&gate.params, gate.pov_daa_score), None);

    let before = lifted_at - 1;
    let params = &gate.params;
    let compute_heavy = NonContextualMasses::new(100_001, 1_000);
    assert_eq!(
        policy::check_standard_compute_mass_cap(params, compute_heavy, before),
        Err(PolicyRefusal::StandardComputeMass { mass: 100_001, cap: 100_000 })
    );
    assert_eq!(policy::check_standard_compute_mass_cap(params, NonContextualMasses::new(100_000, 1_000), before), Ok(()));
    assert_eq!(policy::check_standard_compute_mass_cap(params, compute_heavy, lifted_at), Ok(()));

    let transient_heavy = NonContextualMasses::new(1_000, 100_001);
    assert_eq!(
        policy::check_standard_transient_mass_cap(params, transient_heavy, before),
        Err(PolicyRefusal::StandardTransientMass { mass: 100_001, cap: 100_000 })
    );
    assert_eq!(policy::check_standard_transient_mass_cap(params, NonContextualMasses::new(1_000, 100_000), before), Ok(()));
    assert_eq!(policy::check_standard_transient_mass_cap(params, transient_heavy, lifted_at), Ok(()));

    assert_eq!(
        policy::check_standard_storage_mass_cap(params, 100_001, before),
        Err(PolicyRefusal::StandardStorageMass { mass: 100_001, cap: 100_000 })
    );
    assert_eq!(policy::check_standard_storage_mass_cap(params, 100_000, before), Ok(()));
    assert_eq!(policy::check_standard_storage_mass_cap(params, 100_001, lifted_at), Ok(()));

    // In the composed checks the storage cap answers before the spent scripts and the fee.
    let bare = bare_spend(&gate, &[OP_1], &[], 0);
    let masses = NonContextualMasses::new(1_000, 1_000);
    assert_eq!(
        policy::check_transaction_standard_in_context(params, &bare.tx, &bare.entries, masses, 100_001, 0, Priority::High, before),
        Err(PolicyRefusal::StandardStorageMass { mass: 100_001, cap: 100_000 })
    );
    assert_eq!(
        policy::check_transaction_standard_in_context(params, &bare.tx, &bare.entries, masses, 100_000, 0, Priority::High, before),
        Err(PolicyRefusal::InputScriptClass { input: 0 })
    );

    // In the composed checks the compute cap answers before the transient cap.
    let tx = plain_spend_v0(&gate).tx;
    assert_eq!(
        policy::check_transaction_standard_in_isolation(params, &tx, NonContextualMasses::new(100_001, 100_001), before),
        Err(PolicyRefusal::StandardComputeMass { mass: 100_001, cap: 100_000 })
    );
}

#[test]
fn the_standard_cap_on_a_real_transaction() {
    // A version 0 transaction committing 100 signature operations, one DAA score before
    // the cap is lifted: 264 bytes, one output script (360), 100,000 for the signature operations.
    let gate = node();
    let early = gate.clone().with_daa_score(relaxation_score(&gate) - 1);
    let owner = TestKey::from_seed(OWNER);
    let build = |sig_op_count: u8| {
        let entries = vec![coin(&early, 1_000 * KAS, owner.p2pk_script_public_key())];
        let tx = tx_v0(vec![input_v0(0xa1, sig_op_count)], vec![pay(RECEIVER, 900 * KAS)]);
        let mut spend = Spend::new(tx, entries);
        spend.sign_p2pk(0, &owner, SIG_HASH_ALL);
        spend
    };
    let over = submit(&early, &build(100));
    assert_only(&over, PolicyRule::StandardComputeMassCap, PolicyRefusal::StandardComputeMass { mass: 100_624, cap: 100_000 });
    assert_eq!(over.verdict.policy.as_ref().unwrap().standard_mass_cap, Some(100_000));
    assert!(over.verdict.consensus_accepted);
    assert!(submit(&early, &build(99)).verdict.accepted);
}

#[test]
fn output_scripts_must_be_standard() {
    let gate = node();
    let with_second_output = |script_public_key: ScriptPublicKey| {
        let mut spend = plain_spend(&gate);
        spend.tx.outputs[0].value = 4 * KAS;
        spend.tx.outputs.push(TransactionOutput::new(5 * KAS, script_public_key));
        spend.tx.finalize();
        spend.sign_p2pk(0, &TestKey::from_seed(OWNER), SIG_HASH_ALL);
        spend
    };

    let unknown_version =
        submit(&gate, &with_second_output(ScriptPublicKey::from_vec(1, pay(3, 1).script_public_key.script().to_vec())));
    assert_only(&unknown_version, PolicyRule::OutputScriptsStandard, PolicyRefusal::ScriptPublicKeyVersion { output: 1 });
    assert!(unknown_version.verdict.consensus_accepted);

    let bare = submit(&gate, &with_second_output(ScriptPublicKey::from_vec(0, vec![OP_1])));
    assert_only(&bare, PolicyRule::OutputScriptsStandard, PolicyRefusal::OutputScriptClass { output: 1 });
    assert!(bare.verdict.consensus_accepted);

    // The three standard forms pass.
    let key = TestKey::from_seed(3);
    for standard in [key.p2pk_script_public_key(), key.p2pk_ecdsa_script_public_key(), wallet::p2sh_script_public_key(&[OP_1])] {
        assert!(submit(&gate, &with_second_output(standard)).verdict.accepted);
    }
}

#[test]
fn a_covenant_binding_does_not_make_an_output_non_standard() {
    let gate = node();
    let mut tx = plain_spend(&gate).tx;
    tx.outputs[0].covenant = Some(CovenantBinding::new(0, Hash::from_bytes([9; 32])));
    assert_eq!(policy::check_output_scripts_standard(&tx), Ok(()));
}

#[test]
fn storage_mass_limit() {
    let gate = node();
    // A second output of 1000 sompi: its own term is 10^12 / 1000.
    let with_small_output = |value: u64| {
        let mut spend = plain_spend(&gate);
        spend.tx.outputs[0].value = 9 * KAS;
        spend.tx.outputs.push(pay(3, value));
        spend.tx.finalize();
        spend.sign_p2pk(0, &TestKey::from_seed(OWNER), SIG_HASH_ALL);
        spend
    };
    let small = submit(&gate, &with_small_output(1_000));
    // 10^9 + 10^12 / 900,000,000 - 10^12 / 1,000,000,000 = 10^9 + 1111 - 1000.
    assert_only(&small, PolicyRule::StorageMassLimit, PolicyRefusal::StorageMass { mass: 1_000_000_111, limit: 500_000 });
    // Every script passed; the node refuses afterwards.
    assert!(small.verdict.consensus_accepted);
    assert_eq!(small.verdict.first_refusal.as_ref().unwrap().stage, Stage::MempoolAfterConsensus);
    assert_eq!(small.verdict.first_refusal.as_ref().unwrap().rule, "check_storage_mass_limit");

    // 2,000,441 sompi: 499,889 + 1111 - 1000 = 500,000, exactly the limit.
    let at_limit = submit(&gate, &with_small_output(2_000_441));
    assert_eq!(at_limit.verdict.masses.as_ref().unwrap().calculated_storage_mass, Some(500_000));
    assert!(at_limit.verdict.accepted);
    // One sompi less and the output term is 499,890.
    let above = submit(&gate, &with_small_output(2_000_440));
    assert_only(&above, PolicyRule::StorageMassLimit, PolicyRefusal::StorageMass { mass: 500_001, limit: 500_000 });

    assert_eq!(
        policy::validate_transaction_limits_in_context(&gate.params, 500_001, gate.pov_daa_score),
        Err(PolicyRefusal::StorageMass { mass: 500_001, limit: 500_000 })
    );
}

#[test]
fn spent_scripts_must_be_standard() {
    let gate = node();
    // A coin whose script is just `OpTrue`: anyone can spend it as far as consensus goes.
    let bare = bare_spend(&gate, &[OP_1], &[], 0);
    let evaluation = submit(&gate, &bare);
    assert!(evaluation.verdict.consensus_accepted);
    assert_only(&evaluation, PolicyRule::InputScriptsStandard, PolicyRefusal::InputScriptClass { input: 0 });

    // The same script behind a hash is standard.
    assert!(submit(&gate, &p2sh_spend(&gate, &[OP_1], &[], 0)).verdict.accepted);
}

#[test]
fn signature_operations_in_a_redeem_script() {
    let gate = node();
    // The checks sit in a branch that never runs; the scanner counts them all the same.
    let redeem_script = |checks: usize| {
        let mut script = vec![OP_FALSE, OP_IF];
        script.extend(std::iter::repeat_n(OP_CHECKSIG, checks));
        script.extend_from_slice(&[OP_ENDIF, OP_1]);
        script
    };
    let sixteen = submit(&gate, &p2sh_spend(&gate, &redeem_script(16), &[], 0));
    assert!(sixteen.verdict.consensus_accepted);
    assert_eq!(sixteen.committed_runs[0].used_sig_ops, 0);
    assert_only(&sixteen, PolicyRule::InputScriptsStandard, PolicyRefusal::SignatureCount { input: 0, found: 16, max: 15 });
    assert_eq!(sixteen.verdict.policy.as_ref().unwrap().p2sh_sig_ops, vec![Some(16)]);

    let fifteen = submit(&gate, &p2sh_spend(&gate, &redeem_script(15), &[], 0));
    assert!(fifteen.verdict.accepted);
    assert_eq!(fifteen.verdict.policy.as_ref().unwrap().p2sh_sig_ops, vec![Some(15)]);
}

#[test]
fn minimum_relay_fee_on_compute_mass() {
    let gate = node();
    // compute mass 1,626 against 2 * 266 bytes: the compute mass sets the floor.
    let under = submit(&gate, &plain_spend_with_fee(&gate, 162_599));
    assert_only(
        &under,
        PolicyRule::MinimumRelayFee,
        PolicyRefusal::InsufficientComputeFee { fee: 162_599, minimum_fee: 162_600, compute_mass: 1_626 },
    );
    assert!(under.verdict.consensus_accepted);
    assert!(submit(&gate, &plain_spend_with_fee(&gate, 162_600)).verdict.accepted);

    // No fee at all.
    let free = submit(&gate, &plain_spend_with_fee(&gate, 0));
    assert_eq!(
        outcome(&free, PolicyRule::MinimumRelayFee),
        PolicyOutcome::Refused(PolicyRefusal::InsufficientComputeFee { fee: 0, minimum_fee: 162_600, compute_mass: 1_626 })
    );
}

#[test]
fn minimum_relay_fee_on_size() {
    let gate = node();
    // A 2,000-byte payload: 2,266 bytes, compute mass 3,626, twice the size 4,532.
    let with_fee = |fee: u64| {
        let mut spend = plain_spend_with_fee(&gate, fee);
        spend.tx.payload = vec![0; 2_000];
        spend.tx.finalize();
        spend.sign_p2pk(0, &TestKey::from_seed(OWNER), SIG_HASH_ALL);
        spend
    };
    let under = submit(&gate, &with_fee(453_199));
    assert_only(
        &under,
        PolicyRule::MinimumRelayFee,
        PolicyRefusal::InsufficientTransientFee { fee: 453_199, minimum_fee: 453_200, normalized_transient_mass: 4_532 },
    );
    assert!(submit(&gate, &with_fee(453_200)).verdict.accepted);
}

#[test]
fn fee_floor_arithmetic() {
    let gate = node();
    // One gram of fee mass costs 100 sompi.
    assert_eq!(policy::minimum_required_transaction_relay_fee(1_000, policy::DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE), 100_000);
    assert_eq!(policy::minimum_required_transaction_relay_fee(2_036, policy::DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE), 203_600);
    assert_eq!(policy::minimum_required_transaction_relay_fee(4_137, policy::DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE), 413_700);
    // A mass that rounds to no fee still costs the rate itself.
    assert_eq!(policy::minimum_required_transaction_relay_fee(0, policy::DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE), 100_000);
    assert_eq!(policy::minimum_required_transaction_relay_fee(0, policy::LEGACY_MINIMUM_RELAY_TRANSACTION_FEE), 1_000);
    // The cap at the money supply cannot bind: the product is formed in 64 bits before the
    // division, so the result is at most 2^64 / 1000, far below MAX_SOMPI.
    const { assert!(u64::MAX / 1000 < MAX_SOMPI) };

    // Transient mass is halved, rounded up.
    assert_eq!(policy::normalized_transient_mass(&gate.params, NonContextualMasses::new(0, 1_264)), 632);
    assert_eq!(policy::normalized_transient_mass(&gate.params, NonContextualMasses::new(0, 1_265)), 633);
    // The cofactor is the post-activation one on both sides of the fork.
    assert_eq!(policy::normalized_transient_mass(&node_before_toccata().params, NonContextualMasses::new(0, 1_264)), 632);
}

#[test]
fn before_toccata_peers_relay_under_the_old_fee_rule() {
    let before = node_before_toccata();
    let after = node();
    // The everyday version 0 transaction: compute mass 2,036, transient 1,264.
    let masses = NonContextualMasses::new(2_036, 1_264);
    let daa = before.pov_daa_score;

    assert_eq!(policy::minimum_relay_fee_terms(&before.params, masses, Priority::Low, daa), (2_036, 1_000, 2_036));
    assert_eq!(policy::check_minimum_relay_fee(&before.params, masses, 2_036, Priority::Low, daa), Ok(()));
    assert_eq!(
        policy::check_minimum_relay_fee(&before.params, masses, 2_035, Priority::Low, daa),
        Err(PolicyRefusal::InsufficientComputeFee { fee: 2_035, minimum_fee: 2_036, compute_mass: 2_036 })
    );
    // A submission over RPC pays the new rate already.
    assert_eq!(policy::minimum_relay_fee_terms(&before.params, masses, Priority::High, daa), (2_036, 100_000, 203_600));
    // After activation the priority makes no difference.
    assert_eq!(policy::minimum_relay_fee_terms(&after.params, masses, Priority::Low, after.pov_daa_score), (2_036, 100_000, 203_600));

    // Under the old rule the size is ignored even when it would dominate.
    let bulky = NonContextualMasses::new(2_036, 40_000);
    assert_eq!(policy::minimum_relay_fee_terms(&before.params, bulky, Priority::Low, daa), (2_036, 1_000, 2_036));
    assert_eq!(
        policy::check_minimum_relay_fee(&before.params, bulky, 0, Priority::Low, daa),
        Err(PolicyRefusal::InsufficientComputeFee { fee: 0, minimum_fee: 2_036, compute_mass: 2_036 })
    );
    assert_eq!(
        policy::check_minimum_relay_fee(&before.params, bulky, 0, Priority::High, daa),
        Err(PolicyRefusal::InsufficientTransientFee { fee: 0, minimum_fee: 2_000_000, normalized_transient_mass: 20_000 })
    );
}

#[test]
fn rules_that_cannot_be_evaluated_say_so() {
    let gate = node();
    // The coin is unknown: no storage mass, no fee, no spent script.
    let mut spend = plain_spend(&gate);
    spend.entries.clear();
    let evaluation = submit(&gate, &spend);
    for rule in PolicyRule::AFTER_CONSENSUS {
        assert_eq!(outcome(&evaluation, rule), PolicyOutcome::NotEvaluated, "{rule:?}");
    }
    for rule in PolicyRule::BEFORE_CONSENSUS {
        assert_eq!(outcome(&evaluation, rule), PolicyOutcome::Passed, "{rule:?}");
    }
    assert!(!evaluation.verdict.policy.as_ref().unwrap().accepted);
    assert_eq!(evaluation.policy_refusal, None);

    // A compute commitment of the wrong kind: no masses at all.
    let mixed = Spend::new(tx_v1(vec![input_v0(1, 1)], vec![pay(2, KAS)]), vec![coin(&gate, 2 * KAS, pay(1, 1).script_public_key)]);
    let evaluation = submit(&gate, &mixed);
    assert_eq!(evaluation.verdict.masses, None);
    assert_eq!(outcome(&evaluation, PolicyRule::ComputeMassLimit), PolicyOutcome::NotEvaluated);
    assert_eq!(outcome(&evaluation, PolicyRule::GasLimit), PolicyOutcome::Passed);
    assert_eq!(evaluation.verdict.first_refusal.as_ref().unwrap().stage, Stage::PreMass);
}

#[test]
fn the_composed_checks_answer_in_upstream_order() {
    let gate = node();
    let params = &gate.params;
    let daa = gate.pov_daa_score;

    // Gas, then compute, then transient.
    let mut tx: Transaction = plain_spend(&gate).tx;
    tx.gas = u64::MAX;
    let heavy = NonContextualMasses::new(600_000, 2_000_000);
    assert!(matches!(policy::validate_transaction_limits_in_isolation(params, &tx, heavy, daa), Err(PolicyRefusal::Gas { .. })));
    tx.gas = 0;
    assert!(matches!(
        policy::validate_transaction_limits_in_isolation(params, &tx, heavy, daa),
        Err(PolicyRefusal::ComputeMass { .. })
    ));
    let bulky = NonContextualMasses::new(1_000, 2_000_000);
    assert!(matches!(
        policy::validate_transaction_limits_in_isolation(params, &tx, bulky, daa),
        Err(PolicyRefusal::TransientMass { .. })
    ));

    // Spent script class, then signature count, then fee.
    let spend = bare_spend(&gate, &[OP_1], &[], 0);
    let masses = mass::calculate_transaction_non_contextual_masses(params, &spend.tx).unwrap();
    assert_eq!(
        policy::check_transaction_standard_in_context(params, &spend.tx, &spend.entries, masses, 0, 0, Priority::High, daa),
        Err(PolicyRefusal::InputScriptClass { input: 0 })
    );
    let spend = plain_spend(&gate);
    let masses = mass::calculate_transaction_non_contextual_masses(params, &spend.tx).unwrap();
    assert!(matches!(
        policy::check_transaction_standard_in_context(params, &spend.tx, &spend.entries, masses, 0, 0, Priority::High, daa),
        Err(PolicyRefusal::InsufficientComputeFee { .. })
    ));
    assert_eq!(
        policy::check_transaction_standard_in_context(params, &spend.tx, &spend.entries, masses, 0, 162_600, Priority::High, daa),
        Ok(())
    );
}

#[test]
fn limits_are_inclusive() {
    let gate = node();
    let params = &gate.params;
    let daa = gate.pov_daa_score;
    let masses = NonContextualMasses::new;

    assert_eq!(policy::check_compute_mass_limit(params, masses(500_000, 0), daa), Ok(()));
    assert_eq!(
        policy::check_compute_mass_limit(params, masses(500_001, 0), daa),
        Err(PolicyRefusal::ComputeMass { mass: 500_001, limit: 500_000 })
    );
    assert_eq!(policy::check_transient_mass_limit(params, masses(0, 1_000_000), daa), Ok(()));
    assert_eq!(
        policy::check_transient_mass_limit(params, masses(0, 1_000_001), daa),
        Err(PolicyRefusal::TransientMass { mass: 1_000_001, limit: 1_000_000 })
    );
    assert_eq!(policy::check_storage_mass_limit(params, 500_000, daa), Ok(()));
    assert_eq!(
        policy::check_storage_mass_limit(params, 500_001, daa),
        Err(PolicyRefusal::StorageMass { mass: 500_001, limit: 500_000 })
    );

    let mut tx = plain_spend(&gate).tx;
    tx.gas = 1_000_000_000;
    assert_eq!(policy::check_gas_limit(params, &tx), Ok(()));
    tx.gas += 1;
    assert_eq!(policy::check_gas_limit(params, &tx), Err(PolicyRefusal::Gas { gas: 1_000_000_001, limit: 1_000_000_000 }));
}

#[test]
fn a_fee_floor_tie_is_reported_on_compute_mass() {
    let gate = node();
    // compute mass 1,000 and transient mass 2,000, which normalizes to 1,000.
    let tie = NonContextualMasses::new(1_000, 2_000);
    assert_eq!(
        policy::check_minimum_relay_fee(&gate.params, tie, 99_999, Priority::High, gate.pov_daa_score),
        Err(PolicyRefusal::InsufficientComputeFee { fee: 99_999, minimum_fee: 100_000, compute_mass: 1_000 })
    );
    assert_eq!(policy::check_minimum_relay_fee(&gate.params, tie, 100_000, Priority::High, gate.pov_daa_score), Ok(()));
    let just_over = NonContextualMasses::new(1_000, 2_001);
    assert_eq!(
        policy::check_minimum_relay_fee(&gate.params, just_over, 99_999, Priority::High, gate.pov_daa_score),
        Err(PolicyRefusal::InsufficientTransientFee { fee: 99_999, minimum_fee: 100_100, normalized_transient_mass: 1_001 })
    );
}

#[test]
fn refusals_know_their_upstream_error() {
    assert_eq!(PolicyRefusal::Gas { gas: 2, limit: 1 }.upstream_error(), "RuleError::RejectGas");
    assert!(!PolicyRefusal::StorageMass { mass: 2, limit: 1 }.is_standardness());
    assert_eq!(PolicyRefusal::StandardStorageMass { mass: 2, cap: 1 }.upstream_error(), "NonStandardError::RejectStorageMass");
    assert!(PolicyRefusal::InputScriptClass { input: 0 }.is_standardness());
    assert_eq!(
        PolicyRefusal::SignatureCount { input: 3, found: 16, max: 15 }.to_string(),
        "non-standard: transaction input #3 has 16 signature operations which is more than the allowed max amount of 15"
    );
}

/// The stage and the rule of the node's answer.
fn first_refusal(evaluation: &node_gate::Evaluation) -> (Stage, String) {
    let first = evaluation.verdict.first_refusal.clone().expect("the transaction is refused");
    (first.stage, first.rule)
}

/// The rules that refuse in the rule-by-rule report, in the order of the report.
fn refusing_rules(evaluation: &node_gate::Evaluation) -> Vec<PolicyRule> {
    evaluation.verdict.policy.as_ref().expect("submit mode").refusals().map(|(rule, _)| rule).collect()
}

/// A transaction that breaks several mempool rules at once is answered by the first of
/// them in the node's order (rusty-kaspa a41a333
/// mining/src/mempool/validate_and_insert_transaction.rs:30-33, 76-77;
/// check_transaction_limits.rs:19-30; check_transaction_standard.rs:58-77, 98-157). The
/// node's answer is taken from the composed ports, the report walks the two rule lists:
/// taking one refusal away at a time holds the two against each other through
/// `gate::evaluate`.
#[test]
fn several_refusals_are_answered_in_the_node_order() {
    let gate = node();
    let before = Stage::MempoolBeforeConsensus;
    let after = Stage::MempoolAfterConsensus;
    let mut lane = [0u8; 20];
    lane[..4].copy_from_slice(&[1, 2, 3, 4]);

    // Before the consensus validation: gas, compute mass, transient mass, the outputs.
    // Gas above the lane limit; a budget of 499,400 grams on top of a payload of 250,000
    // bytes, which is 250,000 grams of compute mass and a million of transient mass; and
    // an output locked by a bare `OpTrue`.
    let mut spend = plain_spend(&gate);
    spend.tx.subnetwork_id = SubnetworkId::from_bytes(lane);
    spend.tx.gas = 1_000_000_001;
    spend.tx.inputs[0].compute_commit = kaspa_consensus_core::mass::ComputeBudget(4_994).into();
    spend.tx.payload = vec![0; 250_000];
    spend.tx.outputs[0].script_public_key = ScriptPublicKey::from_vec(0, vec![OP_1]);
    spend.tx.finalize();
    let all_four = submit(&gate, &spend);
    assert_eq!(first_refusal(&all_four), (before, "check_gas_limit".to_string()));
    assert_eq!(
        refusing_rules(&all_four)[..4],
        [PolicyRule::GasLimit, PolicyRule::ComputeMassLimit, PolicyRule::TransientMassLimit, PolicyRule::OutputScriptsStandard]
    );

    spend.tx.gas = 0;
    spend.tx.finalize();
    assert_eq!(first_refusal(&submit(&gate, &spend)), (before, "check_compute_mass_limit".to_string()));

    spend.tx.inputs[0].compute_commit = kaspa_consensus_core::mass::ComputeBudget(10).into();
    spend.tx.finalize();
    let two_left = submit(&gate, &spend);
    assert_eq!(first_refusal(&two_left), (before, "check_transient_mass_limit".to_string()));
    assert_eq!(refusing_rules(&two_left)[..2], [PolicyRule::TransientMassLimit, PolicyRule::OutputScriptsStandard]);

    spend.tx.payload.clear();
    spend.tx.finalize();
    assert_eq!(first_refusal(&submit(&gate, &spend)), (before, "check_output_scripts_standard".to_string()));

    // The check a node makes before it calculates the masses answers before all of them:
    // a version 1 transaction with a version 0 input has no masses, and its non-standard
    // output is only one more reason in the report.
    let mut mixed =
        Spend::new(tx_v1(vec![input_v0(1, 1)], vec![pay(2, KAS)]), vec![coin(&gate, 2 * KAS, pay(1, 1).script_public_key)]);
    mixed.tx.outputs[0].script_public_key = ScriptPublicKey::from_vec(0, vec![OP_1]);
    mixed.tx.finalize();
    let evaluation = submit(&gate, &mixed);
    assert_eq!(first_refusal(&evaluation).0, Stage::PreMass);
    assert_eq!(refusing_rules(&evaluation), vec![PolicyRule::OutputScriptsStandard]);

    // After the consensus validation: the storage limit, the spent scripts, the fee. A
    // coin locked by a bare `OpTrue` (anyone can spend it as far as consensus goes), an
    // output of 1000 sompi and no fee.
    let spend_of_bare_coin = |values: &[u64]| {
        let mut spend = bare_spend(&gate, &[OP_1], &[], 0);
        spend.tx.outputs = values.iter().map(|value| pay(RECEIVER, *value)).collect();
        spend.tx.finalize();
        spend
    };
    let all_three = submit(&gate, &spend_of_bare_coin(&[10 * KAS - 1_000, 1_000]));
    assert!(all_three.verdict.consensus_accepted);
    assert_eq!(first_refusal(&all_three), (after, "check_storage_mass_limit".to_string()));
    assert_eq!(
        refusing_rules(&all_three),
        vec![PolicyRule::StorageMassLimit, PolicyRule::InputScriptsStandard, PolicyRule::MinimumRelayFee]
    );

    let two_left = submit(&gate, &spend_of_bare_coin(&[10 * KAS]));
    assert_eq!(first_refusal(&two_left), (after, "check_input_scripts_standard".to_string()));
    assert_eq!(refusing_rules(&two_left), vec![PolicyRule::InputScriptsStandard, PolicyRule::MinimumRelayFee]);

    // The same script behind a hash is standard: only the fee is left.
    let mut standard = p2sh_spend(&gate, &[OP_1], &[], 0);
    standard.tx.outputs[0].value = 10 * KAS;
    standard.tx.finalize();
    assert_eq!(first_refusal(&submit(&gate, &standard)), (after, "check_minimum_relay_fee".to_string()));

    // While the standard cap is in force, the storage cap sits between the storage limit
    // and the spent scripts. A version 0 spend of a bare coin one DAA score before the
    // cap is lifted, with a second output of 0.05 KAS: 10^12 / 5,000,000 = 200,000 for
    // that output, which is above the cap of 100,000 and below the limit of 500,000.
    let early = gate.clone().with_daa_score(relaxation_score(&gate) - 1);
    let entries = vec![coin(&early, 10 * KAS, ScriptPublicKey::from_vec(0, vec![OP_1]))];
    let tx = tx_v0(vec![input_v0(0xc1, 0)], vec![pay(RECEIVER, 10 * KAS - 5_000_000), pay(RECEIVER, 5_000_000)]);
    let capped = submit(&early, &Spend::new(tx, entries));
    assert!(capped.verdict.consensus_accepted);
    assert_eq!(first_refusal(&capped), (after, "check_standard_storage_mass_cap".to_string()));
    assert_eq!(
        refusing_rules(&capped),
        vec![PolicyRule::StandardStorageMassCap, PolicyRule::InputScriptsStandard, PolicyRule::MinimumRelayFee]
    );
}
