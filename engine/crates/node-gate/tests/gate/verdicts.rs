//! The verdict as a whole: the two modes, the order of refusals, what is recorded when,
//! and the plain-data form.

use kaspa_consensus_core::{
    errors::tx::TxRuleError,
    hashing::sighash_type::SIG_HASH_ALL,
    subnets::SubnetworkId,
    tx::{ScriptPublicKey, TransactionOutput},
};
use kaspa_txscript::script_class::ScriptClass;
use kaspa_txscript_errors::TxScriptError;
use node_gate::{
    ErrorClass, GateOptions, GateParams, GateVerdict, Mode, Stage, StopPoint,
    block::{self, BlockMassError},
    policy::{PolicyRefusal, PolicyRule},
    verdict::{Commitment, PolicyOutcome},
    wallet::TestKey,
};

use crate::common::*;

fn resign(spend: &mut Spend) {
    spend.tx.finalize();
    spend.sign_p2pk(0, &TestKey::from_seed(OWNER), SIG_HASH_ALL);
}

#[test]
fn an_accepted_submission() {
    let gate = node();
    let evaluation = submit(&gate, &plain_spend(&gate));
    let verdict = &evaluation.verdict;
    assert!(verdict.accepted && verdict.consensus_accepted);
    assert_eq!((verdict.mode, verdict.stage_reached), (Mode::Submit, Stage::Accepted));
    assert_eq!((verdict.first_refusal.clone(), verdict.consensus_refusal.clone(), verdict.harness_error.clone()), (None, None, None));
    assert_eq!(verdict.network, "kaspa-testnet-10");
    assert!(verdict.toccata_active);
    assert_eq!(verdict.fee, Some(PLAIN_FEE));

    let masses = verdict.masses.as_ref().unwrap();
    assert_eq!((masses.estimated_size, masses.compute_mass, masses.transient_mass), (266, 1_626, 1_064));
    assert_eq!((masses.calculated_storage_mass, masses.committed_storage_mass), (Some(1), 1));
    assert_eq!((masses.input_plurality.clone(), masses.output_plurality.clone()), (vec![1], vec![1]));

    let input = &verdict.inputs[0];
    assert_eq!((input.index, input.spent_script_class.clone(), input.spent_has_covenant_id), (0, ScriptClass::PubKey, false));
    assert_eq!((input.signature_script_len, input.commitment), (66, Commitment::ComputeBudget(10)));
    assert!(input.committed.accepted);
    assert_eq!(
        (input.committed.script_units_limit, input.committed.used_script_units, input.committed.used_sig_ops),
        (Some(109_999), 100_001, 1)
    );
    let measured = input.measured.as_ref().unwrap();
    assert_eq!((measured.script_units_limit, measured.used_script_units), (Some(u64::MAX), 100_001));
    assert_eq!(input.minimal_budget, Some(10));
}

#[test]
fn the_same_spend_on_mainnet() {
    let gate = GateParams::mainnet();
    let evaluation = submit(&gate, &plain_spend(&gate));
    assert!(evaluation.verdict.accepted);
    assert_eq!(evaluation.verdict.network, "kaspa-mainnet");
}

#[test]
fn verdicts_survive_json() {
    let gate = node();

    let accepted = submit(&gate, &plain_spend(&gate)).verdict;
    let json = accepted.to_json();
    assert_eq!(serde_json::from_str::<GateVerdict>(&json).unwrap(), accepted);
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["mode"], "submit");
    assert_eq!(value["stage_reached"], "accepted");
    assert_eq!(value["inputs"][0]["commitment"]["compute_budget"], 10);
    assert_eq!(value["policy"]["checks"][0]["rule"], "gas_limit");
    assert_eq!(value["policy"]["checks"][0]["outcome"], "passed");

    // A refusal with a stop position, an error class and a policy refusal.
    let mut spend = plain_spend(&gate);
    spend.tx.outputs[0].value = 10 * KAS;
    spend.tx.inputs[0].signature_script.clear();
    spend.tx.finalize();
    let refused = submit(&gate, &spend).verdict;
    let json = refused.to_json();
    assert_eq!(serde_json::from_str::<GateVerdict>(&json).unwrap(), refused);
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["first_refusal"]["stage"], "scripts");
    assert_eq!(value["first_refusal"]["rule"], "check_scripts");
    assert_eq!(value["first_refusal"]["error"], "SignatureEmpty(InvalidStackOperation(2, 1))");
    assert_eq!(value["first_refusal"]["input"], 0);
    assert_eq!(value["inputs"][0]["committed"]["class"], "engine_refused_data");
    assert_eq!(value["inputs"][0]["committed"]["stop"]["opcode"]["script"], "script_public_key");
    assert_eq!(value["inputs"][0]["committed"]["stop"]["opcode"]["byte_offset"], 33);
    // Without the signature script the transaction is 200 bytes: compute mass 1,560.
    assert_eq!(value["policy"]["checks"][9]["outcome"]["refused"]["insufficient_compute_fee"]["minimum_fee"], 156_000);
}

#[test]
fn on_submission_the_first_refusal_follows_the_node_order() {
    let gate = node();
    // A non-standard output, a wrong signature and no fee.
    let mut spend = plain_spend(&gate);
    spend.tx.outputs[0] = TransactionOutput::new(10 * KAS, ScriptPublicKey::from_vec(0, vec![0x51]));
    spend.tx.finalize();
    spend.sign_p2pk(0, &TestKey::from_seed(9), SIG_HASH_ALL);
    let evaluation = submit(&gate, &spend);
    let verdict = &evaluation.verdict;

    // The mempool looks at the outputs before any consensus rule runs.
    let first = verdict.first_refusal.as_ref().unwrap();
    assert_eq!((first.stage, first.rule.as_str()), (Stage::MempoolBeforeConsensus, "check_output_scripts_standard"));
    assert_eq!(evaluation.policy_refusal, Some(PolicyRefusal::OutputScriptClass { output: 0 }));
    // The consensus refusal is reported next to it.
    let consensus = verdict.consensus_refusal.as_ref().unwrap();
    assert_eq!((consensus.stage, consensus.rule.as_str(), consensus.input), (Stage::Scripts, "check_scripts", Some(0)));
    assert_eq!(evaluation.consensus_error, Some(TxRuleError::SignatureInvalid(TxScriptError::EvalFalse)));
    // And every later rule that also refuses.
    let report = verdict.policy.as_ref().unwrap();
    assert_eq!(
        report.refusals().map(|(rule, _)| rule).collect::<Vec<_>>(),
        vec![PolicyRule::OutputScriptsStandard, PolicyRule::MinimumRelayFee]
    );

    // With a standard output the script failure is the first refusal.
    let mut spend = plain_spend(&gate);
    spend.tx.outputs[0].value = 10 * KAS;
    spend.tx.finalize();
    spend.sign_p2pk(0, &TestKey::from_seed(9), SIG_HASH_ALL);
    let evaluation = submit(&gate, &spend);
    assert_eq!(evaluation.verdict.first_refusal.as_ref().unwrap().stage, Stage::Scripts);

    // With a good signature only the fee is left, after consensus.
    spend.sign_p2pk(0, &TestKey::from_seed(OWNER), SIG_HASH_ALL);
    let evaluation = submit(&gate, &spend);
    let first = evaluation.verdict.first_refusal.as_ref().unwrap();
    assert_eq!((first.stage, first.rule.as_str()), (Stage::MempoolAfterConsensus, "check_minimum_relay_fee"));
    assert!(evaluation.verdict.consensus_accepted);
}

#[test]
fn a_block_needs_no_fee_and_no_standard_scripts() {
    let gate = node();
    let mut spend = plain_spend(&gate);
    spend.tx.outputs[0] = TransactionOutput::new(10 * KAS, ScriptPublicKey::from_vec(0, vec![0x51]));
    resign(&mut spend);
    spend.commit_storage_mass(&gate);
    let mined = in_block(&gate, &spend);
    assert!(mined.verdict.accepted);
    assert_eq!(mined.verdict.policy, None);
    assert_eq!((mined.verdict.mode, mined.verdict.fee), (Mode::Block, Some(0)));

    assert!(!submit(&gate, &spend).verdict.accepted);
}

#[test]
fn block_limits_on_one_transaction() {
    let gate = node();
    let refusal = |spend: &Spend| {
        let evaluation = in_block(&gate, spend);
        assert_eq!(evaluation.verdict.stage_reached, Stage::BlockMass);
        assert_eq!(evaluation.verdict.first_refusal.as_ref().unwrap().rule, "check_block_mass");
        assert_eq!(evaluation.consensus_error, None);
        evaluation.block_mass_error.expect("a block limit")
    };

    // Compute mass: 626 + 100 * budget.
    let mut spend = plain_spend(&gate);
    spend.commit_storage_mass(&gate);
    spend.tx.inputs[0].compute_commit = kaspa_consensus_core::mass::ComputeBudget(4_994).into();
    assert_eq!(refusal(&spend), BlockMassError::ExceedsComputeMassLimit(500_026, 500_000));
    spend.tx.inputs[0].compute_commit = kaspa_consensus_core::mass::ComputeBudget(4_993).into();
    assert!(in_block(&gate, &spend).verdict.accepted);

    // Exactly at the limit: budget 4,993 and a payload of 74 bytes make 500,000 grams.
    let with_payload_and_budget = |len: usize| {
        let mut spend = plain_spend(&gate);
        spend.tx.payload = vec![0; len];
        spend.tx.inputs[0].compute_commit = kaspa_consensus_core::mass::ComputeBudget(4_993).into();
        resign(&mut spend);
        spend.commit_storage_mass(&gate);
        spend
    };
    assert_eq!(block::check_block_mass(&gate, &with_payload_and_budget(74).tx), Ok(()));
    assert_eq!(refusal(&with_payload_and_budget(75)), BlockMassError::ExceedsComputeMassLimit(500_001, 500_000));

    // Transient mass: four grams per byte, 266 bytes without the payload.
    let with_payload = |len: usize| {
        let mut spend = plain_spend(&gate);
        spend.tx.payload = vec![0; len];
        resign(&mut spend);
        spend.commit_storage_mass(&gate);
        spend
    };
    assert_eq!(refusal(&with_payload(249_735)), BlockMassError::ExceedsTransientMassLimit(1_000_004, 1_000_000));
    assert!(in_block(&gate, &with_payload(249_734)).verdict.accepted);

    // Storage mass: the block limit is checked on the commitment, before anything can
    // tell whether the commitment is right.
    let spend = plain_spend(&gate);
    spend.tx.set_storage_mass(500_001);
    assert_eq!(refusal(&spend), BlockMassError::ExceedsStorageMassLimit(500_001, 500_000));
    spend.tx.set_storage_mass(500_000);
    assert_eq!(in_block(&gate, &spend).consensus_error, Some(TxRuleError::WrongMass(1, 500_000)));

    // Gas of one lane.
    let mut lane = [0u8; 20];
    lane[..4].copy_from_slice(&[1, 2, 3, 4]);
    let with_gas = |gas: u64| {
        let mut spend = plain_spend(&gate);
        spend.tx.subnetwork_id = SubnetworkId::from_bytes(lane);
        spend.tx.gas = gas;
        resign(&mut spend);
        spend.commit_storage_mass(&gate);
        spend
    };
    // The refusal names the lane, then the gas and the limit, as a node words it
    // (consensus/core/src/errors/block.rs:115-116).
    let over = refusal(&with_gas(1_000_000_001));
    assert_eq!(over, BlockMassError::ExceedsGasPerLaneLimit(SubnetworkId::from_bytes(lane), 1_000_000_001, 1_000_000_000));
    assert_eq!(over.to_string(), format!("block lane {} gas 1000000001 exceeds limit of 1000000000", SubnetworkId::from_bytes(lane)));
    assert!(in_block(&gate, &with_gas(1_000_000_000)).verdict.accepted);
}

#[test]
fn before_toccata_a_block_holds_half_the_transient_mass() {
    let before = node_before_toccata();
    let mut spend = plain_spend_v0(&before);
    // 264 bytes without the payload.
    spend.tx.payload = vec![0; 124_737];
    resign(&mut spend);
    spend.commit_storage_mass(&before);
    assert_eq!(block::check_block_mass(&before, &spend.tx), Err(BlockMassError::ExceedsTransientMassLimit(500_004, 500_000)));
    // The same transaction after the fork fits.
    assert_eq!(block::check_block_mass(&node(), &spend.tx), Ok(()));
}

#[test]
fn scripts_are_run_even_when_an_earlier_rule_refused() {
    let gate = node();
    let mut spend = plain_spend(&gate);
    spend.tx.outputs[0].value = 11 * KAS;
    resign(&mut spend);
    let evaluation = submit(&gate, &spend);
    assert_eq!(evaluation.consensus_error, Some(TxRuleError::SpendTooHigh(11 * KAS, 10 * KAS)));
    assert_eq!(evaluation.verdict.stage_reached, Stage::UtxoContext);
    // A node would not have got to the scripts; the gate still says what they answer.
    assert!(evaluation.verdict.inputs[0].committed.accepted);
    assert_eq!(evaluation.verdict.consensus_refusal.as_ref().unwrap().input, None);
}

#[test]
fn committed_and_measured_runs_side_by_side() {
    let gate = node();
    let mut spend = plain_spend(&gate);
    spend.tx.inputs[0].compute_commit = kaspa_consensus_core::mass::ComputeBudget(3).into();

    let evaluation = submit(&gate, &spend);
    let input = &evaluation.verdict.inputs[0];
    assert_eq!(input.commitment, Commitment::ComputeBudget(3));
    assert_eq!(input.committed.error.as_deref(), Some("ExceededCommittedScriptUnits { used: 100000, limit: 39999 }"));
    assert_eq!(input.committed.class, Some(ErrorClass::ResourceLimit));
    assert!(matches!(input.committed.stop, Some(StopPoint::Opcode(_))));
    assert!(input.measured.as_ref().unwrap().accepted);
    assert_eq!(input.minimal_budget, Some(10));

    let mut quick = GateOptions::submit();
    quick.measure_budgets = false;
    quick.locate_stops = false;
    let evaluation = evaluate(&gate, &spend, quick);
    let input = &evaluation.verdict.inputs[0];
    assert_eq!((input.measured.clone(), input.minimal_budget, input.committed.stop.clone()), (None, None, None));
    assert!(evaluation.measured_runs.is_empty());
    // Without a position the class is the variant's first class.
    assert_eq!(input.committed.class, Some(ErrorClass::ResourceLimit));
}

#[test]
fn questions_no_node_could_be_asked() {
    let gate = node();
    let spend = plain_spend(&gate);
    let harness = |gate: &GateParams, spend: &Spend, options: GateOptions| {
        let evaluation = node_gate::evaluate(gate, &spend.tx, &spend.entries, options);
        assert!(!evaluation.verdict.accepted);
        assert_eq!(evaluation.verdict.stage_reached, Stage::Harness);
        assert_eq!(evaluation.verdict.first_refusal.as_ref().unwrap().stage, Stage::Harness);
        assert_eq!((evaluation.consensus_error.clone(), evaluation.verdict.policy.clone()), (None, None));
        evaluation.verdict.harness_error.expect("a harness error")
    };

    let mut extra = spend.clone();
    extra.entries.push(spend.entries[0].clone());
    assert!(harness(&gate, &extra, GateOptions::submit()).contains("2 coins were supplied for 1 inputs"));

    let far = gate.clone().with_daa_score(u64::MAX);
    assert!(harness(&far, &spend, GateOptions::block()).contains("i64::MAX"));

    let mut split = gate.clone();
    split.block_daa_score -= 1;
    assert!(harness(&split, &spend, GateOptions::submit()).contains("two different DAA scores"));
    // In a block the two scores may differ.
    spend.commit_storage_mass(&gate);
    assert!(node_gate::evaluate(&split, &spend.tx, &spend.entries, GateOptions::block()).verdict.accepted);

    // A coin of zero sompi cannot be in a UTXO set, and the mass calculator divides by it.
    let mut worthless = spend.clone();
    worthless.entries[0].amount = 0;
    worthless.tx.outputs.clear();
    worthless.tx.finalize();
    for options in [GateOptions::submit(), GateOptions::block()] {
        assert!(harness(&gate, &worthless, options).contains("zero amount"));
    }
}

#[test]
fn stages_are_ordered_as_a_node_walks_them() {
    assert!(Stage::Isolation < Stage::HeaderContext);
    assert!(Stage::HeaderContext < Stage::UtxoPopulation);
    assert!(Stage::UtxoPopulation < Stage::UtxoContext);
    assert!(Stage::UtxoContext < Stage::Scripts);
    assert!(Stage::Scripts < Stage::Accepted);
}

#[test]
fn every_policy_rule_is_reported_once_in_order() {
    let gate = node();
    let report = submit(&gate, &plain_spend(&gate)).verdict.policy.unwrap();
    let rules: Vec<PolicyRule> = report.checks.iter().map(|check| check.rule).collect();
    let expected: Vec<PolicyRule> = PolicyRule::BEFORE_CONSENSUS.into_iter().chain(PolicyRule::AFTER_CONSENSUS).collect();
    assert_eq!(rules, expected);
    assert_eq!(report.outcome(PolicyRule::MinimumRelayFee), Some(&PolicyOutcome::Passed));
}
