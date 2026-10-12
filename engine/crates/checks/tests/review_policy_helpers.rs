//! Review of the mempool helper of the test harness: what `expect_mempool_refused` proves.
//!
//! A node applies the minimum fee, the standardness of the spent coins and the storage
//! limit only to a transaction whose consensus validation passed (rusty-kaspa a41a333
//! mining/src/mempool/validate_and_insert_transaction.rs:57-77: a validation error is
//! returned at :68-70, the rules run at :76-77). The outcome records that order in
//! `mempool.first_refusal`. `expect_mempool_refused` asks for that first refusal;
//! `expect_policy_rule_refuses` asks whether a rule is in the list of policy rules that
//! refuse, wherever a node stops.

use std::panic::{AssertUnwindSafe, catch_unwind};

use checks::{Case, run};
use kcc20_family::{
    Scenario,
    shapes::{self, Profile, Realistic},
};
use node_gate::Stage;

/// A one-to-one transfer that pays less than the fee floor and declares one token more
/// than it holds: the leader's script refuses it.
fn underpaid_and_refused_by_its_script() -> Scenario {
    let mut scenario = shapes::transfer(&Profile::Realistic(Realistic::default()), 1, 1);
    scenario.name = "one token more, fee below the floor".to_string();
    scenario.contract_input_mut(0).declared_states_mut()[0].amount += 1;
    scenario
        .contract_output_mut(0)
        .state
        .as_kcc20_mut()
        .expect("a KCC20 output")
        .amount += 1;
    scenario
}

/// What a node answers to that transaction: the script failure. The fee rule is listed
/// as one more reason and is not the node's answer.
#[test]
fn the_outcome_names_the_script_as_the_first_refusal() {
    let outcome = run(&underpaid_and_refused_by_its_script());
    assert!(!outcome.scripts_accept());
    assert!(!outcome.mempool.accepted);
    let first = outcome.mempool.first_refusal.as_ref().unwrap();
    assert_eq!(
        (first.stage, first.rule.as_str()),
        (Stage::Scripts, "check_scripts")
    );
    let refused: Vec<&str> = outcome
        .mempool
        .refused
        .iter()
        .map(|finding| finding.function.as_str())
        .collect();
    assert_eq!(refused, vec!["check_minimum_relay_fee"]);
}

/// The helper does not report a mempool refusal by a rule the node never gets to: it
/// looks at the node's answer, not at the list of refusing policy rules.
#[test]
fn expect_mempool_refused_is_not_satisfied_by_a_rule_behind_a_failing_script() {
    let scenario = underpaid_and_refused_by_its_script();
    let result = catch_unwind(AssertUnwindSafe(|| {
        Case::new("review/fee rule behind a failing script")
            .unrecorded()
            .expect_mempool_refused(&scenario, "check_minimum_relay_fee")
    }));
    assert!(
        result.is_err(),
        "the helper took a script failure for a refusal by the fee rule"
    );
    // The weaker question has a helper of its own: the fee rule is one of the reasons.
    Case::new("review/fee rule as one more reason")
        .unrecorded()
        .expect_policy_rule_refuses(&scenario, "check_minimum_relay_fee");
}
