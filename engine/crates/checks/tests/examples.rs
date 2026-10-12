//! The two examples of the README, as tests: what the README shows is what runs.

use checks::{Budgets, Case, Expected, Harness, expect_accept, twin};
use kcc20_family::shapes::{self, BorrowKind, Profile};
use node_gate::ErrorClass;

#[test]
fn the_token_outputs_add_up_to_the_token_inputs() {
    // An honest transfer of one token coin into one token coin.
    let honest = shapes::transfer(&Profile::Script, 1, 1);
    expect_accept("transfer/honest 1 to 1", &honest);

    // One token more, in the call and in the output alike: only the sum rule objects.
    twin(
        Case::new("transfer/one token more")
            .py(["test_transfer.Conservation.test_one_output_holding_more_is_refused"]),
        &honest,
        |scenario| {
            scenario.contract_input_mut(0).declared_states_mut()[0].amount += 1;
            scenario
                .contract_output_mut(0)
                .state
                .as_kcc20_mut()
                .unwrap()
                .amount += 1;
        },
        0,
        Expected::rule("K-37").at_line(175),
    );
}

#[test]
fn the_leader_of_a_borrowed_receive_needs_budget_seven() {
    let scenario = shapes::borrow(&Profile::Script, BorrowKind::Threshold);

    // Measured: the leader needs 7 units, the delegate 13.
    let measured = checks::run(&scenario);
    assert_eq!(measured.minimal_budgets(), Some(vec![7, 13]));

    // With 6 units on the leader a node refuses that input for the budget, and only it.
    let outcome = Case::new("budget/borrow leader with 6")
        .on(Harness::pinned().with_budgets(Budgets::Exactly(vec![6, 13])))
        .expect_inputs(
            &scenario,
            &[
                (
                    0,
                    Expected::engine("ExceededCommittedScriptUnits")
                        .of_class(ErrorClass::ResourceLimit),
                ),
                (1, Expected::pass()),
            ],
        );
    assert_eq!(outcome.inputs[0].committed.as_ref().unwrap().rule(), None);
    assert!(
        outcome.inputs[0].alone.as_ref().unwrap().ok,
        "without a limit the leader passes"
    );
}
