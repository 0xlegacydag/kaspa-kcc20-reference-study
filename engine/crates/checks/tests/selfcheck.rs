//! The test harness of `crates/checks` checked on the honest shapes, and the helpers checked
//! on themselves.
//!
//! Three questions:
//!
//! 1. Does every honest shape of `kcc20-family` pass: every input by itself, the whole
//!    transaction, and again under the smallest covering budgets?
//! 2. Is a smallest budget really the smallest: does one unit less fail, and for the
//!    budget itself, not for something else?
//! 3. Can the helpers fail? An assertion that accepts everything proves nothing, so every
//!    helper is shown a case it must reject.

use std::collections::BTreeSet;

use checks::{
    BudgetSource, Budgets, Case, Expected, Harness, JudgedRun, Outcome, StorageCommitment,
    attribution::Part, expect_accept, expect_refused, judge_accept, judge_input, judge_inputs,
    judge_twin, judge_twin_scripts_only, results, run, twin,
};
use kaspa_consensus_core::{
    hashing::sighash_type::SIG_HASH_ALL,
    mass::{ComputeBudget, ScriptUnits},
    tx::CovenantBinding,
};
use kaspa_txscript_errors::TxScriptError;
use kcc20_family::{
    Contract, Entry, EntryRole, Family, Scenario, keys, raw, refdata,
    scenario::InputSpec,
    shapes::{self, BorrowKind, Profile, Realistic},
    witness,
};
use node_gate::{ErrorClass, budget, verdict::Commitment};

/// The 29 honest shapes of the script-only profile.
fn honest_shapes() -> Vec<Scenario> {
    shapes::all(&Profile::Script)
}

/// Line `line` (counted from 1) of the generated source of `contract`, trimmed, as it stands
/// in the checkout of the reference the suite reads.
fn source_line(contract: Contract, line: usize) -> &'static str {
    refdata::pinned_sil_source(contract)
        .lines()
        .nth(line - 1)
        .expect("the generated source has that line")
        .trim()
}

/// The indexes of the inputs that spend a coin of one of the three contracts.
fn contract_inputs(scenario: &Scenario) -> Vec<usize> {
    scenario
        .inputs
        .iter()
        .enumerate()
        .filter(|(_, input)| matches!(input, InputSpec::Contract(_)))
        .map(|(index, _)| index)
        .collect()
}

// ---------------------------------------------------------------------------------------
// 1. The honest shapes
// ---------------------------------------------------------------------------------------

#[test]
fn every_honest_shape_passes_per_input_as_a_whole_and_under_its_minimal_budgets() {
    let shapes = honest_shapes();
    assert_eq!(shapes.len(), 29);
    let names: BTreeSet<&str> = shapes
        .iter()
        .map(|scenario| scenario.name.as_str())
        .collect();
    assert_eq!(
        names.len(),
        29,
        "every shape has its own name, so every result line has its own case id"
    );

    for scenario in &shapes {
        let outcome = expect_accept(format!("honest/{}", scenario.name), scenario);

        assert_eq!(outcome.scripts.judged, JudgedRun::Alone);
        assert!(outcome.scripts.accepted, "{}", outcome.describe());
        assert_eq!(
            outcome.scripts.accepted_under_committed_budgets,
            Some(true),
            "{}",
            outcome.describe()
        );
        assert_eq!(outcome.scripts.not_run, None);
        assert!(
            outcome.scripts.disagreements.is_empty(),
            "{}",
            outcome.describe()
        );
        assert_eq!(outcome.inputs.len(), scenario.inputs.len());

        for input in &outcome.inputs {
            let alone = input.alone.as_ref().expect("every input is run by itself");
            let committed = input
                .committed
                .as_ref()
                .expect("every input is run under its budget");
            assert!(alone.ok && committed.ok, "{}", outcome.describe());
            assert_eq!(alone.script_units_limit, None, "the first run has no limit");
            assert!(
                !alone.accepted_unknown_version,
                "a pass without a run proves nothing"
            );

            // The committed budget is the measured one, and it is the smallest that covers
            // the units: 10,000 units per budget unit on top of 9,999 free ones
            // (rusty-kaspa a41a333 consensus/core/src/mass/units.rs:79-85).
            let budget = input
                .minimal_budget
                .expect("an accepted input has a covering budget");
            assert_eq!(input.commitment, Commitment::ComputeBudget(budget));
            assert_eq!(u64::from(budget), alone.used_script_units / 10_000);
            assert_eq!(
                committed.script_units_limit,
                Some(u64::from(budget) * 10_000 + 9_999)
            );
            assert_eq!(committed.used_script_units, alone.used_script_units);
            assert!(committed.used_script_units <= committed.script_units_limit.unwrap());
        }

        // The consensus rules a node applies to a submission accept every honest shape.
        // (They do not limit storage mass; the block and the mempool do, and this test asks
        // neither. The masses are measured in tests/measure.rs.)
        assert!(outcome.consensus.context_accepted, "{}", outcome.describe());
        assert!(outcome.consensus.accepted, "{}", outcome.describe());
        assert_eq!(outcome.consensus.harness_error, None);
        assert!(outcome.masses.is_some());
    }
}

#[test]
fn the_honest_shapes_call_all_eleven_entries() {
    // `contract` and `entry` of an input are read from its bytes (the script the coin is
    // locked to and the dispatch tag the call pushes), not from the scenario's description.
    let mut called = BTreeSet::new();
    for scenario in honest_shapes() {
        let outcome = run(&scenario);
        for input in &outcome.inputs {
            assert!(input.runs_what_is_stated(), "{}", outcome.describe());
            if let (Some(contract), Some(entry)) = (&input.contract, &input.entry) {
                assert!(
                    input.alone.as_ref().is_some_and(|run| run.ok),
                    "{}",
                    outcome.describe()
                );
                called.insert(format!("{contract}.{entry}"));
            }
        }
    }
    let all: BTreeSet<String> = Entry::ALL.iter().map(|entry| entry.to_string()).collect();
    assert_eq!(called, all);

    // And one by one: the shape made for an entry calls it at the input it names, and
    // that input passes.
    for entry in Entry::ALL {
        let (scenario, input) = shapes::for_entry(&Profile::Script, entry);
        let outcome = expect_accept(format!("entry/{entry}"), &scenario);
        assert_eq!(outcome.inputs[input].entry.as_deref(), Some(entry.name()));
        assert_eq!(
            outcome.inputs[input].contract.as_deref(),
            Some(entry.contract().name())
        );
    }
}

// ---------------------------------------------------------------------------------------
// 2. Budgets
// ---------------------------------------------------------------------------------------

#[test]
fn one_budget_unit_less_fails_on_every_contract_input() {
    let mut tested = 0;
    let mut free = Vec::new();
    for scenario in honest_shapes() {
        let honest = run(&scenario);
        let minimal = honest
            .minimal_budgets()
            .expect("every honest input has a covering budget");
        for input in contract_inputs(&scenario) {
            if minimal[input] == 0 {
                // The input runs inside the 9,999 free units: there is no smaller budget.
                free.push(format!("{} / input {input}", scenario.name));
                continue;
            }
            let mut budgets = minimal.clone();
            budgets[input] -= 1;
            let mut expected: Vec<(usize, Expected)> = (0..minimal.len())
                .filter(|other| *other != input)
                .map(|other| (other, Expected::pass()))
                .collect();
            expected.push((
                input,
                Expected::engine("ExceededCommittedScriptUnits")
                    .of_class(ErrorClass::ResourceLimit),
            ));

            let case = Case::new(format!(
                "budget/{}/input {input} one unit less",
                scenario.name
            ))
            .on(Harness::pinned().with_budgets(Budgets::Exactly(budgets)));
            let outcome = case.expect_inputs(&scenario, &expected);

            assert_eq!(outcome.scripts.judged, JudgedRun::Committed);
            let record = &outcome.inputs[input];
            assert!(
                record.alone.as_ref().unwrap().ok,
                "without a limit the input still passes"
            );
            let committed = record.committed.as_ref().unwrap();
            assert_eq!(
                committed.rule(),
                None,
                "a budget that runs out is not a rule of the contract"
            );
            assert_eq!(
                committed.refused_by(),
                Some("engine: ExceededCommittedScriptUnits")
            );
            assert_eq!(
                outcome.scripts.refused_inputs_under_committed_budgets,
                vec![input]
            );
            assert!(outcome.scripts.accepted, "alone, every input passes");
            // The node gets as far as the scripts and refuses there, naming this input.
            assert!(outcome.consensus.context_accepted);
            assert_eq!(outcome.consensus.context_refusal, None);
            assert!(!outcome.consensus.accepted);
            let refusal = outcome
                .consensus
                .refusal
                .as_ref()
                .expect("a script refusal");
            assert_eq!(
                (refusal.rule.as_str(), refusal.input),
                ("check_scripts", Some(input))
            );
            tested += 1;
        }
    }
    assert_eq!(
        (tested, free.len()),
        EXPECTED_BUDGET_COUNTS,
        "contract inputs tested, contract inputs with budget 0: {free:?}"
    );
    assert_eq!(
        free,
        ["seed split / input 0"],
        "the only contract input that runs inside the free units"
    );
}

/// Contract inputs over the 29 honest shapes with a smallest budget above zero, and with a
/// smallest budget of zero. Observed; a change means a shape or a cost changed.
const EXPECTED_BUDGET_COUNTS: (usize, usize) = (47, 1);

#[test]
fn one_script_unit_less_than_used_fails_and_exactly_the_used_units_pass() {
    let node = Harness::pinned().node;
    let mut tested = 0;
    for scenario in honest_shapes() {
        let outcome = run(&scenario);
        for input in contract_inputs(&scenario) {
            let used = outcome.inputs[input]
                .alone
                .as_ref()
                .unwrap()
                .used_script_units;
            assert!(used > 0, "a contract input costs something");
            let run_under = |limit: u64| {
                budget::run_input(
                    &node,
                    &outcome.committed_tx,
                    &outcome.assembled.utxos,
                    input,
                    ScriptUnits(limit),
                    false,
                )
                .unwrap()
            };

            let exact = run_under(used);
            assert!(
                exact.is_ok(),
                "`{}` input {input} under exactly {used} units: {:?}",
                scenario.name,
                exact.result
            );
            assert_eq!(exact.used_script_units, used);

            let short = run_under(used - 1);
            assert!(
                matches!(short.result, Err(TxScriptError::ExceededCommittedScriptUnits { limit, .. }) if limit == used - 1),
                "`{}` input {input} under {} units: {:?}",
                scenario.name,
                used - 1,
                short.result
            );
            tested += 1;
        }
    }
    assert!(
        tested >= 29,
        "at least one contract input per shape, {tested} tested"
    );
}

#[test]
fn the_budgets_a_scenario_states_are_judged_when_asked_for() {
    let stated = Harness::pinned().with_budgets(Budgets::AsStated);

    // A shape states a budget of 0 on every input: far too little for a transfer.
    let honest = shapes::transfer(&Profile::Script, 1, 1);
    let outcome = Case::new("budget/as stated: zero")
        .on(stated.clone())
        .expect_refused(&honest, 0, "ExceededCommittedScriptUnits");
    assert_eq!(outcome.budgets.source, BudgetSource::AsStated);
    assert_eq!(outcome.scripts.judged, JudgedRun::Committed);
    assert_eq!(outcome.inputs[0].commitment, Commitment::ComputeBudget(0));
    assert_eq!(
        outcome.inputs[0].minimal_budget,
        Some(12),
        "the measurement is made all the same"
    );
    assert!(
        outcome.scripts.accepted && outcome.scripts.accepted_under_committed_budgets == Some(false)
    );

    // The same scenario stating the measured budget passes; one unit less does not.
    let mut enough = honest.clone();
    enough.contract_input_mut(0).compute_commit = ComputeBudget(12).into();
    Case::new("budget/as stated: twelve")
        .on(stated.clone())
        .expect_accept(&enough);
    let mut short = honest.clone();
    short.contract_input_mut(0).compute_commit = ComputeBudget(11).into();
    let outcome = Case::new("budget/as stated: eleven")
        .on(stated)
        .expect_refused(&short, 0, "ExceededCommittedScriptUnits");
    let committed = outcome.inputs[0].committed.as_ref().unwrap();
    assert_eq!(committed.script_units_limit, Some(119_999));
    assert!(
        committed.used_script_units <= 119_999,
        "the units used before the charge that did not fit"
    );
    assert!(
        outcome.scripts.accepted && !outcome.scripts_accept(),
        "the judged run is the one under the stated budgets"
    );
}

// ---------------------------------------------------------------------------------------
// 3. The helpers can fail
// ---------------------------------------------------------------------------------------

/// A transfer whose single output holds one token more than the input, declared and locked
/// alike: only the sum rule objects.
fn one_token_more() -> Scenario {
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    scenario.contract_input_mut(0).declared_states_mut()[0].amount += 1;
    scenario
        .contract_output_mut(0)
        .state
        .as_kcc20_mut()
        .expect("a token output")
        .amount += 1;
    scenario
}

fn failure(result: Result<(), String>) -> String {
    result.expect_err("the judge must object")
}

#[test]
fn accept_is_not_given_to_a_refused_transaction() {
    let outcome = run(&one_token_more());
    let message = failure(judge_accept(&outcome));
    assert!(
        message.contains("input 0") && message.contains("K-37"),
        "{message}"
    );
    assert!(!outcome.scripts_accept());
    assert!(run(&shapes::transfer(&Profile::Script, 1, 1)).scripts_accept());
}

#[test]
#[should_panic(expected = "K-37")]
fn expect_accept_panics_and_prints_what_was_observed() {
    Case::new("selftest/accept on a refused transaction")
        .unrecorded()
        .expect_accept(&one_token_more());
}

#[test]
fn a_refusal_is_judged_by_rule_error_label_and_line() {
    let outcome = run(&one_token_more());
    let ok = |expected: Expected| judge_input(&outcome, 0, &expected);

    ok(Expected::rule("K-37")).unwrap();
    ok(Expected::rule("K-37").at_line(175)).unwrap();
    ok(Expected::line(175)).unwrap();
    ok(Expected::engine("VerifyError")).unwrap();
    ok(Expected::engine("VerifyError")
        .at_rule("K-37")
        .of_class(ErrorClass::ContractRefused))
    .unwrap();
    ok(Expected::refused_by("K-37")).unwrap();
    ok(Expected::from("K-37")).unwrap();

    // Each condition alone can fail.
    assert!(failure(ok(Expected::rule("K-38"))).contains("rule K-38"));
    assert!(failure(ok(Expected::rule("K-37").at_line(176))).contains("source line 176"));
    assert!(failure(ok(Expected::line(174))).contains("source line 174"));
    assert!(failure(ok(Expected::engine("NumberTooBig"))).contains("engine error NumberTooBig"));
    assert!(failure(ok(Expected::engine("VerifyError").at_rule("K-36"))).contains("K-36"));
    assert!(
        failure(ok(
            Expected::engine("VerifyError").of_class(ErrorClass::ResourceLimit)
        ))
        .contains("ResourceLimit")
    );
    assert!(failure(ok(Expected::refused_by("P2SH wrapper"))).contains("P2SH wrapper"));
    assert!(failure(ok(Expected::pass())).contains("expected to pass"));

    // The message prints what was observed, with the text of the statement as it stands at
    // line 175 of the generated source.
    let message = failure(ok(Expected::rule("K-66")));
    for part in [
        "VerifyError",
        "K-37",
        "KCC20.sil:175",
        source_line(Contract::Kcc20, 175),
        "byte 2203",
    ] {
        assert!(message.contains(part), "`{part}` is missing in: {message}");
    }

    // An input that passes is not "refused", and an input that does not exist is neither.
    let honest = run(&shapes::transfer(&Profile::Script, 1, 1));
    assert!(failure(judge_input(&honest, 0, &Expected::rule("K-37"))).contains("it passes"));
    assert!(failure(judge_input(&honest, 7, &Expected::rule("K-37"))).contains("no input 7"));
    // A list without any refusal is not a check of a refusal.
    assert!(failure(judge_inputs(&honest, &[(0, Expected::pass())])).contains("could not tell"));
}

#[test]
#[should_panic(expected = "was expected to be refused with rule K-66")]
fn expect_refused_panics_on_another_rule() {
    Case::new("selftest/another rule")
        .unrecorded()
        .expect_refused(&one_token_more(), 0, "K-66");
}

#[test]
fn a_twin_needs_an_accepted_honest_side_a_real_change_and_the_expected_refusal() {
    let honest = run(&shapes::transfer(&Profile::Script, 1, 1));
    let changed = run(&one_token_more());
    let expected = [(0, Expected::rule("K-37"))];

    judge_twin(&honest, &changed, &expected).unwrap();
    assert!(
        failure(judge_twin(&changed, &changed, &expected))
            .contains("the honest twin is not accepted")
    );
    assert!(failure(judge_twin(&honest, &honest, &expected)).contains("altered neither"));
    assert!(
        failure(judge_twin(
            &honest,
            &changed,
            &[(0, Expected::rule("K-38"))]
        ))
        .contains("rule K-38")
    );
}

/// A transfer of one coin of 1000 sompi into two outputs of 1000 and 500 sompi: coin
/// values of an earlier suite, in which nothing compared the sompi paid out with the sompi
/// spent. The scripts pass; a node refuses the transaction for its amounts before it runs
/// one.
fn spending_more_than_it_has() -> Scenario {
    let mut scenario = shapes::transfer(&Profile::Script, 1, 2);
    scenario.contract_output_mut(0).value = shapes::SCRIPT_COIN_VALUE;
    scenario
}

#[test]
fn a_twin_needs_a_node_to_get_to_the_scripts_of_both_sides() {
    let expected = [(0, Expected::rule("K-37"))];
    let one_token_more_in = |scenario: &Scenario| {
        let mut changed = scenario.clone();
        changed.contract_input_mut(0).declared_states_mut()[0].amount += 1;
        changed
            .contract_output_mut(0)
            .state
            .as_kcc20_mut()
            .expect("a token output")
            .amount += 1;
        changed
    };

    // The honest side is a transaction no node runs.
    let honest = run(&spending_more_than_it_has());
    judge_accept(&honest).expect("its scripts pass");
    assert!(!honest.consensus.context_accepted && !honest.consensus.accepted);
    let changed = run(&one_token_more_in(&spending_more_than_it_has()));
    let objection = failure(judge_twin(&honest, &changed, &expected));
    assert!(
        objection.contains("the consensus rules of a node refuse")
            && objection.contains("SpendTooHigh"),
        "{objection}"
    );
    // The engine alone has nothing to object to, and a case may ask the engine alone.
    judge_twin_scripts_only(&honest, &changed, &expected).unwrap();

    // The changed side is a transaction no node runs: the change also raises the value
    // of the output above the value of the coin.
    let honest = run(&shapes::transfer(&Profile::Script, 1, 1));
    assert!(honest.consensus.accepted);
    let mut over = one_token_more();
    over.contract_output_mut(0).value += 1;
    let changed = run(&over);
    assert!(!changed.consensus.context_accepted);
    let objection = failure(judge_twin(&honest, &changed, &expected));
    assert!(
        objection.contains("before it runs a script") && objection.contains("SpendTooHigh"),
        "{objection}"
    );
    judge_twin_scripts_only(&honest, &changed, &expected).unwrap();

    // The expected refusal is still asked for first: another rule is another failure.
    let other_rule = [(0, Expected::rule("K-38"))];
    assert!(failure(judge_twin(&honest, &changed, &other_rule)).contains("rule K-38"));
    assert!(failure(judge_twin_scripts_only(&honest, &changed, &other_rule)).contains("rule K-38"));
}

#[test]
#[should_panic(expected = "the consensus rules of a node refuse")]
fn twin_panics_when_no_node_runs_the_honest_side() {
    Case::new("selftest/a twin of a transaction no node runs")
        .unrecorded()
        .twin(
            &spending_more_than_it_has(),
            |scenario| {
                scenario.contract_input_mut(0).declared_states_mut()[0].amount += 1;
                scenario
                    .contract_output_mut(0)
                    .state
                    .as_kcc20_mut()
                    .expect("a token output")
                    .amount += 1;
            },
            0,
            "K-37",
        );
}

#[test]
fn a_scripts_only_twin_is_accepted_and_says_so_in_its_line() {
    let case = "format/scripts-only twin";
    Case::new(case)
        .scripts_only()
        .note("coin values of the earlier suite, which pay out more sompi than they spend")
        .twin(
            &spending_more_than_it_has(),
            |scenario| {
                scenario.contract_input_mut(0).declared_states_mut()[0].amount += 1;
                scenario
                    .contract_output_mut(0)
                    .state
                    .as_kcc20_mut()
                    .expect("a token output")
                    .amount += 1;
            },
            0,
            "K-37",
        );
    let lines = result_lines(case);
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    assert_eq!(line["passed"], true);
    assert_eq!(line["expected"]["context"], "scripts_only");
    assert_eq!(
        line["twin_context"],
        serde_json::json!({
            "required": false,
            "honest_consensus_accepted": false,
            "changed_context_accepted": false
        })
    );
    assert_eq!(line["consensus"]["context_accepted"], false);
    assert_eq!(
        line["consensus"]["context_refusal"]["rule"],
        "check_transaction_output_values"
    );
}

#[test]
#[should_panic(expected = "is not the id of a check of the earlier Python suite")]
fn a_misspelt_python_id_is_refused_at_once() {
    let _ = Case::new("selftest/misspelt id")
        .py(["test_transfer.Conservation.test_one_output_holding_more_refused"]);
}

#[test]
fn every_python_id_a_case_carries_is_in_the_list() {
    assert_eq!(checks::python_ids::all().len(), 185);
    let case = Case::new("selftest/known ids").py([
        "test_transfer.Conservation.test_one_output_holding_more_is_refused",
        "A_minter.test_a_minter.Mint.test_01_continuation_owner_changed",
    ]);
    assert_eq!(case.py_ids.len(), 2);
    assert!(
        case.py_ids
            .iter()
            .all(|id| checks::python_ids::is_known(id))
    );
}

#[test]
fn an_input_is_recorded_as_what_its_bytes_run() {
    // The honest leader of a transfer: the bytes run what the scenario says.
    let honest = run(&shapes::transfer(&Profile::Script, 1, 1));
    let record = &honest.inputs[0];
    assert_eq!(
        (record.contract.as_deref(), record.entry.as_deref()),
        (Some("KCC20"), Some("transfer"))
    );
    assert!(record.runs_what_is_stated());
    assert_eq!(record.what(), "KCC20.transfer");

    // The same scenario with the coin locked by OP_TRUE and an empty signature script:
    // the input passes, and no opcode of KCC20 runs. The record says so, next to what the
    // scenario says.
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    let input = scenario.contract_input_mut(0);
    input.locking_script = Some(shapes::op_true_script());
    input.signature_script = Some(kcc20_family::scenario::LateBytes::empty());
    let outcome = run(&scenario);
    let record = &outcome.inputs[0];
    assert!(record.alone.as_ref().unwrap().ok);
    assert_eq!(record.kind, "contract");
    assert_eq!(
        (record.contract.as_deref(), record.entry.as_deref()),
        (None, None)
    );
    assert_eq!(
        (
            record.stated_contract.as_deref(),
            record.stated_entry.as_deref()
        ),
        (Some("KCC20"), Some("transfer"))
    );
    assert!(!record.runs_what_is_stated());
    assert_eq!(record.what(), "ordinary (the scenario says KCC20.transfer)");

    // A typed call of the delegate entry on the leader: the bytes select another entry
    // than the honest one, and the record names the entry the tag selects.
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    let witness = witness::owner_key(keys::ALICE, EntryRole::Delegate, SIG_HASH_ALL);
    scenario.contract_input_mut(0).call = kcc20_family::scenario::Call::typed(
        Entry::TransferDelegator,
        vec![kcc20_family::scenario::Arg::Bytes(witness)],
    );
    let outcome = run(&scenario);
    let record = &outcome.inputs[0];
    assert_eq!(record.entry.as_deref(), Some("transfer_delegator"));
    assert!(record.runs_what_is_stated());

    // The tag of an entry of another contract in front of a KCC20 script: the selector of
    // KCC20 knows no such entry.
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    let mint_tag = Family::pinned().dispatch_tag(Entry::Mint);
    scenario.contract_input_mut(0).set_patch(move |parts| {
        parts.tag = raw::push(&mint_tag).expect("a four-byte push");
    });
    let outcome = run(&scenario);
    let record = &outcome.inputs[0];
    assert_eq!(
        (record.contract.as_deref(), record.entry.as_deref()),
        (Some("KCC20"), None)
    );
    assert_eq!(
        record.what(),
        "KCC20, no entry selected (the scenario says KCC20.transfer)"
    );
    let alone = record.alone.as_ref().unwrap();
    assert!(!alone.ok);
    assert_eq!(alone.refused_by(), Some("K-01"), "{}", alone.describe());
}

#[test]
fn accept_needs_two_runs_that_agree() {
    // These three conditions do not occur with the honest shapes, so they are shown here
    // on an accepted outcome with one field changed by hand.
    let honest = run(&shapes::transfer(&Profile::Script, 1, 1));
    judge_accept(&honest).unwrap();

    let mut disagreeing = honest.clone();
    disagreeing
        .scripts
        .disagreements
        .push("input 0: made up".to_string());
    assert!(failure(judge_accept(&disagreeing)).contains("disagrees"));
    assert!(
        failure(judge_inputs(&disagreeing, &[(0, Expected::rule("K-37"))])).contains("disagrees")
    );

    let mut refused_under_budgets = honest.clone();
    refused_under_budgets
        .scripts
        .accepted_under_committed_budgets = Some(false);
    refused_under_budgets
        .scripts
        .refused_inputs_under_committed_budgets = vec![0];
    assert!(failure(judge_accept(&refused_under_budgets)).contains("under the committed budgets"));

    let mut not_run_twice = honest.clone();
    not_run_twice.inputs[0].alone = None;
    assert!(failure(judge_accept(&not_run_twice)).contains("was not run"));
}

#[test]
fn a_pass_without_a_run_is_not_an_accept() {
    // A coin whose script public key has a version the engine does not know is accepted
    // without running anything (rusty-kaspa a41a333 crypto/txscript/src/lib.rs:695-698).
    // The harness reports the pass and refuses to call it an accept.
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    let honest_lock = Family::pinned()
        .script_public_key(&scenario.contract_input(0).state)
        .expect("lock");
    scenario.contract_input_mut(0).locking_script = Some(
        kaspa_consensus_core::tx::ScriptPublicKey::from_vec(1, honest_lock.script().to_vec()),
    );
    let outcome = run(&scenario);
    let alone = outcome.inputs[0].alone.as_ref().unwrap();
    assert!(alone.ok && alone.accepted_unknown_version);
    assert_eq!(alone.used_script_units, 0);
    assert!(failure(judge_accept(&outcome)).contains("without running anything"));
    assert!(failure(judge_input(&outcome, 0, &Expected::rule("K-37"))).contains("it passes"));
}

#[test]
fn a_version_0_transaction_gets_an_answer() {
    // Version 0 commits signature operation counts, and has no covenant bindings. The
    // shape states budgets and bindings, so the rules in isolation refuse it; the harness
    // keeps the stated commitments and says so.
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    scenario.version = 0;
    let outcome = run(&scenario);
    assert_eq!(outcome.budgets.source, BudgetSource::AsStated);
    assert!(
        outcome
            .budgets
            .note
            .as_deref()
            .is_some_and(|note| note.contains("version 0"))
    );
    assert_eq!(outcome.scripts.judged, JudgedRun::Committed);
    assert!(!outcome.consensus.context_accepted);
    assert_eq!(
        outcome
            .consensus
            .context_refusal
            .as_ref()
            .map(|refusal| refusal.rule.as_str()),
        Some("check_tx_version_specific_fields")
    );
    assert_eq!(
        outcome.masses, None,
        "the masses of a transaction with the wrong kind of commitment are undefined"
    );
    assert!(!outcome.mempool.accepted && !outcome.consensus.block.accepted);
}

#[test]
fn on_a_node_before_toccata_there_are_no_budgets() {
    use kaspa_consensus_core::mass::SigopCount;
    use kcc20_family::scenario::{OrdinaryInput, PlainOutput};

    // One pay-to-public-key coin spent by a version 0 transaction that commits to
    // `sig_op_count` signature operations. The signature covers the count.
    let spend = |sig_op_count: u8| {
        let script = shapes::pay_to_public_key_script(&keys::x_only(keys::ALICE));
        let signature = witness::signature(keys::ALICE, SIG_HASH_ALL)
            .map(|signature| raw::push(&signature).expect("a 65-byte push"));
        let mut coin = OrdinaryInput::new(
            script.clone(),
            10 * shapes::SOMPI_PER_KAS,
            shapes::outpoint(3, 0),
            signature,
        );
        coin.compute_commit = SigopCount(sig_op_count).into();
        let mut scenario = Scenario::new(format!("plain spend committing {sig_op_count}"));
        scenario.version = 0;
        scenario.push_ordinary_input(coin);
        scenario.push_plain_output(PlainOutput::new(script, 9 * shapes::SOMPI_PER_KAS));
        scenario
    };
    let testnet = node_gate::GateParams::testnet10();
    let activation = testnet.params.toccata_activation.daa_score();
    let harness = Harness::pinned().with_node(testnet.with_daa_score(activation - 1));

    // The engine counts signature operations and meters no script units: the run without
    // a limit is bound by no count, and there is no budget to read off it.
    let committed_none = harness.run(&spend(0));
    let input = &committed_none.inputs[0];
    let alone = input.alone.as_ref().expect("the input is run");
    assert!(alone.ok, "{}", committed_none.describe());
    assert_eq!(
        (
            alone.script_units_limit,
            alone.sig_op_limit,
            alone.used_script_units,
            alone.used_sig_ops
        ),
        (None, Some(u8::MAX), 0, 1)
    );
    assert_eq!(input.minimal_budget, None);
    assert_eq!(committed_none.budgets.source, BudgetSource::AsStated);
    assert!(
        committed_none
            .budgets
            .note
            .as_deref()
            .is_some_and(|note| note.contains("before Toccata")),
        "{:?}",
        committed_none.budgets.note
    );
    // The node's own run is held to the commitment of zero operations.
    let committed = input.committed.as_ref().expect("the input is run");
    assert_eq!(committed.sig_op_limit, Some(0));
    assert_eq!(committed.error_variant(), Some("ExceededSigOpLimit"));
    assert_eq!(committed_none.scripts.judged, JudgedRun::Committed);
    assert!(!committed_none.consensus.accepted);

    // With the one operation the measuring run counted, the node accepts.
    let committed_one = harness.run(&spend(1));
    assert!(
        committed_one.consensus.accepted,
        "{}",
        committed_one.describe()
    );
    assert_eq!(
        committed_one.inputs[0].committed.as_ref().map(|run| (
            run.ok,
            run.sig_op_limit,
            run.used_sig_ops
        )),
        Some((true, Some(1), 1))
    );
}

#[test]
#[should_panic(expected = "altered neither the transaction nor its coins")]
fn twin_panics_when_the_change_changes_nothing() {
    let honest = shapes::transfer(&Profile::Script, 1, 1);
    Case::new("selftest/empty change")
        .unrecorded()
        .twin(&honest, |_| {}, 0, "K-37");
}

// ---------------------------------------------------------------------------------------
// 4. What refused, when it is not a statement of a contract
// ---------------------------------------------------------------------------------------

#[test]
fn a_twin_names_the_rule_and_the_line() {
    let honest = shapes::transfer(&Profile::Script, 1, 1);
    let result = twin(
        "attribution/sum rule",
        &honest,
        |scenario| *scenario = one_token_more(),
        0,
        Expected::rule("K-37").at_line(175),
    );
    let refusal = result.changed.inputs[0]
        .alone
        .as_ref()
        .unwrap()
        .refusal
        .as_ref()
        .unwrap();
    assert_eq!(refusal.part, Part::ContractScript);
    assert_eq!(refusal.contract.as_deref(), Some("KCC20"));
    assert_eq!(refusal.entry.as_deref(), Some("transfer"));
    assert_eq!(refusal.place.as_deref(), Some("statement"));
    assert_eq!(refusal.byte_offset, Some(2203));
    assert_eq!(refusal.opcode.as_deref(), Some("OpVerify"));
    let sil = refusal.sil.as_ref().unwrap();
    assert_eq!(
        (sil.file.as_str(), sil.line, sil.end_line),
        ("KCC20.sil", 175, 175)
    );
    assert_eq!(sil.text, source_line(Contract::Kcc20, 175));
    assert_eq!(refusal.inventory_line.as_deref(), Some("175"));
    assert_eq!(refusal.note, None);
}

#[test]
fn a_redeem_script_that_is_not_the_coins_script_is_the_p2sh_wrapper() {
    let family = Family::pinned();
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    let mut other = scenario.contract_input_mut(0).state.clone();
    other.as_kcc20_mut().expect("a token coin").amount = 101;
    scenario.contract_input_mut(0).pushed_redeem =
        Some(family.redeem_script(&other).expect("redeem script"));

    let outcome = expect_refused(
        "attribution/redeem script of another state",
        &scenario,
        0,
        Expected::refused_by("P2SH wrapper").of_class(ErrorClass::ScriptFormat),
    );
    let run = outcome.inputs[0].alone.as_ref().unwrap();
    assert_eq!(run.error_variant(), Some("EvalFalse"));
    let refusal = run.refusal.as_ref().unwrap();
    assert_eq!(refusal.part, Part::P2shWrapper);
    assert_eq!(refusal.rule, None);
    assert_eq!(refusal.engine_precondition.as_deref(), Some("E-03"));
}

#[test]
fn an_unknown_tag_is_the_rule_of_the_dispatcher() {
    let mut scenario = shapes::mint_reclaim_into(&Profile::Script);
    scenario
        .contract_input_mut(0)
        .set_patch(|parts| parts.tag = raw::push(&[0, 0, 0, 0]).expect("push"));
    let outcome = expect_refused(
        "attribution/unknown tag",
        &scenario,
        0,
        Expected::rule("M-01").of_class(ErrorClass::ContractRefused),
    );
    let run = outcome.inputs[0].alone.as_ref().unwrap();
    assert_eq!(run.error_variant(), Some("EarlyReturn"));
    let refusal = run.refusal.as_ref().unwrap();
    assert_eq!(refusal.place.as_deref(), Some("dispatcher"));
    assert_eq!(refusal.byte_offset, Some(2013));
    assert_eq!(
        refusal.sil, None,
        "the dispatcher has no line in the source"
    );
}

#[test]
fn an_empty_signature_argument_is_a_rule_of_the_prologue() {
    let mut scenario = shapes::mint_reclaim(&Profile::Script);
    scenario
        .contract_input_mut(0)
        .set_patch(|parts| parts.arguments[0] = vec![0x00]);
    let outcome = expect_refused("attribution/empty signature argument", &scenario, 0, "M-31");
    let refusal = outcome.inputs[0]
        .alone
        .as_ref()
        .unwrap()
        .refusal
        .as_ref()
        .unwrap();
    assert_eq!(refusal.place.as_deref(), Some("prologue"));
    assert_eq!(refusal.entry.as_deref(), Some("reclaim"));
    assert_eq!(refusal.byte_offset, Some(880));
    assert_eq!(
        refusal.sil, None,
        "the argument size checks have no line in the source"
    );
}

#[test]
fn a_malformed_signature_is_the_engines_refusal_not_the_rules() {
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    let honest_witness = scenario.contract_input_mut(0).witness_mut().clone();
    *scenario.contract_input_mut(0).witness_mut() = honest_witness.map(|mut witness| {
        *witness
            .last_mut()
            .expect("the witness ends with the type byte") = 0x03;
        witness
    });
    let outcome = expect_refused(
        "attribution/signature hash type 3",
        &scenario,
        0,
        Expected::engine("InvalidSigHashType").of_class(ErrorClass::MalformedSignatureMaterial),
    );
    let run = outcome.inputs[0].alone.as_ref().unwrap();
    assert_eq!(run.refused_by(), Some("engine: InvalidSigHashType"));
    assert_eq!(
        run.rule(),
        None,
        "the signature rule K-38 is the verify behind the check, which was never reached"
    );
    assert!(judge_input(&outcome, 0, &Expected::rule("K-38")).is_err());
    // The engine was inside the statement of the owner check all the same.
    assert_eq!(run.sil_line(), Some(69));
    assert!(
        judge_input(&outcome, 0, &Expected::line(69)).is_err(),
        "a line alone does not accept a malformed signature"
    );
    judge_input(
        &outcome,
        0,
        &Expected::engine("InvalidSigHashType").at_line(69),
    )
    .unwrap();
}

#[test]
fn a_contract_call_on_a_coin_with_another_lock_ends_at_the_final_stack() {
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    scenario.contract_input_mut(0).locking_script = Some(shapes::op_true_script());
    let outcome = expect_refused(
        "attribution/coin locked by OP_TRUE",
        &scenario,
        0,
        Expected::refused_by("final stack"),
    );
    let run = outcome.inputs[0].alone.as_ref().unwrap();
    assert_eq!(run.error_variant(), Some("CleanStack"));
    assert_eq!(run.refusal.as_ref().unwrap().part, Part::FinalStack);
}

#[test]
fn a_refused_ordinary_input_is_reported_like_any_other() {
    // The funding coin of the realistic profile is a pay-to-public-key coin. Signed by
    // another key, its signature check leaves false: the final stack check refuses.
    let mut scenario = shapes::transfer(&Profile::Realistic(Realistic::default()), 1, 1);
    let funding = scenario.inputs.len() - 1;
    scenario.ordinary_input_mut(funding).signature_script =
        kcc20_family::LateBytes::from_tx(|ctx| {
            raw::push(&keys::schnorr_signature(
                ctx,
                &keys::keypair(keys::CAROL),
                SIG_HASH_ALL,
            ))
            .unwrap()
        });
    let outcome = Case::new("attribution/funding signed by another key").expect_inputs(
        &scenario,
        &[
            (0, Expected::pass()),
            (funding, Expected::refused_by("final stack")),
        ],
    );
    let record = &outcome.inputs[funding];
    assert_eq!(record.kind, "ordinary");
    assert_eq!(record.contract, None);
    let run = record.alone.as_ref().unwrap();
    assert_eq!(run.error_variant(), Some("EvalFalse"));
    assert_eq!(run.class, Some(ErrorClass::ContractRefused));
    assert_eq!(outcome.scripts.refused_inputs, vec![funding]);
}

// ---------------------------------------------------------------------------------------
// 5. The verdicts are kept apart
// ---------------------------------------------------------------------------------------

#[test]
fn scripts_that_pass_and_amounts_that_do_not_are_two_answers() {
    // One sompi more in the output than in the input: the scripts of this transfer pass, and
    // the node's amount rule refuses.
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    scenario.contract_output_mut(0).value += 1;

    let outcome = Case::new("verdicts/outputs exceed inputs: scripts").expect_accept(&scenario);
    assert!(outcome.scripts.accepted);
    assert!(!outcome.consensus.context_accepted);
    assert!(!outcome.consensus.accepted);
    assert!(!outcome.mempool.accepted);

    Case::new("verdicts/outputs exceed inputs: consensus")
        .expect_consensus_refused(&scenario, "SpendTooHigh");
    Case::new("verdicts/outputs exceed inputs: consensus, by function")
        .expect_consensus_refused(&scenario, "check_transaction_output_values");
}

#[test]
#[should_panic(expected = "no consensus rule in front of the scripts refuses")]
fn expect_consensus_refused_panics_on_an_honest_transaction() {
    let scenario = shapes::transfer(&Profile::Script, 1, 1);
    Case::new("selftest/consensus refusal of an honest transaction")
        .unrecorded()
        .expect_consensus_refused(&scenario, "SpendTooHigh");
}

#[test]
fn inconsistent_covenant_bindings_stop_a_node_before_any_script() {
    // The output names an authorizing input the transaction does not have.
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    *scenario.outputs[0].binding_mut() = Some(CovenantBinding::new(5, shapes::covenant_id()));

    let outcome = Case::new("verdicts/binding to a missing input")
        .expect_consensus_refused(&scenario, "check_covenant_info");
    assert!(outcome.scripts.not_run.is_some());
    assert!(!outcome.scripts.accepted);
    assert!(
        outcome
            .inputs
            .iter()
            .all(|input| input.alone.is_none() && input.committed.is_none())
    );
    assert!(failure(judge_accept(&outcome)).contains("no script was run"));
    assert!(
        failure(judge_inputs(&outcome, &[(0, Expected::rule("K-37"))]))
            .contains("no script was run")
    );
}

#[test]
fn the_mempool_and_the_block_answer_for_themselves() {
    // A one-to-three transfer of 1000-sompi coins: the scripts and the consensus rules of a
    // submission accept it, a block and the mempool do not, for its storage mass.
    let small = shapes::transfer(&Profile::Script, 1, 3);
    let outcome = Case::new("verdicts/1000-sompi coins: mempool")
        .expect_mempool_refused(&small, "check_storage_mass_limit");
    assert!(outcome.scripts.accepted && outcome.consensus.accepted);
    assert!(!outcome.mempool.accepted && !outcome.consensus.block.accepted);
    Case::new("verdicts/1000-sompi coins: block")
        .expect_block_refused(&small, "ExceedsStorageMassLimit");
    // The transaction pays no fee either. The fee rule sits behind the storage limit, so
    // it is one more reason in the list and not what the node answers.
    let outcome = Case::new("verdicts/1000-sompi coins: no fee")
        .expect_policy_rule_refuses(&small, "check_minimum_relay_fee");
    let not_the_answer = checks::judge_mempool_refused(&outcome, "check_minimum_relay_fee")
        .expect_err("the node answers with the storage limit");
    assert!(
        not_the_answer.contains("does not get to it")
            && not_the_answer.contains("check_storage_mass_limit"),
        "{not_the_answer}"
    );
    checks::judge_mempool_refused(&outcome, "StorageMass").expect("named by its variant");

    // Coins of 10 KAS, a signed funding coin and change. The fee decides: the mempool's
    // floor depends on the size and the budgets of the transaction, not on its values, so
    // it can be read from one run and paid exactly in the next.
    let floor = run(&ten_kas_transfer(1))
        .mempool
        .minimum_fee
        .expect("the fee floor of a well formed transaction is known");
    assert!(floor > 1);

    let at_the_floor = ten_kas_transfer(floor);
    let outcome = Case::new("verdicts/10-KAS coins, fee at the floor: mempool")
        .expect_mempool_accept(&at_the_floor);
    assert!(
        outcome.mempool.policy_accepted
            && outcome.mempool.refused.is_empty()
            && outcome.mempool.not_evaluated.is_empty()
    );
    assert_eq!(outcome.mempool.fee, Some(floor));
    assert_eq!(outcome.mempool.minimum_fee, Some(floor));
    Case::new("verdicts/10-KAS coins, fee at the floor: block").expect_block_accept(&at_the_floor);
    Case::new("verdicts/10-KAS coins, fee at the floor: consensus")
        .expect_consensus_accept(&at_the_floor);

    let one_sompi_short = ten_kas_transfer(floor - 1);
    let outcome = Case::new("verdicts/10-KAS coins, one sompi below the floor: mempool")
        .expect_mempool_refused(&one_sompi_short, "check_minimum_relay_fee");
    assert_eq!(outcome.mempool.refused.len(), 1, "nothing else refuses");
    assert_eq!(
        outcome
            .mempool
            .first_refusal
            .as_ref()
            .map(|refusal| refusal.rule.as_str()),
        Some("check_minimum_relay_fee")
    );
    assert!(
        outcome.scripts.accepted && outcome.consensus.accepted && outcome.consensus.block.accepted
    );
    assert!(!outcome.mempool.policy_accepted && !outcome.mempool.accepted);

    // The other way round: every policy rule passes and a script refuses. The node does
    // not take the transaction; the policy answer stays an answer of its own.
    let mut wrong_key = ten_kas_transfer(floor);
    *wrong_key.contract_input_mut(0).witness_mut() =
        witness::owner_key(keys::CAROL, EntryRole::Leader, SIG_HASH_ALL);
    let outcome = Case::new("verdicts/10-KAS coins, fee at the floor, another key")
        .expect_refused(&wrong_key, 0, "K-38");
    assert!(outcome.mempool.policy_accepted && outcome.mempool.refused.is_empty());
    assert!(!outcome.mempool.accepted && !outcome.consensus.accepted);
    assert!(outcome.consensus.context_accepted);
    assert_eq!(
        outcome
            .mempool
            .first_refusal
            .as_ref()
            .map(|refusal| (refusal.rule.as_str(), refusal.input)),
        Some(("check_scripts", Some(0)))
    );
}

/// A one-to-one transfer of a 10 KAS token coin with a 100 KAS funding coin, change and
/// the given fee.
fn ten_kas_transfer(fee: u64) -> Scenario {
    shapes::transfer(
        &Profile::Realistic(Realistic {
            fee,
            ..Realistic::default()
        }),
        1,
        1,
    )
}

#[test]
#[should_panic(expected = "not by the policy rule check_storage_mass_limit")]
fn expect_mempool_refused_panics_when_the_rule_passes() {
    Case::new("selftest/mempool refusal by a rule that passes")
        .unrecorded()
        .expect_mempool_refused(&ten_kas_transfer(1), "check_storage_mass_limit");
}

#[test]
#[should_panic(expected = "does not refuse")]
fn expect_policy_rule_refuses_panics_when_the_rule_passes() {
    Case::new("selftest/a policy rule that passes")
        .unrecorded()
        .expect_policy_rule_refuses(&ten_kas_transfer(1), "check_storage_mass_limit");
}

/// A transfer that pays one sompi of fee and is signed by a key that does not own the coin:
/// the fee rule would refuse it, and the node never asks the fee rule.
fn underpaid_and_signed_by_another_key() -> Scenario {
    let mut scenario = ten_kas_transfer(1);
    *scenario.contract_input_mut(0).witness_mut() =
        witness::owner_key(keys::CAROL, EntryRole::Leader, SIG_HASH_ALL);
    scenario
}

#[test]
#[should_panic(expected = "a node does not get to it")]
fn expect_mempool_refused_panics_when_a_script_refuses_first() {
    Case::new("selftest/the fee rule behind a failing script")
        .unrecorded()
        .expect_mempool_refused(
            &underpaid_and_signed_by_another_key(),
            "check_minimum_relay_fee",
        );
}

#[test]
fn a_mempool_refusal_is_the_nodes_answer_or_one_of_the_reasons() {
    // The same transaction, asked the weaker question: the fee rule is one of the reasons.
    let outcome = Case::new("selftest/the fee rule as one of the reasons")
        .unrecorded()
        .expect_policy_rule_refuses(
            &underpaid_and_signed_by_another_key(),
            "check_minimum_relay_fee",
        );
    assert_eq!(
        outcome
            .mempool
            .first_refusal
            .as_ref()
            .map(|refusal| refusal.rule.as_str()),
        Some("check_scripts")
    );
    assert!(checks::judge_mempool_refused(&outcome, "check_minimum_relay_fee").is_err());
    // A consensus refusal is no mempool refusal, by whatever name it is asked for.
    assert!(checks::judge_mempool_refused(&outcome, "check_scripts").is_err());
    assert!(checks::judge_mempool_refused(&outcome, "SignatureInvalid").is_err());

    // With the right key the fee rule is the node's answer, under both of its names.
    let underpaid = run(&ten_kas_transfer(1));
    checks::judge_mempool_refused(&underpaid, "check_minimum_relay_fee").expect("the function");
    checks::judge_mempool_refused(&underpaid, "InsufficientTransientFee").expect("the variant");
    checks::judge_policy_rule_refuses(&underpaid, "check_minimum_relay_fee").expect("listed");
    // An accepted transaction is refused by nothing.
    let floor = underpaid.mempool.minimum_fee.expect("a fee floor");
    let paid = run(&ten_kas_transfer(floor));
    let accepted = checks::judge_mempool_refused(&paid, "check_minimum_relay_fee").unwrap_err();
    assert!(accepted.contains("takes the transaction"), "{accepted}");
}

#[test]
#[should_panic(expected = "does not take the transaction into its mempool")]
fn expect_mempool_accept_panics_on_1000_sompi_coins() {
    let small = shapes::transfer(&Profile::Script, 1, 3);
    Case::new("selftest/mempool acceptance of 1000-sompi coins")
        .unrecorded()
        .expect_mempool_accept(&small);
}

#[test]
#[should_panic(expected = "a block cannot hold the transaction")]
fn expect_block_accept_panics_on_1000_sompi_coins() {
    let small = shapes::transfer(&Profile::Script, 1, 3);
    Case::new("selftest/block acceptance of 1000-sompi coins")
        .unrecorded()
        .expect_block_accept(&small);
}

#[test]
#[should_panic(expected = "not WrongMass")]
fn expect_block_refused_panics_on_another_refusal() {
    let small = shapes::transfer(&Profile::Script, 1, 3);
    Case::new("selftest/block refusal by another rule")
        .unrecorded()
        .expect_block_refused(&small, "WrongMass");
}

#[test]
#[should_panic(expected = "the consensus rules refuse the transaction")]
fn expect_consensus_accept_panics_when_the_amounts_do_not_add_up() {
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    scenario.contract_output_mut(0).value += 1;
    Case::new("selftest/consensus acceptance of outputs above inputs")
        .unrecorded()
        .expect_consensus_accept(&scenario);
}

#[test]
#[should_panic(expected = "not by NotFinalized")]
fn expect_consensus_refused_panics_on_another_refusal() {
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    scenario.contract_output_mut(0).value += 1;
    Case::new("selftest/consensus refusal by another rule")
        .unrecorded()
        .expect_consensus_refused(&scenario, "NotFinalized");
}

#[test]
fn an_expectation_without_a_condition_and_a_transaction_without_inputs_are_not_checks() {
    let outcome = run(&one_token_more());
    let nothing = Expected {
        pass: false,
        rule: None,
        engine: None,
        refused_by: None,
        at_rule: None,
        sil_line: None,
        class: None,
    };
    assert!(failure(judge_input(&outcome, 0, &nothing)).contains("names neither"));

    let mut no_inputs = Scenario::new("no inputs");
    no_inputs.push_plain_output(kcc20_family::PlainOutput::new(
        shapes::op_true_script(),
        1_000,
    ));
    let outcome = run(&no_inputs);
    assert!(outcome.inputs.is_empty());
    assert!(!outcome.scripts.accepted);
    assert!(failure(judge_accept(&outcome)).contains("no inputs"));
    assert_eq!(
        outcome
            .consensus
            .context_refusal
            .as_ref()
            .map(|refusal| refusal.rule.as_str()),
        Some("check_transaction_inputs_count")
    );
}

#[test]
fn a_block_holds_a_transaction_only_with_the_calculated_storage_mass() {
    // By default the harness commits the calculated storage mass for the block answer, as
    // an honest wallet does. Told to keep the scenario's own value, it shows the node's
    // commitment rule: the shape states 0, the calculator says otherwise.
    let scenario = ten_kas_transfer(1_000_000);
    let calculated = run(&scenario)
        .masses
        .and_then(|masses| masses.calculated_storage_mass)
        .expect("the storage mass is calculated");
    assert!(calculated > 0);

    let as_stated = Harness::pinned().with_storage_commitment(StorageCommitment::AsStated);
    let outcome = Case::new("verdicts/storage mass commitment of 0")
        .on(as_stated.clone())
        .expect_block_refused(&scenario, "WrongMass");
    assert_eq!(outcome.consensus.block.committed_storage_mass, 0);
    assert!(
        outcome.mempool.accepted,
        "a submission ignores the commitment: the node calculates the value itself"
    );

    let mut committing = scenario.clone();
    committing.storage_mass = calculated;
    let outcome = Case::new("verdicts/storage mass commitment as calculated")
        .on(as_stated)
        .expect_block_accept(&committing);
    assert_eq!(outcome.consensus.block.committed_storage_mass, calculated);
}

// ---------------------------------------------------------------------------------------
// 6. Another family of contracts
// ---------------------------------------------------------------------------------------

#[test]
fn a_weakened_contract_runs_through_the_same_harness() {
    // The sum rule K-37 is the verify at byte 2203 of KCC20. Replaced by a drop of the
    // same length, the comparison is still made and its result thrown away.
    const OP_VERIFY: u8 = 0x69;
    const OP_DROP: u8 = 0x75;
    let pinned = Family::pinned();
    let mut bytecode = pinned.bytecode(Contract::Kcc20).to_vec();
    assert_eq!(bytecode[2203], OP_VERIFY);
    bytecode[2203] = OP_DROP;
    let weakened = Harness::pinned().with_family(
        pinned
            .with_bytecode(Contract::Kcc20, bytecode)
            .expect("a same-length replacement"),
    );

    let honest = shapes::transfer(&Profile::Script, 1, 1);
    let inflated = one_token_more();

    // The published contract refuses the inflated transfer; the weakened one takes it. A
    // check that expects K-37 therefore fails on the weakened family: it notices.
    judge_input(&run(&inflated), 0, &Expected::rule("K-37")).unwrap();
    let outcome = weakened.run(&inflated);
    assert!(failure(judge_input(&outcome, 0, &Expected::rule("K-37"))).contains("it passes"));
    Case::new("family/sum rule removed: inflated transfer")
        .on(weakened.clone())
        .expect_accept(&inflated);
    Case::new("family/sum rule removed: honest transfer")
        .on(weakened.clone())
        .expect_accept(&honest);

    // The other rules of the weakened contract are still attributed, by the same offsets.
    let outcome = Case::new("family/sum rule removed: another key")
        .on(weakened)
        .twin(
            &honest,
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() =
                    witness::owner_key(keys::CAROL, EntryRole::Leader, SIG_HASH_ALL)
            },
            0,
            Expected::rule("K-38").at_line(69),
        )
        .changed;
    let refusal = outcome.inputs[0]
        .alone
        .as_ref()
        .unwrap()
        .refusal
        .as_ref()
        .unwrap();
    assert_eq!(refusal.contract.as_deref(), Some("KCC20"));
    assert_eq!(refusal.note, None);
}

// ---------------------------------------------------------------------------------------
// 7. The result file
// ---------------------------------------------------------------------------------------

/// The lines of this binary's result file whose case id is `case`.
fn result_lines(case: &str) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(results::results_path())
        .expect("the result file exists after a helper call");
    // Other tests of this binary append while this one reads: a last line without its
    // line end may still be on its way and is left out.
    text.split_inclusive('\n')
        .filter(|line| line.ends_with('\n'))
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .expect("every line is one JSON document")
        })
        .filter(|record| record["case"] == case)
        .collect()
}

#[test]
fn every_helper_call_writes_one_line_in_the_documented_format() {
    assert_eq!(results::binary_name(), "selfcheck");
    assert!(
        results::results_path().ends_with("check-results/selfcheck.jsonl")
            || std::env::var_os(results::RESULTS_DIR_ENV).is_some()
    );

    let honest = shapes::borrow(&Profile::Script, BorrowKind::Threshold);
    let accept_case = "format/accept";
    let written_before = results::lines_written();
    let outcome: Outcome = Case::new(accept_case)
        .py([
            "test_borrow.BorrowedReceive.test_adding_more_than_the_threshold_passes_without_the_recipient_s_signature",
            "test_transfer.Conservation.test_one_output_holding_more_is_refused",
        ])
        .note("two inputs")
        .expect_accept(&honest);

    // The line was written by this run, into a file that this run emptied first: the file
    // holds the lines this process wrote and no others. (Other tests of this binary write
    // at the same time; one line may be counted and still on its way.)
    let written_after = results::lines_written();
    assert!(written_after > written_before);
    let lines_in_the_file = std::fs::read_to_string(results::results_path())
        .expect("the result file exists after a helper call")
        .matches('\n')
        .count();
    let written_later = results::lines_written();
    assert!(
        written_after <= lines_in_the_file + 1 && lines_in_the_file <= written_later,
        "{lines_in_the_file} lines in the file, {written_after} to {written_later} written by this run"
    );

    let lines = result_lines(accept_case);
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    for key in [
        "format",
        "binary",
        "test",
        "case",
        "py_ids",
        "note",
        "kind",
        "helper",
        "expected",
        "passed",
        "failure",
        "scenario",
        "tx_id",
        "network",
        "inputs",
        "scripts",
        "budgets",
        "masses",
        "consensus",
        "mempool",
        "honest",
    ] {
        assert!(line.get(key).is_some(), "the key `{key}` is missing");
    }
    assert_eq!(line["format"], 2);
    assert_eq!(line["binary"], "selfcheck");
    // The test runner names the thread of a test after it; with one test thread the tests
    // run on the main thread and the name is not known.
    assert!(
        line["test"] == "every_helper_call_writes_one_line_in_the_documented_format"
            || line["test"].is_null()
    );
    assert_eq!(
        line["py_ids"],
        serde_json::json!([
            "test_borrow.BorrowedReceive.test_adding_more_than_the_threshold_passes_without_the_recipient_s_signature",
            "test_transfer.Conservation.test_one_output_holding_more_is_refused"
        ])
    );
    assert_eq!(line["note"], "two inputs");
    assert_eq!(line["kind"], "accept");
    assert_eq!(line["helper"], "expect_accept");
    assert_eq!(
        line["expected"],
        serde_json::json!({ "scope": "scripts", "verdict": "accept" })
    );
    assert_eq!(line["passed"], true);
    assert_eq!(line["failure"], serde_json::Value::Null);
    assert_eq!(line["scenario"], "borrow by threshold");
    assert_eq!(line["tx_id"], outcome.tx_id.as_str());
    assert_eq!(line["network"], "kaspa-testnet-10");
    assert_eq!(line["honest"], serde_json::Value::Null);
    assert_eq!(line["twin_context"], serde_json::Value::Null);

    let inputs = line["inputs"].as_array().expect("inputs is a list");
    assert_eq!(inputs.len(), 2);
    let leader = &inputs[0];
    assert_eq!(leader["index"], 0);
    assert_eq!(leader["kind"], "contract");
    // What the bytes run, and what the scenario says.
    assert_eq!(leader["contract"], "KCC20");
    assert_eq!(leader["entry"], "transfer");
    assert_eq!(leader["stated_contract"], "KCC20");
    assert_eq!(leader["stated_entry"], "transfer");
    assert_eq!(inputs[1]["entry"], "transfer_delegator");
    assert_eq!(leader["alone"]["ok"], true);
    assert_eq!(leader["alone"]["sig_op_limit"], serde_json::Value::Null);
    assert_eq!(leader["alone"]["error"], serde_json::Value::Null);
    assert_eq!(
        leader["alone"]["script_units_limit"],
        serde_json::Value::Null
    );
    assert_eq!(
        leader["alone"]["used_script_units"],
        outcome.inputs[0].alone.as_ref().unwrap().used_script_units
    );
    assert_eq!(
        leader["minimal_budget"],
        outcome.inputs[0].minimal_budget.unwrap()
    );
    assert_eq!(
        leader["commitment"]["compute_budget"],
        outcome.inputs[0].minimal_budget.unwrap()
    );
    assert_eq!(leader["committed"]["ok"], true);
    assert_eq!(line["scripts"]["accepted"], true);
    assert_eq!(line["scripts"]["accepted_under_committed_budgets"], true);
    assert_eq!(line["scripts"]["judged"], "alone");
    assert_eq!(line["budgets"]["source"], "minimal");
    assert_eq!(line["budgets"]["minimal"].as_array().unwrap().len(), 2);
    assert!(line["masses"]["compute_mass"].is_u64() && line["masses"]["transient_mass"].is_u64());
    assert!(line["masses"]["calculated_storage_mass"].is_u64());
    assert_eq!(line["consensus"]["context_accepted"], true);
    assert_eq!(
        line["consensus"]["block"]["accepted"],
        outcome.consensus.block.accepted
    );
    assert_eq!(line["mempool"]["accepted"], outcome.mempool.accepted);
    assert!(line["mempool"]["refused"].is_array());

    // A refusal carries the error in three forms, the class, and the attribution.
    let twin_case = "format/twin";
    let delegate_key = witness::owner_key(keys::CAROL, EntryRole::Delegate, SIG_HASH_ALL);
    Case::new(twin_case).twin(
        &honest,
        move |scenario| *scenario.contract_input_mut(1).witness_mut() = delegate_key,
        1,
        "K-38",
    );
    let lines = result_lines(twin_case);
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    assert_eq!(line["kind"], "reject");
    assert_eq!(line["helper"], "twin");
    assert_eq!(line["expected"]["verdict"], "reject");
    assert_eq!(line["expected"]["inputs"][0]["input"], 1);
    assert_eq!(line["expected"]["inputs"][0]["rule"], "K-38");
    assert_eq!(line["expected"]["inputs"][0]["pass"], false);
    assert_eq!(line["expected"]["context"], "node_runs_scripts");
    assert_eq!(
        line["twin_context"],
        serde_json::json!({
            "required": true,
            "honest_consensus_accepted": true,
            "changed_context_accepted": true
        })
    );
    assert_eq!(
        line["honest"]["scripts"]["accepted"], true,
        "the honest twin is recorded in the same line"
    );
    let delegate = &line["inputs"][1]["alone"];
    assert_eq!(delegate["ok"], false);
    assert_eq!(delegate["error"]["variant"], "VerifyError");
    assert_eq!(delegate["error"]["debug"], "VerifyError");
    assert!(delegate["error"]["message"].is_string());
    assert_eq!(delegate["class"], "contract_refused");
    assert_eq!(delegate["refusal"]["refused_by"], "K-38");
    assert_eq!(delegate["refusal"]["rule"], "K-38");
    assert_eq!(delegate["refusal"]["part"], "contract_script");
    assert_eq!(delegate["refusal"]["contract"], "KCC20");
    assert_eq!(delegate["refusal"]["entry"], "transfer_delegator");
    assert_eq!(delegate["refusal"]["byte_offset"], 3837);
    assert_eq!(delegate["refusal"]["sil"]["file"], "KCC20.sil");
    assert_eq!(delegate["refusal"]["sil"]["line"], 69);
    assert_eq!(delegate["stop"]["opcode"]["script"], "redeem_script");
    assert_eq!(
        line["inputs"][0]["alone"]["ok"], true,
        "the leader is not affected"
    );
    assert_eq!(line["scripts"]["refused_inputs"], serde_json::json!([1]));

    // An unrecorded case writes nothing.
    let silent_case = "format/unrecorded";
    Case::new(silent_case).unrecorded().expect_accept(&honest);
    assert!(result_lines(silent_case).is_empty());
}
