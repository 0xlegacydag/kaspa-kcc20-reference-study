//! Assertions for test authors.
//!
//! Every helper runs a scenario through the [`Harness`], judges the [`Outcome`] against
//! what the test expects, appends one line to the result file, and panics with a message
//! that prints everything observed when the expectation does not hold.
//!
//! The judging itself is in the `judge_*` functions. They take an outcome, return
//! `Result<(), String>` and write nothing, so a test can combine them freely.
//!
//! What "accepted" and "refused" mean here: the answer of the script engine. A scenario is
//! accepted when every input passes by itself and again under the smallest covering
//! budgets. Whether the consensus rules around the scripts and the mempool would take the
//! transaction is observed and recorded, but it is asserted only by the helpers that say so
//! in their name.
//!
//! One exception: a twin. A twin says "this rule, and nothing else, turns an accepted
//! transaction into a refused one", and that is a statement about a node only if a node
//! gets to run the scripts of both sides. So a twin also requires that the consensus rules
//! accept the honest side and let the changed side through to its scripts
//! ([`TwinContext`]); a case that is about the engine alone says so with
//! [`Case::scripts_only`].
//!
//! In a mutation run ([`crate::mutation`]) the helpers change in three ways, each set by
//! its own environment variable: a failed expectation is recorded and does not panic; a
//! case that is not selected returns a placeholder outcome and writes no line; and with
//! only the scripts run, an expectation about anything around the scripts is not judged.

use std::borrow::Cow;

use kcc20_family::{Family, Scenario};
use serde::Serialize;
use serde_json::json;

use crate::{
    harness::Harness,
    mutation,
    outcome::{Outcome, PolicyFinding, variant_name},
    python_ids, results,
};
use node_gate::{ErrorClass, Stage};

/// What a check expects of one input.
///
/// An expectation is a set of conditions; all that are set must hold. Build one with a
/// constructor and narrow it with the `at_*` methods:
///
/// ```
/// use checks::Expected;
/// let sum_rule = Expected::rule("K-37").at_line(175);
/// let overflow = Expected::engine("NumberTooBig").at_rule("K-30");
/// let wrapper = Expected::refused_by("P2SH wrapper");
/// assert_ne!(sum_rule, overflow);
/// assert_eq!(Expected::from("K-37"), Expected::rule("K-37"));
/// assert_eq!(Expected::from("NumberTooBig"), Expected::engine("NumberTooBig"));
/// assert_eq!(Expected::from("P2SH wrapper"), wrapper);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Expected {
    /// The input passes.
    pub pass: bool,
    /// The contract rule with this inventory id refused.
    pub rule: Option<String>,
    /// The engine's error has this variant name.
    pub engine: Option<String>,
    /// The short name of what refused is this.
    pub refused_by: Option<String>,
    /// The engine stopped at an opcode the inventory files under this rule, whatever the
    /// error.
    pub at_rule: Option<String>,
    /// The engine stopped in the source statement that starts at this line.
    pub sil_line: Option<u32>,
    /// The refusal has this class of cause.
    pub class: Option<ErrorClass>,
}

impl Expected {
    const NOTHING: Self = Self {
        pass: false,
        rule: None,
        engine: None,
        refused_by: None,
        at_rule: None,
        sil_line: None,
        class: None,
    };

    /// The input passes.
    pub fn pass() -> Self {
        Self {
            pass: true,
            ..Self::NOTHING
        }
    }

    /// The contract rule with this id of the rule inventory (`K-37`, `M-41`, `S-12`)
    /// refused: the engine stopped at one of the rule's opcodes with the kind of error
    /// the rule refuses with. The strongest expectation; prefer it.
    pub fn rule(id: impl Into<String>) -> Self {
        Self {
            rule: Some(id.into()),
            ..Self::NOTHING
        }
    }

    /// The engine refused with the error variant of this name (`NumberTooBig`,
    /// `InvalidSigHashType`, `ExceededCommittedScriptUnits`), wherever it stopped. Narrow
    /// it with [`Expected::at_rule`] or [`Expected::at_line`] when the place matters.
    pub fn engine(variant: impl Into<String>) -> Self {
        Self {
            engine: Some(variant.into()),
            ..Self::NOTHING
        }
    }

    /// The short name of what refused is exactly this: `P2SH wrapper`, `final stack`,
    /// `prologue`, `dispatcher`, or any other value of `Attribution::refused_by`.
    pub fn refused_by(label: impl Into<String>) -> Self {
        Self {
            refused_by: Some(label.into()),
            ..Self::NOTHING
        }
    }

    /// The engine stopped in the source statement that starts at this line of the
    /// contract's generated source, and it was a rule of the contract that refused or the
    /// engine refusing the data of that statement. As strong as a check that asserts a
    /// line and nothing else.
    pub fn line(sil_line: u32) -> Self {
        Self {
            sil_line: Some(sil_line),
            ..Self::NOTHING
        }
    }

    /// Also: the engine stopped in the statement that starts at this line.
    pub fn at_line(mut self, sil_line: u32) -> Self {
        self.sil_line = Some(sil_line);
        self
    }

    /// Also: the engine stopped at an opcode the inventory files under this rule.
    pub fn at_rule(mut self, id: impl Into<String>) -> Self {
        self.at_rule = Some(id.into());
        self
    }

    /// Also: the refusal has this class of cause.
    pub fn of_class(mut self, class: ErrorClass) -> Self {
        self.class = Some(class);
        self
    }
}

/// The labels `Attribution::refused_by` uses besides rule ids and `engine: <Variant>`.
const PLACE_LABELS: [&str; 11] = [
    "P2SH wrapper",
    "final stack",
    "prologue",
    "dispatcher",
    "statement",
    "glue",
    "clean-up",
    "state frame",
    "redeem script",
    "lock script",
    "contract script",
];

impl From<&str> for Expected {
    /// `K-37` is a rule id, `P2SH wrapper` and the other place names are labels,
    /// `engine: NumberTooBig` and a bare `NumberTooBig` are an engine error variant.
    fn from(text: &str) -> Self {
        let is_rule_id = text.split_once('-').is_some_and(|(prefix, number)| {
            matches!(prefix, "K" | "M" | "S")
                && !number.is_empty()
                && number.bytes().all(|b| b.is_ascii_digit())
        });
        if is_rule_id {
            Self::rule(text)
        } else if PLACE_LABELS.contains(&text) {
            Self::refused_by(text)
        } else {
            Self::engine(text.strip_prefix("engine: ").unwrap_or(text))
        }
    }
}

/// What a twin check requires of the consensus rules around the scripts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TwinContext {
    /// A node gets to run the scripts of both sides. The honest side passes the consensus
    /// rules of a submission, scripts included; the changed side passes every consensus
    /// rule a node checks before the scripts. The default.
    NodeRunsScripts,
    /// Only the script engine is asked: what a node says before it runs a script is
    /// observed and recorded, not required. For a case about the engine alone, for
    /// example one whose coin values were chosen for the script engine and not for a
    /// node.
    ScriptsOnly,
}

/// The identity of one check: its id, the checks of the earlier suite it repeats, and the
/// harness it runs on.
#[derive(Clone, Debug)]
pub struct Case {
    /// The id of the case. It names the line in the result file; keep it unique within a
    /// test binary.
    pub id: String,
    /// The ids of the checks of the earlier suite this case repeats ([`Case::py`]).
    pub py_ids: Vec<String>,
    /// Free text kept with the result line.
    pub note: Option<String>,
    /// The harness the scenario runs on.
    pub harness: Harness,
    /// Whether the helpers append a line to the result file for this case.
    pub recorded: bool,
    /// What the twin helpers require besides the scripts.
    pub twin_context: TwinContext,
}

impl Case {
    /// A case on the default harness, repeating no check of the earlier suite.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            py_ids: Vec::new(),
            note: None,
            harness: Harness::pinned(),
            recorded: true,
            twin_context: TwinContext::NodeRunsScripts,
        }
    }

    /// The same case without a line in the result file. For tests of the helpers
    /// themselves, whose expected failures must not look like results.
    pub fn unrecorded(mut self) -> Self {
        self.recorded = false;
        self
    }

    /// The checks of an earlier suite this case repeats, by their ids. That suite was
    /// written in Python for the debug engine of the Kaspa Python SDK and is not published
    /// here: the ids are labels, kept in the result line.
    ///
    /// # Panics
    ///
    /// Panics when an id is not in the list `data/python-check-ids.txt`
    /// ([`crate::python_ids`]): a misspelt id would misfile the case in every later
    /// comparison of the result files.
    pub fn py<I, S>(mut self, py_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for id in py_ids {
            let id = id.into();
            assert!(
                python_ids::is_known(&id),
                "case `{}`: `{id}` is not the id of a check of the earlier Python suite \
                 listed in data/python-check-ids.txt",
                self.id
            );
            self.py_ids.push(id);
        }
        self
    }

    /// The twin helpers judge the scripts only: they do not require that a node gets to
    /// run them ([`TwinContext::ScriptsOnly`]). Say why in the note of the case.
    pub fn scripts_only(mut self) -> Self {
        self.twin_context = TwinContext::ScriptsOnly;
        self
    }

    /// Free text kept with the result line.
    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    /// Runs the case on another harness: other budgets, another node, another family.
    pub fn on(mut self, harness: Harness) -> Self {
        self.harness = harness;
        self
    }

    /// Whether a mutation run leaves this case out: a list of cases is set and the case is
    /// not on it ([`crate::mutation::ONLY_CASES_ENV`]).
    fn left_out(&self) -> bool {
        !mutation::is_standing_in() && !mutation::mode().selects(&results::binary_name(), &self.id)
    }

    /// What a helper returns for a case a mutation run leaves out, `None` for a case that
    /// runs. By default the placeholder outcome of the scenario ([`Outcome::skipped`]):
    /// nothing is run, judged or recorded. With
    /// [`crate::mutation::UNSELECTED_ENV`]`=pinned` the outcome of `rerun` on the
    /// stand-in of the case: the same helper call, on the pinned contracts where the case
    /// used the family of the mutation run, and without a result line.
    fn unselected(
        &self,
        scenario: &Scenario,
        rerun: impl FnOnce(&Case) -> Outcome,
    ) -> Option<Outcome> {
        if !self.left_out() {
            return None;
        }
        if !mutation::mode().unselected_on_pinned {
            return Some(self.harness.skipped(scenario));
        }
        let stand_in = self.stand_in();
        Some(mutation::standing_in(|| rerun(&stand_in)))
    }

    /// The case as an ordinary run has it: on the pinned family when its harness runs on
    /// the family of the mutation run, and without a result line.
    fn stand_in(&self) -> Case {
        let mut case = self.clone();
        case.recorded = false;
        if let Cow::Borrowed(family) = &case.harness.family
            && std::ptr::eq(*family, mutation::family())
        {
            case.harness.family = Cow::Borrowed(Family::pinned());
        }
        case
    }

    /// The scripts accept the transaction: every input passes by itself with no budget
    /// limit and again under the smallest covering budgets, and the two runs agree. With
    /// fixed budgets: every input passes under them.
    pub fn expect_accept(&self, scenario: &Scenario) -> Outcome {
        if let Some(outcome) = self.unselected(scenario, |case| case.expect_accept(scenario)) {
            return outcome;
        }
        let outcome = self.harness.run(scenario);
        let result = judge_accept(&outcome);
        self.conclude(
            "expect_accept",
            Kind::Accept,
            json!({ "scope": "scripts" }),
            outcome,
            None,
            result,
        )
    }

    /// Input `input` is refused as `expected` says. Nothing is asserted about the other
    /// inputs; they are observed and recorded.
    pub fn expect_refused(
        &self,
        scenario: &Scenario,
        input: usize,
        expected: impl Into<Expected>,
    ) -> Outcome {
        self.expect_inputs_as("expect_refused", scenario, &[(input, expected.into())])
    }

    /// Every listed input answers as its expectation says: refused by a rule, refused by
    /// the engine, or passing ([`Expected::pass`]). At least one listed input must be
    /// expected to be refused; use [`Case::expect_accept`] for a transaction that passes.
    pub fn expect_inputs(&self, scenario: &Scenario, expected: &[(usize, Expected)]) -> Outcome {
        self.expect_inputs_as("expect_inputs", scenario, expected)
    }

    fn expect_inputs_as(
        &self,
        helper: &str,
        scenario: &Scenario,
        expected: &[(usize, Expected)],
    ) -> Outcome {
        if let Some(outcome) = self.unselected(scenario, |case| {
            case.expect_inputs_as(helper, scenario, expected)
        }) {
            return outcome;
        }
        let outcome = self.harness.run(scenario);
        let result = judge_inputs(&outcome, expected);
        self.conclude(
            helper,
            Kind::Reject,
            expected_inputs_json(expected),
            outcome,
            None,
            result,
        )
    }

    /// The honest scenario is accepted, and the same scenario after `change` is refused at
    /// input `input` as `expected` says. `change` must alter the transaction or the coins
    /// it spends.
    ///
    /// Unless the case is [`Case::scripts_only`], a node must get to run the scripts of
    /// both sides: the consensus rules accept the honest scenario, and no consensus rule
    /// in front of the scripts refuses the changed one.
    pub fn twin(
        &self,
        honest: &Scenario,
        change: impl FnOnce(&mut Scenario),
        input: usize,
        expected: impl Into<Expected>,
    ) -> Twin {
        self.twin_inputs(honest, change, &[(input, expected.into())])
    }

    /// [`Case::twin`] with an expectation for several inputs of the changed scenario.
    pub fn twin_inputs(
        &self,
        honest: &Scenario,
        change: impl FnOnce(&mut Scenario),
        expected: &[(usize, Expected)],
    ) -> Twin {
        let mut changed_scenario = honest.clone();
        change(&mut changed_scenario);
        self.twin_of(honest, &changed_scenario, expected)
    }

    /// A twin whose changed side is given as a scenario.
    fn twin_of(
        &self,
        honest: &Scenario,
        changed_scenario: &Scenario,
        expected: &[(usize, Expected)],
    ) -> Twin {
        // A case a mutation run leaves out: two placeholders, or the twin of its stand-in.
        if self.left_out() {
            if mutation::mode().unselected_on_pinned {
                let stand_in = self.stand_in();
                return mutation::standing_in(|| {
                    stand_in.twin_of(honest, changed_scenario, expected)
                });
            }
            return Twin {
                honest: self.harness.skipped(honest),
                changed: self.harness.skipped(changed_scenario),
            };
        }
        let honest_outcome = self.harness.run(honest);
        let changed_outcome = self.harness.run(changed_scenario);

        let result = judge_twin_in(
            &honest_outcome,
            &changed_outcome,
            expected,
            self.twin_context,
        );
        let mut expected = expected_inputs_json(expected);
        if let Some(object) = expected.as_object_mut() {
            object.insert("context".to_string(), json!(self.twin_context));
        }
        let changed = self.conclude(
            "twin",
            Kind::Reject,
            expected,
            changed_outcome,
            Some(&honest_outcome),
            result,
        );
        Twin {
            honest: honest_outcome,
            changed,
        }
    }

    /// The scripts accept the transaction and so do the consensus rules a node applies to
    /// a submission. Storage mass is not limited by them; see
    /// [`Case::expect_block_accept`] and [`Case::expect_mempool_accept`].
    pub fn expect_consensus_accept(&self, scenario: &Scenario) -> Outcome {
        if let Some(outcome) =
            self.unselected(scenario, |case| case.expect_consensus_accept(scenario))
        {
            return outcome;
        }
        let outcome = self.harness.run(scenario);
        let result = judge_accept(&outcome).and_then(|()| {
            if outcome.scripts_only() || outcome.consensus.accepted {
                Ok(())
            } else {
                Err("the consensus rules refuse the transaction".to_string())
            }
        });
        self.conclude(
            "expect_consensus_accept",
            Kind::Accept,
            json!({ "scope": "consensus" }),
            outcome,
            None,
            result,
        )
    }

    /// A consensus rule other than the scripts refuses the submitted transaction. `rule`
    /// is the name of the refusing function (`check_transaction_output_values`) or of the
    /// error variant (`SpendTooHigh`).
    pub fn expect_consensus_refused(&self, scenario: &Scenario, rule: &str) -> Outcome {
        if let Some(outcome) = self.unselected(scenario, |case| {
            case.expect_consensus_refused(scenario, rule)
        }) {
            return outcome;
        }
        let outcome = self.harness.run(scenario);
        let result = match &outcome.consensus.context_refusal {
            Some(refusal) if refusal.rule == rule || variant_name(&refusal.error) == rule => Ok(()),
            Some(refusal) => Err(format!(
                "the consensus context refuses by {} ({}), not by {rule}",
                refusal.rule, refusal.error
            )),
            None => Err(format!(
                "no consensus rule in front of the scripts refuses; expected {rule}"
            )),
        };
        self.conclude(
            "expect_consensus_refused",
            Kind::Reject,
            json!({ "scope": "consensus_context", "rule": rule }),
            outcome,
            None,
            result,
        )
    }

    /// The scripts accept the transaction and a block may hold it: the consensus rules
    /// with the calculated storage mass committed, and the limits of a block.
    pub fn expect_block_accept(&self, scenario: &Scenario) -> Outcome {
        if let Some(outcome) = self.unselected(scenario, |case| case.expect_block_accept(scenario))
        {
            return outcome;
        }
        let outcome = self.harness.run(scenario);
        let result = judge_accept(&outcome).and_then(|()| {
            if outcome.scripts_only() || outcome.consensus.block.accepted {
                Ok(())
            } else {
                Err("a block cannot hold the transaction".to_string())
            }
        });
        self.conclude(
            "expect_block_accept",
            Kind::Accept,
            json!({ "scope": "block" }),
            outcome,
            None,
            result,
        )
    }

    /// Inside a block the transaction is refused by `rule`: the name of the refusing
    /// function (`check_block_mass`, `check_mass_commitment`) or of the error variant
    /// (`ExceedsStorageMassLimit`, `WrongMass`).
    pub fn expect_block_refused(&self, scenario: &Scenario, rule: &str) -> Outcome {
        if let Some(outcome) =
            self.unselected(scenario, |case| case.expect_block_refused(scenario, rule))
        {
            return outcome;
        }
        let outcome = self.harness.run(scenario);
        let result = match &outcome.consensus.block.refusal {
            Some(refusal) if refusal.rule == rule || variant_name(&refusal.error) == rule => Ok(()),
            Some(refusal) => Err(format!(
                "inside a block the refusal is {} ({}), not {rule}",
                refusal.rule, refusal.error
            )),
            None => Err(format!(
                "a block may hold the transaction; expected a refusal by {rule}"
            )),
        };
        self.conclude(
            "expect_block_refused",
            Kind::Reject,
            json!({ "scope": "block", "rule": rule }),
            outcome,
            None,
            result,
        )
    }

    /// A default node takes the submitted transaction into its mempool: scripts, consensus
    /// rules and every policy rule.
    pub fn expect_mempool_accept(&self, scenario: &Scenario) -> Outcome {
        if let Some(outcome) =
            self.unselected(scenario, |case| case.expect_mempool_accept(scenario))
        {
            return outcome;
        }
        let outcome = self.harness.run(scenario);
        let result = judge_accept(&outcome).and_then(|()| {
            if outcome.scripts_only() || outcome.mempool.accepted {
                Ok(())
            } else {
                Err("the node does not take the transaction into its mempool".to_string())
            }
        });
        self.conclude(
            "expect_mempool_accept",
            Kind::Accept,
            json!({ "scope": "mempool" }),
            outcome,
            None,
            result,
        )
    }

    /// A default node refuses the submitted transaction by the mempool rule `rule`: the
    /// name of the refusing function (`check_storage_mass_limit`,
    /// `check_minimum_relay_fee`) or of the refusal variant (`StorageMass`,
    /// `InsufficientComputeFee`). The rule must be the node's answer: the first refusal in
    /// the order a node checks. A transaction whose consensus validation fails is refused
    /// by that and never meets the rules behind it (rusty-kaspa a41a333
    /// mining/src/mempool/validate_and_insert_transaction.rs:57-77); to ask what one rule
    /// says by itself, use [`Case::expect_policy_rule_refuses`]. Later rules may refuse as
    /// well; all of them are recorded.
    pub fn expect_mempool_refused(&self, scenario: &Scenario, rule: &str) -> Outcome {
        if let Some(outcome) =
            self.unselected(scenario, |case| case.expect_mempool_refused(scenario, rule))
        {
            return outcome;
        }
        let outcome = self.harness.run(scenario);
        let result = judge_mempool_refused(&outcome, rule);
        self.conclude(
            "expect_mempool_refused",
            Kind::Reject,
            json!({ "scope": "mempool", "rule": rule }),
            outcome,
            None,
            result,
        )
    }

    /// The mempool rule `rule` refuses the transaction when it is evaluated on its own,
    /// whether or not a node gets to it. This is weaker than
    /// [`Case::expect_mempool_refused`]: the rule is one of the reasons listed in
    /// `mempool.refused`, not necessarily the node's answer.
    pub fn expect_policy_rule_refuses(&self, scenario: &Scenario, rule: &str) -> Outcome {
        if let Some(outcome) = self.unselected(scenario, |case| {
            case.expect_policy_rule_refuses(scenario, rule)
        }) {
            return outcome;
        }
        let outcome = self.harness.run(scenario);
        let result = judge_policy_rule_refuses(&outcome, rule);
        self.conclude(
            "expect_policy_rule_refuses",
            Kind::Reject,
            json!({ "scope": "mempool_rule", "rule": rule }),
            outcome,
            None,
            result,
        )
    }

    /// Writes the result line and panics when the expectation did not hold. In a mutation
    /// run that observes ([`crate::mutation::OBSERVE_ENV`]) it does not panic: the line
    /// says what was observed and the outcome is returned.
    fn conclude(
        &self,
        helper: &str,
        kind: Kind,
        mut expected: serde_json::Value,
        outcome: Outcome,
        honest: Option<&Outcome>,
        result: Result<(), String>,
    ) -> Outcome {
        let mode = mutation::mode();
        // With only the scripts run there is no answer to an expectation of a refusal by a
        // consensus, block or mempool rule: the line says so and nothing fails. Every
        // other expectation was judged by the scripts alone.
        let asks_a_node = expected["scope"]
            .as_str()
            .is_some_and(|scope| scope != "scripts");
        let (result, judged) = match (outcome.scripts_only(), asks_a_node, kind) {
            (false, _, _) => (result, "full"),
            (true, true, Kind::Reject) => (Ok(()), "not_at_all"),
            (true, _, _) => (result, "scripts_only"),
        };
        if let Some(object) = expected.as_object_mut() {
            object.insert("verdict".to_string(), json!(kind));
        }
        if self.recorded {
            let binary = results::binary_name();
            results::append(&Record {
                format: results::FORMAT,
                binary: &binary,
                test: results::test_name(),
                case: &self.id,
                py_ids: &self.py_ids,
                note: self.note.as_deref(),
                kind,
                helper,
                expected,
                passed: result.is_ok(),
                failure: result.as_ref().err().map(String::as_str),
                observed: &outcome,
                twin_context: honest.map(|honest| {
                    json!({
                        "required": self.twin_context == TwinContext::NodeRunsScripts,
                        "honest_consensus_accepted": honest.consensus.accepted,
                        "changed_context_accepted": outcome.consensus.context_accepted,
                    })
                }),
                honest,
                mutation: mode.record(judged),
            });
        }
        if let Err(failure) = result
            && !mode.observe
        {
            panic!(
                "case `{}` ({helper}): {failure}\nobserved:\n{}",
                self.id,
                outcome.describe()
            );
        }
        outcome
    }
}

impl From<&str> for Case {
    fn from(id: &str) -> Self {
        Self::new(id)
    }
}

impl From<String> for Case {
    fn from(id: String) -> Self {
        Self::new(id)
    }
}

/// The two outcomes of a twin check.
#[derive(Clone, Debug)]
pub struct Twin {
    /// The honest scenario.
    pub honest: Outcome,
    /// The scenario after the change.
    pub changed: Outcome,
}

/// Whether a check expects the transaction to be accepted or refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Accept,
    Reject,
}

/// One line of a result file. The field list is the documented format; see the README.
#[derive(Serialize)]
struct Record<'a> {
    format: u32,
    binary: &'a str,
    test: Option<String>,
    case: &'a str,
    py_ids: &'a [String],
    note: Option<&'a str>,
    kind: Kind,
    helper: &'a str,
    expected: serde_json::Value,
    passed: bool,
    failure: Option<&'a str>,
    #[serde(flatten)]
    observed: &'a Outcome,
    twin_context: Option<serde_json::Value>,
    honest: Option<&'a Outcome>,
    mutation: Option<serde_json::Value>,
}

fn expected_inputs_json(expected: &[(usize, Expected)]) -> serde_json::Value {
    let inputs: Vec<serde_json::Value> = expected
        .iter()
        .map(|(input, expected)| {
            let mut value =
                serde_json::to_value(expected).expect("an expectation holds only plain data");
            if let Some(object) = value.as_object_mut() {
                object.insert("input".to_string(), json!(input));
            }
            value
        })
        .collect();
    json!({ "scope": "scripts", "inputs": inputs })
}

/// Whether the scripts accept the transaction, in the sense of [`Case::expect_accept`].
pub fn judge_accept(outcome: &Outcome) -> Result<(), String> {
    judge_runs_made(outcome)?;
    for input in &outcome.inputs {
        let run = input
            .judged(outcome.scripts.judged)
            .expect("the runs were made");
        if !run.ok {
            return Err(format!(
                "input {} [{}] is refused: {}",
                input.index,
                input.what(),
                run.describe()
            ));
        }
        if run.accepted_unknown_version {
            return Err(format!(
                "input {} passes without running anything: its coin has an unknown script version",
                input.index
            ));
        }
    }
    if !outcome.scripts_accept() {
        return Err("the scripts do not accept the transaction".to_string());
    }
    // The fast mode of a mutation run makes no run under committed budgets.
    if !outcome.scripts_only() && outcome.scripts.accepted_under_committed_budgets != Some(true) {
        return Err(format!(
            "under the committed budgets the inputs {:?} are refused",
            outcome.scripts.refused_inputs_under_committed_budgets
        ));
    }
    Ok(())
}

/// Whether every listed input answers as its expectation says, in the sense of
/// [`Case::expect_inputs`].
pub fn judge_inputs(outcome: &Outcome, expected: &[(usize, Expected)]) -> Result<(), String> {
    if !expected.iter().any(|(_, expected)| !expected.pass) {
        return Err("no listed input is expected to be refused: this check could not tell a refusal from a pass".to_string());
    }
    judge_runs_made(outcome)?;
    for (input, expected) in expected {
        judge_input(outcome, *input, expected)?;
    }
    Ok(())
}

/// Whether the honest outcome is accepted, the changed transaction really differs from the
/// honest one, the changed outcome answers as `expected` says, and a node gets to run the
/// scripts of both: the sense of [`Case::twin`].
pub fn judge_twin(
    honest: &Outcome,
    changed: &Outcome,
    expected: &[(usize, Expected)],
) -> Result<(), String> {
    judge_twin_in(honest, changed, expected, TwinContext::NodeRunsScripts)
}

/// [`judge_twin`] without the requirement that a node gets to run the scripts: the sense of
/// a twin of a [`Case::scripts_only`] case.
pub fn judge_twin_scripts_only(
    honest: &Outcome,
    changed: &Outcome,
    expected: &[(usize, Expected)],
) -> Result<(), String> {
    judge_twin_in(honest, changed, expected, TwinContext::ScriptsOnly)
}

fn judge_twin_in(
    honest: &Outcome,
    changed: &Outcome,
    expected: &[(usize, Expected)],
    context: TwinContext,
) -> Result<(), String> {
    // The fast mode of a mutation run asks no consensus rule: the scripts are all there is.
    let node_must_run_scripts = context == TwinContext::NodeRunsScripts
        && !honest.scripts_only()
        && !changed.scripts_only();
    judge_accept(honest).map_err(|failure| {
        format!(
            "the honest twin is not accepted: {failure}\nthe honest twin:\n{}",
            honest.describe()
        )
    })?;
    // The scripts were required to pass under the committed budgets just above, so what
    // this adds is the consensus rules in front of the scripts.
    if node_must_run_scripts && !honest.consensus.accepted {
        return Err(format!(
            "the scripts of the honest twin pass, but the consensus rules of a node refuse \
             it{}: what its scripts say is not what a node answers. Give the scenario values \
             a node accepts, or make the case `scripts_only()`\nthe honest twin:\n{}",
            refusal_phrase(honest),
            honest.describe()
        ));
    }
    if honest.assembled.tx == changed.assembled.tx
        && honest.assembled.utxos == changed.assembled.utxos
    {
        return Err("the change altered neither the transaction nor its coins".to_string());
    }
    judge_inputs(changed, expected)?;
    if node_must_run_scripts && !changed.consensus.context_accepted {
        return Err(format!(
            "the changed twin is refused as expected by its scripts, but a node refuses it \
             before it runs a script{}: the change did more than the check is about. Keep \
             the consensus rules in front of the scripts satisfied, or make the case \
             `scripts_only()`",
            refusal_phrase(changed)
        ));
    }
    Ok(())
}

/// `, by <rule> (<error>)` for the consensus refusal of an outcome, or nothing.
fn refusal_phrase(outcome: &Outcome) -> String {
    let refusal = outcome
        .consensus
        .context_refusal
        .as_ref()
        .or(outcome.consensus.refusal.as_ref());
    match (refusal, &outcome.consensus.harness_error) {
        (Some(refusal), _) => format!(", by {} ({})", refusal.rule, refusal.error),
        (None, Some(reason)) => format!(" ({reason})"),
        (None, None) => String::new(),
    }
}

/// Whether `finding` is the policy rule named `rule`: by the function that implements it
/// or by the variant of its refusal.
fn names_policy_rule(finding: &PolicyFinding, rule: &str) -> bool {
    finding.function == rule || variant_name(&format!("{:?}", finding.refusal)) == rule
}

/// Whether the node's answer to the submitted transaction is a refusal by the mempool rule
/// `rule`: the sense of [`Case::expect_mempool_refused`].
pub fn judge_mempool_refused(outcome: &Outcome, rule: &str) -> Result<(), String> {
    let Some(first) = &outcome.mempool.first_refusal else {
        return Err(format!(
            "the node takes the transaction into its mempool; expected a refusal by {rule}"
        ));
    };
    let by_the_mempool = matches!(
        first.stage,
        Stage::MempoolBeforeConsensus | Stage::MempoolAfterConsensus
    );
    if by_the_mempool && (first.rule == rule || variant_name(&first.error) == rule) {
        return Ok(());
    }
    let listed = outcome
        .mempool
        .refused
        .iter()
        .any(|finding| names_policy_rule(finding, rule));
    Err(if listed {
        format!(
            "the policy rule {rule} would refuse, but a node does not get to it: the node's \
             answer is {} ({}) at stage {:?}",
            first.rule, first.error, first.stage
        )
    } else {
        format!(
            "the node refuses by {} ({}) at stage {:?}, not by the policy rule {rule}",
            first.rule, first.error, first.stage
        )
    })
}

/// Whether the mempool rule `rule` is among the policy rules that refuse, whatever the
/// node's own answer is: the sense of [`Case::expect_policy_rule_refuses`].
pub fn judge_policy_rule_refuses(outcome: &Outcome, rule: &str) -> Result<(), String> {
    if outcome
        .mempool
        .refused
        .iter()
        .any(|finding| names_policy_rule(finding, rule))
    {
        return Ok(());
    }
    let refused: Vec<&str> = outcome
        .mempool
        .refused
        .iter()
        .map(|finding| finding.function.as_str())
        .collect();
    Err(format!(
        "the policy rule {rule} does not refuse; refusing policy rules: {refused:?}"
    ))
}

/// Whether one input answers as `expected` says.
pub fn judge_input(outcome: &Outcome, input: usize, expected: &Expected) -> Result<(), String> {
    let Some(record) = outcome.inputs.get(input) else {
        return Err(format!(
            "the transaction has no input {input} (it has {})",
            outcome.inputs.len()
        ));
    };
    let Some(run) = record.judged(outcome.scripts.judged) else {
        return Err(format!("input {input} was not run"));
    };
    let what = record.what();
    if expected.pass {
        return if run.ok {
            Ok(())
        } else {
            Err(format!(
                "input {input} [{what}] was expected to pass: {}",
                run.describe()
            ))
        };
    }
    if *expected == Expected::NOTHING {
        return Err(
            "the expectation names neither a rule, an engine error, a label nor a line".to_string(),
        );
    }
    if run.ok {
        return Err(format!(
            "input {input} [{what}] was expected to be refused, it passes"
        ));
    }
    let refusal = run.refusal.as_ref();
    let mut misses = Vec::new();
    if let Some(rule) = &expected.rule
        && run.rule() != Some(rule.as_str())
    {
        misses.push(format!("rule {rule}"));
    }
    if let Some(engine) = &expected.engine
        && run.error_variant() != Some(engine.as_str())
    {
        misses.push(format!("engine error {engine}"));
    }
    if let Some(label) = &expected.refused_by
        && run.refused_by() != Some(label.as_str())
    {
        misses.push(format!("refused by `{label}`"));
    }
    if let Some(at_rule) = &expected.at_rule
        && refusal.and_then(|refusal| refusal.at_rule.as_deref()) != Some(at_rule.as_str())
    {
        misses.push(format!("at the opcode of rule {at_rule}"));
    }
    if let Some(line) = expected.sil_line {
        // A line alone is an expectation about the contract's own code: the refusal must
        // be one the statement can cause, not a budget or a malformed script.
        let caused_by_statement = matches!(
            run.class,
            Some(ErrorClass::ContractRefused | ErrorClass::EngineRefusedData)
        ) || expected.engine.is_some()
            || expected.class.is_some();
        if run.sil_line() != Some(line) || !caused_by_statement {
            misses.push(format!("at source line {line}"));
        }
    }
    if let Some(class) = expected.class
        && run.class != Some(class)
    {
        misses.push(format!("class {class:?}"));
    }
    if misses.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "input {input} [{what}] was expected to be refused with {}; it was: {}",
            misses.join(" and "),
            run.describe()
        ))
    }
}

/// The scripts were run at all, and the two runs agree where they must.
fn judge_runs_made(outcome: &Outcome) -> Result<(), String> {
    if let Some(reason) = &outcome.scripts.not_run {
        return Err(format!("no script was run: {reason}"));
    }
    if outcome.inputs.is_empty() {
        return Err("the transaction has no inputs".to_string());
    }
    if let Some(input) = outcome
        .inputs
        .iter()
        .find(|input| input.judged(outcome.scripts.judged).is_none())
    {
        return Err(format!("input {} was not run", input.index));
    }
    if !outcome.scripts.disagreements.is_empty() {
        return Err(format!(
            "the run under the smallest covering budgets disagrees with the run without a limit: {}",
            outcome.scripts.disagreements.join("; ")
        ));
    }
    Ok(())
}

/// [`Case::expect_accept`] for a case given by its id or as a [`Case`].
pub fn expect_accept(case: impl Into<Case>, scenario: &Scenario) -> Outcome {
    case.into().expect_accept(scenario)
}

/// [`Case::expect_refused`] for a case given by its id or as a [`Case`].
pub fn expect_refused(
    case: impl Into<Case>,
    scenario: &Scenario,
    input: usize,
    expected: impl Into<Expected>,
) -> Outcome {
    case.into().expect_refused(scenario, input, expected)
}

/// [`Case::twin`] for a case given by its id or as a [`Case`].
pub fn twin(
    case: impl Into<Case>,
    honest: &Scenario,
    change: impl FnOnce(&mut Scenario),
    input: usize,
    expected: impl Into<Expected>,
) -> Twin {
    case.into().twin(honest, change, input, expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mutation::{FAST_NOTE, Mode, SKIPPED_NOTE, mutant_family, with_mode},
        outcome::JudgedRun,
        results::capture,
    };
    use kcc20_family::{
        Contract, Family, SourceMap,
        shapes::{self, Profile},
    };
    use serde_json::Value;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    /// An honest transfer of one token coin into one token coin.
    fn honest_transfer() -> Scenario {
        shapes::transfer(&Profile::Script, 1, 1)
    }

    /// One token more, in the call and in the output alike: only the sum rule objects.
    fn one_token_more(scenario: &mut Scenario) {
        scenario.contract_input_mut(0).declared_states_mut()[0].amount += 1;
        scenario
            .contract_output_mut(0)
            .state
            .as_kcc20_mut()
            .unwrap()
            .amount += 1;
    }

    fn inflated_transfer() -> Scenario {
        let mut scenario = honest_transfer();
        one_token_more(&mut scenario);
        scenario
    }

    #[test]
    fn observing_records_a_failed_expectation_and_does_not_panic() {
        let inflated = inflated_transfer();

        // Without the mode a failed expectation is written and then panics.
        let (panicked, lines) = capture::lines(|| {
            catch_unwind(AssertUnwindSafe(|| {
                Case::new("observe/off").expect_accept(&inflated);
            }))
            .is_err()
        });
        assert!(panicked);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["passed"], false);
        assert_eq!(lines[0]["mutation"], Value::Null);

        let observe = Mode {
            observe: true,
            ..Mode::plain()
        };
        let ((refused, accepted), lines) = capture::lines(|| {
            with_mode(observe, || {
                let refused = Case::new("observe/failed").expect_accept(&inflated);
                let accepted = Case::new("observe/held").expect_refused(&inflated, 0, "K-37");
                (refused, accepted)
            })
        });
        assert!(!refused.scripts.accepted && !refused.scripts_only());
        assert_eq!(
            refused.inputs[0].alone.as_ref().unwrap().rule(),
            Some("K-37")
        );
        assert!(refused.inputs[0].committed.is_some(), "a full run");
        assert_eq!(accepted.tx_id, refused.tx_id);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["case"], "observe/failed");
        assert_eq!(lines[0]["passed"], false);
        assert!(
            lines[0]["failure"].as_str().unwrap().contains("is refused"),
            "{}",
            lines[0]["failure"]
        );
        assert_eq!(lines[0]["inputs"][0]["alone"]["refusal"]["rule"], "K-37");
        assert_eq!(lines[0]["mutation"]["observe"], true);
        assert_eq!(lines[0]["mutation"]["judged"], "full");
        assert_eq!(lines[1]["passed"], true);
        assert_eq!(lines[1]["failure"], Value::Null);
    }

    #[test]
    fn a_case_that_is_not_selected_runs_nothing_and_leaves_no_line() {
        let honest = honest_transfer();
        let selected = format!("{}::only/selected", results::binary_name());
        let mode = Mode {
            only_cases: Some([selected].into_iter().collect()),
            ..Mode::plain()
        };
        let other = || Case::new("only/other");
        // Every expectation below is wrong for the honest transfer: a helper that ran its
        // scenario would panic.
        let ((skipped, twins, ran), lines) = capture::lines(|| {
            with_mode(mode, || {
                let skipped = vec![
                    other().expect_refused(&honest, 0, "K-37"),
                    other().expect_inputs(&honest, &[(0, Expected::rule("K-37"))]),
                    other().expect_accept(&inflated_transfer()),
                    other().expect_consensus_accept(&inflated_transfer()),
                    other().expect_consensus_refused(&honest, "NoSuchRule"),
                    other().expect_block_accept(&inflated_transfer()),
                    other().expect_block_refused(&honest, "NoSuchRule"),
                    other().expect_mempool_accept(&inflated_transfer()),
                    other().expect_mempool_refused(&honest, "NoSuchRule"),
                    other().expect_policy_rule_refuses(&honest, "NoSuchRule"),
                ];
                let twins = vec![
                    other().twin(&honest, |_| {}, 0, "K-37"),
                    other().twin_inputs(&honest, one_token_more, &[(0, Expected::pass())]),
                ];
                let ran = Case::new("only/selected").expect_accept(&honest);
                (skipped, twins, ran)
            })
        });
        let twin_sides = twins.iter().flat_map(|twin| [&twin.honest, &twin.changed]);
        for outcome in skipped.iter().chain(twin_sides) {
            assert!(outcome.skipped() && !outcome.scripts_only());
            assert_eq!(outcome.inputs.len(), 1, "the scenario was assembled");
            assert!(outcome.inputs[0].alone.is_none() && outcome.inputs[0].committed.is_none());
            assert_eq!(outcome.scripts.not_run.as_deref(), Some(SKIPPED_NOTE));
            assert!(!outcome.scripts.accepted && !outcome.consensus.accepted);
            assert_eq!(
                outcome.consensus.harness_error.as_deref(),
                Some(SKIPPED_NOTE)
            );
            assert!(
                judge_accept(outcome).is_err(),
                "a placeholder is no acceptance"
            );
        }
        assert_ne!(
            twins[1].honest.tx_id, twins[1].changed.tx_id,
            "the change of a twin is applied to its placeholder"
        );
        assert!(!ran.skipped() && ran.scripts.accepted);
        assert!(
            ran.inputs[0].committed.is_some(),
            "the selected case is a full run"
        );
        assert_eq!(lines.len(), 1, "only the selected case has a line");
        assert_eq!(lines[0]["case"], "only/selected");
        assert_eq!(lines[0]["passed"], true);
        assert_eq!(lines[0]["mutation"]["only_cases"], true);
    }

    #[test]
    fn a_case_that_is_not_selected_can_run_as_in_an_ordinary_run() {
        let honest = honest_transfer();
        let inflated = inflated_transfer();
        let (family, label) = mutant_family(Family::pinned(), "KCC20@2203").unwrap();
        let selected = format!("{}::stand-in/selected", results::binary_name());
        let mode = Mode {
            family: Some(family),
            family_label: Some(label),
            observe: true,
            only_cases: Some([selected].into_iter().collect()),
            unselected_on_pinned: true,
            ..Mode::plain()
        };
        let ((twin, refused, selected), lines) = capture::lines(|| {
            with_mode(mode, || {
                // Both hold on the pinned contracts and fail on this mutant.
                let twin = Case::new("stand-in/twin").twin(
                    &honest,
                    one_token_more,
                    0,
                    Expected::rule("K-37").at_line(175),
                );
                let refused = Case::new("stand-in/refused").expect_refused(&inflated, 0, "K-37");
                let selected = Case::new("stand-in/selected").expect_refused(&inflated, 0, "K-37");
                (twin, refused, selected)
            })
        });
        let pinned = Harness::pinned();
        assert_eq!(twin.honest.tx_id, pinned.run(&honest).tx_id);
        assert_eq!(twin.changed.tx_id, pinned.run(&inflated).tx_id);
        for outcome in [&twin.changed, &refused] {
            assert!(!outcome.skipped() && !outcome.scripts_only());
            assert_eq!(
                outcome.inputs[0].alone.as_ref().unwrap().rule(),
                Some("K-37")
            );
            assert!(outcome.inputs[0].committed.is_some());
        }
        assert!(
            twin.honest.consensus.accepted,
            "a full run on the pinned contracts"
        );
        // The selected case ran on the mutant, where the sum rule is gone.
        assert_ne!(selected.tx_id, refused.tx_id);
        assert!(selected.scripts.accepted);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["case"], "stand-in/selected");
        assert_eq!(lines[0]["passed"], false);
        assert_eq!(lines[0]["mutation"]["family"]["label"], "KCC20@2203");
    }

    #[test]
    fn the_fast_mode_runs_every_input_by_itself_and_judges_the_scripts_only() {
        let honest = honest_transfer();
        let inflated = inflated_transfer();
        let full = Harness::pinned().run(&inflated);
        let fast = || Mode {
            fast: true,
            ..Mode::plain()
        };
        let (twin, lines) = capture::lines(|| {
            with_mode(fast(), || {
                let twin = Case::new("fast/twin").twin(
                    &honest,
                    one_token_more,
                    0,
                    Expected::rule("K-37").at_line(175),
                );
                Case::new("fast/consensus accept").expect_consensus_accept(&honest);
                Case::new("fast/block accept").expect_block_accept(&honest);
                Case::new("fast/mempool accept").expect_mempool_accept(&honest);
                Case::new("fast/consensus refused").expect_consensus_refused(&honest, "NoSuchRule");
                Case::new("fast/block refused").expect_block_refused(&honest, "NoSuchRule");
                Case::new("fast/mempool refused").expect_mempool_refused(&honest, "NoSuchRule");
                Case::new("fast/policy rule").expect_policy_rule_refuses(&honest, "NoSuchRule");
                twin
            })
        });
        for outcome in [&twin.honest, &twin.changed] {
            assert!(outcome.scripts_only() && !outcome.skipped());
            assert!(
                outcome
                    .inputs
                    .iter()
                    .all(|input| input.alone.is_some() && input.committed.is_none())
            );
            assert_eq!(outcome.scripts.judged, JudgedRun::Alone);
            assert_eq!(outcome.scripts.accepted_under_committed_budgets, None);
            assert!(outcome.scripts.disagreements.is_empty());
            assert_eq!(outcome.scripts.not_run, None);
            assert!(
                outcome.minimal_budgets().is_some(),
                "the inputs were measured"
            );
            assert_eq!(outcome.budgets.note.as_deref(), Some(FAST_NOTE));
            assert_eq!(outcome.consensus.harness_error.as_deref(), Some(FAST_NOTE));
            assert!(!outcome.consensus.context_accepted && !outcome.consensus.accepted);
            assert!(!outcome.consensus.block.accepted && !outcome.mempool.accepted);
            assert!(outcome.masses.is_none());
        }
        assert!(twin.honest.scripts.accepted);
        // The one run that is made is the run of the full mode, attribution included.
        assert_eq!(twin.changed.inputs[0].alone, full.inputs[0].alone);
        assert_eq!(
            twin.changed.inputs[0].alone.as_ref().unwrap().rule(),
            Some("K-37")
        );

        assert_eq!(lines.len(), 8);
        for line in &lines {
            assert_eq!(line["passed"], true, "{}", line["case"]);
            assert_eq!(line["mutation"]["fast"], true);
            assert_eq!(line["inputs"][0]["committed"], Value::Null);
            assert_eq!(line["scripts"]["judged"], "alone");
        }
        let judged: Vec<&str> = lines
            .iter()
            .map(|line| line["mutation"]["judged"].as_str().unwrap())
            .collect();
        assert_eq!(
            judged,
            [
                "scripts_only",
                "scripts_only",
                "scripts_only",
                "scripts_only",
                "not_at_all",
                "not_at_all",
                "not_at_all",
                "not_at_all"
            ]
        );

        // A refusal of the scripts is still a refusal: the fast mode skips runs, not judging.
        for attempt in 0..4 {
            let (panicked, lines) = capture::lines(|| {
                with_mode(fast(), || {
                    catch_unwind(AssertUnwindSafe(|| match attempt {
                        0 => drop(Case::new("fast/x").expect_accept(&inflated)),
                        1 => drop(Case::new("fast/x").expect_mempool_accept(&inflated)),
                        2 => drop(Case::new("fast/x").expect_refused(&honest, 0, "K-37")),
                        _ => drop(Case::new("fast/x").twin(&honest, |_| {}, 0, "K-37")),
                    }))
                    .is_err()
                })
            });
            assert!(panicked, "attempt {attempt}");
            assert_eq!(lines[0]["passed"], false, "attempt {attempt}");
        }
    }

    #[test]
    fn a_neutralised_rule_no_longer_refuses() {
        let honest = honest_transfer();
        let inflated = inflated_transfer();

        // Where the sum rule refuses on the pinned contracts.
        let pinned = Harness::pinned().run(&inflated);
        let refusal = pinned.inputs[0]
            .alone
            .as_ref()
            .and_then(|run| run.refusal.clone())
            .expect("the inflated transfer is refused");
        assert_eq!(refusal.rule.as_deref(), Some("K-37"));
        let offset = refusal.byte_offset.expect("a stop inside the contract");
        let rule = SourceMap::pinned()
            .contract(Contract::Kcc20)
            .rule("K-37")
            .expect("the inventory has the sum rule");
        assert!(rule.offsets.contains(&offset));

        let spec = format!("KCC20@{offset}");
        let (family, label) = mutant_family(Family::pinned(), &spec).unwrap();
        let mode = Mode {
            family: Some(family),
            family_label: Some(label),
            observe: true,
            ..Mode::plain()
        };
        let (twin, lines) = capture::lines(|| {
            with_mode(mode, || {
                Case::new("mutant/one token more").twin(&honest, one_token_more, 0, "K-37")
            })
        });
        // The mutant is a contract of its own: other bytes, another hash, other coins.
        assert_ne!(twin.honest.tx_id, Harness::pinned().run(&honest).tx_id);
        assert!(twin.honest.scripts.accepted, "{}", twin.honest.describe());
        assert_eq!(twin.honest.inputs[0].contract.as_deref(), Some("KCC20"));
        assert_eq!(twin.honest.inputs[0].entry.as_deref(), Some("transfer"));
        let changed = twin.changed.inputs[0].alone.as_ref().unwrap();
        // Observed: no other rule of the transfer objects to one token more. The sum rule
        // is the only guard of this case, which is what a mutation run is there to show.
        assert!(changed.ok, "{}", twin.changed.describe());
        assert!(twin.changed.scripts.accepted);
        assert_eq!(
            twin.changed.scripts.accepted_under_committed_budgets,
            Some(true)
        );

        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["mutation"]["family"]["label"], spec.as_str());
        assert_eq!(
            lines[0]["mutation"]["family"]["from"],
            refusal.opcode.unwrap().as_str()
        );
        assert_eq!(
            lines[0]["passed"], false,
            "the expectation named the neutralised rule"
        );
    }
}
