//! From a scenario to an [`Outcome`].
//!
//! [`Harness::run`] assembles the scenario with `kcc20-family` and asks `node-gate` four
//! things about the transaction, in this order:
//!
//! 1. Every input by itself on the script engine, with the node's engine flags and no
//!    budget limit. This is the verdict of a check that judges one input at a time, and
//!    the measurement of what the input costs.
//! 2. The smallest compute budget that covers each input. Those budgets are committed
//!    (unless the harness was told to keep the scenario's own or to use fixed ones). On a
//!    node before Toccata there are no budgets: the scenario's own commitments are kept.
//! 3. The transaction with the committed budgets, submitted to a node: every input again
//!    under its committed limit, the consensus rules, the masses, the mempool policy.
//! 4. The same transaction inside a block, with the calculated storage mass committed: the
//!    consensus rules and the limits of the block.
//!
//! Nothing is mixed: a transaction whose scripts all pass and whose outputs exceed its
//! inputs has an accepting script verdict and a refusing consensus verdict.

use std::borrow::Cow;

use kaspa_consensus_core::{
    mass::ComputeBudget,
    tx::{ComputeCommit, Transaction, UtxoEntry},
};
use kaspa_txscript::script_class::ScriptClass;
use kcc20_family::{
    Family, Scenario,
    scenario::{Assembled, InputInfo, InputKind},
};
use node_gate::{
    GateOptions, GateParams, Mode, ScriptRun, budget, classify_at,
    gate::{self, Evaluation, policy_rule_function},
    policy::Priority,
    verdict::{GateVerdict, PolicyOutcome, Refusal, Stage},
};

use crate::{
    attribution::{attribute, contract_call},
    mutation,
    outcome::{
        BlockVerdict, BudgetReport, BudgetSource, ConsensusVerdict, EngineError, InputOutcome,
        JudgedRun, MempoolVerdict, Outcome, PolicyFinding, RunOutcome, ScriptVerdict,
    },
};

/// Which compute budgets the second run of the inputs is made under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Budgets {
    /// Measure every input and commit the smallest budget that covers it. The `expect_*`
    /// helpers then judge the runs without a limit and require the committed runs to agree.
    Minimal,
    /// Keep the commitments the scenario states (a compute budget of 0 unless the scenario
    /// sets one). The `expect_*` helpers then judge the committed runs.
    AsStated,
    /// Commit exactly these budgets, one per input. The `expect_*` helpers then judge the
    /// committed runs.
    Exactly(Vec<u16>),
}

/// Which storage mass the transaction commits to inside a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageCommitment {
    /// The value the node's calculator gives: what an honest wallet writes.
    Calculated,
    /// The value the scenario states.
    AsStated,
}

/// The fixed surroundings of a run: the contracts, the node, and the budgets.
#[derive(Clone, Debug)]
pub struct Harness {
    /// The contract family the scenario is assembled against.
    pub family: Cow<'static, Family>,
    /// The node: network parameters and DAA score.
    pub node: GateParams,
    /// The budgets of the second run.
    pub budgets: Budgets,
    /// The storage mass commitment of the block evaluation. A submission ignores the
    /// commitment: the node calculates the value itself.
    pub storage_commitment: StorageCommitment,
}

impl Default for Harness {
    fn default() -> Self {
        Self::pinned()
    }
}

impl Harness {
    /// The pinned contracts on testnet-10 parameters well after the Toccata activation, with
    /// the smallest covering budgets.
    ///
    /// In a mutation run ([`crate::mutation`]) the family is the one the environment
    /// names: the pinned contracts with one refusing opcode neutralised, or the contracts
    /// of another artifact.
    pub fn pinned() -> Self {
        Self {
            family: Cow::Borrowed(mutation::family()),
            node: GateParams::testnet10(),
            budgets: Budgets::Minimal,
            storage_commitment: StorageCommitment::Calculated,
        }
    }

    /// The same harness with another contract family, for example one with a replaced
    /// bytecode.
    pub fn with_family(mut self, family: Family) -> Self {
        self.family = Cow::Owned(family);
        self
    }

    /// The same harness with another node.
    pub fn with_node(mut self, node: GateParams) -> Self {
        self.node = node;
        self
    }

    /// The same harness with other budgets for the second run.
    pub fn with_budgets(mut self, budgets: Budgets) -> Self {
        self.budgets = budgets;
        self
    }

    /// The same harness with another storage mass commitment inside a block.
    pub fn with_storage_commitment(mut self, storage_commitment: StorageCommitment) -> Self {
        self.storage_commitment = storage_commitment;
        self
    }

    /// Assembles the scenario and observes the transaction.
    ///
    /// # Panics
    ///
    /// Panics when the scenario cannot be assembled: the codec refuses to produce the
    /// bytes of a typed value. That is a mistake in the scenario, not an answer of the
    /// engine; write such bytes with `kcc20_family::raw` or a parts patch. Use
    /// [`Harness::try_run`] for the error.
    pub fn run(&self, scenario: &Scenario) -> Outcome {
        self.try_run(scenario).unwrap_or_else(|error| {
            panic!("scenario `{}` cannot be assembled: {error}", scenario.name)
        })
    }

    /// Assembles the scenario and observes the transaction, or returns the assembly error.
    pub fn try_run(&self, scenario: &Scenario) -> kcc20_family::Result<Outcome> {
        Ok(self.run_assembled(scenario.assemble(&self.family)?))
    }

    /// Observes a transaction that was assembled (and possibly changed by hand) already.
    ///
    /// # Panics
    ///
    /// Panics when `Budgets::Exactly` does not hold one budget per input.
    pub fn run_assembled(&self, assembled: Assembled) -> Outcome {
        if mutation::mode().fast {
            return self.partial_outcome(assembled, true, mutation::FAST_NOTE);
        }
        let node = &self.node;
        let coins = &assembled.utxos;

        // 1. Every input by itself, without a limit.
        let (alone, not_run) = match budget::measure_inputs(node, &assembled.tx, coins, true) {
            Ok(runs) => (runs, None),
            Err(error) => (Vec::new(), Some(error.to_string())),
        };
        let minimal: Vec<Option<u16>> = if alone.is_empty() {
            vec![None; assembled.tx.inputs.len()]
        } else {
            alone
                .iter()
                .map(|run| run.covering_budget().map(|budget| budget.0))
                .collect()
        };

        // 2. The budgets of the second run.
        let mut committed_tx = assembled.tx.clone();
        let (source, note) = self.commit_budgets(&mut committed_tx, &minimal);
        let judged = if source == BudgetSource::Minimal {
            JudgedRun::Alone
        } else {
            JudgedRun::Committed
        };

        // 3. Submitted to a node. The gate writes the calculated storage mass into the
        //    transaction, as a node does.
        let submit_options = GateOptions {
            mode: Mode::Submit,
            priority: Priority::High,
            measure_budgets: false,
            locate_stops: true,
        };
        let submit = gate::evaluate(node, &committed_tx, coins, submit_options);

        // 4. Inside a block.
        let block_tx = committed_tx.clone();
        let calculated_storage_mass = submit
            .verdict
            .masses
            .as_ref()
            .and_then(|masses| masses.calculated_storage_mass);
        match (self.storage_commitment, calculated_storage_mass) {
            (StorageCommitment::Calculated, Some(storage_mass)) => {
                block_tx.set_storage_mass(storage_mass)
            }
            _ => block_tx.set_storage_mass(assembled.tx.storage_mass()),
        }
        let block_options = GateOptions {
            mode: Mode::Block,
            priority: Priority::High,
            measure_budgets: false,
            locate_stops: false,
        };
        let block = gate::evaluate(node, &block_tx, coins, block_options);

        let inputs: Vec<InputOutcome> = assembled
            .inputs
            .iter()
            .enumerate()
            .map(|(index, info)| {
                self.input_outcome(
                    index,
                    info,
                    &committed_tx,
                    &coins[index],
                    alone.get(index),
                    minimal[index],
                    submit.committed_runs.get(index),
                )
            })
            .collect();

        let scripts = script_verdict(&inputs, not_run, &source, judged);
        let budgets = BudgetReport {
            source,
            minimal,
            committed: committed_tx
                .inputs
                .iter()
                .map(|input| input.compute_commit.into())
                .collect(),
            note,
        };
        let consensus = consensus_verdict(&submit, &block, block_tx.storage_mass());
        let mempool = mempool_verdict(&submit);

        Outcome {
            scenario: assembled.name.clone(),
            tx_id: committed_tx.id().to_string(),
            network: submit.verdict.network.clone(),
            inputs,
            scripts,
            budgets,
            masses: submit.verdict.masses.clone(),
            consensus,
            mempool,
            assembled,
            committed_tx,
            submit,
            block,
        }
    }

    /// The placeholder outcome of a case the mutation mode does not run: the scenario is
    /// assembled, no script is run and no rule is evaluated ([`Outcome::skipped`]).
    ///
    /// # Panics
    ///
    /// Panics when the scenario cannot be assembled, as [`Harness::run`] does.
    pub(crate) fn skipped(&self, scenario: &Scenario) -> Outcome {
        let assembled = scenario.assemble(&self.family).unwrap_or_else(|error| {
            panic!("scenario `{}` cannot be assembled: {error}", scenario.name)
        });
        self.partial_outcome(assembled, false, mutation::SKIPPED_NOTE)
    }

    /// An outcome without the second run and without the two evaluations of a node: every
    /// input by itself with no budget limit when `run_scripts` is set, nothing otherwise.
    /// `note` says why, in `budgets.note`, in `consensus.harness_error` and as the refusal
    /// of the mempool verdict; none of the three is an answer of a node.
    fn partial_outcome(&self, assembled: Assembled, run_scripts: bool, note: &str) -> Outcome {
        let node = &self.node;
        let coins = &assembled.utxos;
        let (alone, not_run) = if run_scripts {
            match budget::measure_inputs(node, &assembled.tx, coins, true) {
                Ok(runs) => (runs, None),
                Err(error) => (Vec::new(), Some(error.to_string())),
            }
        } else {
            (Vec::new(), Some(note.to_string()))
        };
        let minimal: Vec<Option<u16>> = if alone.is_empty() {
            vec![None; assembled.tx.inputs.len()]
        } else {
            alone
                .iter()
                .map(|run| run.covering_budget().map(|budget| budget.0))
                .collect()
        };

        // No budget is committed: the transaction stays as the scenario assembled it.
        let committed_tx = assembled.tx.clone();
        let submit = not_evaluated(node, &committed_tx, Mode::Submit, note);
        let block = not_evaluated(node, &committed_tx, Mode::Block, note);
        let inputs: Vec<InputOutcome> = assembled
            .inputs
            .iter()
            .enumerate()
            .map(|(index, info)| {
                self.input_outcome(
                    index,
                    info,
                    &committed_tx,
                    &coins[index],
                    alone.get(index),
                    minimal[index],
                    None,
                )
            })
            .collect();

        let source = BudgetSource::AsStated;
        let scripts = script_verdict(&inputs, not_run, &source, JudgedRun::Alone);
        let budgets = BudgetReport {
            source,
            minimal,
            committed: committed_tx
                .inputs
                .iter()
                .map(|input| input.compute_commit.into())
                .collect(),
            note: Some(note.to_string()),
        };
        let consensus = consensus_verdict(&submit, &block, committed_tx.storage_mass());
        let mempool = mempool_verdict(&submit);

        Outcome {
            scenario: assembled.name.clone(),
            tx_id: committed_tx.id().to_string(),
            network: submit.verdict.network.clone(),
            inputs,
            scripts,
            budgets,
            masses: None,
            consensus,
            mempool,
            assembled,
            committed_tx,
            submit,
            block,
        }
    }

    /// Writes the budgets of the second run into `tx` and says where they came from.
    fn commit_budgets(
        &self,
        tx: &mut Transaction,
        minimal: &[Option<u16>],
    ) -> (BudgetSource, Option<String>) {
        let budgets: Vec<u16> = match &self.budgets {
            Budgets::AsStated => return (BudgetSource::AsStated, None),
            Budgets::Exactly(budgets) => {
                assert_eq!(
                    budgets.len(),
                    tx.inputs.len(),
                    "Budgets::Exactly needs one budget per input"
                );
                budgets.clone()
            }
            Budgets::Minimal => {
                if !self.node.toccata_active() {
                    let note = "before Toccata the engine counts signature operations and meters no script units: there is no budget to measure";
                    return (BudgetSource::AsStated, Some(note.to_string()));
                }
                if !ComputeCommit::version_expects_compute_budget_field(tx.version) {
                    let note = format!(
                        "a version {} transaction commits signature operation counts, not budgets",
                        tx.version
                    );
                    return (BudgetSource::AsStated, Some(note));
                }
                match minimal.iter().copied().collect::<Option<Vec<u16>>>() {
                    Some(budgets) => budgets,
                    None => {
                        let note = "the inputs could not be measured, or one of them needs more than the largest budget";
                        return (BudgetSource::AsStated, Some(note.to_string()));
                    }
                }
            }
        };
        let source = if self.budgets == Budgets::Minimal {
            BudgetSource::Minimal
        } else {
            BudgetSource::Exactly
        };
        for (input, budget) in tx.inputs.iter_mut().zip(budgets) {
            input.compute_commit = ComputeBudget(budget).into();
        }
        // Neither the id nor any signature hash of a version 1 transaction covers the
        // budgets (rusty-kaspa a41a333 consensus/core/src/hashing/tx.rs:99-115,
        // hashing/sighash.rs:245-280); the id is recomputed all the same.
        tx.finalize();
        (source, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn input_outcome(
        &self,
        index: usize,
        info: &InputInfo,
        committed_tx: &Transaction,
        coin: &UtxoEntry,
        alone: Option<&ScriptRun>,
        minimal_budget: Option<u16>,
        committed: Option<&ScriptRun>,
    ) -> InputOutcome {
        let input = &committed_tx.inputs[index];
        // What the scenario says the input is.
        let (kind, stated_contract, stated_entry) = match &info.kind {
            InputKind::Contract {
                contract, entry, ..
            } => (
                "contract",
                Some(contract.name().to_string()),
                entry.map(|entry| entry.name().to_string()),
            ),
            InputKind::Ordinary => ("ordinary", None, None),
        };
        // What its bytes make the engine run.
        let ran = contract_call(
            &self.family,
            &input.signature_script,
            coin.script_public_key.script(),
        );
        let run_outcome = |run: &ScriptRun| self.run_outcome(run, &input.signature_script, coin);
        InputOutcome {
            index,
            label: info.label.clone(),
            kind: kind.to_string(),
            contract: ran.map(|(contract, _)| contract.name().to_string()),
            entry: ran.and_then(|(_, entry)| entry.map(|entry| entry.name().to_string())),
            stated_contract,
            stated_entry,
            spent_script_class: ScriptClass::from_script(&coin.script_public_key),
            signature_script_len: input.signature_script.len(),
            alone: alone.map(run_outcome),
            minimal_budget,
            commitment: input.compute_commit.into(),
            committed: committed.map(run_outcome),
        }
    }

    /// The plain-data form of one run, with the refusal attributed.
    fn run_outcome(
        &self,
        run: &ScriptRun,
        signature_script: &[u8],
        coin: &UtxoEntry,
    ) -> RunOutcome {
        let spent_script = coin.script_public_key.script();
        let spent_is_p2sh = ScriptClass::is_pay_to_script_hash(spent_script);
        let class = run
            .error()
            .map(|error| classify_at(error, run.stop.as_ref(), spent_is_p2sh));
        let refusal = match (run.error(), class, run.stop.as_ref()) {
            (Some(error), Some(class), Some(stop)) => Some(attribute(
                &self.family,
                signature_script,
                spent_script,
                error,
                class,
                stop,
            )),
            _ => None,
        };
        RunOutcome {
            ok: run.is_ok(),
            script_units_limit: run.script_units_limit.filter(|limit| *limit != u64::MAX),
            sig_op_limit: run.sig_op_limit,
            used_script_units: run.used_script_units,
            used_sig_ops: run.used_sig_ops,
            accepted_unknown_version: run.accepted_unknown_version,
            error: run.error().map(EngineError::of),
            class,
            stop: run.stop.clone(),
            refusal,
        }
    }
}

/// The evaluation of a question that was not put to a node: no rule was checked and no
/// script was run, and `reason` says why. It has the form `node-gate` gives a question it
/// cannot put (`harness_error`), so nothing in it reads as a node's answer.
fn not_evaluated(node: &GateParams, tx: &Transaction, mode: Mode, reason: &str) -> Evaluation {
    let refusal = Refusal {
        stage: Stage::Harness,
        rule: "harness".to_string(),
        error: reason.to_string(),
        message: reason.to_string(),
        input: None,
    };
    let verdict = GateVerdict {
        mode,
        network: node.params.network_name(),
        pov_daa_score: node.pov_daa_score,
        block_daa_score: node.block_daa_score,
        toccata_active: node.toccata_active(),
        tx_id: tx.id().to_string(),
        accepted: false,
        first_refusal: Some(refusal),
        consensus_accepted: false,
        stage_reached: Stage::Harness,
        consensus_refusal: None,
        fee: None,
        masses: None,
        inputs: Vec::new(),
        policy: None,
        harness_error: Some(reason.to_string()),
    };
    Evaluation {
        verdict,
        pre_mass_error: None,
        consensus_error: None,
        block_mass_error: None,
        policy_refusal: None,
        committed_runs: Vec::new(),
        measured_runs: Vec::new(),
    }
}

/// The whole-transaction answer of the scripts, and whether the two runs agree.
fn script_verdict(
    inputs: &[InputOutcome],
    not_run: Option<String>,
    source: &BudgetSource,
    judged: JudgedRun,
) -> ScriptVerdict {
    type Pick = fn(&InputOutcome) -> Option<&RunOutcome>;
    fn alone_run(input: &InputOutcome) -> Option<&RunOutcome> {
        input.alone.as_ref()
    }
    fn committed_run(input: &InputOutcome) -> Option<&RunOutcome> {
        input.committed.as_ref()
    }
    let refused = |pick: Pick| -> Vec<usize> {
        inputs
            .iter()
            .filter(|input| pick(input).is_some_and(|run| !run.ok))
            .map(|input| input.index)
            .collect()
    };
    let all_ran =
        |pick: Pick| !inputs.is_empty() && inputs.iter().all(|input| pick(input).is_some());

    let refused_inputs = refused(alone_run);
    let refused_inputs_under_committed_budgets = refused(committed_run);

    // With the smallest covering budgets the committed run repeats the run without a
    // limit: the same answer, the same units, the same stop.
    let mut disagreements = Vec::new();
    if *source == BudgetSource::Minimal {
        for input in inputs {
            let (Some(alone), Some(committed)) = (&input.alone, &input.committed) else {
                if input.alone.is_some() != input.committed.is_some() {
                    disagreements.push(format!(
                        "input {}: only one of the two runs was made",
                        input.index
                    ));
                }
                continue;
            };
            if alone.ok != committed.ok || alone.error != committed.error {
                disagreements.push(format!(
                    "input {}: without a limit {}, under {:?} {}",
                    input.index,
                    alone.describe(),
                    input.commitment,
                    committed.describe()
                ));
            } else if alone.used_script_units != committed.used_script_units {
                disagreements.push(format!(
                    "input {}: {} script units without a limit, {} under {:?}",
                    input.index,
                    alone.used_script_units,
                    committed.used_script_units,
                    input.commitment
                ));
            } else if alone.stop != committed.stop {
                disagreements.push(format!(
                    "input {}: the same error at another place: {:?} without a limit, {:?} under {:?}",
                    input.index, alone.stop, committed.stop, input.commitment
                ));
            }
        }
    }

    ScriptVerdict {
        accepted: all_ran(alone_run) && refused_inputs.is_empty(),
        refused_inputs,
        accepted_under_committed_budgets: all_ran(committed_run)
            .then_some(refused_inputs_under_committed_budgets.is_empty()),
        refused_inputs_under_committed_budgets,
        not_run,
        disagreements,
        judged,
    }
}

/// The consensus rules around the scripts, from the two evaluations.
fn consensus_verdict(
    submit: &Evaluation,
    block: &Evaluation,
    block_storage_mass: u64,
) -> ConsensusVerdict {
    let verdict = &submit.verdict;
    let context_accepted = matches!(verdict.stage_reached, Stage::Scripts | Stage::Accepted);
    ConsensusVerdict {
        context_accepted,
        context_refusal: if context_accepted {
            None
        } else {
            verdict
                .consensus_refusal
                .clone()
                .or_else(|| verdict.first_refusal.clone())
        },
        stage_reached: verdict.stage_reached,
        accepted: verdict.consensus_accepted,
        refusal: verdict.consensus_refusal.clone(),
        fee: verdict.fee,
        block: BlockVerdict {
            accepted: block.verdict.accepted,
            stage_reached: block.verdict.stage_reached,
            refusal: block.verdict.first_refusal.clone(),
            committed_storage_mass: block_storage_mass,
        },
        harness_error: verdict
            .harness_error
            .clone()
            .or_else(|| block.verdict.harness_error.clone()),
    }
}

/// The mempool's answer, rule by rule.
fn mempool_verdict(submit: &Evaluation) -> MempoolVerdict {
    let verdict = &submit.verdict;
    let policy = verdict.policy.as_ref();
    let mut refused = Vec::new();
    let mut not_evaluated = Vec::new();
    for check in policy
        .map(|policy| policy.checks.as_slice())
        .unwrap_or_default()
    {
        match &check.outcome {
            PolicyOutcome::Passed => {}
            PolicyOutcome::Refused(refusal) => refused.push(PolicyFinding {
                rule: check.rule,
                function: policy_rule_function(check.rule).to_string(),
                refusal: refusal.clone(),
                message: refusal.to_string(),
            }),
            PolicyOutcome::NotEvaluated => not_evaluated.push(check.rule),
        }
    }
    MempoolVerdict {
        accepted: verdict.accepted,
        first_refusal: verdict.first_refusal.clone(),
        policy_accepted: policy.is_some_and(|policy| policy.accepted),
        refused,
        not_evaluated,
        fee: verdict.fee,
        minimum_fee: policy.and_then(|policy| policy.minimum_fee),
        fee_mass: policy.and_then(|policy| policy.fee_mass),
        p2sh_sig_ops: policy
            .map(|policy| policy.p2sh_sig_ops.clone())
            .unwrap_or_default(),
    }
}

/// Assembles the scenario against the pinned contracts and observes the transaction on
/// testnet-10 parameters, with the smallest covering budgets committed.
///
/// # Panics
///
/// Panics when the scenario cannot be assembled; see [`Harness::run`].
pub fn run(scenario: &Scenario) -> Outcome {
    Harness::pinned().run(scenario)
}

#[cfg(test)]
mod tests {
    use super::*;
    use node_gate::verdict::Commitment;

    fn passing(used_script_units: u64) -> RunOutcome {
        RunOutcome {
            ok: true,
            script_units_limit: None,
            sig_op_limit: None,
            used_script_units,
            used_sig_ops: 0,
            accepted_unknown_version: false,
            error: None,
            class: None,
            stop: None,
            refusal: None,
        }
    }

    fn refused(variant: &str, stop: node_gate::StopPoint) -> RunOutcome {
        RunOutcome {
            ok: false,
            error: Some(EngineError {
                variant: variant.to_string(),
                debug: variant.to_string(),
                message: variant.to_string(),
            }),
            stop: Some(stop),
            ..passing(100)
        }
    }

    fn input(
        index: usize,
        alone: Option<RunOutcome>,
        committed: Option<RunOutcome>,
    ) -> InputOutcome {
        InputOutcome {
            index,
            label: String::new(),
            kind: "ordinary".to_string(),
            contract: None,
            entry: None,
            stated_contract: None,
            stated_entry: None,
            spent_script_class: ScriptClass::NonStandard,
            signature_script_len: 0,
            alone,
            minimal_budget: Some(0),
            commitment: Commitment::ComputeBudget(0),
            committed,
        }
    }

    fn verdict(inputs: &[InputOutcome], source: BudgetSource) -> ScriptVerdict {
        let judged = if source == BudgetSource::Minimal {
            JudgedRun::Alone
        } else {
            JudgedRun::Committed
        };
        script_verdict(inputs, None, &source, judged)
    }

    #[test]
    fn two_equal_runs_agree() {
        let inputs = [
            input(0, Some(passing(7)), Some(passing(7))),
            input(1, Some(passing(9)), Some(passing(9))),
        ];
        let verdict = verdict(&inputs, BudgetSource::Minimal);
        assert!(verdict.accepted);
        assert_eq!(verdict.accepted_under_committed_budgets, Some(true));
        assert!(verdict.refused_inputs.is_empty());
        assert!(verdict.disagreements.is_empty());
    }

    #[test]
    fn every_kind_of_difference_between_the_two_runs_is_listed() {
        let final_stack = node_gate::StopPoint::FinalStack;
        let hash_mismatch = node_gate::StopPoint::P2shHashMismatch;
        let inputs = [
            // Another answer.
            input(
                0,
                Some(passing(7)),
                Some(refused("EvalFalse", final_stack.clone())),
            ),
            // The same answer at another cost.
            input(1, Some(passing(7)), Some(passing(8))),
            // The same error at another place.
            input(
                2,
                Some(refused("EvalFalse", final_stack.clone())),
                Some(refused("EvalFalse", hash_mismatch)),
            ),
            // Another error.
            input(
                3,
                Some(refused("EvalFalse", final_stack.clone())),
                Some(refused("VerifyError", final_stack.clone())),
            ),
            // Only one of the two runs.
            input(4, Some(passing(7)), None),
            // No difference.
            input(
                5,
                Some(refused("EvalFalse", final_stack.clone())),
                Some(refused("EvalFalse", final_stack)),
            ),
        ];
        let minimal = verdict(&inputs, BudgetSource::Minimal);
        assert_eq!(
            minimal.disagreements.len(),
            5,
            "{:?}",
            minimal.disagreements
        );
        for (index, text) in minimal.disagreements.iter().enumerate() {
            assert!(text.starts_with(&format!("input {index}:")), "{text}");
        }
        assert_eq!(minimal.refused_inputs, vec![2, 3, 5]);
        assert_eq!(
            minimal.refused_inputs_under_committed_budgets,
            vec![0, 2, 3, 5]
        );
        assert!(!minimal.accepted);
        assert_eq!(
            minimal.accepted_under_committed_budgets, None,
            "input 4 was not run under a budget"
        );

        // With budgets the caller fixed, a difference is the point of the run.
        let fixed = verdict(&inputs, BudgetSource::Exactly);
        assert!(fixed.disagreements.is_empty());
        assert_eq!(fixed.judged, JudgedRun::Committed);
    }

    #[test]
    fn a_transaction_without_runs_is_not_accepted() {
        let nothing = script_verdict(
            &[input(0, None, None)],
            Some("the covenant bindings are inconsistent".to_string()),
            &BudgetSource::AsStated,
            JudgedRun::Committed,
        );
        assert!(!nothing.accepted);
        assert_eq!(nothing.accepted_under_committed_budgets, None);
        assert!(nothing.not_run.is_some());

        let empty = verdict(&[], BudgetSource::Minimal);
        assert!(!empty.accepted, "no inputs, nothing accepted");
    }
}
