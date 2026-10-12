//! What the harness observed about one transaction.
//!
//! An [`Outcome`] keeps four answers apart, because they come from different rules and a
//! check must be able to speak about one without the others:
//!
//! 1. [`Outcome::inputs`] and [`Outcome::scripts`]: the script engine alone. Every input is
//!    run by itself with no budget limit, then again under the committed budgets.
//! 2. [`Outcome::budgets`] and [`Outcome::masses`]: what the scripts cost.
//! 3. [`Outcome::consensus`]: the consensus rules around the scripts (amounts, lock times,
//!    covenant bindings, block limits).
//! 4. [`Outcome::mempool`]: the policy of a default node's mempool.
//!
//! Everything that is serialized here is part of the result file format described in the
//! README of this crate. Field names are stable; new fields may be added.

use kaspa_consensus_core::tx::Transaction;
use kaspa_txscript::script_class::ScriptClass;
use kaspa_txscript_errors::TxScriptError;
use kcc20_family::scenario::Assembled;
use node_gate::{
    ErrorClass, StopPoint,
    gate::Evaluation,
    mass::MassReport,
    policy::{PolicyRefusal, PolicyRule},
    verdict::{Commitment, Refusal, Stage},
};
use serde::Serialize;

use crate::{attribution::Attribution, mutation};

/// An error of the script engine in three forms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EngineError {
    /// Name of the `TxScriptError` variant without its fields: `VerifyError`,
    /// `NumberTooBig`, `ExceededCommittedScriptUnits`.
    pub variant: String,
    /// Debug text of the error value: the variant with its fields.
    pub debug: String,
    /// Display text of the error, as a node prints it.
    pub message: String,
}

impl EngineError {
    /// The three forms of `error`.
    pub fn of(error: &TxScriptError) -> Self {
        let debug = format!("{error:?}");
        Self {
            variant: variant_name(&debug),
            debug,
            message: error.to_string(),
        }
    }
}

/// The leading identifier of a debug text: the name of an enum variant without its fields.
pub fn variant_name(debug: &str) -> String {
    debug
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// One run of one input on the script engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RunOutcome {
    /// The engine accepted the input.
    pub ok: bool,
    /// The limit the engine was given, in script units; `None` for a run without a limit,
    /// and for every run on a node before Toccata, where the engine meters no script units.
    pub script_units_limit: Option<u64>,
    /// On a node before Toccata: the number of signature operations the engine allowed the
    /// run, 255 for the run without a limit. `None` after Toccata.
    pub sig_op_limit: Option<u8>,
    /// Script units consumed. After a budget failure: the amount consumed before the charge
    /// that did not fit.
    pub used_script_units: u64,
    /// Signature checks that were charged.
    pub used_sig_ops: u16,
    /// The coin has a script version the engine does not know, so the input was accepted
    /// without running anything. Such a pass proves nothing about a script.
    pub accepted_unknown_version: bool,
    /// The engine's error, when it refused.
    pub error: Option<EngineError>,
    /// Why the engine refused, as one of six classes of cause.
    pub class: Option<ErrorClass>,
    /// Where the engine stopped.
    pub stop: Option<StopPoint>,
    /// What refused: the rule of a contract, or the part of the engine's own checks.
    pub refusal: Option<Attribution>,
}

impl RunOutcome {
    /// The variant name of the engine's error, when the run was refused.
    pub fn error_variant(&self) -> Option<&str> {
        self.error.as_ref().map(|error| error.variant.as_str())
    }

    /// The short name of what refused: a rule id, `engine: <Variant>`, `prologue`,
    /// `dispatcher`, `P2SH wrapper`, `final stack`.
    pub fn refused_by(&self) -> Option<&str> {
        self.refusal
            .as_ref()
            .map(|refusal| refusal.refused_by.as_str())
    }

    /// The id of the contract rule that refused, when one did.
    pub fn rule(&self) -> Option<&str> {
        self.refusal
            .as_ref()
            .and_then(|refusal| refusal.rule.as_deref())
    }

    /// The first line of the source statement the engine stopped in, when it stopped in
    /// a statement of a contract.
    pub fn sil_line(&self) -> Option<u32> {
        self.refusal
            .as_ref()
            .and_then(|refusal| refusal.sil.as_ref())
            .map(|sil| sil.line)
    }

    /// One line for a failure message.
    pub fn describe(&self) -> String {
        if self.ok {
            return format!("ok, {} script units", self.used_script_units);
        }
        let error = self
            .error
            .as_ref()
            .map(|error| error.debug.as_str())
            .unwrap_or("?");
        let class = self
            .class
            .map(|class| format!("{class:?}"))
            .unwrap_or_default();
        let refusal = self
            .refusal
            .as_ref()
            .map(Attribution::describe)
            .unwrap_or_else(|| "position not located".to_string());
        format!(
            "REFUSED {error} [{class}] by {refusal}; {} script units",
            self.used_script_units
        )
    }
}

/// Everything observed about one input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InputOutcome {
    /// Index of the input in the transaction.
    pub index: usize,
    /// The label the scenario gives the input.
    pub label: String,
    /// `contract` for a coin of one of the three contracts (as the scenario describes it),
    /// `ordinary` for any other coin.
    pub kind: String,
    /// The contract whose script the input makes the engine run, read from the bytes of
    /// the input ([`crate::attribution::contract_call`]): the coin is locked to the hash
    /// of the script the call pushes, and that script has the frame of the contract.
    /// `None` when the bytes run no contract script, whatever the scenario says.
    pub contract: Option<String>,
    /// The entry the call selects in that script: the one whose dispatch tag the call
    /// pushes in front of the script. Read from the bytes as well.
    pub entry: Option<String>,
    /// The contract of the coin as the scenario describes it: by the state it gives the
    /// coin. A description, not an observation; an override of the lock or of the
    /// signature script makes it differ from `contract`.
    pub stated_contract: Option<String>,
    /// The entry the typed call of the scenario names; `None` for a raw call.
    pub stated_entry: Option<String>,
    /// Standard class of the spent coin's script.
    pub spent_script_class: ScriptClass,
    /// Length of the signature script in bytes.
    pub signature_script_len: usize,
    /// The input run by itself with no budget limit and the node's engine flags. `None`
    /// when no script could be run at all (see [`ScriptVerdict::not_run`]).
    pub alone: Option<RunOutcome>,
    /// The smallest compute budget that covers the run without a limit.
    pub minimal_budget: Option<u16>,
    /// The compute commitment the input carried in the second run.
    pub commitment: Commitment,
    /// The input run under that commitment, as a node runs it.
    pub committed: Option<RunOutcome>,
}

impl InputOutcome {
    /// The run a check judges: under the committed budgets when the harness was given
    /// budgets to commit, otherwise the run without a limit.
    pub fn judged(&self, judged: JudgedRun) -> Option<&RunOutcome> {
        match judged {
            JudgedRun::Alone => self.alone.as_ref(),
            JudgedRun::Committed => self.committed.as_ref(),
        }
    }

    /// What the bytes of the input run, in a phrase: `KCC20.transfer`; `KCC20, no entry
    /// selected` for a contract script whose call carries the tag of none of its entries;
    /// `ordinary` for a coin that runs no contract script. When the scenario describes
    /// the input differently, the description follows in brackets.
    pub fn what(&self) -> String {
        let runs = match (&self.contract, &self.entry) {
            (Some(contract), Some(entry)) => format!("{contract}.{entry}"),
            (Some(contract), None) => format!("{contract}, no entry selected"),
            _ => "ordinary".to_string(),
        };
        if self.runs_what_is_stated() {
            return runs;
        }
        let stated = match (&self.stated_contract, &self.stated_entry) {
            (Some(contract), Some(entry)) => format!("{contract}.{entry}"),
            (Some(contract), None) => format!("{contract}, a raw call"),
            _ => "ordinary".to_string(),
        };
        format!("{runs} (the scenario says {stated})")
    }

    /// Whether the bytes run what the scenario says: the same contract, and the entry of a
    /// typed call. The scenario names no entry for a raw call; nothing is compared then.
    pub fn runs_what_is_stated(&self) -> bool {
        self.contract == self.stated_contract
            && (self.stated_entry.is_none() || self.entry == self.stated_entry)
    }
}

/// Which of the two runs of every input a check judges.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgedRun {
    /// Every input by itself with no budget limit. The run under the smallest covering
    /// budgets must agree with it.
    Alone,
    /// Every input under the budgets the caller fixed: the node's own run.
    Committed,
}

/// The answer of the script engine for the whole transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScriptVerdict {
    /// Every input passes by itself with no budget limit.
    pub accepted: bool,
    /// The inputs that are refused by themselves, in input order.
    pub refused_inputs: Vec<usize>,
    /// Every input passes under its committed budget. `None` when that run was not made.
    pub accepted_under_committed_budgets: Option<bool>,
    /// The inputs that are refused under their committed budget.
    pub refused_inputs_under_committed_budgets: Vec<usize>,
    /// Why no script was run, when none was: the covenant bindings of the transaction are
    /// inconsistent, so a node refuses it before it builds an engine.
    pub not_run: Option<String>,
    /// Differences between the two runs that the budgets do not explain. With the smallest
    /// covering budgets committed the two runs must be equal; anything listed here is a
    /// finding and makes every helper that judges scripts fail (`expect_accept`,
    /// `expect_refused`, `expect_inputs`, the twins, and the three `expect_*_accept`
    /// helpers). The helpers that ask for a refusal by a consensus, block or mempool rule
    /// do not look at the scripts.
    pub disagreements: Vec<String>,
    /// Which run the `expect_*` helpers judge for this outcome.
    pub judged: JudgedRun,
}

/// Where the committed budgets came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetSource {
    /// Measured: the smallest budget that covers each input's run without a limit.
    Minimal,
    /// The commitments the scenario itself states.
    AsStated,
    /// Budgets the caller fixed.
    Exactly,
}

/// The compute budgets of the transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BudgetReport {
    /// Where the committed budgets came from.
    pub source: BudgetSource,
    /// The smallest covering budget of every input, in input order. For a refused input it
    /// covers the units used up to the refusal.
    pub minimal: Vec<Option<u16>>,
    /// The commitment every input carried in the second run.
    pub committed: Vec<Commitment>,
    /// Set when the measured budgets could not be committed and the scenario's own
    /// commitments were kept (a version 0 transaction, or an input no budget covers).
    pub note: Option<String>,
}

/// The transaction inside a block: consensus rules and the limits of the block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BlockVerdict {
    /// A block that holds this transaction is valid as far as this transaction decides.
    pub accepted: bool,
    /// The last step that was entered.
    pub stage_reached: Stage,
    /// The refusal, when there is one.
    pub refusal: Option<Refusal>,
    /// The storage mass the transaction committed to in this evaluation.
    pub committed_storage_mass: u64,
}

/// The consensus rules of a node, apart from what the scripts say.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConsensusVerdict {
    /// Every consensus rule a node checks before it runs the scripts of a submitted
    /// transaction passed: the rules in isolation, lock time, coins, amounts, sequence
    /// locks, covenant bindings.
    pub context_accepted: bool,
    /// The refusal of one of those rules.
    pub context_refusal: Option<Refusal>,
    /// The last step of the consensus validation of the submission that was entered.
    pub stage_reached: Stage,
    /// The consensus rules of a submission accept the transaction: the context and the
    /// scripts under the committed budgets. Storage mass is not limited at this point; the
    /// block verdict and the mempool verdict limit it.
    pub accepted: bool,
    /// The first consensus refusal of the submission, scripts included.
    pub refusal: Option<Refusal>,
    /// Spent amounts minus output values, when both sums are valid.
    pub fee: Option<u64>,
    /// The same transaction inside a block.
    pub block: BlockVerdict,
    /// Set when the question could not be put to a node at all (a coin of zero sompi, for
    /// example). Nothing else in this verdict is then an answer.
    pub harness_error: Option<String>,
}

/// One mempool rule that refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PolicyFinding {
    /// The rule.
    pub rule: PolicyRule,
    /// The name of the function that implements it (`check_minimum_relay_fee`).
    pub function: String,
    /// The refusal with its numbers.
    pub refusal: PolicyRefusal,
    /// The refusal as a node words it.
    pub message: String,
}

/// What a default node says to the transaction when it is submitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MempoolVerdict {
    /// The node takes the transaction into its mempool: consensus rules, scripts under the
    /// committed budgets, and every policy rule.
    pub accepted: bool,
    /// The first refusal in the order a node checks.
    pub first_refusal: Option<Refusal>,
    /// Every policy rule passed. Independent of the consensus answer.
    pub policy_accepted: bool,
    /// Every policy rule that refused, in the node's order. A node stops at the first; the
    /// list shows all reasons.
    pub refused: Vec<PolicyFinding>,
    /// Policy rules that could not be evaluated because an earlier step failed.
    pub not_evaluated: Vec<PolicyRule>,
    /// The fee the transaction pays.
    pub fee: Option<u64>,
    /// The smallest fee the mempool accepts for this transaction.
    pub minimum_fee: Option<u64>,
    /// The mass that floor is charged on.
    pub fee_mass: Option<u64>,
    /// Signature operations the node's static scanner counts in the redeem script of every
    /// pay-to-script-hash input (`None` for other inputs).
    pub p2sh_sig_ops: Vec<Option<u64>>,
}

/// Everything the harness observed about one transaction.
#[derive(Clone, Debug, Serialize)]
pub struct Outcome {
    /// Name of the scenario.
    pub scenario: String,
    /// Transaction id.
    pub tx_id: String,
    /// Network whose parameters were used.
    pub network: String,
    /// One record per input.
    pub inputs: Vec<InputOutcome>,
    /// The script engine's answer for the whole transaction.
    pub scripts: ScriptVerdict,
    /// Compute budgets.
    pub budgets: BudgetReport,
    /// Sizes and masses under the committed budgets. `None` when they are undefined.
    pub masses: Option<MassReport>,
    /// Consensus rules apart from the scripts.
    pub consensus: ConsensusVerdict,
    /// Mempool policy.
    pub mempool: MempoolVerdict,
    /// The transaction as the scenario assembled it, with the scenario's own budgets.
    #[serde(skip)]
    pub assembled: Assembled,
    /// The transaction with the committed budgets, as it was submitted.
    #[serde(skip)]
    pub committed_tx: Transaction,
    /// The full evaluation of the submission.
    #[serde(skip)]
    pub submit: Evaluation,
    /// The full evaluation inside a block.
    #[serde(skip)]
    pub block: Evaluation,
}

impl Outcome {
    /// The run of input `index` that the `expect_*` helpers judge.
    pub fn judged_input(&self, index: usize) -> Option<&RunOutcome> {
        self.inputs
            .get(index)
            .and_then(|input| input.judged(self.scripts.judged))
    }

    /// Whether the judged runs accept every input.
    pub fn scripts_accept(&self) -> bool {
        match self.scripts.judged {
            JudgedRun::Alone => self.scripts.accepted,
            JudgedRun::Committed => self.scripts.accepted_under_committed_budgets == Some(true),
        }
    }

    /// Whether this is an outcome of the fast mode of a mutation run
    /// ([`crate::mutation::FAST_ENV`]): every input was run by itself and nothing else was
    /// asked. `consensus`, `mempool` and the committed runs are then no answers.
    pub fn scripts_only(&self) -> bool {
        self.submit.verdict.harness_error.as_deref() == Some(mutation::FAST_NOTE)
    }

    /// Whether this is the placeholder of a case a mutation run did not select
    /// ([`crate::mutation::ONLY_CASES_ENV`]): nothing was run at all.
    pub fn skipped(&self) -> bool {
        self.submit.verdict.harness_error.as_deref() == Some(mutation::SKIPPED_NOTE)
    }

    /// The smallest covering budget of every input. `None` when one of them is unknown.
    pub fn minimal_budgets(&self) -> Option<Vec<u16>> {
        self.budgets.minimal.iter().copied().collect()
    }

    /// Several lines for a failure message: every input with both runs, then the three
    /// verdicts.
    pub fn describe(&self) -> String {
        let mut text = format!("scenario `{}`, transaction {}\n", self.scenario, self.tx_id);
        for input in &self.inputs {
            text.push_str(&format!(
                "  input {} [{}] {}\n",
                input.index,
                input.what(),
                input.label
            ));
            match &input.alone {
                Some(run) => text.push_str(&format!("    alone, no limit: {}\n", run.describe())),
                None => text.push_str("    alone, no limit: not run\n"),
            }
            match &input.committed {
                Some(run) => text.push_str(&format!(
                    "    under {:?}: {}\n",
                    input.commitment,
                    run.describe()
                )),
                None => text.push_str(&format!("    under {:?}: not run\n", input.commitment)),
            }
        }
        if let Some(reason) = &self.scripts.not_run {
            text.push_str(&format!("  scripts: not run ({reason})\n"));
        } else {
            text.push_str(&format!(
                "  scripts: {} alone (refused inputs {:?}), {} under the committed budgets (refused inputs {:?})\n",
                accept_word(self.scripts.accepted),
                self.scripts.refused_inputs,
                self.scripts.accepted_under_committed_budgets.map(accept_word).unwrap_or("not run"),
                self.scripts.refused_inputs_under_committed_budgets,
            ));
        }
        for disagreement in &self.scripts.disagreements {
            text.push_str(&format!("  DISAGREEMENT: {disagreement}\n"));
        }
        text.push_str(&format!(
            "  consensus context: {}{}\n",
            accept_word(self.consensus.context_accepted),
            refusal_text(self.consensus.context_refusal.as_ref()),
        ));
        text.push_str(&format!(
            "  in a block: {}{}\n",
            accept_word(self.consensus.block.accepted),
            refusal_text(self.consensus.block.refusal.as_ref()),
        ));
        text.push_str(&format!(
            "  mempool: {}{}",
            accept_word(self.mempool.accepted),
            refusal_text(self.mempool.first_refusal.as_ref()),
        ));
        text
    }
}

fn accept_word(accepted: bool) -> &'static str {
    if accepted { "accepted" } else { "refused" }
}

fn refusal_text(refusal: Option<&Refusal>) -> String {
    match refusal {
        Some(refusal) => format!(" ({}: {})", refusal.rule, refusal.error),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_names_drop_the_fields() {
        assert_eq!(variant_name("VerifyError"), "VerifyError");
        assert_eq!(
            variant_name("NumberTooBig(\"Sum exceeds 64-bit signed integer range\")"),
            "NumberTooBig"
        );
        assert_eq!(
            variant_name("ExceededCommittedScriptUnits { used: 10000, limit: 9999 }"),
            "ExceededCommittedScriptUnits"
        );
        assert_eq!(
            variant_name("CovenantsError(InvalidCovInIndex(1, 2))"),
            "CovenantsError"
        );
    }

    #[test]
    fn an_engine_error_keeps_all_three_forms() {
        let error = EngineError::of(&TxScriptError::ExceededCommittedScriptUnits {
            used: 10_000,
            limit: 9_999,
        });
        assert_eq!(error.variant, "ExceededCommittedScriptUnits");
        assert_eq!(
            error.debug,
            "ExceededCommittedScriptUnits { used: 10000, limit: 9999 }"
        );
        assert!(error.message.contains("10000"), "{}", error.message);
    }
}
