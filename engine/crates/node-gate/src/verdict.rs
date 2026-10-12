//! The gate's answer for one transaction, in a form that can be stored and compared.
//!
//! `GateVerdict` holds only plain data. Errors appear twice: as the debug text of the
//! node's own error value (exact variant and fields) and as its display text. The typed
//! values are kept next to the verdict in `gate::Evaluation`.

use kaspa_consensus_core::{
    errors::tx::TxRuleError,
    tx::{ComputeCommit, UtxoEntry},
};
use kaspa_txscript::script_class::ScriptClass;
use serde::{Deserialize, Serialize};

use crate::{
    classify::{ErrorClass, classify_at},
    engine::{ScriptRun, StopPoint},
    mass::MassReport,
    policy::{PolicyRefusal, PolicyRule, Priority},
};

/// Which question the gate answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// The transaction arrives inside a block: the storage mass it commits to must equal
    /// the calculated one, and the block limits apply. Mempool policy plays no part.
    Block,
    /// The transaction is submitted to a node's mempool, as over RPC: the node calculates
    /// the storage mass and writes it into the transaction, then applies mempool policy.
    Submit,
}

/// The steps of a validation, in the order of the enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// The question could not be asked of a node as posed. Not a node's answer.
    Harness,
    /// Submit mode: sanity checks before the non-contextual masses are calculated.
    PreMass,
    /// Submit mode: block-fit limits and standardness checked before consensus rules.
    MempoolBeforeConsensus,
    /// Rules that need no context.
    Isolation,
    /// Block mode: mass and gas limits of the containing block.
    BlockMass,
    /// Lock time and the fork dependent rules.
    HeaderContext,
    /// Looking up the spent coins.
    UtxoPopulation,
    /// Submit mode: calculating the storage mass.
    StorageMass,
    /// Maturity, amounts, fee, mass commitment, sequence lock, covenant bindings.
    UtxoContext,
    /// The script of every input.
    Scripts,
    /// Submit mode: block-fit limit and standardness checked after consensus rules.
    MempoolAfterConsensus,
    /// Nothing refused.
    Accepted,
}

/// One refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    /// The step that refused.
    pub stage: Stage,
    /// The function of this crate that refused; it carries the name of the upstream
    /// function it was ported from.
    pub rule: String,
    /// Debug text of the error value: the exact variant and its fields.
    pub error: String,
    /// Display text of the error.
    pub message: String,
    /// The input, for a script refusal.
    pub input: Option<usize>,
}

/// The compute commitment an input carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Commitment {
    /// Version 1: compute budget units, 10,000 script units each.
    ComputeBudget(u16),
    /// Version 0: signature operations, 100,000 script units each.
    SigOpCount(u8),
}

impl From<ComputeCommit> for Commitment {
    fn from(commit: ComputeCommit) -> Self {
        match commit {
            ComputeCommit::ComputeBudget(budget) => Self::ComputeBudget(budget.0),
            ComputeCommit::SigopCount(count) => Self::SigOpCount(count.0),
        }
    }
}

/// One run of one input on the script engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptRecord {
    /// The engine accepted the input.
    pub accepted: bool,
    /// Accepted without running anything, because the coin's script version is unknown.
    pub accepted_unknown_version: bool,
    /// The script-unit limit the engine held the run to; `u64::MAX` for a measuring run.
    /// `None` before Toccata, where the engine meters no script units.
    pub script_units_limit: Option<u64>,
    /// Before Toccata: the number of signature operations the engine allowed the run, 255
    /// for a measuring run. `None` after Toccata.
    pub sig_op_limit: Option<u8>,
    /// Script units consumed (before the failing charge, if the run failed). Zero before
    /// Toccata.
    pub used_script_units: u64,
    /// Signature checks charged.
    pub used_sig_ops: u16,
    /// Debug text of the `TxScriptError`.
    pub error: Option<String>,
    /// Display text of the `TxScriptError`.
    pub message: Option<String>,
    /// Why the engine refused.
    pub class: Option<ErrorClass>,
    /// Where the engine stopped.
    pub stop: Option<StopPoint>,
}

impl ScriptRecord {
    /// The plain-data form of a run. `spent_is_p2sh` is needed to tell a wrapper failure
    /// from a script failure.
    pub fn from_run(run: &ScriptRun, spent_is_p2sh: bool) -> Self {
        Self {
            accepted: run.is_ok(),
            accepted_unknown_version: run.accepted_unknown_version,
            script_units_limit: run.script_units_limit,
            sig_op_limit: run.sig_op_limit,
            used_script_units: run.used_script_units,
            used_sig_ops: run.used_sig_ops,
            error: run.error().map(|error| format!("{error:?}")),
            message: run.error().map(|error| error.to_string()),
            class: run.error().map(|error| classify_at(error, run.stop.as_ref(), spent_is_p2sh)),
            stop: run.stop.clone(),
        }
    }
}

/// Everything the gate learned about one input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputRecord {
    /// Index of the input.
    pub index: usize,
    /// Standard class of the spent coin's script.
    pub spent_script_class: ScriptClass,
    /// The spent coin carries a covenant id.
    pub spent_has_covenant_id: bool,
    /// Length of the signature script in bytes.
    pub signature_script_len: usize,
    /// The compute commitment of the input.
    pub commitment: Commitment,
    /// The run a node makes: under the limit the commitment allows.
    pub committed: ScriptRecord,
    /// A run without a limit, when measuring was asked for.
    pub measured: Option<ScriptRecord>,
    /// The smallest compute budget covering the measured run. `None` when not measured,
    /// when no budget covers it, and before Toccata: the engine then meters no script
    /// units, and the smallest signature operation count the input must commit to is
    /// `measured.used_sig_ops`.
    pub minimal_budget: Option<u16>,
}

impl InputRecord {
    /// Builds the record of one input from its runs.
    pub fn new(
        index: usize,
        entry: &UtxoEntry,
        signature_script_len: usize,
        commit: ComputeCommit,
        committed: &ScriptRun,
        measured: Option<&ScriptRun>,
    ) -> Self {
        let class = ScriptClass::from_script(&entry.script_public_key);
        let spent_is_p2sh = ScriptClass::is_pay_to_script_hash(entry.script_public_key.script());
        Self {
            index,
            spent_script_class: class,
            spent_has_covenant_id: entry.covenant_id.is_some(),
            signature_script_len,
            commitment: commit.into(),
            committed: ScriptRecord::from_run(committed, spent_is_p2sh),
            measured: measured.map(|run| ScriptRecord::from_run(run, spent_is_p2sh)),
            minimal_budget: measured.and_then(|run| run.covering_budget()).map(|budget| budget.0),
        }
    }
}

/// The result of one named mempool rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcome {
    Passed,
    Refused(PolicyRefusal),
    /// The rule needs a value that could not be calculated (masses, storage mass, fee,
    /// coins) because an earlier step failed.
    NotEvaluated,
}

/// One named mempool rule and its result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCheck {
    pub rule: PolicyRule,
    pub outcome: PolicyOutcome,
}

/// What a default node's mempool says, rule by rule. Every rule is evaluated whenever its
/// inputs are available, also after an earlier rule refused, so the list shows all the
/// reasons and not only the first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyReport {
    /// How the transaction reached the mempool.
    pub priority: Priority,
    /// No evaluated rule refused and none was left unevaluated.
    pub accepted: bool,
    /// The per-dimension standard mass cap in effect at this DAA score, if any.
    pub standard_mass_cap: Option<u64>,
    /// Transient mass on the compute-mass scale, as the fee floor uses it.
    pub normalized_transient_mass: Option<u64>,
    /// The mass the fee floor is charged on.
    pub fee_mass: Option<u64>,
    /// The smallest fee the mempool accepts for this transaction, in sompi.
    pub minimum_fee: Option<u64>,
    /// Signature operations counted in the redeem script of every pay-to-script-hash
    /// input (`None` for other inputs), by the node's static scanner.
    pub p2sh_sig_ops: Vec<Option<u64>>,
    /// The rules in the order a node applies them.
    pub checks: Vec<PolicyCheck>,
}

impl PolicyReport {
    /// The outcome of one rule.
    pub fn outcome(&self, rule: PolicyRule) -> Option<&PolicyOutcome> {
        self.checks.iter().find(|check| check.rule == rule).map(|check| &check.outcome)
    }

    /// The refusals, in the node's order.
    pub fn refusals(&self) -> impl Iterator<Item = (PolicyRule, &PolicyRefusal)> {
        self.checks.iter().filter_map(|check| match &check.outcome {
            PolicyOutcome::Refused(refusal) => Some((check.rule, refusal)),
            _ => None,
        })
    }
}

/// What a node of the pinned revision says about one transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateVerdict {
    /// The question that was asked.
    pub mode: Mode,
    /// Network name, e.g. `kaspa-testnet-10`.
    pub network: String,
    /// DAA score from whose point of view the transaction was judged.
    pub pov_daa_score: u64,
    /// DAA score of the containing block.
    pub block_daa_score: u64,
    /// Whether Toccata rules applied.
    pub toccata_active: bool,
    /// Transaction id.
    pub tx_id: String,
    /// The node's answer in this mode. Block mode: consensus rules and block limits.
    /// Submit mode: those the mempool runs, plus mempool policy.
    pub accepted: bool,
    /// The first refusal in the order a node checks. `None` when accepted.
    pub first_refusal: Option<Refusal>,
    /// The consensus rules alone accept the transaction.
    pub consensus_accepted: bool,
    /// The last step of the consensus validation that was entered.
    pub stage_reached: Stage,
    /// The consensus refusal, also when an earlier mempool rule already refused.
    pub consensus_refusal: Option<Refusal>,
    /// Spent amounts minus output values, when both sums are valid.
    pub fee: Option<u64>,
    /// Sizes and masses. `None` when the compute commitments do not match the version,
    /// which makes the masses undefined.
    pub masses: Option<MassReport>,
    /// One record per input, whenever the scripts could be run: all coins present and the
    /// covenant bindings consistent. The scripts are run even if an earlier consensus
    /// rule refused; `stage_reached` says whether a node would have got to them.
    pub inputs: Vec<InputRecord>,
    /// Submit mode: the mempool rules one by one.
    pub policy: Option<PolicyReport>,
    /// Set when the question could not be put to a node as posed; nothing else in the
    /// verdict is then an answer.
    pub harness_error: Option<String>,
}

impl GateVerdict {
    /// The verdict as pretty-printed JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a verdict holds only plain data")
    }
}

/// The function that refuses with `error` at `stage`. Each name is a function of this
/// crate and of the upstream file it was ported from.
pub fn rule_name(stage: Stage, error: &TxRuleError) -> &'static str {
    use TxRuleError as E;
    match (stage, error) {
        (Stage::PreMass, _) => "validate_transaction_for_non_contextual_masses",

        (Stage::Isolation, E::NoTxInputs | E::TooManyInputs(_, _)) => "check_transaction_inputs_count",
        (Stage::Isolation, E::TooBigSignatureScript(_, _)) => "check_transaction_signature_scripts",
        (Stage::Isolation, E::TooManyOutputs(_, _)) => "check_transaction_outputs_count",
        (Stage::Isolation, E::TooBigScriptPublicKey(_, _)) => "check_transaction_script_public_keys",
        (
            Stage::Isolation,
            E::CoinbaseHasInputs(_)
            | E::CoinbaseNonZeroMassCommitment
            | E::CoinbaseTooManyOutputs(_, _)
            | E::CoinbaseScriptPublicKeyTooLong(_),
        ) => "check_coinbase_in_isolation",
        (Stage::Isolation, E::TxOutZero(_) | E::TxOutTooHigh(_) | E::OutputsValueOverflow | E::TotalTxOutTooHigh) => {
            "check_transaction_output_value_ranges"
        }
        (Stage::Isolation, E::TxDuplicateInputs) => "check_duplicate_transaction_inputs",
        (Stage::Isolation, E::TxHasGas(_)) => "check_gas",
        (Stage::Isolation, E::SubnetworksDisabled(_)) => "check_transaction_subnetwork",
        (Stage::Isolation, E::UnknownTxVersion(_)) => "check_transaction_version",
        (Stage::Isolation, E::SigopCountInV1(_, _) | E::ComputeBudgetInV0(_, _) | E::CovenantBindingInV0(_)) => {
            "check_tx_version_specific_fields"
        }

        (Stage::HeaderContext, E::NotFinalized(_)) => "check_tx_is_finalized",
        (Stage::HeaderContext, E::UnknownTxVersion(_)) => "check_transaction_version",
        (Stage::HeaderContext, E::TooBigSignatureScript(_, _)) => "check_transaction_signature_scripts_in_header_context",

        (Stage::UtxoPopulation, _) => "validate_transaction_in_utxo_context",
        (Stage::StorageMass, _) => "validate_mempool_transaction_in_utxo_context",

        (Stage::UtxoContext, E::ImmatureCoinbaseSpend(_, _, _, _, _)) => "check_transaction_coinbase_maturity",
        (Stage::UtxoContext, E::InputAmountOverflow | E::InputAmountTooHigh) => "check_transaction_input_amounts",
        (Stage::UtxoContext, E::SpendTooHigh(_, _)) => "check_transaction_output_values",
        (Stage::UtxoContext, E::MassIncomputable | E::WrongMass(_, _)) => "check_mass_commitment",
        (Stage::UtxoContext, E::SequenceLockConditionsAreNotMet) => "check_sequence_lock",
        (Stage::UtxoContext, E::CovenantsError(_)) => "check_covenant_info",

        (Stage::Scripts, _) => "check_scripts",

        _ => "unexpected",
    }
}
