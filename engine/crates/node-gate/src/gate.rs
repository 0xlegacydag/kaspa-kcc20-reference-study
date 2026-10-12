//! The whole question: what would a node say about this transaction?
//!
//! `evaluate` walks a transaction through the steps of a node in the node's order and
//! records how far it got. It stops the consensus validation at the first refusal, as a
//! node does, but goes on collecting what can still be measured: masses, the script result
//! of every input, every mempool rule. The first refusal in node order is reported
//! separately from that fuller picture.
//!
//! Order in submit mode (rusty-kaspa a41a333
//! mining/src/mempool/validate_and_insert_transaction.rs:20-37, 73-77;
//! consensus/src/pipeline/virtual_processor/processor.rs:1216-1233;
//! consensus/src/pipeline/virtual_processor/utxo_validation.rs:442-490):
//!
//! 1. sanity checks before the masses, then compute and transient mass;
//! 2. mempool: gas, compute and transient limits; standardness of the outputs;
//! 3. consensus: in isolation, header context, coins, storage mass (calculated and
//!    written into the transaction), UTXO context without the commitment check, scripts;
//! 4. mempool: storage limit; standardness of the spent coins; minimum fee.
//!
//! Order in block mode (consensus/src/pipeline/body_processor/body_validation_in_isolation.rs:17-27,
//! body_validation_in_context.rs:30-46, utxo_validation.rs:366-414):
//!
//! 1. in isolation; 2. block mass and gas limits; 3. header context; 4. coins;
//! 5. UTXO context with the commitment check, scripts.
//!
//! A coinbase goes through the first three steps only: a node never looks up coins for it
//! or applies the UTXO-context rules to it (utxo_validation.rs:117-121, 326, 348). Past
//! step 3 the gate has no answer for a coinbase in a block and says so.

use kaspa_consensus_core::{
    errors::tx::TxRuleError,
    mass::NonContextualMasses,
    tx::{PopulatedTransaction, Transaction, UtxoEntry},
};
use kaspa_txscript::{post_toccata_p2sh_sig_scanner, script_class::ScriptClass};

use crate::{
    block::{self, BlockMassError},
    engine::{ScriptRun, ScriptRunner},
    header, isolation,
    mass::{self, MassReport, StorageMassInputError},
    params::GateParams,
    policy::{self, PolicyRefusal, PolicyResult, PolicyRule, Priority},
    utxo,
    verdict::{GateVerdict, InputRecord, Mode, PolicyCheck, PolicyOutcome, PolicyReport, Refusal, Stage, rule_name},
};

/// How to evaluate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateOptions {
    /// Block or submit.
    pub mode: Mode,
    /// Submit mode: how the transaction reached the mempool. Only the fee floor before
    /// Toccata depends on it.
    pub priority: Priority,
    /// Also run every input without a budget limit and report the smallest covering
    /// budget.
    pub measure_budgets: bool,
    /// Find the opcode at which a refused input stopped. Costs up to two more runs of
    /// that input.
    pub locate_stops: bool,
}

impl GateOptions {
    /// A transaction submitted over RPC, with measuring and stop positions.
    pub fn submit() -> Self {
        Self { mode: Mode::Submit, priority: Priority::High, measure_budgets: true, locate_stops: true }
    }

    /// A transaction inside a block, with measuring and stop positions.
    pub fn block() -> Self {
        Self { mode: Mode::Block, ..Self::submit() }
    }
}

impl Default for GateOptions {
    fn default() -> Self {
        Self::submit()
    }
}

/// The verdict together with the typed error values it was written from.
#[derive(Clone, Debug)]
pub struct Evaluation {
    /// The plain-data answer.
    pub verdict: GateVerdict,
    /// Submit mode: the error of the sanity checks made before the masses.
    pub pre_mass_error: Option<TxRuleError>,
    /// The consensus refusal. A script failure is `SignatureInvalid` or `SignatureEmpty`
    /// around the engine's error, as a node reports it.
    pub consensus_error: Option<TxRuleError>,
    /// Block mode: the block limit the transaction alone exceeds.
    pub block_mass_error: Option<BlockMassError>,
    /// Submit mode: the first refusal of the rule-by-rule mempool report, in node order.
    /// It is set whenever a rule that could be evaluated refuses, also when an earlier
    /// consensus refusal keeps a node from ever applying that rule; the node's own answer
    /// is `verdict.first_refusal`.
    pub policy_refusal: Option<PolicyRefusal>,
    /// The run of every input under its committed limit.
    pub committed_runs: Vec<ScriptRun>,
    /// The run of every input without a budget limit, when measuring was asked for.
    pub measured_runs: Vec<ScriptRun>,
}

impl Evaluation {
    /// The node's answer in the evaluated mode.
    pub fn accepted(&self) -> bool {
        self.verdict.accepted
    }

    /// The engine's error for the first input that fails under its committed limit.
    pub fn first_script_error(&self) -> Option<&kaspa_txscript_errors::TxScriptError> {
        self.committed_runs.iter().find_map(|run| run.error())
    }
}

/// What the consensus steps produced.
struct Consensus {
    stage_reached: Stage,
    error: Option<TxRuleError>,
    block_mass_error: Option<BlockMassError>,
    harness_error: Option<String>,
    fee: Option<u64>,
    calculated_storage_mass: Option<u64>,
}

impl Consensus {
    /// Before the first step.
    fn start() -> Self {
        Self {
            stage_reached: Stage::Isolation,
            error: None,
            block_mass_error: None,
            harness_error: None,
            fee: None,
            calculated_storage_mass: None,
        }
    }

    /// Refused by a consensus rule at the current stage.
    fn refused(mut self, error: TxRuleError) -> Self {
        self.error = Some(error);
        self
    }

    /// The data could not have reached this step in a node.
    fn unanswerable(mut self, reason: String) -> Self {
        self.harness_error = Some(reason);
        self
    }

    fn accepted(&self) -> bool {
        self.stage_reached == Stage::Accepted
    }
}

/// Evaluates `tx` spending `entries` (`entries[i]` is the coin of input `i`).
///
/// The gate has no UTXO set. Fewer coins than inputs means the remaining outpoints are
/// unknown to the node, which it reports as `MissingTxOutpoints`.
///
/// In submit mode the storage mass field of `tx` is overwritten with the calculated
/// value, exactly as a node does on submission (utxo_validation.rs:460); the field is
/// behind a shared reference upstream too. It is not part of the transaction id.
pub fn evaluate(gate: &GateParams, tx: &Transaction, entries: &[UtxoEntry], options: GateOptions) -> Evaluation {
    if let Some(reason) = unanswerable(gate, tx, entries, options) {
        return harness_evaluation(gate, tx, options, reason);
    }

    // Submit mode starts with these; in block mode they are implied by the in-isolation
    // rules. Either way the masses are defined only if they pass.
    let pre_mass = mass::validate_transaction_for_non_contextual_masses(&gate.params, tx);
    let non_contextual = pre_mass.is_ok().then(|| gate.mass_calculator().calc_non_contextual_masses(tx));

    let mut consensus = match options.mode {
        Mode::Submit => consensus_on_submit(gate, tx, entries),
        Mode::Block => consensus_in_block(gate, tx, entries),
    };
    if let Some(reason) = consensus.harness_error.take() {
        return harness_evaluation(gate, tx, options, reason);
    }

    let (committed_runs, measured_runs) = run_scripts(gate, tx, entries, options);

    // The script stage of the node (tx_validation_in_utxo_context.rs:196-204, 225-227):
    // the first input that fails under its committed limit refuses the transaction.
    if consensus.stage_reached == Stage::Scripts {
        match committed_runs.iter().find_map(|run| run.error().map(|error| (run.input_index, error))) {
            Some((input_index, error)) => consensus.error = Some(utxo::map_script_err(error.clone(), &tx.inputs[input_index])),
            None => consensus.stage_reached = Stage::Accepted,
        }
    }

    let coins_present = entries.len() == tx.inputs.len();
    let calculated_storage_mass = consensus.calculated_storage_mass.or_else(|| {
        // Block mode, or a submission refused before the calculation: still report the
        // number when the calculator can be called.
        if coins_present && isolation::validate_tx_in_isolation(&gate.params, tx).is_ok() {
            mass::calculated_storage_mass(&gate.params, tx, entries).ok().flatten()
        } else {
            None
        }
    });
    let masses = non_contextual.map(|masses| MassReport {
        estimated_size: mass::estimated_size(tx),
        compute_mass: masses.compute_mass,
        transient_mass: masses.transient_mass,
        calculated_storage_mass,
        committed_storage_mass: tx.storage_mass(),
        input_plurality: mass::input_pluralities(entries),
        output_plurality: mass::output_pluralities(tx),
    });

    let policy = (options.mode == Mode::Submit)
        .then(|| policy_report(gate, tx, entries, non_contextual, consensus.calculated_storage_mass, consensus.fee, options.priority));

    // The first refusal, in the node's order.
    let consensus_stage = consensus.stage_reached;
    let consensus_refusal = match (&consensus.error, &consensus.block_mass_error) {
        (Some(error), _) => Some(Refusal {
            stage: consensus_stage,
            rule: rule_name(consensus_stage, error).to_string(),
            error: format!("{error:?}"),
            message: error.to_string(),
            input: (consensus_stage == Stage::Scripts).then(|| committed_runs.iter().position(|run| !run.is_ok())).flatten(),
        }),
        (None, Some(error)) => Some(Refusal {
            stage: Stage::BlockMass,
            rule: "check_block_mass".to_string(),
            error: format!("{error:?}"),
            message: error.to_string(),
            input: None,
        }),
        (None, None) => None,
    };

    let policy_refusal_before = policy.as_ref().and_then(|report| first_refusal_among(report, &PolicyRule::BEFORE_CONSENSUS));
    let policy_refusal_after = policy.as_ref().and_then(|report| first_refusal_among(report, &PolicyRule::AFTER_CONSENSUS));

    // The mempool refusals a node really gets to, from the composed ports: they keep the
    // upstream order in their bodies, so the node's answer does not depend on the order
    // of the rule lists behind the report. A node applies the first group once the masses
    // are known and the second once the consensus validation passed
    // (validate_and_insert_transaction.rs:30-33, 57-77).
    let submitted = options.mode == Mode::Submit;
    let mempool_refusal_before =
        non_contextual.filter(|_| submitted).and_then(|masses| mempool_refusal_before_consensus(gate, tx, masses));
    let mempool_refusal_after = match (non_contextual, consensus.calculated_storage_mass, consensus.fee) {
        (Some(masses), Some(storage_mass), Some(fee)) if submitted && consensus.accepted() => {
            mempool_refusal_after_consensus(gate, tx, entries, masses, storage_mass, fee, options.priority)
        }
        _ => None,
    };
    let first_refusal = match options.mode {
        Mode::Block => consensus_refusal.clone(),
        Mode::Submit => pre_mass
            .as_ref()
            .err()
            .map(|error| Refusal {
                stage: Stage::PreMass,
                rule: rule_name(Stage::PreMass, error).to_string(),
                error: format!("{error:?}"),
                message: error.to_string(),
                input: None,
            })
            .or_else(|| mempool_refusal_before.as_ref().map(|refusal| policy_refusal_record(Stage::MempoolBeforeConsensus, refusal)))
            .or_else(|| consensus_refusal.clone())
            .or_else(|| mempool_refusal_after.as_ref().map(|refusal| policy_refusal_record(Stage::MempoolAfterConsensus, refusal))),
    };

    let inputs = committed_runs
        .iter()
        .enumerate()
        .map(|(i, committed)| {
            let input = &tx.inputs[i];
            InputRecord::new(i, &entries[i], input.signature_script.len(), input.compute_commit, committed, measured_runs.get(i))
        })
        .collect();

    let verdict = GateVerdict {
        mode: options.mode,
        network: gate.params.network_name(),
        pov_daa_score: gate.pov_daa_score,
        block_daa_score: gate.block_daa_score,
        toccata_active: gate.toccata_active(),
        tx_id: tx.id().to_string(),
        accepted: first_refusal.is_none(),
        first_refusal,
        consensus_accepted: consensus.accepted(),
        stage_reached: consensus.stage_reached,
        consensus_refusal,
        fee: consensus.fee,
        masses,
        inputs,
        policy,
        harness_error: None,
    };

    Evaluation {
        verdict,
        pre_mass_error: if options.mode == Mode::Submit { pre_mass.err() } else { None },
        consensus_error: consensus.error,
        block_mass_error: consensus.block_mass_error,
        policy_refusal: policy_refusal_before.or(policy_refusal_after).map(|(_, refusal)| refusal),
        committed_runs,
        measured_runs,
    }
}

/// Reasons why a node could never be asked this question.
fn unanswerable(gate: &GateParams, tx: &Transaction, entries: &[UtxoEntry], options: GateOptions) -> Option<String> {
    if entries.len() > tx.inputs.len() {
        return Some(format!("{} coins were supplied for {} inputs", entries.len(), tx.inputs.len()));
    }
    if gate.pov_daa_score > i64::MAX as u64 || gate.block_daa_score > i64::MAX as u64 {
        return Some("a DAA score above i64::MAX: the sequence lock casts the score to a signed number".to_string());
    }
    if options.mode == Mode::Submit && gate.pov_daa_score != gate.block_daa_score {
        return Some("submit mode with two different DAA scores: a mempool judges at its virtual DAA score only".to_string());
    }
    None
}

/// The consensus steps of a submission, up to the scripts.
///
/// processor.rs:1216-1233 and utxo_validation.rs:442-490.
fn consensus_on_submit(gate: &GateParams, tx: &Transaction, entries: &[UtxoEntry]) -> Consensus {
    let mut out = Consensus::start();

    if let Err(error) = isolation::validate_tx_in_isolation(&gate.params, tx) {
        return out.refused(error);
    }

    out.stage_reached = Stage::HeaderContext;
    if let Err(error) = header::validate_tx_in_header_context_with_args(&gate.params, tx, gate.pov_daa_score, gate.past_median_time) {
        return out.refused(error);
    }

    out.stage_reached = Stage::UtxoPopulation;
    if entries.len() < tx.inputs.len() {
        return out.refused(TxRuleError::MissingTxOutpoints);
    }

    // Calc the contextual storage mass and set the inner mass field (utxo_validation.rs:452-460).
    out.stage_reached = Stage::StorageMass;
    match mass::calculated_storage_mass(&gate.params, tx, entries) {
        Ok(Some(storage_mass)) => {
            tx.set_storage_mass(storage_mass);
            out.calculated_storage_mass = Some(storage_mass);
        }
        Ok(None) => return out.refused(TxRuleError::MassIncomputable),
        // The node's calculator adds the spent amounts with a plain `+`
        // (consensus/core/src/mass/mod.rs:502-503) before the amounts rule has run
        // (utxo_validation.rs:452-457), and the node is built with overflow checks on
        // (Cargo.toml:368-371): it would panic on such coins, not answer. A UTXO set cannot
        // hold them. The gate skips the calculation and reports the refusal the next step
        // gives, `InputAmountOverflow`.
        Err(StorageMassInputError::InputAmountsOverflow) => {}
        Err(reason) => return out.unanswerable(reason.to_string()),
    }

    utxo_context(gate, tx, entries, utxo::TxValidationFlags::SkipMassCheck, out)
}

/// The consensus steps of a transaction inside a block, up to the scripts.
///
/// body_validation_in_isolation.rs:17-27, body_validation_in_context.rs:30-46,
/// utxo_validation.rs:366-414.
fn consensus_in_block(gate: &GateParams, tx: &Transaction, entries: &[UtxoEntry]) -> Consensus {
    let mut out = Consensus::start();

    if let Err(error) = isolation::validate_tx_in_isolation(&gate.params, tx) {
        return out.refused(error);
    }

    out.stage_reached = Stage::BlockMass;
    if let Err(error) = block::check_block_mass(gate, tx) {
        out.block_mass_error = Some(error);
        return out;
    }

    out.stage_reached = Stage::HeaderContext;
    if let Err(error) = header::validate_tx_in_header_context_with_args(&gate.params, tx, gate.block_daa_score, gate.past_median_time)
    {
        return out.refused(error);
    }

    // A node never puts a coinbase through the UTXO-context rules. The virtual processor
    // skips the first transaction of a block and accepts it as it is
    // (utxo_validation.rs:117-121, 326, 348); a coinbase in any other place is refused as a
    // second coinbase (body_validation_in_isolation.rs:46-56). What decides about it from
    // here on are block rules: payload, blue score, subsidy, the expected coinbase.
    if tx.is_coinbase() {
        return out.unanswerable(
            "a coinbase passed the transaction rules a node applies to it in a block (in isolation, block limits, header \
             context); what remains are block rules the gate does not model"
                .to_string(),
        );
    }

    out.stage_reached = Stage::UtxoPopulation;
    if entries.len() < tx.inputs.len() {
        return out.refused(TxRuleError::MissingTxOutpoints);
    }

    utxo_context(gate, tx, entries, utxo::TxValidationFlags::Full, out)
}

/// The steps of `validate_populated_transaction_and_get_fee`
/// (tx_validation_in_utxo_context.rs:37-67) one by one up to the scripts, so that the fee
/// and the stage are known when a later step refuses. It ends at `Stage::Scripts`; the
/// caller runs the scripts. `utxo::validate_populated_transaction_and_get_fee` is the same
/// sequence in one function with its own script loop; the tests hold the two against each
/// other.
fn utxo_context(
    gate: &GateParams,
    tx: &Transaction,
    entries: &[UtxoEntry],
    flags: utxo::TxValidationFlags,
    mut out: Consensus,
) -> Consensus {
    out.stage_reached = Stage::UtxoContext;
    let populated = PopulatedTransaction::new(tx, entries.to_vec());

    if let Err(error) = utxo::check_transaction_coinbase_maturity(gate, &populated, gate.pov_daa_score) {
        return out.refused(error);
    }
    let total_in = match utxo::check_transaction_input_amounts(&populated) {
        Ok(total_in) => total_in,
        Err(error) => return out.refused(error),
    };
    let total_out = match utxo::check_transaction_output_values(&populated, total_in) {
        Ok(total_out) => total_out,
        Err(error) => return out.refused(error),
    };
    out.fee = Some(total_in - total_out);

    if flags != utxo::TxValidationFlags::SkipMassCheck {
        // The calculator divides by the amounts; a node's UTXO set holds no zero amount.
        if let Err(reason) = mass::check_storage_mass_inputs(&gate.params, tx, entries) {
            return out.unanswerable(reason.to_string());
        }
        out.calculated_storage_mass = gate.mass_calculator().calc_contextual_masses(&populated).map(|masses| masses.storage_mass);
        if let Err(error) = utxo::check_mass_commitment(gate, &populated) {
            return out.refused(error);
        }
    }
    if let Err(error) = utxo::check_sequence_lock(&populated, gate.pov_daa_score) {
        return out.refused(error);
    }
    if let Err(error) = utxo::check_covenant_info(gate, &populated, gate.block_daa_score) {
        return out.refused(error);
    }

    out.stage_reached = Stage::Scripts;
    out
}

/// Runs every input under its committed limit and, if asked, without a limit. Returns
/// nothing when the scripts cannot be run at all: a coin is missing, or the covenant
/// bindings are inconsistent.
fn run_scripts(gate: &GateParams, tx: &Transaction, entries: &[UtxoEntry], options: GateOptions) -> (Vec<ScriptRun>, Vec<ScriptRun>) {
    if entries.len() != tx.inputs.len() || tx.inputs.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let Ok(covenants_ctx) = utxo::check_covenant_info(gate, &populated, gate.block_daa_score) else {
        return (Vec::new(), Vec::new());
    };
    let runner = ScriptRunner::new(&populated, &covenants_ctx, gate.engine_flags());
    let committed = runner.run_all_committed(options.locate_stops);
    let measured = if options.measure_budgets { runner.run_all_unlimited(options.locate_stops) } else { Vec::new() };
    (committed, measured)
}

/// Evaluates every mempool rule whose inputs are known.
fn policy_report(
    gate: &GateParams,
    tx: &Transaction,
    entries: &[UtxoEntry],
    masses: Option<NonContextualMasses>,
    storage_mass: Option<u64>,
    fee: Option<u64>,
    priority: Priority,
) -> PolicyReport {
    let params = &gate.params;
    let daa = gate.pov_daa_score;
    let coins_present = entries.len() == tx.inputs.len();

    let outcome = |result: Option<PolicyResult<()>>| match result {
        Some(Ok(())) => PolicyOutcome::Passed,
        Some(Err(refusal)) => PolicyOutcome::Refused(refusal),
        None => PolicyOutcome::NotEvaluated,
    };
    let check = |rule: PolicyRule| {
        let result = match rule {
            PolicyRule::GasLimit => Some(policy::check_gas_limit(params, tx)),
            PolicyRule::ComputeMassLimit => masses.map(|masses| policy::check_compute_mass_limit(params, masses, daa)),
            PolicyRule::TransientMassLimit => masses.map(|masses| policy::check_transient_mass_limit(params, masses, daa)),
            PolicyRule::StandardComputeMassCap => masses.map(|masses| policy::check_standard_compute_mass_cap(params, masses, daa)),
            PolicyRule::StandardTransientMassCap => {
                masses.map(|masses| policy::check_standard_transient_mass_cap(params, masses, daa))
            }
            PolicyRule::OutputScriptsStandard => Some(policy::check_output_scripts_standard(tx)),
            PolicyRule::StorageMassLimit => {
                storage_mass.map(|storage_mass| policy::check_storage_mass_limit(params, storage_mass, daa))
            }
            PolicyRule::StandardStorageMassCap => {
                storage_mass.map(|storage_mass| policy::check_standard_storage_mass_cap(params, storage_mass, daa))
            }
            PolicyRule::InputScriptsStandard => coins_present.then(|| policy::check_input_scripts_standard(tx, entries)),
            PolicyRule::MinimumRelayFee => match (masses, fee) {
                (Some(masses), Some(fee)) => Some(policy::check_minimum_relay_fee(params, masses, fee, priority, daa)),
                _ => None,
            },
        };
        PolicyCheck { rule, outcome: outcome(result) }
    };

    let checks: Vec<PolicyCheck> =
        PolicyRule::BEFORE_CONSENSUS.iter().chain(PolicyRule::AFTER_CONSENSUS.iter()).map(|rule| check(*rule)).collect();
    let fee_terms = masses.map(|masses| policy::minimum_relay_fee_terms(params, masses, priority, daa));
    let p2sh_sig_ops = if coins_present {
        tx.inputs
            .iter()
            .zip(entries)
            .map(|(input, entry)| {
                (ScriptClass::from_script(&entry.script_public_key) == ScriptClass::ScriptHash)
                    .then(|| post_toccata_p2sh_sig_scanner(&input.signature_script, &entry.script_public_key))
            })
            .collect()
    } else {
        Vec::new()
    };

    PolicyReport {
        priority,
        accepted: checks.iter().all(|check| check.outcome == PolicyOutcome::Passed),
        standard_mass_cap: policy::standard_transaction_mass_cap(params, daa),
        normalized_transient_mass: masses.map(|masses| policy::normalized_transient_mass(params, masses)),
        fee_mass: fee_terms.map(|(fee_mass, _, _)| fee_mass),
        minimum_fee: fee_terms.map(|(_, _, minimum_fee)| minimum_fee),
        p2sh_sig_ops,
        checks,
    }
}

fn first_refusal_among(report: &PolicyReport, rules: &[PolicyRule]) -> Option<(PolicyRule, PolicyRefusal)> {
    report.refusals().find(|(rule, _)| rules.contains(rule)).map(|(rule, refusal)| (rule, refusal.clone()))
}

/// The refusal of the mempool rules a node applies before the consensus validation: the
/// block-fit limits, then standardness (validate_and_insert_transaction.rs:32-33).
fn mempool_refusal_before_consensus(gate: &GateParams, tx: &Transaction, masses: NonContextualMasses) -> Option<PolicyRefusal> {
    let (params, daa) = (&gate.params, gate.pov_daa_score);
    policy::validate_transaction_limits_in_isolation(params, tx, masses, daa)
        .and_then(|()| policy::check_transaction_standard_in_isolation(params, tx, masses, daa))
        .err()
}

/// The refusal of the mempool rules a node applies after the consensus validation passed:
/// the storage limit, then standardness (validate_and_insert_transaction.rs:76-77).
fn mempool_refusal_after_consensus(
    gate: &GateParams,
    tx: &Transaction,
    entries: &[UtxoEntry],
    masses: NonContextualMasses,
    storage_mass: u64,
    fee: u64,
    priority: Priority,
) -> Option<PolicyRefusal> {
    let (params, daa) = (&gate.params, gate.pov_daa_score);
    policy::validate_transaction_limits_in_context(params, storage_mass, daa)
        .and_then(|()| policy::check_transaction_standard_in_context(params, tx, entries, masses, storage_mass, fee, priority, daa))
        .err()
}

fn policy_refusal_record(stage: Stage, refusal: &PolicyRefusal) -> Refusal {
    Refusal {
        stage,
        rule: policy_rule_function(refusal.rule()).to_string(),
        error: format!("{refusal:?}"),
        message: refusal.to_string(),
        input: None,
    }
}

/// The function of `policy` that implements a rule.
pub fn policy_rule_function(rule: PolicyRule) -> &'static str {
    match rule {
        PolicyRule::GasLimit => "check_gas_limit",
        PolicyRule::ComputeMassLimit => "check_compute_mass_limit",
        PolicyRule::TransientMassLimit => "check_transient_mass_limit",
        PolicyRule::StandardComputeMassCap => "check_standard_compute_mass_cap",
        PolicyRule::StandardTransientMassCap => "check_standard_transient_mass_cap",
        PolicyRule::OutputScriptsStandard => "check_output_scripts_standard",
        PolicyRule::StorageMassLimit => "check_storage_mass_limit",
        PolicyRule::StandardStorageMassCap => "check_standard_storage_mass_cap",
        PolicyRule::InputScriptsStandard => "check_input_scripts_standard",
        PolicyRule::MinimumRelayFee => "check_minimum_relay_fee",
    }
}

/// The evaluation of a question no node could be asked.
fn harness_evaluation(gate: &GateParams, tx: &Transaction, options: GateOptions, reason: String) -> Evaluation {
    let refusal =
        Refusal { stage: Stage::Harness, rule: "harness".to_string(), error: reason.clone(), message: reason.clone(), input: None };
    let verdict = GateVerdict {
        mode: options.mode,
        network: gate.params.network_name(),
        pov_daa_score: gate.pov_daa_score,
        block_daa_score: gate.block_daa_score,
        toccata_active: gate.toccata_active(),
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
        harness_error: Some(reason),
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
