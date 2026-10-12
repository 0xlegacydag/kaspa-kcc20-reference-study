//! Compute budgets: measure the inputs of a transaction, commit the smallest budgets that
//! cover them, and run again under the committed budgets.
//!
//! A node never does the first two; a wallet does. They are here because the smallest
//! sufficient budget is a property worth pinning: one unit less must fail with
//! `ExceededCommittedScriptUnits`, and the budget is what the compute mass, and so the
//! fee, is charged on (100 grams per unit, rusty-kaspa a41a333
//! consensus/core/src/mass/mod.rs:349-356).
//!
//! In a version 1 transaction neither the transaction id nor any signature hash covers
//! the budgets (consensus/core/src/hashing/tx.rs:99-115, hashing/sighash.rs:245-280), so
//! they can be written after signing.
//!
//! Budgets exist after Toccata only. Before it the engine meters no script units
//! (crypto/txscript/src/lib.rs:542-546): `measure_inputs` then reports the signature
//! operations every input needs (`ScriptRun::used_sig_ops`), and `minimal_budgets` and
//! `commit_minimal_budgets` answer `BudgetError::BeforeToccata`.

use kaspa_consensus_core::{
    errors::tx::TxRuleError,
    mass::{ComputeBudget, ScriptUnits},
    tx::{ComputeCommit, PopulatedTransaction, Transaction, UtxoEntry},
};
use thiserror::Error;

use crate::{
    engine::{ScriptRun, ScriptRunner},
    params::GateParams,
    utxo,
};

/// Why budgets could not be measured or committed.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum BudgetError {
    #[error("{entries} coins were supplied for {inputs} inputs")]
    EntryCountMismatch { inputs: usize, entries: usize },
    #[error(
        "a version {0} transaction commits signature operation counts, which its signatures cover; only version 1 budgets can be rewritten"
    )]
    NotVersionOne(u16),
    #[error("the covenant bindings are inconsistent: {0}")]
    Covenants(TxRuleError),
    #[error("input {input} used {used_script_units} script units, more than the largest budget covers")]
    NotCoverable { input: usize, used_script_units: u64 },
    #[error("before Toccata the engine counts signature operations and meters no script units: there is no budget to measure")]
    BeforeToccata,
}

/// The measured need of one input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measurement {
    /// The run without a budget limit. If it failed, the units are those used up to the
    /// failure, and a budget covering them reproduces the same failure.
    pub run: ScriptRun,
    /// The smallest budget that covers the run.
    pub budget: ComputeBudget,
}

/// Runs every input with no limit, with the node's flags and covenant context.
///
/// After Toccata the runs are metered in script units and `ScriptRun::covering_budget`
/// gives the smallest budget of each input. Before Toccata they are bound by no signature
/// operation count (`ScriptRunner::run_unlimited`); they report the signature operations
/// used and no budget.
pub fn measure_inputs(
    gate: &GateParams,
    tx: &Transaction,
    entries: &[UtxoEntry],
    locate: bool,
) -> Result<Vec<ScriptRun>, BudgetError> {
    run_inputs(gate, tx, entries, |runner| runner.run_all_unlimited(locate))
}

/// Runs every input under its committed limit, as a node's script check does, and
/// returns all results instead of the first failure.
pub fn run_committed_inputs(
    gate: &GateParams,
    tx: &Transaction,
    entries: &[UtxoEntry],
    locate: bool,
) -> Result<Vec<ScriptRun>, BudgetError> {
    run_inputs(gate, tx, entries, |runner| runner.run_all_committed(locate))
}

/// Runs one input under a limit of the caller's choice, with the node's flags and
/// covenant context. Before Toccata the engine ignores `limit` and holds the input to the
/// signature operation count it commits to.
///
/// Panics when `input_index` is not an input of the transaction, as the engine does.
pub fn run_input(
    gate: &GateParams,
    tx: &Transaction,
    entries: &[UtxoEntry],
    input_index: usize,
    limit: ScriptUnits,
    locate: bool,
) -> Result<ScriptRun, BudgetError> {
    let mut runs = run_inputs(gate, tx, entries, |runner| vec![runner.run(input_index, limit, locate)])?;
    Ok(runs.remove(0))
}

/// The smallest budget for every input of a transaction, by measuring. After Toccata only.
pub fn minimal_budgets(gate: &GateParams, tx: &Transaction, entries: &[UtxoEntry]) -> Result<Vec<Measurement>, BudgetError> {
    if !gate.toccata_active() {
        return Err(BudgetError::BeforeToccata);
    }
    measure_inputs(gate, tx, entries, false)?
        .into_iter()
        .map(|run| {
            let budget = run
                .covering_budget()
                .ok_or(BudgetError::NotCoverable { input: run.input_index, used_script_units: run.used_script_units })?;
            Ok(Measurement { run, budget })
        })
        .collect()
}

/// Measures every input and writes the smallest covering budget into it.
///
/// Version 1 and after Toccata only. Signature scripts are not touched.
pub fn commit_minimal_budgets(
    gate: &GateParams,
    tx: &mut Transaction,
    entries: &[UtxoEntry],
) -> Result<Vec<Measurement>, BudgetError> {
    if !ComputeCommit::version_expects_compute_budget_field(tx.version) {
        return Err(BudgetError::NotVersionOne(tx.version));
    }
    let measurements = minimal_budgets(gate, tx, entries)?;
    for (input, measurement) in tx.inputs.iter_mut().zip(&measurements) {
        input.compute_commit = ComputeCommit::ComputeBudget(measurement.budget);
    }
    tx.finalize();
    Ok(measurements)
}

fn run_inputs(
    gate: &GateParams,
    tx: &Transaction,
    entries: &[UtxoEntry],
    run: impl FnOnce(&ScriptRunner<'_, PopulatedTransaction<'_>>) -> Vec<ScriptRun>,
) -> Result<Vec<ScriptRun>, BudgetError> {
    if entries.len() != tx.inputs.len() {
        return Err(BudgetError::EntryCountMismatch { inputs: tx.inputs.len(), entries: entries.len() });
    }
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let covenants_ctx = utxo::check_covenant_info(gate, &populated, gate.block_daa_score).map_err(BudgetError::Covenants)?;
    let runner = ScriptRunner::new(&populated, &covenants_ctx, gate.engine_flags());
    Ok(run(&runner))
}
