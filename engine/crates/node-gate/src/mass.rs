//! Sizes and masses of a transaction.
//!
//! Every number is produced by the node's own code in `kaspa_consensus_core::mass`
//! (rusty-kaspa a41a333 consensus/core/src/mass/mod.rs). This module only adds the guards
//! a node applies before it calls that code, because the calculators assume those guards
//! and panic or divide by zero without them.
//!
//! Source: rusty-kaspa a41a333 consensus/src/consensus/mod.rs:599-627 and :689-692
//! (ISC License, Copyright (c) 2022-2024 Kaspa developers) for two functions,
//! `validate_transaction_for_non_contextual_masses` and
//! `calculate_transaction_non_contextual_masses`. Their names and bodies follow upstream;
//! the limits and the mass calculator a node holds are taken from `Params`. The rest of
//! this file is not a port.

use kaspa_consensus_core::{
    config::params::Params,
    errors::tx::{TxResult, TxRuleError},
    mass::{MassCalculator, NonContextualMasses, UtxoPlurality, transaction_estimated_serialized_size},
    tx::{ComputeCommit, PopulatedTransaction, Transaction, UtxoEntry},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The masses of one transaction, as a node computes them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MassReport {
    /// `transaction_estimated_serialized_size` (mass/mod.rs:21-40).
    pub estimated_size: u64,
    /// Compute mass (mass/mod.rs:335-370): size, output scripts and the committed budgets.
    pub compute_mass: u64,
    /// Transient mass: four grams per byte of the estimated size.
    pub transient_mass: u64,
    /// Storage mass calculated from the spent coins and the outputs (KIP-9 with
    /// plurality, mass/mod.rs:439-513). `None` when it was not calculated: the stage was
    /// not reached, the coins are missing, or the sum is incomputable.
    pub calculated_storage_mass: Option<u64>,
    /// The storage mass field the transaction carries after the evaluation. In submit
    /// mode the gate has overwritten it, as a node does.
    pub committed_storage_mass: u64,
    /// Storage plurality of every spent coin, in input order (mass/mod.rs:83-111).
    pub input_plurality: Vec<u64>,
    /// Storage plurality of every output, in output order (mass/mod.rs:113-117).
    pub output_plurality: Vec<u64>,
}

/// The sanity checks a node runs before it calculates the non-contextual masses of a
/// transaction that arrives at the mempool: input and output counts, and a compute
/// commitment of the kind the version expects.
///
/// Port of `Consensus::validate_transaction_for_non_contextual_masses`, rusty-kaspa
/// a41a333 consensus/src/consensus/mod.rs:599-627. Unlike the in-isolation rule, this one
/// reports `max_tx_outputs` in `TooManyOutputs`.
pub fn validate_transaction_for_non_contextual_masses(params: &Params, transaction: &Transaction) -> TxResult<()> {
    if transaction.is_coinbase() {
        return Ok(());
    }

    if transaction.inputs.len() > params.max_tx_inputs {
        return Err(TxRuleError::TooManyInputs(transaction.inputs.len(), params.max_tx_inputs));
    }

    if transaction.outputs.len() > params.max_tx_outputs {
        return Err(TxRuleError::TooManyOutputs(transaction.outputs.len(), params.max_tx_outputs));
    }

    if ComputeCommit::version_expects_compute_budget_field(transaction.version) {
        for (i, input) in transaction.inputs.iter().enumerate() {
            if let Some(sig_op_count) = input.compute_commit.sig_op_count() {
                return Err(TxRuleError::SigopCountInV1(i, sig_op_count));
            }
        }
    } else {
        for (i, input) in transaction.inputs.iter().enumerate() {
            if let Some(compute_budget) = input.compute_commit.compute_budget() {
                return Err(TxRuleError::ComputeBudgetInV0(i, compute_budget));
            }
        }
    }

    Ok(())
}

/// Compute and transient mass, behind the sanity checks above.
///
/// Port of `Consensus::calculate_transaction_non_contextual_masses`, rusty-kaspa a41a333
/// consensus/src/consensus/mod.rs:689-692. Without the checks
/// `MassCalculator::calc_non_contextual_masses` panics on an input whose compute
/// commitment does not match the transaction version (mass/mod.rs:354, 361).
pub fn calculate_transaction_non_contextual_masses(params: &Params, transaction: &Transaction) -> TxResult<NonContextualMasses> {
    validate_transaction_for_non_contextual_masses(params, transaction)?;
    Ok(MassCalculator::new_with_consensus_params(params).calc_non_contextual_masses(transaction))
}

/// Estimated serialized size in bytes (mass/mod.rs:21-40).
pub fn estimated_size(tx: &Transaction) -> u64 {
    transaction_estimated_serialized_size(tx)
}

/// Storage plurality of every spent coin, in input order.
pub fn input_pluralities(entries: &[UtxoEntry]) -> Vec<u64> {
    entries.iter().map(UtxoPlurality::plurality).collect()
}

/// Storage plurality of every output, in output order.
pub fn output_pluralities(tx: &Transaction) -> Vec<u64> {
    tx.outputs.iter().map(UtxoPlurality::plurality).collect()
}

/// Data the storage mass calculator must never be given. A node cannot get here: the
/// in-isolation rules and its own UTXO set exclude every case.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum StorageMassInputError {
    #[error("the number of coins ({entries}) differs from the number of inputs ({inputs})")]
    EntryCountMismatch { inputs: usize, entries: usize },
    #[error("a non-coinbase transaction without inputs")]
    NoInputs,
    #[error("output {0} has zero value")]
    ZeroOutputValue(usize),
    #[error("the coin of input {0} has zero amount, which no unspent output can have")]
    ZeroInputAmount(usize),
    #[error("the amounts of the coins overflow 64 bits, which no set of unspent outputs can do")]
    InputAmountsOverflow,
    #[error("the script of the coin of input {0} is {1} bytes long, above the {2} bytes an output may have")]
    OversizedInputScript(usize, usize, usize),
}

/// Checks that `calc_storage_mass` can be called without dividing by zero or overflowing
/// in the places where it assumes it cannot (mass/mod.rs:433-438, 463, 493, 503, 506).
pub fn check_storage_mass_inputs(params: &Params, tx: &Transaction, entries: &[UtxoEntry]) -> Result<(), StorageMassInputError> {
    if entries.len() != tx.inputs.len() {
        return Err(StorageMassInputError::EntryCountMismatch { inputs: tx.inputs.len(), entries: entries.len() });
    }
    if tx.is_coinbase() {
        return Ok(());
    }
    if tx.inputs.is_empty() {
        return Err(StorageMassInputError::NoInputs);
    }
    if let Some(i) = tx.outputs.iter().position(|output| output.value == 0) {
        return Err(StorageMassInputError::ZeroOutputValue(i));
    }
    let mut total: u64 = 0;
    for (i, entry) in entries.iter().enumerate() {
        if entry.amount == 0 {
            return Err(StorageMassInputError::ZeroInputAmount(i));
        }
        let script_len = entry.script_public_key.script().len();
        if script_len > params.max_script_public_key_len {
            return Err(StorageMassInputError::OversizedInputScript(i, script_len, params.max_script_public_key_len));
        }
        total = total.checked_add(entry.amount).ok_or(StorageMassInputError::InputAmountsOverflow)?;
    }
    Ok(())
}

/// Storage mass of a transaction spending `entries`, by the node's calculator
/// (`MassCalculator::calc_contextual_masses`, mass/mod.rs:378-386).
///
/// `Ok(None)` is the calculator's "incomputable" answer, which a node turns into
/// `TxRuleError::MassIncomputable`. `Err` means the data could not have reached the
/// calculator in a node.
pub fn calculated_storage_mass(
    params: &Params,
    tx: &Transaction,
    entries: &[UtxoEntry],
) -> Result<Option<u64>, StorageMassInputError> {
    check_storage_mass_inputs(params, tx, entries)?;
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    Ok(MassCalculator::new_with_consensus_params(params).calc_contextual_masses(&populated).map(|masses| masses.storage_mass))
}
