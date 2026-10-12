//! Transaction rules that need no context: a port of
//! `TransactionValidator::validate_tx_in_isolation`.
//!
//! Source: rusty-kaspa a41a333
//! consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs:18-217
//! (ISC License, Copyright (c) 2022-2024 Kaspa developers). The functions keep the upstream
//! names, order and bodies so they can be compared line by line; the validator's fields are
//! read from `Params` exactly as the node fills them
//! (consensus/src/consensus/services.rs:136-148).

use std::collections::HashSet;

use kaspa_consensus_core::{
    config::params::Params,
    constants::{MAX_SOMPI, TX_VERSION_TOCCATA},
    errors::tx::{TxResult, TxRuleError},
    subnets::{CoinbaseSubnetwork, NativeSubnetwork, SUBNETWORK_NAMESPACE_LEN, SUBNETWORK_ZERO_TAIL_LEN, Subnetwork},
    tx::Transaction,
};

/// All context free checks, in the node's order.
///
/// tx_validation_in_isolation.rs:18-29.
pub fn validate_tx_in_isolation(params: &Params, tx: &Transaction) -> TxResult<()> {
    check_transaction_inputs_in_isolation(params, tx)?;
    check_transaction_outputs_in_isolation(params, tx)?;
    check_coinbase_in_isolation(params, tx)?;

    check_transaction_output_value_ranges(tx)?;
    check_duplicate_transaction_inputs(tx)?;
    check_gas(tx)?;
    check_transaction_subnetwork(tx)?;
    check_transaction_version(tx)?;
    check_tx_version_specific_fields(tx)
}

/// tx_validation_in_isolation.rs:31-34.
pub fn check_transaction_inputs_in_isolation(params: &Params, tx: &Transaction) -> TxResult<()> {
    check_transaction_inputs_count(params, tx)?;
    check_transaction_signature_scripts(params, tx)
}

/// tx_validation_in_isolation.rs:36-39.
pub fn check_transaction_outputs_in_isolation(params: &Params, tx: &Transaction) -> TxResult<()> {
    check_transaction_outputs_count(params, tx)?;
    check_transaction_script_public_keys(params, tx)
}

/// Coinbase only: no inputs, no mass commitment, at most `ghostdag_k + 2` outputs, short
/// output scripts. Any other transaction passes.
///
/// tx_validation_in_isolation.rs:41-64.
pub fn check_coinbase_in_isolation(params: &Params, tx: &Transaction) -> TxResult<()> {
    if !tx.is_coinbase() {
        return Ok(());
    }
    if !tx.inputs.is_empty() {
        return Err(TxRuleError::CoinbaseHasInputs(tx.inputs.len()));
    }

    if tx.storage_mass() > 0 {
        return Err(TxRuleError::CoinbaseNonZeroMassCommitment);
    }

    let outputs_limit = params.ghostdag_k() as u64 + 2;
    if tx.outputs.len() as u64 > outputs_limit {
        return Err(TxRuleError::CoinbaseTooManyOutputs(tx.outputs.len(), outputs_limit));
    }

    for (i, output) in tx.outputs.iter().enumerate() {
        if output.script_public_key.script().len() > params.coinbase_payload_script_public_key_max_len as usize {
            return Err(TxRuleError::CoinbaseScriptPublicKeyTooLong(i));
        }
    }
    Ok(())
}

/// More than `max_tx_outputs` outputs. The second field of the error is `max_tx_inputs`,
/// as upstream writes it (line 72); the two limits are the same number on every network
/// today.
///
/// tx_validation_in_isolation.rs:66-76.
pub fn check_transaction_outputs_count(params: &Params, tx: &Transaction) -> TxResult<()> {
    if tx.is_coinbase() {
        // We already check coinbase outputs count vs. Ghostdag K + 2
        return Ok(());
    }
    if tx.outputs.len() > params.max_tx_outputs {
        return Err(TxRuleError::TooManyOutputs(tx.outputs.len(), params.max_tx_inputs));
    }

    Ok(())
}

/// No inputs in a non-coinbase transaction, or more than `max_tx_inputs`.
///
/// tx_validation_in_isolation.rs:78-88.
pub fn check_transaction_inputs_count(params: &Params, tx: &Transaction) -> TxResult<()> {
    if !tx.is_coinbase() && tx.inputs.is_empty() {
        return Err(TxRuleError::NoTxInputs);
    }

    if tx.inputs.len() > params.max_tx_inputs {
        return Err(TxRuleError::TooManyInputs(tx.inputs.len(), params.max_tx_inputs));
    }

    Ok(())
}

/// A signature script longer than `ForkedParam::upper_bound` of the two fork values: the
/// larger one while the fork is scheduled, the pre-fork value if it never activates, the
/// post-fork value if it has always been active (consensus/core/src/config/params.rs:162-173).
/// The fork dependent limit is checked again in header context.
///
/// tx_validation_in_isolation.rs:91-100.
pub fn check_transaction_signature_scripts(params: &Params, tx: &Transaction) -> TxResult<()> {
    let max_signature_script_len = params.max_signature_script_len().upper_bound();
    if let Some(i) = tx.inputs.iter().position(|input| input.signature_script.len() > max_signature_script_len) {
        return Err(TxRuleError::TooBigSignatureScript(i, max_signature_script_len));
    }

    Ok(())
}

/// An output script longer than `max_script_public_key_len`.
///
/// tx_validation_in_isolation.rs:103-109.
pub fn check_transaction_script_public_keys(params: &Params, tx: &Transaction) -> TxResult<()> {
    if let Some(i) = tx.outputs.iter().position(|out| out.script_public_key.script().len() > params.max_script_public_key_len) {
        return Err(TxRuleError::TooBigScriptPublicKey(i, params.max_script_public_key_len));
    }

    Ok(())
}

/// Two inputs spending the same outpoint.
///
/// tx_validation_in_isolation.rs:112-120.
pub fn check_duplicate_transaction_inputs(tx: &Transaction) -> TxResult<()> {
    let mut existing = HashSet::new();
    for input in &tx.inputs {
        if !existing.insert(input.previous_outpoint) {
            return Err(TxRuleError::TxDuplicateInputs);
        }
    }
    Ok(())
}

/// tx_validation_in_isolation.rs:122.
const ZEROES_19: &[u8; 19] = &[0; 19];

/// Gas is allowed only in a version 1 transaction on a user lane.
///
/// tx_validation_in_isolation.rs:124-140.
pub fn check_gas(tx: &Transaction) -> TxResult<()> {
    if tx.gas == 0 {
        return Ok(());
    }

    if tx.version < TX_VERSION_TOCCATA {
        return Err(TxRuleError::TxHasGas("gas is only allowed for Toccata-or-newer tx versions"));
    }

    // Only post-Toccata non-system lanes may carry gas; reserved system lanes
    // have a 19-byte zero suffix and must remain gas-free.
    if !matches!(tx.subnetwork_id.as_bytes(), [_x, rest @ ..] if rest == ZEROES_19) {
        return Ok(());
    }

    Err(TxRuleError::TxHasGas("native / system subnetworks must use zero gas"))
}

/// A version above `TX_VERSION_TOCCATA`. The fork dependent version rule is in header
/// context.
///
/// tx_validation_in_isolation.rs:142-147.
pub fn check_transaction_version(tx: &Transaction) -> TxResult<()> {
    if tx.version > TX_VERSION_TOCCATA {
        return Err(TxRuleError::UnknownTxVersion(tx.version));
    }
    Ok(())
}

/// Per output, in order: zero value, value above `MAX_SOMPI`, running sum overflowing
/// `u64`, running sum above `MAX_SOMPI`.
///
/// tx_validation_in_isolation.rs:149-172.
pub fn check_transaction_output_value_ranges(tx: &Transaction) -> TxResult<()> {
    let mut total: u64 = 0;
    for (i, output) in tx.outputs.iter().enumerate() {
        if output.value == 0 {
            return Err(TxRuleError::TxOutZero(i));
        }

        if output.value > MAX_SOMPI {
            return Err(TxRuleError::TxOutTooHigh(i));
        }

        if let Some(new_total) = total.checked_add(output.value) {
            total = new_total
        } else {
            return Err(TxRuleError::OutputsValueOverflow);
        }

        if total > MAX_SOMPI {
            return Err(TxRuleError::TotalTxOutTooHigh);
        }
    }

    Ok(())
}

/// The subnetwork id must be native, coinbase, or (version 1 only) a user lane: four
/// namespace bytes followed by sixteen zero bytes.
///
/// tx_validation_in_isolation.rs:174-193.
pub fn check_transaction_subnetwork(tx: &Transaction) -> TxResult<()> {
    const ZEROES_16: &[u8; SUBNETWORK_ZERO_TAIL_LEN] = &[0; SUBNETWORK_ZERO_TAIL_LEN];

    match tx.subnetwork_id.as_bytes() {
        // Native and coinbase (reserved) subnetwork IDs are always allowed
        [NativeSubnetwork::FIRST_BYTE, rest @ ..] | [CoinbaseSubnetwork::FIRST_BYTE, rest @ ..] if rest == ZEROES_19 => Ok(()),
        [_x, rest @ ..] if rest == ZEROES_19 => Err(TxRuleError::SubnetworksDisabled(tx.subnetwork_id)),
        bytes if tx.version >= TX_VERSION_TOCCATA && &bytes[SUBNETWORK_NAMESPACE_LEN..] == ZEROES_16 => Ok(()),
        _ => Err(TxRuleError::SubnetworksDisabled(tx.subnetwork_id)),
    }
}

/// The compute commitment of every input must match the transaction version, and a
/// version 0 transaction must not bind an output to a covenant.
///
/// tx_validation_in_isolation.rs:195-217.
pub fn check_tx_version_specific_fields(tx: &Transaction) -> TxResult<()> {
    if tx.version > 0 {
        for (i, input) in tx.inputs.iter().enumerate() {
            if let Some(sig_op_count) = input.compute_commit.sig_op_count() {
                return Err(TxRuleError::SigopCountInV1(i, sig_op_count));
            }
        }
    } else {
        for (i, input) in tx.inputs.iter().enumerate() {
            if let Some(compute_budget) = input.compute_commit.compute_budget() {
                return Err(TxRuleError::ComputeBudgetInV0(i, compute_budget));
            }
        }

        for (i, output) in tx.outputs.iter().enumerate() {
            if output.covenant.is_some() {
                return Err(TxRuleError::CovenantBindingInV0(i));
            }
        }
    }

    Ok(())
}
