//! Transaction rules that depend on the containing block header: lock time, and the two
//! rules that change at the Toccata fork (version, signature script length).
//!
//! Source: rusty-kaspa a41a333
//! consensus/src/processes/transaction_validator/tx_validation_in_header_context.rs:15-119
//! (ISC License, Copyright (c) 2022-2024 Kaspa developers). Names, order and bodies follow
//! upstream.

use kaspa_consensus_core::{
    config::params::Params,
    constants::{LOCK_TIME_THRESHOLD, TX_VERSION, TX_VERSION_TOCCATA},
    errors::tx::{TxResult, TxRuleError},
    tx::Transaction,
};

/// What a lock time value means. tx_validation_in_header_context.rs:15-19.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockTimeType {
    Finalized,
    DaaScore,
    Time,
}

/// The context value a lock time is compared with.
/// tx_validation_in_header_context.rs:21-25.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockTimeArg {
    Finalized,
    DaaScore(u64),
    MedianTime(u64),
}

/// Picks the lock time argument from the context and runs the header checks.
///
/// tx_validation_in_header_context.rs:28-43. A mempool calls this with the virtual DAA
/// score and the virtual past median time
/// (consensus/src/pipeline/virtual_processor/processor.rs:1225-1230).
pub fn validate_tx_in_header_context_with_args(
    params: &Params,
    tx: &Transaction,
    ctx_daa_score: u64,
    ctx_block_time: u64,
) -> TxResult<()> {
    validate_tx_in_header_context(
        params,
        tx,
        match get_lock_time_type(tx) {
            LockTimeType::Finalized => LockTimeArg::Finalized,
            LockTimeType::DaaScore => LockTimeArg::DaaScore(ctx_daa_score),
            LockTimeType::Time => LockTimeArg::MedianTime(ctx_block_time),
        },
        ctx_daa_score,
    )
}

/// The three header checks, in the node's order.
///
/// tx_validation_in_header_context.rs:45-54.
pub fn validate_tx_in_header_context(
    params: &Params,
    tx: &Transaction,
    lock_time_arg: LockTimeArg,
    block_daa_score: u64,
) -> TxResult<()> {
    check_tx_is_finalized(tx, lock_time_arg)?;
    check_transaction_version(params, tx, block_daa_score)?;
    check_transaction_signature_scripts_in_header_context(params, tx, block_daa_score)
}

/// tx_validation_in_header_context.rs:56-70.
pub fn get_lock_time_type(tx: &Transaction) -> LockTimeType {
    match tx.lock_time {
        // Lock time of zero means the transaction is finalized.
        0 => LockTimeType::Finalized,

        // The lock time field of a transaction is either a block DAA score at
        // which the transaction is finalized or a timestamp depending on if the
        // value is before the LOCK_TIME_THRESHOLD. When it is under the
        // threshold it is a DAA score
        t if t < LOCK_TIME_THRESHOLD => LockTimeType::DaaScore,

        // ..and when equal or above the threshold it represents time
        _t => LockTimeType::Time,
    }
}

/// A lock time not yet reached refuses the transaction unless every input has the
/// maximal sequence number.
///
/// tx_validation_in_header_context.rs:72-93.
pub fn check_tx_is_finalized(tx: &Transaction, lock_time_arg: LockTimeArg) -> TxResult<()> {
    let block_time_or_daa_score = match lock_time_arg {
        LockTimeArg::Finalized => return Ok(()),
        LockTimeArg::DaaScore(ctx_daa_score) => ctx_daa_score,
        LockTimeArg::MedianTime(ctx_block_time) => ctx_block_time,
    };

    if tx.lock_time < block_time_or_daa_score {
        return Ok(());
    }

    // At this point, the transaction's lock time hasn't occurred yet, but
    // the transaction might still be finalized if the sequence number
    // for all transaction inputs is maxed out.
    for (i, input) in tx.inputs.iter().enumerate() {
        if input.sequence != u64::MAX {
            return Err(TxRuleError::NotFinalized(i));
        }
    }

    Ok(())
}

/// Before Toccata only version 0 is known; after it, versions 0 and 1.
///
/// tx_validation_in_header_context.rs:96-109.
pub fn check_transaction_version(params: &Params, tx: &Transaction, block_daa_score: u64) -> TxResult<()> {
    if params.toccata_activation.is_active(block_daa_score) {
        if tx.version > TX_VERSION_TOCCATA {
            return Err(TxRuleError::UnknownTxVersion(tx.version));
        }
        return Ok(());
    }

    if tx.version != TX_VERSION {
        return Err(TxRuleError::UnknownTxVersion(tx.version));
    }

    Ok(())
}

/// The signature script length limit of the fork side the block is on.
///
/// tx_validation_in_header_context.rs:112-119.
pub fn check_transaction_signature_scripts_in_header_context(params: &Params, tx: &Transaction, block_daa_score: u64) -> TxResult<()> {
    let max_signature_script_len = params.max_signature_script_len().get(block_daa_score);
    if let Some(i) = tx.inputs.iter().position(|input| input.signature_script.len() > max_signature_script_len) {
        return Err(TxRuleError::TooBigSignatureScript(i, max_signature_script_len));
    }

    Ok(())
}
