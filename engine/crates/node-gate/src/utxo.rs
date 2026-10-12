//! Transaction rules that need the spent coins: a port of
//! `TransactionValidator::validate_populated_transaction_and_get_fee`.
//!
//! Source: rusty-kaspa a41a333
//! consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs:23-227
//! (ISC License, Copyright (c) 2022-2024 Kaspa developers). Names, order and bodies follow
//! upstream. Three things differ and are marked where they occur:
//!
//! * scripts always run one input after the other. A node does that for one input and
//!   uses a thread pool for more (lines 186-194, 206-214); the verdict is the same, but
//!   with several failing inputs a node may report any of them, the gate the first.
//! * the replace-by-fee feerate threshold (lines 69-79) is not modelled: outside a
//!   replacement a node passes `None`, which checks nothing.
//! * no `SeqCommitAccessor` is passed, so `OpChainblockSeqCommit` fails with
//!   `InvalidOpcode` instead of consulting the header chain.
//!
//! The functions expect what a node guarantees before it calls them: the in-isolation
//! rules passed and one coin is supplied per input. `gate::evaluate` checks that.
//!
//! The script check here builds the engine directly, as upstream does, and does not go
//! through `engine::ScriptRunner`. `gate::evaluate` takes its script results from the
//! runner; the shared helper of the tests compares the two on each transaction it evaluates.

use kaspa_consensus_core::{
    constants::{MAX_SOMPI, SEQUENCE_LOCK_TIME_DISABLED, SEQUENCE_LOCK_TIME_MASK},
    errors::tx::{TxResult, TxRuleError},
    hashing::sighash::SigHashReusedValuesUnsync,
    mass::Gram,
    tx::{TransactionInput, VerifiableTransaction},
};
use kaspa_txscript::{
    EngineCtx, EngineCtxUnsync, EngineFlags, SigCacheKey, TxScriptEngine, caches::Cache, covenants::CovenantsContext,
};
use kaspa_txscript_errors::TxScriptError;

use crate::{engine::SIG_CACHE_SIZE, params::GateParams};

/// How much of the UTXO-context validation to run.
/// tx_validation_in_utxo_context.rs:23-34.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxValidationFlags {
    /// Perform full validation including script verification
    Full,

    /// Perform fee and sequence/maturity validations but skip script checks. This is usually
    /// an optimization to be applied when it is known that scripts were already checked
    SkipScriptChecks,

    /// When validating mempool transactions, we just set this value ourselves
    SkipMassCheck,
}

/// All UTXO-context checks in the node's order; returns the fee.
///
/// tx_validation_in_utxo_context.rs:37-67. `gate.pov_daa_score` and
/// `gate.block_daa_score` take the place of the two score arguments.
pub fn validate_populated_transaction_and_get_fee(
    gate: &GateParams,
    tx: &impl VerifiableTransaction,
    flags: TxValidationFlags,
) -> TxResult<u64> {
    check_transaction_coinbase_maturity(gate, tx, gate.pov_daa_score)?;
    let total_in = check_transaction_input_amounts(tx)?;
    let total_out = check_transaction_output_values(tx, total_in)?;
    let fee = total_in - total_out;
    if flags != TxValidationFlags::SkipMassCheck {
        check_mass_commitment(gate, tx)?;
    }
    check_sequence_lock(tx, gate.pov_daa_score)?;

    // Upstream calls check_feerate_threshold here (replace by fee only, not modelled).
    let covenants_ctx = check_covenant_info(gate, tx, gate.block_daa_score)?;

    match flags {
        TxValidationFlags::Full | TxValidationFlags::SkipMassCheck => {
            check_scripts(gate, tx, covenants_ctx, gate.block_daa_score)?;
        }
        TxValidationFlags::SkipScriptChecks => {}
    }
    Ok(fee)
}

/// A coinbase coin must be `coinbase_maturity` DAA scores old.
///
/// tx_validation_in_utxo_context.rs:81-97.
pub fn check_transaction_coinbase_maturity(gate: &GateParams, tx: &impl VerifiableTransaction, pov_daa_score: u64) -> TxResult<()> {
    let coinbase_maturity = gate.params.coinbase_maturity();
    if let Some((index, (input, entry))) = tx
        .populated_inputs()
        .enumerate()
        .find(|(_, (_, entry))| entry.is_coinbase && entry.block_daa_score + coinbase_maturity > pov_daa_score)
    {
        return Err(TxRuleError::ImmatureCoinbaseSpend(
            index,
            input.previous_outpoint,
            entry.block_daa_score,
            pov_daa_score,
            coinbase_maturity,
        ));
    }

    Ok(())
}

/// The sum of the spent amounts must fit in `u64` and stay within `MAX_SOMPI`.
///
/// tx_validation_in_utxo_context.rs:99-114.
pub fn check_transaction_input_amounts(tx: &impl VerifiableTransaction) -> TxResult<u64> {
    let mut total: u64 = 0;
    for (_, entry) in tx.populated_inputs() {
        if let Some(new_total) = total.checked_add(entry.amount) {
            total = new_total
        } else {
            return Err(TxRuleError::InputAmountOverflow);
        }

        if total > MAX_SOMPI {
            return Err(TxRuleError::InputAmountTooHigh);
        }
    }

    Ok(total)
}

/// The outputs must not be worth more than the inputs. A zero fee passes.
///
/// tx_validation_in_utxo_context.rs:116-124.
pub fn check_transaction_output_values(tx: &impl VerifiableTransaction, total_in: u64) -> TxResult<u64> {
    // There's no need to check for overflow here because it was already checked by check_transaction_output_value_ranges
    let total_out: u64 = tx.outputs().iter().map(|out| out.value).sum();
    if total_in < total_out {
        return Err(TxRuleError::SpendTooHigh(total_out, total_in));
    }

    Ok(total_out)
}

/// The storage mass the transaction commits to must equal the calculated one.
///
/// tx_validation_in_utxo_context.rs:126-134.
pub fn check_mass_commitment(gate: &GateParams, tx: &impl VerifiableTransaction) -> TxResult<()> {
    let calculated_contextual_mass =
        gate.mass_calculator().calc_contextual_masses(tx).ok_or(TxRuleError::MassIncomputable)?.storage_mass;
    let committed_contextual_mass = tx.tx().storage_mass();
    if committed_contextual_mass != calculated_contextual_mass {
        return Err(TxRuleError::WrongMass(calculated_contextual_mass, committed_contextual_mass));
    }
    Ok(())
}

/// Relative lock of every input whose sequence does not disable it.
///
/// tx_validation_in_utxo_context.rs:136-161.
pub fn check_sequence_lock(tx: &impl VerifiableTransaction, pov_daa_score: u64) -> TxResult<()> {
    let pov_daa_score: i64 = pov_daa_score as i64;
    if tx.populated_inputs().filter(|(input, _)| input.sequence & SEQUENCE_LOCK_TIME_DISABLED != SEQUENCE_LOCK_TIME_DISABLED).any(
        |(input, entry)| {
            // Given a sequence number, we apply the relative time lock
            // mask in order to obtain the time lock delta required before
            // this input can be spent.
            let relative_lock = (input.sequence & SEQUENCE_LOCK_TIME_MASK) as i64;

            // The relative lock-time for this input is expressed
            // in blocks so we calculate the relative offset from
            // the input's DAA score as its converted absolute
            // lock-time. We subtract one from the relative lock in
            // order to maintain the original lockTime semantics.
            let lock_daa_score = entry.block_daa_score as i64 + relative_lock - 1;

            lock_daa_score >= pov_daa_score
        },
    ) {
        return Err(TxRuleError::SequenceLockConditionsAreNotMet);
    }
    Ok(())
}

/// Builds the covenant context with the engine crate's own `CovenantsContext::from_tx`
/// (crypto/txscript/src/covenants.rs:101-163) once Toccata is active; before that the
/// context is empty and bindings are not looked at.
///
/// tx_validation_in_utxo_context.rs:177-183.
pub fn check_covenant_info(gate: &GateParams, tx: &impl VerifiableTransaction, block_daa_score: u64) -> TxResult<CovenantsContext> {
    if !gate.params.toccata_activation.is_active(block_daa_score) {
        return Ok(Default::default());
    }

    Ok(CovenantsContext::from_tx(tx)?)
}

/// Builds the engine context and the node's flags, and checks the script of every input.
///
/// tx_validation_in_utxo_context.rs:163-175. The signature cache is local to the call (a
/// node keeps one per validator) and no `SeqCommitAccessor` is attached. Upstream then
/// picks the parallel path for more than one input (lines 186-194); here the sequential
/// path is taken for any number of inputs.
pub fn check_scripts(
    gate: &GateParams,
    tx: &impl VerifiableTransaction,
    covenants_ctx: CovenantsContext,
    block_daa_score: u64,
) -> TxResult<()> {
    let sig_cache: Cache<SigCacheKey, bool> = Cache::new(SIG_CACHE_SIZE);
    let ctx = EngineCtx::new(&sig_cache).with_covenants_ctx(&covenants_ctx);
    let covenants_enabled = gate.params.toccata_activation.is_active(block_daa_score);
    let flags: EngineFlags = EngineFlags { covenants_enabled, sigop_script_units: Gram(gate.params.mass_per_sig_op).into() };

    let reused_values = SigHashReusedValuesUnsync::new();
    check_scripts_sequential(tx, ctx.with_reused(&reused_values), flags)
}

/// Runs every input on the script engine under the limit its own compute commitment
/// allows, and returns the first failure.
///
/// tx_validation_in_utxo_context.rs:196-204.
pub fn check_scripts_sequential(tx: &impl VerifiableTransaction, ctx: EngineCtxUnsync<'_>, flags: EngineFlags) -> TxResult<()> {
    for (i, (input, entry)) in tx.populated_inputs().enumerate() {
        let script_units_limit = input.compute_commit.allowed_script_units();
        let mut vm =
            TxScriptEngine::from_transaction_input_with_script_units_limit(tx, input, i, entry, ctx, flags, script_units_limit);
        vm.execute().map_err(|err| map_script_err(err, input))?;
    }
    Ok(())
}

/// A script failure is reported as `SignatureEmpty` when the input carries no signature
/// script at all, as `SignatureInvalid` otherwise.
///
/// tx_validation_in_utxo_context.rs:225-227.
pub fn map_script_err(script_err: TxScriptError, input: &TransactionInput) -> TxRuleError {
    if input.signature_script.is_empty() { TxRuleError::SignatureEmpty(script_err) } else { TxRuleError::SignatureInvalid(script_err) }
}
