//! What a default node's mempool requires on top of consensus: the block-fit limits and
//! the standardness rules.
//!
//! Source: rusty-kaspa a41a333 mining/src/mempool/check_transaction_limits.rs:14-52,
//! mining/src/mempool/check_transaction_standard.rs:19-181,
//! mining/src/mempool/config.rs:23, 28 and, for the texts of the refusals,
//! mining/errors/src/mempool.rs:47-57, 116-155 (ISC License, Copyright (c) 2022-2024 Kaspa
//! developers). None of this is consensus.
//!
//! Upstream has four functions. Here every rule is a function of its own so that a report
//! can name it, and the four upstream functions call them in the upstream order. The
//! mempool configuration is the one the daemon builds (kaspad/src/daemon.rs:643-651 and
//! `Config::build_default`, config.rs:102-134): limits from
//! `Params::mempool_block_mass_limits`, lane limits from `Params::block_lane_limits`,
//! standardness always on.

use kaspa_consensus_core::{
    config::params::Params,
    constants::{MAX_SCRIPT_PUBLIC_KEY_VERSION, MAX_SOMPI},
    mass::NonContextualMasses,
    tx::{Transaction, UtxoEntry},
};
use kaspa_txscript::{post_toccata_p2sh_sig_scanner, script_class::ScriptClass};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The most signature operations a pay-to-script-hash redeem script may contain to be
/// standard. check_transaction_standard.rs:19.
pub const MAX_STANDARD_P2SH_SIG_OPS: u16 = 15;

/// Per-dimension mass cap of a standard transaction before Toccata.
/// check_transaction_standard.rs:26.
pub const MAXIMUM_STANDARD_TRANSACTION_MASS_PRE_TOCCATA: u64 = 100_000;

/// Seconds before Toccata activation at which that cap is lifted.
/// check_transaction_standard.rs:31.
pub const STANDARD_MASS_RELAXATION_WINDOW_SECONDS: u64 = 30 * 60;

/// Minimum relay fee in sompi per 1000 grams of mass. config.rs:23.
pub const DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE: u64 = 100_000;

/// Minimum relay fee before Toccata, for transactions relayed by peers. config.rs:28.
pub const LEGACY_MINIMUM_RELAY_TRANSACTION_FEE: u64 = 1_000;

/// How the transaction reached the mempool. An RPC submission is `High`; a transaction
/// relayed by a peer is `Low` (mining/src/manager.rs:296-342,
/// protocol/flows/src/flow_context.rs:681-698).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Low,
    High,
}

/// A refusal by the mempool. The first four are block-fit limits
/// (`RuleError::Reject*`, mining/errors/src/mempool.rs:47-57), never skipped; the rest are
/// standardness (`NonStandardError::Reject*`, mempool.rs:116-155), which the daemon always
/// applies. The transaction id that the upstream errors carry is left out.
#[derive(Clone, Debug, PartialEq, Eq, Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRefusal {
    #[error("transaction gas of {gas} is larger than max allowed per-lane gas of {limit}")]
    Gas { gas: u64, limit: u64 },
    #[error("transaction compute mass of {mass} is larger than max allowed size of {limit}")]
    ComputeMass { mass: u64, limit: u64 },
    #[error("transaction transient (storage) mass of {mass} is larger than max allowed size of {limit}")]
    TransientMass { mass: u64, limit: u64 },
    #[error("transaction storage mass of {mass} is larger than max allowed size of {limit}")]
    StorageMass { mass: u64, limit: u64 },

    #[error("non-standard: transaction compute mass of {mass} is larger than max allowed size of {cap}")]
    StandardComputeMass { mass: u64, cap: u64 },
    #[error("non-standard: transaction transient (storage) mass of {mass} is larger than max allowed size of {cap}")]
    StandardTransientMass { mass: u64, cap: u64 },
    #[error("non-standard: transaction storage mass of {mass} is larger than max allowed size of {cap}")]
    StandardStorageMass { mass: u64, cap: u64 },
    #[error("non-standard: transaction output #{output}: the version of the scriptPublicKey is higher than the known version")]
    ScriptPublicKeyVersion { output: usize },
    #[error("non-standard: transaction output #{output}: non-standard script form")]
    OutputScriptClass { output: usize },
    #[error("non-standard: transaction input {input}: non-standard script form")]
    InputScriptClass { input: usize },
    #[error(
        "non-standard: transaction input #{input} has {found} signature operations which is more than the allowed max amount of {max}"
    )]
    SignatureCount { input: usize, found: u64, max: u16 },
    #[error(
        "non-standard: transaction has {fee} fees which is under the required amount of {minimum_fee} for compute mass {compute_mass}"
    )]
    InsufficientComputeFee { fee: u64, minimum_fee: u64, compute_mass: u64 },
    #[error(
        "non-standard: transaction has {fee} fees which is under the required amount of {minimum_fee} for normalized transient mass {normalized_transient_mass} (proportional to transaction byte size)"
    )]
    InsufficientTransientFee { fee: u64, minimum_fee: u64, normalized_transient_mass: u64 },
}

impl PolicyRefusal {
    /// The upstream error variant this refusal stands for.
    pub fn upstream_error(&self) -> &'static str {
        match self {
            Self::Gas { .. } => "RuleError::RejectGas",
            Self::ComputeMass { .. } => "RuleError::RejectComputeMass",
            Self::TransientMass { .. } => "RuleError::RejectTransientMass",
            Self::StorageMass { .. } => "RuleError::RejectStorageMass",
            Self::StandardComputeMass { .. } => "NonStandardError::RejectComputeMass",
            Self::StandardTransientMass { .. } => "NonStandardError::RejectTransientMass",
            Self::StandardStorageMass { .. } => "NonStandardError::RejectStorageMass",
            Self::ScriptPublicKeyVersion { .. } => "NonStandardError::RejectScriptPublicKeyVersion",
            Self::OutputScriptClass { .. } => "NonStandardError::RejectOutputScriptClass",
            Self::InputScriptClass { .. } => "NonStandardError::RejectInputScriptClass",
            Self::SignatureCount { .. } => "NonStandardError::RejectSignatureCount",
            Self::InsufficientComputeFee { .. } => "NonStandardError::RejectInsufficientComputeFee",
            Self::InsufficientTransientFee { .. } => "NonStandardError::RejectInsufficientTransientFee",
        }
    }

    /// Whether this is a standardness rule (skipped by a node that accepts non-standard
    /// transactions) rather than a block-fit limit.
    pub fn is_standardness(&self) -> bool {
        !matches!(self, Self::Gas { .. } | Self::ComputeMass { .. } | Self::TransientMass { .. } | Self::StorageMass { .. })
    }

    /// The named rule that gives this refusal.
    pub fn rule(&self) -> PolicyRule {
        match self {
            Self::Gas { .. } => PolicyRule::GasLimit,
            Self::ComputeMass { .. } => PolicyRule::ComputeMassLimit,
            Self::TransientMass { .. } => PolicyRule::TransientMassLimit,
            Self::StorageMass { .. } => PolicyRule::StorageMassLimit,
            Self::StandardComputeMass { .. } => PolicyRule::StandardComputeMassCap,
            Self::StandardTransientMass { .. } => PolicyRule::StandardTransientMassCap,
            Self::StandardStorageMass { .. } => PolicyRule::StandardStorageMassCap,
            Self::ScriptPublicKeyVersion { .. } | Self::OutputScriptClass { .. } => PolicyRule::OutputScriptsStandard,
            Self::InputScriptClass { .. } | Self::SignatureCount { .. } => PolicyRule::InputScriptsStandard,
            Self::InsufficientComputeFee { .. } | Self::InsufficientTransientFee { .. } => PolicyRule::MinimumRelayFee,
        }
    }
}

pub type PolicyResult<T> = Result<T, PolicyRefusal>;

/// The named mempool rules, in the order a node applies them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRule {
    /// `check_gas_limit`
    GasLimit,
    /// `check_compute_mass_limit`
    ComputeMassLimit,
    /// `check_transient_mass_limit`
    TransientMassLimit,
    /// `check_standard_compute_mass_cap`
    StandardComputeMassCap,
    /// `check_standard_transient_mass_cap`
    StandardTransientMassCap,
    /// `check_output_scripts_standard`
    OutputScriptsStandard,
    /// `check_storage_mass_limit`
    StorageMassLimit,
    /// `check_standard_storage_mass_cap`
    StandardStorageMassCap,
    /// `check_input_scripts_standard`
    InputScriptsStandard,
    /// `check_minimum_relay_fee`
    MinimumRelayFee,
}

impl PolicyRule {
    /// The rules checked before the consensus validation, in order
    /// (mining/src/mempool/validate_and_insert_transaction.rs:32-33).
    ///
    /// The two lists order the rule-by-rule report of `gate::evaluate`. The node's own
    /// answer, the first refusal, is not read from them: it comes from the composed
    /// ports (`validate_transaction_limits_in_isolation` and the three functions after
    /// it), which keep the upstream order in their bodies.
    pub const BEFORE_CONSENSUS: [PolicyRule; 6] = [
        PolicyRule::GasLimit,
        PolicyRule::ComputeMassLimit,
        PolicyRule::TransientMassLimit,
        PolicyRule::StandardComputeMassCap,
        PolicyRule::StandardTransientMassCap,
        PolicyRule::OutputScriptsStandard,
    ];

    /// The rules checked after the consensus validation, in order
    /// (validate_and_insert_transaction.rs:76-77).
    pub const AFTER_CONSENSUS: [PolicyRule; 4] = [
        PolicyRule::StorageMassLimit,
        PolicyRule::StandardStorageMassCap,
        PolicyRule::InputScriptsStandard,
        PolicyRule::MinimumRelayFee,
    ];
}

// ---------------------------------------------------------------------------------------
// Block-fit limits, before the consensus validation
// ---------------------------------------------------------------------------------------

/// Gas above the per-lane limit of a block. check_transaction_limits.rs:19-21.
pub fn check_gas_limit(params: &Params, tx: &Transaction) -> PolicyResult<()> {
    if tx.gas > params.block_lane_limits.gas_per_lane {
        return Err(PolicyRefusal::Gas { gas: tx.gas, limit: params.block_lane_limits.gas_per_lane });
    }
    Ok(())
}

/// Compute mass above what one block can hold. check_transaction_limits.rs:23-27.
pub fn check_compute_mass_limit(params: &Params, masses: NonContextualMasses, virtual_daa_score: u64) -> PolicyResult<()> {
    let limits = params.mempool_block_mass_limits().get(virtual_daa_score);
    if masses.compute_mass > limits.compute {
        return Err(PolicyRefusal::ComputeMass { mass: masses.compute_mass, limit: limits.compute });
    }
    Ok(())
}

/// Transient mass above what one block can hold. The mempool adopts the post-Toccata
/// limit one day after activation (consensus/core/src/config/params.rs:436-454).
/// check_transaction_limits.rs:23-24, 28-30.
pub fn check_transient_mass_limit(params: &Params, masses: NonContextualMasses, virtual_daa_score: u64) -> PolicyResult<()> {
    let limits = params.mempool_block_mass_limits().get(virtual_daa_score);
    if masses.transient_mass > limits.transient {
        return Err(PolicyRefusal::TransientMass { mass: masses.transient_mass, limit: limits.transient });
    }
    Ok(())
}

/// The three limits checked before scripts run. check_transaction_limits.rs:14-33.
pub fn validate_transaction_limits_in_isolation(
    params: &Params,
    tx: &Transaction,
    masses: NonContextualMasses,
    virtual_daa_score: u64,
) -> PolicyResult<()> {
    check_gas_limit(params, tx)?;
    check_compute_mass_limit(params, masses, virtual_daa_score)?;
    check_transient_mass_limit(params, masses, virtual_daa_score)
}

// ---------------------------------------------------------------------------------------
// Standardness, before the consensus validation
// ---------------------------------------------------------------------------------------

/// The per-dimension standard mass cap in effect, or `None` once it is lifted: from
/// thirty minutes before Toccata activation on.
///
/// check_transaction_standard.rs:43-47. `network_blocks_per_second` of the mempool
/// configuration is `1000 / target_time_per_block` (config.rs:132), which is
/// `Params::bps`.
pub fn standard_transaction_mass_cap(params: &Params, virtual_daa_score: u64) -> Option<u64> {
    let window = STANDARD_MASS_RELAXATION_WINDOW_SECONDS.saturating_mul(params.bps());
    let relaxation = params.toccata_activation.early_by(window);
    (!relaxation.is_active(virtual_daa_score)).then_some(MAXIMUM_STANDARD_TRANSACTION_MASS_PRE_TOCCATA)
}

/// Compute mass above the standard cap, while the cap is in effect.
/// check_transaction_standard.rs:58-62.
/// The comparison stays nested in the `if let`, as upstream writes it.
#[allow(clippy::collapsible_if)]
pub fn check_standard_compute_mass_cap(params: &Params, masses: NonContextualMasses, virtual_daa_score: u64) -> PolicyResult<()> {
    if let Some(cap) = standard_transaction_mass_cap(params, virtual_daa_score) {
        if masses.compute_mass > cap {
            return Err(PolicyRefusal::StandardComputeMass { mass: masses.compute_mass, cap });
        }
    }
    Ok(())
}

/// Transient mass above the standard cap, while the cap is in effect.
/// check_transaction_standard.rs:58-59, 63-65.
/// The comparison stays nested in the `if let`, as upstream writes it.
#[allow(clippy::collapsible_if)]
pub fn check_standard_transient_mass_cap(params: &Params, masses: NonContextualMasses, virtual_daa_score: u64) -> PolicyResult<()> {
    if let Some(cap) = standard_transaction_mass_cap(params, virtual_daa_score) {
        if masses.transient_mass > cap {
            return Err(PolicyRefusal::StandardTransientMass { mass: masses.transient_mass, cap });
        }
    }
    Ok(())
}

/// Every output script must have version 0 and one of the three standard forms:
/// pay-to-pubkey, pay-to-pubkey-ECDSA or pay-to-script-hash. A covenant binding on the
/// output is not looked at.
///
/// check_transaction_standard.rs:68-77.
pub fn check_output_scripts_standard(tx: &Transaction) -> PolicyResult<()> {
    // None of the output public key scripts can be a non-standard script.
    for (i, output) in tx.outputs.iter().enumerate() {
        if output.script_public_key.version() > MAX_SCRIPT_PUBLIC_KEY_VERSION {
            return Err(PolicyRefusal::ScriptPublicKeyVersion { output: i });
        }

        if ScriptClass::from_script(&output.script_public_key) == ScriptClass::NonStandard {
            return Err(PolicyRefusal::OutputScriptClass { output: i });
        }
    }
    Ok(())
}

/// The standardness checks made before scripts run.
/// check_transaction_standard.rs:49-80.
pub fn check_transaction_standard_in_isolation(
    params: &Params,
    tx: &Transaction,
    masses: NonContextualMasses,
    virtual_daa_score: u64,
) -> PolicyResult<()> {
    check_standard_compute_mass_cap(params, masses, virtual_daa_score)?;
    check_standard_transient_mass_cap(params, masses, virtual_daa_score)?;
    check_output_scripts_standard(tx)
}

// ---------------------------------------------------------------------------------------
// Block-fit limit, after the consensus validation
// ---------------------------------------------------------------------------------------

/// Storage mass above what one block can hold. `storage_mass` is the value the node
/// calculated and wrote into the transaction during the consensus validation.
///
/// check_transaction_limits.rs:40-52 (`validate_transaction_limits_in_context`).
pub fn check_storage_mass_limit(params: &Params, storage_mass: u64, virtual_daa_score: u64) -> PolicyResult<()> {
    let limits = params.mempool_block_mass_limits().get(virtual_daa_score);
    if storage_mass > limits.storage {
        return Err(PolicyRefusal::StorageMass { mass: storage_mass, limit: limits.storage });
    }
    Ok(())
}

/// The upstream name of `check_storage_mass_limit`.
pub fn validate_transaction_limits_in_context(params: &Params, storage_mass: u64, virtual_daa_score: u64) -> PolicyResult<()> {
    check_storage_mass_limit(params, storage_mass, virtual_daa_score)
}

// ---------------------------------------------------------------------------------------
// Standardness, after the consensus validation
// ---------------------------------------------------------------------------------------

/// Storage mass above the standard cap, while the cap is in effect.
/// check_transaction_standard.rs:98-103.
/// The comparison stays nested in the `if let`, as upstream writes it.
#[allow(clippy::collapsible_if)]
pub fn check_standard_storage_mass_cap(params: &Params, storage_mass: u64, virtual_daa_score: u64) -> PolicyResult<()> {
    if let Some(cap) = standard_transaction_mass_cap(params, virtual_daa_score) {
        if storage_mass > cap {
            return Err(PolicyRefusal::StandardStorageMass { mass: storage_mass, cap });
        }
    }
    Ok(())
}

/// Every spent coin must have a standard script, and the redeem script of a
/// pay-to-script-hash coin must not hold more than fifteen signature operations. The
/// count is the engine crate's own static scan (`post_toccata_p2sh_sig_scanner`,
/// crypto/txscript/src/lib.rs:260-308): every branch counts, and a script that does not
/// parse counts as zero.
///
/// check_transaction_standard.rs:105-125. `entries[i]` is the coin spent by input `i`.
/// The loop is indexed as upstream writes it.
#[allow(clippy::needless_range_loop)]
pub fn check_input_scripts_standard(tx: &Transaction, entries: &[UtxoEntry]) -> PolicyResult<()> {
    for i in 0..tx.inputs.len() {
        let entry = &entries[i];
        match ScriptClass::from_script(&entry.script_public_key) {
            ScriptClass::NonStandard => {
                return Err(PolicyRefusal::InputScriptClass { input: i });
            }
            ScriptClass::PubKey => {}
            ScriptClass::PubKeyECDSA => {}
            ScriptClass::ScriptHash => {
                // post-toccata scanner is valid pre-toccata as well
                let num_sig_ops = post_toccata_p2sh_sig_scanner(&tx.inputs[i].signature_script, &entry.script_public_key);
                if num_sig_ops > MAX_STANDARD_P2SH_SIG_OPS as u64 {
                    return Err(PolicyRefusal::SignatureCount { input: i, found: num_sig_ops, max: MAX_STANDARD_P2SH_SIG_OPS });
                }
            }
        }
    }
    Ok(())
}

/// Transient mass on the compute-mass scale, with the post-Toccata cofactor whatever the
/// activation status (`mempool_mass_cofactors.raw_post()`,
/// check_transaction_standard.rs:131-135): half the transient mass, rounded up.
pub fn normalized_transient_mass(params: &Params, masses: NonContextualMasses) -> u64 {
    let cofactors = params.mempool_block_mass_cofactors().raw_post();
    masses.normalized_transient(&cofactors)
}

/// The fee floor: mass in grams times the rate in sompi per kilogram, at least the rate
/// itself, at most `MAX_SOMPI`.
///
/// check_transaction_standard.rs:165-181.
pub fn minimum_required_transaction_relay_fee(mass: u64, minimum_relay_transaction_fee: u64) -> u64 {
    // Calculate the minimum fee for a transaction to be allowed into the
    // mempool and relayed by scaling the base fee. MinimumRelayTransactionFee is in
    // sompi/kg so multiply by mass (which is in grams) and divide by 1000 to get
    // minimum sompis.
    let mut minimum_fee = (mass * minimum_relay_transaction_fee) / 1000;

    if minimum_fee == 0 {
        minimum_fee = minimum_relay_transaction_fee;
    }

    // Set the minimum fee to the maximum possible value if the calculated
    // fee is not in the valid range for monetary amounts.
    minimum_fee = minimum_fee.min(MAX_SOMPI);

    minimum_fee
}

/// The mass the fee floor is charged on and the rate, as a node picks them: the larger
/// of compute mass and normalized transient mass at 100 sompi per gram, or, for a
/// peer-relayed transaction before Toccata, compute mass at 1 sompi per gram.
///
/// check_transaction_standard.rs:141-148. Returns `(fee_mass, relay_fee, minimum_fee)`.
pub fn minimum_relay_fee_terms(
    params: &Params,
    masses: NonContextualMasses,
    priority: Priority,
    virtual_daa_score: u64,
) -> (u64, u64, u64) {
    let normalized_transient_mass = normalized_transient_mass(params, masses);
    let use_prior_p2p_fee_rules = priority == Priority::Low && !params.toccata_activation.is_active(virtual_daa_score);
    let (fee_mass, relay_fee) = if use_prior_p2p_fee_rules {
        // Prior P2P relay-fee policy: legacy base fee over compute mass only.
        (masses.compute_mass, LEGACY_MINIMUM_RELAY_TRANSACTION_FEE)
    } else {
        (masses.compute_mass.max(normalized_transient_mass), DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE)
    };
    (fee_mass, relay_fee, minimum_required_transaction_relay_fee(fee_mass, relay_fee))
}

/// The fee must reach the floor. Storage mass is not part of it.
///
/// check_transaction_standard.rs:127-157. `fee` is the fee the consensus validation
/// calculated: spent amounts minus output values.
pub fn check_minimum_relay_fee(
    params: &Params,
    masses: NonContextualMasses,
    fee: u64,
    priority: Priority,
    virtual_daa_score: u64,
) -> PolicyResult<()> {
    let normalized_transient_mass = normalized_transient_mass(params, masses);
    let use_prior_p2p_fee_rules = priority == Priority::Low && !params.toccata_activation.is_active(virtual_daa_score);
    let (_, _, minimum_fee) = minimum_relay_fee_terms(params, masses, priority, virtual_daa_score);

    if fee < minimum_fee {
        return if use_prior_p2p_fee_rules || masses.compute_mass >= normalized_transient_mass {
            Err(PolicyRefusal::InsufficientComputeFee { fee, minimum_fee, compute_mass: masses.compute_mass })
        } else {
            Err(PolicyRefusal::InsufficientTransientFee { fee, minimum_fee, normalized_transient_mass })
        };
    }
    Ok(())
}

/// The standardness checks made after scripts ran.
/// check_transaction_standard.rs:89-161.
#[allow(clippy::too_many_arguments)]
pub fn check_transaction_standard_in_context(
    params: &Params,
    tx: &Transaction,
    entries: &[UtxoEntry],
    masses: NonContextualMasses,
    storage_mass: u64,
    fee: u64,
    priority: Priority,
    virtual_daa_score: u64,
) -> PolicyResult<()> {
    check_standard_storage_mass_cap(params, storage_mass, virtual_daa_score)?;
    check_input_scripts_standard(tx, entries)?;
    check_minimum_relay_fee(params, masses, fee, priority, virtual_daa_score)
}
