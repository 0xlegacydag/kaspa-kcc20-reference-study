//! The block-level mass and gas limits, applied to one transaction.
//!
//! Consensus has no per-transaction mass limit. A transaction is bound by the limits of
//! the block that must contain it: the node sums compute mass, transient mass and the
//! committed storage mass over the block's transactions and compares each sum with its
//! limit, and it sums gas per subnetwork lane.
//!
//! Source: rusty-kaspa a41a333
//! consensus/src/pipeline/body_processor/body_validation_in_isolation.rs:67-121
//! (ISC License, Copyright (c) 2022-2024 Kaspa developers). The port keeps the comparisons
//! and drops the loop: it answers for a block that holds this transaction next to its
//! coinbase, whose masses are zero. Limits that only several transactions can break (the
//! sums themselves, fifty lanes per block) are not modelled.

use kaspa_consensus_core::{mass::NonContextualMasses, subnets::SubnetworkId, tx::Transaction};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::params::GateParams;

/// A block holding only this transaction would break a block limit. The variants mirror
/// `RuleError::Exceeds*` of `kaspa_consensus_core::errors::block` (lines 103-116) field by
/// field and word by word, so that the debug and display texts are those of a node; the
/// upstream type itself cannot be compared for equality.
#[derive(Clone, Debug, PartialEq, Eq, Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockMassError {
    #[error("block compute mass {0} exceeds limit of {1}")]
    ExceedsComputeMassLimit(u64, u64),
    #[error("block transient storage mass {0} exceeds limit of {1}")]
    ExceedsTransientMassLimit(u64, u64),
    #[error("block persistent storage mass {0} exceeds limit of {1}")]
    ExceedsStorageMassLimit(u64, u64),
    #[error("block lane {0} gas {1} exceeds limit of {2}")]
    ExceedsGasPerLaneLimit(SubnetworkId, u64, u64),
}

/// Compares the transaction's own masses and gas with the limits of the block that
/// contains it. The storage mass used is the one the transaction commits to; whether the
/// commitment is right is a UTXO-context rule.
///
/// body_validation_in_isolation.rs:67-121. Call it after the in-isolation rules passed, as
/// the node does (line 21-22): the mass calculator panics on a compute commitment that
/// does not match the transaction version.
pub fn check_block_mass(gate: &GateParams, tx: &Transaction) -> Result<(), BlockMassError> {
    let block_mass_limits = gate.params.block_mass_limits().get(gate.block_daa_score);

    // Calculate the non-contextual masses
    let NonContextualMasses { compute_mass, transient_mass } = gate.mass_calculator().calc_non_contextual_masses(tx);

    // Read the storage mass commitment. This value cannot be computed here w/o UTXO context
    // so we use the commitment.
    let storage_mass_commitment = tx.storage_mass();

    // Verify each dimension against its own limit
    if compute_mass > block_mass_limits.compute {
        return Err(BlockMassError::ExceedsComputeMassLimit(compute_mass, block_mass_limits.compute));
    }
    if transient_mass > block_mass_limits.transient {
        return Err(BlockMassError::ExceedsTransientMassLimit(transient_mass, block_mass_limits.transient));
    }
    if storage_mass_commitment > block_mass_limits.storage {
        return Err(BlockMassError::ExceedsStorageMassLimit(storage_mass_commitment, block_mass_limits.storage));
    }

    if !tx.is_coinbase() && tx.gas > gate.params.block_lane_limits.gas_per_lane {
        return Err(BlockMassError::ExceedsGasPerLaneLimit(tx.subnetwork_id, tx.gas, gate.params.block_lane_limits.gas_per_lane));
    }
    Ok(())
}
