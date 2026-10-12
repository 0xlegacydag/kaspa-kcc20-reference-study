//! Network parameters and the point in time the gate answers for.
//!
//! Every number comes from `kaspa_consensus_core::config::params` at the pinned revision;
//! nothing is copied here. The gate only adds the DAA scores and the past median time a node
//! would take from its own chain state.

use kaspa_consensus_core::{
    config::params::{MAINNET_PARAMS, Params, TESTNET_PARAMS},
    mass::{Gram, MassCalculator},
};
use kaspa_txscript::EngineFlags;

/// How far after the Toccata activation score the default "now" is placed.
///
/// It must be larger than the 864,000 DAA delay after which the mempool adopts the
/// post-activation transient mass limit (rusty-kaspa a41a333
/// consensus/core/src/config/params.rs:20, 436-454), so that with the defaults every
/// post-Toccata rule is in force. Ten million DAA scores are about eleven and a half days
/// at ten blocks per second.
pub const DEFAULT_DAA_MARGIN_AFTER_TOCCATA: u64 = 10_000_000;

/// Default past median time in milliseconds. A fixed number, not a clock: it is only
/// compared with lock times that are at or above `LOCK_TIME_THRESHOLD`.
pub const DEFAULT_PAST_MEDIAN_TIME_MS: u64 = 1_780_000_000_000;

/// Consensus parameters plus the chain context of one question to the gate.
#[derive(Clone, Debug)]
pub struct GateParams {
    /// Consensus parameters of the network.
    pub params: Params,
    /// DAA score from whose point of view the transaction is accepted. In a mempool this
    /// is the virtual DAA score. Used by coinbase maturity and the sequence lock.
    ///
    /// Never set it to `u64::MAX`: the sequence lock casts it to `i64`
    /// (tx_validation_in_utxo_context.rs:137), which turns that value into -1.
    pub pov_daa_score: u64,
    /// DAA score of the block that contains the transaction. In a mempool it equals
    /// `pov_daa_score` (rusty-kaspa a41a333
    /// consensus/src/pipeline/virtual_processor/utxo_validation.rs:480-487). It decides
    /// which side of the Toccata fork the header rules, the covenant rules and the script
    /// engine are on.
    pub block_daa_score: u64,
    /// Past median time in milliseconds, compared with time based lock times.
    pub past_median_time: u64,
}

impl GateParams {
    /// Testnet-10 (`TESTNET_PARAMS`), well after Toccata activation.
    pub fn testnet10() -> Self {
        Self::after_toccata(TESTNET_PARAMS)
    }

    /// Mainnet (`MAINNET_PARAMS`), well after Toccata activation.
    pub fn mainnet() -> Self {
        Self::after_toccata(MAINNET_PARAMS)
    }

    /// The given parameters with "now" set `DEFAULT_DAA_MARGIN_AFTER_TOCCATA` after their
    /// Toccata activation score. For a network that never activates Toccata the score
    /// saturates below `u64::MAX` and stays inactive; for one that always has it, the
    /// score is simply the margin.
    pub fn after_toccata(params: Params) -> Self {
        let now = params.toccata_activation.daa_score().saturating_add(DEFAULT_DAA_MARGIN_AFTER_TOCCATA).min(i64::MAX as u64);
        Self { params, pov_daa_score: now, block_daa_score: now, past_median_time: DEFAULT_PAST_MEDIAN_TIME_MS }
    }

    /// Sets both DAA scores, as in a mempool where the transaction is judged at the
    /// virtual DAA score.
    pub fn with_daa_score(mut self, daa_score: u64) -> Self {
        self.pov_daa_score = daa_score;
        self.block_daa_score = daa_score;
        self
    }

    /// Sets the past median time (milliseconds).
    pub fn with_past_median_time(mut self, past_median_time: u64) -> Self {
        self.past_median_time = past_median_time;
        self
    }

    /// Whether Toccata rules apply to the block that contains the transaction.
    pub fn toccata_active(&self) -> bool {
        self.params.toccata_activation.is_active(self.block_daa_score)
    }

    /// The engine flags a node builds for script checks: covenants follow the fork, and a
    /// signature check is priced from `mass_per_sig_op`
    /// (rusty-kaspa a41a333
    /// consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs:171-172).
    ///
    /// `EngineFlags::default()` is not this: its `covenants_enabled` is false.
    pub fn engine_flags(&self) -> EngineFlags {
        EngineFlags { covenants_enabled: self.toccata_active(), sigop_script_units: Gram(self.params.mass_per_sig_op).into() }
    }

    /// The mass calculator a node builds from its parameters
    /// (rusty-kaspa a41a333 consensus/src/consensus/services.rs:133-134).
    pub fn mass_calculator(&self) -> MassCalculator {
        MassCalculator::new_with_consensus_params(&self.params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_after_every_toccata_switch() {
        for gate in [GateParams::testnet10(), GateParams::mainnet()] {
            assert!(gate.toccata_active());
            assert_eq!(gate.pov_daa_score, gate.block_daa_score);
            assert!(gate.pov_daa_score < i64::MAX as u64);
            // The mempool's delayed transient limit is already the post-activation one.
            assert_eq!(gate.params.mempool_block_mass_limits().get(gate.pov_daa_score).transient, 1_000_000);
            let flags = gate.engine_flags();
            assert!(flags.covenants_enabled);
            assert_eq!(flags.sigop_script_units.0, 100_000);
        }
    }

    #[test]
    fn network_constants_are_the_pinned_ones() {
        assert_eq!(GateParams::testnet10().params.toccata_activation.daa_score(), 467_579_632);
        assert_eq!(GateParams::mainnet().params.toccata_activation.daa_score(), 474_165_565);
    }
}
