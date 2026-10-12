//! Review of the network the numbers are measured on: testnet-10, and whether mainnet
//! would give the same ones.
//!
//! The test harness answers for testnet-10 parameters ten million DAA scores after the Toccata
//! activation (`Harness::pinned`, `GateParams::testnet10`). At rusty-kaspa a41a333 every
//! parameter that a transaction's size, masses, budgets, limits or fee floor depend on has
//! the same value on mainnet (consensus/core/src/config/params.rs:653-725 against
//! :727-786); the two networks differ in the DAA score at which Toccata activates, which
//! shifts every switch by the same amount.

use checks::{Harness, Outcome};
use kaspa_consensus_core::{
    config::params::{MAINNET_PARAMS, Params, TESTNET_PARAMS},
    mass::NonContextualMasses,
};
use kcc20_family::{
    Scenario,
    keys::FUNDER,
    shapes::{self, Profile, Realistic, SOMPI_PER_KAS},
};
use node_gate::{
    GateParams,
    policy::{self, Priority},
};

/// Every parameter the mass calculator, the block limits, the mempool limits and the
/// in-isolation size rules read, as one comparable value.
fn transaction_parameters(params: &Params) -> impl PartialEq + std::fmt::Debug {
    (
        (
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.prior_max_signature_script_len,
            params.new_max_signature_script_len,
            params.max_script_public_key_len,
        ),
        (
            params.mass_per_tx_byte,
            params.mass_per_script_pub_key_byte,
            params.mass_per_sig_op,
            params.storage_mass_parameter,
        ),
        (
            params.prior_block_mass_limits,
            params.new_transient_mass_limit,
            params.block_lane_limits,
        ),
        (
            params.target_time_per_block(),
            params.bps(),
            params.coinbase_maturity(),
        ),
    )
}

#[test]
fn testnet_10_and_mainnet_have_the_same_transaction_parameters() {
    assert_eq!(
        transaction_parameters(&TESTNET_PARAMS),
        transaction_parameters(&MAINNET_PARAMS)
    );
    // The values themselves (config/params.rs:686-702, 748-764).
    let params = &TESTNET_PARAMS;
    assert_eq!((params.max_tx_inputs, params.max_tx_outputs), (1000, 1000));
    assert_eq!(
        (
            params.prior_max_signature_script_len,
            params.new_max_signature_script_len,
            params.max_script_public_key_len
        ),
        (10_000, 250_000, 10_000)
    );
    assert_eq!(
        (
            params.mass_per_tx_byte,
            params.mass_per_script_pub_key_byte,
            params.mass_per_sig_op,
            params.storage_mass_parameter
        ),
        (1, 10, 1000, 1_000_000_000_000)
    );
    assert_eq!(
        (
            params.block_lane_limits.lanes_per_block,
            params.block_lane_limits.gas_per_lane
        ),
        (50, 1_000_000_000)
    );
    assert_eq!(params.bps(), 10);

    // What differs: the name and the activation score.
    assert_eq!(TESTNET_PARAMS.network_name(), "kaspa-testnet-10");
    assert_eq!(MAINNET_PARAMS.network_name(), "kaspa-mainnet");
    assert_eq!(TESTNET_PARAMS.toccata_activation.daa_score(), 467_579_632);
    assert_eq!(MAINNET_PARAMS.toccata_activation.daa_score(), 474_165_565);
}

/// The limits and switches, at the same distance from each network's activation.
#[test]
fn the_limits_switch_at_the_same_distance_from_the_activation() {
    for params in [TESTNET_PARAMS, MAINNET_PARAMS] {
        let name = params.network_name();
        let activation = params.toccata_activation.daa_score();
        let block = |distance: i64| {
            let limits = params
                .block_mass_limits()
                .get(activation.wrapping_add_signed(distance));
            (limits.compute, limits.transient, limits.storage)
        };
        let mempool = |distance: i64| {
            let limits = params
                .mempool_block_mass_limits()
                .get(activation.wrapping_add_signed(distance));
            (limits.compute, limits.transient, limits.storage)
        };
        let cap = |distance: i64| {
            policy::standard_transaction_mass_cap(&params, activation.wrapping_add_signed(distance))
        };

        // A block: the transient limit doubles at activation.
        assert_eq!(block(-1), (500_000, 500_000, 500_000), "{name}");
        assert_eq!(block(0), (500_000, 1_000_000, 500_000), "{name}");
        // The mempool follows one day (864,000 scores at ten per second) later.
        assert_eq!(mempool(863_999), (500_000, 500_000, 500_000), "{name}");
        assert_eq!(mempool(864_000), (500_000, 1_000_000, 500_000), "{name}");
        // The standard cap of 100,000 is lifted thirty minutes (18,000 scores) before.
        assert_eq!(cap(-18_001), Some(100_000), "{name}");
        assert_eq!(cap(-18_000), None, "{name}");

        // The fee floor: 1 sompi per gram of compute mass for a relayed transaction until
        // activation, 100 per gram of the larger of compute and half the transient mass
        // for everything else.
        let masses = NonContextualMasses::new(1_000, 4_000);
        let terms = |priority: Priority, distance: i64| {
            policy::minimum_relay_fee_terms(
                &params,
                masses,
                priority,
                activation.wrapping_add_signed(distance),
            )
        };
        assert_eq!(terms(Priority::Low, -1), (1_000, 1_000, 1_000), "{name}");
        assert_eq!(terms(Priority::Low, 0), (2_000, 100_000, 200_000), "{name}");
        assert_eq!(
            terms(Priority::High, -1),
            (2_000, 100_000, 200_000),
            "{name}"
        );
        assert_eq!(
            terms(Priority::High, 0),
            (2_000, 100_000, 200_000),
            "{name}"
        );
    }

    // The default "now" of both gates is past every one of these switches.
    for gate in [GateParams::testnet10(), GateParams::mainnet()] {
        let activation = gate.params.toccata_activation.daa_score();
        assert_eq!(gate.pov_daa_score, activation + 10_000_000);
        assert_eq!(gate.block_daa_score, gate.pov_daa_score);
        assert!(gate.pov_daa_score >= activation + 864_000);
    }
}

/// What the measurement would report for one shape.
fn numbers(outcome: &Outcome) -> impl PartialEq + std::fmt::Debug {
    let masses = outcome.masses.as_ref().expect("masses");
    let used: Vec<Option<u64>> = outcome
        .inputs
        .iter()
        .map(|input| input.alone.as_ref().map(|run| run.used_script_units))
        .collect();
    let refused: Vec<String> = outcome
        .mempool
        .refused
        .iter()
        .map(|finding| finding.function.clone())
        .collect();
    (
        (
            masses.estimated_size,
            masses.compute_mass,
            masses.transient_mass,
            masses.calculated_storage_mass,
        ),
        (used, outcome.minimal_budgets()),
        (
            outcome.mempool.fee,
            outcome.mempool.minimum_fee,
            outcome.mempool.fee_mass,
            outcome.mempool.p2sh_sig_ops.clone(),
        ),
        (
            outcome.scripts_accept(),
            outcome.consensus.accepted,
            outcome.consensus.block.accepted,
            outcome.mempool.accepted,
            refused,
        ),
    )
}

/// The same scenario on both networks gives the same numbers and the same answers.
fn assert_same_on_mainnet(scenario: &Scenario) {
    let testnet = Harness::pinned().run(scenario);
    let mainnet = Harness::pinned()
        .with_node(GateParams::mainnet())
        .run(scenario);
    assert_eq!(testnet.network, "kaspa-testnet-10");
    assert_eq!(mainnet.network, "kaspa-mainnet");
    // The transaction is the same one: its id does not depend on the network.
    assert_eq!(testnet.tx_id, mainnet.tx_id, "{}", scenario.name);
    assert_eq!(
        format!("{:?}", numbers(&testnet)),
        format!("{:?}", numbers(&mainnet)),
        "{}",
        scenario.name
    );
}

#[test]
fn every_honest_shape_measures_the_same_on_mainnet() {
    for profile in [Profile::Script, Profile::Realistic(Realistic::default())] {
        let scenarios = shapes::all(&profile);
        assert_eq!(scenarios.len(), 29);
        for scenario in &scenarios {
            assert_same_on_mainnet(scenario);
        }
    }
}

#[test]
fn the_smallest_token_coin_is_the_same_on_mainnet() {
    let transfer = |token_coin_value: u64| {
        shapes::transfer(
            &Profile::Realistic(Realistic {
                coin_value: token_coin_value,
                funding_value: 100 * SOMPI_PER_KAS,
                fee: 925_000,
                funding_key: FUNDER,
            }),
            1,
            1,
        )
    };
    let mainnet = Harness::pinned().with_node(GateParams::mainnet());

    let at = mainnet.run(&transfer(7_987_253));
    assert!(at.consensus.block.accepted && at.mempool.accepted);
    let below = mainnet.run(&transfer(7_987_252));
    assert!(!below.consensus.block.accepted && !below.mempool.accepted);
    assert_eq!(
        below.mempool.first_refusal.as_ref().unwrap().rule,
        "check_storage_mass_limit"
    );
    assert_same_on_mainnet(&transfer(7_987_253));
    assert_same_on_mainnet(&transfer(7_987_252));
}
