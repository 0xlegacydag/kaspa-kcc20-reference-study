//! Review of the measured numbers: the masses and the fee floor, worked out again.
//!
//! `tests/measure.rs` reports what the node's calculator says and asserts nothing about it.
//! Here the same numbers are derived a second time, without the calculator:
//!
//! - for three transactions (a funded one-to-one transfer, a mint, a three-to-three
//!   transfer) by hand, term by term, from the byte sizes and values of the transaction;
//! - for every honest shape in every value profile by the formulas written out once more
//!   in this file, in 128-bit arithmetic.
//!
//! The formulas are those of rusty-kaspa a41a333 consensus/core/src/mass/mod.rs: size
//! :21-78, plurality :83-100, compute and transient mass :335-370, storage mass :439-513;
//! the fee floor is mining/src/mempool/check_transaction_standard.rs:133-148, 165-181.

use checks::{Harness, Outcome, run};
use kaspa_consensus_core::{
    mass::{SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT, free_script_units_per_input},
    tx::{Transaction, UtxoEntry},
};
use kcc20_family::{
    Scenario,
    shapes::{self, Profile, Realistic, SOMPI_PER_KAS},
};
use node_gate::policy::{self, PolicyRefusal, PolicyRule};

/// The storage mass parameter: 10,000 KAS in sompi (consensus/core/src/constants.rs:31).
const C: u128 = 1_000_000_000_000;

/// Estimated serialized size of a version 1 transaction (mass/mod.rs:21-78).
fn size_by_hand(tx: &Transaction) -> u64 {
    assert_eq!(
        tx.version, 1,
        "the formula below is the version 1 one: two bytes of budget per input"
    );
    // version 2, input count 8, output count 8, lock time 8, subnetwork 20, gas 8,
    // payload hash 32, payload length 8
    let frame = 2 + 8 + 8 + 8 + 20 + 8 + 32 + 8;
    // outpoint 32 + 4, script length 8, script, sequence 8, compute budget 2
    let inputs: u64 = tx
        .inputs
        .iter()
        .map(|input| 36 + 8 + input.signature_script.len() as u64 + 8 + 2)
        .sum();
    // value 8, script version 2, script length 8, script; with a covenant binding the
    // authorizing input 2 and the covenant id 32
    let outputs: u64 = tx
        .outputs
        .iter()
        .map(|output| {
            let binding = if output.covenant.is_some() { 34 } else { 0 };
            8 + 2 + 8 + output.script_public_key.script().len() as u64 + binding
        })
        .sum();
    frame + inputs + outputs + tx.payload.len() as u64
}

/// Compute mass of a version 1 transaction: one gram per byte, ten per byte of output
/// script (with its two version bytes), a hundred per committed budget unit
/// (mass/mod.rs:340-366 with the parameters of config/params.rs:695-697).
fn compute_by_hand(tx: &Transaction) -> u64 {
    let scripts: u64 = tx
        .outputs
        .iter()
        .map(|output| 2 + output.script_public_key.script().len() as u64)
        .sum();
    let budgets: u64 = tx
        .inputs
        .iter()
        .map(|input| {
            u64::from(
                input
                    .compute_commit
                    .compute_budget()
                    .expect("a version 1 input commits a budget"),
            )
        })
        .sum();
    size_by_hand(tx) + 10 * scripts + 100 * budgets
}

/// Storage units of a coin: 63 fixed bytes, the script, 32 more with a covenant id, in
/// units of 100 bytes rounded up (mass/mod.rs:83-100).
fn plurality_by_hand(script_len: usize, bound: bool) -> u128 {
    let bytes = 63 + script_len as u128 + if bound { 32 } else { 0 };
    bytes.div_ceil(100)
}

/// Storage mass from `(plurality, amount)` pairs (mass/mod.rs:439-513).
fn storage_by_hand(inputs: &[(u128, u128)], outputs: &[(u128, u128)]) -> u128 {
    let harmonic = |cells: &[(u128, u128)]| -> u128 {
        cells
            .iter()
            .map(|(plurality, amount)| C * plurality * plurality / amount)
            .sum()
    };
    let outs_plurality: u128 = outputs.iter().map(|(plurality, _)| plurality).sum();
    let ins_plurality: u128 = inputs.iter().map(|(plurality, _)| plurality).sum();
    let relaxed =
        outs_plurality == 1 || ins_plurality == 1 || (outs_plurality == 2 && ins_plurality == 2);
    let credit = if relaxed {
        harmonic(inputs)
    } else {
        let sum_ins: u128 = inputs.iter().map(|(_, amount)| amount).sum();
        let mean_ins = (sum_ins / ins_plurality).max(1);
        ins_plurality * (C / mean_ins)
    };
    harmonic(outputs).saturating_sub(credit)
}

fn storage_of(tx: &Transaction, coins: &[UtxoEntry]) -> u64 {
    let inputs: Vec<(u128, u128)> = coins
        .iter()
        .map(|coin| {
            (
                plurality_by_hand(
                    coin.script_public_key.script().len(),
                    coin.covenant_id.is_some(),
                ),
                u128::from(coin.amount),
            )
        })
        .collect();
    let outputs: Vec<(u128, u128)> = tx
        .outputs
        .iter()
        .map(|output| {
            (
                plurality_by_hand(
                    output.script_public_key.script().len(),
                    output.covenant.is_some(),
                ),
                u128::from(output.value),
            )
        })
        .collect();
    u64::try_from(storage_by_hand(&inputs, &outputs)).expect("a storage mass that fits 64 bits")
}

/// The mass the fee floor is charged on and the floor itself, after Toccata: the larger
/// of compute mass and half the transient mass (rounded up), at 100 sompi per gram, at
/// least 100,000 sompi (check_transaction_standard.rs:133-148, 165-181).
fn fee_floor_by_hand(compute_mass: u64, transient_mass: u64) -> (u64, u64) {
    let fee_mass = compute_mass.max(transient_mass.div_ceil(2));
    (fee_mass, (fee_mass * 100).max(100_000))
}

/// The numbers `tests/measure.rs` writes for one shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Reported {
    estimated_size: u64,
    compute_mass: u64,
    transient_mass: u64,
    storage_mass: u64,
    fee_mass: u64,
    minimum_fee: u64,
}

fn reported(outcome: &Outcome) -> Reported {
    let masses = outcome.masses.as_ref().expect("an honest shape has masses");
    Reported {
        estimated_size: masses.estimated_size,
        compute_mass: masses.compute_mass,
        transient_mass: masses.transient_mass,
        storage_mass: masses
            .calculated_storage_mass
            .expect("an honest shape has a storage mass"),
        fee_mass: outcome.mempool.fee_mass.expect("a fee mass"),
        minimum_fee: outcome.mempool.minimum_fee.expect("a fee floor"),
    }
}

fn by_formula(outcome: &Outcome) -> Reported {
    let tx = &outcome.committed_tx;
    let size = size_by_hand(tx);
    let compute = compute_by_hand(tx);
    let (fee_mass, minimum_fee) = fee_floor_by_hand(compute, 4 * size);
    Reported {
        estimated_size: size,
        compute_mass: compute,
        transient_mass: 4 * size,
        storage_mass: storage_of(tx, &outcome.assembled.utxos),
        fee_mass,
        minimum_fee,
    }
}

fn signature_script_lengths(outcome: &Outcome) -> Vec<usize> {
    outcome
        .committed_tx
        .inputs
        .iter()
        .map(|input| input.signature_script.len())
        .collect()
}

/// `(script length, has a covenant binding, value)` of every output.
fn output_facts(outcome: &Outcome) -> Vec<(usize, bool, u64)> {
    outcome
        .committed_tx
        .outputs
        .iter()
        .map(|output| {
            (
                output.script_public_key.script().len(),
                output.covenant.is_some(),
                output.value,
            )
        })
        .collect()
}

/// `(script length, has a covenant id, amount)` of every spent coin.
fn coin_facts(outcome: &Outcome) -> Vec<(usize, bool, u64)> {
    outcome
        .assembled
        .utxos
        .iter()
        .map(|coin| {
            (
                coin.script_public_key.script().len(),
                coin.covenant_id.is_some(),
                coin.amount,
            )
        })
        .collect()
}

const KAS: u64 = SOMPI_PER_KAS;
/// Fee of the realistic profile: 0.001 KAS.
const FEE: u64 = 100_000;

fn realistic() -> Profile {
    let values = Realistic::default();
    assert_eq!(
        (values.coin_value, values.funding_value, values.fee),
        (10 * KAS, 100 * KAS, FEE)
    );
    Profile::Realistic(values)
}

/// One token coin to one token coin, with a fee-paying coin and change.
#[test]
fn a_funded_one_to_one_transfer_by_hand() {
    let outcome = run(&shapes::transfer(&realistic(), 1, 1));

    // What the transaction is made of.
    assert_eq!(signature_script_lengths(&outcome), vec![4_218, 66]);
    assert_eq!(outcome.minimal_budgets(), Some(vec![12, 10]));
    assert_eq!(
        coin_facts(&outcome),
        vec![(35, true, 10 * KAS), (34, false, 100 * KAS)]
    );
    assert_eq!(
        output_facts(&outcome),
        vec![(35, true, 10 * KAS), (34, false, 100 * KAS - FEE)]
    );

    // Size: frame 94; inputs 54 + 4,218 and 54 + 66; a bound output 18 + 35 + 34 and a
    // plain one 18 + 34.
    let size = 94 + (54 + 4_218) + (54 + 66) + (18 + 35 + 34) + (18 + 34);
    assert_eq!(size, 4_625);
    // Compute: the size, ten grams per output script byte (37 + 36 with the version
    // bytes), a hundred per budget unit (12 + 10).
    let compute = size + 10 * (37 + 36) + 100 * (12 + 10);
    assert_eq!(compute, 7_555);
    let transient = 4 * size;
    assert_eq!(transient, 18_500);

    // Storage. A bound pay-to-script-hash coin takes 63 + 35 + 32 = 130 bytes: two units.
    // A pay-to-pubkey coin takes 97: one unit.
    //   outputs: 4 * 10^12 / 10^9 = 4,000 and 10^12 / 9,999,900,000 = 100 (100.001)
    //   inputs:  three units, so no relaxed formula; mean 11 * 10^9 / 3 = 3,666,666,666;
    //            10^12 / 3,666,666,666 = 272 (272.7); three times that is 816
    let storage = (4_000 + 100) - 3 * 272;
    assert_eq!(storage, 3_284);
    assert_eq!(1_000_000_000_000u64 / 9_999_900_000, 100);
    assert_eq!(1_000_000_000_000u64 / (11_000_000_000 / 3), 272);

    // Fee floor: half the transient mass is 9,250, more than the compute mass.
    let fee_mass = 9_250;
    let minimum_fee = 925_000;

    let by_hand = Reported {
        estimated_size: size,
        compute_mass: compute,
        transient_mass: transient,
        storage_mass: storage,
        fee_mass,
        minimum_fee,
    };
    assert_eq!(reported(&outcome), by_hand);
    assert_eq!(by_formula(&outcome), by_hand);
}

/// `PublicMint.mint`: the minter and a fee-paying coin in; the minter, a new token coin
/// and change out.
#[test]
fn a_mint_by_hand() {
    let outcome = run(&shapes::mint(&realistic()));

    assert_eq!(signature_script_lengths(&outcome), vec![6_021, 66]);
    assert_eq!(outcome.minimal_budgets(), Some(vec![5, 10]));
    assert_eq!(
        coin_facts(&outcome),
        vec![(35, true, 10 * KAS), (34, false, 100 * KAS)]
    );
    // The new token coin is paid for by the fee-paying coin.
    assert_eq!(
        output_facts(&outcome),
        vec![
            (35, true, 10 * KAS),
            (35, true, 10 * KAS),
            (34, false, 90 * KAS - FEE)
        ]
    );

    let size = 94 + (54 + 6_021) + (54 + 66) + 2 * (18 + 35 + 34) + (18 + 34);
    assert_eq!(size, 6_515);
    let compute = size + 10 * (37 + 37 + 36) + 100 * (5 + 10);
    assert_eq!(compute, 9_115);
    let transient = 4 * size;
    assert_eq!(transient, 26_060);

    //   outputs: 4,000 + 4,000 and 10^12 / 8,999,900,000 = 111 (111.11)
    //   inputs:  three units, mean 3,666,666,666, 272 each
    let storage = (4_000 + 4_000 + 111) - 3 * 272;
    assert_eq!(storage, 7_295);
    assert_eq!(1_000_000_000_000u64 / 8_999_900_000, 111);

    let by_hand = Reported {
        estimated_size: size,
        compute_mass: compute,
        transient_mass: transient,
        storage_mass: storage,
        fee_mass: 13_030,
        minimum_fee: 1_303_000,
    };
    assert_eq!(reported(&outcome), by_hand);
    assert_eq!(by_formula(&outcome), by_hand);
}

/// Three token coins to three token coins, with a fee-paying coin and change.
#[test]
fn a_funded_three_to_three_transfer_by_hand() {
    let outcome = run(&shapes::transfer(&realistic(), 3, 3));

    assert_eq!(
        signature_script_lengths(&outcome),
        vec![4_433, 4_105, 4_105, 66]
    );
    assert_eq!(outcome.minimal_budgets(), Some(vec![22, 13, 13, 10]));
    assert_eq!(
        coin_facts(&outcome),
        vec![
            (35, true, 10 * KAS),
            (35, true, 10 * KAS),
            (35, true, 10 * KAS),
            (34, false, 100 * KAS)
        ]
    );
    assert_eq!(
        output_facts(&outcome),
        vec![
            (35, true, 10 * KAS),
            (35, true, 10 * KAS),
            (35, true, 10 * KAS),
            (34, false, 100 * KAS - FEE)
        ]
    );

    let size = 94 + (54 + 4_433) + 2 * (54 + 4_105) + (54 + 66) + 3 * (18 + 35 + 34) + (18 + 34);
    assert_eq!(size, 13_332);
    let compute = size + 10 * (3 * 37 + 36) + 100 * (22 + 13 + 13 + 10);
    assert_eq!(compute, 20_602);
    let transient = 4 * size;
    assert_eq!(transient, 53_328);

    //   outputs: three times 4,000 and 100 for the change
    //   inputs:  seven units; mean 13 * 10^9 / 7 = 1,857,142,857;
    //            10^12 / 1,857,142,857 = 538 (538.46); seven times that is 3,766
    let storage = (3 * 4_000 + 100) - 7 * 538;
    assert_eq!(storage, 8_334);
    assert_eq!(1_000_000_000_000u64 / (13_000_000_000 / 7), 538);

    let by_hand = Reported {
        estimated_size: size,
        compute_mass: compute,
        transient_mass: transient,
        storage_mass: storage,
        fee_mass: 26_664,
        minimum_fee: 2_666_400,
    };
    assert_eq!(reported(&outcome), by_hand);
    assert_eq!(by_formula(&outcome), by_hand);
}

/// The shapes of the third profile of `tests/measure.rs`: each paying its own fee floor.
fn realistic_shapes_at_the_fee_floor() -> Vec<(Scenario, u64)> {
    let with_default_fee = shapes::all(&realistic());
    with_default_fee
        .iter()
        .enumerate()
        .map(|(index, scenario)| {
            let floor = run(scenario).mempool.minimum_fee.expect("a fee floor");
            let profile = Profile::Realistic(Realistic {
                fee: floor,
                ..Realistic::default()
            });
            (shapes::all(&profile).swap_remove(index), floor)
        })
        .collect()
}

/// Every number of every shape, in the three profiles of `tests/measure.rs`.
#[test]
fn every_shape_in_every_profile_by_the_formulas() {
    let mut compared = 0;
    let mut set_by_compute_mass = Vec::new();
    for (profile_name, profile) in [("script", Profile::Script), ("realistic", realistic())] {
        let scenarios = shapes::all(&profile);
        assert_eq!(scenarios.len(), 29);
        for scenario in &scenarios {
            let outcome = run(scenario);
            assert_eq!(
                reported(&outcome),
                by_formula(&outcome),
                "{profile_name}: {}",
                scenario.name
            );
            let masses = outcome.masses.as_ref().unwrap();
            assert_eq!(
                masses.input_plurality,
                coin_facts(&outcome)
                    .iter()
                    .map(|(len, bound, _)| plurality_by_hand(*len, *bound) as u64)
                    .collect::<Vec<_>>(),
                "{profile_name}: {}",
                scenario.name
            );
            assert_eq!(
                masses.output_plurality,
                output_facts(&outcome)
                    .iter()
                    .map(|(len, bound, _)| plurality_by_hand(*len, *bound) as u64)
                    .collect::<Vec<_>>(),
                "{profile_name}: {}",
                scenario.name
            );
            // The fee the node sees is what the coins leave over.
            let spent: u64 = coin_facts(&outcome)
                .iter()
                .map(|(_, _, amount)| amount)
                .sum();
            let paid: u64 = output_facts(&outcome)
                .iter()
                .map(|(_, _, value)| value)
                .sum();
            assert_eq!(outcome.mempool.fee, Some(spent - paid));
            if profile_name == "realistic" && masses.compute_mass >= masses.transient_mass / 2 {
                set_by_compute_mass.push(scenario.name.clone());
            }
            compared += 1;
        }
    }

    for (scenario, floor) in realistic_shapes_at_the_fee_floor() {
        let outcome = run(&scenario);
        assert_eq!(
            reported(&outcome),
            by_formula(&outcome),
            "at the fee floor: {}",
            scenario.name
        );
        // The floor does not move when the fee changes: it depends on bytes and budgets.
        assert_eq!(
            outcome.mempool.minimum_fee,
            Some(floor),
            "{}",
            scenario.name
        );
        assert_eq!(outcome.mempool.fee, Some(floor), "{}", scenario.name);
        assert!(outcome.mempool.accepted, "{}", scenario.name);
        compared += 1;
    }
    assert_eq!(compared, 3 * 29);

    // For 27 of the 29 realistic shapes the floor is set by the byte size (200 sompi per
    // byte), not by the budgets. The two exceptions are the smallest transactions.
    assert_eq!(set_by_compute_mass, vec!["minter reclaim", "seed split"]);
}

/// One sompi below its fee floor a transaction is refused for the fee and for nothing
/// else; at the floor it is taken.
#[test]
fn the_fee_floor_is_exact() {
    let shape = |name: &str, fee: u64| {
        let profile = Profile::Realistic(Realistic {
            fee,
            ..Realistic::default()
        });
        match name {
            "transfer 1 to 1" => shapes::transfer(&profile, 1, 1),
            "mint" => shapes::mint(&profile),
            "transfer 3 to 3" => shapes::transfer(&profile, 3, 3),
            "minter reclaim" => shapes::mint_reclaim(&profile),
            other => panic!("no shape named {other}"),
        }
    };
    // (shape, floor, the floor is set by the byte size)
    let cases = [
        ("transfer 1 to 1", 925_000, true),
        ("mint", 1_303_000, true),
        ("transfer 3 to 3", 2_666_400, true),
        ("minter reclaim", 518_500, false),
    ];
    for (name, floor, by_size) in cases {
        let at = run(&shape(name, floor));
        assert_eq!(at.scenario, name);
        assert!(
            at.mempool.accepted,
            "{name}: {:?}",
            at.mempool.first_refusal
        );

        let below = run(&shape(name, floor - 1));
        assert!(!below.mempool.accepted, "{name}");
        assert!(below.consensus.accepted, "{name}");
        assert!(
            below.consensus.block.accepted,
            "{name}: a block asks no fee"
        );
        let refused: Vec<PolicyRule> = below.mempool.refused.iter().map(|f| f.rule).collect();
        assert_eq!(refused, vec![PolicyRule::MinimumRelayFee], "{name}");
        let masses = below.masses.as_ref().unwrap();
        let expected = if by_size {
            PolicyRefusal::InsufficientTransientFee {
                fee: floor - 1,
                minimum_fee: floor,
                normalized_transient_mass: masses.transient_mass / 2,
            }
        } else {
            PolicyRefusal::InsufficientComputeFee {
                fee: floor - 1,
                minimum_fee: floor,
                compute_mass: masses.compute_mass,
            }
        };
        assert_eq!(below.mempool.refused[0].refusal, expected, "{name}");
    }
}

/// The limits `tests/measure.rs` prints next to its numbers.
#[test]
fn the_limits_of_the_measurement() {
    let node = Harness::pinned().node;
    let daa_score = node.pov_daa_score;
    assert_eq!(node.params.network_name(), "kaspa-testnet-10");
    // Ten million DAA scores after the testnet-10 activation (config/params.rs:785).
    assert_eq!(daa_score, 467_579_632 + 10_000_000);

    let block = node.params.block_mass_limits().get(daa_score);
    assert_eq!(
        (block.compute, block.transient, block.storage),
        (500_000, 1_000_000, 500_000)
    );
    let mempool = node.params.mempool_block_mass_limits().get(daa_score);
    assert_eq!(
        (mempool.compute, mempool.transient, mempool.storage),
        (500_000, 1_000_000, 500_000)
    );
    assert_eq!(
        policy::standard_transaction_mass_cap(&node.params, daa_score),
        None
    );
    // The two constants `tests/measure.rs` writes next to the limits.
    assert_eq!(SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT, 10_000);
    assert_eq!(free_script_units_per_input().0, 9_999);
}
