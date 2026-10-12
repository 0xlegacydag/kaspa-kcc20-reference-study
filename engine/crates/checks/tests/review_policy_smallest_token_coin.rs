//! Review of the "smallest token coin" that `tests/measure.rs` reports: is the number a
//! boundary, of what, and under which assumptions.
//!
//! The measurement finds 7,987,253 sompi by halving an interval and asserts that what it
//! finds is a boundary, whatever the number. Here the number itself is pinned from both
//! sides, the storage mass of the measured transaction is given as a closed formula and
//! scanned sompi by sompi, and the assumptions are moved one at a time to show what the
//! number depends on.
//!
//! The measured transaction: one KCC20 coin of `v` sompi and one pay-to-pubkey coin of
//! 100 KAS in; one KCC20 coin of the same `v` sompi and the change out; the fee is the
//! mempool's floor for this transaction, 925,000 sompi.
//!
//! What the tests below establish:
//!
//! - The limit that binds is the storage mass limit of a block, 500,000 grams
//!   (rusty-kaspa a41a333 consensus/core/src/config/params.rs:698, 760). It is consensus:
//!   below the value the transaction fits no block. The mempool has the same limit, so
//!   both searches of the measurement must find the same value.
//! - The value depends on the fee-paying coin: 6,968,120 sompi with a coin of 1 KAS,
//!   7,987,253 with 100 KAS, 7,998,753 with 1,000 KAS. It tends to 4 * 10^12 / 500,000 =
//!   8,000,000 sompi (0.08 KAS) as that coin grows.
//! - It is a limit on the token coin that is created, not on the one that is spent: with
//!   the fee-paying coin of 100 KAS a token coin of 1,000 sompi moves into a token coin of
//!   0.1 KAS when the fee payer adds the difference, and a token coin of 10 KAS moved into
//!   one of 1,000 sompi is above the limit.
//! - It is the limit of a one-to-one transfer. Two token coins of that value out of one
//!   transaction with the same fee-paying coin do not fit a block.
//! - A minter is different: `PublicMint.mint` requires the next minter to hold exactly
//!   the value of the spent one (rule M-18). With one paying coin of 100 KAS the mint from
//!   a minter of 1,000 sompi is above the limit.
//!
//! Every transaction of this file has one fee-paying coin. A transaction paid by several
//! coins is not measured here; `review_engine_topics.rs` pays a small minter with several.

use checks::{Outcome, run};
use kaspa_consensus_core::{
    constants::STORAGE_MASS_PARAMETER,
    mass::{UtxoCell, calc_storage_mass},
};
use kcc20_family::{
    Scenario,
    keys::FUNDER,
    shapes::{self, Profile, Realistic, SOMPI_PER_KAS},
};
use node_gate::policy::PolicyRule;

const KAS: u64 = SOMPI_PER_KAS;

/// The storage mass a block may hold, and so may one transaction.
const LIMIT: u64 = 500_000;

/// The fee floor of the measured transaction.
const FEE: u64 = 925_000;

/// The value `tests/measure.rs` reports for a fee-paying coin of 100 KAS.
const REPORTED: u64 = 7_987_253;

/// The transaction of the measurement (`token_transfer` in `tests/measure.rs`).
fn token_transfer(token_coin_value: u64, funding_value: u64, fee: u64) -> Scenario {
    shapes::transfer(
        &Profile::Realistic(Realistic {
            coin_value: token_coin_value,
            funding_value,
            fee,
            funding_key: FUNDER,
        }),
        1,
        1,
    )
}

/// Storage mass of the measured transaction, from
/// consensus/core/src/mass/mod.rs:439-513 with the pluralities of its coins: 2 for a
/// KCC20 coin (a 35-byte script and a covenant id), 1 for a pay-to-pubkey coin.
///
/// Three storage units on each side, so the inputs count by their arithmetic mean:
/// `4C/v + C/change - 3 * (C / ((v + funding) / 3))`, every division rounded down.
fn storage_mass(token_coin_value: u64, funding_value: u64, fee: u64) -> u64 {
    let c = STORAGE_MASS_PARAMETER;
    let outputs = 4 * c / token_coin_value + c / (funding_value - fee);
    let mean_of_inputs = ((token_coin_value + funding_value) / 3).max(1);
    outputs.saturating_sub(3 * (c / mean_of_inputs))
}

/// The same number from the node's own function.
fn storage_mass_by_the_node(token_coin_value: u64, funding_value: u64, fee: u64) -> u64 {
    let inputs = [
        UtxoCell::new(2, token_coin_value),
        UtxoCell::new(1, funding_value),
    ];
    let outputs = [
        UtxoCell::new(2, token_coin_value),
        UtxoCell::new(1, funding_value - fee),
    ];
    calc_storage_mass(
        false,
        inputs.into_iter(),
        outputs.into_iter(),
        STORAGE_MASS_PARAMETER,
    )
    .expect("a computable storage mass")
}

fn storage_of(outcome: &Outcome) -> u64 {
    outcome
        .masses
        .as_ref()
        .and_then(|masses| masses.calculated_storage_mass)
        .expect("a storage mass")
}

/// Asserts what a block and a default mempool say to the outcome: both take it, or both
/// refuse it for the storage mass and for nothing else.
fn assert_fits(outcome: &Outcome, fits: bool) {
    let what = &outcome.scenario;
    assert!(outcome.scripts_accept(), "{what}: the scripts accept it");
    assert!(outcome.consensus.accepted, "{what}");
    assert_eq!(outcome.consensus.block.accepted, fits, "{what}: block");
    assert_eq!(outcome.mempool.accepted, fits, "{what}: mempool");
    if !fits {
        let storage = storage_of(outcome);
        let block = outcome.consensus.block.refusal.as_ref().unwrap();
        assert_eq!(block.rule, "check_block_mass", "{what}");
        assert_eq!(
            block.error,
            format!("ExceedsStorageMassLimit({storage}, {LIMIT})"),
            "{what}"
        );
        let mempool = outcome.mempool.first_refusal.as_ref().unwrap();
        assert_eq!(mempool.rule, "check_storage_mass_limit", "{what}");
        let refused: Vec<PolicyRule> = outcome.mempool.refused.iter().map(|f| f.rule).collect();
        assert_eq!(refused, vec![PolicyRule::StorageMassLimit], "{what}");
    }
}

#[test]
fn the_reported_value_passes_and_one_sompi_less_fails() {
    let at = run(&token_transfer(REPORTED, 100 * KAS, FEE));
    assert_eq!(storage_of(&at), LIMIT);
    assert_fits(&at, true);

    let below = run(&token_transfer(REPORTED - 1, 100 * KAS, FEE));
    assert_eq!(storage_of(&below), LIMIT + 1);
    assert_fits(&below, false);
}

/// The fee of the search is the floor of the transaction at every token coin value: the
/// size and the budgets do not change with the value.
#[test]
fn the_fee_floor_does_not_depend_on_the_token_coin_value() {
    for value in [1, 1_000, REPORTED, 10 * KAS, 100 * KAS] {
        let outcome = run(&token_transfer(value, 100 * KAS, FEE));
        let masses = outcome.masses.as_ref().unwrap();
        assert_eq!(
            (
                masses.estimated_size,
                masses.compute_mass,
                masses.transient_mass
            ),
            (4_625, 7_555, 18_500),
            "token coin of {value}"
        );
        assert_eq!(outcome.minimal_budgets(), Some(vec![12, 10]));
        assert_eq!(outcome.mempool.minimum_fee, Some(FEE));
        assert_eq!(outcome.mempool.fee, Some(FEE));
    }
}

/// The closed formula is the node's number: at the round values `tests/measure.rs` lists,
/// around the boundary, and on a grid.
#[test]
fn the_storage_mass_of_the_measured_transaction_has_a_closed_formula() {
    // (token coin value, storage mass) as written to `measure.json`.
    let listed = [
        (1_000, 3_999_999_203),
        (100_000, 39_999_203),
        (1_000_000, 3_999_203),
        (10_000_000, 399_203),
        (100_000_000, 39_209),
        (1_000_000_000, 3_284),
        (10_000_000_000, 50),
    ];
    for (value, storage) in listed {
        assert_eq!(storage_mass(value, 100 * KAS, FEE), storage, "{value}");
        let outcome = run(&token_transfer(value, 100 * KAS, FEE));
        assert_eq!(storage_of(&outcome), storage, "{value}");
        assert_fits(&outcome, storage <= LIMIT);
    }

    for funding in [KAS, 100 * KAS, 1_000 * KAS] {
        for value in (1..=30_000_000u64).step_by(9_973) {
            assert_eq!(
                storage_mass(value, funding, FEE),
                storage_mass_by_the_node(value, funding, FEE),
                "token coin of {value}, fee payer of {funding}"
            );
        }
    }
}

/// The smallest token coin value whose transaction is within the limit, and a proof that
/// it is the only boundary up to `upper`: every value below it is above the limit, every
/// value from it to 30,000,000 sompi is within, and from there on the output terms alone
/// are within the limit and only fall.
fn boundary(funding_value: u64, fee: u64, upper: u64) -> u64 {
    let scanned_to = 30_000_000;
    let mut first_within = None;
    for value in 1..=scanned_to {
        let within = storage_mass(value, funding_value, fee) <= LIMIT;
        match (first_within, within) {
            (None, true) => first_within = Some(value),
            (Some(first), false) => {
                panic!("within the limit at {first} and above it again at {value}")
            }
            _ => {}
        }
    }
    // Above the scanned range the mass is at most the sum of the two output terms, which
    // do not grow with the token coin value.
    let c = STORAGE_MASS_PARAMETER;
    assert!(upper >= scanned_to);
    assert!(4 * c / scanned_to + c / (funding_value - fee) <= LIMIT);
    first_within.expect("a value within the limit in the scanned range")
}

#[test]
fn the_reported_value_is_the_only_boundary_up_to_the_upper_bound_of_the_search() {
    assert_eq!(boundary(100 * KAS, FEE, 100 * KAS), REPORTED);
}

/// The value is not a constant of the contract or of the network: it moves with the coin
/// that pays the fee, because the inputs are credited by their mean.
#[test]
fn the_boundary_moves_with_the_fee_paying_coin() {
    // (value of the fee-paying coin, smallest token coin value)
    let cases = [
        (KAS, 6_968_120),
        (100 * KAS, REPORTED),
        (1_000 * KAS, 7_998_753),
    ];
    for (funding, expected) in cases {
        assert_eq!(
            boundary(funding, FEE, 100 * KAS),
            expected,
            "fee payer of {funding}"
        );
        assert_fits(&run(&token_transfer(expected, funding, FEE)), true);
        assert_fits(&run(&token_transfer(expected - 1, funding, FEE)), false);
    }
    // With an ever larger fee payer the credit and the change term vanish and the bound
    // is that of a lone output of two storage units: 4 * 10^12 / v <= 500,000.
    assert_eq!(4 * STORAGE_MASS_PARAMETER / 7_999_985, LIMIT);
    assert_eq!(4 * STORAGE_MASS_PARAMETER / 7_999_984, LIMIT + 1);
}

/// The fee hardly matters: it only enters through the change output, whose term is 100
/// grams at the floor and 101 when a whole KAS is paid.
#[test]
fn the_boundary_hardly_moves_with_the_fee() {
    let cases = [(FEE, REPORTED), (10 * FEE, REPORTED), (KAS, REPORTED + 16)];
    for (fee, expected) in cases {
        assert_eq!(
            boundary(100 * KAS, fee, 100 * KAS),
            expected,
            "fee of {fee}"
        );
    }
}

/// The limit is on the token coin that is created. With the fee-paying coin of 100 KAS a
/// token coin worth 1,000 sompi moves into a token coin of 0.1 KAS when the fee payer adds
/// the difference. The other way round, a token coin of 10 KAS moved into one of 1,000
/// sompi is above the storage mass limit.
#[test]
fn the_limit_is_on_the_created_coin_not_on_the_spent_one() {
    let small = 1_000;
    let large = KAS / 10;

    // Spend `small`, create `large`: the change gives up the difference.
    let mut topped_up = token_transfer(large, 100 * KAS, FEE);
    topped_up.name = "token coin of 1,000 sompi into one of 0.1 KAS".to_string();
    topped_up.contract_input_mut(0).value = small;
    topped_up.plain_output_mut(1).value -= large - small;
    let outcome = run(&topped_up);
    assert_eq!(outcome.mempool.fee, Some(FEE));
    // 4 * 10^12 / 10^7 = 400,000; change 100; inputs 3 * 299.
    assert_eq!(storage_of(&outcome), 400_000 + 100 - 897);
    assert_fits(&outcome, true);

    // Spend `10 KAS`, create `small`: the change takes the difference.
    let mut drained = token_transfer(10 * KAS, 100 * KAS, FEE);
    drained.name = "token coin of 10 KAS into one of 1,000 sompi".to_string();
    drained.contract_output_mut(0).value = small;
    drained.plain_output_mut(1).value += 10 * KAS - small;
    let outcome = run(&drained);
    assert_eq!(outcome.mempool.fee, Some(FEE));
    assert!(storage_of(&outcome) > 3_999_000_000);
    assert_fits(&outcome, false);
}

/// The value is that of a one-to-one transfer. One token coin split into two of the
/// reported value, the second paid for by the fee payer, does not fit a block; two of
/// twice the value do.
#[test]
fn two_created_coins_need_about_twice_the_value_each() {
    let split = |coin_value: u64| {
        let profile = Profile::Realistic(Realistic {
            coin_value,
            funding_value: 100 * KAS,
            // The fee floor of the one-to-two transfer.
            fee: 963_600,
            funding_key: FUNDER,
        });
        run(&shapes::transfer(&profile, 1, 2))
    };

    let at_reported = split(REPORTED);
    assert_eq!(at_reported.mempool.minimum_fee, Some(963_600));
    // Twice 4 * 10^12 / 7,987,253 = 500,797, and 100 for the change, less 897.
    assert_eq!(storage_of(&at_reported), 2 * 500_797 + 100 - 897);
    assert_fits(&at_reported, false);

    let at_twice = split(2 * REPORTED);
    assert_eq!(storage_of(&at_twice), 2 * 250_398 + 100 - 897);
    assert_fits(&at_twice, true);
}

/// `PublicMint.mint` keeps the minter's value: the first bound output must be worth
/// exactly what the minter is worth (rule M-18). Measured with one paying coin: a minter
/// of 1,000 sompi and one fee-paying coin of 100 KAS. The next minter then puts
/// 4 * 10^12 / 1,000 grams of storage mass into the mint, the inputs take off 897. A mint
/// paid by several coins is not measured here.
#[test]
fn a_small_minter_with_one_paying_coin_exceeds_the_storage_limit() {
    // The fee floor of the mint shape.
    let fee = 1_303_000;
    let profile = Profile::Realistic(Realistic {
        coin_value: 10 * KAS,
        funding_value: 100 * KAS,
        fee,
        funding_key: FUNDER,
    });
    let honest = run(&shapes::mint(&profile));
    assert_eq!(honest.mempool.minimum_fee, Some(fee));
    assert_fits(&honest, true);

    // The same mint from a minter of 1,000 sompi; the new token coin still gets 10 KAS.
    let mut small = shapes::mint(&profile);
    small.name = "mint from a minter of 1,000 sompi".to_string();
    small.contract_input_mut(0).value = 1_000;
    small.contract_output_mut(0).value = 1_000;
    let outcome = run(&small);
    assert_eq!(outcome.mempool.fee, Some(fee));
    // The minter 4 * 10^9, the token coin 4,000, the change 111, less three times 299.
    assert_eq!(storage_of(&outcome), 4_000_000_000 + 4_000 + 111 - 897);
    assert_fits(&outcome, false);
}
