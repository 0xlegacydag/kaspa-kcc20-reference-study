//! A second set of cases for topics of three engine files (`engine_limits.rs`,
//! `engine_signatures.rs`, `engine_gaps.rs`), built without the helpers of those files.
//!
//! Every transaction is built from the honest shapes of `kcc20-family` and judged by
//! `checks::run` / `Harness::run`, which assert nothing and write no result line; the
//! assertions are the plain `assert!`s below.
//!
//! Topics:
//!
//! 1. Storage mass and the coins that pay. The same contract call is paid with one coin of
//!    100 KAS and change, with one coin that is just large enough, and with several equal
//!    small coins, and the tests record what a block and a default mempool answer. The
//!    storage mass of KIP-9 (rusty-kaspa a41a333 consensus/core/src/mass/mod.rs:439-513)
//!    credits the inputs with `N * (C / mean)` = about `N^2 * C / sum`, where N counts the
//!    spent coins (a covenant coin twice) and `sum` is their total value, so the number of
//!    paying coins enters the result.
//!
//!    Measured on the default node of the test harness of `crates/checks` (testnet-10
//!    parameters), with the fee at the floor of a default mempool:
//!
//!    - `PublicMint.mint` from a minter of 0.01 KAS, new token coin 0.1 KAS. One paying
//!      coin (100 KAS with change, or just large enough): refused for storage mass by block
//!      and mempool. Several small coins: accepted with 5 coins of 2,277,720 sompi (fee
//!      1,388,600 sompi against a floor of 1,292,600 with one coin) and with 50, refused
//!      with 4. From a minter of 0.001 KAS: accepted with 21 coins of 624,300 sompi,
//!      refused with 20. `TokenSeed.create` from a seed of 0.01 and of 0.001 KAS: the same
//!      answers, with 5 and with 21 coins.
//!    - A new token coin of 0.01 KAS: refused with one paying coin; with several the
//!      smallest accepted count is 8 next to a minter of 0.2 KAS and 58 next to a minter of
//!      10 KAS.
//!    - Making the small paying coins: one coin of 2,277,720 sompi is cut from a coin of 100
//!      KAS in one transaction, two are refused; a coin of 2,000,100 sompi is cut, one of
//!      1,990,000 sompi and one of 624,300 sompi are refused.
//!    - `PublicMint.split` of a minter of 0.01 KAS with a new minter of 0.2 KAS: refused
//!      with one paying coin, accepted with several small ones. `reclaim_into` of a minter
//!      of 0.01 KAS into a minter of 10 KAS, paid by one coin of 100 KAS whose change takes
//!      the freed value: accepted.
//!    - `PublicMint.reclaim` of an exhausted minter with a deposit of 0.01 KAS. The deposit
//!      as a coin of its own: refused for storage mass when one coin of 100 KAS pays and
//!      takes change; accepted with one paying coin worth exactly the fee, with one of 0.05
//!      KAS and change, and with no paying coin (the fee comes out of the deposit). The
//!      deposit added to the change of the 100 KAS coin in one output: accepted.
//!    - The same deposit next to a surviving coin of 10 KAS (`PublicMint.reclaim_into` and
//!      `TokenSeed.reclaim`). As a coin of its own: refused with one paying coin (100 KAS
//!      with change, or worth exactly the fee) and with 18 small coins, accepted with 19.
//!      Added to the payer's change in one output: accepted. Next to a survivor of 0.2 KAS
//!      one paying coin worth exactly the fee is enough.
//! 2. Refusals checked by removal: the refusing opcode at the byte offset of the refusal is
//!    replaced (OpVerify -> OpDrop, OpEqualVerify / OpNumEqualVerify -> Op2Drop) and the
//!    same changed transaction then passes that input.

use std::sync::{Arc, Mutex};

use checks::{Budgets, Harness, Outcome, run};
use kaspa_consensus_core::constants::STORAGE_MASS_PARAMETER;
use kaspa_consensus_core::hashing::sighash_type::{SIG_HASH_ALL, SigHashType};
use kaspa_consensus_core::mass::{UtxoCell, calc_storage_mass};
use kcc20_family::keys::{self, ALICE, CAROL, FUNDER};
use kcc20_family::scenario::{InputSpec, LateBytes, OrdinaryInput, OutputSpec, PlainOutput};
use kcc20_family::shapes::{self, Profile, Realistic, SOMPI_PER_KAS};
use kcc20_family::{Contract, EntryRole, Family, Scenario, raw, witness};

const KAS: u64 = SOMPI_PER_KAS;

/// The storage mass a block may hold and a default mempool accepts for one transaction.
const STORAGE_LIMIT: u64 = 500_000;

/// The budget a pay-to-public-key Schnorr input needs (100,001 script units).
const FEE_COIN_BUDGET: u16 = 10;

fn plain_mode() -> bool {
    checks::mutation::mode().is_plain()
}

fn realistic(coin_value: u64) -> Profile {
    Profile::Realistic(Realistic {
        coin_value,
        funding_value: 100 * KAS,
        fee: 1,
        funding_key: FUNDER,
    })
}

fn funder_script() -> kaspa_consensus_core::tx::ScriptPublicKey {
    shapes::pay_to_public_key_script(&keys::x_only(FUNDER))
}

/// A pay-to-public-key coin of the fee payer, spent with a fresh Schnorr signature of the
/// given type over the transaction it ends up in.
fn fee_coin(index: u32, value: u64, hash_type: SigHashType) -> OrdinaryInput {
    let signature_script = LateBytes::from_tx(move |ctx| {
        raw::push(&keys::schnorr_signature(
            ctx,
            &keys::keypair(FUNDER),
            hash_type,
        ))
        .expect("a 65-byte push fits a script")
    });
    OrdinaryInput::new(
        funder_script(),
        value,
        shapes::outpoint(3, index),
        signature_script,
    )
    .labelled(format!("fee coin {index}"))
}

/// A shape of the realistic profile without its funding coin and without its change.
fn stripped(mut scenario: Scenario, contract_inputs: usize, outputs: usize) -> Scenario {
    scenario.inputs.truncate(contract_inputs);
    scenario.outputs.truncate(outputs);
    scenario
}

/// How the transaction is paid.
#[derive(Clone, Copy, Debug)]
enum Pay {
    /// This many equal coins that together cover what the outputs lack plus the fee floor;
    /// no change output (up to `count - 1` sompi above the floor go to the fee).
    JustEnough(usize),
    /// This many coins of this value; one change output to the payer takes everything above
    /// the fee floor.
    WithChange(usize, u64),
}

/// What the gate said about one paid transaction.
#[derive(Clone, Debug)]
struct Row {
    label: String,
    fee_coins: usize,
    each: u64,
    total_in: u64,
    fee: u64,
    floor: u64,
    compute: u64,
    transient: u64,
    storage: u64,
    scripts: bool,
    block: bool,
    mempool: bool,
    block_refusal: String,
    mempool_refusal: String,
}

impl Row {
    fn accepted(&self) -> bool {
        self.scripts && self.block && self.mempool
    }

    fn refused_for_storage(&self) -> bool {
        self.scripts
            && !self.block
            && !self.mempool
            && self.storage > STORAGE_LIMIT
            && self.block_refusal.contains("ExceedsStorageMassLimit")
            && self.mempool_refusal.contains("StorageMass")
    }

    fn line(&self) -> String {
        format!(
            "ROW | {:<58} | coins {:>2} x {:>11} | in {:>12} | fee {:>8} (floor {:>8}) | \
             compute {:>6} transient {:>6} storage {:>10} | scripts {} block {} mempool {} | {} | {}",
            self.label,
            self.fee_coins,
            self.each,
            self.total_in,
            self.fee,
            self.floor,
            self.compute,
            self.transient,
            self.storage,
            self.scripts,
            self.block,
            self.mempool,
            self.block_refusal,
            self.mempool_refusal
        )
    }
}

/// The storage mass by the consensus formula, from the values of the scenario and the
/// plurality stated here: a coin or output that carries a covenant id counts twice.
fn storage_by_hand(scenario: &Scenario) -> u64 {
    let inputs: Vec<UtxoCell> = scenario
        .inputs
        .iter()
        .map(|input| {
            let bound = match input {
                InputSpec::Contract(coin) => coin.covenant_id.is_some(),
                InputSpec::Ordinary(coin) => coin.covenant_id.is_some(),
            };
            UtxoCell::new(if bound { 2 } else { 1 }, input.value())
        })
        .collect();
    let outputs: Vec<UtxoCell> = scenario
        .outputs
        .iter()
        .map(|output| {
            let bound = match output {
                OutputSpec::Contract(out) => out.binding.is_some(),
                OutputSpec::Plain(out) => out.binding.is_some(),
            };
            UtxoCell::new(if bound { 2 } else { 1 }, output.value())
        })
        .collect();
    calc_storage_mass(
        false,
        inputs.into_iter(),
        outputs.into_iter(),
        STORAGE_MASS_PARAMETER,
    )
    .expect("the storage mass of these values is computable")
}

fn row(label: &str, fee_coins: usize, each: u64, scenario: &Scenario, outcome: &Outcome) -> Row {
    let masses = outcome
        .masses
        .as_ref()
        .expect("the masses of a well formed transaction are known");
    let storage = masses
        .calculated_storage_mass
        .expect("the storage mass was calculated");
    assert_eq!(
        storage,
        storage_by_hand(scenario),
        "{label}: the gate's storage mass is the consensus formula on the stated values"
    );
    Row {
        label: label.to_string(),
        fee_coins,
        each,
        total_in: scenario.total_in(),
        fee: scenario.total_in() - scenario.total_out(),
        floor: outcome.mempool.minimum_fee.unwrap_or(0),
        compute: masses.compute_mass,
        transient: masses.transient_mass,
        storage,
        scripts: outcome.scripts_accept(),
        block: outcome.consensus.block.accepted,
        mempool: outcome.mempool.accepted,
        block_refusal: outcome
            .consensus
            .block
            .refusal
            .as_ref()
            .map(|refusal| refusal.error.clone())
            .unwrap_or_else(|| "-".to_string()),
        mempool_refusal: outcome
            .mempool
            .first_refusal
            .as_ref()
            .map(|refusal| format!("{}: {}", refusal.rule, refusal.error))
            .unwrap_or_else(|| "-".to_string()),
    }
}

/// The smallest budgets of the contract inputs of `base`, measured with one large fee coin.
fn contract_budgets(base: &dyn Fn() -> Scenario) -> Vec<u16> {
    let mut scenario = base();
    let contracts = scenario.inputs.len();
    scenario.push_ordinary_input(fee_coin(0, 100 * KAS, SIG_HASH_ALL));
    let change = scenario.total_in() - scenario.total_out() - KAS;
    scenario.push_plain_output(PlainOutput::new(funder_script(), change));
    let outcome = run(&scenario);
    assert!(
        outcome.scripts_accept(),
        "the honest call passes its scripts: {}",
        outcome.describe()
    );
    let budgets = outcome
        .minimal_budgets()
        .expect("every input of an honest call has a smallest budget");
    assert_eq!(
        budgets[contracts], FEE_COIN_BUDGET,
        "a pay-to-public-key input needs budget 10"
    );
    budgets[..contracts].to_vec()
}

/// Pays `base` as `pay` says, at the fee floor of a default mempool, and reports.
fn paid(label: &str, base: &dyn Fn() -> Scenario, budgets: &[u16], pay: Pay) -> Row {
    let count = match pay {
        Pay::JustEnough(count) | Pay::WithChange(count, _) => count,
    };
    assert!(count > 0, "at least one paying coin");
    let build = |each: u64, change: Option<u64>| {
        let mut scenario = base();
        for index in 0..count {
            scenario.push_ordinary_input(fee_coin(index as u32, each, SIG_HASH_ALL));
        }
        if let Some(value) = change {
            scenario.push_plain_output(PlainOutput::new(funder_script(), value));
        }
        scenario
    };
    let harness = || {
        let mut all = budgets.to_vec();
        all.extend(std::iter::repeat_n(FEE_COIN_BUDGET, count));
        Harness::pinned().with_budgets(Budgets::Exactly(all))
    };
    // The fee floor depends on the size and the budgets, not on the values: probe it.
    let probe = match pay {
        Pay::JustEnough(_) => build(10 * KAS, None),
        Pay::WithChange(_, each) => build(each, Some(1)),
    };
    let floor = harness()
        .run(&probe)
        .mempool
        .minimum_fee
        .expect("the fee floor of a well formed transaction is known");
    let bare = base();
    let lacking = bare.total_out() as i128 - bare.total_in() as i128 + floor as i128;
    let (each, scenario) = match pay {
        Pay::JustEnough(_) => {
            assert!(
                lacking > 0,
                "{label}: the outputs and the fee need paying coins"
            );
            let each = (lacking as u64).div_ceil(count as u64);
            (each, build(each, None))
        }
        Pay::WithChange(_, each) => {
            let rest = (count as u64 * each) as i128 - lacking;
            assert!(
                rest > 0,
                "{label}: the paying coins cover the outputs and the fee"
            );
            (each, build(each, Some(rest as u64)))
        }
    };
    let outcome = harness().run(&scenario);
    let result = row(label, count, each, &scenario, &outcome);
    println!("{}", result.line());
    result
}

/// The smallest number of equal just-large-enough paying coins with which a block and a
/// default mempool accept `base`; the row for that count and the row for one coin less.
fn smallest_count(
    label: &str,
    base: &dyn Fn() -> Scenario,
    budgets: &[u16],
    guess: usize,
    max: usize,
) -> (Row, Option<Row>) {
    let at = |count: usize| {
        paid(
            &format!("{label}, {count} small coins"),
            base,
            budgets,
            Pay::JustEnough(count),
        )
    };
    let mut count = guess;
    let mut here = at(count);
    if here.accepted() {
        loop {
            if count == 1 {
                return (here, None);
            }
            let below = at(count - 1);
            if !below.accepted() {
                return (here, Some(below));
            }
            count -= 1;
            here = below;
        }
    }
    loop {
        assert!(count < max, "{label}: no count up to {max} is accepted");
        let above = at(count + 1);
        if above.accepted() {
            return (above, Some(here));
        }
        count += 1;
        here = above;
    }
}

// --- the contract calls, without any paying coin -------------------------------------

/// `PublicMint.mint`: a minter worth `minter`, its successor of the same value (M-18), and a
/// new token coin worth `token`.
fn mint_base(minter: u64, token: u64) -> Scenario {
    let mut scenario = stripped(shapes::mint(&realistic(minter)), 1, 2);
    *scenario.outputs[1].value_mut() = token;
    scenario
}

/// `TokenSeed.create`: a seed worth `seed`, its successor of the same value (S-16), and a
/// new token coin worth `token`.
fn create_base(seed: u64, token: u64) -> Scenario {
    let mut scenario = stripped(shapes::seed_create(&realistic(seed)), 1, 2);
    *scenario.outputs[1].value_mut() = token;
    scenario
}

/// `PublicMint.reclaim`: an exhausted minter worth `deposit`; with `own_coin` the deposit is
/// paid to a coin of its owner, without it no output is stated here.
fn reclaim_base(deposit: u64, own_coin: bool) -> Scenario {
    stripped(
        shapes::mint_reclaim(&realistic(deposit)),
        1,
        usize::from(own_coin),
    )
}

/// `PublicMint.reclaim_into` + `reclaim_delegator`: a surviving minter worth `survivor` and a
/// retiring one worth `deposit`.
fn reclaim_into_base(survivor: u64, deposit: u64, own_coin: bool) -> Scenario {
    let mut scenario = stripped(
        shapes::mint_reclaim_into(&realistic(survivor)),
        2,
        1 + usize::from(own_coin),
    );
    scenario.contract_input_mut(1).value = deposit;
    if own_coin {
        *scenario.outputs[1].value_mut() = deposit;
    }
    scenario
}

/// `TokenSeed.reclaim` + `reclaim_delegator`: a surviving seed worth `survivor` and a
/// retiring one worth `deposit`.
fn seed_reclaim_base(survivor: u64, deposit: u64, own_coin: bool) -> Scenario {
    let mut scenario = stripped(
        shapes::seed_reclaim(&realistic(survivor)),
        2,
        1 + usize::from(own_coin),
    );
    scenario.contract_input_mut(1).value = deposit;
    if own_coin {
        *scenario.outputs[1].value_mut() = deposit;
    }
    scenario
}

/// No paying coin at all: the fee floor comes out of the last output.
fn fee_out_of_the_last_output(label: &str, base: &dyn Fn() -> Scenario) -> Option<Row> {
    let floor = run(&base())
        .mempool
        .minimum_fee
        .expect("the fee floor of a well formed transaction is known");
    let mut scenario = base();
    let last = scenario.outputs.len() - 1;
    let value = scenario.outputs[last].value();
    if value <= floor {
        println!("ROW | {label}: the last output ({value}) does not cover the floor ({floor})");
        return None;
    }
    *scenario.outputs[last].value_mut() = value - floor;
    let outcome = run(&scenario);
    let result = row(label, 0, 0, &scenario, &outcome);
    println!("{}", result.line());
    Some(result)
}

// --- storage mass: a small minter, seed or new token coin -------------------------------

/// The rows of one small continuing coin: one large coin, one just-enough coin, 5 / 10 / 20 /
/// 50 small coins, and the smallest count that works.
struct Rescue {
    large: Row,
    one: Row,
    counted: Vec<Row>,
    smallest: Row,
    below: Option<Row>,
}

fn rescue(label: &str, base: &dyn Fn() -> Scenario, counts: &[usize], guess: usize) -> Rescue {
    let budgets = contract_budgets(base);
    println!("ROW | {label}: contract budgets {budgets:?}");
    let large = paid(
        &format!("{label}, one coin of 100 KAS, change"),
        base,
        &budgets,
        Pay::WithChange(1, 100 * KAS),
    );
    let one = paid(
        &format!("{label}, one coin just large enough"),
        base,
        &budgets,
        Pay::JustEnough(1),
    );
    let counted = counts
        .iter()
        .map(|&count| {
            paid(
                &format!("{label}, {count} small coins"),
                base,
                &budgets,
                Pay::JustEnough(count),
            )
        })
        .collect();
    let (smallest, below) = smallest_count(label, base, &budgets, guess, 90);
    Rescue {
        large,
        one,
        counted,
        smallest,
        below,
    }
}

#[test]
fn mass_a_small_minter_with_one_paying_coin_and_with_several() {
    if !plain_mode() {
        return;
    }
    // A mint out of a small minter, paid in three ways. Measured: refused for storage mass
    // with one paying coin, large or just large enough; accepted by a block and a default
    // mempool with several small paying coins.
    let token = KAS / 10;
    for (name, minter, guess) in [("0.01 KAS", KAS / 100, 5), ("0.001 KAS", KAS / 1000, 23)] {
        let base = move || mint_base(minter, token);
        let found = rescue(
            &format!("mint, minter {name}, new token coin 0.1 KAS"),
            &base,
            &[5, 10, 20, 50],
            guess,
        );
        assert!(
            found.large.refused_for_storage(),
            "one coin of 100 KAS: refused for storage mass by block and mempool"
        );
        assert!(
            found.one.refused_for_storage(),
            "one coin just large enough: refused for storage mass by block and mempool"
        );
        let fifty = found.counted.last().expect("the row of 50 coins");
        assert!(
            fifty.accepted(),
            "50 small coins: accepted by block and mempool"
        );
        assert!(found.smallest.accepted());
        if let Some(below) = &found.below {
            assert!(
                below.refused_for_storage(),
                "one coin less is refused for storage mass"
            );
        }
        // Observed on the default node (testnet-10 parameters): 5 coins of 2,277,720 sompi
        // for the 0.01 KAS minter (fee 1,388,600 against 1,292,600 with one coin), 21 coins
        // of 624,300 sompi for the 0.001 KAS minter (fee 3,110,300).
        let (count, each, fee) = if minter == KAS / 100 {
            (5, 2_277_720, 1_388_600)
        } else {
            (21, 624_300, 3_110_300)
        };
        assert_eq!(
            (
                found.smallest.fee_coins,
                found.smallest.each,
                found.smallest.fee
            ),
            (count, each, fee)
        );
        assert_eq!(found.one.fee, 1_292_600);
        println!(
            "RESULT | mint, minter {name}: smallest count {} (each {} sompi, fee {}); fee with \
             one coin {}; extra fee {}",
            found.smallest.fee_coins,
            found.smallest.each,
            found.smallest.fee,
            found.one.fee,
            found.smallest.fee - found.one.fee
        );
    }
}

#[test]
fn mass_a_small_seed_with_one_paying_coin_and_with_several() {
    if !plain_mode() {
        return;
    }
    // The same measurement for a small seed (TokenSeed.create).
    let token = KAS / 10;
    for (name, seed, guess) in [("0.01 KAS", KAS / 100, 5), ("0.001 KAS", KAS / 1000, 23)] {
        let base = move || create_base(seed, token);
        let found = rescue(
            &format!("seed create, seed {name}, new token coin 0.1 KAS"),
            &base,
            &[10, 50],
            guess,
        );
        assert!(found.large.refused_for_storage());
        assert!(found.one.refused_for_storage());
        assert!(
            found
                .counted
                .last()
                .expect("the row of 50 coins")
                .accepted()
        );
        assert!(found.smallest.accepted());
        if let Some(below) = &found.below {
            assert!(below.refused_for_storage());
        }
        // Observed: 5 coins for the 0.01 KAS seed, 21 for the 0.001 KAS seed.
        assert_eq!(
            found.smallest.fee_coins,
            if seed == KAS / 100 { 5 } else { 21 }
        );
        println!(
            "RESULT | seed create, seed {name}: smallest count {} (each {} sompi, fee {}); fee \
             with one coin {}; extra fee {}",
            found.smallest.fee_coins,
            found.smallest.each,
            found.smallest.fee,
            found.one.fee,
            found.smallest.fee - found.one.fee
        );
    }
}

#[test]
fn mass_a_small_new_token_coin_with_one_paying_coin_and_with_several() {
    if !plain_mode() {
        return;
    }
    // The same measurement for a small created coin: a new token coin of 0.01 KAS out of a
    // minter worth 0.2 KAS and out of one worth 10 KAS.
    let token = KAS / 100;
    for (name, minter, guess) in [("0.2 KAS", KAS / 5, 8), ("10 KAS", 10 * KAS, 59)] {
        let base = move || mint_base(minter, token);
        let found = rescue(
            &format!("mint, minter {name}, new token coin 0.01 KAS"),
            &base,
            &[],
            guess,
        );
        assert!(found.large.refused_for_storage());
        assert!(found.one.refused_for_storage());
        assert!(found.smallest.accepted());
        // Observed: 8 coins next to a minter of 0.2 KAS, 58 next to a minter of 10 KAS (the
        // minter's own value enters the mean of the inputs).
        assert_eq!(
            found.smallest.fee_coins,
            if minter == KAS / 5 { 8 } else { 58 }
        );
        println!(
            "RESULT | new token coin 0.01 KAS, minter {name}: smallest count {} (each {} sompi, \
             fee {}, compute mass {}); fee with one coin {}",
            found.smallest.fee_coins,
            found.smallest.each,
            found.smallest.fee,
            found.smallest.compute,
            found.one.fee
        );
    }
}

// --- storage mass: a small deposit ------------------------------------------------------

#[test]
fn mass_a_small_deposit_of_an_exhausted_minter_comes_back_in_four_arrangements() {
    if !plain_mode() {
        return;
    }
    // PublicMint.reclaim with a deposit of 0.01 KAS. Measured: as a coin of its own the
    // deposit is refused for storage mass when one coin of 100 KAS pays and takes change,
    // and accepted with a paying coin worth exactly the fee, with one of 0.05 KAS and
    // change, and with no paying coin; added to the change of the 100 KAS coin in one
    // output it is accepted.
    let deposit = KAS / 100;
    let own = move || reclaim_base(deposit, true);
    let merged = move || reclaim_base(deposit, false);
    let budgets = contract_budgets(&own);
    let label = "minter reclaim, deposit 0.01 KAS";

    let large = paid(
        &format!("{label}, own coin, one coin of 100 KAS, change"),
        &own,
        &budgets,
        Pay::WithChange(1, 100 * KAS),
    );
    assert!(
        large.refused_for_storage(),
        "one coin of 100 KAS with change: refused for storage mass"
    );

    let exact = paid(
        &format!("{label}, own coin, one coin worth exactly the fee, no change"),
        &own,
        &budgets,
        Pay::JustEnough(1),
    );
    let small = paid(
        &format!("{label}, own coin, one coin of 0.05 KAS, change"),
        &own,
        &budgets,
        Pay::WithChange(1, KAS / 20),
    );
    let alone = fee_out_of_the_last_output(&format!("{label}, own coin, no paying coin"), &own);
    let one_output = paid(
        &format!("{label}, ONE output: deposit + change of a 100 KAS coin"),
        &merged,
        &budgets,
        Pay::WithChange(1, 100 * KAS),
    );
    println!(
        "RESULT | minter reclaim 0.01 KAS as a coin of its own: exact-fee coin {}, 0.05 KAS coin \
         {}, no paying coin {:?}; one output {}",
        exact.accepted(),
        small.accepted(),
        alone.as_ref().map(Row::accepted),
        one_output.accepted()
    );
    assert!(
        one_output.accepted(),
        "the deposit added to the payer's change"
    );
    assert_eq!(one_output.storage, 0);
    assert!(
        exact.accepted(),
        "a coin of its own, paid by a coin worth exactly the fee"
    );
    assert!(
        small.accepted(),
        "a coin of its own, paid by a coin of 0.05 KAS"
    );
    assert!(
        alone.expect("the deposit covers the floor").accepted(),
        "a coin of its own, the fee out of the deposit"
    );
}

#[test]
fn mass_a_small_deposit_next_to_a_survivor_of_ten_kas() {
    if !plain_mode() {
        return;
    }
    // The two flows with a surviving coin (PublicMint.reclaim_into and TokenSeed.reclaim,
    // each with its reclaim_delegator): survivor 10 KAS, deposit 0.01 KAS.
    let survivor = 10 * KAS;
    let deposit = KAS / 100;
    type Base = fn(u64, u64, bool) -> Scenario;
    let flows: [(&str, Base); 2] = [
        ("minter reclaim into", reclaim_into_base),
        ("seed reclaim", seed_reclaim_base),
    ];
    for (name, flow) in flows {
        let own = move || flow(survivor, deposit, true);
        let merged = move || flow(survivor, deposit, false);
        let budgets = contract_budgets(&own);
        let label = format!("{name}, survivor 10 KAS, deposit 0.01 KAS");

        let large = paid(
            &format!("{label}, own coin, one coin of 100 KAS, change"),
            &own,
            &budgets,
            Pay::WithChange(1, 100 * KAS),
        );
        assert!(
            large.refused_for_storage(),
            "one coin of 100 KAS with change: refused for storage mass"
        );

        let exact = paid(
            &format!("{label}, own coin, one coin worth exactly the fee"),
            &own,
            &budgets,
            Pay::JustEnough(1),
        );
        let one_output = paid(
            &format!("{label}, ONE plain output: deposit + change of a 100 KAS coin"),
            &merged,
            &budgets,
            Pay::WithChange(1, 100 * KAS),
        );
        assert!(
            one_output.accepted(),
            "the deposit added to the payer's change"
        );
        let (smallest, below) =
            smallest_count(&format!("{label}, own coin"), &own, &budgets, 20, 90);
        assert!(smallest.accepted());
        // Observed for both flows: one coin worth exactly the fee is refused (storage mass
        // about 979,000), 18 small coins are refused, 19 are accepted.
        assert!(exact.refused_for_storage());
        assert_eq!(smallest.fee_coins, 19);
        assert!(
            below
                .as_ref()
                .expect("the row of 18 coins")
                .refused_for_storage()
        );
        println!(
            "RESULT | {label}: own coin with one exact coin {}; smallest count of small coins {} \
             (each {} sompi, fee {}; below: {:?}); one output: fee {}, storage {}",
            exact.accepted(),
            smallest.fee_coins,
            smallest.each,
            smallest.fee,
            below.as_ref().map(Row::accepted),
            one_output.fee,
            one_output.storage
        );

        // The same deposit next to a survivor that is small itself.
        let small_survivor = move || flow(KAS / 5, deposit, true);
        let budgets = contract_budgets(&small_survivor);
        let (smallest, _) = smallest_count(
            &format!("{name}, survivor 0.2 KAS, deposit 0.01 KAS, own coin"),
            &small_survivor,
            &budgets,
            2,
            90,
        );
        println!(
            "RESULT | {name}, survivor 0.2 KAS: smallest count of small coins {} (fee {})",
            smallest.fee_coins, smallest.fee
        );
        // Observed: next to a survivor of 0.2 KAS one coin worth exactly the fee is enough.
        assert_eq!(smallest.fee_coins, 1);
    }
}

/// `PublicMint.split`: a minter worth `minter` continues with the same value (M-28) and hands
/// part of its allowance to a new minter worth `added`.
fn split_base(minter: u64, added: u64) -> Scenario {
    let mut scenario = stripped(shapes::mint_split(&realistic(minter)), 1, 2);
    *scenario.outputs[1].value_mut() = added;
    scenario
}

#[test]
fn mass_the_allowance_of_a_small_minter_moves_by_split_and_by_reclaim_into() {
    if !plain_mode() {
        return;
    }
    // The continuing minter keeps its value (M-18, M-28, M-48); the allowance it holds can
    // move to a coin of another value. (1) split hands allowance to a new minter, here one
    // of 0.2 KAS; (2) reclaim_into moves the whole allowance of a small minter into another
    // minter.
    let small = KAS / 100;
    let base = move || split_base(small, KAS / 5);
    let found = rescue(
        "minter split, minter 0.01 KAS, new minter 0.2 KAS",
        &base,
        &[],
        5,
    );
    assert!(found.large.refused_for_storage());
    assert!(found.one.refused_for_storage());
    assert!(found.smallest.accepted());
    println!(
        "RESULT | minter split 0.01 KAS -> new minter 0.2 KAS: smallest count {} (each {} \
         sompi, fee {})",
        found.smallest.fee_coins, found.smallest.each, found.smallest.fee
    );

    // (2) A minter of 0.01 KAS with 4 left is absorbed by a minter of 10 KAS (18 left ->
    // 22); one large coin pays, the freed 0.01 KAS join its change.
    let absorbed = move || reclaim_into_base(10 * KAS, small, false);
    let budgets = contract_budgets(&absorbed);
    let row = paid(
        "minter 0.01 KAS absorbed by a minter of 10 KAS, one coin of 100 KAS, one plain output",
        &absorbed,
        &budgets,
        Pay::WithChange(1, 100 * KAS),
    );
    assert!(row.accepted());
    let scenario = absorbed();
    let survivor = scenario.outputs[0].clone();
    match survivor {
        OutputSpec::Contract(output) => {
            let state = output.state.as_public_mint().expect("a minter").clone();
            assert_eq!(state.remaining, 22, "the allowance of both minters");
        }
        OutputSpec::Plain(_) => panic!("output 0 is the surviving minter"),
    }
}

#[test]
fn mass_what_the_small_paying_coins_cost_to_make() {
    if !plain_mode() {
        return;
    }
    // Paying with several small coins needs such coins in the paying wallet. Cutting them
    // from a large coin is an ordinary transaction under the same storage rule: one input,
    // so the relaxed formula applies and every new coin costs C / value.
    let cut = |label: &str, coins: usize, value: u64| {
        let build = |change: u64| {
            let mut scenario = Scenario::new("cut small coins");
            scenario.push_ordinary_input(fee_coin(0, 100 * KAS, SIG_HASH_ALL));
            for _ in 0..coins {
                scenario.push_plain_output(PlainOutput::new(funder_script(), value));
            }
            scenario.push_plain_output(PlainOutput::new(funder_script(), change));
            scenario
        };
        let harness = || Harness::pinned().with_budgets(Budgets::Exactly(vec![FEE_COIN_BUDGET]));
        let floor = harness()
            .run(&build(1))
            .mempool
            .minimum_fee
            .expect("the fee floor of a well formed transaction is known");
        let scenario = build(100 * KAS - coins as u64 * value - floor);
        let outcome = harness().run(&scenario);
        let result = row(label, 1, 100 * KAS, &scenario, &outcome);
        println!("{}", result.line());
        result
    };
    // The paying coin of the 0.01 KAS minter (2,277,720 sompi): one per transaction, not two.
    let one = cut("cut one coin of 2,277,720 sompi from 100 KAS", 1, 2_277_720);
    let two = cut(
        "cut two coins of 2,277,720 sompi from 100 KAS",
        2,
        2_277_720,
    );
    assert!(one.accepted());
    assert!(two.refused_for_storage());
    // The paying coin of the 0.001 KAS minter (624,300 sompi): refused when cut from a coin
    // of 100 KAS.
    let tiny = cut("cut one coin of 624,300 sompi from 100 KAS", 1, 624_300);
    assert!(tiny.refused_for_storage());
    // Around 0.02 KAS: a coin of 2,000,100 sompi is cut from a coin of 100 KAS, one of
    // 1,990,000 sompi is refused.
    let edge = cut("cut one coin of 2,000,100 sompi from 100 KAS", 1, 2_000_100);
    let under = cut("cut one coin of 1,990,000 sompi from 100 KAS", 1, 1_990_000);
    println!(
        "RESULT | cutting: 2,277,720 fee {} storage {}; 2,000,100 accepted {} storage {}; \
         1,990,000 accepted {} storage {}",
        one.fee,
        one.storage,
        edge.accepted(),
        edge.storage,
        under.accepted(),
        under.storage
    );
    assert!(edge.accepted());
    assert!(under.refused_for_storage());

    // The 0.001 KAS minter paid with coins of 0.0205 KAS (cut in one step each) and change.
    // The rows are printed; nothing is asserted about them.
    let minter = KAS / 1000;
    let base = move || mint_base(minter, KAS / 10);
    let budgets = contract_budgets(&base);
    for count in [60, 70, 76, 80] {
        let result = paid(
            &format!("mint, minter 0.001 KAS, {count} coins of 0.0205 KAS, change"),
            &base,
            &budgets,
            Pay::WithChange(count, 2_050_000),
        );
        println!(
            "RESULT | 0.001 KAS minter with {count} one-step coins: accepted {} (storage {}, \
             compute {}, fee {}) {}",
            result.accepted(),
            result.storage,
            result.compute,
            result.fee,
            result.mempool_refusal
        );
    }
}

// --- a transfer and the bytes of its owner's witness ------------------------------------

/// A one-to-one transfer of Alice's token coin (10 KAS) to `recipient`, with a signed funding
/// coin at `outpoint(funding_seed, 0)`, change, and a fee of 0.05 KAS.
fn transfer_to(recipient: u8, funding_seed: u8) -> Scenario {
    let mut scenario = shapes::transfer(
        &Profile::Realistic(Realistic {
            fee: KAS / 20,
            ..Realistic::default()
        }),
        1,
        1,
    );
    let owner = keys::x_only(recipient);
    scenario.contract_input_mut(0).declared_states_mut()[0].owner = owner;
    scenario
        .contract_output_mut(0)
        .state
        .as_kcc20_mut()
        .expect("a token output")
        .owner = owner;
    scenario.ordinary_input_mut(1).outpoint = shapes::outpoint(funding_seed, 0);
    scenario
}

/// Wraps late bytes so that what they resolve to can be read after a run.
fn remembered(late: LateBytes) -> (LateBytes, Arc<Mutex<Vec<u8>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let late = late.map(move |bytes| {
        *sink.lock().expect("no panic while signing") = bytes.clone();
        bytes
    });
    (late, seen)
}

/// Alice signs the transfer to Bob (funding coin 3) with `hash_type`; the bytes of her witness.
fn owner_witness_for_bob(harness: &Harness, hash_type: SigHashType) -> Vec<u8> {
    let mut first = transfer_to(keys::BOB, 3);
    let (late, seen) = remembered(witness::owner_key(ALICE, EntryRole::Leader, hash_type));
    *first.contract_input_mut(0).witness_mut() = late;
    let outcome = harness.run(&first);
    assert!(
        outcome.scripts_accept() && outcome.consensus.accepted,
        "the transaction the signature was made for is accepted: {}",
        outcome.describe()
    );
    let bytes = seen.lock().expect("no panic while signing").clone();
    assert_eq!(bytes.len(), 66, "path byte and a 65-byte signature");
    assert_eq!(*bytes.last().expect("a type byte"), hash_type.to_u8());
    bytes
}

/// The same witness bytes in another transaction of the same token coin.
fn replayed(harness: &Harness, witness_bytes: &[u8], recipient: u8, funding_seed: u8) -> Outcome {
    let mut second = transfer_to(recipient, funding_seed);
    *second.contract_input_mut(0).witness_mut() = LateBytes::fixed(witness_bytes.to_vec());
    harness.run(&second)
}

fn passes(outcome: &Outcome, input: usize) -> bool {
    outcome.inputs[input]
        .alone
        .as_ref()
        .expect("the input was run")
        .ok
}

// --- refusals checked by removal ----------------------------------------------------------

/// The pinned contracts with the refusing opcode at `offset` of `contract` made harmless.
fn without_opcode(contract: Contract, offset: usize, opcode: &str) -> Family {
    let (from, to) = match opcode {
        "OpVerify" => (0x69u8, 0x75u8),
        "OpEqualVerify" => (0x88, 0x6d),
        "OpNumEqualVerify" => (0x9d, 0x6d),
        other => panic!("no replacement for {other}"),
    };
    let mut bytes = Family::pinned().bytecode(contract).to_vec();
    assert_eq!(bytes[offset], from, "{opcode} is at offset {offset}");
    bytes[offset] = to;
    Family::pinned()
        .with_bytecode(contract, bytes)
        .expect("a same-length replacement")
}

/// Where and by what `input` of `outcome` was refused: rule, byte offset, opcode name.
fn stop_of(outcome: &Outcome, input: usize) -> (Option<String>, usize, String) {
    let run = outcome.inputs[input]
        .alone
        .as_ref()
        .expect("the input was run");
    assert!(!run.ok, "input {input} is refused: {}", outcome.describe());
    let refusal = run.refusal.as_ref().expect("a refusal is attributed");
    (
        refusal.rule.clone(),
        refusal.byte_offset.expect("a byte offset"),
        refusal.opcode.clone().expect("an opcode"),
    )
}

#[test]
fn removal_the_value_rules_of_the_continuing_minter_and_seed() {
    if !plain_mode() {
        return;
    }
    // The value rules: the continuing coin keeps exactly the value of the spent one. Each
    // rule refuses one sompi less and one sompi more on output 0, and with the rule's own
    // opcode replaced the same transaction passes that input.
    let profile = Profile::Realistic(Realistic {
        fee: KAS / 20,
        ..Realistic::default()
    });
    type Shape = fn(&Profile) -> Scenario;
    let cases: [(&str, Contract, Shape); 6] = [
        ("M-18", Contract::PublicMint, shapes::mint),
        ("M-28", Contract::PublicMint, shapes::mint_split),
        ("M-48", Contract::PublicMint, shapes::mint_reclaim_into),
        ("S-16", Contract::TokenSeed, shapes::seed_create),
        ("S-23", Contract::TokenSeed, shapes::seed_split),
        ("S-34", Contract::TokenSeed, shapes::seed_reclaim),
    ];
    for (rule, contract, shape) in cases {
        let honest = run(&shape(&profile));
        assert!(
            honest.scripts_accept() && honest.consensus.accepted,
            "{rule}: honest"
        );
        let mut removed_at = None;
        for less in [true, false] {
            let mut changed = shape(&profile);
            let value = changed.outputs[0].value();
            *changed.outputs[0].value_mut() = if less { value - 1 } else { value + 1 };
            let outcome = run(&changed);
            let (by, offset, opcode) = stop_of(&outcome, 0);
            assert_eq!(
                by.as_deref(),
                Some(rule),
                "one sompi {}",
                if less { "less" } else { "more" }
            );
            assert!(
                outcome.consensus.context_accepted,
                "a node gets to the scripts"
            );
            for other in 1..outcome.inputs.len() {
                assert!(passes(&outcome, other), "{rule}: input {other} passes");
            }
            let family = without_opcode(contract, offset, &opcode);
            let relaxed = Harness::pinned().with_family(family).run(&changed);
            assert!(
                passes(&relaxed, 0),
                "{rule}: without the opcode at {offset} the input passes: {}",
                relaxed.describe()
            );
            removed_at = Some((offset, opcode));
        }
        println!("REMOVAL | {rule} {contract:?}: refusing opcode {removed_at:?}");
    }
}

#[test]
fn removal_a_stale_owner_signature_is_refused_by_k_38_itself() {
    if !plain_mode() {
        return;
    }
    let pinned = Harness::pinned();
    let w01 = owner_witness_for_bob(&pinned, SIG_HASH_ALL);
    let stale = replayed(&pinned, &w01, CAROL, 9);
    let (rule, offset, opcode) = stop_of(&stale, 0);
    assert_eq!(rule.as_deref(), Some("K-38"));
    assert_eq!(opcode, "OpVerify");
    println!("REMOVAL | K-38 KCC20.transfer: {opcode} at {offset}");

    let relaxed = Harness::pinned().with_family(without_opcode(Contract::Kcc20, offset, &opcode));
    let w01 = owner_witness_for_bob(&relaxed, SIG_HASH_ALL);
    let outcome = replayed(&relaxed, &w01, CAROL, 9);
    assert!(
        passes(&outcome, 0),
        "without K-38's OpVerify the stale signature passes: {}",
        outcome.describe()
    );
    assert!(outcome.scripts_accept());
}

#[test]
fn removal_the_delegate_side_refusal_of_a_stranger_s_signature() {
    if !plain_mode() {
        return;
    }
    // A delegate signed by a stranger: refused by the delegate-side copy of K-38, which has
    // its own offset; the leader passes.
    let stranger = || {
        let mut scenario = shapes::transfer(&Profile::Script, 2, 1);
        *scenario.contract_input_mut(1).witness_mut() =
            witness::owner_key(CAROL, EntryRole::Delegate, SIG_HASH_ALL);
        scenario
    };
    let outcome = run(&stranger());
    assert!(passes(&outcome, 0), "the leader passes alone");
    let (rule, offset, opcode) = stop_of(&outcome, 1);
    assert_eq!(rule.as_deref(), Some("K-38"));
    assert_ne!(offset, 2249, "not the leader-side copy of the rule");
    let relaxed = Harness::pinned()
        .with_family(without_opcode(Contract::Kcc20, offset, &opcode))
        .run(&stranger());
    assert!(passes(&relaxed, 1), "{}", relaxed.describe());
    println!("REMOVAL | K-38 KCC20.transfer_delegator: {opcode} at {offset}: passes");
}
