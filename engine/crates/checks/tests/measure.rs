//! What the honest transactions cost. Numbers only.
//!
//! The test writes `measure.json` next to the result files: for every honest shape of
//! `kcc20-family`, in each value profile, the size of every signature script, the script
//! units and the smallest budget of every input, and the three masses of the transaction;
//! and for a one-to-one token transfer with a fee-paying coin and change, the smallest
//! value of the token coin it can create so that a block may hold the transaction, and the
//! smallest with which a default node takes it into its mempool at the minimum fee.
//!
//! Nothing here asserts that a shape fits a limit. Whatever the numbers are, they are
//! the result; what a node says about each shape is recorded next to them as an observation.
//! What is asserted is that the measurement is sound: two measurements give the same
//! document, and every value a search reports is a boundary (accepted at the value, refused
//! one sompi below it, for the storage mass, with no counterexample among the probes). The
//! numbers themselves are pinned in `review_policy_masses_by_hand.rs` and
//! `review_policy_smallest_token_coin.rs`.

use checks::{Harness, Outcome, results, run};
use kcc20_family::{
    Scenario,
    keys::FUNDER,
    shapes::{self, Profile, Realistic, SOMPI_PER_KAS},
};
use serde::Serialize;

/// Version of the layout of `measure.json`: the profiles, and `smallest_created_token_coin`
/// with its assumptions and a sweep over the fee-paying coin.
const FORMAT: u32 = 2;

/// Value of the fee-paying coin in the search for the smallest created token coin.
const SEARCH_FUNDING_VALUE: u64 = 100 * SOMPI_PER_KAS;

/// The values of the fee-paying coin the search is repeated with, to show how far the
/// answer moves with it.
const SWEEP_FUNDING_VALUES: [u64; 4] = [
    SOMPI_PER_KAS,
    10 * SOMPI_PER_KAS,
    100 * SOMPI_PER_KAS,
    1_000 * SOMPI_PER_KAS,
];

/// Upper end of the search: a token coin as large as the fee-paying coin.
const SEARCH_UPPER_BOUND: u64 = 100 * SOMPI_PER_KAS;

#[derive(Clone, Debug, PartialEq, Serialize)]
struct InputMeasure {
    index: usize,
    /// `KCC20.transfer`, or `ordinary` for a coin of no contract.
    what: String,
    label: String,
    signature_script_bytes: usize,
    used_script_units: Option<u64>,
    used_sig_ops: Option<u16>,
    minimal_budget: Option<u16>,
    /// Signature operations the node's static scanner counts in the redeem script.
    p2sh_sig_ops: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ShapeMeasure {
    shape: String,
    inputs: Vec<InputMeasure>,
    outputs: usize,
    estimated_size: Option<u64>,
    compute_mass: Option<u64>,
    transient_mass: Option<u64>,
    storage_mass: Option<u64>,
    fee: Option<u64>,
    minimum_fee: Option<u64>,
    /// Observations, not requirements.
    scripts_accepted: bool,
    consensus_accepted_on_submission: bool,
    block_accepted: bool,
    block_refusal: Option<String>,
    mempool_accepted: bool,
    mempool_refusing_rules: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ProfileMeasure {
    profile: String,
    description: String,
    contract_coin_value: u64,
    shapes: Vec<ShapeMeasure>,
    /// The largest value over the shapes, with the shape that has it.
    largest_compute_mass: Option<(u64, String)>,
    largest_transient_mass: Option<(u64, String)>,
    largest_storage_mass: Option<(u64, String)>,
    largest_minimal_budget: Option<(u16, String)>,
    largest_signature_script_bytes: Option<(usize, String)>,
    shapes_accepted_by_scripts: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Probe {
    token_coin_value: u64,
    storage_mass: Option<u64>,
    accepted: bool,
    refusal: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Search {
    question: String,
    /// The smallest value, in sompi, of the token coin the transfer spends and creates for
    /// which the answer is yes. `None` when the answer is no even at the upper bound.
    smallest_created_token_coin_value: Option<u64>,
    /// The answer at that value and one sompi below it.
    at_the_value: Option<Probe>,
    one_sompi_below: Option<Probe>,
    /// The answer at the upper bound of the search.
    at_the_upper_bound: Probe,
    /// The search halves an interval, which finds the smallest value only if the answer
    /// never turns from yes to no as the value grows. These probes were made to look for a
    /// counterexample: values below the found one must say no, values above it yes.
    monotonicity_probes: Vec<Probe>,
    monotone_on_the_probes: bool,
    evaluations: usize,
}

/// The block search repeated with another fee-paying coin.
#[derive(Clone, Debug, PartialEq, Serialize)]
struct SweepPoint {
    funding_coin_value: u64,
    smallest_created_token_coin_value: Option<u64>,
    at_the_value: Option<Probe>,
    one_sompi_below: Option<Probe>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct SmallestCreatedTokenCoin {
    transaction: String,
    /// What the number depends on, and what it does not say.
    assumptions: Vec<String>,
    /// The rule both searches stop at.
    binding_rule: String,
    funding_coin_value: u64,
    fee: u64,
    fee_note: String,
    upper_bound: u64,
    /// Storage mass at a few round token coin values, for orientation.
    storage_mass_by_token_coin_value: Vec<Probe>,
    block: Search,
    mempool: Search,
    /// The block search with other fee-paying coins: the value moves with that coin.
    block_by_funding_coin_value: Vec<SweepPoint>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Limits {
    block_compute_mass: u64,
    block_transient_mass: u64,
    block_storage_mass: u64,
    mempool_compute_mass: u64,
    mempool_transient_mass: u64,
    mempool_storage_mass: u64,
    standard_mass_cap: Option<u64>,
    script_units_per_budget_unit: u64,
    free_script_units_per_input: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Document {
    format: u32,
    network: String,
    daa_score: u64,
    limits: Limits,
    budgets: String,
    profiles: Vec<ProfileMeasure>,
    smallest_created_token_coin: SmallestCreatedTokenCoin,
}

fn shape_measure(outcome: &Outcome) -> ShapeMeasure {
    let inputs = outcome
        .inputs
        .iter()
        .map(|input| InputMeasure {
            index: input.index,
            what: input.what(),
            label: input.label.clone(),
            signature_script_bytes: input.signature_script_len,
            used_script_units: input.alone.as_ref().map(|run| run.used_script_units),
            used_sig_ops: input.alone.as_ref().map(|run| run.used_sig_ops),
            minimal_budget: input.minimal_budget,
            p2sh_sig_ops: outcome
                .mempool
                .p2sh_sig_ops
                .get(input.index)
                .copied()
                .flatten(),
        })
        .collect();
    let masses = outcome.masses.as_ref();
    ShapeMeasure {
        shape: outcome.scenario.clone(),
        inputs,
        outputs: outcome.committed_tx.outputs.len(),
        estimated_size: masses.map(|masses| masses.estimated_size),
        compute_mass: masses.map(|masses| masses.compute_mass),
        transient_mass: masses.map(|masses| masses.transient_mass),
        storage_mass: masses.and_then(|masses| masses.calculated_storage_mass),
        fee: outcome.mempool.fee,
        minimum_fee: outcome.mempool.minimum_fee,
        scripts_accepted: outcome.scripts.accepted
            && outcome.scripts.accepted_under_committed_budgets == Some(true),
        consensus_accepted_on_submission: outcome.consensus.accepted,
        block_accepted: outcome.consensus.block.accepted,
        block_refusal: outcome
            .consensus
            .block
            .refusal
            .as_ref()
            .map(|refusal| refusal.error.clone()),
        mempool_accepted: outcome.mempool.accepted,
        mempool_refusing_rules: outcome
            .mempool
            .refused
            .iter()
            .map(|finding| finding.function.clone())
            .collect(),
    }
}

fn largest<T: Ord + Copy>(
    shapes: &[ShapeMeasure],
    value: impl Fn(&ShapeMeasure) -> Option<T>,
) -> Option<(T, String)> {
    shapes
        .iter()
        .filter_map(|shape| value(shape).map(|value| (value, shape.shape.clone())))
        // The first shape wins among equal values, so the answer does not depend on how
        // ties happen to be ordered.
        .fold(None, |best: Option<(T, String)>, candidate| match best {
            Some(best) if best.0 >= candidate.0 => Some(best),
            _ => Some(candidate),
        })
}

fn profile_measure(
    name: &str,
    description: &str,
    contract_coin_value: u64,
    scenarios: Vec<Scenario>,
) -> ProfileMeasure {
    let shapes: Vec<ShapeMeasure> = scenarios
        .iter()
        .map(|scenario| shape_measure(&run(scenario)))
        .collect();
    ProfileMeasure {
        profile: name.to_string(),
        description: description.to_string(),
        contract_coin_value,
        largest_compute_mass: largest(&shapes, |shape| shape.compute_mass),
        largest_transient_mass: largest(&shapes, |shape| shape.transient_mass),
        largest_storage_mass: largest(&shapes, |shape| shape.storage_mass),
        largest_minimal_budget: largest(&shapes, |shape| {
            shape
                .inputs
                .iter()
                .filter_map(|input| input.minimal_budget)
                .max()
        }),
        largest_signature_script_bytes: largest(&shapes, |shape| {
            shape
                .inputs
                .iter()
                .map(|input| input.signature_script_bytes)
                .max()
        }),
        shapes_accepted_by_scripts: shapes.iter().filter(|shape| shape.scripts_accepted).count(),
        shapes,
    }
}

/// The realistic shapes once more, each paying exactly the fee floor a mempool sets for it.
/// The floor depends on the size and the budgets of a transaction, not on its values, so
/// it is read from the run with the default fee.
fn realistic_shapes_at_the_fee_floor(with_default_fee: &ProfileMeasure) -> Vec<Scenario> {
    with_default_fee
        .shapes
        .iter()
        .enumerate()
        .map(|(index, measured)| {
            let fee = measured.minimum_fee.unwrap_or(Realistic::default().fee);
            let mut shapes = shapes::all(&Profile::Realistic(Realistic {
                fee,
                ..Realistic::default()
            }));
            shapes.swap_remove(index)
        })
        .collect()
}

/// A one-to-one token transfer with a fee-paying pay-to-public-key coin and change: the
/// token coin spent and the token coin created both have the value `token_coin_value`.
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

/// Which node answer a search asks for.
#[derive(Clone, Copy)]
enum Gate {
    Block,
    Mempool,
}

/// The two values of a search that do not change while it runs.
#[derive(Clone, Copy)]
struct Payer {
    /// Value of the fee-paying coin.
    funding_value: u64,
    /// The fee the transaction pays.
    fee: u64,
}

fn probe(gate: Gate, token_coin_value: u64, payer: Payer, evaluations: &mut usize) -> Probe {
    *evaluations += 1;
    let outcome = run(&token_transfer(
        token_coin_value,
        payer.funding_value,
        payer.fee,
    ));
    let (accepted, refusal) = match gate {
        Gate::Block => (
            outcome.consensus.block.accepted,
            outcome.consensus.block.refusal.as_ref(),
        ),
        Gate::Mempool => (
            outcome.mempool.accepted,
            outcome.mempool.first_refusal.as_ref(),
        ),
    };
    Probe {
        token_coin_value,
        storage_mass: outcome
            .masses
            .as_ref()
            .and_then(|masses| masses.calculated_storage_mass),
        accepted,
        refusal: refusal.map(|refusal| format!("{}: {}", refusal.rule, refusal.error)),
    }
}

/// The smallest token coin value in `1..=SEARCH_UPPER_BOUND` the gate accepts, by halving.
fn search(gate: Gate, question: &str, payer: Payer) -> Search {
    let mut evaluations = 0;
    let at_the_upper_bound = probe(gate, SEARCH_UPPER_BOUND, payer, &mut evaluations);
    if !at_the_upper_bound.accepted {
        return Search {
            question: question.to_string(),
            smallest_created_token_coin_value: None,
            at_the_value: None,
            one_sompi_below: None,
            at_the_upper_bound,
            monotonicity_probes: Vec::new(),
            monotone_on_the_probes: false,
            evaluations,
        };
    }
    // Invariant: `high` is accepted; every value below `low` that was probed is refused.
    let (mut low, mut high) = (1u64, SEARCH_UPPER_BOUND);
    while low < high {
        let middle = low + (high - low) / 2;
        if probe(gate, middle, payer, &mut evaluations).accepted {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    let found = high;
    let at_the_value = probe(gate, found, payer, &mut evaluations);
    let one_sompi_below = (found > 1).then(|| probe(gate, found - 1, payer, &mut evaluations));

    let mut probe_values: Vec<u64> = [
        found / 1000,
        found / 100,
        found / 10,
        found / 2,
        found * 2,
        found * 10,
        found * 100,
        found * 1000,
    ]
    .into_iter()
    .filter(|value| (1..=SEARCH_UPPER_BOUND).contains(value) && *value != found)
    .collect();
    probe_values.dedup();
    let monotonicity_probes: Vec<Probe> = probe_values
        .into_iter()
        .map(|value| probe(gate, value, payer, &mut evaluations))
        .collect();
    let monotone_on_the_probes = monotonicity_probes
        .iter()
        .all(|probe| probe.accepted == (probe.token_coin_value > found));

    Search {
        question: question.to_string(),
        smallest_created_token_coin_value: Some(found),
        at_the_value: Some(at_the_value),
        one_sompi_below,
        at_the_upper_bound,
        monotonicity_probes,
        monotone_on_the_probes,
        evaluations,
    }
}

fn smallest_created_token_coin(block_storage_limit: u64) -> SmallestCreatedTokenCoin {
    // The fee floor of this transaction, read from a run with a token coin of 10 KAS.
    let fee = run(&token_transfer(10 * SOMPI_PER_KAS, SEARCH_FUNDING_VALUE, 1))
        .mempool
        .minimum_fee
        .expect("the fee floor of a well formed transaction is known");
    let payer = Payer {
        funding_value: SEARCH_FUNDING_VALUE,
        fee,
    };
    let block_question = "a block may hold the transaction: consensus rules with the calculated storage mass committed, and the block's mass limits";
    let block_by_funding_coin_value = SWEEP_FUNDING_VALUES
        .into_iter()
        .map(|funding_value| {
            let found = search(Gate::Block, block_question, Payer { funding_value, fee });
            SweepPoint {
                funding_coin_value: funding_value,
                smallest_created_token_coin_value: found.smallest_created_token_coin_value,
                at_the_value: found.at_the_value,
                one_sompi_below: found.one_sompi_below,
            }
        })
        .collect();
    let mut unused = 0;
    let round_values = [
        1_000,
        SOMPI_PER_KAS / 1000,
        SOMPI_PER_KAS / 100,
        SOMPI_PER_KAS / 10,
        SOMPI_PER_KAS,
        10 * SOMPI_PER_KAS,
        100 * SOMPI_PER_KAS,
    ];
    SmallestCreatedTokenCoin {
        transaction: "KCC20.transfer of one token coin into one token coin of the same value, plus a pay-to-public-key coin that pays \
                      the fee and takes the change"
            .to_string(),
        assumptions: vec![
            "the token coin that is spent and the token coin that is created have the same value: that value is searched".to_string(),
            format!(
                "one ordinary coin of {SEARCH_FUNDING_VALUE} sompi pays the fee and takes the change; the value found moves with that coin \
                 (see block_by_funding_coin_value)"
            ),
            "the transfer is one to one: two token coins of the value found out of one transaction do not fit a block".to_string(),
            "the value limits the token coin a transfer creates, not the one it spends: review_policy_smallest_token_coin.rs moves \
             a token coin of 1,000 sompi into one of 0.1 KAS, the fee-paying coin adding the difference"
                .to_string(),
        ],
        binding_rule: format!(
            "the storage mass limit of a block, {block_storage_limit} grams: a consensus rule. The mempool applies the same number at \
             this DAA score, so the block search and the mempool search are one question and find one value"
        ),
        funding_coin_value: SEARCH_FUNDING_VALUE,
        fee,
        fee_note: "the smallest fee a default mempool accepts for this transaction; it depends on size and budgets only".to_string(),
        upper_bound: SEARCH_UPPER_BOUND,
        storage_mass_by_token_coin_value: round_values.into_iter().map(|value| probe(Gate::Block, value, payer, &mut unused)).collect(),
        block: search(Gate::Block, block_question, payer),
        mempool: search(Gate::Mempool, "a default node takes the transaction into its mempool at this fee: consensus rules and policy", payer),
        block_by_funding_coin_value,
    }
}

fn measure() -> Document {
    let harness = Harness::pinned();
    let node = &harness.node;
    let daa_score = node.pov_daa_score;
    let block_limits = node.params.block_mass_limits().get(daa_score);
    let mempool_limits = node.params.mempool_block_mass_limits().get(daa_score);

    let script = profile_measure(
        "script",
        "the script-only profile: contract coins of 1000 sompi, an OP_TRUE funding coin where a shape has one, no change",
        Profile::Script.coin_value(),
        shapes::all(&Profile::Script),
    );
    let realistic_default = Realistic::default();
    let realistic = profile_measure(
        "realistic",
        "contract coins of 10 KAS, a signed pay-to-public-key funding coin of 100 KAS, change, and the default fee of the profile",
        realistic_default.coin_value,
        shapes::all(&Profile::Realistic(realistic_default.clone())),
    );
    let realistic_at_the_fee_floor = profile_measure(
        "realistic_at_the_fee_floor",
        "the realistic profile with every transaction paying exactly the smallest fee a default mempool accepts for it",
        realistic_default.coin_value,
        realistic_shapes_at_the_fee_floor(&realistic),
    );

    Document {
        format: FORMAT,
        network: node.params.network_name(),
        daa_score,
        limits: Limits {
            block_compute_mass: block_limits.compute,
            block_transient_mass: block_limits.transient,
            block_storage_mass: block_limits.storage,
            mempool_compute_mass: mempool_limits.compute,
            mempool_transient_mass: mempool_limits.transient,
            mempool_storage_mass: mempool_limits.storage,
            standard_mass_cap: node_gate::policy::standard_transaction_mass_cap(&node.params, daa_score),
            script_units_per_budget_unit: kaspa_consensus_core::mass::SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT,
            free_script_units_per_input: kaspa_consensus_core::mass::free_script_units_per_input().0,
        },
        budgets: "every input carries the smallest compute budget that covers its run; the masses are those of that transaction".to_string(),
        profiles: vec![script, realistic, realistic_at_the_fee_floor],
        smallest_created_token_coin: smallest_created_token_coin(block_limits.storage),
    }
}

/// Asserts that a value a search reports is a boundary of the storage mass limit: the
/// gate accepts the transaction at the value with a storage mass within `limit`, and
/// refuses it one sompi below with a storage mass above `limit`, for that mass.
fn assert_is_a_storage_boundary(
    what: &str,
    value: Option<u64>,
    at_the_value: Option<&Probe>,
    one_sompi_below: Option<&Probe>,
    limit: u64,
) {
    let value = value.unwrap_or_else(|| panic!("{what}: no value was found"));
    let at = at_the_value.unwrap_or_else(|| panic!("{what}: no probe at the value"));
    let below = one_sompi_below.unwrap_or_else(|| panic!("{what}: no probe below the value"));
    assert_eq!(
        (at.token_coin_value, below.token_coin_value),
        (value, value - 1),
        "{what}"
    );
    assert!(at.accepted, "{what}: refused at the value: {at:?}");
    assert!(
        !below.accepted,
        "{what}: accepted one sompi below: {below:?}"
    );
    assert!(
        at.storage_mass.is_some_and(|mass| mass <= limit),
        "{what}: {at:?}"
    );
    assert!(
        below.storage_mass.is_some_and(|mass| mass > limit),
        "{what}: {below:?}"
    );
    let refusal = below.refusal.as_deref().unwrap_or_default();
    assert!(
        refusal.contains("StorageMass"),
        "{what}: one sompi below the transaction is refused by something else: {refusal}"
    );
}

#[test]
fn the_measurements_are_written_and_repeat() {
    let first = measure();
    let second = measure();
    let text = |document: &Document| serde_json::to_string(document).expect("plain data");
    assert_eq!(
        text(&first),
        text(&second),
        "two measurements of the same transactions differ"
    );

    // The document covers what it says it covers.
    assert_eq!(first.profiles.len(), 3);
    for profile in &first.profiles {
        assert_eq!(profile.shapes.len(), 29, "profile `{}`", profile.profile);
        assert!(profile.shapes.iter().all(|shape| !shape.inputs.is_empty()));
    }

    // The searches found boundaries, not just values: accepted at the value, refused one
    // sompi below for the storage mass, and no probe on the wrong side.
    let coin = &first.smallest_created_token_coin;
    let limit = first.limits.block_storage_mass;
    for (name, search) in [("block", &coin.block), ("mempool", &coin.mempool)] {
        assert_is_a_storage_boundary(
            name,
            search.smallest_created_token_coin_value,
            search.at_the_value.as_ref(),
            search.one_sompi_below.as_ref(),
            limit,
        );
        assert!(search.at_the_upper_bound.accepted, "{name}");
        assert!(
            !search.monotonicity_probes.is_empty() && search.monotone_on_the_probes,
            "{name}: a probe is on the wrong side of the value found: {:?}",
            search.monotonicity_probes
        );
    }
    // What the document says about the two searches: one limit, one value.
    assert_eq!(limit, first.limits.mempool_storage_mass);
    assert_eq!(
        coin.block.smallest_created_token_coin_value,
        coin.mempool.smallest_created_token_coin_value
    );
    // The sweep: every point is a boundary too, and the point of the main search is in it.
    assert_eq!(
        coin.block_by_funding_coin_value.len(),
        SWEEP_FUNDING_VALUES.len()
    );
    for point in &coin.block_by_funding_coin_value {
        assert_is_a_storage_boundary(
            &format!("fee-paying coin of {} sompi", point.funding_coin_value),
            point.smallest_created_token_coin_value,
            point.at_the_value.as_ref(),
            point.one_sompi_below.as_ref(),
            limit,
        );
        if point.funding_coin_value == coin.funding_coin_value {
            assert_eq!(
                point.smallest_created_token_coin_value,
                coin.block.smallest_created_token_coin_value
            );
        }
    }
    assert!(
        coin.block_by_funding_coin_value
            .iter()
            .any(|point| point.funding_coin_value == coin.funding_coin_value)
    );
    // The value does move with the fee-paying coin, as the document says.
    let values: std::collections::BTreeSet<Option<u64>> = coin
        .block_by_funding_coin_value
        .iter()
        .map(|point| point.smallest_created_token_coin_value)
        .collect();
    assert!(values.len() > 1, "{values:?}");

    let path = results::write_document("measure.json", &first);
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the file was written"))
            .expect("JSON");
    assert_eq!(written["format"], FORMAT);
    assert_eq!(written["profiles"].as_array().map(Vec::len), Some(3));
    println!("measurements written to {}", path.display());
}
