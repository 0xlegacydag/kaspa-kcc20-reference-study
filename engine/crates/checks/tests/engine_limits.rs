//! Numbers a wallet or a launch plan needs, measured on the node's own code.
//!
//! `measure.rs` records what the 29 honest shapes cost and the smallest token coin a
//! one-to-one transfer can create. This file goes on from there and writes `limits.json`
//! next to the result files, in five sections:
//!
//! 1. `expensive_transfers`: three token coins into three token coins with the costly owner
//!    and borrow schemes, against every limit a node applies, and how many of each fit a
//!    block; and an authority script at the limit of signature opcodes a mempool's scanner
//!    takes;
//! 2. `budget_floor`: the compute budget of every call of every honest shape against the
//!    script units an input gets for free, and what the budgets add to the fee floor;
//! 3. `smallest_values`: for every shape that creates coins, the smallest coin value a block
//!    and a default mempool accept when one fee-paying coin of 100 KAS pays;
//! 4. `chains`: the smallest single value for every covenant coin of a token's life (mint,
//!    transfer, create, receive, reclaim), each step paid by one fee-paying coin, for four
//!    sizes of that coin;
//! 5. `reclaims`: three deposits of a closed minter or seed, each paid out in three ways
//!    (to a plain coin of its own, added to the change of the fee-paying coin, or with no
//!    fee-paying coin): where the sompi go, who pays the fee, and what the storage mass
//!    rule says to each.
//!
//! The numbers are the result; they are written, not asserted. What is asserted is what must
//! hold for the numbers to mean anything: the honest transactions are accepted, a second
//! measurement gives the same document, a budget covers its run and one unit less does not,
//! every value a search reports is a boundary (accepted at the value, refused one sompi
//! below it).
//!
//! Every search rests on stated assumptions (who pays the fee, with a coin of which size,
//! which coins share the value searched); they are written into the document next to the
//! numbers, under `assumptions`. In the searches of sections 3 to 5 at most one coin pays
//! the fee. A value found is the smallest for that transaction with that coin: it is no
//! floor for a transaction built otherwise, for example one paid by several coins. This
//! file does not measure such transactions; `review_engine_topics.rs` pays a small minter,
//! a small seed and a small deposit with several coins.
//!
//! The result file of the binary has one summary line per measuring test. The measuring
//! tests are for an ordinary run; in the mutation mode of the test harness they return at
//! once.

use std::sync::OnceLock;

use checks::{Budgets, Harness, Outcome, results, run};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::{
    SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT, free_script_units_per_input,
};
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_txscript::opcodes::codes::{OpCheckSig, OpEndIf, OpFalse, OpIf, OpTrue};
use kaspa_txscript::{pay_to_script_hash_script, script_class::ScriptClass};
use kcc20_family::{
    EntryRole, Kcc20State, Scenario,
    keys::{self, ALICE, BOB, CAROL, FUNDER},
    raw,
    scenario::{InputSpec, LateBytes, OrdinaryInput},
    shapes::{self, BorrowKind, Profile, Realistic, SOMPI_PER_KAS},
    states::{BORROW_HASH_CHAIN, OWNER_P2PKH_ECDSA, OWNER_P2PKH_SCHNORR, OWNER_P2SH},
    witness,
};
use node_gate::policy::{
    DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE, MAX_STANDARD_P2SH_SIG_OPS,
    minimum_required_transaction_relay_fee,
};
use serde::Serialize;

/// Version of the layout of `limits.json`.
const LAYOUT: u32 = 1;

const KAS: u64 = SOMPI_PER_KAS;

/// Value of a covenant coin wherever a section is not about coin values.
const ROOMY_COIN: u64 = 10 * KAS;

/// Value of the fee-paying coin unless a section says otherwise.
const FUNDING: u64 = 100 * KAS;

/// A fee far above every floor, for the run a floor is read from.
const GENEROUS_FEE: u64 = KAS / 10;

/// Where the search for a smallest value starts doubling.
const SCAN_START: u64 = 100_000;

/// Where it gives up.
const SCAN_CEILING: u64 = 100 * KAS;

/// The sizes of the fee-paying coin the chain search is repeated with.
const SWEEP_FUNDING: [u64; 4] = [KAS, 10 * KAS, 100 * KAS, 1_000 * KAS];

/// The deposits of the reclaim section: 0.01, 0.1 and 1 KAS.
const DEPOSITS: [u64; 3] = [KAS / 100, KAS / 10, KAS];

// ---------------------------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------------------------

/// The realistic profile with the given values and the usual fee-paying key.
fn profile(coin_value: u64, funding_value: u64, fee: u64) -> Profile {
    Profile::Realistic(Realistic {
        coin_value,
        funding_value,
        fee,
        funding_key: FUNDER,
    })
}

/// Leader for input 0, delegate for the others.
fn role_of(input: usize) -> EntryRole {
    if input == 0 {
        EntryRole::Leader
    } else {
        EntryRole::Delegate
    }
}

/// Three token coins into three, every coin owned by the hash of a public key: scheme 0x01
/// (x-only key, Schnorr signature) or 0x02 (compressed key, ECDSA signature).
fn three_key_hash_owners(profile: &Profile, scheme: u8) -> Scenario {
    let mut scenario = shapes::transfer(profile, 3, 3);
    scenario.name = format!("transfer 3 to 3, three owners of scheme {scheme:#04x}");
    for index in 0..3 {
        let seed = ALICE + index as u8;
        let (owner, signed) = match scheme {
            OWNER_P2PKH_SCHNORR => (
                witness::public_key_hash(&keys::x_only(seed)),
                witness::owner_key_hash_schnorr(seed, role_of(index), SIG_HASH_ALL),
            ),
            OWNER_P2PKH_ECDSA => (
                witness::public_key_hash(&keys::compressed(seed)),
                witness::owner_key_hash_ecdsa(seed, role_of(index), SIG_HASH_ALL),
            ),
            other => panic!("owner scheme {other:#04x} is not a key hash scheme"),
        };
        let input = scenario.contract_input_mut(index);
        let state = input.state.as_kcc20_mut().expect("a token coin");
        state.owner_scheme = scheme;
        state.owner = owner;
        *input.witness_mut() = signed;
    }
    scenario
}

fn three_ecdsa_owners(profile: &Profile) -> Scenario {
    three_key_hash_owners(profile, OWNER_P2PKH_ECDSA)
}

fn three_schnorr_hash_owners(profile: &Profile) -> Scenario {
    three_key_hash_owners(profile, OWNER_P2PKH_SCHNORR)
}

fn three_plain_key_owners(profile: &Profile) -> Scenario {
    shapes::transfer(profile, 3, 3)
}

/// A hash-chain borrow with two signing delegates: Bob's coin (200 tokens) leads on the
/// borrow path with the one-time key's signature and gains one token; two owners join with
/// their signatures; three token coins come out.
fn hash_chain_leader_two_delegates(profile: &Profile) -> Scenario {
    let mut scenario = shapes::transfer(profile, 3, 3);
    scenario.name = "transfer 3 to 3, hash-chain borrow leader, two signing delegates".to_string();
    let guard = witness::chain_guard(&shapes::CHAIN_NEXT_GUARD, CAROL);
    let leader = Kcc20State::new(keys::x_only(BOB), 200).with_borrow(BORROW_HASH_CHAIN, guard);
    let next_states = vec![
        leader
            .clone()
            .with_amount(201)
            .with_borrow(BORROW_HASH_CHAIN, shapes::CHAIN_NEXT_GUARD),
        Kcc20State::new(keys::x_only(BOB + 1), 99),
        Kcc20State::new(keys::x_only(BOB + 2), 100),
    ];
    let input = scenario.contract_input_mut(0);
    input.label = "leader: Bob, hash-chain borrow".to_string();
    input.state = leader.into();
    *input.declared_states_mut() = next_states.clone();
    *input.witness_mut() =
        witness::borrow_hash_chain(shapes::CHAIN_NEXT_GUARD, CAROL, SIG_HASH_ALL);
    for (index, state) in next_states.into_iter().enumerate() {
        scenario.contract_output_mut(index).state = state.into();
    }
    scenario
}

/// Three token coins into three, every coin owned by a script hash (scheme 0x03), with one
/// authority coin per owner: inputs 3, 4 and 5, in front of the fee-paying coin. The three
/// authority scripts are the one-opcode scripts `OP_1`, `OP_2` and `OP_3`; their sompi go to
/// the change.
fn three_script_hash_owners(profile: &Profile) -> Scenario {
    let mut scenario = shapes::transfer(profile, 3, 3);
    scenario.name = "transfer 3 to 3, three owners of scheme 0x03".to_string();
    let authority_value = profile.coin_value();
    for (index, redeem) in [[0x51u8], [0x52], [0x53]].iter().enumerate() {
        let script = pay_to_script_hash_script(redeem);
        let owner: [u8; 32] = script.script()[2..34]
            .try_into()
            .expect("a pay-to-script-hash script holds a 32-byte hash");
        let authority_index = 3 + index;
        let input = scenario.contract_input_mut(index);
        let state = input.state.as_kcc20_mut().expect("a token coin");
        state.owner_scheme = OWNER_P2SH;
        state.owner = owner;
        *input.witness_mut() = witness::owner_script_hash(authority_index as u8, role_of(index));
        let authority = OrdinaryInput::new(
            script,
            authority_value,
            shapes::outpoint(2, index as u32),
            LateBytes::fixed(raw::push(redeem).expect("a one-byte push always fits a script")),
        )
        .labelled(format!("authority of token coin {index}"));
        scenario
            .inputs
            .insert(authority_index, InputSpec::Ordinary(authority));
    }
    let change = scenario.outputs.len() - 1;
    *scenario.outputs[change].value_mut() += 3 * authority_value;
    scenario
}

/// A transfer of a token coin owned by a script hash (scheme 0x03) whose authority script
/// holds `count` signature opcodes in a branch that never runs:
/// `OP_FALSE OP_IF <count x OP_CHECKSIG> OP_ENDIF OP_TRUE`. The scanner of a mempool counts
/// the opcodes of a redeem script whether they run or not.
fn authority_with_signature_opcodes(profile: &Profile, count: usize) -> Scenario {
    let mut redeem = vec![OpFalse, OpIf];
    redeem.extend(std::iter::repeat_n(OpCheckSig, count));
    redeem.extend([OpEndIf, OpTrue]);
    let script = pay_to_script_hash_script(&redeem);
    let owner: [u8; 32] = script.script()[2..34]
        .try_into()
        .expect("a pay-to-script-hash script holds a 32-byte hash");
    let mut scenario = shapes::transfer_with_owner_scheme(profile, EntryRole::Leader, OWNER_P2SH);
    scenario.name = format!("transfer, authority script with {count} signature opcodes");
    scenario
        .contract_input_mut(0)
        .state
        .as_kcc20_mut()
        .expect("a token coin")
        .owner = owner;
    let authority = scenario.ordinary_input_mut(1);
    authority.script_public_key = script;
    authority.signature_script =
        LateBytes::fixed(raw::push(&redeem).expect("a short push always fits a script"));
    scenario
}

/// A receive into a seeded coin: Bob's coin of zero tokens with threshold 0, as
/// `TokenSeed.create` makes it, leads on the borrow path without Bob's signature; Alice's
/// coin joins, signs and pays 11 tokens into it.
fn receive_into_a_seeded_coin(profile: &Profile) -> Scenario {
    let mut scenario = shapes::borrow(profile, BorrowKind::Threshold);
    scenario.name = "receive into a seeded zero coin".to_string();
    let seeded = Kcc20State::new(keys::x_only(BOB), 0).with_threshold(0);
    let next_states = vec![
        seeded.clone().with_amount(11),
        Kcc20State::new(keys::x_only(ALICE), 89),
    ];
    let input = scenario.contract_input_mut(0);
    input.label = "leader: Bob's seeded coin of zero tokens".to_string();
    input.state = seeded.into();
    *input.declared_states_mut() = next_states.clone();
    for (index, state) in next_states.into_iter().enumerate() {
        scenario.contract_output_mut(index).state = state.into();
    }
    scenario
}

fn transfer_1_to_1(profile: &Profile) -> Scenario {
    shapes::transfer(profile, 1, 1)
}

fn transfer_1_to_2(profile: &Profile) -> Scenario {
    shapes::transfer(profile, 1, 2)
}

fn transfer_1_to_3(profile: &Profile) -> Scenario {
    shapes::transfer(profile, 1, 3)
}

fn borrow_by_threshold(profile: &Profile) -> Scenario {
    shapes::borrow(profile, BorrowKind::Threshold)
}

/// The smallest fee a default mempool accepts for the transactions `build` makes. The floor
/// depends on the size and the budgets of a transaction, not on its values, so it is read
/// from one run with roomy values and a generous fee.
fn fee_floor(build: fn(&Profile) -> Scenario) -> u64 {
    run(&build(&profile(ROOMY_COIN, FUNDING, GENEROUS_FEE)))
        .mempool
        .minimum_fee
        .expect("the fee floor of a well formed transaction is known")
}

// ---------------------------------------------------------------------------------------------
// What is read from an outcome
// ---------------------------------------------------------------------------------------------

fn refusal_text(refusal: Option<&node_gate::verdict::Refusal>) -> Option<String> {
    refusal.map(|refusal| format!("{}: {}", refusal.rule, refusal.error))
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct InputCost {
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
struct TxCost {
    scenario: String,
    inputs: Vec<InputCost>,
    outputs: usize,
    estimated_size: Option<u64>,
    compute_mass: Option<u64>,
    transient_mass: Option<u64>,
    storage_mass: Option<u64>,
    fee: Option<u64>,
    minimum_fee: Option<u64>,
    /// The mass the fee floor is charged on.
    fee_mass: Option<u64>,
    scripts_accepted: bool,
    block_accepted: bool,
    block_refusal: Option<String>,
    mempool_accepted: bool,
    mempool_refusal: Option<String>,
}

fn scripts_accepted(outcome: &Outcome) -> bool {
    outcome.scripts.accepted && outcome.scripts.accepted_under_committed_budgets == Some(true)
}

fn tx_cost(outcome: &Outcome) -> TxCost {
    let inputs = outcome
        .inputs
        .iter()
        .map(|input| InputCost {
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
    TxCost {
        scenario: outcome.scenario.clone(),
        inputs,
        outputs: outcome.committed_tx.outputs.len(),
        estimated_size: masses.map(|masses| masses.estimated_size),
        compute_mass: masses.map(|masses| masses.compute_mass),
        transient_mass: masses.map(|masses| masses.transient_mass),
        storage_mass: masses.and_then(|masses| masses.calculated_storage_mass),
        fee: outcome.mempool.fee,
        minimum_fee: outcome.mempool.minimum_fee,
        fee_mass: outcome.mempool.fee_mass,
        scripts_accepted: scripts_accepted(outcome),
        block_accepted: outcome.consensus.block.accepted,
        block_refusal: refusal_text(outcome.consensus.block.refusal.as_ref()),
        mempool_accepted: outcome.mempool.accepted,
        mempool_refusal: refusal_text(outcome.mempool.first_refusal.as_ref()),
    }
}

// ---------------------------------------------------------------------------------------------
// The limits of the node
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize)]
struct NodeLimits {
    network: String,
    daa_score: u64,
    block_compute_mass: u64,
    block_transient_mass: u64,
    block_storage_mass: u64,
    mempool_compute_mass: u64,
    mempool_transient_mass: u64,
    mempool_storage_mass: u64,
    /// The mempool's transient mass limit one DAA score after the activation: the lower
    /// figure a mempool applies for a while after the fork.
    mempool_transient_mass_just_after_activation: u64,
    standard_mass_cap: Option<u64>,
    max_signature_script_bytes: usize,
    largest_compute_budget: u16,
    script_units_per_budget_unit: u64,
    free_script_units_per_input: u64,
    standard_p2sh_signature_operations: u16,
    relay_fee_sompi_per_kilogram: u64,
}

fn node_limits() -> NodeLimits {
    let harness = Harness::pinned();
    let node = &harness.node;
    let daa_score = node.pov_daa_score;
    let block = node.params.block_mass_limits().get(daa_score);
    let mempool = node.params.mempool_block_mass_limits().get(daa_score);
    let just_after_activation =
        daa_score.saturating_sub(node_gate::params::DEFAULT_DAA_MARGIN_AFTER_TOCCATA) + 1;
    NodeLimits {
        network: node.params.network_name(),
        daa_score,
        block_compute_mass: block.compute,
        block_transient_mass: block.transient,
        block_storage_mass: block.storage,
        mempool_compute_mass: mempool.compute,
        mempool_transient_mass: mempool.transient,
        mempool_storage_mass: mempool.storage,
        mempool_transient_mass_just_after_activation: node
            .params
            .mempool_block_mass_limits()
            .get(just_after_activation)
            .transient,
        standard_mass_cap: node_gate::policy::standard_transaction_mass_cap(
            &node.params,
            daa_score,
        ),
        max_signature_script_bytes: node.params.max_signature_script_len().get(daa_score),
        largest_compute_budget: u16::MAX,
        script_units_per_budget_unit: SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT,
        free_script_units_per_input: free_script_units_per_input().0,
        standard_p2sh_signature_operations: MAX_STANDARD_P2SH_SIG_OPS,
        relay_fee_sompi_per_kilogram: DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE,
    }
}

// ---------------------------------------------------------------------------------------------
// Section 1: the most expensive honest transfers
// ---------------------------------------------------------------------------------------------

/// How many copies of one transaction fit a block, by each mass a block limits.
#[derive(Clone, Debug, PartialEq, Serialize)]
struct PerBlock {
    by_compute_mass: Option<u64>,
    by_transient_mass: Option<u64>,
    /// `None` when the transaction has no storage mass.
    by_storage_mass: Option<u64>,
    fit: Option<u64>,
    binding_mass: String,
}

fn per_block(cost: &TxCost, compute: u64, transient: u64, storage: u64) -> PerBlock {
    let copies =
        |limit: u64, mass: Option<u64>| mass.filter(|mass| *mass > 0).map(|mass| limit / mass);
    let by_compute_mass = copies(compute, cost.compute_mass);
    let by_transient_mass = copies(transient, cost.transient_mass);
    let by_storage_mass = copies(storage, cost.storage_mass);
    let binding = [
        (by_compute_mass, "compute"),
        (by_transient_mass, "transient"),
        (by_storage_mass, "storage"),
    ]
    .into_iter()
    .filter_map(|(copies, name)| copies.map(|copies| (copies, name)))
    .min();
    PerBlock {
        by_compute_mass,
        by_transient_mass,
        by_storage_mass,
        fit: binding.map(|(copies, _)| copies),
        binding_mass: binding.map(|(_, name)| name).unwrap_or("none").to_string(),
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ExpensiveTransfer {
    description: String,
    cost: TxCost,
    largest_minimal_budget: Option<u16>,
    sum_of_minimal_budgets: u64,
    largest_signature_script_bytes: usize,
    sum_of_signature_script_bytes: usize,
    largest_p2sh_sig_ops: Option<u64>,
    /// Against the limits of a block.
    per_block: PerBlock,
    /// Against the limits a mempool builds block templates with.
    per_mempool_block: PerBlock,
    /// Against those limits with the transient figure of the time just after the fork.
    per_mempool_block_just_after_activation: PerBlock,
    /// Every input that needs a budget, with one unit less committed.
    one_budget_unit_less: Vec<BudgetBelow>,
    /// The first refusal of a default mempool when the fee is one sompi below the floor.
    one_sompi_below_the_fee_floor: Option<String>,
}

/// One input run under a budget one unit below its smallest, the other inputs unchanged.
#[derive(Clone, Debug, PartialEq, Serialize)]
struct BudgetBelow {
    input: usize,
    smallest_budget: u16,
    /// The engine's error for that input under the smaller budget.
    error: Option<String>,
    /// The inputs the node refuses under these budgets.
    refused_inputs: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ExpensiveTransfers {
    assumptions: Vec<String>,
    transfers: Vec<ExpensiveTransfer>,
    /// The scanner's limit from both sides: a token coin owned by a script hash, moved with
    /// an authority script of 1, 15 and 16 signature opcodes that never run.
    authority_script_at_the_scan_limit: Vec<ScanProbe>,
}

/// One transfer whose authority script holds a given number of signature opcodes.
#[derive(Clone, Debug, PartialEq, Serialize)]
struct ScanProbe {
    signature_opcodes: usize,
    /// What the node's static scanner counts in the authority's redeem script.
    counted_by_the_scanner: Option<u64>,
    /// What the authority input costs when it runs: the opcodes are in a dead branch.
    authority_script_units: Option<u64>,
    authority_budget: Option<u16>,
    fee: Option<u64>,
    minimum_fee: Option<u64>,
    scripts_accepted: bool,
    block_accepted: bool,
    mempool_accepted: bool,
    mempool_refusal: Option<String>,
}

fn scan_probe(signature_opcodes: usize) -> ScanProbe {
    let build = |fee: u64| {
        authority_with_signature_opcodes(&profile(ROOMY_COIN, FUNDING, fee), signature_opcodes)
    };
    let fee = run(&build(GENEROUS_FEE))
        .mempool
        .minimum_fee
        .expect("the fee floor of a well formed transaction is known");
    let outcome = run(&build(fee));
    let authority = &outcome.inputs[1];
    ScanProbe {
        signature_opcodes,
        counted_by_the_scanner: outcome.mempool.p2sh_sig_ops.get(1).copied().flatten(),
        authority_script_units: authority.alone.as_ref().map(|run| run.used_script_units),
        authority_budget: authority.minimal_budget,
        fee: outcome.mempool.fee,
        minimum_fee: outcome.mempool.minimum_fee,
        scripts_accepted: scripts_accepted(&outcome),
        block_accepted: outcome.consensus.block.accepted,
        mempool_accepted: outcome.mempool.accepted,
        mempool_refusal: refusal_text(outcome.mempool.first_refusal.as_ref()),
    }
}

fn expensive_transfers() -> ExpensiveTransfers {
    let limits = node_limits();
    // (what the transfer is, the function that builds its scenario)
    type Variant = (&'static str, fn(&Profile) -> Scenario);
    let variants: [Variant; 5] = [
        (
            "three owners by the hash of a compressed key, each with an ECDSA signature (scheme 0x02)",
            three_ecdsa_owners,
        ),
        (
            "three owners by the hash of an x-only key, each with a Schnorr signature (scheme 0x01)",
            three_schnorr_hash_owners,
        ),
        (
            "a hash-chain borrow leader (borrow scheme 0x03) and two delegates that sign with their keys",
            hash_chain_leader_two_delegates,
        ),
        (
            "three owners by script hash (scheme 0x03), each with an authority coin of its own",
            three_script_hash_owners,
        ),
        (
            "for comparison, the shape of the family: three owners by x-only key (scheme 0x00)",
            three_plain_key_owners,
        ),
    ];
    let transfers = variants
        .into_iter()
        .map(|(description, build)| {
            let fee = fee_floor(build);
            let scenario = build(&profile(ROOMY_COIN, FUNDING, fee));
            let outcome = run(&scenario);
            let cost = tx_cost(&outcome);
            let budgets = outcome
                .minimal_budgets()
                .expect("every input of an honest transfer has a smallest budget");
            let one_budget_unit_less = budgets
                .iter()
                .enumerate()
                .filter(|(_, budget)| **budget > 0)
                .map(|(input, budget)| {
                    let mut lowered = budgets.clone();
                    lowered[input] -= 1;
                    let under = Harness::pinned()
                        .with_budgets(Budgets::Exactly(lowered))
                        .run(&scenario);
                    BudgetBelow {
                        input,
                        smallest_budget: *budget,
                        error: under.inputs[input]
                            .committed
                            .as_ref()
                            .and_then(|run| run.error_variant())
                            .map(str::to_string),
                        refused_inputs: under
                            .scripts
                            .refused_inputs_under_committed_budgets
                            .clone(),
                    }
                })
                .collect();
            let below_the_floor = run(&build(&profile(ROOMY_COIN, FUNDING, fee - 1)));
            ExpensiveTransfer {
                one_budget_unit_less,
                one_sompi_below_the_fee_floor: refusal_text(
                    below_the_floor.mempool.first_refusal.as_ref(),
                ),
                description: description.to_string(),
                largest_minimal_budget: cost
                    .inputs
                    .iter()
                    .filter_map(|input| input.minimal_budget)
                    .max(),
                sum_of_minimal_budgets: cost
                    .inputs
                    .iter()
                    .filter_map(|input| input.minimal_budget)
                    .map(u64::from)
                    .sum(),
                largest_signature_script_bytes: cost
                    .inputs
                    .iter()
                    .map(|input| input.signature_script_bytes)
                    .max()
                    .unwrap_or(0),
                sum_of_signature_script_bytes: cost
                    .inputs
                    .iter()
                    .map(|input| input.signature_script_bytes)
                    .sum(),
                largest_p2sh_sig_ops: cost
                    .inputs
                    .iter()
                    .filter_map(|input| input.p2sh_sig_ops)
                    .max(),
                per_block: per_block(
                    &cost,
                    limits.block_compute_mass,
                    limits.block_transient_mass,
                    limits.block_storage_mass,
                ),
                per_mempool_block: per_block(
                    &cost,
                    limits.mempool_compute_mass,
                    limits.mempool_transient_mass,
                    limits.mempool_storage_mass,
                ),
                per_mempool_block_just_after_activation: per_block(
                    &cost,
                    limits.mempool_compute_mass,
                    limits.mempool_transient_mass_just_after_activation,
                    limits.mempool_storage_mass,
                ),
                cost,
            }
        })
        .collect();
    ExpensiveTransfers {
        assumptions: vec![
            format!("every covenant coin and every authority coin is worth {ROOMY_COIN} sompi"),
            format!(
                "one pay-to-public-key coin of {FUNDING} sompi pays the fee and takes the change; the fee is the smallest a default \
                 mempool accepts"
            ),
            "every input carries the smallest compute budget that covers its run".to_string(),
            "copies per block: the limit divided by the mass of one transaction, as if a block held nothing else".to_string(),
        ],
        transfers,
        authority_script_at_the_scan_limit: {
            let limit = usize::from(MAX_STANDARD_P2SH_SIG_OPS);
            [1, limit, limit + 1].into_iter().map(scan_probe).collect()
        },
    }
}

// ---------------------------------------------------------------------------------------------
// Section 2: the budget floor
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize)]
struct CallBudget {
    input: usize,
    /// `KCC20.transfer`, or `ordinary: ` and the label of a coin of no contract.
    what: String,
    /// Signature operations the node's static scanner counts in the redeem script; a
    /// default mempool takes no more than 15.
    p2sh_sig_ops: Option<u64>,
    used_script_units: u64,
    minimal_budget: u16,
    /// The run fits the script units every input gets without a budget.
    runs_for_free: bool,
    /// Script units the budget covers and the run does not use.
    unused_script_units: u64,
    /// Compute mass the budget adds, and that mass at the relay fee rate. A transaction pays
    /// for it only where compute mass is the mass its fee floor is charged on.
    budget_grams: u64,
    budget_sompi_at_the_relay_rate: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ShapeBudgets {
    shape: String,
    calls: Vec<CallBudget>,
    compute_mass: u64,
    compute_mass_with_budgets_of_zero: u64,
    transient_mass: u64,
    /// `compute` or `transient`: the mass the fee floor is charged on.
    fee_floor_charged_on: String,
    fee_floor: u64,
    fee_floor_with_budgets_of_zero: u64,
    /// What the budgets add to the smallest fee a mempool accepts.
    fee_floor_added_by_the_budgets: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct BudgetFloor {
    assumptions: Vec<String>,
    free_script_units_per_input: u64,
    script_units_per_budget_unit: u64,
    grams_per_budget_unit: u64,
    sompi_per_gram: u64,
    /// Every distinct call with the smallest and the largest budget seen over the shapes.
    calls: Vec<CallRange>,
    calls_that_run_for_free: Vec<String>,
    shapes: Vec<ShapeBudgets>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct CallRange {
    what: String,
    p2sh_sig_ops: Option<u64>,
    smallest_budget: u16,
    largest_budget: u16,
    fewest_script_units: u64,
    most_script_units: u64,
}

/// The fee floor of a transaction with these masses, by the node's own formula: the larger
/// of compute mass and half the transient mass, at the relay rate.
fn fee_floor_of_masses(compute_mass: u64, transient_mass: u64) -> (u64, &'static str) {
    let normalized_transient = transient_mass.div_ceil(2);
    let (mass, charged_on) = if compute_mass >= normalized_transient {
        (compute_mass, "compute")
    } else {
        (normalized_transient, "transient")
    };
    (
        minimum_required_transaction_relay_fee(mass, DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE),
        charged_on,
    )
}

fn budget_floor() -> BudgetFloor {
    let free = free_script_units_per_input().0;
    let per_unit = SCRIPT_UNITS_PER_COMPUTE_BUDGET_UNIT;
    let sompi_per_gram = DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE / 1_000;
    let mut grams_per_budget_unit = 0;
    let mut shapes_measured = Vec::new();
    let mut ranges: Vec<CallRange> = Vec::new();
    for scenario in shapes::all(&Profile::Realistic(Realistic::default())) {
        let outcome = run(&scenario);
        let budgets = outcome
            .minimal_budgets()
            .expect("every input of an honest shape has a smallest budget");
        let masses = outcome.masses.as_ref().expect("an honest shape has masses");
        let without = Harness::pinned()
            .with_budgets(Budgets::Exactly(vec![0; budgets.len()]))
            .run(&scenario);
        let masses_without = without
            .masses
            .as_ref()
            .expect("the masses do not depend on what the scripts say");
        let units: u64 = budgets.iter().copied().map(u64::from).sum();
        if units > 0 {
            grams_per_budget_unit = (masses.compute_mass - masses_without.compute_mass) / units;
        }
        let (floor, charged_on) = fee_floor_of_masses(masses.compute_mass, masses.transient_mass);
        let (floor_without, _) =
            fee_floor_of_masses(masses_without.compute_mass, masses_without.transient_mass);
        let calls: Vec<CallBudget> = outcome
            .inputs
            .iter()
            .map(|input| {
                let used = input
                    .alone
                    .as_ref()
                    .expect("every input of an honest shape runs")
                    .used_script_units;
                let budget = input.minimal_budget.expect("measured above");
                let budget_grams = u64::from(budget) * grams_per_budget_unit.max(1);
                CallBudget {
                    input: input.index,
                    what: match &input.contract {
                        Some(_) => input.what(),
                        None => format!("ordinary: {}", input.label),
                    },
                    p2sh_sig_ops: outcome
                        .mempool
                        .p2sh_sig_ops
                        .get(input.index)
                        .copied()
                        .flatten(),
                    used_script_units: used,
                    minimal_budget: budget,
                    runs_for_free: budget == 0,
                    unused_script_units: free + per_unit * u64::from(budget) - used,
                    budget_grams,
                    budget_sompi_at_the_relay_rate: budget_grams * sompi_per_gram,
                }
            })
            .collect();
        for call in &calls {
            match ranges.iter_mut().find(|range| range.what == call.what) {
                Some(range) => {
                    range.smallest_budget = range.smallest_budget.min(call.minimal_budget);
                    range.largest_budget = range.largest_budget.max(call.minimal_budget);
                    range.fewest_script_units =
                        range.fewest_script_units.min(call.used_script_units);
                    range.most_script_units = range.most_script_units.max(call.used_script_units);
                }
                None => ranges.push(CallRange {
                    what: call.what.clone(),
                    p2sh_sig_ops: call.p2sh_sig_ops,
                    smallest_budget: call.minimal_budget,
                    largest_budget: call.minimal_budget,
                    fewest_script_units: call.used_script_units,
                    most_script_units: call.used_script_units,
                }),
            }
        }
        shapes_measured.push(ShapeBudgets {
            shape: outcome.scenario.clone(),
            calls,
            compute_mass: masses.compute_mass,
            compute_mass_with_budgets_of_zero: masses_without.compute_mass,
            transient_mass: masses.transient_mass,
            fee_floor_charged_on: charged_on.to_string(),
            fee_floor: outcome.mempool.minimum_fee.unwrap_or(floor),
            fee_floor_with_budgets_of_zero: floor_without,
            fee_floor_added_by_the_budgets: floor - floor_without,
        });
    }
    BudgetFloor {
        assumptions: vec![
            "the honest shapes of the family in its realistic profile; `ordinary` is a coin of no contract, named by its label: \
             the fee-paying pay-to-public-key coin (one Schnorr check) or the one-opcode coin the owner schemes 0x03 and 0x04 need"
                .to_string(),
            "the fee floor with budgets of zero is the floor of the same bytes with every budget set to 0: a transaction a node \
             refuses wherever a call needs a budget, computed only to show what the budgets add"
                .to_string(),
            "budget_sompi_at_the_relay_rate is the budget's compute mass at the relay rate; the floor rises by less wherever it is \
             charged on the transient mass, which the budgets do not change"
                .to_string(),
        ],
        free_script_units_per_input: free,
        script_units_per_budget_unit: per_unit,
        grams_per_budget_unit,
        sompi_per_gram,
        calls_that_run_for_free: ranges
            .iter()
            .filter(|range| range.largest_budget == 0)
            .map(|range| range.what.clone())
            .collect(),
        calls: ranges,
        shapes: shapes_measured,
    }
}

// ---------------------------------------------------------------------------------------------
// Sections 3 and 4: the smallest coin values
// ---------------------------------------------------------------------------------------------

/// Which answer of the node a search asks for.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Gate {
    /// A block may hold the transaction.
    Block,
    /// A default node takes the transaction into its mempool.
    Mempool,
}

/// One transaction at one coin value, with both answers.
#[derive(Clone, Debug, PartialEq, Serialize)]
struct Probe {
    coin_value: u64,
    /// The fee-paying coin cannot cover the outputs and the fee: there is no transaction.
    not_affordable: bool,
    storage_mass: Option<u64>,
    fee: Option<u64>,
    minimum_fee: Option<u64>,
    block_accepted: bool,
    block_refusal: Option<String>,
    mempool_accepted: bool,
    mempool_refusal: Option<String>,
}

impl Probe {
    fn of(coin_value: u64, outcome: &Outcome) -> Self {
        Self {
            coin_value,
            not_affordable: false,
            storage_mass: outcome
                .masses
                .as_ref()
                .and_then(|masses| masses.calculated_storage_mass),
            fee: outcome.mempool.fee,
            minimum_fee: outcome.mempool.minimum_fee,
            block_accepted: outcome.consensus.block.accepted,
            block_refusal: refusal_text(outcome.consensus.block.refusal.as_ref()),
            mempool_accepted: outcome.mempool.accepted,
            mempool_refusal: refusal_text(outcome.mempool.first_refusal.as_ref()),
        }
    }

    fn not_affordable(coin_value: u64) -> Self {
        Self {
            coin_value,
            not_affordable: true,
            storage_mass: None,
            fee: None,
            minimum_fee: None,
            block_accepted: false,
            block_refusal: None,
            mempool_accepted: false,
            mempool_refusal: None,
        }
    }

    fn accepted(&self, gate: Gate) -> bool {
        match gate {
            Gate::Block => self.block_accepted,
            Gate::Mempool => self.mempool_accepted,
        }
    }

    fn refusal(&self, gate: Gate) -> &str {
        match gate {
            Gate::Block => self.block_refusal.as_deref(),
            Gate::Mempool => self.mempool_refusal.as_deref(),
        }
        .unwrap_or_default()
    }
}

/// The result of one search.
#[derive(Clone, Debug, PartialEq, Serialize)]
struct Smallest {
    /// The smallest accepted coin value in sompi. `None` when no value up to the ceiling of
    /// the search is accepted.
    smallest_coin_value: Option<u64>,
    at_the_value: Option<Probe>,
    one_sompi_below: Option<Probe>,
    /// Probes at a half, a tenth and a hundredth of the value: the search doubles and then
    /// halves, which finds the smallest value only if nothing below it is accepted.
    far_below: Vec<Probe>,
    evaluations: usize,
}

/// The smallest value in `1..=SCAN_CEILING` the gate accepts: the value is doubled from
/// `SCAN_START` until the gate accepts, then the last step is halved down to the boundary.
fn smallest_accepted(gate: Gate, mut probe: impl FnMut(u64) -> Probe) -> Smallest {
    let mut evaluations = 0usize;
    let mut refused_up_to = 0u64;
    let mut value = SCAN_START;
    let accepted_at = loop {
        evaluations += 1;
        if probe(value).accepted(gate) {
            break Some(value);
        }
        refused_up_to = value;
        if value >= SCAN_CEILING {
            break None;
        }
        value = (value * 2).min(SCAN_CEILING);
    };
    let Some(mut high) = accepted_at else {
        return Smallest {
            smallest_coin_value: None,
            at_the_value: None,
            one_sompi_below: None,
            far_below: Vec::new(),
            evaluations,
        };
    };
    let mut low = refused_up_to + 1;
    while low < high {
        let middle = low + (high - low) / 2;
        evaluations += 1;
        if probe(middle).accepted(gate) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    let far_below: Vec<Probe> = [high / 2, high / 10, high / 100]
        .into_iter()
        .filter(|value| *value >= 1 && *value < high)
        .map(&mut probe)
        .collect();
    evaluations += far_below.len() + 2;
    Smallest {
        smallest_coin_value: Some(high),
        at_the_value: Some(probe(high)),
        one_sompi_below: (high > 1).then(|| probe(high - 1)),
        far_below,
        evaluations,
    }
}

/// Asserts that a search found a boundary of `gate`: accepted at the value, refused one
/// sompi below it and at every probe far below it.
fn assert_is_a_boundary(what: &str, gate: Gate, found: &Smallest) {
    let value = found
        .smallest_coin_value
        .unwrap_or_else(|| panic!("{what}: no value was found"));
    let at = found.at_the_value.as_ref().expect("probed");
    let below = found.one_sompi_below.as_ref().expect("probed");
    assert_eq!(
        (at.coin_value, below.coin_value),
        (value, value - 1),
        "{what}"
    );
    assert!(at.accepted(gate), "{what}: refused at the value: {at:?}");
    assert!(
        !below.accepted(gate),
        "{what}: accepted one sompi below: {below:?}"
    );
    assert!(
        found.far_below.iter().all(|probe| !probe.accepted(gate)),
        "{what}: a smaller value is accepted: {:?}",
        found.far_below
    );
}

/// A shape that creates coins.
struct Creating {
    name: &'static str,
    build: fn(&Profile) -> Scenario,
    /// What the transaction creates.
    creates: &'static str,
    /// Covenant coins created minus covenant coins spent: what the fee-paying coin adds when
    /// every covenant coin has one value.
    coins_added: u64,
    /// The outputs that are new coins, as opposed to the successor of the coin spent.
    new_outputs: &'static [usize],
}

const CREATING: [Creating; 6] = [
    Creating {
        name: "mint",
        build: shapes::mint,
        creates: "the continuing minter (output 0) and a new token coin (output 1)",
        coins_added: 1,
        new_outputs: &[1],
    },
    Creating {
        name: "minter split",
        build: shapes::mint_split,
        creates: "the retained minter (output 0) and an added minter (output 1)",
        coins_added: 1,
        new_outputs: &[1],
    },
    Creating {
        name: "seed create",
        build: shapes::seed_create,
        creates: "the continuing seed (output 0) and a new token coin of zero tokens (output 1)",
        coins_added: 1,
        new_outputs: &[1],
    },
    Creating {
        name: "seed split",
        build: shapes::seed_split,
        creates: "the retained seed (output 0) and an added seed (output 1)",
        coins_added: 1,
        new_outputs: &[1],
    },
    Creating {
        name: "transfer 1 to 2",
        build: transfer_1_to_2,
        creates: "two token coins (outputs 0 and 1) out of one",
        coins_added: 1,
        new_outputs: &[0, 1],
    },
    Creating {
        name: "transfer 1 to 3",
        build: transfer_1_to_3,
        creates: "three token coins (outputs 0, 1 and 2) out of one",
        coins_added: 2,
        new_outputs: &[0, 1, 2],
    },
];

/// The transaction of `shape` with every covenant coin, spent and created, worth `value`.
fn uniform_probe(shape: &Creating, funding_value: u64, fee: u64, value: u64) -> Probe {
    let needed = u128::from(shape.coins_added) * u128::from(value) + u128::from(fee);
    if needed > u128::from(funding_value) {
        return Probe::not_affordable(value);
    }
    Probe::of(
        value,
        &run(&(shape.build)(&profile(value, funding_value, fee))),
    )
}

/// Gives every new coin of `shape` the value `new_value`; the change takes the difference.
/// `None` when the change cannot.
fn with_new_coins_worth(
    mut scenario: Scenario,
    shape: &Creating,
    new_value: u64,
) -> Option<Scenario> {
    let change = scenario.outputs.len() - 1;
    for &index in shape.new_outputs {
        let freed = scenario.outputs[index].value();
        *scenario.outputs[index].value_mut() = new_value;
        let rest = (scenario.outputs[change].value() + freed).checked_sub(new_value)?;
        *scenario.outputs[change].value_mut() = rest;
    }
    Some(scenario)
}

/// The transaction of `shape` with the coin spent and its successor worth `ROOMY_COIN` and
/// every new coin worth `value`; the difference goes to the change.
fn new_coin_probe(shape: &Creating, funding_value: u64, fee: u64, value: u64) -> Probe {
    let roomy = (shape.build)(&profile(ROOMY_COIN, funding_value, fee));
    match with_new_coins_worth(roomy, shape, value) {
        Some(scenario) => Probe::of(value, &run(&scenario)),
        None => Probe::not_affordable(value),
    }
}

/// The transaction of `shape` with the coin spent and its successor worth `value` and
/// every new coin worth `ROOMY_COIN`: how little a minter or a seed may hold for this
/// transaction, paid by this one fee-paying coin, to be accepted. The successor has the
/// value of the coin spent in every probe.
fn continuing_coin_probe(shape: &Creating, funding_value: u64, fee: u64, value: u64) -> Probe {
    let needed = u128::from(shape.coins_added) * u128::from(value) + u128::from(fee);
    if needed > u128::from(funding_value) {
        return Probe::not_affordable(value);
    }
    let small = (shape.build)(&profile(value, funding_value, fee));
    match with_new_coins_worth(small, shape, ROOMY_COIN) {
        Some(scenario) => Probe::of(value, &run(&scenario)),
        None => Probe::not_affordable(value),
    }
}

/// Both answers for one way of choosing the values of one shape.
#[derive(Clone, Debug, PartialEq, Serialize)]
struct BothGates {
    /// A block may hold the transaction: the consensus rules with the calculated storage
    /// mass committed, and the mass limits of a block.
    block: Smallest,
    /// A default node takes the transaction into its mempool at the fee floor.
    mempool: Smallest,
    /// The storage mass at a few round values, for orientation.
    at_round_values: Vec<Probe>,
}

fn both_gates(probe: impl Fn(u64) -> Probe) -> BothGates {
    let block = smallest_accepted(Gate::Block, &probe);
    // A mempool applies the consensus rules and more, so its smallest value is not below
    // the block's. Where it accepts at the block's value, that is its boundary as well.
    let mempool = match (&block.at_the_value, &block.one_sompi_below) {
        (Some(at), Some(below)) if at.mempool_accepted && !below.mempool_accepted => block.clone(),
        _ => smallest_accepted(Gate::Mempool, &probe),
    };
    BothGates {
        block,
        mempool,
        at_round_values: [KAS / 100, KAS / 10, KAS, 10 * KAS]
            .into_iter()
            .map(probe)
            .collect(),
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct SmallestOfShape {
    shape: String,
    creates: String,
    fee: u64,
    /// Every covenant coin of the transaction, spent and created, has the value searched.
    every_covenant_coin_alike: BothGates,
    /// The coin spent and its successor are worth 10 KAS; only the new coins have the value
    /// searched. For the two transfers every output is a new coin.
    only_the_new_coins: BothGates,
    /// The coin spent and its successor (a minter or a seed) have the value searched; the
    /// new coin is worth 10 KAS. `None` for the transfers, which have no successor.
    only_the_continuing_coin: Option<BothGates>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct SmallestValues {
    assumptions: Vec<String>,
    funding_coin_value: u64,
    shapes: Vec<SmallestOfShape>,
}

fn smallest_of_shape(shape: &Creating) -> SmallestOfShape {
    let fee = fee_floor(shape.build);
    SmallestOfShape {
        shape: shape.name.to_string(),
        creates: shape.creates.to_string(),
        fee,
        every_covenant_coin_alike: both_gates(|value| uniform_probe(shape, FUNDING, fee, value)),
        only_the_new_coins: both_gates(|value| new_coin_probe(shape, FUNDING, fee, value)),
        only_the_continuing_coin: (!shape.new_outputs.contains(&0))
            .then(|| both_gates(|value| continuing_coin_probe(shape, FUNDING, fee, value))),
    }
}

fn smallest_values() -> SmallestValues {
    SmallestValues {
        assumptions: vec![
            format!("one pay-to-public-key coin of {FUNDING} sompi pays the fee, adds the sompi of the new coins and takes the change"),
            "the fee is the smallest a default mempool accepts for the transaction; it depends on size and budgets, not on values"
                .to_string(),
            "every input carries the smallest compute budget that covers its run".to_string(),
            "the values are the smallest for coins CREATED by these transactions with this one fee-paying coin; they move with that \
             coin (see the section chains) and with the number of outputs, and they are no floor for a coin that only gets spent \
             nor for a transaction paid by several coins, which is not measured here"
                .to_string(),
            format!(
                "the search doubles the value from {SCAN_START} sompi until the node accepts and then halves the last step; a value \
                 is reported only as a boundary: accepted at the value, refused one sompi below"
            ),
        ],
        funding_coin_value: FUNDING,
        shapes: CREATING.iter().map(smallest_of_shape).collect(),
    }
}

/// One step of a token's life.
struct Step {
    name: &'static str,
    build: fn(&Profile) -> Scenario,
    /// Covenant coins and plain coins of the searched value created, minus those spent.
    coins_added: u64,
}

/// The steps, the most demanding first so that a probe below the answer fails early.
const STEPS: [Step; 9] = [
    Step {
        name: "mint",
        build: shapes::mint,
        coins_added: 1,
    },
    Step {
        name: "seed create",
        build: shapes::seed_create,
        coins_added: 1,
    },
    Step {
        name: "transfer 1 to 2 (a payment with token change)",
        build: transfer_1_to_2,
        coins_added: 1,
    },
    Step {
        name: "transfer 1 to 1",
        build: transfer_1_to_1,
        coins_added: 0,
    },
    Step {
        name: "receive into a seeded zero coin",
        build: receive_into_a_seeded_coin,
        coins_added: 0,
    },
    Step {
        name: "receive by threshold borrow",
        build: borrow_by_threshold,
        coins_added: 0,
    },
    Step {
        name: "minter reclaim",
        build: shapes::mint_reclaim,
        coins_added: 0,
    },
    Step {
        name: "minter reclaim into",
        build: shapes::mint_reclaim_into,
        coins_added: 0,
    },
    Step {
        name: "seed reclaim",
        build: shapes::seed_reclaim,
        coins_added: 0,
    },
];

fn step_probe(step: &Step, funding_value: u64, fee: u64, value: u64) -> Probe {
    let needed = u128::from(step.coins_added) * u128::from(value) + u128::from(fee);
    if needed > u128::from(funding_value) {
        return Probe::not_affordable(value);
    }
    Probe::of(
        value,
        &run(&(step.build)(&profile(value, funding_value, fee))),
    )
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct StepAnswer {
    step: String,
    fee: u64,
    at_the_value: Probe,
    one_sompi_below: Probe,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Chain {
    funding_coin_value: u64,
    /// The smallest single value of every covenant coin with which every step is taken into
    /// a default mempool.
    smallest_coin_value: Option<u64>,
    /// Every step at that value and one sompi below it.
    steps: Vec<StepAnswer>,
    /// The steps a mempool refuses one sompi below the value: the ones that set it.
    binding_steps: Vec<String>,
    far_below_refused_at: Vec<(u64, String)>,
    sum_of_fees: u64,
    evaluations: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Chains {
    assumptions: Vec<String>,
    steps: Vec<String>,
    chains: Vec<Chain>,
    /// A few single values put to every step with every fee-paying coin of the sweep: the
    /// largest value the sweep found, and three round ones.
    one_value_for_every_fee_paying_coin: Vec<OneValue>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct OneValue {
    coin_value: u64,
    every_step_accepted_with_every_fee_paying_coin: bool,
    /// Fee-paying coin and the first step a mempool refuses with it.
    refused: Vec<(u64, String)>,
    /// The fee-paying coins with which a mempool refuses a transfer of one token coin into
    /// three, which is not among the steps, at this value.
    transfer_1_to_3_refused_with: Vec<u64>,
}

fn one_value(fees: &[u64], fee_1_to_3: u64, coin_value: u64) -> OneValue {
    let mut runs = 0;
    let refused: Vec<(u64, String)> = SWEEP_FUNDING
        .into_iter()
        .filter_map(|funding_value| {
            first_refused_step(fees, funding_value, coin_value, &mut runs)
                .map(|step| (funding_value, STEPS[step].name.to_string()))
        })
        .collect();
    let into_three = CREATING
        .iter()
        .find(|shape| shape.name == "transfer 1 to 3")
        .expect("the shape is in the table");
    OneValue {
        coin_value,
        every_step_accepted_with_every_fee_paying_coin: refused.is_empty(),
        refused,
        transfer_1_to_3_refused_with: SWEEP_FUNDING
            .into_iter()
            .filter(|funding_value| {
                !uniform_probe(into_three, *funding_value, fee_1_to_3, coin_value).mempool_accepted
            })
            .collect(),
    }
}

/// The first step a default mempool refuses at `value`, if any.
fn first_refused_step(
    fees: &[u64],
    funding_value: u64,
    value: u64,
    runs: &mut usize,
) -> Option<usize> {
    STEPS.iter().zip(fees).position(|(step, fee)| {
        *runs += 1;
        !step_probe(step, funding_value, *fee, value).mempool_accepted
    })
}

fn chain(fees: &[u64], funding_value: u64) -> Chain {
    let mut runs = 0usize;
    let accepted = |value: u64, runs: &mut usize| {
        first_refused_step(fees, funding_value, value, runs).is_none()
    };
    let mut refused_up_to = 0u64;
    let mut value = SCAN_START;
    let accepted_at = loop {
        if accepted(value, &mut runs) {
            break Some(value);
        }
        refused_up_to = value;
        if value >= SCAN_CEILING {
            break None;
        }
        value = (value * 2).min(SCAN_CEILING);
    };
    let Some(mut high) = accepted_at else {
        return Chain {
            funding_coin_value: funding_value,
            smallest_coin_value: None,
            steps: Vec::new(),
            binding_steps: Vec::new(),
            far_below_refused_at: Vec::new(),
            sum_of_fees: fees.iter().sum(),
            evaluations: runs,
        };
    };
    let mut low = refused_up_to + 1;
    while low < high {
        let middle = low + (high - low) / 2;
        if accepted(middle, &mut runs) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    let steps: Vec<StepAnswer> = STEPS
        .iter()
        .zip(fees)
        .map(|(step, fee)| StepAnswer {
            step: step.name.to_string(),
            fee: *fee,
            at_the_value: step_probe(step, funding_value, *fee, high),
            one_sompi_below: step_probe(step, funding_value, *fee, high - 1),
        })
        .collect();
    runs += 2 * steps.len();
    let far_below_refused_at = [high / 2, high / 10]
        .into_iter()
        .filter_map(|value| {
            first_refused_step(fees, funding_value, value, &mut runs)
                .map(|step| (value, STEPS[step].name.to_string()))
        })
        .collect();
    Chain {
        funding_coin_value: funding_value,
        smallest_coin_value: Some(high),
        binding_steps: steps
            .iter()
            .filter(|step| !step.one_sompi_below.mempool_accepted)
            .map(|step| step.step.clone())
            .collect(),
        steps,
        far_below_refused_at,
        sum_of_fees: fees.iter().sum(),
        evaluations: runs,
    }
}

/// The fee floor of every step.
fn step_fees() -> Vec<u64> {
    STEPS.iter().map(|step| fee_floor(step.build)).collect()
}

fn chains() -> Chains {
    let fees = step_fees();
    let chains: Vec<Chain> = SWEEP_FUNDING
        .into_iter()
        .map(|funding_value| chain(&fees, funding_value))
        .collect();
    let largest_found = chains
        .iter()
        .filter_map(|chain| chain.smallest_coin_value)
        .max();
    let fee_1_to_3 = fee_floor(transfer_1_to_3);
    let one_value_for_every_fee_paying_coin = largest_found
        .into_iter()
        .chain([16_000_000, 20_000_000, 25_000_000])
        .map(|coin_value| one_value(&fees, fee_1_to_3, coin_value))
        .collect();
    Chains {
        assumptions: vec![
            "one value v for every covenant coin: the minter and the seed a launch leaves behind, every token coin, and the plain \
             coin a reclaim pays out"
                .to_string(),
            "every step is its own transaction with one fee-paying pay-to-public-key coin of the stated size, which adds the sompi \
             of a new coin, pays the fee and takes the change; v moves with the size of that coin (compare the chains); a step \
             paid by several coins is not measured"
                .to_string(),
            "every step pays exactly the smallest fee a default mempool accepts for it and carries the smallest budgets".to_string(),
            "the steps are judged one by one against coins of value v with synthetic outpoints: the values and scripts of a chain, \
             not one chain of transactions spending each other"
                .to_string(),
            "a transfer into three token coins is not among the steps; it needs a larger value (see smallest_values)".to_string(),
            "the launch transaction itself is not among the steps".to_string(),
        ],
        steps: STEPS.iter().map(|step| step.name.to_string()).collect(),
        chains,
        one_value_for_every_fee_paying_coin,
    }
}

// ---------------------------------------------------------------------------------------------
// Section 5: reclaims
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
enum Flow {
    MinterReclaim,
    MinterReclaimInto,
    SeedReclaim,
}

impl Flow {
    const ALL: [Flow; 3] = [
        Flow::MinterReclaim,
        Flow::MinterReclaimInto,
        Flow::SeedReclaim,
    ];

    fn name(self) -> &'static str {
        match self {
            Flow::MinterReclaim => "PublicMint.reclaim: the owner closes an exhausted minter",
            Flow::MinterReclaimInto => {
                "PublicMint.reclaim_into with reclaim_delegator: a minter is folded into another, its owner signs"
            }
            Flow::SeedReclaim => {
                "TokenSeed.reclaim with reclaim_delegator: a seed is closed next to another, its owner signs"
            }
        }
    }

    fn build(self, profile: &Profile) -> Scenario {
        match self {
            Flow::MinterReclaim => shapes::mint_reclaim(profile),
            Flow::MinterReclaimInto => shapes::mint_reclaim_into(profile),
            Flow::SeedReclaim => shapes::seed_reclaim(profile),
        }
    }

    /// The input that is closed, and the plain output its sompi go to in the honest shape.
    fn closed_input(self) -> usize {
        match self {
            Flow::MinterReclaim => 0,
            Flow::MinterReclaimInto | Flow::SeedReclaim => 1,
        }
    }

    fn deposit_output(self) -> usize {
        self.closed_input()
    }

    fn has_a_survivor(self) -> bool {
        self != Flow::MinterReclaim
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct CoinOut {
    index: usize,
    script_class: String,
    belongs_to: String,
    value: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Reclaim {
    flow: String,
    deposit: u64,
    variant: String,
    input_values: Vec<u64>,
    outputs: Vec<CoinOut>,
    fee: Option<u64>,
    minimum_fee: Option<u64>,
    fee_paid_by: String,
    scripts_accepted: bool,
    storage_mass: Option<u64>,
    block_accepted: bool,
    block_refusal: Option<String>,
    mempool_accepted: bool,
    mempool_refusal: Option<String>,
    /// The storage mass rule is what refuses the transaction.
    blocked_by_the_storage_mass: bool,
    note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Reclaims {
    assumptions: Vec<String>,
    cases: Vec<Reclaim>,
    /// For every flow, the smallest deposit its transaction pays out as a plain coin of its
    /// own: once with one fee-paying coin, once with none.
    smallest_deposits: Vec<SmallestDeposit>,
}

/// A search over the deposit: `coin_value` in its probes is the value of the closed coin.
#[derive(Clone, Debug, PartialEq, Serialize)]
struct SmallestDeposit {
    flow: String,
    variant: String,
    fee: u64,
    smallest: BothGates,
}

fn belongs_to(script: &ScriptPublicKey) -> String {
    for (seed, name) in [(ALICE, "Alice"), (BOB, "Bob"), (FUNDER, "the fee payer")] {
        if *script == shapes::pay_to_public_key_script(&keys::x_only(seed)) {
            return name.to_string();
        }
    }
    "a contract".to_string()
}

fn reclaim_record(
    flow: Flow,
    deposit: u64,
    variant: &str,
    fee_paid_by: &str,
    scenario: &Scenario,
    note: Option<String>,
) -> Reclaim {
    let outcome = run(scenario);
    let outputs = outcome
        .committed_tx
        .outputs
        .iter()
        .enumerate()
        .map(|(index, output)| CoinOut {
            index,
            script_class: format!("{:?}", ScriptClass::from_script(&output.script_public_key)),
            belongs_to: belongs_to(&output.script_public_key),
            value: output.value,
        })
        .collect();
    let block_refusal = refusal_text(outcome.consensus.block.refusal.as_ref());
    let mempool_refusal = refusal_text(outcome.mempool.first_refusal.as_ref());
    let blocked_by_the_storage_mass =
        [&block_refusal, &mempool_refusal]
            .into_iter()
            .any(|refusal| {
                refusal
                    .as_deref()
                    .is_some_and(|text| text.contains("StorageMass"))
            });
    Reclaim {
        flow: flow.name().to_string(),
        deposit,
        variant: variant.to_string(),
        input_values: scenario.inputs.iter().map(InputSpec::value).collect(),
        outputs,
        fee: outcome.mempool.fee,
        minimum_fee: outcome.mempool.minimum_fee,
        fee_paid_by: fee_paid_by.to_string(),
        scripts_accepted: scripts_accepted(&outcome),
        storage_mass: outcome
            .masses
            .as_ref()
            .and_then(|masses| masses.calculated_storage_mass),
        block_accepted: outcome.consensus.block.accepted,
        blocked_by_the_storage_mass,
        block_refusal,
        mempool_accepted: outcome.mempool.accepted,
        mempool_refusal,
        note,
    }
}

/// The honest shape with a fee-paying coin: the closed coin is worth `deposit`, a surviving
/// coin `ROOMY_COIN`, and the deposit goes to a plain coin of the owner who signs.
fn funded_reclaim(flow: Flow, deposit: u64, fee: u64) -> Scenario {
    let mut scenario = flow.build(&profile(ROOMY_COIN, FUNDING, fee));
    scenario.contract_input_mut(flow.closed_input()).value = deposit;
    scenario.plain_output_mut(flow.deposit_output()).value = deposit;
    scenario
}

/// The same with the deposit added to the change of the fee payer instead of a coin of its
/// own: one output less.
fn merged_reclaim(flow: Flow, deposit: u64, fee: u64) -> Scenario {
    let mut scenario = funded_reclaim(flow, deposit, fee);
    scenario.outputs.remove(flow.deposit_output());
    let change = scenario.outputs.len() - 1;
    *scenario.outputs[change].value_mut() += deposit;
    scenario
}

/// The shape of the script profile, without a fee-paying coin: the fee comes out of the
/// deposit.
fn self_paid_reclaim(flow: Flow, deposit: u64, paid_out: u64) -> Scenario {
    let mut scenario = flow.build(&Profile::Script);
    if flow.has_a_survivor() {
        scenario.contract_input_mut(0).value = ROOMY_COIN;
        scenario.contract_output_mut(0).value = ROOMY_COIN;
    }
    scenario.contract_input_mut(flow.closed_input()).value = deposit;
    scenario.plain_output_mut(flow.deposit_output()).value = paid_out;
    scenario
}

fn reclaims() -> Reclaims {
    let mut cases = Vec::new();
    let mut smallest_deposits = Vec::new();
    for flow in Flow::ALL {
        let funded_fee = run(&funded_reclaim(flow, KAS, GENEROUS_FEE))
            .mempool
            .minimum_fee
            .expect("known");
        let merged_fee = run(&merged_reclaim(flow, KAS, GENEROUS_FEE))
            .mempool
            .minimum_fee
            .expect("known");
        let self_paid_fee = run(&self_paid_reclaim(flow, KAS, KAS / 2))
            .mempool
            .minimum_fee
            .expect("known");
        for deposit in DEPOSITS {
            cases.push(reclaim_record(
                flow,
                deposit,
                "a fee-paying coin; the deposit goes to a plain coin of its owner",
                "the fee-paying coin: none of the fee comes out of the deposit",
                &funded_reclaim(flow, deposit, funded_fee),
                None,
            ));
            cases.push(reclaim_record(
                flow,
                deposit,
                "a fee-paying coin; the deposit is added to its change, no coin of its own",
                "the fee-paying coin, which also takes the deposit",
                &merged_reclaim(flow, deposit, merged_fee),
                None,
            ));
            let (paid_out, note) = match deposit.checked_sub(self_paid_fee) {
                Some(rest) if rest > 0 => (rest, None),
                _ => (
                    1,
                    Some(format!(
                        "the deposit of {deposit} sompi does not cover the fee floor of {self_paid_fee} sompi: the transaction \
                         pays out 1 sompi and its fee is below the floor"
                    )),
                ),
            };
            cases.push(reclaim_record(
                flow,
                deposit,
                "no fee-paying coin; the fee comes out of the deposit",
                "the deposit",
                &self_paid_reclaim(flow, deposit, paid_out),
                note,
            ));
        }
        smallest_deposits.push(SmallestDeposit {
            flow: flow.name().to_string(),
            variant: "a fee-paying coin; the deposit goes to a plain coin of its owner".to_string(),
            fee: funded_fee,
            smallest: both_gates(|deposit| {
                Probe::of(deposit, &run(&funded_reclaim(flow, deposit, funded_fee)))
            }),
        });
        smallest_deposits.push(SmallestDeposit {
            flow: flow.name().to_string(),
            variant: "no fee-paying coin; the fee comes out of the deposit".to_string(),
            fee: self_paid_fee,
            smallest: both_gates(|deposit| match deposit.checked_sub(self_paid_fee) {
                Some(paid_out) if paid_out > 0 => {
                    Probe::of(deposit, &run(&self_paid_reclaim(flow, deposit, paid_out)))
                }
                _ => Probe::not_affordable(deposit),
            }),
        });
    }
    Reclaims {
        smallest_deposits,
        assumptions: vec![
            format!(
                "a surviving minter or seed is worth {ROOMY_COIN} sompi and keeps that value; only the closed coin has the deposit's value"
            ),
            format!("the fee-paying coin, where there is one, is a pay-to-public-key coin of {FUNDING} sompi"),
            "every transaction pays the smallest fee a default mempool accepts for it".to_string(),
            "the variants differ in where the deposit goes: a plain coin of its own, the change of the fee-paying coin, or a plain \
             coin after the fee where no coin pays it; the answer of the storage mass rule is recorded per variant and holds for \
             that variant only"
                .to_string(),
        ],
        cases,
    }
}

// ---------------------------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Document {
    layout: u32,
    limits: NodeLimits,
    expensive_transfers: ExpensiveTransfers,
    budget_floor: BudgetFloor,
    smallest_values: SmallestValues,
    chains: Chains,
    reclaims: Reclaims,
}

fn expensive_transfers_once() -> &'static ExpensiveTransfers {
    static CELL: OnceLock<ExpensiveTransfers> = OnceLock::new();
    CELL.get_or_init(expensive_transfers)
}

fn budget_floor_once() -> &'static BudgetFloor {
    static CELL: OnceLock<BudgetFloor> = OnceLock::new();
    CELL.get_or_init(budget_floor)
}

fn smallest_values_once() -> &'static SmallestValues {
    static CELL: OnceLock<SmallestValues> = OnceLock::new();
    CELL.get_or_init(smallest_values)
}

fn chains_once() -> &'static Chains {
    static CELL: OnceLock<Chains> = OnceLock::new();
    CELL.get_or_init(chains)
}

fn reclaims_once() -> &'static Reclaims {
    static CELL: OnceLock<Reclaims> = OnceLock::new();
    CELL.get_or_init(reclaims)
}

fn json(value: &impl Serialize) -> String {
    serde_json::to_string(value).expect("plain data")
}

/// Whether this is an ordinary run. The measurements are of the pinned contracts as a node
/// judges them; in the mutation mode of the test harness (a weakened contract, a list of
/// cases, script verdicts only) there is nothing to measure and the measuring tests return
/// at once.
fn measuring() -> bool {
    checks::mutation::mode().is_plain()
}

/// Sompi as KAS with eight decimals, for the notes of the result lines.
fn kas(sompi: u64) -> String {
    format!("{}.{:08} KAS", sompi / KAS, sompi % KAS)
}

// ---------------------------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------------------------

#[test]
fn the_most_expensive_transfers_are_accepted_and_measured_alike_twice() {
    if !measuring() {
        return;
    }
    let first = expensive_transfers_once();
    assert_eq!(
        json(first),
        json(&expensive_transfers()),
        "two measurements differ"
    );
    assert_eq!(first.transfers.len(), 5);
    let limits = node_limits();
    for transfer in &first.transfers {
        let cost = &transfer.cost;
        let what = &cost.scenario;
        // The numbers are those of a transaction a node accepts, at exactly the fee floor.
        assert!(cost.scripts_accepted, "{what}: {cost:?}");
        assert!(cost.block_accepted, "{what}: {:?}", cost.block_refusal);
        assert!(cost.mempool_accepted, "{what}: {:?}", cost.mempool_refusal);
        assert_eq!(cost.fee, cost.minimum_fee, "{what}");
        // Three token coins in, three out, and whatever the scheme adds.
        assert_eq!(
            cost.inputs
                .iter()
                .filter(|input| input.what.starts_with("KCC20."))
                .count(),
            3,
            "{what}"
        );
        // The limits a default node applies to one input, as read from the node.
        for input in &cost.inputs {
            assert!(
                input.signature_script_bytes <= limits.max_signature_script_bytes,
                "{what}"
            );
            assert!(
                input.p2sh_sig_ops.is_none_or(
                    |count| count <= u64::from(limits.standard_p2sh_signature_operations)
                ),
                "{what}: input {} has {:?} signature operations",
                input.index,
                input.p2sh_sig_ops
            );
        }
        assert!(
            transfer.per_block.fit.is_some_and(|copies| copies >= 1),
            "{what}"
        );
        // The budgets are boundaries on the engine: with one unit less on one input a node
        // refuses that input, and only it, for the budget.
        assert_eq!(
            transfer.one_budget_unit_less.len(),
            cost.inputs
                .iter()
                .filter(|input| input.minimal_budget.is_some_and(|budget| budget > 0))
                .count(),
            "{what}"
        );
        for below in &transfer.one_budget_unit_less {
            assert_eq!(
                below.error.as_deref(),
                Some("ExceededCommittedScriptUnits"),
                "{what}, input {}",
                below.input
            );
            assert_eq!(below.refused_inputs, vec![below.input], "{what}");
        }
        // So is the fee: one sompi below the floor a default mempool refuses for the fee.
        assert!(
            transfer
                .one_sompi_below_the_fee_floor
                .as_deref()
                .is_some_and(|refusal| refusal.starts_with("check_minimum_relay_fee")),
            "{what}: {:?}",
            transfer.one_sompi_below_the_fee_floor
        );
    }
    // The scanner's limit is a boundary of a default mempool, and of nothing else: the
    // scripts and a block take the authority script with one signature opcode more.
    let scan = &first.authority_script_at_the_scan_limit;
    let limit = usize::from(limits.standard_p2sh_signature_operations);
    assert_eq!(
        scan.iter()
            .map(|probe| probe.signature_opcodes)
            .collect::<Vec<_>>(),
        vec![1, limit, limit + 1]
    );
    for probe in scan {
        let what = format!(
            "authority script with {} signature opcodes",
            probe.signature_opcodes
        );
        assert_eq!(
            probe.counted_by_the_scanner,
            Some(probe.signature_opcodes as u64),
            "{what}"
        );
        assert!(probe.scripts_accepted && probe.block_accepted, "{what}");
        assert_eq!(probe.fee, probe.minimum_fee, "{what}");
        assert_eq!(
            probe.mempool_accepted,
            probe.signature_opcodes <= limit,
            "{what}: {:?}",
            probe.mempool_refusal
        );
    }
    let worst =
        |value: fn(&ExpensiveTransfer) -> u64| first.transfers.iter().map(value).max().unwrap_or(0);
    results::record_structural(
        "limits/expensive transfers",
        &[],
        &format!(
            "five transfers of three token coins into three are accepted by the scripts, a block and a default mempool at the \
             fee floor; one budget unit less on any input and one sompi less fee are refused. Largest over the five: budget {} \
             of {}, signature script {} of {} bytes, compute mass {} of {}, transient mass {} of {}, {} signature \
             operations by the scanner of {}; fewest copies per block {}. An authority script with {limit} signature \
             opcodes is taken by a default mempool, one with {} is not, though the scripts and a block take it. Numbers: \
             limits.json, expensive_transfers",
            worst(|transfer| u64::from(transfer.largest_minimal_budget.unwrap_or(0))),
            limits.largest_compute_budget,
            worst(|transfer| transfer.largest_signature_script_bytes as u64),
            limits.max_signature_script_bytes,
            worst(|transfer| transfer.cost.compute_mass.unwrap_or(0)),
            limits.block_compute_mass,
            worst(|transfer| transfer.cost.transient_mass.unwrap_or(0)),
            limits.block_transient_mass,
            worst(|transfer| transfer.largest_p2sh_sig_ops.unwrap_or(0)),
            limits.standard_p2sh_signature_operations,
            first
                .transfers
                .iter()
                .filter_map(|transfer| transfer.per_block.fit)
                .min()
                .unwrap_or(0),
            limit + 1,
        ),
    );
}

#[test]
fn a_budget_covers_its_run_and_one_unit_less_does_not() {
    if !measuring() {
        return;
    }
    let floor = budget_floor_once();
    assert_eq!(
        json(floor),
        json(&budget_floor()),
        "two measurements differ"
    );
    assert_eq!(floor.shapes.len(), 29);
    let (free, per_unit) = (
        floor.free_script_units_per_input,
        floor.script_units_per_budget_unit,
    );
    for shape in &floor.shapes {
        for call in &shape.calls {
            let what = format!("{} input {} ({})", shape.shape, call.input, call.what);
            let budget = u64::from(call.minimal_budget);
            assert!(call.used_script_units <= free + per_unit * budget, "{what}");
            assert!(
                budget == 0 || call.used_script_units > free + per_unit * (budget - 1),
                "{what}: a smaller budget would cover {} script units",
                call.used_script_units
            );
            assert_eq!(call.runs_for_free, call.used_script_units <= free, "{what}");
            assert!(
                call.p2sh_sig_ops
                    .is_none_or(|count| count <= u64::from(MAX_STANDARD_P2SH_SIG_OPS)),
                "{what}: {:?} signature operations",
                call.p2sh_sig_ops
            );
        }
        // The formula the document uses for the floor without budgets is the node's: with
        // the measured budgets it gives the floor the node reports.
        let (by_formula, _) = fee_floor_of_masses(shape.compute_mass, shape.transient_mass);
        assert_eq!(by_formula, shape.fee_floor, "{}", shape.shape);
        // Budgets are compute mass and nothing else.
        let units: u64 = shape
            .calls
            .iter()
            .map(|call| u64::from(call.minimal_budget))
            .sum();
        assert_eq!(
            shape.compute_mass - shape.compute_mass_with_budgets_of_zero,
            units * floor.grams_per_budget_unit,
            "{}",
            shape.shape
        );
    }
    let paying: Vec<&str> = floor
        .shapes
        .iter()
        .filter(|shape| shape.fee_floor_added_by_the_budgets > 0)
        .map(|shape| shape.shape.as_str())
        .collect();
    results::record_structural(
        "limits/budget floor",
        &[],
        &format!(
            "every call of the 29 honest shapes: the smallest budget covers the run and one unit less does not. Calls that run \
             on the free {} script units: {:?}. A budget unit adds {} grams of compute mass; the relay rate is {} sompi per gram. \
             The fee floor is charged on the larger of compute mass and half the transient mass: the budgets raise the floor \
             of {} of 29 shapes only ({:?}). Numbers: limits.json, budget_floor",
            floor.free_script_units_per_input,
            floor.calls_that_run_for_free,
            floor.grams_per_budget_unit,
            floor.sompi_per_gram,
            paying.len(),
            paying,
        ),
    );
}

#[test]
fn the_smallest_values_of_created_coins_are_boundaries() {
    if !measuring() {
        return;
    }
    let values = smallest_values_once();
    assert_eq!(values.shapes.len(), CREATING.len());
    for shape in &values.shapes {
        let variants = [
            (
                "every covenant coin alike",
                Some(&shape.every_covenant_coin_alike),
            ),
            ("only the new coins", Some(&shape.only_the_new_coins)),
            (
                "only the continuing coin",
                shape.only_the_continuing_coin.as_ref(),
            ),
        ];
        for (name, gates) in variants
            .into_iter()
            .filter_map(|(name, gates)| gates.map(|gates| (name, gates)))
        {
            let what = format!("{}, {name}", shape.shape);
            assert_is_a_boundary(&format!("{what}, block"), Gate::Block, &gates.block);
            assert_is_a_boundary(&format!("{what}, mempool"), Gate::Mempool, &gates.mempool);
            // What the mempool search was asked: the transaction at exactly the fee floor.
            let at = gates.mempool.at_the_value.as_ref().expect("asserted above");
            assert_eq!(at.fee, at.minimum_fee, "{what}");
            assert_eq!(at.fee, Some(shape.fee), "{what}");
            // One sompi below the block's value it is the storage mass that refuses.
            let below = gates
                .block
                .one_sompi_below
                .as_ref()
                .expect("asserted above");
            assert!(
                below.refusal(Gate::Block).contains("StorageMass"),
                "{what}: refused below the value by {}",
                below.refusal(Gate::Block)
            );
        }
    }
    // A second search of one shape finds the same boundary.
    let again = smallest_of_shape(&CREATING[0]);
    assert_eq!(json(&values.shapes[0]), json(&again), "two searches differ");
    let found: Vec<String> = values
        .shapes
        .iter()
        .map(|shape| {
            format!(
                "{}: {} with every covenant coin alike, {} for the new coins alone{}",
                shape.shape,
                kas(shape
                    .every_covenant_coin_alike
                    .mempool
                    .smallest_coin_value
                    .unwrap_or(0)),
                kas(shape
                    .only_the_new_coins
                    .mempool
                    .smallest_coin_value
                    .unwrap_or(0)),
                shape
                    .only_the_continuing_coin
                    .as_ref()
                    .map(|gates| format!(
                        ", {} for the continuing minter or seed alone",
                        kas(gates.mempool.smallest_coin_value.unwrap_or(0))
                    ))
                    .unwrap_or_default(),
            )
        })
        .collect();
    results::record_structural(
        "limits/smallest values of created coins",
        &[],
        &format!(
            "smallest coin value a block and a default mempool accept, with one fee-paying coin of {} at the fee floor; each is \
             a boundary of the storage mass limit for that transaction; a transaction paid by several coins is not measured. \
             {}. Numbers and assumptions: limits.json, smallest_values",
            kas(values.funding_coin_value),
            found.join("; "),
        ),
    );
}

#[test]
fn the_smallest_value_of_a_whole_chain_is_a_boundary() {
    if !measuring() {
        return;
    }
    let chains = chains_once();
    assert_eq!(chains.chains.len(), SWEEP_FUNDING.len());
    for chain in &chains.chains {
        let what = format!("fee-paying coin of {} sompi", chain.funding_coin_value);
        let value = chain
            .smallest_coin_value
            .unwrap_or_else(|| panic!("{what}: no value was found"));
        assert_eq!(chain.steps.len(), STEPS.len(), "{what}");
        for step in &chain.steps {
            let at = &step.at_the_value;
            assert_eq!(at.coin_value, value, "{what}");
            assert!(at.mempool_accepted, "{what}, {}: {at:?}", step.step);
            assert_eq!(at.fee, Some(step.fee), "{what}, {}", step.step);
            assert_eq!(at.fee, at.minimum_fee, "{what}, {}", step.step);
        }
        assert!(
            !chain.binding_steps.is_empty(),
            "{what}: every step passes one sompi below"
        );
        assert_eq!(
            chain.far_below_refused_at.len(),
            2,
            "{what}: a smaller value passes every step"
        );
    }
    // A second search with one of the fee-paying coins finds the same boundary.
    let again = chain(&step_fees(), SWEEP_FUNDING[2]);
    assert_eq!(json(&chains.chains[2]), json(&again), "two searches differ");
    let found: Vec<String> = chains
        .chains
        .iter()
        .map(|chain| {
            format!(
                "{} with a fee-paying coin of {}",
                kas(chain.smallest_coin_value.unwrap_or(0)),
                kas(chain.funding_coin_value)
            )
        })
        .collect();
    results::record_structural(
        "limits/one value for a whole chain",
        &[],
        &format!(
            "smallest single value of every covenant coin with which a default mempool takes every step ({}), each step paid by \
             one fee-paying coin: {}. Numbers and assumptions: limits.json, chains",
            chains.steps.join(", "),
            found.join("; "),
        ),
    );
}

#[test]
fn the_reclaims_are_measured_alike_twice() {
    if !measuring() {
        return;
    }
    let first = reclaims_once();
    assert_eq!(json(first), json(&reclaims()), "two measurements differ");
    assert_eq!(first.cases.len(), Flow::ALL.len() * DEPOSITS.len() * 3);
    for case in &first.cases {
        // The scripts accept every case of the section: the cases differ in sompi values
        // and in where the deposit goes.
        assert!(
            case.scripts_accepted,
            "{} with {}: {}",
            case.flow, case.deposit, case.variant
        );
    }
    // The smallest deposits that come back as a coin of their own are boundaries.
    assert_eq!(first.smallest_deposits.len(), 2 * Flow::ALL.len());
    for found in &first.smallest_deposits {
        let what = format!("{}; {}", found.flow, found.variant);
        assert_is_a_boundary(
            &format!("{what}, block"),
            Gate::Block,
            &found.smallest.block,
        );
        assert_is_a_boundary(
            &format!("{what}, mempool"),
            Gate::Mempool,
            &found.smallest.mempool,
        );
        let at = found
            .smallest
            .mempool
            .at_the_value
            .as_ref()
            .expect("asserted above");
        assert_eq!(at.fee, Some(found.fee), "{what}");
        assert_eq!(at.fee, at.minimum_fee, "{what}");
    }
    let blocked: Vec<String> = first
        .cases
        .iter()
        .filter(|case| case.blocked_by_the_storage_mass)
        .map(|case| format!("{} of {}, {}", case.flow, kas(case.deposit), case.variant))
        .collect();
    let smallest: Vec<String> = first
        .smallest_deposits
        .iter()
        .map(|found| {
            format!(
                "{} ({}): {}",
                found.flow,
                found.variant,
                kas(found.smallest.mempool.smallest_coin_value.unwrap_or(0))
            )
        })
        .collect();
    results::record_structural(
        "limits/reclaims",
        &[],
        &format!(
            "the scripts accept each of the {} reclaims of this section: deposits of 0.01, 0.1 and 1 KAS, paid out to a plain \
             coin of their own, added to the change of the one fee-paying coin, or with no fee-paying coin. The storage mass \
             limit refuses {} of them, listed with their variant; a refusal of one variant says nothing about another: {:?}. \
             Smallest deposit that comes back as a plain coin of its own: {}. Numbers: limits.json, reclaims",
            first.cases.len(),
            blocked.len(),
            blocked,
            smallest.join("; "),
        ),
    );
}

#[test]
fn the_limits_are_written() {
    if !measuring() {
        return;
    }
    let document = Document {
        layout: LAYOUT,
        limits: node_limits(),
        expensive_transfers: expensive_transfers_once().clone(),
        budget_floor: budget_floor_once().clone(),
        smallest_values: smallest_values_once().clone(),
        chains: chains_once().clone(),
        reclaims: reclaims_once().clone(),
    };
    let path = results::write_document("limits.json", &document);
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the file was written"))
            .expect("JSON");
    assert_eq!(written["layout"], LAYOUT);
    for section in [
        "limits",
        "expensive_transfers",
        "budget_floor",
        "smallest_values",
        "chains",
        "reclaims",
    ] {
        assert!(
            written[section].is_object(),
            "section `{section}` is missing"
        );
    }
    println!("limits written to {}", path.display());
}
