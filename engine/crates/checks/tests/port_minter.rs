//! The earlier Python checks of the minter contract, run again on the script engine of a
//! node.
//!
//! Two groups of the earlier Python checks are repeated here, case by case:
//!
//! - the 24 minter checks (`A_minter.*`): merging two minters, the survivor that needs no
//!   signature, splitting, the deposit and the owner of the continuation of a mint, and the
//!   count of covenant inputs of the four leader entries;
//! - the 13 checks of `PublicMint.mint` (`test_public_mint.*`): how much may be minted, what
//!   the two outputs must hold, and the spending of a minted coin.
//!
//! The earlier checks ran one input at a time on a debug engine that executes neither the
//! other inputs nor the pay-to-script-hash wrapper and counts no budget. Here every case
//! assembles the whole transaction and runs the scripts of every input.
//!
//! What a line asserts:
//!
//! - An accept line made by `expect_accept` asserts the SCRIPTS of the whole transaction and
//!   nothing else: these lines use the 1000-sompi coins of the script-only profile and ask
//!   no block and no mempool. The accepted calls are repeated in the last section,
//!   `realistic/..`, in 10 KAS coins with a signed funding coin, change and a fee exactly at
//!   the mempool's floor, where scripts, consensus rules, a block and a default mempool
//!   accept them (`expect_mempool_accept`).
//! - Where an earlier check asserted a source line, the case is a twin (`twin`,
//!   `twin_inputs`): the honest transaction passes, a node gets to the scripts of both
//!   sides, one change is made, and the input the earlier check ran is refused at that line
//!   by the rule the inventory has for it.
//! - Nine lines of `SingleInputCounts` are NOT twins: `single/split|reclaim|mint: token coin
//!   of the covenant`, `single/split|reclaim|mint: minter coin of the covenant`,
//!   `single/merge: token coin of the covenant as third input` and the two lines
//!   `single/merge: token coin in the retiring place..`. They repeat the line assertion of
//!   the earlier check with `expect_inputs` (the scripts only, no honest side). The twins of
//!   the same count rules are the lines `single/..: a coin anybody can spend joins the
//!   covenant` and `single/..: joined, ..`.
//! - The control of the earlier count-rule checks (the same coin outside the covenant beside
//!   the leader: the leader passes) is an accepted transaction here, `single/..: control,
//!   ..`: the token coin under another covenant id runs its own leader entry into an output
//!   of its own. The lines `single/..: .. outside the covenant` run the bytes of the earlier
//!   control as written; a node refuses that transaction, and the line records where.
//! - Where the earlier check left another contract input without a call, the input carries
//!   the call a real transaction would carry, and the note of the case says so.
//!
//! The note of a case starts with `DIFFERS FROM PYTHON:` when the engine answers otherwise
//! than the earlier check, or shows something the earlier check could not see: an input it
//! never ran. A note that starts with `NO PYTHON ENGINE VERDICT:` marks a line whose earlier
//! check was refused by the Python library before any engine ran (three sub-cases); such a
//! line is an observation made here, not an agreement, and the Python id is carried by a
//! structural line next to it. A note that starts with `ADDED HERE:` marks a line that is
//! not a sub-case of the earlier check it names. On the inputs the earlier checks ran and
//! asserted, no case of this file differs.

use checks::{Case, Expected, Outcome};
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{CovenantBinding, TransactionOutpoint};
use kaspa_txscript::pay_to_script_hash_script;
use kcc20_family::{
    Entry, EntryRole, Family, Scenario,
    keys::{self, ALICE, BOB, CAROL},
    raw,
    scenario::{
        Arg, Call, ContractInput, ContractOutput, InputSpec, LateBytes, OrdinaryInput, PlainOutput,
    },
    shapes::{self, Profile, Realistic},
    states::{Kcc20State, OWNER_P2PKH_SCHNORR, PublicMintState},
    witness,
};

/// Another token family: the value the earlier checks used for a foreign extension
/// commitment.
const OTHER_FAMILY: [u8; 32] = [0xee; 32];
/// Another covenant: the id of a coin that is not of the minter's family.
const OTHER_COVENANT: [u8; 32] = [0x22; 32];

const I64_MAX: i64 = i64::MAX;
const TWO_POW_62: i64 = 1 << 62;

/// The value of the funding coin of the earlier checks, in sompi.
const FUNDING: u64 = 2_000;

fn script() -> Profile {
    Profile::Script
}

/// A case that repeats one earlier Python check.
fn case(id: &str, py_id: &str) -> Case {
    Case::new(id).py([py_id])
}

/// A rule of the contract refused, in the statement that starts at `line`.
fn rule(id: &str, line: u32) -> Expected {
    Expected::rule(id).at_line(line)
}

/// The state of the minter coin spent by input `input`.
fn minter_in(scenario: &mut Scenario, input: usize) -> &mut PublicMintState {
    scenario
        .contract_input_mut(input)
        .state
        .as_public_mint_mut()
        .expect("a minter coin")
}

/// The state locked into the minter output `output`.
fn minter_out(scenario: &mut Scenario, output: usize) -> &mut PublicMintState {
    scenario
        .contract_output_mut(output)
        .state
        .as_public_mint_mut()
        .expect("a minter output")
}

/// The state locked into the token output `output`.
fn token_out(scenario: &mut Scenario, output: usize) -> &mut Kcc20State {
    scenario
        .contract_output_mut(output)
        .state
        .as_kcc20_mut()
        .expect("a token output")
}

/// Changes the recipient state of a mint in the call and in the output alike.
fn change_minted_coin(scenario: &mut Scenario, change: impl Fn(&mut Kcc20State)) {
    change(scenario.contract_input_mut(0).declared_state_mut());
    change(token_out(scenario, 1));
}

/// The funding coin of the earlier checks: locked by `OP_TRUE`, spent with an empty
/// signature script.
fn funding_coin(value: u64) -> OrdinaryInput {
    OrdinaryInput::new(
        shapes::op_true_script(),
        value,
        shapes::outpoint(3, 0),
        LateBytes::empty(),
    )
    .labelled("funding (OP_TRUE)")
}

// ---------------------------------------------------------------------------------------
// The shapes of the earlier minter checks
// ---------------------------------------------------------------------------------------

/// The merge of the earlier checks: Alice's minter (18 remaining) absorbs Bob's (4).
fn merge() -> Scenario {
    shapes::mint_reclaim_into(&script())
}

/// A merge with other allowances: the survivor, the retiring minter and the successor.
fn merge_of(survivor: i64, retiring: i64, successor: i64) -> Scenario {
    let mut scenario = merge();
    minter_in(&mut scenario, 0).remaining = survivor;
    minter_in(&mut scenario, 1).remaining = retiring;
    minter_out(&mut scenario, 0).remaining = successor;
    scenario
}

/// The split of the earlier checks: `take` of the `remaining` allowance of Alice's minter go
/// to a new minter of Bob.
fn split_of(remaining: i64, take: i64) -> Scenario {
    let mut scenario = shapes::mint_split(&script());
    set_take(&mut scenario, remaining, take);
    scenario
}

/// Makes the call and both outputs of a split follow `take` consistently.
fn set_take(scenario: &mut Scenario, remaining: i64, take: i64) {
    minter_in(scenario, 0).remaining = remaining;
    scenario.contract_input_mut(0).args_mut()[0] = Arg::int(take);
    minter_out(scenario, 0).remaining = remaining - take;
    minter_out(scenario, 1).remaining = take;
}

/// The mint of the earlier minter checks: Alice's minter holds a deposit of `deposit` sompi
/// and mints `amount` of its `remaining` allowance to Carol.
fn deposit_mint(remaining: i64, amount: i64, deposit: u64) -> Scenario {
    let mut scenario = mint_of(remaining, 10, amount);
    scenario.contract_input_mut(0).value = deposit;
    scenario.contract_output_mut(0).value = deposit;
    change_minted_coin(&mut scenario, |state| state.owner = keys::x_only(CAROL));
    scenario
}

/// The mint of the earlier mint checks: a minter of Alice with `remaining` allowance and a
/// per-mint limit of `limit` mints `amount` to Bob; the continuation and the new coin follow
/// the call.
fn mint_of(remaining: i64, limit: i64, amount: i64) -> Scenario {
    let mut scenario = shapes::mint(&script());
    let minter = minter_in(&mut scenario, 0);
    minter.remaining = remaining;
    minter.mint_amount = limit;
    let continuation = minter_out(&mut scenario, 0);
    continuation.remaining = remaining - amount;
    continuation.mint_amount = limit;
    change_minted_coin(&mut scenario, |state| state.amount = amount);
    scenario
}

/// The reclaim of the earlier checks: Alice closes her minter, which holds `deposit` sompi.
fn reclaim_of(remaining: i64, deposit: u64) -> Scenario {
    let mut scenario = shapes::mint_reclaim(&script());
    minter_in(&mut scenario, 0).remaining = remaining;
    scenario.contract_input_mut(0).value = deposit;
    scenario.plain_output_mut(0).value = deposit;
    scenario
}

// ---------------------------------------------------------------------------------------
// A_minter: ReclaimInto
// ---------------------------------------------------------------------------------------

#[test]
fn merge_the_reference_shape_passes() {
    // The first earlier check is this shape alone; the others ran it first as their control.
    Case::new("merge/honest 18 + 4 -> 22")
        .py([
            "A_minter.test_a_minter.ReclaimInto.test_01_honest_reference_shape",
            "A_minter.test_a_minter.ReclaimInto.test_03_retiring_of_another_family",
            "A_minter.test_a_minter.ReclaimInto.test_04_retiring_with_another_per_mint_limit",
            "A_minter.test_a_minter.ReclaimInto.test_05_successor_with_another_owner",
            "A_minter.test_a_minter.ReclaimInto.test_06_retiring_input_placed_first",
            "A_minter.test_a_minter.ReclaimInto.test_07_three_minters",
            "A_minter.test_a_minter.ReclaimInto.test_09_retiring_signature",
            "A_minter.test_a_minter.ReclaimInto.\
             test_10_retiring_without_signature_cannot_be_called",
        ])
        .expect_accept(&merge());
}

#[test]
fn merge_the_survivor_keeps_its_sompi() {
    let py = "A_minter.test_a_minter.ReclaimInto.test_02_survivor_deposit_plus_and_minus_one";
    let mut honest = merge();
    honest.push_ordinary_input(funding_coin(FUNDING));
    case("merge/deposit: honest with funding", py).expect_accept(&honest);
    for (id, value) in [
        ("merge/deposit: successor one sompi more", 1_001),
        ("merge/deposit: successor one sompi less", 999),
    ] {
        case(id, py).twin_inputs(
            &honest,
            |scenario| scenario.contract_output_mut(0).value = value,
            &[(0, rule("M-48", 288)), (1, Expected::pass())],
        );
    }
}

#[test]
fn merge_the_retiring_minter_is_of_the_same_family_and_limit() {
    case(
        "merge/retiring minter of another family",
        "A_minter.test_a_minter.ReclaimInto.test_03_retiring_of_another_family",
    )
    .twin_inputs(
        &merge(),
        |scenario| minter_in(scenario, 1).extension_commitment = OTHER_FAMILY,
        &[(0, rule("M-46", 280)), (1, Expected::pass())],
    );
    case(
        "merge/retiring minter with a per-mint limit of 11",
        "A_minter.test_a_minter.ReclaimInto.test_04_retiring_with_another_per_mint_limit",
    )
    .twin_inputs(
        &merge(),
        |scenario| minter_in(scenario, 1).mint_amount = 11,
        &[(0, rule("M-45", 279)), (1, Expected::pass())],
    );
}

#[test]
fn merge_the_successor_keeps_the_owner() {
    case(
        "merge/successor owned by Carol",
        "A_minter.test_a_minter.ReclaimInto.test_05_successor_with_another_owner",
    )
    .twin_inputs(
        &merge(),
        |scenario| minter_out(scenario, 0).owner = keys::x_only(CAROL),
        &[(0, rule("M-49", 300)), (1, Expected::pass())],
    );
}

/// Puts the retiring minter in front of the survivor and binds the successor to the
/// survivor's new place.
fn retiring_first(scenario: &mut Scenario) {
    scenario.inputs.swap(0, 1);
    scenario.contract_output_mut(0).binding = Some(CovenantBinding::new(1, shapes::covenant_id()));
}

#[test]
fn merge_the_survivor_is_the_first_input_of_the_covenant() {
    let py = "A_minter.test_a_minter.ReclaimInto.test_06_retiring_input_placed_first";
    // Bob's signature is made over the changed transaction, for his new place at input 0.
    let refused = [(1, rule("M-37", 261)), (0, rule("M-52", 312))];
    case("merge/retiring minter first, successor 22", py).twin_inputs(
        &merge(),
        retiring_first,
        &refused,
    );
    // The same change with a successor of 36.
    case("merge/retiring minter first, successor 36", py).twin_inputs(
        &merge(),
        |scenario| {
            retiring_first(scenario);
            minter_out(scenario, 0).remaining = 36;
        },
        &refused,
    );
}

/// Adds a third minter of Bob (3 remaining) that retires like the second one.
fn third_minter(scenario: &mut Scenario) {
    scenario.push_contract_input(
        ContractInput::new(
            PublicMintState::new(keys::x_only(BOB), 3, 10),
            shapes::SCRIPT_SPLIT_VALUE,
            Some(shapes::covenant_id()),
            shapes::outpoint(1, 2),
            Call::typed(
                Entry::MintReclaimDelegator,
                vec![Arg::Bytes(witness::signature(BOB, SIG_HASH_ALL))],
            ),
        )
        .labelled("a third minter: Bob, 3 remaining"),
    );
    scenario.push_plain_output(PlainOutput::new(
        shapes::pay_to_public_key_script(&keys::x_only(BOB)),
        shapes::SCRIPT_SPLIT_VALUE,
    ));
}

#[test]
fn merge_takes_exactly_two_minters() {
    let py = "A_minter.test_a_minter.ReclaimInto.test_07_three_minters";
    case("merge/three minters, successor 25", py).twin_inputs(
        &merge(),
        |scenario| {
            third_minter(scenario);
            minter_out(scenario, 0).remaining = 25;
        },
        &[
            (0, rule("M-36", 260)),
            (1, Expected::pass()),
            (2, Expected::pass()),
        ],
    );
    case("merge/three minters, successor 22", py)
        .note(
            "The earlier check ran the two retiring minters in this sub-case and dropped \
             their answers; both pass.",
        )
        .twin_inputs(
            &merge(),
            third_minter,
            &[
                (0, rule("M-36", 260)),
                (1, Expected::pass()),
                (2, Expected::pass()),
            ],
        );
}

#[test]
fn merge_the_sum_stays_inside_64_bits() {
    let py = "A_minter.test_a_minter.ReclaimInto.test_08_sum_past_the_int64_range";
    // The honest twin adds up to exactly the largest number.
    let honest = merge_of(TWO_POW_62, TWO_POW_62 - 1, I64_MAX);
    case("merge/sum: exactly the largest number", py).expect_accept(&honest);
    // The last sub-case of the earlier check, a successor of 2^63, is not a transaction: the
    // number cannot be written as a state value, there or here. Its Python verdict was a
    // refusal of the Python library (assertRaises on the SDK), not of an engine.
    checks::results::record_structural(
        "merge/sum: successor 2^63, no Python engine verdict",
        &[py],
        "NO PYTHON ENGINE VERDICT: the last sub-case of the earlier check (2^62 + 2^62 with a \
         successor of 2^63) was refused by the Python library before any engine ran: 2^63 is \
         not a state value. No transaction is run here either; this line is not an agreement \
         with an engine verdict.",
    );
    // The engine's checked addition refuses before the successor is compared, whatever the
    // successor declares.
    let overflow = [
        (
            0,
            Expected::engine("NumberTooBig")
                .at_rule("M-47")
                .at_line(281),
        ),
        (1, Expected::pass()),
    ];
    for (id, survivor, retiring, successor) in [
        (
            "merge/sum: 2^62 + 2^62, successor the largest number",
            TWO_POW_62,
            TWO_POW_62,
            I64_MAX,
        ),
        (
            "merge/sum: 2^62 + 2^62, successor the wrapped value",
            TWO_POW_62,
            TWO_POW_62,
            -I64_MAX,
        ),
        (
            "merge/sum: 2^62 + 2^62, successor 0",
            TWO_POW_62,
            TWO_POW_62,
            0,
        ),
        ("merge/sum: the largest number + 1", I64_MAX, 1, I64_MAX),
    ] {
        case(id, py).twin_inputs(
            &honest,
            |scenario| *scenario = merge_of(survivor, retiring, successor),
            &overflow,
        );
    }
}

#[test]
fn merge_the_retiring_owner_signs() {
    let py = "A_minter.test_a_minter.ReclaimInto.test_09_retiring_signature";
    case("merge/signature: the survivor's key", py).twin_inputs(
        &merge(),
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() = witness::signature(ALICE, SIG_HASH_ALL)
        },
        &[(1, rule("M-57", 324)), (0, Expected::pass())],
    );
    case("merge/signature: a stranger's key", py)
        .note(SURVIVOR_NOT_ASSERTED)
        .twin_inputs(
            &merge(),
            |scenario| {
                *scenario.contract_input_mut(1).witness_mut() =
                    witness::signature(CAROL, SIG_HASH_ALL)
            },
            &[(1, rule("M-57", 324)), (0, Expected::pass())],
        );
    // Sixty-five zero bytes: the last one is not a signature hash type. The engine refuses
    // inside the statement of the rule, in the signature check itself.
    case("merge/signature: sixty-five zero bytes", py)
        .note(SURVIVOR_NOT_ASSERTED)
        .twin_inputs(
            &merge(),
            |scenario| {
                *scenario.contract_input_mut(1).witness_mut() = LateBytes::fixed(vec![0u8; 65])
            },
            &[
                (1, Expected::engine("InvalidSigHashType").at_line(324)),
                (0, Expected::pass()),
            ],
        );
}

/// The note of a sub-case in which the earlier check judged the retiring input only.
const SURVIVOR_NOT_ASSERTED: &str =
    "The earlier check did not assert the survivor in this sub-case; it passes.";

#[test]
fn merge_the_retiring_call_without_a_signature() {
    let py =
        "A_minter.test_a_minter.ReclaimInto.test_10_retiring_without_signature_cannot_be_called";
    // The library of the earlier checks refused to build these two calls, so they have no
    // earlier verdict. Here the signature script of the retiring input is built by hand:
    // the tag and the redeem script, with the argument left out or pushed empty. The two
    // engine lines carry no Python id: they are observations made here. The Python id is
    // carried by the two structural lines, which say that Python has no engine verdict.
    let left_out = Case::new("merge/no signature: the argument left out")
        .note(
            "NO PYTHON ENGINE VERDICT: ADDED HERE: the earlier check \
             (A_minter.test_a_minter.ReclaimInto.\
             test_10_retiring_without_signature_cannot_be_called) has no engine verdict, its \
             library refused to build the call (`expects 1 arguments, got 0`). The engine \
             refuses the retiring input with InvalidState at OpPick, byte 1545 of the script \
             (both asserted): the size check of the argument (M-50) finds nothing to measure. \
             The survivor passes.",
        )
        .twin_inputs(
            &merge(),
            |scenario| {
                scenario
                    .contract_input_mut(1)
                    .set_patch(|parts| parts.arguments.clear())
            },
            &[(1, Expected::engine("InvalidState")), (0, Expected::pass())],
        );
    // The place of the stop: the opcode in front of the size check of the argument.
    // (The twin above has already required the refusal; a run that judges no script, as a
    // run of selected cases does, has nothing to read here.)
    if let Some(stop) = left_out
        .changed
        .inputs
        .get(1)
        .and_then(|input| input.alone.as_ref())
        .and_then(|run| run.refusal.as_ref())
    {
        assert_eq!(stop.byte_offset, Some(1545), "{stop:?}");
        assert_eq!(stop.opcode.as_deref(), Some("OpPick"), "{stop:?}");
    }
    checks::results::record_structural(
        "merge/no signature: the argument left out, no Python engine verdict",
        &[py],
        "NO PYTHON ENGINE VERDICT: the earlier check asserted that the Python library refuses \
         to build the call without the argument (`expects 1 arguments, got 0`); no engine \
         ran. The engine's answer to the call built by hand is the line 'merge/no signature: \
         the argument left out', an observation made here, not an agreement.",
    );
    checks::results::record_structural(
        "merge/no signature: an empty argument, no Python engine verdict",
        &[py],
        "NO PYTHON ENGINE VERDICT: the earlier check asserted that the Python library refuses \
         to build the call with an empty argument (`owner_signature` expects 65 bytes, got \
         0); no engine ran. The engine's answer to the call built by hand is the line \
         'merge/no signature: an empty argument', an observation made here, not an agreement.",
    );
    Case::new("merge/no signature: an empty argument")
        .note(
            "NO PYTHON ENGINE VERDICT: ADDED HERE: the earlier check \
             (A_minter.test_a_minter.ReclaimInto.\
             test_10_retiring_without_signature_cannot_be_called) has no engine verdict, its \
             library refused to build the call (`owner_signature` expects 65 bytes, got 0). \
             The engine refuses the retiring input by rule M-50, the 65-byte size check of the \
             argument; the rule has no source line. The \
             survivor passes.",
        )
        .twin_inputs(
            &merge(),
            |scenario| {
                scenario.contract_input_mut(1).set_patch(|parts| {
                    parts.arguments = vec![raw::push(&[]).expect("an empty push")]
                })
            },
            &[(1, Expected::rule("M-50")), (0, Expected::pass())],
        );
}

// ---------------------------------------------------------------------------------------
// A_minter: SurvivorNeedsNoSignature
// ---------------------------------------------------------------------------------------

#[test]
fn a_merge_into_a_live_minter_is_signed_by_the_retiring_owner_only() {
    case(
        "merge/live minter: 18 + 4 -> 22, only Bob signs",
        "A_minter.test_a_minter.SurvivorNeedsNoSignature.test_merge_into_a_live_minter",
    )
    .expect_accept(&merge());
}

// ---------------------------------------------------------------------------------------
// A_minter: Split
// ---------------------------------------------------------------------------------------

#[test]
fn split_takes_more_than_nothing() {
    let py = "A_minter.test_a_minter.Split.test_01_take_zero_and_minus_one";
    // The control four of the earlier checks ran first.
    Case::new("split/honest take 7 of 25")
        .py([
            py,
            "A_minter.test_a_minter.Split.test_04_retained_deposit_plus_and_minus_one",
            "A_minter.test_a_minter.Split.test_05_outputs_swapped",
            "A_minter.test_a_minter.Split.test_06_retained_owner_changed",
        ])
        .expect_accept(&split_of(25, 7));
    // Both outputs follow the take, so only the rule about the take objects.
    for (id, take) in [("split/take 0", 0), ("split/take -1", -1)] {
        case(id, py).twin(
            &split_of(25, 7),
            |scenario| set_take(scenario, 25, take),
            0,
            rule("M-26", 196),
        );
    }
}

#[test]
fn split_takes_at_most_half() {
    let py = "A_minter.test_a_minter.Split.test_02_half_boundary";
    let honest = split_of(25, 12);
    case("split/take 12 of 25", py).expect_accept(&honest);
    case("split/take 13 of 25", py).twin(
        &honest,
        |scenario| set_take(scenario, 25, 13),
        0,
        rule("M-27", 197),
    );

    let py = "A_minter.test_a_minter.Split.test_03_smallest_minters";
    let honest = split_of(2, 1);
    case("split/take 1 of 2", py).expect_accept(&honest);
    case("split/take 1 of 1", py).twin(
        &honest,
        |scenario| set_take(scenario, 1, 1),
        0,
        rule("M-27", 197),
    );
}

#[test]
fn split_the_retained_minter_keeps_its_sompi() {
    let py = "A_minter.test_a_minter.Split.test_04_retained_deposit_plus_and_minus_one";
    for (id, value) in [
        ("split/deposit: retained one sompi more", 1_001),
        ("split/deposit: retained one sompi less", 999),
    ] {
        case(id, py).twin(
            &split_of(25, 7),
            |scenario| scenario.contract_output_mut(0).value = value,
            0,
            rule("M-28", 212),
        );
    }
}

#[test]
fn split_the_retained_minter_is_the_first_output() {
    let py = "A_minter.test_a_minter.Split.test_05_outputs_swapped";
    // With the reference values the deposit rule sees the swap first.
    case("split/outputs swapped, values 321 and 1000", py).twin(
        &split_of(25, 7),
        |scenario| scenario.outputs.swap(0, 1),
        0,
        rule("M-28", 212),
    );
    // With equal values the order of the states is the only difference.
    let mut honest = split_of(25, 7);
    honest.contract_output_mut(1).value = 1_000;
    case("split/outputs of 1000 and 1000", py).expect_accept(&honest);
    case("split/outputs swapped, values 1000 and 1000", py).twin(
        &honest,
        |scenario| scenario.outputs.swap(0, 1),
        0,
        rule("M-29", 224),
    );
}

#[test]
fn split_the_retained_minter_keeps_the_owner() {
    case(
        "split/retained minter owned by Carol",
        "A_minter.test_a_minter.Split.test_06_retained_owner_changed",
    )
    .twin(
        &split_of(25, 7),
        |scenario| minter_out(scenario, 0).owner = keys::x_only(CAROL),
        0,
        rule("M-29", 224),
    );
}

// ---------------------------------------------------------------------------------------
// A_minter: Mint
// ---------------------------------------------------------------------------------------

#[test]
fn mint_the_continuation_keeps_owner_and_sompi() {
    let honest = deposit_mint(25, 10, 7_000);
    let py = "A_minter.test_a_minter.Mint.test_01_continuation_owner_changed";
    let deposit_py = "A_minter.test_a_minter.Mint.test_02_continuation_deposit_plus_and_minus_one";
    Case::new("mint/deposit 7000: honest")
        .py([py, deposit_py])
        .expect_accept(&honest);
    case("mint/continuation owned by Carol", py).twin(
        &honest,
        |scenario| minter_out(scenario, 0).owner = keys::x_only(CAROL),
        0,
        rule("M-19", 161),
    );

    for (id, value) in [
        ("mint/deposit: continuation one sompi more", 7_001),
        ("mint/deposit: continuation one sompi less", 6_999),
    ] {
        case(id, deposit_py).twin(
            &honest,
            |scenario| scenario.contract_output_mut(0).value = value,
            0,
            rule("M-18", 149),
        );
    }
}

// ---------------------------------------------------------------------------------------
// A_minter: SingleInputCounts
// ---------------------------------------------------------------------------------------

/// A coin anybody can spend (pay to script hash of `OP_TRUE`), with or without the id of
/// the token's covenant.
fn anybodys_coin(value: u64, of_the_covenant: bool) -> InputSpec {
    let redeem = raw::push(&shapes::AUTHORITY_REDEEM_SCRIPT).expect("a one-byte push");
    let mut coin = OrdinaryInput::new(
        pay_to_script_hash_script(&shapes::AUTHORITY_REDEEM_SCRIPT),
        value,
        shapes::outpoint(2, 0),
        LateBytes::fixed(redeem),
    )
    .labelled("a coin anybody can spend");
    if of_the_covenant {
        coin = coin.with_covenant_id(shapes::covenant_id());
    }
    InputSpec::Ordinary(coin)
}

/// The token coin of the earlier checks, 5 tokens of Bob with 1000 sompi, as input `index`.
/// It joins as a real second coin of the covenant would: with `transfer_delegator` and
/// Bob's signature.
fn token_coin_of_bob(index: usize) -> ContractInput {
    ContractInput::new(
        Kcc20State::new(keys::x_only(BOB), 5),
        shapes::SCRIPT_COIN_VALUE,
        Some(shapes::covenant_id()),
        shapes::outpoint(1, index as u32),
        Call::typed(
            Entry::TransferDelegator,
            vec![Arg::Bytes(witness::owner_key(
                BOB,
                EntryRole::Delegate,
                SIG_HASH_ALL,
            ))],
        ),
    )
    .labelled("a token coin of the covenant: Bob, 5 tokens")
}

/// The minter coin of the earlier checks, 4 remaining of Bob with 321 sompi, as input
/// `index`. It joins as a retiring minter would: with `reclaim_delegator` and Bob's
/// signature.
fn minter_coin_of_bob(index: usize) -> ContractInput {
    ContractInput::new(
        PublicMintState::new(keys::x_only(BOB), 4, 10),
        shapes::SCRIPT_SPLIT_VALUE,
        Some(shapes::covenant_id()),
        shapes::outpoint(1, index as u32),
        Call::typed(
            Entry::MintReclaimDelegator,
            vec![Arg::Bytes(witness::signature(BOB, SIG_HASH_ALL))],
        ),
    )
    .labelled("a minter coin of the covenant: Bob, 4 remaining")
}

/// The same coin outside the covenant, as the earlier checks wrote their control: no
/// covenant id and an empty signature script.
fn outside_the_covenant(mut coin: ContractInput) -> ContractInput {
    coin.covenant_id = None;
    coin.signature_script = Some(LateBytes::empty());
    coin.label = format!("{}, without the covenant id", coin.label);
    coin
}

/// The note of the twin that stands in for the control of the earlier checks.
const TWIN_NOTE: &str = "The control of the earlier check, the same coin bytes without the \
                         covenant id and with an empty signature script, cannot be spent. \
                         This twin uses a coin anybody can spend; only the covenant id on the \
                         coin differs between its two sides.";

/// The note of the control of the earlier checks, run as a whole transaction.
const CONTROL_NOTE: &str = "DIFFERS FROM PYTHON: whole transaction only. The bytes of the \
                            control of the earlier check, run once as written (scripts only): \
                            Python's control passes on the input it ran, and so it does here. \
                            Its other coin, a pay-to-script-hash coin with an empty signature \
                            script, Python never ran: the engine refuses it in the \
                            pay-to-script-hash wrapper (InvalidStackOperation), so the control \
                            as written is not a transaction a node accepts. This line records \
                            that refusal; the accepting control is the line 'control, a token \
                            coin under another covenant id' of the same check.";

/// `leader` with one more token coin as its last input: the token coin of the family
/// crate's one-to-one transfer, under the covenant id `covenant`, running its own leader
/// entry (`transfer`, signed by its owner) into one more output, a token coin of its own
/// bound to it under that covenant. Only `covenant` differs between the control (another
/// covenant id) and the joined side (the covenant id of the leader).
fn with_a_token_coin_under(leader: &Scenario, covenant: Hash) -> Scenario {
    let transfer = shapes::transfer(&script(), 1, 1);
    let mut scenario = leader.clone();
    let input = scenario.inputs.len();
    let output = scenario.outputs.len();
    scenario.inputs.push(transfer.inputs[0].clone());
    scenario.outputs.push(transfer.outputs[0].clone());
    let coin = scenario.contract_input_mut(input);
    coin.covenant_id = Some(covenant);
    coin.outpoint = shapes::outpoint(1, 2);
    scenario.contract_output_mut(output).binding = Some(CovenantBinding::new(
        input.try_into().expect("a small input index"),
        covenant,
    ));
    scenario
}

/// The control of an earlier count-rule check as a transaction a node runs, and its twin.
///
/// The earlier control: the same coin, not of the covenant, beside the leader, and the
/// leader passes. Here the token coin is of ANOTHER covenant and spends itself by its own
/// leader entry into an output of its own: every script passes and the consensus rules of a
/// submission accept the transaction (an accept line). With the covenant id of the leader on
/// that coin and its output, and nothing else changed, the leader is refused by the count
/// rule at the line the earlier check asserted (a twin line).
fn control_pair(name: &str, py: &str, leader: &Scenario, count_rule: Expected) {
    let control = with_a_token_coin_under(leader, Hash::from_bytes(OTHER_COVENANT));
    case(
        &format!("single/{name}: control, a token coin under another covenant id"),
        py,
    )
    .note(
        "The accepting control of the earlier check as a transaction a node runs: scripts of \
         every input and the consensus rules of a submission (1000-sompi coins: no block or \
         mempool question is asked). The earlier control had the coin without a covenant id \
         and without a call; here the coin is of another covenant and runs transfer, signed \
         by its owner, into an output of its own covenant.",
    )
    .expect_consensus_accept(&control);
    case(
        &format!("single/{name}: joined, the same token coin under the leader's covenant id"),
        py,
    )
    .note(
        "Twin of the control: only the covenant id of the extra coin and of its output \
         differs. The leader is refused by the count rule at the line of the earlier check. \
         The answer of the extra coin is not asserted.",
    )
    .twin(
        &control,
        |scenario| *scenario = with_a_token_coin_under(leader, shapes::covenant_id()),
        0,
        count_rule,
    );
}

/// What a token coin answers when it joins with `transfer_delegator` behind a leader that is
/// a minter running `split`, `reclaim` or `reclaim_into`: the engine refuses it.
fn token_delegate_refused_by_the_engine() -> Expected {
    Expected::engine("InvalidIndex").at_line(257)
}

/// The checks of one earlier method: a leader entry that works alone (`split`, `reclaim`,
/// `mint`) next to a second coin of the covenant as input 1.
fn refuses_a_second_coin_of_the_covenant(
    name: &str,
    py: &str,
    honest: &Scenario,
    count_rule: Expected,
    token_delegate: Expected,
) {
    let with = |coin: InputSpec| {
        let mut scenario = honest.clone();
        scenario.inputs.insert(1, coin);
        scenario
    };

    control_pair(name, py, honest, count_rule.clone());

    case(
        &format!("single/{name}: a coin anybody can spend joins the covenant"),
        py,
    )
    .note(TWIN_NOTE)
    .twin_inputs(
        &with(anybodys_coin(shapes::SCRIPT_COIN_VALUE, false)),
        |scenario| scenario.inputs[1] = anybodys_coin(shapes::SCRIPT_COIN_VALUE, true),
        &[(0, count_rule.clone()), (1, Expected::pass())],
    );

    case(&format!("single/{name}: token coin of the covenant"), py)
        .note(
            "DIFFERS FROM PYTHON: whole transaction only. Python refused the leader at this \
             line, and so does the engine. Python never ran the token coin and gave it no \
             call; here it carries the call of a second coin of the covenant \
             (transfer_delegator, signed by its owner), and that input is refused as well. \
             Not a twin: the scripts of this one transaction, no honest side; the twins of \
             this count rule are the lines 'joined, ..' and 'a coin anybody can spend joins \
             the covenant'.",
        )
        .expect_inputs(
            &with(InputSpec::Contract(token_coin_of_bob(1))),
            &[(0, count_rule.clone()), (1, token_delegate)],
        );
    case(&format!("single/{name}: minter coin of the covenant"), py)
        .note(
            "DIFFERS FROM PYTHON: whole transaction only. Python refused the leader at this \
             line, and so does the engine. Python never ran the second minter and gave it \
             no call; here it carries the call of a retiring minter (reclaim_delegator, \
             signed by its owner), and the engine accepts that input: the leader alone \
             stops the transaction. Not a twin: the scripts of this one transaction, no \
             honest side; the twins of this count rule are the lines 'joined, ..' and 'a \
             coin anybody can spend joins the covenant'.",
        )
        .expect_inputs(
            &with(InputSpec::Contract(minter_coin_of_bob(1))),
            &[(0, count_rule), (1, Expected::pass())],
        );

    for (what, coin) in [
        ("token coin", token_coin_of_bob(1)),
        ("minter coin", minter_coin_of_bob(1)),
    ] {
        case(&format!("single/{name}: {what} outside the covenant"), py)
            .note(CONTROL_NOTE)
            .expect_inputs(
                &with(InputSpec::Contract(outside_the_covenant(coin))),
                &[
                    (0, Expected::pass()),
                    (1, Expected::refused_by("P2SH wrapper")),
                ],
            );
    }
}

#[test]
fn split_works_on_one_coin_of_the_covenant() {
    refuses_a_second_coin_of_the_covenant(
        "split",
        "A_minter.test_a_minter.SingleInputCounts.test_01_split",
        &split_of(25, 7),
        rule("M-24", 187),
        token_delegate_refused_by_the_engine(),
    );
}

#[test]
fn reclaim_works_on_one_coin_of_the_covenant() {
    refuses_a_second_coin_of_the_covenant(
        "reclaim",
        "A_minter.test_a_minter.SingleInputCounts.test_02_reclaim",
        &reclaim_of(0, 1_000),
        rule("M-32", 243),
        token_delegate_refused_by_the_engine(),
    );
}

#[test]
fn mint_works_on_one_coin_of_the_covenant() {
    // Beside a mint the token coin is refused by a rule of its own contract, K-70.
    refuses_a_second_coin_of_the_covenant(
        "mint",
        "A_minter.test_a_minter.SingleInputCounts.test_03_mint",
        &deposit_mint(25, 10, 7_000),
        rule("M-10", 127),
        rule("K-70", 257),
    );
}

#[test]
fn merge_counts_a_token_coin_of_the_covenant() {
    let py = "A_minter.test_a_minter.SingleInputCounts.\
              test_04_reclaim_into_with_a_token_coin_as_third_input";
    let with = |coin: InputSpec| {
        let mut scenario = merge();
        scenario.inputs.push(coin);
        scenario
    };
    control_pair("merge", py, &merge(), rule("M-36", 260));
    case(
        "single/merge: a coin anybody can spend joins the covenant",
        py,
    )
    .note(TWIN_NOTE)
    .twin_inputs(
        &with(anybodys_coin(shapes::SCRIPT_COIN_VALUE, false)),
        |scenario| scenario.inputs[2] = anybodys_coin(shapes::SCRIPT_COIN_VALUE, true),
        &[
            (0, rule("M-36", 260)),
            (1, Expected::pass()),
            (2, Expected::pass()),
        ],
    );
    case(
        "single/merge: token coin of the covenant as third input",
        py,
    )
    .note(
        "DIFFERS FROM PYTHON: whole transaction only. Python refused the survivor at this \
         line, and so does the engine. Python dropped the answer of the retiring minter and \
         never ran the token coin; here the retiring minter passes, and the token coin, \
         with a transfer_delegator call signed by its owner, is refused as well \
         (InvalidIndex). Not a twin: the scripts of this one transaction, no honest side; \
         the twins of this count rule are the lines 'single/merge: joined, ..' and \
         'single/merge: a coin anybody can spend joins the covenant'.",
    )
    .expect_inputs(
        &with(InputSpec::Contract(token_coin_of_bob(2))),
        &[
            (0, rule("M-36", 260)),
            (1, Expected::pass()),
            (2, token_delegate_refused_by_the_engine()),
        ],
    );
    case(
        "single/merge: token coin outside the covenant as third input",
        py,
    )
    .note(CONTROL_NOTE)
    .expect_inputs(
        &with(InputSpec::Contract(outside_the_covenant(
            token_coin_of_bob(2),
        ))),
        &[
            (0, Expected::pass()),
            (1, Expected::pass()),
            (2, Expected::refused_by("P2SH wrapper")),
        ],
    );
}

#[test]
fn merge_refuses_a_token_coin_in_the_retiring_place() {
    // Two coins of the covenant, but the second is a token coin. The successor keeps 18 and
    // nothing is paid out.
    let mut scenario = merge_of(18, 4, 18);
    scenario.inputs[1] = InputSpec::Contract(token_coin_of_bob(1));
    scenario.outputs.truncate(1);
    case(
        "single/merge: token coin in the retiring place",
        "A_minter.test_a_minter.SingleInputCounts.\
         test_05_reclaim_into_with_a_token_coin_in_the_retiring_place",
    )
    .note(
        "DIFFERS FROM PYTHON: whole transaction only. Python refused the survivor at this \
         line, and so does the engine. Python gave the token coin a bare redeem push and \
         never ran it; here it carries a transfer_delegator call signed by its owner. The \
         survivor is refused as before; the token coin is refused as well (InvalidIndex). \
         Not a twin: the scripts of this one transaction, no honest side.",
    )
    .expect_inputs(
        &scenario,
        &[
            (0, rule("M-38", 263)),
            (1, token_delegate_refused_by_the_engine()),
        ],
    );

    // The signature script of the token coin exactly as the earlier check had it: the push
    // of its redeem script and nothing in front.
    scenario.contract_input_mut(1).call = Call::Raw(LateBytes::empty());
    case(
        "single/merge: token coin in the retiring place, bare redeem push",
        "A_minter.test_a_minter.SingleInputCounts.\
         test_05_reclaim_into_with_a_token_coin_in_the_retiring_place",
    )
    .note(
        "DIFFERS FROM PYTHON: whole transaction only. The bytes of the earlier check: the \
         survivor is refused at the same line. The token coin, which Python never ran, \
         cannot be spent by a bare redeem push: its script finds an empty stack at its \
         first opcode (InvalidStackOperation at OpToAltStack, byte 0). Not a twin: the \
         scripts of this one transaction, no honest side.",
    )
    .expect_inputs(
        &scenario,
        &[
            (0, rule("M-38", 263)),
            (1, Expected::engine("InvalidStackOperation")),
        ],
    );
}

// ---------------------------------------------------------------------------------------
// test_public_mint
// ---------------------------------------------------------------------------------------

#[test]
fn mint_anybody_mints_up_to_the_per_mint_limit() {
    let py = "test_public_mint.PublicMint.test_anyone_mints_up_to_the_per_mint_limit";
    for (remaining, limit, amount) in [
        (25, 10, 10),
        (25, 10, 3),
        (10, 10, 10),
        (5, 10, 5),
        (5, 10, 4),
        (TWO_POW_62, TWO_POW_62, TWO_POW_62),
    ] {
        case(
            &format!("mint/honest: {amount} of {remaining}, limit {limit}"),
            py,
        )
        .expect_accept(&mint_of(remaining, limit, amount));
    }
}

#[test]
fn mint_the_caller_chooses_scheme_and_policy_of_the_new_coin() {
    let py = "test_public_mint.PublicMint.\
              test_the_caller_chooses_the_new_coin_s_owner_scheme_and_borrow_policy";
    let bob = keys::x_only(BOB);
    for (id, recipient) in [
        (
            "mint/new coin with a borrow threshold of 3",
            Kcc20State::new(bob, 10).with_threshold(3),
        ),
        (
            "mint/new coin owned by the hash of a key",
            Kcc20State::new(bob, 10)
                .with_owner(OWNER_P2PKH_SCHNORR, witness::public_key_hash(&bob)),
        ),
    ] {
        let mut scenario = mint_of(25, 10, 10);
        change_minted_coin(&mut scenario, |state| *state = recipient.clone());
        case(id, py).expect_accept(&scenario);
    }
}

#[test]
fn mint_stays_within_the_limit_and_the_allowance() {
    let py = "test_public_mint.PublicMint.test_more_than_the_per_mint_limit_is_refused";
    let honest = mint_of(25, 10, 10);
    case("mint/limit: 10 with a limit of 10", py).expect_accept(&honest);
    // The continuation (14) and the new coin (11) follow the call.
    case("mint/limit: 11 with a limit of 10", py).twin(
        &honest,
        |scenario| *scenario = mint_of(25, 10, 11),
        0,
        rule("M-13", 137),
    );

    let py = "test_public_mint.PublicMint.test_more_than_the_remaining_allowance_is_refused";
    let honest = mint_of(5, 10, 5);
    case("mint/allowance: 5 of 5", py).expect_accept(&honest);
    // In both refusals the continuation follows the call.
    case("mint/allowance: 6 of 5", py).twin(
        &honest,
        |scenario| *scenario = mint_of(5, 10, 6),
        0,
        rule("M-14", 138),
    );
    case("mint/allowance: 1 of 0", py)
        .note("The honest side of this twin is 1 of 1; the earlier control was 5 of 5.")
        .twin(
            &mint_of(1, 10, 1),
            |scenario| *scenario = mint_of(0, 10, 1),
            0,
            rule("M-14", 138),
        );
}

#[test]
fn mint_makes_more_than_nothing() {
    let py = "test_public_mint.PublicMint.test_zero_and_negative_amounts_are_refused";
    for (id, amount) in [
        ("mint/amount 0", 0),
        ("mint/amount -1", -1),
        ("mint/amount -2^62", -TWO_POW_62),
    ] {
        case(id, py).twin(
            &mint_of(25, 10, 10),
            |scenario| *scenario = mint_of(25, 10, amount),
            0,
            rule("M-12", 136),
        );
    }
}

#[test]
fn mint_the_allowance_goes_down_by_the_minted_amount() {
    let py = "test_public_mint.PublicMint.\
              test_the_allowance_must_go_down_by_exactly_the_minted_amount";
    let honest = mint_of(25, 10, 10);
    case("mint/continuation: 15 after 10 of 25", py).expect_accept(&honest);
    for remaining in [25, 16, 14] {
        case(
            &format!("mint/continuation: {remaining} after 10 of 25"),
            py,
        )
        .twin(
            &honest,
            |scenario| minter_out(scenario, 0).remaining = remaining,
            0,
            rule("M-19", 161),
        );
    }
}

#[test]
fn mint_the_new_coin_is_what_the_call_names() {
    case(
        "mint/new coin locked to 1000 tokens, the call names 10",
        "test_public_mint.PublicMint.test_the_new_coin_must_hold_what_the_call_names",
    )
    .twin(
        &mint_of(25, 10, 10),
        |scenario| token_out(scenario, 1).amount = 1_000,
        0,
        rule("M-21", 174),
    );
    case(
        "mint/new coin of another family",
        "test_public_mint.PublicMint.test_the_new_coin_must_be_of_the_minter_s_token_family",
    )
    .twin(
        &mint_of(25, 10, 10),
        |scenario| change_minted_coin(scenario, |state| state.extension_commitment = OTHER_FAMILY),
        0,
        rule("M-15", 139),
    );
}

#[test]
fn mint_the_minter_keeps_its_sompi() {
    let py = "test_public_mint.PublicMint.test_the_minter_keeps_its_sompi";
    let mut honest = mint_of(25, 10, 10);
    honest.contract_input_mut(0).value = 7_000;
    honest.contract_output_mut(0).value = 7_000;
    case("mint/sompi: 7000 kept", py).expect_accept(&honest);
    for value in [6_999, 7_001] {
        case(&format!("mint/sompi: {value} kept of 7000"), py).twin(
            &honest,
            |scenario| scenario.contract_output_mut(0).value = value,
            0,
            rule("M-18", 149),
        );
    }
}

#[test]
fn mint_a_token_script_with_one_bit_flipped_is_refused() {
    // One bit of the token script handed to the minter is flipped, in the last byte of the
    // suffix argument. The output is the genuine token coin.
    case(
        "mint/token script in the call with one bit flipped",
        "test_public_mint.PublicMint.test_a_look_alike_token_script_is_refused",
    )
    .note(
        "Same line as the earlier check, which saw one statement (lines 174-180). The engine \
         tells its two comparisons apart: the first refuses, the hash of the script handed \
         over against the token template hash in the minter's state (M-20, byte 451), not \
         the script of the output (M-21).",
    )
    .twin(
        &mint_of(25, 10, 10),
        |scenario| {
            scenario.contract_input_mut(0).set_patch(|parts| {
                let suffix = parts.arguments.last_mut().expect("the suffix argument");
                *suffix.last_mut().expect("the suffix has bytes") ^= 1;
            })
        },
        0,
        rule("M-20", 174),
    );
}

#[test]
fn mint_creates_exactly_one_token_coin() {
    // A second token coin of 1000, bound to the minter like the two honest outputs.
    case(
        "mint/a second token coin",
        "test_public_mint.PublicMint.test_one_mint_creates_exactly_one_token_coin",
    )
    .twin(
        &mint_of(25, 10, 10),
        |scenario| {
            scenario.push_contract_output(ContractOutput::new(
                Kcc20State::new(keys::x_only(BOB), 1_000),
                shapes::SCRIPT_COIN_VALUE,
                Some(CovenantBinding::new(0, shapes::covenant_id())),
            ));
            scenario.ordinary_input_mut(1).value = 3_000;
        },
        0,
        rule("M-11", 130),
    );
}

#[test]
fn mint_runs_with_no_other_coin_of_the_covenant() {
    // A token coin of the covenant in the place of the funding coin.
    case(
        "mint/token coin of the covenant instead of the funding coin",
        "test_public_mint.PublicMint.\
         test_mint_runs_with_no_other_coin_of_the_covenant_beside_the_minter",
    )
    .note(
        "DIFFERS FROM PYTHON: whole transaction only. Python refused the minter at this \
         line, and so does the engine. Python gave the token coin a bare redeem push and \
         never ran it; here it carries a transfer_delegator call signed by its owner, and \
         the engine refuses it too: the leader it reads is a minter, not a token coin \
         (K-70).",
    )
    .twin_inputs(
        &mint_of(25, 10, 10),
        |scenario| scenario.inputs[1] = InputSpec::Contract(token_coin_of_bob(1)),
        &[(0, rule("M-10", 127)), (1, rule("K-70", 257))],
    );
}

#[test]
fn mint_the_new_coin_is_spent_by_its_owner() {
    let py = "test_public_mint.PublicMint.test_a_minted_coin_can_be_spent_by_its_owner";
    let mint = mint_of(25, 10, 10);
    case("spend/the mint", py).expect_accept(&mint);

    // Bob moves the minted coin to Alice. The earlier check linked the two transactions by
    // the state only; here the transfer spends output 1 of the mint itself.
    let minted = mint
        .assemble(Family::pinned())
        .expect("the honest mint assembles")
        .tx;
    let to_alice = Kcc20State::new(keys::x_only(ALICE), 10);
    let mut transfer = shapes::transfer(&script(), 1, 1);
    let coin = transfer.contract_input_mut(0);
    coin.state = Kcc20State::new(keys::x_only(BOB), 10).into();
    coin.outpoint = TransactionOutpoint::new(minted.id(), 1);
    coin.declared_states_mut()[0] = to_alice.clone();
    *coin.witness_mut() = witness::owner_key(BOB, EntryRole::Leader, SIG_HASH_ALL);
    transfer.contract_output_mut(0).state = to_alice.into();

    // The coin the transfer spends is the output the mint created: same script, same value,
    // same covenant.
    let spent = &transfer
        .assemble(Family::pinned())
        .expect("the transfer assembles")
        .utxos[0];
    let created = &minted.outputs[1];
    assert_eq!(spent.script_public_key, created.script_public_key);
    assert_eq!(spent.amount, created.value);
    assert_eq!(
        spent.covenant_id,
        created.covenant.map(|binding| binding.covenant_id)
    );

    case("spend/the new owner moves the minted coin", py)
        .note("The transfer spends the real outpoint of the mint's token output.")
        .expect_accept(&transfer);
}

// ---------------------------------------------------------------------------------------
// The accepted transactions in coin values a node takes
// ---------------------------------------------------------------------------------------

/// [`mint_of`] in the coin values of `profile`.
fn mint_in(profile: &Profile, remaining: i64, limit: i64, amount: i64) -> Scenario {
    let mut scenario = shapes::mint(profile);
    let minter = minter_in(&mut scenario, 0);
    minter.remaining = remaining;
    minter.mint_amount = limit;
    let continuation = minter_out(&mut scenario, 0);
    continuation.remaining = remaining - amount;
    continuation.mint_amount = limit;
    change_minted_coin(&mut scenario, |state| state.amount = amount);
    scenario
}

/// The realistic profile (10 KAS coins, a signed funding coin of 100 KAS, change) with a
/// fee of `fee` sompi.
fn realistic_paying(fee: u64) -> Profile {
    Profile::Realistic(Realistic {
        fee,
        ..Realistic::default()
    })
}

/// The transaction of `build` paying exactly the smallest fee a default mempool accepts
/// for it, and that fee. The floor depends on the size and the budgets of a transaction,
/// not on its values, so it is read from a run with a fee of 0.05 KAS. A run that judges
/// the scripts only knows no floor: the fee stays 0.05 KAS and no floor is returned.
fn at_the_fee_floor(build: &dyn Fn(&Profile) -> Scenario) -> (Scenario, Option<u64>) {
    let generous = shapes::SOMPI_PER_KAS / 20;
    let probe = checks::run(&build(&realistic_paying(generous)));
    if probe.scripts_only() {
        return (build(&realistic_paying(generous)), None);
    }
    let floor = probe
        .mempool
        .minimum_fee
        .expect("the fee floor of a well formed transaction is known");
    (build(&realistic_paying(floor)), Some(floor))
}

/// The accepted transaction pays exactly the fee floor, and a block may hold it.
fn assert_paid_at_the_floor(name: &str, outcome: &Outcome, floor: Option<u64>) {
    let Some(floor) = floor else { return };
    if outcome.scripts_only() {
        return;
    }
    assert_eq!(outcome.mempool.fee, Some(floor), "{name}: the fee paid");
    assert_eq!(
        outcome.mempool.minimum_fee,
        Some(floor),
        "{name}: the floor of the transaction that was run"
    );
    assert!(
        outcome.consensus.block.accepted,
        "{name}: a block refuses it: {:?}",
        outcome.consensus.block.refusal
    );
}

/// The note of the lines of the realistic section.
const REALISTIC_NOTE: &str = "ADDED HERE: the accepted call of the earlier check in 10 KAS \
    coins, with a signed funding coin of 100 KAS, change and a fee exactly at the mempool's \
    floor for this transaction (asserted: fee paid = smallest fee accepted): scripts, the \
    consensus rules of a submission, a block (asserted) and a default node's mempool accept \
    it. The earlier check ran one input of the same call in 1000-sompi coins.";

/// The cases above run the scripts of whole transactions in the 1000-sompi coins of the
/// script-only profile and ask no block and no mempool. Here the same calls and states are
/// put into 10 KAS coins with a signed funding coin, change and a fee at the floor, and a
/// default node takes each of them into its mempool.
#[test]
fn the_accepted_mints_pass_a_default_node_in_realistic_coin_values() {
    const MINT_LIMIT: &str =
        "test_public_mint.PublicMint.test_anyone_mints_up_to_the_per_mint_limit";
    const MINT_POLICY: &str = "test_public_mint.PublicMint.\
        test_the_caller_chooses_the_new_coin_s_owner_scheme_and_borrow_policy";
    const MINT_SPEND: &str =
        "test_public_mint.PublicMint.test_a_minted_coin_can_be_spent_by_its_owner";
    const DEPOSIT_OWNER: &str = "A_minter.test_a_minter.Mint.test_01_continuation_owner_changed";
    const DEPOSIT_VALUE: &str =
        "A_minter.test_a_minter.Mint.test_02_continuation_deposit_plus_and_minus_one";
    const LIVE: &str =
        "A_minter.test_a_minter.SurvivorNeedsNoSignature.test_merge_into_a_live_minter";
    // The deposit of the minter of the deposit cases: 25 KAS, not the 10 KAS of the coins.
    const DEPOSIT: u64 = 25 * shapes::SOMPI_PER_KAS;

    type Build = Box<dyn Fn(&Profile) -> Scenario>;
    let mint = |remaining: i64, limit: i64, amount: i64| -> Build {
        Box::new(move |profile| mint_in(profile, remaining, limit, amount))
    };
    let mint_to = |recipient: Kcc20State| -> Build {
        Box::new(move |profile| {
            let mut scenario = mint_in(profile, 25, 10, 10);
            change_minted_coin(&mut scenario, |state| *state = recipient.clone());
            scenario
        })
    };
    let deposit_mint_in = |remaining: i64, amount: i64| -> Build {
        Box::new(move |profile| {
            let mut scenario = mint_in(profile, remaining, 10, amount);
            scenario.contract_input_mut(0).value = DEPOSIT;
            scenario.contract_output_mut(0).value = DEPOSIT;
            change_minted_coin(&mut scenario, |state| state.owner = keys::x_only(CAROL));
            scenario
        })
    };
    let merge_in = |survivor: i64, retiring: i64| -> Build {
        Box::new(move |profile| {
            let mut scenario = shapes::mint_reclaim_into(profile);
            minter_in(&mut scenario, 0).remaining = survivor;
            minter_in(&mut scenario, 1).remaining = retiring;
            minter_out(&mut scenario, 0).remaining = survivor + retiring;
            scenario
        })
    };
    let bob = keys::x_only(BOB);

    let accepted: Vec<(&str, Vec<&str>, Build)> = vec![
        (
            "mint 10 of 25, limit 10",
            vec![MINT_LIMIT, MINT_SPEND],
            mint(25, 10, 10),
        ),
        ("mint 3 of 25, limit 10", vec![MINT_LIMIT], mint(25, 10, 3)),
        ("mint 5 of 5, limit 10", vec![MINT_LIMIT], mint(5, 10, 5)),
        (
            "mint 2^62 of 2^62, limit 2^62",
            vec![MINT_LIMIT],
            mint(TWO_POW_62, TWO_POW_62, TWO_POW_62),
        ),
        (
            "mint a new coin with a borrow threshold of 3",
            vec![MINT_POLICY],
            mint_to(Kcc20State::new(bob, 10).with_threshold(3)),
        ),
        (
            "mint a new coin owned by the hash of a key",
            vec![MINT_POLICY],
            mint_to(
                Kcc20State::new(bob, 10)
                    .with_owner(OWNER_P2PKH_SCHNORR, witness::public_key_hash(&bob)),
            ),
        ),
        (
            "deposit mint: a minter with a deposit of 25 KAS mints 10 of 25 to Carol",
            vec![DEPOSIT_OWNER, DEPOSIT_VALUE],
            deposit_mint_in(25, 10),
        ),
        (
            "merge into a live minter: 18 + 4 -> 22, only Bob signs",
            vec![LIVE],
            merge_in(18, 4),
        ),
    ];
    for (name, py_ids, build) in &accepted {
        let (scenario, floor) = at_the_fee_floor(build.as_ref());
        let outcome = Case::new(format!("realistic/{name}"))
            .py(py_ids.iter().copied())
            .note(REALISTIC_NOTE)
            .expect_mempool_accept(&scenario);
        assert_paid_at_the_floor(name, &outcome, floor);
    }

    // The spend of a minted coin: Bob moves it to Alice. The transfer spends output 1 of the
    // first mint above, the transaction as it is built at its fee floor.
    let (mint, _) = at_the_fee_floor(&|profile| mint_in(profile, 25, 10, 10));
    let minted = mint
        .assemble(Family::pinned())
        .expect("the realistic mint assembles")
        .tx;
    let minted_id = minted.id();
    let spend = move |profile: &Profile| {
        let to_alice = Kcc20State::new(keys::x_only(ALICE), 10);
        let mut transfer = shapes::transfer(profile, 1, 1);
        let coin = transfer.contract_input_mut(0);
        coin.state = Kcc20State::new(keys::x_only(BOB), 10).into();
        coin.outpoint = TransactionOutpoint::new(minted_id, 1);
        coin.declared_states_mut()[0] = to_alice.clone();
        *coin.witness_mut() = witness::owner_key(BOB, EntryRole::Leader, SIG_HASH_ALL);
        transfer.contract_output_mut(0).state = to_alice.into();
        transfer
    };
    let (transfer, floor) = at_the_fee_floor(&spend);
    // The coin the transfer spends is the output the mint created: same script, same value,
    // same covenant.
    let spent = &transfer
        .assemble(Family::pinned())
        .expect("the realistic transfer assembles")
        .utxos[0];
    let created = &minted.outputs[1];
    assert_eq!(spent.script_public_key, created.script_public_key);
    assert_eq!(spent.amount, created.value);
    assert_eq!(
        spent.covenant_id,
        created.covenant.map(|binding| binding.covenant_id)
    );
    let name = "the new owner moves the minted coin";
    let outcome = Case::new(format!("realistic/{name}"))
        .py([MINT_SPEND])
        .note(format!(
            "{REALISTIC_NOTE} The transfer spends the real outpoint of the token output of \
             the line 'realistic/mint 10 of 25, limit 10'."
        ))
        .expect_mempool_accept(&transfer);
    assert_paid_at_the_floor(name, &outcome, floor);
}
