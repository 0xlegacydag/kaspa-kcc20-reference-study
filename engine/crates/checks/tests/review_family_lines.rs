//! The source line the test harness of `crates/checks` names for a refusal, held against
//! the line an earlier suite of checks asserted with a debug engine, on refusals the other
//! tests of the harness do not use. The earlier suite is not published here; the ids of
//! its checks are kept as labels. A line is given as a file name and a number, and that
//! is what the cases compare: no text of the reference's sources stands in this file.
//!
//! Every case does three things:
//!
//! 1. The honest twin is accepted, one change is made, and the named input is refused by
//!    the named rule at the named line of the generated source.
//! 2. The attributed file is the file of the contract the input really spends.
//! 3. The attributed opcode is neutralised: the family is rebuilt with that one opcode
//!    replaced by a drop of the same stack items (`OpVerify` by `OpDrop`, `OpEqualVerify`
//!    and `OpNumEqualVerify` by `Op2Drop`). On that family the honest twin still passes
//!    and the changed transaction is no longer refused at that opcode. This does not use
//!    the opcode log at all, so it tests the position the harness reports by another
//!    way: an offset that is one opcode off would leave the refusal where it was.
//!
//! The cases cover the three contracts and every entry: `transfer` on the owner path and
//! on the borrow path, `transfer_delegator`, `mint`, the two splits, `create`, and the
//! reclaim entries with their delegates.

use checks::{Case, Expected, Harness, Outcome, RunOutcome, judge_accept};
use kaspa_consensus_core::{hashing::sighash_type::SIG_HASH_ALL, tx::CovenantBinding};
use kaspa_txscript::opcodes::codes::{Op2Drop, OpDrop, OpEqualVerify, OpNumEqualVerify, OpVerify};
use kcc20_family::{
    Contract, Entry, EntryRole, Family, Scenario,
    keys::{self, ALICE, BOB, CAROL, SigningContext},
    scenario::{Arg, Call, ContractInput, ContractOutput, InputSpec, LateBytes, PlainOutput},
    shapes::{self, BorrowKind, Profile},
    states::{
        Kcc20State, OWNER_COVENANT_ID, OWNER_P2PKH_ECDSA, OWNER_P2SH, PATH_BORROW, PATH_NORMAL,
    },
    witness,
};

const KCC20: &str = "KCC20.sil";
const PUBLIC_MINT: &str = "PublicMint.sil";
const TOKEN_SEED: &str = "TokenSeed.sil";

/// Another token family: the extension commitment the earlier suite used.
const OTHER_FAMILY: [u8; 32] = [0xee; 32];
/// Another covenant id: the owner of the covenant-id owner cases of the earlier suite.
const OTHER_COVENANT: [u8; 32] = [0x33; 32];

fn script() -> Profile {
    Profile::Script
}

/// One refusal the earlier suite asserted by its source line.
struct Asserted {
    input: usize,
    /// The rule of the inventory at that line. Empty when the engine refuses the data of
    /// the statement at an opcode that is not the refusing opcode of a rule.
    rule: &'static str,
    /// The engine error variant, when the refusal is not a failed check of the script.
    engine: Option<&'static str>,
    file: &'static str,
    line: u32,
    /// The byte offset of the refusing opcode in the redeem script.
    offset: usize,
}

/// A rule of the contract refused at `file:line`, at the opcode at `offset`.
fn refused(
    input: usize,
    rule: &'static str,
    file: &'static str,
    line: u32,
    offset: usize,
) -> Asserted {
    Asserted {
        input,
        rule,
        engine: None,
        file,
        line,
        offset,
    }
}

/// The engine refused the data of the statement at `file:line`.
fn engine_error(
    input: usize,
    variant: &'static str,
    rule: &'static str,
    file: &'static str,
    line: u32,
    offset: usize,
) -> Asserted {
    Asserted {
        input,
        rule,
        engine: Some(variant),
        file,
        line,
        offset,
    }
}

fn contract_of_file(file: &str) -> Contract {
    match file {
        KCC20 => Contract::Kcc20,
        PUBLIC_MINT => Contract::PublicMint,
        TOKEN_SEED => Contract::TokenSeed,
        other => panic!("no contract has the source file {other}"),
    }
}

/// The pinned family with the checking opcode at `offset` of `contract` replaced by a drop
/// of the items it would have judged. `None` for an opcode that is not such a check.
fn family_without_check(contract: Contract, offset: usize) -> Option<Family> {
    let family = Family::pinned();
    let mut bytecode = family.bytecode(contract).to_vec();
    let opcode = bytecode[offset];
    let replacement = if opcode == OpVerify {
        OpDrop
    } else if opcode == OpEqualVerify || opcode == OpNumEqualVerify {
        Op2Drop
    } else {
        return None;
    };
    bytecode[offset] = replacement;
    Some(
        family
            .with_bytecode(contract, bytecode)
            .expect("a replacement of the same length"),
    )
}

fn judged(outcome: &Outcome, input: usize) -> &RunOutcome {
    outcome.inputs[input]
        .alone
        .as_ref()
        .expect("the input was run")
}

/// Runs the twin and holds rule, file, line and offset against the asserted ones; then
/// neutralises the attributed opcode and requires the refusal to move.
/// `passing` lists the inputs the earlier suite asserted to pass in the changed scenario.
fn check(
    case: &str,
    py_ids: &[&str],
    honest: &Scenario,
    change: impl FnOnce(&mut Scenario),
    asserted: &[Asserted],
    passing: &[usize],
) -> Outcome {
    let mut changed = honest.clone();
    change(&mut changed);

    let mut expected: Vec<(usize, Expected)> = asserted
        .iter()
        .map(|asserted| {
            let expected = match asserted.engine {
                Some(variant) if asserted.rule.is_empty() => {
                    Expected::engine(variant).at_line(asserted.line)
                }
                Some(variant) => Expected::engine(variant)
                    .at_rule(asserted.rule)
                    .at_line(asserted.line),
                None => Expected::rule(asserted.rule).at_line(asserted.line),
            };
            (asserted.input, expected)
        })
        .collect();
    expected.extend(passing.iter().map(|input| (*input, Expected::pass())));

    let replacement = changed.clone();
    let twin = Case::new(format!("review/{case}"))
        .py(py_ids.iter().copied())
        .twin_inputs(honest, move |scenario| *scenario = replacement, &expected);

    // The twin helper judges the scripts only. A refusal by a rule of a contract is what a
    // node answers only if the node gets as far as the scripts: both sides of the twin must
    // pass every consensus rule in front of them (amounts, lock times, covenant bindings).
    assert!(
        twin.honest.consensus.accepted,
        "case `{case}`: the honest twin is not a transaction a node accepts: {:?}",
        twin.honest.consensus.refusal
    );
    assert!(
        twin.changed.consensus.context_accepted,
        "case `{case}`: a node refuses the changed transaction before it runs a script: {:?}",
        twin.changed.consensus.context_refusal
    );

    for asserted in asserted {
        let run = judged(&twin.changed, asserted.input);
        let refusal = run.refusal.as_ref().expect("a refused run is attributed");
        let sil = refusal.sil.as_ref().expect("the refusal has a source line");
        assert_eq!(sil.file, asserted.file, "case `{case}`: {}", run.describe());
        assert_eq!(sil.line, asserted.line, "case `{case}`: {}", run.describe());
        assert_eq!(
            refusal.byte_offset,
            Some(asserted.offset),
            "case `{case}`: {}",
            run.describe()
        );
        assert_eq!(
            refusal.contract.as_deref(),
            Some(contract_of_file(asserted.file).name()),
            "case `{case}`"
        );
        assert_eq!(refusal.note, None, "case `{case}`: {}", run.describe());

        // The test of the position without the opcode log. Only for a check of the script:
        // an engine error has no opcode that can be replaced without changing what is
        // computed.
        if asserted.engine.is_some() {
            continue;
        }
        let contract = contract_of_file(asserted.file);
        let weakened = family_without_check(contract, asserted.offset)
            .unwrap_or_else(|| panic!("case `{case}`: byte {} is not a check", asserted.offset));
        let harness = Harness::pinned().with_family(weakened);
        let honest_outcome = harness.run(honest);
        judge_accept(&honest_outcome).unwrap_or_else(|failure| {
            panic!("case `{case}`: without the check the honest twin fails: {failure}")
        });
        let outcome = harness.run(&changed);
        let run = judged(&outcome, asserted.input);
        if !run.ok {
            let moved = run.refusal.as_ref().expect("a refused run is attributed");
            match moved.byte_offset {
                Some(offset) if moved.contract.is_some() => assert!(
                    offset > asserted.offset,
                    "case `{case}`: without the check at byte {} the input is still refused \
                     at byte {offset}: {}",
                    asserted.offset,
                    run.describe()
                ),
                _ => {}
            }
        }
    }
    twin.changed
}

/// A token coin of the shapes' covenant that joins a transaction as one more input. The
/// earlier suite never ran such an input; here it runs the delegate entry with its owner's
/// signature, and nothing is asserted about it.
fn extra_token_coin(outpoint_index: u32) -> ContractInput {
    ContractInput::new(
        Kcc20State::new(keys::x_only(BOB), 5),
        shapes::SCRIPT_COIN_VALUE,
        Some(shapes::covenant_id()),
        shapes::outpoint(1, outpoint_index),
        Call::typed(
            Entry::TransferDelegator,
            vec![Arg::Bytes(witness::owner_key(
                BOB,
                EntryRole::Delegate,
                SIG_HASH_ALL,
            ))],
        ),
    )
    .labelled("one more token coin of the same covenant")
}

fn bound_to(input: u16) -> Option<CovenantBinding> {
    Some(CovenantBinding::new(input, shapes::covenant_id()))
}

/// Changes output `index` of a transfer in the call and in the output alike.
fn change_token_output(scenario: &mut Scenario, index: usize, change: impl Fn(&mut Kcc20State)) {
    change(&mut scenario.contract_input_mut(0).declared_states_mut()[index]);
    change(
        scenario
            .contract_output_mut(index)
            .state
            .as_kcc20_mut()
            .expect("a token output"),
    );
}

/// Changes the recipient state of `mint` or `create` in the call and in the output alike.
fn change_new_coin(scenario: &mut Scenario, change: impl Fn(&mut Kcc20State)) {
    change(scenario.contract_input_mut(0).declared_state_mut());
    change(
        scenario
            .contract_output_mut(1)
            .state
            .as_kcc20_mut()
            .expect("the new token coin"),
    );
}

// ---------------------------------------------------------------------------------------
// PublicMint.mint
// ---------------------------------------------------------------------------------------

#[test]
fn mint_the_amount_is_positive_within_the_limit_and_within_the_allowance() {
    check(
        "PublicMint 136 amount 0",
        &["test_public_mint.PublicMint.test_zero_and_negative_amounts_are_refused"],
        &shapes::mint(&script()),
        |scenario| {
            change_new_coin(scenario, |state| state.amount = 0);
            scenario
                .contract_output_mut(0)
                .state
                .as_public_mint_mut()
                .unwrap()
                .remaining = 25;
        },
        &[refused(0, "M-12", PUBLIC_MINT, 136, 239)],
        &[],
    );
    check(
        "PublicMint 137 amount 11 of 10 per mint",
        &["test_public_mint.PublicMint.test_more_than_the_per_mint_limit_is_refused"],
        &shapes::mint(&script()),
        |scenario| {
            change_new_coin(scenario, |state| state.amount = 11);
            scenario
                .contract_output_mut(0)
                .state
                .as_public_mint_mut()
                .unwrap()
                .remaining = 14;
        },
        &[refused(0, "M-13", PUBLIC_MINT, 137, 245)],
        &[],
    );

    // A minter with 5 left mints 5; one more is above the allowance, not above the limit.
    let mut honest = shapes::mint(&script());
    honest
        .contract_input_mut(0)
        .state
        .as_public_mint_mut()
        .unwrap()
        .remaining = 5;
    change_new_coin(&mut honest, |state| state.amount = 5);
    honest
        .contract_output_mut(0)
        .state
        .as_public_mint_mut()
        .unwrap()
        .remaining = 0;
    check(
        "PublicMint 138 amount 6 of 5 left",
        &["test_public_mint.PublicMint.test_more_than_the_remaining_allowance_is_refused"],
        &honest,
        |scenario| {
            change_new_coin(scenario, |state| state.amount = 6);
            scenario
                .contract_output_mut(0)
                .state
                .as_public_mint_mut()
                .unwrap()
                .remaining = -1;
        },
        &[refused(0, "M-14", PUBLIC_MINT, 138, 251)],
        &[],
    );
}

#[test]
fn mint_the_new_coin_is_of_the_minters_family() {
    check(
        "PublicMint 139 new coin of another family",
        &["test_public_mint.PublicMint.test_the_new_coin_must_be_of_the_minter_s_token_family"],
        &shapes::mint(&script()),
        |scenario| change_new_coin(scenario, |state| state.extension_commitment = OTHER_FAMILY),
        &[refused(0, "M-15", PUBLIC_MINT, 139, 257)],
        &[],
    );
}

#[test]
fn mint_the_minter_keeps_its_sompi_and_its_allowance_goes_down_by_the_amount() {
    check(
        "PublicMint 149 minter deposit",
        &[
            "test_public_mint.PublicMint.test_the_minter_keeps_its_sompi",
            "A_minter.test_a_minter.Mint.test_02_continuation_deposit_plus_and_minus_one",
        ],
        &shapes::mint(&script()),
        |scenario| scenario.contract_output_mut(0).value = 999,
        &[refused(0, "M-18", PUBLIC_MINT, 149, 302)],
        &[],
    );
    check(
        "PublicMint 161 allowance 16 instead of 15",
        &[
            "test_public_mint.PublicMint.test_the_allowance_must_go_down_by_exactly_the_minted_amount",
        ],
        &shapes::mint(&script()),
        |scenario| {
            scenario
                .contract_output_mut(0)
                .state
                .as_public_mint_mut()
                .unwrap()
                .remaining = 16
        },
        &[refused(0, "M-19", PUBLIC_MINT, 161, 396)],
        &[],
    );
}

#[test]
fn mint_makes_one_coin_and_runs_alone_in_its_covenant() {
    check(
        "PublicMint 130 a second token coin bound to the minter",
        &["test_public_mint.PublicMint.test_one_mint_creates_exactly_one_token_coin"],
        &shapes::mint(&script()),
        |scenario| {
            scenario.push_contract_output(ContractOutput::new(
                Kcc20State::new(keys::x_only(BOB), 1000),
                shapes::SCRIPT_COIN_VALUE,
                bound_to(0),
            ));
        },
        &[refused(0, "M-11", PUBLIC_MINT, 130, 228)],
        &[],
    );
    check(
        "PublicMint 127 a token coin of the covenant beside the minter",
        &[
            "test_public_mint.PublicMint.test_mint_runs_with_no_other_coin_of_the_covenant_beside_the_minter",
            "A_minter.test_a_minter.SingleInputCounts.test_03_mint",
        ],
        &shapes::mint(&script()),
        |scenario| scenario.inputs[1] = InputSpec::Contract(extra_token_coin(1)),
        &[refused(0, "M-10", PUBLIC_MINT, 127, 223)],
        &[],
    );
}

// ---------------------------------------------------------------------------------------
// PublicMint.split
// ---------------------------------------------------------------------------------------

#[test]
fn minter_split_takes_more_than_nothing() {
    check(
        "PublicMint 196 take 0",
        &["A_minter.test_a_minter.Split.test_01_take_zero_and_minus_one"],
        &shapes::mint_split(&script()),
        |scenario| {
            scenario.contract_input_mut(0).args_mut()[0] = Arg::int(0);
            scenario
                .contract_output_mut(0)
                .state
                .as_public_mint_mut()
                .unwrap()
                .remaining = 25;
            scenario
                .contract_output_mut(1)
                .state
                .as_public_mint_mut()
                .unwrap()
                .remaining = 0;
        },
        &[refused(0, "M-26", PUBLIC_MINT, 196, 607)],
        &[],
    );
}

#[test]
fn minter_split_keeps_the_owner_and_the_per_mint_limit() {
    check(
        "PublicMint 224 retained owner",
        &["A_minter.test_a_minter.Split.test_06_retained_owner_changed"],
        &shapes::mint_split(&script()),
        |scenario| {
            scenario
                .contract_output_mut(0)
                .state
                .as_public_mint_mut()
                .unwrap()
                .owner = keys::x_only(CAROL)
        },
        &[refused(0, "M-29", PUBLIC_MINT, 224, 735)],
        &[],
    );
    check(
        "PublicMint 236 new minter with another per-mint limit",
        &["test_lifecycle.MinterLifecycle.test_a_split_keeps_the_per_mint_limit"],
        &shapes::mint_split(&script()),
        |scenario| {
            scenario
                .contract_output_mut(1)
                .state
                .as_public_mint_mut()
                .unwrap()
                .mint_amount = 1_000_000
        },
        &[refused(0, "M-30", PUBLIC_MINT, 236, 832)],
        &[],
    );
}

#[test]
fn minter_split_runs_alone_in_its_covenant() {
    check(
        "PublicMint 187 a token coin of the covenant beside the minter",
        &["A_minter.test_a_minter.SingleInputCounts.test_01_split"],
        &shapes::mint_split(&script()),
        |scenario| {
            scenario
                .inputs
                .insert(1, InputSpec::Contract(extra_token_coin(7)))
        },
        &[refused(0, "M-24", PUBLIC_MINT, 187, 591)],
        &[],
    );
}

// ---------------------------------------------------------------------------------------
// PublicMint.reclaim, reclaim_into, reclaim_delegator
// ---------------------------------------------------------------------------------------

#[test]
fn minter_reclaim_runs_alone_and_asks_the_owner() {
    check(
        "PublicMint 243 a token coin of the covenant beside the minter",
        &["A_minter.test_a_minter.SingleInputCounts.test_02_reclaim"],
        &shapes::mint_reclaim(&script()),
        |scenario| {
            scenario.push_contract_input(extra_token_coin(7));
        },
        &[refused(0, "M-32", PUBLIC_MINT, 243, 888)],
        &[],
    );
    check(
        "PublicMint 249 signature of another key",
        &["test_lifecycle.MinterLifecycle.test_the_owner_takes_the_deposit_of_an_exhausted_minter"],
        &shapes::mint_reclaim(&script()),
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() = witness::signature(CAROL, SIG_HASH_ALL)
        },
        &[refused(0, "M-35", PUBLIC_MINT, 249, 904)],
        &[],
    );
}

#[test]
fn minter_merge_the_survivor_is_the_first_input_of_the_covenant() {
    // The two inputs change places and the successor is bound to the survivor at input 1.
    check(
        "PublicMint 261 and 312 retiring minter placed first",
        &["A_minter.test_a_minter.ReclaimInto.test_06_retiring_input_placed_first"],
        &shapes::mint_reclaim_into(&script()),
        |scenario| {
            scenario.inputs.swap(0, 1);
            scenario.contract_output_mut(0).binding = bound_to(1);
        },
        &[
            refused(1, "M-37", PUBLIC_MINT, 261, 946),
            refused(0, "M-52", PUBLIC_MINT, 312, 1573),
        ],
        &[],
    );
}

#[test]
fn minter_merge_the_allowance_is_the_sum() {
    check(
        "PublicMint 300 merged allowance 23 instead of 22",
        &["test_lifecycle.MinterLifecycle.test_the_merged_allowance_is_exactly_the_sum"],
        &shapes::mint_reclaim_into(&script()),
        |scenario| {
            scenario
                .contract_output_mut(0)
                .state
                .as_public_mint_mut()
                .unwrap()
                .remaining = 23
        },
        &[refused(0, "M-49", PUBLIC_MINT, 300, 1505)],
        &[1],
    );
}

// ---------------------------------------------------------------------------------------
// TokenSeed.create
// ---------------------------------------------------------------------------------------

#[test]
fn seed_create_the_new_coin_is_of_the_seeds_family() {
    check(
        "TokenSeed 133 new coin of another family",
        &["B_seed.test_b_seed.Create.test_recipient_of_another_family"],
        &shapes::seed_create(&script()),
        |scenario| change_new_coin(scenario, |state| state.extension_commitment = OTHER_FAMILY),
        &[refused(0, "S-13", TOKEN_SEED, 133, 227)],
        &[],
    );
}

#[test]
fn seed_create_makes_one_coin_and_runs_alone_in_its_covenant() {
    check(
        "TokenSeed 126 a second token coin bound to the seed",
        &["B_seed.test_b_seed.Create.test_no_second_coin_bound_to_the_seed"],
        &shapes::seed_create(&script()),
        |scenario| {
            scenario.push_contract_output(ContractOutput::new(
                Kcc20State::new(keys::x_only(CAROL), 1000),
                shapes::SCRIPT_COIN_VALUE,
                bound_to(0),
            ));
        },
        &[refused(0, "S-11", TOKEN_SEED, 126, 210)],
        &[],
    );
    check(
        "TokenSeed 123 a token coin of the covenant beside the seed",
        &["B_seed.test_b_seed.Create.test_no_other_input_of_the_family"],
        &shapes::seed_create(&script()),
        |scenario| {
            scenario.push_contract_input(extra_token_coin(2));
        },
        &[refused(0, "S-10", TOKEN_SEED, 123, 205)],
        &[],
    );
}

// ---------------------------------------------------------------------------------------
// TokenSeed.split
// ---------------------------------------------------------------------------------------

#[test]
fn seed_split_keeps_the_seed_and_runs_alone_in_its_covenant() {
    // A `require` over lines 183-186.
    check(
        "TokenSeed 183 retained seed owner",
        &["B_seed.test_b_seed.Split.test_retained_seed_keeps_its_owner"],
        &shapes::seed_split(&script()),
        |scenario| {
            scenario
                .contract_output_mut(0)
                .state
                .as_token_seed_mut()
                .unwrap()
                .owner = keys::x_only(CAROL)
        },
        &[refused(0, "S-24", TOKEN_SEED, 183, 469)],
        &[],
    );
    check(
        "TokenSeed 167 a token coin of the covenant beside the seed",
        &["B_seed.test_b_seed.Split.test_no_other_input_of_the_family"],
        &shapes::seed_split(&script()),
        |scenario| {
            scenario.push_contract_input(extra_token_coin(2));
        },
        &[refused(0, "S-21", TOKEN_SEED, 167, 440)],
        &[],
    );
    check(
        "TokenSeed 196 the added output is a token coin",
        &["B_seed.test_b_seed.Split.test_added_output_must_be_a_seed"],
        &shapes::seed_split(&script()),
        |scenario| {
            scenario.contract_output_mut(1).state = Kcc20State::new(keys::x_only(BOB), 1000).into()
        },
        &[refused(0, "S-25", TOKEN_SEED, 196, 543)],
        &[],
    );
}

// ---------------------------------------------------------------------------------------
// TokenSeed.reclaim, reclaim_delegator
// ---------------------------------------------------------------------------------------

#[test]
fn seed_reclaim_keeps_the_survivors_owner() {
    // A `require` over lines 227-230.
    check(
        "TokenSeed 227 survivor owner",
        &["B_seed.test_b_seed.Reclaim.test_survivor_keeps_its_owner"],
        &shapes::seed_reclaim(&script()),
        |scenario| {
            scenario
                .contract_output_mut(0)
                .state
                .as_token_seed_mut()
                .unwrap()
                .owner = keys::x_only(CAROL)
        },
        &[refused(0, "S-35", TOKEN_SEED, 227, 946)],
        &[1],
    );
}

#[test]
fn seed_reclaim_needs_two_seeds() {
    // One seed alone runs the leader entry and recreates itself.
    check(
        "TokenSeed 207 a single seed runs reclaim",
        &[
            "B_seed.test_b_seed.Reclaim.test_a_single_seed_running_reclaim",
            "test_lifecycle.SeedLifecycle.test_a_lone_seed_cannot_be_reclaimed",
        ],
        &shapes::seed_reclaim(&script()),
        |scenario| {
            scenario.inputs.truncate(1);
            scenario.outputs.truncate(1);
        },
        &[refused(0, "S-26", TOKEN_SEED, 207, 585)],
        &[],
    );
    // The retiring seed alone: its owner signs and takes the deposit.
    check(
        "TokenSeed 241 a lone seed runs reclaim_delegator",
        &[
            "B_seed.test_b_seed.Reclaim.test_a_lone_seed_cannot_reclaim",
            "test_lifecycle.SeedLifecycle.test_a_lone_seed_cannot_be_reclaimed",
        ],
        &shapes::seed_reclaim(&script()),
        |scenario| {
            scenario.inputs.remove(0);
            scenario.outputs.remove(0);
        },
        &[refused(0, "S-37", TOKEN_SEED, 241, 994)],
        &[],
    );
}

// ---------------------------------------------------------------------------------------
// KCC20.transfer, owner path
// ---------------------------------------------------------------------------------------

#[test]
fn transfer_an_output_carries_an_assigned_scheme_byte() {
    // Lines 58 and 61 are inside two helper functions inlined at lines 170 and 171.
    check(
        "KCC20 58 output owner scheme 5",
        &[
            "test_transfer.HonestTransfer.test_an_output_may_carry_any_assigned_scheme_byte_and_no_other",
        ],
        &shapes::transfer(&script(), 1, 1),
        |scenario| change_token_output(scenario, 0, |state| state.owner_scheme = 0x05),
        &[refused(0, "K-33", KCC20, 58, 1898)],
        &[],
    );
    check(
        "KCC20 61 output borrow scheme 4",
        &[
            "test_transfer.HonestTransfer.test_an_output_may_carry_any_assigned_scheme_byte_and_no_other",
        ],
        &shapes::transfer(&script(), 1, 1),
        |scenario| change_token_output(scenario, 0, |state| state.borrow_scheme = 0x04),
        &[refused(0, "K-34", KCC20, 61, 1920)],
        &[],
    );
}

#[test]
fn transfer_has_at_least_one_token_output() {
    check(
        "KCC20 155 no token output",
        &["C_token.test_c_token.Bounds.test_zero_token_outputs_are_refused"],
        &shapes::transfer(&script(), 1, 1),
        |scenario| {
            scenario.contract_input_mut(0).declared_states_mut().clear();
            scenario.outputs.clear();
            scenario.push_plain_output(PlainOutput::new(
                shapes::op_true_script(),
                shapes::SCRIPT_COIN_VALUE,
            ));
        },
        &[refused(0, "K-21", KCC20, 155, 1615)],
        &[],
    );
}

#[test]
fn transfer_every_token_output_is_bound_to_the_leader() {
    check(
        "KCC20 158 and 265 a token output bound to the delegate",
        &[
            "test_delegator.LeaderAndDelegator.test_a_token_output_bound_to_the_delegator_is_refused_by_both_inputs",
        ],
        &shapes::transfer(&script(), 2, 1),
        |scenario| {
            scenario.contract_output_mut(0).value = shapes::SCRIPT_COIN_VALUE;
            scenario.push_contract_output(ContractOutput::new(
                Kcc20State::new(keys::x_only(BOB), 1000),
                shapes::SCRIPT_COIN_VALUE,
                bound_to(1),
            ));
        },
        &[
            refused(0, "K-23", KCC20, 158, 1626),
            refused(1, "K-73", KCC20, 265, 3820),
        ],
        &[],
    );
}

#[test]
fn transfer_takes_at_most_two_delegates_of_its_own_family() {
    check(
        "KCC20 132 four token inputs",
        &[
            "test_delegator.LeaderAndDelegator.test_four_token_inputs_are_refused_whatever_the_outputs_say",
        ],
        &shapes::transfer(&script(), 3, 1),
        |scenario| *scenario = shapes::transfer(&script(), 4, 1),
        &[refused(0, "K-16", KCC20, 132, 278)],
        &[],
    );
    check(
        "KCC20 164 delegate of another family",
        &[
            "test_delegator.LeaderAndDelegator.test_a_delegator_of_another_token_family_is_refused_by_the_leader",
        ],
        &shapes::transfer(&script(), 2, 1),
        |scenario| {
            scenario
                .contract_input_mut(1)
                .state
                .as_kcc20_mut()
                .unwrap()
                .extension_commitment = OTHER_FAMILY
        },
        &[refused(0, "K-29", KCC20, 164, 1696)],
        &[],
    );
}

#[test]
fn transfer_the_first_token_input_does_not_run_the_delegate_entry() {
    check(
        "KCC20 255 first token input as delegate",
        &[
            "test_delegator.LeaderAndDelegator.test_the_first_token_input_cannot_run_the_delegator_entry",
        ],
        &shapes::transfer(&script(), 2, 1),
        |scenario| {
            scenario.contract_input_mut(0).call = Call::typed(
                Entry::TransferDelegator,
                vec![Arg::Bytes(witness::owner_key(
                    ALICE,
                    EntryRole::Delegate,
                    SIG_HASH_ALL,
                ))],
            );
        },
        &[refused(0, "K-69", KCC20, 255, 3363)],
        &[],
    );
}

/// The witness of the ECDSA key-hash scheme with the owner's key and another key's
/// signature.
fn ecdsa_witness_signed_by(role: EntryRole, public_key_of: u8, signer: u8) -> LateBytes {
    LateBytes::from_tx(move |ctx| {
        let mut witness = match role {
            EntryRole::Leader => vec![PATH_NORMAL],
            EntryRole::Delegate => Vec::new(),
        };
        witness.extend(keys::compressed(public_key_of));
        witness.extend(keys::ecdsa_signature(
            ctx,
            &keys::keypair(signer),
            SIG_HASH_ALL,
        ));
        witness
    })
}

#[test]
fn transfer_the_ecdsa_key_hash_scheme_checks_the_key_then_the_signature() {
    let py_ids = ["test_schemes.OwnerSchemes.test_p2pkh_ecdsa_owner_is_the_hash_of_an_ecdsa_key"];
    let honest =
        shapes::transfer_with_owner_scheme(&script(), EntryRole::Leader, OWNER_P2PKH_ECDSA);
    check(
        "KCC20 85 leader, another ECDSA key pair",
        &py_ids,
        &honest,
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                witness::owner_key_hash_ecdsa(CAROL, EntryRole::Leader, SIG_HASH_ALL)
        },
        &[refused(0, "K-43", KCC20, 85, 2329)],
        &[],
    );
    check(
        "KCC20 86 leader, the owner's key and another key's ECDSA signature",
        &py_ids,
        &honest,
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                ecdsa_witness_signed_by(EntryRole::Leader, ALICE, CAROL)
        },
        &[refused(0, "K-44", KCC20, 86, 2335)],
        &[],
    );

    let py_ids = ["C_token.test_c_token.DelegateOwnerSchemes.test_p2pkh_ecdsa_delegate"];
    let honest =
        shapes::transfer_with_owner_scheme(&script(), EntryRole::Delegate, OWNER_P2PKH_ECDSA);
    check(
        "KCC20 85 delegate, another ECDSA key pair",
        &py_ids,
        &honest,
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() =
                witness::owner_key_hash_ecdsa(CAROL, EntryRole::Delegate, SIG_HASH_ALL)
        },
        &[refused(1, "K-43", KCC20, 85, 3917)],
        &[0],
    );
    check(
        "KCC20 86 delegate, the owner's key and another key's ECDSA signature",
        &py_ids,
        &honest,
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() =
                ecdsa_witness_signed_by(EntryRole::Delegate, ALICE, CAROL)
        },
        &[refused(1, "K-44", KCC20, 86, 3923)],
        &[0],
    );
}

/// A transfer whose coin at `token_input` is owned by another covenant, with an ordinary
/// input that carries that covenant's id: the honest shape of the earlier suite and the
/// shape of the family crate for owner scheme 0x04.
fn owned_by_another_covenant(role: EntryRole, token_input: usize) -> Scenario {
    let scenario = shapes::transfer_with_owner_scheme(&script(), role, OWNER_COVENANT_ID);
    assert_eq!(
        scenario
            .contract_input(token_input)
            .state
            .as_kcc20()
            .unwrap()
            .owner,
        OTHER_COVENANT
    );
    assert_eq!(shapes::OWNING_COVENANT_ID_BYTES, OTHER_COVENANT);
    scenario
}

#[test]
fn transfer_the_covenant_id_scheme_needs_an_input_of_the_owning_covenant() {
    let py_ids =
        ["test_schemes.OwnerSchemes.test_covenant_id_owner_needs_an_input_of_that_covenant"];
    let honest = owned_by_another_covenant(EntryRole::Leader, 0);
    check(
        "KCC20 96 leader, no input of the owning covenant",
        &py_ids,
        &honest,
        |scenario| scenario.ordinary_input_mut(1).covenant_id = None,
        &[refused(0, "K-48", KCC20, 96, 2407)],
        &[1],
    );
    check(
        "KCC20 95 leader, a witness byte behind the path byte",
        &py_ids,
        &honest,
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                LateBytes::fixed(vec![PATH_NORMAL, 0x00])
        },
        &[refused(0, "K-47", KCC20, 95, 2401)],
        &[1],
    );

    let honest = owned_by_another_covenant(EntryRole::Delegate, 1);
    check(
        "KCC20 96 delegate, no input of the owning covenant",
        &["C_token.test_c_token.DelegateOwnerSchemes.test_covenant_id_delegate"],
        &honest,
        |scenario| scenario.ordinary_input_mut(2).covenant_id = None,
        &[refused(1, "K-48", KCC20, 96, 3995)],
        &[0, 2],
    );
}

#[test]
fn transfer_the_script_hash_scheme_needs_an_input_locked_to_the_hash() {
    // A `require` over lines 90-93. The authority input is locked by a bare OP_TRUE instead
    // of the pay-to-script-hash of it.
    check(
        "KCC20 90 leader, the named input has another lock",
        &["test_schemes.OwnerSchemes.test_p2sh_owner_is_a_script_hash_and_needs_such_an_input"],
        &shapes::transfer_with_owner_scheme(&script(), EntryRole::Leader, OWNER_P2SH),
        |scenario| {
            let authority = scenario.ordinary_input_mut(1);
            authority.script_public_key = shapes::op_true_script();
            authority.signature_script = LateBytes::empty();
        },
        &[refused(0, "K-46", KCC20, 90, 2385)],
        &[1],
    );

    let honest = shapes::transfer_with_owner_scheme(&script(), EntryRole::Delegate, OWNER_P2SH);
    check(
        "KCC20 90 delegate, the index names the leader",
        &[
            "C_token.test_c_token.DelegateOwnerSchemes.test_p2sh_delegate_pointing_at_the_leader_itself_or_an_ordinary_coin_is_refused",
        ],
        &honest,
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() =
                witness::owner_script_hash(0, EntryRole::Delegate)
        },
        &[refused(1, "K-46", KCC20, 90, 3973)],
        &[0, 2],
    );
    // An index behind the last input: the engine refuses the read of the input, inside the
    // same statement and in front of the comparison of the rule.
    check(
        "KCC20 90 delegate, the index names no input",
        &[
            "C_token.test_c_token.DelegateOwnerSchemes.test_p2sh_delegate_index_out_of_range_is_an_engine_error_at_the_rule",
        ],
        &honest,
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() =
                witness::owner_script_hash(4, EntryRole::Delegate)
        },
        &[engine_error(1, "InvalidInputIndex", "", KCC20, 90, 3955)],
        &[0, 2],
    );
}

#[test]
fn transfer_a_signature_for_another_transaction_is_not_the_owners_word() {
    // The owner signs the same transaction with one sompi more on the second output. The
    // signature is genuine, by the right key, and stale.
    check(
        "KCC20 69 signature made for another transaction",
        &[
            "test_transfer.OwnerSignature.test_the_owner_s_signature_for_another_transaction_is_refused",
        ],
        &shapes::transfer(&script(), 1, 2),
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() = LateBytes::from_tx(|ctx| {
                let mut other = ctx.tx.clone();
                other.tx.outputs[1].value += 1;
                let other_ctx = SigningContext {
                    tx: &other,
                    input_index: ctx.input_index,
                };
                let mut witness = vec![PATH_NORMAL];
                witness.extend(keys::schnorr_signature(
                    &other_ctx,
                    &keys::keypair(ALICE),
                    SIG_HASH_ALL,
                ));
                witness
            })
        },
        &[refused(0, "K-38", KCC20, 69, 2249)],
        &[],
    );
    // Sixty-four zero bytes and the type byte ALL: what a builder writes before it signs.
    check(
        "KCC20 69 placeholder signature",
        &["test_transfer.OwnerSignature.test_made_up_and_placeholder_signatures_are_refused"],
        &shapes::transfer(&script(), 1, 2),
        |scenario| {
            let mut witness = vec![PATH_NORMAL];
            witness.extend([0u8; 64]);
            witness.push(SIG_HASH_ALL.to_u8());
            *scenario.contract_input_mut(0).witness_mut() = LateBytes::fixed(witness);
        },
        &[refused(0, "K-38", KCC20, 69, 2249)],
        &[],
    );
}

#[test]
fn transfer_three_inputs_stay_inside_64_bits() {
    // (largest - 1) + 1 + 0 is exactly the largest number. With 1 on the third coin the
    // first addition still holds and the second one overflows: the second copy of the loop
    // body over the delegates.
    let mut honest = shapes::transfer(&script(), 3, 1);
    let amounts = [i64::MAX - 1, 1, 0];
    for (index, amount) in amounts.into_iter().enumerate() {
        honest
            .contract_input_mut(index)
            .state
            .as_kcc20_mut()
            .unwrap()
            .amount = amount;
    }
    change_token_output(&mut honest, 0, |state| state.amount = i64::MAX);
    check(
        "KCC20 165 third input overflows the sum",
        &[
            "C_token.test_c_token.Bounds.test_three_inputs_summing_past_i64_are_refused_by_the_engine_s_overflow_check",
        ],
        &honest,
        |scenario| {
            scenario
                .contract_input_mut(2)
                .state
                .as_kcc20_mut()
                .unwrap()
                .amount = 1
        },
        &[engine_error(0, "NumberTooBig", "K-30", KCC20, 165, 1813)],
        &[1, 2],
    );
}

// ---------------------------------------------------------------------------------------
// KCC20.transfer, borrow path
// ---------------------------------------------------------------------------------------

#[test]
fn borrow_the_coin_keeps_its_sompi_its_owner_and_its_policy() {
    check(
        "KCC20 220 the coin loses one sompi",
        &["test_borrow.BorrowedReceive.test_the_recipient_s_coin_does_not_lose_sompi"],
        &shapes::borrow(&script(), BorrowKind::Threshold),
        |scenario| scenario.contract_output_mut(0).value = 999,
        &[refused(0, "K-62", KCC20, 220, 2643)],
        &[1],
    );
    check(
        "KCC20 214 the coin changes its owner",
        &["test_borrow.BorrowedReceive.test_the_recipient_s_coin_keeps_its_owner"],
        &shapes::borrow(&script(), BorrowKind::Threshold),
        |scenario| change_token_output(scenario, 0, |state| state.owner = keys::x_only(CAROL)),
        &[refused(0, "K-57", KCC20, 214, 2571)],
        &[1],
    );
    check(
        "KCC20 217 the coin changes its guard",
        &["test_borrow.BorrowedReceive.test_the_recipient_s_coin_keeps_its_policy"],
        &shapes::borrow(&script(), BorrowKind::Threshold),
        |scenario| change_token_output(scenario, 0, |state| state.borrow_guard = [0; 32]),
        &[refused(0, "K-60", KCC20, 217, 2616)],
        &[1],
    );
    check(
        "KCC20 172 the coin changes its family",
        &[
            "C_token.test_c_token.BorrowCorners.test_a_borrowed_receive_cannot_change_only_the_successor_s_extension_commitment",
        ],
        &shapes::borrow(&script(), BorrowKind::Threshold),
        |scenario| {
            change_token_output(scenario, 0, |state| {
                state.extension_commitment = OTHER_FAMILY
            })
        },
        &[refused(0, "K-35", KCC20, 172, 1938)],
        &[1],
    );
}

#[test]
fn borrow_the_signature_scheme_asks_the_guard_key() {
    // A `require` over lines 192-195. The sender signs instead of the guard key.
    check(
        "KCC20 192 the sender signs for the guard",
        &[
            "test_schemes.BorrowSchemes.test_schnorr_signature_scheme_asks_the_borrow_key_not_the_owner",
        ],
        &shapes::borrow(&script(), BorrowKind::Signature),
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                witness::borrow_signature(ALICE, SIG_HASH_ALL)
        },
        &[refused(0, "K-52", KCC20, 192, 2485)],
        &[1],
    );
    // The owner of the coin signs: on the borrow path that is not the guard either.
    check(
        "KCC20 192 the owner signs for the guard",
        &[
            "test_schemes.BorrowSchemes.test_schnorr_signature_scheme_asks_the_borrow_key_not_the_owner",
        ],
        &shapes::borrow(&script(), BorrowKind::Signature),
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                witness::borrow_signature(BOB, SIG_HASH_ALL)
        },
        &[refused(0, "K-52", KCC20, 192, 2485)],
        &[1],
    );
}

#[test]
fn borrow_the_hash_chain_witness_has_129_bytes() {
    let honest = shapes::borrow(&script(), BorrowKind::HashChain);
    let Call::Typed { args, .. } = honest.contract_input(0).call.clone() else {
        panic!("the shape has a typed call")
    };
    let Some(Arg::Bytes(witness)) = args.last().cloned() else {
        panic!("the last argument is the witness")
    };
    check(
        "KCC20 197 hash chain witness one byte longer",
        &[
            "C_token.test_c_token.BorrowCorners.test_hash_chain_witness_one_byte_short_or_long_is_refused",
        ],
        &honest,
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() = witness.map(|mut bytes| {
                assert_eq!(bytes[0], PATH_BORROW);
                assert_eq!(bytes.len(), 130, "the path byte and 129 bytes");
                bytes.push(0x00);
                bytes
            })
        },
        &[refused(0, "K-53", KCC20, 197, 2505)],
        &[1],
    );
}

// ---------------------------------------------------------------------------------------
// A check the compiler adds on its own
// ---------------------------------------------------------------------------------------

#[test]
fn with_the_limit_of_two_delegates_replaced_the_bound_of_the_loop_refuses() {
    // With the rule of line 132 removed, four token inputs reach the bound the compiler
    // writes in front of the loop over the delegates. The refusal is named by the line of
    // the loop statement, which has no `require` of its own.
    let weakened = family_without_check(Contract::Kcc20, 278).expect("K-16 is a verify");
    let outcome = Case::new("review/KCC20 134 four token inputs without the rule of line 132")
        .on(Harness::pinned().with_family(weakened))
        .expect_refused(
            &shapes::transfer(&script(), 4, 1),
            0,
            Expected::rule("K-17").at_line(134),
        );
    let refusal = judged(&outcome, 0).refusal.as_ref().unwrap();
    assert_eq!(refusal.byte_offset, Some(295));
    assert_eq!(refusal.place.as_deref(), Some("statement"));
    assert_eq!(refusal.inventory_line.as_deref(), Some("134"));
}
