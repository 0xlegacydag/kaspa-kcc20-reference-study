//! Cases that stop at rules of PublicMint at which no other case of the suite stops.
//!
//! A run that neutralises every refusing opcode in turn can judge a rule only at an opcode
//! where some case stops. The cases of this file stop at seven rules of PublicMint, each by a
//! twin: the honest transaction passes, a node gets to the scripts of both sides, one change
//! is made, and the judged input stops exactly at the rule.
//!
//! | Rule | Entry | Source line | What the changed transaction does |
//! |---|---|---|---|
//! | `M-16` | `mint` | 140 -> 68 | the new coin has an owner scheme above 0x04 |
//! | `M-17` | `mint` | 141 -> 71 | the new coin has a borrow scheme above 0x03 |
//! | `M-25` | `split` | 190 | one output, or three, bound to the minter |
//! | `M-33` | `reclaim` | 246 | an output bound to the closed minter |
//! | `M-41` | `reclaim_into` | 271 | no output, or two, bound to the survivor |
//! | `M-42` | `reclaim_into` | 275 | a family output bound to the retiring minter |
//! | `M-56` | `reclaim_delegator` | 322 | a family output bound to the retiring minter |
//!
//! No case of this suite stops at `M-39`, `M-43`, `M-44` or `M-54`.
//!
//! `M-42` and `M-56` answer the same transaction on two inputs: an output of the family
//! that the retiring minter authorises is counted by the survivor (`M-42`) and by the
//! retiring minter itself (`M-56`). In the cases of this file neither is the only refusal of
//! its transaction: where the survivor stops at `M-42`, the second minter stops at `M-56`
//! when it retires and at `M-10` when it mints (the last case of
//! `merge_the_retiring_minter_binds_no_output`); where the retiring minter stops at `M-56`,
//! the survivor stops at `M-42` or at `M-41`.

use checks::{Case, Expected};
use kaspa_consensus_core::tx::CovenantBinding;
use kcc20_family::{
    Contract, Entry, Scenario,
    keys::{self, BOB, CAROL},
    scenario::{Arg, Call, ContractOutput, LateBytes, OrdinaryInput},
    shapes::{self, Profile},
    states::{BORROW_HASH_CHAIN, Kcc20State, OWNER_COVENANT_ID, PublicMintState},
};

/// The value of the coin that pays for an added output, in sompi.
const FUNDING: u64 = 2_000;

fn script() -> Profile {
    Profile::Script
}

/// A rule of the contract refused, in the statement that starts at `line`.
fn rule(id: &str, line: u32) -> Expected {
    Expected::rule(id).at_line(line)
}

/// A binding to the family of the shapes, authorised by input `input`.
fn bound_to(input: u16) -> Option<CovenantBinding> {
    Some(CovenantBinding::new(input, shapes::covenant_id()))
}

/// A coin anybody can spend, so that an added output does not spend more than there is.
fn funding_coin() -> OrdinaryInput {
    OrdinaryInput::new(
        shapes::op_true_script(),
        FUNDING,
        shapes::outpoint(3, 0),
        LateBytes::empty(),
    )
    .labelled("funding (OP_TRUE)")
}

/// The same scenario with the funding coin behind its inputs.
fn funded(mut scenario: Scenario) -> Scenario {
    scenario.push_ordinary_input(funding_coin());
    scenario
}

/// Changes the recipient state of a mint in the call and in the output alike.
fn change_minted_coin(scenario: &mut Scenario, change: impl Fn(&mut Kcc20State)) {
    change(scenario.contract_input_mut(0).declared_state_mut());
    change(
        scenario
            .contract_output_mut(1)
            .state
            .as_kcc20_mut()
            .expect("a token output"),
    );
}

/// A mint whose new coin has the given owner scheme and borrow scheme.
fn mint_with_schemes(owner_scheme: u8, borrow_scheme: u8) -> Scenario {
    let mut scenario = shapes::mint(&script());
    change_minted_coin(&mut scenario, |state| {
        state.owner_scheme = owner_scheme;
        state.borrow_scheme = borrow_scheme;
    });
    scenario
}

// ---------------------------------------------------------------------------------------
// mint: the schemes of the new coin (M-16, M-17)
// ---------------------------------------------------------------------------------------

#[test]
fn mint_the_owner_scheme_of_the_new_coin_is_one_of_the_five() {
    // The honest side is the last scheme the rule lets through.
    let honest = mint_with_schemes(OWNER_COVENANT_ID, 0);
    Case::new("M-16/mint: owner scheme 0x04 passes").expect_accept(&honest);

    // The call and the coin name the same scheme, so no rule about the output objects.
    for scheme in [0x05u8, 0x7f, 0x80, 0x81, 0xff] {
        Case::new(format!(
            "M-16/mint: owner scheme {scheme:#04x}, call and coin alike"
        ))
        .note(
            "the scheme is one byte read as an unsigned number: 0x80 and 0xff are 128 and \
                 255, not the numbers a script reads from those bytes",
        )
        .twin_inputs(
            &honest,
            move |scenario| {
                change_minted_coin(scenario, |state| state.owner_scheme = scheme);
            },
            &[(0, rule("M-16", 68))],
        );
    }
}

#[test]
fn mint_the_borrow_scheme_of_the_new_coin_is_one_of_the_four() {
    let honest = mint_with_schemes(0, BORROW_HASH_CHAIN);
    Case::new("M-17/mint: borrow scheme 0x03 passes").expect_accept(&honest);

    for scheme in [0x04u8, 0x7f, 0x80, 0x81, 0xff] {
        Case::new(format!(
            "M-17/mint: borrow scheme {scheme:#04x}, call and coin alike"
        ))
        .note("the scheme is one byte read as an unsigned number")
        .twin_inputs(
            &honest,
            move |scenario| {
                change_minted_coin(scenario, |state| state.borrow_scheme = scheme);
            },
            &[(0, rule("M-17", 71))],
        );
    }
}

#[test]
fn mint_an_owner_scheme_out_of_range_is_judged_before_the_borrow_scheme() {
    // Both schemes out of range: the owner scheme answers, as the source orders them.
    Case::new("M-16/mint: owner scheme 0x05 and borrow scheme 0x04")
        .note("this case stops at M-16 before it reaches M-17")
        .twin_inputs(
            &shapes::mint(&script()),
            |scenario| {
                change_minted_coin(scenario, |state| {
                    state.owner_scheme = 0x05;
                    state.borrow_scheme = 0x04;
                });
            },
            &[(0, rule("M-16", 68))],
        );
}

// ---------------------------------------------------------------------------------------
// split: exactly two outputs bound to the minter (M-25)
// ---------------------------------------------------------------------------------------

#[test]
fn split_binds_exactly_two_outputs_to_the_minter() {
    // The shape brings its own funding coin, which also pays for a third output.
    let honest = shapes::mint_split(&script());
    Case::new("M-25/split: honest 25 -> 18 + 7").expect_accept(&honest);

    // A third minter out of nothing, bound to the splitting minter: the case stops at the
    // count of bound outputs.
    Case::new("M-25/split: a third minter of Carol bound to the minter")
        .note("7 more of allowance than the minter had; the count of bound outputs refuses")
        .twin_inputs(
            &honest,
            |scenario| {
                scenario.push_contract_output(ContractOutput::new(
                    PublicMintState::new(keys::x_only(CAROL), 7, 10),
                    shapes::SCRIPT_SPLIT_VALUE,
                    bound_to(0),
                ));
            },
            &[(0, rule("M-25", 190))],
        );

    // A token coin instead of a third minter: the same count answers.
    Case::new("M-25/split: a token coin of 1000 bound to the minter")
        .note("a split makes no token coin")
        .twin_inputs(
            &honest,
            |scenario| {
                scenario.push_contract_output(ContractOutput::new(
                    Kcc20State::new(keys::x_only(CAROL), 1_000),
                    shapes::SCRIPT_SPLIT_VALUE,
                    bound_to(0),
                ));
            },
            &[(0, rule("M-25", 190))],
        );

    // One bound output: the new minter left outside the covenant.
    Case::new("M-25/split: the added minter is not bound to the covenant")
        .note("the coin has the minter's script and no covenant id")
        .twin_inputs(
            &honest,
            |scenario| scenario.contract_output_mut(1).binding = None,
            &[(0, rule("M-25", 190))],
        );
}

// ---------------------------------------------------------------------------------------
// reclaim: no output bound to the closed minter (M-33)
// ---------------------------------------------------------------------------------------

#[test]
fn reclaim_binds_no_output_to_the_minter() {
    let honest = funded(shapes::mint_reclaim(&script()));
    Case::new("M-33/reclaim: honest with funding").expect_accept(&honest);

    // The owner's payout joins the family. Her signature is made over this transaction.
    Case::new("M-33/reclaim: the payout is bound to the minter")
        .note("an ordinary coin of the owner with the covenant id of the family")
        .twin_inputs(
            &honest,
            |scenario| scenario.plain_output_mut(0).binding = bound_to(0),
            &[(0, rule("M-33", 246))],
        );

    // A token coin out of nothing beside the payout, bound to the closed minter.
    Case::new("M-33/reclaim: a token coin of 1000 bound to the minter")
        .note("the count of bound outputs refuses")
        .twin_inputs(
            &honest,
            |scenario| {
                scenario.push_contract_output(ContractOutput::new(
                    Kcc20State::new(keys::x_only(CAROL), 1_000),
                    shapes::SCRIPT_SPLIT_VALUE,
                    bound_to(0),
                ));
            },
            &[(0, rule("M-33", 246))],
        );
}

// ---------------------------------------------------------------------------------------
// reclaim_into: exactly one output bound to the survivor (M-41)
// ---------------------------------------------------------------------------------------

#[test]
fn merge_binds_exactly_one_output_to_the_survivor() {
    let honest = funded(shapes::mint_reclaim_into(&script()));
    Case::new("M-41/merge: honest with funding").expect_accept(&honest);

    // No bound output: the successor left outside the covenant.
    Case::new("M-41/merge: the successor is not bound to the covenant")
        .note("the retiring minter binds nothing either and passes")
        .twin_inputs(
            &honest,
            |scenario| scenario.contract_output_mut(0).binding = None,
            &[(0, rule("M-41", 271)), (1, Expected::pass())],
        );

    // Two bound outputs: the retiring owner's payout joins the family through the survivor.
    Case::new("M-41/merge: the payout of the retiring owner is bound to the survivor")
        .note("counted by the survivor alone: the retiring minter passes")
        .twin_inputs(
            &honest,
            |scenario| scenario.plain_output_mut(1).binding = bound_to(0),
            &[(0, rule("M-41", 271)), (1, Expected::pass())],
        );

    // Two bound outputs, the second a token coin out of nothing: the case stops at M-41, in
    // front of M-42.
    Case::new("M-41/merge: a token coin of 1000 bound to the survivor")
        .note("the count of the survivor's outputs refuses")
        .twin_inputs(
            &honest,
            |scenario| {
                scenario.push_contract_output(ContractOutput::new(
                    Kcc20State::new(keys::x_only(CAROL), 1_000),
                    shapes::SCRIPT_SPLIT_VALUE,
                    bound_to(0),
                ));
            },
            &[(0, rule("M-41", 271)), (1, Expected::pass())],
        );
}

// ---------------------------------------------------------------------------------------
// reclaim_into and reclaim_delegator: no output of the family beside the successor
// (M-42 on the survivor, M-56 on the retiring minter)
// ---------------------------------------------------------------------------------------

#[test]
fn merge_the_retiring_minter_binds_no_output() {
    let honest = funded(shapes::mint_reclaim_into(&script()));

    // The retiring owner's payout joins the family through his own input. The survivor has
    // its one output and sees two of the family; the retiring minter sees one of its own.
    // Bob's signature is made over this transaction.
    Case::new("M-42 M-56/merge: the payout of the retiring owner is bound to the retiring minter")
        .note("one transaction, two answers: the survivor at line 275, the retiring minter at 322")
        .twin_inputs(
            &honest,
            |scenario| scenario.plain_output_mut(1).binding = bound_to(1),
            &[(0, rule("M-42", 275)), (1, rule("M-56", 322))],
        );

    // The same with a token coin out of nothing.
    Case::new("M-42 M-56/merge: a token coin of 1000 bound to the retiring minter")
        .note("the same two answers as for the payout")
        .twin_inputs(
            &honest,
            |scenario| {
                scenario.push_contract_output(ContractOutput::new(
                    Kcc20State::new(keys::x_only(BOB), 1_000),
                    shapes::SCRIPT_SPLIT_VALUE,
                    bound_to(1),
                ));
            },
            &[(0, rule("M-42", 275)), (1, rule("M-56", 322))],
        );

    // The successor itself moves to the retiring minter: the survivor is left with no output
    // and stops one rule earlier, the retiring minter stops as before.
    Case::new("M-41 M-56/merge: the successor is bound to the retiring minter")
        .note("the survivor counts none of its own before it counts those of the family")
        .twin_inputs(
            &honest,
            |scenario| scenario.contract_output_mut(0).binding = bound_to(1),
            &[(0, rule("M-41", 271)), (1, rule("M-56", 322))],
        );

    // The second minter does not retire: it mints its 4 to Carol and continues with 0, while
    // the survivor takes the same 4 into its successor. The survivor sees three outputs of
    // the family for its one; the minting input is not alone in the covenant.
    Case::new("M-42 M-10/merge: the second minter mints its allowance instead of retiring")
        .note(
            "the allowance of the second minter would be used twice; the survivor stops at \
             line 275, the minting input at its count of covenant inputs, line 127",
        )
        .twin_inputs(
            &honest,
            |scenario| {
                let recipient = Kcc20State::new(keys::x_only(CAROL), 4);
                scenario.contract_input_mut(1).call =
                    Call::typed(Entry::Mint, vec![Arg::State(recipient.clone())]);
                scenario.push_contract_output(ContractOutput::new(
                    PublicMintState::new(keys::x_only(BOB), 0, 10),
                    shapes::SCRIPT_SPLIT_VALUE,
                    bound_to(1),
                ));
                scenario.push_contract_output(ContractOutput::new(
                    recipient,
                    shapes::SCRIPT_SPLIT_VALUE,
                    bound_to(1),
                ));
            },
            &[(0, rule("M-42", 275)), (1, rule("M-10", 127))],
        );
}

// ---------------------------------------------------------------------------------------
// The bytes in front of M-16 and M-17
// ---------------------------------------------------------------------------------------

#[test]
fn the_scheme_rules_compare_the_byte_as_an_unsigned_number() {
    // `<scheme> 0x00 OpCat  <bound> 0x00 OpCat  OpLessThanOrEqual OpVerify`: a zero byte behind
    // the scheme makes every value of the byte a number from 0 to 255, so a byte with its top
    // bit set is above the bound and is not read as a negative number below it.
    const PUSH_ZERO_CAT: [u8; 3] = [0x01, 0x00, 0x7e];
    const LESS_THAN_OR_EQUAL: u8 = 0xa1;
    let code = checks::family().bytecode(Contract::PublicMint);
    for (name, verify_at, bound) in [("owner", 270usize, 0x04u8), ("borrow", 283, 0x03)] {
        assert_eq!(
            code[verify_at - 9..verify_at - 6],
            PUSH_ZERO_CAT,
            "{name} scheme: the byte"
        );
        assert_eq!(
            code[verify_at - 6..verify_at - 4],
            [0x01, bound],
            "{name} scheme: the bound"
        );
        assert_eq!(
            code[verify_at - 4..verify_at - 1],
            PUSH_ZERO_CAT,
            "{name} scheme: the bound"
        );
        assert_eq!(
            code[verify_at - 1],
            LESS_THAN_OR_EQUAL,
            "{name} scheme: the comparison"
        );
    }
    checks::results::record_structural(
        "M-16 M-17/structure: the scheme byte is compared as an unsigned number",
        &[],
        "read the bytes 261-269 and 274-282 of the minter's script: a zero byte is appended to \
         the scheme and to the bound (0x04, 0x03) in front of OpLessThanOrEqual",
    );
}
