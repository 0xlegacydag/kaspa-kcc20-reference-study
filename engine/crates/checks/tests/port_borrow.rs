//! The earlier Python checks of the borrowed receive and of the delegate entry of KCC20,
//! re-run on the real script engine.
//!
//! The earlier Python checks ran one input per call on a debug engine and named the source
//! line of a refusal. They gave the inputs they did not run a bare push of the redeem
//! script. Here every scenario is assembled as a whole transaction: each token input carries
//! its real call, the signatures are made over the finished transaction, and the engine of a
//! node runs the script of every input.
//!
//! What an accept line asserts depends on its helper. `expect_accept` asserts the scripts of
//! the whole transaction only; it is used for the honest side of a twin (the twin itself
//! requires that a node gets to the scripts) and for the two lines `.., the scripts`, each
//! paired with a line `.., the node` that asserts the consensus refusal. Every other accept
//! line is made by `expect_consensus_accept`: scripts and the consensus rules of a
//! submission. The coins are the 1000-sompi coins of the earlier checks; no line of this
//! file asks a block or a mempool. A line that is not a sub-case of the earlier check whose
//! id it carries starts its note with `ADDED HERE:`.
//!
//! One case per sub-case of an earlier check, with the id of that check attached. A refusal
//! the earlier check asserted by its source line is a twin: an honest transaction passes,
//! the change of the earlier check is made, and the input it ran is refused by the rule at
//! that line. An input the earlier check did not run carries its honest call here. Its
//! answer, and the answer of an input the earlier check ran without asserting anything, is
//! pinned next to the asserted one and named in the note of the case. Where the engine
//! shows what the earlier check could not, the note says `DIFFERS FROM PYTHON:` and gives
//! both answers.
//!
//! A few cases are not a sub-case of an earlier check and say so in their notes: the
//! control of the group `delegator/read/..` with the very bytes of the earlier check, a
//! second call for an input the earlier check left without one, and the consensus view of
//! the two transactions that create sompi (last paragraph).
//!
//! Two groups:
//!
//! - `borrow/..`: `test_borrow.BorrowedReceive`, 11 checks. Bob's coin leads on the borrow
//!   path with the one-byte witness, Alice's coin joins with the delegate entry and signs.
//! - `delegator/..`: `test_delegator.LeaderAndDelegator`, 15 checks. Alice's coin leads on
//!   the owner path, Bob's coin joins with the delegate entry.
//!
//! All coins are worth 1000 sompi unless a check is about coin values, as in the earlier
//! checks. Two of their accepted transactions create more sompi than they spend. Each is
//! judged three times: by the scripts (`expect_accept`), by the consensus rule that
//! refuses it in front of the scripts, and once more with a funding coin added, as a
//! transaction a node gets to run.

use checks::{Case, Expected};
use kaspa_consensus_core::{hashing::sighash_type::SIG_HASH_ALL, tx::CovenantBinding};
use kcc20_family::{
    Entry, EntryRole, Family, Scenario,
    keys::{self, ALICE, BOB, CAROL, DAVE},
    raw,
    scenario::{Arg, Call, ContractInput, ContractOutput, LateBytes, OrdinaryInput, PlainOutput},
    shapes::{self, BorrowKind, Profile},
    states::{Kcc20State, PATH_BORROW},
    witness,
};

/// A key that owns no coin of a scenario: the stranger of the earlier checks.
const MALLORY: u8 = DAVE;

const COIN: u64 = shapes::SCRIPT_COIN_VALUE;

fn script() -> Profile {
    Profile::Script
}

/// A token coin state with the plain owner scheme and borrowing disabled.
fn tokens(owner: u8, amount: i64) -> Kcc20State {
    Kcc20State::new(keys::x_only(owner), amount)
}

fn bound_to(input: u16) -> Option<CovenantBinding> {
    Some(CovenantBinding::new(input, shapes::covenant_id()))
}

/// The leader call on the owner path: the declared next states and the owner's signature.
fn leader_call(next_states: &[Kcc20State], owner: u8) -> Call {
    Call::typed(
        Entry::Transfer,
        vec![
            Arg::States(next_states.to_vec()),
            Arg::Bytes(witness::owner_key(owner, EntryRole::Leader, SIG_HASH_ALL)),
        ],
    )
}

/// The delegate call: the owner's signature.
fn delegate_call(owner: u8) -> Call {
    Call::typed(
        Entry::TransferDelegator,
        vec![Arg::Bytes(witness::owner_key(
            owner,
            EntryRole::Delegate,
            SIG_HASH_ALL,
        ))],
    )
}

/// A token coin of the shapes' covenant at outpoint `(01 x32, index)`.
fn token_coin(state: Kcc20State, index: u32, call: Call) -> ContractInput {
    ContractInput::new(
        state,
        COIN,
        Some(shapes::covenant_id()),
        shapes::outpoint(1, index),
        call,
    )
}

/// Writes the next states of a transfer into the leader's call (input 0) and into the token
/// outputs alike.
fn set_next_states(scenario: &mut Scenario, next_states: &[Kcc20State]) {
    *scenario.contract_input_mut(0).declared_states_mut() = next_states.to_vec();
    for (index, state) in next_states.iter().enumerate() {
        scenario.contract_output_mut(index).state = state.clone().into();
    }
}

/// Changes token output `index` in the leader's call (input 0) and in the output alike.
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

/// The id of the assembled transaction: equal ids, equal transactions.
fn tx_id(scenario: &Scenario) -> String {
    scenario
        .assemble(Family::pinned())
        .expect("the scenario assembles")
        .tx
        .id()
        .to_string()
}

/// The redeem script of a token coin in `state`.
fn redeem_script(state: &Kcc20State) -> Vec<u8> {
    Family::pinned()
        .redeem_script(&state.clone().into())
        .expect("a token state has a redeem script")
}

/// One data push of `script`, as a signature script pushes a redeem script.
fn push(script: &[u8]) -> Vec<u8> {
    raw::push_redeem(script).expect("a redeem script fits a push")
}

/// The scenario with the funding coin of the reference's tests as one more input: 2000 sompi
/// locked by `OP_TRUE`, spent with an empty signature script.
fn funded(mut scenario: Scenario) -> Scenario {
    scenario.push_ordinary_input(
        OrdinaryInput::new(
            shapes::op_true_script(),
            shapes::SCRIPT_FUNDING_VALUE,
            shapes::outpoint(3, 0),
            LateBytes::empty(),
        )
        .labelled("funding (OP_TRUE)"),
    );
    scenario
}

/// A contract rule refused, at the source line the earlier check asserted.
fn rule(id: &str, line: u32) -> Expected {
    Expected::rule(id).at_line(line)
}

fn pass() -> Expected {
    Expected::pass()
}

// ---------------------------------------------------------------------------------------
// The borrowed receive (test_borrow.BorrowedReceive)
// ---------------------------------------------------------------------------------------

fn borrow_case(id: &str, method: &str) -> Case {
    Case::new(format!("borrow/{id}")).py([format!("test_borrow.BorrowedReceive.{method}")])
}

/// Bob's coin of the reference example: 200 tokens, anybody may add more than 10.
fn bob_coin() -> Kcc20State {
    tokens(BOB, 200).with_threshold(10)
}

/// The borrowed receive of the earlier checks: Bob's coin `bob` leads on the borrow path
/// with the witness `01` and no signature, Alice's coin of `alice_amount` tokens joins with
/// the delegate entry and signs, and `increase` tokens move from Alice's coin to Bob's.
/// The shape of `shapes::borrow` with other numbers.
fn receive(bob: Kcc20State, alice_amount: i64, increase: i64) -> Scenario {
    let mut scenario = shapes::borrow(&script(), BorrowKind::Threshold);
    scenario.name = format!("borrowed receive of {increase}");
    let next_states = [
        bob.clone().with_amount(bob.amount + increase),
        tokens(ALICE, alice_amount - increase),
    ];
    scenario.contract_input_mut(0).state = bob.into();
    scenario.contract_input_mut(1).state = tokens(ALICE, alice_amount).into();
    set_next_states(&mut scenario, &next_states);
    scenario
}

/// Bob holds 200 with threshold 10, Alice holds 100 and adds 11.
fn honest_receive() -> Scenario {
    receive(bob_coin(), 100, 11)
}

#[test]
fn borrow_more_than_the_threshold_passes_without_the_recipients_signature() {
    let honest = honest_receive();
    assert_eq!(
        tx_id(&honest),
        tx_id(&shapes::borrow(&script(), BorrowKind::Threshold)),
        "the honest receive of this file is the reference shape, byte for byte"
    );
    let outcome = borrow_case(
        "honest/add 11 above threshold 10",
        "test_adding_more_than_the_threshold_passes_without_the_recipient_s_signature",
    )
    .note("both inputs pass; the leader's signature script holds no signature")
    .expect_accept(&honest);
    let leader = outcome.inputs[0]
        .alone
        .as_ref()
        .expect("the leader was run");
    assert_eq!(
        leader.used_sig_ops, 0,
        "the leader's run uses no signature operation"
    );
    assert_eq!(outcome.inputs[0].entry.as_deref(), Some("transfer"));
    assert_eq!(
        outcome.inputs[1].entry.as_deref(),
        Some("transfer_delegator")
    );
}

#[test]
fn borrow_other_thresholds_and_amounts_pass() {
    let method = "test_other_thresholds_and_amounts";
    // (increase, threshold, Bob's amount, Alice's amount)
    let numbers: [(i64, i64, i64, i64); 3] = [
        (1, 0, 0, 1),
        (501, 500, 1000, 2000),
        (1 << 40, (1 << 40) - 1, 5, 1 << 41),
    ];
    for (increase, threshold, bob_amount, alice_amount) in numbers {
        borrow_case(
            &format!("honest/add {increase} above threshold {threshold}"),
            method,
        )
        .expect_consensus_accept(&receive(
            tokens(BOB, bob_amount).with_threshold(threshold),
            alice_amount,
            increase,
        ));
    }
}

#[test]
fn borrow_exactly_the_threshold_or_less_is_refused() {
    for increase in [10, 9, 1, 0] {
        borrow_case(
            &format!("threshold/add {increase} with threshold 10"),
            "test_adding_exactly_the_threshold_or_less_is_refused",
        )
        .twin_inputs(
            &honest_receive(),
            |scenario| *scenario = receive(bob_coin(), 100, increase),
            &[(0, rule("K-61", 219)), (1, pass())],
        );
    }
}

#[test]
fn borrow_tokens_cannot_be_taken_out_of_the_recipients_coin() {
    borrow_case(
        "threshold/take 100 out of the coin",
        "test_tokens_cannot_be_taken_out_of_the_recipient_s_coin",
    )
    .note("input 1 (the delegate, run but not asserted by the earlier check) passes")
    .twin_inputs(
        &honest_receive(),
        |scenario| *scenario = receive(bob_coin(), 100, -100),
        &[(0, rule("K-61", 219)), (1, pass())],
    );
}

#[test]
fn borrow_the_recipients_coin_keeps_its_owner_and_its_policy() {
    borrow_case(
        "successor/owner replaced",
        "test_the_recipient_s_coin_keeps_its_owner",
    )
    .note("input 1 (the delegate, run but not asserted by the earlier check) passes")
    .twin_inputs(
        &honest_receive(),
        |scenario| change_token_output(scenario, 0, |state| state.owner = keys::x_only(MALLORY)),
        &[(0, rule("K-57", 214)), (1, pass())],
    );
    borrow_case(
        "successor/threshold lowered to 0",
        "test_the_recipient_s_coin_keeps_its_policy",
    )
    .note("input 1 (the delegate, run but not asserted by the earlier check) passes")
    .twin_inputs(
        &honest_receive(),
        |scenario| change_token_output(scenario, 0, |state| state.borrow_guard = [0; 32]),
        &[(0, rule("K-60", 217)), (1, pass())],
    );
}

#[test]
fn borrow_the_recipients_coin_does_not_lose_sompi() {
    let method = "test_the_recipient_s_coin_does_not_lose_sompi";
    // The recipient's coin is worth 5000 sompi and its successor keeps `kept`.
    let with_kept = |kept: u64| {
        let mut scenario = honest_receive();
        scenario.contract_input_mut(0).value = 5_000;
        scenario.contract_output_mut(0).value = kept;
        scenario
    };

    borrow_case("sompi/successor keeps 5000 of 5000", method).expect_accept(&with_kept(5_000));

    borrow_case("sompi/successor holds 5001 of 5000, the scripts", method)
        .note(
            "the scripts accept, as the earlier check said: the rule is `>=`; the transaction \
             creates one sompi more than it spends, see the next case",
        )
        .expect_accept(&with_kept(5_001));
    borrow_case("sompi/successor holds 5001 of 5000, the node", method)
        .note(
            "DIFFERS FROM PYTHON: whole transaction only. Python: both inputs pass. The \
             node: refuses the transaction before it runs a script, SpendTooHigh, outputs of \
             6001 sompi against inputs of 6000",
        )
        .expect_consensus_refused(&with_kept(5_001), "SpendTooHigh");
    borrow_case("sompi/successor holds 5001 of 5000, funded", method)
        .note(
            "ADDED HERE: not a sub-case of the earlier check. \
             The same transaction with a funding coin of 2000 sompi, which the earlier check \
             did not have: scripts and consensus rules accept, the coin gains one sompi",
        )
        .expect_consensus_accept(&funded(with_kept(5_001)));

    borrow_case("sompi/successor keeps 4999 of 5000", method)
        .note("input 1 (the delegate, run but not asserted by the earlier check) passes")
        .twin_inputs(
            &with_kept(5_000),
            |scenario| scenario.contract_output_mut(0).value = 4_999,
            &[(0, rule("K-62", 220)), (1, pass())],
        );
}

#[test]
fn borrow_the_tokens_still_come_from_somewhere() {
    borrow_case(
        "sum/sender keeps 90 of 100 after giving 11",
        "test_borrowed_tokens_still_have_to_come_from_somewhere",
    )
    .note("input 1 (the delegate, run but not asserted by the earlier check) passes")
    .twin_inputs(
        &honest_receive(),
        |scenario| change_token_output(scenario, 1, |state| state.amount = 90),
        &[(0, rule("K-37", 175)), (1, pass())],
    );
}

#[test]
fn borrow_the_sender_still_signs() {
    borrow_case(
        "sender/signed by a stranger",
        "test_the_sender_still_has_to_sign",
    )
    .note("the leader passes; the refusal is that of the delegate's own input")
    .twin_inputs(
        &honest_receive(),
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() =
                witness::owner_key(MALLORY, EntryRole::Delegate, SIG_HASH_ALL)
        },
        &[(0, pass()), (1, rule("K-38", 69))],
    );
}

#[test]
fn borrow_a_coin_with_borrowing_disabled_cannot_be_paid_into() {
    borrow_case(
        "scheme/borrowing disabled",
        "test_a_coin_with_borrowing_disabled_cannot_be_paid_into",
    )
    .note(
        "the earlier check asserted the text of the refusing statement, which stands on four \
         lines of KCC20.sil; the engine stops in the one of the disabled branch, line 184. \
         Input 1 (the delegate, run but not asserted by the earlier check) passes",
    )
    .twin_inputs(
        &honest_receive(),
        |scenario| *scenario = receive(tokens(BOB, 200), 100, 11),
        &[(0, rule("K-50", 184)), (1, pass())],
    );
}

#[test]
fn borrow_the_threshold_scheme_takes_no_extra_witness_bytes() {
    borrow_case(
        "scheme/witness 01 00",
        "test_the_threshold_scheme_takes_no_extra_witness_bytes",
    )
    .note("input 1 (the delegate, run but not asserted by the earlier check) passes")
    .twin_inputs(
        &honest_receive(),
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() = LateBytes::fixed([PATH_BORROW, 0x00])
        },
        &[(0, rule("K-51", 186)), (1, pass())],
    );
}

// ---------------------------------------------------------------------------------------
// Leader and delegate (test_delegator.LeaderAndDelegator)
// ---------------------------------------------------------------------------------------

fn delegator_case(id: &str, method: &str) -> Case {
    Case::new(format!("delegator/{id}")).py([format!("test_delegator.LeaderAndDelegator.{method}")])
}

/// A transfer on the owner path: the first coin leads and its owner signs, every other coin
/// joins with the delegate entry and its owner signs, every output is bound to the leader.
/// Coins and outputs are `(owner key, token amount)`, 1000 sompi each.
fn join_of(coins: &[(u8, i64)], outputs: &[(u8, i64)]) -> Scenario {
    let next_states: Vec<Kcc20State> = outputs
        .iter()
        .map(|&(owner, amount)| tokens(owner, amount))
        .collect();
    let mut scenario = Scenario::new(format!(
        "join of {} token coins into {}",
        coins.len(),
        outputs.len()
    ));
    for (index, &(owner, amount)) in coins.iter().enumerate() {
        let (call, role) = if index == 0 {
            (leader_call(&next_states, owner), "leader")
        } else {
            (delegate_call(owner), "delegate")
        };
        scenario.push_contract_input(
            token_coin(tokens(owner, amount), index as u32, call)
                .labelled(format!("{role}: key {owner:#04x}, {amount} tokens")),
        );
    }
    for state in next_states {
        scenario.push_contract_output(ContractOutput::new(state, COIN, bound_to(0)));
    }
    scenario
}

/// The honest join of the earlier checks: Alice's 100 tokens lead, Bob's 50 join, Carol
/// receives the parts.
fn join(parts: &[i64]) -> Scenario {
    let outputs: Vec<(u8, i64)> = parts.iter().map(|&part| (CAROL, part)).collect();
    join_of(&[(ALICE, 100), (BOB, 50)], &outputs)
}

#[test]
fn delegator_two_coins_of_two_owners_merge_and_split() {
    let method = "test_two_coins_of_two_owners_merge_and_split";
    delegator_case("honest/parts 150", method).expect_accept(&join(&[150]));
    delegator_case("honest/parts 120 30", method).expect_consensus_accept(&join(&[120, 30]));
    delegator_case("honest/parts 100 49 1, the scripts", method)
        .note("the scripts accept; three 1000-sompi outputs from two 1000-sompi coins")
        .expect_accept(&join(&[100, 49, 1]));
    delegator_case("honest/parts 100 49 1, the node", method)
        .note(
            "DIFFERS FROM PYTHON: whole transaction only. Python: both inputs pass. The \
             node: refuses the transaction before it runs a script, SpendTooHigh, outputs of \
             3000 sompi against inputs of 2000",
        )
        .expect_consensus_refused(&join(&[100, 49, 1]), "SpendTooHigh");
    delegator_case("honest/parts 100 49 1, funded", method)
        .note(
            "ADDED HERE: not a sub-case of the earlier check. \
             The same transaction with a funding coin of 2000 sompi, which the earlier check \
             did not have: scripts and consensus rules accept",
        )
        .expect_consensus_accept(&funded(join(&[100, 49, 1])));
}

#[test]
fn delegator_three_coins_into_three_coins() {
    let method = "test_three_coins_into_three_coins_the_largest_shape_this_reference_allows";
    let honest = join_of(
        &[(ALICE, 100), (BOB, 50), (CAROL, 25)],
        &[(ALICE, 5), (BOB, 70), (CAROL, 100)],
    );
    let outcome = delegator_case("honest/three into three", method).expect_accept(&honest);
    assert_eq!(outcome.inputs.len(), 3, "three answers");
    // Measured here; the earlier checks had no budgets. The leader of the largest shape
    // needs 22 units, a delegate 13.
    assert_eq!(outcome.minimal_budgets(), Some(vec![22, 13, 13]));

    delegator_case("sum/three into three, one token more", method)
        .note("inputs 1 and 2 (the delegates, run but not asserted by the earlier check) pass")
        .twin_inputs(
            &honest,
            |scenario| change_token_output(scenario, 2, |state| state.amount = 101),
            &[(0, rule("K-37", 175)), (1, pass()), (2, pass())],
        );
}

#[test]
fn delegator_other_amounts_and_coin_sizes_pass() {
    let mut scenario = join_of(&[(ALICE, 1 << 61), (BOB, 5)], &[(CAROL, (1 << 61) + 5)]);
    scenario.contract_input_mut(0).value = 7_000;
    scenario.contract_input_mut(1).value = 300;
    delegator_case(
        "honest/2^61 and 5 tokens, coins of 7000 and 300 sompi",
        "test_other_amounts_and_coin_sizes",
    )
    .expect_consensus_accept(&scenario);
}

#[test]
fn delegator_each_owner_signs_for_its_own_input() {
    let honest = join(&[150]);
    let method = "test_delegator_signed_by_a_stranger_is_refused_on_its_own_input_only";
    delegator_case("signature/delegate signed by its owner", method).expect_accept(&honest);
    delegator_case("signature/delegate signed by the receiver", method)
        .note("the leader passes; the refusal is that of the delegate's own input")
        .twin_inputs(
            &honest,
            |scenario| {
                *scenario.contract_input_mut(1).witness_mut() =
                    witness::owner_key(CAROL, EntryRole::Delegate, SIG_HASH_ALL)
            },
            &[(0, pass()), (1, rule("K-38", 69))],
        );
    delegator_case("signature/delegate signed by the leader's owner", method)
        .note(
            "the earlier check asserted only that input 1 is refused; the engine: VerifyError \
             at the signature check of the delegate entry, rule K-38, line 69. Input 0 (run \
             but not asserted by the earlier check) passes",
        )
        .twin_inputs(
            &honest,
            |scenario| {
                *scenario.contract_input_mut(1).witness_mut() =
                    witness::owner_key(ALICE, EntryRole::Delegate, SIG_HASH_ALL)
            },
            &[(0, pass()), (1, rule("K-38", 69))],
        );

    delegator_case(
        "signature/leader signed by the delegate's owner",
        "test_leader_signed_by_the_delegator_s_owner_is_refused",
    )
    .twin_inputs(
        &honest,
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                witness::owner_key(BOB, EntryRole::Leader, SIG_HASH_ALL)
        },
        &[(0, rule("K-38", 69)), (1, pass())],
    );
}

#[test]
fn delegator_the_leader_carries_the_sum_rule() {
    let method = "test_outputs_summing_to_more_than_both_inputs_are_refused_by_the_leader";
    let honest = join_of(&[(ALICE, 100), (BOB, 50)], &[(CAROL, 120), (ALICE, 30)]);
    delegator_case("sum/120 and 30 of 150", method).expect_accept(&honest);
    delegator_case("sum/120 and 31 of 150", method)
        .note("the delegate passes on its own input: the leader carries the sum rule")
        .twin_inputs(
            &honest,
            |scenario| change_token_output(scenario, 1, |state| state.amount = 31),
            &[(0, rule("K-37", 175)), (1, pass())],
        );

    delegator_case(
        "sum/the delegate's tokens counted twice",
        "test_the_delegator_s_tokens_are_counted_once",
    )
    .note("input 1 (the delegate, run but not asserted by the earlier check) passes")
    .twin_inputs(
        &join(&[150]),
        |scenario| change_token_output(scenario, 0, |state| state.amount = 200),
        &[(0, rule("K-37", 175)), (1, pass())],
    );
}

#[test]
fn delegator_of_another_token_family_is_refused_by_the_leader() {
    delegator_case(
        "family/delegate of another token family",
        "test_a_delegator_of_another_token_family_is_refused_by_the_leader",
    )
    .note("input 1 (the delegate, run but not asserted by the earlier check) passes")
    .twin_inputs(
        &join(&[150]),
        |scenario| {
            scenario
                .contract_input_mut(1)
                .state
                .as_kcc20_mut()
                .expect("a token coin")
                .extension_commitment = [0xee; 32]
        },
        &[(0, rule("K-29", 164)), (1, pass())],
    );
}

#[test]
fn delegator_a_token_output_bound_to_the_delegate_is_refused_by_both_inputs() {
    delegator_case(
        "binding/a second token output bound to the delegate",
        "test_a_token_output_bound_to_the_delegator_is_refused_by_both_inputs",
    )
    .twin_inputs(
        &join(&[150]),
        |scenario| {
            scenario.push_contract_output(ContractOutput::new(
                tokens(CAROL, 1000),
                COIN,
                bound_to(1),
            ));
        },
        &[(0, rule("K-23", 158)), (1, rule("K-73", 265))],
    );
}

#[test]
fn delegator_four_token_inputs_are_refused_whatever_the_outputs_say() {
    // The honest side: a leader of 1000 tokens and two delegates of 100, the most the
    // contract takes. The change: a third delegate, the same state and lock once more.
    let honest = join_of(&[(ALICE, 1000), (BOB, 100), (BOB, 100)], &[(CAROL, 1200)]);
    for total in [1300, 1200, 1100] {
        delegator_case(
            &format!("count/four token inputs, output of {total}"),
            "test_four_token_inputs_are_refused_whatever_the_outputs_say",
        )
        .note(
            "DIFFERS FROM PYTHON: whole transaction only. Python: inputs 1 to 3 not run. \
             The engine: the three delegates, with their owner's signatures, pass; with \
             four token inputs only the leader refuses",
        )
        .twin_inputs(
            &honest,
            |scenario| {
                scenario.push_contract_input(
                    token_coin(tokens(BOB, 100), 3, delegate_call(BOB))
                        .labelled("delegate: a third one"),
                );
                change_token_output(scenario, 0, |state| state.amount = total);
            },
            &[
                (0, rule("K-16", 132)),
                (1, pass()),
                (2, pass()),
                (3, pass()),
            ],
        );
    }
}

#[test]
fn delegator_the_first_token_input_leads_and_only_it() {
    let honest = join(&[150]);

    delegator_case(
        "role/first token input runs the delegate entry",
        "test_the_first_token_input_cannot_run_the_delegator_entry",
    )
    .note(
        "DIFFERS FROM PYTHON: whole transaction only. Python: input 1 not run. The engine: \
         input 1 with its honest delegate call passes",
    )
    .twin_inputs(
        &honest,
        |scenario| scenario.contract_input_mut(0).call = delegate_call(ALICE),
        &[(0, rule("K-69", 255)), (1, pass())],
    );

    delegator_case(
        "role/second token input runs the leader entry",
        "test_the_second_token_input_cannot_run_the_leader_entry",
    )
    .note(
        "DIFFERS FROM PYTHON: whole transaction only. Python: input 0 not run. The engine: \
         input 0 with its honest leader call passes; the transaction is refused by input 1 \
         alone",
    )
    .twin_inputs(
        &honest,
        |scenario| scenario.contract_input_mut(1).call = leader_call(&[tokens(CAROL, 150)], BOB),
        &[(0, pass()), (1, rule("K-14", 129))],
    );

    delegator_case(
        "role/second token input leads, the only output bound to it",
        "test_the_second_token_input_cannot_lead_even_when_the_only_output_is_bound_to_it",
    )
    .note(
        "DIFFERS FROM PYTHON: whole transaction only. Python: input 0 not run. The engine: \
         input 0 with a leader call for the same output is refused as well, no output is \
         bound to it (rule K-21, line 155)",
    )
    .twin_inputs(
        &honest,
        |scenario| {
            let next_states = [tokens(CAROL, 100)];
            set_next_states(scenario, &next_states);
            scenario.contract_output_mut(0).binding = bound_to(1);
            scenario.contract_input_mut(1).call = leader_call(&next_states, BOB);
        },
        &[(0, rule("K-21", 155)), (1, rule("K-14", 129))],
    );

    delegator_case(
        "role/second token input leads, the only output bound to it, input 0 as delegate",
        "test_the_second_token_input_cannot_lead_even_when_the_only_output_is_bound_to_it",
    )
    .note(
        "ADDED HERE: not a sub-case of the earlier check. \
         The same transaction with a delegate call on input 0, the other call a spender \
         could give it. DIFFERS FROM PYTHON: whole transaction only. Python: input 0 not \
         run. The engine: input 0 is refused as the first token input (rule K-69, line 255)",
    )
    .twin_inputs(
        &honest,
        |scenario| {
            let next_states = [tokens(CAROL, 100)];
            scenario.contract_output_mut(0).state = next_states[0].clone().into();
            scenario.contract_output_mut(0).binding = bound_to(1);
            scenario.contract_input_mut(0).call = delegate_call(ALICE);
            scenario.contract_input_mut(1).call = leader_call(&next_states, BOB);
        },
        &[(0, rule("K-69", 255)), (1, rule("K-14", 129))],
    );
}

#[test]
fn delegator_a_lone_token_input_cannot_run_the_delegate_entry() {
    let method = "test_a_lone_token_input_cannot_run_the_delegator_entry";
    let honest = join_of(&[(ALICE, 100)], &[(CAROL, 100)]);
    delegator_case("role/lone token input as delegate, a token output", method).twin(
        &honest,
        |scenario| scenario.contract_input_mut(0).call = delegate_call(ALICE),
        0,
        rule("K-68", 254),
    );
    delegator_case("role/lone token input as delegate, no token output", method)
        .note("the tokens would vanish: the only output is a plain coin without a binding")
        .twin(
            &honest,
            |scenario| {
                scenario.contract_input_mut(0).call = delegate_call(ALICE);
                scenario.outputs.clear();
                scenario.push_plain_output(PlainOutput::new(shapes::op_true_script(), COIN));
            },
            0,
            rule("K-68", 254),
        );
}

#[test]
fn delegator_cannot_show_a_state_its_coin_is_not_locked_to() {
    let method = "test_a_delegator_cannot_show_a_state_its_coin_is_not_locked_to";
    let real = tokens(BOB, 50);
    let claimed = tokens(BOB, 1_000_000);
    let claimed_script = redeem_script(&claimed);

    // The control: a coin really locked to the million.
    let honest = join_of(&[(ALICE, 100), (BOB, 1_000_000)], &[(CAROL, 1_000_100)]);
    delegator_case("read/control: a coin really locked to the million", method)
        .note(
            "the earlier check gave input 1 the bare push of its redeem script and did not \
             run it; here it carries its honest delegate call and passes",
        )
        .expect_accept(&honest);

    // The control as the earlier check wrote it: input 1 pushes its redeem script and
    // nothing else.
    let mut bare = honest.clone();
    bare.contract_input_mut(1).signature_script = Some(LateBytes::fixed(push(&claimed_script)));
    delegator_case(
        "read/control with the bare push of the earlier check",
        method,
    )
    .note(
        "ADDED HERE: the transaction of the earlier control run once as written; a reject \
         line under a sub-case the earlier check accepted (it ran input 0 only), recording \
         the node's refusal of input 1. \
         The bytes of the earlier check; input 0 passes, as it said. DIFFERS FROM PYTHON: \
         whole transaction only. Python: input 1 not run, the transaction is its accepted \
         control. The engine: input 1 carries no call and is refused at the first opcode of \
         the token script, InvalidStackOperation; with its honest call it passes (the case \
         before)",
    )
    .expect_inputs(
        &bare,
        &[(0, pass()), (1, Expected::engine("InvalidStackOperation"))],
    );

    // The coin is locked to 50 tokens; its signature script is the claimed script alone.
    let alone = push(&claimed_script);
    delegator_case("read/the claimed script alone", method)
        .note(
            "the leader refuses at rule K-18, line 136: the script shown does not hash to \
             the coin. DIFFERS FROM PYTHON: whole transaction only. Python: input 1 not \
             run. The engine: input 1 is refused by the pay-to-script-hash check, for the \
             same reason and before any contract code",
        )
        .twin_inputs(
            &honest,
            |scenario| {
                let input = scenario.contract_input_mut(1);
                input.state = real.clone().into();
                input.signature_script = Some(LateBytes::fixed(alone));
            },
            &[
                (0, rule("K-18", 136)),
                (1, Expected::refused_by("P2SH wrapper")),
            ],
        );

    // The real script first, the claimed one last.
    let both = [push(&redeem_script(&real)), push(&claimed_script)].concat();
    delegator_case("read/the real script first, the claimed one last", method)
        .note(
            "as the case before: the leader refuses at rule K-18, line 136. \
             DIFFERS FROM PYTHON: whole transaction only. Python: input 1 not run. The \
             engine: input 1 is refused by the pay-to-script-hash check as well",
        )
        .twin_inputs(
            &honest,
            |scenario| {
                let input = scenario.contract_input_mut(1);
                input.state = real.clone().into();
                input.signature_script = Some(LateBytes::fixed(both));
            },
            &[
                (0, rule("K-18", 136)),
                (1, Expected::refused_by("P2SH wrapper")),
            ],
        );
}
