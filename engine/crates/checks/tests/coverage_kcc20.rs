//! Cases that stop at opcodes of KCC20 at which no other case of the suite stops.
//!
//! A removal run over the rules of the inventory can judge a rule only at an opcode where
//! some case stops. This file holds such stops for KCC20:
//!
//! - rules that are reached by a small change of an honest transaction, each as a twin
//!   that names the rule and the byte offset of the refusing opcode: the copies of the
//!   per-state rules for the second and the third declared state, the copy of the family
//!   rule for the second delegate, the comparison of the third bound output, the rules of
//!   the borrow path about the successor's schemes, the witness length of the script-hash
//!   owner scheme, and the two refusing branches for a spent coin whose own scheme byte is
//!   not assigned;
//! - the copies of the twelve owner rules inside `transfer_delegator`. The inventory
//!   lists them apart from the rule's own opcodes, as reached from another entry, and a
//!   removal run replaces a rule's own opcodes only, so the removal is done here: each
//!   copy is replaced by a drop and the transaction it refused passes;
//! - cases that stop at one rule before they reach another (the bounds the SilverScript
//!   compiler writes in front of the unrolled loops, and the two count rules for the bound
//!   outputs, the one of the source and the one argentc generates in front of the become).
//!   Each is run twice: on the contracts as they are the case stops at
//!   the rule in front, and with that rule replaced by a drop the same transaction stops at
//!   the next one.
//!
//! The families with a rule replaced are built from `checks::family()`, so a removal run
//! weakens them once more and sees the case move.

use checks::{Case, Expected, Harness, Outcome};
use kaspa_consensus_core::{hashing::sighash_type::SIG_HASH_ALL, tx::CovenantBinding};
use kaspa_txscript::opcodes::codes::{Op2Drop, OpDrop, OpEqualVerify, OpNumEqualVerify, OpVerify};
use kcc20_family::{
    Contract, EntryRole, Family, Scenario,
    keys::{self, ALICE, BOB, CAROL},
    scenario::{ContractOutput, LateBytes},
    shapes::{self, BorrowKind, Profile},
    states::{
        BORROW_DISABLED, Kcc20State, OWNER_COVENANT_ID, OWNER_P2PKH_ECDSA, OWNER_P2PKH_SCHNORR,
        OWNER_P2SH, PATH_NORMAL,
    },
    witness,
};

/// Another token family: an extension commitment no honest coin of the shapes carries.
const OTHER_FAMILY: [u8; 32] = [0xee; 32];
/// An owner scheme byte that is not assigned (the assigned ones are 0x00..=0x04).
const OWNER_SCHEME_UNASSIGNED: u8 = 0x05;
/// A borrow scheme byte that is not assigned (the assigned ones are 0x00..=0x03).
const BORROW_SCHEME_UNASSIGNED: u8 = 0x04;

// Byte offsets of refusing opcodes in the KCC20 script, as the rule inventory lists them.
const K16_AT: usize = 278;
const K17_AT: usize = 295;
const K22_AT: usize = 1619;
const K24_AT: usize = 1637;
const K26_AT: usize = 1662;
const K31_AT: usize = 1858;
const K64_AT: usize = 2663;
const K65_AT: usize = 2674;

fn script() -> Profile {
    Profile::Script
}

/// The family of the run with the checking opcodes at `offsets` of KCC20 replaced by a
/// drop of the items they judge (`OpVerify` by `OpDrop`, the two comparing verifies by
/// `Op2Drop`). An opcode a removal run has replaced already is left as it is.
fn family_without(offsets: &[usize]) -> Family {
    let family = checks::family();
    let mut bytecode = family.bytecode(Contract::Kcc20).to_vec();
    let plain = checks::mutation::mode().is_plain();
    for &offset in offsets {
        let opcode = bytecode.get(offset).copied();
        let replacement = if opcode == Some(OpVerify) {
            OpDrop
        } else if opcode == Some(OpEqualVerify) || opcode == Some(OpNumEqualVerify) {
            Op2Drop
        } else {
            // In a removal run the opcode may be replaced already, and contracts rebuilt
            // from changed source have other offsets: the case is observed as it comes.
            assert!(!plain, "byte {offset} of KCC20 is no check: {opcode:?}");
            continue;
        };
        bytecode[offset] = replacement;
    }
    family
        .with_bytecode(Contract::Kcc20, bytecode)
        .expect("a replacement of the same length")
}

fn without(offsets: &[usize]) -> Harness {
    Harness::pinned().with_family(family_without(offsets))
}

/// The refusal of `input` is at byte `offset` of the KCC20 script. A removal run observes
/// the cases on changed contracts, where they stop elsewhere; nothing is asserted then.
fn stops_at(outcome: &Outcome, input: usize, offset: usize) {
    if !checks::mutation::mode().is_plain() {
        return;
    }
    let run = outcome.inputs[input]
        .alone
        .as_ref()
        .expect("the input was run");
    let refusal = run.refusal.as_ref().expect("a refused run is attributed");
    assert_eq!(
        refusal.contract.as_deref(),
        Some("KCC20"),
        "{}",
        run.describe()
    );
    assert_eq!(refusal.byte_offset, Some(offset), "{}", run.describe());
}

/// Changes declared state `index` of the leader and the state output `index` is locked to
/// in the same way, so that the output still holds what the call declares.
fn declare_and_lock(scenario: &mut Scenario, index: usize, change: impl Fn(&mut Kcc20State)) {
    change(&mut scenario.contract_input_mut(0).declared_states_mut()[index]);
    change(
        scenario
            .contract_output_mut(index)
            .state
            .as_kcc20_mut()
            .expect("a token output"),
    );
}

/// The state of the token coin spent by `input`.
fn spent_state(scenario: &mut Scenario, input: usize) -> &mut Kcc20State {
    scenario
        .contract_input_mut(input)
        .state
        .as_kcc20_mut()
        .expect("a token coin")
}

/// One more token output bound to the leader, holding no tokens; its value is taken from
/// output 0, so the transaction spends what it spent before.
fn push_bound_output(scenario: &mut Scenario, owner_seed: u8) {
    let value = 100;
    *scenario.outputs[0].value_mut() -= value;
    scenario.push_contract_output(ContractOutput::new(
        Kcc20State::new(keys::x_only(owner_seed), 0),
        value,
        Some(CovenantBinding::new(0, shapes::covenant_id())),
    ));
}

/// One more declared state that holds no tokens.
fn push_declared_state(scenario: &mut Scenario, owner_seed: u8) {
    scenario
        .contract_input_mut(0)
        .declared_states_mut()
        .push(Kcc20State::new(keys::x_only(owner_seed), 0));
}

// ---------------------------------------------------------------------------------------
// The per-state rules at the second and the third declared state
// ---------------------------------------------------------------------------------------

#[test]
fn the_third_declared_state_is_held_to_the_rules_of_the_first() {
    // One token coin of 100 into three: 34, 33 and 33 tokens.
    let honest = shapes::transfer(&script(), 1, 3);

    // 72, 33 and -5: the sum is still 100.
    let twin = Case::new("coverage/K-32 the third declared amount is -5").twin(
        &honest,
        |scenario| {
            declare_and_lock(scenario, 0, |state| state.amount += 38);
            declare_and_lock(scenario, 2, |state| state.amount = -5);
        },
        0,
        Expected::rule("K-32").at_line(169),
    );
    stops_at(&twin.changed, 0, 2103);

    let twin = Case::new("coverage/K-33 the third declared owner scheme is 0x05").twin(
        &honest,
        |scenario| {
            declare_and_lock(scenario, 2, |state| {
                state.owner_scheme = OWNER_SCHEME_UNASSIGNED
            })
        },
        0,
        Expected::rule("K-33").at_line(58),
    );
    stops_at(&twin.changed, 0, 2124);

    let twin = Case::new("coverage/K-34 the second declared borrow scheme is 0x04").twin(
        &honest,
        |scenario| {
            declare_and_lock(scenario, 1, |state| {
                state.borrow_scheme = BORROW_SCHEME_UNASSIGNED
            })
        },
        0,
        Expected::rule("K-34").at_line(61),
    );
    stops_at(&twin.changed, 0, 2033);

    let twin = Case::new("coverage/K-34 the third declared borrow scheme is 0x04").twin(
        &honest,
        |scenario| {
            declare_and_lock(scenario, 2, |state| {
                state.borrow_scheme = BORROW_SCHEME_UNASSIGNED
            })
        },
        0,
        Expected::rule("K-34").at_line(61),
    );
    stops_at(&twin.changed, 0, 2146);

    let twin = Case::new("coverage/K-35 the third declared state is of another family").twin(
        &honest,
        |scenario| {
            declare_and_lock(scenario, 2, |state| {
                state.extension_commitment = OTHER_FAMILY
            })
        },
        0,
        Expected::rule("K-35").at_line(172),
    );
    stops_at(&twin.changed, 0, 2164);
}

#[test]
fn the_third_addition_of_the_output_total_is_checked_by_the_engine() {
    // The largest number, nothing, and 1: the first two additions stay in range, the third
    // does not. The engine refuses the addition; the sum rule behind it is not reached.
    let honest = shapes::transfer(&script(), 1, 3);
    let twin = Case::new("coverage/K-36 the largest number, 0 and 1").twin(
        &honest,
        |scenario| {
            declare_and_lock(scenario, 0, |state| state.amount = i64::MAX);
            declare_and_lock(scenario, 1, |state| state.amount = 0);
            declare_and_lock(scenario, 2, |state| state.amount = 1);
        },
        0,
        Expected::rule("K-36").at_line(173),
    );
    stops_at(&twin.changed, 0, 2178);
}

#[test]
fn the_first_addition_of_the_output_total_takes_the_largest_amount() {
    // The first addition is 0 + amount. The case with the largest amount there is passes it
    // and stops at the sum rule.
    let honest = shapes::transfer(&script(), 1, 1);
    let twin = Case::new("coverage/K-36 the largest number alone reaches the sum rule").twin(
        &honest,
        |scenario| declare_and_lock(scenario, 0, |state| state.amount = i64::MAX),
        0,
        Expected::rule("K-37").at_line(175),
    );
    stops_at(&twin.changed, 0, 2203);

    // The case with the most negative declared amount stops at the rule about negative
    // declared amounts in front of the addition. With that rule replaced by a drop it
    // passes the addition too and stops at the sum rule.
    let most_negative =
        |scenario: &mut Scenario| declare_and_lock(scenario, 0, |state| state.amount = -i64::MAX);
    let mut changed = honest.clone();
    most_negative(&mut changed);
    let outcome = Case::new("coverage/K-32 the most negative number alone").expect_refused(
        &changed,
        0,
        Expected::rule("K-32").at_line(169),
    );
    stops_at(&outcome, 0, 1877);
    let twin = Case::new("coverage/K-36 the most negative number alone without K-32")
        .on(without(&[1877]))
        .twin(
            &honest,
            most_negative,
            0,
            Expected::rule("K-37").at_line(175),
        );
    stops_at(&twin.changed, 0, 2203);
}

#[test]
fn the_third_bound_output_is_compared_with_the_third_declared_state() {
    // The call declares 33 tokens for the third output; the output is locked to 34.
    let honest = shapes::transfer(&script(), 1, 3);
    let twin = Case::new("coverage/K-66 the third output is locked to one token more").twin(
        &honest,
        |scenario| {
            scenario
                .contract_output_mut(2)
                .state
                .as_kcc20_mut()
                .expect("a token output")
                .amount += 1
        },
        0,
        Expected::rule("K-66").at_line(239),
    );
    stops_at(&twin.changed, 0, 3258);
}

// ---------------------------------------------------------------------------------------
// The family rule at the second delegate
// ---------------------------------------------------------------------------------------

#[test]
fn the_second_delegate_is_held_to_the_family_of_the_leader() {
    let honest = shapes::transfer(&script(), 3, 1);
    let twin = Case::new("coverage/K-29 the second delegate is of another family").twin(
        &honest,
        |scenario| spent_state(scenario, 2).extension_commitment = OTHER_FAMILY,
        0,
        Expected::rule("K-29").at_line(164),
    );
    stops_at(&twin.changed, 0, 1785);
}

// ---------------------------------------------------------------------------------------
// Owner scheme 0x03: the witness is one byte
// ---------------------------------------------------------------------------------------

#[test]
fn the_script_hash_owner_takes_a_witness_of_one_byte() {
    // Leader: the path byte, the index of the authority input, and one byte more.
    let honest = shapes::transfer_with_owner_scheme(&script(), EntryRole::Leader, OWNER_P2SH);
    let twin = Case::new("coverage/K-45 leader, one byte behind the input index").twin(
        &honest,
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                LateBytes::fixed(vec![PATH_NORMAL, 1, 0x00])
        },
        0,
        Expected::rule("K-45").at_line(88),
    );
    stops_at(&twin.changed, 0, 2354);

    // Delegate: the copy of the rule inside `transfer_delegator`. The leader passes.
    let honest = shapes::transfer_with_owner_scheme(&script(), EntryRole::Delegate, OWNER_P2SH);
    let longer = |scenario: &mut Scenario| {
        *scenario.contract_input_mut(1).witness_mut() = LateBytes::fixed(vec![2, 0x00])
    };
    let twin = Case::new("coverage/K-45 delegate, one byte behind the input index").twin_inputs(
        &honest,
        longer,
        &[
            (0, Expected::pass()),
            (1, Expected::rule("K-45").at_line(88)),
        ],
    );
    stops_at(&twin.changed, 1, 3942);

    // The removal of the copy, which a removal run over the rules' own opcodes does not
    // make: with the opcode at 3942 replaced by a drop the same transaction passes.
    let mut changed = honest.clone();
    longer(&mut changed);
    Case::new("coverage/K-45 delegate, the same without the opcode at 3942")
        .on(without(&[3942]))
        .expect_accept(&changed);
}

// ---------------------------------------------------------------------------------------
// Owner scheme 0x04: the witness is empty, also for a delegate
// ---------------------------------------------------------------------------------------

#[test]
fn the_covenant_owner_of_a_delegate_takes_an_empty_witness() {
    // The copy of the rule inside `transfer_delegator`: one byte where none belongs.
    let honest =
        shapes::transfer_with_owner_scheme(&script(), EntryRole::Delegate, OWNER_COVENANT_ID);
    let one_byte = |scenario: &mut Scenario| {
        *scenario.contract_input_mut(1).witness_mut() = LateBytes::fixed(vec![0x00])
    };
    let twin = Case::new("coverage/K-47 delegate, a witness of one byte").twin_inputs(
        &honest,
        one_byte,
        &[
            (0, Expected::pass()),
            (1, Expected::rule("K-47").at_line(95)),
        ],
    );
    stops_at(&twin.changed, 1, 3989);

    // The removal of the copy: without the opcode at 3989 the same transaction passes.
    let mut changed = honest.clone();
    one_byte(&mut changed);
    Case::new("coverage/K-47 delegate, the same without the opcode at 3989")
        .on(without(&[3989]))
        .expect_accept(&changed);
}

// ---------------------------------------------------------------------------------------
// The other copies of the owner rules inside the delegate entry, each removed
// ---------------------------------------------------------------------------------------

/// A change of the witness of the delegate at input 1.
fn delegate_witness(witness: LateBytes) -> Box<dyn Fn(&mut Scenario)> {
    Box::new(move |scenario: &mut Scenario| {
        *scenario.contract_input_mut(1).witness_mut() = witness.clone()
    })
}

#[test]
fn every_copy_of_an_owner_rule_inside_the_delegate_entry_is_the_guard_of_a_case() {
    let delegate =
        |scheme: u8| shapes::transfer_with_owner_scheme(&script(), EntryRole::Delegate, scheme);
    let one_byte_more = |witness: LateBytes| {
        witness.map(|mut bytes| {
            bytes.push(0x00);
            bytes
        })
    };
    // The key of the owner with a valid signature of another key.
    let schnorr_of_another_key = LateBytes::from_tx(|ctx| {
        let mut bytes = keys::x_only(ALICE).to_vec();
        bytes.extend(keys::schnorr_signature(
            ctx,
            &keys::keypair(CAROL),
            SIG_HASH_ALL,
        ));
        bytes
    });
    let ecdsa_of_another_key = LateBytes::from_tx(|ctx| {
        let mut bytes = keys::compressed(ALICE).to_vec();
        bytes.extend(keys::ecdsa_signature(
            ctx,
            &keys::keypair(CAROL),
            SIG_HASH_ALL,
        ));
        bytes
    });

    // Rule, its line, the offset of the copy, the case, the honest transaction, the change.
    type Row = (
        &'static str,
        u32,
        usize,
        &'static str,
        Scenario,
        Box<dyn Fn(&mut Scenario)>,
    );
    let rows: Vec<Row> = vec![
        (
            "K-38",
            69,
            3837,
            "signed by another key",
            shapes::transfer(&script(), 2, 1),
            delegate_witness(witness::owner_key(CAROL, EntryRole::Delegate, SIG_HASH_ALL)),
        ),
        (
            "K-39",
            74,
            3853,
            "key hash owner, one byte behind the signature",
            delegate(OWNER_P2PKH_SCHNORR),
            delegate_witness(one_byte_more(witness::owner_key_hash_schnorr(
                ALICE,
                EntryRole::Delegate,
                SIG_HASH_ALL,
            ))),
        ),
        (
            "K-40",
            78,
            3872,
            "key hash owner, key and signature of another key pair",
            delegate(OWNER_P2PKH_SCHNORR),
            delegate_witness(witness::owner_key_hash_schnorr(
                CAROL,
                EntryRole::Delegate,
                SIG_HASH_ALL,
            )),
        ),
        (
            "K-41",
            79,
            3878,
            "key hash owner, the owner's key with a signature of another key",
            delegate(OWNER_P2PKH_SCHNORR),
            delegate_witness(schnorr_of_another_key),
        ),
        (
            "K-42",
            81,
            3898,
            "ECDSA key hash owner, one byte behind the signature",
            delegate(OWNER_P2PKH_ECDSA),
            delegate_witness(one_byte_more(witness::owner_key_hash_ecdsa(
                ALICE,
                EntryRole::Delegate,
                SIG_HASH_ALL,
            ))),
        ),
        (
            "K-43",
            85,
            3917,
            "ECDSA key hash owner, key and signature of another key pair",
            delegate(OWNER_P2PKH_ECDSA),
            delegate_witness(witness::owner_key_hash_ecdsa(
                CAROL,
                EntryRole::Delegate,
                SIG_HASH_ALL,
            )),
        ),
        (
            "K-44",
            86,
            3923,
            "ECDSA key hash owner, the owner's key with a signature of another key",
            delegate(OWNER_P2PKH_ECDSA),
            delegate_witness(ecdsa_of_another_key),
        ),
        (
            "K-46",
            90,
            3973,
            "script hash owner, the witness names the leader",
            delegate(OWNER_P2SH),
            delegate_witness(LateBytes::fixed(vec![0])),
        ),
        (
            "K-48",
            96,
            3995,
            "covenant owner, no input of the owning covenant",
            delegate(OWNER_COVENANT_ID),
            Box::new(|scenario: &mut Scenario| scenario.ordinary_input_mut(2).covenant_id = None),
        ),
    ];

    for (rule, line, offset, what, honest, change) in rows {
        let twin = Case::new(format!("coverage/{rule} delegate, {what}")).twin_inputs(
            &honest,
            |scenario| change(scenario),
            &[
                (0, Expected::pass()),
                (1, Expected::rule(rule).at_line(line)),
            ],
        );
        stops_at(&twin.changed, 1, offset);

        let mut changed = honest.clone();
        change(&mut changed);
        Case::new(format!(
            "coverage/{rule} delegate, {what}, without the opcode at {offset}"
        ))
        .on(without(&[offset]))
        .expect_accept(&changed);
    }
}

// ---------------------------------------------------------------------------------------
// A spent coin whose own scheme byte is not assigned
// ---------------------------------------------------------------------------------------

#[test]
fn a_coin_with_an_unassigned_owner_scheme_cannot_be_spent_by_its_owner() {
    // Leader: the coin itself holds owner scheme 0x05. Its owner signs as for scheme 0x00.
    let honest = shapes::transfer(&script(), 1, 1);
    let twin = Case::new("coverage/K-49 leader coin with owner scheme 0x05").twin(
        &honest,
        |scenario| spent_state(scenario, 0).owner_scheme = OWNER_SCHEME_UNASSIGNED,
        0,
        Expected::rule("K-49").at_line(98),
    );
    stops_at(&twin.changed, 0, 2410);

    // Delegate: the copy inside `transfer_delegator`. The leader passes.
    let honest = shapes::transfer(&script(), 2, 1);
    let unassigned =
        |scenario: &mut Scenario| spent_state(scenario, 1).owner_scheme = OWNER_SCHEME_UNASSIGNED;
    let twin = Case::new("coverage/K-49 delegate coin with owner scheme 0x05").twin_inputs(
        &honest,
        unassigned,
        &[
            (0, Expected::pass()),
            (1, Expected::rule("K-49").at_line(98)),
        ],
    );
    stops_at(&twin.changed, 1, 3998);

    // The removal of the copy: without the opcode at 3998 the same transaction passes.
    let mut changed = honest.clone();
    unassigned(&mut changed);
    Case::new("coverage/K-49 delegate, the same without the opcode at 3998")
        .on(without(&[3998]))
        .expect_accept(&changed);
}

#[test]
fn a_coin_with_an_unassigned_borrow_scheme_cannot_be_borrowed() {
    // The coin itself holds borrow scheme 0x04 and is spent on the borrow path. The
    // declared successor keeps the assigned scheme 0x01, so the rule for declared states
    // has nothing to say.
    let honest = shapes::borrow(&script(), BorrowKind::Threshold);
    let twin = Case::new("coverage/K-56 leader coin with borrow scheme 0x04").twin(
        &honest,
        |scenario| spent_state(scenario, 0).borrow_scheme = BORROW_SCHEME_UNASSIGNED,
        0,
        Expected::rule("K-56").at_line(212),
    );
    stops_at(&twin.changed, 0, 2548);

    // The successor keeps the unassigned scheme: the rule for declared states answers
    // first, at the first declared state.
    let keeps_the_scheme = |scenario: &mut Scenario| {
        spent_state(scenario, 0).borrow_scheme = BORROW_SCHEME_UNASSIGNED;
        declare_and_lock(scenario, 0, |state| {
            state.borrow_scheme = BORROW_SCHEME_UNASSIGNED
        });
    };
    let mut changed = honest.clone();
    keeps_the_scheme(&mut changed);
    let outcome = Case::new("coverage/K-34 coin and successor with borrow scheme 0x04")
        .expect_refused(&changed, 0, Expected::rule("K-34").at_line(61));
    stops_at(&outcome, 0, 1920);

    // With that rule at the first declared state replaced by a drop the case stops at the
    // branch of the coin's own scheme.
    let twin = Case::new("coverage/K-56 coin and successor with borrow scheme 0x04 without K-34")
        .on(without(&[1920]))
        .twin(
            &honest,
            keeps_the_scheme,
            0,
            Expected::rule("K-56").at_line(212),
        );
    stops_at(&twin.changed, 0, 2548);
}

// ---------------------------------------------------------------------------------------
// The borrow path: the successor keeps the schemes of the coin
// ---------------------------------------------------------------------------------------

#[test]
fn the_successor_of_a_borrowed_coin_keeps_both_schemes() {
    let honest = shapes::borrow(&script(), BorrowKind::Threshold);

    // The same owner bytes under another assigned owner scheme.
    let twin = Case::new("coverage/K-58 the successor changes the owner scheme").twin(
        &honest,
        |scenario| {
            declare_and_lock(scenario, 0, |state| {
                state.owner_scheme = OWNER_P2PKH_SCHNORR
            })
        },
        0,
        Expected::rule("K-58").at_line(215),
    );
    stops_at(&twin.changed, 0, 2586);

    // The same guard with borrowing switched off.
    let twin = Case::new("coverage/K-59 the successor switches borrowing off").twin(
        &honest,
        |scenario| declare_and_lock(scenario, 0, |state| state.borrow_scheme = BORROW_DISABLED),
        0,
        Expected::rule("K-59").at_line(216),
    );
    stops_at(&twin.changed, 0, 2601);
}

// ---------------------------------------------------------------------------------------
// Cases that stop at one rule before they reach another
// ---------------------------------------------------------------------------------------

#[test]
fn four_token_inputs_stop_at_the_limit_and_then_at_the_bounds_of_two_loops() {
    // Three token inputs are the most; a fourth one is a third delegate.
    let three = shapes::transfer(&script(), 3, 1);
    let four = shapes::transfer(&script(), 4, 1);

    let outcome = Case::new("coverage/K-16 four token inputs, the contracts as they are")
        .expect_refused(&four, 0, Expected::rule("K-16").at_line(132));
    stops_at(&outcome, 0, K16_AT);

    // Without the rule of line 132: the bound of the loop that reads the delegates.
    let twin = Case::new("coverage/K-17 four token inputs without K-16")
        .on(without(&[K16_AT]))
        .twin(
            &three,
            |scenario| *scenario = four.clone(),
            0,
            Expected::rule("K-17").at_line(134),
        );
    stops_at(&twin.changed, 0, K17_AT);

    // Without that bound too: the bound of the loop that adds the delegates' amounts.
    let twin = Case::new("coverage/K-26 four token inputs without K-16 and K-17")
        .on(without(&[K16_AT, K17_AT]))
        .twin(
            &three,
            |scenario| *scenario = four.clone(),
            0,
            Expected::rule("K-26").at_line(163),
        );
    stops_at(&twin.changed, 0, K26_AT);
}

#[test]
fn four_declared_states_stop_at_a_count_rule_and_then_at_the_bound_of_their_loop() {
    let honest = shapes::transfer(&script(), 1, 3);

    // Four declared states for three bound outputs.
    let one_state_more = |scenario: &mut Scenario| push_declared_state(scenario, BOB + 3);
    let mut changed = honest.clone();
    one_state_more(&mut changed);
    let outcome = Case::new("coverage/K-24 four declared states for three outputs").expect_refused(
        &changed,
        0,
        Expected::rule("K-24").at_line(160),
    );
    stops_at(&outcome, 0, K24_AT);
    let twin = Case::new("coverage/K-31 four declared states for three outputs without K-24")
        .on(without(&[K24_AT]))
        .twin(
            &honest,
            one_state_more,
            0,
            Expected::rule("K-31").at_line(168),
        );
    stops_at(&twin.changed, 0, K31_AT);

    // Four declared states for four bound outputs.
    let one_of_each_more = |scenario: &mut Scenario| {
        push_declared_state(scenario, BOB + 3);
        push_bound_output(scenario, BOB + 3);
    };
    let mut changed = honest.clone();
    one_of_each_more(&mut changed);
    let outcome = Case::new("coverage/K-22 four declared states and four outputs").expect_refused(
        &changed,
        0,
        Expected::rule("K-22").at_line(156),
    );
    stops_at(&outcome, 0, K22_AT);
    let twin = Case::new("coverage/K-31 four declared states and four outputs without K-22")
        .on(without(&[K22_AT]))
        .twin(
            &honest,
            one_of_each_more,
            0,
            Expected::rule("K-31").at_line(168),
        );
    stops_at(&twin.changed, 0, K31_AT);
}

#[test]
fn one_output_less_stops_at_the_count_rule_and_then_at_the_generated_count_rule() {
    // Two declared states, 50 tokens each, and only the first output.
    let honest = shapes::transfer(&script(), 1, 2);
    let one_output_less = |scenario: &mut Scenario| {
        scenario.outputs.pop();
    };
    let mut changed = honest.clone();
    one_output_less(&mut changed);
    let outcome = Case::new("coverage/K-24 two declared states for one output").expect_refused(
        &changed,
        0,
        Expected::rule("K-24").at_line(160),
    );
    stops_at(&outcome, 0, K24_AT);

    let twin = Case::new("coverage/K-64 two declared states for one output without K-24")
        .on(without(&[K24_AT]))
        .twin(
            &honest,
            one_output_less,
            0,
            Expected::rule("K-64").at_line(224),
        );
    stops_at(&twin.changed, 0, K64_AT);
}

#[test]
fn one_bound_output_more_stops_at_four_rules_one_after_the_other() {
    // Three declared states and four bound outputs. The case stops at four rules, each
    // once the one in front is replaced: the limit of three outputs, the count rule of the
    // source, the count rule argentc generates in front of the become, and the bound of the
    // loop.
    let honest = shapes::transfer(&script(), 1, 3);
    let one_output_more = |scenario: &mut Scenario| push_bound_output(scenario, BOB + 3);
    let mut changed = honest.clone();
    one_output_more(&mut changed);

    let outcome = Case::new("coverage/K-22 three declared states for four outputs").expect_refused(
        &changed,
        0,
        Expected::rule("K-22").at_line(156),
    );
    stops_at(&outcome, 0, K22_AT);

    let outcome = Case::new("coverage/K-24 three declared states for four outputs without K-22")
        .on(without(&[K22_AT]))
        .expect_refused(&changed, 0, Expected::rule("K-24").at_line(160));
    stops_at(&outcome, 0, K24_AT);

    let outcome =
        Case::new("coverage/K-64 three declared states for four outputs without K-22 and K-24")
            .on(without(&[K22_AT, K24_AT]))
            .expect_refused(&changed, 0, Expected::rule("K-64").at_line(224));
    stops_at(&outcome, 0, K64_AT);

    let twin = Case::new(
        "coverage/K-65 three declared states for four outputs without K-22, K-24 and K-64",
    )
    .on(without(&[K22_AT, K24_AT, K64_AT]))
    .twin(
        &honest,
        one_output_more,
        0,
        Expected::rule("K-65").at_line(225),
    );
    stops_at(&twin.changed, 0, K65_AT);
}

#[test]
fn the_bound_of_the_loop_over_the_outputs_is_reached_with_four_states_too() {
    // Four declared states and four bound outputs: the counts agree, so neither count rule
    // has anything to say. Without the limit of three outputs the bound
    // of the loop over the declared states answers (shown above); without that bound as
    // well the loop reads three states, the sum holds, and the bound of the loop over the
    // outputs is reached.
    let honest = shapes::transfer(&script(), 1, 3);
    let twin = Case::new("coverage/K-65 four declared states and four outputs without K-22, K-31")
        .on(without(&[K22_AT, K31_AT]))
        .twin(
            &honest,
            |scenario| {
                push_declared_state(scenario, BOB + 3);
                push_bound_output(scenario, BOB + 3);
            },
            0,
            Expected::rule("K-65").at_line(225),
        );
    stops_at(&twin.changed, 0, K65_AT);
}
