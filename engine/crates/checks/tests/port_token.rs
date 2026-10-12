//! The earlier Python checks of the token contract, package `C_token`, on the real script
//! engine.
//!
//! This file repeats 19 checks of that package, checks of `KCC20.transfer` and
//! `KCC20.transfer_delegator`: the owner schemes 0x01 to 0x04 on a delegate, the bounds of
//! the two sums and of the output count, corners of the borrow path, a signature of another
//! key under each of the six signature hash types, and a minter or a seed as the third
//! input of a token transfer. The package ran one input per call on a debug engine that
//! names the source line of a refusal and never executed the bytes of a signature script.
//!
//! Here every transaction of those checks is assembled as a node would receive it and
//! every input is run. One case repeats one sub-case of an earlier check and carries its
//! id. A line that carries the id of an earlier check without being one of its sub-cases
//! says so at the start of its note: `ADDED HERE:` (the nine lines `mixed/leader,
//! <Contract>.<entry> behind`, where input 2 makes a real call instead of the bare push of
//! the earlier check; for `PublicMint.mint` and `TokenSeed.create` the leader's answer is of
//! another kind than the earlier one, rule K-18 instead of the engine error InvalidIndex).
//! An accept line made by `expect_accept` asserts the scripts only (the lines `.., as the
//! earlier shape` say that a node refuses that transaction for its amounts, and assert it);
//! `expect_consensus_accept` adds the consensus rules of a submission. The coins are the
//! 1000-sompi coins of the earlier checks: no line of this file asks a block or a mempool.
//! The sighash cases also assert the type byte of the stranger's signature. Where the
//! earlier check asserted a source line, the case is a twin: the honest
//! transaction of the earlier check passes, the change of the earlier check is made, and
//! the input the earlier check ran is refused at that line by the rule the inventory has
//! there. Signatures are made after the change.
//!
//! What differs from the earlier shapes, case by case in the notes:
//!
//! - The keys are the fixed keys of the family crate (Alice, Bob, Carol; Dave is the
//!   stranger).
//! - An input the earlier suite gave a bare redeem push carries its real call. The
//!   delegates and the authority coins of the earlier shapes, which that suite ran in a
//!   call of their own or not at all, are run here in the same transaction and must pass.
//! - A shape that pays out more sompi than it takes in is judged twice: as the earlier
//!   check built it, where only the scripts can be asked, and with an `OP_TRUE` funding
//!   coin behind its token coin, where a node gets to the scripts.
//! - A minter or a seed behind a leader and a delegate is given the bare redeem push of
//!   the earlier suite and, case by case, each of its real calls. The leader refuses in
//!   every one of them; the notes of those cases say how its answer differs from the
//!   earlier one.

use checks::{Case, Expected, Outcome, RunOutcome, Twin};
use kaspa_consensus_core::{
    Hash,
    hashing::sighash_type::{
        SIG_HASH_ALL, SIG_HASH_ANY_ONE_CAN_PAY, SIG_HASH_NONE, SIG_HASH_SINGLE, SigHashType,
    },
    tx::CovenantBinding,
};
use kaspa_txscript::pay_to_script_hash_script;
use kcc20_family::{
    Entry, EntryRole, Family, Scenario,
    keys::{self, ALICE, BOB, CAROL, DAVE, SigningContext},
    raw,
    scenario::{Arg, Call, ContractInput, ContractOutput, LateBytes, OrdinaryInput, PlainOutput},
    shapes::{self, BorrowKind, Profile},
    states::{
        BORROW_HASH_CHAIN, Kcc20State, OWNER_COVENANT_ID, OWNER_P2PKH_ECDSA, OWNER_P2PKH_SCHNORR,
        OWNER_P2SH, PATH_BORROW, PublicMintState, State, TokenSeedState,
    },
    witness,
};

/// The stranger of the earlier suite.
const MALLORY: u8 = DAVE;

/// Value of every coin and of every token output of the earlier suite, in sompi.
const COIN: u64 = shapes::SCRIPT_COIN_VALUE;

/// Another covenant: the owner of the covenant-id owner cases.
const OTHER_COVENANT: [u8; 32] = [0x33; 32];
/// A third covenant, which owns nothing.
const THIRD_COVENANT: [u8; 32] = [0x44; 32];
/// Another token family.
const OTHER_FAMILY: [u8; 32] = [0xee; 32];

const I64_MAX: i64 = i64::MAX;
const TWO_POW_61: i64 = 1 << 61;
const TWO_POW_62: i64 = 1 << 62;

/// The six signature hash types of the consensus rules, by the names of the earlier suite.
fn sighash_types() -> [(&'static str, SigHashType); 6] {
    [
        ("All", SIG_HASH_ALL),
        ("None", SIG_HASH_NONE),
        ("Single", SIG_HASH_SINGLE),
        ("AllAnyOneCanPay", SIG_HASH_ALL | SIG_HASH_ANY_ONE_CAN_PAY),
        ("NoneAnyOneCanPay", SIG_HASH_NONE | SIG_HASH_ANY_ONE_CAN_PAY),
        (
            "SingleAnyOneCanPay",
            SIG_HASH_SINGLE | SIG_HASH_ANY_ONE_CAN_PAY,
        ),
    ]
}

/// A case that repeats the earlier check `C_token.test_c_token.<method>`.
fn case(id: impl Into<String>, method: &str) -> Case {
    Case::new(id).py([format!("C_token.test_c_token.{method}")])
}

/// A plain token coin of the key with the given seed.
fn token(owner_seed: u8, amount: i64) -> Kcc20State {
    Kcc20State::new(keys::x_only(owner_seed), amount)
}

/// The owner signature of a leader on the normal path.
fn leader_signature(key_seed: u8) -> LateBytes {
    witness::owner_key(key_seed, EntryRole::Leader, SIG_HASH_ALL)
}

/// The owner signature of a delegate.
fn delegate_signature(key_seed: u8) -> LateBytes {
    witness::owner_key(key_seed, EntryRole::Delegate, SIG_HASH_ALL)
}

fn bound_to_leader() -> Option<CovenantBinding> {
    Some(CovenantBinding::new(0, shapes::covenant_id()))
}

/// A token transfer as the earlier suite builds it: the first coin leads with `transfer`
/// and declares `next_states`, every other coin joins with `transfer_delegator`; each coin
/// comes with its witness. Every coin and every output is worth 1000 sompi, every output
/// is bound to the leader.
fn token_transfer(
    name: &str,
    coins: Vec<(Kcc20State, LateBytes)>,
    next_states: Vec<Kcc20State>,
) -> Scenario {
    let mut scenario = Scenario::new(name);
    for (index, (state, witness)) in coins.into_iter().enumerate() {
        let call = if index == 0 {
            Call::typed(
                Entry::Transfer,
                vec![Arg::States(next_states.clone()), Arg::Bytes(witness)],
            )
        } else {
            Call::typed(Entry::TransferDelegator, vec![Arg::Bytes(witness)])
        };
        scenario.push_contract_input(ContractInput::new(
            state,
            COIN,
            Some(shapes::covenant_id()),
            shapes::outpoint(1, index as u32),
            call,
        ));
    }
    for state in next_states {
        scenario.push_contract_output(ContractOutput::new(state, COIN, bound_to_leader()));
    }
    scenario
}

/// Alice's plain coin of 100 leads, `delegate` joins with `delegate_witness`; one output
/// to Carol holds both amounts. In 2000 sompi, out 1000.
fn leader_and_delegate(delegate: Kcc20State, delegate_witness: LateBytes) -> Scenario {
    let total = 100 + delegate.amount;
    token_transfer(
        "leader and delegate",
        vec![
            (token(ALICE, 100), leader_signature(ALICE)),
            (delegate, delegate_witness),
        ],
        vec![token(CAROL, total)],
    )
}

/// Plain token coins of Alice (who leads), Bob and Carol into outputs of Carol; every
/// owner signs.
fn tokens_in_out(in_amounts: &[i64], out_amounts: &[i64]) -> Scenario {
    let owners = [ALICE, BOB, CAROL];
    let coins = in_amounts
        .iter()
        .zip(owners)
        .enumerate()
        .map(|(index, (amount, owner))| {
            let signature = if index == 0 {
                leader_signature(owner)
            } else {
                delegate_signature(owner)
            };
            (token(owner, *amount), signature)
        })
        .collect();
    token_transfer(
        "tokens in and out",
        coins,
        out_amounts
            .iter()
            .map(|amount| token(CAROL, *amount))
            .collect(),
    )
}

/// One token coin into `after`, with the given witness.
fn lone(before: Kcc20State, after: Vec<Kcc20State>, witness: LateBytes) -> Scenario {
    token_transfer("lone token coin", vec![(before, witness)], after)
}

/// The same transaction with an `OP_TRUE` funding coin of 4000 sompi behind its inputs.
/// The earlier suite had shapes that pay out up to 4000 sompi from one coin of 1000; a
/// node refuses those before it runs a script.
fn funded(mut scenario: Scenario) -> Scenario {
    let position = scenario.inputs.len() as u32;
    scenario.push_ordinary_input(
        OrdinaryInput::new(
            shapes::op_true_script(),
            4 * COIN,
            shapes::outpoint(3, position),
            LateBytes::empty(),
        )
        .labelled("funding (OP_TRUE)"),
    );
    scenario
}

/// Bob's coin leads on the borrow path with `leader_witness`, Alice's plain coin of
/// `alice_before` tokens pays the growth in and signs.
fn borrow_receive(
    bob_before: Kcc20State,
    bob_after: Kcc20State,
    leader_witness: LateBytes,
    alice_before: i64,
) -> Scenario {
    let growth = bob_after.amount - bob_before.amount;
    token_transfer(
        "borrowed receive",
        vec![
            (bob_before, leader_witness),
            (token(ALICE, alice_before), delegate_signature(ALICE)),
        ],
        vec![bob_after, token(ALICE, alice_before - growth)],
    )
}

/// An ordinary coin locked by a bare `OP_TRUE`, worth 1000 sompi, at input `position`.
fn op_true_coin(position: u32, covenant_id: Option<[u8; 32]>) -> OrdinaryInput {
    let mut coin = OrdinaryInput::new(
        shapes::op_true_script(),
        COIN,
        shapes::outpoint(2, position),
        LateBytes::empty(),
    )
    .labelled("ordinary coin (OP_TRUE)");
    coin.covenant_id = covenant_id.map(Hash::from_bytes);
    coin
}

/// The run of input `input` that the helpers judge.
fn run_of(outcome: &Outcome, input: usize) -> &RunOutcome {
    outcome.inputs[input]
        .alone
        .as_ref()
        .expect("the input was run")
}

/// The honest transaction passes; after `change`, input `input` is refused by `rule` at
/// `line` and the inputs in `passing` pass.
fn refused_twin(
    case: Case,
    honest: &Scenario,
    change: impl FnOnce(&mut Scenario),
    input: usize,
    rule: &str,
    line: u32,
    passing: &[usize],
) -> Twin {
    let mut expected = vec![(input, Expected::rule(rule).at_line(line))];
    expected.extend(passing.iter().map(|input| (*input, Expected::pass())));
    case.twin_inputs(honest, change, &expected)
}

/// The honest transaction passes; after `change`, the engine refuses the data of the
/// statement at `line` on input `input` with the error `variant`, and the inputs in
/// `passing` pass. `at_rule` is the rule whose opcode the engine stopped at, or empty when
/// it stopped at another opcode of the statement.
fn engine_error_twin(
    case: Case,
    honest: &Scenario,
    change: impl FnOnce(&mut Scenario),
    input: usize,
    (variant, at_rule): (&str, &str),
    line: u32,
    passing: &[usize],
) -> Twin {
    let mut refusal = Expected::engine(variant).at_line(line);
    if !at_rule.is_empty() {
        refusal = refusal.at_rule(at_rule);
    }
    let mut expected = vec![(input, refusal)];
    expected.extend(passing.iter().map(|input| (*input, Expected::pass())));
    case.twin_inputs(honest, change, &expected)
}

// ---------------------------------------------------------------------------------------
// Owner schemes 0x01 to 0x04 on a delegate
// ---------------------------------------------------------------------------------------

/// The witness of the Schnorr key-hash scheme on a delegate: the key of `public_key_of`
/// and a signature by `signer` for input `signed_input`, or for the input that carries the
/// witness when none is named.
fn key_hash_witness(public_key_of: u8, signer: u8, signed_input: Option<usize>) -> LateBytes {
    LateBytes::from_tx(move |ctx| {
        let ctx = SigningContext {
            tx: ctx.tx,
            input_index: signed_input.unwrap_or(ctx.input_index),
        };
        let mut witness = keys::x_only(public_key_of).to_vec();
        witness.extend(keys::schnorr_signature(
            &ctx,
            &keys::keypair(signer),
            SIG_HASH_ALL,
        ));
        witness
    })
}

/// A public key followed by 64 zero bytes and the type byte ALL.
fn key_and_placeholder_signature(public_key: &[u8]) -> LateBytes {
    let mut witness = public_key.to_vec();
    witness.extend([0u8; 64]);
    witness.push(SIG_HASH_ALL.to_u8());
    LateBytes::fixed(witness)
}

#[test]
fn delegate_owned_by_the_hash_of_a_schnorr_key() {
    const METHOD: &str = "DelegateOwnerSchemes.test_p2pkh_schnorr_delegate";
    let owner = witness::public_key_hash(&keys::x_only(BOB));
    let delegate = Kcc20State::new(owner, 50).with_owner(OWNER_P2PKH_SCHNORR, owner);
    let honest = leader_and_delegate(
        delegate,
        witness::owner_key_hash_schnorr(BOB, EntryRole::Delegate, SIG_HASH_ALL),
    );
    case("p2pkh-schnorr delegate/honest", METHOD).expect_consensus_accept(&honest);

    refused_twin(
        case(
            "p2pkh-schnorr delegate/a stranger's key and signature",
            METHOD,
        ),
        &honest,
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() =
                witness::owner_key_hash_schnorr(MALLORY, EntryRole::Delegate, SIG_HASH_ALL)
        },
        1,
        "K-40",
        78,
        &[0],
    );
    refused_twin(
        case(
            "p2pkh-schnorr delegate/the owner's key, a stranger's signature",
            METHOD,
        ),
        &honest,
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() = key_hash_witness(BOB, MALLORY, None)
        },
        1,
        "K-41",
        79,
        &[0],
    );
    refused_twin(
        case(
            "p2pkh-schnorr delegate/the owner's key, 64 zero bytes",
            METHOD,
        ),
        &honest,
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() =
                key_and_placeholder_signature(&keys::x_only(BOB))
        },
        1,
        "K-41",
        79,
        &[0],
    );
    refused_twin(
        case(
            "p2pkh-schnorr delegate/the owner's signature for the leader's input",
            METHOD,
        )
        .note("the signature is genuine and made for input 0 of the same transaction"),
        &honest,
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() = key_hash_witness(BOB, BOB, Some(0))
        },
        1,
        "K-41",
        79,
        &[0],
    );
}

/// The witness of the ECDSA key-hash scheme on a delegate: the compressed key of
/// `public_key_of` and a signature by `signer`.
fn ecdsa_key_hash_witness(public_key_of: u8, signer: u8) -> LateBytes {
    LateBytes::from_tx(move |ctx| {
        let mut witness = keys::compressed(public_key_of).to_vec();
        witness.extend(keys::ecdsa_signature(
            ctx,
            &keys::keypair(signer),
            SIG_HASH_ALL,
        ));
        witness
    })
}

#[test]
fn delegate_owned_by_the_hash_of_an_ecdsa_key() {
    const METHOD: &str = "DelegateOwnerSchemes.test_p2pkh_ecdsa_delegate";
    let owner = witness::public_key_hash(&keys::compressed(BOB));
    let delegate = Kcc20State::new(owner, 50).with_owner(OWNER_P2PKH_ECDSA, owner);
    let honest = leader_and_delegate(
        delegate,
        witness::owner_key_hash_ecdsa(BOB, EntryRole::Delegate, SIG_HASH_ALL),
    );
    case("p2pkh-ecdsa delegate/honest", METHOD).expect_consensus_accept(&honest);

    refused_twin(
        case("p2pkh-ecdsa delegate/another key pair", METHOD),
        &honest,
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() =
                witness::owner_key_hash_ecdsa(MALLORY, EntryRole::Delegate, SIG_HASH_ALL)
        },
        1,
        "K-43",
        85,
        &[0],
    );
    refused_twin(
        case(
            "p2pkh-ecdsa delegate/the owner's key, another key's signature",
            METHOD,
        ),
        &honest,
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() = ecdsa_key_hash_witness(BOB, MALLORY)
        },
        1,
        "K-44",
        86,
        &[0],
    );
    refused_twin(
        case(
            "p2pkh-ecdsa delegate/the owner's key, 64 zero bytes",
            METHOD,
        ),
        &honest,
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() =
                key_and_placeholder_signature(&keys::compressed(BOB))
        },
        1,
        "K-44",
        86,
        &[0],
    );
}

/// The script-hash shape of the earlier suite: input 0 leads, input 1 is a delegate owned
/// by the hash of `OP_TRUE` whose witness names input `named_input`, input 2 is the
/// authority (pay to script hash of `OP_TRUE`), input 3 an `OP_TRUE` funding coin.
fn script_hash_delegate(named_input: u8) -> Scenario {
    let authority_lock = pay_to_script_hash_script(&shapes::AUTHORITY_REDEEM_SCRIPT);
    let owner: [u8; 32] = authority_lock.script()[2..34]
        .try_into()
        .expect("a pay-to-script-hash script holds a 32-byte hash");
    let delegate = Kcc20State::new(owner, 50).with_owner(OWNER_P2SH, owner);
    let mut scenario = leader_and_delegate(
        delegate,
        witness::owner_script_hash(named_input, EntryRole::Delegate),
    );
    scenario.push_ordinary_input(
        OrdinaryInput::new(
            authority_lock,
            COIN,
            shapes::outpoint(2, 2),
            LateBytes::fixed(
                raw::push(&shapes::AUTHORITY_REDEEM_SCRIPT).expect("a one-byte push fits"),
            ),
        )
        .labelled("authority (pay to script hash of OP_TRUE)"),
    );
    scenario.push_ordinary_input(op_true_coin(3, None));
    scenario
}

#[test]
fn delegate_owned_by_a_script_hash_names_its_authority() {
    case(
        "p2sh delegate/the witness names the authority",
        "DelegateOwnerSchemes.test_p2sh_delegate_points_at_its_authority",
    )
    .note(
        "all four inputs run: the authority spends its OP_TRUE redeem script and the \
         funding coin its bare OP_TRUE, which the earlier suite never executed",
    )
    .expect_consensus_accept(&script_hash_delegate(2));
}

#[test]
fn delegate_owned_by_a_script_hash_cannot_name_another_coin() {
    const METHOD: &str = "DelegateOwnerSchemes.\
        test_p2sh_delegate_pointing_at_the_leader_itself_or_an_ordinary_coin_is_refused";
    let honest = script_hash_delegate(2);
    for (index, label) in [
        (0u8, "the leader"),
        (1, "the delegate itself"),
        (3, "the OP_TRUE funding coin"),
    ] {
        refused_twin(
            case(format!("p2sh delegate/the witness names {label}"), METHOD),
            &honest,
            |scenario| {
                *scenario.contract_input_mut(1).witness_mut() =
                    witness::owner_script_hash(index, EntryRole::Delegate)
            },
            1,
            "K-46",
            90,
            &[0, 2, 3],
        );
    }
}

#[test]
fn delegate_owned_by_a_script_hash_cannot_name_an_input_that_is_not_there() {
    const METHOD: &str = "DelegateOwnerSchemes.\
        test_p2sh_delegate_index_out_of_range_is_an_engine_error_at_the_rule";
    let honest = script_hash_delegate(2);
    for index in [4u8, 0x7f, 0xff] {
        let twin = engine_error_twin(
            case(
                format!("p2sh delegate/the witness names input {index}"),
                METHOD,
            ),
            &honest,
            |scenario| {
                *scenario.contract_input_mut(1).witness_mut() =
                    witness::owner_script_hash(index, EntryRole::Delegate)
            },
            1,
            ("InvalidInputIndex", ""),
            90,
            &[0, 2, 3],
        );
        // The byte is read as an unsigned number: 0xff names input 255, not input -1.
        let error = run_of(&twin.changed, 1)
            .error
            .as_ref()
            .expect("an engine error");
        assert_eq!(error.debug, format!("InvalidInputIndex({index}, 4)"));
    }
}

/// The covenant-id shape of the earlier suite: the delegate is owned by another covenant,
/// and input 2 is an ordinary `OP_TRUE` coin with the covenant id `carried`.
fn covenant_owned_delegate(carried: Option<[u8; 32]>) -> Scenario {
    let delegate =
        Kcc20State::new(OTHER_COVENANT, 50).with_owner(OWNER_COVENANT_ID, OTHER_COVENANT);
    let mut scenario =
        leader_and_delegate(delegate, witness::owner_covenant_id(EntryRole::Delegate));
    scenario.push_ordinary_input(op_true_coin(2, carried));
    scenario
}

#[test]
fn delegate_owned_by_a_covenant_needs_an_input_of_that_covenant() {
    const METHOD: &str = "DelegateOwnerSchemes.test_covenant_id_delegate";
    let honest = covenant_owned_delegate(Some(OTHER_COVENANT));
    case("covenant-id delegate/honest", METHOD)
        .note(
            "the witness of the delegate is an empty byte string, pushed as OP_0. Input 2 \
             is a bare OP_TRUE coin that carries the id of the owning covenant while no \
             output continues that covenant; the consensus rules of a node accept this",
        )
        .expect_consensus_accept(&honest);

    refused_twin(
        case(
            "covenant-id delegate/input 2 carries no covenant id",
            METHOD,
        ),
        &honest,
        |scenario| scenario.ordinary_input_mut(2).covenant_id = None,
        1,
        "K-48",
        96,
        &[0, 2],
    );
    refused_twin(
        case(
            "covenant-id delegate/input 2 carries a third covenant id",
            METHOD,
        ),
        &honest,
        |scenario| {
            scenario.ordinary_input_mut(2).covenant_id = Some(Hash::from_bytes(THIRD_COVENANT))
        },
        1,
        "K-48",
        96,
        &[0, 2],
    );
}

// ---------------------------------------------------------------------------------------
// Bounds of the sums and of the output count
// ---------------------------------------------------------------------------------------

#[test]
fn three_token_inputs_stay_inside_64_bits() {
    const METHOD: &str = "Bounds.\
        test_three_inputs_summing_past_i64_are_refused_by_the_engine_s_overflow_check";
    let honest = tokens_in_out(&[TWO_POW_61; 3], &[TWO_POW_61; 3]);
    case("input sum/three coins of 2^61 into three", METHOD).expect_consensus_accept(&honest);

    for (label, amounts) in [
        ("2^62 three times", [TWO_POW_62; 3]),
        ("the largest number, 1 and 0", [I64_MAX, 1, 0]),
        ("the largest number less one, 1 and 1", [I64_MAX - 1, 1, 1]),
    ] {
        engine_error_twin(
            case(format!("input sum/{label}"), METHOD).note(
                "the changed side is that of the earlier check: other amounts and one output \
                 of 2^62; the delegates pass",
            ),
            &honest,
            |scenario| *scenario = tokens_in_out(&amounts, &[TWO_POW_62]),
            0,
            ("NumberTooBig", "K-30"),
            165,
            &[1, 2],
        );
    }
}

#[test]
fn two_token_inputs_stay_inside_64_bits() {
    const METHOD: &str = "Bounds.test_two_inputs_summing_past_i64_too";
    let honest = tokens_in_out(&[I64_MAX - 1, 1], &[I64_MAX]);
    case(
        "input sum/the largest number moves through a transfer",
        METHOD,
    )
    .expect_consensus_accept(&honest);
    engine_error_twin(
        case("input sum/the largest number and 1", METHOD)
            .note("input 1 passes; the earlier check did not assert it"),
        &honest,
        |scenario| *scenario = tokens_in_out(&[I64_MAX, 1], &[I64_MAX]),
        0,
        ("NumberTooBig", "K-30"),
        165,
        &[1],
    );
}

/// The note of a case that keeps a shape of the earlier suite which pays out more sompi
/// than it takes in.
const AS_BUILT: &str = "scripts only: the shape of the earlier check, which pays out more \
    sompi than its one coin holds. DIFFERS FROM PYTHON: for the whole transaction only. \
    Python judged the script of input 0, and the real engine gives the same answer; a node \
    refuses this transaction before it runs a script, for outputs worth more than its \
    inputs (check_transaction_output_values)";

/// The note of the same case with a funding coin.
const FUNDED: &str = "the shape of the earlier check with an OP_TRUE funding coin behind the \
    token coin, so that a node gets to the scripts";

/// An accepted shape of the earlier suite that pays out more sompi than it takes in,
/// judged twice: as it was built, where the scripts accept it and a node refuses it for
/// its amounts, and with a funding coin, where the consensus rules of a node accept it.
fn overspending_accept(id: &str, method: &str, scenario: &Scenario) {
    let outcome = case(format!("{id}, as the earlier shape"), method)
        .note(AS_BUILT)
        .expect_accept(scenario);
    assert_eq!(
        outcome
            .consensus
            .context_refusal
            .as_ref()
            .map(|refusal| refusal.rule.as_str()),
        Some("check_transaction_output_values"),
        "case `{id}`: the earlier shape spends more than it has"
    );
    case(format!("{id}, funded"), method)
        .note(FUNDED)
        .expect_consensus_accept(&funded(scenario.clone()));
}

/// A refusal of the earlier suite on such a shape, judged twice: `honest` passes and
/// `changed` is refused at input 0 as `expected` says, as the two were built (scripts
/// only) and with a funding coin behind each (a node gets to the scripts of both).
fn overspending_twin(
    id: &str,
    method: &str,
    honest: &Scenario,
    changed: &Scenario,
    expected: Expected,
) {
    case(format!("{id}, as the earlier shape"), method)
        .scripts_only()
        .note(AS_BUILT)
        .twin(
            honest,
            |scenario| *scenario = changed.clone(),
            0,
            expected.clone(),
        );
    case(format!("{id}, funded"), method)
        .note(FUNDED)
        .twin_inputs(
            &funded(honest.clone()),
            |scenario| *scenario = funded(changed.clone()),
            &[(0, expected), (1, Expected::pass())],
        );
}

/// Alice's coin of `amount` tokens into outputs of Bob.
fn alice_pays_bob(amount: i64, outputs: &[i64]) -> Scenario {
    lone(
        token(ALICE, amount),
        outputs.iter().map(|amount| token(BOB, *amount)).collect(),
        leader_signature(ALICE),
    )
}

#[test]
fn the_token_outputs_stay_inside_64_bits() {
    const METHOD: &str = "Bounds.\
        test_outputs_summing_past_i64_are_refused_by_the_engine_s_overflow_check";
    let overflow = || {
        Expected::engine("NumberTooBig")
            .at_rule("K-36")
            .at_line(173)
    };

    let honest = alice_pays_bob(I64_MAX, &[I64_MAX - 1, 1]);
    overspending_accept(
        "output sum/the largest number as its two parts",
        METHOD,
        &honest,
    );
    overspending_twin(
        "output sum/the largest number and 1",
        METHOD,
        &honest,
        &alice_pays_bob(I64_MAX, &[I64_MAX, 1]),
        overflow(),
    );

    // Outputs whose sum would wrap around to exactly the input, from a coin of nothing.
    let honest = alice_pays_bob(0, &[0, 0, 0]);
    overspending_accept(
        "output sum/nothing into three times nothing",
        METHOD,
        &honest,
    );
    overspending_twin(
        "output sum/a sum that would wrap around to nothing",
        METHOD,
        &honest,
        &alice_pays_bob(0, &[I64_MAX, I64_MAX, 2]),
        overflow(),
    );
}

#[test]
fn a_transfer_has_at_most_three_token_outputs() {
    const METHOD: &str = "Bounds.test_four_token_outputs_are_refused";
    let honest = alice_pays_bob(100, &[25, 25, 50]);
    overspending_accept("output count/three outputs", METHOD, &honest);
    overspending_twin(
        "output count/four outputs",
        METHOD,
        &honest,
        &alice_pays_bob(100, &[25; 4]),
        Expected::rule("K-22").at_line(156),
    );
}

#[test]
fn a_transfer_has_at_least_one_token_output() {
    const METHOD: &str = "Bounds.test_zero_token_outputs_are_refused";
    // 0: an empty coin, where the sum rule alone would not object.
    for amount in [100, 0] {
        let before = token(ALICE, amount);
        let honest = lone(
            before.clone(),
            vec![token(BOB, amount)],
            leader_signature(ALICE),
        );
        case(
            format!("output count/a coin of {amount} into one output"),
            METHOD,
        )
        .expect_consensus_accept(&honest);

        let no_token_output = || lone(before.clone(), Vec::new(), leader_signature(ALICE));
        refused_twin(
            case(
                format!("output count/a coin of {amount}, one ordinary output takes the sompi"),
                METHOD,
            ),
            &honest,
            |scenario| {
                *scenario = no_token_output();
                scenario.push_plain_output(PlainOutput::new(shapes::op_true_script(), COIN));
            },
            0,
            "K-21",
            155,
            &[],
        );
        refused_twin(
            case(
                format!("output count/a coin of {amount}, no output at all"),
                METHOD,
            )
            .note(
                "a transaction without any output: no consensus rule in front of the \
                 scripts refuses it, the rule of the contract does",
            ),
            &honest,
            |scenario| *scenario = no_token_output(),
            0,
            "K-21",
            155,
            &[],
        );
    }
}

// ---------------------------------------------------------------------------------------
// Corners of the borrow path
// ---------------------------------------------------------------------------------------

/// Bob's coin with the amount-threshold borrow policy.
fn threshold_coin(amount: i64, threshold: i64) -> Kcc20State {
    token(BOB, amount).with_threshold(threshold)
}

/// Bob's coin of 200 with the given threshold receives `growth` tokens from Alice's coin
/// of 100.
fn threshold_receive(threshold: i64, growth: i64) -> Scenario {
    borrow_receive(
        threshold_coin(200, threshold),
        threshold_coin(200 + growth, threshold),
        witness::borrow_threshold(),
        100,
    )
}

/// A coin alone on the borrow path: no payer, one output.
fn lone_borrower(before: Kcc20State, after: Kcc20State) -> Scenario {
    lone(before, vec![after], witness::borrow_threshold())
}

#[test]
fn a_lone_borrowing_leader_cannot_grow_and_cannot_stand_still() {
    const METHOD: &str = "BorrowCorners.test_a_lone_borrowing_leader_cannot_grow_without_a_payer";
    let honest = threshold_receive(10, 11);
    let family = Family::pinned();
    assert_eq!(
        honest.assemble(family).unwrap().tx,
        shapes::borrow(&Profile::Script, BorrowKind::Threshold)
            .assemble(family)
            .unwrap()
            .tx,
        "the twin of the earlier check is the threshold borrow of the family crate"
    );
    case("lone borrower/twin: Alice pays 11 in", METHOD).expect_consensus_accept(&honest);

    for grown in [211, 201, I64_MAX] {
        refused_twin(
            case(
                format!("lone borrower/200 into {grown} without a payer"),
                METHOD,
            ),
            &honest,
            |scenario| {
                *scenario = lone_borrower(threshold_coin(200, 10), threshold_coin(grown, 10))
            },
            0,
            "K-37",
            175,
            &[],
        );
    }

    // Alone and unchanged the sum holds and the growth rule refuses.
    refused_twin(
        case("lone borrower/unchanged, threshold 10", METHOD),
        &honest,
        |scenario| *scenario = lone_borrower(threshold_coin(200, 10), threshold_coin(200, 10)),
        0,
        "K-61",
        219,
        &[],
    );
    // With threshold 0, growth 0 is refused by the growth rule alone.
    let honest = threshold_receive(0, 1);
    case("lone borrower/twin: threshold 0, Alice pays 1 in", METHOD)
        .expect_consensus_accept(&honest);
    refused_twin(
        case("lone borrower/unchanged, threshold 0", METHOD).note(
            "no signature anywhere in this transaction: growth 0 against threshold 0 is the \
             one rule that refuses it",
        ),
        &honest,
        |scenario| *scenario = lone_borrower(threshold_coin(200, 0), threshold_coin(200, 0)),
        0,
        "K-61",
        219,
        &[],
    );
}

#[test]
fn a_borrowed_receive_keeps_the_family_of_the_coin() {
    const METHOD: &str = "BorrowCorners.\
        test_a_borrowed_receive_cannot_change_only_the_successor_s_extension_commitment";
    let honest = threshold_receive(10, 11);
    case("borrow family/twin: honest receive of 11", METHOD).expect_consensus_accept(&honest);
    refused_twin(
        case("borrow family/the successor is of another family", METHOD)
            .note("declared and locked alike"),
        &honest,
        |scenario| {
            scenario.contract_input_mut(0).declared_states_mut()[0].extension_commitment =
                OTHER_FAMILY;
            scenario
                .contract_output_mut(0)
                .state
                .as_kcc20_mut()
                .expect("the successor of the leading coin")
                .extension_commitment = OTHER_FAMILY;
        },
        0,
        "K-35",
        172,
        &[1],
    );
}

/// The one-time keys of the two links of the hash chain.
const CHAIN_KEY_1: u8 = CAROL;
const CHAIN_KEY_2: u8 = DAVE;

/// A two-link hash chain as the earlier suite builds it: `guard0 = H(link1, key 1)` and
/// `link1 = H(link2, key 2)`. Returns `(guard0, link1, link2)`.
fn chain() -> ([u8; 32], [u8; 32], [u8; 32]) {
    let link2 = [0x55; 32];
    let link1 = witness::chain_guard(&link2, CHAIN_KEY_2);
    let guard0 = witness::chain_guard(&link1, CHAIN_KEY_1);
    (guard0, link1, link2)
}

/// Bob's coin with the hash-chain borrow policy.
fn chain_coin(amount: i64, guard: [u8; 32]) -> Kcc20State {
    token(BOB, amount).with_borrow(BORROW_HASH_CHAIN, guard)
}

#[test]
fn the_hash_chain_witness_has_exactly_129_bytes() {
    const METHOD: &str = "BorrowCorners.test_hash_chain_witness_one_byte_short_or_long_is_refused";
    let (guard0, link1, _) = chain();
    let honest_witness = || witness::borrow_hash_chain(link1, CHAIN_KEY_1, SIG_HASH_ALL);
    let honest = borrow_receive(
        chain_coin(200, guard0),
        chain_coin(201, link1),
        honest_witness(),
        100,
    );
    case("chain witness/twin: 129 bytes", METHOD).expect_consensus_accept(&honest);

    type Damage = fn(Vec<u8>) -> Vec<u8>;
    let damages: [(&str, Damage); 3] = [
        (
            "128 bytes, the signature without its type byte",
            |mut witness| {
                witness.pop();
                witness
            },
        ),
        ("130 bytes, one byte appended", |mut witness| {
            witness.push(0x00);
            witness
        }),
        ("130 bytes, one byte in front", |mut witness| {
            assert_eq!(witness[0], PATH_BORROW);
            witness.insert(1, 0x00);
            witness
        }),
    ];
    for (label, damage) in damages {
        refused_twin(
            case(format!("chain witness/{label}"), METHOD),
            &honest,
            |scenario| *scenario.contract_input_mut(0).witness_mut() = honest_witness().map(damage),
            0,
            "K-53",
            197,
            &[1],
        );
    }
}

#[test]
fn a_hash_chain_link_is_good_for_one_receive() {
    const METHOD: &str =
        "BorrowCorners.test_the_same_hash_chain_link_cannot_be_used_twice_in_a_row";
    let (guard0, link1, link2) = chain();
    let first = borrow_receive(
        chain_coin(200, guard0),
        chain_coin(201, link1),
        witness::borrow_hash_chain(link1, CHAIN_KEY_1, SIG_HASH_ALL),
        100,
    );
    case("chain link/first receive with link 1", METHOD).expect_consensus_accept(&first);

    // The second receive goes into the coin the first one made; Alice's change of 99 pays.
    let second = borrow_receive(
        chain_coin(201, link1),
        chain_coin(202, link2),
        witness::borrow_hash_chain(link2, CHAIN_KEY_2, SIG_HASH_ALL),
        99,
    );
    case("chain link/twin: second receive with link 2", METHOD).expect_consensus_accept(&second);

    for (label, successor_guard) in [("link 1", link1), ("link 2", link2)] {
        refused_twin(
            case(
                format!("chain link/link 1 again, the successor guarded by {label}"),
                METHOD,
            )
            .note("the signature of the one-time key is genuine and made for this transaction"),
            &second,
            |scenario| {
                *scenario = borrow_receive(
                    chain_coin(201, link1),
                    chain_coin(202, successor_guard),
                    witness::borrow_hash_chain(link1, CHAIN_KEY_1, SIG_HASH_ALL),
                    99,
                )
            },
            0,
            "K-54",
            205,
            &[1],
        );
    }
}

// ---------------------------------------------------------------------------------------
// Signature hash types
// ---------------------------------------------------------------------------------------

/// The dispatch tag of `transfer` in a signature script.
const TRANSFER_TAG: [u8; 4] = [0x79, 0xc7, 0x1c, 0x23];

/// The type bytes the earlier suite stated for the six signature hash types, written out.
fn stated_type_byte(name: &str) -> u8 {
    match name {
        "All" => 0x01,
        "None" => 0x02,
        "Single" => 0x04,
        "AllAnyOneCanPay" => 0x81,
        "NoneAnyOneCanPay" => 0x82,
        "SingleAnyOneCanPay" => 0x84,
        other => panic!("the earlier suite states no type byte for `{other}`"),
    }
}

/// The type byte of the signature that token input `input` of the assembled transaction
/// carries: the last byte of its witness, which is the last of the 65 bytes of the
/// signature. The witness stands in front of the push of the dispatch tag `tag`, which
/// stands in front of the push of the redeem script of `state`; `witness_len` is the length
/// of the witness, whose push opcode must be where that length puts it.
fn signature_type_byte(
    scenario: &Scenario,
    input: usize,
    state: &Kcc20State,
    tag: [u8; 4],
    witness_len: usize,
) -> u8 {
    let assembled = scenario
        .assemble(Family::pinned())
        .expect("the scenario assembles");
    let script = &assembled.tx.inputs[input].signature_script;
    let redeem = Family::pinned()
        .redeem_script(&State::from(state.clone()))
        .expect("a token state has a redeem script");
    let tail = raw::push_redeem(&redeem).expect("a redeem script fits a push");
    assert!(
        script.ends_with(&tail),
        "the signature script ends with the push of the redeem script"
    );
    let head = &script[..script.len() - tail.len()];
    let mut tag_push = vec![0x04];
    tag_push.extend(tag);
    assert!(
        head.ends_with(&tag_push),
        "the dispatch tag is pushed in front of the redeem script"
    );
    let witness_end = head.len() - tag_push.len();
    assert_eq!(
        head[witness_end - witness_len - 1] as usize,
        witness_len,
        "the push of the witness is where its length puts it"
    );
    head[witness_end - 1]
}

/// Said in the note of a sighash case: what is asserted of the signature itself.
const TYPE_BYTE_ASSERTED: &str = "the type byte of the stranger's signature in the assembled \
    transaction (the last byte of the 65) is asserted to be the byte the earlier suite \
    states for this type";

#[test]
fn the_signature_of_a_stranger_is_refused_with_each_signature_hash_type() {
    const METHOD: &str =
        "SignatureTypes.test_a_signature_of_another_key_stays_refused_with_each_type";
    for (name, hash_type) in sighash_types() {
        // The twin is the same transfer signed by the owner, with type All.
        let honest = lone(
            token(ALICE, 100),
            vec![token(BOB, 100)],
            leader_signature(ALICE),
        );
        // The type byte of the stranger's signature is the one of the case.
        let mut by_the_stranger = honest.clone();
        *by_the_stranger.contract_input_mut(0).witness_mut() =
            witness::owner_key(MALLORY, EntryRole::Leader, hash_type);
        assert_eq!(
            signature_type_byte(&by_the_stranger, 0, &token(ALICE, 100), TRANSFER_TAG, 66),
            stated_type_byte(name),
            "sighash stranger/{name}: the type byte of the stranger's signature"
        );
        refused_twin(
            case(format!("sighash stranger/{name}"), METHOD).note(format!(
                "the twin is the same transfer signed by the owner with type All; \
                 {TYPE_BYTE_ASSERTED}"
            )),
            &honest,
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() =
                    witness::owner_key(MALLORY, EntryRole::Leader, hash_type)
            },
            0,
            "K-38",
            69,
            &[],
        );
    }
}

// ---------------------------------------------------------------------------------------
// A minter or a seed as the third input of a token transfer
// ---------------------------------------------------------------------------------------

/// A coin of the covenant of the token that is locked to another contract of the family,
/// as input 2.
fn foreign_coin(state: impl Into<State>, call: Call) -> ContractInput {
    ContractInput::new(
        state,
        COIN,
        Some(shapes::covenant_id()),
        shapes::outpoint(1, 2),
        call,
    )
    .labelled("a coin of another contract of the family")
}

/// Alice's coin of 100 leads, Bob's coin of 50 joins, `foreign` is input 2; one output of
/// `out_amount` tokens to Carol.
fn three_with_foreign(foreign: ContractInput, out_amount: i64) -> Scenario {
    let mut scenario = tokens_in_out(&[100, 50], &[out_amount]);
    scenario.push_contract_input(foreign);
    scenario
}

fn foreign_minter() -> PublicMintState {
    PublicMintState::new(keys::x_only(CAROL), 1_000, 10)
}

fn foreign_seed() -> TokenSeedState {
    TokenSeedState::new(keys::x_only(CAROL))
}

/// One entry of the two other contracts, called on input 2 with the arguments the earlier
/// suite gave it.
struct ForeignCall {
    contract: &'static str,
    entry: &'static str,
    coin: ContractInput,
    /// The rule of its own contract at which the foreign coin is refused, and its line in
    /// the source of that contract. The earlier suite printed these lines and asserted
    /// only that the call is refused.
    rule: &'static str,
    line: u32,
}

fn foreign_calls() -> Vec<ForeignCall> {
    let carol_signs = || Arg::Bytes(witness::signature(CAROL, SIG_HASH_ALL));
    let carol = || Arg::bytes(keys::x_only(CAROL));
    let minter = |entry, args, rule, line| ForeignCall {
        contract: "PublicMint",
        entry: Entry::name(entry),
        coin: foreign_coin(foreign_minter(), Call::typed(entry, args)),
        rule,
        line,
    };
    let seed = |entry, args, rule, line| ForeignCall {
        contract: "TokenSeed",
        entry: Entry::name(entry),
        coin: foreign_coin(foreign_seed(), Call::typed(entry, args)),
        rule,
        line,
    };
    vec![
        minter(Entry::Mint, vec![Arg::State(token(CAROL, 10))], "M-10", 127),
        minter(Entry::MintSplit, vec![Arg::int(1), carol()], "M-24", 187),
        minter(Entry::MintReclaim, vec![carol_signs()], "M-32", 243),
        minter(Entry::MintReclaimInto, Vec::new(), "M-36", 260),
        minter(
            Entry::MintReclaimDelegator,
            vec![carol_signs()],
            "M-53",
            314,
        ),
        seed(
            Entry::SeedCreate,
            vec![Arg::State(token(CAROL, 0))],
            "S-10",
            123,
        ),
        seed(Entry::SeedSplit, vec![carol()], "S-21", 167),
        seed(Entry::SeedReclaim, Vec::new(), "S-26", 207),
        seed(
            Entry::SeedReclaimDelegator,
            vec![carol_signs()],
            "S-39",
            244,
        ),
    ]
}

/// The honest twin of the mixed cases: three token coins into one.
fn three_token_coins() -> Scenario {
    tokens_in_out(&[100, 50, 25], &[175])
}

/// Length of the signature script of input `input` of the assembled scenario.
fn signature_script_len(scenario: &Scenario, input: usize) -> i64 {
    scenario
        .assemble(Family::pinned())
        .expect("the scenario assembles")
        .tx
        .inputs[input]
        .signature_script
        .len() as i64
}

#[test]
fn three_token_inputs_pass() {
    case(
        "mixed/twin: three token coins into one",
        "MixedActorsThirdInput.test_twin_three_token_inputs_pass",
    )
    .expect_consensus_accept(&three_token_coins());
}

#[test]
fn a_leader_refuses_a_minter_or_a_seed_given_as_the_earlier_suite_gave_it() {
    const METHOD: &str = "MixedActorsThirdInput.\
        test_a_minter_or_seed_behind_a_leader_and_a_delegator_is_refused_by_the_leader";
    // The earlier suite gave the coin of the other contract a signature script that is the
    // push of its redeem script and nothing else.
    for (contract, state) in [
        ("PublicMint", State::from(foreign_minter())),
        ("TokenSeed", State::from(foreign_seed())),
    ] {
        // One output: the 150 tokens of the two token coins.
        {
            let out_amount = 150;
            let changed = three_with_foreign(
                foreign_coin(state.clone(), Call::Raw(LateBytes::empty())),
                out_amount,
            );
            let twin = case(
                format!("mixed/leader, bare {contract} script behind, {out_amount} tokens out"),
                METHOD,
            )
            .note(
                "input 2 carries the bare redeem push of the earlier shape. Input 0 answers \
                 as in Python, with the same engine error at the same line. DIFFERS FROM \
                 PYTHON: for input 2 only. Python did not run input 2 in this check; the real \
                 engine runs it and refuses it with InvalidStackOperation at the first opcode \
                 of its script, which finds no arguments",
            )
            .twin_inputs(
                &three_token_coins(),
                |scenario| *scenario = changed.clone(),
                &[
                    (0, Expected::engine("InvalidIndex").at_line(136)),
                    (1, Expected::pass()),
                    (2, Expected::engine("InvalidStackOperation")),
                ],
            );
            let error = run_of(&twin.changed, 0).error.as_ref().expect("an error");
            assert!(error.debug.starts_with("InvalidIndex("), "{}", error.debug);
        }
    }
}

#[test]
fn a_leader_refuses_a_minter_or_a_seed_that_makes_its_real_call() {
    const METHOD: &str = "MixedActorsThirdInput.\
        test_a_minter_or_seed_behind_a_leader_and_a_delegator_is_refused_by_the_leader";
    for foreign in foreign_calls() {
        let ForeignCall {
            contract, entry, ..
        } = foreign;
        let changed = three_with_foreign(foreign.coin, 150);
        let call_len = signature_script_len(&changed, 2);
        // With the calls of `mint` and `create` the leader stops at rule K-18; with the
        // calls of the other entries it stops with the engine error of the earlier check.
        let by_rule = matches!(entry, "mint" | "create");
        let (leader, differs) = if by_rule {
            (
                Expected::rule("K-18").at_line(136),
                "Python, with a bare redeem push on input 2, said the engine error \
                 InvalidIndex at KCC20.sil:136; the real engine refuses at the same line by \
                 rule K-18 (VerifyError)",
            )
        } else {
            (
                Expected::engine("InvalidIndex").at_line(136),
                "in the number the error carries only. Python, with a bare redeem push on \
                 input 2, and the real engine, with the real call, both say InvalidIndex at \
                 KCC20.sil:136",
            )
        };
        let twin = case(format!("mixed/leader, {contract}.{entry} behind"), METHOD)
            .note(format!(
                "ADDED HERE: not a sub-case of the earlier check, which gave input 2 the bare \
                 push of its redeem script (the lines 'mixed/leader, bare .. script behind' \
                 are its sub-cases). Input 2 makes its real call, a signature script of \
                 {call_len} bytes. DIFFERS FROM PYTHON: {differs}"
            ))
            .twin_inputs(
                &three_token_coins(),
                |scenario| *scenario = changed.clone(),
                &[(0, leader), (1, Expected::pass())],
            );
        if !by_rule {
            let error = run_of(&twin.changed, 0).error.as_ref().expect("an error");
            assert!(error.debug.starts_with("InvalidIndex("), "{}", error.debug);
        }
    }
}

#[test]
fn no_entry_of_a_minter_or_a_seed_passes_as_the_third_input() {
    const METHOD: &str =
        "MixedActorsThirdInput.test_no_entry_of_the_foreign_coin_passes_as_the_third_input";
    for foreign in foreign_calls() {
        let ForeignCall {
            contract,
            entry,
            rule,
            line,
            ..
        } = foreign;
        case(
            format!("mixed/{contract}.{entry} as the third input"),
            METHOD,
        )
        .note(
            "the earlier check asserted a refusal by some line of the contract; the rule \
             and the line are those the real engine stops at, and the line is the one the \
             earlier suite printed for this entry. Inputs 0 and 1 make their real calls; \
             input 0 refuses too, as the cases of the leader say",
        )
        .twin_inputs(
            &three_token_coins(),
            |scenario| *scenario = three_with_foreign(foreign.coin, 150),
            &[
                (2, Expected::rule(rule).at_line(line)),
                (1, Expected::pass()),
            ],
        );
    }
}
