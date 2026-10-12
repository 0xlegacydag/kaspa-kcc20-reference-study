//! The earlier Python checks of `TokenSeed` and of the minter and seed lifecycles, run again
//! on the script engine of a node.
//!
//! Three groups of the earlier Python checks are repeated here, case by case:
//!
//! - `B_seed.test_b_seed` (22 methods): `create`, `split`, `reclaim` and
//!   `reclaim_delegator` of `TokenSeed`, and three recorded facts about the coin a seed
//!   creates;
//! - `test_token_seed` (8 methods): `TokenSeed.create`;
//! - `test_lifecycle` (10 methods): split, reclaim and merge of a minter, split and reclaim
//!   of a seed.
//!
//! The earlier checks ran one input per call on a debug engine and named the source line of
//! a refusal. Here the whole transaction is assembled and every input runs its script. A
//! case asserts the input the earlier check ran, with the rule of the rule inventory at the
//! line the earlier check asserted; what the other inputs of the same transaction answer is
//! asserted next to it and described in the note of the case.
//!
//! Differences in the shapes, none of which a script of the three contracts can see:
//!
//! - The parties are the keys of the honest shapes: the owner of a seed or of a surviving
//!   coin is Alice, a recipient or a retiring owner is Bob, and the stranger of the earlier
//!   checks (their "Mallory") is Carol.
//! - The `OP_TRUE` funding coin holds 2000 sompi and has the outpoint of the honest shapes.
//! - Where an earlier shape paid out more sompi than it spent, an `OP_TRUE` funding coin is
//!   added to both sides of the twin, so that a node gets to run the scripts. The earlier
//!   shape itself is kept next to it: judged by its scripts only, and shown to be refused
//!   by a node for its amounts.
//! - A contract coin that an earlier shape carried along without running it gets a call
//!   here: a transaction cannot spend a coin without one. The call is the joining entry of
//!   its contract, signed by the coin's owner.
//! - The accepting control of the two count-rule checks (a token coin that is not of the
//!   seed's covenant beside the seed) is an accepted transaction: the lines
//!   `b_seed/create|split/control, ..`, in which that coin runs its own leader entry into an
//!   output of its own covenant; its twin `b_seed/create|split/joined, ..` differs only in
//!   the covenant id. The lines `.. a token coin of another covenant beside the seed` run
//!   the same coin with the joining entry and record the refusal of that transaction.
//!
//! What "accepted" means on a line: `expect_accept` and the honest side of a twin assert
//! the scripts of the whole transaction (for a twin also that a node gets to the scripts);
//! `expect_consensus_accept` adds the consensus rules of a submission. Only the lines
//! `realistic/..` of the last section ask a default mempool, and it takes them, as a block
//! does. All other accept lines use the 1000-sompi coins of the script-only profile and
//! ask no block and no mempool.

use checks::{Case, Expected, Twin};
use kaspa_consensus_core::{Hash, hashing::sighash_type::SIG_HASH_ALL, tx::CovenantBinding};
use kcc20_family::{
    Entry, EntryRole, Scenario,
    keys::{self, ALICE, BOB, CAROL},
    scenario::{
        Arg, Call, ContractInput, ContractOutput, InputSpec, LateBytes, OrdinaryInput, OutputSpec,
        PlainOutput,
    },
    shapes::{self, BorrowKind, Profile, Realistic},
    states::{BORROW_HASH_CHAIN, Kcc20State, OWNER_COVENANT_ID, PublicMintState, TokenSeedState},
    witness,
};
use node_gate::ErrorClass;

/// Another token family: the extension commitment the earlier checks used.
const OTHER_FAMILY: [u8; 32] = [0xee; 32];
/// Another covenant: the id the earlier checks gave a coin that is not of the seed's family.
const OTHER_COVENANT: [u8; 32] = [0x22; 32];

fn script() -> Profile {
    Profile::Script
}

fn case(id: &str, py_ids: &[&str], note: &str) -> Case {
    let case = Case::new(id).py(py_ids.iter().copied());
    if note.is_empty() {
        case
    } else {
        case.note(note)
    }
}

/// A rule of a contract refused at the line the earlier check asserted.
fn rule_at(rule: &str, line: u32) -> Expected {
    Expected::rule(rule).at_line(line)
}

/// The honest scenario passes; after `change` input `input` is refused by `rule` at `line`
/// and every input of `passing` passes.
fn refused(
    case: Case,
    honest: &Scenario,
    change: impl FnOnce(&mut Scenario),
    input: usize,
    rule: &str,
    line: u32,
    passing: &[usize],
) -> Twin {
    let mut expected = vec![(input, rule_at(rule, line))];
    expected.extend(passing.iter().map(|input| (*input, Expected::pass())));
    case.twin_inputs(honest, change, &expected)
}

fn bound_to_leader() -> Option<CovenantBinding> {
    Some(CovenantBinding::new(0, shapes::covenant_id()))
}

fn pay_to(key_seed: u8, value: u64) -> PlainOutput {
    PlainOutput::new(
        shapes::pay_to_public_key_script(&keys::x_only(key_seed)),
        value,
    )
}

/// An `OP_TRUE` coin behind the other inputs, as the honest shapes with funding have it.
fn funding() -> OrdinaryInput {
    OrdinaryInput::new(
        shapes::op_true_script(),
        shapes::SCRIPT_FUNDING_VALUE,
        shapes::outpoint(3, 0),
        LateBytes::empty(),
    )
    .labelled("funding (OP_TRUE)")
}

// ---------------------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------------------

/// A plain empty coin of Bob: borrowing off. The recipient of most earlier `create` checks.
fn empty_coin() -> Kcc20State {
    Kcc20State::new(keys::x_only(BOB), 0)
}

/// Sets the recipient of `TokenSeed.create`, in the call and in the output alike.
fn set_created_coin(scenario: &mut Scenario, recipient: Kcc20State) {
    *scenario.contract_input_mut(0).declared_state_mut() = recipient.clone();
    scenario.contract_output_mut(1).state = recipient.into();
}

/// `TokenSeed.create`: Alice's seed and an `OP_TRUE` funding coin in; the same seed and the
/// new coin `recipient` out, both bound to the seed.
fn create(recipient: Kcc20State) -> Scenario {
    create_in(&script(), recipient)
}

/// [`create`] in the coin values of `profile`.
fn create_in(profile: &Profile, recipient: Kcc20State) -> Scenario {
    let mut scenario = shapes::seed_create(profile);
    set_created_coin(&mut scenario, recipient);
    scenario
}

/// `TokenSeed.split`: Alice's seed and funding in; Alice's seed and a new seed of Bob out.
fn split() -> Scenario {
    shapes::seed_split(&script())
}

/// `TokenSeed.reclaim` with `reclaim_delegator`: Alice's seed survives, Bob's retires.
fn reclaim() -> Scenario {
    shapes::seed_reclaim(&script())
}

/// One more token coin of Bob (5 tokens) under the covenant `covenant`, as input 2. It runs
/// `transfer_delegator` with Bob's signature.
fn extra_token_coin(covenant: Hash) -> ContractInput {
    ContractInput::new(
        Kcc20State::new(keys::x_only(BOB), 5),
        shapes::SCRIPT_COIN_VALUE,
        Some(covenant),
        shapes::outpoint(1, 2),
        Call::typed(
            Entry::TransferDelegator,
            vec![Arg::Bytes(witness::owner_key(
                BOB,
                EntryRole::Delegate,
                SIG_HASH_ALL,
            ))],
        ),
    )
    .labelled("one more token coin of Bob")
}

/// One more seed of Bob under the covenant of the shapes. It runs `reclaim_delegator` with
/// Bob's signature.
fn extra_seed() -> ContractInput {
    ContractInput::new(
        TokenSeedState::new(keys::x_only(BOB)),
        shapes::SCRIPT_COIN_VALUE,
        Some(shapes::covenant_id()),
        shapes::outpoint(1, 2),
        Call::typed(
            Entry::SeedReclaimDelegator,
            vec![Arg::Bytes(witness::signature(BOB, SIG_HASH_ALL))],
        ),
    )
    .labelled("one more seed of Bob")
}

/// One more minter of Bob (25 remaining, 10 per mint) under the covenant of the shapes. It
/// runs `PublicMint.reclaim_delegator` with Bob's signature.
fn extra_minter() -> ContractInput {
    ContractInput::new(
        PublicMintState::new(keys::x_only(BOB), 25, 10),
        shapes::SCRIPT_COIN_VALUE,
        Some(shapes::covenant_id()),
        shapes::outpoint(1, 2),
        Call::typed(
            Entry::MintReclaimDelegator,
            vec![Arg::Bytes(witness::signature(BOB, SIG_HASH_ALL))],
        ),
    )
    .labelled("one more minter of Bob")
}

/// A borrowed receive: the coin `receiving` leads on the borrow path with the path byte
/// alone, and the key `payer` moves `added` of its 100 tokens into it and signs.
fn pay_into(receiving: Kcc20State, payer: u8, added: i64) -> Scenario {
    pay_into_in(&script(), receiving, payer, added)
}

/// [`pay_into`] in the coin values of `profile`.
fn pay_into_in(profile: &Profile, receiving: Kcc20State, payer: u8, added: i64) -> Scenario {
    let mut scenario = shapes::borrow(profile, BorrowKind::Threshold);
    let paying = Kcc20State::new(keys::x_only(payer), 100);
    let after = vec![
        receiving.clone().with_amount(receiving.amount + added),
        paying.clone().with_amount(100 - added),
    ];
    let leader = scenario.contract_input_mut(0);
    leader.state = receiving.into();
    *leader.declared_states_mut() = after.clone();
    let delegate = scenario.contract_input_mut(1);
    delegate.state = paying.into();
    *delegate.witness_mut() = witness::owner_key(payer, EntryRole::Delegate, SIG_HASH_ALL);
    for (index, state) in after.into_iter().enumerate() {
        scenario.contract_output_mut(index).state = state.into();
    }
    scenario
}

/// The owner of `coin` moves all of it to a plain coin of the key `to`.
fn owner_spends(coin: Kcc20State, owner: u8, to: u8) -> Scenario {
    owner_spends_in(&script(), coin, owner, to)
}

/// [`owner_spends`] in the coin values of `profile`.
fn owner_spends_in(profile: &Profile, coin: Kcc20State, owner: u8, to: u8) -> Scenario {
    let mut scenario = shapes::transfer(profile, 1, 1);
    let next = Kcc20State::new(keys::x_only(to), coin.amount);
    let input = scenario.contract_input_mut(0);
    input.state = coin.into();
    *input.declared_states_mut() = vec![next.clone()];
    *input.witness_mut() = witness::owner_key(owner, EntryRole::Leader, SIG_HASH_ALL);
    scenario.contract_output_mut(0).state = next.into();
    scenario
}

fn seed_output(scenario: &mut Scenario, index: usize) -> &mut TokenSeedState {
    scenario
        .contract_output_mut(index)
        .state
        .as_token_seed_mut()
        .expect("a seed output")
}

fn minter_output(scenario: &mut Scenario, index: usize) -> &mut PublicMintState {
    scenario
        .contract_output_mut(index)
        .state
        .as_public_mint_mut()
        .expect("a minter output")
}

/// Sets how much of its allowance of 25 `PublicMint.split` hands over, in the call and in
/// both outputs alike.
fn set_take(scenario: &mut Scenario, take: i64) {
    scenario.contract_input_mut(0).args_mut()[0] = Arg::int(take);
    minter_output(scenario, 0).remaining = 25 - take;
    minter_output(scenario, 1).remaining = take;
}

/// What the three kinds of coin of the seed's own covenant answer as input 2 beside a seed
/// that runs `create`: the coin, the answer of its own input, and a description of it.
fn coins_of_the_family_beside_create() -> [(&'static str, ContractInput, Expected, &'static str); 3]
{
    [
        (
            "a token coin",
            extra_token_coin(shapes::covenant_id()),
            rule_at("K-70", 257),
            "runs transfer_delegator with Bob's signature and is refused at KCC20.sil:257: \
             the first coin of the covenant is not a token coin",
        ),
        (
            "a seed",
            extra_seed(),
            Expected::pass(),
            "runs reclaim_delegator with Bob's signature and PASSES; the transaction is \
             refused by the leading seed alone",
        ),
        (
            "a minter",
            extra_minter(),
            rule_at("M-53", 314),
            "runs PublicMint.reclaim_delegator with Bob's signature and is refused at \
             PublicMint.sil:314: the first coin of the covenant is not a minter",
        ),
    ]
}

/// The same three coins beside a seed that runs `split`. A token coin and a minter are
/// refused by the engine (`InvalidIndex`).
fn coins_of_the_family_beside_split() -> [(&'static str, ContractInput, Expected, &'static str); 3]
{
    [
        (
            "a token coin",
            extra_token_coin(shapes::covenant_id()),
            Expected::engine("InvalidIndex")
                .at_line(257)
                .of_class(ErrorClass::EngineRefusedData),
            "runs transfer_delegator with Bob's signature and the engine refuses it \
             (InvalidIndex, KCC20.sil:257)",
        ),
        (
            "a seed",
            extra_seed(),
            Expected::pass(),
            "runs reclaim_delegator with Bob's signature and PASSES; the transaction is \
             refused by the leading seed alone",
        ),
        (
            "a minter",
            extra_minter(),
            Expected::engine("InvalidIndex")
                .at_line(314)
                .of_class(ErrorClass::EngineRefusedData),
            "runs PublicMint.reclaim_delegator with Bob's signature and the engine refuses \
             it (InvalidIndex, PublicMint.sil:314)",
        ),
    ]
}

/// The coin that an earlier shape carried along without running it runs, in the changed
/// scenario, the contract and the entry its scenario states: its answer is the answer of
/// that entry, not of a script that could not be read.
fn assert_runs_its_own_entry(twin: &Twin, input: usize) {
    let observed = &twin.changed.inputs[input];
    assert!(
        observed.contract.is_some() && observed.runs_what_is_stated(),
        "input {input} runs {}",
        observed.what()
    );
}

/// The note of a case whose earlier check ran the seed with a coin of another covenant
/// beside it.
const OTHER_COVENANT_NOTE: &str = "DIFFERS FROM PYTHON: the earlier check ran input 0 alone and \
    it passed. Input 0 passes here too, but the transaction is refused as a whole: the coin of \
    the other covenant must run an entry, it runs transfer_delegator with its owner's signature \
    and stops at KCC20.sil:254 (K-68), being the only coin of its covenant. This line runs \
    the coin with the joining entry and records the refusal of the transaction; with its own \
    leader entry (transfer) and an output of its own covenant the same coin passes, and that \
    transaction is the accepting control: the line 'control, a token coin under another \
    covenant id' of the same check.";

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
/// The earlier control: the same coin, not of the covenant, beside the seed, and the seed
/// passes. Here the token coin is of ANOTHER covenant and spends itself by its own leader
/// entry into an output of its own: every script passes and the consensus rules of a
/// submission accept the transaction (an accept line). With the covenant id of the seed on
/// that coin and its output, and nothing else changed, the seed is refused by the count
/// rule at the line the earlier check asserted (a twin line).
fn control_pair(name: &str, py: &str, leader: &Scenario, count_rule: Expected) {
    let control = with_a_token_coin_under(leader, Hash::from_bytes(OTHER_COVENANT));
    case(
        &format!("b_seed/{name}/control, a token coin under another covenant id"),
        &[py],
        "The accepting control of the earlier check as a transaction a node runs: scripts of \
         every input and the consensus rules of a submission (1000-sompi coins: no block or \
         mempool question is asked). The coin of the other covenant runs transfer, signed by \
         its owner, into an output of its own covenant.",
    )
    .expect_consensus_accept(&control);
    case(
        &format!("b_seed/{name}/joined, the same token coin under the seed's covenant id"),
        &[py],
        "Twin of the control: only the covenant id of the extra coin and of its output \
         differs. The seed is refused by the count rule at the line of the earlier check. The \
         answer of the extra coin is not asserted.",
    )
    .twin(
        &control,
        |scenario| *scenario = with_a_token_coin_under(leader, shapes::covenant_id()),
        0,
        count_rule,
    );
}

// ---------------------------------------------------------------------------------------
// B_seed: TokenSeed.create
// ---------------------------------------------------------------------------------------

#[test]
fn b_seed_create_recipient_amount_minus_one() {
    const PY: &str = "B_seed.test_b_seed.Create.test_recipient_amount_minus_one";
    let honest = create(empty_coin());
    case("b_seed/create/honest: an empty coin of Bob", &[PY], "").expect_accept(&honest);
    refused(
        case("b_seed/create/recipient amount -1", &[PY], ""),
        &honest,
        |scenario| set_created_coin(scenario, empty_coin().with_amount(-1)),
        0,
        "S-12",
        132,
        &[1],
    );
}

#[test]
fn b_seed_create_recipient_owner_scheme_out_of_range() {
    const PY: &str = "B_seed.test_b_seed.Create.test_recipient_owner_scheme_out_of_range";
    let with_scheme = |scheme: u8| empty_coin().with_owner(scheme, keys::x_only(BOB));
    let highest = create(with_scheme(OWNER_COVENANT_ID));
    case(
        "b_seed/create/owner scheme 0x04, the highest assigned",
        &[PY],
        "",
    )
    .expect_accept(&highest);
    for scheme in [0x05u8, 0x7f, 0x80, 0xff] {
        refused(
            case(
                &format!("b_seed/create/owner scheme {scheme:#04x}"),
                &[PY],
                "the twin is the same create with owner scheme 0x04; the line is inside the \
                 helper function called at line 134; 0x80 and 0xff show that the byte is \
                 compared as unsigned",
            ),
            &highest,
            |scenario| set_created_coin(scenario, with_scheme(scheme)),
            0,
            "S-14",
            66,
            &[1],
        );
    }
}

#[test]
fn b_seed_create_recipient_borrow_scheme_out_of_range() {
    const PY: &str = "B_seed.test_b_seed.Create.test_recipient_borrow_scheme_out_of_range";
    let with_scheme = |scheme: u8| empty_coin().with_borrow(scheme, [0; 32]);
    let highest = create(with_scheme(BORROW_HASH_CHAIN));
    case(
        "b_seed/create/borrow scheme 0x03, the highest assigned",
        &[PY],
        "",
    )
    .expect_accept(&highest);
    refused(
        case(
            "b_seed/create/borrow scheme 0x04",
            &[PY],
            "the twin is the same create with borrow scheme 0x03; the line is inside the \
             helper function called at line 135",
        ),
        &highest,
        |scenario| set_created_coin(scenario, with_scheme(0x04)),
        0,
        "S-15",
        69,
        &[1],
    );
}

#[test]
fn b_seed_create_recipient_of_another_family() {
    const PY: &str = "B_seed.test_b_seed.Create.test_recipient_of_another_family";
    refused(
        case("b_seed/create/recipient of another family", &[PY], ""),
        &create(empty_coin()),
        |scenario| set_created_coin(scenario, empty_coin().with_extension(OTHER_FAMILY)),
        0,
        "S-13",
        133,
        &[1],
    );
}

#[test]
fn b_seed_create_seed_keeps_its_sompi() {
    const PY: &str = "B_seed.test_b_seed.Create.test_seed_keeps_its_sompi";
    for kept in [1001u64, 999] {
        refused(
            case(
                &format!("b_seed/create/seed output value {kept}"),
                &[PY],
                "",
            ),
            &create(empty_coin()),
            |scenario| scenario.contract_output_mut(0).value = kept,
            0,
            "S-16",
            136,
            &[1],
        );
    }
}

#[test]
fn b_seed_create_seed_keeps_its_owner() {
    const PY: &str = "B_seed.test_b_seed.Create.test_seed_keeps_its_owner";
    refused(
        case(
            "b_seed/create/seed output owned by a stranger",
            &[PY],
            "the statement of lines 138-141",
        ),
        &create(empty_coin()),
        |scenario| seed_output(scenario, 0).owner = keys::x_only(CAROL),
        0,
        "S-17",
        138,
        &[1],
    );
}

#[test]
fn b_seed_create_no_second_coin_bound_to_the_seed() {
    const PY: &str = "B_seed.test_b_seed.Create.test_no_second_coin_bound_to_the_seed";
    let honest = create(empty_coin());
    let mut with_change = honest.clone();
    with_change.push_plain_output(pay_to(BOB, shapes::SCRIPT_COIN_VALUE));
    case("b_seed/create/a third output without a binding", &[PY], "").expect_accept(&with_change);
    refused(
        case(
            "b_seed/create/a second token coin bound to the seed",
            &[PY],
            "the third output holds 1000 tokens of a stranger and is bound to the seed's input",
        ),
        &honest,
        |scenario| {
            scenario.push_contract_output(ContractOutput::new(
                Kcc20State::new(keys::x_only(CAROL), 1000),
                shapes::SCRIPT_COIN_VALUE,
                bound_to_leader(),
            ));
        },
        0,
        "S-11",
        126,
        &[1],
    );
}

#[test]
fn b_seed_create_no_other_input_of_the_family() {
    const PY: &str = "B_seed.test_b_seed.Create.test_no_other_input_of_the_family";
    let honest = create(empty_coin());
    control_pair("create", PY, &honest, rule_at("S-10", 123));

    let mut beside_another_covenant = honest.clone();
    beside_another_covenant.push_contract_input(extra_token_coin(Hash::from_bytes(OTHER_COVENANT)));
    case(
        "b_seed/create/a token coin of another covenant beside the seed",
        &[PY],
        OTHER_COVENANT_NOTE,
    )
    .expect_inputs(
        &beside_another_covenant,
        &[
            (0, Expected::pass()),
            (1, Expected::pass()),
            (2, rule_at("K-68", 254)),
        ],
    );

    for (kind, coin, its_answer, what_it_does) in coins_of_the_family_beside_create() {
        let twin = case(
            &format!("b_seed/create/{kind} of the covenant beside the seed"),
            &[PY],
            &format!(
                "the earlier check did not run input 2. Here it {what_it_does}. Input 0 is \
                 refused as the earlier check says."
            ),
        )
        .twin_inputs(
            &honest,
            |scenario| {
                scenario.push_contract_input(coin);
            },
            &[
                (0, rule_at("S-10", 123)),
                (1, Expected::pass()),
                (2, its_answer),
            ],
        );
        assert_runs_its_own_entry(&twin, 2);
    }
}

// ---------------------------------------------------------------------------------------
// B_seed: TokenSeed.split
// ---------------------------------------------------------------------------------------

#[test]
fn b_seed_split_retained_seed_keeps_its_sompi() {
    const PY: &str = "B_seed.test_b_seed.Split.test_retained_seed_keeps_its_sompi";
    case("b_seed/split/honest: a new seed of Bob", &[PY], "").expect_accept(&split());
    for kept in [1001u64, 999] {
        refused(
            case(
                &format!("b_seed/split/retained seed value {kept}"),
                &[PY],
                "",
            ),
            &split(),
            |scenario| scenario.contract_output_mut(0).value = kept,
            0,
            "S-23",
            181,
            &[1],
        );
    }
}

#[test]
fn b_seed_split_retained_seed_keeps_its_owner() {
    const PY: &str = "B_seed.test_b_seed.Split.test_retained_seed_keeps_its_owner";
    refused(
        case(
            "b_seed/split/retained seed owned by a stranger",
            &[PY],
            "the statement of lines 183-186",
        ),
        &split(),
        |scenario| seed_output(scenario, 0).owner = keys::x_only(CAROL),
        0,
        "S-24",
        183,
        &[1],
    );
}

#[test]
fn b_seed_split_added_output_must_be_a_seed() {
    const PY: &str = "B_seed.test_b_seed.Split.test_added_output_must_be_a_seed";
    for amount in [0i64, 1000] {
        refused(
            case(
                &format!("b_seed/split/added output is a token coin holding {amount}"),
                &[PY],
                "same value and binding as the seed it replaces",
            ),
            &split(),
            |scenario| {
                scenario.contract_output_mut(1).state =
                    Kcc20State::new(keys::x_only(BOB), amount).into()
            },
            0,
            "S-25",
            196,
            &[1],
        );
    }
}

#[test]
fn b_seed_split_added_seed_of_the_same_family() {
    const PY: &str = "B_seed.test_b_seed.Split.test_added_seed_of_the_same_family";
    refused(
        case("b_seed/split/added seed of another family", &[PY], ""),
        &split(),
        |scenario| seed_output(scenario, 1).extension_commitment = OTHER_FAMILY,
        0,
        "S-25",
        196,
        &[1],
    );
}

#[test]
fn b_seed_split_no_other_input_of_the_family() {
    const PY: &str = "B_seed.test_b_seed.Split.test_no_other_input_of_the_family";
    let honest = split();
    control_pair("split", PY, &honest, rule_at("S-21", 167));

    let mut beside_another_covenant = honest.clone();
    beside_another_covenant.push_contract_input(extra_token_coin(Hash::from_bytes(OTHER_COVENANT)));
    case(
        "b_seed/split/a token coin of another covenant beside the seed",
        &[PY],
        OTHER_COVENANT_NOTE,
    )
    .expect_inputs(
        &beside_another_covenant,
        &[
            (0, Expected::pass()),
            (1, Expected::pass()),
            (2, rule_at("K-68", 254)),
        ],
    );

    for (kind, coin, its_answer, what_it_does) in coins_of_the_family_beside_split() {
        let twin = case(
            &format!("b_seed/split/{kind} of the covenant beside the seed"),
            &[PY],
            &format!(
                "the earlier check did not run input 2. Here it {what_it_does}. Input 0 is \
                 refused as the earlier check says."
            ),
        )
        .twin_inputs(
            &honest,
            |scenario| {
                scenario.push_contract_input(coin);
            },
            &[
                (0, rule_at("S-21", 167)),
                (1, Expected::pass()),
                (2, its_answer),
            ],
        );
        assert_runs_its_own_entry(&twin, 2);
    }
}

// ---------------------------------------------------------------------------------------
// B_seed: TokenSeed.reclaim and reclaim_delegator
// ---------------------------------------------------------------------------------------

/// The honest reclaim with an `OP_TRUE` funding coin behind the two seeds, as input 2.
fn funded_reclaim() -> Scenario {
    let mut scenario = reclaim();
    scenario.push_ordinary_input(funding());
    scenario
}

#[test]
fn b_seed_reclaim_survivor_keeps_its_sompi() {
    const PY: &str = "B_seed.test_b_seed.Reclaim.test_survivor_keeps_its_sompi";
    case("b_seed/reclaim/honest: Bob's seed retires", &[PY], "").expect_accept(&reclaim());
    refused(
        case(
            "b_seed/reclaim/survivor value 1001",
            &[PY],
            "the earlier shape paid out 1322 sompi of 1321; here both sides of the twin have \
             an OP_TRUE funding coin as input 2, so that a node gets to the scripts",
        ),
        &funded_reclaim(),
        |scenario| scenario.contract_output_mut(0).value = 1001,
        0,
        "S-34",
        225,
        &[1, 2],
    );
    refused(
        case("b_seed/reclaim/survivor value 999", &[PY], ""),
        &reclaim(),
        |scenario| scenario.contract_output_mut(0).value = 999,
        0,
        "S-34",
        225,
        &[1],
    );

    // The earlier shape as it was built: no funding, 1322 sompi paid out of 1321.
    let mut overspending = reclaim();
    overspending.contract_output_mut(0).value = 1001;
    refused(
        case(
            "b_seed/reclaim/survivor value 1001 without funding, the scripts",
            &[PY],
            "the earlier shape itself, judged by its scripts only: they answer as the earlier \
             check says",
        )
        .scripts_only(),
        &reclaim(),
        |scenario| *scenario = overspending.clone(),
        0,
        "S-34",
        225,
        &[1],
    );
    case(
        "b_seed/reclaim/survivor value 1001 without funding, a node",
        &[PY],
        "DIFFERS FROM PYTHON: the earlier check named line 225 for this transaction. A node \
         refuses it for its amounts (1322 sompi out of 1321) before it runs a script.",
    )
    .expect_consensus_refused(&overspending, "SpendTooHigh");
}

#[test]
fn b_seed_reclaim_survivor_keeps_its_owner() {
    const PY: &str = "B_seed.test_b_seed.Reclaim.test_survivor_keeps_its_owner";
    refused(
        case(
            "b_seed/reclaim/survivor owned by a stranger",
            &[PY],
            "the statement of lines 227-230; nobody signs for the survivor",
        ),
        &reclaim(),
        |scenario| seed_output(scenario, 0).owner = keys::x_only(CAROL),
        0,
        "S-35",
        227,
        &[1],
    );
}

#[test]
fn b_seed_reclaim_retiring_seed_of_another_family() {
    const PY: &str = "B_seed.test_b_seed.Reclaim.test_retiring_seed_of_another_family";
    refused(
        case("b_seed/reclaim/retiring seed of another family", &[PY], ""),
        &reclaim(),
        |scenario| {
            scenario
                .contract_input_mut(1)
                .state
                .as_token_seed_mut()
                .expect("the retiring seed")
                .extension_commitment = OTHER_FAMILY
        },
        0,
        "S-33",
        224,
        &[1],
    );
}

#[test]
fn b_seed_reclaim_retiring_seed_asks_its_owner() {
    const PY: &str = "B_seed.test_b_seed.Reclaim.test_retiring_seed_asks_its_owner";
    refused(
        case(
            "b_seed/reclaim/retiring seed signed by the survivor's key",
            &[PY],
            "a valid signature over this transaction by a key that is not the owner's",
        ),
        &reclaim(),
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() = witness::signature(ALICE, SIG_HASH_ALL)
        },
        1,
        "S-43",
        254,
        &[0],
    );

    // 65 zero bytes: the last byte is the signature hash type, and 0 is none.
    case(
        "b_seed/reclaim/retiring seed with 65 zero bytes",
        &[PY],
        "the earlier check asserted the line only and saw the words 'invalid hash type 0x00'; \
         the engine of a node refuses the signature material at OpCheckSig of the same line \
         (InvalidSigHashType), before the rule's OpVerify",
    )
    .twin_inputs(
        &reclaim(),
        |scenario| *scenario.contract_input_mut(1).witness_mut() = LateBytes::fixed(vec![0u8; 65]),
        &[
            (0, Expected::pass()),
            (
                1,
                Expected::engine("InvalidSigHashType")
                    .at_line(254)
                    .of_class(ErrorClass::MalformedSignatureMaterial),
            ),
        ],
    );

    // 64 zero bytes and the type byte of SIG_HASH_ALL: a signature that parses and is false.
    refused(
        case(
            "b_seed/reclaim/retiring seed with 64 zero bytes and hash type 01",
            &[PY],
            "the signature parses, verifies false, and the rule refuses",
        ),
        &reclaim(),
        |scenario| {
            let mut signature = vec![0u8; 64];
            signature.push(SIG_HASH_ALL.to_u8());
            *scenario.contract_input_mut(1).witness_mut() = LateBytes::fixed(signature)
        },
        1,
        "S-43",
        254,
        &[0],
    );
}

#[test]
fn b_seed_reclaim_a_single_seed_running_reclaim() {
    const PY: &str = "B_seed.test_b_seed.Reclaim.test_a_single_seed_running_reclaim";
    refused(
        case(
            "b_seed/reclaim/a single seed recreating itself",
            &[PY],
            "the retiring seed and its payout are removed",
        ),
        &reclaim(),
        |scenario| {
            scenario.inputs.truncate(1);
            scenario.outputs.truncate(1);
        },
        0,
        "S-26",
        207,
        &[],
    );
    refused(
        case(
            "b_seed/reclaim/a single seed paying its deposit out",
            &[PY],
            "the only output is a plain coin of the seed's owner",
        ),
        &reclaim(),
        |scenario| {
            scenario.inputs.truncate(1);
            scenario.outputs = vec![OutputSpec::Plain(pay_to(ALICE, shapes::SCRIPT_COIN_VALUE))];
        },
        0,
        "S-26",
        207,
        &[],
    );
}

#[test]
fn b_seed_reclaim_a_lone_seed_cannot_reclaim() {
    const PY: &str = "B_seed.test_b_seed.Reclaim.test_a_lone_seed_cannot_reclaim";
    const FUNDED: &str = "the honest reclaim with the survivor's input removed and its output \
        kept; the earlier shape paid out 1321 sompi of 321, here both sides of the twin have an \
        OP_TRUE funding coin behind the seeds, so that a node gets to the scripts";
    refused(
        case(
            "b_seed/reclaim/survivor removed, the retiring seed runs reclaim_delegator",
            &[PY],
            FUNDED,
        ),
        &funded_reclaim(),
        |scenario| {
            scenario.inputs.remove(0);
        },
        0,
        "S-37",
        241,
        &[1],
    );
    refused(
        case(
            "b_seed/reclaim/survivor removed, the retiring seed runs reclaim",
            &[PY],
            FUNDED,
        ),
        &funded_reclaim(),
        |scenario| {
            scenario.inputs.remove(0);
            scenario.contract_input_mut(0).call = Call::typed(Entry::SeedReclaim, Vec::new());
        },
        0,
        "S-26",
        207,
        &[1],
    );
    refused(
        case(
            "b_seed/reclaim/a lone seed, its owner signs and takes the deposit",
            &[PY],
            "the count rule stops before the signature is looked at",
        ),
        &reclaim(),
        |scenario| {
            scenario.inputs.remove(0);
            scenario.outputs.remove(0);
        },
        0,
        "S-37",
        241,
        &[],
    );

    // The earlier shape as it was built: no funding, 1321 sompi paid out of 321.
    let mut overspending = reclaim();
    overspending.inputs.remove(0);
    refused(
        case(
            "b_seed/reclaim/survivor removed without funding, the scripts",
            &[PY],
            "the earlier shape itself, judged by its scripts only: reclaim_delegator answers \
             as the earlier check says",
        )
        .scripts_only(),
        &reclaim(),
        |scenario| *scenario = overspending.clone(),
        0,
        "S-37",
        241,
        &[],
    );
    case(
        "b_seed/reclaim/survivor removed without funding, a node",
        &[PY],
        "DIFFERS FROM PYTHON: the earlier check named lines 241 and 207 for this transaction. \
         A node refuses it for its amounts (1321 sompi out of 321) before it runs a script.",
    )
    .expect_consensus_refused(&overspending, "SpendTooHigh");
}

// ---------------------------------------------------------------------------------------
// B_seed: the creator chooses owner and policy (recorded facts)
// ---------------------------------------------------------------------------------------

#[test]
fn b_seed_a_coin_for_bob_who_did_not_ask_then_anyone_adds_to_it() {
    const PY: &str = "B_seed.test_b_seed.CreatorChoosesOwnerAndPolicy.\
        test_a_coin_for_bob_who_did_not_ask_then_anyone_adds_to_it";
    let open = empty_coin().with_threshold(0);
    case(
        "b_seed/policy/an empty coin of Bob with threshold 0 is created",
        &[PY],
        "nobody signs: neither the seed's owner nor Bob",
    )
    .expect_accept(&create(open.clone()));
    case(
        "b_seed/policy/a stranger adds 1 token to it",
        &[PY],
        "Bob's coin leads on the borrow path with the path byte alone, the stranger's coin \
         joins and signs; as in the earlier check the coin is given, not the output of the \
         create above",
    )
    .expect_accept(&pay_into(open, CAROL, 1));
}

#[test]
fn b_seed_contrast_a_coin_with_borrowing_off_cannot_be_added_to() {
    const PY: &str = "B_seed.test_b_seed.CreatorChoosesOwnerAndPolicy.\
        test_contrast_a_coin_with_borrowing_off_cannot_be_added_to";
    case(
        "b_seed/policy/an empty coin of Bob with borrowing off is created",
        &[PY],
        "",
    )
    .expect_accept(&create(empty_coin()));
    refused(
        case(
            "b_seed/policy/a stranger cannot add to a coin with borrowing off",
            &[PY],
            "the twin is the same receive into a coin with threshold 0; only Bob's borrow \
             scheme differs, in the coin, in the call and in the output",
        ),
        &pay_into(empty_coin().with_threshold(0), CAROL, 1),
        |scenario| *scenario = pay_into(empty_coin(), CAROL, 1),
        0,
        "K-50",
        184,
        &[1],
    );
}

#[test]
fn b_seed_a_coin_owned_by_the_token_covenant_itself() {
    const PY: &str = "B_seed.test_b_seed.CreatorChoosesOwnerAndPolicy.\
        test_a_coin_owned_by_the_token_covenant_itself";
    let recipient = Kcc20State::new(shapes::COVENANT_ID_BYTES, 0)
        .with_owner(OWNER_COVENANT_ID, shapes::COVENANT_ID_BYTES)
        .with_threshold(0);
    case(
        "b_seed/policy/a coin owned by the token's own covenant id is created",
        &[PY],
        "owner scheme 0x04 with the token's covenant id as owner, threshold 0; only the \
         creation is run",
    )
    .expect_accept(&create(recipient));
}

// ---------------------------------------------------------------------------------------
// test_token_seed: TokenSeed.create
// ---------------------------------------------------------------------------------------

#[test]
fn token_seed_a_coin_holding_tokens_cannot_be_created() {
    const PY: &str = "test_token_seed.TokenSeedCreate.test_a_coin_holding_tokens_cannot_be_created";
    let honest = create(empty_coin());
    case("token_seed/create/amount 0", &[PY], "the control").expect_accept(&honest);
    for amount in [1i64, 1 << 62, -1] {
        refused(
            case(&format!("token_seed/create/amount {amount}"), &[PY], ""),
            &honest,
            |scenario| set_created_coin(scenario, empty_coin().with_amount(amount)),
            0,
            "S-12",
            132,
            &[1],
        );
    }
}

#[test]
fn token_seed_a_created_coin_can_be_paid_into_and_then_spent_by_its_owner() {
    const PY: &str = "test_token_seed.TokenSeedCreate.\
        test_a_created_coin_can_be_paid_into_and_then_spent_by_its_owner";
    const NOTE: &str = "one of three transactions that agree in their states and are not \
        chained by outpoints, as in the earlier check";
    let open = empty_coin().with_threshold(0);
    case(
        "token_seed/life of a coin/1 an empty coin with threshold 0 is created",
        &[PY],
        NOTE,
    )
    .expect_accept(&create(open.clone()));
    case(
        "token_seed/life of a coin/2 Alice pays 30 into it",
        &[PY],
        NOTE,
    )
    .expect_accept(&pay_into(open.clone(), ALICE, 30));
    case(
        "token_seed/life of a coin/3 its owner spends it",
        &[PY],
        NOTE,
    )
    .expect_accept(&owner_spends(open.with_amount(30), BOB, ALICE));
}

#[test]
fn token_seed_anyone_creates_an_empty_coin_with_a_chosen_owner_and_policy() {
    const PY: &str = "test_token_seed.TokenSeedCreate.\
        test_anyone_creates_an_empty_coin_with_a_chosen_owner_and_policy";
    for (name, recipient) in [
        ("a plain empty coin", empty_coin()),
        (
            "an empty coin with threshold 10",
            empty_coin().with_threshold(10),
        ),
        (
            "an empty coin with threshold 0",
            empty_coin().with_threshold(0),
        ),
    ] {
        case(
            &format!("token_seed/create/{name}"),
            &[PY],
            "no signature and no key of the seed's owner",
        )
        .expect_accept(&create(recipient));
    }
}

#[test]
fn token_seed_create_runs_with_no_other_coin_of_the_covenant_beside_the_seed() {
    const PY: &str = "test_token_seed.TokenSeedCreate.\
        test_create_runs_with_no_other_coin_of_the_covenant_beside_the_seed";
    case(
        "token_seed/create/a token coin of the covenant in place of the funding",
        &[PY],
        "the earlier check did not run input 1, a token coin of Bob with 5 tokens. Here it \
         runs transfer_delegator with Bob's signature and is refused at KCC20.sil:257: the \
         first coin of the covenant is not a token coin. Input 0 is refused as the earlier \
         check says.",
    )
    .twin_inputs(
        &create(empty_coin()),
        |scenario| {
            let mut coin = extra_token_coin(shapes::covenant_id());
            coin.outpoint = shapes::outpoint(1, 1);
            scenario.inputs[1] = InputSpec::Contract(coin);
        },
        &[(0, rule_at("S-10", 123)), (1, rule_at("K-70", 257))],
    );
}

#[test]
fn token_seed_one_create_makes_exactly_one_coin() {
    const PY: &str = "test_token_seed.TokenSeedCreate.test_one_create_makes_exactly_one_coin";
    refused(
        case(
            "token_seed/create/a second coin of Bob with 1000 tokens bound to the seed",
            &[PY],
            "",
        ),
        &create(empty_coin()),
        |scenario| {
            scenario.push_contract_output(ContractOutput::new(
                empty_coin().with_amount(1000),
                shapes::SCRIPT_COIN_VALUE,
                bound_to_leader(),
            ));
        },
        0,
        "S-11",
        126,
        &[1],
    );
}

#[test]
fn token_seed_the_new_coin_must_be_of_the_seed_s_token_family() {
    const PY: &str = "test_token_seed.TokenSeedCreate.\
        test_the_new_coin_must_be_of_the_seed_s_token_family";
    refused(
        case("token_seed/create/a coin of another family", &[PY], ""),
        &create(empty_coin()),
        |scenario| set_created_coin(scenario, empty_coin().with_extension(OTHER_FAMILY)),
        0,
        "S-13",
        133,
        &[1],
    );
}

#[test]
fn token_seed_the_new_coin_must_hold_what_the_call_names() {
    const PY: &str = "test_token_seed.TokenSeedCreate.\
        test_the_new_coin_must_hold_what_the_call_names";
    refused(
        case(
            "token_seed/create/the output holds 1000 tokens, the call names none",
            &[PY],
            "the statement of lines 154-160; the amount rule of line 132 sees the number of \
             the call and passes",
        ),
        &create(empty_coin()),
        |scenario| scenario.contract_output_mut(1).state = empty_coin().with_amount(1000).into(),
        0,
        "S-19",
        154,
        &[1],
    );
}

#[test]
fn token_seed_the_seed_stays_exactly_as_it_was() {
    const PY: &str = "test_token_seed.TokenSeedCreate.test_the_seed_stays_exactly_as_it_was";
    let mut rich = create(empty_coin());
    rich.contract_input_mut(0).value = 7000;
    rich.contract_output_mut(0).value = 7000;
    case(
        "token_seed/create/a seed of 7000 sompi stays 7000",
        &[PY],
        "the control",
    )
    .expect_accept(&rich);
    for kept in [6999u64, 7001] {
        refused(
            case(
                &format!("token_seed/create/a seed of 7000 sompi becomes {kept}"),
                &[PY],
                "",
            ),
            &rich,
            |scenario| scenario.contract_output_mut(0).value = kept,
            0,
            "S-16",
            136,
            &[1],
        );
    }
    refused(
        case(
            "token_seed/create/the caller makes Bob the seed's owner",
            &[PY],
            "the statement of lines 138-141",
        ),
        &create(empty_coin()),
        |scenario| seed_output(scenario, 0).owner = keys::x_only(BOB),
        0,
        "S-17",
        138,
        &[1],
    );
}

// ---------------------------------------------------------------------------------------
// test_lifecycle: a minter
// ---------------------------------------------------------------------------------------

#[test]
fn lifecycle_minter_anyone_splits_off_up_to_half_of_the_allowance() {
    const PY: &str =
        "test_lifecycle.MinterLifecycle.test_anyone_splits_off_up_to_half_of_the_allowance";
    // The honest shape takes 7 of 25.
    let honest = shapes::mint_split(&script());
    for take in [7i64, 12, 1] {
        let mut scenario = honest.clone();
        set_take(&mut scenario, take);
        case(
            &format!("lifecycle/minter split/take {take} of 25"),
            &[PY],
            "nobody signs; 12 is 25 / 2 in whole numbers",
        )
        .expect_accept(&scenario);
    }
    for (take, rule, line) in [(13i64, "M-27", 197), (25, "M-27", 197), (0, "M-26", 196)] {
        refused(
            case(
                &format!("lifecycle/minter split/take {take} of 25"),
                &[PY],
                "the call and both outputs follow the number, so only the rule on the number \
                 can refuse; the twin takes 7",
            ),
            &honest,
            |scenario| set_take(scenario, take),
            0,
            rule,
            line,
            &[1],
        );
    }
}

#[test]
fn lifecycle_minter_a_split_keeps_the_per_mint_limit() {
    const PY: &str = "test_lifecycle.MinterLifecycle.test_a_split_keeps_the_per_mint_limit";
    refused(
        case(
            "lifecycle/minter split/the new minter mints 1000000 at a time",
            &[PY],
            "",
        ),
        &shapes::mint_split(&script()),
        |scenario| minter_output(scenario, 1).mint_amount = 1_000_000,
        0,
        "M-30",
        236,
        &[1],
    );
}

#[test]
fn lifecycle_minter_the_owner_takes_the_deposit_of_an_exhausted_minter() {
    const PY: &str =
        "test_lifecycle.MinterLifecycle.test_the_owner_takes_the_deposit_of_an_exhausted_minter";
    let honest = shapes::mint_reclaim(&script());
    case(
        "lifecycle/minter reclaim/exhausted, signed by its owner",
        &[PY],
        "the only output is a plain coin of the owner; the transaction pays no fee",
    )
    .expect_accept(&honest);
    refused(
        case(
            "lifecycle/minter reclaim/an allowance of 1 is left",
            &[PY],
            "",
        ),
        &honest,
        |scenario| {
            scenario
                .contract_input_mut(0)
                .state
                .as_public_mint_mut()
                .expect("the minter")
                .remaining = 1
        },
        0,
        "M-34",
        248,
        &[],
    );
    refused(
        case(
            "lifecycle/minter reclaim/signed by Bob",
            &[PY],
            "a valid signature over this transaction by a key that is not the owner's; the \
             earlier check compared the text of the line, which is also the text of line 324",
        ),
        &honest,
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() = witness::signature(BOB, SIG_HASH_ALL)
        },
        0,
        "M-35",
        249,
        &[],
    );
}

#[test]
fn lifecycle_minter_a_retiring_minter_returns_its_allowance_to_a_surviving_one() {
    const PY: &str = "test_lifecycle.MinterLifecycle.\
        test_a_retiring_minter_returns_its_allowance_to_a_surviving_one";
    case(
        "lifecycle/minter merge/18 and 4 make 22",
        &[PY],
        "the survivor signs nothing, the retiring minter's owner signs",
    )
    .expect_accept(&shapes::mint_reclaim_into(&script()));
}

#[test]
fn lifecycle_minter_the_merged_allowance_is_exactly_the_sum() {
    const PY: &str = "test_lifecycle.MinterLifecycle.test_the_merged_allowance_is_exactly_the_sum";
    for total in [23i64, 21, 18] {
        refused(
            case(
                &format!("lifecycle/minter merge/18 and 4 make {total}"),
                &[PY],
                "the retiring minter passes by itself, as in the earlier check",
            ),
            &shapes::mint_reclaim_into(&script()),
            |scenario| minter_output(scenario, 0).remaining = total,
            0,
            "M-49",
            300,
            &[1],
        );
    }
}

#[test]
fn lifecycle_minter_the_retiring_minter_asks_its_own_owner() {
    const PY: &str = "test_lifecycle.MinterLifecycle.test_the_retiring_minter_asks_its_own_owner";
    refused(
        case(
            "lifecycle/minter merge/the retiring minter signed by the survivor's owner",
            &[PY],
            "the earlier check compared the text of the line, which is also the text of line \
             249; the survivor passes",
        ),
        &shapes::mint_reclaim_into(&script()),
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() = witness::signature(ALICE, SIG_HASH_ALL)
        },
        1,
        "M-57",
        324,
        &[0],
    );
}

#[test]
fn lifecycle_minter_minters_with_different_per_mint_limits_do_not_merge() {
    const PY: &str = "test_lifecycle.MinterLifecycle.\
        test_minters_with_different_per_mint_limits_do_not_merge";
    refused(
        case(
            "lifecycle/minter merge/the retiring minter mints 11 at a time, the survivor 10",
            &[PY],
            "the earlier check ran the retiring minter and discarded its answer; here it \
             passes",
        ),
        &shapes::mint_reclaim_into(&script()),
        |scenario| {
            scenario
                .contract_input_mut(1)
                .state
                .as_public_mint_mut()
                .expect("the retiring minter")
                .mint_amount = 11
        },
        0,
        "M-45",
        279,
        &[1],
    );
}

// ---------------------------------------------------------------------------------------
// test_lifecycle: a seed
// ---------------------------------------------------------------------------------------

#[test]
fn lifecycle_seed_anyone_adds_a_second_seed_of_the_same_family() {
    const PY: &str =
        "test_lifecycle.SeedLifecycle.test_anyone_adds_a_second_seed_of_the_same_family";
    case(
        "lifecycle/seed split/a second seed of Bob",
        &[PY],
        "nobody signs",
    )
    .expect_accept(&split());
    refused(
        case(
            "lifecycle/seed split/a second seed of another family",
            &[PY],
            "",
        ),
        &split(),
        |scenario| seed_output(scenario, 1).extension_commitment = OTHER_FAMILY,
        0,
        "S-25",
        196,
        &[1],
    );
}

#[test]
fn lifecycle_seed_a_retiring_seed_gives_its_deposit_back_while_another_seed_survives() {
    const PY: &str = "test_lifecycle.SeedLifecycle.\
        test_a_retiring_seed_gives_its_deposit_back_while_another_seed_survives";
    case(
        "lifecycle/seed reclaim/Bob's seed retires, Bob signs",
        &[PY],
        "the survivor signs nothing; the transaction pays no fee",
    )
    .expect_accept(&reclaim());
    refused(
        case(
            "lifecycle/seed reclaim/Bob's seed retires, Alice signs",
            &[PY],
            "the survivor passes in this run too",
        ),
        &reclaim(),
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() = witness::signature(ALICE, SIG_HASH_ALL)
        },
        1,
        "S-43",
        254,
        &[0],
    );
}

#[test]
fn lifecycle_seed_a_lone_seed_cannot_be_reclaimed() {
    const PY: &str = "test_lifecycle.SeedLifecycle.test_a_lone_seed_cannot_be_reclaimed";
    const NOTE: &str = "Alice's seed alone pays its deposit to a plain coin of Alice. The \
        earlier check ran both entries on one described transaction; the entry is part of the \
        signature script, so these are two transactions.";
    // The seed alone, its deposit to its owner's key.
    let alone = |scenario: &mut Scenario| {
        scenario.inputs.truncate(1);
        scenario.outputs = vec![OutputSpec::Plain(pay_to(ALICE, shapes::SCRIPT_COIN_VALUE))];
    };
    refused(
        case(
            "lifecycle/seed reclaim/a lone seed runs reclaim",
            &[PY],
            NOTE,
        ),
        &reclaim(),
        alone,
        0,
        "S-26",
        207,
        &[],
    );
    refused(
        case(
            "lifecycle/seed reclaim/a lone seed runs reclaim_delegator, its owner signs",
            &[PY],
            NOTE,
        ),
        &reclaim(),
        |scenario| {
            alone(scenario);
            scenario.contract_input_mut(0).call = Call::typed(
                Entry::SeedReclaimDelegator,
                vec![Arg::Bytes(witness::signature(ALICE, SIG_HASH_ALL))],
            );
        },
        0,
        "S-37",
        241,
        &[],
    );
}

// ---------------------------------------------------------------------------------------
// The accepted transactions in coin values a node takes
// ---------------------------------------------------------------------------------------

/// The cases above run the scripts of whole transactions in the 1000-sompi coins of the
/// script-only profile and ask no block and no mempool. Here the same calls and states are
/// put into 10 KAS coins with a signed funding coin, change and a fee, and a default node
/// takes each of them into its mempool.
#[test]
fn the_accepted_transactions_pass_a_default_node_in_realistic_coin_values() {
    const B_SEED_OPEN: &str = "B_seed.test_b_seed.CreatorChoosesOwnerAndPolicy.\
        test_a_coin_for_bob_who_did_not_ask_then_anyone_adds_to_it";
    const B_SEED_OFF: &str = "B_seed.test_b_seed.CreatorChoosesOwnerAndPolicy.\
        test_contrast_a_coin_with_borrowing_off_cannot_be_added_to";
    const B_SEED_COVENANT: &str = "B_seed.test_b_seed.CreatorChoosesOwnerAndPolicy.\
        test_a_coin_owned_by_the_token_covenant_itself";
    const B_SEED_OWNER_SCHEME: &str =
        "B_seed.test_b_seed.Create.test_recipient_owner_scheme_out_of_range";
    const B_SEED_BORROW_SCHEME: &str =
        "B_seed.test_b_seed.Create.test_recipient_borrow_scheme_out_of_range";
    const CREATE_ANYONE: &str = "test_token_seed.TokenSeedCreate.\
        test_anyone_creates_an_empty_coin_with_a_chosen_owner_and_policy";
    const LIFE_OF_A_COIN: &str = "test_token_seed.TokenSeedCreate.\
        test_a_created_coin_can_be_paid_into_and_then_spent_by_its_owner";
    const MINTER_SPLIT: &str =
        "test_lifecycle.MinterLifecycle.test_anyone_splits_off_up_to_half_of_the_allowance";
    const MINTER_RECLAIM: &str =
        "test_lifecycle.MinterLifecycle.test_the_owner_takes_the_deposit_of_an_exhausted_minter";
    const MINTER_MERGE: &str = "test_lifecycle.MinterLifecycle.\
        test_a_retiring_minter_returns_its_allowance_to_a_surviving_one";
    const SEED_SPLIT: &str =
        "test_lifecycle.SeedLifecycle.test_anyone_adds_a_second_seed_of_the_same_family";
    const SEED_RECLAIM: &str = "test_lifecycle.SeedLifecycle.\
        test_a_retiring_seed_gives_its_deposit_back_while_another_seed_survives";

    // The default fee of the realistic profile, 0.001 KAS, is under the fee floor of the
    // mempool for each of these transactions (between 0.004 KAS for a seed split and
    // 0.018 KAS for a borrowed receive; a create needs 0.0117 KAS), so the fee is
    // 0.05 KAS here.
    let realistic = Profile::Realistic(Realistic {
        fee: shapes::SOMPI_PER_KAS / 20,
        ..Realistic::default()
    });
    let open = empty_coin().with_threshold(0);
    let split_taking = |take: i64| {
        let mut scenario = shapes::mint_split(&realistic);
        set_take(&mut scenario, take);
        scenario
    };
    let covenant_owned = Kcc20State::new(shapes::COVENANT_ID_BYTES, 0)
        .with_owner(OWNER_COVENANT_ID, shapes::COVENANT_ID_BYTES)
        .with_threshold(0);

    let accepted: Vec<(&str, &[&str], Scenario)> = vec![
        (
            "create a plain empty coin",
            &[CREATE_ANYONE, B_SEED_OFF],
            create_in(&realistic, empty_coin()),
        ),
        (
            "create an empty coin with threshold 10",
            &[CREATE_ANYONE],
            create_in(&realistic, empty_coin().with_threshold(10)),
        ),
        (
            "create an empty coin with threshold 0",
            &[CREATE_ANYONE, LIFE_OF_A_COIN, B_SEED_OPEN],
            create_in(&realistic, open.clone()),
        ),
        (
            "create a coin with owner scheme 0x04",
            &[B_SEED_OWNER_SCHEME],
            create_in(
                &realistic,
                empty_coin().with_owner(OWNER_COVENANT_ID, keys::x_only(BOB)),
            ),
        ),
        (
            "create a coin with borrow scheme 0x03",
            &[B_SEED_BORROW_SCHEME],
            create_in(
                &realistic,
                empty_coin().with_borrow(BORROW_HASH_CHAIN, [0; 32]),
            ),
        ),
        (
            "create a coin owned by the token's own covenant id",
            &[B_SEED_COVENANT],
            create_in(&realistic, covenant_owned),
        ),
        (
            "a stranger adds 1 token to an empty coin with threshold 0",
            &[B_SEED_OPEN],
            pay_into_in(&realistic, open.clone(), CAROL, 1),
        ),
        (
            "Alice pays 30 into an empty coin with threshold 0",
            &[LIFE_OF_A_COIN],
            pay_into_in(&realistic, open.clone(), ALICE, 30),
        ),
        (
            "the owner spends the coin that was paid into",
            &[LIFE_OF_A_COIN],
            owner_spends_in(&realistic, open.with_amount(30), BOB, ALICE),
        ),
        (
            "a minter hands over 7 of 25",
            &[MINTER_SPLIT],
            split_taking(7),
        ),
        (
            "a minter hands over 12 of 25",
            &[MINTER_SPLIT],
            split_taking(12),
        ),
        (
            "a minter hands over 1 of 25",
            &[MINTER_SPLIT],
            split_taking(1),
        ),
        (
            "the owner closes an exhausted minter",
            &[MINTER_RECLAIM],
            shapes::mint_reclaim(&realistic),
        ),
        (
            "a retiring minter returns its allowance",
            &[MINTER_MERGE],
            shapes::mint_reclaim_into(&realistic),
        ),
        (
            "a seed adds a second seed",
            &[SEED_SPLIT],
            shapes::seed_split(&realistic),
        ),
        (
            "a retiring seed gives its deposit back",
            &[SEED_RECLAIM],
            shapes::seed_reclaim(&realistic),
        ),
    ];
    for (name, py_ids, scenario) in accepted {
        case(
            &format!("realistic/{name}"),
            py_ids,
            "the accepted transaction of the earlier check in 10 KAS coins, with a signed \
             funding coin, change and a fee of 0.05 KAS: a default node takes it into its \
             mempool",
        )
        .expect_mempool_accept(&scenario);
    }
}
