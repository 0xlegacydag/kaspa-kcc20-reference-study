//! Probes of the token, transfer and borrow cases (`port_token.rs`, `port_transfer.rs`,
//! `port_borrow.rs`): is a refusal refused for the reason its case names?
//!
//! Each probe rebuilds one refusal case of those files from their scenario builders, copied
//! here (the three probes `negative output/..` are cases of this file only), and asks three
//! things:
//!
//! 1. on the pinned contracts the honest side passes and the named input of the changed
//!    side is refused by the named rule at the named source line;
//! 2. with the refusing opcode neutralised (`OpVerify` by `OpDrop`, `OpEqualVerify` and
//!    `OpNumEqualVerify` by `Op2Drop`, at the byte the engine stopped at) the honest side
//!    still passes;
//! 3. on that weakened family the named input of the changed side passes, or stops at
//!    another opcode and another rule.
//!
//! A refusal that stays where it was with the rule removed is not a refusal by that rule: a
//! stale signature, a lock that does not match or a codec refusal would not move.
//!
//! Every probe prints one line (`cargo test .. -- --nocapture`), and each test counts what
//! the removals led to. The byte that is neutralised must be one the rule inventory lists
//! for the rule, in `bytecode_at` or, for the copy of the owner rules inlined in
//! `transfer_delegator`, in `also_reached_from`.
//!
//! Three more tests, at the end of the file, hold what a removal cannot show:
//!
//! - a signature of each signature hash type carries its type byte, read here with code
//!   of its own;
//! - the 23 transactions of the conformance vector answer the same when the transaction
//!   around the vector's states, values and witnesses is built here and not taken from a
//!   shape of the family crate;
//! - the funding coin `port_transfer.rs` adds changes no answer of a token input.
//!
//! No case here writes a result line: the cases are those of the three files.

use checks::{Expected, Harness, Outcome, RunOutcome, judge_accept, judge_input};
use kaspa_consensus_core::{
    Hash,
    hashing::sighash_type::{
        SIG_HASH_ALL, SIG_HASH_ANY_ONE_CAN_PAY, SIG_HASH_NONE, SIG_HASH_SINGLE, SigHashType,
    },
    tx::{CovenantBinding, Transaction},
};
use kaspa_txscript::{
    opcodes::codes::{Op2Drop, OpDrop, OpEqualVerify, OpNumEqualVerify, OpVerify},
    pay_to_script_hash_script,
};
use kcc20_family::{
    Contract, Entry, EntryRole, Family, Scenario, State,
    keys::{self, ALICE, BOB, CAROL, DAVE, SigningContext},
    raw, refdata,
    scenario::{
        Arg, Call, ContractInput, ContractOutput, InputSpec, LateBytes, OrdinaryInput, OutputSpec,
        PlainOutput,
    },
    shapes::{self, BorrowKind, Profile},
    states::{
        BORROW_HASH_CHAIN, Kcc20State, OWNER_COVENANT_ID, OWNER_P2PKH_ECDSA, OWNER_P2PKH_SCHNORR,
        OWNER_P2SH, PATH_BORROW, PATH_NORMAL, PublicMintState, TokenSeedState,
    },
    witness,
};
use serde_json::Value;

const MALLORY: u8 = DAVE;
const COIN: u64 = shapes::SCRIPT_COIN_VALUE;

// ---------------------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------------------

/// The byte offsets the rule inventory lists for the refusing opcode of `rule`: the
/// offsets of the entry the rule is filed under, and those of the copy of an inlined
/// helper in another entry (`also_reached_from`).
fn inventory_offsets(rule: &str) -> Vec<usize> {
    let text = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../data/rule-inventory.json"
    ));
    let inventory: Value = serde_json::from_str(text).expect("the rule inventory is JSON");
    let entry = inventory["rules"]
        .as_array()
        .expect("the inventory lists rules")
        .iter()
        .find(|entry| entry["rule_id"] == rule)
        .unwrap_or_else(|| panic!("the inventory has no rule {rule}"))
        .clone();
    let numbers = |list: &Value| -> Vec<usize> {
        list.as_array()
            .map(|offsets| {
                offsets
                    .iter()
                    .filter_map(|offset| offset.as_u64())
                    .map(|offset| offset as usize)
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut offsets = numbers(&entry["bytecode_at"]);
    if let Some(copies) = entry["also_reached_from"].as_array() {
        for copy in copies {
            offsets.extend(numbers(&copy["bytecode_at"]));
        }
    }
    offsets
}

fn contract_of(rule: &str) -> Contract {
    match rule.as_bytes()[0] {
        b'K' => Contract::Kcc20,
        b'M' => Contract::PublicMint,
        b'S' => Contract::TokenSeed,
        _ => panic!("rule {rule} belongs to no contract"),
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

fn judged(outcome: &Outcome, input: usize) -> Option<&RunOutcome> {
    outcome
        .inputs
        .get(input)
        .and_then(|input| input.alone.as_ref())
}

/// What a removal led to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum After {
    /// The input passes without the rule.
    Passes,
    /// The input stops at another opcode: what refuses there and the byte offset.
    Moves(String, Option<usize>),
}

/// One probe: see the head of the file. `Err` describes what did not hold.
fn removal(
    name: &str,
    honest: &Scenario,
    changed: &Scenario,
    input: usize,
    rule: &str,
    line: u32,
) -> Result<After, String> {
    let fail = |what: String| format!("probe `{name}` ({rule}, line {line}): {what}");

    let pinned_honest = checks::run(honest);
    judge_accept(&pinned_honest).map_err(|failure| fail(format!("the honest side: {failure}")))?;
    for (index, each) in pinned_honest.inputs.iter().enumerate() {
        let run = each
            .alone
            .as_ref()
            .ok_or_else(|| fail(format!("honest input {index} was not run")))?;
        if run.accepted_unknown_version {
            return Err(fail(format!("honest input {index} passed without running")));
        }
    }

    let pinned = checks::run(changed);
    judge_input(&pinned, input, &Expected::rule(rule).at_line(line))
        .map_err(|failure| fail(format!("on the pinned contracts: {failure}")))?;
    let refusal = judged(&pinned, input)
        .and_then(|run| run.refusal.as_ref())
        .ok_or_else(|| fail("no attribution".to_string()))?;
    let offset = refusal
        .byte_offset
        .ok_or_else(|| fail("the refusal has no byte offset".to_string()))?;
    if !inventory_offsets(rule).contains(&offset) {
        return Err(fail(format!(
            "the engine stopped at byte {offset}, which the inventory does not list for the rule"
        )));
    }

    let weakened = family_without_check(contract_of(rule), offset)
        .ok_or_else(|| fail(format!("byte {offset} is not a verify opcode")))?;
    let harness = Harness::pinned().with_family(weakened);
    judge_accept(&harness.run(honest)).map_err(|failure| {
        fail(format!(
            "without the check the honest side fails: {failure}"
        ))
    })?;
    let outcome = harness.run(changed);
    let run = judged(&outcome, input)
        .ok_or_else(|| fail("without the check the input was not run".to_string()))?;
    let after = if run.ok {
        After::Passes
    } else {
        let moved = run
            .refusal
            .as_ref()
            .ok_or_else(|| fail("the moved refusal has no attribution".to_string()))?;
        if moved.contract.is_some() && moved.byte_offset == Some(offset) {
            return Err(fail(format!(
                "without the check at byte {offset} the input is still refused there: {}",
                run.describe()
            )));
        }
        if moved.rule.as_deref() == Some(rule) && moved.byte_offset == Some(offset) {
            return Err(fail(format!(
                "without the check the same rule still refuses: {}",
                run.describe()
            )));
        }
        After::Moves(moved.refused_by.clone(), moved.byte_offset)
    };
    println!(
        "REMOVAL {name}: input {input}, {rule} line {line}, byte {offset} -> {after:?}; whole \
         changed transaction without the check: {}",
        if outcome.scripts_accept() {
            "scripts accept".to_string()
        } else {
            format!("refused inputs {:?}", outcome.scripts.refused_inputs)
        }
    );
    Ok(after)
}

/// Runs the probes of one test and fails with every probe that did not hold.
fn hold(results: Vec<Result<After, String>>, at_least: usize) -> (usize, usize) {
    let failures: Vec<&String> = results
        .iter()
        .filter_map(|each| each.as_ref().err())
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} probes did not hold:\n{}",
        failures.len(),
        results.len(),
        failures
            .iter()
            .map(|each| each.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(results.len() >= at_least, "{} probes", results.len());
    let passes = results
        .iter()
        .filter(|each| **each == Ok(After::Passes))
        .count();
    println!(
        "REMOVAL SUMMARY: {} probes, {} pass without the rule, {} stop at another opcode",
        results.len(),
        passes,
        results.len() - passes
    );
    (passes, results.len() - passes)
}

fn after(change: impl FnOnce(&mut Scenario), honest: &Scenario) -> Scenario {
    let mut changed = honest.clone();
    change(&mut changed);
    changed
}

// ---------------------------------------------------------------------------------------
// The builders of port_token.rs
// ---------------------------------------------------------------------------------------

mod token_port {
    use super::*;

    pub fn token(owner_seed: u8, amount: i64) -> Kcc20State {
        Kcc20State::new(keys::x_only(owner_seed), amount)
    }

    pub fn leader_signature(key_seed: u8) -> LateBytes {
        witness::owner_key(key_seed, EntryRole::Leader, SIG_HASH_ALL)
    }

    pub fn delegate_signature(key_seed: u8) -> LateBytes {
        witness::owner_key(key_seed, EntryRole::Delegate, SIG_HASH_ALL)
    }

    fn bound_to_leader() -> Option<CovenantBinding> {
        Some(CovenantBinding::new(0, shapes::covenant_id()))
    }

    pub fn token_transfer(
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

    pub fn leader_and_delegate(delegate: Kcc20State, delegate_witness: LateBytes) -> Scenario {
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

    pub fn tokens_in_out(in_amounts: &[i64], out_amounts: &[i64]) -> Scenario {
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

    pub fn lone(before: Kcc20State, after: Vec<Kcc20State>, witness: LateBytes) -> Scenario {
        token_transfer("lone token coin", vec![(before, witness)], after)
    }

    pub fn funded(mut scenario: Scenario) -> Scenario {
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

    pub fn borrow_receive(
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

    pub fn op_true_coin(position: u32, covenant_id: Option<[u8; 32]>) -> OrdinaryInput {
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

    pub fn key_hash_witness(
        public_key_of: u8,
        signer: u8,
        signed_input: Option<usize>,
    ) -> LateBytes {
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

    pub fn key_and_placeholder_signature(public_key: &[u8]) -> LateBytes {
        let mut witness = public_key.to_vec();
        witness.extend([0u8; 64]);
        witness.push(SIG_HASH_ALL.to_u8());
        LateBytes::fixed(witness)
    }

    pub fn ecdsa_key_hash_witness(public_key_of: u8, signer: u8) -> LateBytes {
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

    pub fn script_hash_delegate(named_input: u8) -> Scenario {
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

    pub const OTHER_COVENANT: [u8; 32] = [0x33; 32];
    pub const THIRD_COVENANT: [u8; 32] = [0x44; 32];
    pub const OTHER_FAMILY: [u8; 32] = [0xee; 32];

    pub fn covenant_owned_delegate(carried: Option<[u8; 32]>) -> Scenario {
        let delegate =
            Kcc20State::new(OTHER_COVENANT, 50).with_owner(OWNER_COVENANT_ID, OTHER_COVENANT);
        let mut scenario =
            leader_and_delegate(delegate, witness::owner_covenant_id(EntryRole::Delegate));
        scenario.push_ordinary_input(op_true_coin(2, carried));
        scenario
    }

    pub fn alice_pays_bob(amount: i64, outputs: &[i64]) -> Scenario {
        lone(
            token(ALICE, amount),
            outputs.iter().map(|amount| token(BOB, *amount)).collect(),
            leader_signature(ALICE),
        )
    }

    pub fn mint_of(amount: i64) -> Scenario {
        let mut scenario = shapes::mint(&Profile::Script);
        scenario.contract_input_mut(0).declared_state_mut().amount = amount;
        scenario.contract_output_mut(1).state = token(BOB, amount).into();
        scenario
            .contract_output_mut(0)
            .state
            .as_public_mint_mut()
            .expect("the successor of the minter")
            .remaining = 25 - amount;
        scenario
    }

    pub fn create_of(amount: i64) -> Scenario {
        let mut scenario = shapes::seed_create(&Profile::Script);
        *scenario.contract_input_mut(0).declared_state_mut() = token(BOB, amount);
        scenario.contract_output_mut(1).state = token(BOB, amount).into();
        scenario
    }

    pub fn threshold_coin(amount: i64, threshold: i64) -> Kcc20State {
        token(BOB, amount).with_threshold(threshold)
    }

    pub fn threshold_receive(threshold: i64, growth: i64) -> Scenario {
        borrow_receive(
            threshold_coin(200, threshold),
            threshold_coin(200 + growth, threshold),
            witness::borrow_threshold(),
            100,
        )
    }

    pub fn lone_borrower(before: Kcc20State, after: Kcc20State) -> Scenario {
        lone(before, vec![after], witness::borrow_threshold())
    }

    pub const CHAIN_KEY_1: u8 = CAROL;
    pub const CHAIN_KEY_2: u8 = DAVE;

    pub fn chain() -> ([u8; 32], [u8; 32], [u8; 32]) {
        let link2 = [0x55; 32];
        let link1 = witness::chain_guard(&link2, CHAIN_KEY_2);
        let guard0 = witness::chain_guard(&link1, CHAIN_KEY_1);
        (guard0, link1, link2)
    }

    pub fn chain_coin(amount: i64, guard: [u8; 32]) -> Kcc20State {
        token(BOB, amount).with_borrow(BORROW_HASH_CHAIN, guard)
    }

    pub fn foreign_coin(state: impl Into<State>, call: Call) -> ContractInput {
        ContractInput::new(
            state,
            COIN,
            Some(shapes::covenant_id()),
            shapes::outpoint(1, 2),
            call,
        )
        .labelled("a coin of another contract of the family")
    }

    pub fn three_with_foreign(foreign: ContractInput, out_amount: i64) -> Scenario {
        let mut scenario = tokens_in_out(&[100, 50], &[out_amount]);
        scenario.push_contract_input(foreign);
        scenario
    }

    pub fn foreign_minter() -> PublicMintState {
        PublicMintState::new(keys::x_only(CAROL), 1_000, 10)
    }

    pub fn foreign_seed() -> TokenSeedState {
        TokenSeedState::new(keys::x_only(CAROL))
    }

    pub fn three_token_coins() -> Scenario {
        tokens_in_out(&[100, 50, 25], &[175])
    }

    pub fn sighash_types() -> [(&'static str, SigHashType); 6] {
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
}

#[test]
fn port_token_refusals_move_when_their_rule_is_removed() {
    use token_port::*;
    let mut results = Vec::new();

    // Owner schemes on a delegate.
    let owner = witness::public_key_hash(&keys::x_only(BOB));
    let honest = leader_and_delegate(
        Kcc20State::new(owner, 50).with_owner(OWNER_P2PKH_SCHNORR, owner),
        witness::owner_key_hash_schnorr(BOB, EntryRole::Delegate, SIG_HASH_ALL),
    );
    let witnesses: [(&str, LateBytes, &str, u32); 4] = [
        (
            "p2pkh-schnorr delegate/a stranger's key and signature",
            witness::owner_key_hash_schnorr(MALLORY, EntryRole::Delegate, SIG_HASH_ALL),
            "K-40",
            78,
        ),
        (
            "p2pkh-schnorr delegate/the owner's key, a stranger's signature",
            key_hash_witness(BOB, MALLORY, None),
            "K-41",
            79,
        ),
        (
            "p2pkh-schnorr delegate/the owner's key, 64 zero bytes",
            key_and_placeholder_signature(&keys::x_only(BOB)),
            "K-41",
            79,
        ),
        (
            "p2pkh-schnorr delegate/the owner's signature for the leader's input",
            key_hash_witness(BOB, BOB, Some(0)),
            "K-41",
            79,
        ),
    ];
    for (name, bytes, rule, line) in witnesses {
        let changed = after(|s| *s.contract_input_mut(1).witness_mut() = bytes, &honest);
        results.push(removal(name, &honest, &changed, 1, rule, line));
    }

    let owner = witness::public_key_hash(&keys::compressed(BOB));
    let honest = leader_and_delegate(
        Kcc20State::new(owner, 50).with_owner(OWNER_P2PKH_ECDSA, owner),
        witness::owner_key_hash_ecdsa(BOB, EntryRole::Delegate, SIG_HASH_ALL),
    );
    let witnesses: [(&str, LateBytes, &str, u32); 2] = [
        (
            "p2pkh-ecdsa delegate/another key pair",
            witness::owner_key_hash_ecdsa(MALLORY, EntryRole::Delegate, SIG_HASH_ALL),
            "K-43",
            85,
        ),
        (
            "p2pkh-ecdsa delegate/the owner's key, another key's signature",
            ecdsa_key_hash_witness(BOB, MALLORY),
            "K-44",
            86,
        ),
    ];
    for (name, bytes, rule, line) in witnesses {
        let changed = after(|s| *s.contract_input_mut(1).witness_mut() = bytes, &honest);
        results.push(removal(name, &honest, &changed, 1, rule, line));
    }

    let honest = script_hash_delegate(2);
    for index in [0u8, 1, 3] {
        results.push(removal(
            &format!("p2sh delegate/the witness names input {index}"),
            &honest,
            &script_hash_delegate(index),
            1,
            "K-46",
            90,
        ));
    }

    let honest = covenant_owned_delegate(Some(OTHER_COVENANT));
    results.push(removal(
        "covenant-id delegate/input 2 carries no covenant id",
        &honest,
        &covenant_owned_delegate(None),
        1,
        "K-48",
        96,
    ));
    results.push(removal(
        "covenant-id delegate/input 2 carries a third covenant id",
        &honest,
        &covenant_owned_delegate(Some(THIRD_COVENANT)),
        1,
        "K-48",
        96,
    ));

    // Bounds.
    results.push(removal(
        "output count/four outputs, funded",
        &funded(alice_pays_bob(100, &[25, 25, 50])),
        &funded(alice_pays_bob(100, &[25; 4])),
        0,
        "K-22",
        156,
    ));
    for amount in [100, 0] {
        let honest = lone(
            token(ALICE, amount),
            vec![token(BOB, amount)],
            leader_signature(ALICE),
        );
        let none = lone(token(ALICE, amount), Vec::new(), leader_signature(ALICE));
        results.push(removal(
            &format!("output count/a coin of {amount}, no output at all"),
            &honest,
            &none,
            0,
            "K-21",
            155,
        ));
        let mut plain = none.clone();
        plain.push_plain_output(PlainOutput::new(shapes::op_true_script(), COIN));
        results.push(removal(
            &format!("output count/a coin of {amount}, one ordinary output"),
            &honest,
            &plain,
            0,
            "K-21",
            155,
        ));
    }

    // An amount below zero on an output: cases of this file only.
    let splits = |bob: i64, alice: i64| {
        funded(lone(
            token(ALICE, 100),
            vec![token(BOB, bob), token(ALICE, alice)],
            leader_signature(ALICE),
        ))
    };
    results.push(removal(
        "negative output/transfer 100 into 105 and -5, funded",
        &splits(100, 0),
        &splits(105, -5),
        0,
        "K-32",
        169,
    ));
    results.push(removal(
        "negative output/mint -5",
        &mint_of(5),
        &mint_of(-5),
        0,
        "M-12",
        136,
    ));
    results.push(removal(
        "negative output/create a coin of -5",
        &create_of(0),
        &create_of(-5),
        0,
        "S-12",
        132,
    ));

    // Corners of the borrow path.
    let honest = threshold_receive(10, 11);
    for grown in [211, 201, i64::MAX] {
        results.push(removal(
            &format!("lone borrower/200 into {grown} without a payer"),
            &honest,
            &lone_borrower(threshold_coin(200, 10), threshold_coin(grown, 10)),
            0,
            "K-37",
            175,
        ));
    }
    results.push(removal(
        "lone borrower/unchanged, threshold 10",
        &honest,
        &lone_borrower(threshold_coin(200, 10), threshold_coin(200, 10)),
        0,
        "K-61",
        219,
    ));
    results.push(removal(
        "lone borrower/unchanged, threshold 0",
        &threshold_receive(0, 1),
        &lone_borrower(threshold_coin(200, 0), threshold_coin(200, 0)),
        0,
        "K-61",
        219,
    ));
    let other_family = after(
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
        &honest,
    );
    results.push(removal(
        "borrow family/the successor is of another family",
        &honest,
        &other_family,
        0,
        "K-35",
        172,
    ));

    let (guard0, link1, link2) = chain();
    let honest_witness = || witness::borrow_hash_chain(link1, CHAIN_KEY_1, SIG_HASH_ALL);
    let honest = borrow_receive(
        chain_coin(200, guard0),
        chain_coin(201, link1),
        honest_witness(),
        100,
    );
    type Damage = fn(Vec<u8>) -> Vec<u8>;
    let damages: [(&str, Damage); 3] = [
        ("128 bytes", |mut witness| {
            witness.pop();
            witness
        }),
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
        let changed = after(
            |s| *s.contract_input_mut(0).witness_mut() = honest_witness().map(damage),
            &honest,
        );
        results.push(removal(
            &format!("chain witness/{label}"),
            &honest,
            &changed,
            0,
            "K-53",
            197,
        ));
    }
    let second = borrow_receive(
        chain_coin(201, link1),
        chain_coin(202, link2),
        witness::borrow_hash_chain(link2, CHAIN_KEY_2, SIG_HASH_ALL),
        99,
    );
    for (label, successor_guard) in [("link 1", link1), ("link 2", link2)] {
        results.push(removal(
            &format!("chain link/link 1 again, the successor guarded by {label}"),
            &second,
            &borrow_receive(
                chain_coin(201, link1),
                chain_coin(202, successor_guard),
                witness::borrow_hash_chain(link1, CHAIN_KEY_1, SIG_HASH_ALL),
                99,
            ),
            0,
            "K-54",
            205,
        ));
    }

    // Signature hash types: a stranger signs with each type; the honest side is the owner's
    // signature of type All.
    for (name, hash_type) in sighash_types() {
        let honest = lone(
            token(ALICE, 100),
            vec![token(BOB, 100)],
            leader_signature(ALICE),
        );
        let changed = after(
            |s| {
                *s.contract_input_mut(0).witness_mut() =
                    witness::owner_key(MALLORY, EntryRole::Leader, hash_type)
            },
            &honest,
        );
        results.push(removal(
            &format!("sighash stranger/{name}"),
            &honest,
            &changed,
            0,
            "K-38",
            69,
        ));
    }

    // A minter or a seed as the third input: its own refusal.
    let carol_signs = || Arg::Bytes(witness::signature(CAROL, SIG_HASH_ALL));
    let carol = || Arg::bytes(keys::x_only(CAROL));
    let minter_calls: Vec<(Entry, Vec<Arg>, &str, u32)> = vec![
        (Entry::Mint, vec![Arg::State(token(CAROL, 10))], "M-10", 127),
        (Entry::MintSplit, vec![Arg::int(1), carol()], "M-24", 187),
        (Entry::MintReclaim, vec![carol_signs()], "M-32", 243),
        (Entry::MintReclaimInto, Vec::new(), "M-36", 260),
    ];
    let seed_calls: Vec<(Entry, Vec<Arg>, &str, u32)> = vec![
        (
            Entry::SeedCreate,
            vec![Arg::State(token(CAROL, 0))],
            "S-10",
            123,
        ),
        (Entry::SeedSplit, vec![carol()], "S-21", 167),
        (Entry::SeedReclaim, Vec::new(), "S-26", 207),
    ];
    let honest = three_token_coins();
    let mut foreign: Vec<(String, ContractInput, &str, u32)> = Vec::new();
    for (entry, args, rule, line) in minter_calls {
        foreign.push((
            format!("PublicMint.{}", Entry::name(entry)),
            foreign_coin(foreign_minter(), Call::typed(entry, args)),
            rule,
            line,
        ));
    }
    for (entry, args, rule, line) in seed_calls {
        foreign.push((
            format!("TokenSeed.{}", Entry::name(entry)),
            foreign_coin(foreign_seed(), Call::typed(entry, args)),
            rule,
            line,
        ));
    }
    for (name, coin, rule, line) in foreign {
        let changed = three_with_foreign(coin, 150);
        results.push(removal(
            &format!("mixed/{name} as the third input"),
            &honest,
            &changed,
            2,
            rule,
            line,
        ));
    }

    hold(results, 12);
}

// ---------------------------------------------------------------------------------------
// The builders of port_transfer.rs
// ---------------------------------------------------------------------------------------

mod transfer_port {
    use super::*;

    pub const TOKEN_SOMPI: u64 = 1_000;

    pub fn token(owner_seed: u8, amount: i64) -> Kcc20State {
        Kcc20State::new(keys::x_only(owner_seed), amount)
    }

    pub struct Coin {
        pub state: Kcc20State,
        pub value: u64,
        pub witness: LateBytes,
    }

    pub fn alice_coin(amount: i64, value: u64) -> Coin {
        Coin {
            state: token(ALICE, amount),
            value,
            witness: witness::owner_key(ALICE, EntryRole::Leader, SIG_HASH_ALL),
        }
    }

    fn fund(mut scenario: Scenario) -> Scenario {
        let missing = scenario.total_out().saturating_sub(scenario.total_in());
        if missing > 0 {
            scenario.push_ordinary_input(
                OrdinaryInput::new(
                    shapes::op_true_script(),
                    missing,
                    shapes::outpoint(3, 0),
                    LateBytes::empty(),
                )
                .labelled("funding (OP_TRUE)"),
            );
        }
        scenario
    }

    pub fn transfer_of(coins: Vec<Coin>, outputs: Vec<(Kcc20State, u64)>) -> Scenario {
        let mut scenario = shapes::transfer(&Profile::Script, coins.len(), outputs.len());
        for (index, coin) in coins.into_iter().enumerate() {
            let input = scenario.contract_input_mut(index);
            input.state = coin.state.into();
            input.value = coin.value;
            *input.witness_mut() = coin.witness;
        }
        for (index, (state, value)) in outputs.into_iter().enumerate() {
            scenario.contract_input_mut(0).declared_states_mut()[index] = state.clone();
            let output = scenario.contract_output_mut(index);
            output.state = state.into();
            output.value = value;
        }
        fund(scenario)
    }

    pub fn spend(parts: &[(u8, i64)]) -> Scenario {
        transfer_of(
            vec![alice_coin(100, TOKEN_SOMPI)],
            parts
                .iter()
                .map(|(owner, amount)| (token(*owner, *amount), TOKEN_SOMPI))
                .collect(),
        )
    }

    pub fn sixty_forty() -> Scenario {
        spend(&[(BOB, 60), (ALICE, 40)])
    }

    pub fn change_token_output(
        scenario: &mut Scenario,
        index: usize,
        change: impl Fn(&mut Kcc20State),
    ) {
        change(&mut scenario.contract_input_mut(0).declared_states_mut()[index]);
        change(
            scenario
                .contract_output_mut(index)
                .state
                .as_kcc20_mut()
                .expect("a token output"),
        );
    }

    pub fn normal_path(owner_witness: impl AsRef<[u8]>) -> LateBytes {
        let mut witness = vec![PATH_NORMAL];
        witness.extend_from_slice(owner_witness.as_ref());
        LateBytes::fixed(witness)
    }

    pub fn signed_for_another_transaction(
        alter: impl Fn(&mut Transaction) + Send + Sync + 'static,
    ) -> LateBytes {
        LateBytes::from_tx(move |ctx| {
            let mut other = ctx.tx.clone();
            alter(&mut other.tx);
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
    }

    pub fn owner_scheme_transfer(scheme: u8) -> Scenario {
        shapes::transfer_with_owner_scheme(&Profile::Script, EntryRole::Leader, scheme)
    }

    pub fn owned_by_another_covenant() -> Scenario {
        let mut scenario = owner_scheme_transfer(OWNER_COVENANT_ID);
        let other = scenario.ordinary_input_mut(1);
        other.script_public_key = shapes::op_true_script();
        other.signature_script = LateBytes::empty();
        scenario
    }

    pub const NEXT_GUARD: [u8; 32] = [0x77; 32];
    pub const WRONG_LINK: [u8; 32] = [0x78; 32];

    pub fn hash_chain_receive() -> Scenario {
        let mut scenario = shapes::borrow(&Profile::Script, BorrowKind::HashChain);
        let leader = scenario.contract_input_mut(0);
        leader
            .state
            .as_kcc20_mut()
            .expect("a token coin")
            .borrow_guard = witness::chain_guard(&NEXT_GUARD, CAROL);
        *leader.witness_mut() = witness::borrow_hash_chain(NEXT_GUARD, CAROL, SIG_HASH_ALL);
        change_token_output(&mut scenario, 0, |state| state.borrow_guard = NEXT_GUARD);
        scenario
    }

    // The conformance vectors.

    const LEADER: u8 = ALICE;
    const SENDER: u8 = BOB;
    const ONE_TIME: u8 = CAROL;

    pub fn conformance_vectors() -> Value {
        refdata::load_conformance_vectors().expect("the conformance vectors of the reference")
    }

    pub fn list(value: &Value) -> &[Value] {
        value.as_array().expect("a list")
    }

    fn int(value: &Value) -> i64 {
        value.as_i64().expect("an integer")
    }

    fn hex(value: &Value) -> Vec<u8> {
        let text = value.as_str().expect("a hex string");
        assert!(text.len().is_multiple_of(2), "`{text}` is not whole bytes");
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex digits"))
            .collect()
    }

    fn hex32(value: &Value) -> [u8; 32] {
        hex(value).try_into().expect("32 bytes")
    }

    fn hex_byte(value: &Value) -> u8 {
        let bytes = hex(value);
        assert_eq!(bytes.len(), 1, "one byte");
        bytes[0]
    }

    pub fn case_id(case: &Value) -> &str {
        case["id"].as_str().expect("the id of a vector case")
    }

    fn vector_state(described: &Value) -> Kcc20State {
        Kcc20State {
            amount: int(&described["amount"]),
            owner: hex32(&described["owner_hex"]),
            owner_scheme: hex_byte(&described["owner_scheme_hex"]),
            borrow_scheme: hex_byte(&described["borrow_scheme_hex"]),
            borrow_guard: hex32(&described["borrow_guard_hex"]),
            extension_commitment: hex32(&described["extension_commitment_hex"]),
        }
    }

    pub fn standard_transfer(vectors: &Value, case: Option<&Value>) -> Scenario {
        let common = &vectors["standard_transfer"]["common"];
        let listed = |field: &str| case.and_then(|case| case.get(field));

        let mut leader = vector_state(&common["leader_state"]);
        leader.owner = keys::x_only(LEADER);
        let mut after: Vec<Kcc20State> = list(&vectors["transfer_arguments"]["next_states"])
            .iter()
            .map(vector_state)
            .collect();
        if let Some(amounts) = listed("next_state_amounts") {
            for (state, amount) in after.iter_mut().zip(list(amounts)) {
                state.amount = int(amount);
            }
        }
        if let Some(schemes) = listed("next_state_owner_schemes_hex") {
            for (state, scheme) in after.iter_mut().zip(list(schemes)) {
                state.owner_scheme = hex_byte(scheme);
            }
        }
        if let Some(commitments) = listed("next_state_extension_commitments_hex") {
            for (state, commitment) in after.iter_mut().zip(list(commitments)) {
                state.extension_commitment = hex32(commitment);
            }
        }

        let leader_witness = match listed("witness_hex") {
            Some(witness) => LateBytes::fixed(hex(witness)),
            None => witness::owner_key(LEADER, EntryRole::Leader, SIG_HASH_ALL),
        };
        let mut coins = vec![Coin {
            state: leader,
            value: TOKEN_SOMPI,
            witness: leader_witness,
        }];
        let delegate_amounts = listed("delegate_amounts").unwrap_or(&common["delegate_amounts"]);
        coins.extend(list(delegate_amounts).iter().map(|amount| Coin {
            state: token(SENDER, int(amount)),
            value: TOKEN_SOMPI,
            witness: witness::owner_key(SENDER, EntryRole::Delegate, SIG_HASH_ALL),
        }));

        transfer_of(
            coins,
            after
                .into_iter()
                .map(|state| (state, TOKEN_SOMPI))
                .collect(),
        )
    }

    pub fn borrowed_receive(vectors: &Value, case: &Value) -> Scenario {
        let common = &vectors["borrowed_receive"]["common"];
        let scheme = hex_byte(&case["borrow_scheme_hex"]);
        let mut leader = Kcc20State {
            amount: int(&common["leader_amount"]),
            owner: hex32(&common["owner_hex"]),
            owner_scheme: hex_byte(&common["owner_scheme_hex"]),
            borrow_scheme: scheme,
            borrow_guard: hex32(&case["leader_borrow_guard_hex"]),
            extension_commitment: hex32(&common["extension_commitment_hex"]),
        };
        let mut successor = leader.clone();
        successor.amount = int(&case["successor_amount"]);
        successor.borrow_guard = hex32(&case["successor_borrow_guard_hex"]);
        if let Some(owner) = case.get("successor_owner_hex") {
            successor.owner = hex32(owner);
        }

        let vector_witness = hex(&case["witness_hex"]);
        let mut leader_witness = LateBytes::fixed(vector_witness.clone());
        if scheme == BORROW_HASH_CHAIN {
            let revealed: [u8; 32] = vector_witness[1..33].try_into().expect("32 bytes");
            let intended = hex32(&vectors["hash_chain"]["links"][1]["x_hex"]);
            let committed = witness::chain_guard(&intended, ONE_TIME);
            leader.borrow_guard = committed;
            if case["successor_borrow_guard_hex"] == case["leader_borrow_guard_hex"] {
                successor.borrow_guard = committed;
            }
            leader_witness = witness::borrow_hash_chain(revealed, ONE_TIME, SIG_HASH_ALL);
        }

        let leader_sompi = case
            .get("leader_kas_value_sompi")
            .map_or(TOKEN_SOMPI, |value| {
                value.as_u64().expect("a value in sompi")
            });
        let successor_sompi = case
            .get("successor_kas_value_sompi")
            .map_or(leader_sompi, |value| {
                value.as_u64().expect("a value in sompi")
            });
        let change = token(SENDER, leader.amount + 2000 - successor.amount);

        transfer_of(
            vec![
                Coin {
                    state: leader,
                    value: leader_sompi,
                    witness: leader_witness,
                },
                Coin {
                    state: token(SENDER, 2000),
                    value: TOKEN_SOMPI,
                    witness: witness::owner_key(SENDER, EntryRole::Delegate, SIG_HASH_ALL),
                },
            ],
            vec![(successor, successor_sompi), (change, TOKEN_SOMPI)],
        )
    }
}

#[test]
fn port_transfer_refusals_move_when_their_rule_is_removed() {
    use transfer_port::*;
    let mut results = Vec::new();
    let honest = sixty_forty();

    let plain = spend(&[(BOB, 100)]);
    results.push(removal(
        "transfer/output schemes/owner 0x05 is not assigned",
        &plain,
        &after(
            |s| change_token_output(s, 0, |state| state.owner_scheme = 0x05),
            &plain,
        ),
        0,
        "K-33",
        58,
    ));
    results.push(removal(
        "transfer/output schemes/borrow 0x04 is not assigned",
        &plain,
        &after(
            |s| change_token_output(s, 0, |state| state.borrow_scheme = 0x04),
            &plain,
        ),
        0,
        "K-34",
        61,
    ));
    for amount in [41, 39] {
        results.push(removal(
            &format!("transfer/conservation/60 + {amount} of 100"),
            &honest,
            &after(
                |s| change_token_output(s, 1, |state| state.amount = amount),
                &honest,
            ),
            0,
            "K-37",
            175,
        ));
    }
    results.push(removal(
        "transfer/conservation/200 and -100 of 100",
        &honest,
        &after(
            |s| {
                change_token_output(s, 0, |state| state.amount = 200);
                change_token_output(s, 1, |state| state.amount = -100);
            },
            &honest,
        ),
        0,
        "K-32",
        169,
    ));
    results.push(removal(
        "transfer/conservation/output locked to 41, declared 40",
        &honest,
        &after(
            |s| {
                s.contract_output_mut(1)
                    .state
                    .as_kcc20_mut()
                    .expect("a token output")
                    .amount = 41
            },
            &honest,
        ),
        0,
        "K-66",
        239,
    ));

    let made_up: Vec<u8> = (0..64u8)
        .map(|index| index.wrapping_mul(37).wrapping_add(11))
        .collect();
    let mut made_up_signature = made_up;
    made_up_signature.push(SIG_HASH_ALL.to_u8());
    let mut zero_signature = vec![0u8; 64];
    zero_signature.push(SIG_HASH_ALL.to_u8());
    let witnesses: Vec<(&str, LateBytes, &str, u32)> = vec![
        (
            "transfer/signature/signed by Bob, who receives",
            witness::owner_key(BOB, EntryRole::Leader, SIG_HASH_ALL),
            "K-38",
            69,
        ),
        (
            "transfer/signature/signed for another recipient",
            signed_for_another_transaction(|tx| {
                tx.outputs[0].script_public_key = Family::pinned()
                    .script_public_key(&State::from(token(CAROL, 60)))
                    .expect("the script of a token coin")
            }),
            "K-38",
            69,
        ),
        (
            "transfer/signature/signed for another coin value",
            signed_for_another_transaction(|tx| tx.outputs[1].value += 1),
            "K-38",
            69,
        ),
        (
            "transfer/signature/made-up bytes",
            normal_path(made_up_signature),
            "K-38",
            69,
        ),
        (
            "transfer/signature/zero bytes",
            normal_path(zero_signature),
            "K-38",
            69,
        ),
        (
            "transfer/signature/witness of the path byte alone",
            normal_path([]),
            "K-38",
            69,
        ),
        (
            "transfer/signature/no witness bytes at all",
            LateBytes::empty(),
            "K-25",
            161,
        ),
        (
            "transfer/signature/path byte 2",
            witness::owner_key(ALICE, EntryRole::Leader, SIG_HASH_ALL).map(|mut witness| {
                witness[0] = 0x02;
                witness
            }),
            "K-63",
            222,
        ),
    ];
    for (name, bytes, rule, line) in witnesses {
        let changed = after(|s| *s.contract_input_mut(0).witness_mut() = bytes, &honest);
        results.push(removal(name, &honest, &changed, 0, rule, line));
    }

    // Owner schemes.
    let honest = owner_scheme_transfer(OWNER_P2PKH_SCHNORR);
    results.push(removal(
        "schemes/owner key hash, schnorr/another key pair",
        &honest,
        &after(
            |s| {
                *s.contract_input_mut(0).witness_mut() =
                    witness::owner_key_hash_schnorr(BOB, EntryRole::Leader, SIG_HASH_ALL)
            },
            &honest,
        ),
        0,
        "K-40",
        78,
    ));
    results.push(removal(
        "schemes/owner key hash, schnorr/the owner's key, another key's signature",
        &honest,
        &after(
            |s| {
                *s.contract_input_mut(0).witness_mut() = LateBytes::from_tx(|ctx| {
                    let mut witness = vec![PATH_NORMAL];
                    witness.extend(keys::x_only(ALICE));
                    witness.extend(keys::schnorr_signature(
                        ctx,
                        &keys::keypair(BOB),
                        SIG_HASH_ALL,
                    ));
                    witness
                })
            },
            &honest,
        ),
        0,
        "K-41",
        79,
    ));
    let honest = owner_scheme_transfer(OWNER_P2PKH_ECDSA);
    results.push(removal(
        "schemes/owner key hash, ecdsa/another key pair",
        &honest,
        &after(
            |s| {
                *s.contract_input_mut(0).witness_mut() =
                    witness::owner_key_hash_ecdsa(CAROL, EntryRole::Leader, SIG_HASH_ALL)
            },
            &honest,
        ),
        0,
        "K-43",
        85,
    ));
    results.push(removal(
        "schemes/owner key hash, ecdsa/the owner's key, another key's signature",
        &honest,
        &after(
            |s| {
                *s.contract_input_mut(0).witness_mut() = LateBytes::from_tx(|ctx| {
                    let mut witness = vec![PATH_NORMAL];
                    witness.extend(keys::compressed(ALICE));
                    witness.extend(keys::ecdsa_signature(
                        ctx,
                        &keys::keypair(CAROL),
                        SIG_HASH_ALL,
                    ));
                    witness
                })
            },
            &honest,
        ),
        0,
        "K-44",
        86,
    ));
    let honest = owner_scheme_transfer(OWNER_P2SH);
    results.push(removal(
        "schemes/owner script hash/index 0, the token coin itself",
        &honest,
        &after(
            |s| {
                *s.contract_input_mut(0).witness_mut() =
                    witness::owner_script_hash(0, EntryRole::Leader)
            },
            &honest,
        ),
        0,
        "K-46",
        90,
    ));
    results.push(removal(
        "schemes/owner script hash/input 1 is locked by another script",
        &honest,
        &after(
            |s| {
                let other = s.ordinary_input_mut(1);
                other.script_public_key = shapes::op_true_script();
                other.signature_script = LateBytes::empty();
            },
            &honest,
        ),
        0,
        "K-46",
        90,
    ));
    let honest = owned_by_another_covenant();
    results.push(removal(
        "schemes/owner covenant id/no input of the owning covenant",
        &honest,
        &after(|s| s.ordinary_input_mut(1).covenant_id = None, &honest),
        0,
        "K-48",
        96,
    ));
    results.push(removal(
        "schemes/owner covenant id/one witness byte behind the path byte",
        &honest,
        &after(
            |s| *s.contract_input_mut(0).witness_mut() = normal_path([0x00]),
            &honest,
        ),
        0,
        "K-47",
        95,
    ));

    // Borrow schemes.
    let honest = shapes::borrow(&Profile::Script, BorrowKind::Signature);
    for seed in [ALICE, BOB] {
        results.push(removal(
            &format!("schemes/borrow signature/signed by key {seed:#04x}"),
            &honest,
            &after(
                |s| {
                    *s.contract_input_mut(0).witness_mut() =
                        witness::borrow_signature(seed, SIG_HASH_ALL)
                },
                &honest,
            ),
            0,
            "K-52",
            192,
        ));
    }
    let honest = hash_chain_receive();
    let used_guard = witness::chain_guard(&NEXT_GUARD, CAROL);
    results.push(removal(
        "schemes/borrow hash chain/the guard is not moved on",
        &honest,
        &after(
            |s| change_token_output(s, 0, |state| state.borrow_guard = used_guard),
            &honest,
        ),
        0,
        "K-60",
        217,
    ));
    results.push(removal(
        "schemes/borrow hash chain/the revealed link does not hash to the guard",
        &honest,
        &after(
            |s| {
                *s.contract_input_mut(0).witness_mut() =
                    witness::borrow_hash_chain(WRONG_LINK, CAROL, SIG_HASH_ALL);
                change_token_output(s, 0, |state| state.borrow_guard = WRONG_LINK);
            },
            &honest,
        ),
        0,
        "K-54",
        205,
    ));

    hold(results, 12);
}

#[test]
fn conformance_vector_refusals_move_when_their_rule_is_removed() {
    use transfer_port::*;
    let vectors = conformance_vectors();
    let mut results = Vec::new();

    let common = standard_transfer(&vectors, None);
    let three_inputs = serde_json::json!({
        "id": "three token inputs",
        "delegate_amounts": [100, 100],
        "next_state_amounts": [600, 600],
    });
    let refusing: [(&str, &str, u32); 6] = [
        ("negative-amount", "K-32", 169),
        ("unsupported-owner-scheme", "K-33", 58),
        ("invalid-witness-path-byte", "K-63", 222),
        ("extension-commitment-not-preserved", "K-35", 172),
        ("amount-not-preserved", "K-37", 175),
        ("over-max-token-inputs", "K-16", 132),
    ];
    for case in list(&vectors["standard_transfer"]["cases"]) {
        let id = case_id(case);
        let (_, rule, line) = refusing
            .iter()
            .find(|(refused, ..)| *refused == id)
            .unwrap_or_else(|| panic!("no rule written down for `{id}`"));
        let honest = if case.get("delegate_amounts").is_some() {
            standard_transfer(&vectors, Some(&three_inputs))
        } else {
            common.clone()
        };
        results.push(removal(
            &format!("conformance/standard/{id}"),
            &honest,
            &standard_transfer(&vectors, Some(case)),
            0,
            rule,
            *line,
        ));
    }

    let cases = list(&vectors["borrowed_receive"]["cases"]);
    let vector_case = |id: &str| {
        cases
            .iter()
            .find(|case| case_id(case) == id)
            .unwrap_or_else(|| panic!("the vector has no case `{id}`"))
    };
    let refusing: [(&str, &str, &str, u32); 11] = [
        ("threshold-equal", "threshold-exceeded", "K-61", 219),
        (
            "threshold-negative-unchanged",
            "threshold-negative",
            "K-61",
            219,
        ),
        (
            "threshold-negative-decrease",
            "threshold-negative",
            "K-61",
            219,
        ),
        (
            "threshold-negative-zero-unchanged",
            "threshold-negative-zero",
            "K-61",
            219,
        ),
        (
            "threshold-guard-normalized",
            "threshold-negative",
            "K-60",
            217,
        ),
        ("disabled", "threshold-zero", "K-50", 184),
        (
            "hash-chain-guard-not-advanced",
            "hash-chain-valid",
            "K-60",
            217,
        ),
        ("unassigned-scheme", "threshold-zero", "K-34", 61),
        ("successor-changes-owner", "threshold-exceeded", "K-57", 214),
        ("successor-reduces-kas-value", "", "K-62", 220),
        ("hash-chain-link-mismatch", "hash-chain-valid", "K-54", 205),
    ];
    for (id, twin_id, rule, line) in refusing {
        let case = vector_case(id);
        let honest = if twin_id.is_empty() {
            let mut kept = case.clone();
            kept.as_object_mut()
                .expect("a vector case is an object")
                .remove("successor_kas_value_sompi");
            borrowed_receive(&vectors, &kept)
        } else {
            borrowed_receive(&vectors, vector_case(twin_id))
        };
        results.push(removal(
            &format!("conformance/borrowed/{id}"),
            &honest,
            &borrowed_receive(&vectors, case),
            0,
            rule,
            line,
        ));
    }

    hold(results, 17);
}

// ---------------------------------------------------------------------------------------
// The builders of port_borrow.rs
// ---------------------------------------------------------------------------------------

mod borrow_port {
    use super::*;

    pub fn tokens(owner: u8, amount: i64) -> Kcc20State {
        Kcc20State::new(keys::x_only(owner), amount)
    }

    pub fn bound_to(input: u16) -> Option<CovenantBinding> {
        Some(CovenantBinding::new(input, shapes::covenant_id()))
    }

    pub fn leader_call(next_states: &[Kcc20State], owner: u8) -> Call {
        Call::typed(
            Entry::Transfer,
            vec![
                Arg::States(next_states.to_vec()),
                Arg::Bytes(witness::owner_key(owner, EntryRole::Leader, SIG_HASH_ALL)),
            ],
        )
    }

    pub fn delegate_call(owner: u8) -> Call {
        Call::typed(
            Entry::TransferDelegator,
            vec![Arg::Bytes(witness::owner_key(
                owner,
                EntryRole::Delegate,
                SIG_HASH_ALL,
            ))],
        )
    }

    pub fn token_coin(state: Kcc20State, index: u32, call: Call) -> ContractInput {
        ContractInput::new(
            state,
            COIN,
            Some(shapes::covenant_id()),
            shapes::outpoint(1, index),
            call,
        )
    }

    pub fn set_next_states(scenario: &mut Scenario, next_states: &[Kcc20State]) {
        *scenario.contract_input_mut(0).declared_states_mut() = next_states.to_vec();
        for (index, state) in next_states.iter().enumerate() {
            scenario.contract_output_mut(index).state = state.clone().into();
        }
    }

    pub fn change_token_output(
        scenario: &mut Scenario,
        index: usize,
        change: impl Fn(&mut Kcc20State),
    ) {
        change(&mut scenario.contract_input_mut(0).declared_states_mut()[index]);
        change(
            scenario
                .contract_output_mut(index)
                .state
                .as_kcc20_mut()
                .expect("a token output"),
        );
    }

    pub fn bob_coin() -> Kcc20State {
        tokens(BOB, 200).with_threshold(10)
    }

    pub fn receive(bob: Kcc20State, alice_amount: i64, increase: i64) -> Scenario {
        let mut scenario = shapes::borrow(&Profile::Script, BorrowKind::Threshold);
        let next_states = [
            bob.clone().with_amount(bob.amount + increase),
            tokens(ALICE, alice_amount - increase),
        ];
        scenario.contract_input_mut(0).state = bob.into();
        scenario.contract_input_mut(1).state = tokens(ALICE, alice_amount).into();
        set_next_states(&mut scenario, &next_states);
        scenario
    }

    pub fn honest_receive() -> Scenario {
        receive(bob_coin(), 100, 11)
    }

    pub fn join_of(coins: &[(u8, i64)], outputs: &[(u8, i64)]) -> Scenario {
        let next_states: Vec<Kcc20State> = outputs
            .iter()
            .map(|&(owner, amount)| tokens(owner, amount))
            .collect();
        let mut scenario = Scenario::new("join of token coins");
        for (index, &(owner, amount)) in coins.iter().enumerate() {
            let call = if index == 0 {
                leader_call(&next_states, owner)
            } else {
                delegate_call(owner)
            };
            scenario.push_contract_input(token_coin(tokens(owner, amount), index as u32, call));
        }
        for state in next_states {
            scenario.push_contract_output(ContractOutput::new(state, COIN, bound_to(0)));
        }
        scenario
    }

    pub fn join(parts: &[i64]) -> Scenario {
        let outputs: Vec<(u8, i64)> = parts.iter().map(|&part| (CAROL, part)).collect();
        join_of(&[(ALICE, 100), (BOB, 50)], &outputs)
    }
}

#[test]
fn port_borrow_refusals_move_when_their_rule_is_removed() {
    use borrow_port::*;
    let mut results = Vec::new();

    // The borrowed receive.
    let honest = honest_receive();
    for increase in [10, 9, 1, 0, -100] {
        results.push(removal(
            &format!("borrow/threshold/add {increase} with threshold 10"),
            &honest,
            &receive(bob_coin(), 100, increase),
            0,
            "K-61",
            219,
        ));
    }
    results.push(removal(
        "borrow/successor/owner replaced",
        &honest,
        &after(
            |s| change_token_output(s, 0, |state| state.owner = keys::x_only(MALLORY)),
            &honest,
        ),
        0,
        "K-57",
        214,
    ));
    results.push(removal(
        "borrow/successor/threshold lowered to 0",
        &honest,
        &after(
            |s| change_token_output(s, 0, |state| state.borrow_guard = [0; 32]),
            &honest,
        ),
        0,
        "K-60",
        217,
    ));
    let with_kept = |kept: u64| {
        let mut scenario = honest_receive();
        scenario.contract_input_mut(0).value = 5_000;
        scenario.contract_output_mut(0).value = kept;
        scenario
    };
    results.push(removal(
        "borrow/sompi/successor keeps 4999 of 5000",
        &with_kept(5_000),
        &with_kept(4_999),
        0,
        "K-62",
        220,
    ));
    results.push(removal(
        "borrow/sum/sender keeps 90 of 100 after giving 11",
        &honest,
        &after(
            |s| change_token_output(s, 1, |state| state.amount = 90),
            &honest,
        ),
        0,
        "K-37",
        175,
    ));
    results.push(removal(
        "borrow/sender/signed by a stranger",
        &honest,
        &after(
            |s| {
                *s.contract_input_mut(1).witness_mut() =
                    witness::owner_key(MALLORY, EntryRole::Delegate, SIG_HASH_ALL)
            },
            &honest,
        ),
        1,
        "K-38",
        69,
    ));
    results.push(removal(
        "borrow/scheme/borrowing disabled",
        &honest,
        &receive(tokens(BOB, 200), 100, 11),
        0,
        "K-50",
        184,
    ));
    results.push(removal(
        "borrow/scheme/witness 01 00",
        &honest,
        &after(
            |s| *s.contract_input_mut(0).witness_mut() = LateBytes::fixed([PATH_BORROW, 0x00]),
            &honest,
        ),
        0,
        "K-51",
        186,
    ));

    // Leader and delegate.
    let honest = join(&[150]);
    for signer in [CAROL, ALICE] {
        results.push(removal(
            &format!("delegator/signature/delegate signed by key {signer:#04x}"),
            &honest,
            &after(
                |s| {
                    *s.contract_input_mut(1).witness_mut() =
                        witness::owner_key(signer, EntryRole::Delegate, SIG_HASH_ALL)
                },
                &honest,
            ),
            1,
            "K-38",
            69,
        ));
    }
    results.push(removal(
        "delegator/signature/leader signed by the delegate's owner",
        &honest,
        &after(
            |s| {
                *s.contract_input_mut(0).witness_mut() =
                    witness::owner_key(BOB, EntryRole::Leader, SIG_HASH_ALL)
            },
            &honest,
        ),
        0,
        "K-38",
        69,
    ));
    let two_parts = join_of(&[(ALICE, 100), (BOB, 50)], &[(CAROL, 120), (ALICE, 30)]);
    results.push(removal(
        "delegator/sum/120 and 31 of 150",
        &two_parts,
        &after(
            |s| change_token_output(s, 1, |state| state.amount = 31),
            &two_parts,
        ),
        0,
        "K-37",
        175,
    ));
    results.push(removal(
        "delegator/sum/the delegate's tokens counted twice",
        &honest,
        &after(
            |s| change_token_output(s, 0, |state| state.amount = 200),
            &honest,
        ),
        0,
        "K-37",
        175,
    ));
    results.push(removal(
        "delegator/family/delegate of another token family",
        &honest,
        &after(
            |s| {
                s.contract_input_mut(1)
                    .state
                    .as_kcc20_mut()
                    .expect("a token coin")
                    .extension_commitment = [0xee; 32]
            },
            &honest,
        ),
        0,
        "K-29",
        164,
    ));
    let bound_to_delegate = after(
        |s| {
            s.push_contract_output(ContractOutput::new(tokens(CAROL, 1000), COIN, bound_to(1)));
        },
        &honest,
    );
    results.push(removal(
        "delegator/binding/a second token output bound to the delegate, the leader",
        &honest,
        &bound_to_delegate,
        0,
        "K-23",
        158,
    ));
    results.push(removal(
        "delegator/binding/a second token output bound to the delegate, the delegate",
        &honest,
        &bound_to_delegate,
        1,
        "K-73",
        265,
    ));
    let three = join_of(&[(ALICE, 1000), (BOB, 100), (BOB, 100)], &[(CAROL, 1200)]);
    for total in [1300, 1200, 1100] {
        results.push(removal(
            &format!("delegator/count/four token inputs, output of {total}"),
            &three,
            &after(
                |s| {
                    s.push_contract_input(token_coin(tokens(BOB, 100), 3, delegate_call(BOB)));
                    change_token_output(s, 0, |state| state.amount = total);
                },
                &three,
            ),
            0,
            "K-16",
            132,
        ));
    }
    results.push(removal(
        "delegator/role/first token input runs the delegate entry",
        &honest,
        &after(
            |s| s.contract_input_mut(0).call = delegate_call(ALICE),
            &honest,
        ),
        0,
        "K-69",
        255,
    ));
    results.push(removal(
        "delegator/role/second token input runs the leader entry",
        &honest,
        &after(
            |s| s.contract_input_mut(1).call = leader_call(&[tokens(CAROL, 150)], BOB),
            &honest,
        ),
        1,
        "K-14",
        129,
    ));
    let second_leads = after(
        |s| {
            let next_states = [tokens(CAROL, 100)];
            set_next_states(s, &next_states);
            s.contract_output_mut(0).binding = bound_to(1);
            s.contract_input_mut(1).call = leader_call(&next_states, BOB);
        },
        &honest,
    );
    results.push(removal(
        "delegator/role/second token input leads, the only output bound to it",
        &honest,
        &second_leads,
        1,
        "K-14",
        129,
    ));
    results.push(removal(
        "delegator/role/second token input leads, input 0",
        &honest,
        &second_leads,
        0,
        "K-21",
        155,
    ));
    let lone = join_of(&[(ALICE, 100)], &[(CAROL, 100)]);
    results.push(removal(
        "delegator/role/lone token input as delegate, a token output",
        &lone,
        &after(
            |s| s.contract_input_mut(0).call = delegate_call(ALICE),
            &lone,
        ),
        0,
        "K-68",
        254,
    ));
    results.push(removal(
        "delegator/role/lone token input as delegate, no token output",
        &lone,
        &after(
            |s| {
                s.contract_input_mut(0).call = delegate_call(ALICE);
                s.outputs.clear();
                s.push_plain_output(PlainOutput::new(shapes::op_true_script(), COIN));
            },
            &lone,
        ),
        0,
        "K-68",
        254,
    ));

    hold(results, 12);
}

// ---------------------------------------------------------------------------------------
// Three things the removals do not show
// ---------------------------------------------------------------------------------------

/// The last byte of the witness of input `input`: the byte in front of the push of the
/// dispatch tag, which is in front of the push of the redeem script. `witness_len` is the
/// length of the witness, whose push opcode must be where that length puts it.
fn last_witness_byte(
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

/// A signature helper that ignored the requested type would pass the sighash cases of
/// `port_token.rs` with signatures of type All. That file asserts the type byte of the
/// stranger's signature itself; this test reads the same byte with code of its own.
#[test]
fn a_signature_of_each_hash_type_carries_its_type_byte() {
    use token_port::*;
    const TRANSFER: [u8; 4] = [0x79, 0xc7, 0x1c, 0x23];
    // The bytes of the earlier suite, written out.
    let stated: [(&str, u8); 6] = [
        ("All", 0x01),
        ("None", 0x02),
        ("Single", 0x04),
        ("AllAnyOneCanPay", 0x81),
        ("NoneAnyOneCanPay", 0x82),
        ("SingleAnyOneCanPay", 0x84),
    ];
    for ((name, hash_type), (stated_name, byte)) in sighash_types().into_iter().zip(stated) {
        assert_eq!(name, stated_name);
        let stranger = lone(
            token(ALICE, 100),
            vec![token(BOB, 100)],
            witness::owner_key(MALLORY, EntryRole::Leader, hash_type),
        );
        assert_eq!(
            last_witness_byte(&stranger, 0, &token(ALICE, 100), TRANSFER, 66),
            byte,
            "stranger, {name}"
        );
    }
}

/// The same token coins, calls and outputs in a transaction that is put together here: the
/// outpoints, the covenant id of every token coin and the binding of every token output
/// are set by this function and not taken from a shape of the family crate.
fn from_scratch(built: &Scenario) -> Scenario {
    let mut scenario = Scenario::new(format!("{}, from scratch", built.name));
    for (index, spec) in built.inputs.iter().enumerate() {
        match spec {
            InputSpec::Contract(input) => {
                scenario.push_contract_input(ContractInput::new(
                    input.state.clone(),
                    input.value,
                    Some(shapes::covenant_id()),
                    shapes::outpoint(7, index as u32),
                    input.call.clone(),
                ));
            }
            InputSpec::Ordinary(input) => {
                scenario.push_ordinary_input(input.clone());
            }
        }
    }
    for spec in &built.outputs {
        match spec {
            OutputSpec::Contract(output) => {
                scenario.push_contract_output(ContractOutput::new(
                    output.state.clone(),
                    output.value,
                    Some(CovenantBinding::new(0, shapes::covenant_id())),
                ));
            }
            OutputSpec::Plain(output) => {
                scenario.push_plain_output(output.clone());
            }
        }
    }
    scenario
}

/// What every input answers: `pass`, or what refused and at which byte.
fn answers(outcome: &Outcome) -> Vec<String> {
    outcome
        .inputs
        .iter()
        .map(|input| match input.alone.as_ref() {
            None => "not run".to_string(),
            Some(run) if run.ok => "pass".to_string(),
            Some(run) => match run.refusal.as_ref() {
                Some(refusal) => {
                    format!("{} at byte {:?}", refusal.refused_by, refusal.byte_offset)
                }
                None => "refused".to_string(),
            },
        })
        .collect()
}

/// The 23 transactions of the conformance vector (the common transfer, 6 standard cases,
/// 16 borrowed receives) answer the same when the transaction around the vector's states,
/// values and witnesses is not the transfer shape of the family crate, and each answers as
/// the vector states: every input passes, or input 0 is refused and the sender coins pass.
#[test]
fn the_conformance_vectors_answer_the_same_in_a_transaction_built_from_scratch() {
    use transfer_port::*;
    let vectors = conformance_vectors();
    let mut scenarios = vec![("accept".to_string(), standard_transfer(&vectors, None))];
    for case in list(&vectors["standard_transfer"]["cases"]) {
        scenarios.push((
            case["result"].as_str().expect("a result").to_string(),
            standard_transfer(&vectors, Some(case)),
        ));
    }
    for case in list(&vectors["borrowed_receive"]["cases"]) {
        scenarios.push((
            case["result"].as_str().expect("a result").to_string(),
            borrowed_receive(&vectors, case),
        ));
    }
    assert_eq!(scenarios.len(), 23);
    let mut accepted = 0;
    for (index, (stated, scenario)) in scenarios.iter().enumerate() {
        let shaped = checks::run(scenario);
        let rebuilt = checks::run(&from_scratch(scenario));
        assert_ne!(shaped.tx_id, rebuilt.tx_id, "vector transaction {index}");
        assert_eq!(
            answers(&shaped),
            answers(&rebuilt),
            "vector transaction {index}"
        );
        let answers = answers(&rebuilt);
        if stated == "accept" {
            assert!(answers.iter().all(|answer| answer == "pass"), "{answers:?}");
            accepted += 1;
        } else {
            assert_ne!(answers[0], "pass", "vector transaction {index}");
            assert!(
                answers[1..].iter().all(|answer| answer == "pass"),
                "{answers:?}"
            );
        }
        println!("VECTOR {index} ({stated}): {answers:?}");
    }
    assert_eq!(
        accepted, 6,
        "the common transfer and five borrowed receives"
    );
}

/// The scenario without the funding coin `port_transfer.rs` adds as the last input: the
/// transaction of the earlier check itself. `None` when the scenario has no such coin.
fn without_funding(scenario: &Scenario) -> Option<Scenario> {
    let funded = matches!(
        scenario.inputs.last(),
        Some(InputSpec::Ordinary(input)) if input.label == "funding (OP_TRUE)"
    );
    if !funded {
        return None;
    }
    let mut bare = scenario.clone();
    bare.inputs.pop();
    bare.name = format!("{}, without the funding coin", scenario.name);
    Some(bare)
}

/// `port_transfer.rs` runs a transaction that pays out more than it takes in only with a
/// funding coin added; the transaction the earlier check built is not run there. Here it
/// is: every token input answers the same with and without the added coin, to the rule and
/// the byte. (A node refuses the transaction without the coin before it runs a script.)
#[test]
fn the_added_funding_coin_changes_no_answer_of_a_token_input() {
    use transfer_port::*;
    let vectors = conformance_vectors();
    let honest = sixty_forty();
    let mut scenarios = vec![
        spend(&[(BOB, 100)]),
        honest.clone(),
        spend(&[(BOB, 60), (CAROL, 30), (ALICE, 10)]),
        after(
            |s| change_token_output(s, 1, |state| state.amount = 41),
            &honest,
        ),
        after(
            |s| change_token_output(s, 1, |state| state.amount = 39),
            &honest,
        ),
        after(
            |s| {
                change_token_output(s, 0, |state| state.amount = 200);
                change_token_output(s, 1, |state| state.amount = -100);
            },
            &honest,
        ),
        after(
            |s| {
                s.contract_output_mut(1)
                    .state
                    .as_kcc20_mut()
                    .expect("a token output")
                    .amount = 41
            },
            &honest,
        ),
    ];
    let witnesses = [
        witness::owner_key(BOB, EntryRole::Leader, SIG_HASH_ALL),
        signed_for_another_transaction(|tx| tx.outputs[1].value += 1),
        normal_path([]),
        LateBytes::empty(),
        witness::owner_key(ALICE, EntryRole::Leader, SIG_HASH_ALL).map(|mut witness| {
            witness[0] = 0x02;
            witness
        }),
        witness::owner_key(ALICE, EntryRole::Leader, SIG_HASH_ALL).map(|mut witness| {
            witness.push(0x00);
            witness
        }),
    ];
    for bytes in witnesses {
        scenarios.push(after(
            |s| *s.contract_input_mut(0).witness_mut() = bytes,
            &honest,
        ));
    }
    scenarios.push(standard_transfer(&vectors, None));
    for case in list(&vectors["standard_transfer"]["cases"]) {
        scenarios.push(standard_transfer(&vectors, Some(case)));
    }
    for case in list(&vectors["borrowed_receive"]["cases"]) {
        scenarios.push(borrowed_receive(&vectors, case));
    }

    let mut compared = 0;
    for scenario in &scenarios {
        let Some(bare) = without_funding(scenario) else {
            continue;
        };
        let with_coin = answers(&checks::run(scenario));
        let bare_outcome = checks::run(&bare);
        let without_coin = answers(&bare_outcome);
        assert_eq!(
            with_coin[..without_coin.len()],
            without_coin[..],
            "scenario `{}`",
            scenario.name
        );
        assert!(
            !bare_outcome.consensus.context_accepted,
            "scenario `{}`: without the coin the transaction spends more than it has",
            scenario.name
        );
        compared += 1;
    }
    println!(
        "FUNDING: {compared} of {} transactions carry the added coin; every token input answers \
         the same without it",
        scenarios.len()
    );
    assert!(compared >= 10, "{compared} transactions compared");
}
