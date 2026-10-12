//! What an earlier debug-engine suite could not reach, shown on the script engine.
//!
//! An earlier suite of checks, written in Python and not published here, handed the
//! arguments of an entry to the debug engine that comes with the SilverScript bindings of
//! the Kaspa Python SDK. That engine is a debugging aid and not a node: it runs one entry
//! of a contract with typed arguments. As that suite called it, it never executed the
//! bytes of a call, never counted a compute budget, never compared the lock of the spent
//! coin with the script that ran, and never ran the script of an ordinary input. The
//! suite's own checks with ids `test_engine_limits.*` pin that. This file puts the same
//! transactions, and the ones that follow from them, to the script engine:
//!
//! 1. the seven checks with ids `test_engine_limits.*`, with the engine's answer next to
//!    the earlier one;
//! 2. the twenty-six checks with ids `test_build.*`, which run no engine: the published
//!    artifact is what those checks pinned (bytes, hashes, layouts, tags, vectors);
//! 3. the lock of a contract coin: a spender who pushes any script but the one the coin is
//!    locked to is refused before a contract opcode runs; for a coin in the delegate role
//!    the leader refuses as well;
//! 4. ordinary inputs beside contract inputs: a fee payer with a wrong or missing
//!    signature, other kinds of fee payer, and the authority coin of the script-hash owner
//!    scheme;
//! 5. a contract coin that carries no covenant id.
//!
//! Every expectation was written down from the engine's answer. Where a note says "the
//! earlier engine", it quotes the verdict the earlier check asserted for the same bytes.
//!
//! The seven checks with ids `test_engine_limits.*`, side by side. The middle column is what
//! that suite asserted on an engine that runs one entry on typed arguments: the reach of the
//! suite, not a judgement of the engine.
//!
//! | what the check varied | earlier suite | script engine |
//! |---|---|---|
//! | compute budget 0, 1, 255 | pass, pass, pass | refused for the budget, refused for the budget, pass (14 is the smallest that covers the run) |
//! | signature script: junk; the other entry's call; the script alone | pass with honest arguments | no entry has the tag (K-01); the other entry runs and refuses (K-68); the first opcode finds no tag |
//! | signature script without the push of the script | an index error inside the contract | the coin's lock refuses, no contract opcode runs |
//! | coin locked to the script of another state | pass | the coin's lock refuses |
//! | delegate signed by a stranger | the leader, asked alone, passes | the same; the transaction is refused at the delegate (K-38) |
//! | made-up covenant id on an output | structure error before the contract | `check_covenant_info` before any script |
//! | covenant output without an authorizing input | the helper refuses to write it | cannot be written: a binding holds both |

use std::collections::BTreeMap;
use std::fs;
use std::sync::OnceLock;

use argent::codec::{decode_hex, encode_hex};
use checks::results::record_structural;
use checks::{Budgets, Case, Expected, Harness, Outcome, Part, RunOutcome, expect_accept, run};
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash_type::{SIG_HASH_ALL, SigHashType};
use kaspa_consensus_core::tx::{CovenantBinding, ScriptPublicKey};
use kaspa_txscript::opcodes::codes::{OpCheckSig, OpCheckSigECDSA, OpDrop, OpTrue, OpVerify};
use kaspa_txscript::pay_to_script_hash_script;
use kcc20_family::{
    Contract, Entry, EntryRole, Family, Scenario, SourceMap, State,
    keys::{self, ALICE, BOB, CAROL, DAVE},
    raw, refdata,
    scenario::{Arg, Call, LateBytes},
    shapes::{self, Profile, Realistic},
    sourcemap::compile_source,
    states::{Kcc20State, OWNER_P2SH, PublicMintState, TokenSeedState, kcc20_states_value},
    witness,
};
use node_gate::{ErrorClass, StopPoint};
use serde_json::{Value, json};
use silverscript_lang::compiler::COMPILER_VERSION;
use silverscript_lang::template::template_hash;

// ---------------------------------------------------------------------------------------
// Helpers: scenarios
// ---------------------------------------------------------------------------------------

/// The transfer of the earlier checks: Alice's 100 tokens become 60 for Bob and 40 for
/// Alice. (The earlier scenario gave both outputs 1000 sompi against a 1000-sompi coin:
/// nothing in that suite compared the sompi paid out with the sompi spent. Here the outputs
/// share the 1000 sompi, so that a node gets to the scripts.)
fn py_transfer() -> Scenario {
    let mut scenario = shapes::transfer(&Profile::Script, 1, 2);
    let alice = keys::x_only(ALICE);
    for (index, amount) in [(0, 60), (1, 40)] {
        scenario.contract_input_mut(0).declared_states_mut()[index].amount = amount;
        let output = scenario
            .contract_output_mut(index)
            .state
            .as_kcc20_mut()
            .expect("a token output");
        output.amount = amount;
        if index == 1 {
            output.owner = alice;
        }
    }
    scenario.contract_input_mut(0).declared_states_mut()[1].owner = alice;
    scenario
}

/// The merge of the earlier checks: Alice's 100 tokens and Bob's 50 become 150 for Alice.
/// The key with seed `delegate_signer` signs for Bob's coin.
fn py_merge(delegate_signer: u8) -> Scenario {
    let mut scenario = shapes::transfer(&Profile::Script, 2, 1);
    let alice = keys::x_only(ALICE);
    {
        let bob_coin = scenario.contract_input_mut(1);
        let state = bob_coin.state.as_kcc20_mut().expect("a token coin");
        state.owner = keys::x_only(BOB);
        state.amount = 50;
        *bob_coin.witness_mut() =
            witness::owner_key(delegate_signer, EntryRole::Delegate, SIG_HASH_ALL);
    }
    let declared = &mut scenario.contract_input_mut(0).declared_states_mut()[0];
    declared.owner = alice;
    declared.amount = 150;
    let locked = scenario
        .contract_output_mut(0)
        .state
        .as_kcc20_mut()
        .expect("a token output");
    locked.owner = alice;
    locked.amount = 150;
    scenario
}

/// The realistic profile with a fee a default mempool takes for these transactions
/// (0.02 KAS; the floor for the one-to-one transfer is 925,000 sompi).
fn realistic() -> Profile {
    Profile::Realistic(Realistic {
        fee: 2_000_000,
        ..Realistic::default()
    })
}

/// A realistic one-to-one transfer: input 0 is Alice's token coin, input 1 the fee payer
/// (pay to public key, Schnorr), output 0 Bob's token coin, output 1 the change.
fn funded_transfer() -> Scenario {
    shapes::transfer(&realistic(), 1, 1)
}

/// The signature script of a pay-to-public-key coin: one push of a Schnorr signature.
fn schnorr_spend(key_seed: u8, hash_type: SigHashType) -> LateBytes {
    witness::signature(key_seed, hash_type).map(|signature| raw::push(&signature).expect("a push"))
}

/// `<33-byte key> OP_CHECKSIGECDSA`, version 0.
fn pay_to_ecdsa_key_script(compressed_key: &[u8; 33]) -> ScriptPublicKey {
    let mut script = raw::push(compressed_key).expect("a push");
    script.push(OpCheckSigECDSA);
    ScriptPublicKey::from_vec(0, script)
}

/// The reference's script-hash authority shape with a real lock on the authority: Alice's
/// token coin (owner scheme 0x03) is owned by the hash of `<Carol's key> OP_CHECKSIG`;
/// input 1 spends a coin of that script with `signature`; input 2 pays the fee.
fn authority_with_key(signature: LateBytes) -> Scenario {
    let mut scenario =
        shapes::transfer_with_owner_scheme(&realistic(), EntryRole::Leader, OWNER_P2SH);
    let mut redeem = raw::push(&keys::x_only(CAROL)).expect("a push");
    redeem.push(OpCheckSig);
    let lock = pay_to_script_hash_script(&redeem);
    let owner: [u8; 32] = lock.script()[2..34].try_into().expect("32 bytes");
    scenario
        .contract_input_mut(0)
        .state
        .as_kcc20_mut()
        .expect("a token coin")
        .owner = owner;
    let authority = scenario.ordinary_input_mut(1);
    authority.script_public_key = lock;
    authority.signature_script = signature.map(move |signature| {
        let mut script = raw::push(&signature).expect("a push");
        script.extend(raw::push(&redeem).expect("a push"));
        script
    });
    scenario
}

/// The change that takes the covenant id off the coin calling `entry` in its honest shape.
/// For a leader the outputs lose their bindings as well: an output bound to an input
/// without an id claims a new covenant, and a node judges that claim before any script
/// (see `a_made_up_covenant_id_on_an_output_is_refused_before_any_script`).
fn take_the_covenant_id_off(scenario: &mut Scenario, entry: Entry, input: usize) {
    scenario.contract_input_mut(input).covenant_id = None;
    if entry.role() == EntryRole::Leader {
        for output in &mut scenario.outputs {
            *output.binding_mut() = None;
        }
    }
}

/// One honest shape per contract whose input 0 is a coin of that contract.
fn one_coin_of_each_contract() -> [(Contract, Scenario); 3] {
    [
        (Contract::Kcc20, shapes::transfer(&Profile::Script, 1, 1)),
        (Contract::PublicMint, shapes::mint(&Profile::Script)),
        (Contract::TokenSeed, shapes::seed_create(&Profile::Script)),
    ]
}

/// Scripts a spender could push in place of the one the coin is locked to, with a name
/// each: the script of another state (one unit more; another owner), the script of another
/// contract of the family, the honest script with one byte of its code changed, and the
/// honest script with one rule removed (the `OpVerify` of a rule made an `OpDrop`).
fn other_redeem_scripts(contract: Contract, state: &State) -> Vec<(String, Vec<u8>)> {
    let family = Family::pinned();
    let redeem = |state: &State| family.redeem_script(state).expect("a redeem script");
    let honest = redeem(state);
    let carol = keys::x_only(CAROL);
    let mut scripts = Vec::new();

    let mut one_more = state.clone();
    let mut another_owner = state.clone();
    let unit = match (&mut one_more, &mut another_owner) {
        (State::Kcc20(more), State::Kcc20(other)) => {
            more.amount += 1;
            other.owner = carol;
            "one token more"
        }
        (State::PublicMint(more), State::PublicMint(other)) => {
            more.remaining += 1;
            other.owner = carol;
            "one more to mint"
        }
        (State::TokenSeed(more), State::TokenSeed(other)) => {
            // A seed holds no number; its second field is the extension commitment.
            more.extension_commitment = [0xee; 32];
            other.owner = carol;
            "another extension commitment"
        }
        _ => unreachable!("both are clones of one state"),
    };
    scripts.push((format!("another state, {unit}"), redeem(&one_more)));
    scripts.push((
        "another state, another owner".to_string(),
        redeem(&another_owner),
    ));

    let sibling: State = match contract {
        Contract::Kcc20 => PublicMintState::new(keys::x_only(ALICE), 25, 10).into(),
        Contract::PublicMint => TokenSeedState::new(keys::x_only(ALICE)).into(),
        Contract::TokenSeed => Kcc20State::new(keys::x_only(ALICE), 100).into(),
    };
    scripts.push((
        format!("the script of a {} coin", sibling.contract()),
        redeem(&sibling),
    ));

    let code_start = family.state_span(contract).end;
    let offset = code_start + (honest.len() - code_start) / 2;
    let mut one_byte = honest.clone();
    one_byte[offset] ^= 0x01;
    scripts.push((format!("one code byte changed, at {offset}"), one_byte));

    let map = SourceMap::pinned().contract(contract);
    let verify = map
        .opcodes()
        .iter()
        .find(|opcode| {
            opcode.offset >= code_start
                && opcode.code == OpVerify
                && map.rule_at(opcode.offset).is_some()
        })
        .expect("every contract has a rule that ends in OpVerify");
    let rule = &map.rule_at(verify.offset).expect("a rule").id;
    let mut one_rule_less = honest.clone();
    assert_eq!(one_rule_less[verify.offset], OpVerify);
    one_rule_less[verify.offset] = OpDrop;
    scripts.push((
        format!(
            "rule {rule} removed, OpVerify at {} made OpDrop",
            verify.offset
        ),
        one_rule_less,
    ));
    scripts
}

// ---------------------------------------------------------------------------------------
// Helpers: expectations and what is read off an outcome
// ---------------------------------------------------------------------------------------

/// The run of `input` without a budget limit.
fn alone(outcome: &Outcome, input: usize) -> &RunOutcome {
    outcome.inputs[input]
        .alone
        .as_ref()
        .expect("the input was run")
}

/// The coin's own lock refuses: the last push of the signature script does not hash to the
/// coin.
fn by_the_lock_of_the_coin() -> Expected {
    let mut expected = Expected::refused_by("P2SH wrapper").of_class(ErrorClass::ScriptFormat);
    expected.engine = Some("EvalFalse".to_string());
    expected
}

/// A signature check of an ordinary script pushed false, and nothing else is on the stack.
fn by_a_false_signature_check() -> Expected {
    let mut expected = Expected::refused_by("final stack").of_class(ErrorClass::ContractRefused);
    expected.engine = Some("EvalFalse".to_string());
    expected
}

/// The engine stopped at the hash comparison of the coin's lock: after the pushes of the
/// signature script and the three opcodes of the lock, before the first opcode of the
/// pushed script. No contract script ran.
fn assert_stopped_at_the_lock(outcome: &Outcome, input: usize) {
    let record = &outcome.inputs[input];
    let run = alone(outcome, input);
    assert_eq!(run.error_variant(), Some("EvalFalse"));
    assert_eq!(run.stop, Some(StopPoint::P2shHashMismatch));
    let refusal = run.refusal.as_ref().expect("a refusal");
    assert_eq!(refusal.part, Part::P2shWrapper);
    assert_eq!(refusal.rule, None);
    assert_eq!(refusal.byte_offset, None, "no opcode of a redeem script");
    assert_eq!(record.contract, None, "the bytes run no contract script");
}

/// A node gets to the scripts of the transaction and refuses it for the script of `input`,
/// as a submission and in the mempool alike.
fn assert_a_node_refuses_at(outcome: &Outcome, input: usize) {
    assert!(outcome.consensus.context_accepted);
    assert!(!outcome.consensus.accepted);
    let refusal = outcome
        .consensus
        .refusal
        .as_ref()
        .expect("a consensus refusal");
    assert_eq!(refusal.rule, "check_scripts");
    assert_eq!(refusal.input, Some(input));
    assert!(!outcome.mempool.accepted);
    let first = outcome
        .mempool
        .first_refusal
        .as_ref()
        .expect("a mempool refusal");
    assert_eq!(first.rule, "check_scripts");
    assert_eq!(first.input, Some(input));
}

// ---------------------------------------------------------------------------------------
// Helpers: the published files
// ---------------------------------------------------------------------------------------

/// A JSON file next to the published artifact (`fixtures/public-mint/<name>`).
fn published_json(name: &str) -> Value {
    let path = refdata::artifact_path().with_file_name(name);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} is not readable: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The published artifact as plain JSON, as the earlier checks read it.
fn artifact_json() -> &'static Value {
    static ARTIFACT: OnceLock<Value> = OnceLock::new();
    ARTIFACT.get_or_init(|| published_json("artifact.json"))
}

/// The conformance vectors of the reference, read from the reader's clone.
fn spec_vectors() -> Value {
    refdata::load_conformance_vectors().expect("the conformance vectors are readable")
}

/// A JSON array of numbers as bytes.
fn json_bytes(value: &Value) -> Vec<u8> {
    value
        .as_array()
        .expect("an array of bytes")
        .iter()
        .map(|byte| u8::try_from(byte.as_u64().expect("a number")).expect("a byte"))
        .collect()
}

/// A JSON hex string as bytes.
fn hex_bytes(value: &Value) -> Vec<u8> {
    unhex(value.as_str().expect("a hex string"))
}

fn unhex(text: &str) -> Vec<u8> {
    decode_hex(text).expect("valid hex")
}

/// The token state one conformance vector describes: the amount as a JSON number, every
/// other field as a hex string.
fn token_state_of_vector(vector: &Value) -> Kcc20State {
    let hex = |field: &str| hex_bytes(&vector[field]);
    let word = |field: &str| -> [u8; 32] { hex(field).try_into().expect("32 bytes") };
    let first_byte = |field: &str| -> u8 { hex(field)[0] };
    let amount = vector["amount"].as_i64().expect("an integer amount");
    let mut state = Kcc20State::new(word("owner_hex"), amount);
    state.owner_scheme = first_byte("owner_scheme_hex");
    state.borrow_scheme = first_byte("borrow_scheme_hex");
    state.borrow_guard = word("borrow_guard_hex");
    state.extension_commitment = word("extension_commitment_hex");
    state
}

/// The template hash formula, written out: BLAKE3 over the length of the prefix as eight
/// little-endian bytes, the prefix, the length of the suffix likewise, the suffix.
fn template_hash_of_parts(prefix: &[u8], suffix: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(prefix.len() as u64).to_le_bytes());
    hasher.update(prefix);
    hasher.update(&(suffix.len() as u64).to_le_bytes());
    hasher.update(suffix);
    *hasher.finalize().as_bytes()
}

/// The push of `len` zero bytes with an explicit length byte.
fn zero_push(len: u8) -> Vec<u8> {
    let mut push = vec![len];
    push.resize(usize::from(len) + 1, 0);
    push
}

/// The bytecode the pinned compiler gives for the pinned source of `contract` with
/// zero-valued constructor arguments.
fn recompiled(contract: Contract) -> &'static [u8] {
    static BYTECODE: OnceLock<[Vec<u8>; 3]> = OnceLock::new();
    &BYTECODE.get_or_init(|| {
        Contract::ALL.map(|contract| {
            compile_source(contract, refdata::pinned_sil_source(contract), false)
                .expect("the pinned source compiles")
                .bytecode
        })
    })[contract.index()]
}

/// The name the sources give a parameter type of the artifact.
fn type_name(ty: &Value) -> String {
    // The array layers come off first; what is inside them gets its name.
    let mut inner = ty;
    let mut arrays = 0;
    while inner["kind"] == "dynamic_array" {
        inner = &inner["item"];
        arrays += 1;
    }
    let kind = inner["kind"].as_str().expect("a type kind");
    let base = if kind == "struct" {
        inner["name"].as_str().expect("a struct name")
    } else if kind == "bytes" {
        "byte[]"
    } else {
        kind
    };
    format!("{base}{}", "[]".repeat(arrays))
}

/// A `gen__const_<symbol>_<part>_len` constant of a generated source: four bytes, read as
/// a little-endian number.
fn template_length_in_source(source: &str, symbol: &str, part: &str) -> usize {
    let marker = format!("gen__const_{symbol}_{part}_len");
    let at = source.find(&marker).expect("the constant is in the source") + marker.len();
    let start = at
        + source[at..]
            .find("0x")
            .expect("the hex literal of the constant")
        + 2;
    let bytes: [u8; 4] = unhex(&source[start..start + 8])
        .try_into()
        .expect("four bytes");
    u32::from_le_bytes(bytes) as usize
}

/// The names of the constructor parameters of a generated source, in order.
fn constructor_parameters(source: &str, contract: Contract) -> Vec<String> {
    let marker = format!("contract {}(", contract.name());
    let start = source.find(&marker).expect("the contract declaration") + marker.len();
    let end = start
        + source[start..]
            .find(") {")
            .expect("the end of the parameters");
    source[start..end]
        .split(',')
        .map(|parameter| {
            parameter
                .split_whitespace()
                .last()
                .expect("a parameter name")
                .to_string()
        })
        .collect()
}

/// Records one of the earlier checks with ids `test_build.*` as checked without an engine
/// run.
fn built(py_method: &str, note: &str) {
    let py_id = format!("test_build.{py_method}");
    record_structural(&format!("build/{py_method}"), &[py_id.as_str()], note);
}

/// Size, state span and template hash of every contract as published.
const PUBLISHED: [(Contract, usize, usize, usize, &str); 3] = [
    (
        Contract::Kcc20,
        4031,
        1,
        145,
        "9703112ee6e3555107cd168858992b77d3b74f655205b2b463b1f9ec2ec73cf7",
    ),
    (
        Contract::PublicMint,
        2019,
        1,
        150,
        "14b0f06bc176b78c94f19292e409c622636f31dae6bb31ff3d4d3308a6053b49",
    ),
    (
        Contract::TokenSeed,
        1355,
        1,
        132,
        "f79a3fccf6f87d7076662410a17e54d1531889d9b60f630f9fbb8465a384e62d",
    ),
];

/// BLAKE3 of the reference's conformance vectors with LF line ends.
const CONFORMANCE_TEXT_BLAKE3: &str =
    "69cb75d37bd56bc02bba7936e41c2a4847dc49ad297cdc83af2ae19407d05129";

/// The entries of every contract with their parameters, as the earlier checks spelt them.
type EntryTable = &'static [(&'static str, &'static [(&'static str, &'static str)])];
const ENTRIES: [(Contract, EntryTable); 3] = [
    (
        Contract::Kcc20,
        &[
            (
                "transfer",
                &[("next_states", "KCC20State[]"), ("witness", "byte[]")],
            ),
            ("transfer_delegator", &[("witness", "byte[]")]),
        ],
    ),
    (
        Contract::PublicMint,
        &[
            (
                "mint",
                &[
                    ("recipient_state", "KCC20State"),
                    ("gen__kcc20_prefix", "byte[]"),
                    ("gen__kcc20_suffix", "byte[]"),
                ],
            ),
            ("split", &[("take", "int"), ("new_owner", "pubkey")]),
            ("reclaim", &[("owner_signature", "sig")]),
            ("reclaim_into", &[]),
            ("reclaim_delegator", &[("owner_signature", "sig")]),
        ],
    ),
    (
        Contract::TokenSeed,
        &[
            (
                "create",
                &[
                    ("recipient_state", "KCC20State"),
                    ("gen__kcc20_prefix", "byte[]"),
                    ("gen__kcc20_suffix", "byte[]"),
                ],
            ),
            ("split", &[("new_owner", "pubkey")]),
            ("reclaim", &[]),
            ("reclaim_delegator", &[("owner_signature", "sig")]),
        ],
    ),
];

// ---------------------------------------------------------------------------------------
// 1. The seven checks with ids test_engine_limits.*
// ---------------------------------------------------------------------------------------

const PY_BUDGET: &str = "test_engine_limits.NotChecked.test_compute_budget_is_not_counted";
const PY_BYTES: &str = "test_engine_limits.NotChecked.test_the_bytes_of_the_call_are_not_what_runs";
const PY_REDEEM: &str = "test_engine_limits.NotChecked.test_the_contract_does_read_its_own_script_from_the_end_of_the_signature_script";
const PY_LOCK: &str = "test_engine_limits.NotChecked.test_the_active_coin_s_lock_is_not_compared_with_the_script_that_runs";
const PY_ACTIVE: &str = "test_engine_limits.NotChecked.test_only_the_active_input_is_run";
const PY_MADE_UP_ID: &str = "test_engine_limits.StructureComesFirst.test_a_made_up_covenant_id_on_an_output_is_refused_before_the_contract_runs";
const PY_BINDING: &str = "test_engine_limits.StructureComesFirst.test_the_helper_refuses_a_covenant_output_without_an_authorizing_input";

#[test]
fn the_compute_budget_is_counted() {
    // The earlier engine: budget 0, 1 and 255 all pass. The script engine meters script
    // units against the committed budget: a budget of n allows 9,999 + 10,000 n units.
    let scenario = py_transfer();
    let measured = run(&scenario);
    assert_eq!(alone(&measured, 0).used_script_units, 144_833);
    assert_eq!(measured.minimal_budgets(), Some(vec![14]));

    let with = |budget: u16| Harness::pinned().with_budgets(Budgets::Exactly(vec![budget]));
    let over_budget =
        || Expected::engine("ExceededCommittedScriptUnits").of_class(ErrorClass::ResourceLimit);

    for (budget, limit) in [(0u16, 9_999u64), (1, 19_999), (13, 139_999)] {
        let outcome = Case::new(format!("gap/budget {budget}"))
            .py([PY_BUDGET])
            .note("the earlier engine: pass; the script engine: the budget runs out")
            .on(with(budget))
            .expect_refused(&scenario, 0, over_budget());
        let committed = outcome.inputs[0]
            .committed
            .as_ref()
            .expect("the run under the budget");
        assert_eq!(committed.script_units_limit, Some(limit));
        assert_eq!(committed.rule(), None, "no rule of the contract refused");
        assert!(alone(&outcome, 0).ok, "without a limit the input passes");
        if budget < 2 {
            // The first thing that does not fit is the signature check of the owner: it
            // costs 100,000 units at once.
            let refusal = committed.refusal.as_ref().expect("a refusal");
            assert_eq!(refusal.opcode.as_deref(), Some("OpCheckSig"));
            assert_eq!(committed.sil_line(), Some(69));
            assert_eq!(committed.used_script_units, 9_567);
        }
        assert_a_node_refuses_at(&outcome, 0);
    }

    for budget in [14u16, 255] {
        let outcome = Case::new(format!("gap/budget {budget}"))
            .py([PY_BUDGET])
            .note("the earlier engine: pass; the script engine: pass, the budget covers the run")
            .on(with(budget))
            .expect_accept(&scenario);
        assert!(outcome.consensus.accepted);
    }

    // The budget a scenario states when it says nothing is 0, as in the earlier checks.
    let outcome = Case::new("gap/budget as the scenario states it")
        .py([PY_BUDGET])
        .note("the earlier engine: pass; the script engine: a transaction that commits to no budget is refused")
        .on(Harness::pinned().with_budgets(Budgets::AsStated))
        .expect_refused(&scenario, 0, over_budget());
    assert_eq!(
        outcome.inputs[0]
            .committed
            .as_ref()
            .unwrap()
            .script_units_limit,
        Some(9_999)
    );
}

#[test]
fn the_bytes_of_the_call_are_what_runs() {
    // The earlier engine: four different signature scripts change nothing; with honest
    // arguments all four pass, with the arguments of a wrong key all four stop at the
    // owner's signature check. On the script engine the signature script is the call.
    let honest = py_transfer();
    expect_accept(
        Case::new("gap/call bytes, the real call")
            .py([PY_BYTES])
            .note("the earlier engine: pass; the script engine: pass"),
        &honest,
    );

    // The real call with a genuine signature of another key in its bytes.
    Case::new("gap/call bytes, the real call signed by another key")
        .py([PY_BYTES])
        .note("the earlier engine: KCC20.sil:69; the script engine: the same line, rule K-38")
        .twin(
            &honest,
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() =
                    witness::owner_key(BOB, EntryRole::Leader, SIG_HASH_ALL);
            },
            0,
            Expected::rule("K-38").at_line(69),
        );

    // One push of 40 bytes where the arguments and the tag belong.
    let twin = Case::new("gap/call bytes, junk")
        .py([PY_BYTES])
        .note("the earlier engine: pass; the script engine: no entry has this tag, K-01")
        .twin(
            &honest,
            |scenario| {
                scenario.contract_input_mut(0).call =
                    Call::Raw(LateBytes::fixed(raw::push(&[0x5a; 40]).expect("a push")));
            },
            0,
            Expected::rule("K-01").of_class(ErrorClass::ContractRefused),
        );
    let run = alone(&twin.changed, 0);
    assert_eq!(run.error_variant(), Some("EarlyReturn"));
    assert_eq!(
        run.refusal.as_ref().unwrap().place.as_deref(),
        Some("dispatcher")
    );
    assert_eq!(twin.changed.inputs[0].entry, None);

    // The call of the other entry of the same contract, well formed and signed by the
    // owner.
    let twin = Case::new("gap/call bytes, another entry's call")
        .py([PY_BYTES])
        .note("the earlier engine: pass; the script engine: transfer_delegator runs and wants a second covenant input, K-68")
        .twin(
            &honest,
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
            0,
            Expected::rule("K-68").at_line(254),
        );
    assert_eq!(
        twin.changed.inputs[0].entry.as_deref(),
        Some("transfer_delegator")
    );

    // Nothing in front of the redeem script.
    let twin = Case::new("gap/call bytes, nothing but the script")
        .py([PY_BYTES])
        .note("the earlier engine: pass; the script engine: the first opcode of the script finds no tag to move")
        .twin(
            &honest,
            |scenario| scenario.contract_input_mut(0).call = Call::Raw(LateBytes::empty()),
            0,
            Expected::engine("InvalidStackOperation").of_class(ErrorClass::EngineRefusedData),
        );
    let refusal = alone(&twin.changed, 0).refusal.as_ref().unwrap();
    assert_eq!(refusal.byte_offset, Some(0));
    assert_eq!(refusal.opcode.as_deref(), Some("OpToAltStack"));
    assert_eq!(refusal.rule, None);
}

#[test]
fn a_call_without_the_push_of_the_script_never_reaches_the_contract() {
    // The earlier engine ran the contract anyway and failed inside it with an index error
    // ("cannot be used as an array index"). On the script engine the last push is the
    // script: here that is the four bytes of the tag, which do not hash to the coin.
    let twin = Case::new("gap/the redeem push is missing")
        .py([PY_REDEEM])
        .note("the earlier engine: an index error inside the contract; the script engine: the coin's own lock refuses, no contract opcode runs")
        .twin(
            &py_transfer(),
            |scenario| {
                scenario
                    .contract_input_mut(0)
                    .set_patch(|parts| parts.redeem.clear());
            },
            0,
            by_the_lock_of_the_coin(),
        );
    assert_stopped_at_the_lock(&twin.changed, 0);
    assert_a_node_refuses_at(&twin.changed, 0);
}

#[test]
fn the_lock_of_the_coin_is_compared_with_the_script_that_runs() {
    // The coin is locked to the script of a coin holding a million tokens; the spender
    // pushes the script of the coin holding 100.
    let family = Family::pinned();
    let honest = py_transfer();
    let mut rich = honest.contract_input(0).state.clone();
    rich.as_kcc20_mut().expect("a token coin").amount = 1_000_000;
    let other_lock =
        pay_to_script_hash_script(&family.redeem_script(&rich).expect("a redeem script"));

    // The owner signs the transaction as it is: the signature covers the lock of the coin.
    // The earlier engine accepted this.
    let lock = other_lock.clone();
    let twin = Case::new("gap/coin locked to another state, signed for that lock")
        .py([PY_LOCK])
        .note("the earlier engine: pass; the script engine: the coin's own lock refuses")
        .twin(
            &honest,
            |scenario| scenario.contract_input_mut(0).locking_script = Some(lock),
            0,
            by_the_lock_of_the_coin(),
        );
    assert_stopped_at_the_lock(&twin.changed, 0);
    assert_a_node_refuses_at(&twin.changed, 0);

    // The witness the owner made for the honest coin: the seventh push of the honest call.
    let assembled = honest.assemble(family).expect("the scenario assembles");
    let pushes = raw::split_pushes(&assembled.tx.inputs[0].signature_script).expect("pushes");
    assert_eq!(pushes.len(), 9, "six columns, witness, tag, redeem script");
    let honest_witness = pushes[6][1..].to_vec();
    assert_eq!(honest_witness.len(), 66);
    let twin = Case::new("gap/coin locked to another state, signed for the honest lock")
        .py([PY_LOCK])
        .note("the earlier engine: KCC20.sil:69; the script engine: the coin's own lock refuses before any signature is looked at")
        .twin(
            &honest,
            |scenario| {
                let input = scenario.contract_input_mut(0);
                input.locking_script = Some(other_lock);
                *input.witness_mut() = LateBytes::fixed(honest_witness);
            },
            0,
            by_the_lock_of_the_coin(),
        );
    assert_stopped_at_the_lock(&twin.changed, 0);
}

#[test]
fn every_input_is_run_and_a_stranger_cannot_sign_for_the_delegate() {
    // The earlier engine, asked about input 0 alone, said pass: the authorization of a
    // delegate is checked by the delegate's own script. A node runs every input.
    let twin = Case::new("gap/delegate signed by a stranger")
        .py([PY_ACTIVE])
        .note("the earlier engine: the leader alone passes, the delegate asked by itself fails; the script engine: the same two answers, and the transaction is refused at input 1")
        .twin_inputs(
            &py_merge(BOB),
            |scenario| {
                *scenario.contract_input_mut(1).witness_mut() =
                    witness::owner_key(ALICE, EntryRole::Delegate, SIG_HASH_ALL);
            },
            &[
                (0, Expected::pass()),
                (1, Expected::rule("K-38").at_line(69)),
            ],
        );
    assert_eq!(twin.changed.scripts.refused_inputs, [1]);
    assert_a_node_refuses_at(&twin.changed, 1);
}

#[test]
fn a_made_up_covenant_id_on_an_output_is_refused_before_any_script() {
    let mut scenario = py_transfer();
    *scenario.outputs[1].binding_mut() =
        Some(CovenantBinding::new(0, Hash::from_bytes([0x22; 32])));
    let outcome = Case::new("gap/made-up covenant id on an output")
        .py([PY_MADE_UP_ID])
        .note("the earlier engine: 'Covenant structure error' before the contract ran; a node: check_covenant_info, WrongGenesisCovenantId, no script is run")
        .expect_consensus_refused(&scenario, "check_covenant_info");
    assert!(outcome.scripts.not_run.is_some());
    assert!(outcome.inputs.iter().all(|input| input.alone.is_none()));
    let refusal = outcome
        .consensus
        .context_refusal
        .as_ref()
        .expect("a refusal in front of the scripts");
    assert!(
        refusal
            .error
            .starts_with("CovenantsError(WrongGenesisCovenantId(0, 2222"),
        "{}",
        refusal.error
    );
}

#[test]
fn a_binding_always_names_its_authorizing_input() {
    // The earlier helper refused to write a covenant output without an authorizing input.
    // Here that output cannot be written at all: a binding is the pair of both.
    let binding = CovenantBinding::new(0, shapes::covenant_id());
    assert_eq!(binding.authorizing_input, 0);
    assert_eq!(binding.covenant_id, shapes::covenant_id());
    record_structural(
        "gap/a binding names its authorizing input",
        &[PY_BINDING],
        "behaviour of the earlier helper; here CovenantBinding::new takes the authorizing input and the id together",
    );
}

// ---------------------------------------------------------------------------------------
// 3. The lock of a contract coin
// ---------------------------------------------------------------------------------------

#[test]
fn a_coin_runs_only_the_script_it_is_locked_to() {
    // The coin is locked to the honest script. Whatever else the spender pushes as the
    // script, the lock refuses at its hash comparison; the pushed script is never run, so
    // it does not matter what it would allow. Signatures are made over the transaction as
    // it is.
    for (contract, honest) in one_coin_of_each_contract() {
        let scripts = other_redeem_scripts(contract, &honest.contract_input(0).state);
        assert_eq!(scripts.len(), 5);
        for (name, redeem) in scripts {
            let twin = Case::new(format!("own script/{contract} coin, pushed: {name}"))
                .note("refused by the coin's own lock before any opcode of the pushed script")
                .twin(
                    &honest,
                    |scenario| scenario.contract_input_mut(0).pushed_redeem = Some(redeem),
                    0,
                    by_the_lock_of_the_coin(),
                );
            assert_stopped_at_the_lock(&twin.changed, 0);
            assert_a_node_refuses_at(&twin.changed, 0);
        }
    }
}

#[test]
fn a_delegate_that_pushes_another_script_is_refused_by_its_lock_and_by_its_leader() {
    // The same five scripts, pushed by a coin in the delegate role. Its own lock refuses as
    // above. The leader refuses as well, by a rule of its contract (K-18, M-38, S-28): the
    // script the delegate pushed is not the one the delegate's coin is locked to. For some of
    // the pushed scripts the leader stops at the same line with an index error of the engine
    // instead; the condition below picks the expectation.
    //
    // (contract, honest shape with the delegate at input 1, rule and line of the leader)
    let family = Family::pinned();
    let delegates = [
        (Contract::Kcc20, py_merge(BOB), "K-18", 136),
        (
            Contract::PublicMint,
            shapes::mint_reclaim_into(&Profile::Script),
            "M-38",
            263,
        ),
        (
            Contract::TokenSeed,
            shapes::seed_reclaim(&Profile::Script),
            "S-28",
            210,
        ),
    ];
    for (contract, honest, rule, line) in delegates {
        for (name, redeem) in other_redeem_scripts(contract, &honest.contract_input(1).state) {
            let mut changed = honest.clone();
            changed.contract_input_mut(1).pushed_redeem = Some(redeem);
            let delegate_script_len = changed
                .assemble(family)
                .expect("the scenario assembles")
                .tx
                .inputs[1]
                .signature_script
                .len();
            let leader = if delegate_script_len < family.bytecode(contract).len() {
                Expected::engine("InvalidIndex")
                    .of_class(ErrorClass::EngineRefusedData)
                    .at_line(line)
            } else {
                Expected::rule(rule).at_line(line)
            };
            let twin = Case::new(format!("own script/{contract} delegate, pushed: {name}"))
                .note("refused twice: by the delegate's own lock, and by the leader, which is shown a script the delegate's coin is not locked to")
                .twin_inputs(
                    &honest,
                    |scenario| *scenario = changed,
                    &[(0, leader), (1, by_the_lock_of_the_coin())],
                );
            assert_stopped_at_the_lock(&twin.changed, 1);
            assert_eq!(twin.changed.scripts.refused_inputs, [0, 1]);
            // A node reports the first input that fails.
            assert_a_node_refuses_at(&twin.changed, 0);
        }
    }
}

// ---------------------------------------------------------------------------------------
// 4. Ordinary inputs beside contract inputs
// ---------------------------------------------------------------------------------------

#[test]
fn a_fee_payer_signed_by_another_key_stops_the_transaction_at_its_own_input() {
    let twin = Case::new("ordinary/fee payer signed by another key")
        .note("the token input passes by itself; the transaction is refused at the fee payer")
        .twin_inputs(
            &funded_transfer(),
            |scenario| {
                scenario.ordinary_input_mut(1).signature_script =
                    schnorr_spend(CAROL, SIG_HASH_ALL);
            },
            &[(0, Expected::pass()), (1, by_a_false_signature_check())],
        );
    // The honest transaction is one a default node takes into its mempool.
    assert!(twin.honest.mempool.accepted);
    let fee_payer = alone(&twin.changed, 1);
    // The check ran and was charged: a well-formed signature of the wrong key is false,
    // not an error.
    assert_eq!(fee_payer.used_script_units, 100_000);
    assert_eq!(twin.changed.inputs[1].contract, None);
    assert_eq!(twin.changed.scripts.refused_inputs, [1]);
    assert_a_node_refuses_at(&twin.changed, 1);
}

#[test]
fn a_fee_payer_without_a_signature_stops_the_transaction_at_its_own_input() {
    let honest = funded_transfer();

    // An empty signature script: the lock finds one item where it needs two.
    let twin = Case::new("ordinary/fee payer with an empty signature script").twin_inputs(
        &honest,
        |scenario| scenario.ordinary_input_mut(1).signature_script = LateBytes::empty(),
        &[
            (0, Expected::pass()),
            (
                1,
                Expected::engine("InvalidStackOperation").of_class(ErrorClass::EngineRefusedData),
            ),
        ],
    );
    let refusal = alone(&twin.changed, 1).refusal.as_ref().unwrap();
    assert_eq!(refusal.part, Part::LockScript);
    assert_eq!(refusal.opcode.as_deref(), Some("OpCheckSig"));
    assert_a_node_refuses_at(&twin.changed, 1);
    // The node words an empty signature script differently from a wrong one.
    let node = twin.changed.consensus.refusal.as_ref().unwrap();
    assert!(node.error.starts_with("SignatureEmpty("), "{}", node.error);

    // A push of an empty signature: the check pushes false without an error and without
    // the charge of a signature check.
    let twin = Case::new("ordinary/fee payer with an empty signature").twin_inputs(
        &honest,
        |scenario| {
            scenario.ordinary_input_mut(1).signature_script =
                LateBytes::fixed(raw::push(&[]).expect("a push"));
        },
        &[(0, Expected::pass()), (1, by_a_false_signature_check())],
    );
    assert_eq!(alone(&twin.changed, 1).used_script_units, 0);
    assert_a_node_refuses_at(&twin.changed, 1);
}

#[test]
fn other_kinds_of_fee_payer_pass_beside_a_token_input() {
    // A pay-to-public-key coin of an ECDSA key.
    let mut scenario = funded_transfer();
    let fee_payer = scenario.ordinary_input_mut(1);
    fee_payer.script_public_key = pay_to_ecdsa_key_script(&keys::compressed(DAVE));
    fee_payer.signature_script = LateBytes::from_tx(|ctx| {
        raw::push(&keys::ecdsa_signature(
            ctx,
            &keys::keypair(DAVE),
            SIG_HASH_ALL,
        ))
        .expect("a push")
    });
    let outcome = Case::new("ordinary/ECDSA fee payer").expect_consensus_accept(&scenario);
    assert_eq!(
        format!("{:?}", outcome.inputs[1].spent_script_class),
        "PubKeyECDSA"
    );
    assert!(outcome.mempool.accepted);

    // The same coin signed by another ECDSA key.
    let twin = Case::new("ordinary/ECDSA fee payer signed by another key").twin_inputs(
        &scenario,
        |scenario| {
            scenario.ordinary_input_mut(1).signature_script = LateBytes::from_tx(|ctx| {
                raw::push(&keys::ecdsa_signature(
                    ctx,
                    &keys::keypair(CAROL),
                    SIG_HASH_ALL,
                ))
                .expect("a push")
            });
        },
        &[(0, Expected::pass()), (1, by_a_false_signature_check())],
    );
    assert_a_node_refuses_at(&twin.changed, 1);

    // A pay-to-script-hash coin of OP_TRUE: anybody can pay the fee with it.
    let mut scenario = funded_transfer();
    let fee_payer = scenario.ordinary_input_mut(1);
    fee_payer.script_public_key = pay_to_script_hash_script(&[OpTrue]);
    fee_payer.signature_script = LateBytes::fixed(raw::push(&[OpTrue]).expect("a push"));
    let outcome =
        Case::new("ordinary/script-hash OP_TRUE fee payer").expect_consensus_accept(&scenario);
    assert_eq!(
        format!("{:?}", outcome.inputs[1].spent_script_class),
        "ScriptHash"
    );
    assert_eq!(outcome.inputs[1].contract, None);
    assert!(outcome.mempool.accepted);
}

#[test]
fn the_authority_of_a_script_hash_owner_must_run_successfully() {
    // The reference's own test (src/bin/kcc20/tests.rs, p2sh_authority_must_also_execute_
    // successfully): the token contract only asks that input 1 spends the script that owns
    // the coin. Whether that script is satisfied is the business of input 1.
    let honest = authority_with_key(witness::signature(CAROL, SIG_HASH_ALL));
    let outcome =
        Case::new("ordinary/authority coin signed by its key").expect_consensus_accept(&honest);
    assert_eq!(outcome.inputs[0].entry.as_deref(), Some("transfer"));
    assert!(outcome.mempool.accepted);

    let zeroed = witness::signature(CAROL, SIG_HASH_ALL).map(|mut signature| {
        signature[..64].fill(0);
        signature
    });
    let stranger = witness::signature(DAVE, SIG_HASH_ALL);
    for (name, signature) in [
        ("a zeroed signature", zeroed),
        ("the signature of a stranger", stranger),
    ] {
        let changed = authority_with_key(signature);
        let twin = Case::new(format!("ordinary/authority coin with {name}"))
            .note("the token input passes by itself; the transaction is refused at the authority input")
            .twin_inputs(
                &honest,
                |scenario| *scenario = changed,
                &[
                    (0, Expected::pass()),
                    (1, by_a_false_signature_check()),
                    (2, Expected::pass()),
                ],
            );
        assert_eq!(twin.changed.scripts.refused_inputs, [1]);
        assert_a_node_refuses_at(&twin.changed, 1);
    }
}

// ---------------------------------------------------------------------------------------
// 5. A contract coin without a covenant id
// ---------------------------------------------------------------------------------------

#[test]
fn a_contract_coin_without_a_covenant_id_is_refused_by_every_entry() {
    // Sompi paid to the address of a token coin, a minter or a seed without a covenant
    // binding make a coin with the contract's script and no covenant id. Every entry reads
    // the covenant id of its own coin and, in its very next statement, asks about the inputs
    // of that covenant: how many there are, or which is the first. For a coin without an id
    // the engine hands the script 32 zero bytes, and no input of these transactions belongs
    // to that group: each entry, called in its honest shape by such a coin, stops at that
    // statement.
    //
    // (entry; rule and source line that refuse the coin without an id; the same for the
    // honest leader beside a delegate without an id)
    type Refusal = (&'static str, u32);
    let table: [(Entry, Refusal, Option<Refusal>); 11] = [
        // The engine refuses inside OpCovInputIdx, before the comparison of the statement.
        (Entry::Transfer, ("CovenantsError", 129), None),
        (Entry::TransferDelegator, ("K-68", 254), Some(("K-37", 175))),
        (Entry::Mint, ("M-10", 127), None),
        (Entry::MintSplit, ("M-24", 187), None),
        (Entry::MintReclaim, ("M-32", 243), None),
        (Entry::MintReclaimInto, ("M-36", 260), None),
        (
            Entry::MintReclaimDelegator,
            ("M-51", 311),
            Some(("M-36", 260)),
        ),
        (Entry::SeedCreate, ("S-10", 123), None),
        (Entry::SeedSplit, ("S-21", 167), None),
        (Entry::SeedReclaim, ("S-26", 207), None),
        (
            Entry::SeedReclaimDelegator,
            ("S-37", 241),
            Some(("S-26", 207)),
        ),
    ];
    let listed: Vec<Entry> = table.iter().map(|(entry, ..)| *entry).collect();
    assert_eq!(listed, Entry::ALL, "every entry of the family");
    let expected = |(name, line): Refusal| {
        if name == "CovenantsError" {
            Expected::engine(name)
                .of_class(ErrorClass::EngineRefusedData)
                .at_line(line)
        } else {
            Expected::rule(name).at_line(line)
        }
    };

    // The statement that reads the coin's own covenant id is one and the same line in all
    // eleven entries. It is taken from the reader's clone of the reference: line 128 of
    // KCC20.sil, the line in front of the statement that refuses in `transfer`.
    let read_of_the_id = refdata::pinned_sil_source(Contract::Kcc20)
        .lines()
        .nth(127)
        .expect("KCC20.sil has a line 128")
        .trim();
    assert!(read_of_the_id.contains("OpInputCovenantId"));

    for (entry, coin, leader) in table {
        // The refusing statement is the one right behind the read of the coin's own id.
        let source: Vec<&str> = refdata::pinned_sil_source(entry.contract())
            .lines()
            .collect();
        let line = coin.1 as usize;
        assert_eq!(source[line - 2].trim(), read_of_the_id, "{entry}");
        assert!(source[line - 1].contains("(gen__cov_id"), "{entry}");

        let (honest, input) = shapes::for_entry(&Profile::Script, entry);
        let mut expectations = vec![(input, expected(coin))];
        if let Some(leader) = leader {
            assert_ne!(input, 0, "a delegate stands behind its leader");
            expectations.push((0, expected(leader)));
        }
        let twin = Case::new(format!("no covenant id/{entry}"))
            .note("the coin calling the entry carries no covenant id")
            .twin_inputs(
                &honest,
                |scenario| take_the_covenant_id_off(scenario, entry, input),
                &expectations,
            );
        let record = &twin.changed.inputs[input];
        assert_eq!(record.contract.as_deref(), Some(entry.contract().name()));
        assert_eq!(record.entry.as_deref(), Some(entry.name()));
        // A node reports the first input that fails: the leader, when a delegate without
        // an id leaves its leader with the wrong sums or counts.
        assert_a_node_refuses_at(&twin.changed, 0);
        if leader.is_some() {
            assert_eq!(twin.changed.scripts.refused_inputs, [0, input]);
        }
    }

    // Two coins without an id as leader and delegate of one transfer: each is refused by
    // its own first statement.
    Case::new("no covenant id/KCC20.transfer with KCC20.transfer_delegator, both coins")
        .note("neither coin carries a covenant id")
        .twin_inputs(
            &shapes::transfer(&Profile::Script, 2, 1),
            |scenario| {
                take_the_covenant_id_off(scenario, Entry::Transfer, 0);
                take_the_covenant_id_off(scenario, Entry::TransferDelegator, 1);
            },
            &[
                (0, expected(("CovenantsError", 129))),
                (1, expected(("K-68", 254))),
            ],
        );

    // What `transfer` trips over: the id the script asks about is 32 zero bytes, and no
    // input belongs to it.
    let (mut scenario, input) = shapes::for_entry(&Profile::Script, Entry::Transfer);
    take_the_covenant_id_off(&mut scenario, Entry::Transfer, input);
    let outcome = run(&scenario);
    let run = alone(&outcome, input);
    assert!(
        run.error
            .as_ref()
            .unwrap()
            .debug
            .starts_with("CovenantsError(InvalidCovInIndex(0000000000000000"),
        "{}",
        run.describe()
    );
    assert_eq!(
        run.refusal.as_ref().unwrap().opcode.as_deref(),
        Some("OpCovInputIdx")
    );
}

// ---------------------------------------------------------------------------------------
// 2. The twenty-six checks with ids test_build.*: the published artifact, no engine run
// ---------------------------------------------------------------------------------------

#[test]
fn build_compiler_is_the_pinned_one() {
    let artifact = artifact_json();
    assert_eq!(COMPILER_VERSION, "0.1.0");
    assert_eq!(artifact["sil_abi"]["compiler_version"], COMPILER_VERSION);
    assert_eq!(
        artifact["generator"],
        json!({ "name": "argentc", "version": "0.1.0" })
    );
    let family = Family::pinned();
    // The version every source names in its first line.
    for contract in Contract::ALL {
        let first = refdata::pinned_sil_source(contract)
            .lines()
            .next()
            .expect("a first line");
        assert!(first.contains(COMPILER_VERSION), "{contract}");
        assert!(
            recompiled(contract) == family.bytecode(contract),
            "{contract}"
        );
    }
    built(
        "PinnedArtifact.test_compiler_is_the_pinned_one",
        "the compiler of this workspace calls itself 0.1.0, the artifact names compiler 0.1.0 and generator argentc 0.1.0, the three sources name 0.1.0 in their first line and compile to the published bytes",
    );
}

#[test]
fn build_bytecode_template_hash_and_state_span_equal_the_pinned_ones() {
    let family = Family::pinned();
    for (contract, size, offset, len, hash) in PUBLISHED {
        assert_eq!(recompiled(contract).len(), size, "{contract}");
        assert!(
            recompiled(contract) == family.bytecode(contract),
            "{contract}"
        );
        assert_eq!(
            encode_hex(&family.template_hash(contract)),
            hash,
            "{contract}"
        );
        assert_eq!(
            family.state_span(contract),
            offset..offset + len,
            "{contract}"
        );
    }
    built(
        "PinnedArtifact.test_bytecode_template_hash_and_state_span_equal_the_pinned_ones",
        "sizes 4031 / 2019 / 1355, state spans (1,145) / (1,150) / (1,132), the three template hashes, and the recompiled bytes equal the published ones",
    );
}

#[test]
fn build_the_whole_contract_section_equals_the_pinned_one() {
    let family = Family::pinned();
    let contracts = &artifact_json()["sil_abi"]["contracts"];
    for contract in Contract::ALL {
        let section = &contracts[contract.name()];
        assert_eq!(
            section["source_path"],
            format!("sil/{}", contract.sil_file_name())
        );
        let compiled = &section["compiled"];
        assert!(
            json_bytes(&compiled["bytecode"]) == recompiled(contract),
            "{contract}"
        );
        assert_eq!(
            json_bytes(&compiled["template_hash"]),
            family.template_hash(contract),
            "{contract}"
        );
        let span = family.state_span(contract);
        assert_eq!(
            compiled["state_span"],
            json!({ "offset": span.start, "len": span.len() }),
            "{contract}"
        );
        let entries = section["entries"]
            .as_object()
            .expect("an object of entries");
        for (name, published) in entries {
            let entry = Entry::from_name(contract, name).expect("an entry the family knows");
            assert_eq!(
                published["dispatch_tag"],
                encode_hex(&family.dispatch_tag(entry)),
                "{entry}"
            );
        }
        assert_eq!(
            entries.len(),
            Entry::ALL
                .iter()
                .filter(|entry| entry.contract() == contract)
                .count()
        );
    }
    assert_eq!(artifact_json()["sil_abi"]["schema_version"], 1);
    built(
        "PinnedArtifact.test_the_whole_contract_section_equals_the_pinned_one",
        "per contract: source path, bytecode (against the recompiled bytes), template hash, state span, and every entry with its dispatch tag as the family reads them. Not rebuilt: the compiler's own ABI document; the parameter lists are held in test_entry_lists_are_exactly_these",
    );
}

#[test]
fn build_the_three_compiles_together_give_the_pinned_sil_abi_section() {
    let abi = &artifact_json()["sil_abi"];
    let keys = |value: &Value| -> Vec<String> {
        value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect()
    };
    assert_eq!(
        keys(abi),
        ["compiler_version", "contracts", "schema_version", "structs"]
    );
    assert_eq!(
        keys(&abi["structs"]),
        [
            "Gen__KCC20State",
            "KCC20State",
            "PublicMintState",
            "TokenSeedState"
        ]
    );
    assert_eq!(
        keys(&abi["contracts"]),
        ["KCC20", "PublicMint", "TokenSeed"]
    );
    built(
        "PinnedArtifact.test_the_three_compiles_together_give_the_pinned_sil_abi_section",
        "the section holds exactly the three contracts and the four struct layouts (Gen__KCC20State, KCC20State, PublicMintState, TokenSeedState). Not rebuilt: the union of three compiler ABI documents",
    );
}

#[test]
fn build_the_pinned_artifact_was_compiled_with_all_zero_arguments() {
    let family = Family::pinned();
    let hash = || zero_push(32);
    let int = || zero_push(8);
    let byte = || zero_push(1);
    let layouts = [
        (
            Contract::Kcc20,
            [hash(), int(), hash(), byte(), byte(), hash(), hash()].concat(),
        ),
        (
            Contract::PublicMint,
            [hash(), hash(), int(), int(), hash(), hash()].concat(),
        ),
        (
            Contract::TokenSeed,
            [hash(), hash(), hash(), hash()].concat(),
        ),
    ];
    for (contract, zero_state) in layouts {
        assert_eq!(
            family.bytecode(contract)[family.state_span(contract)],
            zero_state[..],
            "{contract}"
        );
    }
    built(
        "PinnedArtifact.test_the_pinned_artifact_was_compiled_with_all_zero_arguments",
        "the state span of each published bytecode is the all-zero state",
    );
}

#[test]
fn build_entry_lists_are_exactly_these() {
    let contracts = &artifact_json()["sil_abi"]["contracts"];
    for (contract, table) in ENTRIES {
        let published: BTreeMap<String, Vec<(String, String)>> =
            contracts[contract.name()]["entries"]
                .as_object()
                .expect("an object of entries")
                .iter()
                .map(|(name, entry)| {
                    let params = entry["params"]
                        .as_array()
                        .expect("an array of parameters")
                        .iter()
                        .map(|param| {
                            (
                                param["name"].as_str().expect("a name").to_string(),
                                type_name(&param["type"]),
                            )
                        })
                        .collect();
                    (name.clone(), params)
                })
                .collect();
        let expected: BTreeMap<String, Vec<(String, String)>> = table
            .iter()
            .map(|(name, params)| {
                let params = params
                    .iter()
                    .map(|(name, ty)| (name.to_string(), ty.to_string()))
                    .collect();
                (name.to_string(), params)
            })
            .collect();
        assert_eq!(published, expected, "{contract}");
        // The family knows the same entries, no more and no fewer.
        let known: Vec<&str> = Entry::ALL
            .iter()
            .filter(|entry| entry.contract() == contract)
            .map(|entry| entry.name())
            .collect();
        let listed: Vec<&str> = table.iter().map(|(name, _)| *name).collect();
        assert_eq!(known, listed, "{contract}");
    }
    built(
        "PinnedArtifact.test_entry_lists_are_exactly_these",
        "the eleven entries with parameter names and types, exact equality with the published artifact; the family's own entry list is the same eleven",
    );
}

#[test]
fn build_entry_lists_equal_the_manifest_s() {
    let manifest = published_json("manifest.json");
    let actors = manifest["actors"].as_array().expect("an array of actors");
    assert_eq!(actors.len(), 3);
    for ((contract, table), actor) in ENTRIES.iter().zip(actors) {
        assert_eq!(actor["name"], contract.name());
        assert_eq!(actor["sil"], format!("sil/{}", contract.sil_file_name()));
        let names: Vec<&str> = actor["entries"]
            .as_array()
            .expect("an array of entries")
            .iter()
            .map(|entry| entry["name"].as_str().expect("a name"))
            .collect();
        let listed: Vec<&str> = table.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, listed, "{contract}");
    }
    let templates = manifest["templates"].as_array().expect("an array");
    assert_eq!(templates.len(), 3);
    assert!(templates.iter().all(|template| template["hash"].is_null()));
    built(
        "PinnedArtifact.test_entry_lists_equal_the_manifest_s",
        "manifest.json: actors KCC20, PublicMint, TokenSeed with sil/<name>.sil, their entries in the published order, and null template hashes",
    );
}

#[test]
fn build_kcc20_json_names_the_two_token_entrypoints() {
    let descriptor = published_json("kcc20.json");
    assert_eq!(
        descriptor["entrypoints"],
        json!({ "transfer": "transfer", "delegator": "transfer_delegator" })
    );
    assert_eq!(descriptor["owner_schemes"], json!([0, 1, 2, 3, 4]));
    assert_eq!(descriptor["max_token_inputs"], 3);
    assert_eq!(descriptor["max_token_outputs"], 3);
    built(
        "PinnedArtifact.test_kcc20_json_names_the_two_token_entrypoints",
        "kcc20.json: entrypoints transfer / transfer_delegator, owner schemes 0..4, at most 3 token inputs and 3 token outputs",
    );
}

#[test]
fn build_golden_template_hashes_of_the_compiler_source() {
    assert_eq!(template_hash_of_parts(&[], &[]), template_hash(&[], &[]));
    assert_eq!(
        template_hash_of_parts(&[0x00, 0xff], &[0x10, 0x00, 0x80]),
        template_hash(&[0x00, 0xff], &[0x10, 0x00, 0x80])
    );
    // The two golden values are those of the unit tests in silverscript-lang/src/template.rs
    // of SilverScript 3ed9733.
    assert_eq!(
        encode_hex(&template_hash_of_parts(&[], &[])),
        "e572dff82304700b856a555ac3a4558d0df3646a3727816500270a93c66aac1e"
    );
    assert_eq!(
        encode_hex(&template_hash_of_parts(&[0x00, 0xff], &[0x10, 0x00, 0x80])),
        "6616a66757315de0221cb2acba729113cebde31f8d3ca7fa93878a0584b96905"
    );
    built(
        "Blake3.test_golden_template_hashes_of_the_compiler_source",
        "the template hash formula written out with the blake3 crate, and the compiler's own function, give the two golden values of the compiler's tests in silverscript-lang/src/template.rs of SilverScript 3ed9733 (empty parts; 00ff / 100080)",
    );
}

#[test]
fn build_hash_chain_vectors_of_the_spec() {
    let chain = &spec_vectors()["hash_chain"];
    let mut value: [u8; 32] = hex_bytes(&chain["x_0_hex"]).try_into().expect("32 bytes");
    let links = chain["links"].as_array().expect("an array of links");
    assert_eq!(links.len(), 3);
    for link in links {
        let key: [u8; 32] = hex_bytes(&link["pubkey_hex"]).try_into().expect("32 bytes");
        let mut preimage = value.to_vec();
        preimage.extend(key);
        let next = *blake3::hash(&preimage).as_bytes();
        assert_eq!(next, witness::chain_guard_for_key(&value, &key));
        assert_eq!(encode_hex(&next), link["x_hex"].as_str().expect("hex"));
        value = next;
    }
    assert_eq!(
        encode_hex(&value),
        chain["initial_borrow_guard_hex"].as_str().expect("hex")
    );
    assert_eq!(
        encode_hex(&value),
        "46530c9d75f7a5a1ce01b4e04cd8833f5f30c2482f99d855e3841279a8bcb8cc"
    );
    built(
        "Blake3.test_hash_chain_vectors_of_the_spec",
        "three links from a0*32: each value is BLAKE3(previous | key), by hand and by witness::chain_guard_for_key; the last is the initial borrow guard of the vectors",
    );
}

#[test]
fn build_p2sh_owner_value_of_the_spec_is_what_the_sdk_computes() {
    // The authority vector of the specification for a script-hash owner: redeem script 51.
    let lock = pay_to_script_hash_script(&[OpTrue]);
    assert_eq!(
        encode_hex(lock.script()),
        "aa20ce57216285125006ec18197bd8184221cefa559bb0798410d99a5bba5b07cd1d87"
    );
    assert_eq!(
        encode_hex(&lock.script()[2..34]),
        "ce57216285125006ec18197bd8184221cefa559bb0798410d99a5bba5b07cd1d"
    );
    // The owner field of the script-hash shape is that value.
    let scenario =
        shapes::transfer_with_owner_scheme(&Profile::Script, EntryRole::Leader, OWNER_P2SH);
    let owner = scenario.contract_input(0).state.as_kcc20().unwrap().owner;
    assert_eq!(owner, lock.script()[2..34]);
    built(
        "Blake3.test_p2sh_owner_value_of_the_spec_is_what_the_sdk_computes",
        "pay_to_script_hash_script(51) is aa20 ce57..cd1d 87 and its 32 middle bytes are the authority value of the specification's vector (the values are written out here; the vector file is not among the pinned inputs)",
    );
}

#[test]
fn build_public_key_hashes_of_the_spec() {
    // The two authority vectors of the specification, written out.
    let x_only = unhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    assert_eq!(
        encode_hex(&witness::public_key_hash(&x_only)),
        "f9f2a0b353f482f415281da3a00929d08a7d9a6498054f5ef6623b5580e607f7"
    );
    let compressed = [vec![0x02], x_only].concat();
    assert_eq!(
        encode_hex(&witness::public_key_hash(&compressed)),
        "1a15d6547364ad963c3b840e885639bb8136a4de757c0e7cf63f5de2f1cfbdbe"
    );
    // The owner witnesses of the conformance vectors that carry a key hash.
    let vectors = spec_vectors();
    let mut hashed = 0;
    for vector in vectors["owner_witness"].as_array().expect("an array") {
        let Some(expected) = vector["p2pkh_hash_hex"].as_str() else {
            continue;
        };
        let witness_bytes = hex_bytes(&vector["witness_hex"]);
        let public_key = &witness_bytes[1..witness_bytes.len() - 65];
        assert_eq!(
            encode_hex(blake3::hash(public_key).as_bytes()),
            expected,
            "{}",
            vector["scheme"]
        );
        hashed += 1;
    }
    assert_eq!(hashed, 2, "the Schnorr and the ECDSA key-hash scheme");
    built(
        "Blake3.test_public_key_hashes_of_the_spec",
        "BLAKE3 of the x-only and of the compressed generator key give the two authority values of the specification (written out here; that vector file is not among the pinned inputs); the two key-hash owner witnesses of the conformance vectors hash to their p2pkh_hash_hex",
    );
}

#[test]
fn build_template_hash_recomputed_by_hand_equals_the_compiler_s_and_the_artifact_s() {
    let family = Family::pinned();
    for (contract, size, offset, len, hash) in PUBLISHED {
        let bytecode = recompiled(contract);
        let (prefix, suffix) = (&bytecode[..offset], &bytecode[offset + len..]);
        let by_hand = template_hash_of_parts(prefix, suffix);
        assert_eq!(by_hand, template_hash(prefix, suffix), "{contract}");
        assert_eq!(encode_hex(&by_hand), hash, "{contract}");
        assert_eq!(by_hand, family.template_hash(contract), "{contract}");
        assert_eq!(prefix.len() + len + suffix.len(), size, "{contract}");
        assert_eq!(suffix.len(), [3885, 1868, 1222][contract.index()]);
    }
    built(
        "TemplateHashes.test_template_hash_recomputed_by_hand_equals_the_compiler_s_and_the_artifact_s",
        "BLAKE3(len8(prefix) | prefix | len8(suffix) | suffix) over the recompiled bytes equals the published hashes; 1+145+3885, 1+150+1868, 1+132+1222",
    );
}

#[test]
fn build_template_lengths_written_in_the_sources_are_the_real_ones() {
    let family = Family::pinned();
    for (contract, symbol) in [
        (Contract::Kcc20, "kcc20"),
        (Contract::PublicMint, "public_mint"),
        (Contract::TokenSeed, "token_seed"),
    ] {
        let source = refdata::pinned_sil_source(contract);
        assert_eq!(
            template_length_in_source(source, symbol, "prefix"),
            family.prefix(contract).len(),
            "{contract}"
        );
        assert_eq!(
            template_length_in_source(source, symbol, "suffix"),
            family.suffix(contract).len(),
            "{contract}"
        );
    }
    built(
        "TemplateHashes.test_template_lengths_written_in_the_sources_are_the_real_ones",
        "the gen__const_<symbol>_prefix_len / _suffix_len constants of the three sources, read as little-endian numbers, are the real lengths: 1 and 3885, 1 and 1868, 1 and 1222",
    );
}

#[test]
fn build_template_hash_is_the_same_for_every_state() {
    let family = Family::pinned();
    let states: [State; 3] = [
        Kcc20State {
            amount: 12_345,
            owner: [0x07; 32],
            owner_scheme: 0x04,
            borrow_scheme: 0x03,
            borrow_guard: [0x09; 32],
            extension_commitment: [0x05; 32],
        }
        .into(),
        PublicMintState::new([0x07; 32], 1 << 62, 77)
            .with_extension([0x05; 32])
            .into(),
        TokenSeedState::new([0x07; 32])
            .with_extension([0x05; 32])
            .into(),
    ];
    for state in states {
        let contract = state.contract();
        let span = family.state_span(contract);
        let redeem = family.redeem_script(&state).expect("a redeem script");
        assert_eq!(redeem.len(), family.bytecode(contract).len(), "{contract}");
        assert_eq!(redeem[..span.start], *family.prefix(contract), "{contract}");
        assert_eq!(redeem[span.end..], *family.suffix(contract), "{contract}");
        assert_eq!(
            template_hash_of_parts(&redeem[..span.start], &redeem[span.end..]),
            family.template_hash(contract),
            "{contract}"
        );
        assert!(
            redeem != family.bytecode(contract),
            "{contract}: the state differs"
        );
    }
    built(
        "TemplateHashes.test_template_hash_is_the_same_for_every_state",
        "the script of a coin with a non-zero state (amount 12345 and schemes 04/03; remaining 2^62 and 77 per mint; a seed) has the published length, prefix and suffix, so the same template hash; only the state bytes differ. Built by the family from the published bytes, not by a second compile",
    );
}

#[test]
fn build_argent_template_plan_carries_the_same_hashes() {
    let family = Family::pinned();
    let templates = artifact_json()["argent"]["template_plan"]["templates"]
        .as_array()
        .expect("an array of templates");
    assert_eq!(templates.len(), 3);
    for (contract, template) in Contract::ALL.iter().zip(templates) {
        assert_eq!(template["actor"], contract.name());
        assert_eq!(
            json_bytes(&template["sil_template_hash"]),
            family.template_hash(*contract),
            "{contract}"
        );
    }
    built(
        "TemplateHashes.test_argent_template_plan_carries_the_same_hashes",
        "argent.template_plan.templates lists KCC20, PublicMint, TokenSeed in this order, each with the template hash of its bytecode",
    );
}

#[test]
fn build_actor_type_handles_are_the_prefix_extended_by_the_template_hashes() {
    let family = Family::pinned();
    let templates = artifact_json()["argent"]["template_plan"]["templates"]
        .as_array()
        .expect("an array of templates");
    let context: [&[Contract]; 3] = [
        &[Contract::Kcc20],
        &[Contract::Kcc20, Contract::PublicMint],
        &[Contract::Kcc20, Contract::TokenSeed],
    ];
    for (contract, template) in Contract::ALL.iter().zip(templates) {
        let handle = &template["actor_type_handle"]["template"];
        let mut extended = family.prefix(*contract).to_vec();
        for carried in context[contract.index()] {
            extended.push(0x20);
            extended.extend(family.template_hash(*carried));
        }
        let suffix = family.suffix(*contract);
        assert_eq!(json_bytes(&handle["prefix"]), extended, "{contract}");
        assert!(json_bytes(&handle["suffix"]) == suffix, "{contract}");
        assert_eq!(
            json_bytes(&handle["hash"]),
            template_hash_of_parts(&extended, suffix),
            "{contract}"
        );
    }
    built(
        "TemplateHashes.test_actor_type_handles_are_the_prefix_extended_by_the_template_hashes",
        "each actor type handle is the prefix followed by the pushes of the template hashes the contract carries (KCC20; KCC20 and PublicMint; KCC20 and TokenSeed), the same suffix, and the template hash formula over the two",
    );
}

#[test]
fn build_constructor_parameters_in_the_sources_are_in_the_order_the_helper_uses() {
    let expected: [(Contract, &[&str]); 3] = [
        (
            Contract::Kcc20,
            &[
                "gen__init_kcc20_template",
                "init_amount",
                "init_owner",
                "init_owner_scheme",
                "init_borrow_scheme",
                "init_borrow_guard",
                "init_extension_commitment",
            ],
        ),
        (
            Contract::PublicMint,
            &[
                "gen__init_kcc20_template",
                "gen__init_public_mint_template",
                "init_remaining",
                "init_mint_amount",
                "init_owner",
                "init_extension_commitment",
            ],
        ),
        (
            Contract::TokenSeed,
            &[
                "gen__init_kcc20_template",
                "gen__init_token_seed_template",
                "init_owner",
                "init_extension_commitment",
            ],
        ),
    ];
    let family = Family::pinned();
    for (contract, parameters) in expected {
        let source = refdata::pinned_sil_source(contract);
        assert_eq!(
            constructor_parameters(source, contract),
            parameters,
            "{contract}"
        );
        // One push in the state of a coin per constructor parameter, in that order.
        let state = &family.bytecode(contract)[family.state_span(contract)];
        assert_eq!(
            raw::split_pushes(state).expect("pushes").len(),
            parameters.len(),
            "{contract}"
        );
    }
    built(
        "ConstructorArguments.test_constructor_parameters_in_the_sources_are_in_the_order_the_helper_uses",
        "the constructor parameters of the three sources in order; the state of a coin holds one push per parameter",
    );
}

#[test]
fn build_template_arguments_are_the_template_hashes() {
    let family = Family::pinned();
    let token: State = Kcc20State::new([0x07; 32], 5).into();
    let minter: State = PublicMintState::new([0x07; 32], 25, 10).into();
    let seed: State = TokenSeedState::new([0x07; 32]).into();
    let fields = |state: &State| -> Vec<Vec<u8>> {
        let bytes = family.state_bytes(state).expect("the state encodes");
        raw::split_pushes(&bytes).expect("pushes")
    };
    let push_of =
        |contract: Contract| [vec![0x20], family.template_hash(contract).to_vec()].concat();
    assert_eq!(fields(&token)[0], push_of(Contract::Kcc20));
    assert_eq!(
        fields(&minter)[..2],
        [push_of(Contract::Kcc20), push_of(Contract::PublicMint)]
    );
    assert_eq!(
        fields(&seed)[..2],
        [push_of(Contract::Kcc20), push_of(Contract::TokenSeed)]
    );
    built(
        "ConstructorArguments.test_template_arguments_are_the_template_hashes",
        "the leading state fields the family writes: a token coin carries the KCC20 template hash, a minter the KCC20 and PublicMint hashes, a seed the KCC20 and TokenSeed hashes",
    );
}

#[test]
fn build_a_coin_s_script_is_prefix_then_state_then_suffix() {
    let family = Family::pinned();
    let mut guard = [0u8; 32];
    guard[..8].copy_from_slice(&500i64.to_le_bytes());
    let state: State = Kcc20State {
        amount: 1000,
        owner: [0xab; 32],
        owner_scheme: 0x01,
        borrow_scheme: 0x01,
        borrow_guard: guard,
        extension_commitment: [0; 32],
    }
    .into();
    let by_hand = [
        family.prefix(Contract::Kcc20).to_vec(),
        vec![0x20],
        family.template_hash(Contract::Kcc20).to_vec(),
        unhex("08e803000000000000"),
        vec![0x20],
        vec![0xab; 32],
        vec![0x01, 0x01, 0x01, 0x01],
        vec![0x20],
        guard.to_vec(),
        zero_push(32),
        family.suffix(Contract::Kcc20).to_vec(),
    ]
    .concat();
    assert!(family.redeem_script(&state).expect("a redeem script") == by_hand);
    let lock = family.script_public_key(&state).expect("a lock");
    assert_eq!(lock.script().len(), 35);
    assert_eq!(lock.script()[..2], [0xaa, 0x20]);
    assert_eq!(lock.script()[34], 0x87);
    assert_eq!(lock, pay_to_script_hash_script(&by_hand));
    built(
        "ConstructorArguments.test_a_coin_s_script_is_prefix_then_state_then_suffix",
        "the script of a token coin written out by hand (prefix, template hash, amount 1000, owner, schemes 01/01, threshold guard 500, zero commitment, suffix) is what the family builds; its lock is aa 20 <hash> 87, 35 bytes. On the script engine this lock is compared with the pushed script (see own script/...)",
    );
}

#[test]
fn build_state_encoding_equals_the_spec_vector() {
    let vectors = spec_vectors();
    let family = Family::pinned();
    let state = token_state_of_vector(&vectors["state_encoding"]["state"]);
    let redeem = family
        .redeem_script(&State::Kcc20(state))
        .expect("a redeem script");
    assert_eq!(redeem[1], 0x20);
    assert_eq!(redeem[2..34], family.template_hash(Contract::Kcc20));
    assert_eq!(
        encode_hex(&redeem[34..146]),
        vectors["state_encoding"]["encoded_hex"]
            .as_str()
            .expect("hex")
    );
    assert_eq!(vectors["state_record"]["encoded_state_length"], 145 - 33);
    built(
        "ConstructorArguments.test_state_encoding_equals_the_spec_vector",
        "bytes 34..146 of the coin's script are the 112 encoded bytes of the specification's state vector, behind the 33-byte push of the template hash",
    );
}

#[test]
fn build_transfer_call_bytes_equal_the_spec_vector() {
    let vectors = spec_vectors();
    let family = Family::pinned();
    let arguments = &vectors["transfer_arguments"];
    let states: Vec<Kcc20State> = arguments["next_states"]
        .as_array()
        .expect("an array")
        .iter()
        .map(token_state_of_vector)
        .collect();
    let witness_bytes = hex_bytes(&arguments["witness_hex"]);
    let mut expected: Vec<u8> = arguments["grouped_field_pushes_hex"]
        .as_array()
        .expect("an array")
        .iter()
        .flat_map(hex_bytes)
        .collect();
    expected.extend(hex_bytes(&arguments["witness_push_hex"]));
    expected.extend(hex_bytes(&arguments["dispatch_tag_push_hex"]));

    let call = family
        .call_bytes(
            Entry::Transfer,
            &[kcc20_states_value(&states), witness_bytes.clone().into()],
        )
        .expect("the call encodes");
    assert_eq!(encode_hex(&call), encode_hex(&expected));

    // The same bytes are what a scenario puts in front of the redeem script, and so what
    // the engine executes.
    let mut scenario = shapes::transfer(&Profile::Script, 1, 2);
    let input = scenario.contract_input_mut(0);
    *input.declared_states_mut() = states;
    *input.witness_mut() = witness_bytes.into();
    let assembled = scenario
        .assemble(family)
        .expect("the assembler does not judge");
    let pushes = raw::split_pushes(&assembled.tx.inputs[0].signature_script).expect("pushes");
    assert_eq!(pushes.len(), 9);
    assert_eq!(pushes[..8].concat(), expected);
    built(
        "ConstructorArguments.test_transfer_call_bytes_equal_the_spec_vector",
        "the call bytes of transfer for the vector's two next states and placeholder witness: six column pushes, the witness push, the tag push 04 79c71c23; a scenario writes exactly these eight pushes in front of the redeem script",
    );
}

#[test]
fn build_dispatch_tags_equal_the_spec_vector() {
    let vectors = spec_vectors();
    let family = Family::pinned();
    let dispatch = vectors["dispatch"].as_array().expect("an array");
    assert_eq!(dispatch.len(), 2);
    for vector in dispatch {
        let name = vector["entrypoint"].as_str().expect("a name");
        let entry = Entry::from_name(Contract::Kcc20, name).expect("a KCC20 entry");
        assert_eq!(
            encode_hex(&family.dispatch_tag(entry)),
            vector["dispatch_tag_hex"].as_str().expect("hex"),
            "{name}"
        );
    }
    assert_eq!(
        encode_hex(&family.dispatch_tag(Entry::Transfer)),
        "79c71c23"
    );
    assert_eq!(
        encode_hex(&family.dispatch_tag(Entry::TransferDelegator)),
        "fd3ef14a"
    );
    built(
        "ConstructorArguments.test_dispatch_tags_equal_the_spec_vector",
        "transfer 79c71c23 and transfer_delegator fd3ef14a, as in the conformance vectors",
    );
}

#[test]
fn build_dispatch_tags_recomputed_by_hand() {
    let family = Family::pinned();
    let signatures = [
        (
            Entry::Transfer,
            "transfer({int,byte[32],byte,byte,byte[32],byte[32]}[],byte[])",
        ),
        (Entry::TransferDelegator, "transfer_delegator(byte[])"),
        (Entry::MintReclaimInto, "reclaim_into()"),
        (Entry::SeedReclaim, "reclaim()"),
        (Entry::SeedReclaimDelegator, "reclaim_delegator(sig)"),
        (Entry::MintReclaimDelegator, "reclaim_delegator(sig)"),
        (Entry::MintSplit, "split(int,pubkey)"),
        (Entry::MintReclaim, "reclaim(sig)"),
        (Entry::SeedSplit, "split(pubkey)"),
    ];
    for (entry, signature) in signatures {
        assert_eq!(
            blake3::hash(signature.as_bytes()).as_bytes()[..4],
            family.dispatch_tag(entry),
            "{entry}: {signature}"
        );
    }
    built(
        "ConstructorArguments.test_dispatch_tags_recomputed_by_hand",
        "a tag is the first four bytes of BLAKE3 over the signature text: the six texts of the earlier check and three more (PublicMint reclaim_delegator, reclaim(sig), TokenSeed split(pubkey)). The two reclaim_delegator entries share one tag, in two different scripts",
    );
}

#[test]
fn build_the_reference_s_copy_of_the_vectors_is_the_spec_s_file() {
    let bytes = fs::read(refdata::conformance_path()).expect("the vectors are readable");
    // Line ends differ between checkouts; the text does not.
    let text: Vec<u8> = bytes.into_iter().filter(|byte| *byte != b'\r').collect();
    assert_eq!(text.len(), 19_275);
    assert_eq!(
        encode_hex(blake3::hash(&text).as_bytes()),
        CONFORMANCE_TEXT_BLAKE3
    );
    let vectors = spec_vectors();
    assert_eq!(vectors["kcc"], 20);
    assert_eq!(vectors["format_version"], 1);
    built(
        "ConstructorArguments.test_the_reference_s_copy_of_the_vectors_is_the_spec_s_file",
        "the reference's copy of the conformance vectors is pinned by content (19,275 bytes with LF line ends, BLAKE3 as written here). The specification repository's file is not among the pinned inputs of this workspace, so the two files are not compared here",
    );
}

#[test]
fn build_unknown_state_field_is_a_usage_error_of_the_helper() {
    // The earlier helper took a state as a dictionary and raised on a field the contract
    // does not have. Here a state is a struct: a seed has an owner and an extension
    // commitment, and no place to write an amount.
    let seed = TokenSeedState::new([0; 32]);
    let authored = seed.authored();
    assert!(authored.contains_key("owner"));
    assert!(authored.contains_key("extension_commitment"));
    assert!(!authored.contains_key("amount"));
    built(
        "ConstructorArguments.test_unknown_state_field_is_a_usage_error_of_the_helper",
        "behaviour of the earlier helper; here the three states are structs with fixed fields, so a seed with an amount cannot be written",
    );
}
