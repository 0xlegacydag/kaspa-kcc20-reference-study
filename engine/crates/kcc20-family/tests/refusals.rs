//! Wrong transactions leave the assembler and reach the engine.
//!
//! The crate does not judge; these tests only show that a scenario made wrong on purpose is
//! assembled, is refused by the authors' runner at the expected input, and that the opcode
//! the engine stopped at is the one the rule inventory names for the broken rule.

mod common;

use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_txscript_errors::TxScriptError;
use kcc20_family::scenario::{Assembled, Call, LateBytes};
use kcc20_family::shapes::{self, BorrowKind, Profile};
use kcc20_family::sourcemap::SourceMap;
use kcc20_family::states::State;
use kcc20_family::{Contract, EntryRole, Family, keys, raw, witness};

/// The id of the rule whose refusing opcode is the last one the engine logged for the input.
fn refusing_rule(
    assembled: &Assembled,
    input_index: usize,
    contract: Contract,
) -> (TxScriptError, Option<String>, usize) {
    let run = common::run_input_with_log(assembled, input_index);
    let error = run.result.clone().expect_err("the input is refused");
    let op_index = common::last_redeem_opcode_index(assembled, input_index, &run)
        .expect("the engine reached the redeem script");
    let map = SourceMap::pinned().contract(contract);
    let opcode = map
        .opcode_by_index(op_index)
        .expect("the opcode exists in the redeem script");
    assert!(
        run.last_line
            .starts_with(&format!("Executing opcode: {}", opcode.name)),
        "the log ends with `{}`, the source map says opcode {op_index} is {}",
        run.last_line.chars().take(60).collect::<String>(),
        opcode.name
    );
    (
        error,
        map.rule_at(opcode.offset).map(|rule| rule.id.clone()),
        opcode.offset,
    )
}

#[test]
fn a_wrong_owner_key_is_refused_at_the_leader() {
    let family = Family::pinned();
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    *scenario.contract_input_mut(0).witness_mut() =
        witness::owner_key(keys::CAROL, EntryRole::Leader, SIG_HASH_ALL);
    let assembled = scenario
        .assemble(family)
        .expect("the assembler does not judge");

    let (input_index, error) = common::refused_input(&assembled);
    assert_eq!(input_index, 0);
    assert_eq!(error, TxScriptError::VerifyError);
    // K-38: the Schnorr signature of owner scheme 0x00 (OpVerify behind OpCheckSig).
    let (error, rule, offset) = refusing_rule(&assembled, 0, Contract::Kcc20);
    assert_eq!(error, TxScriptError::VerifyError);
    assert_eq!(rule.as_deref(), Some("K-38"));
    assert_eq!(offset, 2249);
}

#[test]
fn a_wrong_owner_key_is_refused_at_the_delegate() {
    let family = Family::pinned();
    let mut scenario = shapes::borrow(&Profile::Script, BorrowKind::Threshold);
    *scenario.contract_input_mut(1).witness_mut() =
        witness::owner_key(keys::CAROL, EntryRole::Delegate, SIG_HASH_ALL);
    let assembled = scenario
        .assemble(family)
        .expect("the assembler does not judge");

    // The runner stops at the first failing input, so index 1 also says the leader passed.
    let (input_index, error) = common::refused_input(&assembled);
    assert_eq!(input_index, 1);
    assert_eq!(error, TxScriptError::VerifyError);
    let (_, rule, offset) = refusing_rule(&assembled, 1, Contract::Kcc20);
    assert_eq!(rule.as_deref(), Some("K-38"));
    assert_eq!(
        offset, 3837,
        "the same rule, in the copy of the owner check that transfer_delegator runs"
    );
}

#[test]
fn one_token_more_in_the_output_is_refused() {
    // Declared and locked alike: 101 tokens out of 100. The output check would hold; the sum
    // rule does not.
    let family = Family::pinned();
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    scenario.contract_input_mut(0).declared_states_mut()[0].amount += 1;
    scenario
        .contract_output_mut(0)
        .state
        .as_kcc20_mut()
        .expect("a token output")
        .amount += 1;
    let assembled = scenario
        .assemble(family)
        .expect("the assembler does not judge");

    let (input_index, error) = common::refused_input(&assembled);
    assert_eq!(input_index, 0);
    assert_eq!(error, TxScriptError::VerifyError);
    // K-37: the sum of the declared amounts equals the sum of the input amounts.
    let (_, rule, offset) = refusing_rule(&assembled, 0, Contract::Kcc20);
    assert_eq!(rule.as_deref(), Some("K-37"));
    assert_eq!(offset, 2203);
}

#[test]
fn a_declared_state_that_differs_from_the_locked_output_is_refused() {
    // The call declares the honest successor; the output is locked to another owner. The
    // owner's signature covers the outputs, so the scenario signs what it really sends.
    let family = Family::pinned();
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    scenario
        .contract_output_mut(0)
        .state
        .as_kcc20_mut()
        .expect("a token output")
        .owner = [0x42; 32];
    let assembled = scenario
        .assemble(family)
        .expect("the assembler does not judge");

    // Declared and locked really differ in the assembled bytes.
    let declared = family
        .script_public_key(&State::Kcc20(
            scenario.contract_input_mut(0).declared_states_mut()[0].clone(),
        ))
        .expect("spk");
    assert_ne!(assembled.tx.outputs[0].script_public_key, declared);

    let (input_index, error) = common::refused_input(&assembled);
    assert_eq!(input_index, 0);
    assert_eq!(error, TxScriptError::VerifyError);
    // K-66: every bound output is locked to the script of its declared state.
    let (_, rule, offset) = refusing_rule(&assembled, 0, Contract::Kcc20);
    assert_eq!(rule.as_deref(), Some("K-66"));
    assert_eq!(offset, 2854);
}

#[test]
fn a_redeem_script_that_is_not_the_coins_script_stops_at_the_coins_own_check() {
    // The coin is locked to the state with 100 tokens; the signature script pushes the
    // script of the state with 101. The coin's own pay-to-script-hash test fails before any
    // contract code runs.
    let family = Family::pinned();
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    let mut other = scenario.contract_input_mut(0).state.clone();
    other.as_kcc20_mut().expect("a token coin").amount = 101;
    scenario.contract_input_mut(0).pushed_redeem =
        Some(family.redeem_script(&other).expect("redeem script"));
    let assembled = scenario
        .assemble(family)
        .expect("the assembler does not judge");

    let (input_index, error) = common::refused_input(&assembled);
    assert_eq!(input_index, 0);
    assert_eq!(error, TxScriptError::EvalFalse);
    // The log ends inside the coin's script (OpBlake2b, push of the hash, OpEqual): no opcode
    // of the redeem script was reached.
    let run = common::run_input_with_log(&assembled, 0);
    let pushes = assembled.inputs[0]
        .signature_script_opcodes
        .expect("the signature script parses");
    assert_eq!(run.log_lines, pushes + 3);
    assert!(
        run.last_line.starts_with("Executing opcode: OpEqual"),
        "{}",
        run.last_line
    );
}

#[test]
fn a_coin_locked_to_another_script_is_spent_by_that_script() {
    // The locking script override: the coin is said to hold a token state but is locked by
    // OP_TRUE. The engine runs what the coin says, not what the scenario believes.
    let family = Family::pinned();
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    scenario.contract_input_mut(0).locking_script = Some(shapes::op_true_script());
    let assembled = scenario
        .assemble(family)
        .expect("the assembler does not judge");
    assert_eq!(
        assembled.utxos[0].script_public_key,
        shapes::op_true_script()
    );
    // Not a pay-to-script-hash coin: the pushes of the call stay on the stack next to the
    // result of OP_TRUE, and the engine demands a clean stack.
    let run = common::run_input_with_log(&assembled, 0);
    let pushes = assembled.inputs[0]
        .signature_script_opcodes
        .expect("the signature script parses");
    assert_eq!(run.result, Err(TxScriptError::CleanStack(pushes)));
}

#[test]
fn an_empty_signature_reaches_the_argument_size_check_of_reclaim() {
    // The codec cannot write a signature argument that is not 65 bytes long. The parts patch
    // can: the signature push becomes an empty push.
    let family = Family::pinned();
    let mut scenario = shapes::mint_reclaim(&Profile::Script);
    scenario
        .contract_input_mut(0)
        .set_patch(|parts| parts.arguments[0] = vec![0x00]);
    let assembled = scenario
        .assemble(family)
        .expect("the assembler does not judge");
    assert_eq!(
        assembled.tx.inputs[0].signature_script[..6],
        [0x00, 0x04, 0x35, 0xee, 0xcc, 0xa6]
    );

    let (input_index, error) = common::refused_input(&assembled);
    assert_eq!(input_index, 0);
    assert_eq!(error, TxScriptError::VerifyError);
    // M-31: the owner_signature push is exactly 65 bytes; OpCheckSig is never reached.
    let (_, rule, offset) = refusing_rule(&assembled, 0, Contract::PublicMint);
    assert_eq!(rule.as_deref(), Some("M-31"));
    assert_eq!(offset, 880);
}

#[test]
fn an_unknown_tag_reaches_the_end_of_the_dispatcher() {
    let family = Family::pinned();
    let mut scenario = shapes::mint_reclaim_into(&Profile::Script);
    scenario
        .contract_input_mut(0)
        .set_patch(|parts| parts.tag = raw::push(&[0, 0, 0, 0]).expect("push"));
    let assembled = scenario
        .assemble(family)
        .expect("the assembler does not judge");
    assert_eq!(
        assembled.tx.inputs[0].signature_script[..5],
        [0x04, 0, 0, 0, 0]
    );

    let (input_index, error) = common::refused_input(&assembled);
    assert_eq!(input_index, 0);
    // M-01: no entry has this tag; the script ends in OpReturn.
    let (log_error, rule, offset) = refusing_rule(&assembled, 0, Contract::PublicMint);
    assert_eq!(error, log_error);
    assert_eq!(rule.as_deref(), Some("M-01"));
    assert_eq!(offset, 2013);
    assert!(
        matches!(error, TxScriptError::EarlyReturn),
        "observed: {error:?}"
    );
}

#[test]
fn raw_call_bytes_equal_to_the_typed_call_give_the_same_transaction() {
    // `Call::Raw` takes the bytes in front of the redeem push as they are. Fed with the bytes
    // of the honest call, it must reproduce the honest transaction.
    let family = Family::pinned();
    let scenario = shapes::mint(&Profile::Script);
    let honest = scenario.assemble(family).expect("the shape assembles");

    let mut raw_scenario = scenario.clone();
    let input = raw_scenario.contract_input_mut(0);
    let redeem = family.redeem_script(&input.state).expect("redeem script");
    let honest_script = honest.tx.inputs[0].signature_script.clone();
    let call_bytes = honest_script
        [..honest_script.len() - raw::push_redeem(&redeem).expect("push").len()]
        .to_vec();
    input.call = Call::Raw(LateBytes::fixed(call_bytes));
    let assembled = raw_scenario
        .assemble(family)
        .expect("the assembler does not judge");
    assert_eq!(assembled.tx, honest.tx);
    assert_eq!(
        assembled.inputs[0].entry(),
        None,
        "a raw call names no entry"
    );
    common::run_authors(&assembled).expect("the same bytes are accepted");
}

#[test]
fn a_whole_signature_script_override_is_written_as_given() {
    let family = Family::pinned();
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    scenario.contract_input_mut(0).signature_script = Some(LateBytes::fixed([0x51, 0x52]));
    let assembled = scenario
        .assemble(family)
        .expect("the assembler does not judge");
    assert_eq!(assembled.tx.inputs[0].signature_script, [0x51, 0x52]);
    assert_eq!(assembled.inputs[0].signature_script_opcodes, Some(2));
}

#[test]
fn a_damaged_signature_is_made_from_a_real_one() {
    // `LateBytes::map` post-processes the witness the shape computes: here the signature hash
    // type byte is replaced by one the engine does not know.
    let family = Family::pinned();
    let mut scenario = shapes::transfer(&Profile::Script, 1, 1);
    let honest = scenario.contract_input_mut(0).witness_mut().clone();
    *scenario.contract_input_mut(0).witness_mut() = honest.map(|mut witness| {
        *witness
            .last_mut()
            .expect("the witness ends with the type byte") = 0x03;
        witness
    });
    let assembled = scenario
        .assemble(family)
        .expect("the assembler does not judge");
    let (input_index, error) = common::refused_input(&assembled);
    assert_eq!(input_index, 0);
    assert_eq!(error, TxScriptError::InvalidSigHashType(0x03));
}
