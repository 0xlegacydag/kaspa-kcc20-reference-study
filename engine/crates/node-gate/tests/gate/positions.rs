//! Where the engine stopped: the position method on scripts assembled in the tests, where
//! the failing opcode is known in advance.

use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_txscript_errors::TxScriptError;
use node_gate::{
    GateParams, ScriptKind, StopPoint,
    engine::{OpcodeStop, ScriptRun},
};

use crate::common::*;

const OP_FALSE: u8 = 0x00;
const OP_1: u8 = 0x51;
const OP_2: u8 = 0x52;
const OP_3: u8 = 0x53;
const OP_NOP: u8 = 0x61;
const OP_IF: u8 = 0x63;
const OP_VERIF: u8 = 0x65;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_VERIFY: u8 = 0x69;
const OP_RETURN: u8 = 0x6a;
const OP_TOALTSTACK: u8 = 0x6b;
const OP_DROP: u8 = 0x75;
const OP_DUP: u8 = 0x76;
const OP_CAT: u8 = 0x7e;
const OP_LEFT: u8 = 0x80;
const OP_1ADD: u8 = 0x8b;
const OP_ADD: u8 = 0x93;
const OP_NUMEQUALVERIFY: u8 = 0x9d;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_CHAINBLOCKSEQCOMMIT: u8 = 0xd4;
const OP_BLAKE3WITHKEY: u8 = 0xda;

fn run(gate: &GateParams, spend: &Spend) -> ScriptRun {
    submit(gate, spend).committed_runs.remove(0)
}

/// `run` under a name that a local variable called `run` does not hide.
fn run_one(gate: &GateParams, spend: &Spend) -> ScriptRun {
    run(gate, spend)
}

fn at(script: ScriptKind, op_index: usize, byte_offset: usize, opcode: u8, name: &str, executed: bool) -> Option<StopPoint> {
    Some(StopPoint::Opcode(OpcodeStop { script, op_index, byte_offset, opcode, opcode_name: Some(name.to_string()), executed }))
}

/// Runs `redeem_script` in a pay-to-script-hash coin with `arguments` as the other pushes
/// of the signature script, under a budget of one unit.
fn redeem(redeem_script: &[u8], arguments: &[u8]) -> ScriptRun {
    let gate = node();
    run(&gate, &p2sh_spend(&gate, redeem_script, arguments, 1))
}

#[test]
fn a_failed_verify_in_a_straight_script() {
    // index:  0     1         2         3          4
    let script = [OP_1, OP_VERIFY, OP_FALSE, OP_VERIFY, OP_1];
    let run = redeem(&script, &[]);
    assert_eq!(run.result, Err(TxScriptError::VerifyError));
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 3, 3, OP_VERIFY, "OpVerify", true));
    // One line for the push of the redeem script, three for the lock, four in the redeem script.
    assert_eq!(run.trace.as_ref().unwrap().opcodes_logged, 1 + 3 + 4);
    assert!(run.trace.unwrap().last_line.unwrap().starts_with("Executing opcode: OpVerify, astack: [], dstack: [\"0x\"]"));
}

#[test]
fn data_pushes_move_the_byte_offset_away_from_the_opcode_index() {
    // index 0: push 3 bytes (offset 0), 1: push 70 bytes (4), 2: push 300 bytes (75), 3: OpDrop (378),
    // 4: Op2Drop (379), 5: OpFalse (380), 6: OpVerify (381), 7: Op1 (382)
    let mut script = vec![0x03, 1, 2, 3];
    script.push(70);
    script.extend_from_slice(&[7; 70]);
    script.extend_from_slice(&[0x4d, 0x2c, 0x01]);
    script.extend_from_slice(&[9; 300]);
    script.extend_from_slice(&[OP_DROP, 0x6d, OP_FALSE, OP_VERIFY, OP_1]);
    let run = redeem(&script, &[]);
    assert_eq!(run.result, Err(TxScriptError::VerifyError));
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 6, 381, OP_VERIFY, "OpVerify", true));
}

#[test]
fn opcodes_in_a_skipped_branch_are_counted() {
    // 0: OpFalse (0), 1: OpIf (1), 2: push 3 bytes (2), 3: OpDrop (6), 4: OpVerify (7) - skipped,
    // 5: OpEndIf (8), 6: Op1 (9), 7: OpFalse (10), 8: OpVerify (11) - fails, 9: Op1 (12)
    let script = [OP_FALSE, OP_IF, 0x03, 0xaa, 0xbb, 0xcc, OP_DROP, OP_VERIFY, OP_ENDIF, OP_1, OP_FALSE, OP_VERIFY, OP_1];
    let run = redeem(&script, &[]);
    assert_eq!(run.result, Err(TxScriptError::VerifyError));
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 8, 11, OP_VERIFY, "OpVerify", true));
}

#[test]
fn a_failure_in_the_taken_else_branch() {
    // 0: OpFalse (0), 1: OpIf (1), 2: Op1 (2), 3: OpVerify (3), 4: OpElse (4), 5: push 2 bytes (5),
    // 6: OpDrop (8), 7: OpReturn (9) - fails, 8: OpEndIf (10), 9: Op1 (11)
    let script = [OP_FALSE, OP_IF, OP_1, OP_VERIFY, OP_ELSE, 0x02, 0xaa, 0xbb, OP_DROP, OP_RETURN, OP_ENDIF, OP_1];
    let run = redeem(&script, &[]);
    assert_eq!(run.result, Err(TxScriptError::EarlyReturn));
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 7, 9, OP_RETURN, "OpReturn", true));

    // The same script with the condition true: the If branch runs, the Else branch is skipped.
    let mut taken = script;
    taken[0] = OP_1;
    assert_eq!(redeem(&taken, &[]).result, Ok(()));
}

#[test]
fn nested_branches() {
    // 0: Op1, 1: OpIf, 2: OpFalse, 3: OpIf, 4: OpReturn (skipped), 5: OpElse, 6: Op2, 7: Op3,
    // 8: OpNumEqualVerify (fails), 9: OpEndIf, 10: OpEndIf, 11: Op1
    let script = [OP_1, OP_IF, OP_FALSE, OP_IF, OP_RETURN, OP_ELSE, OP_2, OP_3, OP_NUMEQUALVERIFY, OP_ENDIF, OP_ENDIF, OP_1];
    let run = redeem(&script, &[]);
    assert_eq!(run.result, Err(TxScriptError::VerifyError));
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 8, 8, OP_NUMEQUALVERIFY, "OpNumEqualVerify", true));
}

#[test]
fn arguments_in_the_signature_script_do_not_shift_the_redeem_position() {
    // Redeem: 0: OpAdd, 1: Op3, 2: OpNumEqualVerify, 3: Op1. Arguments 1 and 2 pass, 2 and 2 fail.
    let script = [OP_ADD, OP_3, OP_NUMEQUALVERIFY, OP_1];
    assert_eq!(redeem(&script, &[OP_1, OP_2]).result, Ok(()));
    let run = redeem(&script, &[OP_2, OP_2]);
    assert_eq!(run.result, Err(TxScriptError::VerifyError));
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 2, 2, OP_NUMEQUALVERIFY, "OpNumEqualVerify", true));

    // Many arguments, some of them long: the redeem position is the same.
    let mut arguments = Vec::new();
    for _ in 0..20 {
        arguments.extend_from_slice(&[0x02, 0xaa, 0xbb]);
    }
    arguments.extend_from_slice(&[OP_2, OP_2]);
    let script_dropping: Vec<u8> = [vec![OP_ADD, OP_3, OP_NUMEQUALVERIFY], vec![0x6d; 10], vec![OP_1]].concat();
    let ok_arguments: Vec<u8> = [arguments[..60].to_vec(), vec![OP_1, OP_2]].concat();
    assert_eq!(redeem(&script_dropping, &ok_arguments).result, Ok(()));
    let run = redeem(&script_dropping, &arguments);
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 2, 2, OP_NUMEQUALVERIFY, "OpNumEqualVerify", true));
}

#[test]
fn a_disabled_opcode_is_refused_even_in_a_skipped_branch() {
    // 0: OpFalse, 1: OpIf, 2: OpLeft (disabled; refused before it is logged), 3: OpEndIf, 4: Op1
    let script = [OP_FALSE, OP_IF, OP_LEFT, OP_ENDIF, OP_1];
    let run = redeem(&script, &[]);
    assert!(matches!(run.result, Err(TxScriptError::OpcodeDisabled(_))), "{:?}", run.result);
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 2, 2, OP_LEFT, "OpLeft", false));
}

#[test]
fn an_always_illegal_opcode_is_refused_even_in_a_skipped_branch() {
    let script = [OP_FALSE, OP_IF, OP_NOP, OP_VERIF, OP_ENDIF, OP_1];
    let run = redeem(&script, &[]);
    assert!(matches!(run.result, Err(TxScriptError::OpcodeReserved(_))), "{:?}", run.result);
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 3, 3, OP_VERIF, "OpVerIf", false));
}

#[test]
fn a_reserved_opcode_fails_only_when_executed() {
    // OpReserved (0x50) in a skipped branch is harmless; executed, it is the last logged opcode.
    let skipped = [OP_FALSE, OP_IF, 0x50, OP_ENDIF, OP_1];
    assert_eq!(redeem(&skipped, &[]).result, Ok(()));
    let executed = [OP_1, OP_IF, 0x50, OP_ENDIF, OP_1];
    let run = redeem(&executed, &[]);
    assert!(matches!(run.result, Err(TxScriptError::OpcodeReserved(_))), "{:?}", run.result);
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 2, 2, 0x50, "OpReserved", true));

    // An executed OpReserved directly before an always illegal opcode: the error text names
    // the opcode, so the two are told apart.
    let both = [OP_1, OP_IF, 0x50, OP_VERIF, OP_ENDIF, OP_1];
    assert_eq!(redeem(&both, &[]).stop, at(ScriptKind::RedeemScript, 2, 2, 0x50, "OpReserved", true));
}

#[test]
fn a_truncated_push_at_the_end_of_the_redeem_script() {
    // 0: Op1 (0), 1: OpDrop (1), 2: push of 5 bytes with only 2 present (2)
    let script = [OP_1, OP_DROP, 0x05, 0xaa, 0xbb];
    let run = redeem(&script, &[]);
    assert_eq!(run.result, Err(TxScriptError::MalformedPush(5, 2)));
    assert_eq!(
        run.stop,
        Some(StopPoint::Opcode(OpcodeStop {
            script: ScriptKind::RedeemScript,
            op_index: 2,
            byte_offset: 2,
            opcode: 0x05,
            opcode_name: None,
            executed: false,
        }))
    );

    // A push-data opcode without its length bytes.
    let script = [OP_1, 0x4d, 0x01];
    let run = redeem(&script, &[]);
    assert_eq!(run.result, Err(TxScriptError::MalformedPushSize(vec![0x01])));
    assert!(
        matches!(&run.stop, Some(StopPoint::Opcode(at)) if at.op_index == 1 && at.byte_offset == 1 && at.opcode == 0x4d && !at.executed)
    );
}

#[test]
fn a_truncated_push_in_the_signature_script() {
    let gate = node();
    let mut spend = p2sh_spend(&gate, &[OP_1], &[], 0);
    // push 1, then a push of 4 bytes that is cut short.
    spend.tx.inputs[0].signature_script = vec![OP_1, 0x04, 0x01];
    let run = run(&gate, &spend);
    assert_eq!(run.result, Err(TxScriptError::MalformedPush(4, 1)));
    assert!(
        matches!(&run.stop, Some(StopPoint::Opcode(at)) if at.script == ScriptKind::SignatureScript && at.op_index == 1 && at.byte_offset == 1 && !at.executed)
    );
}

#[test]
fn an_unbalanced_conditional_is_noticed_at_the_end_of_the_script() {
    let run = redeem(&[OP_1, OP_IF, OP_1], &[]);
    assert_eq!(run.result, Err(TxScriptError::ErrUnbalancedConditional));
    assert_eq!(run.stop, Some(StopPoint::EndOfScript(ScriptKind::RedeemScript)));

    // OpEndIf without OpIf is an error of that opcode.
    let run = redeem(&[OP_1, OP_ENDIF], &[]);
    assert_eq!(run.result, Err(TxScriptError::InvalidState("condition stack empty".to_string())));
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 1, 1, OP_ENDIF, "OpEndIf", true));
}

#[test]
fn empty_stack_in_the_middle_and_at_the_end_are_told_apart() {
    // OpCat as the last opcode with one item: the opcode fails.
    let run_cat = redeem(&[OP_1, OP_CAT], &[]);
    assert_eq!(run_cat.result, Err(TxScriptError::EmptyStack));
    assert_eq!(run_cat.stop, at(ScriptKind::RedeemScript, 1, 1, OP_CAT, "OpCat", true));

    // OpDrop as the last opcode: the script ends with nothing on the stack.
    let run_drop = redeem(&[OP_1, OP_DROP], &[]);
    assert_eq!(run_drop.result, Err(TxScriptError::EmptyStack));
    assert_eq!(run_drop.stop, Some(StopPoint::FinalStack));
    // Same error, same number of logged opcodes.
    assert_eq!(run_cat.trace.unwrap().opcodes_logged, run_drop.trace.unwrap().opcodes_logged);
}

#[test]
fn the_stack_limit_names_the_opcode_that_crossed_it() {
    // 245 items: the limit of 244 is checked after each opcode.
    let script = vec![OP_1; 245];
    let run = redeem(&script, &[]);
    assert_eq!(run.result, Err(TxScriptError::StackSizeExceeded(245, 244)));
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 244, 244, OP_1, "OpTrue", true));

    // Items on the alt stack count too: 243 pushes, one item moved over, two more pushes.
    let mut script = vec![OP_1; 243];
    script.extend_from_slice(&[OP_TOALTSTACK, OP_1, OP_1]);
    let run = redeem(&script, &[]);
    assert_eq!(run.result, Err(TxScriptError::StackSizeExceeded(245, 244)));
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 245, 245, OP_1, "OpTrue", true));
}

#[test]
fn the_budget_runs_out_at_a_known_opcode() {
    let gate = node();
    // A 3,000-byte item pushed literally (free), then duplicated: each OpDup costs 3,000 units.
    // Budget 0 allows 9,999. The wrapper costs 2 * 3,009 + 33 = 6,051; the first OpDup brings
    // the total to 9,051; the second would need 12,051.
    let mut script = vec![0x4d, 0xb8, 0x0b];
    script.extend_from_slice(&[0x11; 3_000]);
    script.extend_from_slice(&[OP_DUP, OP_DUP, OP_DROP, OP_DROP, OP_DROP, OP_1]);
    // The redeem script as a whole: 3 + 3000 + 6 = 3,009 bytes.
    assert_eq!(script.len(), 3_009);
    let spend = p2sh_spend(&gate, &script, &[], 0);
    let run = run(&gate, &spend);
    let wrapper = 2 * 3_009 + 33;
    assert_eq!(run.result, Err(TxScriptError::ExceededCommittedScriptUnits { used: wrapper + 6_000, limit: 9_999 }));
    assert_eq!(run.used_script_units, wrapper + 3_000);
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 2, 3_004, OP_DUP, "OpDup", true));
}

#[test]
fn a_long_script_public_key_is_charged_before_any_opcode() {
    let gate = node();
    // 136 bytes of no-ops ending in Op1: (136 - 35) * 100 = 10,100 units up front.
    let mut script = vec![OP_NOP; 136];
    script[135] = OP_1;
    let run = run_one(&gate, &bare_spend(&gate, &script, &[], 0));
    assert_eq!(run.result, Err(TxScriptError::ExceededCommittedScriptUnits { used: 10_100, limit: 9_999 }));
    assert_eq!(run.stop, Some(StopPoint::BeforeAnyOpcode));
    assert_eq!(run.trace.unwrap().opcodes_logged, 0);

    // 135 bytes cost exactly 10,000, one unit above the free allowance; 134 bytes cost 9,900.
    let mut script = vec![OP_NOP; 135];
    script[134] = OP_1;
    let failing = run_one(&gate, &bare_spend(&gate, &script, &[], 0));
    assert_eq!(failing.result, Err(TxScriptError::ExceededCommittedScriptUnits { used: 10_000, limit: 9_999 }));
    let mut script = vec![OP_NOP; 134];
    script[133] = OP_1;
    let passing = run_one(&gate, &bare_spend(&gate, &script, &[], 0));
    assert_eq!((passing.result.clone(), passing.used_script_units), (Ok(()), 9_900));
}

#[test]
fn positions_in_a_bare_script_public_key() {
    let gate = node();
    // The coin's script is the contract itself: no hash wrapper, no redeem script.
    // Signature script pushes 2 and 2; script: 0: OpAdd, 1: Op3, 2: OpNumEqualVerify, 3: Op1.
    let script = [OP_ADD, OP_3, OP_NUMEQUALVERIFY, OP_1];
    assert_eq!(run(&gate, &bare_spend(&gate, &script, &[OP_1, OP_2], 0)).result, Ok(()));
    let failing = run(&gate, &bare_spend(&gate, &script, &[OP_2, OP_2], 0));
    assert_eq!(failing.result, Err(TxScriptError::VerifyError));
    assert_eq!(failing.stop, at(ScriptKind::ScriptPublicKey, 2, 2, OP_NUMEQUALVERIFY, "OpNumEqualVerify", true));

    // A disabled opcode as the first opcode of the script public key, after a signature
    // script that ran completely.
    let failing = run(&gate, &bare_spend(&gate, &[OP_LEFT, OP_1], &[OP_1], 0));
    assert_eq!(failing.stop, at(ScriptKind::ScriptPublicKey, 0, 0, OP_LEFT, "OpLeft", false));

    // Both scripts empty.
    let empty = run(&gate, &bare_spend(&gate, &[], &[], 0));
    assert_eq!((empty.result.clone(), empty.stop.clone()), (Err(TxScriptError::EvalFalse), Some(StopPoint::BeforeAnyOpcode)));

    // An empty script public key and a signature script that leaves `true`: accepted.
    assert_eq!(run(&gate, &bare_spend(&gate, &[], &[OP_1], 0)).result, Ok(()));
}

#[test]
fn a_wrong_key_length_for_keyed_blake3_looks_like_a_truncated_push() {
    // data, a 5-byte "key", OpBlake3WithKey: the opcode reports MalformedPush(32, 5).
    let script = [OP_1, 0x05, 1, 2, 3, 4, 5, OP_BLAKE3WITHKEY, OP_1];
    let run = redeem(&script, &[]);
    assert_eq!(run.result, Err(TxScriptError::MalformedPush(32, 5)));
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 2, 7, OP_BLAKE3WITHKEY, "OpBlake3WithKey", true));

    // The documented ambiguity: the same opcode directly before a 32-byte push that holds
    // only 5 bytes. Both explanations give the same error value; the position names the push.
    let script = [OP_1, 0x05, 1, 2, 3, 4, 5, OP_BLAKE3WITHKEY, 0x20, 1, 2, 3, 4, 5];
    let run = redeem(&script, &[]);
    assert_eq!(run.result, Err(TxScriptError::MalformedPush(32, 5)));
    assert!(matches!(&run.stop, Some(StopPoint::Opcode(at)) if at.op_index == 3 && at.byte_offset == 8 && !at.executed));
}

#[test]
fn an_opcode_that_needs_the_chain_is_a_harness_condition() {
    let gate = node();
    let spend = p2sh_spend(&gate, &[OP_1, OP_CHAINBLOCKSEQCOMMIT], &[], 0);
    let evaluation = submit(&gate, &spend);
    let run = &evaluation.committed_runs[0];
    assert!(matches!(run.result, Err(TxScriptError::InvalidOpcode(_))), "{:?}", run.result);
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 1, 1, OP_CHAINBLOCKSEQCOMMIT, "OpChainblockSeqCommit", true));
    assert_eq!(evaluation.verdict.inputs[0].committed.class, Some(node_gate::ErrorClass::Harness));
}

#[test]
fn the_position_is_optional() {
    let gate = node();
    let spend = p2sh_spend(&gate, &[OP_FALSE, OP_VERIFY, OP_1], &[], 0);
    let mut options = node_gate::GateOptions::submit();
    options.locate_stops = false;
    let evaluation = node_gate::evaluate(&gate, &spend.tx, &spend.entries, options);
    let run = &evaluation.committed_runs[0];
    assert_eq!(run.result, Err(TxScriptError::VerifyError));
    assert_eq!((run.stop.clone(), run.trace.clone()), (None, None));
}

/// A coin whose script public key is `script` itself, spent by a version 0 transaction
/// that commits to `sig_op_count` signature operations: the shape for the side of the fork
/// without covenants.
fn bare_spend_v0(gate: &GateParams, script: &[u8], sig_op_count: u8) -> Spend {
    let entries = vec![coin(gate, 10 * KAS, ScriptPublicKey::from_vec(0, script.to_vec()))];
    Spend::new(tx_v0(vec![input_v0(0xc1, sig_op_count)], vec![pay(RECEIVER, 10 * KAS - PLAIN_FEE)]), entries)
}

/// The engine raises three refusals after it has logged an opcode and before it hands it
/// to the interpreter (rusty-kaspa a41a333 crypto/txscript/src/lib.rs:617-629): more
/// operations than a script may hold, a literal push above the element size, and, before
/// Toccata, a push that could be shorter. Such an opcode did not run: `executed` is false.
/// The same three errors raised from inside the interpreter leave it true.
#[test]
fn an_opcode_refused_between_the_log_and_the_interpreter_was_not_executed() {
    let before = node_before_toccata();
    let after = node();

    // The 202nd operation of a script, in a branch that is not taken:
    // OpFalse, OpIf (operation 1), 201 no-ops (operations 2 to 202), OpEndIf, Op1.
    let mut skipped = vec![OP_FALSE, OP_IF];
    skipped.extend_from_slice(&[OP_NOP; 201]);
    skipped.extend_from_slice(&[OP_ENDIF, OP_1]);
    let run = run_one(&before, &bare_spend_v0(&before, &skipped, 0));
    assert_eq!(run.result, Err(TxScriptError::TooManyOperations(201)));
    assert_eq!(run.stop, at(ScriptKind::ScriptPublicKey, 202, 202, OP_NOP, "OpNop", false));
    // And in a straight script, where the branch is executing: not interpreted either.
    let mut straight = vec![OP_NOP; 202];
    straight.push(OP_1);
    let run = run_one(&before, &bare_spend_v0(&before, &straight, 0));
    assert_eq!(run.result, Err(TxScriptError::TooManyOperations(201)));
    assert_eq!(run.stop, at(ScriptKind::ScriptPublicKey, 201, 201, OP_NOP, "OpNop", false));

    // The same error from inside the interpreter: a multi-signature opcode adds its
    // number of keys to the count while it runs (lib.rs:807-809). 180 no-ops and the
    // opcode itself are 181 operations; twenty keys make 201, twenty-one would not be a
    // legal key count, so 181 no-ops and twenty keys: 182 + 20 = 202. The push of the key
    // count is opcode 181 at byte 181 and two bytes long.
    let mut by_keys = vec![OP_NOP; 181];
    by_keys.extend_from_slice(&[0x01, 20, OP_CHECKMULTISIG]);
    let run = run_one(&before, &bare_spend_v0(&before, &by_keys, 0));
    assert_eq!(run.result, Err(TxScriptError::TooManyOperations(201)));
    assert_eq!(run.stop, at(ScriptKind::ScriptPublicKey, 182, 183, OP_CHECKMULTISIG, "OpCheckMultiSig", true));
    // The same opcode as the 202nd operation of the script is refused before it runs.
    let mut by_count = vec![OP_NOP; 201];
    by_count.extend_from_slice(&[0x01, 20, OP_CHECKMULTISIG]);
    let run = run_one(&before, &bare_spend_v0(&before, &by_count, 0));
    assert_eq!(run.result, Err(TxScriptError::TooManyOperations(201)));
    assert_eq!(run.stop, at(ScriptKind::ScriptPublicKey, 202, 203, OP_CHECKMULTISIG, "OpCheckMultiSig", false));

    // A literal push of 521 bytes before Toccata, where an element holds at most 520:
    // refused in a branch that is not taken too.
    let mut long_push = vec![OP_FALSE, OP_IF, 0x4d, 0x09, 0x02];
    long_push.extend_from_slice(&[0x11; 521]);
    long_push.extend_from_slice(&[OP_ENDIF, OP_1]);
    let run = run_one(&before, &bare_spend_v0(&before, &long_push, 0));
    assert_eq!(run.result, Err(TxScriptError::ElementTooBig(521, 520)));
    assert_eq!(run.stop, at(ScriptKind::ScriptPublicKey, 2, 2, 0x4d, "OpPushData2", false));
    // The same error from inside the interpreter, after Toccata: 250 bytes doubled twelve
    // times by OpDup OpCat would be 1,024,000 bytes, above the 1,000,000 an element holds.
    let mut doubling = vec![0x4c, 250];
    doubling.extend_from_slice(&[0x22; 250]);
    for _ in 0..12 {
        doubling.extend_from_slice(&[OP_DUP, OP_CAT]);
    }
    doubling.extend_from_slice(&[OP_DROP, OP_1]);
    let run = run_one(&after, &p2sh_spend(&after, &doubling, &[], u16::MAX));
    assert_eq!(run.result, Err(TxScriptError::ElementTooBig(1_024_000, 1_000_000)));
    // Opcode 0 is the push; the twelfth OpCat is opcode 24 at byte 252 + 23.
    assert_eq!(run.stop, at(ScriptKind::RedeemScript, 24, 275, OP_CAT, "OpCat", true));

    // A push that could be shorter, before Toccata: one byte with the value 5 pushed as
    // data instead of by Op5.
    let run = run_one(&before, &bare_spend_v0(&before, &[0x01, 0x05], 0));
    assert!(matches!(run.result, Err(TxScriptError::NotMinimalData(_))), "{:?}", run.result);
    assert_eq!(run.stop, at(ScriptKind::ScriptPublicKey, 0, 0, 0x01, "OpData1", false));
    // The same error from inside the interpreter: a number with a needless zero byte,
    // pushed minimally as two bytes of data and then read by Op1Add.
    let needless_zero = [0x02, 0x05, 0x00, OP_1ADD, OP_DROP, OP_1];
    let run = run_one(&before, &bare_spend_v0(&before, &needless_zero, 0));
    assert!(matches!(run.result, Err(TxScriptError::NotMinimalData(_))), "{:?}", run.result);
    assert_eq!(run.stop, at(ScriptKind::ScriptPublicKey, 1, 3, OP_1ADD, "Op1Add", true));
    // After Toccata the engine reads that number as 5.
    assert_eq!(redeem(&needless_zero, &[]).result, Ok(()));
}
