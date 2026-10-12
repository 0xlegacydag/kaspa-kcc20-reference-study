//! Pay-to-script-hash coins: the wrapper the engine runs around every redeem script, its
//! failures, and its price.

use kaspa_consensus_core::{errors::tx::TxRuleError, hashing::sighash_type::SIG_HASH_ALL};
use kaspa_txscript_errors::TxScriptError;
use node_gate::{
    ErrorClass, GateParams, ScriptKind, StopPoint,
    engine::{OpcodeStop, ScriptRun},
    wallet::{self, TestKey},
};

use crate::common::*;

const OP_TRUE: u8 = 0x51;
const OP_NOP: u8 = 0x61;
const OP_DUP: u8 = 0x76;
const OP_CHECKSIG: u8 = 0xac;

fn run(gate: &GateParams, spend: &Spend) -> ScriptRun {
    submit(gate, spend).committed_runs.remove(0)
}

/// A redeem script of `len` bytes that leaves a single true item: `OpTrue` and no-ops.
fn padded_true(len: usize) -> Vec<u8> {
    let mut script = vec![OP_NOP; len];
    script[0] = OP_TRUE;
    script
}

#[test]
fn the_right_redeem_script_passes() {
    let gate = node();
    let spend = p2sh_spend(&gate, &[OP_TRUE], &[], 0);
    assert_eq!(spend.tx.inputs[0].signature_script, vec![0x01, OP_TRUE]);
    assert_eq!(spend.entries[0].script_public_key.script().len(), 35);
    let evaluation = submit(&gate, &spend);
    assert!(evaluation.accepted());
    // Hashing one byte costs 2 units, the digest 32, the `true` of OpEqual 1.
    assert_eq!(evaluation.committed_runs[0].used_script_units, 35);
    assert_eq!(evaluation.verdict.inputs[0].minimal_budget, Some(0));
}

#[test]
fn a_redeem_script_that_does_not_hash_to_the_coin() {
    let gate = node();
    let mut spend = p2sh_spend(&gate, &[OP_TRUE], &[], 0);
    // Another script that would also leave `true`.
    spend.tx.inputs[0].signature_script = wallet::p2sh_signature_script(&[], &[OP_TRUE, OP_NOP]);
    let evaluation = submit(&gate, &spend);
    assert_eq!(evaluation.consensus_error, Some(TxRuleError::SignatureInvalid(TxScriptError::EvalFalse)));
    let run = &evaluation.committed_runs[0];
    assert_eq!(run.stop, Some(StopPoint::P2shHashMismatch));
    // Two bytes hashed, the digest pushed; OpEqual pushes an empty item for false.
    assert_eq!(run.used_script_units, 2 * 2 + 32);
    assert_eq!(evaluation.verdict.inputs[0].committed.class, Some(ErrorClass::ScriptFormat));
}

#[test]
fn a_non_push_opcode_in_the_signature_script() {
    let gate = node();
    let mut spend = p2sh_spend(&gate, &[OP_TRUE], &[], 0);
    // push 1, OpDup, push of the redeem script: would work if it were allowed.
    spend.tx.inputs[0].signature_script = vec![0x51, OP_DUP, 0x75, 0x01, OP_TRUE];
    let run = run(&gate, &spend);
    assert_eq!(run.result, Err(TxScriptError::SignatureScriptNotPushOnly));
    assert_eq!(
        run.stop,
        Some(StopPoint::Opcode(OpcodeStop {
            script: ScriptKind::SignatureScript,
            op_index: 1,
            byte_offset: 1,
            opcode: OP_DUP,
            opcode_name: Some("OpDup".to_string()),
            executed: false,
        }))
    );
    assert_eq!(run.used_script_units, 0);
}

#[test]
fn an_extra_stack_item() {
    let gate = node();
    // One argument the redeem script does not consume.
    let spend = p2sh_spend(&gate, &[OP_TRUE], &[0x52], 0);
    let evaluation = submit(&gate, &spend);
    assert_eq!(evaluation.consensus_error, Some(TxRuleError::SignatureInvalid(TxScriptError::CleanStack(1))));
    assert_eq!(evaluation.committed_runs[0].stop, Some(StopPoint::FinalStack));
    assert_eq!(evaluation.verdict.inputs[0].committed.class, Some(ErrorClass::ContractRefused));

    let three = p2sh_spend(&gate, &[OP_TRUE], &[0x52, 0x53, 0x00], 0);
    assert_eq!(run(&gate, &three).result, Err(TxScriptError::CleanStack(3)));
}

#[test]
fn an_empty_signature_script() {
    let gate = node();
    let mut spend = p2sh_spend(&gate, &[OP_TRUE], &[], 0);
    spend.tx.inputs[0].signature_script.clear();
    let evaluation = submit(&gate, &spend);
    assert_eq!(evaluation.consensus_error, Some(TxRuleError::SignatureEmpty(TxScriptError::InvalidStackOperation(1, 0))));
    assert_eq!(
        evaluation.committed_runs[0].stop,
        Some(StopPoint::Opcode(OpcodeStop {
            script: ScriptKind::ScriptPublicKey,
            op_index: 0,
            byte_offset: 0,
            opcode: 0xaa,
            opcode_name: Some("OpBlake2b".to_string()),
            executed: true,
        }))
    );
    assert_eq!(evaluation.verdict.inputs[0].committed.class, Some(ErrorClass::ScriptFormat));
}

#[test]
fn a_false_redeem_script_is_a_contract_refusal() {
    let gate = node();
    // The redeem script hashes to the coin and leaves false.
    let spend = p2sh_spend(&gate, &[0x00], &[], 0);
    let evaluation = submit(&gate, &spend);
    assert_eq!(evaluation.first_script_error(), Some(&TxScriptError::EvalFalse));
    assert_eq!(evaluation.committed_runs[0].stop, Some(StopPoint::FinalStack));
    assert_eq!(evaluation.verdict.inputs[0].committed.class, Some(ErrorClass::ContractRefused));
}

#[test]
fn an_empty_redeem_script_runs_nothing() {
    let gate = node();
    // The coin commits to the empty script. Its "arguments" are then the final stack.
    let accepted = p2sh_spend(&gate, &[], &[OP_TRUE], 0);
    assert_eq!(accepted.tx.inputs[0].signature_script, vec![OP_TRUE, 0x00]);
    assert_eq!(run(&gate, &accepted).result, Ok(()));

    let refused = p2sh_spend(&gate, &[], &[0x00], 0);
    let run = run(&gate, &refused);
    // The hash matched; the false item is the final result, not the wrapper's answer.
    assert_eq!((run.result.clone(), run.stop.clone()), (Err(TxScriptError::EvalFalse), Some(StopPoint::FinalStack)));
}

#[test]
fn a_signature_check_inside_a_redeem_script() {
    let gate = node();
    let owner = TestKey::from_seed(OWNER);
    let mut redeem_script = wallet::push_data(&owner.schnorr_public_key());
    redeem_script.push(OP_CHECKSIG);
    assert_eq!(redeem_script.len(), 34);

    let mut spend = p2sh_spend(&gate, &redeem_script, &[], 10);
    let signature = owner.schnorr_signature(&spend.populated(), 0, SIG_HASH_ALL);
    spend.tx.inputs[0].signature_script = wallet::p2sh_signature_script(&wallet::push_data(&signature), &redeem_script);
    let evaluation = submit(&gate, &spend);
    assert!(evaluation.accepted());
    // Wrapper 2 * 34 + 33, the check 100,000, its `true` 1.
    assert_eq!(evaluation.committed_runs[0].used_script_units, 2 * 34 + 33 + 100_000 + 1);
    assert_eq!(evaluation.verdict.inputs[0].minimal_budget, Some(10));

    // Without the signature item the check finds one item instead of two.
    spend.tx.inputs[0].signature_script = wallet::p2sh_signature_script(&[], &redeem_script);
    let run = run(&gate, &spend);
    assert_eq!(run.result, Err(TxScriptError::InvalidStackOperation(2, 1)));
    assert_eq!(
        run.stop,
        Some(StopPoint::Opcode(OpcodeStop {
            script: ScriptKind::RedeemScript,
            op_index: 1,
            byte_offset: 33,
            opcode: OP_CHECKSIG,
            opcode_name: Some("OpCheckSig".to_string()),
            executed: true,
        }))
    );
}

#[test]
fn the_wrapper_costs_two_units_per_byte_plus_thirty_three() {
    let gate = node();
    for len in [1usize, 2, 35, 76, 256, 600, 4_000] {
        let spend = p2sh_spend(&gate, &padded_true(len), &[], 1);
        let run = run(&gate, &spend);
        assert_eq!(run.result, Ok(()), "length {len}");
        assert_eq!(run.used_script_units, 2 * len as u64 + 33, "length {len}");
    }
}

#[test]
fn the_free_units_cover_a_redeem_script_of_4983_bytes() {
    let gate = node();
    // 2 * 4983 + 33 = 9,999: exactly the free allowance of an input with budget zero.
    let fits = p2sh_spend(&gate, &padded_true(4_983), &[], 0);
    let run_fits = run(&gate, &fits);
    assert_eq!((run_fits.result.clone(), run_fits.used_script_units), (Ok(()), 9_999));

    // One byte more: the hash is paid (9,968), the digest push is not.
    let over = p2sh_spend(&gate, &padded_true(4_984), &[], 0);
    let evaluation = submit(&gate, &over);
    let run_over = &evaluation.committed_runs[0];
    assert_eq!(run_over.result, Err(TxScriptError::ExceededCommittedScriptUnits { used: 10_000, limit: 9_999 }));
    assert_eq!(run_over.used_script_units, 9_968);
    assert!(
        matches!(&run_over.stop, Some(StopPoint::Opcode(at)) if at.script == ScriptKind::ScriptPublicKey && at.op_index == 0 && at.executed)
    );
    assert_eq!(evaluation.verdict.inputs[0].committed.class, Some(ErrorClass::ResourceLimit));
    assert_eq!(evaluation.verdict.inputs[0].minimal_budget, Some(1));

    // With a budget of one unit it passes.
    assert_eq!(run(&gate, &p2sh_spend(&gate, &padded_true(4_984), &[], 1)).result, Ok(()));

    // 5,000 bytes: already the hash charge of 10,000 units is one too many.
    let big = run(&gate, &p2sh_spend(&gate, &padded_true(5_000), &[], 0));
    assert_eq!(big.result, Err(TxScriptError::ExceededCommittedScriptUnits { used: 10_000, limit: 9_999 }));
    assert_eq!(big.used_script_units, 0);
}

#[test]
fn a_redeem_script_above_520_bytes_needs_the_post_toccata_engine() {
    let after = node();
    let redeem_script = padded_true(600);
    assert_eq!(run(&after, &p2sh_spend(&after, &redeem_script, &[], 0)).result, Ok(()));

    // The same bytes in a version 0 transaction before the fork: the push is too big.
    let before = node_before_toccata();
    let entries = vec![coin(&before, 10 * KAS, wallet::p2sh_script_public_key(&redeem_script))];
    let mut input = input_v0(0xb1, 0);
    input.signature_script = wallet::p2sh_signature_script(&[], &redeem_script);
    let spend = Spend::new(tx_v0(vec![input], vec![pay(RECEIVER, 10 * KAS - PLAIN_FEE)]), entries);
    let evaluation = submit(&before, &spend);
    let run = &evaluation.committed_runs[0];
    assert_eq!(run.result, Err(TxScriptError::ElementTooBig(600, 520)));
    // The engine refuses the push after logging it and before interpreting it
    // (crypto/txscript/src/lib.rs:622-624): it did not run.
    assert!(
        matches!(&run.stop, Some(StopPoint::Opcode(at)) if at.script == ScriptKind::SignatureScript && at.op_index == 0 && !at.executed)
    );
    // A literal push above the element size is a limit, not bad data.
    assert_eq!(evaluation.verdict.inputs[0].committed.class, Some(ErrorClass::ResourceLimit));
}
