//! The covenant context reaches the engine. Without it the covenant opcodes silently
//! answer zero, so a gate that forgot to attach it would still run every script.
//!
//! The scripts here are four questions to the engine and nothing more: how many inputs
//! carry this covenant id, how many outputs continue it, how many outputs this input
//! authorized, and which id this input carries.

use kaspa_consensus_core::tx::{CovenantBinding, TransactionOutput};
use kaspa_hashes::Hash;
use kaspa_txscript_errors::TxScriptError;
use node_gate::{
    ErrorClass, GateParams, ScriptKind, StopPoint,
    engine::OpcodeStop,
    wallet::{self},
};

use crate::common::*;

const OP_1: u8 = 0x51;
const OP_EQUAL: u8 = 0x87;
const OP_NUMEQUALVERIFY: u8 = 0x9d;
const OP_TX_INPUT_INDEX: u8 = 0xb9;
const OP_AUTH_OUTPUT_COUNT: u8 = 0xcb;
const OP_INPUT_COVENANT_ID: u8 = 0xcf;
const OP_COV_INPUT_COUNT: u8 = 0xd0;
const OP_COV_OUTPUT_COUNT: u8 = 0xd2;

fn id() -> Hash {
    Hash::from_bytes([0xc7; 32])
}

/// A small number as a push opcode: `OpFalse` for 0, `Op1`..`Op16` otherwise.
fn small(n: u8) -> u8 {
    if n == 0 { 0x00 } else { OP_1 + n - 1 }
}

/// Expects `inputs` inputs with the id, `outputs` continuing outputs, `authorized` outputs
/// authorized by the running input, and the running input to carry `carried`.
///
/// index: 0 push id, 1 OpCovInputCount, 2 number, 3 OpNumEqualVerify,
///        4 push id, 5 OpCovOutputCount, 6 number, 7 OpNumEqualVerify,
///        8 OpTxInputIndex, 9 OpAuthOutputCount, 10 number, 11 OpNumEqualVerify,
///        12 OpTxInputIndex, 13 OpInputCovenantId, 14 push carried, 15 OpEqual
fn questions(inputs: u8, outputs: u8, authorized: u8, carried: Hash) -> Vec<u8> {
    let mut script = wallet::push_data(&id().as_bytes());
    script.extend_from_slice(&[OP_COV_INPUT_COUNT, small(inputs), OP_NUMEQUALVERIFY]);
    script.extend_from_slice(&wallet::push_data(&id().as_bytes()));
    script.extend_from_slice(&[OP_COV_OUTPUT_COUNT, small(outputs), OP_NUMEQUALVERIFY]);
    script.extend_from_slice(&[OP_TX_INPUT_INDEX, OP_AUTH_OUTPUT_COUNT, small(authorized), OP_NUMEQUALVERIFY]);
    script.extend_from_slice(&[OP_TX_INPUT_INDEX, OP_INPUT_COVENANT_ID]);
    script.extend_from_slice(&wallet::push_data(&carried.as_bytes()));
    script.push(OP_EQUAL);
    script
}

/// One pay-to-script-hash coin locked to `redeem_script`, carrying the covenant id if
/// `bound`, spent to `continuing` outputs that continue the covenant and one plain output.
fn spend(gate: &GateParams, redeem_script: &[u8], bound: bool, continuing: usize) -> Spend {
    let mut spend = p2sh_spend(gate, redeem_script, &[], 0);
    if bound {
        spend.entries[0].covenant_id = Some(id());
    }
    let mut outputs = vec![pay(RECEIVER, KAS)];
    for _ in 0..continuing {
        outputs.push(TransactionOutput::with_covenant(KAS, pay(RECEIVER, KAS).script_public_key, Some(CovenantBinding::new(0, id()))));
    }
    spend.tx.outputs = outputs;
    spend.tx.finalize();
    spend
}

#[test]
fn the_engine_sees_the_covenant_inputs_and_outputs() {
    let gate = node();
    for continuing in 0..=3u8 {
        let script = questions(1, continuing, continuing, id());
        let evaluation = submit(&gate, &spend(&gate, &script, true, continuing as usize));
        assert!(evaluation.verdict.consensus_accepted, "{continuing} continuing outputs: {:?}", evaluation.consensus_error);
        assert!(evaluation.verdict.inputs[0].spent_has_covenant_id);
    }
}

#[test]
fn a_wrong_expectation_stops_at_its_own_opcode() {
    let gate = node();
    let stop_of = |script: &[u8], continuing: usize| {
        let evaluation = submit(&gate, &spend(&gate, script, true, continuing));
        let run = &evaluation.committed_runs[0];
        assert_eq!(run.result, Err(TxScriptError::VerifyError));
        assert_eq!(evaluation.verdict.inputs[0].committed.class, Some(ErrorClass::ContractRefused));
        run.stop.clone()
    };
    let at = |op_index: usize, byte_offset: usize| {
        Some(StopPoint::Opcode(OpcodeStop {
            script: ScriptKind::RedeemScript,
            op_index,
            byte_offset,
            opcode: OP_NUMEQUALVERIFY,
            opcode_name: Some("OpNumEqualVerify".to_string()),
            executed: true,
        }))
    };
    // Two continuing outputs. Each script is wrong in one number only.
    assert_eq!(stop_of(&questions(2, 2, 2, id()), 2), at(3, 35));
    assert_eq!(stop_of(&questions(1, 1, 2, id()), 2), at(7, 71));
    assert_eq!(stop_of(&questions(1, 2, 1, id()), 2), at(11, 75));
}

#[test]
fn a_coin_without_a_covenant_id_counts_nowhere() {
    let gate = node();
    let zero = Hash::from_bytes([0; 32]);
    // No input carries the id; the input's own id reads as 32 zero bytes.
    assert!(submit(&gate, &spend(&gate, &questions(0, 0, 0, zero), false, 0)).verdict.consensus_accepted);
    let evaluation = submit(&gate, &spend(&gate, &questions(0, 0, 0, id()), false, 0));
    assert_eq!(evaluation.first_script_error(), Some(&TxScriptError::EvalFalse));
    assert_eq!(evaluation.committed_runs[0].stop, Some(StopPoint::FinalStack));
}

#[test]
fn before_toccata_the_covenant_opcodes_do_not_exist() {
    let before = node_before_toccata();
    let script = questions(1, 0, 0, id());
    let entries = vec![coin(&before, 10 * KAS, wallet::p2sh_script_public_key(&script))];
    let mut input = input_v0(0xb1, 0);
    input.signature_script = wallet::p2sh_signature_script(&[], &script);
    let evaluation = submit(&before, &Spend::new(tx_v0(vec![input], vec![pay(RECEIVER, 9 * KAS)]), entries));
    let run = &evaluation.committed_runs[0];
    assert!(matches!(run.result, Err(TxScriptError::InvalidOpcode(_))), "{:?}", run.result);
    assert!(
        matches!(&run.stop, Some(StopPoint::Opcode(at)) if at.script == ScriptKind::RedeemScript && at.op_index == 1 && at.opcode == OP_COV_INPUT_COUNT)
    );
    assert_eq!(evaluation.verdict.inputs[0].committed.class, Some(ErrorClass::ScriptFormat));
}
