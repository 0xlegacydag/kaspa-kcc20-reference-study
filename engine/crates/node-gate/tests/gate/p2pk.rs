//! An ordinary pay-to-pubkey input on the real engine: good and bad signatures, what each
//! costs, and what the node reports.

use kaspa_consensus_core::{errors::tx::TxRuleError, hashing::sighash_type::SIG_HASH_ALL, tx::ScriptPublicKey};
use kaspa_txscript_errors::TxScriptError;
use node_gate::{
    ErrorClass, GateParams, ScriptKind, StopPoint,
    engine::{OpcodeStop, ScriptRun},
    wallet::{self, TestKey},
};

use crate::common::*;

/// The run of input 0 under its committed limit, as a node makes it.
fn run(gate: &GateParams, spend: &Spend) -> ScriptRun {
    submit(gate, spend).committed_runs.remove(0)
}

/// `plain_spend` with the signature item replaced.
fn with_signature_item(gate: &GateParams, item: &[u8]) -> Spend {
    let mut spend = plain_spend(gate);
    spend.set_signature_item(0, item);
    spend
}

#[test]
fn a_real_signature_passes() {
    let gate = node();
    let spend = plain_spend(&gate);
    assert_eq!(spend.tx.inputs[0].signature_script.len(), 66);
    let evaluation = submit(&gate, &spend);
    assert!(evaluation.accepted());
    let run = &evaluation.committed_runs[0];
    assert_eq!(run.result, Ok(()));
    // One signature check, and one unit for the pushed `true`.
    assert_eq!((run.used_script_units, run.used_sig_ops), (100_001, 1));
    assert_eq!((run.script_units_limit, run.sig_op_limit), (Some(109_999), None));
    assert!(!run.accepted_unknown_version);
}

#[test]
fn signing_is_deterministic() {
    let gate = node();
    assert_eq!(plain_spend(&gate).tx.inputs[0].signature_script, plain_spend(&gate).tx.inputs[0].signature_script);
}

#[test]
fn a_signature_by_another_key_is_false_not_an_error() {
    let gate = node();
    let mut spend = plain_spend(&gate);
    spend.sign_p2pk(0, &TestKey::from_seed(9), SIG_HASH_ALL);
    let evaluation = submit(&gate, &spend);
    assert_eq!(evaluation.consensus_error, Some(TxRuleError::SignatureInvalid(TxScriptError::EvalFalse)));
    let run = &evaluation.committed_runs[0];
    // The check was made and paid for; pushing `false` (an empty item) costs nothing.
    assert_eq!((run.used_script_units, run.used_sig_ops), (100_000, 1));
    assert_eq!(run.stop, Some(StopPoint::FinalStack));
    assert_eq!(evaluation.verdict.inputs[0].committed.class, Some(ErrorClass::ContractRefused));
}

#[test]
fn changing_a_committed_field_after_signing_invalidates_the_signature() {
    let gate = node();
    // (what is changed, the change)
    type Change = (&'static str, fn(&mut Spend));
    let changes: Vec<Change> = vec![
        ("output value", |spend| spend.tx.outputs[0].value -= 1),
        ("output script", |spend| spend.tx.outputs[0].script_public_key = TestKey::from_seed(3).p2pk_script_public_key()),
        ("sequence", |spend| spend.tx.inputs[0].sequence = 1),
        ("payload", |spend| spend.tx.payload = vec![1]),
        ("outpoint", |spend| spend.tx.inputs[0].previous_outpoint = outpoint(0xa9, 0)),
        ("spent amount", |spend| spend.entries[0].amount += 1),
    ];
    for (what, change) in changes {
        let mut spend = plain_spend(&gate);
        change(&mut spend);
        spend.tx.finalize();
        assert_eq!(run(&gate, &spend).result, Err(TxScriptError::EvalFalse), "{what}");
    }
}

#[test]
fn fields_the_signature_does_not_cover() {
    let gate = node();
    // The compute budget, the storage mass commitment and the coin's covenant id are not
    // part of the version 1 signature hash.
    let mut spend = plain_spend(&gate);
    spend.tx.inputs[0].compute_commit = kaspa_consensus_core::mass::ComputeBudget(11).into();
    spend.tx.set_storage_mass(42);
    spend.entries[0].covenant_id = Some(kaspa_hashes::Hash::from_bytes([5; 32]));
    spend.entries[0].block_daa_score -= 1;
    spend.tx.finalize();
    assert_eq!(run(&gate, &spend).result, Ok(()));
}

#[test]
fn an_empty_signature_item_is_false_and_free() {
    let gate = node();
    let spend = with_signature_item(&gate, &[]);
    assert_eq!(spend.tx.inputs[0].signature_script, vec![0x00]);
    let evaluation = submit(&gate, &spend);
    // The signature script is not empty, so the node says "invalid", not "empty".
    assert_eq!(evaluation.consensus_error, Some(TxRuleError::SignatureInvalid(TxScriptError::EvalFalse)));
    let run = &evaluation.committed_runs[0];
    assert_eq!((run.used_script_units, run.used_sig_ops), (0, 0));
    assert_eq!(run.stop, Some(StopPoint::FinalStack));
}

#[test]
fn an_empty_signature_script_leaves_the_check_without_its_argument() {
    let gate = node();
    let mut spend = plain_spend(&gate);
    spend.tx.inputs[0].signature_script.clear();
    let evaluation = submit(&gate, &spend);
    assert_eq!(evaluation.consensus_error, Some(TxRuleError::SignatureEmpty(TxScriptError::InvalidStackOperation(2, 1))));
    let run = &evaluation.committed_runs[0];
    assert_eq!((run.used_script_units, run.used_sig_ops), (0, 0));
    assert_eq!(
        run.stop,
        Some(StopPoint::Opcode(OpcodeStop {
            script: ScriptKind::ScriptPublicKey,
            op_index: 1,
            byte_offset: 33,
            opcode: 0xac,
            opcode_name: Some("OpCheckSig".to_string()),
            executed: true,
        }))
    );
    assert_eq!(evaluation.verdict.inputs[0].committed.class, Some(ErrorClass::EngineRefusedData));
}

#[test]
fn zero_signatures() {
    let gate = node();

    // 64 zero bytes and a valid type: it parses, the verification fails, the check is paid.
    let mut zero_all = vec![0u8; 64];
    zero_all.push(0x01);
    let run_all = run(&gate, &with_signature_item(&gate, &zero_all));
    assert_eq!(run_all.result, Err(TxScriptError::EvalFalse));
    assert_eq!((run_all.used_script_units, run_all.used_sig_ops), (100_000, 1));

    // 65 zero bytes: the last byte is the sighash type, and zero is not one.
    let run_zero = run(&gate, &with_signature_item(&gate, &[0u8; 65]));
    assert_eq!(run_zero.result, Err(TxScriptError::InvalidSigHashType(0x00)));
    assert_eq!((run_zero.used_script_units, run_zero.used_sig_ops), (0, 0));
}

#[test]
fn malformed_signature_material() {
    let gate = node();
    let good = wallet::TestKey::from_seed(OWNER).schnorr_signature(&plain_spend(&gate).populated(), 0, SIG_HASH_ALL);
    assert_eq!(good.len(), 65);
    let invalid_signature = Err(TxScriptError::InvalidSignature(secp256k1::Error::InvalidSignature));

    // Only the type byte: a signature body of zero bytes.
    let only_type = run(&gate, &with_signature_item(&gate, &[0x01]));
    assert_eq!(only_type.result, invalid_signature);
    // The check is charged before the signature is parsed.
    assert_eq!((only_type.used_script_units, only_type.used_sig_ops), (100_000, 1));

    // One byte short, one byte long.
    let mut short = good[..63].to_vec();
    short.push(0x01);
    assert_eq!(run(&gate, &with_signature_item(&gate, &short)).result, invalid_signature);
    let mut long = good[..64].to_vec();
    long.extend_from_slice(&[0x00, 0x01]);
    assert_eq!(run(&gate, &with_signature_item(&gate, &long)).result, invalid_signature);

    // A good signature with a type byte outside the six allowed values.
    for bad_type in [0x00u8, 0x03, 0x05, 0x80, 0x83, 0xff] {
        let mut item = good[..64].to_vec();
        item.push(bad_type);
        let run = run(&gate, &with_signature_item(&gate, &item));
        assert_eq!(run.result, Err(TxScriptError::InvalidSigHashType(bad_type)));
        assert_eq!(run.used_sig_ops, 0);
    }

    // A good signature under another allowed type: well formed, but for another message.
    let mut retyped = good[..64].to_vec();
    retyped.push(0x02);
    assert_eq!(run(&gate, &with_signature_item(&gate, &retyped)).result, Err(TxScriptError::EvalFalse));
}

#[test]
fn a_malformed_public_key_in_the_coin() {
    let gate = node();
    // 32 bytes that are not the x coordinate of a curve point, in the standard script form.
    let mut script = vec![0x20];
    script.extend_from_slice(&[0xff; 32]);
    script.push(0xac);
    let mut spend = plain_spend(&gate);
    spend.entries[0].script_public_key = ScriptPublicKey::from_vec(0, script);
    spend.tx.finalize();

    // With a signature item the key is parsed, after the charge.
    let with_signature = run(&gate, &spend);
    assert_eq!(with_signature.result, Err(TxScriptError::InvalidPubkey(secp256k1::Error::InvalidPublicKey)));
    assert_eq!(with_signature.used_sig_ops, 1);

    // With an empty signature item the key is never looked at.
    spend.set_signature_item(0, &[]);
    let without_signature = run(&gate, &spend);
    assert_eq!(without_signature.result, Err(TxScriptError::EvalFalse));
    assert_eq!(without_signature.used_sig_ops, 0);
}

fn ecdsa_spend(gate: &GateParams) -> Spend {
    let owner = TestKey::from_seed(OWNER);
    let mut spend = plain_spend(gate);
    spend.entries[0].script_public_key = owner.p2pk_ecdsa_script_public_key();
    let script = owner.p2pk_ecdsa_signature_script(&spend.populated(), 0, SIG_HASH_ALL);
    spend.tx.inputs[0].signature_script = script;
    spend
}

#[test]
fn ecdsa_pay_to_pubkey() {
    let gate = node();
    let spend = ecdsa_spend(&gate);
    assert_eq!(spend.tx.inputs[0].signature_script.len(), 66);
    let good = run(&gate, &spend);
    assert_eq!(good.result, Ok(()));
    assert_eq!((good.used_script_units, good.used_sig_ops), (100_001, 1));

    // A Schnorr signature of the right key is not an ECDSA signature.
    let mut schnorr_item = ecdsa_spend(&gate);
    let item = TestKey::from_seed(OWNER).schnorr_signature(&schnorr_item.populated(), 0, SIG_HASH_ALL);
    schnorr_item.set_signature_item(0, &item);
    assert_eq!(run(&gate, &schnorr_item).result, Err(TxScriptError::EvalFalse));

    // Empty item: false, free.
    let mut empty = ecdsa_spend(&gate);
    empty.set_signature_item(0, &[]);
    let run_empty = run(&gate, &empty);
    assert_eq!(run_empty.result, Err(TxScriptError::EvalFalse));
    assert_eq!(run_empty.used_sig_ops, 0);

    // 64 zero bytes and a valid type: the compact parser accepts r = s = 0, verification fails.
    let mut zeros = ecdsa_spend(&gate);
    let mut item = vec![0u8; 64];
    item.push(0x01);
    zeros.set_signature_item(0, &item);
    let run_zeros = run(&gate, &zeros);
    assert_eq!(run_zeros.result, Err(TxScriptError::EvalFalse));
    assert_eq!(run_zeros.used_sig_ops, 1);

    // r above the group order does not parse.
    let mut overflow = ecdsa_spend(&gate);
    let mut item = vec![0xffu8; 64];
    item.push(0x01);
    overflow.set_signature_item(0, &item);
    assert_eq!(run(&gate, &overflow).result, Err(TxScriptError::InvalidSignature(secp256k1::Error::InvalidSignature)));
}

#[test]
fn version_0_spend_after_toccata_is_metered_in_script_units() {
    let gate = node();
    let spend = plain_spend_v0(&gate);
    let evaluation = submit(&gate, &spend);
    assert!(evaluation.verdict.consensus_accepted);
    let run = &evaluation.committed_runs[0];
    // One committed signature operation allows 100,000 units plus the free 9,999.
    assert_eq!((run.script_units_limit, run.used_script_units), (Some(109_999), 100_001));

    // With a count of zero the node does not report a signature operation limit any
    // more, but the script unit budget.
    let owner = TestKey::from_seed(OWNER);
    let mut zero = plain_spend_v0(&gate);
    zero.tx.inputs[0].compute_commit = kaspa_consensus_core::mass::SigopCount(0).into();
    zero.tx.finalize();
    zero.sign_p2pk(0, &owner, SIG_HASH_ALL);
    assert_eq!(run_of(&gate, &zero), Err(TxScriptError::ExceededCommittedScriptUnits { used: 100_000, limit: 9_999 }));
}

fn run_of(gate: &GateParams, spend: &Spend) -> Result<(), TxScriptError> {
    run(gate, spend).result
}

#[test]
fn version_0_signature_covers_the_signature_operation_count() {
    let gate = node();
    let mut spend = plain_spend_v0(&gate);
    // Raising the count after signing changes the message.
    spend.tx.inputs[0].compute_commit = kaspa_consensus_core::mass::SigopCount(2).into();
    spend.tx.finalize();
    assert_eq!(run_of(&gate, &spend), Err(TxScriptError::EvalFalse));
}

#[test]
fn before_toccata_the_engine_counts_signature_operations() {
    let before = node_before_toccata();
    let owner = TestKey::from_seed(OWNER);
    let spend = plain_spend_v0(&before);
    let evaluation = submit(&before, &spend);
    assert!(evaluation.verdict.consensus_accepted);
    let run = &evaluation.committed_runs[0];
    // Script units are not metered on this side of the fork.
    assert_eq!((run.used_script_units, run.used_sig_ops), (0, 1));

    let mut zero = plain_spend_v0(&before);
    zero.tx.inputs[0].compute_commit = kaspa_consensus_core::mass::SigopCount(0).into();
    zero.tx.finalize();
    zero.sign_p2pk(0, &owner, SIG_HASH_ALL);
    assert_eq!(run_of(&before, &zero), Err(TxScriptError::ExceededSigOpLimit(0)));
}

#[test]
fn a_coin_with_an_unknown_script_version_is_accepted_unexecuted() {
    let gate = node();
    let mut spend = plain_spend(&gate);
    let script = spend.entries[0].script_public_key.script().to_vec();
    spend.entries[0].script_public_key = ScriptPublicKey::from_vec(1, script);
    spend.tx.inputs[0].signature_script.clear();
    let evaluation = submit(&gate, &spend);
    assert!(evaluation.verdict.consensus_accepted);
    let run = &evaluation.committed_runs[0];
    assert!(run.accepted_unknown_version);
    assert_eq!((run.result.clone(), run.used_script_units), (Ok(()), 0));
    assert!(evaluation.verdict.inputs[0].committed.accepted_unknown_version);
}
