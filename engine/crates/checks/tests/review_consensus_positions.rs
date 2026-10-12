//! Where the engine stopped: `node_gate::engine::ScriptRunner` on scripts whose failing
//! opcode is known in advance, and on generated scripts where it is established by an
//! independent experiment.
//!
//! The fixed cases go beyond `node-gate/tests/gate/positions.rs`: nested
//! conditionals inside a branch that is not taken, pushes with one, two and four length
//! bytes, pushed data that looks like code, one script failing at two different places
//! depending on its argument, several inputs in one transaction, the rules that exist
//! only before Toccata.
//!
//! The generated cases carry no expectation fixed in advance. For every refused
//! script the reported opcode is checked by cutting the script: the part that ends with
//! the reported opcode must be refused in the same way at the same place, and the part
//! that ends just before it must not be refused by any opcode at all. A final-stack
//! verdict is checked by appending one push of `true`, whose effect on each of the three
//! final-stack errors is known.

use kaspa_consensus_core::{
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
};
use kaspa_hashes::Hash;
use kaspa_txscript::opcodes::codes::{
    Op2Drop, OpAdd, OpBlake2b, OpCat, OpData5, OpDrop, OpElse, OpEndIf, OpEqualVerify, OpFalse,
    OpIf, OpNop, OpNotIf, OpNumEqualVerify, OpPushData1, OpPushData2, OpPushData4, OpReturn,
    OpTrue, OpVerify,
};
use kaspa_txscript_errors::TxScriptError;
use node_gate::{
    GateOptions, GateParams, ScriptKind, ScriptRun, ScriptRunner, StopPoint,
    engine::OpcodeStop,
    gate, utxo,
    wallet::{p2sh_script_public_key, p2sh_signature_script},
};

const OP_3: u8 = 0x53;
const OP_DUP: u8 = 0x76;

/// Testnet-10 well after Toccata.
fn node() -> GateParams {
    GateParams::testnet10()
}

/// Testnet-10 one DAA score before Toccata.
fn node_before_toccata() -> GateParams {
    let gate = GateParams::testnet10();
    let activation = gate.params.toccata_activation.daa_score();
    gate.with_daa_score(activation - 1)
}

/// One input: the coin's script and the signature script that spends it.
struct Spent {
    script_public_key: ScriptPublicKey,
    signature_script: Vec<u8>,
}

impl Spent {
    /// A pay-to-script-hash coin locked to `redeem_script`, spent with `arguments`
    /// (encoded pushes) followed by the push of the redeem script.
    fn p2sh(redeem_script: &[u8], arguments: &[u8]) -> Self {
        Self {
            script_public_key: p2sh_script_public_key(redeem_script),
            signature_script: p2sh_signature_script(arguments, redeem_script),
        }
    }

    /// A coin whose script public key is `script` itself.
    fn bare(script: &[u8], signature_script: &[u8]) -> Self {
        Self {
            script_public_key: ScriptPublicKey::from_vec(0, script.to_vec()),
            signature_script: signature_script.to_vec(),
        }
    }
}

/// A transaction spending `coins`, one input each, to one output. Version 1 inputs commit
/// `commitment` budget units, version 0 inputs the same number of signature operations.
fn spend(
    gate: &GateParams,
    version: u16,
    commitment: u8,
    coins: &[Spent],
) -> (Transaction, Vec<UtxoEntry>) {
    let inputs = coins
        .iter()
        .enumerate()
        .map(|(i, coin)| {
            let outpoint = TransactionOutpoint::new(Hash::from_bytes([i as u8 + 1; 32]), 0);
            if version == 0 {
                TransactionInput::new(outpoint, coin.signature_script.clone(), 0, commitment)
            } else {
                TransactionInput::new_with_compute_budget(
                    outpoint,
                    coin.signature_script.clone(),
                    0,
                    commitment as u16,
                )
            }
        })
        .collect();
    let entries = coins
        .iter()
        .map(|coin| {
            UtxoEntry::new(
                1_000_000_000,
                coin.script_public_key.clone(),
                gate.pov_daa_score - 1_000,
                false,
                None,
            )
        })
        .collect();
    let output = TransactionOutput::new(
        999_000_000 * coins.len() as u64,
        ScriptPublicKey::from_vec(0, vec![OpTrue]),
    );
    (
        Transaction::new(
            version,
            inputs,
            vec![output],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        ),
        entries,
    )
}

/// Runs every input under its committed limit with the node's flags, locating refusals.
/// Every run is repeated without locating; the answer and the units must not depend on it.
fn runs(gate: &GateParams, tx: &Transaction, entries: &[UtxoEntry]) -> Vec<ScriptRun> {
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let covenants = utxo::check_covenant_info(gate, &populated, gate.block_daa_score)
        .expect("no covenant bindings");
    let runner = ScriptRunner::new(&populated, &covenants, gate.engine_flags());
    let located = runner.run_all_committed(true);
    let plain = runner.run_all_committed(false);
    for (with, without) in located.iter().zip(&plain) {
        assert_eq!(with.result, without.result);
        assert_eq!(
            (with.used_script_units, with.used_sig_ops),
            (without.used_script_units, without.used_sig_ops)
        );
        assert_eq!(with.stop.is_some(), with.result.is_err());
        assert_eq!(without.stop, None);
    }
    located
}

/// One version 1 input with a budget of `budget` units, after Toccata.
fn run(coin: Spent, budget: u8) -> ScriptRun {
    let gate = node();
    let (tx, entries) = spend(&gate, 1, budget, &[coin]);
    runs(&gate, &tx, &entries).remove(0)
}

/// One version 0 input committing `sig_ops` signature operations, before Toccata.
fn run_before_toccata(coin: Spent, sig_ops: u8) -> ScriptRun {
    let gate = node_before_toccata();
    let (tx, entries) = spend(&gate, 0, sig_ops, &[coin]);
    runs(&gate, &tx, &entries).remove(0)
}

fn at(
    script: ScriptKind,
    op_index: usize,
    byte_offset: usize,
    opcode: u8,
    name: &str,
    executed: bool,
) -> Option<StopPoint> {
    Some(StopPoint::Opcode(OpcodeStop {
        script,
        op_index,
        byte_offset,
        opcode,
        opcode_name: Some(name.to_string()),
        executed,
    }))
}

/// A script with a branch that is not taken in front of the failing opcode. The skipped
/// branch holds a nested conditional with both arms and pushes in all three long forms.
#[rustfmt::skip]
fn script_with_a_skipped_nested_branch(condition: u8, last_byte_of_second_item: u8) -> Vec<u8> {
    vec![
        condition,                                      //  0 @ 0
        OpIf,                                           //  1 @ 1
            OpPushData1, 3, 0xaa, 0xbb, 0xcc,           //  2 @ 2   five bytes
            OpIf,                                       //  3 @ 7
                OpPushData2, 4, 0, 1, 2, 3, 4,          //  4 @ 8   seven bytes
            OpElse,                                     //  5 @15
                OpPushData4, 2, 0, 0, 0, 9, 9,          //  6 @16   seven bytes
            OpEndIf,                                    //  7 @23
            OpVerify,                                   //  8 @24
        OpElse,                                         //  9 @25
            OpData5, 1, 2, 3, 4, 5,                     // 10 @26   six bytes
            OpData5, 1, 2, 3, 4, last_byte_of_second_item, // 11 @32
            OpEqualVerify,                              // 12 @38
        OpEndIf,                                        // 13 @39
        OpTrue,                                         // 14 @40
    ]
}

#[test]
fn a_refusal_behind_a_skipped_branch_with_nested_conditionals_and_long_pushes() {
    let script = script_with_a_skipped_nested_branch(OpFalse, 6);
    assert_eq!(script.len(), 41);
    let refused = run(Spent::p2sh(&script, &[]), 1);
    assert_eq!(refused.result, Err(TxScriptError::VerifyError));
    assert_eq!(
        refused.stop,
        at(
            ScriptKind::RedeemScript,
            12,
            38,
            OpEqualVerify,
            "OpEqualVerify",
            true
        )
    );
    // One line for the push of the redeem script, three for the lock, thirteen in the
    // redeem script: the eight opcodes of the skipped branch are logged too.
    assert_eq!(refused.trace.unwrap().opcodes_logged, 1 + 3 + 13);

    // Equal items: the same script passes.
    assert_eq!(
        run(
            Spent::p2sh(&script_with_a_skipped_nested_branch(OpFalse, 5), &[]),
            1
        )
        .result,
        Ok(())
    );
    // The other condition: the first branch runs, its inner conditional takes the first
    // arm, and the unequal items are skipped.
    assert_eq!(
        run(
            Spent::p2sh(&script_with_a_skipped_nested_branch(OpTrue, 6), &[]),
            1
        )
        .result,
        Ok(())
    );
}

#[test]
fn pushed_data_that_looks_like_code_is_not_counted_as_opcodes() {
    // The first pushed item reads as two returns, an always illegal opcode, a disabled
    // opcode and a push without its length; the second as three open conditionals and a
    // push without its length.
    #[rustfmt::skip]
    let script = vec![
        OpDrop,                                         // 0 @ 0   drops the argument
        OpData5, OpReturn, OpReturn, 0x65, 0x80, 0x4c,  // 1 @ 1   six bytes
        OpPushData1, 4, OpIf, OpIf, OpIf, 0x4e,         // 2 @ 7   six bytes
        Op2Drop,                                        // 3 @13
        OpFalse,                                        // 4 @14
        OpVerify,                                       // 5 @15   fails
        OpTrue,                                         // 6 @16
    ];
    // The argument is itself a script: three returns.
    let arguments = [0x03, OpReturn, OpReturn, OpReturn];
    let refused = run(Spent::p2sh(&script, &arguments), 1);
    assert_eq!(refused.result, Err(TxScriptError::VerifyError));
    assert_eq!(
        refused.stop,
        at(ScriptKind::RedeemScript, 5, 15, OpVerify, "OpVerify", true)
    );
    assert_eq!(refused.trace.unwrap().opcodes_logged, 2 + 3 + 6);

    let mut passing = script;
    passing[14] = OpTrue;
    assert_eq!(run(Spent::p2sh(&passing, &arguments), 1).result, Ok(()));
}

/// A lock of 15 bytes used as the script public key itself: the argument chooses the
/// branch, and each branch ends in a verification that fails.
#[rustfmt::skip]
fn two_way_lock() -> Vec<u8> {
    vec![
        OpIf,                   //  0 @ 0
            0x02, 0xaa, 0xbb,   //  1 @ 1
            OpDrop,             //  2 @ 4
            OpFalse,            //  3 @ 5
            OpVerify,           //  4 @ 6   fails when the argument is true
        OpElse,                 //  5 @ 7
            OpTrue,             //  6 @ 8
            OpTrue,             //  7 @ 9
            OpAdd,              //  8 @10
            OP_3,               //  9 @11
            OpNumEqualVerify,   // 10 @12   fails when the argument is false
        OpEndIf,                // 11 @13
        OpTrue,                 // 12 @14
    ]
}

#[test]
fn one_script_one_error_two_places() {
    let lock = two_way_lock();

    let first_branch = run(Spent::bare(&lock, &[OpTrue]), 0);
    assert_eq!(first_branch.result, Err(TxScriptError::VerifyError));
    assert_eq!(
        first_branch.stop,
        at(
            ScriptKind::ScriptPublicKey,
            4,
            6,
            OpVerify,
            "OpVerify",
            true
        )
    );

    let second_branch = run(Spent::bare(&lock, &[OpFalse]), 0);
    assert_eq!(second_branch.result, Err(TxScriptError::VerifyError));
    assert_eq!(
        second_branch.stop,
        at(
            ScriptKind::ScriptPublicKey,
            10,
            12,
            OpNumEqualVerify,
            "OpNumEqualVerify",
            true
        )
    );

    // Without an argument the conditional itself has nothing to read.
    let no_argument = run(Spent::bare(&lock, &[]), 0);
    assert_eq!(
        no_argument.result,
        Err(TxScriptError::InvalidStackOperation(1, 0))
    );
    assert_eq!(
        no_argument.stop,
        at(ScriptKind::ScriptPublicKey, 0, 0, OpIf, "OpIf", true)
    );

    // The same lock behind a hash: the positions move to the redeem script unchanged.
    let hashed = run(Spent::p2sh(&lock, &[OpFalse]), 1);
    assert_eq!(
        hashed.stop,
        at(
            ScriptKind::RedeemScript,
            10,
            12,
            OpNumEqualVerify,
            "OpNumEqualVerify",
            true
        )
    );
}

#[test]
fn every_input_of_a_transaction_has_its_own_position() {
    let gate = node();
    let lock = two_way_lock();
    let nested = script_with_a_skipped_nested_branch(OpFalse, 6);
    let coins = [
        Spent::p2sh(&[OpTrue], &[]),
        Spent::p2sh(&nested, &[]),
        Spent::bare(&lock, &[OpTrue]),
        Spent::p2sh(&script_with_a_skipped_nested_branch(OpFalse, 5), &[]),
        Spent::p2sh(&lock, &[OpFalse]),
    ];
    let (tx, entries) = spend(&gate, 1, 1, &coins);
    let all = runs(&gate, &tx, &entries);
    let stops: Vec<Option<StopPoint>> = all.iter().map(|run| run.stop.clone()).collect();
    assert_eq!(
        stops,
        vec![
            None,
            at(
                ScriptKind::RedeemScript,
                12,
                38,
                OpEqualVerify,
                "OpEqualVerify",
                true
            ),
            at(
                ScriptKind::ScriptPublicKey,
                4,
                6,
                OpVerify,
                "OpVerify",
                true
            ),
            None,
            at(
                ScriptKind::RedeemScript,
                10,
                12,
                OpNumEqualVerify,
                "OpNumEqualVerify",
                true
            ),
        ]
    );
    assert_eq!(
        all.iter().map(|run| run.input_index).collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );

    // The gate names the first refused input and keeps the record of every one.
    let evaluation = gate::evaluate(&gate, &tx, &entries, GateOptions::submit());
    assert_eq!(
        evaluation.verdict.consensus_refusal.as_ref().unwrap().input,
        Some(1)
    );
    let recorded: Vec<Option<StopPoint>> = evaluation
        .verdict
        .inputs
        .iter()
        .map(|input| input.committed.stop.clone())
        .collect();
    assert_eq!(recorded, stops);
}

#[test]
fn the_end_of_a_script_inside_a_conditional() {
    // A script public key that opens a conditional and ends.
    let open = run(Spent::bare(&[OpTrue, OpIf, OpTrue], &[]), 0);
    assert_eq!(open.result, Err(TxScriptError::ErrUnbalancedConditional));
    assert_eq!(
        open.stop,
        Some(StopPoint::EndOfScript(ScriptKind::ScriptPublicKey))
    );

    // Two levels deep at the end of a redeem script, the inner one in a skipped branch.
    let nested = run(
        Spent::p2sh(&[OpFalse, OpIf, OpTrue, OpNotIf, OpElse, OpEndIf], &[]),
        1,
    );
    assert_eq!(nested.result, Err(TxScriptError::ErrUnbalancedConditional));
    assert_eq!(
        nested.stop,
        Some(StopPoint::EndOfScript(ScriptKind::RedeemScript))
    );

    // One closing opcode too many is the error of that opcode, not of the end.
    let closed_twice = run(
        Spent::p2sh(&[OpTrue, OpTrue, OpIf, OpEndIf, OpEndIf], &[]),
        1,
    );
    assert_eq!(
        closed_twice.result,
        Err(TxScriptError::InvalidState(
            "condition stack empty".to_string()
        ))
    );
    assert_eq!(
        closed_twice.stop,
        at(ScriptKind::RedeemScript, 4, 4, OpEndIf, "OpEndIf", true)
    );
}

#[test]
fn the_hash_wrapper_and_the_final_stack() {
    // Nothing pushed for a pay-to-script-hash coin: the hash opcode of the lock has no item.
    let mut nothing = Spent::p2sh(&[OpTrue], &[]);
    nothing.signature_script.clear();
    let nothing = run(nothing, 0);
    assert_eq!(
        nothing.result,
        Err(TxScriptError::InvalidStackOperation(1, 0))
    );
    assert_eq!(
        nothing.stop,
        at(
            ScriptKind::ScriptPublicKey,
            0,
            0,
            OpBlake2b,
            "OpBlake2b",
            true
        )
    );

    // An item that is not the redeem script, and does not even parse as a script.
    let mut other = Spent::p2sh(&[OpTrue], &[]);
    other.signature_script = vec![0x03, OpPushData1, 0xff, 0x01];
    let other = run(other, 0);
    assert_eq!(other.result, Err(TxScriptError::EvalFalse));
    assert_eq!(other.stop, Some(StopPoint::P2shHashMismatch));

    // An empty redeem script: the wrapper passes and nothing is left on the stack.
    let empty = run(Spent::p2sh(&[], &[]), 0);
    assert_eq!(empty.result, Err(TxScriptError::EmptyStack));
    assert_eq!(empty.stop, Some(StopPoint::FinalStack));
    // With one true argument under it, the same coin is spent.
    assert_eq!(run(Spent::p2sh(&[], &[OpTrue]), 0).result, Ok(()));
    // With a false one, the final stack is false.
    let false_left = run(Spent::p2sh(&[], &[OpFalse]), 0);
    assert_eq!(
        (false_left.result.clone(), false_left.stop.clone()),
        (Err(TxScriptError::EvalFalse), Some(StopPoint::FinalStack))
    );

    // Two items left.
    let unclean = run(Spent::p2sh(&[OpTrue, OpTrue], &[]), 0);
    assert_eq!(
        (unclean.result.clone(), unclean.stop.clone()),
        (
            Err(TxScriptError::CleanStack(1)),
            Some(StopPoint::FinalStack)
        )
    );
}

#[test]
fn rules_that_exist_only_before_toccata() {
    // 201 operations are allowed in one script, the 202nd is refused where it stands.
    let mut script = vec![OpNop; 201];
    script.push(OpTrue);
    assert_eq!(
        run_before_toccata(Spent::bare(&script, &[]), 0).result,
        Ok(())
    );
    let mut script = vec![OpNop; 202];
    script.push(OpTrue);
    let too_many = run_before_toccata(Spent::bare(&script, &[]), 0);
    assert_eq!(too_many.result, Err(TxScriptError::TooManyOperations(201)));
    // The engine counts the operation and refuses before it interprets the opcode
    // (rusty-kaspa a41a333 crypto/txscript/src/lib.rs:617-621): it did not run.
    assert_eq!(
        too_many.stop,
        at(ScriptKind::ScriptPublicKey, 201, 201, OpNop, "OpNop", false)
    );
    // After Toccata the limit is far away. The script is 203 bytes long, so 168 bytes
    // above a standard one are charged up front: budget 2 covers 16,800 units.
    assert_eq!(run(Spent::bare(&script, &[]), 2).result, Ok(()));

    // A push that could be shorter: refused in a branch that is executing, by a check in
    // front of the interpreter (lib.rs:627-629), and ignored in a skipped branch.
    let padded = [OpTrue, OpPushData1, 1, 5, OpDrop];
    let not_minimal = run_before_toccata(Spent::bare(&padded, &[]), 0);
    assert!(
        matches!(not_minimal.result, Err(TxScriptError::NotMinimalData(_))),
        "{:?}",
        not_minimal.result
    );
    assert_eq!(
        not_minimal.stop,
        at(
            ScriptKind::ScriptPublicKey,
            1,
            1,
            OpPushData1,
            "OpPushData1",
            false
        )
    );
    let skipped = [OpFalse, OpIf, OpPushData1, 1, 5, OpEndIf, OpTrue];
    assert_eq!(
        run_before_toccata(Spent::bare(&skipped, &[]), 0).result,
        Ok(())
    );
    assert_eq!(run(Spent::bare(&padded, &[]), 0).result, Ok(()));

    // OpCat is disabled: refused before it runs, even in a skipped branch.
    let cat = [OpFalse, OpIf, OpCat, OpEndIf, OpTrue];
    let disabled = run_before_toccata(Spent::bare(&cat, &[]), 0);
    assert!(
        matches!(disabled.result, Err(TxScriptError::OpcodeDisabled(_))),
        "{:?}",
        disabled.result
    );
    assert_eq!(
        disabled.stop,
        at(ScriptKind::ScriptPublicKey, 2, 2, OpCat, "OpCat", false)
    );
    assert_eq!(run(Spent::bare(&cat, &[]), 0).result, Ok(()));
}

/// The budget of a pay-to-script-hash input pays for hashing the redeem script before the
/// redeem script runs. A long script can use up a small budget in the hash opcode of the
/// lock; with one unit more the budget lasts into the redeem script, past a branch that is
/// not taken and costs nothing.
#[test]
fn the_budget_runs_out_in_the_lock_or_behind_a_skipped_branch() {
    // Opcode index @ byte offset:
    //   0 @0 OpFalse, 1 @1 OpIf,
    //   2 @2 push of 3,000 bytes, 3 @3005 OpDup, 4 @3006 OpDup (all three skipped),
    //   5 @3007 OpEndIf,
    //   6 @3008 push of 3,000 bytes, 7 @6011 OpDup, 8 @6012 OpDup, 9 @6013 OpDup,
    //   10 @6014 Op2Drop, 11 @6015 Op2Drop, 12 @6016 OpTrue.
    let long_push = [0x4d, 0xb8, 0x0b]; // OpPushData2 with a length of 3,000
    let mut script = vec![OpFalse, OpIf];
    script.extend_from_slice(&long_push);
    script.extend_from_slice(&[0x22; 3_000]);
    script.extend_from_slice(&[OP_DUP, OP_DUP, OpEndIf]);
    script.extend_from_slice(&long_push);
    script.extend_from_slice(&[0x33; 3_000]);
    script.extend_from_slice(&[OP_DUP, OP_DUP, OP_DUP]);
    script.extend_from_slice(&[Op2Drop, Op2Drop, OpTrue]);
    assert_eq!(script.len(), 6_017);

    // Hashing 6,017 bytes costs 12,034 units, more than the 9,999 a budget of zero allows.
    let in_the_lock = run(Spent::p2sh(&script, &[]), 0);
    assert_eq!(
        in_the_lock.result,
        Err(TxScriptError::ExceededCommittedScriptUnits {
            used: 12_034,
            limit: 9_999
        })
    );
    assert_eq!(
        in_the_lock.stop,
        at(
            ScriptKind::ScriptPublicKey,
            0,
            0,
            OpBlake2b,
            "OpBlake2b",
            true
        )
    );
    assert_eq!(in_the_lock.used_script_units, 0);

    // A budget of one allows 19,999. The lock costs 12,067 in all; the two copies in the
    // skipped branch cost nothing; each copy after it costs 3,000 and the third does not fit.
    let behind_the_branch = run(Spent::p2sh(&script, &[]), 1);
    assert_eq!(
        behind_the_branch.result,
        Err(TxScriptError::ExceededCommittedScriptUnits {
            used: 21_067,
            limit: 19_999
        })
    );
    assert_eq!(
        behind_the_branch.stop,
        at(ScriptKind::RedeemScript, 9, 6_013, OP_DUP, "OpDup", true)
    );
    assert_eq!(behind_the_branch.used_script_units, 18_067);

    // A budget of two covers the 21,067 units.
    let covered = run(Spent::p2sh(&script, &[]), 2);
    assert_eq!(
        (covered.result, covered.used_script_units),
        (Ok(()), 21_067)
    );
}

/// `OpcodeStop::executed` is true when the opcode was handed to the interpreter and failed
/// there, false when it was refused before that. Three refusals are raised by the engine
/// after it has logged the opcode and before it hands it to the interpreter, two of them
/// also for an opcode in a branch that is not taken
/// (rusty-kaspa a41a333 crypto/txscript/src/lib.rs:617-630): too many operations, a
/// literal push above the element size, and a push that is not minimal. Here the 202nd
/// operation of a script sits in a skipped branch and is never interpreted, so the flag
/// must say false.
#[test]
fn an_opcode_refused_in_a_skipped_branch_was_not_executed() {
    // OpFalse, OpIf (operation 1), 201 no-ops (operations 2 to 202), OpEndIf, OpTrue.
    let mut script = vec![OpFalse, OpIf];
    script.extend_from_slice(&[OpNop; 201]);
    script.extend_from_slice(&[OpEndIf, OpTrue]);
    let refused = run_before_toccata(Spent::bare(&script, &[]), 0);
    assert_eq!(refused.result, Err(TxScriptError::TooManyOperations(201)));
    // The place is right: the last of the no-ops, opcode 202 at byte 202.
    let Some(StopPoint::Opcode(found)) = refused.stop else {
        panic!("{:?}", refused.stop)
    };
    assert_eq!(
        (
            found.script,
            found.op_index,
            found.byte_offset,
            found.opcode
        ),
        (ScriptKind::ScriptPublicKey, 202, 202, OpNop)
    );
    assert!(
        !found.executed,
        "an opcode in a branch that is not taken is reported as executed"
    );
}

/// A fixed sequence of numbers (xorshift64*). Not random: the same seed gives the same
/// scripts on every run.
struct Sequence(u64);

impl Sequence {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn pick<'a>(&mut self, items: &'a [&'a [u8]]) -> &'a [u8] {
        items[self.below(items.len() as u64) as usize]
    }
}

/// One opcode of a generated script, with the place the generator put it.
struct Placed {
    offset: usize,
    bytes: Vec<u8>,
}

/// A script as the list of its opcodes.
struct Generated {
    ops: Vec<Placed>,
}

impl Generated {
    fn bytes(&self) -> Vec<u8> {
        self.ops
            .iter()
            .flat_map(|op| op.bytes.iter().copied())
            .collect()
    }

    /// The script cut after its first `count` opcodes.
    fn prefix(&self, count: usize) -> Vec<u8> {
        self.ops[..count]
            .iter()
            .flat_map(|op| op.bytes.iter().copied())
            .collect()
    }
}

/// Builds a script of `len` opcodes from pushes, conditionals, stack and arithmetic
/// opcodes and, now and then, an opcode that is always refused. The first few opcodes are
/// pushes, so that the stack is not empty when the others begin and refusals are spread
/// over the whole script.
fn generate(sequence: &mut Sequence, len: usize) -> Generated {
    const PUSHES: &[&[u8]] = &[
        &[0x00],
        &[0x51],
        &[0x51],
        &[0x52],
        &[0x4f],
        &[0x03, 0x07, 0x00, 0x09],
        &[0x4c, 0x02, 0x11, 0x22],
        &[0x4d, 0x03, 0x00, 0x01, 0x02, 0x03],
        &[0x4e, 0x01, 0x00, 0x00, 0x00, 0x01],
    ];
    const CONDITIONALS: &[&[u8]] = &[&[0x63], &[0x63], &[0x64], &[0x67], &[0x68], &[0x68]];
    // verify, drop, dup, add, equal, equalverify, nop, swap, depth, cat, size, 1add, not,
    // to alt stack, from alt stack, 2drop
    const OTHERS: &[&[u8]] = &[
        &[0x69],
        &[0x75],
        &[0x76],
        &[0x93],
        &[0x87],
        &[0x88],
        &[0x61],
        &[0x7c],
        &[0x74],
        &[0x7e],
        &[0x82],
        &[0x8b],
        &[0x91],
        &[0x6b],
        &[0x6c],
        &[0x6d],
    ];
    // return, a disabled opcode, an always illegal one, two reserved ones, an unassigned one
    const RARE: &[&[u8]] = &[&[0x6a], &[0x80], &[0x65], &[0x50], &[0x62], &[0xfa]];

    let leading_pushes = 2 + sequence.below(7) as usize;
    let mut ops = Vec::with_capacity(len);
    let mut offset = 0;
    for position in 0..len {
        let bytes = match sequence.below(100) {
            _ if position < leading_pushes => sequence.pick(PUSHES),
            0..=47 => sequence.pick(PUSHES),
            48..=65 => sequence.pick(CONDITIONALS),
            66..=96 => sequence.pick(OTHERS),
            _ => sequence.pick(RARE),
        }
        .to_vec();
        let size = bytes.len();
        ops.push(Placed { offset, bytes });
        offset += size;
    }
    Generated { ops }
}

/// How a generated script is put on a coin.
#[derive(Clone)]
struct Setting {
    /// Behind a hash, as a redeem script; otherwise the script public key itself.
    hashed: bool,
    /// Pushes in front, in the signature script.
    arguments: Vec<u8>,
}

impl Setting {
    /// The script kind a refusal inside the generated script is reported in.
    fn kind(&self) -> ScriptKind {
        if self.hashed {
            ScriptKind::RedeemScript
        } else {
            ScriptKind::ScriptPublicKey
        }
    }

    /// Runs `script` under a budget large enough that no generated script can exhaust it.
    fn run(&self, script: &[u8]) -> ScriptRun {
        let coin = if self.hashed {
            Spent::p2sh(script, &self.arguments)
        } else {
            Spent::bare(script, &self.arguments)
        };
        run(coin, 100)
    }
}

/// What kind of verdict a run ended with, for the tally at the end of the generated test.
#[derive(Default, Debug)]
struct Tally {
    accepted: usize,
    at_an_opcode: usize,
    refused_before_running: usize,
    deep: usize,
    final_stack: usize,
    end_of_script: usize,
}

#[test]
fn generated_scripts_stop_where_cutting_the_script_says_they_stop() {
    const ARGUMENTS: &[&[u8]] = &[
        &[0x00],
        &[0x51],
        &[0x52],
        &[0x02, 0x05, 0x06],
        &[0x4c, 0x01, 0x07],
    ];
    let mut sequence = Sequence(0x9e37_79b9_7f4a_7c15);
    let mut tally = Tally::default();

    for case in 0..2_000 {
        let len = 1 + sequence.below(40) as usize;
        let generated = generate(&mut sequence, len);
        let mut arguments = Vec::new();
        for _ in 0..sequence.below(4) {
            arguments.extend_from_slice(sequence.pick(ARGUMENTS));
        }
        let setting = Setting {
            hashed: sequence.below(3) != 0,
            arguments,
        };
        let script = generated.bytes();
        let outcome = setting.run(&script);
        let context = || {
            let hashed = if setting.hashed { "hashed" } else { "bare" };
            format!(
                "case {case} ({hashed}), arguments {}, script {}",
                faster_hex::hex_string(&setting.arguments),
                faster_hex::hex_string(&script)
            )
        };

        let Some(stop) = outcome.stop.clone() else {
            assert_eq!(outcome.result, Ok(()), "{}", context());
            tally.accepted += 1;
            continue;
        };
        let error = outcome.result.clone().unwrap_err();

        match stop {
            StopPoint::Opcode(found) => {
                assert_eq!(found.script, setting.kind(), "{}", context());
                // The index, the offset and the opcode byte agree with the generator's own list.
                let placed = &generated.ops[found.op_index];
                assert_eq!(
                    (found.byte_offset, found.opcode),
                    (placed.offset, placed.bytes[0]),
                    "{}",
                    context()
                );

                // Cut after the reported opcode: refused in the same way at the same place.
                let through = setting.run(&generated.prefix(found.op_index + 1));
                assert_eq!(through.result, Err(error.clone()), "{}", context());
                assert_eq!(
                    through.stop,
                    Some(StopPoint::Opcode(found.clone())),
                    "{}",
                    context()
                );

                // Cut before it: no opcode refuses. What is left ends cleanly, on its final
                // stack, inside a conditional or, when nothing at all is left, before any opcode.
                let before = setting.run(&generated.prefix(found.op_index));
                let nothing_left =
                    found.op_index == 0 && !setting.hashed && setting.arguments.is_empty();
                let acceptable = match &before.stop {
                    None | Some(StopPoint::FinalStack) => true,
                    Some(StopPoint::EndOfScript(kind)) => *kind == setting.kind(),
                    Some(StopPoint::BeforeAnyOpcode) => nothing_left,
                    _ => false,
                };
                assert!(
                    acceptable,
                    "{}: the part before the reported opcode stops at {:?}",
                    context(),
                    before.stop
                );

                if found.op_index >= 6 {
                    tally.deep += 1;
                }
                if found.executed {
                    tally.at_an_opcode += 1;
                } else {
                    tally.refused_before_running += 1;
                }
            }
            StopPoint::FinalStack => {
                // One more push of true turns an empty final stack into an accepted one, and a
                // false or unclean one into an unclean one with one more item.
                let mut extended = script.clone();
                extended.push(OpTrue);
                let after = setting.run(&extended);
                let expected = match error {
                    TxScriptError::EmptyStack => Ok(()),
                    TxScriptError::EvalFalse => Err(TxScriptError::CleanStack(1)),
                    TxScriptError::CleanStack(extra) => Err(TxScriptError::CleanStack(extra + 1)),
                    ref other => panic!("{}: {other:?} reported as a final stack error", context()),
                };
                assert_eq!(after.result, expected, "{}", context());
                tally.final_stack += 1;
            }
            StopPoint::EndOfScript(kind) => {
                assert_eq!(
                    (kind, error.clone()),
                    (setting.kind(), TxScriptError::ErrUnbalancedConditional),
                    "{}",
                    context()
                );
                // Closing every open conditional removes this error.
                let mut closed = script.clone();
                let mut closings = 0;
                loop {
                    closed.push(OpEndIf);
                    closings += 1;
                    if setting.run(&closed).result != Err(TxScriptError::ErrUnbalancedConditional) {
                        break;
                    }
                    assert!(
                        closings <= len,
                        "{}: still unbalanced after {closings} closing opcodes",
                        context()
                    );
                }
                tally.end_of_script += 1;
            }
            other => panic!("{}: unexpected stop {other:?} for {error:?}", context()),
        }
    }

    // The generator reaches every kind of verdict; the numbers are fixed by the seed.
    assert!(tally.accepted > 0, "{tally:?}");
    assert!(tally.at_an_opcode > 500, "{tally:?}");
    assert!(tally.refused_before_running > 40, "{tally:?}");
    assert!(tally.deep > 400, "{tally:?}");
    assert!(tally.final_stack > 100, "{tally:?}");
    assert!(tally.end_of_script > 100, "{tally:?}");
}
