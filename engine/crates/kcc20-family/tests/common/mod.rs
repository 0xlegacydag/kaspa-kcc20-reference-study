//! Shared helpers of the integration tests.
//!
//! The crate under test does not judge transactions. The tests borrow two judges:
//!
//! - the reference authors' own runner, `execute_transaction_with_covenants` of the Argent
//!   runtime, as the yardstick for "accepted" and "refused at input N";
//! - the script engine itself with its opcode log, only to find out WHICH opcode refused, so
//!   that the source map can be checked against a real run.

#![allow(dead_code)]

use argent_runtime::{BuilderError, covenant_engine_flags, execute_transaction_with_covenants};
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::mass::ScriptUnits;
use kaspa_consensus_core::tx::Transaction;
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::{EngineCtx, SigCacheKey, TxScriptEngine};
use kaspa_txscript_errors::TxScriptError;
use kcc20_family::scenario::Assembled;

/// Runs the authors' runner on a copy of the assembled transaction. On success returns the
/// transaction as the runner leaves it: with the compute budgets it measured.
pub fn run_authors(assembled: &Assembled) -> Result<Transaction, BuilderError> {
    let mut tx = assembled.tx.clone();
    execute_transaction_with_covenants(&mut tx, assembled.utxos.clone())?;
    Ok(tx)
}

/// The authors' verdict in the only form their own tests use: the index of the first input
/// whose script fails, with the engine's error.
pub fn refused_input(assembled: &Assembled) -> (usize, TxScriptError) {
    match run_authors(assembled) {
        Err(BuilderError::InputScript {
            input_index,
            source,
        }) => (input_index, source),
        Err(other) => panic!(
            "`{}`: expected a script refusal, got {other}",
            assembled.name
        ),
        Ok(_) => panic!(
            "`{}`: expected a script refusal, the transaction was accepted",
            assembled.name
        ),
    }
}

/// What the engine did with one input.
pub struct InputRun {
    /// The engine's verdict.
    pub result: Result<(), TxScriptError>,
    /// Number of lines in the opcode log: one per opcode the engine parsed, the failing one
    /// included (the line is written before the opcode runs).
    pub log_lines: usize,
    /// The last line of the log: the opcode that failed, when the run failed in an opcode.
    pub last_line: String,
}

/// Runs one input on the script engine with the authors' flags and no script-unit limit
/// (argent 9a9f4b1 crates/argent-runtime/src/lib.rs:1929-1954) and keeps the opcode log
/// (rusty-kaspa a41a333 crypto/txscript/src/lib.rs:496-499, 639-654).
pub fn run_input_with_log(assembled: &Assembled, input_index: usize) -> InputRun {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_cache: Cache<SigCacheKey, bool> = Cache::new(100);
    let populated = assembled.populated();
    let covenants = CovenantsContext::from_tx(&populated)
        .expect("the covenant bindings of the scenario are well formed");
    let input = assembled.tx.inputs[input_index].clone();
    let mut log: Vec<u8> = Vec::new();
    let result = {
        let mut engine = TxScriptEngine::from_transaction_input_with_script_units_limit(
            &populated,
            &input,
            input_index,
            &assembled.utxos[input_index],
            EngineCtx::new(&sig_cache)
                .with_reused(&reused_values)
                .with_covenants_ctx(&covenants),
            covenant_engine_flags(),
            ScriptUnits(u64::MAX),
        )
        .with_opcode_execution_log_buffer(&mut log);
        engine.execute()
    };
    let text = String::from_utf8(log).expect("the opcode log is text");
    let lines: Vec<&str> = text.lines().collect();
    InputRun {
        result,
        log_lines: lines.len(),
        last_line: lines.last().copied().unwrap_or_default().to_string(),
    }
}

/// The ordinal, inside the redeem script, of the last opcode the engine logged for a
/// pay-to-script-hash input: the log holds the pushes of the signature script, then the three
/// opcodes of the coin's own script, then the redeem script.
pub fn last_redeem_opcode_index(
    assembled: &Assembled,
    input_index: usize,
    run: &InputRun,
) -> Option<usize> {
    let pushes = assembled.inputs[input_index].signature_script_opcodes?;
    kcc20_family::sourcemap::last_redeem_opcode_index(run.log_lines, pushes)
}
