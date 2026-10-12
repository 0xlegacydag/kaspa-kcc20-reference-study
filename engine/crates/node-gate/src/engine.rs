//! One input on the node's script engine: the answer, the script units it used, and the
//! place where it stopped.
//!
//! The engine is `kaspa_txscript::TxScriptEngine` itself. This module builds it the way a
//! node does (rusty-kaspa a41a333
//! consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs:196-204)
//! and adds two things a node does not need: a run with an unlimited budget to measure an
//! input, and the position of the opcode that refused.
//!
//! # How the position is found
//!
//! With a log buffer attached the engine writes one line per opcode at the top of
//! `execute_opcode` (crypto/txscript/src/lib.rs:612-613, 639-654): before the opcode runs,
//! and also for opcodes inside a branch that is not executing. The number of lines is
//! therefore a position in the linear disassembly of the scripts, in the order the engine
//! runs them: signature script, script public key and, for a pay-to-script-hash coin, the
//! redeem script.
//!
//! Four checks in `execute_script` (lib.rs:656-669) refuse an opcode before that line is
//! written: a push that does not parse, a disabled opcode, an always illegal opcode, and
//! a non-push opcode in a signature script. The scripts are parsed here a second time with
//! the engine's own parser, and the same four checks are evaluated on the opcode that
//! follows the last logged one. If the error they predict is the engine's error, that
//! opcode is the one that refused; otherwise the last logged opcode is. Errors that belong
//! to no opcode (script size, the two final stack checks, the hash comparison of a
//! pay-to-script-hash coin, an unbalanced conditional) are told apart by the error itself
//! and by a run that skips the final stack check (`execute_and_return_stacks`).
//!
//! One case stays ambiguous by construction: `OpBlake3WithKey` given a key of the wrong
//! length reports `MalformedPush(32, n)` (crypto/txscript/src/opcodes/mod.rs:1671), the
//! same value a truncated 32-byte push right after it would produce. The position then
//! names the push.
//!
//! # Before Toccata
//!
//! With covenants disabled the engine meters no script units. Whatever limit it is handed,
//! it allows an input the number of signature operations the input commits to
//! (lib.rs:542-546). A run then has a signature operation limit and no script-unit limit,
//! and no compute budget can be read off it. The run without a limit hands the engine a
//! copy of the input that commits to the largest count; see `ScriptRunner::run_unlimited`.

use std::{
    borrow::Cow,
    io::{self, Write},
};

use kaspa_consensus_core::{
    hashing::sighash::SigHashReusedValuesUnsync,
    mass::{ComputeBudget, ScriptUnits, SigopCount},
    tx::{ComputeCommit, PopulatedTransaction, TransactionInput, VerifiableTransaction},
};
use kaspa_txscript::{
    EngineCtx, EngineFlags, MAX_SCRIPT_PUBLIC_KEY_VERSION, SigCacheKey, TxScriptEngine,
    caches::Cache,
    covenants::CovenantsContext,
    max_ops_per_script, max_script_element_size,
    opcodes::codes::{OpCheckMultiSig, OpCheckMultiSigECDSA, OpCheckMultiSigVerify},
    parse_script,
    script_class::ScriptClass,
};
use kaspa_txscript_errors::TxScriptError;
use serde::{Deserialize, Serialize};

/// Entries of the signature cache. The cache only remembers the result of a signature
/// verification for the same signature, key and message (crypto/txscript/src/lib.rs:112-117),
/// so its size has no effect on any answer; a node uses 10,000
/// (consensus/src/processes/transaction_validator/mod.rs:57).
pub(crate) const SIG_CACHE_SIZE: u64 = 256;

/// The prefix of every line the engine writes to its opcode log (lib.rs:639-654).
const LOG_LINE_PREFIX: &str = "Executing opcode: ";

/// Which of the scripts of an input was running.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptKind {
    /// The signature script carried by the input.
    SignatureScript,
    /// The script public key of the spent coin.
    ScriptPublicKey,
    /// The script a pay-to-script-hash coin commits to: the last item pushed by the
    /// signature script.
    RedeemScript,
}

/// One opcode, located.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpcodeStop {
    /// The script the opcode is in.
    pub script: ScriptKind,
    /// Zero-based ordinal of the opcode in the linear disassembly of that script.
    pub op_index: usize,
    /// Offset of the opcode's first byte in that script.
    pub byte_offset: usize,
    /// The opcode byte.
    pub opcode: u8,
    /// The engine's name of the opcode. `None` for a push that does not parse.
    pub opcode_name: Option<String>,
    /// `true` when the opcode was handed to the interpreter and failed there, or right
    /// after it on the stack size or on the charge for the bytes it pushed.
    ///
    /// `false` when the engine refused the opcode without interpreting it. Four refusals
    /// come before the opcode is logged (lib.rs:656-669): a malformed push, a disabled
    /// opcode, an always illegal opcode, an opcode that is not a push inside a signature
    /// script. Three come right after it is logged (lib.rs:617-629): more operations than
    /// a script may hold, a literal push above the element size, and, before Toccata, a
    /// push that could be shorter. The first two of those three are raised also for an
    /// opcode in a branch that is not taken.
    ///
    /// One case is decided by a count. A multi-signature opcode adds its number of keys
    /// to the operation count while it runs (lib.rs:807-809), so `TooManyOperations` at
    /// such an opcode can come from either side. It is reported as not executed when the
    /// opcodes of the script alone exceed the limit, and as executed otherwise. That is
    /// wrong only if an earlier multi-signature opcode of the same script already used up
    /// the count, which the log cannot show.
    pub executed: bool,
}

/// Where the engine stopped when it refused an input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopPoint {
    /// Before the first opcode: both scripts empty, a script above the size limit, or the
    /// up-front charge for a long script public key above the budget (lib.rs:703-731).
    BeforeAnyOpcode,
    /// At this opcode.
    Opcode(OpcodeStop),
    /// At the end of this script, inside an open conditional (lib.rs:681-683).
    EndOfScript(ScriptKind),
    /// After the script public key of a pay-to-script-hash coin: the redeem script does
    /// not hash to the coin (lib.rs:745-746).
    P2shHashMismatch,
    /// After the last opcode: the final stack is empty, false, or holds more than one
    /// item (lib.rs:773-787).
    FinalStack,
    /// The log and the scripts could not be matched. This is a defect of the method, not
    /// an answer of the engine; the text says what did not fit.
    Unknown(String),
}

/// What the opcode log of a traced run held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    /// Number of opcodes the engine logged, over all scripts of the input.
    pub opcodes_logged: usize,
    /// The last line of the log: the last logged opcode and both stacks as they were
    /// just before it ran.
    pub last_line: Option<String>,
}

/// The engine's answer for one input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptRun {
    /// Index of the input in the transaction.
    pub input_index: usize,
    /// The engine's result.
    pub result: Result<(), TxScriptError>,
    /// The script-unit limit the engine held the run to; `u64::MAX` for a run without a
    /// limit. `None` when covenants are disabled: the engine then ignores the limit it is
    /// handed (lib.rs:542-546).
    pub script_units_limit: Option<u64>,
    /// The number of signature operations the engine allowed the run when covenants are
    /// disabled: the count the input commits to, or 255 for a run without a limit. `None`
    /// when covenants are enabled, where a signature check is paid in script units.
    pub sig_op_limit: Option<u8>,
    /// Script units consumed. After a failure this is the amount consumed before the
    /// failing charge (crypto/txscript/src/runtime_resource_meter.rs:92-104). Zero when
    /// covenants are disabled: the engine then counts signature operations only.
    pub used_script_units: u64,
    /// Signature checks that were charged.
    pub used_sig_ops: u16,
    /// The spent coin has a script public key version above zero, so the engine accepted
    /// the input without running anything (lib.rs:695-698). Such a pass proves nothing.
    pub accepted_unknown_version: bool,
    /// Where the engine stopped. `None` when the input passed or when the position was
    /// not asked for.
    pub stop: Option<StopPoint>,
    /// The opcode log summary of the run that located the stop.
    pub trace: Option<Trace>,
}

impl ScriptRun {
    /// Whether the engine accepted the input.
    pub fn is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// The error, if the engine refused the input.
    pub fn error(&self) -> Option<&TxScriptError> {
        self.result.as_ref().err()
    }

    /// The smallest compute budget that covers the script units this run used
    /// (`ComputeBudget::checked_covering_script_units`, consensus/core/src/mass/units.rs:79-85).
    /// `None` when even the largest budget does not cover them, and `None` for a run with
    /// covenants disabled: no script unit was metered, so the run says nothing about a
    /// budget (the same input needs one after Toccata).
    pub fn covering_budget(&self) -> Option<ComputeBudget> {
        self.script_units_limit?;
        ComputeBudget::checked_covering_script_units(ScriptUnits(self.used_script_units))
    }
}

/// Runs the inputs of one transaction on the script engine.
///
/// One runner holds what a node holds for one `check_scripts` call: the covenant context,
/// the flags, a signature cache and the reused sighash values of this transaction. Do not
/// reuse it for another transaction; the reused values belong to the first one they see.
pub struct ScriptRunner<'a, T: VerifiableTransaction> {
    tx: &'a T,
    covenants: &'a CovenantsContext,
    flags: EngineFlags,
    sig_cache: Cache<SigCacheKey, bool>,
    reused: SigHashReusedValuesUnsync,
}

/// What a run may use.
#[derive(Clone, Copy)]
struct Allowance {
    /// The script-unit limit handed to the engine. It binds only with covenants enabled.
    script_units: ScriptUnits,
    /// With covenants disabled: replace the signature operation count the input commits
    /// to by the largest one an input can commit to.
    lift_sig_op_commitment: bool,
}

struct Executed {
    result: Result<(), TxScriptError>,
    used_script_units: u64,
    used_sig_ops: u16,
}

impl<'a, T: VerifiableTransaction> ScriptRunner<'a, T> {
    /// A runner for `tx` with the given covenant context and engine flags. For the
    /// node's answer use `GateParams::engine_flags` and `CovenantsContext::from_tx`.
    pub fn new(tx: &'a T, covenants: &'a CovenantsContext, flags: EngineFlags) -> Self {
        Self { tx, covenants, flags, sig_cache: Cache::new(SIG_CACHE_SIZE), reused: SigHashReusedValuesUnsync::new() }
    }

    /// Runs one input under `limit` script units. With `locate` a refused input is run
    /// again with the opcode log attached to find where it stopped.
    ///
    /// With covenants disabled the engine ignores `limit` and allows the input the
    /// signature operations it commits to (lib.rs:542-546); the run records that count as
    /// its limit.
    ///
    /// Panics when `input_index` is not an input of the transaction, as the engine does
    /// (lib.rs:551).
    pub fn run(&self, input_index: usize, limit: ScriptUnits, locate: bool) -> ScriptRun {
        self.run_with(input_index, Allowance { script_units: limit, lift_sig_op_commitment: false }, locate)
    }

    /// Runs one input under the limit its own compute commitment allows, as a node does
    /// (`ComputeCommit::allowed_script_units`, consensus/core/src/tx.rs:100-103).
    pub fn run_committed(&self, input_index: usize, locate: bool) -> ScriptRun {
        let (input, _) = self.tx.populated_input(input_index);
        self.run(input_index, input.compute_commit.allowed_script_units(), locate)
    }

    /// Runs one input with no limit, to measure it.
    ///
    /// With covenants enabled the engine gets a script-unit limit of `u64::MAX`, and
    /// `ScriptRun::covering_budget` of the result is the smallest budget of the input.
    ///
    /// With covenants disabled there is no script-unit meter. The engine then gets a copy
    /// of the input that commits to 255 signature operations, the largest count an input
    /// can commit to, so that the input's own commitment does not stop the run;
    /// `ScriptRun::used_sig_ops` of the result is the smallest count the input must commit
    /// to, and there is no budget. The copy changes nothing but the meter: the engine
    /// reads the signature script and the sequence from the input it is handed and takes
    /// every signature hash from the transaction (lib.rs:694-706, 887, 916;
    /// crypto/txscript/src/opcodes/mod.rs:1016, 1068).
    pub fn run_unlimited(&self, input_index: usize, locate: bool) -> ScriptRun {
        self.run_with(input_index, Allowance { script_units: ScriptUnits(u64::MAX), lift_sig_op_commitment: true }, locate)
    }

    /// Every input under its committed limit, in input order.
    pub fn run_all_committed(&self, locate: bool) -> Vec<ScriptRun> {
        (0..self.tx.inputs().len()).map(|i| self.run_committed(i, locate)).collect()
    }

    /// Every input with no limit, in input order. See [`ScriptRunner::run_unlimited`].
    pub fn run_all_unlimited(&self, locate: bool) -> Vec<ScriptRun> {
        (0..self.tx.inputs().len()).map(|i| self.run_unlimited(i, locate)).collect()
    }

    fn run_with(&self, input_index: usize, allowance: Allowance, locate: bool) -> ScriptRun {
        let (input, entry) = self.tx.populated_input(input_index);
        let accepted_unknown_version = entry.script_public_key.version() > MAX_SCRIPT_PUBLIC_KEY_VERSION;
        let metered_in_script_units = self.flags.covenants_enabled;
        // The same expression as the engine's (lib.rs:545), on the input it is handed.
        let sig_op_limit =
            (!metered_in_script_units).then(|| self.engine_input(input, allowance).compute_commit.sig_op_count().unwrap_or(0));
        let executed = self.execute_once(input_index, allowance, None);
        let (stop, trace) = match &executed.result {
            Err(error) if locate => {
                let (stop, trace) = self.locate(input_index, allowance, error);
                (Some(stop), Some(trace))
            }
            _ => (None, None),
        };
        ScriptRun {
            input_index,
            result: executed.result,
            script_units_limit: metered_in_script_units.then_some(allowance.script_units.0),
            sig_op_limit,
            used_script_units: executed.used_script_units,
            used_sig_ops: executed.used_sig_ops,
            accepted_unknown_version,
            stop,
            trace,
        }
    }

    /// The input as the engine is to see it: the input itself, or, for a run without a
    /// limit with covenants disabled, a copy that commits to the largest signature
    /// operation count.
    fn engine_input<'i>(&self, input: &'i TransactionInput, allowance: Allowance) -> Cow<'i, TransactionInput> {
        if allowance.lift_sig_op_commitment && !self.flags.covenants_enabled {
            let mut lifted = input.clone();
            lifted.compute_commit = ComputeCommit::SigopCount(SigopCount(u8::MAX));
            Cow::Owned(lifted)
        } else {
            Cow::Borrowed(input)
        }
    }

    fn execute_once(&self, input_index: usize, allowance: Allowance, log: Option<&mut OpcodeLog>) -> Executed {
        let (input, entry) = self.tx.populated_input(input_index);
        let input = self.engine_input(input, allowance);
        let ctx = EngineCtx::new(&self.sig_cache).with_reused(&self.reused).with_covenants_ctx(self.covenants);
        let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
            self.tx,
            &input,
            input_index,
            entry,
            ctx,
            self.flags,
            allowance.script_units,
        );
        if let Some(log) = log {
            vm = vm.with_opcode_execution_log_buffer(log);
        }
        let result = vm.execute();
        Executed { result, used_script_units: vm.used_script_units().0, used_sig_ops: vm.used_sig_ops() }
    }

    /// Whether the scripts themselves run to their end, leaving only the final stack
    /// check to fail.
    fn scripts_complete(&self, input_index: usize, allowance: Allowance) -> bool {
        let (input, entry) = self.tx.populated_input(input_index);
        let input = self.engine_input(input, allowance);
        let ctx = EngineCtx::new(&self.sig_cache).with_reused(&self.reused).with_covenants_ctx(self.covenants);
        let vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
            self.tx,
            &input,
            input_index,
            entry,
            ctx,
            self.flags,
            allowance.script_units,
        );
        vm.execute_and_return_stacks().is_ok()
    }

    fn locate(&self, input_index: usize, allowance: Allowance, error: &TxScriptError) -> (StopPoint, Trace) {
        let (input, entry) = self.tx.populated_input(input_index);
        let signature_script = input.signature_script.as_slice();
        let script_public_key = entry.script_public_key.script();
        let is_p2sh = ScriptClass::is_pay_to_script_hash(script_public_key);

        let parsed_signature_script = parse(signature_script, self.flags, true);
        let parsed_script_public_key = parse(script_public_key, self.flags, false);

        // For a pay-to-script-hash coin the first line of the script public key shows the
        // stack the signature script left; its top item is the redeem script.
        let first_lock_line = if signature_script.is_empty() { 0 } else { parsed_signature_script.ops.len() };
        let mut log = OpcodeLog::new(is_p2sh.then_some(first_lock_line));
        let traced = self.execute_once(input_index, allowance, Some(&mut log));
        let trace = Trace { opcodes_logged: log.names.len(), last_line: log.last_line() };
        if traced.result.as_ref().err() != Some(error) {
            let reason = format!("the traced run answered {:?} instead of {error:?}", traced.result);
            return (StopPoint::Unknown(reason), trace);
        }

        let final_check = match error {
            TxScriptError::CleanStack(_) => true,
            TxScriptError::EmptyStack | TxScriptError::EvalFalse => self.scripts_complete(input_index, allowance),
            _ => false,
        };
        if final_check {
            return (StopPoint::FinalStack, trace);
        }

        let parsed_redeem_script =
            log.kept_line.as_deref().and_then(top_of_data_stack).map(|redeem_script| parse(&redeem_script, self.flags, false));

        // The scripts in the order the engine runs them. Empty scripts are skipped by the
        // engine (lib.rs:736), and so here.
        let mut segments: Vec<(ScriptKind, &ParsedScript)> = Vec::with_capacity(3);
        if !signature_script.is_empty() {
            segments.push((ScriptKind::SignatureScript, &parsed_signature_script));
        }
        if !script_public_key.is_empty() {
            segments.push((ScriptKind::ScriptPublicKey, &parsed_script_public_key));
        }
        if let Some(parsed) = parsed_redeem_script.as_ref() {
            segments.push((ScriptKind::RedeemScript, parsed));
        }

        (locate_in_segments(&segments, &log.names, error, is_p2sh, self.flags.covenants_enabled), trace)
    }
}

/// One opcode of a parsed script.
struct ParsedOp {
    value: u8,
    offset: usize,
    name: String,
    /// The opcode counts as an operation of its script: every opcode that is not a push
    /// (lib.rs:617-618).
    counts_as_operation: bool,
    /// The error `execute_script` raises for this opcode before it logs it, if any.
    refused_before_execution: Option<TxScriptError>,
    /// The error `execute_opcode` raises for this opcode after it has logged it and
    /// before it interprets it, if any: a literal push above the element size
    /// (lib.rs:622-624) or, with covenants disabled, a push that could be shorter
    /// (lib.rs:627-629; raised only in a branch that is executing).
    refused_before_interpretation: Option<TxScriptError>,
}

/// A script split into opcodes by the engine's parser.
struct ParsedScript {
    ops: Vec<ParsedOp>,
    /// Offset, opcode byte and error of the first push that does not parse.
    parse_error: Option<(usize, u8, TxScriptError)>,
}

/// Parses `script` with the engine's parser and evaluates, per opcode, the checks the
/// engine makes before it logs the opcode (lib.rs:656-669) and between logging and
/// interpreting it (lib.rs:622-629), with upstream's conditions and errors (rusty-kaspa
/// a41a333 crypto/txscript/src/lib.rs; ISC License, Copyright (c) 2022-2024 Kaspa
/// developers).
fn parse(script: &[u8], flags: EngineFlags, verify_only_push: bool) -> ParsedScript {
    let mut ops = Vec::new();
    let mut offset = 0;
    let mut parse_error = None;
    let max_element_size = max_script_element_size(flags.covenants_enabled);
    for item in parse_script::<PopulatedTransaction<'static>, SigHashReusedValuesUnsync>(script) {
        match item {
            Ok(opcode) => {
                let refused_before_execution = if opcode.is_disabled(flags) {
                    Some(TxScriptError::OpcodeDisabled(format!("{opcode:?}")))
                } else if opcode.always_illegal() {
                    Some(TxScriptError::OpcodeReserved(format!("{opcode:?}")))
                } else if verify_only_push && !opcode.is_push_opcode() {
                    Some(TxScriptError::SignatureScriptNotPushOnly)
                } else {
                    None
                };
                let refused_before_interpretation = if opcode.is_push_opcode() && opcode.len() > max_element_size {
                    Some(TxScriptError::ElementTooBig(opcode.len(), max_element_size))
                } else if !flags.covenants_enabled && opcode.value() > 0 && opcode.value() <= 0x4e {
                    opcode.check_minimal_data_push().err()
                } else {
                    None
                };
                let size = opcode.serialize().len();
                ops.push(ParsedOp {
                    value: opcode.value(),
                    offset,
                    name: opcode_name(&opcode.to_string()),
                    counts_as_operation: !opcode.is_push_opcode(),
                    refused_before_execution,
                    refused_before_interpretation,
                });
                offset += size;
            }
            Err(error) => {
                parse_error = Some((offset, script[offset], error));
                break;
            }
        }
    }
    ParsedScript { ops, parse_error }
}

/// The name part of an opcode's display form, which is `Name` or `Name 0x<data>`
/// (crypto/txscript/src/opcodes/macros.rs:68-77).
fn opcode_name(display: &str) -> String {
    display.split([' ', ',']).next().unwrap_or_default().to_string()
}

/// The opcode at a position of the run order, or the reason there is none.
enum Next<'s> {
    Op(ScriptKind, usize, &'s ParsedOp),
    ParseError(ScriptKind, usize, usize, u8, &'s TxScriptError),
    None,
}

/// Whether the engine handed the logged opcode `op_index` of `parsed` to the interpreter
/// before it raised `error` at it. See `OpcodeStop::executed`.
fn was_interpreted(parsed: &ParsedScript, op_index: usize, error: &TxScriptError, covenants_enabled: bool) -> bool {
    let op = &parsed.ops[op_index];
    if op.refused_before_interpretation.as_ref() == Some(error) {
        return false;
    }
    if matches!(error, TxScriptError::TooManyOperations(_)) {
        // Only a multi-signature opcode raises this error from inside the interpreter
        // (lib.rs:807-809). The operation count is per script (lib.rs:687) and every
        // logged opcode that is not a push adds one to it (lib.rs:617-618).
        let multi_signature = [OpCheckMultiSig, OpCheckMultiSigVerify, OpCheckMultiSigECDSA].contains(&op.value);
        let operations = parsed.ops[..=op_index].iter().filter(|op| op.counts_as_operation).count();
        return multi_signature && operations <= max_ops_per_script(covenants_enabled) as usize;
    }
    true
}

/// Maps the number of logged opcodes and the error to a stop point. `segments` are the
/// parsed scripts in run order; `logged` holds the opcode name of every log line.
fn locate_in_segments(
    segments: &[(ScriptKind, &ParsedScript)],
    logged: &[String],
    error: &TxScriptError,
    is_p2sh: bool,
    covenants_enabled: bool,
) -> StopPoint {
    // Walk the log along the scripts and check that the names agree.
    let mut last: Option<(ScriptKind, &ParsedScript, usize)> = None;
    let mut segment = 0;
    let mut op_index = 0;
    for (line, name) in logged.iter().enumerate() {
        while segment < segments.len() && op_index == segments[segment].1.ops.len() {
            if segments[segment].1.parse_error.is_some() {
                return StopPoint::Unknown(format!("log line {line} follows a push that does not parse"));
            }
            segment += 1;
            op_index = 0;
        }
        let Some((kind, parsed)) = segments.get(segment) else {
            return StopPoint::Unknown(format!("the log has {} lines, more than the scripts have opcodes", logged.len()));
        };
        let op = &parsed.ops[op_index];
        if &op.name != name {
            return StopPoint::Unknown(format!("log line {line} names {name}, the script has {} there", op.name));
        }
        last = Some((*kind, *parsed, op_index));
        op_index += 1;
    }

    // The opcode the engine meets next, if it goes on.
    let next = loop {
        let Some((kind, parsed)) = segments.get(segment) else {
            break Next::None;
        };
        if let Some(op) = parsed.ops.get(op_index) {
            break Next::Op(*kind, op_index, op);
        }
        if let Some((offset, byte, parse_error)) = parsed.parse_error.as_ref() {
            break Next::ParseError(*kind, op_index, *offset, *byte, parse_error);
        }
        segment += 1;
        op_index = 0;
    };

    match next {
        Next::Op(script, op_index, op) if op.refused_before_execution.as_ref() == Some(error) => {
            return StopPoint::Opcode(OpcodeStop {
                script,
                op_index,
                byte_offset: op.offset,
                opcode: op.value,
                opcode_name: Some(op.name.clone()),
                executed: false,
            });
        }
        Next::ParseError(script, op_index, byte_offset, opcode, parse_error) if parse_error == error => {
            return StopPoint::Opcode(OpcodeStop { script, op_index, byte_offset, opcode, opcode_name: None, executed: false });
        }
        _ => {}
    }

    let Some((script, parsed, op_index)) = last else {
        return StopPoint::BeforeAnyOpcode;
    };
    let op = &parsed.ops[op_index];
    match error {
        TxScriptError::ErrUnbalancedConditional => StopPoint::EndOfScript(script),
        // The final stack check was ruled out by the caller, and no opcode raises this
        // error (lib.rs:726-728, 773-787): what is left is the hash comparison.
        TxScriptError::EvalFalse if is_p2sh && script == ScriptKind::ScriptPublicKey => StopPoint::P2shHashMismatch,
        TxScriptError::EvalFalse => StopPoint::Unknown("a false result that is neither final nor the hash comparison".to_string()),
        _ => StopPoint::Opcode(OpcodeStop {
            script,
            op_index,
            byte_offset: op.offset,
            opcode: op.value,
            opcode_name: Some(op.name.clone()),
            executed: was_interpreted(parsed, op_index, error, covenants_enabled),
        }),
    }
}

/// Receives the engine's opcode log line by line and keeps only what the position needs:
/// the opcode name of every line, the last line, and one chosen line in full.
struct OpcodeLog {
    current: Vec<u8>,
    names: Vec<String>,
    last: Vec<u8>,
    keep_line: Option<usize>,
    kept_line: Option<String>,
}

impl OpcodeLog {
    fn new(keep_line: Option<usize>) -> Self {
        Self { current: Vec::new(), names: Vec::new(), last: Vec::new(), keep_line, kept_line: None }
    }

    fn finish_line(&mut self) {
        let line = String::from_utf8_lossy(&self.current);
        self.names.push(opcode_name(line.strip_prefix(LOG_LINE_PREFIX).unwrap_or(&line)));
        if self.keep_line == Some(self.names.len() - 1) {
            self.kept_line = Some(line.into_owned());
        }
        std::mem::swap(&mut self.last, &mut self.current);
        self.current.clear();
    }

    fn last_line(&self) -> Option<String> {
        (!self.names.is_empty()).then(|| String::from_utf8_lossy(&self.last).into_owned())
    }
}

impl Write for OpcodeLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for chunk in buf.split_inclusive(|byte| *byte == b'\n') {
            match chunk.strip_suffix(b"\n") {
                Some(line_end) => {
                    self.current.extend_from_slice(line_end);
                    self.finish_line();
                }
                None => self.current.extend_from_slice(chunk),
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The top item of the data stack as printed in a log line, whose tail is
/// `dstack: ["0x..", "0x.."]` (lib.rs:639-654).
fn top_of_data_stack(line: &str) -> Option<Vec<u8>> {
    let stack = line.rsplit_once("dstack: [")?.1.strip_suffix(']')?;
    let top = stack.rsplit(", ").next()?;
    let hex = top.strip_prefix("\"0x")?.strip_suffix('"')?;
    if hex.is_empty() {
        return Some(Vec::new());
    }
    let mut bytes = vec![0u8; hex.len() / 2];
    faster_hex::hex_decode(hex.as_bytes(), &mut bytes).ok()?;
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_lines_are_split_and_named() {
        let mut log = OpcodeLog::new(Some(1));
        log.write_all(b"Executing opcode: OpTrue, astack: [], dst").unwrap();
        log.write_all(b"ack: []\nExecuting opcode: OpData2 0xaabb, astack: [], dstack: [\"0x01\"]\n").unwrap();
        assert_eq!(log.names, vec!["OpTrue".to_string(), "OpData2".to_string()]);
        assert_eq!(log.kept_line.as_deref(), Some("Executing opcode: OpData2 0xaabb, astack: [], dstack: [\"0x01\"]"));
        assert_eq!(log.last_line(), log.kept_line);
    }

    #[test]
    fn top_item_is_read_from_a_log_line() {
        let line = |stack: &str| format!("Executing opcode: OpBlake2b, astack: [\"0x07\"], dstack: [{stack}]");
        assert_eq!(top_of_data_stack(&line("")), None);
        assert_eq!(top_of_data_stack(&line("\"0x\"")), Some(vec![]));
        assert_eq!(top_of_data_stack(&line("\"0x51\"")), Some(vec![0x51]));
        assert_eq!(top_of_data_stack(&line("\"0x51\", \"0x\", \"0xaabbcc\"")), Some(vec![0xaa, 0xbb, 0xcc]));
    }

    #[test]
    fn parser_gives_offsets_and_early_refusals() {
        let covenants = EngineFlags { covenants_enabled: true, ..Default::default() };
        // OpTrue, OpData2 aa bb, OpPushData1 01 cc, OpLeft (disabled), OpVerIf (illegal), OpDup, truncated OpData3.
        let script = [0x51, 0x02, 0xaa, 0xbb, 0x4c, 0x01, 0xcc, 0x80, 0x65, 0x76, 0x03, 0x01];
        let parsed = parse(&script, covenants, true);
        let offsets: Vec<usize> = parsed.ops.iter().map(|op| op.offset).collect();
        assert_eq!(offsets, vec![0, 1, 4, 7, 8, 9]);
        let names: Vec<&str> = parsed.ops.iter().map(|op| op.name.as_str()).collect();
        assert_eq!(names, vec!["OpTrue", "OpData2", "OpPushData1", "OpLeft", "OpVerIf", "OpDup"]);
        assert_eq!(parsed.ops[0].refused_before_execution, None);
        assert!(matches!(parsed.ops[3].refused_before_execution, Some(TxScriptError::OpcodeDisabled(_))));
        assert!(matches!(parsed.ops[4].refused_before_execution, Some(TxScriptError::OpcodeReserved(_))));
        assert_eq!(parsed.ops[5].refused_before_execution, Some(TxScriptError::SignatureScriptNotPushOnly));
        assert_eq!(parsed.parse_error, Some((10, 0x03, TxScriptError::MalformedPush(3, 1))));
    }
}
