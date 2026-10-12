//! Why the script engine refused an input: `TxScriptError` sorted into six classes.
//!
//! The engine has one error type for very different events: a rule of the script that
//! said no, an opcode that could not compute on the data it was given, a signature that
//! is not even well formed, a resource limit, a script that is not a legal script, and
//! conditions that only a broken test setup produces. A check that expects "the contract
//! refuses" must not be satisfied by any of the others.
//!
//! Variants are listed from rusty-kaspa a41a333 crypto/txscript/errors/src/lib.rs:4-102.
//! Six of them fall into two classes depending on where they are raised; `classify`
//! names both, `classify_at` decides with the stop position. A seventh, `InvalidState`,
//! is split by its text.

use kaspa_txscript_errors::{CovenantsError, TxScriptError};
use serde::{Deserialize, Serialize};

use crate::engine::{ScriptKind, StopPoint};

/// `OpChainblockSeqCommit`. Without a sequencing commitment accessor, which the gate does
/// not provide, it answers `InvalidOpcode` (crypto/txscript/src/opcodes/mod.rs:1581-1585).
const OP_CHAINBLOCK_SEQ_COMMIT: u8 = 0xd4;

/// The last opcode that pushes a literal (`NO_COST_OPCODE`, crypto/txscript/src/lib.rs:93).
const LAST_PUSH_OPCODE: u8 = 0x60;

/// The text of the `InvalidState` raised by `OpElse` or `OpEndIf` without an open
/// conditional (opcodes/mod.rs:494, 500).
const CONDITION_STACK_EMPTY: &str = "condition stack empty";

/// The class of a script engine refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// A rule written in the script said no: a failed verify, a false or unclean final
    /// stack, an executed `OpReturn`, a lock time opcode, a failed multisig.
    ContractRefused,
    /// An opcode could not work on the data it was given: too few stack items, a number
    /// out of range, an index beyond the transaction, a slice beyond its data. No rule
    /// of the script is involved; the refusal is still deterministic and final.
    EngineRefusedData,
    /// A signature, key or sighash type that is not well formed. A well formed but wrong
    /// signature is not here: it makes the check push false and ends in `ContractRefused`.
    MalformedSignatureMaterial,
    /// A budget or size limit: script units, signature operations, stack depth, number
    /// of operations, script or element size.
    ResourceLimit,
    /// The bytes are not a legal script, or the wrapper around the script refused: a
    /// non-push opcode in a signature script, a truncated push, a disabled or unknown
    /// opcode, an unbalanced conditional, a redeem script that does not hash to the coin.
    ScriptFormat,
    /// Something a node would not answer for this transaction at all: the engine was
    /// used outside a transaction input, or a feature that needs the node's chain state
    /// was asked for. Read it as a defect of the test, not as a verdict.
    Harness,
}

/// A class, and the second class the same error variant can mean elsewhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Classification {
    /// The class when nothing is known about where the error was raised.
    pub class: ErrorClass,
    /// The other class this variant can belong to, if it has one.
    pub other: Option<ErrorClass>,
}

impl Classification {
    const fn one(class: ErrorClass) -> Self {
        Self { class, other: None }
    }

    const fn two(class: ErrorClass, other: ErrorClass) -> Self {
        Self { class, other: Some(other) }
    }
}

/// Sorts an error by its variant alone.
///
/// `InvalidState` is split by its text alone: "condition stack empty" (`OpElse` or
/// `OpEndIf` without `OpIf`) is a format error, every other text a data error. The
/// variants whose class depends on the place:
///
/// | Variant | First class | Second class |
/// |---|---|---|
/// | `EvalFalse` | contract: false final stack | format: redeem script does not hash to the coin, or both scripts empty |
/// | `EmptyStack` | data: `OpCat` or `OpFromAltStack` on too few items | contract: empty final stack |
/// | `ElementTooBig` | limit: a literal push above the element size | data: a computed item above it |
/// | `InvalidStackOperation` | data: too few arguments | format: empty signature script on a pay-to-script-hash coin |
/// | `MalformedPush` | format: truncated push | data: `OpBlake3WithKey` key of the wrong length |
/// | `InvalidOpcode` | format: unknown opcode, covenant opcode before activation | harness: `OpChainblockSeqCommit` without chain state |
pub fn classify(error: &TxScriptError) -> Classification {
    use ErrorClass::*;
    use TxScriptError as E;
    match error {
        E::VerifyError | E::EarlyReturn | E::CleanStack(_) | E::UnsatisfiedLockTime(_) | E::NullFail => {
            Classification::one(ContractRefused)
        }
        E::EvalFalse => Classification::two(ContractRefused, ScriptFormat),

        E::EmptyStack => Classification::two(EngineRefusedData, ContractRefused),
        E::InvalidStackOperation(_, _) => Classification::two(EngineRefusedData, ScriptFormat),
        E::InvalidState(text) if text == CONDITION_STACK_EMPTY => Classification::one(ScriptFormat),
        E::InvalidState(_) => Classification::one(EngineRefusedData),
        E::NumberTooBig(_)
        | E::Serialization(_)
        | E::NotMinimalData(_)
        | E::InvalidIndex(_)
        | E::InvalidRange { .. }
        | E::OutOfBoundsSubstring(_, _, _)
        | E::InvalidInputIndex(_, _)
        | E::InvalidOutputIndex(_, _)
        | E::InvalidLengthOfBlockHash(_) => Classification::one(EngineRefusedData),
        E::CovenantsError(
            CovenantsError::InvalidCovInIndex(_, _)
            | CovenantsError::InvalidCovOutIndex(_, _)
            | CovenantsError::InvalidAuthCovOutIndex(_, _, _),
        ) => Classification::one(EngineRefusedData),

        E::InvalidSigHashType(_)
        | E::InvalidSignature(_)
        | E::InvalidPubkey(_)
        | E::PubKeyFormat
        | E::InvalidSignatureCount(_)
        | E::InvalidPubKeyCount(_)
        | E::SigcacheSignatureInvalid => Classification::one(MalformedSignatureMaterial),

        E::ExceededCommittedScriptUnits { .. }
        | E::ExceededSigOpLimit(_)
        | E::StackSizeExceeded(_, _)
        | E::TooManyOperations(_)
        | E::ScriptSize(_, _) => Classification::one(ResourceLimit),
        E::ElementTooBig(_, _) => Classification::two(ResourceLimit, EngineRefusedData),

        E::SignatureScriptNotPushOnly
        | E::MalformedPushSize(_)
        | E::OpcodeDisabled(_)
        | E::OpcodeReserved(_)
        | E::ErrUnbalancedConditional
        | E::NoScripts => Classification::one(ScriptFormat),
        E::MalformedPush(_, _) => Classification::two(ScriptFormat, EngineRefusedData),
        E::InvalidOpcode(_) => Classification::two(ScriptFormat, Harness),

        E::NotATransactionInput
        | E::InvalidSource(_)
        | E::BlockNotSelected(_)
        | E::BlockAlreadyPruned(_)
        | E::BlockIsTooDeep(_)
        | E::ZkIntegrity(_)
        | E::InvalidCovInputIndex(_) => Classification::one(Harness),
        // Raised by `CovenantsContext::from_tx` before any script runs.
        E::CovenantsError(CovenantsError::WrongGenesisCovenantId(_, _) | CovenantsError::AuthInputOutOfBounds(_, _)) => {
            Classification::one(Harness)
        }
    }
}

/// Sorts an error using the place where the engine stopped. `spent_is_p2sh` says whether
/// the coin has the pay-to-script-hash form. Without a stop point, or with one the
/// position method could not determine, the answer is `classify(error).class`.
pub fn classify_at(error: &TxScriptError, stop: Option<&StopPoint>, spent_is_p2sh: bool) -> ErrorClass {
    use ErrorClass::*;
    use TxScriptError as E;
    let default = classify(error).class;
    let Some(stop) = stop else {
        return default;
    };
    match (error, stop) {
        (_, StopPoint::Unknown(_)) => default,

        (E::EvalFalse, StopPoint::FinalStack) => ContractRefused,
        (E::EvalFalse, StopPoint::P2shHashMismatch | StopPoint::BeforeAnyOpcode) => ScriptFormat,

        (E::EmptyStack, StopPoint::FinalStack) => ContractRefused,
        (E::EmptyStack, _) => EngineRefusedData,

        (E::ElementTooBig(_, _), StopPoint::Opcode(at)) if at.opcode <= LAST_PUSH_OPCODE => ResourceLimit,
        (E::ElementTooBig(_, _), StopPoint::Opcode(_)) => EngineRefusedData,

        (E::InvalidStackOperation(_, _), StopPoint::Opcode(at)) if spent_is_p2sh && at.script == ScriptKind::ScriptPublicKey => {
            ScriptFormat
        }
        (E::InvalidStackOperation(_, _), _) => EngineRefusedData,

        (E::InvalidState(text), _) if text == CONDITION_STACK_EMPTY => ScriptFormat,
        (E::InvalidState(_), _) => EngineRefusedData,

        (E::MalformedPush(_, _), StopPoint::Opcode(at)) if at.executed => EngineRefusedData,
        (E::MalformedPush(_, _), _) => ScriptFormat,

        (E::InvalidOpcode(_), StopPoint::Opcode(at)) if at.opcode == OP_CHAINBLOCK_SEQ_COMMIT => Harness,
        (E::InvalidOpcode(_), _) => ScriptFormat,

        _ => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::OpcodeStop;

    fn at(script: ScriptKind, opcode: u8, executed: bool) -> StopPoint {
        StopPoint::Opcode(OpcodeStop { script, op_index: 0, byte_offset: 0, opcode, opcode_name: None, executed })
    }

    #[test]
    fn single_class_variants() {
        use ErrorClass::*;
        let cases = [
            (TxScriptError::VerifyError, ContractRefused),
            (TxScriptError::EarlyReturn, ContractRefused),
            (TxScriptError::CleanStack(1), ContractRefused),
            (TxScriptError::NumberTooBig(String::new()), EngineRefusedData),
            (TxScriptError::InvalidInputIndex(3, 2), EngineRefusedData),
            (TxScriptError::OutOfBoundsSubstring(0, 9, 4), EngineRefusedData),
            (TxScriptError::InvalidSigHashType(0), MalformedSignatureMaterial),
            (TxScriptError::PubKeyFormat, MalformedSignatureMaterial),
            (TxScriptError::ExceededCommittedScriptUnits { used: 2, limit: 1 }, ResourceLimit),
            (TxScriptError::StackSizeExceeded(245, 244), ResourceLimit),
            (TxScriptError::SignatureScriptNotPushOnly, ScriptFormat),
            (TxScriptError::ErrUnbalancedConditional, ScriptFormat),
            (TxScriptError::InvalidState(CONDITION_STACK_EMPTY.to_string()), ScriptFormat),
            (TxScriptError::NotATransactionInput, Harness),
        ];
        for (error, class) in cases {
            assert_eq!(classify(&error), Classification { class, other: None }, "{error:?}");
        }
    }

    #[test]
    fn two_class_variants_are_named_and_resolved_by_position() {
        use ErrorClass::*;
        assert_eq!(classify(&TxScriptError::EvalFalse).other, Some(ScriptFormat));
        assert_eq!(classify_at(&TxScriptError::EvalFalse, Some(&StopPoint::FinalStack), true), ContractRefused);
        assert_eq!(classify_at(&TxScriptError::EvalFalse, Some(&StopPoint::P2shHashMismatch), true), ScriptFormat);
        assert_eq!(classify_at(&TxScriptError::EvalFalse, Some(&StopPoint::BeforeAnyOpcode), false), ScriptFormat);

        assert_eq!(classify(&TxScriptError::EmptyStack).other, Some(ContractRefused));
        assert_eq!(classify_at(&TxScriptError::EmptyStack, Some(&StopPoint::FinalStack), true), ContractRefused);
        assert_eq!(classify_at(&TxScriptError::EmptyStack, Some(&at(ScriptKind::RedeemScript, 0x7e, true)), true), EngineRefusedData);

        let too_big = TxScriptError::ElementTooBig(2_000_000, 1_000_000);
        assert_eq!(classify(&too_big).other, Some(EngineRefusedData));
        assert_eq!(classify_at(&too_big, Some(&at(ScriptKind::RedeemScript, 0x4e, true)), true), ResourceLimit);
        assert_eq!(classify_at(&too_big, Some(&at(ScriptKind::RedeemScript, 0x7e, true)), true), EngineRefusedData);

        let too_few = TxScriptError::InvalidStackOperation(1, 0);
        assert_eq!(classify(&too_few).other, Some(ScriptFormat));
        assert_eq!(classify_at(&too_few, Some(&at(ScriptKind::ScriptPublicKey, 0xaa, true)), true), ScriptFormat);
        assert_eq!(classify_at(&too_few, Some(&at(ScriptKind::ScriptPublicKey, 0xac, true)), false), EngineRefusedData);
        assert_eq!(classify_at(&too_few, Some(&at(ScriptKind::RedeemScript, 0x76, true)), true), EngineRefusedData);

        let malformed = TxScriptError::MalformedPush(32, 5);
        assert_eq!(classify(&malformed).other, Some(EngineRefusedData));
        assert_eq!(classify_at(&malformed, Some(&at(ScriptKind::RedeemScript, 0x20, false)), true), ScriptFormat);
        assert_eq!(classify_at(&malformed, Some(&at(ScriptKind::RedeemScript, 0xda, true)), true), EngineRefusedData);

        let invalid = TxScriptError::InvalidOpcode(String::new());
        assert_eq!(classify(&invalid).other, Some(Harness));
        assert_eq!(classify_at(&invalid, Some(&at(ScriptKind::RedeemScript, OP_CHAINBLOCK_SEQ_COMMIT, true)), true), Harness);
        assert_eq!(classify_at(&invalid, Some(&at(ScriptKind::RedeemScript, 0xfa, true)), true), ScriptFormat);

        let state = TxScriptError::InvalidState("pick at an invalid location".to_string());
        assert_eq!(classify(&state), Classification { class: EngineRefusedData, other: None });
        assert_eq!(classify_at(&state, Some(&at(ScriptKind::RedeemScript, 0x79, true)), true), EngineRefusedData);
    }

    #[test]
    fn without_a_position_the_first_class_is_used() {
        assert_eq!(classify_at(&TxScriptError::EvalFalse, None, true), ErrorClass::ContractRefused);
        let unknown = StopPoint::Unknown("x".to_string());
        assert_eq!(classify_at(&TxScriptError::EmptyStack, Some(&unknown), true), ErrorClass::EngineRefusedData);
    }
}
