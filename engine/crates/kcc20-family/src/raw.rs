//! Hand-made pushes and the parts of a signature script.
//!
//! The codec only writes well-formed calls: it refuses a signature that is not 65 bytes long,
//! a public key that is not 32, a wrong number of arguments. To study what the contracts and
//! the engine do with a malformed call, the bytes have to be written by hand. This module
//! holds the small tools for that:
//!
//! - [`push`], [`push_number`], [`push_explicit`]: the three push forms the codec itself uses;
//! - [`push_as`]: a push with a chosen opcode form, minimal or not;
//! - [`split_pushes`]: a push-only script cut into its pushes;
//! - [`CallParts`]: a signature script as a list of parts that can be changed one by one.
//!
//! Signature script of a contract input (argent 9a9f4b1 crates/argent-runtime/src/resolve.rs:
//! 689-701; silverscript 3ed9733 silverscript-abi/src/lib.rs:483-516):
//!
//! ```text
//! <argument pushes: user arguments, then hidden ones>
//! <push of the 4-byte dispatch tag>
//! <push of the redeem script>
//! ```

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::PopulatedTransaction;
use kaspa_txscript::opcodes::codes::{OpPushData1, OpPushData2, OpPushData4};
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{EngineFlags, parse_script, pay_to_script_hash_signature_script_with_flags};

use crate::error::{Error, Result};

/// The engine flags the reference's authors run with: covenants enabled, everything else at
/// its default (argent 9a9f4b1 crates/argent-runtime/src/lib.rs:1952-1954). For the script
/// builder they lift the size limits of a push from 520 bytes to 1,000,000
/// (rusty-kaspa a41a333 crypto/txscript/src/lib.rs:137-143), which the 4031-byte KCC20 redeem
/// script needs.
pub fn covenant_flags() -> EngineFlags {
    EngineFlags {
        covenants_enabled: true,
        ..Default::default()
    }
}

/// The canonical (minimal) push of `data`: what the codec writes for `byte`, `bytes`,
/// `pubkey`, `sig` and array arguments and for the dispatch tag. An empty item is `00`, a
/// single byte 1..=16 is `51..60`, a single byte 0x81 is `4f`
/// (rusty-kaspa a41a333 crypto/txscript/src/script_builder.rs:154-170, 212-216).
pub fn push(data: &[u8]) -> Result<Vec<u8>> {
    Ok(ScriptBuilder::with_flags(covenant_flags())
        .add_data(data)?
        .drain())
}

/// The push of a number as the codec writes an `int` argument: `00` for zero, `51..60` for
/// 1..=16, `4f` for -1, otherwise the shortest sign-magnitude bytes
/// (rusty-kaspa a41a333 crypto/txscript/src/script_builder.rs:282-302).
pub fn push_number(value: i64) -> Result<Vec<u8>> {
    Ok(ScriptBuilder::with_flags(covenant_flags())
        .add_i64(value)?
        .drain())
}

/// The push of `data` with an explicit length opcode, never a small-integer opcode
/// (rusty-kaspa a41a333 crypto/txscript/src/script_builder.rs:226-233, 255-280).
pub fn push_explicit(data: &[u8]) -> Result<Vec<u8>> {
    Ok(ScriptBuilder::with_flags(covenant_flags())
        .add_data_with_push_opcode(data)?
        .drain())
}

/// The canonical push of a redeem script, exactly as the standard helper appends it to a
/// signature script (rusty-kaspa a41a333 crypto/txscript/src/standard.rs:63-70).
pub fn push_redeem(redeem_script: &[u8]) -> Result<Vec<u8>> {
    Ok(pay_to_script_hash_signature_script_with_flags(
        redeem_script.to_vec(),
        Vec::new(),
        covenant_flags(),
    )?)
}

/// The opcode form of a hand-made push.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushForm {
    /// One length byte 0x01..=0x4b, then the data (`OpData1..OpData75`).
    Direct,
    /// `4c`, one length byte, then the data (`OpPushData1`).
    PushData1,
    /// `4d`, two length bytes little-endian, then the data (`OpPushData2`).
    PushData2,
    /// `4e`, four length bytes little-endian, then the data (`OpPushData4`).
    PushData4,
}

/// A push of `data` in the given opcode form, whether or not that form is the shortest one.
/// Returns `None` when the length does not fit the form (`Direct` holds 1..=75 bytes).
/// What an engine makes of a push that is not the shortest one is for the engine to say.
pub fn push_as(form: PushForm, data: &[u8]) -> Option<Vec<u8>> {
    let mut script = Vec::with_capacity(data.len() + 5);
    match form {
        PushForm::Direct => {
            if data.is_empty() || data.len() > 75 {
                return None;
            }
            script.push(data.len() as u8);
        }
        PushForm::PushData1 => {
            script.push(OpPushData1);
            script.push(u8::try_from(data.len()).ok()?);
        }
        PushForm::PushData2 => {
            script.push(OpPushData2);
            script.extend(u16::try_from(data.len()).ok()?.to_le_bytes());
        }
        PushForm::PushData4 => {
            script.push(OpPushData4);
            script.extend(u32::try_from(data.len()).ok()?.to_le_bytes());
        }
    }
    script.extend_from_slice(data);
    Some(script)
}

/// Cuts a script into its opcodes, each returned with its data as the bytes found in the
/// script. Meant for push-only scripts (the output of the codec), but any well-formed script
/// is cut the same way. Fails when the script ends inside an opcode.
pub fn split_pushes(script: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut parts = Vec::new();
    let mut offset = 0;
    for opcode in parse_script::<PopulatedTransaction<'_>, SigHashReusedValuesUnsync>(script) {
        let opcode = opcode.map_err(|error| Error::Script(format!("at byte {offset}: {error}")))?;
        let len = opcode.serialize().len();
        let end = offset + len;
        let bytes = script.get(offset..end).ok_or_else(|| {
            Error::Script(format!(
                "the opcode at byte {offset} runs past the end of the script"
            ))
        })?;
        parts.push(bytes.to_vec());
        offset = end;
    }
    Ok(parts)
}

/// Number of opcodes in a script, or `None` when it cannot be parsed. For a signature script
/// this is the number of pushes; the engine's opcode log holds one line for each.
pub fn count_opcodes(script: &[u8]) -> Option<usize> {
    split_pushes(script).ok().map(|parts| parts.len())
}

/// A signature script of a contract input as separate parts.
///
/// Every part is a piece of script, normally one push with its opcode. Nothing checks the
/// parts: an element may hold two pushes, half a push, a non-push opcode, or nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallParts {
    /// The argument pushes, user arguments first, then the hidden ones.
    pub arguments: Vec<Vec<u8>>,
    /// The push of the dispatch tag (`04` and four bytes when honest).
    pub tag: Vec<u8>,
    /// The push of the redeem script (`4d`, two length bytes and the script when honest).
    pub redeem: Vec<u8>,
}

impl CallParts {
    /// The bytes in front of the redeem push: all argument parts, then the tag part.
    pub fn call_bytes(&self) -> Vec<u8> {
        let mut script = self.arguments.concat();
        script.extend_from_slice(&self.tag);
        script
    }

    /// The whole signature script: arguments, tag, redeem push.
    pub fn signature_script(&self) -> Vec<u8> {
        let mut script = self.call_bytes();
        script.extend_from_slice(&self.redeem);
        script
    }
}
