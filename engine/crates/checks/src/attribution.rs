//! What refused an input: the rule of a contract, or a check of the engine itself.
//!
//! Almost every refusal of the three contracts is the same engine error, a failed verify.
//! To say which rule refused, the opcode at which the engine stopped is looked up twice:
//!
//! - in the source map of `kcc20-family`, which gives the entry, the part of the script
//!   and the statement of the generated SilverScript source the opcode was compiled from;
//! - in the rule inventory, which gives the rule id (`K-nn`, `M-nn`, `S-nn`) of the check
//!   that refuses at that opcode.
//!
//! The lookup is by the byte offset of the opcode inside the redeem script that really ran.
//! That script is read from the signature script of the input (its last push) and compared
//! with the three contracts of the family: only a script that has the frame of a contract
//! (the same length, the same bytes before and after the state) is given lines and rules.
//!
//! A refusal is attributed to a rule only when the error fits the rule:
//!
//! - a rule that the script checks (a verify opcode or the `OpReturn` of a dispatcher)
//!   refused when the engine reports a contract refusal at its opcode;
//! - a rule that only the engine enforces (the checked additions `K-30`, `K-36`, `M-47`)
//!   refused when the engine reports a data error at its opcode.
//!
//! A budget that runs out at the opcode of a rule, or a malformed signature at a signature
//! check, is not the rule refusing. [`Attribution::at_rule`] still names the rule whose
//! opcode it was.

use kaspa_consensus_core::{hashing::sighash::SigHashReusedValuesUnsync, tx::PopulatedTransaction};
use kaspa_txscript::{
    opcodes::codes::OpReserved, parse_script, pay_to_script_hash_script, script_class::ScriptClass,
};
use kaspa_txscript_errors::TxScriptError;
use kcc20_family::{
    Contract, Entry, Family, SourceMap,
    sourcemap::{ContractMap, Place},
};
use node_gate::{ErrorClass, ScriptKind, StopPoint};
use serde::Serialize;

use crate::outcome::variant_name;

/// The label of a refusal by the pay-to-script-hash test of the coin's own script.
pub const P2SH_WRAPPER: &str = "P2SH wrapper";
/// The label of a refusal by the final stack check after the last opcode.
pub const FINAL_STACK: &str = "final stack";
/// The label of a contract refusal in the argument size checks of an entry, when the
/// inventory has no rule for the opcode.
pub const PROLOGUE: &str = "prologue";
/// The label of a contract refusal in the entry selector, when the inventory has no rule
/// for the opcode.
pub const DISPATCHER: &str = "dispatcher";

/// The part of an input's scripts in which the engine stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Part {
    /// Before any opcode ran.
    BeforeAnyOpcode,
    /// The signature script: the pushes of the call.
    SignatureScript,
    /// The script of a pay-to-script-hash coin (hash the last push, compare), including a
    /// redeem script that does not hash to the coin.
    P2shWrapper,
    /// The redeem script, which has the frame of one of the three contracts.
    ContractScript,
    /// A redeem script that is not one of the three contracts.
    OtherRedeemScript,
    /// The script of a coin that is not pay-to-script-hash.
    LockScript,
    /// After the last opcode: the final stack is empty, false or not clean.
    FinalStack,
    /// The position could not be determined.
    Unknown,
}

/// A statement of the generated SilverScript source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SilLine {
    /// File name of the source: `KCC20.sil`, `PublicMint.sil` or `TokenSeed.sil`.
    pub file: String,
    /// First line of the innermost statement the opcode was compiled from. Inside an
    /// inlined helper function this is the line in the helper, not the line of the call;
    /// the call site is in [`Attribution::inventory_line`] (`134 -> 66`), which is taken from
    /// the rule inventory.
    pub line: u32,
    /// Last line of that statement.
    pub end_line: u32,
    /// The text of the statement, its lines trimmed and joined by one space.
    pub text: String,
}

/// What refused an input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Attribution {
    /// The short name of what refused: the rule id when a contract rule refused; otherwise
    /// `P2SH wrapper`, `final stack`, `prologue`, `dispatcher` (also `statement`, `glue`,
    /// `clean-up`, `state frame`, `redeem script`, `lock script` for a contract refusal at
    /// an opcode without a rule), or `engine: <Variant>` for any refusal that is the
    /// engine's own.
    pub refused_by: String,
    /// The part of the input's scripts in which the engine stopped.
    pub part: Part,
    /// The id of the contract rule that refused. Set only when the error fits the rule;
    /// see the module text.
    pub rule: Option<String>,
    /// The id of the rule whose refusing opcode the engine stopped at, whatever the error.
    pub at_rule: Option<String>,
    /// The contract whose frame the redeem script has.
    pub contract: Option<String>,
    /// The entry whose code holds the opcode.
    pub entry: Option<String>,
    /// The part of the contract script: `statement`, `prologue`, `dispatcher`, `glue`,
    /// `clean-up` or `state frame`.
    pub place: Option<String>,
    /// Byte offset of the opcode in the script named by `part`.
    pub byte_offset: Option<usize>,
    /// Zero-based ordinal of the opcode in that script.
    pub op_index: Option<usize>,
    /// The engine's name of the opcode.
    pub opcode: Option<String>,
    /// The source statement the opcode was compiled from.
    pub sil: Option<SilLine>,
    /// The line or lines the rule inventory names for the rule at this opcode.
    pub inventory_line: Option<String>,
    /// The id of the engine precondition of the rule inventory this refusal belongs to:
    /// `E-02` signature script holds pushes only, `E-03` the redeem script hashes to the
    /// coin, `E-04` exactly one true item is left.
    pub engine_precondition: Option<String>,
    /// Something a reader of the record must know: why no line is given, or what did not
    /// fit.
    pub note: Option<String>,
}

impl Attribution {
    /// One line for a failure message.
    pub fn describe(&self) -> String {
        let mut text = self.refused_by.clone();
        if let (Some(at_rule), None) = (&self.at_rule, &self.rule) {
            text.push_str(&format!(" (at the opcode of {at_rule})"));
        }
        if let Some(sil) = &self.sil {
            text.push_str(&format!(" | {}:{} {}", sil.file, sil.line, sil.text));
        }
        match (&self.contract, &self.entry, &self.place) {
            (Some(contract), Some(entry), Some(place)) => {
                text.push_str(&format!(" | {contract}.{entry}, {place}"))
            }
            (Some(contract), None, Some(place)) => {
                text.push_str(&format!(" | {contract}, {place}"))
            }
            _ => {}
        }
        if let (Some(offset), Some(index), Some(opcode)) =
            (self.byte_offset, self.op_index, &self.opcode)
        {
            text.push_str(&format!(
                " | {:?} byte {offset}, opcode #{index} {opcode}",
                self.part
            ));
        } else {
            text.push_str(&format!(" | {:?}", self.part));
        }
        if let Some(note) = &self.note {
            text.push_str(&format!(" | note: {note}"));
        }
        text
    }

    fn engine(part: Part, error: &TxScriptError) -> Self {
        Self {
            refused_by: engine_label(error),
            part,
            rule: None,
            at_rule: None,
            contract: None,
            entry: None,
            place: None,
            byte_offset: None,
            op_index: None,
            opcode: None,
            sil: None,
            inventory_line: None,
            engine_precondition: None,
            note: None,
        }
    }

    fn labelled(part: Part, label: &str, error: &TxScriptError) -> Self {
        Self {
            refused_by: label.to_string(),
            ..Self::engine(part, error)
        }
    }
}

/// `engine: <Variant>` for an engine error.
pub fn engine_label(error: &TxScriptError) -> String {
    format!("engine: {}", variant_name(&format!("{error:?}")))
}

/// The data of the last push of a signature script: the redeem script of a
/// pay-to-script-hash input. `None` when the script is empty or does not parse.
pub fn pushed_redeem_script(signature_script: &[u8]) -> Option<Vec<u8>> {
    let mut last = None;
    for opcode in
        parse_script::<PopulatedTransaction<'static>, SigHashReusedValuesUnsync>(signature_script)
    {
        last = Some(opcode.ok()?.get_data().to_vec());
    }
    last
}

/// The contract whose frame `redeem_script` has in `family`: the same length, and the same
/// bytes before and after the state.
pub fn contract_of_redeem_script(family: &Family, redeem_script: &[u8]) -> Option<Contract> {
    Contract::ALL.into_iter().find(|contract| {
        let bytecode = family.bytecode(*contract);
        let span = family.state_span(*contract);
        redeem_script.len() == bytecode.len()
            && redeem_script[..span.start] == bytecode[..span.start]
            && redeem_script[span.end..] == bytecode[span.end..]
    })
}

/// The contract script an input makes the engine run and the entry its call selects there,
/// read from the bytes of the input alone. What a scenario says about the input plays no
/// part.
///
/// `Some` when the coin is a pay-to-script-hash coin, the signature script holds pushes
/// only, its last push hashes to the coin, and that script has the frame of one of the
/// three contracts of `family`: then the engine runs that contract script. The entry is the
/// one whose dispatch tag is the item pushed right in front of the script; the selector of
/// a contract compares that item byte for byte with the tag of every entry (silverscript
/// 3ed9733 silverscript-lang/src/compiler/compile.rs:371-376). It is `None` when the call
/// pushes no such item or the tag of no entry: the selector then refuses.
///
/// `None` for every other input: a coin with another script, a redeem script that does not
/// hash to the coin or is not one of the three contracts, a signature script the engine
/// refuses before the coin's script runs.
pub fn contract_call(
    family: &Family,
    signature_script: &[u8],
    spent_script: &[u8],
) -> Option<(Contract, Option<Entry>)> {
    if !ScriptClass::is_pay_to_script_hash(spent_script) {
        return None;
    }
    let mut pushes: Vec<Vec<u8>> = Vec::new();
    for opcode in
        parse_script::<PopulatedTransaction<'static>, SigHashReusedValuesUnsync>(signature_script)
    {
        let opcode = opcode.ok()?;
        // `OpReserved` passes the engine's pushes-only rule and fails when it runs.
        if !opcode.is_push_opcode() || opcode.value() == OpReserved {
            return None;
        }
        pushes.push(opcode.get_data().to_vec());
    }
    let redeem_script = pushes.pop()?;
    if pay_to_script_hash_script(&redeem_script).script() != spent_script {
        return None;
    }
    let contract = contract_of_redeem_script(family, &redeem_script)?;
    let entry = pushes.last().and_then(|tag| {
        Entry::ALL.into_iter().find(|entry| {
            entry.contract() == contract && family.dispatch_tag(*entry).as_slice() == tag.as_slice()
        })
    });
    Some((contract, entry))
}

/// Names what refused one input.
///
/// `signature_script` and `spent_script` are those of the input, `error`, `class` and `stop`
/// come from the run. The lines and rules of the pinned source map are used for a contract
/// of `family` whenever its bytecode has the pinned length, which holds for the pinned
/// family and for one with a same-length replacement.
pub fn attribute(
    family: &Family,
    signature_script: &[u8],
    spent_script: &[u8],
    error: &TxScriptError,
    class: ErrorClass,
    stop: &StopPoint,
) -> Attribution {
    let spent_is_p2sh = ScriptClass::is_pay_to_script_hash(spent_script);
    let contract_refused = class == ErrorClass::ContractRefused;
    let at = match stop {
        StopPoint::BeforeAnyOpcode => return Attribution::engine(Part::BeforeAnyOpcode, error),
        StopPoint::P2shHashMismatch => {
            let mut attribution = Attribution::labelled(Part::P2shWrapper, P2SH_WRAPPER, error);
            attribution.engine_precondition = Some("E-03".to_string());
            return attribution;
        }
        StopPoint::FinalStack => {
            let mut attribution = Attribution::labelled(Part::FinalStack, FINAL_STACK, error);
            attribution.engine_precondition = Some("E-04".to_string());
            return attribution;
        }
        StopPoint::EndOfScript(kind) => {
            return Attribution::engine(part_of(*kind, spent_is_p2sh, false), error);
        }
        StopPoint::Unknown(reason) => {
            let mut attribution = Attribution::engine(Part::Unknown, error);
            attribution.note = Some(format!("the position was not determined: {reason}"));
            return attribution;
        }
        StopPoint::Opcode(at) => at,
    };

    let redeem_script = (at.script == ScriptKind::RedeemScript)
        .then(|| pushed_redeem_script(signature_script))
        .flatten();
    let contract = redeem_script
        .as_deref()
        .and_then(|script| contract_of_redeem_script(family, script));
    let part = part_of(at.script, spent_is_p2sh, contract.is_some());
    let mut attribution = Attribution::engine(part, error);
    attribution.byte_offset = Some(at.byte_offset);
    attribution.op_index = Some(at.op_index);
    attribution.opcode = at.opcode_name.clone();

    match part {
        Part::SignatureScript => {
            if matches!(error, TxScriptError::SignatureScriptNotPushOnly) {
                attribution.engine_precondition = Some("E-02".to_string());
            }
        }
        Part::P2shWrapper => {
            attribution.refused_by = P2SH_WRAPPER.to_string();
            attribution.engine_precondition = Some("E-03".to_string());
        }
        Part::LockScript if contract_refused => attribution.refused_by = "lock script".to_string(),
        Part::OtherRedeemScript if contract_refused => {
            attribution.refused_by = "redeem script".to_string()
        }
        Part::ContractScript => {
            let contract = contract.expect("a contract script has a contract");
            attribution.contract = Some(contract.name().to_string());
            in_contract(
                family,
                contract,
                at.byte_offset,
                at.op_index,
                at.opcode,
                class,
                &mut attribution,
            );
        }
        _ => {}
    }
    attribution
}

fn part_of(kind: ScriptKind, spent_is_p2sh: bool, is_contract: bool) -> Part {
    match kind {
        ScriptKind::SignatureScript => Part::SignatureScript,
        ScriptKind::ScriptPublicKey if spent_is_p2sh => Part::P2shWrapper,
        ScriptKind::ScriptPublicKey => Part::LockScript,
        ScriptKind::RedeemScript if is_contract => Part::ContractScript,
        ScriptKind::RedeemScript => Part::OtherRedeemScript,
    }
}

/// Fills in what the source map and the rule inventory know about one opcode of a contract.
fn in_contract(
    family: &Family,
    contract: Contract,
    byte_offset: usize,
    op_index: usize,
    opcode: u8,
    class: ErrorClass,
    attribution: &mut Attribution,
) {
    let map = SourceMap::pinned().contract(contract);
    if family.bytecode(contract).len() != map.bytecode().len() {
        attribution.note = Some("the bytecode of this family has another length than the pinned one: no lines, no rules".to_string());
        if class == ErrorClass::ContractRefused {
            attribution.refused_by = "contract script".to_string();
        }
        return;
    }

    let mut notes = Vec::new();
    match map.opcode_at(byte_offset) {
        Some(mapped) if mapped.offset == byte_offset => {
            if mapped.index != op_index {
                notes.push(format!(
                    "the engine counted opcode #{op_index}, the pinned script has #{} at this byte",
                    mapped.index
                ));
            }
            if mapped.code != opcode {
                notes.push(format!(
                    "the opcode byte {opcode:#04x} differs from the pinned {:#04x}",
                    mapped.code
                ));
            }
        }
        _ => notes.push("no opcode of the pinned script starts at this byte".to_string()),
    }

    let (place, entry) = match map.place_at(byte_offset) {
        Place::Frame => ("state frame", None),
        Place::Dispatcher => (DISPATCHER, None),
        Place::Prologue { entry } => (PROLOGUE, Some(entry)),
        Place::Statement { entry, .. } => ("statement", Some(entry)),
        Place::Glue { entry, .. } => ("glue", Some(entry)),
        Place::Epilogue { entry } => ("clean-up", Some(entry)),
    };
    attribution.place = Some(place.to_string());
    attribution.entry = entry.map(str::to_string);
    attribution.sil = sil_line(map, contract, byte_offset);

    if let Some(rule) = map.rule_at(byte_offset) {
        attribution.at_rule = Some(rule.id.clone());
        attribution.inventory_line = rule.sil_line.clone();
        // A rule the engine alone enforces has the origin `engine` in the inventory and
        // refuses with a data error; every other rule is a check of the script.
        let engine_rule = rule
            .record
            .get("origin")
            .and_then(serde_json::Value::as_str)
            == Some("engine");
        let fits = if engine_rule {
            class == ErrorClass::EngineRefusedData
        } else {
            class == ErrorClass::ContractRefused
        };
        if fits {
            attribution.rule = Some(rule.id.clone());
            attribution.refused_by = rule.id.clone();
        }
    }
    if attribution.rule.is_none() && class == ErrorClass::ContractRefused {
        attribution.refused_by = place.to_string();
    }
    if !notes.is_empty() {
        attribution.note = Some(notes.join("; "));
    }
}

/// The innermost statement that covers the byte.
fn sil_line(map: &ContractMap, contract: Contract, byte_offset: usize) -> Option<SilLine> {
    let innermost = map.line_at(byte_offset)?;
    Some(SilLine {
        file: contract.sil_file_name().to_string(),
        line: innermost.line,
        end_line: innermost.end_line,
        text: innermost.text,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use node_gate::OpcodeStop;

    fn stop(
        script: ScriptKind,
        byte_offset: usize,
        op_index: usize,
        opcode: u8,
        name: &str,
    ) -> StopPoint {
        StopPoint::Opcode(OpcodeStop {
            script,
            op_index,
            byte_offset,
            opcode,
            opcode_name: Some(name.to_string()),
            executed: true,
        })
    }

    #[test]
    fn stops_outside_a_redeem_script_are_named_by_their_part() {
        let family = Family::pinned();
        let p2sh = [0xaa, 0x20]
            .iter()
            .copied()
            .chain([0u8; 32])
            .chain([0x87])
            .collect::<Vec<u8>>();

        let mismatch = attribute(
            family,
            &[0x51],
            &p2sh,
            &TxScriptError::EvalFalse,
            ErrorClass::ScriptFormat,
            &StopPoint::P2shHashMismatch,
        );
        assert_eq!(mismatch.refused_by, P2SH_WRAPPER);
        assert_eq!(mismatch.part, Part::P2shWrapper);
        assert_eq!(mismatch.engine_precondition.as_deref(), Some("E-03"));

        let unclean = attribute(
            family,
            &[0x51, 0x51],
            &[0x51],
            &TxScriptError::CleanStack(2),
            ErrorClass::ContractRefused,
            &StopPoint::FinalStack,
        );
        assert_eq!(unclean.refused_by, FINAL_STACK);
        assert_eq!(unclean.engine_precondition.as_deref(), Some("E-04"));

        let not_push = attribute(
            family,
            &[0x76],
            &p2sh,
            &TxScriptError::SignatureScriptNotPushOnly,
            ErrorClass::ScriptFormat,
            &stop(ScriptKind::SignatureScript, 0, 0, 0x76, "OpDup"),
        );
        assert_eq!(not_push.refused_by, "engine: SignatureScriptNotPushOnly");
        assert_eq!(not_push.part, Part::SignatureScript);
        assert_eq!(not_push.engine_precondition.as_deref(), Some("E-02"));

        let empty_call = attribute(
            family,
            &[],
            &p2sh,
            &TxScriptError::InvalidStackOperation(1, 0),
            ErrorClass::ScriptFormat,
            &stop(ScriptKind::ScriptPublicKey, 0, 0, 0xaa, "OpBlake2b"),
        );
        assert_eq!(empty_call.refused_by, P2SH_WRAPPER);
    }

    #[test]
    fn a_redeem_script_is_recognised_by_its_frame_only() {
        let family = Family::pinned();
        for contract in Contract::ALL {
            let mut script = family.bytecode(contract).to_vec();
            assert_eq!(contract_of_redeem_script(family, &script), Some(contract));
            // Any state bytes: still the contract.
            let span = family.state_span(contract);
            script[span.start + 1] ^= 0xff;
            assert_eq!(contract_of_redeem_script(family, &script), Some(contract));
            // One byte of code changed behind the state: not the contract.
            let last = script.len() - 1;
            script[last] ^= 0x01;
            assert_eq!(contract_of_redeem_script(family, &script), None);
            // One byte of code changed in front of the state: not the contract either.
            script[last] ^= 0x01;
            assert!(
                span.start > 0,
                "every contract has code in front of its state"
            );
            script[0] ^= 0x01;
            assert_eq!(contract_of_redeem_script(family, &script), None);
        }
        assert_eq!(contract_of_redeem_script(family, &[0x51]), None);
    }

    #[test]
    fn what_does_not_fit_the_pinned_script_is_said_in_a_note() {
        let family = Family::pinned();
        let map = SourceMap::pinned().contract(Contract::Kcc20);
        let redeem = family.bytecode(Contract::Kcc20).to_vec();
        let signature_script = kcc20_family::raw::push_redeem(&redeem).expect("push");
        let spent = kaspa_txscript::pay_to_script_hash_script(&redeem);

        // A byte inside the data of a push: no opcode starts there.
        let push = map
            .opcodes()
            .iter()
            .find(|opcode| {
                opcode.len > 1 && opcode.offset >= family.state_span(Contract::Kcc20).end
            })
            .expect("the code holds a push with data");
        let inside = attribute(
            family,
            &signature_script,
            spent.script(),
            &TxScriptError::VerifyError,
            ErrorClass::ContractRefused,
            &stop(
                ScriptKind::RedeemScript,
                push.offset + 1,
                push.index,
                push.code,
                &push.name,
            ),
        );
        assert_eq!(
            inside.note.as_deref(),
            Some("no opcode of the pinned script starts at this byte")
        );

        // The right byte, another ordinal and another opcode byte than the pinned script has.
        let verify = map.opcode_at(2203).expect("an opcode at 2203");
        let shifted = attribute(
            family,
            &signature_script,
            spent.script(),
            &TxScriptError::VerifyError,
            ErrorClass::ContractRefused,
            &stop(
                ScriptKind::RedeemScript,
                2203,
                verify.index + 1,
                0x75,
                "OpDrop",
            ),
        );
        let note = shifted.note.expect("two things do not fit");
        assert!(
            note.contains(&format!("#{}", verify.index + 1)) && note.contains("0x75"),
            "{note}"
        );
        assert_eq!(
            shifted.rule.as_deref(),
            Some("K-37"),
            "the offset still names the rule"
        );

        // A family whose KCC20 has another length: the pinned lines do not apply.
        let mut longer = redeem.clone();
        longer.push(0x61);
        let other = family
            .with_bytecode(Contract::Kcc20, longer.clone())
            .expect("a replacement");
        let signature_script = kcc20_family::raw::push_redeem(&longer).expect("push");
        let spent = kaspa_txscript::pay_to_script_hash_script(&longer);
        let unmapped = attribute(
            &other,
            &signature_script,
            spent.script(),
            &TxScriptError::VerifyError,
            ErrorClass::ContractRefused,
            &stop(
                ScriptKind::RedeemScript,
                2203,
                verify.index,
                verify.code,
                &verify.name,
            ),
        );
        assert_eq!(unmapped.contract.as_deref(), Some("KCC20"));
        assert_eq!(unmapped.refused_by, "contract script");
        assert_eq!(
            (unmapped.rule, unmapped.at_rule, unmapped.sil),
            (None, None, None)
        );
        assert!(
            unmapped
                .note
                .is_some_and(|note| note.contains("another length"))
        );
    }

    #[test]
    fn what_an_input_runs_is_read_from_its_bytes() {
        let family = Family::pinned();
        let redeem = family.bytecode(Contract::Kcc20).to_vec();
        let spent = pay_to_script_hash_script(&redeem);
        let push_redeem = kcc20_family::raw::push_redeem(&redeem).expect("push");
        let call = |tag: &[u8]| {
            let mut script = kcc20_family::raw::push(tag).expect("push");
            script.extend_from_slice(&push_redeem);
            script
        };
        let transfer = family.dispatch_tag(Entry::Transfer);
        let delegator = family.dispatch_tag(Entry::TransferDelegator);

        // The tag in front of the redeem script selects the entry.
        assert_eq!(
            contract_call(family, &call(&transfer), spent.script()),
            Some((Contract::Kcc20, Some(Entry::Transfer)))
        );
        assert_eq!(
            contract_call(family, &call(&delegator), spent.script()),
            Some((Contract::Kcc20, Some(Entry::TransferDelegator)))
        );
        // The tag of an entry of another contract, or no item at all: no entry.
        let mint = family.dispatch_tag(Entry::Mint);
        assert_ne!(mint, transfer);
        assert_eq!(
            contract_call(family, &call(&mint), spent.script()),
            Some((Contract::Kcc20, None))
        );
        assert_eq!(
            contract_call(family, &push_redeem, spent.script()),
            Some((Contract::Kcc20, None))
        );

        // A coin that is not locked to the hash of the pushed script runs no contract:
        // a bare script, and a hash of another script.
        assert_eq!(contract_call(family, &call(&transfer), &[0x51]), None);
        let other = pay_to_script_hash_script(&[0x51]);
        assert_eq!(
            contract_call(family, &call(&transfer), other.script()),
            None
        );
        // A script behind the hash that is not one of the three contracts.
        let plain = kcc20_family::raw::push_redeem(&[0x51]).expect("push");
        assert_eq!(contract_call(family, &plain, other.script()), None);
        // A signature script the engine refuses: an opcode that is no push or the
        // reserved one, a cut push, no bytes at all.
        for no_push in [0x76, OpReserved] {
            let mut not_only_pushes = vec![no_push];
            not_only_pushes.extend_from_slice(&call(&transfer));
            assert_eq!(
                contract_call(family, &not_only_pushes, spent.script()),
                None
            );
        }
        let cut = &call(&transfer)[..10];
        assert_eq!(contract_call(family, cut, spent.script()), None);
        assert_eq!(contract_call(family, &[], spent.script()), None);
    }

    #[test]
    fn the_last_push_of_a_signature_script_is_read() {
        assert_eq!(pushed_redeem_script(&[]), None);
        assert_eq!(
            pushed_redeem_script(&[0x01, 0xaa, 0x02, 0xbb, 0xcc]),
            Some(vec![0xbb, 0xcc])
        );
        assert_eq!(
            pushed_redeem_script(&[0x02, 0xbb]),
            None,
            "a truncated push"
        );
    }

    #[test]
    fn a_rule_is_named_only_when_the_error_fits_it() {
        let family = Family::pinned();
        let redeem = family.bytecode(Contract::Kcc20).to_vec();
        let signature_script = kcc20_family::raw::push_redeem(&redeem).expect("push");
        let spent = kaspa_txscript::pay_to_script_hash_script(&redeem);
        let map = SourceMap::pinned().contract(Contract::Kcc20);
        // K-37, the sum rule, refuses at byte 2203 with a verify.
        let opcode = map.opcode_at(2203).expect("an opcode at 2203");
        let at = stop(
            ScriptKind::RedeemScript,
            2203,
            opcode.index,
            opcode.code,
            &opcode.name,
        );

        let verify = attribute(
            family,
            &signature_script,
            spent.script(),
            &TxScriptError::VerifyError,
            ErrorClass::ContractRefused,
            &at,
        );
        assert_eq!(verify.refused_by, "K-37");
        assert_eq!(verify.rule.as_deref(), Some("K-37"));
        assert_eq!(verify.contract.as_deref(), Some("KCC20"));
        assert_eq!(verify.entry.as_deref(), Some("transfer"));
        assert_eq!(verify.sil.as_ref().map(|sil| sil.line), Some(175));
        assert_eq!(verify.note, None);

        // The budget running out at the same opcode is not the rule refusing.
        let budget = TxScriptError::ExceededCommittedScriptUnits {
            used: 10_000,
            limit: 9_999,
        };
        let exceeded = attribute(
            family,
            &signature_script,
            spent.script(),
            &budget,
            ErrorClass::ResourceLimit,
            &at,
        );
        assert_eq!(exceeded.refused_by, "engine: ExceededCommittedScriptUnits");
        assert_eq!(exceeded.rule, None);
        assert_eq!(exceeded.at_rule.as_deref(), Some("K-37"));

        // K-30 is enforced by the engine's checked addition: a data error fits, a verify does not.
        let add = map.opcode_at(1724).expect("an opcode at 1724");
        let at_add = stop(
            ScriptKind::RedeemScript,
            1724,
            add.index,
            add.code,
            &add.name,
        );
        let too_big =
            TxScriptError::NumberTooBig("Sum exceeds 64-bit signed integer range".to_string());
        let overflow = attribute(
            family,
            &signature_script,
            spent.script(),
            &too_big,
            ErrorClass::EngineRefusedData,
            &at_add,
        );
        assert_eq!(overflow.rule.as_deref(), Some("K-30"));
        assert_eq!(overflow.refused_by, "K-30");
        let odd = attribute(
            family,
            &signature_script,
            spent.script(),
            &TxScriptError::VerifyError,
            ErrorClass::ContractRefused,
            &at_add,
        );
        assert_eq!(odd.rule, None);
        assert_eq!(odd.at_rule.as_deref(), Some("K-30"));
        assert_eq!(odd.refused_by, "statement");
        // Nor does a budget that runs out at the addition.
        let exceeded = attribute(
            family,
            &signature_script,
            spent.script(),
            &budget,
            ErrorClass::ResourceLimit,
            &at_add,
        );
        assert_eq!(exceeded.rule, None);
        assert_eq!(exceeded.at_rule.as_deref(), Some("K-30"));
        assert_eq!(exceeded.refused_by, "engine: ExceededCommittedScriptUnits");
    }
}
