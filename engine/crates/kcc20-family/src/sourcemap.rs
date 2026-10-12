//! Byte offset in a redeem script to source line and to rule id.
//!
//! Almost every refusal of the three contracts is the same engine error (a failed verify).
//! To name the rule that refused, one needs the opcode that failed; this module turns its
//! byte offset into
//!
//! - the opcode itself and its ordinal in the script,
//! - the entry whose code it belongs to,
//! - the line of the generated SilverScript source it was compiled from, and
//! - the rule of the rule inventory (`K-nn`, `M-nn`, `S-nn`) that refuses there.
//!
//! The lines come from the SilverScript compiler itself: the three pinned sources are
//! compiled again with debug information on, and the result must be byte-identical to the
//! bytecode of the artifact. The rules come from `data/rule-inventory.json` in the workspace.
//!
//! Offsets are those of the script in the artifact (the template with a zero-filled state).
//! They are the same in every redeem script the family builds for the contract, because the
//! encoded state always has the length of the state span.

use std::collections::BTreeMap;
use std::fs;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::OnceLock;

use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::PopulatedTransaction;
use kaspa_txscript::parse_script;
use serde::Deserialize;
use silverscript_lang::ast::{ArrayDim, Expr, TypeBase, TypeRef, parse_contract_ast};
use silverscript_lang::compiler::{CompileOptions, compile_contract};
use silverscript_lang::debug_info::StepKind as DebugStepKind;

use crate::error::{Error, Result};
use crate::family::{Contract, Family};
use crate::refdata;

/// One opcode of a script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opcode {
    /// Ordinal of the opcode in the script, from 0. The engine's opcode log holds one line
    /// per opcode of every script it runs, skipped branches included.
    pub index: usize,
    /// Byte offset of the opcode in the script.
    pub offset: usize,
    /// Length in bytes, data included.
    pub len: usize,
    /// The opcode byte.
    pub code: u8,
    /// Name of the opcode as the engine prints it, without its data (`OpVerify`).
    pub name: String,
}

/// Cuts a script into opcodes with their offsets.
pub fn disassemble(script: &[u8]) -> Result<Vec<Opcode>> {
    let mut opcodes = Vec::new();
    let mut offset = 0;
    for (index, opcode) in
        parse_script::<PopulatedTransaction<'_>, SigHashReusedValuesUnsync>(script).enumerate()
    {
        let opcode = opcode.map_err(|error| Error::Script(format!("at byte {offset}: {error}")))?;
        let len = opcode.serialize().len();
        let text = opcode.to_string();
        let name = text.split(' ').next().unwrap_or_default().to_string();
        opcodes.push(Opcode {
            index,
            offset,
            len,
            code: opcode.value(),
            name,
        });
        offset += len;
    }
    if offset != script.len() {
        return Err(Error::Script(format!(
            "the last opcode ends at byte {offset}, the script has {} bytes",
            script.len()
        )));
    }
    Ok(opcodes)
}

/// A statement of the source and the bytes compiled from it, as the compiler records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceStep {
    /// First byte of the statement's code.
    pub start: usize,
    /// One past the last byte of the statement's code.
    pub end: usize,
    /// First line of the statement in the source, from 1.
    pub line: u32,
    /// Column of its first character, from 1.
    pub column: u32,
    /// Last line of the statement.
    pub end_line: u32,
    /// Column one past its last character.
    pub end_column: u32,
    /// The call depth the compiler recorded for the step, copied as it is (silverscript
    /// 3ed9733 silverscript-lang/src/compiler/debug_recording.rs:1011-1080). Nothing in this
    /// crate decides anything by it.
    pub call_depth: u32,
    /// What the step marks.
    pub kind: StepKind,
}

/// What a recorded step marks.
///
/// The two markers of an inlined call are copied from the compiler as they are and are used
/// for nothing; only the statement steps are used for lookups.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepKind {
    /// A source statement.
    Statement,
    /// The start of an inlined call of the named function, as recorded.
    InlineEnter(String),
    /// The end of an inlined call of the named function, as recorded.
    InlineExit(String),
}

/// The byte range of one entry in the script, dispatcher test excluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryRange {
    /// Name of the entry in the source.
    pub name: String,
    /// First byte of the entry's code.
    pub start: usize,
    /// One past its last byte.
    pub end: usize,
}

/// One record of the rule inventory. Only the fields used for lookups are typed; the whole
/// record is kept in `record`.
#[derive(Clone, Debug)]
pub struct Rule {
    /// `K-nn`, `M-nn` or `S-nn`.
    pub id: String,
    /// The contract of the rule.
    pub contract: Contract,
    /// The entry the record is filed under (`transfer`, `dispatcher (both entries)`, ...).
    pub entry: String,
    /// The opcode that refuses, when the rule has one.
    pub check_opcode: Option<String>,
    /// Lines of the generated source the inventory names for the rule.
    pub sil_line: Option<String>,
    /// What the rule demands.
    pub meaning: String,
    /// Every byte offset at which the rule refuses, over all entries that reach it.
    pub offsets: Vec<usize>,
    /// The complete record as written in the inventory.
    pub record: serde_json::Value,
}

/// The source statement an opcode was compiled from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceLine {
    /// First line of the statement in the generated source, from 1.
    pub line: u32,
    /// Last line of the statement.
    pub end_line: u32,
    /// The text of the statement: its lines trimmed and joined by one space.
    pub text: String,
}

/// What part of a contract script a byte belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Place<'a> {
    /// In front of the entries: `OpToAltStack` and the state pushes.
    Frame,
    /// The entry selector: the tag comparisons in front of every entry and the
    /// `OpElse` / `OpReturn` / `OpEndIf` tail.
    Dispatcher,
    /// The size checks of the call arguments that the compiler puts in front of the first
    /// statement of an entry. They have no line in the source.
    Prologue { entry: &'a str },
    /// The code of a statement.
    Statement { entry: &'a str, line: SourceLine },
    /// Stack clean-up or branch glue between statements, after the statement given.
    Glue { entry: &'a str, after: SourceLine },
    /// The clean-up at the end of an entry: the drops and the final `OpTrue`.
    Epilogue { entry: &'a str },
}

/// Everything known about one contract's script.
#[derive(Clone, Debug)]
pub struct ContractMap {
    contract: Contract,
    source: String,
    bytecode: Vec<u8>,
    state_span: Range<usize>,
    opcodes: Vec<Opcode>,
    steps: Vec<SourceStep>,
    entries: Vec<EntryRange>,
    rules: Vec<Rule>,
    rule_at: BTreeMap<usize, usize>,
}

impl ContractMap {
    /// The contract.
    pub fn contract(&self) -> Contract {
        self.contract
    }

    /// The generated source the map was compiled from.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The bytecode the map describes (the template with a zero-filled state).
    pub fn bytecode(&self) -> &[u8] {
        &self.bytecode
    }

    /// Every opcode of the script, in order.
    pub fn opcodes(&self) -> &[Opcode] {
        &self.opcodes
    }

    /// Every statement step the compiler recorded, in recording order.
    pub fn steps(&self) -> &[SourceStep] {
        &self.steps
    }

    /// The byte ranges of the entries.
    pub fn entries(&self) -> &[EntryRange] {
        &self.entries
    }

    /// The opcode that covers the byte at `offset` (its first byte or a byte of its data).
    pub fn opcode_at(&self, offset: usize) -> Option<&Opcode> {
        let position = self
            .opcodes
            .partition_point(|opcode| opcode.offset <= offset)
            .checked_sub(1)?;
        let opcode = &self.opcodes[position];
        (offset < opcode.offset + opcode.len).then_some(opcode)
    }

    /// The opcode with the given ordinal: the way from a line count of the engine's opcode
    /// log to a byte offset.
    pub fn opcode_by_index(&self, index: usize) -> Option<&Opcode> {
        self.opcodes.get(index)
    }

    /// The entry whose code covers the byte at `offset`.
    pub fn entry_at(&self, offset: usize) -> Option<&EntryRange> {
        self.entries
            .iter()
            .find(|entry| entry.start <= offset && offset < entry.end)
    }

    /// The innermost recorded statement whose code covers the byte at `offset`: the one with
    /// the narrowest byte range. No two statements of a map share a byte range
    /// ([`SourceMap::build`] refuses such debug information), so the answer does not depend
    /// on the order of the steps.
    pub fn step_at(&self, offset: usize) -> Option<&SourceStep> {
        self.steps
            .iter()
            .filter(|step| {
                step.kind == StepKind::Statement && step.start <= offset && offset < step.end
            })
            .min_by_key(|step| step.end - step.start)
    }

    /// The statement of a recorded step, with its text.
    fn source_line(&self, step: &SourceStep) -> SourceLine {
        let first = step.line.saturating_sub(1) as usize;
        let count = (step.end_line.saturating_sub(step.line) + 1) as usize;
        let text = self
            .source
            .lines()
            .skip(first)
            .take(count)
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(" ");
        SourceLine {
            line: step.line,
            end_line: step.end_line,
            text,
        }
    }

    /// The source statement the opcode at `offset` was compiled from. `None` for code that
    /// belongs to no statement: the dispatcher, the argument size checks at the start of an
    /// entry, the clean-up at its end, and the stack and branch glue between statements.
    /// [`ContractMap::place_at`] tells these apart.
    pub fn line_at(&self, offset: usize) -> Option<SourceLine> {
        self.step_at(offset).map(|step| self.source_line(step))
    }

    /// What part of the script the byte at `offset` belongs to.
    pub fn place_at(&self, offset: usize) -> Place<'_> {
        if offset < self.state_span.end {
            return Place::Frame;
        }
        let Some(entry) = self.entry_at(offset) else {
            return Place::Dispatcher;
        };
        let name = entry.name.as_str();
        if let Some(step) = self.step_at(offset) {
            return Place::Statement {
                entry: name,
                line: self.source_line(step),
            };
        }
        let statements = || {
            self.steps.iter().filter(|step| {
                step.kind == StepKind::Statement
                    && step.start < step.end
                    && entry.start <= step.start
                    && step.end <= entry.end
            })
        };
        let last_end = statements()
            .map(|step| step.end)
            .max()
            .unwrap_or(entry.start);
        if offset >= last_end {
            return Place::Epilogue { entry: name };
        }
        // The statement that ended last before this byte; among those, the narrowest one.
        match statements()
            .filter(|step| step.end <= offset)
            .max_by_key(|step| (step.end, std::cmp::Reverse(step.end - step.start)))
        {
            Some(step) => Place::Glue {
                entry: name,
                after: self.source_line(step),
            },
            None => Place::Prologue { entry: name },
        }
    }

    /// Every rule of the contract, in inventory order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The rule with the given id.
    pub fn rule(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.id == id)
    }

    /// The rule whose refusing opcode starts at `offset`.
    pub fn rule_at(&self, offset: usize) -> Option<&Rule> {
        self.rule_at
            .get(&offset)
            .map(|position| &self.rules[*position])
    }

    /// One line for a report about the byte at `offset`: contract, offset, opcode, the part of
    /// the script, the source statement and the rule, as far as each is known, separated by
    /// ` | `.
    pub fn describe(&self, offset: usize) -> String {
        let mut text = format!("{} byte {offset}", self.contract);
        match self.opcode_at(offset) {
            Some(opcode) => text.push_str(&format!(" | opcode #{} {}", opcode.index, opcode.name)),
            None => return format!("{text} | outside the script"),
        }
        let statement = |line: &SourceLine| {
            if line.line == line.end_line {
                format!("line {}: {}", line.line, line.text)
            } else {
                format!("lines {}-{}: {}", line.line, line.end_line, line.text)
            }
        };
        text.push_str(&match self.place_at(offset) {
            Place::Frame => " | state frame".to_string(),
            Place::Dispatcher => " | dispatcher".to_string(),
            Place::Prologue { entry } => format!(" | {entry} | argument size checks"),
            Place::Statement { entry, line } => format!(" | {entry} | {}", statement(&line)),
            Place::Glue { entry, after } => {
                format!(" | {entry} | glue after {}", statement(&after))
            }
            Place::Epilogue { entry } => format!(" | {entry} | clean-up"),
        });
        if let Some(rule) = self
            .opcode_at(offset)
            .and_then(|opcode| self.rule_at(opcode.offset))
        {
            text.push_str(&format!(" | rule {}", rule.id));
        }
        text
    }
}

/// Number of opcodes in the script of a pay-to-script-hash coin: `OpBlake2b`, the push of the
/// hash and `OpEqual` (rusty-kaspa a41a333 crypto/txscript/src/standard.rs:34-38).
pub const P2SH_SCRIPT_OPCODES: usize = 3;

/// The ordinal, inside the redeem script, of the last opcode the engine logged for a
/// pay-to-script-hash input.
///
/// The engine writes one log line per opcode it parses, before running it, skipped branches
/// included (rusty-kaspa a41a333 crypto/txscript/src/lib.rs:612-613, 639-671). For a
/// pay-to-script-hash input the log holds the pushes of the signature script, then the
/// opcodes of the coin's own script, then the redeem script. `None` when the log ended before
/// the redeem script began.
pub fn last_redeem_opcode_index(
    log_lines: usize,
    signature_script_opcodes: usize,
) -> Option<usize> {
    log_lines.checked_sub(signature_script_opcodes + P2SH_SCRIPT_OPCODES + 1)
}

/// The maps of the three contracts.
#[derive(Clone, Debug)]
pub struct SourceMap {
    contracts: [ContractMap; 3],
}

impl SourceMap {
    /// Compiles the three pinned sources with debug information, requires the result to equal
    /// the bytecode of `family`, and attaches the rule inventory.
    ///
    /// Fails when two statements of the debug information cover exactly the same bytes: the
    /// innermost statement of such a byte would be a guess.
    pub fn build(family: &Family) -> Result<Self> {
        let rules = load_rule_inventory()?;
        let mut maps = Vec::with_capacity(3);
        for contract in Contract::ALL {
            let source = refdata::load_sil_source(contract)?;
            let compiled = compile_source(contract, &source, true)?;
            if compiled.bytecode != family.bytecode(contract) {
                return Err(Error::Compile {
                    contract: contract.name(),
                    message: format!(
                        "the source compiles to {} bytes, not to the {} bytes of the artifact",
                        compiled.bytecode.len(),
                        family.bytecode(contract).len()
                    ),
                });
            }
            if let Some((first, second)) = statements_with_one_byte_range(&compiled.steps) {
                return Err(Error::Compile {
                    contract: contract.name(),
                    message: format!(
                        "the debug information gives the bytes {}..{} to the statements of line {} and of line {}",
                        first.start, first.end, first.line, second.line
                    ),
                });
            }
            let opcodes = disassemble(&compiled.bytecode)?;
            let rules: Vec<Rule> = rules
                .iter()
                .filter(|rule| rule.contract == contract)
                .cloned()
                .collect();
            let mut rule_at = BTreeMap::new();
            for (position, rule) in rules.iter().enumerate() {
                for offset in &rule.offsets {
                    rule_at.insert(*offset, position);
                }
            }
            maps.push(ContractMap {
                contract,
                source,
                bytecode: compiled.bytecode,
                state_span: family.state_span(contract),
                opcodes,
                steps: compiled.steps,
                entries: compiled.entries,
                rules,
                rule_at,
            });
        }
        let contracts: [ContractMap; 3] = maps.try_into().expect("one map per contract");
        Ok(Self { contracts })
    }

    /// The source map of the pinned family, built once per process.
    ///
    /// # Panics
    ///
    /// Panics when the reference or the rule inventory is not available, or when the pinned
    /// sources do not compile to the pinned bytecode. Use [`SourceMap::build`] for the error.
    pub fn pinned() -> &'static SourceMap {
        static MAP: OnceLock<SourceMap> = OnceLock::new();
        MAP.get_or_init(|| {
            SourceMap::build(Family::pinned())
                .unwrap_or_else(|error| panic!("the source map of the pinned family: {error}"))
        })
    }

    /// The map of one contract.
    pub fn contract(&self, contract: Contract) -> &ContractMap {
        &self.contracts[contract.index()]
    }

    /// The rule with the given id, in whichever contract it belongs to.
    pub fn rule(&self, id: &str) -> Option<&Rule> {
        self.contracts.iter().find_map(|map| map.rule(id))
    }
}

/// Two statement steps with the same non-empty byte range, if there are any.
fn statements_with_one_byte_range(steps: &[SourceStep]) -> Option<(&SourceStep, &SourceStep)> {
    let mut seen: BTreeMap<(usize, usize), &SourceStep> = BTreeMap::new();
    for step in steps {
        if step.kind != StepKind::Statement || step.start >= step.end {
            continue;
        }
        if let Some(first) = seen.insert((step.start, step.end), step) {
            return Some((first, step));
        }
    }
    None
}

/// The output of one compilation, in owned form.
#[derive(Clone, Debug)]
pub struct CompiledSource {
    /// The compiled script with the constructor placeholders as state.
    pub bytecode: Vec<u8>,
    /// The recorded statements.
    pub steps: Vec<SourceStep>,
    /// The byte ranges of the entries.
    pub entries: Vec<EntryRange>,
}

/// A zero value for one constructor parameter, as Argent passes when it compiles the
/// template of an actor: zero bytes for byte arrays and public keys, 0 for numbers and single
/// bytes (argent 9a9f4b1 src/compiler/codegen/emitter.rs:2691-2756). The constructor
/// parameters of the generated sources are exactly the state fields, so the values land in
/// the state span and nowhere else.
fn placeholder(contract: Contract, name: &str, type_ref: &TypeRef) -> Result<Expr<'static>> {
    match (&type_ref.base, type_ref.array_dims.as_slice()) {
        (TypeBase::Byte, [ArrayDim::Fixed(len)]) => Ok(Expr::bytes(vec![0; *len])),
        (TypeBase::Pubkey, []) => Ok(Expr::bytes(vec![0; 32])),
        (TypeBase::Int, []) => Ok(Expr::int(0)),
        (TypeBase::Byte, []) => Ok(Expr::byte(0)),
        _ => Err(Error::Compile {
            contract: contract.name(),
            message: format!(
                "no placeholder for constructor parameter `{name}` of type `{}`",
                type_ref.type_name()
            ),
        }),
    }
}

/// Compiles one generated source with the SilverScript compiler
/// (silverscript 3ed9733 silverscript-lang/src/compiler/mod.rs:86-90, 123-133), with or
/// without debug information. Without it the lists of steps and entries are empty.
pub fn compile_source(
    contract: Contract,
    source: &str,
    record_debug_info: bool,
) -> Result<CompiledSource> {
    let compile_error = |error: &dyn std::fmt::Display| Error::Compile {
        contract: contract.name(),
        message: error.to_string(),
    };
    let ast = parse_contract_ast(source).map_err(|error| compile_error(&error))?;
    let mut args = Vec::with_capacity(ast.params.len());
    for param in &ast.params {
        args.push(placeholder(contract, &param.name, &param.type_ref)?);
    }
    let options = CompileOptions {
        record_debug_infos: record_debug_info,
        ..Default::default()
    };
    let compiled =
        compile_contract(source, &args, options).map_err(|error| compile_error(&error))?;
    let Some(debug_info) = compiled.debug_info.as_ref() else {
        if record_debug_info {
            return Err(compile_error(&"the compiler returned no debug information"));
        }
        return Ok(CompiledSource {
            bytecode: compiled.bytecode.clone(),
            steps: Vec::new(),
            entries: Vec::new(),
        });
    };
    let steps = debug_info
        .steps
        .iter()
        .map(|step| SourceStep {
            start: step.bytecode_start,
            end: step.bytecode_end,
            line: step.span.line,
            column: step.span.col,
            end_line: step.span.end_line,
            end_column: step.span.end_col,
            call_depth: step.call_depth,
            kind: match &step.kind {
                DebugStepKind::Source {} => StepKind::Statement,
                DebugStepKind::InlineCallEnter { callee } => StepKind::InlineEnter(callee.clone()),
                DebugStepKind::InlineCallExit { callee } => StepKind::InlineExit(callee.clone()),
            },
        })
        .collect();
    let entries = debug_info
        .functions
        .iter()
        .map(|function| EntryRange {
            name: function.name.clone(),
            start: function.bytecode_start,
            end: function.bytecode_end,
        })
        .collect();
    Ok(CompiledSource {
        bytecode: compiled.bytecode.clone(),
        steps,
        entries,
    })
}

/// Path of the rule inventory in the workspace: `data/rule-inventory.json` next to the
/// `crates` directory.
pub fn rule_inventory_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("data")
        .join("rule-inventory.json")
}

#[derive(Deserialize)]
struct RawReach {
    #[serde(default)]
    bytecode_at: Vec<usize>,
}

#[derive(Deserialize)]
struct RawRule {
    rule_id: String,
    contract: String,
    entry: String,
    #[serde(default)]
    check_opcode: Option<String>,
    #[serde(default)]
    sil_line: Option<String>,
    #[serde(default)]
    meaning: String,
    #[serde(default)]
    bytecode_at: Vec<usize>,
    #[serde(default)]
    also_reached_from: Vec<RawReach>,
}

/// Reads the rule inventory: one record per rule of the three contracts, with the byte offset
/// of every opcode at which the rule refuses.
pub fn load_rule_inventory() -> Result<Vec<Rule>> {
    let path = rule_inventory_path();
    let json = fs::read_to_string(&path).map_err(|source| Error::Io {
        path: path.clone(),
        source,
    })?;
    let root: serde_json::Value = serde_json::from_str(&json).map_err(|source| Error::Json {
        path: path.clone(),
        source,
    })?;
    let records = root
        .get("rules")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::Data {
            path: path.clone(),
            message: "no `rules` array".to_string(),
        })?;
    let mut rules = Vec::with_capacity(records.len());
    for record in records {
        let raw: RawRule =
            serde_json::from_value(record.clone()).map_err(|source| Error::Json {
                path: path.clone(),
                source,
            })?;
        let contract = Contract::from_name(&raw.contract).ok_or_else(|| Error::Data {
            path: path.clone(),
            message: format!(
                "rule `{}` names the unknown contract `{}`",
                raw.rule_id, raw.contract
            ),
        })?;
        let mut offsets = raw.bytecode_at;
        offsets.extend(
            raw.also_reached_from
                .into_iter()
                .flat_map(|reach| reach.bytecode_at),
        );
        rules.push(Rule {
            id: raw.rule_id,
            contract,
            entry: raw.entry,
            check_opcode: raw.check_opcode,
            sil_line: raw.sil_line,
            meaning: raw.meaning,
            offsets,
            record: record.clone(),
        });
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(kind: StepKind, start: usize, end: usize, line: u32) -> SourceStep {
        SourceStep {
            start,
            end,
            line,
            column: 1,
            end_line: line,
            end_column: 2,
            call_depth: 0,
            kind,
        }
    }

    #[test]
    fn two_statements_with_one_byte_range_are_found() {
        let statement = |start, end, line| step(StepKind::Statement, start, end, line);
        // Nested and adjacent statements are fine; so are empty steps and markers at the
        // same place.
        let fine = [
            statement(10, 20, 1),
            statement(12, 20, 2),
            statement(20, 30, 3),
            statement(30, 30, 4),
            statement(30, 30, 5),
            step(StepKind::InlineEnter("f".to_string()), 10, 20, 6),
        ];
        assert!(statements_with_one_byte_range(&fine).is_none());

        // The same range twice: reported with both statements, in recording order.
        let tied = [
            statement(10, 20, 1),
            statement(12, 20, 2),
            statement(10, 20, 7),
        ];
        let (first, second) = statements_with_one_byte_range(&tied).expect("a tie");
        assert_eq!((first.line, second.line), (1, 7));
    }
}
