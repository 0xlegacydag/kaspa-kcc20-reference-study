//! The mutation mode: the same checks against a weakened contract.
//!
//! A check that names the rule that refuses says nothing about the checks next to it: would
//! another rule have refused the same transaction, or was this rule the only guard? The
//! mutation mode answers that by running the cases again with one refusing opcode of one
//! contract neutralised, or against a contract rebuilt from changed source, and recording
//! what the engine says then.
//!
//! The mode is set by environment variables. They are read once per process, by the default
//! harness ([`crate::Harness::pinned`]) and by the helpers of [`crate::Case`]. With none of
//! them set, nothing in this crate behaves differently.
//!
//! | Variable | Effect |
//! |---|---|
//! | [`MUTANT_ENV`] `=<Contract>@<byte offset>` | the default family is the pinned one with the refusing opcode at that offset of that contract's bytecode neutralised |
//! | [`ARTIFACT_ENV`] `=<path>` | the default family is built from that `artifact.json` |
//! | [`OBSERVE_ENV`] `=1` | no helper panics on a failed expectation; the result line says what was observed |
//! | [`ONLY_CASES_ENV`] `=<path>` | only the cases listed in that file run; helper calls for other cases return a placeholder |
//! | [`FAST_ENV`] `=1` | only the run of every input by itself is made |
//! | [`UNSELECTED_ENV`] `=pinned` | with a case list: a case that is not selected runs as in an ordinary run, on the pinned family and without a line |
//!
//! Neutralised means: `OpVerify` becomes `OpDrop`, `OpEqualVerify` and `OpNumEqualVerify`
//! become `Op2Drop`. The replacement takes the same items off the stack and never refuses.
//! The bytecode keeps its length, so the source map and the rule inventory still name the
//! place of every other refusal; the template hash of the contract is recomputed and flows
//! into the states and hidden arguments of the family (`Family::with_bytecode`).

use std::{collections::BTreeSet, path::Path, sync::OnceLock};

use kcc20_family::{Contract, Family, refdata, sourcemap};
use serde::Serialize;
use serde_json::json;

/// `<Contract>@<byte offset>`: the refusing opcode to neutralise, for example `KCC20@2203`.
pub const MUTANT_ENV: &str = "CHECKS_MUTANT";

/// Path of an `artifact.json` the default family is built from.
pub const ARTIFACT_ENV: &str = "CHECKS_ARTIFACT";

/// `1`: helpers record a failed expectation and do not panic.
pub const OBSERVE_ENV: &str = "CHECKS_OBSERVE";

/// Path of a text file with one `<test binary name>::<case id>` per line.
pub const ONLY_CASES_ENV: &str = "CHECKS_ONLY_CASES";

/// `1`: script verdicts only.
pub const FAST_ENV: &str = "CHECKS_FAST";

/// What a helper does for a case the list of [`ONLY_CASES_ENV`] does not select. `skip`
/// (the default): it returns a placeholder at once. `pinned`: it runs the case as an
/// ordinary run would, on the pinned family and without a result line, so that the
/// assertions a test makes on the returned outcome hold and the test gets to its selected
/// case.
pub const UNSELECTED_ENV: &str = "CHECKS_UNSELECTED";

/// What an outcome of the fast mode carries in `budgets.note` and `consensus.harness_error`.
pub const FAST_NOTE: &str = "CHECKS_FAST: only the run of every input by itself was made; \
                             no budget was committed and no consensus, block or mempool rule \
                             was evaluated";

/// What the placeholder outcome of a case that was not selected carries in
/// `scripts.not_run`, `budgets.note` and `consensus.harness_error`.
pub const SKIPPED_NOTE: &str = "CHECKS_ONLY_CASES: the case is not selected; nothing was run";

/// The refusing opcodes the mutation mode neutralises: the opcode byte, its name, the byte
/// that replaces it, and the name of the replacement (rusty-kaspa a41a333
/// crypto/txscript/src/opcodes/mod.rs: OpVerify 0x69, OpEqualVerify 0x88, OpNumEqualVerify
/// 0x9d, Op2Drop 0x6d, OpDrop 0x75).
pub const NEUTRALISED: [(u8, &str, u8, &str); 3] = [
    (0x69, "OpVerify", 0x75, "OpDrop"),
    (0x88, "OpEqualVerify", 0x6d, "Op2Drop"),
    (0x9d, "OpNumEqualVerify", 0x6d, "Op2Drop"),
];

/// Which family the default harness uses instead of the pinned one. It is written into
/// every result line of the process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FamilyLabel {
    /// The pinned family with one refusing opcode neutralised.
    Mutant {
        /// `<Contract>@<byte offset>`, as the variable gave it.
        label: String,
        /// The contract whose bytecode was changed.
        contract: String,
        /// The byte offset of the changed opcode in that bytecode.
        byte_offset: usize,
        /// The opcode that was there.
        from: String,
        /// The opcode that is there now.
        to: String,
    },
    /// A family built from another artifact.
    Artifact {
        /// The path, as the variable gave it.
        label: String,
        /// The id the artifact states.
        artifact_id: String,
    },
}

impl FamilyLabel {
    /// The label: `KCC20@2203`, or the path of the artifact.
    pub fn label(&self) -> &str {
        match self {
            Self::Mutant { label, .. } | Self::Artifact { label, .. } => label,
        }
    }
}

/// The mutation mode of a process.
#[derive(Clone, Debug)]
pub struct Mode {
    /// The family of the default harness, when it is not the pinned one.
    pub family: Option<Family>,
    /// What that family is.
    pub family_label: Option<FamilyLabel>,
    /// A failed expectation is recorded and does not panic.
    pub observe: bool,
    /// Only the run of every input by itself is made.
    pub fast: bool,
    /// The selected cases, each as `<test binary name>::<case id>`. `None`: all cases run.
    pub only_cases: Option<BTreeSet<String>>,
    /// A case that is not selected runs on the pinned family, without a result line,
    /// instead of returning a placeholder.
    pub unselected_on_pinned: bool,
}

impl Mode {
    /// No mutation mode: the behaviour of a process without any of the variables.
    pub fn plain() -> Self {
        Self {
            family: None,
            family_label: None,
            observe: false,
            fast: false,
            only_cases: None,
            unselected_on_pinned: false,
        }
    }

    /// Whether nothing is set.
    pub fn is_plain(&self) -> bool {
        self.family.is_none() && !self.observe && !self.fast && self.only_cases.is_none()
    }

    /// The mode the environment of the process asks for.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// The mode a set of variables asks for; `lookup` answers for one variable name.
    ///
    /// An empty value is the same as no value. Everything that cannot be done as asked is
    /// an error: a run that silently fell back to the pinned contracts would report every
    /// rule as backed by another.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let value = |name: &str| lookup(name).filter(|value| !value.trim().is_empty());
        let flag = |name: &str| match value(name).as_deref().map(str::trim) {
            None | Some("0") => Ok(false),
            Some("1") => Ok(true),
            Some(other) => Err(format!("{name} must be 1 or 0, it is `{other}`")),
        };

        let mut mode = Self::plain();
        mode.observe = flag(OBSERVE_ENV)?;
        mode.fast = flag(FAST_ENV)?;
        match (value(MUTANT_ENV), value(ARTIFACT_ENV)) {
            (Some(_), Some(_)) => {
                return Err(format!(
                    "{MUTANT_ENV} and {ARTIFACT_ENV} are both set; a run has one family"
                ));
            }
            (Some(mutant), None) => {
                let (family, label) = mutant_family(Family::pinned(), mutant.trim())
                    .map_err(|error| format!("{MUTANT_ENV}={mutant}: {error}"))?;
                mode.family = Some(family);
                mode.family_label = Some(label);
            }
            (None, Some(path)) => {
                let (family, label) = artifact_family(Path::new(path.trim()))
                    .map_err(|error| format!("{ARTIFACT_ENV}={path}: {error}"))?;
                mode.family = Some(family);
                mode.family_label = Some(label);
            }
            (None, None) => {}
        }
        mode.unselected_on_pinned = match value(UNSELECTED_ENV).as_deref().map(str::trim) {
            None | Some("skip") => false,
            Some("pinned") => true,
            Some(other) => {
                return Err(format!(
                    "{UNSELECTED_ENV} must be skip or pinned, it is `{other}`"
                ));
            }
        };
        if let Some(path) = value(ONLY_CASES_ENV) {
            let text = std::fs::read_to_string(path.trim())
                .map_err(|error| format!("{ONLY_CASES_ENV}={path}: {error}"))?;
            mode.only_cases = Some(
                parse_cases(&text).map_err(|error| format!("{ONLY_CASES_ENV}={path}: {error}"))?,
            );
        }
        Ok(mode)
    }

    /// Whether the case `case` of the test binary `binary` runs.
    pub fn selects(&self, binary: &str, case: &str) -> bool {
        match &self.only_cases {
            None => true,
            Some(cases) => cases.contains(&format!("{binary}::{case}")),
        }
    }

    /// The `mutation` value of a result line: `None` without a mutation mode. `judged` says
    /// how much of the expectation the helper could judge: `full`, `scripts_only` (the
    /// fast mode judged the scripts and nothing around them) or `not_at_all` (the fast mode
    /// has no answer to an expectation about a consensus, block or mempool rule).
    pub fn record(&self, judged: &str) -> Option<serde_json::Value> {
        if self.is_plain() {
            return None;
        }
        Some(json!({
            "family": self.family_label,
            "observe": self.observe,
            "fast": self.fast,
            "only_cases": self.only_cases.is_some(),
            "judged": judged,
        }))
    }
}

/// The lines of a case list: one `<test binary name>::<case id>` per line; empty lines and
/// lines starting with `#` are skipped. A case id is taken as it is, inner spaces and `::`
/// included; only the line ending and surrounding blanks are dropped.
pub fn parse_cases(text: &str) -> Result<BTreeSet<String>, String> {
    let mut cases = BTreeSet::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.split_once("::") {
            Some((binary, case)) if !binary.is_empty() && !case.is_empty() => {
                cases.insert(line.to_string());
            }
            _ => {
                return Err(format!(
                    "line {}: `{line}` is not `<test binary name>::<case id>`",
                    number + 1
                ));
            }
        }
    }
    Ok(cases)
}

/// `family` with the refusing opcode named by `spec` (`<Contract>@<byte offset>`)
/// neutralised, and the label of the result.
///
/// The offset must be the first byte of an opcode of the contract's bytecode, and that
/// opcode must be one of [`NEUTRALISED`]. A byte of that value inside pushed data is not
/// an opcode and is refused.
pub fn mutant_family(family: &Family, spec: &str) -> Result<(Family, FamilyLabel), String> {
    let (contract_name, offset_text) = spec.split_once('@').ok_or_else(|| {
        "expected `<Contract>@<byte offset>`, for example `KCC20@2203`".to_string()
    })?;
    let contract = Contract::from_name(contract_name)
        .ok_or_else(|| format!("`{contract_name}` is not one of KCC20, PublicMint, TokenSeed"))?;
    let offset: usize = offset_text
        .parse()
        .map_err(|_| format!("`{offset_text}` is not a byte offset"))?;

    let mut bytecode = family.bytecode(contract).to_vec();
    let opcodes = sourcemap::disassemble(&bytecode)
        .map_err(|error| format!("the bytecode of {contract_name} cannot be read: {error}"))?;
    let Some(opcode) = opcodes.iter().find(|opcode| opcode.offset == offset) else {
        return Err(format!(
            "no opcode of {contract_name} starts at byte {offset} (the bytecode has {} bytes)",
            bytecode.len()
        ));
    };
    let Some((_, from, replacement, to)) = NEUTRALISED
        .iter()
        .find(|(code, _, _, _)| *code == opcode.code)
    else {
        return Err(format!(
            "the opcode at byte {offset} of {contract_name} is {} (0x{:02x}): only OpVerify, \
             OpEqualVerify and OpNumEqualVerify can be neutralised",
            opcode.name, opcode.code
        ));
    };
    if family.state_span(contract).contains(&offset) {
        return Err(format!(
            "byte {offset} of {contract_name} is inside the state of the coin, not code"
        ));
    }
    bytecode[offset] = *replacement;
    let mutant = family
        .with_bytecode(contract, bytecode)
        .map_err(|error| format!("the changed bytecode is not accepted: {error}"))?;
    let label = FamilyLabel::Mutant {
        label: format!("{contract_name}@{offset}"),
        contract: contract_name.to_string(),
        byte_offset: offset,
        from: (*from).to_string(),
        to: (*to).to_string(),
    };
    Ok((mutant, label))
}

/// The family of the artifact at `path`, and the label of the result.
pub fn artifact_family(path: &Path) -> Result<(Family, FamilyLabel), String> {
    let artifact = refdata::load_artifact(path).map_err(|error| error.to_string())?;
    let artifact_id = artifact.id.clone();
    let family = Family::from_artifact(artifact).map_err(|error| error.to_string())?;
    let label = FamilyLabel::Artifact {
        label: path.display().to_string(),
        artifact_id,
    };
    Ok((family, label))
}

#[cfg(test)]
thread_local! {
    /// The mode a unit test put in place of the mode of the process, on its own thread.
    static OVERRIDE: std::cell::Cell<Option<&'static Mode>> = const { std::cell::Cell::new(None) };
}

/// Runs `body` with `mode` in place of the mode of the process, on this thread only.
#[cfg(test)]
pub(crate) fn with_mode<R>(mode: Mode, body: impl FnOnce() -> R) -> R {
    struct Restore(Option<&'static Mode>);
    impl Drop for Restore {
        fn drop(&mut self) {
            OVERRIDE.with(|cell| cell.set(self.0));
        }
    }
    let mode: &'static Mode = Box::leak(Box::new(mode));
    let _restore = Restore(OVERRIDE.with(|cell| cell.replace(Some(mode))));
    body()
}

thread_local! {
    /// Set while a helper runs the stand-in of a case that is not selected.
    static STANDING_IN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `body` as the stand-in of a case that is not selected: inside it no helper asks
/// the case list again.
pub(crate) fn standing_in<R>(body: impl FnOnce() -> R) -> R {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            STANDING_IN.with(|cell| cell.set(self.0));
        }
    }
    let _restore = Restore(STANDING_IN.with(|cell| cell.replace(true)));
    body()
}

/// Whether the running helper call is the stand-in of a case that is not selected.
pub(crate) fn is_standing_in() -> bool {
    STANDING_IN.with(std::cell::Cell::get)
}

/// The mutation mode of this process, read from the environment at the first call.
///
/// # Panics
///
/// Panics, at every call, when the variables ask for something that cannot be done: an
/// offset that holds none of the three opcodes, an artifact that cannot be read, a case
/// list with a malformed line.
pub fn mode() -> &'static Mode {
    #[cfg(test)]
    if let Some(mode) = OVERRIDE.with(std::cell::Cell::get) {
        return mode;
    }
    static MODE: OnceLock<Mode> = OnceLock::new();
    MODE.get_or_init(|| {
        Mode::from_env().unwrap_or_else(|error| panic!("the mutation mode cannot be set: {error}"))
    })
}

/// The family the default harness runs on: the pinned one, or the one the mutation mode
/// puts in its place. A test that builds bytes by hand (a call, a redeem script, a lock)
/// takes them from this family and not from `Family::pinned()`, so that the bytes still
/// fit the contracts when a mutant is run.
pub fn family() -> &'static Family {
    mode().family.as_ref().unwrap_or_else(|| Family::pinned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// The mode a list of variables asks for.
    fn mode_of(variables: &[(&str, &str)]) -> Result<Mode, String> {
        Mode::from_lookup(|name| {
            variables
                .iter()
                .find(|(variable, _)| *variable == name)
                .map(|(_, value)| (*value).to_string())
        })
    }

    /// The offset of the first opcode with this byte in the pinned bytecode of `contract`.
    fn first_opcode(contract: Contract, code: u8) -> usize {
        sourcemap::disassemble(Family::pinned().bytecode(contract))
            .expect("the pinned bytecode is a script")
            .into_iter()
            .find(|opcode| opcode.code == code)
            .unwrap_or_else(|| panic!("{contract} has no opcode 0x{code:02x}"))
            .offset
    }

    #[test]
    fn without_variables_nothing_is_set() {
        let mode = mode_of(&[]).unwrap();
        assert!(mode.is_plain());
        assert!(mode.family.is_none() && mode.family_label.is_none());
        assert!(mode.selects("any", "case"));
        assert_eq!(mode.record("full"), None);
        // An empty value and a zero are no value.
        let mode = mode_of(&[
            (MUTANT_ENV, ""),
            (ARTIFACT_ENV, " "),
            (OBSERVE_ENV, "0"),
            (FAST_ENV, ""),
            (ONLY_CASES_ENV, ""),
        ])
        .unwrap();
        assert!(mode.is_plain());
    }

    #[test]
    fn a_mutant_differs_from_the_pinned_family_in_one_opcode_and_its_hash() {
        let pinned = Family::pinned();
        for contract in Contract::ALL {
            for (code, from, replacement, to) in NEUTRALISED {
                let offset = first_opcode(contract, code);
                let spec = format!("{}@{offset}", contract.name());
                let mode = mode_of(&[(MUTANT_ENV, &spec)]).unwrap();
                let family = mode.family.as_ref().expect("a mutant family");

                let before = pinned.bytecode(contract);
                let after = family.bytecode(contract);
                assert_eq!(before.len(), after.len(), "{spec}");
                let changed: Vec<usize> = (0..before.len())
                    .filter(|index| before[*index] != after[*index])
                    .collect();
                assert_eq!(changed, vec![offset], "{spec}");
                assert_eq!(
                    (before[offset], after[offset]),
                    (code, replacement),
                    "{spec}"
                );
                assert_ne!(
                    pinned.template_hash(contract),
                    family.template_hash(contract),
                    "{spec}: the template hash follows the bytes"
                );
                for other in Contract::ALL.into_iter().filter(|other| *other != contract) {
                    assert_eq!(pinned.bytecode(other), family.bytecode(other), "{spec}");
                }
                assert_eq!(family.replaced(), &[contract], "{spec}");
                assert_eq!(
                    mode.family_label,
                    Some(FamilyLabel::Mutant {
                        label: spec.clone(),
                        contract: contract.name().to_string(),
                        byte_offset: offset,
                        from: from.to_string(),
                        to: to.to_string(),
                    })
                );
                let record = mode.record("full").expect("a label for the result lines");
                assert_eq!(record["family"]["kind"], "mutant");
                assert_eq!(record["family"]["label"], spec.as_str());
                assert_eq!(record["family"]["byte_offset"], offset);
                assert_eq!(record["judged"], "full");
            }
        }
    }

    #[test]
    fn a_mutant_that_cannot_be_made_is_an_error() {
        let pinned = Family::pinned();
        let bytecode = pinned.bytecode(Contract::Kcc20);
        let opcodes = sourcemap::disassemble(bytecode).unwrap();

        // An opcode that is none of the three.
        let other = opcodes
            .iter()
            .find(|opcode| {
                NEUTRALISED
                    .iter()
                    .all(|(code, _, _, _)| *code != opcode.code)
            })
            .unwrap();
        let error = mode_of(&[(MUTANT_ENV, &format!("KCC20@{}", other.offset))]).unwrap_err();
        assert!(error.contains("only OpVerify"), "{error}");

        // A byte with the value of OpVerify that is data of a push, not an opcode.
        let starts: BTreeSet<usize> = opcodes.iter().map(|opcode| opcode.offset).collect();
        let inside_a_push = (0..bytecode.len()).find(|offset| {
            !starts.contains(offset)
                && NEUTRALISED
                    .iter()
                    .any(|(code, _, _, _)| *code == bytecode[*offset])
        });
        if let Some(offset) = inside_a_push {
            let error = mode_of(&[(MUTANT_ENV, &format!("KCC20@{offset}"))]).unwrap_err();
            assert!(error.contains("no opcode of KCC20 starts"), "{error}");
        }

        for (spec, expected) in [
            (
                format!("KCC20@{}", bytecode.len()),
                "no opcode of KCC20 starts",
            ),
            ("KCC20".to_string(), "expected `<Contract>@<byte offset>`"),
            ("KCC20@".to_string(), "is not a byte offset"),
            ("KCC20@-1".to_string(), "is not a byte offset"),
            ("Kcc20@162".to_string(), "is not one of KCC20"),
            ("@162".to_string(), "is not one of KCC20"),
        ] {
            let error = mode_of(&[(MUTANT_ENV, &spec)]).unwrap_err();
            assert!(error.contains(expected), "{spec}: {error}");
            assert!(error.starts_with(MUTANT_ENV), "{error}");
        }
    }

    #[test]
    fn an_artifact_gives_the_family_of_that_file() {
        let path = refdata::artifact_path();
        let text = path.to_string_lossy().into_owned();
        let mode = mode_of(&[(ARTIFACT_ENV, &text)]).unwrap();
        let family = mode.family.as_ref().expect("a family of the artifact");
        for contract in Contract::ALL {
            assert_eq!(
                family.bytecode(contract),
                Family::pinned().bytecode(contract)
            );
            assert_eq!(
                family.template_hash(contract),
                Family::pinned().template_hash(contract)
            );
        }
        assert!(family.replaced().is_empty());
        assert_eq!(
            mode.family_label,
            Some(FamilyLabel::Artifact {
                label: path.display().to_string(),
                artifact_id: refdata::PINNED_ARTIFACT_ID.to_string(),
            })
        );
        assert_eq!(mode.record("full").unwrap()["family"]["kind"], "artifact");

        let missing = path.with_file_name("no-such-artifact.json");
        let error = mode_of(&[(ARTIFACT_ENV, &missing.to_string_lossy())]).unwrap_err();
        assert!(error.starts_with(ARTIFACT_ENV), "{error}");

        // A file that is not an artifact.
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"{\"schema_version\": 1}").unwrap();
        let error = mode_of(&[(ARTIFACT_ENV, &file.path().to_string_lossy())]).unwrap_err();
        assert!(error.starts_with(ARTIFACT_ENV), "{error}");

        // One family per run.
        let error = mode_of(&[(ARTIFACT_ENV, &text), (MUTANT_ENV, "KCC20@162")]).unwrap_err();
        assert!(error.contains("both set"), "{error}");
    }

    #[test]
    fn the_two_flags_take_one_and_zero_only() {
        for name in [OBSERVE_ENV, FAST_ENV] {
            let on = mode_of(&[(name, "1")]).unwrap();
            assert_eq!(
                (on.observe, on.fast),
                (name == OBSERVE_ENV, name == FAST_ENV)
            );
            assert!(!on.is_plain());
            let record = on.record("scripts_only").unwrap();
            assert_eq!(record["observe"], name == OBSERVE_ENV);
            assert_eq!(record["fast"], name == FAST_ENV);
            assert_eq!(record["family"], serde_json::Value::Null);
            assert_eq!(record["only_cases"], false);
            for wrong in ["true", "yes", "2"] {
                let error = mode_of(&[(name, wrong)]).unwrap_err();
                assert!(error.starts_with(name), "{error}");
            }
        }
    }

    #[test]
    fn a_case_list_selects_its_lines_and_nothing_else() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(
            b"# cases of one rule\r\n\
              selfcheck::transfer/one token more\r\n\
              \n\
              attribution::line/KCC20 175 sum\n\
              port::odd::id with colons  \n",
        )
        .unwrap();
        let mode = mode_of(&[(ONLY_CASES_ENV, &file.path().to_string_lossy())]).unwrap();
        assert!(!mode.is_plain());
        assert_eq!(mode.only_cases.as_ref().map(BTreeSet::len), Some(3));
        assert!(mode.selects("selfcheck", "transfer/one token more"));
        assert!(mode.selects("attribution", "line/KCC20 175 sum"));
        assert!(mode.selects("port", "odd::id with colons"));
        // The same id in another binary, another id in the same binary, a comment.
        assert!(!mode.selects("attribution", "transfer/one token more"));
        assert!(!mode.selects("selfcheck", "transfer/one token"));
        assert!(!mode.selects("#", "cases of one rule"));
        assert_eq!(mode.record("full").unwrap()["only_cases"], true);

        // An empty list selects nothing; that is not the same as no list.
        let empty = tempfile::NamedTempFile::new().unwrap();
        let mode = mode_of(&[(ONLY_CASES_ENV, &empty.path().to_string_lossy())]).unwrap();
        assert!(!mode.selects("selfcheck", "transfer/one token more"));

        assert!(parse_cases("selfcheck\n").unwrap_err().contains("line 1"));
        assert!(
            parse_cases("a::b\n::case\n")
                .unwrap_err()
                .contains("line 2")
        );
        assert!(parse_cases("binary::\n").is_err());
        let missing = file.path().with_file_name("no-such-list.txt");
        let error = mode_of(&[(ONLY_CASES_ENV, &missing.to_string_lossy())]).unwrap_err();
        assert!(error.starts_with(ONLY_CASES_ENV), "{error}");

        // What becomes of the other cases.
        assert!(!mode.unselected_on_pinned);
        assert!(
            !mode_of(&[(UNSELECTED_ENV, "skip")])
                .unwrap()
                .unselected_on_pinned
        );
        assert!(
            mode_of(&[(UNSELECTED_ENV, "pinned")])
                .unwrap()
                .unselected_on_pinned
        );
        let error = mode_of(&[(UNSELECTED_ENV, "1")]).unwrap_err();
        assert!(error.starts_with(UNSELECTED_ENV), "{error}");
    }

    #[test]
    fn a_mode_put_in_place_by_a_test_ends_with_it() {
        assert!(
            mode().is_plain(),
            "the unit tests run without the variables"
        );
        let fast = Mode {
            fast: true,
            ..Mode::plain()
        };
        with_mode(fast, || {
            assert!(mode().fast);
            assert!(std::ptr::eq(family(), Family::pinned()));
        });
        assert!(mode().is_plain());

        let offset = first_opcode(Contract::Kcc20, 0x69);
        let mutant = mode_of(&[(MUTANT_ENV, &format!("KCC20@{offset}"))]).unwrap();
        with_mode(mutant, || {
            assert_eq!(family().bytecode(Contract::Kcc20)[offset], 0x75);
            assert_eq!(
                crate::Harness::pinned().family.bytecode(Contract::Kcc20)[offset],
                0x75,
                "the default harness runs on the mutant"
            );
        });
        assert_eq!(family().bytecode(Contract::Kcc20)[offset], 0x69);
    }
}
