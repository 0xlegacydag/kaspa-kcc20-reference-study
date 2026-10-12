//! The result files: one JSON line per assertion.
//!
//! Every `expect_*` helper appends one line to
//! `<target directory>/check-results/<test binary name>.jsonl`. The file is created empty
//! the first time a test binary writes to it, so it always holds the lines of one run of
//! that binary. Tests of one binary run on several threads of one process; a line is
//! written whole, under a lock.
//!
//! The directory can be set with the environment variable [`RESULTS_DIR_ENV`]. Without
//! it, the directory is found from the place of the running test executable
//! (`<target>/<profile>/deps/<name>-<hash>`), which follows `CARGO_TARGET_DIR` and
//! `--target-dir`.
//!
//! One process per binary is assumed, as `cargo test` runs them. A runner that starts one
//! process per test would leave only the lines of the last test in the file.

use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use serde::Serialize;

/// Environment variable that names the directory of the result files.
pub const RESULTS_DIR_ENV: &str = "CHECK_RESULTS_DIR";

/// Name of the directory inside the target directory.
pub const RESULTS_DIR_NAME: &str = "check-results";

/// Version of the line format. It is written into every line and raised when a field
/// changes its meaning or is removed. Added fields do not raise it.
pub const FORMAT: u32 = 2;

/// The directory the result files are written to.
pub fn results_dir() -> PathBuf {
    match std::env::var_os(RESULTS_DIR_ENV) {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => target_dir().join(RESULTS_DIR_NAME),
    }
}

/// The target directory of the build that produced the running executable.
fn target_dir() -> PathBuf {
    let from_executable = std::env::current_exe()
        .ok()
        .and_then(|path| target_dir_of_executable(&path));
    // The workspace's own target directory, two levels above this crate, when the
    // executable is not where cargo puts test binaries.
    from_executable.unwrap_or_else(|| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
    })
}

/// `<target>` for an executable at `<target>/<profile>/deps/<file>`.
fn target_dir_of_executable(executable: &Path) -> Option<PathBuf> {
    let deps = executable.parent()?;
    if deps.file_name()? != "deps" {
        return None;
    }
    Some(deps.parent()?.parent()?.to_path_buf())
}

/// The name of the running test binary without the hash cargo appends: `selfcheck` for
/// `selfcheck-0123456789abcdef.exe`.
pub fn binary_name() -> String {
    let stem = std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "unknown".to_string());
    strip_cargo_hash(&stem).to_string()
}

fn strip_cargo_hash(stem: &str) -> &str {
    match stem.rsplit_once('-') {
        Some((name, hash))
            if hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            name
        }
        _ => stem,
    }
}

/// The result file of the running test binary.
pub fn results_path() -> PathBuf {
    results_dir().join(format!("{}.jsonl", binary_name()))
}

/// The name of the running test, as the test runner names its thread. `None` on the main
/// thread, which is where tests run with `--test-threads=1`.
pub fn test_name() -> Option<String> {
    std::thread::current()
        .name()
        .filter(|name| *name != "main")
        .map(str::to_string)
}

struct Sink {
    path: PathBuf,
    file: File,
    lines_written: usize,
}

/// The number of lines this process has appended to its result file so far. The file never
/// holds more complete lines than this: it was emptied before the first of them.
pub fn lines_written() -> usize {
    SINK.get().map_or(0, |sink| {
        sink.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .lines_written
    })
}

static SINK: OnceLock<Mutex<Sink>> = OnceLock::new();

fn sink() -> &'static Mutex<Sink> {
    SINK.get_or_init(|| {
        let path = results_path();
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).unwrap_or_else(|error| {
                panic!(
                    "cannot create the results directory {}: {error}",
                    dir.display()
                )
            });
        }
        // `File::create` truncates: the file starts empty once per process.
        let file = File::create(&path).unwrap_or_else(|error| {
            panic!("cannot create the results file {}: {error}", path.display())
        });
        Mutex::new(Sink {
            path,
            file,
            lines_written: 0,
        })
    })
}

/// Appends one record as one line to the result file of the running test binary.
///
/// # Panics
///
/// Panics when the file cannot be written: a missing line would silently drop a case from
/// every later comparison.
pub fn append(record: &impl Serialize) {
    let mut line = serde_json::to_string(record).expect("a record holds only plain data");
    #[cfg(test)]
    if capture::take(&line) {
        return;
    }
    line.push('\n');
    // A panic while the lock is held cannot leave a half-written line: the line is written
    // with one call. A poisoned lock is therefore still usable.
    let mut sink = sink()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Sink {
        path,
        file,
        lines_written,
    } = &mut *sink;
    // Counted before it is written: a reader never finds more lines than the count.
    *lines_written += 1;
    file.write_all(line.as_bytes())
        .and_then(|()| file.flush())
        .unwrap_or_else(|error| {
            panic!(
                "cannot write to the results file {}: {error}",
                path.display()
            )
        });
}

/// One line of a check that has no engine run: a fact about the pinned bytes, the source
/// map or the rule inventory that a test established by reading them.
#[derive(Serialize)]
struct StructuralRecord<'a> {
    format: u32,
    binary: &'a str,
    test: Option<String>,
    case: &'a str,
    py_ids: &'a [&'a str],
    note: &'a str,
    kind: &'static str,
    helper: &'static str,
    passed: bool,
    failure: Option<&'a str>,
    mutation: Option<serde_json::Value>,
}

/// Appends a result line of kind `structural` for a check that ran no transaction: the
/// test looked at bytes, at the source or at the inventory, and its own assertions held
/// when it got here. The line has `passed: true` and no observed outcome; `note` says what
/// was established. Call it after the assertions, so a failing test leaves no line.
///
/// In a mutation run ([`crate::mutation`]) a case that is not selected leaves no line.
///
/// # Panics
///
/// Panics when the case id is empty, or when an id of `py_ids` is not in the list of ids
/// of the earlier suite ([`crate::python_ids`]), as [`crate::Case::py`] does.
pub fn record_structural(case_id: &str, py_ids: &[&str], note: &str) {
    assert!(!case_id.is_empty(), "a structural case needs an id");
    for id in py_ids {
        assert!(
            crate::python_ids::is_known(id),
            "case `{case_id}`: `{id}` is not the id of a check of the earlier Python suite \
             listed in data/python-check-ids.txt"
        );
    }
    let binary = binary_name();
    let mode = crate::mutation::mode();
    if !mode.selects(&binary, case_id) {
        return;
    }
    append(&StructuralRecord {
        format: FORMAT,
        binary: &binary,
        test: test_name(),
        case: case_id,
        py_ids,
        note,
        kind: "structural",
        helper: "record_structural",
        passed: true,
        failure: None,
        mutation: mode.record("full"),
    });
}

/// Writes a whole JSON document next to the result files, replacing an earlier one. Used
/// for measurements that are one document, not a list of cases.
///
/// # Panics
///
/// Panics when the file cannot be written.
pub fn write_document(file_name: &str, document: &impl Serialize) -> PathBuf {
    let dir = results_dir();
    fs::create_dir_all(&dir).unwrap_or_else(|error| {
        panic!(
            "cannot create the results directory {}: {error}",
            dir.display()
        )
    });
    let path = dir.join(file_name);
    let mut text =
        serde_json::to_string_pretty(document).expect("a document holds only plain data");
    text.push('\n');
    fs::write(&path, text)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
    path
}

/// Result lines of unit tests of this crate: kept in memory, away from the result files.
#[cfg(test)]
pub(crate) mod capture {
    use std::cell::RefCell;

    thread_local! {
        static LINES: RefCell<Option<Vec<serde_json::Value>>> = const { RefCell::new(None) };
    }

    /// Keeps `line` when the running thread captures its lines; says whether it did.
    pub(super) fn take(line: &str) -> bool {
        LINES.with(|lines| match lines.borrow_mut().as_mut() {
            Some(lines) => {
                lines.push(serde_json::from_str(line).expect("a result line is JSON"));
                true
            }
            None => false,
        })
    }

    /// Runs `body` and returns what it returns with the result lines it appended on this
    /// thread; none of them reaches a file.
    pub(crate) fn lines<R>(body: impl FnOnce() -> R) -> (R, Vec<serde_json::Value>) {
        let before = LINES.with(|lines| lines.borrow_mut().replace(Vec::new()));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
        let captured = LINES.with(|lines| std::mem::replace(&mut *lines.borrow_mut(), before));
        match result {
            Ok(value) => (value, captured.unwrap_or_default()),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_structural_line_has_its_keys_and_known_python_ids() {
        let py_id = "test_transfer.Conservation.test_one_output_holding_more_is_refused";
        let ((), lines) = capture::lines(|| {
            record_structural("structure/one", &[py_id], "read from the bytes");
            record_structural("structure/two", &[], "");
        });
        assert_eq!(lines.len(), 2);
        let line = &lines[0];
        assert_eq!(line["format"], FORMAT);
        assert_eq!(line["binary"], binary_name().as_str());
        assert_eq!(line["case"], "structure/one");
        assert_eq!(line["py_ids"], serde_json::json!([py_id]));
        assert_eq!(line["note"], "read from the bytes");
        assert_eq!(line["kind"], "structural");
        assert_eq!(line["helper"], "record_structural");
        assert_eq!(line["passed"], true);
        assert_eq!(line["failure"], serde_json::Value::Null);
        assert_eq!(line["mutation"], serde_json::Value::Null);
        assert!(line.get("test").is_some());
        assert!(line.get("inputs").is_none(), "no observed outcome");
        assert_eq!(lines[1]["py_ids"], serde_json::json!([]));

        let misspelt = std::panic::catch_unwind(|| {
            record_structural("structure/three", &["test_transfer.Nothing.test_x"], "")
        });
        assert!(misspelt.is_err(), "an unknown Python id stops the test");
        let unnamed = std::panic::catch_unwind(|| record_structural("", &[], ""));
        assert!(unnamed.is_err(), "a case needs an id");
    }

    #[test]
    fn a_structural_line_follows_the_case_selection_of_a_mutation_run() {
        use crate::mutation::{Mode, with_mode};
        let selected = format!("{}::structure/selected", binary_name());
        let mode = Mode {
            only_cases: Some([selected].into_iter().collect()),
            ..Mode::plain()
        };
        let ((), lines) = capture::lines(|| {
            with_mode(mode, || {
                record_structural("structure/selected", &[], "kept");
                record_structural("structure/other", &[], "dropped");
            })
        });
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["case"], "structure/selected");
        assert_eq!(lines[0]["mutation"]["only_cases"], true);
    }

    #[test]
    fn the_hash_cargo_appends_is_stripped() {
        assert_eq!(strip_cargo_hash("selfcheck-0123456789abcdef"), "selfcheck");
        assert_eq!(strip_cargo_hash("two-words-0123456789abcdef"), "two-words");
        assert_eq!(strip_cargo_hash("selfcheck"), "selfcheck");
        assert_eq!(strip_cargo_hash("not-a-hash"), "not-a-hash");
        assert_eq!(strip_cargo_hash("short-0123abcd"), "short-0123abcd");
    }

    #[test]
    fn the_target_directory_is_two_levels_above_deps() {
        let executable = Path::new("some")
            .join("target")
            .join("debug")
            .join("deps")
            .join("selfcheck-0123456789abcdef.exe");
        assert_eq!(
            target_dir_of_executable(&executable),
            Some(Path::new("some").join("target"))
        );
        let elsewhere = Path::new("some").join("bin").join("selfcheck.exe");
        assert_eq!(target_dir_of_executable(&elsewhere), None);
    }
}
