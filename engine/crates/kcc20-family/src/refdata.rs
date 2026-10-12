//! Where the pinned KCC-20 reference lives on disk and how its published files are loaded.
//!
//! No file of the reference is copied into this repository: the artifact, the generated
//! SilverScript sources and the conformance vectors are read from a checkout of
//! `argent-lang/kcc20-reference` at revision `c8a0871`.
//!
//! The checkout is the directory named by the environment variable `KCC20_REFERENCE_DIR`.
//! Without the variable it is the directory `kcc20-reference` beside the workspace directory.
//! In the repository the workspace is the folder `engine/`, so the default place is the folder
//! `kcc20-reference` at the root of the working copy, next to `engine/`; git ignores it there.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use argent::artifact::Artifact;

use crate::error::{Error, Result};
use crate::family::Contract;

/// Environment variable that names the directory of the reference checkout.
pub const REFERENCE_DIR_ENV: &str = "KCC20_REFERENCE_DIR";

/// Name of the directory used when [`REFERENCE_DIR_ENV`] is not set: a checkout next to the
/// directory of this workspace. This is the only place in the crate where a location of the
/// reference is written down.
const DEFAULT_REFERENCE_DIR_NAME: &str = "kcc20-reference";

/// The default directory of the reference checkout: `kcc20-reference` beside the workspace
/// directory, that is three levels above this crate's manifest. With the workspace in the
/// folder `engine/` of the repository, that is `kcc20-reference` at the root of the working
/// copy.
fn default_reference_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join(DEFAULT_REFERENCE_DIR_NAME)
}

/// Identity of the published artifact `fixtures/public-mint/artifact.json` at `c8a0871`.
///
/// The id is Argent's hash over the whole artifact with the source paths cleared
/// (argent 9a9f4b1 crates/argent-artifact/src/lib.rs:171-190).
pub const PINNED_ARTIFACT_ID: &str =
    "b48c90c8e287d227821ac40f0875a753e329e1ab3c8fdfa1477f55419cfa26ab";

/// Application name written in the published artifact.
pub const PINNED_APP: &str = "KCC20PublicMint";

/// The directory named by the value of [`REFERENCE_DIR_ENV`], or the default when the
/// variable is unset or empty.
fn resolve_reference_dir(value: Option<OsString>) -> PathBuf {
    match value {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => default_reference_dir(),
    }
}

/// Directory of the reference checkout.
pub fn reference_dir() -> PathBuf {
    resolve_reference_dir(std::env::var_os(REFERENCE_DIR_ENV))
}

/// Path of the published artifact inside the reference.
pub fn artifact_path() -> PathBuf {
    reference_dir()
        .join("fixtures")
        .join("public-mint")
        .join("artifact.json")
}

/// Path of the generated SilverScript source of one contract inside the reference.
pub fn sil_path(contract: Contract) -> PathBuf {
    reference_dir()
        .join("fixtures")
        .join("public-mint")
        .join("sil")
        .join(contract.sil_file_name())
}

/// Path of the KCC-20 conformance vectors inside the reference.
pub fn conformance_path() -> PathBuf {
    reference_dir()
        .join("fixtures")
        .join("kcc20")
        .join("conformance.json")
}

fn read_text(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Reads an Argent artifact from a JSON file and runs Argent's consistency check on it
/// (schema version, ABI, template frames, template plan, cardinalities and the artifact id;
/// argent 9a9f4b1 crates/argent-artifact/src/lib.rs:132-140).
///
/// This is what `argentc inspect` does (argent 9a9f4b1 src/inspect.rs:83-92). The check
/// proves that the file agrees with itself, not that it is the pinned artifact: see
/// [`load_pinned_artifact`].
pub fn load_artifact(path: &Path) -> Result<Artifact> {
    let json = read_text(path)?;
    let artifact: Artifact = serde_json::from_str(&json).map_err(|source| Error::Json {
        path: path.to_path_buf(),
        source,
    })?;
    artifact.check_consistency()?;
    Ok(artifact)
}

/// Reads the published artifact of the reference and requires its id to be
/// [`PINNED_ARTIFACT_ID`].
pub fn load_pinned_artifact() -> Result<Artifact> {
    let artifact = load_artifact(&artifact_path())?;
    if artifact.id != PINNED_ARTIFACT_ID {
        return Err(Error::ArtifactId {
            expected: PINNED_ARTIFACT_ID.to_string(),
            found: artifact.id,
        });
    }
    Ok(artifact)
}

/// The published artifact, read once per process.
///
/// # Panics
///
/// Panics when the reference is not where [`reference_dir`] says, or when the artifact is
/// not the pinned one. Use [`load_pinned_artifact`] to get the error instead.
pub fn pinned_artifact() -> &'static Artifact {
    static ARTIFACT: OnceLock<Artifact> = OnceLock::new();
    ARTIFACT.get_or_init(|| {
        load_pinned_artifact().unwrap_or_else(|error| {
            panic!("the pinned KCC-20 artifact is not available ({REFERENCE_DIR_ENV}): {error}")
        })
    })
}

/// Reads the generated SilverScript source of one contract from the reference.
pub fn load_sil_source(contract: Contract) -> Result<String> {
    read_text(&sil_path(contract))
}

/// The generated SilverScript source of one contract, read once per process.
///
/// # Panics
///
/// Panics when the file cannot be read. Use [`load_sil_source`] to get the error instead.
pub fn pinned_sil_source(contract: Contract) -> &'static str {
    static SOURCES: OnceLock<[String; 3]> = OnceLock::new();
    let sources = SOURCES.get_or_init(|| {
        Contract::ALL.map(|contract| {
            load_sil_source(contract).unwrap_or_else(|error| {
                panic!(
                    "the pinned SilverScript source is not available ({REFERENCE_DIR_ENV}): {error}"
                )
            })
        })
    });
    &sources[contract.index()]
}

/// Reads the KCC-20 conformance vectors of the reference as JSON.
pub fn load_conformance_vectors() -> Result<serde_json::Value> {
    let path = conformance_path();
    let json = read_text(&path)?;
    serde_json::from_str(&json).map_err(|source| Error::Json { path, source })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_environment_variable_overrides_the_default_directory() {
        assert_eq!(
            resolve_reference_dir(Some(OsString::from("D:/elsewhere"))),
            PathBuf::from("D:/elsewhere")
        );
    }

    #[test]
    fn an_unset_or_empty_variable_gives_the_default_directory() {
        assert_eq!(resolve_reference_dir(None), default_reference_dir());
        assert_eq!(
            resolve_reference_dir(Some(OsString::new())),
            default_reference_dir()
        );
    }

    #[test]
    fn the_default_directory_is_a_sibling_of_the_workspace() {
        // No machine-specific location is written in the source: the default is derived
        // from where the crate is built.
        let default = default_reference_dir();
        assert!(default.starts_with(env!("CARGO_MANIFEST_DIR")));
        let tail = Path::new("..")
            .join("..")
            .join("..")
            .join("kcc20-reference");
        assert!(default.ends_with(&tail), "{}", default.display());
    }
}
