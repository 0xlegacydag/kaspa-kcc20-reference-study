//! Errors of the crate.
//!
//! An error here always means "the requested bytes cannot be produced" (a file is missing,
//! the codec cannot encode a value, a name is unknown). It never means "the transaction is
//! invalid": this crate does not judge transactions.

use std::path::PathBuf;

use argent::artifact::ArtifactVerificationError;
use argent::codec::CodecError;
use kaspa_txscript::script_builder::ScriptBuilderError;
use thiserror::Error;

/// Result type of the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can stop the crate from producing bytes.
#[derive(Debug, Error)]
pub enum Error {
    /// A file of the reference or of the workspace could not be read.
    #[error("cannot read `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A JSON file could not be parsed.
    #[error("cannot parse `{path}`: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    /// The artifact failed Argent's own consistency check.
    #[error("artifact is not consistent: {0}")]
    Artifact(#[from] Box<ArtifactVerificationError>),
    /// The artifact on disk is not the pinned one.
    #[error("artifact id is `{found}`, the pinned artifact is `{expected}`")]
    ArtifactId { expected: String, found: String },
    /// The artifact lacks a contract of the family.
    #[error("the artifact has no contract `{0}`")]
    MissingContract(&'static str),
    /// The artifact lacks an entry of the family.
    #[error("contract `{contract}` has no entry `{entry}`")]
    MissingEntry {
        contract: &'static str,
        entry: &'static str,
    },
    /// A compiler-owned state field or hidden argument has a role this crate does not know.
    #[error("unsupported artifact feature: {0}")]
    Unsupported(String),
    /// A replacement bytecode is too short to hold the state span of its contract.
    #[error("bytecode of `{contract}` has {len} bytes, its state span ends at byte {span_end}")]
    BytecodeTooShort {
        contract: &'static str,
        len: usize,
        span_end: usize,
    },
    /// The codec refused a value (wrong type, wrong length, a number it cannot encode).
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    /// The script builder refused a push.
    #[error("script builder: {0}")]
    ScriptBuilder(#[from] ScriptBuilderError),
    /// A script could not be split into opcodes.
    #[error("cannot parse script: {0}")]
    Script(String),
    /// A scenario refers to something it does not contain.
    #[error("scenario: {0}")]
    Scenario(String),
    /// The SilverScript compiler refused a source file.
    #[error("cannot compile `{contract}`: {message}")]
    Compile {
        contract: &'static str,
        message: String,
    },
    /// A file of the workspace has an unexpected content.
    #[error("unexpected data in `{path}`: {message}")]
    Data { path: PathBuf, message: String },
}

impl From<ArtifactVerificationError> for Error {
    fn from(value: ArtifactVerificationError) -> Self {
        Self::Artifact(Box::new(value))
    }
}
