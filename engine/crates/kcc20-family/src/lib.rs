//! The pinned KCC-20 reference contracts as data.
//!
//! The crate loads the published artifact of the KCC-20 reference (KCC20, PublicMint and
//! TokenSeed) and builds scripts, states, calls and whole transactions from it with its own
//! assembler. Nothing here judges a transaction: every field can be made wrong on purpose and
//! the result still reaches whatever engine the caller runs it on.
//!
//! Module map:
//!
//! - [`refdata`]: where the reference lives on disk, the published artifact and its identity.
//! - [`family`]: the three contracts as one family: bytecode, template hashes, redeem
//!   scripts, script public keys and call bytes.
//! - [`states`]: typed states of the three contracts and the KCC-20 scheme constants.
//! - [`raw`]: hand-made pushes and the parts of a signature script, for malformed calls.
//! - [`keys`]: fixed keys and deterministic signatures.
//! - [`witness`]: the witnesses of the KCC-20 owner and borrow schemes.
//! - [`scenario`]: a declarative description of one transaction and its assembly.
//! - [`shapes`]: one honest transaction per entry, as a starting point for changes.
//! - [`sourcemap`]: byte offset in a redeem script to source line and to rule id.
//!
//! The codec (argument and state encoding) and the artifact types come from Argent and
//! SilverScript; the transaction assembly is written here and uses neither Argent's
//! transaction builder nor its execution helpers.

pub mod error;
pub mod family;
pub mod keys;
pub mod raw;
pub mod refdata;
pub mod scenario;
pub mod shapes;
pub mod sourcemap;
pub mod states;
pub mod witness;

pub use error::{Error, Result};
pub use family::{Contract, Entry, EntryRole, Family};
pub use scenario::{
    Arg, Assembled, Call, ContractInput, ContractOutput, LateBytes, OrdinaryInput, PlainOutput,
    Scenario,
};
pub use shapes::Profile;
pub use sourcemap::SourceMap;
pub use states::{Kcc20State, PublicMintState, State, TokenSeedState};
