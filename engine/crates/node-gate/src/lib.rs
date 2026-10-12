//! What a Kaspa node checks about a transaction, outside the node.
//!
//! The crate answers one question: what would a node of rusty-kaspa revision a41a333 say
//! about this transaction, spending these coins, at this DAA score? It needs no node, no
//! database and no network.
//!
//! Two kinds of code are involved and they are kept apart:
//!
//! * The node's own code, called as it is: the script engine and the covenant context
//!   (`kaspa-txscript`), the mass calculator, the sighash, the parameters and the error
//!   types (`kaspa-consensus-core`). Nothing of that is re-implemented here.
//! * Rules that live in crates the gate cannot depend on (`kaspa-consensus`,
//!   `kaspa-mining`). They are ported, function by function, under the upstream names and
//!   with the upstream file and line range in every doc comment: [`isolation`],
//!   [`header`], [`utxo`], [`block`], [`policy`], and the two guards in [`mass`].
//!
//! [`gate::evaluate`] runs a transaction through all of it in the node's order and returns
//! a [`verdict::GateVerdict`]. [`engine`] runs single inputs and tells where the engine
//! stopped; [`budget`] measures inputs and commits the smallest budgets; [`mod@classify`]
//! sorts engine errors by cause; [`wallet`] makes ordinary coins and signatures for test
//! transactions.
//!
//! The crate knows nothing about any particular contract.
//!
//! ```
//! use kaspa_consensus_core::{
//!     hashing::sighash_type::SIG_HASH_ALL,
//!     subnets::SUBNETWORK_ID_NATIVE,
//!     tx::{PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
//! };
//! use kaspa_hashes::Hash;
//! use node_gate::{gate, params::GateParams, wallet::TestKey};
//!
//! let node = GateParams::testnet10();
//! let key = TestKey::from_seed(1);
//!
//! // One pay-to-pubkey coin of 10 KAS in, 9.99 KAS out, version 1, budget 10.
//! let coin = UtxoEntry::new(1_000_000_000, key.p2pk_script_public_key(), node.pov_daa_score - 10, false, None);
//! let outpoint = TransactionOutpoint::new(Hash::from_bytes([7; 32]), 0);
//! let input = TransactionInput::new_with_compute_budget(outpoint, vec![], 0, 10);
//! let output = TransactionOutput::new(999_000_000, key.p2pk_script_public_key());
//! let mut tx = Transaction::new(1, vec![input], vec![output], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
//! let signature_script = key.p2pk_signature_script(&PopulatedTransaction::new(&tx, vec![coin.clone()]), 0, SIG_HASH_ALL);
//! tx.inputs[0].signature_script = signature_script;
//!
//! let answer = gate::evaluate(&node, &tx, &[coin], gate::GateOptions::submit());
//! assert!(answer.accepted());
//! assert_eq!(answer.verdict.inputs[0].committed.used_script_units, 100_001);
//! assert_eq!(answer.verdict.inputs[0].minimal_budget, Some(10));
//! ```

pub mod block;
pub mod budget;
pub mod classify;
pub mod engine;
pub mod gate;
pub mod header;
pub mod isolation;
pub mod mass;
pub mod params;
pub mod policy;
pub mod utxo;
pub mod verdict;
pub mod wallet;

pub use classify::{Classification, ErrorClass, classify, classify_at};
pub use engine::{OpcodeStop, ScriptKind, ScriptRun, ScriptRunner, StopPoint};
pub use gate::{Evaluation, GateOptions, evaluate};
pub use params::GateParams;
pub use verdict::{GateVerdict, Mode, Stage};
