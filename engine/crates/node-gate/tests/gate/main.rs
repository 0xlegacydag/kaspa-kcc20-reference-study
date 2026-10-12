//! Checks of the gate on transactions built in the tests, with ordinary coins. No contracts.
//!
//! One test binary; the modules follow the modules of the crate.

mod common;

mod budgets;
mod covenant_context;
mod header_context;
mod in_isolation;
mod masses;
mod mempool_policy;
mod p2pk;
mod p2sh;
mod positions;
mod utxo_context;
mod verdicts;
