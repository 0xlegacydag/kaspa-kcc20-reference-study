//! Checks of the KCC-20 reference contracts on the Kaspa script engine.
//!
//! The crate is a harness for test files. A test describes a transaction as a
//! `kcc20_family::Scenario`; the harness assembles it, puts it to the node rules of
//! `node_gate`, and says what happened:
//!
//! - [`run`] returns an [`Outcome`]: every input run by itself, the whole-transaction
//!   answer of the scripts, the smallest budgets and a second run under them, the masses,
//!   and, kept apart, the answer of the consensus rules around the scripts and of the
//!   mempool policy.
//! - A refused input is attributed ([`attribution`]): the rule id of the rule inventory
//!   and the statement of the generated SilverScript source, or the part of the engine's
//!   own checks that refused.
//! - [`expect_accept`], [`expect_refused`] and [`twin`] assert an outcome and append one
//!   line per call to a result file ([`results`]). A twin also requires that a node gets
//!   to run the scripts of both of its sides ([`TwinContext`]).
//! - What an input is recorded as (`contract`, `entry`) is read from its bytes
//!   ([`attribution::contract_call`]), next to what the scenario says about it.
//! - The ids of checks of an earlier suite that a case names are held against a list of
//!   them ([`python_ids`]).
//! - The same cases can be run against a weakened contract ([`mutation`]): environment
//!   variables put a mutant in place of the pinned family and make the helpers record
//!   what they observe instead of asserting it.
//!
//! ```no_run
//! use checks::{Case, Expected, expect_accept, twin};
//! use kcc20_family::shapes::{self, Profile};
//!
//! // An honest transfer passes.
//! let honest = shapes::transfer(&Profile::Script, 1, 1);
//! expect_accept("transfer/honest", &honest);
//!
//! // One token more in the output: the sum rule refuses at the leader.
//! twin(
//!     Case::new("transfer/one-token-more").py(["test_transfer.Conservation.test_one_output_holding_more_is_refused"]),
//!     &honest,
//!     |scenario| {
//!         scenario.contract_input_mut(0).declared_states_mut()[0].amount += 1;
//!         scenario.contract_output_mut(0).state.as_kcc20_mut().unwrap().amount += 1;
//!     },
//!     0,
//!     Expected::rule("K-37").at_line(175),
//! );
//! ```

pub mod attribution;
pub mod expect;
pub mod harness;
pub mod mutation;
pub mod outcome;
pub mod python_ids;
pub mod results;

pub use attribution::{Attribution, Part, SilLine};
pub use expect::{
    Case, Expected, Kind, Twin, TwinContext, expect_accept, expect_refused, judge_accept,
    judge_input, judge_inputs, judge_mempool_refused, judge_policy_rule_refuses, judge_twin,
    judge_twin_scripts_only, twin,
};
pub use harness::{Budgets, Harness, StorageCommitment, run};
pub use mutation::family;
pub use outcome::{
    BlockVerdict, BudgetReport, BudgetSource, ConsensusVerdict, EngineError, InputOutcome,
    JudgedRun, MempoolVerdict, Outcome, PolicyFinding, RunOutcome, ScriptVerdict,
};
