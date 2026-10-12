# node-gate

What would a Kaspa node say about this transaction? This crate answers without a node:
no database, no network, no chain. It is pinned to rusty-kaspa revision
`a41a333b08848f41bf737b72592e463a6011b8ac` (workspace version 2.0.1).

It knows nothing about any particular contract. It takes a transaction, the coins it
spends, network parameters and a DAA score, and returns a verdict. It is not part of
rusty-kaspa and not endorsed by its developers.

```rust
let node = GateParams::testnet10();               // well after Toccata activation
let answer = gate::evaluate(&node, &tx, &coins, GateOptions::submit());
answer.verdict            // plain data, serializable: stage, refusal, inputs, masses, policy
answer.consensus_error    // the node's own TxRuleError
answer.committed_runs     // per input: TxScriptError, script units, where it stopped
```

## Two kinds of code

The crate keeps them apart, because they deserve different amounts of trust.

**The node's own code, called as it is.** Nothing below is re-implemented, except that
`engine::parse` evaluates the engine's opcode checks a second time to find where a run
stopped:

| What | Where it comes from |
|---|---|
| script engine, opcode parser | `kaspa_txscript::{TxScriptEngine, parse_script}` |
| covenant context and genesis id rule | `kaspa_txscript::covenants::CovenantsContext::from_tx` |
| pay-to-script-hash signature operation scan | `kaspa_txscript::post_toccata_p2sh_sig_scanner` |
| script classes, pay-to-script-hash script | `kaspa_txscript::script_class::ScriptClass`, `pay_to_script_hash_script` |
| size, compute, transient and storage mass, plurality | `kaspa_consensus_core::mass::*` |
| budget units and the smallest covering budget | `kaspa_consensus_core::mass::{ComputeBudget, ScriptUnits, ...}` |
| signature hashes | `kaspa_consensus_core::hashing::sighash::*` |
| network parameters and fork values | `kaspa_consensus_core::config::params::*` |
| error types | `TxRuleError`, `TxScriptError`, `CovenantsError` |

**Rules ported from crates this one cannot depend on** (`kaspa-consensus`, which brings a
database, and `kaspa-mining`). Each port follows the upstream body and cites the upstream
lines in its doc comment, so the two can be read side by side; it keeps the upstream
function name, except in `policy.rs`, where upstream's functions are split into one
function per rule (see below). What a node keeps in its validator and its mempool
configuration is read from `Params` here; the other departures are named in the module
headers and doc comments.
Upstream is ISC licensed, Copyright (c) 2022-2024 Kaspa developers.

| Function here | Upstream file and lines |
|---|---|
| `isolation::validate_tx_in_isolation` | `consensus/src/processes/transaction_validator/tx_validation_in_isolation.rs:18-29` |
| `isolation::check_transaction_inputs_in_isolation`, `check_transaction_outputs_in_isolation` | same file `:31-39` |
| `isolation::check_coinbase_in_isolation` | `:41-64` |
| `isolation::check_transaction_outputs_count` | `:66-76` |
| `isolation::check_transaction_inputs_count` | `:78-88` |
| `isolation::check_transaction_signature_scripts` | `:91-100` |
| `isolation::check_transaction_script_public_keys` | `:103-109` |
| `isolation::check_duplicate_transaction_inputs` | `:112-120` |
| `isolation::check_gas` | `:122-140` |
| `isolation::check_transaction_version` | `:142-147` |
| `isolation::check_transaction_output_value_ranges` | `:149-172` |
| `isolation::check_transaction_subnetwork` | `:174-193` |
| `isolation::check_tx_version_specific_fields` | `:195-217` |
| `header::LockTimeType`, `LockTimeArg` | `consensus/src/processes/transaction_validator/tx_validation_in_header_context.rs:15-25` |
| `header::validate_tx_in_header_context_with_args` | same file `:28-43` |
| `header::validate_tx_in_header_context` | `:45-54` |
| `header::get_lock_time_type` | `:56-70` |
| `header::check_tx_is_finalized` | `:72-93` |
| `header::check_transaction_version` | `:96-109` |
| `header::check_transaction_signature_scripts_in_header_context` | `:112-119` |
| `utxo::TxValidationFlags` | `consensus/src/processes/transaction_validator/tx_validation_in_utxo_context.rs:23-34` |
| `utxo::validate_populated_transaction_and_get_fee` | same file `:37-67` |
| `utxo::check_transaction_coinbase_maturity` | `:81-97` |
| `utxo::check_transaction_input_amounts` | `:99-114` |
| `utxo::check_transaction_output_values` | `:116-124` |
| `utxo::check_mass_commitment` | `:126-134` |
| `utxo::check_sequence_lock` | `:136-161` |
| `utxo::check_covenant_info` | `:177-183` |
| `utxo::check_scripts` | `:163-175`, `:196-204` |
| `utxo::map_script_err` | `:225-227` |
| `block::check_block_mass` | `consensus/src/pipeline/body_processor/body_validation_in_isolation.rs:67-121` |
| `mass::validate_transaction_for_non_contextual_masses` | `consensus/src/consensus/mod.rs:599-627` |
| `mass::calculate_transaction_non_contextual_masses` | `consensus/src/consensus/mod.rs:689-692` |
| `policy::check_gas_limit`, `check_compute_mass_limit`, `check_transient_mass_limit`, `validate_transaction_limits_in_isolation` | `mining/src/mempool/check_transaction_limits.rs:14-33` |
| `policy::check_storage_mass_limit` (`validate_transaction_limits_in_context`) | `mining/src/mempool/check_transaction_limits.rs:40-52` |
| `policy::standard_transaction_mass_cap` | `mining/src/mempool/check_transaction_standard.rs:43-47` |
| `policy::check_standard_compute_mass_cap`, `check_standard_transient_mass_cap`, `check_output_scripts_standard`, `check_transaction_standard_in_isolation` | same file `:49-80` |
| `policy::check_standard_storage_mass_cap`, `check_input_scripts_standard`, `check_minimum_relay_fee`, `check_transaction_standard_in_context` | `:89-161` |
| `policy::minimum_required_transaction_relay_fee` | `:165-181` |
| `policy` constants | `check_transaction_standard.rs:19, 26, 31`; `mining/src/mempool/config.rs:23, 28` |
| the texts of the 13 `policy::PolicyRefusal` messages | `mining/errors/src/mempool.rs:47-57` (`RuleError::Reject*`) and `:116-155` (`NonStandardError::Reject*`); the standardness texts carry the prefix `non-standard: ` here |
| the texts of the `block::BlockMassError` messages | `consensus/core/src/errors/block.rs:103-116` (`RuleError::Exceeds*`) |
| the order of steps in `gate::evaluate`, submit mode | `mining/src/mempool/validate_and_insert_transaction.rs:20-37, 73-77`; `consensus/src/pipeline/virtual_processor/processor.rs:1216-1233`; `consensus/src/pipeline/virtual_processor/utxo_validation.rs:442-490` |
| the order of steps in `gate::evaluate`, block mode | `consensus/src/pipeline/body_processor/body_validation_in_isolation.rs:17-27`; `body_validation_in_context.rs:30-46`; `utxo_validation.rs:366-414` |

Upstream has four mempool functions; here each rule inside them is a function of its own,
so that a report can name the rule, and the four upstream functions call them in the
upstream order.

## Modules

| Module | Content |
|---|---|
| `params` | `GateParams`: consensus `Params` plus the DAA scores and past median time of the question. `testnet10()` and `mainnet()` place "now" ten million DAA scores after Toccata activation. |
| `isolation`, `header`, `utxo`, `block`, `policy` | the ports listed above |
| `mass` | sizes, masses and plurality from the node's calculator, behind the guards a node applies first |
| `engine` | `ScriptRunner`: one input on the engine with the node's flags, under its committed limit or without a limit; where it stopped. Before Toccata the engine meters signature operations and no script units: a run then records a signature operation limit and no script-unit limit |
| `budget` | measure the inputs, commit the smallest covering budgets, run again under them. Budgets exist after Toccata only; before it measuring reports the signature operations an input needs |
| `classify` | `TxScriptError` sorted into six classes of cause |
| `gate` | `evaluate`: the whole walk, in the node's order |
| `verdict` | `GateVerdict` and its parts: plain data, `serde` in both directions |
| `wallet` | fixed test keys, the three standard lock scripts, Schnorr and ECDSA signatures for one input |

## The two modes

* **Submit** - the transaction is sent to a node, as over RPC. The node calculates the
  storage mass itself and writes it into the transaction (`evaluate` does the same to the
  transaction it is given), skips the commitment check, and applies mempool policy before
  and after the consensus rules. `first_refusal` is the first refusal in that order.
* **Block** - the transaction arrives in a block. The storage mass it commits to must be
  exactly the calculated one, the block's mass and gas limits apply to it, and mempool
  policy plays no part.

The consensus validation stops at the first refusal, as in a node. The verdict still
records what can be established independently of it: the masses, the result of every
input's script, and every mempool rule, each with its own outcome. `stage_reached` says how
far a node would really have got.

`first_refusal` in submit mode is the node's own answer. Its mempool part is taken from the
four composed ports (`validate_transaction_limits_in_isolation` and the three after it),
which keep the upstream order in their bodies, and only where a node gets to them: the
first group once the masses are known, the second once the consensus validation passed.
The rule-by-rule report (`policy.checks`) walks the two lists of `PolicyRule`; the tests
hold the two against each other on every evaluation.

## Where the engine stopped

For a refused input the gate reports which script was running (signature script, script
public key, redeem script), the ordinal of the opcode in the linear disassembly of that
script, and the byte offset of the opcode, and whether the opcode ran (`executed`) or was
refused before the interpreter got it. The method and its known ambiguities are
described at the top of `src/engine.rs` and at `OpcodeStop::executed`. It rests on the engine's own opcode log and the
engine's own parser; `tests/gate/positions.rs` checks it on scripts assembled in the tests,
where the failing opcode is known, including skipped branches, refused-before-execution
opcodes, truncated pushes and the budget.

## What is not modelled

* The UTXO set. The caller supplies the coins; fewer coins than inputs is reported as
  `MissingTxOutpoints`.
* Anything that needs more than one transaction: the block-level sums of mass and gas over
  several transactions, the limit of fifty lanes per block, duplicate transactions and
  double spends inside a block, chained transactions in a block.
* The parallel script path. A node runs the inputs of a multi-input transaction on a
  thread pool; the gate runs them one after the other. The verdict is the same; when
  several inputs fail a node may report any of them, the gate reports the first.
* `OpChainblockSeqCommit`. It needs the node's header chain; here it fails with
  `InvalidOpcode`, classified as `ErrorClass::Harness`: not a verdict of a node.
* The mempool as a container: duplicates, double spends against pooled transactions,
  replace by fee and its feerate threshold, orphans, eviction when the pool is full,
  expiry, block template selection and its feerate ordering. A coin created by a pooled
  transaction (which carries the DAA score `u64::MAX` in a node) is not modelled either.
* A node that accepts non-standard transactions. The daemon passes `false` for that
  switch on every network (`kaspad/src/daemon.rs:643-651`); the gate always applies
  standardness in submit mode.
* Coinbase transactions as such: the in-isolation coinbase rules are ported, the coinbase
  payload, subsidy and blue score rules are block rules and are not. In block mode a
  coinbase that passed the rules in isolation, the block limits and the header context
  gets no further answer (`harness_error`): a node does not put it through the
  UTXO-context rules of ordinary spends. In submit mode it goes through them, as in a
  node, and fails the amounts rule.
* Header validity, proof of work, GHOSTDAG, pruning, initial block download, the P2P and
  RPC layers and their own size limits.
* Wall-clock time. The past median time is a number the caller sets.

## Tests

`tests/gate/` holds transactions built in the tests, with ordinary coins only: every
in-isolation rule, every header rule, every UTXO-context rule and every mempool rule is
tripped alone, next to a neighbour that passes; signatures good and bad on the real engine;
budgets one unit below and at the need; storage mass against numbers worked out from the
formulas; four questions to the covenant opcodes, to show that the covenant context reaches
the engine.

```
cargo test --frozen -p node-gate
```

`--frozen` needs one `cargo fetch --locked` with a network first; see
[../../README.md](../../README.md).

Everything is deterministic: keys come from seed bytes, Schnorr signatures use no auxiliary
randomness, no clock is read.

Two things keep the tests honest.

* A second path to the same answer. `gate::evaluate` walks the rules step by step and takes
  its script results from `engine::ScriptRunner`.
  `utxo::validate_populated_transaction_and_get_fee` chains the same ports in one function
  and builds the engine directly, the way upstream does. The shared helper of the tests
  (`evaluate` in `tests/gate/common.rs`) compares each evaluation with the chained answer,
  unless a block limit has already refused the transaction. A few tests call
  `gate::evaluate` directly; those evaluations are not compared.
* Tests that make equal values differ. A check that reads the wrong one of two equal values
  passes every test that leaves them equal. `the_two_count_limits_are_told_apart` gives the
  input limit and the output limit different values,
  `coinbase_maturity_is_judged_from_the_point_of_view_score` does so for the two DAA scores
  of the gate, and `the_price_of_a_signature_check_comes_from_the_parameters` for the price
  in the network parameters and the one in `EngineFlags::default()`.
  `several_refusals_are_answered_in_the_node_order` breaks several mempool rules at once
  and takes one refusal away at a time, which holds the rule-by-rule report and the node's
  answer against each other.

One thing no test here can tell: whether `gate::evaluate` skips the commitment check on
submission, as a node does. The gate has just written the calculated storage mass into the
transaction, so the check would pass anyway.

## Formatting

`rustfmt.toml` in this folder carries the settings of rusty-kaspa (its `.rustfmt.toml`, with
the line ending fixed to LF), so that the ported functions have the same layout as upstream
and can be compared with a plain diff.
