# The builder and the checks: the KCC20 reference on the Kaspa script engine

A Rust workspace, part of [this study](../README.md): an independent study, not affiliated
with or endorsed by the authors of KCC-20, the authors of the reference, or the Kaspa
developers. Two things live here:

- **the builder** of the launch chain, `crates/checks/tests/launch_real.rs`: the program that
  built and signed the 16 transactions of the
  [recorded run](../launch/results/2026-10-11-testnet-10/README.md) and judged each one
  offline before anything was sent;
- **checks** of the KCC20 reference contracts (`argent-lang/kcc20-reference`, revision
  `c8a0871`: KCC20, PublicMint, TokenSeed) on the script engine and the mass calculator of a
  Kaspa node (`rusty-kaspa`, revision `a41a333`, the one the reference pins).

The question behind the checks: a contract check that runs one input on a simplified engine
says nothing about the bytes of the call, an empty signature, the compute budget, the mass,
the coin's own lock or the ordinary inputs beside it. Here every case is a whole
transaction, built byte by byte and put to the rules a node applies to it.

This is a study, not a node and not an audit. See "What this does not show".

## Layout

| Crate | What it is |
|---|---|
| `crates/node-gate` | What a node checks about a transaction, outside the node. The engine and the mass calculator are the node's own crates, called directly; the rules around them (transaction in isolation, coin context, block mass, mempool policy) are ported, each function naming its upstream file and lines. Knows nothing about tokens. |
| `crates/kcc20-family` | The pinned reference as data: the published artifact, an assembler of our own for whole transactions (any field can be made wrong on purpose), 29 honest shapes covering all 11 entries (the functions of the three contracts that a spend may call), a map from a byte of a script to its source line, and the inventory of the contracts' rules (`data/rule-inventory.json`). |
| `crates/checks` | The test harness and the checks. A case is run per input and as a transaction; a refusal is traced to the rule that refused; consensus, block and mempool answers are kept apart from the script verdict. Every case writes a result line. |

On the pages of `launch/` "the harness" is another thing: the unpublished tool
`kcc20_harness.py`. Here the word means the test harness of `crates/checks`.

## What you need

- **Rust**, through rustup: `rust-toolchain.toml` pins 1.94.1. `rustup toolchain install`
  with no toolchain named, run in `engine/`, fetches it (rustup 1.28 or newer); by default
  rustup also fetches it by itself at the first command that needs it.
- **A C compiler and an assembler.** Three dependencies compile native code (secp256k1,
  Keccak, BLAKE3). On Windows: the Microsoft C++ Build Tools with a Windows SDK. On Linux
  or macOS: a `cc`.
- **A clone of the reference** at revision `c8a0871`, for everything except
  `crates/node-gate` and the replay of a chain file. It is not copied here. Make it at the
  root of this repository's working copy, next to `engine/` (git ignores the folder
  `kcc20-reference` there), or anywhere else with its path in `KCC20_REFERENCE_DIR`:

  ```
  git clone -c core.autocrlf=false https://github.com/argent-lang/kcc20-reference
  git -C kcc20-reference checkout c8a087117735a1f87c5c6d115fcddeaf2562c784
  ```

  `-c core.autocrlf=false` matters on Windows: the checks were run against a clone with LF
  line endings only. Without a clone the tests that touch the contracts do not skip. They
  fail: most with a message that names `KCC20_REFERENCE_DIR`, the others with an error
  about a file of the reference that could not be read.
- **Node.js**, only for `tools/mutation-run.mjs`.

## Running

In `engine/`:

```
cargo fetch --locked
cargo test --frozen --workspace
cargo test --frozen -p checks --test engine_signatures
```

Of the cargo commands only `cargo fetch --locked` needs a network: it fetches three git
repositories (rusty-kaspa, Argent and SilverScript at the revisions `Cargo.lock` pins) and
the crates.io packages the lock file names. Every `cargo test` after it is given
`--frozen` and fetches nothing itself. One build script goes to the network on its own
account when it can: `workflow-core` 0.18.0, a crates.io package that crates of
rusty-kaspa depend on, asks cargo for a list of its own dependencies while it is built,
outside `--frozen`. In one run, with the network on, that call downloaded newer
versions of some packages the lock file pins, and nothing compiled them. In another,
where cargo could not reach crates.io, the call failed quietly and the build went
through as well. Both runs are described below. (Getting the toolchain and cloning the
reference need a network too.)

On 2026-10-12, on Windows 11 (x86_64, Microsoft C++ Build Tools, a four-core laptop),
`cargo test --frozen --workspace` ran 762 tests in 50 test programs. All passed and none
is marked to be skipped. In a fresh copy the first build took about nine minutes and the
tests about five, with two build jobs (`CARGO_BUILD_JOBS=2` was set; cargo's default is
one job per logical processor); a second full run took a little under five minutes.

The same day the three commands were run twice with cargo's home set to a new empty
folder, each time with a newly made clone of the reference. `cargo fetch --locked`
downloaded the 417 crates.io packages the lock file names (about 80 MB packed) and the
three git repositories in about two minutes; after the first of the two fetches cargo's
home held about 0.7 GB. The first time the network stayed on, and during the build the
call of that build script downloaded newer versions of 31 packages (about 5 MB packed).
The second time cargo's proxy settings were pointed at a closed local port after the
fetch; a `cargo search` then failed to reach crates.io, and nothing more was downloaded.
Both times the build and the tests gave the same 762 passes in 50 test programs. After
the second run `engine/target` held more than 9 GB. The Rust toolchain and the Microsoft
build tools were already installed, and the commands were run by a script in Git Bash.

`cargo fmt --all --check` and
`cargo clippy --frozen --workspace --all-targets -- -D warnings` were run on the same day
and system: the first reported no difference, the second no remark. Eight functions
carry an `#[allow]` for one clippy lint each: four for the number of their arguments,
and four in `crates/node-gate/src/policy.rs` that keep a loop or a nested `if` as
rusty-kaspa writes it.

The workflow [`../.github/workflows/checks.yml`](../.github/workflows/checks.yml) runs
`cargo fetch --locked`, `cargo fmt --all --check`, the clippy command above, the two test
commands and the replay of the run's chain file on pushes to `main`, on pull requests and
when started by hand, on machines hosted by GitHub: `ubuntu-24.04` (x64), `macos-26` (arm64)
and `windows-2025` (x64). Each time the machine is new: the workflow fetches the toolchain
with rustup, makes a new clone of the reference, leaves the network on,
and builds without debug information and incremental data (`CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_INCREMENTAL=0`) to take less room on the machine's disk. The counts of tests, the
times, the sizes and the two fetches into an empty cargo home above are from the Windows 11
laptop only.

Result lines go to `target/check-results/<test file>.jsonl`. Some tests also write
documents there: `measure.json`, `limits.json`, `signature-matrix.json`, the launch
rehearsal `launch-plan.json` and `launch-plan.txt`, `launch-genesis-case.json` (the same
launch in the input format of the separate program, not published here, that derived the
covenant id of the rehearsal; see "What is not in this repository" on the first page), and
the builder's self-test `launch-real-selftest-<fee rate>.chain.json` with a table `.txt`
beside each, at the fee rates 955 and 100. An ordinary run leaves nothing in the repository
outside `target/`; a few unit tests of `crates/checks` make short-lived files in the
system's temporary folder. The format of a result line is described in
[`crates/checks/README.md`](crates/checks/README.md).

## Test files of `crates/checks`

- `selfcheck`, `attribution`, `examples`, `measure`, `smoke` - the test harness judged
  against the honest shapes and against known refusals.
- `port_*` - cases of an earlier suite of checks, run again here as whole transactions.
  That suite was written in Python for the debug engine that comes with the SilverScript
  bindings of the Kaspa Python SDK, which runs one entry of a contract with typed
  arguments. It is not published here; each case names the earlier check it repeats, and
  the names (`crates/checks/data/python-check-ids.txt`) are labels only.
- `engine_call_bytes`, `engine_signatures`, `engine_gaps`, `engine_limits` - what only the
  real engine can show: the bytes of a call, signature material that is empty, malformed,
  misplaced or stale, the coin's own lock and the ordinary inputs, budgets, masses and fees.
- `coverage_kcc20`, `coverage_public_mint`, `coverage_token_seed` - cases that stop at rules
  no other case of the suite stops at, and at the copies a rule has at each call site of an
  inlined helper.
- `launch_dry_run` - a token launch and its life as a chain of 13 transactions, each
  spending the real outputs of the one before. Nothing is sent; keys and the funding
  outpoint are made up.
- `launch_real` - the builder; see the next section.
- `review_launch_real` - a finished chain file read back and replayed through the rules
  from its bytes alone.
- the other `review_*` files - a second set of cases for the code above, built without its
  helpers: upstream's own unit tests replayed against the ported rules, masses worked out
  from the formulas, the shapes and the source map checked a second way. Kept as
  regression tests.

## Building a chain

`launch_real` is a test file, not a program with a command line. Without a request it is a
self-test: it makes up three keys and a funding coin, builds the chain of 13 steps and 3
forbidden moves at two fee rates, judges every transaction and writes the two chain files
named above. It needs the clone of the reference, like the other checks of the contracts.
It sends nothing and holds no network code:

```
cargo test --frozen -p checks --test launch_real -- --nocapture
```

For a real run it reads five environment variables:

| Variable | What it names |
|---|---|
| `KCC20_LAUNCH_INPUT` | the request file written by `launch_send.py prepare` ([`../launch/FORMAT.md`](../launch/FORMAT.md)) |
| `KCC20_LAUNCH_OUTPUT` | the chain file to write; it must not exist yet |
| `KASPA_LAB_KEY_FILE` | the key file of the issuer, who owns the funding coin and pays every fee |
| `KASPA_LAB_SECOND_KEY_FILE` | the key file of the second party (Bob) |
| `KASPA_LAB_THIRD_KEY_FILE` | the key file of the third party (Alice) |

Give every path in full: cargo starts a test with the crate's folder as the current
directory. A key file holds 64 hex characters. The builder refuses a key file that lies
inside this workspace folder (`engine/`) or at the path of its output; it does not look at
the rest of the repository, so keep key files outside the repository altogether. Keep the
default target directory, `engine/target`: one test of the builder expects it there. It
builds for testnet-10 only: it checks the network label of the request and uses the rules
of testnet-10. Like the sender, it cannot tell where a key or a coin really lives. Whoever
builds a chain with keys of their own answers for it.

The chain of the recorded run was built this way, once. By the builder's code the same
request and the same keys give the same transactions again, and the file differs in the
time `built_at_utc` and nothing else: it signs without randomness, builds the chain twice
and compares, and reads the clock for that one field. The run's chain was not built a
second time to show it.

## Checking the checks

`node tools/mutation-run.mjs rules` neutralises one refusing opcode of a contract at a time
(it is replaced by a drop of the same length, so positions and source lines stay) and
repeats the cases that were refused at that opcode: each should now pass or stop somewhere
else; a case that brings a contract of its own is reported as unchanged. It needs an
ordinary run of the tests first and edits no file: the opcode is replaced in memory, and
the output goes to `target/mutation`. The copies of the owner rules inside
`transfer_delegator` are not replaced by the runner; `coverage_kcc20` replaces them one by
one. See "Mutation runs" in [`crates/checks/README.md`](crates/checks/README.md).

One such run was made over this workspace on 2026-10-12: 154 opcodes of 142 rules were
replaced, one at a time, and the 679 refusals of an ordinary run at those opcodes were
repeated. In 372 of them the transaction was then accepted; in 305 it was refused
somewhere else (by another rule, by the engine, or at another input); the other 2 are
cases that bring a contract of their own, which the replacement does not reach. The
summary files of that run are not published here.

## Environment variables

Besides the five of the builder: `KCC20_REFERENCE_DIR` (the clone of the reference),
`CHECK_RESULTS_DIR` (another place for the result files), `REVIEW_CHAIN_FILES` (chain files
for `review_launch_real` to replay, separated by `;`), and the variables of a mutation run,
`CHECKS_MUTANT`, `CHECKS_ARTIFACT`, `CHECKS_OBSERVE`, `CHECKS_ONLY_CASES`, `CHECKS_FAST`,
`CHECKS_UNSELECTED`, which the runner sets by itself. With none of them set a run is the
ordinary one.

## What this does not show

- A live node. The engine and the mass calculator are the node's code; the rules around
  them are a port of one revision, held against the source and against upstream's own test
  cases. Blocks, the coin set and the mempool as a container are not modelled. `a41a333`
  is older than the 2.1.0 nodes of the recorded run; the port was not rebuilt on 2.1.0.
- Every rule of the contracts. The inventory has 173 records, and no case of this suite
  stops at 25 of them: K-02, K-06, K-08, K-15, K-19, K-20, K-27, K-28, K-67, K-71, K-72,
  M-08, M-09, M-39, M-40, M-43, M-44, M-54, M-55, S-08, S-09, S-29, S-30, S-40 and S-41.
  Six of these (K-20, K-72, M-40, M-55, S-30, S-41) are decode steps. K-36 has a case at
  two of its three opcodes. The mutation runner prints such a list for a run of its own.
- Other tokens: every coin in these checks is built by the checks themselves.
- An audit. Nothing here is a statement about the safety of the reference, and a passing
  run is not one either.

The mutation run was made on Windows 11 only. The tests are also run on machines hosted by
GitHub (see "Running"), the builder only as its self-test. A green mark there says that
they passed on those machines; like any passing run, it shows none of the things listed above.

## Licences

[`../LICENSE`](../LICENSE) (ISC) covers this workspace, with the exceptions
[`../NOTICE`](../NOTICE) names: the rules ported from rusty-kaspa in `crates/node-gate` and
three test files that replay its unit tests stay under rusty-kaspa's licence. The
reference's sources are not included.
