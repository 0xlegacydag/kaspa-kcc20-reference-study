# checks

Checks of the KCC-20 reference contracts (KCC20, PublicMint, TokenSeed) on the Kaspa script
engine.

`src/` is a test harness in Rust; "the harness" on this page is this one, not the tool
`kcc20_harness.py` that the launch pages of this repository name. A test describes one
transaction as a `kcc20_family::Scenario`; the harness assembles it, puts it to the node
rules of `node-gate`, says what happened, and writes one line per assertion to a result
file. `tests/` holds the checks, one topic per file.

```
cargo test --frozen -p checks
```

A command with `--frozen` needs one `cargo fetch --locked` with a network before it; see
[`../../README.md`](../../README.md).

## The API in one page

```rust
use checks::{run, expect_accept, expect_refused, twin, Case, Expected, Harness, Budgets};
```

| Call | What it does |
|---|---|
| `run(&scenario) -> Outcome` | assemble, run, observe; asserts nothing |
| `expect_accept(case, &scenario)` | the scripts accept the transaction |
| `expect_refused(case, &scenario, input, expected)` | input `input` is refused as `expected` says |
| `twin(case, &honest, \|s\| change, input, expected)` | the honest scenario is accepted; after ONE change the input is refused as `expected` says; a node gets to run the scripts of both |

`case` is a string (the id of the case) or a `Case`:

```rust
Case::new("transfer/one-token-more")            // id: names the line in the result file
    .py(["test_transfer.Conservation.test_one_output_holding_more_is_refused"])  // optional
    .note("declared and locked alike")          // optional
    .on(Harness::pinned().with_budgets(Budgets::Exactly(vec![11])))              // optional
    .scripts_only()                             // optional, twins only; see below
```

`py` takes ids of checks of an earlier suite that the case repeats. That suite was written
in Python for the debug engine that comes with the SilverScript bindings of the Kaspa
Python SDK (it runs one entry of a contract with typed arguments) and is not published
here: the ids are labels and point to nothing in this repository. `py` panics on an id
that is not in `data/python-check-ids.txt` (`checks::python_ids`): a misspelt id would
misfile the case in every later comparison of the result files.

`expected` is an `Expected`, or a string that converts into one:

| Expectation | Holds when |
|---|---|
| `Expected::rule("K-37")` or `"K-37"` | the contract rule with this inventory id refused |
| `Expected::engine("NumberTooBig")` or `"NumberTooBig"` | the engine's error has this variant name |
| `Expected::refused_by("P2SH wrapper")` or `"P2SH wrapper"` | the short name of what refused is this |
| `Expected::line(175)` | the engine stopped in the source statement starting at this line |
| `Expected::pass()` | the input passes (for lists of inputs) |
| `.at_line(n)`, `.at_rule(id)`, `.of_class(class)` | narrow any of the above; all conditions must hold |

More helpers, all methods of `Case`:

| Method | Asserts |
|---|---|
| `expect_inputs(&scenario, &[(input, Expected), ..])` | every listed input answers as stated; at least one must be a refusal |
| `twin_inputs(&honest, change, &[(input, Expected), ..])` | a twin with expectations for several inputs |
| `expect_consensus_accept(&scenario)` | scripts, and the consensus rules of a submission |
| `expect_consensus_refused(&scenario, rule)` | a consensus rule in front of the scripts refuses (`"SpendTooHigh"` or `"check_transaction_output_values"`) |
| `expect_block_accept(&scenario)` / `expect_block_refused(&scenario, rule)` | the transaction inside a block (`"ExceedsStorageMassLimit"`, `"WrongMass"`) |
| `expect_mempool_accept(&scenario)` / `expect_mempool_refused(&scenario, rule)` | a default node's mempool; a refusal must be the node's answer, its first refusal (`"check_minimum_relay_fee"`, `"StorageMass"`) |
| `expect_policy_rule_refuses(&scenario, rule)` | the mempool rule refuses when evaluated on its own, whether or not a node gets to it |

The judging without the result line and without the panic: `judge_accept(&outcome)`,
`judge_input(&outcome, input, &expected)`, `judge_inputs(..)`, `judge_twin(..)`,
`judge_twin_scripts_only(..)`, `judge_mempool_refused(&outcome, rule)`,
`judge_policy_rule_refuses(&outcome, rule)`. They return `Result<(), String>`.

### A check without an engine run

Some checks run no transaction: they establish a fact about the pinned bytes, the source
map or the rule inventory by reading them (which opcodes an entry holds, where a rule's
opcode is in the bytes). Such a check keeps its place in the result file with

```rust
checks::results::record_structural(
    "structure/what was read",                    // the case id
    &[],                                          // ids of the earlier suite, or none
    "what the test established, in one sentence", // the note
);
```

Call it after the test's own assertions, so a failing test leaves no line. The line has
`"kind": "structural"`, `"helper": "record_structural"`, `"passed": true` and the keys
`format`, `binary`, `test`, `case`, `py_ids`, `note`, `failure`, `mutation`; it has no
observed outcome. The ids of the earlier suite are held against the list as `Case::py`
does. A structural line says nothing about a changed contract, so the mutation mode
(see "Mutation runs") neither repeats nor counts it.

### What a twin requires

A twin says: this change, and nothing else, turns an accepted transaction into one that is
refused by this rule. That is a statement about a node only if a node gets to run the
scripts of both sides. So besides the scripts a twin requires

- of the honest side: the consensus rules of a submission accept it (`consensus.accepted`);
- of the changed side: no consensus rule in front of the scripts refuses it
  (`consensus.context_accepted`).

A twin whose honest side spends more than it has, for example, fails with the consensus
refusal in its message. A case that is about the engine alone says so:
`Case::new(..).scripts_only().note("why")`; its line carries
`"expected": {"context": "scripts_only"}`. `expect_accept`, `expect_refused` and
`expect_inputs` are about the scripts only.

### A mempool refusal is the node's answer

A node applies the fee, the standardness of the spent coins and the storage limit only to a
transaction whose consensus validation passed. `expect_mempool_refused(.., rule)` therefore
holds only when `rule` is `mempool.first_refusal`: the first refusal in the order a node
checks, at one of the two mempool stages. A transaction whose script fails is refused by
that, whatever its fee. To ask whether a rule is among the reasons listed in
`mempool.refused`, wherever a node stops, use `expect_policy_rule_refuses`.

## Two complete examples

A transaction that must pass, and a twin that must be refused by one named rule:

```rust
use checks::{Case, Expected, expect_accept, twin};
use kcc20_family::shapes::{self, Profile};

#[test]
fn the_token_outputs_add_up_to_the_token_inputs() {
    // An honest transfer of one token coin into one token coin.
    let honest = shapes::transfer(&Profile::Script, 1, 1);
    expect_accept("transfer/honest 1 to 1", &honest);

    // One token more, in the call and in the output alike: only the sum rule objects.
    twin(
        Case::new("transfer/one token more")
            .py(["test_transfer.Conservation.test_one_output_holding_more_is_refused"]),
        &honest,
        |scenario| {
            scenario.contract_input_mut(0).declared_states_mut()[0].amount += 1;
            scenario.contract_output_mut(0).state.as_kcc20_mut().unwrap().amount += 1;
        },
        0,
        Expected::rule("K-37").at_line(175),
    );
}
```

A refusal that is not a rule of a contract, several inputs judged at once, and a look at
the outcome:

```rust
use checks::{Case, Expected, Harness, Budgets};
use kcc20_family::shapes::{self, BorrowKind, Profile};
use node_gate::ErrorClass;

#[test]
fn the_leader_of_a_borrowed_receive_needs_budget_seven() {
    let scenario = shapes::borrow(&Profile::Script, BorrowKind::Threshold);

    // Measured: the leader needs 7 units, the delegate 13.
    let measured = checks::run(&scenario);
    assert_eq!(measured.minimal_budgets(), Some(vec![7, 13]));

    // With 6 units on the leader a node refuses that input for the budget, and only it.
    let outcome = Case::new("budget/borrow leader with 6")
        .on(Harness::pinned().with_budgets(Budgets::Exactly(vec![6, 13])))
        .expect_inputs(
            &scenario,
            &[
                (0, Expected::engine("ExceededCommittedScriptUnits").of_class(ErrorClass::ResourceLimit)),
                (1, Expected::pass()),
            ],
        );
    assert_eq!(outcome.inputs[0].committed.as_ref().unwrap().rule(), None);
    assert!(outcome.inputs[0].alone.as_ref().unwrap().ok, "without a limit the leader passes");
}
```

## What `run` observes

1. **Every input by itself**, with the node's engine flags and no budget limit
   (`outcome.inputs[i].alone`). This is the verdict of a check that judges one input at a
   time, and the measurement of the input.
2. **The smallest budgets** (`outcome.inputs[i].minimal_budget`, `outcome.budgets`). They
   are committed, and **every input is run again under its committed limit**, as a node
   runs it (`outcome.inputs[i].committed`). `outcome.scripts` is the whole-transaction
   answer of both runs. With the smallest budgets the two runs must be equal; a difference
   is listed in `outcome.scripts.disagreements` and fails every helper that judges scripts
   (not the four that ask for a refusal by a consensus, block or mempool rule).
3. **The masses** of the transaction with those budgets (`outcome.masses`).
4. **The consensus rules around the scripts** (`outcome.consensus`): `context_accepted` is
   everything a node checks before the scripts of a submitted transaction; `block` is the
   same transaction inside a block, with the calculated storage mass committed and the
   block limits applied.
5. **The mempool policy** of a default node (`outcome.mempool`), rule by rule.

The answers are never mixed. A transaction whose scripts pass and whose outputs exceed its
inputs satisfies `expect_accept` and `expect_consensus_refused(.., "SpendTooHigh")` alike.

`accept` and `refuse` in `expect_accept`, `expect_refused` and `twin` are about the scripts
(a twin asks in addition that a node gets to them, see above).
With `Budgets::Minimal` (the default) the run without a limit is judged. With
`Budgets::Exactly(..)` or `Budgets::AsStated` the run under those budgets is judged: the
question is then what a node says to exactly this transaction.

When no script can be run (the covenant bindings of the transaction are inconsistent, so a
node refuses before it builds an engine), `outcome.scripts.not_run` says why and the script
helpers fail; use `expect_consensus_refused(.., "check_covenant_info")`.

## What an input runs

`outcome.inputs[i].contract` and `.entry` say what the bytes of the input make the engine
run, not what the scenario says about it: the coin is a pay-to-script-hash coin, the
signature script holds pushes only, its last push hashes to the coin and has the frame of
one of the three contracts, and the entry is the one whose dispatch tag is pushed in front
of that script (`checks::attribution::contract_call`). The scenario's own description is
kept next to it in `stated_contract` and `stated_entry`; `runs_what_is_stated()` compares
the two, and `what()` names both when they differ
(`ordinary (the scenario says KCC20.transfer)`). An input whose lock or signature script
was overridden so that no contract code runs is recorded with `contract: null`, also when
it passes. Count the entries that accepting checks exercised by `contract` and `entry`.

## What refused

For a refused run, `refusal` (`checks::Attribution`) names what refused:

| `refused_by` | Meaning |
|---|---|
| `K-37`, `M-41`, `S-12`, ... | a rule of the rule inventory refused: the engine stopped at one of the rule's opcodes with the kind of error the rule refuses with |
| `engine: <Variant>` | the engine's own refusal: bad data, a malformed signature, a budget, a script that is not a legal script |
| `P2SH wrapper` | the redeem script does not hash to the coin, or the coin's own script failed |
| `final stack` | after the last opcode the stack is empty, false or not clean |
| `prologue`, `dispatcher`, `statement`, `glue`, `clean-up`, `state frame` | a contract refusal at an opcode of that part of a contract script for which the inventory has no rule |
| `redeem script`, `lock script` | a refusal by a script that is not one of the three contracts |

How a rule is found: the engine's stop position is a byte offset in the redeem script that
ran. The script is read from the signature script and must have the frame of a contract
(same length, same bytes before and after the state). The offset is looked up in the source
map of `kcc20-family` (entry, part of the script, statement of the generated `.sil` source)
and in the rule inventory (rule id).

A rule is named only when the error fits it. A budget that runs out at the opcode of a rule,
or a malformed signature in front of a signature rule, leaves `rule` empty; `at_rule` still
says whose opcode it was. The three rules that only the engine enforces (the checked
additions `K-30`, `K-36`, `M-47`) are named when the engine reports a data error there.

`sil.line` is the first line of the innermost statement. Inside an inlined helper function
it is the line in the helper; the call site is in `inventory_line` (`134 -> 66`).

`tests/attribution.rs` holds the derived rule and line against line numbers that the
earlier suite asserted with its debug engine, over all three contracts.

## Result files

Every helper call appends one JSON line to

```
<target directory>/check-results/<test binary name>.jsonl
```

The file is emptied the first time a test binary writes to it, so it holds exactly the lines
of the last run of that binary. Lines are written whole under a lock; tests may run on
several threads. The directory can be set with the environment variable `CHECK_RESULTS_DIR`.
One process per test binary is assumed, as `cargo test` runs them.

A line is written before the helper panics, so a failed expectation is in the file with
`"passed": false`. `Case::unrecorded()` suppresses the line (for tests of the helpers
themselves). `checks::results::results_path()` is the file of the running binary and
`checks::results::lines_written()` the number of lines this run has put into it.

### Format 2

Field names are stable. `format` is raised when a field changes meaning or is removed;
fields may be added without raising it. Every key is always present; absent values are
`null`.

| Key | Content |
|---|---|
| `format` | `2` |
| `binary` | name of the test binary (`selfcheck`) |
| `test` | name of the test function, `null` when tests run on one thread |
| `case` | the case id |
| `py_ids` | list of ids of checks of the earlier suite this case repeats (labels); each is in `data/python-check-ids.txt` |
| `note` | free text or `null` |
| `kind` | `accept` or `reject`: what the check expects; `structural` for a line of `record_structural`, which has the keys `format` to `helper`, `passed`, `failure` and `mutation` only |
| `helper` | `expect_accept`, `expect_refused`, `expect_inputs`, `twin`, `expect_consensus_accept`, `expect_consensus_refused`, `expect_block_accept`, `expect_block_refused`, `expect_mempool_accept`, `expect_mempool_refused`, `expect_policy_rule_refuses` |
| `expected` | `{"verdict": "accept"\|"reject", "scope": "scripts"\|"consensus"\|"consensus_context"\|"block"\|"mempool"\|"mempool_rule", ..}`; for script refusals `"inputs": [{"input", "pass", "rule", "engine", "refused_by", "at_rule", "sil_line", "class"}]`; for a twin also `"context": "node_runs_scripts"\|"scripts_only"`; for the others `"rule"` |
| `passed` | whether the expectation held |
| `failure` | the reason when it did not |
| `scenario` | name of the scenario |
| `tx_id` | transaction id (with the committed budgets) |
| `network` | `kaspa-testnet-10` |
| `inputs` | one object per input, see below |
| `scripts` | `{accepted, refused_inputs, accepted_under_committed_budgets, refused_inputs_under_committed_budgets, not_run, disagreements, judged}`; `judged` is `alone` or `committed` |
| `budgets` | `{source: "minimal"\|"as_stated"\|"exactly", minimal: [u16\|null], committed: [{"compute_budget": n} \| {"sig_op_count": n}], note}` |
| `masses` | `{estimated_size, compute_mass, transient_mass, calculated_storage_mass, committed_storage_mass, input_plurality, output_plurality}` or `null` |
| `consensus` | `{context_accepted, context_refusal, stage_reached, accepted, refusal, fee, block: {accepted, stage_reached, refusal, committed_storage_mass}, harness_error}` |
| `mempool` | `{accepted, first_refusal, policy_accepted, refused: [{rule, function, refusal, message}], not_evaluated, fee, minimum_fee, fee_mass, p2sh_sig_ops}` |
| `twin_context` | for a twin: `{required, honest_consensus_accepted, changed_context_accepted}`: whether the twin had to be one a node runs, and whether a node gets to the scripts of each side; otherwise `null` |
| `honest` | for a twin: the honest scenario, an object with the keys `scenario` to `mempool`; otherwise `null` |
| `mutation` | `null` in an ordinary run. In a mutation run: `{family, observe, fast, only_cases, judged}`; `family` is `null`, `{"kind": "mutant", label, contract, byte_offset, from, to}` or `{"kind": "artifact", label, artifact_id}`; `judged` is `full`, `scripts_only` or `not_at_all` (see "Mutation runs") |

A refusal object (`context_refusal`, `refusal`, `first_refusal`) is
`{stage, rule, error, message, input}`: `rule` is the name of the refusing function, `error`
the debug text of the node's error value.

One input:

| Key | Content |
|---|---|
| `index`, `label` | position and the scenario's label |
| `kind` | `contract` or `ordinary`, as the scenario describes the coin |
| `contract`, `entry` | `KCC20` / `transfer`: the contract script the bytes of the input run and the entry its call selects; `null` when they run none |
| `stated_contract`, `stated_entry` | the same two as the scenario states them; `stated_entry` is `null` for a raw call |
| `spent_script_class` | `PubKey`, `PubKeyECDSA`, `ScriptHash`, `NonStandard` |
| `signature_script_len` | bytes |
| `alone` | the run without a budget limit, see below; `null` when no script was run |
| `minimal_budget` | smallest covering budget |
| `commitment` | `{"compute_budget": n}` or `{"sig_op_count": n}` of the second run |
| `committed` | the run under that commitment |

One run (`alone`, `committed`):

| Key | Content |
|---|---|
| `ok` | the engine accepted the input |
| `script_units_limit` | `null` for a run without a limit, and on a node before Toccata |
| `sig_op_limit` | on a node before Toccata: the signature operations the engine allowed (255 for the run without a limit); otherwise `null` |
| `used_script_units`, `used_sig_ops` | cost |
| `accepted_unknown_version` | passed without running: proves nothing |
| `error` | `{variant, debug, message}` or `null`: `VerifyError`, the debug text with fields, the display text |
| `class` | `contract_refused`, `engine_refused_data`, `malformed_signature_material`, `resource_limit`, `script_format`, `harness` |
| `stop` | where the engine stopped: `{"opcode": {script, op_index, byte_offset, opcode, opcode_name, executed}}`, `"final_stack"`, `"p2sh_hash_mismatch"`, `"before_any_opcode"`, `{"end_of_script": ..}`, `{"unknown": reason}`; `executed` is `false` when the engine refused the opcode without interpreting it |
| `refusal` | `{refused_by, part, rule, at_rule, contract, entry, place, byte_offset, op_index, opcode, sil: {file, line, end_line, text}, inventory_line, engine_precondition, note}` |

`refusal.part` is one of `before_any_opcode`, `signature_script`, `p2sh_wrapper`,
`contract_script`, `other_redeem_script`, `lock_script`, `final_stack`, `unknown`.

### `measure.json`

`tests/measure.rs` writes one document to the same directory: for each honest shape in three
value profiles (the script-only profile with contract coins of 1000 sompi; 10 KAS coins with
a signed funding coin, change and the profile's default fee; the same paying exactly the
mempool's fee floor) the signature script size, script units and smallest budget of every
input and the three masses. What a node says about a shape is recorded next to its numbers
as an observation. Under `smallest_created_token_coin` the document holds the smallest
value of the token coin a one-to-one transfer can create so that a block, and so that a
default mempool, accepts the transaction. That
value is the smallest value of the coin CREATED by a transfer whose spent token coin has
the same value and whose fee is paid by one ordinary coin of 100 KAS: it moves with the
fee-paying coin (`block_by_funding_coin_value` repeats the search with 1, 10, 100 and 1000
KAS), it is not a floor for an existing coin (a smaller coin can be moved into a larger
one), and both searches stop at the same rule, the storage mass limit of a block
(`assumptions`, `binding_rule`). Its format version is 2 (the key `format`).

The test asserts that two measurements are equal and that every value a search reports is
a boundary: accepted at the value, refused one sompi below it for the storage mass, with no
probe on the wrong side. It asserts no number; the numbers are pinned in
`tests/review_policy_masses_by_hand.rs` and `tests/review_policy_smallest_token_coin.rs`.

## Mutation runs

A check that names the rule that refused says nothing about the checks next to it: would
another rule have refused the same transaction, or was this rule its only guard? A mutation
run answers that. It takes the result files of an ordinary run as the baseline, weakens one
contract, runs the cases again and says what the engine answers then.

After an ordinary run of the test files (`cargo test --frozen -p checks`), from the
workspace directory, in a shell in which that command works:

```
node tools/mutation-run.mjs rules
```

That is the whole campaign over the rules. It

1. builds the test executables once (`cargo test --frozen -p checks --no-run`);
2. reads the baseline `target/check-results/*.jsonl` and finds, for every rule of
   `data/rule-inventory.json`, the cases in which an input, run by itself, was refused
   exactly at an opcode of that rule. It takes a rule's opcodes from `bytecode_at`: the
   copies of the rules of an inlined helper in another entry (`also_reached_from` in the
   inventory: K-38 to K-49 inside `transfer_delegator`) are not replaced, and the summary
   lists the refusals there in its line about opcodes outside the rules' own offsets;
   `tests/coverage_kcc20.rs` replaces those copies one by one;
3. for every such opcode that is `OpVerify`, `OpEqualVerify` or `OpNumEqualVerify`:
   neutralises it (`OpDrop`, `Op2Drop`, `Op2Drop`: the same items leave the stack, nothing
   is refused) and starts the test executables again for those cases only, script
   verdicts only, at most three at a time, each mutant writing into
   `target/mutation/rules/<Contract>-at-<offset>/`;
4. runs again what left no line (a test that stopped at an assertion of its own before it
   got to the case): the tests of those cases once more in full (`pass2/`), and each case
   still missing by itself with the cases in front of it as an ordinary run has them
   (`pass3/`, at most `--alone-limit` cases per mutant);
5. writes `target/mutation/rules-summary.json` and the table
   `target/mutation/rules-summary.txt`, which it also prints.

Every repeated refusal is one of

| Class | Meaning |
|---|---|
| now accepted | every input of the transaction passes: the rule was the only guard of this case |
| refused by another rule | the same input is refused at another rule of a contract, which is named |
| refused by the engine | the same input is refused, and not by a rule: a data error, the final stack, the P2SH wrapper |
| refused at another input | the input passes; another input of the transaction is refused, as it was in the baseline or newly |
| unchanged | refused at the neutralised opcode: the case did not run on the mutant (it brings a family of its own, or built its bytes from `Family::pinned()`) |
| not run | the case left no line in any of the three passes |

and every rule is: the only guard in at least one case, always backed by another refusal
in the cases of the baseline, without an answer (every case unchanged or not run), without
any case in the baseline, or covered with a refusing opcode that is none of the three
(`OpReturn`, the checked additions). Rules with a case
that is unchanged or not run are listed once more, with those cases. A rule with several
refusing opcodes is one mutant per opcode that has a case; the opcodes without a case are
listed. A timeout and a test executable that
could not be started are listed and make the runner end with status 1. An executable that
ends with a failure status is counted and listed too; in a mutation run that is common and
no fault: a test that asserts something of its own about an outcome stops there.

```
node tools/mutation-run.mjs artifacts mutants.json
```

runs ALL cases of the baseline against contracts rebuilt from changed source and reports
the cases whose script verdict flipped, in `target/mutation/artifacts-summary.json` and
`.txt`. `mutants.json` is a list of
`{"id": "...", "artifact": "path/to/artifact.json", "contracts": ["KCC20"]}`; a relative
path is taken from the folder of the list. The bytecode of such an artifact has other
offsets, so rule and line of a refusal are usually not available: the verdict is what is
compared.

Options of both: `--tests a,b` (only these test binaries), `--rules K-37,M-19` (only these
rules), `--baseline DIR`, `--out DIR`, `--jobs N` (1 to 3), `--threads N`, `--timeout SEC`,
`--alone-limit N`, `--no-build` (take the newest executables of `target/debug/deps`),
`--dry-run` (list the mutants and stop). The baseline is only read; it must be an ordinary
run (lines that carry a `mutation` object are left out and counted).

### The environment variables

The runner drives the helpers through six variables. They are read once per process, by
`Harness::pinned()` and by the helpers of `Case`; with none of them set nothing behaves
differently. A value that cannot be honoured makes every helper call panic with the reason.

| Variable | Effect |
|---|---|
| `CHECKS_MUTANT=<Contract>@<byte offset>` | `Harness::pinned()` and `checks::family()` are the pinned family with the refusing opcode at that offset neutralised (`KCC20@2203`). The bytecode keeps its length, so rule and line of every other refusal are still named; the template hash is recomputed and flows into states and hidden arguments. The offset must be the first byte of one of the three opcodes |
| `CHECKS_ARTIFACT=<path>` | the same two are the family of that `artifact.json`. Not together with `CHECKS_MUTANT` |
| `CHECKS_OBSERVE=1` | no helper panics on a failed expectation: the line is written with `passed` and `failure` as they are, and the outcome is returned |
| `CHECKS_ONLY_CASES=<path>` | a text file, one `<test binary name>::<case id>` per line (`#` starts a comment). A helper call for another case returns a placeholder outcome at once (`outcome.skipped()`: the scenario assembled, no input run, no line written); a twin returns two |
| `CHECKS_UNSELECTED=pinned` | with a case list: a case that is not selected runs as in an ordinary run instead, on the pinned family and without a line, so that what a test asserts about its outcome holds and the test gets to its selected case |
| `CHECKS_FAST=1` | `run` makes only the run of every input by itself, with the node's flags and no budget limit (`outcome.scripts_only()`). No budget is committed and no consensus, block or mempool rule is evaluated: `committed` is `null`, `masses` is `null`, `consensus.harness_error` says why. The helpers judge the scripts and nothing around them: `expect_accept` and the three `expect_*_accept` ask for passing scripts, a twin does not ask that a node gets to the scripts, and the four helpers that expect a refusal by a consensus, block or mempool rule judge nothing (`"judged": "not_at_all"`) |

Every line of such a process carries the `mutation` object: the family, the flags, and how
much of the expectation was judged. `CHECK_RESULTS_DIR` keeps the lines out of the baseline.

One case of one mutant without the runner, in Git Bash or a Unix shell, from the folder of
this crate (`crates/checks`): cargo starts a test there, and the two relative paths are
taken from it.

```
printf 'attribution::line/KCC20 175 one token more\n' > cases.txt
CHECKS_MUTANT=KCC20@2203 CHECKS_ONLY_CASES=cases.txt CHECKS_OBSERVE=1 CHECKS_FAST=1 \
  CHECK_RESULTS_DIR=target/tmp/one cargo test --frozen -p checks --test attribution
```

The command ends with a failure status and `FAILED` for every test of the file: the tests
without a selected case stop at an assertion of their own, and the selected one may stop at
an assertion that does not hold on the mutant. The answer is the one line in
`target/tmp/one/attribution.jsonl`: `passed` is false and `scripts.accepted` is true, the
transaction is accepted once the opcode of the sum rule is neutralised. Both stay in
`crates/checks` afterwards (`cases.txt` and the folder `target/tmp/one`); remove them when
done.

### What a test must do to be repeatable

- **Take the family from the harness.** A test that builds bytes by hand (a call, a redeem
  script, a lock, a template hash) takes them from `checks::family()`, or from
  `Harness::pinned().family`, not from `Family::pinned()`. Under a mutant the two differ in
  one opcode and in the template hash; bytes of the pinned family then do not fit the coin
  and the case reads as "refused by the engine: P2SH wrapper" or "unchanged".
- **A case on a family of its own** (`Case::on(Harness::pinned().with_family(..))`) is not
  mutated. It is reported as unchanged.
- **Unique case ids within a test binary.** An id recorded more than once is matched by
  order; the summary lists such ids (`case_ids_recorded_more_than_once`).
- **Assertions about a returned outcome are fine.** Under a mutant, on a placeholder or in
  the fast mode they may fail and stop the test; the runner then repeats what left no
  line, first the tests in full and then every case still missing by itself, with the
  cases in front of it standing in as an ordinary run has them. What that cannot mend: an
  assertion about `checks::run(..)` or `Harness::pinned().run(..)` called directly between
  two cases, which runs on the mutant. Put such assertions behind the last helper call of
  the test, or into a test of their own. A test with very many cases that each stop it
  costs one run of the whole test per case; split it.
- **`record_structural`** lines are not repeated; a mutation run counts cases with inputs.
- With `--test-threads=1` the result lines do not name their test (`"test": null`) and
  the runner has to run the whole binary for them. Write the baseline with the default
  threads.

## Test files

The test files of `tests/` are listed, group by group, on the first page of the workspace,
[`../../README.md`](../../README.md). `tests/examples.rs` holds the two examples of this
page; `tests/smoke.rs` checks only that the dependencies link.

The unit tests in `src/` (`cargo test --frozen -p checks --lib`) cover the judging of two
runs, the attribution, the list of ids of the earlier suite, the structural line, and the
mutation mode variable by variable: a mutant differs from the pinned family in one opcode
and its hash and does not refuse there, an artifact gives its family, observing records
and does not panic, a case that is not selected runs nothing or stands in on the pinned
family, the fast mode makes one run per input and judges the scripts only.

## Things to know

- The default node is testnet-10 parameters ten million DAA scores after the Toccata
  activation (`node_gate::GateParams::testnet10()`).
- The source lines come from the pinned source map. They are given for the pinned family and
  for a family whose bytecode has the pinned length (`Family::with_bytecode` with a
  same-length patch). For another length the attribution has a note and no lines.
- On a node before Toccata (`Harness::with_node`) there are no budgets: the engine counts
  signature operations. The run without a limit is then bound by no signature operation
  count, `minimal_budget` is `null`, and `used_sig_ops` of that run is the count the input
  must commit to.
- A scenario that cannot be assembled (the codec refuses a typed value) makes `run` panic:
  that is a mistake in the scenario, not an answer of the engine. Write such bytes with
  `kcc20_family::raw` or a parts patch.
- The harness measures before it commits budgets, so a scenario's own `compute_commit` is
  replaced unless the harness runs with `Budgets::AsStated`.
- `checks::family()` is the family `Harness::pinned()` runs on: the pinned one, or the one
  a mutation run puts in its place. Use it wherever a test needs the family.
- The unit tests of `src/` write no result file: their lines are kept in memory.
