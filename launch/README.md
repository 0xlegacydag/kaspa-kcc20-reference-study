# The sender, and the builder it works with

Two programs take a chain of KCC-20 transactions to Kaspa **testnet-10**. Test network
only: the sender accepts no other. KAS on this page always means test KAS of testnet-10.

- The **builder** (Rust; [`../engine`](../engine), the test file
  `crates/checks/tests/launch_real.rs`) works offline. It holds the keys, builds and signs
  every transaction of the run, runs each one against the node rules of `node-gate`, its
  offline stand-in for a node, and writes the chain file.
- The **sender** (`launch_send.py`, Python with the Kaspa SDK, package `kaspa` 2.1.0) holds
  no keys and has no option that takes one. It reads the network, checks the chain file by
  its own rules, submits the transactions one by one and records what the node answers.

The two files that pass between them are described in [FORMAT.md](FORMAT.md).

## Order of a run

```
python launch_send.py prepare --issuer-address kaspatest:... --out request.json --token-name NAME [--feerate N]
      (the builder reads request.json and writes chain.json; nothing is sent)
python launch_send.py check  chain.json --party issuer=kaspatest:... --party alice=... --party bob=... --harness DIR
python launch_send.py check  chain.json --party ... --harness DIR --online
python launch_send.py send   chain.json --party ... --harness DIR --record DIR --yes-send-to-testnet-10
python launch_send.py status chain.json --party ...
```

1. `prepare` (read-only) finds the one plain coin of exactly 30 KAS at the issuer's address
   (`--funding-kas` for less), prints the node's fee estimate and writes the request. The
   request carries the node's priority estimate, rounded up, or the rate given with
   `--feerate`. It refuses when there is no such coin or more than one, and never
   overwrites a file.
2. The builder makes the chain file from the request; how it is started is in
   [`../engine/README.md`](../engine/README.md) under "Building a chain".
3. `check` verifies the chain file offline; `--online` also reads the network. The parties'
   addresses come from the command line: they are what the file is measured against.
4. `send` runs the whole check with the network first, then submits the steps in order and,
   after the last one, the probes: transactions that break a rule on purpose and are
   expected to be refused. It sends nothing without `--yes-send-to-testnet-10`, and does
   not start without `--harness`.
5. `status` (read-only) shows which steps are on chain, the coins of the chain that are
   unspent, and the parties' balances.

`--harness DIR` (or the environment variable `KCC20_HARNESS_DIR`) names the folder of
`kcc20_harness.py` (not in this repository), a second tool that compiles the
reference's contracts with the SDK, independently of the builder: with it the lock of
every covenant output is recomputed from the state the file gives for it. `check` runs
without it, but then prints `NOT CHECKED` for the locks, and its last line says so.

## What `check` checks

A file that lacks a field, or has one of the wrong kind, or names a key twice, is refused
on that alone: the other checks are not run on it. Otherwise every refusal of every check
is printed, not only the first.

| | |
|---|---|
| a | format, network, `nothing_was_sent`, the limits, what the builder's gate answered |
| b | the parties of the file are the parties named on the command line, by their addresses; the funding coin is locked to its owner, who is the party named `issuer` when there is one |
| c | every transaction, rebuilt by the SDK from the fields, has the id the file states; version 1, no payload, no gas, no lock time, the plain subnetwork, sequence 0 and no signature operation count on every input; the mass field and the compute budgets within bounds, no empty signature script |
| d | steps spend the funding coin or outputs of earlier steps, each once; probes spend what is left |
| e | every fee equals the spent values minus the output values and is at or above the floor the file states; the sum is within the cap and the limit |
| f | every output is a pay-to-script-hash coin of exactly 1 KAS bound to this token's covenant id, or pays a party of the file |
| g | the covenant id is the one the SDK derives from the first step |
| h | every covenant output carries a state of one of the three contracts whose owner is the key of a party (a token coin: owner scheme 0 only); with `--harness` its lock is recomputed from that state |
| i | a summary: steps, probes, fees, tokens by party, covenant id |

Limits, constants of the program: a funding coin of at most 30 KAS; fees of all steps plus
the most expensive probe of at most 15 KAS; covenant coins of exactly 1 KAS; at most 20
steps and 10 probes.

With `--online`, and so at the start of every `send`: the node is a synced testnet-10
node; the coins of the chain that are on chain are exactly those unspent after some number
of its steps; and while no step is on chain, the first step is built for sending from the
node's own entry of the funding coin, without being submitted.

## When `send` stops

Within a run no submission is retried and nothing is rebuilt: a stop ends that run. (A
read of the node is tried up to four times.) The record (`DIR/run-<UTC time>.jsonl`, one
JSON object per event) and the screen tell the same story. The record names the chain
file by its name and SHA-256 and the harness by the SHA-256 of `kcc20_harness.py`; it
holds no path.

| Exit code | Meaning |
|---|---|
| 0 | every step was handed over and seen on chain, or found there; every probe was refused by the node in this run |
| 1 | wrong usage, or a check failed, or the node could not be reached or read or was not a synced testnet-10 node before the run began, or an earlier stop stands in the way (see below); nothing was sent |
| 2 | the node refused a step; its answer is recorded word for word |
| 3 | a submission got no answer (60 s at most), and its outputs did not show up in 60 checks one second apart |
| 4 | a step was accepted, but not all of its outputs showed up in 120 checks one second apart |
| 5 | `FORBIDDEN MOVE ACCEPTED`: a node accepted a probe, or says it already has it; no further probe is sent in this run |
| 6 | the coins on chain are not what the file expects (a missing input, a coin listed twice, another id returned) |
| 7 | the node could not be read, or was no longer a synced testnet-10 node, before a submission or at the last reading of the balances |
| 8 | the record could not be written; the lines are on screen instead and nothing more was submitted |
| 130 | interrupted from the keyboard; if a hand-over was under way, the record and the last line name the transaction, which may or may not have reached the node |

What a later `send` does with the same `--record` folder:

- A step that is on chain is not sent. It counts as on chain when one of its outputs is
  visible, or when a later step that spends its outputs is on chain - and for no other
  reason: what a record says is not taken as proof. A step with neither its inputs nor
  such a trace stops the run with code 6.
- A step that was accepted while its outputs were not seen (code 4) is never submitted a
  second time under the same record: the program waits for its outputs again. If the
  node has dropped the transaction, only a run with a new `--record` folder submits it.
- A step is not handed over again automatically when an earlier run saw it refused
  (code 2), lost the answer to it (code 3), or left its hand-over without an outcome in
  the record (the program was interrupted or killed, or the record broke). If such a step
  is not on chain and no run since saw it accepted, `send` refuses to start (code 1).
  `--again-after-a-stop` hands it over again by the operator's decision, and the screen
  and the record say so.
- After a probe that was accepted, that a node said it already had, whose answer was
  lost, or whose hand-over has no outcome in the record, no run with that record starts
  again: `send` refuses to start, with code 5, 5, 3 and 3 in that order. No flag
  overrides this: a forbidden move may be on its way or on chain. Look with `status`.
- `send` on a chain whose steps are all on chain still hands over its probes again. They
  are expected to be refused again, and a new record file is written.

A probe refused for a reason that does not read like a failed script (a fee, an orphan) is
recorded as `REFUSED FOR ANOTHER REASON` and the run goes on: such a refusal does not show
what the probe was made to show.

## What this tool does not show

- It does not run scripts and does not verify signatures. A transaction id covers neither
  the signature scripts, nor the mass field, nor the compute budgets; they travel as the
  file has them, and only a node judges them. `check` passes a file whose signatures are
  wrong.
- It calculates no mass. The fee floor and the masses are the builder's numbers; the
  sender checks each fee against the floor the file states.
- That a covenant output is a coin of the token's contracts rests on the harness: on its
  compiler and on the three SilverScript files of the reference it reads. The record keeps
  its SHA-256. The harness is whatever module named `kcc20_harness.py` the folder holds:
  that `send` asks for one is a rule for the operator, not a proof.
- "Seen" means that one node lists the output among the unspent coins of its address. It
  is not a number of confirmations, and a reorganisation is not followed.
- A node is asked which network it is on and whether it is synced, and is believed.
- The record names the node the run connected to at its start. If the SDK's client
  reconnected to another node by itself, the record would not show it.
- Coins are found by address among the unspent ones. A step all of whose outputs are spent
  is known to be on chain only through a later step.
- A record of another folder is not known: the rules above about earlier stops hold for
  runs that share a `--record` folder.
- The fee estimate is printed next to the feerate of the file and not enforced: a chain
  built at a lower rate may wait or be refused.
- The reason for a refusal is only what the words of the node's answer say. The answer
  itself is in the record.
- A key carries no network. The program cannot tell a throwaway key from any other: it
  only refuses addresses that do not start with `kaspatest:`.
- `status` reads the transactions of the chain file and does not look at its `format` and
  `network` labels. The program reaches testnet-10 and nothing else.
- The token name is a label of the files. Nothing on chain carries it.

## Tests

```
python -m unittest discover -s tests -v
```

Offline, against a fake node. Two chain files are under test:

- `tests/fixture-chain.json`, made by `tests/make_fixture.py` from a rehearsal plan of the
  builder: its transaction ids are true ids of its fields and its covenant states are the
  rehearsal's, while its signature scripts are placeholders and its three probes are made
  up (the head of that script says what else is made up). The plan file is the
  `launch-plan.json` that the test `launch_dry_run` of [`../engine`](../engine) writes into
  `engine/target/check-results/`; given that file and a second argument for the output,
  the script writes this fixture again, byte for byte. Run with one argument it would
  overwrite the fixture;
- `tests/fixture-selftest-955.json`, a chain file written by the builder's own self-test
  with made-up keys; none of its transactions was ever sent. Here the signature scripts of
  its covenant spends are replaced by placeholders of the same length, which changes no
  transaction id. The builder in `engine/` words the sentence in the field `fee_rule`
  differently from this file; its self-test gives the same 16 transaction ids and the same
  key signatures.

The tests of `send` use a stand-in for the harness that knows the locks of these two files.
The tests that recompute the locks for real need the harness: set `KCC20_HARNESS_DIR` to
its folder, otherwise they are skipped and say so. No test talks to a network: how a real
node words its answers, and that it accepts a transaction built this way, is shown only by
a run.
