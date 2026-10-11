# A study of the KCC20 reference contracts on Kaspa

One launch of a test token made from the published KCC20 reference contracts on a Kaspa
test network, recorded step by step, and the program that sent it. The program that built
and signed the transactions is not published here.

**Status: the record of one run. Educational, unaudited, test network only.**

An independent study: not affiliated with or endorsed by the authors of KCC-20, the
authors of the reference, or the Kaspa developers.

The token described here is a **test token on testnet-10**. It has no value, it is not
offered to anyone, and nothing in this repository is an invitation to buy, hold or trade
anything. This is not a token project. What was launched is one instance of the published
reference contracts, unchanged and written by their authors, made only to study them. Its
25 units are held by the study's own test keys and are not distributed. Nothing here ever
touched mainnet or real funds. This is not an audit of the reference and not a statement
about its safety.

On these pages a "coin" is a UTXO and a "move" is a transaction.

## At a glance

On 2026-10-11 one test token was launched on Kaspa testnet-10 from the contracts KCC20,
PublicMint and TokenSeed of
[argent-lang/kcc20-reference](https://github.com/argent-lang/kcc20-reference) at revision
`c8a0871`, the reference implementation of
[KCC-20](https://github.com/kaspanet/kccs/blob/main/kcc-0020.md) (the Fungible Token
Covenant Specification). It was then taken through 12 further moves. The question: does a
live network judge these moves the way an offline check had judged them beforehand?

| | |
|---|---|
| Honest moves | 13 sent, 13 accepted, each under the transaction id calculated offline before anything was sent |
| Forbidden moves | 3 sent after them, 3 refused by the node |
| Network | Kaspa testnet-10, public nodes that report version 2.1.0 |
| Token | covenant id `0d81e3e1d9f1c9568acd38e932f22eef1ea96dd6480d351e47cf61c692a4716a` (the number that ties all coins of one token together) |
| Label | `0xlegacydag` - the field `token_name` of the run's files: it says whose run this is. KCC-20 defines no name field; this token is identified by its covenant id. This is not a ticker |
| Left on chain | 25 tokens in six coins, and one seed (a coin that may create empty token coins); each of the seven holds 1 test KAS |
| Fees | 3.38598 test KAS over the 13 moves, at 400 sompi per gram of transaction mass (1 KAS = 100,000,000 sompi) |

The 13 honest moves, in order: the launch (a minter that may mint 25 tokens, at most 10
at a time, and a seed); a mint; a transfer; a zero-token coin created by the seed; a
payment into that coin without its owner's signature ("borrowed receive"); a minter
split; a mint from the split; the return of the split minter into the first one; two
more mints, the second using up the allowance; the closing of the empty minter; a seed
split; the closing of the second seed.

The 3 forbidden moves, called probes in the files: a transfer signed by the wrong key; a
transfer with more tokens going out than coming in; a seed creating a coin that already
holds tokens.

The record, with every transaction id, every fee and the node's answers word for word:
[launch/results/2026-10-11-testnet-10/README.md](launch/results/2026-10-11-testnet-10/README.md).

## What is in this repository

- [`launch/launch_send.py`](launch/launch_send.py) - the sender. It holds no keys and has
  no option that takes one. It reads a prepared chain of signed transactions, rebuilds and
  checks every one of them by rules of its own, submits them one at a time and records
  what the node answers. It accepts testnet-10 and no other network.
- [`launch/README.md`](launch/README.md) - how the sender is used, what it checks, when it
  stops and what it does not show.
- [`launch/FORMAT.md`](launch/FORMAT.md) - the two files that pass between the sender and
  the builder (the program that built the chain; see the next section).
- [`launch/tests/`](launch/tests) - 106 offline checks of the sender against a fake node.
- [`launch/results/2026-10-11-testnet-10/`](launch/results/2026-10-11-testnet-10) - the
  run: the chain file with all 16 transactions in full, the sender's checks before
  sending, the run line by line, and the chain read back from a second node afterwards.

## What is not in this repository

- **The builder.** The chain of transactions was built and signed offline by a second
  program, written in Rust. Before anything was sent it checked every transaction against
  a node's rules without running a node: the node's own script engine and mass calculator,
  called directly, with the rules around them ported from the node's source (rusty-kaspa
  at revision `a41a333`, older than the 2.1.0 nodes that later accepted the
  transactions). That program is not published here. With what is here a new chain cannot
  be built: the sender only checks and sends a chain that exists.
- **The harness.** A covenant coin is locked by a script made from a contract and the
  coin's state. With `--harness` the sender recomputes that lock for every covenant coin
  from the state the chain file gives for it, using a second tool (`kcc20_harness.py`)
  that compiles the reference's contracts with the Kaspa SDK. It is not published here
  either. Without it `check` prints `NOT CHECKED` for the locks, five tests are skipped,
  and `send` refuses to start.
- **The reference.** No file of the reference is copied here. Its sources are written in
  Argent (`contracts/` there); the SilverScript generated from them and the compiled
  scripts are tracked in its `fixtures/public-mint/`. `NOTICE` says which part of it the
  recorded transactions carry.
- **Keys.** The three keys of the run are throwaway test keys kept outside this
  repository. The addresses in the record are their testnet addresses: do not send
  anything of value to them.

## Check it yourself

What can be checked with what is here, without a key and without sending anything: the
tests, the chain file, the state of the network, and two checksums.

```
python -m venv .venv
.venv\Scripts\python -m pip install --require-hashes -r requirements.txt
cd launch
..\.venv\Scripts\python -m unittest discover -s tests
```

The last command ends with `Ran 106 tests` and `OK (skipped=5)`. It needs no network.

**The chain file, offline.** The sender rebuilds every transaction from its fields with
the SDK and compares the id. It checks that the steps spend only the funding coin and
outputs of earlier steps, that every fee equals the spent values minus the output values,
that every output is either a coin bound to the token's covenant id or a payment to one
of the three parties, and that the covenant id is the one the SDK derives from the first
step. Whether such a coin is locked by one of the reference's contracts is check h;
recomputing the locks needs the harness, so the command below prints `NOT CHECKED` for it.

```
..\.venv\Scripts\python launch_send.py check results\2026-10-11-testnet-10\chain.json --party issuer=kaspatest:qr9qu3z2cfv03506hxwct55hz00acg0wynz2c733cnhy0t9v0d4kg8gzyrlea --party bob=kaspatest:qp947566r49dz85sryktf2e3eys783hp2u527u0fnyynnhn937jtk4rz3q9m9 --party alice=kaspatest:qpqhsayjhjz8846pr3cxxc4gfnpdawhn3cvlht3xyyqt839u3xnzy3v7q4ckw
```

It prints `ok` for checks a to g, `NOT CHECKED` for check h, and a summary: 13 steps,
3 probes, 25 tokens.

**The network, read only.** `status` asks a public testnet-10 node which steps of the
chain file are on chain and which of its coins are unspent. It sends nothing:

```
..\.venv\Scripts\python launch_send.py status results\2026-10-11-testnet-10\chain.json --party issuer=kaspatest:qr9qu3z2cfv03506hxwct55hz00acg0wynz2c733cnhy0t9v0d4kg8gzyrlea --party bob=kaspatest:qp947566r49dz85sryktf2e3eys783hp2u527u0fnyynnhn937jtk4rz3q9m9 --party alice=kaspatest:qpqhsayjhjz8846pr3cxxc4gfnpdawhn3cvlht3xyyqt839u3xnzy3v7q4ckw
```

On the day of the run it answered `on chain` for each of the 13 steps, `no trace` for
each of the 3 forbidden moves, and listed six `covenant KCC20` coins and one
`covenant TokenSeed` coin of 1 test KAS each.
[`launch/results/2026-10-11-testnet-10/status-after.log`](launch/results/2026-10-11-testnet-10/status-after.log)
holds that answer, taken 23 seconds after the run. The picture can change: these coins
can still be spent - by the reference's rules anyone may use the seed to create an empty
token coin, or split the seed - and a test network can be reset.

**Two checksums.** The first line of the run's record
([`launch/results/2026-10-11-testnet-10/records/`](launch/results/2026-10-11-testnet-10/records))
names the SHA-256 of the chain file and of the sender as they were at the run. Both files
are here unchanged, so the numbers can be compared: `check` prints the chain file's, and
`Get-FileHash launch_send.py -Algorithm SHA256` (PowerShell; it prints capital letters,
the value is the same) or `sha256sum launch_send.py` gives the sender's.

These commands were run from a fresh copy of the repository on 2026-10-11, on Windows 11.
`python` in the first line was CPython 3.12.14, called by its full path; any CPython from
3.10 to 3.14 that the `kaspa` package supports should do. On Linux or macOS use
`.venv/bin/python` and forward slashes; with forward slashes the three commands after the
install were also run in Git Bash on Windows, not on another system.

No block-explorer links are given. On the day of the run the two public testnet-10
explorers that were tried did not know the launch transaction, while nodes listed its
coins; `status` reads the same facts from a node.

## How to read the record

**Offline and live.** "Offline" in the record means the builder's judgement before
sending; "the node" means the live answer of a testnet-10 node. All three forbidden moves
got the same answer, `script ran, but verification failed`: it names the kind of script
failure, not the check of the contract that failed. Other kinds of failure were not tried
live. So that each move was refused *at its own rule* is known from the offline judgement
only; the live run shows that each was refused.

**Rule ids.** `K-38`, `K-37` and `S-12` are this study's own numbers for the checks in
the reference's contracts; the full numbered list is not published here. The three are,
in the generated SilverScript the reference tracks at `c8a0871` in
`fixtures/public-mint/sil/`:

| Id | Where | The rule |
|---|---|---|
| K-38 | [`KCC20.sil`, lines 69-72](https://github.com/argent-lang/kcc20-reference/blob/c8a087117735a1f87c5c6d115fcddeaf2562c784/fixtures/public-mint/sil/KCC20.sil#L69-L72) | the owner's signature: `checkSig` against the key in the coin's owner field |
| K-37 | [`KCC20.sil`, line 175](https://github.com/argent-lang/kcc20-reference/blob/c8a087117735a1f87c5c6d115fcddeaf2562c784/fixtures/public-mint/sil/KCC20.sil#L175) | the tokens going out equal the tokens coming in |
| S-12 | [`TokenSeed.sil`, line 132](https://github.com/argent-lang/kcc20-reference/blob/c8a087117735a1f87c5c6d115fcddeaf2562c784/fixtures/public-mint/sil/TokenSeed.sil#L132) | a coin created by a seed holds zero tokens |

**Honest twins.** Each forbidden move was built as an honest move with one thing wrong,
and offline the honest move of the same shape was accepted. The twins themselves were not
sent.

## What the run made concrete

- **Ids calculated ahead held.** All 13 transactions were built and signed before the
  first was sent, each spending outputs of the one before, and each was accepted under
  the id calculated offline. A transaction id covers the outpoints, the outputs and a few
  fixed fields. It does not cover the signature scripts, the mass field or the compute
  budgets (the last section of [`launch/FORMAT.md`](launch/FORMAT.md)). So a chain can be
  prepared in one tool and checked and sent by another - and equal ids prove nothing
  about the signatures.
- **The fee followed the storage mass, by choice.** Every covenant coin of the run holds
  1 test KAS. For ten of the 13 steps the storage mass a node calculates was between
  70,721 and 80,028 grams, several times the mass a node's fee floor is charged on (2,540
  to 17,822). This run charged its fee rate on the larger of the two, so those steps cost
  0.28 to 0.32 test KAS each; the three steps that close a coin and return the 1 test KAS
  it held cost 0.02 to 0.16. The rate, 400 sompi per gram, was set on the command line:
  above the nodes' normal estimate on the day (196 to 282) and below their priority
  estimate (1,212 to 2,379); every step was still seen within 6 seconds. Whether a node
  would have accepted these steps for less - the default relay floor, as the builder
  calculated it for them, was 0.0025 to 0.018 test KAS - was not tried. The numbers of
  every step are in
  [`chain.json.txt`](launch/results/2026-10-11-testnet-10/chain.json.txt).

## What this shows and what it does not

It shows that one honest launch and 12 honest moves of the reference contracts were
accepted by testnet-10 nodes of version 2.1.0 exactly as built, and that three moves a
contract rule forbids were refused.

It does not show:

- which rule a live node refused at;
- anything about other networks, about mainnet, or about other launches of the reference
  or other tokens;
- that the reference is safe: this is one run on one day with one fee rate, 16
  transactions in all, and not an audit;
- the paths the 13 moves did not take: every token coin of the run is owned by a plain
  key (owner scheme 0), only the borrow schemes 0 and 1 occur, and no move has more than
  two token coins going in or coming out, while the reference supports other owner
  schemes, other borrow schemes and up to three token coins in and out;
- proof, from here, that the three forbidden moves were sent and refused: a refused
  transaction leaves nothing on chain, and `no trace` fits "never sent" as well. That
  rests on `send.log` and the run's record, as does "calculated offline before anything
  was sent", which rests on the times the files state;
- what the two unpublished programs did. That every transaction passed the node's rules
  offline, that each forbidden move was refused offline at the rule named and its honest
  twin accepted, and that every covenant lock was recomputed from its stated state before
  sending, are stated in the record and cannot be checked from here. What can be checked
  from here is named under "Check it yourself".

The sender has limits of its own, listed in [`launch/README.md`](launch/README.md) under
"What this tool does not show": it does not run scripts or verify signatures, it believes
the node it asks, and "seen" means one node listed the coin, not a number of
confirmations.

## Environment

- `kaspa==2.1.0` from PyPI (the Kaspa Python SDK), hashes pinned in `requirements.txt`;
  no other dependency, the tests use the standard library
- Public testnet-10 nodes found by the SDK's resolver; the two used on the day of the run
  are named in the logs of the record

## Related

An earlier and smaller exercise:
[kaspa-covenant-starter-lab](https://github.com/0xlegacydag/kaspa-covenant-starter-lab) -
six small contracts checked offline, four of them also run on testnet-10.

## License

ISC - see `LICENSE`. `NOTICE` says what in this repository comes from the work of others.
