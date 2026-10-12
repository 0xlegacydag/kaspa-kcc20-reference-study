# kcc20-family

The pinned KCC-20 reference contracts (KCC20, PublicMint, TokenSeed) as data: scripts,
states, calls and whole transaction shapes.

The crate builds transactions with its own assembler. It never asks whether a transaction
is valid, so any field can be made wrong on purpose and the result still reaches the script
engine. It does not judge transactions; another crate does.

## What it reads

No file of the reference is copied here. The crate reads, from a checkout of
`argent-lang/kcc20-reference` at `c8a0871`:

- `fixtures/public-mint/artifact.json` (the published artifact, id
  `b48c90c8e287d227821ac40f0875a753e329e1ab3c8fdfa1477f55419cfa26ab`),
- `fixtures/public-mint/sil/{KCC20,PublicMint,TokenSeed}.sil` (the generated sources),
- `fixtures/kcc20/conformance.json` (the conformance vectors, tests only).

The checkout is found through the environment variable `KCC20_REFERENCE_DIR`. Without it
the crate looks for a directory `kcc20-reference` beside the directory of this workspace.
In this repository the workspace is the folder `engine/`, so the default place is the
folder `kcc20-reference` at the root of the working copy, next to `engine/`; git ignores it
there. The default is written in one place, `src/refdata.rs`. How to make the checkout is in
[the README of the workspace](../../README.md). The rule inventory is read from
`data/rule-inventory.json` of this workspace.

## What is taken from Argent and SilverScript, and what is written here

Taken: the artifact types and Argent's consistency check (`argent::artifact`), the codec
that encodes states and call arguments (`argent::codec`), the SilverScript compiler (only to
rebuild the pinned sources with debug information), and the script builder and standard
script helpers of `kaspa-txscript`.

Written here: which bytes go where. The redeem script, the script public key, the hidden
arguments of `mint` and `create`, the signature script, the transaction and its coins are
all put together by this crate. Argent's `TxBuilder` and its execution helpers are used only
in the tests, as the authors' yardstick.

## API in one page

```rust
use kcc20_family::{Family, Entry, Profile, shapes, SourceMap, Contract};

let family = Family::pinned();                       // the published artifact
let mut scenario = shapes::transfer(&Profile::Script, 1, 1);   // an honest transaction
scenario.contract_input_mut(0).declared_states_mut()[0].amount += 1;   // make it wrong
let assembled = scenario.assemble(family)?;          // Transaction + coins + input reports
// assembled.tx, assembled.utxos, assembled.inputs -> hand them to an engine
```

`refdata` - `reference_dir()`, `load_pinned_artifact()` (checks the id),
`pinned_artifact()`, `load_sil_source(contract)`, `load_conformance_vectors()`.

`family` - `Contract`, `Entry` (the 11 entries), `EntryRole`, and `Family`:

- `Family::pinned()`, `Family::from_artifact(artifact)`,
  `family.with_bytecode(contract, bytes)` (one contract's bytecode replaced, its template
  hash recomputed, the state span kept; the other contracts meet the new hash through their
  state fields and hidden arguments);
- `bytecode`, `state_span`, `prefix`, `suffix`, `template_hash`, `dispatch_tag`;
- `runtime_state(&state)`, `state_bytes(&state)`, `redeem_script(&state)`,
  `script_public_key(&state)`;
- `hidden_args(entry)`, `call_bytes(entry, &user_args)`,
  `call_parts(entry, &user_args, &redeem)`, `signature_script(entry, &user_args, &state)`.

`states` - `Kcc20State`, `PublicMintState`, `TokenSeedState`, `State`, and the scheme
constants (`OWNER_*`, `BORROW_*`, `PATH_*`). The types do not restrict values.

`raw` - `push`, `push_number`, `push_explicit`, `push_redeem`, `push_as(form, data)` (any
opcode form), `split_pushes`, and `CallParts { arguments, tag, redeem }`: a signature script
as parts that can be changed one by one.

`keys` - fixed keys (`keypair(seed)`, `x_only`, `compressed`; `ALICE`, `BOB`, `CAROL`,
`DAVE`, `FUNDER`), `SigningContext`, deterministic `schnorr_signature` / `ecdsa_signature`
for any key and signature hash type.

`witness` - the witnesses of the five owner schemes and the three borrow schemes, as
`LateBytes`; `public_key_hash`, `chain_guard`.

`scenario` - `Scenario { inputs, outputs, version, lock_time, subnetwork_id, gas, payload,
storage_mass }` with

- `ContractInput`: state, value, covenant id, outpoint, `Call::Typed { entry, args }` or
  `Call::Raw(bytes)`, sequence, compute commitment, and the overrides `patch` (edit the
  `CallParts`), `pushed_redeem`, `locking_script`, `signature_script`; `witness_mut()` is
  the witness or owner signature of the five entries that take one and panics for the
  others, `new_owner_mut()` is the public key of the two `split` entries;
- `OrdinaryInput`: script public key, value, covenant id, signature script;
- `ContractOutput` (the state LOCKED into the output; the state DECLARED to the entry lives
  in the call arguments, independently) and `PlainOutput`;
- `Arg::{Value, Bytes, State, States, Computed}` and `LateBytes::{Fixed, FromTx}`: bytes
  known now or computed from the finished transaction (signatures), with `LateBytes::map`
  to damage a real signature;
- `scenario.assemble(&family) -> Assembled { tx, utxos, inputs }`. Signing happens after all
  outputs exist. The assembler validates nothing.

`shapes` - honest scenarios: `transfer(profile, inputs, outputs)`,
`transfer_with_owner_scheme(profile, role, scheme)`, `borrow(profile, kind)`, `mint`,
`mint_split`, `mint_reclaim`, `mint_reclaim_into`, `seed_create`, `seed_split`,
`seed_reclaim`, `for_entry(profile, entry)`, `all(profile)` (29 shapes). Every party of a
shape has a key of its own and no two token outputs hold the same state: a transfer goes
from the keys `0xaa + k` to the keys `0xbb + k`, a mint goes from Alice's minter to Bob,
and a coin of owner scheme 0x04 is owned by a second covenant whose coin is an input of
its own. The reference's own shape of that scheme, a coin owned by the token's covenant
itself, is `transfer_owned_by_its_own_covenant(profile, role)`, outside `all`. Two value profiles:
`Profile::Script` (1000-sompi coins and, where a shape has one, an `OP_TRUE` funding coin) and
`Profile::Realistic` (caller's coin values, a signed pay-to-public-key funding coin, change
and fee).

`sourcemap` - `SourceMap::pinned().contract(c)` gives `opcodes()`, `opcode_at(offset)`,
`opcode_by_index(n)`, `entry_at`, `line_at` (statement and text from the compiler's debug
information; the innermost statement is the one with the narrowest byte range, and a map
in which two statements share a range is refused), `place_at` (frame, dispatcher, argument size checks, statement, glue,
clean-up), `rule_at(offset)` (the `K-nn` / `M-nn` / `S-nn` record of the rule inventory) and
`describe(offset)`. `last_redeem_opcode_index(log_lines, pushes)` turns a line count of the
engine's opcode log into an opcode ordinal of the redeem script.

## Things to know

- Offsets of the source map are those of the artifact's bytecode. They hold for every
  redeem script this crate builds for the same contract (the encoded state always has the
  length of the state span) and for a same-length replacement made with `with_bytecode`.
- A family with a replaced bytecode is no longer an Argent artifact: `family.artifact()`
  returns `None`, and `SourceMap::build` refuses it, because the sources no longer compile
  to its bytes. Use `SourceMap::pinned()` for the lines.
- The script profile is for the script engine only: it asks no block and no mempool. The
  realistic profile takes its coin values, funding and fee from the caller.
- Signatures are deterministic (Schnorr without auxiliary randomness, ECDSA by RFC 6979):
  a scenario always assembles to the same bytes.
- The source map takes the statement of a byte to be the one with the narrowest byte
  range. The call depth and the markers of inlined calls that the compiler's debug
  information also carries (`SourceStep::call_depth` and the two marker kinds) are copied
  as recorded and used for nothing.

## Tests

`cargo test --frozen -p kcc20-family`

`--frozen` works after one `cargo fetch --locked` with a network, and the tests need the
checkout of the reference: both are described in
[the README of the workspace](../../README.md).

- `identity`: the artifact id, sizes, spans, template hashes and tags as published; the
  pinned sources compile to the pinned bytecode; a replaced bytecode reaches the other
  contracts through hashes only.
- `shapes`: the authors' runner accepts all 29 honest shapes in both profiles; no shape
  gives two roles one key or two token outputs one state; the covenant-id scheme needs
  the coin of the second covenant.
- `differential`: every honest shape built through Argent's `TxBuilder` gives the same
  bytes; the only difference before the runner is the compute budget the builder measures.
- `conformance`: state and argument encoding, tags, witness lengths, key hashes and the
  hash chain equal the vectors of the reference.
- `refusals`: wrong transactions leave the assembler, are refused at the expected input,
  and the opcode the engine stopped at is the one the rule inventory names.
- `sourcemap`: every refusing opcode of the inventory is where the inventory says, and the
  compiler's lines agree with the inventory's lines.

Unit tests inside `src/` cover the table of registered keys, the default directory of the
reference and the detection of two statements with one byte range.
