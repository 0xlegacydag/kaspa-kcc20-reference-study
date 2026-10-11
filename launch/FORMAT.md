# File formats of the launch

Two JSON files pass between the two programs. Both are UTF-8 with LF line endings. All
amounts are sompi (1 KAS = 100,000,000 sompi). All byte strings are lowercase hex.
Neither file ever holds a secret key. KAS on this page always means test KAS of
testnet-10.

- The **request** is written by the sender's `prepare` command after it has read the
  network, and read by the builder.
- The **chain** is written by the builder, offline, and read by the sender.

The builder is a Rust program that is not in this repository. It builds and signs every
transaction and runs each one against the node rules of `node-gate`, its offline stand-in
for a node: the node's own script engine and mass calculator, with the rules around them.
The sender is `launch_send.py` (Python, Kaspa SDK). It holds no keys: every signature is
already in
the chain file. It rebuilds every transaction from the fields, checks the file by its own
rules and only then submits. It does not submit unless a second tool has rebuilt the lock
of every covenant coin from its stated contract state (`--harness`).

## Request: `kcc20-launch-request/1`

```
{
  "format": "kcc20-launch-request/1",
  "network": "testnet-10",
  "read_at_utc": "2026-01-01T12:00:00Z",
  "node": "wss://...",
  "token_name": "example-token",
  "coin_value": 100000000,
  "feerate": 955,
  "fee_cap_total": 1500000000,
  "funding": {
    "transaction_id": "<64 hex>",
    "index": 0,
    "value": 3000000000,
    "script_public_key_version": 0,
    "script_public_key": "<hex>"
  }
}
```

- `token_name` is a label the operator gives a run. Nothing on chain carries it.
- `coin_value` is the value of every covenant coin of the run.
- `feerate` is sompi per gram, a whole number, at least 100.
- `fee_cap_total` bounds the sum of the fees of all steps. The builder writes no chain
  above it.
- `funding` is the one plain coin the whole run starts from, as the node reported it. It
  must be locked to the issuer's key; in the chain its `owner` is `issuer`.

Keys are not in the request. The builder reads them from key files kept outside the
repository.

## Chain: `kcc20-launch-chain/1`

```
{
  "format": "kcc20-launch-chain/1",
  "network": "testnet-10",
  "built_at_utc": "2026-01-01T12:05:00Z",
  "nothing_was_sent": true,
  "token_name": "example-token",
  "coin_value": 100000000,
  "feerate": 955,
  "fee_rule": "<one sentence>",
  "fee_cap_total": 1500000000,
  "funding": { ...as in the request..., "owner": "issuer" },
  "parties": {
    "issuer": { "x_only_public_key": "<64 hex>", "script_public_key": "<hex>" },
    "alice":  { ... },
    "bob":    { ... }
  },
  "covenant_id": "<64 hex>",
  "steps":  [ <transaction>, ... ],
  "probes": [ <transaction>, ... ],
  "totals": {
    "fees": 0,
    "locked_at_peak": 0,
    "locked_at_the_end": 0,
    "deposits_returned": 0,
    "change_at_the_end": 0,
    "tokens_minted": 25
  }
}
```

- `parties` maps a name to a key. A party's `script_public_key` is the pay-to-public-key
  script of its key: `20 <32-byte x-only key> ac`, version 0. The names are arbitrary; the
  real run has `issuer`, `alice` and `bob`. The sender is told the parties' addresses on its
  command line and compares. No two parties share a key.
- `steps` are sent in order. Each is expected to be accepted. Each spends the funding coin
  or outputs of earlier steps of this file.
- `probes` are forbidden moves. Each is expected to be refused. Each spends only coins
  that are unspent after the last step; two probes may spend the same coin, because none
  of them is meant to be accepted. A probe is a whole transaction like a step, with its
  fee, masses and gate answers, and its outputs still go only to the contracts and the
  parties, in the same form as a step's.
- Names of transactions are unique across steps and probes. No JSON object repeats a key.
- `totals.fees` is the sum of the fees of the steps and is checked; the other totals are
  for a reader, and a difference is noted, not refused.

### Transaction

```
{
  "name": "01 launch",
  "what": "<one sentence for a reader>",
  "expect": "accepted",
  "transaction_id": "<64 hex>",
  "version": 1,
  "lock_time": 0,
  "subnetwork_id": "<40 hex>",
  "gas": 0,
  "payload": "",
  "mass": 80002,
  "inputs": [
    {
      "transaction_id": "<64 hex>",
      "index": 0,
      "sequence": 0,
      "sig_op_count": 0,
      "compute_budget": 10,
      "signature_script": "<hex>",
      "spends": {
        "from": "funding",
        "value": 3000000000,
        "script_public_key_version": 0,
        "script_public_key": "<hex>",
        "covenant_id": null,
        "what": "<a few words>"
      }
    }
  ],
  "outputs": [
    {
      "value": 100000000,
      "script_public_key_version": 0,
      "script_public_key": "<hex>",
      "covenant_binding": { "authorizing_input": 0, "covenant_id": "<64 hex>" },
      "role": "covenant",
      "to": null,
      "state": { "contract": "PublicMint", "remaining": 25, "mint_amount": 10,
                 "owner": "<64 hex>", "extension_commitment": "<64 hex>" },
      "what": "<a few words>"
    },
    {
      "value": 2799000000,
      "script_public_key_version": 0,
      "script_public_key": "<hex>",
      "covenant_binding": null,
      "role": "change",
      "to": "issuer",
      "state": null,
      "what": "<a few words>"
    }
  ],
  "fee": 0,
  "fee_floor": 0,
  "masses": {
    "compute_mass": 0,
    "transient_mass": 0,
    "calculated_storage_mass": 0,
    "fee_mass": 0
  },
  "gate": {
    "scripts": true,
    "consensus": true,
    "mempool": true,
    "block": true,
    "refusal": null
  }
}
```

- `expect` is `"accepted"` for a step and `"refused"` for a probe.
- Fixed values, the same in every transaction of a chain: `version` 1, `lock_time` 0,
  `gas` 0, an empty `payload`, the all-zero `subnetwork_id`, and on every input `sequence` 0
  and `sig_op_count` 0. A version-1 input commits to a compute budget instead of a count of
  signature operations. The run writes nothing into a payload.
- `mass` is the storage mass a node calculates for the transaction; it is the value of the
  transaction's mass field.
- `spends.from` is `"funding"` or `{ "step": "<name of an earlier step>", "output": <index> }`.
  `spends.covenant_id` is the covenant id the spent coin carries, or null.
- `role` is `"covenant"` (a coin of one of the three contracts, bound to the token's
  covenant id), `"deposit"` (a covenant coin's value returned to a party) or `"change"`
  (the remainder, to the party that pays). `to` names the party for the last two and is
  null for a covenant coin.
- `state` describes a covenant coin so that a second tool can rebuild its lock. Every
  covenant output has one, in steps and in probes; for a probe it is the state the
  forbidden move claims. The `owner` of a state is the x-only key of a party, and a KCC20
  coin has `owner_scheme` 0 (a key owner, Schnorr):
  - `{ "contract": "KCC20", "amount": 0, "owner": "<64 hex>", "owner_scheme": 0,
    "borrow_scheme": 0, "borrow_guard": "<64 hex>", "extension_commitment": "<64 hex>" }`
  - `{ "contract": "PublicMint", "remaining": 0, "mint_amount": 0, "owner": "<64 hex>",
    "extension_commitment": "<64 hex>" }`
  - `{ "contract": "TokenSeed", "owner": "<64 hex>", "extension_commitment": "<64 hex>" }`
- `fee` is the sum of the spent values minus the sum of the output values. `fee_floor` is
  the least fee a default node relays the transaction for.
- `gate` is what `node-gate` answered. For a step all four are true and `refusal` is null.
  For a probe `refusal` is
  `{ "layer": "scripts", "input": 0, "rule": "<rule id or null>", "message": "<text>" }`
  and the builder has also checked that the honest twin of the probe is accepted.

### Limits the sender enforces

The sender refuses a chain outside these bounds, whatever the file says: the funding coin
holds at most 30 KAS; `coin_value` is exactly 1 KAS; the fees of the steps plus the most
expensive probe are at most 15 KAS; at most 20 steps and 10 probes; a mass field between 1
and 500,000; a compute budget of at most 1,000 per input; no empty signature script.

### What a transaction id does and does not cover

The id covers the version, the outpoints, the sequence numbers, the outputs with their
bindings, the lock time, the subnetwork, the gas and the payload. It does not cover the
signature scripts, the mass field or the compute budgets. Equal ids therefore prove
nothing about those three; they travel in the file as they are and a node judges them.
(In the SDK's object the signature operation count of an input is outside the id as well;
it is 0 in every transaction of a chain, and the sender refuses anything else.)
