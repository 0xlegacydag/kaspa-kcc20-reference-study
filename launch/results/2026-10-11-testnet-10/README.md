# Run record: a test token from the KCC20 reference contracts on Kaspa testnet-10, 2026-10-11

A test network and test coins without value: **KAS below always means test KAS of
testnet-10.** This is the record of an independent study, not a token offering and not a
token project. The token below is one instance of the published KCC20 reference contracts
(`argent-lang/kcc20-reference`, revision `c8a0871`: the contracts KCC20, PublicMint and
TokenSeed), launched once and taken through 12 further moves, to see whether a live
network judges its moves the way an offline check did. The study is not affiliated with
the authors of the reference.

## The test token

| | |
|---|---|
| Label | `0xlegacydag` - the field `token_name` of the files: it says whose run this is. KCC-20 defines no name field; this token is identified by its covenant id. This is not a ticker. |
| Covenant id | `0d81e3e1d9f1c9568acd38e932f22eef1ea96dd6480d351e47cf61c692a4716a` |
| Launch transaction | `0f6a30b3b5a6b3b086b759a26db094513aeb3b6bc1239860963994f58c0466de` |
| Supply | 25 tokens in 6 coins: bob 12, alice 13 |
| Minters | none left: the whole allowance of 25 was minted and the minter was closed |
| Seeds | 1 |

## Words used here

- **Covenant id** - the number every coin of one token carries; it ties them together.
- **Minter** - a coin of the PublicMint contract: it holds an allowance and mints tokens
  out of it.
- **Seed** - a coin of the TokenSeed contract: it may create token coins that hold zero
  tokens.
- **Deposit** - the 1 test KAS a covenant coin holds; it goes back to a party when the
  coin is closed.
- **Open to payments** - a token coin that accepts incoming tokens without its owner's
  signature (the reference's "borrowed receive"); "threshold 0" is the parameter of that
  permission as the chain file states it.
- **Witness** - what a spender hands to a contract's script; here, the owner's signature.
- **Honest twin** - a forbidden move with its one wrong thing put right; built and judged
  offline, not sent.
- **Gate** - the builder's offline stand-in for a node (the builder is the program that
  built and signed the chain; it is not in this repository).

## The run

- Submitted 2026-10-11T12:28:36Z to 2026-10-11T12:29:19Z (UTC) through the public node
  `wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh` (version 2.1.0), and read back
  23 seconds later from a second one, `wss://muon-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh`
  (version 2.1.0).
- 13 steps, each submitted only after every output of the step before it was visible on chain
  with the expected value, script and covenant id. All 13 were accepted, each under the id the
  offline builder had calculated.
- Then 3 forbidden moves. All 3 were refused by the node.
- Every covenant coin holds 1.00000000 test KAS. Fee rate 400 sompi per gram, charged on the
  larger of the mass a node's fee floor uses and the storage mass: 3.38598000 test KAS over the
  13 steps. The rate was set on the command line, above the nodes' normal estimate at the time
  and below their priority estimate (`prepare.log` and the check logs show both).

### Steps

| # | Step | What happens | Transaction | Fee, test KAS | Seconds until all outputs were seen |
|---|---|---|---|---|---|
| 1 | launch | the issuer's coin creates the minter (25 to mint, at most 10 per mint) and the seed | `0f6a30b3b5a6b3b086b759a26db094513aeb3b6bc1239860963994f58c0466de` | 0.32011200 | 1.3 |
| 2 | mint | the minter mints 10 tokens to Alice | `d810a15d1c470f700f66fc86c7be84f33f21f2f59d3217fe4313bc6f366c9722` | 0.30896400 | 2.7 |
| 3 | transfer | Alice moves 4 tokens to Bob and keeps 6 (one coin in, two out) | `c4d393e714fd7288373f61d6f4e6db4383b5ca8855bd9079538a389bd09eae7c` | 0.30844400 | 1.3 |
| 4 | seed create | the seed creates a zero-token coin for Bob, open to payments (threshold 0) | `e2396f7b70f0d571405bdfc67000b1b76d93ea259f737a62e2aed03dfef1eba7` | 0.30786800 | 2.4 |
| 5 | borrowed receive | Alice pays 3 tokens into Bob's open coin; Bob does not sign | `02968cd4ad7a24c82448267b4017670505c69b36b66af44ddb533d5cf94f5c5f` | 0.28288400 | 2.4 |
| 6 | minter split | the minter hands 5 of its 15 to a new minter owned by Bob | `067572570985f44903c2485ea772e098b1b460f3c25aeae8e2b6483e548370c2` | 0.30710400 | 2.5 |
| 7 | mint from the split | Bob's minter mints 2 tokens to Bob | `2806c76782e7bfda79508fdc4f0c204d80abbeee8f89dd837ba8a5da69d035c4` | 0.30637600 | 4.7 |
| 8 | reclaim into | Bob's minter (3 left) retires into the issuer's minter; Bob signs and gets the deposit | `3122ba0632f1a0e601915bdbab0c60c987071c419fd30b7d5b7d6ab11a079d14` | 0.15819200 | 6.0 |
| 9 | mint | the minter mints 10 tokens to Alice | `78e23990321b7decd966c14887b59806310b6faed043a3cbe44de2489c989da5` | 0.30547600 | 3.6 |
| 10 | last mint | the minter mints its last 3 tokens to Bob | `da0e499e795454c2dbecea6a38ccbce336829c916315f95f25096a8e7a309961` | 0.30456800 | 2.4 |
| 11 | minter reclaim | the issuer closes the empty minter and gets the deposit | `da5a7ffe0f388af7b4f56e2652aa2750784e46782df90a72abdef51ca4bde74e` | 0.02336000 | 2.2 |
| 12 | seed split | the seed creates a second seed owned by Bob | `e00b6f02fca077c329034dde626d4536089bdd3e1b86e6b492c3e5b55e97be65` | 0.30350800 | 6.0 |
| 13 | seed reclaim | Bob's seed is closed next to the issuer's; Bob signs and gets the deposit | `c5f46d16f2df63f1c86584de96942ae6ab9a0210880a4805d5040ed6fc72bcde` | 0.14912400 | 2.5 |

### Forbidden moves

Each differs from an honest move in one thing. Offline, the script engine refused each at
the rule named below while the honest twin of the same shape was accepted. A live node does
not name a rule; its answer is given word for word. The rule ids are this study's own
numbers for the checks in the reference's contracts; the
[README at the root of the repository](../../../README.md#how-to-read-the-record) says where
each of the three is in the SilverScript the reference generates and tracks.

- **B1 transfer without the owner's signature.** Alice's 10 tokens are moved to Bob with a witness signed by Bob's key, not Alice's. Transaction `d6fcdb55f0b88bc35ce204eb3857c7833b16d772bc722e02ef8f5cad5f2c5d5d`. Offline: refused at input 0, rule K-38. The node: `RPC Server (remote error) -> Rejected transaction d6fcdb55f0b88bc35ce204eb3857c7833b16d772bc722e02ef8f5cad5f2c5d5d: failed to verify the signature script: script ran, but verification failed`
- **B2 more tokens out than in.** Alice signs a transfer of her 3-token coin into 3 tokens for herself and 1 for Bob: 4 out of 3. Transaction `7fe40b514e880a246bfd4e4f6b4de099e2759f01bdd23eb33c2e1297cfad6bdc`. Offline: refused at input 0, rule K-37. The node: `RPC Server (remote error) -> Rejected transaction 7fe40b514e880a246bfd4e4f6b4de099e2759f01bdd23eb33c2e1297cfad6bdc: failed to verify the signature script: script ran, but verification failed`
- **B3 the seed creates a coin that already holds tokens.** The issuer's seed creates a token coin for Bob that holds 5 tokens nobody minted. Transaction `911cab536d942c7d5e80d551eefe3fa580451c6967eb9a1853a406c43710918e`. Offline: refused at input 0, rule S-12. The node: `RPC Server (remote error) -> Rejected transaction 911cab536d942c7d5e80d551eefe3fa580451c6967eb9a1853a406c43710918e: failed to verify the signature script: script ran, but verification failed`

### Balances of the three keys

| Party | Address | Before, test KAS | After, test KAS |
|---|---|---|---|
| alice | `kaspatest:qpqhsayjhjz8846pr3cxxc4gfnpdawhn3cvlht3xyyqt839u3xnzy3v7q4ckw` | 0.00000000 | 0.00000000 |
| bob | `kaspatest:qp947566r49dz85sryktf2e3eys783hp2u527u0fnyynnhn937jtk4rz3q9m9` | 19.98118900 | 21.98118900 |
| issuer | `kaspatest:qr9qu3z2cfv03506hxwct55hz00acg0wynz2c733cnhy0t9v0d4kg8gzyrlea` | 974.40389316 | 962.01791316 |

The three are throwaway test keys. The issuer paid every fee. Of the 30.00000000 test KAS coin
the run started from, 7.00000000 stay in covenant coins, 3.00000000 came back as the deposits
of two closed minters and one closed seed, 3.38598000 were fees, and 16.61402000 returned as
change.

### Coins of the run that are unspent after the last step

| Transaction | Output | Test KAS | What |
|---|---|---|---|
| `c4d393e714fd7288373f61d6f4e6db4383b5ca8855bd9079538a389bd09eae7c` | 0 | 1.00000000 | token coin of bob: 4 tokens |
| `02968cd4ad7a24c82448267b4017670505c69b36b66af44ddb533d5cf94f5c5f` | 0 | 1.00000000 | token coin of bob: 3 tokens, open to payments |
| `02968cd4ad7a24c82448267b4017670505c69b36b66af44ddb533d5cf94f5c5f` | 1 | 1.00000000 | token coin of alice: 3 tokens |
| `2806c76782e7bfda79508fdc4f0c204d80abbeee8f89dd837ba8a5da69d035c4` | 1 | 1.00000000 | token coin of bob: 2 tokens |
| `3122ba0632f1a0e601915bdbab0c60c987071c419fd30b7d5b7d6ab11a079d14` | 1 | 1.00000000 | deposit to bob |
| `78e23990321b7decd966c14887b59806310b6faed043a3cbe44de2489c989da5` | 1 | 1.00000000 | token coin of alice: 10 tokens |
| `da0e499e795454c2dbecea6a38ccbce336829c916315f95f25096a8e7a309961` | 1 | 1.00000000 | token coin of bob: 3 tokens |
| `da5a7ffe0f388af7b4f56e2652aa2750784e46782df90a72abdef51ca4bde74e` | 0 | 1.00000000 | deposit to issuer |
| `c5f46d16f2df63f1c86584de96942ae6ab9a0210880a4805d5040ed6fc72bcde` | 0 | 1.00000000 | seed of issuer |
| `c5f46d16f2df63f1c86584de96942ae6ab9a0210880a4805d5040ed6fc72bcde` | 1 | 1.00000000 | deposit to bob |
| `c5f46d16f2df63f1c86584de96942ae6ab9a0210880a4805d5040ed6fc72bcde` | 2 | 16.61402000 | change to issuer |

## Files in this folder

The files below are kept byte for byte as the programs and the shell wrote them. This page
is a summary of them, written after the run.

- `request.json`, `prepare.log` - the funding coin as read from the network before building,
  and the fee rate of the run: 400 sompi per gram, given on the command line. `prepare.log`
  is what `prepare` printed, with the node's own fee estimates at that moment.
- `chain.json`, `chain.json.txt` - every transaction in full, as built and signed offline and
  judged by the builder's gate; SHA-256 of `chain.json`:
  `fb4c8dee62d86fc7e82a3696e188b1f1dc6881f9906ca6f4a86d8f880e841d99`. `chain.json` gives
  12:20:12Z as the time it was built; both files were written before sending: that is why they
  say that nothing was sent (the sender refuses a chain file that does not say so), and
  "accepted by scripts, consensus on submission, the mempool and inside a block" in them is
  the answer of the offline gate, not of the network.
  The fee sentence at the head of `chain.json.txt` ends "it did not settle ... for 0 of the 13
  steps": the calculation settled for all 16 transactions, so every fee equals the rate times
  the larger mass. The first line of `chain.json.txt` calls the token "KCC-20 reference
  token": read "a test token made from the reference contracts".
- `check-online.log`, `check-online-2.log` - the sender's check of that file with the network
  read, before anything was sent: the same check through two nodes.
- `send.log`, `records/` - the run as it happened: the screen, and one JSON object per event.
- `status-after.log` - the chain read back from the second node after the run.

In `send.log` and `status-after.log` the time lines at the top and the bottom and the line
`exit=0` were added by the shell that captured the output; everything between them is the
program's output.

## What this shows and what it does not

It shows that one honest launch and 12 honest moves of the reference contracts were accepted
by testnet-10 nodes of version 2.1.0 exactly as built, and that three moves a contract rule
forbids were refused. It is one run on one day with one fee rate, and not an audit. What it
does not show is listed in the
[README at the root of the repository](../../../README.md#what-this-shows-and-what-it-does-not).
