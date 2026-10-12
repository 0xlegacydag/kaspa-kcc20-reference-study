//! A dry run of launching the reference token on testnet-10 and walking it through its life.
//!
//! Nothing is sent anywhere and nothing here can send: the chain of transactions is built in
//! memory and every transaction is put to the node rules of `node-gate` (scripts, consensus
//! on submission, the mempool policy of a default node, and the same transaction inside a
//! block). Every transaction spends outputs of the transactions before it: an outpoint is the
//! id of the earlier transaction and the index of the output, the value and the covenant id
//! are read from that output, and its script must be the script of the state the step claims.
//!
//! The keys are dry-run keys: a seed byte repeated 32 times. They are public knowledge and
//! guard nothing. The funding outpoint is made up.
//!
//! The run writes three files into the result directory:
//!
//! - `launch-plan.json`: every step with its transaction id, inputs, outputs, masses, fee,
//!   fee floor and the gate's verdicts; the totals; the search for the smallest coin value;
//! - `launch-plan.txt`: the same as a table for a reader;
//! - `launch-genesis-case.json`: the launch in the input format of a separate launch checker
//!   that is not published here; that program derived the same covenant id from it.

use std::fmt::Write as _;
use std::fs;

use checks::{Case, Harness, Outcome};
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::covenant_id::covenant_id;
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    CovenantBinding, TransactionId, TransactionOutpoint, TransactionOutput,
};
use kcc20_family::shapes::{SOMPI_PER_KAS, pay_to_public_key_script};
use kcc20_family::{
    Arg, Call, ContractInput, ContractOutput, Entry, EntryRole, Kcc20State, LateBytes,
    OrdinaryInput, PlainOutput, PublicMintState, Scenario, State, TokenSeedState, keys, raw,
    witness,
};
use serde_json::{Value, json};

/// Seed of the dry-run key of the issuer: owner of the starting coin, the minter and the seed.
const DRY_RUN_ISSUER: u8 = 0x15;
/// Seed of the dry-run key of Alice.
const DRY_RUN_ALICE: u8 = 0xa1;
/// Seed of the dry-run key of Bob.
const DRY_RUN_BOB: u8 = 0xb0;
/// Seed of the dry-run key that pays the fees from the launch change onwards.
const DRY_RUN_FEE_PAYER: u8 = 0xfe;

/// The made-up transaction id of the starting coin.
const FUNDING_TX_ID: [u8; 32] = [0xd0; 32];
/// The output index of the starting coin.
const FUNDING_INDEX: u32 = 0;
/// Value of the starting coin of the main run.
const START_VALUE: u64 = 100 * SOMPI_PER_KAS;

/// The reference's own demo numbers: 25 tokens to mint, at most 10 per mint.
const SUPPLY: i64 = 25;
const MINT_LIMIT: i64 = 10;

/// The fee of every step: the mempool floor of that transaction plus this share, rounded up.
const FEE_MARGIN_PERCENT: u64 = 10;

/// The covenant id of the launch with 1 KAS coins, as a separate program derived it: a
/// launch checker that is not published here was given `launch-genesis-case.json` and
/// derived this id from the outpoint and the two outputs. The node's function must give the
/// same id here.
const CROSS_CHECKED_COVENANT_ID: &str =
    "01cec74a0eea9ff51d31a5e948520ea7048b8775f70439f2d749db29fa7d5462";

/// Who or what holds a coin.
#[derive(Clone, Debug)]
enum Holder {
    /// A coin of one of the three contracts, with the state it holds.
    Covenant(State),
    /// A pay-to-public-key coin of the dry-run key with this seed.
    Key(u8),
}

/// A coin that exists at some point of the run.
#[derive(Clone, Debug)]
struct Coin {
    outpoint: TransactionOutpoint,
    value: u64,
    covenant_id: Option<Hash>,
    holder: Holder,
    what: String,
}

fn party(seed: u8) -> &'static str {
    match seed {
        DRY_RUN_ISSUER => "issuer",
        DRY_RUN_ALICE => "Alice",
        DRY_RUN_BOB => "Bob",
        DRY_RUN_FEE_PAYER => "fee payer",
        _ => "?",
    }
}

fn owner_name(owner: &[u8; 32]) -> &'static str {
    [
        DRY_RUN_ISSUER,
        DRY_RUN_ALICE,
        DRY_RUN_BOB,
        DRY_RUN_FEE_PAYER,
    ]
    .into_iter()
    .find(|seed| keys::x_only(*seed) == *owner)
    .map(party)
    .unwrap_or("?")
}

fn describe(state: &State) -> String {
    match state {
        State::Kcc20(token) => format!(
            "token coin of {}: {} tokens{}",
            owner_name(&token.owner),
            token.amount,
            if token.borrow_scheme == 0 {
                ""
            } else {
                ", open to payments"
            }
        ),
        State::PublicMint(minter) => {
            format!(
                "minter of {}: {} left to mint",
                owner_name(&minter.owner),
                minter.remaining
            )
        }
        State::TokenSeed(seed) => format!("seed of {}", owner_name(&seed.owner)),
    }
}

fn kas(sompi: u64) -> String {
    format!("{}.{:08}", sompi / SOMPI_PER_KAS, sompi % SOMPI_PER_KAS)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The signature script of a pay-to-public-key coin: one real Schnorr signature over the
/// whole transaction.
fn p2pk_signature(seed: u8) -> LateBytes {
    LateBytes::from_tx(move |ctx| {
        raw::push(&keys::schnorr_signature(
            ctx,
            &keys::keypair(seed),
            SIG_HASH_ALL,
        ))
        .expect("a 65-byte push always fits a script")
    })
}

/// Why a node would not take the transaction, in one line; `None` when scripts, consensus on
/// submission, the block and the mempool all accept.
fn refusal_of(outcome: &Outcome) -> Option<String> {
    if !outcome.scripts.disagreements.is_empty() {
        return Some(format!(
            "the two script runs disagree: {:?}",
            outcome.scripts.disagreements
        ));
    }
    if !outcome.scripts_accept() {
        return Some(format!(
            "scripts refuse inputs {:?}",
            outcome.scripts.refused_inputs
        ));
    }
    if !outcome.consensus.accepted {
        let refusal = outcome.consensus.refusal.as_ref();
        return Some(format!(
            "consensus refuses: {}",
            refusal
                .map(|r| format!("{} ({})", r.rule, r.message))
                .unwrap_or_default()
        ));
    }
    if !outcome.consensus.block.accepted {
        let refusal = outcome.consensus.block.refusal.as_ref();
        return Some(format!(
            "a block with it is refused: {}",
            refusal
                .map(|r| format!("{} ({})", r.rule, r.message))
                .unwrap_or_default()
        ));
    }
    if !outcome.mempool.accepted {
        let refusal = outcome.mempool.first_refusal.as_ref();
        return Some(format!(
            "the mempool refuses: {}",
            refusal
                .map(|r| format!("{} ({})", r.rule, r.message))
                .unwrap_or_default()
        ));
    }
    None
}

/// The run so far.
struct Chain<'a> {
    harness: &'a Harness,
    /// The one value of every covenant coin.
    coin_value: u64,
    /// Whether the steps leave lines in the result file of this test binary.
    record: bool,
    /// The covenant id of the token: derived at the launch, carried by every later coin.
    covenant: Option<Hash>,
    /// The pay-to-public-key coin that pays the next step.
    payer: Coin,
    /// Every unspent coin of the run.
    live: Vec<Coin>,
    minted: i64,
    fees: u64,
    locked_at_peak: u64,
    smallest_paying_coin: u64,
    deposits_returned: u64,
    ids: Vec<String>,
    steps: Vec<Value>,
    table: String,
}

impl Chain<'_> {
    fn locked(&self) -> u64 {
        self.live
            .iter()
            .filter(|coin| matches!(coin.holder, Holder::Covenant(_)))
            .map(|coin| coin.value)
            .sum()
    }

    fn supply(&self) -> i64 {
        self.live
            .iter()
            .filter_map(|coin| match &coin.holder {
                Holder::Covenant(State::Kcc20(token)) => Some(token.amount),
                _ => None,
            })
            .sum()
    }

    fn allowance(&self) -> i64 {
        self.live
            .iter()
            .filter_map(|coin| match &coin.holder {
                Holder::Covenant(State::PublicMint(minter)) => Some(minter.remaining),
                _ => None,
            })
            .sum()
    }

    /// One transaction: the covenant coins `inputs` with their calls, then the paying coin;
    /// the covenant outputs `outputs` (each of the one coin value, bound to input 0), then one
    /// pay-to-public-key output of the coin value per key in `deposits_to`, then the change
    /// to the fee payer. Returns the coins the transaction created, in output order.
    ///
    /// `Err` says why a node would not take the step. A step that a node takes and whose
    /// outputs are not what the step claims is a panic.
    fn step(
        &mut self,
        name: &str,
        what: &str,
        inputs: Vec<(Coin, Call)>,
        outputs: Vec<State>,
        deposits_to: Vec<u8>,
        minted: i64,
    ) -> Result<Vec<Coin>, String> {
        let family = &*self.harness.family;
        let coin_value = self.coin_value;
        let payer = self.payer.clone();
        let Holder::Key(payer_key) = payer.holder else {
            panic!("the paying coin is a pay-to-public-key coin");
        };
        let payer_script = pay_to_public_key_script(&keys::x_only(payer_key));
        let change_script = pay_to_public_key_script(&keys::x_only(DRY_RUN_FEE_PAYER));

        // The covenant id. At the launch it is derived by the node's own function from the
        // authorizing outpoint (input 0, the issuer's coin) and the ordered group of outputs.
        let covenant = match self.covenant {
            Some(id) => id,
            None => {
                let group: Vec<TransactionOutput> = outputs
                    .iter()
                    .map(|state| {
                        let script = family.script_public_key(state).expect("an honest state");
                        TransactionOutput::with_covenant(coin_value, script, None)
                    })
                    .collect();
                covenant_id(
                    payer.outpoint,
                    group
                        .iter()
                        .enumerate()
                        .map(|(index, output)| (index as u32, output)),
                )
            }
        };

        let build = |fee: u64| -> Option<Scenario> {
            let mut scenario = Scenario::new(name);
            for (coin, call) in &inputs {
                let Holder::Covenant(state) = &coin.holder else {
                    panic!("`{}` is not a covenant coin", coin.what);
                };
                scenario.push_contract_input(
                    ContractInput::new(
                        state.clone(),
                        coin.value,
                        coin.covenant_id,
                        coin.outpoint,
                        call.clone(),
                    )
                    .labelled(coin.what.clone()),
                );
            }
            scenario.push_ordinary_input(
                OrdinaryInput::new(
                    payer_script.clone(),
                    payer.value,
                    payer.outpoint,
                    p2pk_signature(payer_key),
                )
                .labelled(payer.what.clone()),
            );
            for state in &outputs {
                scenario.push_contract_output(ContractOutput::new(
                    state.clone(),
                    coin_value,
                    Some(CovenantBinding::new(0, covenant)),
                ));
            }
            for key in &deposits_to {
                scenario.push_plain_output(PlainOutput::new(
                    pay_to_public_key_script(&keys::x_only(*key)),
                    coin_value,
                ));
            }
            let change = scenario
                .total_in()
                .checked_sub(scenario.total_out())?
                .checked_sub(fee)?;
            scenario.push_plain_output(PlainOutput::new(change_script.clone(), change));
            Some(scenario)
        };

        // The fee: the mempool floor of this very transaction plus the margin. The floor is
        // read from a first build without a fee and confirmed on the final build.
        let mut fee = 0u64;
        let mut settled = None;
        for _ in 0..6 {
            let scenario = build(fee).ok_or_else(|| {
                format!(
                    "{name}: the paying coin of {} KAS does not cover the step",
                    kas(payer.value)
                )
            })?;
            let outcome = self.harness.run(&scenario);
            let floor = outcome.mempool.minimum_fee.ok_or_else(|| {
                format!(
                    "{name}: no fee floor; {}",
                    refusal_of(&outcome).unwrap_or_default()
                )
            })?;
            let wanted = floor + (floor * FEE_MARGIN_PERCENT).div_ceil(100);
            if wanted == fee {
                settled = Some((scenario, outcome, floor));
                break;
            }
            fee = wanted;
        }
        let (scenario, outcome, floor) =
            settled.ok_or_else(|| format!("{name}: the fee did not settle"))?;
        if let Some(refusal) = refusal_of(&outcome) {
            return Err(format!("{name}: {refusal}"));
        }
        if self.record {
            Case::new(format!("launch dry run/{name}/submitted"))
                .note(what)
                .expect_mempool_accept(&scenario);
            Case::new(format!("launch dry run/{name}/in a block"))
                .note(what)
                .expect_block_accept(&scenario);
            // The floor is the floor: the same step paying exactly the floor is taken, one
            // sompi less is refused for the fee.
            let at_the_floor = build(floor).expect("the paying coin covers the floor");
            Case::new(format!("launch dry run/{name}/fee at the floor"))
                .expect_mempool_accept(&at_the_floor);
            let below_the_floor = build(floor - 1).expect("the paying coin covers the floor");
            Case::new(format!(
                "launch dry run/{name}/fee one sompi below the floor"
            ))
            .expect_mempool_refused(&below_the_floor, "check_minimum_relay_fee");
        }

        // The transaction as a node holds it: the smallest budgets committed and the storage
        // mass written as the node calculates it on submission.
        let masses = outcome
            .masses
            .clone()
            .expect("an accepted transaction has masses");
        let storage_mass = masses
            .calculated_storage_mass
            .expect("the storage mass was calculated");
        let mut tx = outcome.committed_tx.clone();
        tx.set_storage_mass(storage_mass);
        tx.finalize();
        let id = tx.id();
        assert_eq!(
            outcome.consensus.fee,
            Some(fee),
            "{name}: the fee a node sees"
        );
        assert_eq!(
            outcome.mempool.fee,
            Some(fee),
            "{name}: the fee the mempool sees"
        );
        assert!(fee >= floor, "{name}: the fee is at least the floor");
        assert_eq!(
            outcome.consensus.block.committed_storage_mass, storage_mass,
            "{name}: the block commits to the calculated storage mass"
        );
        assert_eq!(
            outcome.minimal_budgets().map(|budgets| budgets.len()),
            Some(tx.inputs.len()),
            "{name}: every input has a smallest budget"
        );

        // What the transaction created. The script of every covenant output must be the
        // script of the state the step claims, and its binding the token's covenant id.
        let mut created = Vec::new();
        for (index, output) in tx.outputs.iter().enumerate() {
            let (holder, what) = if let Some(state) = outputs.get(index) {
                assert_eq!(
                    output.script_public_key,
                    family.script_public_key(state).expect("an honest state"),
                    "{name}: output {index} is locked to the claimed state"
                );
                assert_eq!(
                    output
                        .covenant
                        .map(|binding| (binding.authorizing_input, binding.covenant_id)),
                    Some((0, covenant)),
                    "{name}: output {index} is bound to input 0 under the covenant id"
                );
                assert_eq!(output.value, coin_value);
                (Holder::Covenant(state.clone()), describe(state))
            } else if let Some(key) = deposits_to.get(index - outputs.len()) {
                assert!(output.covenant.is_none());
                assert_eq!(output.value, coin_value);
                (
                    Holder::Key(*key),
                    format!("deposit back to {}", party(*key)),
                )
            } else {
                assert!(output.covenant.is_none());
                (
                    Holder::Key(DRY_RUN_FEE_PAYER),
                    "paying coin of the fee payer".to_string(),
                )
            };
            created.push(Coin {
                outpoint: TransactionOutpoint::new(id, index as u32),
                value: output.value,
                covenant_id: output.covenant.map(|binding| binding.covenant_id),
                holder,
                what,
            });
        }
        assert_eq!(created.len(), outputs.len() + deposits_to.len() + 1);

        if self.covenant.is_none() {
            // The launch: the id once more, from the finished transaction.
            let group: Vec<(u32, &TransactionOutput)> = tx
                .outputs
                .iter()
                .enumerate()
                .filter(|(_, output)| output.covenant.is_some())
                .map(|(index, output)| (index as u32, output))
                .collect();
            assert_eq!(group.len(), outputs.len());
            assert_eq!(
                covenant_id(tx.inputs[0].previous_outpoint, group.into_iter()),
                covenant,
                "the id of the finished launch transaction"
            );
            self.covenant = Some(covenant);
        }

        // Every input spent a coin that existed and was unspent.
        let spent: Vec<TransactionOutpoint> = tx
            .inputs
            .iter()
            .map(|input| input.previous_outpoint)
            .collect();
        let before = self.live.len();
        self.live.retain(|coin| !spent.contains(&coin.outpoint));
        assert_eq!(
            before - self.live.len(),
            spent.len(),
            "{name}: every input is a live coin"
        );
        self.live.extend(created.iter().cloned());
        self.payer = created.last().expect("the change output").clone();

        self.minted += minted;
        self.fees += fee;
        self.deposits_returned += coin_value * deposits_to.len() as u64;
        self.locked_at_peak = self.locked_at_peak.max(self.locked());
        self.smallest_paying_coin = self.smallest_paying_coin.min(self.payer.value);
        assert_eq!(
            self.supply(),
            self.minted,
            "{name}: the supply is what was minted"
        );
        assert_eq!(
            self.allowance(),
            SUPPLY - self.minted,
            "{name}: the allowance went down by what was minted"
        );

        let inputs_json: Vec<Value> = tx
            .inputs
            .iter()
            .enumerate()
            .map(|(index, input)| {
                let seen = &outcome.inputs[index];
                json!({
                    "index": index,
                    "outpoint": {
                        "transaction_id": input.previous_outpoint.transaction_id.to_string(),
                        "index": input.previous_outpoint.index,
                    },
                    "value": outcome.assembled.utxos[index].amount,
                    "kind": seen.kind,
                    "what": seen.label,
                    "contract": seen.contract,
                    "entry": seen.entry,
                    "compute_budget": seen.minimal_budget,
                    "commitment": seen.commitment,
                    "script_units": seen.committed.as_ref().map(|run| run.used_script_units),
                    "signature_script_bytes": seen.signature_script_len,
                })
            })
            .collect();
        let outputs_json: Vec<Value> = tx
            .outputs
            .iter()
            .enumerate()
            .map(|(index, output)| {
                json!({
                    "index": index,
                    "value": output.value,
                    "what": created[index].what,
                    "script_public_key_version": output.script_public_key.version(),
                    "script_public_key": hex(output.script_public_key.script()),
                    "covenant_binding": output.covenant.map(|binding| json!({
                        "authorizing_input": binding.authorizing_input,
                        "covenant_id": binding.covenant_id.to_string(),
                    })),
                })
            })
            .collect();
        let coins_after: Vec<String> = self
            .live
            .iter()
            .map(|coin| format!("{} [{} KAS]", coin.what, kas(coin.value)))
            .collect();
        self.steps.push(json!({
            "step": name,
            "what": what,
            "transaction_id": id.to_string(),
            "inputs": inputs_json,
            "outputs": outputs_json,
            "masses": masses,
            "storage_mass_written": storage_mass,
            "fee": fee,
            "fee_floor": floor,
            "fee_mass": outcome.mempool.fee_mass,
            "verdicts": {
                "scripts": outcome.scripts_accept(),
                "consensus_on_submission": outcome.consensus.accepted,
                "mempool": outcome.mempool.accepted,
                "block": outcome.consensus.block.accepted,
            },
            "minted_so_far": self.minted,
            "allowance_left": self.allowance(),
            "locked_in_covenant_coins": self.locked(),
            "fees_so_far": self.fees,
            "coins_after": coins_after,
        }));
        let _ = writeln!(
            self.table,
            "{name:<22} | {what}\n{:<22} | transaction {id}\n{:<22} | locked {} KAS | fee {} KAS | \
             fees so far {} KAS",
            "",
            "",
            kas(self.locked()),
            kas(fee),
            kas(self.fees),
        );
        for coin in &coins_after {
            let _ = writeln!(self.table, "{:<22} |   {coin}", "");
        }
        self.ids.push(id.to_string());
        Ok(created)
    }

    fn totals(&self, start_value: u64) -> Value {
        json!({
            "coin_value": self.coin_value,
            "starting_coin": start_value,
            "transactions": self.ids.len(),
            "fees_total": self.fees,
            "locked_at_peak": self.locked_at_peak,
            "locked_at_the_end": self.locked(),
            "deposits_returned": self.deposits_returned,
            "paying_coin_at_the_end": self.payer.value,
            "smallest_paying_coin_along_the_run": self.smallest_paying_coin,
            "largest_outlay_along_the_run": start_value - self.smallest_paying_coin,
            "tokens_minted": self.minted,
            "allowance_left": self.allowance(),
        })
    }
}

/// The whole life of the token with one value for every covenant coin, from one starting coin.
fn dry_run(
    harness: &Harness,
    coin_value: u64,
    start_value: u64,
    record: bool,
) -> Result<Chain<'_>, String> {
    let issuer = keys::x_only(DRY_RUN_ISSUER);
    let alice = keys::x_only(DRY_RUN_ALICE);
    let bob = keys::x_only(DRY_RUN_BOB);
    let start = Coin {
        outpoint: TransactionOutpoint::new(TransactionId::from_bytes(FUNDING_TX_ID), FUNDING_INDEX),
        value: start_value,
        covenant_id: None,
        holder: Holder::Key(DRY_RUN_ISSUER),
        what: "starting coin of the issuer".to_string(),
    };
    let mut chain = Chain {
        harness,
        coin_value,
        record,
        covenant: None,
        payer: start.clone(),
        live: vec![start],
        minted: 0,
        fees: 0,
        locked_at_peak: 0,
        smallest_paying_coin: start_value,
        deposits_returned: 0,
        ids: Vec::new(),
        steps: Vec::new(),
        table: String::new(),
    };
    let minter_of = |owner: [u8; 32], remaining: i64| -> State {
        PublicMintState::new(owner, remaining, MINT_LIMIT).into()
    };
    let seed_of = |owner: [u8; 32]| -> State { TokenSeedState::new(owner).into() };
    let signed_by = |seed: u8| Arg::Bytes(witness::signature(seed, SIG_HASH_ALL));

    // 1. The launch: the issuer's coin authorizes the minter and the seed.
    let made = chain.step(
        "01 launch",
        "the issuer's coin creates the minter (25 to mint, at most 10 per mint) and the seed",
        Vec::new(),
        vec![minter_of(issuer, SUPPLY), seed_of(issuer)],
        Vec::new(),
        0,
    )?;
    let (minter, seed) = (made[0].clone(), made[1].clone());

    // 2. Mint 10 to Alice.
    let alice_10 = Kcc20State::new(alice, 10);
    let made = chain.step(
        "02 mint",
        "the minter mints 10 tokens to Alice",
        vec![(
            minter,
            Call::typed(Entry::Mint, vec![Arg::State(alice_10.clone())]),
        )],
        vec![minter_of(issuer, 15), alice_10.into()],
        Vec::new(),
        10,
    )?;
    let (minter, alice_coin) = (made[0].clone(), made[1].clone());

    // 3. Alice transfers 4 to Bob and keeps 6.
    let next = vec![Kcc20State::new(bob, 4), Kcc20State::new(alice, 6)];
    let made = chain.step(
        "03 transfer",
        "Alice moves 4 tokens to Bob and keeps 6 (one coin in, two out)",
        vec![(
            alice_coin,
            Call::typed(
                Entry::Transfer,
                vec![
                    Arg::States(next.clone()),
                    Arg::Bytes(witness::owner_key(
                        DRY_RUN_ALICE,
                        EntryRole::Leader,
                        SIG_HASH_ALL,
                    )),
                ],
            ),
        )],
        next.into_iter().map(State::from).collect(),
        Vec::new(),
        0,
    )?;
    let alice_coin = made[1].clone();

    // 4. The seed creates a zero-token coin for Bob that anybody may pay into.
    let bob_open = Kcc20State::new(bob, 0).with_threshold(0);
    let made = chain.step(
        "04 seed create",
        "the seed creates a zero-token coin for Bob, open to payments (threshold 0)",
        vec![(
            seed,
            Call::typed(Entry::SeedCreate, vec![Arg::State(bob_open.clone())]),
        )],
        vec![seed_of(issuer), bob_open.clone().into()],
        Vec::new(),
        0,
    )?;
    let (seed, bob_open_coin) = (made[0].clone(), made[1].clone());

    // 5. Borrowed receive: Bob's open coin leads without Bob's signature, Alice's coin joins
    //    and signs; 3 tokens move from Alice into Bob's coin.
    let next = vec![bob_open.with_amount(3), Kcc20State::new(alice, 3)];
    chain.step(
        "05 borrowed receive",
        "Alice pays 3 tokens into Bob's open coin; Bob does not sign",
        vec![
            (
                bob_open_coin,
                Call::typed(
                    Entry::Transfer,
                    vec![
                        Arg::States(next.clone()),
                        Arg::Bytes(witness::borrow_threshold()),
                    ],
                ),
            ),
            (
                alice_coin,
                Call::typed(
                    Entry::TransferDelegator,
                    vec![Arg::Bytes(witness::owner_key(
                        DRY_RUN_ALICE,
                        EntryRole::Delegate,
                        SIG_HASH_ALL,
                    ))],
                ),
            ),
        ],
        next.into_iter().map(State::from).collect(),
        Vec::new(),
        0,
    )?;

    // 6. The minter hands 5 of its allowance to a new minter of Bob.
    let made = chain.step(
        "06 minter split",
        "the minter hands 5 of its 15 to a new minter owned by Bob",
        vec![(
            minter,
            Call::typed(Entry::MintSplit, vec![Arg::int(5), Arg::bytes(bob)]),
        )],
        vec![minter_of(issuer, 10), minter_of(bob, 5)],
        Vec::new(),
        0,
    )?;
    let (minter, bob_minter) = (made[0].clone(), made[1].clone());

    // 7. A mint from the split minter.
    let bob_2 = Kcc20State::new(bob, 2);
    let made = chain.step(
        "07 mint from the split",
        "Bob's minter mints 2 tokens to Bob",
        vec![(
            bob_minter,
            Call::typed(Entry::Mint, vec![Arg::State(bob_2.clone())]),
        )],
        vec![minter_of(bob, 3), bob_2.into()],
        Vec::new(),
        2,
    )?;
    let bob_minter = made[0].clone();

    // 8. Bob's minter retires into the issuer's; its deposit goes back to Bob.
    let made = chain.step(
        "08 reclaim into",
        "Bob's minter (3 left) retires into the issuer's minter; Bob signs and gets the deposit",
        vec![
            (minter, Call::typed(Entry::MintReclaimInto, Vec::new())),
            (
                bob_minter,
                Call::typed(Entry::MintReclaimDelegator, vec![signed_by(DRY_RUN_BOB)]),
            ),
        ],
        vec![minter_of(issuer, 13)],
        vec![DRY_RUN_BOB],
        0,
    )?;
    let minter = made[0].clone();

    // 9. Two more mints empty the allowance.
    let alice_10 = Kcc20State::new(alice, 10);
    let made = chain.step(
        "09 mint",
        "the minter mints 10 tokens to Alice",
        vec![(
            minter,
            Call::typed(Entry::Mint, vec![Arg::State(alice_10.clone())]),
        )],
        vec![minter_of(issuer, 3), alice_10.into()],
        Vec::new(),
        10,
    )?;
    let minter = made[0].clone();
    let bob_3 = Kcc20State::new(bob, 3);
    let made = chain.step(
        "10 last mint",
        "the minter mints its last 3 tokens to Bob",
        vec![(
            minter,
            Call::typed(Entry::Mint, vec![Arg::State(bob_3.clone())]),
        )],
        vec![minter_of(issuer, 0), bob_3.into()],
        Vec::new(),
        3,
    )?;
    let minter = made[0].clone();

    // 10. The issuer closes the exhausted minter and takes its deposit.
    chain.step(
        "11 minter reclaim",
        "the issuer closes the empty minter and gets the deposit",
        vec![(
            minter,
            Call::typed(Entry::MintReclaim, vec![signed_by(DRY_RUN_ISSUER)]),
        )],
        Vec::new(),
        vec![DRY_RUN_ISSUER],
        0,
    )?;

    // 11. The seed creates a second seed for Bob, and that seed is closed again.
    let made = chain.step(
        "12 seed split",
        "the seed creates a second seed owned by Bob",
        vec![(seed, Call::typed(Entry::SeedSplit, vec![Arg::bytes(bob)]))],
        vec![seed_of(issuer), seed_of(bob)],
        Vec::new(),
        0,
    )?;
    let (seed, bob_seed) = (made[0].clone(), made[1].clone());
    chain.step(
        "13 seed reclaim",
        "Bob's seed is closed next to the issuer's; Bob signs and gets the deposit",
        vec![
            (seed, Call::typed(Entry::SeedReclaim, Vec::new())),
            (
                bob_seed,
                Call::typed(Entry::SeedReclaimDelegator, vec![signed_by(DRY_RUN_BOB)]),
            ),
        ],
        vec![seed_of(issuer)],
        vec![DRY_RUN_BOB],
        0,
    )?;

    assert_eq!(chain.minted, SUPPLY, "the whole supply was minted");
    assert_eq!(chain.allowance(), 0);
    Ok(chain)
}

/// The launch in the input format of a separate launch checker that is not published here:
/// the authorizing outpoint, the genesis outputs as a node would report them, and the
/// claimed states.
fn genesis_case(launch: &Value, coin_value: u64) -> Value {
    let outpoint = json!({
        "transactionId": launch["inputs"][0]["outpoint"]["transaction_id"],
        "index": launch["inputs"][0]["outpoint"]["index"],
    });
    let id = launch["outputs"][0]["covenant_binding"]["covenant_id"].clone();
    let zero = hex(&[0u8; 32]);
    let issuer = hex(&keys::x_only(DRY_RUN_ISSUER));
    json!({
        "outpoint": outpoint,
        "outputs": [
            {
                "index": 0,
                "value": coin_value,
                "script": launch["outputs"][0]["script_public_key"],
                "covenant_id": id,
            },
            {
                "index": 1,
                "value": coin_value,
                "script": launch["outputs"][1]["script_public_key"],
                "covenant_id": launch["outputs"][1]["covenant_binding"]["covenant_id"],
            },
        ],
        "bootstrap": {
            "app": "KCC20PublicMint",
            "authorizing_outpoint": outpoint,
            "advertised_supply": SUPPLY,
            "outputs": [
                {
                    "index": 0,
                    "value": coin_value,
                    "contract": "PublicMint",
                    "runtime_state": {
                        "remaining": SUPPLY,
                        "mint_amount": MINT_LIMIT,
                        "owner": issuer,
                        "extension_commitment": zero,
                    },
                },
                {
                    "index": 1,
                    "value": coin_value,
                    "contract": "TokenSeed",
                    "runtime_state": {
                        "owner": issuer,
                        "extension_commitment": zero,
                    },
                },
            ],
        },
        "claimed_covenant_id": id,
    })
}

#[test]
fn the_token_is_launched_and_lives_its_life_without_a_refusal() {
    // The plan is of the pinned contracts as a node judges them. In the mutation mode of the
    // test harness of `crates/checks` (a weakened contract, a list of cases, script verdicts
    // only) there is no fee floor and no node verdict to build a chain on, and the test
    // returns at once.
    if !checks::mutation::mode().is_plain() {
        return;
    }
    let harness = Harness::pinned();

    // The main run: 1 KAS in every covenant coin.
    let one_kas = dry_run(&harness, SOMPI_PER_KAS, START_VALUE, true)
        .unwrap_or_else(|refusal| panic!("with 1 KAS coins a step is refused: {refusal}"));
    assert_eq!(one_kas.ids.len(), 13);
    assert_eq!(
        one_kas.covenant.map(|id| id.to_string()).as_deref(),
        Some(CROSS_CHECKED_COVENANT_ID),
        "the covenant id of the launch is not the one the separate launch checker derived"
    );

    // Deterministic: a second build gives the same transactions.
    let again = dry_run(&harness, SOMPI_PER_KAS, START_VALUE, false).expect("the same run");
    assert_eq!(
        one_kas.ids, again.ids,
        "two builds give the same transaction ids"
    );

    // The smallest round coin value: hundredths of a KAS, upwards, until every step passes.
    // The value moves with the coin that pays (a smaller paying coin adds storage mass), so
    // the search is repeated for smaller starting coins.
    let smallest_round = |start_value: u64| -> (Option<Chain<'_>>, Vec<Value>) {
        let mut search = Vec::new();
        for hundredths in 1..=100u64 {
            let coin_value = hundredths * SOMPI_PER_KAS / 100;
            match dry_run(&harness, coin_value, start_value, false) {
                Ok(chain) => {
                    search.push(json!({"coin_value": coin_value, "every_step_accepted": true}));
                    return (Some(chain), search);
                }
                Err(refusal) => search.push(json!({
                    "coin_value": coin_value,
                    "every_step_accepted": false,
                    "first_refusal": refusal,
                })),
            }
        }
        (None, search)
    };
    let (smallest, search) = smallest_round(START_VALUE);
    let smallest = smallest.expect("1 KAS passes, so the search ends at or below it");
    let mut by_starting_coin = Vec::new();
    let mut by_starting_coin_text = String::new();
    for start_kas in [50u64, 20, 10, 5, 3, 2] {
        let start_value = start_kas * SOMPI_PER_KAS;
        let (found, tried) = smallest_round(start_value);
        let _ = writeln!(
            by_starting_coin_text,
            "  starting coin {start_kas:>3} KAS: {}",
            match &found {
                Some(chain) => format!(
                    "{} KAS per covenant coin; largest outlay {} KAS, fees {} KAS",
                    kas(chain.coin_value),
                    kas(start_value - chain.smallest_paying_coin),
                    kas(chain.fees)
                ),
                None => "no value up to 1 KAS lets every step pass".to_string(),
            }
        );
        by_starting_coin.push(json!({
            "starting_coin": start_value,
            "coin_value": found.as_ref().map(|chain| chain.coin_value),
            "totals": found.as_ref().map(|chain| chain.totals(start_value)),
            "last_refusal_below": tried.iter().rev().find_map(|entry| entry.get("first_refusal")),
        }));
    }

    // The 1 KAS run once more from a starting coin that is only as large as the run needs:
    // the largest outlay rounded up to a whole KAS, then one KAS more at a time until every
    // step passes. Recorded, not asserted.
    let outlay = START_VALUE - one_kas.smallest_paying_coin;
    let mut tight_attempts = Vec::new();
    let mut smallest_whole_start = None;
    for extra in 0..4u64 {
        let start_value = (outlay.div_ceil(SOMPI_PER_KAS) + extra) * SOMPI_PER_KAS;
        match dry_run(&harness, one_kas.coin_value, start_value, false) {
            Ok(run) => {
                tight_attempts.push(json!({
                    "starting_coin": start_value,
                    "every_step_accepted": true,
                    "totals": run.totals(start_value),
                }));
                smallest_whole_start = Some(start_value);
                break;
            }
            Err(refusal) => tight_attempts.push(json!({
                "starting_coin": start_value,
                "every_step_accepted": false,
                "first_refusal": refusal,
            })),
        }
    }
    let tight_one_kas = json!({
        "smallest_whole_kas_starting_coin": smallest_whole_start,
        "attempts": tight_attempts,
    });

    let directory = checks::results::results_dir();
    fs::create_dir_all(&directory).expect("the result directory");

    let case = genesis_case(&one_kas.steps[0], one_kas.coin_value);
    fs::write(
        directory.join("launch-genesis-case.json"),
        serde_json::to_string_pretty(&case).expect("json") + "\n",
    )
    .expect("the case file");

    let plan = json!({
        "layout": 1,
        "network": harness.node.params.network_name(),
        "nothing_was_sent": true,
        "keys": "dry-run keys: one seed byte repeated 32 times; they guard nothing",
        "assumptions": [
            "the node is a default node with testnet-10 parameters, ten million DAA scores \
             after the Toccata activation",
            "every transaction is judged by itself against the coins it spends; the mempool as \
             a container, the fee market and the block template are not modelled",
            "every input carries the smallest compute budget that covers its run",
            "the storage mass is the value the node calculates and writes on submission; the \
             block verdict is of the transaction committing to that value",
            "every transaction is built after the one before it was accepted: its outpoints \
             are the ids of the earlier transactions of this very run",
        ],
        "covenant_id_cross_checked": {
            "case_file": "launch-genesis-case.json",
            "derived_by": "a separate launch checker that is not published here",
            "derived_covenant_id": CROSS_CHECKED_COVENANT_ID,
        },
        "funding_outpoint": {
            "transaction_id": hex(&FUNDING_TX_ID),
            "index": FUNDING_INDEX,
            "made_up": true,
        },
        "fee_rule": format!(
            "the mempool floor of the transaction plus {FEE_MARGIN_PERCENT} percent, rounded up"
        ),
        "covenant_id": one_kas.covenant.map(|id| id.to_string()),
        "steps": one_kas.steps,
        "totals": one_kas.totals(START_VALUE),
        "from_a_tight_starting_coin": tight_one_kas,
        "smallest_round_coin_value": {
            "granularity": SOMPI_PER_KAS / 100,
            "coin_value": smallest.coin_value,
            "covenant_id": smallest.covenant.map(|id| id.to_string()),
            "transaction_ids": smallest.ids,
            "starting_coin": START_VALUE,
            "totals": smallest.totals(START_VALUE),
            "search": search,
            "by_smaller_starting_coins": by_starting_coin,
        },
    });
    fs::write(
        directory.join("launch-plan.json"),
        serde_json::to_string_pretty(&plan).expect("json") + "\n",
    )
    .expect("the plan");

    let mut text = String::new();
    let _ = writeln!(
        text,
        "KCC-20 reference token on testnet-10: a dry run. NOTHING WAS SENT."
    );
    let _ = writeln!(
        text,
        "Keys are dry-run keys, the funding outpoint is made up."
    );
    let _ = writeln!(
        text,
        "Every covenant coin holds {} KAS; the starting coin holds {} KAS.",
        kas(one_kas.coin_value),
        kas(START_VALUE)
    );
    let _ = writeln!(
        text,
        "Fee of a step: its mempool floor plus {FEE_MARGIN_PERCENT} percent. Every step was \
         accepted by scripts, consensus on submission, the mempool and inside a block."
    );
    let _ = writeln!(
        text,
        "Covenant id: {}",
        plan["covenant_id"].as_str().unwrap_or("?")
    );
    let _ = writeln!(text);
    let _ = writeln!(text, "{:<22} | what happens / coins after the step", "step");
    let _ = writeln!(text, "{}", "-".repeat(100));
    text.push_str(&one_kas.table);
    let _ = writeln!(text, "{}", "-".repeat(100));
    for (title, chain) in [
        ("Totals with 1 KAS coins", &one_kas),
        ("Totals with the smallest round coin value", &smallest),
    ] {
        let _ = writeln!(
            text,
            "{title} ({} KAS per covenant coin):",
            kas(chain.coin_value)
        );
        let _ = writeln!(
            text,
            "  transactions                      {}",
            chain.ids.len()
        );
        let _ = writeln!(
            text,
            "  fees, all steps                   {} KAS",
            kas(chain.fees)
        );
        let _ = writeln!(
            text,
            "  locked in covenant coins, peak    {} KAS",
            kas(chain.locked_at_peak)
        );
        let _ = writeln!(
            text,
            "  locked in covenant coins, end     {} KAS",
            kas(chain.locked())
        );
        let _ = writeln!(
            text,
            "  deposits returned to keys         {} KAS",
            kas(chain.deposits_returned)
        );
        let _ = writeln!(
            text,
            "  largest outlay along the run      {} KAS (the starting coin must exceed this)",
            kas(START_VALUE - chain.smallest_paying_coin)
        );
        let _ = writeln!(
            text,
            "  paying coin left at the end       {} KAS",
            kas(chain.payer.value)
        );
        let _ = writeln!(text);
    }
    let _ = writeln!(
        text,
        "Smallest coin value in hundredths of a KAS that lets every step pass, by starting coin\n  \
         starting coin 100 KAS: {} KAS per covenant coin",
        kas(smallest.coin_value)
    );
    text.push_str(&by_starting_coin_text);
    let _ = writeln!(text);
    let _ = writeln!(
        text,
        "Smallest starting coin in whole KAS that carries the run with 1 KAS coins: {}",
        match smallest_whole_start {
            Some(start_value) => format!("{} KAS", kas(start_value)),
            None => "not found within 3 KAS above the largest outlay".to_string(),
        }
    );
    fs::write(directory.join("launch-plan.txt"), text).expect("the table");
}
