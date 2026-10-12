//! The launch of the reference token on testnet-10 and its life, built for a real run.
//!
//! This is the sibling of `launch_dry_run.rs`: the same chain of 13 transactions, but from a
//! real funding coin and signed with three keys read from files. Nothing is sent anywhere and
//! nothing here can send: the test builds and signs every transaction in memory, puts each one
//! to the node rules of `node-gate` and writes them into a chain file. A separate program,
//! the sender in `launch/` of this repository, reads that file, checks it by its own rules
//! and submits. The two file formats (the request this test reads, `kcc20-launch-request/1`,
//! and the chain it writes, `kcc20-launch-chain/1`) are described in `launch/FORMAT.md`.
//!
//! What differs from the dry run:
//!
//! - the keys: `KASPA_LAB_KEY_FILE` (the issuer, who owns the funding coin and pays every
//!   fee), `KASPA_LAB_SECOND_KEY_FILE` (Bob) and `KASPA_LAB_THIRD_KEY_FILE` (Alice) name three
//!   files of 64 hex characters each. A secret key never reaches an output, a message or a
//!   file of this test;
//! - the funding coin, the value of a covenant coin, the fee rate and the fee cap come from
//!   the request file named by `KCC20_LAUNCH_INPUT`;
//! - the fee of a transaction is the fee rate times the larger of its fee mass and its
//!   storage mass, and the change goes back to the issuer;
//! - after the 13 steps three forbidden moves are built from coins that are then unspent.
//!   Each must be refused by the scripts at the rule it breaks, and the same transaction with
//!   the one wrong thing put right must be accepted. A forbidden move carries the compute
//!   budgets and pays the fee of that honest twin;
//! - the chain file named by `KCC20_LAUNCH_OUTPUT` (it must not exist yet) holds every
//!   transaction in full, signature scripts included; a table for a reader is written next
//!   to it with `.txt` appended to the name.
//!
//! Without `KCC20_LAUNCH_INPUT` the test is a self-test that needs no key file and no
//! request, only the clone of the reference every check of the contracts reads: it makes up
//! three keys and a funding coin, builds the chain at two fee rates and writes
//! `launch-real-selftest-<fee rate>.chain.json` into the result directory.

use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use checks::expect::{Expected, judge_input};
use checks::{Budgets, Harness, Outcome};
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::covenant_id::covenant_id;
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    CovenantBinding, ScriptPublicKey, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput,
};
use kcc20_family::shapes::{SOMPI_PER_KAS, pay_to_public_key_script};
use kcc20_family::{
    Arg, Call, ContractInput, ContractOutput, Entry, EntryRole, Kcc20State, LateBytes,
    OrdinaryInput, PlainOutput, PublicMintState, Scenario, State, TokenSeedState, keys, raw,
    witness,
};
use node_gate::verdict::Commitment;
use secp256k1::{Keypair, SECP256K1, SecretKey};
use serde_json::{Value, json};

/// Environment variable: the request file.
const INPUT_ENV: &str = "KCC20_LAUNCH_INPUT";
/// Environment variable: the chain file to write.
const OUTPUT_ENV: &str = "KCC20_LAUNCH_OUTPUT";
/// Environment variables of the three key files: the issuer, Bob, Alice.
const ISSUER_KEY_ENV: &str = "KASPA_LAB_KEY_FILE";
const BOB_KEY_ENV: &str = "KASPA_LAB_SECOND_KEY_FILE";
const ALICE_KEY_ENV: &str = "KASPA_LAB_THIRD_KEY_FILE";

const REQUEST_FORMAT: &str = "kcc20-launch-request/1";
const CHAIN_FORMAT: &str = "kcc20-launch-chain/1";
/// The network of the run as the two files name it.
const NETWORK: &str = "testnet-10";
/// The same network as the node parameters name it.
const GATE_NETWORK: &str = "kaspa-testnet-10";

/// The reference's own demo numbers: 25 tokens to mint, at most 10 per mint.
const SUPPLY: i64 = 25;
const MINT_LIMIT: i64 = 10;

/// The smallest fee rate a request may ask for, in sompi per gram.
const MIN_FEERATE: u64 = 100;
/// How often a fee is recalculated before the larger of the last two candidates is taken.
const FEE_ROUNDS: usize = 6;
/// The fee rule, true whether or not the calculation of a fee settles. The chain file states
/// it with the ending of [`fee_rule_sentence`].
const FEE_RULE: &str = "the fee of a transaction is at least the fee rate times the larger of its \
                        fee mass (the mass a node charges its fee floor on) and the storage mass a \
                        node calculates for it, both read from that very transaction, and equal to \
                        that product whenever the calculation settles";

/// The fee rule as the chain file states it: [`FEE_RULE`], ending with the number of
/// transactions of this chain whose fee did not settle, so that the larger of the last two
/// candidates was taken.
fn fee_rule_sentence(unsettled_steps: usize, unsettled_probes: usize) -> String {
    format!(
        "{FEE_RULE}; in this chain it did not settle, and the larger of the last two candidates \
         was taken, for {unsettled_steps} of the 13 steps and {unsettled_probes} of the 3 \
         forbidden moves"
    )
}

/// The seed bytes that stand for the three keys of a run: handles of keys registered with
/// `keys::register_key`, not seeds of repeated-byte keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Handles {
    issuer: u8,
    bob: u8,
    alice: u8,
}

/// The handles of a real run.
const REAL: Handles = Handles {
    issuer: 0x01,
    bob: 0x02,
    alice: 0x03,
};
/// The handles of the made-up keys of the self-test. The tests of this file share one
/// process and one key table, so the two sets must not overlap.
const SELF_TEST: Handles = Handles {
    issuer: 0x21,
    bob: 0x22,
    alice: 0x23,
};

impl Handles {
    /// The name of the party in the chain file.
    fn party(&self, handle: u8) -> &'static str {
        if handle == self.issuer {
            "issuer"
        } else if handle == self.bob {
            "bob"
        } else if handle == self.alice {
            "alice"
        } else {
            panic!("handle {handle:#04x} is no party of the run")
        }
    }

    /// The name of the party in a sentence.
    fn person(&self, handle: u8) -> &'static str {
        match self.party(handle) {
            "issuer" => "the issuer",
            "bob" => "Bob",
            _ => "Alice",
        }
    }

    fn owner(&self, owner: &[u8; 32]) -> &'static str {
        [self.issuer, self.bob, self.alice]
            .into_iter()
            .find(|handle| keys::x_only(*handle) == *owner)
            .map(|handle| self.person(handle))
            .unwrap_or("an unknown key")
    }

    fn describe(&self, state: &State) -> String {
        match state {
            State::Kcc20(token) => format!(
                "token coin of {}: {} tokens{}",
                self.owner(&token.owner),
                token.amount,
                if token.borrow_scheme == 0 {
                    ""
                } else {
                    ", open to payments"
                }
            ),
            State::PublicMint(minter) => format!(
                "minter of {}: {} left to mint",
                self.owner(&minter.owner),
                minter.remaining
            ),
            State::TokenSeed(seed) => format!("seed of {}", self.owner(&seed.owner)),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------

fn kas(sompi: u64) -> String {
    format!("{}.{:08}", sompi / SOMPI_PER_KAS, sompi % SOMPI_PER_KAS)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The bytes of a hex text; `None` when it is not hex of whole bytes.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok())
        .collect()
}

/// The time of the clock in UTC, to the second: `2026-10-11T12:05:00Z`.
fn utc_now() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    let (days, rest) = ((seconds / 86_400) as i64, seconds % 86_400);
    // The civil date of a day count (days since 1970-01-01), by eras of 400 years.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

/// The x-only public key of a secret key, without the key table.
fn x_only_of(secret_key: &SecretKey) -> [u8; 32] {
    Keypair::from_secret_key(SECP256K1, secret_key)
        .x_only_public_key()
        .0
        .serialize()
}

// ---------------------------------------------------------------------------------------
// The keys
// ---------------------------------------------------------------------------------------

/// The paths of the three key files.
struct KeyFiles {
    issuer: PathBuf,
    bob: PathBuf,
    alice: PathBuf,
}

impl KeyFiles {
    fn listed(&self) -> [(&'static str, &Path); 3] {
        [
            (ISSUER_KEY_ENV, &self.issuer),
            (BOB_KEY_ENV, &self.bob),
            (ALICE_KEY_ENV, &self.alice),
        ]
    }
}

/// The three secret keys of a run: the issuer, Bob, Alice. No `Debug`: a key is never shown.
struct Secrets {
    issuer: SecretKey,
    bob: SecretKey,
    alice: SecretKey,
}

/// A path in a form two paths can be compared in: resolved when the file exists, otherwise
/// the resolved directory with the file name.
fn resolved(path: &Path) -> PathBuf {
    if let Ok(resolved) = path.canonicalize() {
        return resolved;
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let directory = parent
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let directory = directory.canonicalize().unwrap_or(directory);
    match path.file_name() {
        Some(name) => directory.join(name),
        None => directory,
    }
}

/// The directory this test takes for its repository: the workspace folder, two levels above
/// the crate (`engine/` in the repository of the study, not the whole of it).
fn repository() -> PathBuf {
    resolved(&Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(".."))
}

/// Where key files of a real run must not be.
struct Forbidden<'a> {
    /// No key file inside this directory.
    repository: &'a Path,
    /// No key file at the path of the chain file or of its table.
    output: &'a Path,
}

/// Reads one key file: 64 hex characters, white space around them allowed. The error names
/// the variable and never the content of the file.
fn load_key(variable: &str, path: &Path) -> Result<SecretKey, String> {
    let text = fs::read_to_string(path).map_err(|error| {
        format!(
            "{variable}: the key file cannot be read ({:?})",
            error.kind()
        )
    })?;
    let text = text.trim();
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{variable}: the key file does not hold 64 hex characters"
        ));
    }
    let bytes = unhex(text).ok_or_else(|| format!("{variable}: the key file is not hex"))?;
    SecretKey::from_slice(&bytes)
        .map_err(|_| format!("{variable}: the 32 bytes of the key file are not a valid secret key"))
}

/// Reads the three keys. They must differ from each other; in a real run no key file may lie
/// inside the repository or at the path of the output.
fn load_keys(files: &KeyFiles, forbidden: Option<&Forbidden<'_>>) -> Result<Secrets, String> {
    if let Some(forbidden) = forbidden {
        let output = resolved(forbidden.output);
        let table = table_path(&output);
        for (variable, path) in files.listed() {
            let path = resolved(path);
            if path.starts_with(forbidden.repository) {
                return Err(format!(
                    "{variable}: the key file lies inside the repository; keep keys outside it"
                ));
            }
            if path == output || path == table {
                return Err(format!(
                    "{variable}: the key file is at the path the chain is to be written to"
                ));
            }
        }
    }
    let issuer = load_key(ISSUER_KEY_ENV, &files.issuer)?;
    let bob = load_key(BOB_KEY_ENV, &files.bob)?;
    let alice = load_key(ALICE_KEY_ENV, &files.alice)?;
    for (first, second, a, b) in [
        (ISSUER_KEY_ENV, BOB_KEY_ENV, &issuer, &bob),
        (ISSUER_KEY_ENV, ALICE_KEY_ENV, &issuer, &alice),
        (BOB_KEY_ENV, ALICE_KEY_ENV, &bob, &alice),
    ] {
        if a == b {
            return Err(format!(
                "{first} and {second} hold the same key; the three parties need three keys"
            ));
        }
    }
    Ok(Secrets { issuer, bob, alice })
}

// ---------------------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------------------

/// The funding coin as the request reports it.
#[derive(Clone, Debug)]
struct Funding {
    transaction_id: [u8; 32],
    index: u32,
    value: u64,
    script_public_key: ScriptPublicKey,
}

/// A request: `kcc20-launch-request/1`.
#[derive(Clone, Debug)]
struct Request {
    network: String,
    token_name: String,
    coin_value: u64,
    feerate: u64,
    fee_cap_total: u64,
    funding: Funding,
}

fn text_field<'a>(object: &'a Value, field: &str) -> Result<&'a str, String> {
    object[field]
        .as_str()
        .ok_or_else(|| format!("the request has no text field `{field}`"))
}

fn number_field(object: &Value, field: &str) -> Result<u64, String> {
    object[field]
        .as_u64()
        .ok_or_else(|| format!("the request has no whole number `{field}`"))
}

fn parse_request(text: &str) -> Result<Request, String> {
    let document: Value =
        serde_json::from_str(text).map_err(|error| format!("the request is not JSON: {error}"))?;
    let format = text_field(&document, "format")?;
    if format != REQUEST_FORMAT {
        return Err(format!(
            "the request has format `{format}`, not `{REQUEST_FORMAT}`"
        ));
    }
    let funding = &document["funding"];
    if !funding.is_object() {
        return Err("the request has no `funding`".to_string());
    }
    let transaction_id = unhex(text_field(funding, "transaction_id")?)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or("funding.transaction_id is not 64 hex characters")?;
    let index = u32::try_from(number_field(funding, "index")?)
        .map_err(|_| "funding.index does not fit an output index")?;
    let version = u16::try_from(number_field(funding, "script_public_key_version")?)
        .map_err(|_| "funding.script_public_key_version does not fit a script version")?;
    let script = unhex(text_field(funding, "script_public_key")?)
        .ok_or("funding.script_public_key is not hex")?;
    Ok(Request {
        network: text_field(&document, "network")?.to_string(),
        token_name: text_field(&document, "token_name")?.to_string(),
        coin_value: number_field(&document, "coin_value")?,
        feerate: number_field(&document, "feerate")?,
        fee_cap_total: number_field(&document, "fee_cap_total")?,
        funding: Funding {
            transaction_id,
            index,
            value: number_field(funding, "value")?,
            script_public_key: ScriptPublicKey::from_vec(version, script),
        },
    })
}

impl Funding {
    fn json(&self) -> Value {
        json!({
            "transaction_id": hex(&self.transaction_id),
            "index": self.index,
            "value": self.value,
            "script_public_key_version": self.script_public_key.version(),
            "script_public_key": hex(self.script_public_key.script()),
            "owner": "issuer",
        })
    }
}

// ---------------------------------------------------------------------------------------
// Coins and transactions
// ---------------------------------------------------------------------------------------

/// Who or what holds a coin.
#[derive(Clone, Debug)]
enum Holder {
    /// A coin of one of the three contracts, with the state it holds.
    Covenant(State),
    /// A pay-to-public-key coin of the key behind this handle.
    Key(u8),
}

/// Where a coin comes from.
#[derive(Clone, Debug)]
enum Origin {
    /// The funding coin of the request.
    Funding,
    /// An output of a step of this run.
    Step { name: String, output: u32 },
}

/// A coin that exists at some point of the run.
#[derive(Clone, Debug)]
struct Coin {
    outpoint: TransactionOutpoint,
    value: u64,
    script_public_key: ScriptPublicKey,
    covenant_id: Option<Hash>,
    holder: Holder,
    origin: Origin,
    what: String,
}

/// What a transaction is made of, apart from the coin that pays and the fee: the covenant
/// coins it spends with their calls, the covenant outputs (each of the one coin value, bound
/// to input 0), and the keys that get one coin value back each. The paying coin of the issuer
/// is the last input and the change to the issuer the last output.
#[derive(Clone)]
struct Plan {
    name: String,
    what: String,
    inputs: Vec<(Coin, Call)>,
    outputs: Vec<State>,
    deposits_to: Vec<u8>,
}

impl Plan {
    fn new(name: &str, what: &str) -> Self {
        Self {
            name: name.to_string(),
            what: what.to_string(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            deposits_to: Vec::new(),
        }
    }

    fn spending(mut self, coin: &Coin, call: Call) -> Self {
        self.inputs.push((coin.clone(), call));
        self
    }

    fn creating(mut self, states: impl IntoIterator<Item = State>) -> Self {
        self.outputs.extend(states);
        self
    }

    fn returning_a_deposit_to(mut self, handle: u8) -> Self {
        self.deposits_to.push(handle);
        self
    }
}

/// The signature script of a pay-to-public-key coin: one Schnorr signature over the whole
/// transaction.
fn p2pk_signature(handle: u8) -> LateBytes {
    LateBytes::from_tx(move |ctx| {
        raw::push(&keys::schnorr_signature(
            ctx,
            &keys::keypair(handle),
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

/// The masses and the fee floor of one evaluated transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Numbers {
    compute_mass: u64,
    transient_mass: u64,
    storage_mass: u64,
    fee_mass: u64,
    fee_floor: u64,
}

impl Numbers {
    /// What the gate reports; `None` when it could not calculate one of them.
    fn of(outcome: &Outcome) -> Option<Self> {
        let masses = outcome.masses.as_ref()?;
        Some(Self {
            compute_mass: masses.compute_mass,
            transient_mass: masses.transient_mass,
            storage_mass: masses.calculated_storage_mass?,
            fee_mass: outcome.mempool.fee_mass?,
            fee_floor: outcome.mempool.minimum_fee?,
        })
    }

    /// The mass the fee rule charges.
    fn charged_mass(&self) -> u64 {
        self.fee_mass.max(self.storage_mass)
    }
}

/// A transaction with its fee settled by the fee rule.
struct Settled {
    outcome: Outcome,
    numbers: Numbers,
    fee: u64,
    /// Whether a build asked for exactly the fee it was built with. When not, the fee is the
    /// larger of the last two candidates and may be above the product of the fee rule.
    at_the_fixed_point: bool,
}

/// A transaction as it goes into the chain file.
struct Written {
    json: Value,
    id: TransactionId,
    tx: Transaction,
    created: Vec<Coin>,
}

fn state_json(state: &State) -> Value {
    match state {
        State::Kcc20(token) => json!({
            "contract": "KCC20",
            "amount": token.amount,
            "owner": hex(&token.owner),
            "owner_scheme": token.owner_scheme,
            "borrow_scheme": token.borrow_scheme,
            "borrow_guard": hex(&token.borrow_guard),
            "extension_commitment": hex(&token.extension_commitment),
        }),
        State::PublicMint(minter) => json!({
            "contract": "PublicMint",
            "remaining": minter.remaining,
            "mint_amount": minter.mint_amount,
            "owner": hex(&minter.owner),
            "extension_commitment": hex(&minter.extension_commitment),
        }),
        State::TokenSeed(seed) => json!({
            "contract": "TokenSeed",
            "owner": hex(&seed.owner),
            "extension_commitment": hex(&seed.extension_commitment),
        }),
    }
}

/// The transaction a reader of the chain file builds from the fields of one entry, and from
/// nothing else: the version, the inputs with their outpoints, sequence numbers, commitments
/// and signature scripts, the outputs with their bindings, the lock time, the subnetwork, the
/// gas, the payload and the mass field.
fn rebuilt_from_the_file(entry: &Value) -> Transaction {
    let number = |value: &Value| value.as_u64().expect("a whole number");
    let bytes = |value: &Value| unhex(value.as_str().expect("a hex text")).expect("hex");
    let hash =
        |value: &Value| Hash::from_bytes(<[u8; 32]>::try_from(bytes(value)).expect("32 bytes"));
    let version = u16::try_from(number(&entry["version"])).expect("a version");
    let inputs = entry["inputs"]
        .as_array()
        .expect("inputs")
        .iter()
        .map(|input| {
            let outpoint = TransactionOutpoint::new(
                hash(&input["transaction_id"]),
                u32::try_from(number(&input["index"])).expect("an output index"),
            );
            let signature_script = bytes(&input["signature_script"]);
            let sequence = number(&input["sequence"]);
            // A version-1 input commits to a compute budget, a version-0 input to a count of
            // signature operations.
            if version >= 1 {
                assert_eq!(input["sig_op_count"], 0);
                TransactionInput::new_with_compute_budget(
                    outpoint,
                    signature_script,
                    sequence,
                    u16::try_from(number(&input["compute_budget"])).expect("a compute budget"),
                )
            } else {
                assert_eq!(input["compute_budget"], 0);
                TransactionInput::new(
                    outpoint,
                    signature_script,
                    sequence,
                    u8::try_from(number(&input["sig_op_count"])).expect("a sig-op count"),
                )
            }
        })
        .collect();
    let outputs = entry["outputs"]
        .as_array()
        .expect("outputs")
        .iter()
        .map(|output| {
            let binding = &output["covenant_binding"];
            let binding = (!binding.is_null()).then(|| {
                CovenantBinding::new(
                    u16::try_from(number(&binding["authorizing_input"])).expect("an input index"),
                    hash(&binding["covenant_id"]),
                )
            });
            TransactionOutput::with_covenant(
                number(&output["value"]),
                ScriptPublicKey::from_vec(
                    u16::try_from(number(&output["script_public_key_version"]))
                        .expect("a script version"),
                    bytes(&output["script_public_key"]),
                ),
                binding,
            )
        })
        .collect();
    let subnetwork_id =
        <[u8; 20]>::try_from(bytes(&entry["subnetwork_id"])).expect("a subnetwork id of 20 bytes");
    let tx = Transaction::new(
        version,
        inputs,
        outputs,
        number(&entry["lock_time"]),
        SubnetworkId::from(subnetwork_id),
        number(&entry["gas"]),
        bytes(&entry["payload"]),
    );
    tx.set_storage_mass(number(&entry["mass"]));
    tx
}

/// The fixed terms of a run: the node, the keys, the coin value and the fee rate.
#[derive(Clone, Copy)]
struct Terms<'a> {
    harness: &'a Harness,
    handles: Handles,
    coin_value: u64,
    feerate: u64,
}

impl Terms<'_> {
    fn issuer_script(&self) -> ScriptPublicKey {
        pay_to_public_key_script(&keys::x_only(self.handles.issuer))
    }

    /// The transaction of `plan`, paid from `payer`, with this fee. `None` when the paying
    /// coin does not cover the outputs and the fee.
    fn scenario(&self, plan: &Plan, payer: &Coin, covenant: Hash, fee: u64) -> Option<Scenario> {
        let Holder::Key(payer_key) = payer.holder else {
            panic!("the paying coin is a pay-to-public-key coin");
        };
        let mut scenario = Scenario::new(plan.name.clone());
        for (coin, call) in &plan.inputs {
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
                payer.script_public_key.clone(),
                payer.value,
                payer.outpoint,
                p2pk_signature(payer_key),
            )
            .labelled(payer.what.clone()),
        );
        for state in &plan.outputs {
            scenario.push_contract_output(ContractOutput::new(
                state.clone(),
                self.coin_value,
                Some(CovenantBinding::new(0, covenant)),
            ));
        }
        for key in &plan.deposits_to {
            scenario.push_plain_output(PlainOutput::new(
                pay_to_public_key_script(&keys::x_only(*key)),
                self.coin_value,
            ));
        }
        let change = scenario
            .total_in()
            .checked_sub(scenario.total_out())?
            .checked_sub(fee)?;
        scenario.push_plain_output(PlainOutput::new(self.issuer_script(), change));
        Some(scenario)
    }

    /// The fee the rule asks of an evaluated transaction.
    fn fee_for(&self, name: &str, outcome: &Outcome) -> Result<(Numbers, u64), String> {
        let numbers = Numbers::of(outcome).ok_or_else(|| {
            format!(
                "{name}: the gate gives no masses or no fee floor; {}",
                refusal_of(outcome).unwrap_or_default()
            )
        })?;
        let fee = self
            .feerate
            .checked_mul(numbers.charged_mass())
            .ok_or_else(|| format!("{name}: the fee does not fit 64 bits"))?;
        Ok((numbers, fee))
    }

    /// Builds the transaction of `plan` with the fee of the fee rule. The fee and the masses
    /// depend on each other through the change output, so the fee is recalculated until a
    /// build asks for the fee it was built with. If that does not happen within a few rounds,
    /// the larger of the last two candidates is taken and must cover what its own build asks.
    fn settle(&self, plan: &Plan, payer: &Coin, covenant: Hash) -> Result<Settled, String> {
        let name = &plan.name;
        let build = |fee: u64| -> Result<(Outcome, Numbers, u64), String> {
            let scenario = self.scenario(plan, payer, covenant, fee).ok_or_else(|| {
                format!(
                    "{name}: the paying coin of {} KAS does not cover the step",
                    kas(payer.value)
                )
            })?;
            let outcome = self.harness.run(&scenario);
            let (numbers, wanted) = self.fee_for(name, &outcome)?;
            Ok((outcome, numbers, wanted))
        };
        let (mut fee, mut before) = (0u64, 0u64);
        let mut settled = None;
        for _ in 0..FEE_ROUNDS {
            let (outcome, numbers, wanted) = build(fee)?;
            if wanted == fee {
                settled = Some((outcome, numbers));
                break;
            }
            before = fee;
            fee = wanted;
        }
        let (outcome, numbers, at_the_fixed_point) = match settled {
            Some((outcome, numbers)) => (outcome, numbers, true),
            None => {
                fee = fee.max(before);
                println!(
                    "{name}: the fee did not settle in {FEE_ROUNDS} rounds; the larger of the \
                     last two candidates, {fee} sompi, is taken"
                );
                let (outcome, numbers, wanted) = build(fee)?;
                if fee < wanted {
                    return Err(format!(
                        "{name}: the fee did not settle; {fee} sompi is below the {wanted} its \
                         own transaction asks"
                    ));
                }
                (outcome, numbers, false)
            }
        };
        if fee < numbers.fee_floor {
            return Err(format!(
                "{name}: the fee of {fee} sompi is below the mempool floor of {} sompi",
                numbers.fee_floor
            ));
        }
        Ok(Settled {
            outcome,
            numbers,
            fee,
            at_the_fixed_point,
        })
    }

    /// The evaluated transaction in the form of the chain file, and the coins it creates.
    ///
    /// The transaction is the one the gate judged: the committed budgets, and the mass field
    /// set to the storage mass a node calculates. What the outputs are is asserted here: every
    /// covenant output is locked to the state the plan claims and bound to input 0 under the
    /// covenant id; every spent coin is the coin the plan names, script included.
    #[allow(clippy::too_many_arguments)]
    fn written(
        &self,
        plan: &Plan,
        payer: &Coin,
        covenant: Hash,
        outcome: &Outcome,
        numbers: &Numbers,
        fee: u64,
        refusal: Option<Value>,
    ) -> Written {
        let name = &plan.name;
        let family = &*self.harness.family;
        let handles = &self.handles;
        let mut tx = outcome.committed_tx.clone();
        tx.set_storage_mass(numbers.storage_mass);
        tx.finalize();
        let id = tx.id();

        let spent: Vec<&Coin> = plan
            .inputs
            .iter()
            .map(|(coin, _)| coin)
            .chain(std::iter::once(payer))
            .collect();
        assert_eq!(tx.inputs.len(), spent.len(), "{name}: the number of inputs");
        let mut total_in = 0u64;
        let inputs_json: Vec<Value> = tx
            .inputs
            .iter()
            .enumerate()
            .map(|(index, input)| {
                let coin = spent[index];
                let entry = &outcome.assembled.utxos[index];
                assert_eq!(
                    input.previous_outpoint, coin.outpoint,
                    "{name}: the outpoint of input {index}"
                );
                assert_eq!(
                    entry.amount, coin.value,
                    "{name}: the value input {index} spends"
                );
                assert_eq!(
                    entry.script_public_key, coin.script_public_key,
                    "{name}: input {index} spends the script the coin was created with"
                );
                assert_eq!(
                    entry.covenant_id, coin.covenant_id,
                    "{name}: the covenant id input {index} spends"
                );
                let commitment = outcome.inputs[index].commitment;
                assert_eq!(
                    Commitment::from(input.compute_commit),
                    commitment,
                    "{name}: the commitment input {index} carries"
                );
                let (sig_op_count, compute_budget) = match commitment {
                    Commitment::ComputeBudget(budget) => (0u8, budget),
                    Commitment::SigOpCount(count) => (count, 0u16),
                };
                total_in += entry.amount;
                let from = match &coin.origin {
                    Origin::Funding => json!("funding"),
                    Origin::Step { name, output } => json!({"step": name, "output": output}),
                };
                json!({
                    "transaction_id": input.previous_outpoint.transaction_id.to_string(),
                    "index": input.previous_outpoint.index,
                    "sequence": input.sequence,
                    "sig_op_count": sig_op_count,
                    "compute_budget": compute_budget,
                    "signature_script": hex(&input.signature_script),
                    "spends": {
                        "from": from,
                        "value": entry.amount,
                        "script_public_key_version": entry.script_public_key.version(),
                        "script_public_key": hex(entry.script_public_key.script()),
                        "covenant_id": entry.covenant_id.map(|id| id.to_string()),
                        "what": coin.what,
                    },
                })
            })
            .collect();

        let covenant_outputs = plan.outputs.len();
        assert_eq!(
            tx.outputs.len(),
            covenant_outputs + plan.deposits_to.len() + 1,
            "{name}: the number of outputs"
        );
        let mut created = Vec::new();
        let mut outputs_json = Vec::new();
        let mut total_out = 0u64;
        for (index, output) in tx.outputs.iter().enumerate() {
            let (holder, role, to, state, what) = if let Some(state) = plan.outputs.get(index) {
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
                assert_eq!(output.value, self.coin_value);
                (
                    Holder::Covenant(state.clone()),
                    "covenant",
                    None,
                    Some(state_json(state)),
                    handles.describe(state),
                )
            } else if let Some(key) = plan.deposits_to.get(index - covenant_outputs) {
                assert!(output.covenant.is_none());
                assert_eq!(output.value, self.coin_value);
                assert_eq!(
                    output.script_public_key,
                    pay_to_public_key_script(&keys::x_only(*key))
                );
                (
                    Holder::Key(*key),
                    "deposit",
                    Some(handles.party(*key)),
                    None,
                    format!("deposit back to {}", handles.person(*key)),
                )
            } else {
                assert!(output.covenant.is_none());
                assert_eq!(output.script_public_key, self.issuer_script());
                (
                    Holder::Key(handles.issuer),
                    "change",
                    Some(handles.party(handles.issuer)),
                    None,
                    "change of the issuer".to_string(),
                )
            };
            total_out += output.value;
            outputs_json.push(json!({
                "value": output.value,
                "script_public_key_version": output.script_public_key.version(),
                "script_public_key": hex(output.script_public_key.script()),
                "covenant_binding": output.covenant.map(|binding| json!({
                    "authorizing_input": binding.authorizing_input,
                    "covenant_id": binding.covenant_id.to_string(),
                })),
                "role": role,
                "to": to,
                "state": state,
                "what": what,
            }));
            created.push(Coin {
                outpoint: TransactionOutpoint::new(id, index as u32),
                value: output.value,
                script_public_key: output.script_public_key.clone(),
                covenant_id: output.covenant.map(|binding| binding.covenant_id),
                holder,
                origin: Origin::Step {
                    name: name.clone(),
                    output: index as u32,
                },
                what,
            });
        }
        assert_eq!(
            total_in.checked_sub(total_out),
            Some(fee),
            "{name}: the fee is what the inputs hold above the outputs"
        );
        assert_eq!(tx.storage_mass(), numbers.storage_mass);
        // Nothing but the contracts' own data goes on chain: no payload, no gas, no lock time.
        assert!(tx.payload.is_empty(), "{name}: the payload is empty");
        assert_eq!((tx.gas, tx.lock_time), (0, 0), "{name}: gas and lock time");

        let json = json!({
            "name": name,
            "what": plan.what,
            "expect": if refusal.is_some() { "refused" } else { "accepted" },
            "transaction_id": id.to_string(),
            "version": tx.version,
            "lock_time": tx.lock_time,
            "subnetwork_id": hex(tx.subnetwork_id.as_ref()),
            "gas": tx.gas,
            "payload": hex(&tx.payload),
            "mass": tx.storage_mass(),
            "inputs": inputs_json,
            "outputs": outputs_json,
            "fee": fee,
            "fee_floor": numbers.fee_floor,
            "masses": {
                "compute_mass": numbers.compute_mass,
                "transient_mass": numbers.transient_mass,
                "calculated_storage_mass": numbers.storage_mass,
                "fee_mass": numbers.fee_mass,
            },
            "gate": {
                "scripts": outcome.scripts_accept(),
                "consensus": outcome.consensus.accepted,
                "mempool": outcome.mempool.accepted,
                "block": outcome.consensus.block.accepted,
                "refusal": refusal,
            },
        });
        // The entry holds the whole transaction: built again from the entry alone it is the
        // transaction the gate judged, with the id the entry states.
        let rebuilt = rebuilt_from_the_file(&json);
        assert_eq!(
            rebuilt.id(),
            id,
            "{name}: the id of the transaction as the file holds it"
        );
        assert_eq!(rebuilt.storage_mass(), tx.storage_mass());
        assert_eq!(
            rebuilt, tx,
            "{name}: the file holds the transaction the gate judged"
        );
        Written {
            json,
            id,
            tx,
            created,
        }
    }
}

// ---------------------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------------------

/// A forbidden move and what refuses it.
struct Probe {
    forbidden: Plan,
    honest: Plan,
    /// The input the scripts refuse.
    input: usize,
    /// The rule of the contract that refuses it.
    expected: Expected,
}

/// The run so far.
struct Chain<'a> {
    terms: Terms<'a>,
    fee_cap_total: u64,
    /// The covenant id of the token: derived at the launch, carried by every later coin.
    covenant: Option<Hash>,
    /// The pay-to-public-key coin of the issuer that pays the next step.
    payer: Coin,
    /// Every unspent coin of the run.
    live: Vec<Coin>,
    minted: i64,
    fees: u64,
    locked_at_peak: u64,
    deposits_returned: u64,
    /// The steps and the honest twins of the probes whose fee did not settle.
    unsettled_steps: usize,
    unsettled_probes: usize,
    steps: Vec<Value>,
    probes: Vec<Value>,
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

    fn is_live(&self, coin: &Coin) -> bool {
        self.live.iter().any(|live| live.outpoint == coin.outpoint)
    }

    /// One step of the run. Returns the coins it created, in output order.
    ///
    /// `Err` says why the step cannot go into a chain: a node would not take it, or the fees
    /// pass the cap. A step that a node takes and whose outputs are not what the plan claims
    /// is a panic.
    fn step(&mut self, plan: Plan, minted: i64) -> Result<Vec<Coin>, String> {
        let name = plan.name.clone();
        let terms = self.terms;
        let family = &*terms.harness.family;
        let payer = self.payer.clone();

        // The covenant id. At the launch it is derived by the node's own function from the
        // authorizing outpoint (input 0, the issuer's coin) and the ordered group of outputs.
        let covenant = match self.covenant {
            Some(id) => id,
            None => {
                let group: Vec<TransactionOutput> = plan
                    .outputs
                    .iter()
                    .map(|state| {
                        let script = family.script_public_key(state).expect("an honest state");
                        TransactionOutput::with_covenant(terms.coin_value, script, None)
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

        let Settled {
            outcome,
            numbers,
            fee,
            at_the_fixed_point,
        } = terms.settle(&plan, &payer, covenant)?;
        if !at_the_fixed_point {
            self.unsettled_steps += 1;
        }
        if let Some(refusal) = refusal_of(&outcome) {
            return Err(format!("{name}: {refusal}"));
        }
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
        assert!(
            fee >= numbers.fee_floor,
            "{name}: the fee is at least the floor"
        );
        assert!(
            fee >= terms.feerate * numbers.charged_mass(),
            "{name}: the fee covers the fee rate on the larger mass"
        );
        assert_eq!(
            outcome.consensus.block.committed_storage_mass, numbers.storage_mass,
            "{name}: the block commits to the calculated storage mass"
        );
        assert_eq!(
            outcome.minimal_budgets().map(|budgets| budgets.len()),
            Some(outcome.committed_tx.inputs.len()),
            "{name}: every input has a smallest budget"
        );
        if self.fees + fee > self.fee_cap_total {
            return Err(format!(
                "{name}: the fees reach {} sompi with this step, above the cap of {} sompi",
                self.fees + fee,
                self.fee_cap_total
            ));
        }

        let written = terms.written(&plan, &payer, covenant, &outcome, &numbers, fee, None);
        let created = written.created;

        if self.covenant.is_none() {
            // The launch: the id once more, from the finished transaction.
            let group: Vec<(u32, &TransactionOutput)> = written
                .tx
                .outputs
                .iter()
                .enumerate()
                .filter(|(_, output)| output.covenant.is_some())
                .map(|(index, output)| (index as u32, output))
                .collect();
            assert_eq!(group.len(), plan.outputs.len());
            assert_eq!(
                covenant_id(written.tx.inputs[0].previous_outpoint, group.into_iter()),
                covenant,
                "the id of the finished launch transaction"
            );
            self.covenant = Some(covenant);
        }

        // Every input spent a coin that existed and was unspent.
        let spent: Vec<TransactionOutpoint> = written
            .tx
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
        self.deposits_returned += terms.coin_value * plan.deposits_to.len() as u64;
        self.locked_at_peak = self.locked_at_peak.max(self.locked());
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

        let _ = writeln!(
            self.table,
            "{name:<22} | {}\n{:<22} | transaction {}\n{:<22} | fee {} KAS (floor {}) | fee mass \
             {} | storage mass {} | fees so far {} KAS | locked {} KAS",
            plan.what,
            "",
            written.id,
            "",
            kas(fee),
            kas(numbers.fee_floor),
            numbers.fee_mass,
            numbers.storage_mass,
            kas(self.fees),
            kas(self.locked()),
        );
        for coin in &self.live {
            let _ = writeln!(
                self.table,
                "{:<22} |   {} [{} KAS]",
                "",
                coin.what,
                kas(coin.value)
            );
        }
        self.steps.push(written.json);
        Ok(created)
    }

    /// One forbidden move, built from coins that are unspent after the last step. Its honest
    /// twin must be accepted by scripts, consensus, the block and the mempool; the move itself
    /// carries the twin's budgets and pays the twin's fee, so that the one wrong thing is all
    /// a node can hold against it, and must be refused by the scripts at the expected rule.
    fn probe(&mut self, probe: Probe) -> Result<(), String> {
        let name = probe.forbidden.name.clone();
        let terms = self.terms;
        let payer = self.payer.clone();
        let covenant = self.covenant.expect("the launch is behind us");
        for (coin, _) in probe.forbidden.inputs.iter().chain(&probe.honest.inputs) {
            assert!(self.is_live(coin), "{name}: `{}` is unspent", coin.what);
        }
        assert!(self.is_live(&payer));

        // The honest twin, with the fee of the fee rule.
        let twin = terms
            .settle(&probe.honest, &payer, covenant)
            .map_err(|error| format!("{name}: the honest twin: {error}"))?;
        if let Some(refusal) = refusal_of(&twin.outcome) {
            return Err(format!("{name}: the honest twin is refused: {refusal}"));
        }
        if !twin.at_the_fixed_point {
            self.unsettled_probes += 1;
        }
        let budgets = twin
            .outcome
            .minimal_budgets()
            .ok_or_else(|| format!("{name}: the honest twin has an input without a budget"))?;

        // The forbidden move under the same budgets and the same fee.
        let scenario = terms
            .scenario(&probe.forbidden, &payer, covenant, twin.fee)
            .ok_or_else(|| format!("{name}: the paying coin does not cover the move"))?;
        let harness = terms
            .harness
            .clone()
            .with_budgets(Budgets::Exactly(budgets));
        let outcome = harness.run(&scenario);
        let honest_tx = &twin.outcome.committed_tx;
        let forbidden_tx = &outcome.committed_tx;
        let scripts_of = |tx: &Transaction| -> Vec<Vec<u8>> {
            tx.inputs
                .iter()
                .map(|input| input.signature_script.clone())
                .collect()
        };
        assert!(
            honest_tx.id() != forbidden_tx.id()
                || scripts_of(honest_tx) != scripts_of(forbidden_tx),
            "{name}: the forbidden move differs from its honest twin"
        );

        // Refused by the scripts, at the expected rule, in both runs of the input; every other
        // input passes; a node gets as far as the scripts.
        judge_input(&outcome, probe.input, &probe.expected)
            .map_err(|error| format!("{name}: {error}"))?;
        let record = &outcome.inputs[probe.input];
        let alone = record.alone.as_ref().expect("the input was run by itself");
        let committed = record
            .committed
            .as_ref()
            .expect("the input was run under its budget");
        assert_eq!(
            alone.rule(),
            probe.expected.rule.as_deref(),
            "{name}: the rule without a budget limit"
        );
        assert_eq!(
            committed.rule(),
            probe.expected.rule.as_deref(),
            "{name}: the rule under the committed budget"
        );
        assert_eq!(outcome.scripts.refused_inputs, vec![probe.input]);
        assert_eq!(
            outcome.scripts.refused_inputs_under_committed_budgets,
            vec![probe.input]
        );
        assert!(
            outcome.consensus.context_accepted,
            "{name}: a node gets to run the scripts: {:?}",
            outcome.consensus.context_refusal
        );
        assert!(!outcome.scripts_accept(), "{name}: the scripts refuse");
        assert!(!outcome.consensus.accepted, "{name}: consensus refuses");
        assert!(
            !outcome.consensus.block.accepted,
            "{name}: a block with it is refused"
        );
        assert!(!outcome.mempool.accepted, "{name}: the mempool refuses");
        // The scripts are all a node holds against the move: the two runs of the inputs agree
        // and no policy rule of the mempool refuses, the fee floor included.
        assert!(
            outcome.scripts.disagreements.is_empty(),
            "{name}: the two script runs disagree: {:?}",
            outcome.scripts.disagreements
        );
        assert!(
            outcome.mempool.policy_accepted,
            "{name}: a policy rule refuses as well: {:?}",
            outcome.mempool.refused
        );
        let node_refusal = outcome.consensus.refusal.as_ref();
        assert_eq!(
            node_refusal.and_then(|refusal| refusal.input),
            Some(probe.input),
            "{name}: the input a node names in its refusal"
        );

        // The masses and the floor of the move itself where the gate gives them; they are
        // those of the twin when the two transactions have the same sizes.
        let own = Numbers::of(&outcome);
        let numbers = own.unwrap_or(twin.numbers);
        assert!(
            twin.fee >= numbers.fee_floor,
            "{name}: the twin's fee covers the floor of the move itself"
        );
        let error = committed
            .error
            .as_ref()
            .expect("a refused run has an error");
        println!(
            "{name}: refused at input {} by {} ({}); a node says: {}; masses of the move itself: \
             {}; policy alone: {}; fee {} against its own floor {}",
            probe.input,
            committed.refused_by().unwrap_or("?"),
            error.message,
            node_refusal
                .map(|refusal| format!("{} ({})", refusal.rule, refusal.message))
                .unwrap_or_default(),
            match own {
                Some(own) if own == twin.numbers => "equal to the twin's".to_string(),
                Some(own) => format!("{own:?}, the twin's {:?}", twin.numbers),
                None => "not given by the gate, the twin's are written".to_string(),
            },
            if outcome.mempool.policy_accepted {
                "accepted"
            } else {
                "refused"
            },
            twin.fee,
            numbers.fee_floor,
        );
        let refusal = json!({
            "layer": "scripts",
            "input": probe.input,
            "rule": committed.rule(),
            "message": error.message,
        });
        let written = terms.written(
            &probe.forbidden,
            &payer,
            covenant,
            &outcome,
            &numbers,
            twin.fee,
            Some(refusal),
        );
        if self.probes.is_empty() {
            let _ = writeln!(
                self.table,
                "{}\nForbidden moves, built from coins that are unspent after step 13. Each must be \
                 refused; none changes the coins above.",
                "-".repeat(100)
            );
        }
        let _ = writeln!(
            self.table,
            "{name}\n{:<22} | {}\n{:<22} | transaction {}\n{:<22} | refused by the scripts at input \
             {}, rule {}: {}\n{:<22} | the honest twin is accepted; both pay {} KAS",
            "",
            probe.forbidden.what,
            "",
            written.id,
            "",
            probe.input,
            committed.rule().unwrap_or("?"),
            error.message,
            "",
            kas(twin.fee),
        );
        self.probes.push(written.json);
        Ok(())
    }
}

/// The result of one build: what goes into the chain file, and the table.
#[derive(Debug, PartialEq)]
struct Run {
    covenant: String,
    steps: Vec<Value>,
    probes: Vec<Value>,
    totals: Value,
    table: String,
    /// The steps and the probes whose fee did not settle.
    unsettled_steps: usize,
    unsettled_probes: usize,
}

/// The 13 steps of the dry run and the three forbidden moves, from the funding coin.
fn run_once(terms: Terms<'_>, request: &Request) -> Result<Run, String> {
    let handles = terms.handles;
    let issuer = keys::x_only(handles.issuer);
    let alice = keys::x_only(handles.alice);
    let bob = keys::x_only(handles.bob);
    let start = Coin {
        outpoint: TransactionOutpoint::new(
            TransactionId::from_bytes(request.funding.transaction_id),
            request.funding.index,
        ),
        value: request.funding.value,
        script_public_key: request.funding.script_public_key.clone(),
        covenant_id: None,
        holder: Holder::Key(handles.issuer),
        origin: Origin::Funding,
        what: "funding coin of the issuer".to_string(),
    };
    let mut chain = Chain {
        terms,
        fee_cap_total: request.fee_cap_total,
        covenant: None,
        payer: start.clone(),
        live: vec![start],
        minted: 0,
        fees: 0,
        locked_at_peak: 0,
        deposits_returned: 0,
        unsettled_steps: 0,
        unsettled_probes: 0,
        steps: Vec::new(),
        probes: Vec::new(),
        table: String::new(),
    };
    let minter_of = |owner: [u8; 32], remaining: i64| -> State {
        PublicMintState::new(owner, remaining, MINT_LIMIT).into()
    };
    let seed_of = |owner: [u8; 32]| -> State { TokenSeedState::new(owner).into() };
    let signed_by = |handle: u8| Arg::Bytes(witness::signature(handle, SIG_HASH_ALL));
    let owner_witness =
        |handle: u8, role: EntryRole| Arg::Bytes(witness::owner_key(handle, role, SIG_HASH_ALL));

    // 1. The launch: the issuer's coin authorizes the minter and the seed.
    let made = chain.step(
        Plan::new(
            "01 launch",
            "the issuer's coin creates the minter (25 to mint, at most 10 per mint) and the seed",
        )
        .creating([minter_of(issuer, SUPPLY), seed_of(issuer)]),
        0,
    )?;
    let (minter, seed) = (made[0].clone(), made[1].clone());

    // 2. Mint 10 to Alice.
    let alice_10 = Kcc20State::new(alice, 10);
    let made = chain.step(
        Plan::new("02 mint", "the minter mints 10 tokens to Alice")
            .spending(
                &minter,
                Call::typed(Entry::Mint, vec![Arg::State(alice_10.clone())]),
            )
            .creating([minter_of(issuer, 15), alice_10.into()]),
        10,
    )?;
    let (minter, alice_coin) = (made[0].clone(), made[1].clone());

    // 3. Alice transfers 4 to Bob and keeps 6.
    let next = vec![Kcc20State::new(bob, 4), Kcc20State::new(alice, 6)];
    let made = chain.step(
        Plan::new(
            "03 transfer",
            "Alice moves 4 tokens to Bob and keeps 6 (one coin in, two out)",
        )
        .spending(
            &alice_coin,
            Call::typed(
                Entry::Transfer,
                vec![
                    Arg::States(next.clone()),
                    owner_witness(handles.alice, EntryRole::Leader),
                ],
            ),
        )
        .creating(next.into_iter().map(State::from)),
        0,
    )?;
    let alice_coin = made[1].clone();

    // 4. The seed creates a zero-token coin for Bob that anybody may pay into.
    let bob_open = Kcc20State::new(bob, 0).with_threshold(0);
    let made = chain.step(
        Plan::new(
            "04 seed create",
            "the seed creates a zero-token coin for Bob, open to payments (threshold 0)",
        )
        .spending(
            &seed,
            Call::typed(Entry::SeedCreate, vec![Arg::State(bob_open.clone())]),
        )
        .creating([seed_of(issuer), bob_open.clone().into()]),
        0,
    )?;
    let (seed, bob_open_coin) = (made[0].clone(), made[1].clone());

    // 5. Borrowed receive: Bob's open coin leads without Bob's signature, Alice's coin joins
    //    and signs; 3 tokens move from Alice into Bob's coin.
    let next = vec![bob_open.with_amount(3), Kcc20State::new(alice, 3)];
    let made = chain.step(
        Plan::new(
            "05 borrowed receive",
            "Alice pays 3 tokens into Bob's open coin; Bob does not sign",
        )
        .spending(
            &bob_open_coin,
            Call::typed(
                Entry::Transfer,
                vec![
                    Arg::States(next.clone()),
                    Arg::Bytes(witness::borrow_threshold()),
                ],
            ),
        )
        .spending(
            &alice_coin,
            Call::typed(
                Entry::TransferDelegator,
                vec![owner_witness(handles.alice, EntryRole::Delegate)],
            ),
        )
        .creating(next.into_iter().map(State::from)),
        0,
    )?;
    let alice_3_coin = made[1].clone();

    // 6. The minter hands 5 of its allowance to a new minter of Bob.
    let made = chain.step(
        Plan::new(
            "06 minter split",
            "the minter hands 5 of its 15 to a new minter owned by Bob",
        )
        .spending(
            &minter,
            Call::typed(Entry::MintSplit, vec![Arg::int(5), Arg::bytes(bob)]),
        )
        .creating([minter_of(issuer, 10), minter_of(bob, 5)]),
        0,
    )?;
    let (minter, bob_minter) = (made[0].clone(), made[1].clone());

    // 7. A mint from the split minter.
    let bob_2 = Kcc20State::new(bob, 2);
    let made = chain.step(
        Plan::new(
            "07 mint from the split",
            "Bob's minter mints 2 tokens to Bob",
        )
        .spending(
            &bob_minter,
            Call::typed(Entry::Mint, vec![Arg::State(bob_2.clone())]),
        )
        .creating([minter_of(bob, 3), bob_2.into()]),
        2,
    )?;
    let bob_minter = made[0].clone();

    // 8. Bob's minter retires into the issuer's; its deposit goes back to Bob.
    let made = chain.step(
        Plan::new(
            "08 reclaim into",
            "Bob's minter (3 left) retires into the issuer's minter; Bob signs and gets the deposit",
        )
        .spending(&minter, Call::typed(Entry::MintReclaimInto, Vec::new()))
        .spending(
            &bob_minter,
            Call::typed(Entry::MintReclaimDelegator, vec![signed_by(handles.bob)]),
        )
        .creating([minter_of(issuer, 13)])
        .returning_a_deposit_to(handles.bob),
        0,
    )?;
    let minter = made[0].clone();

    // 9. Two more mints empty the allowance.
    let alice_10 = Kcc20State::new(alice, 10);
    let made = chain.step(
        Plan::new("09 mint", "the minter mints 10 tokens to Alice")
            .spending(
                &minter,
                Call::typed(Entry::Mint, vec![Arg::State(alice_10.clone())]),
            )
            .creating([minter_of(issuer, 3), alice_10.into()]),
        10,
    )?;
    let (minter, alice_10_coin) = (made[0].clone(), made[1].clone());
    let bob_3 = Kcc20State::new(bob, 3);
    let made = chain.step(
        Plan::new("10 last mint", "the minter mints its last 3 tokens to Bob")
            .spending(
                &minter,
                Call::typed(Entry::Mint, vec![Arg::State(bob_3.clone())]),
            )
            .creating([minter_of(issuer, 0), bob_3.into()]),
        3,
    )?;
    let minter = made[0].clone();

    // 10. The issuer closes the exhausted minter and takes its deposit.
    chain.step(
        Plan::new(
            "11 minter reclaim",
            "the issuer closes the empty minter and gets the deposit",
        )
        .spending(
            &minter,
            Call::typed(Entry::MintReclaim, vec![signed_by(handles.issuer)]),
        )
        .returning_a_deposit_to(handles.issuer),
        0,
    )?;

    // 11. The seed creates a second seed for Bob, and that seed is closed again.
    let made = chain.step(
        Plan::new(
            "12 seed split",
            "the seed creates a second seed owned by Bob",
        )
        .spending(&seed, Call::typed(Entry::SeedSplit, vec![Arg::bytes(bob)]))
        .creating([seed_of(issuer), seed_of(bob)]),
        0,
    )?;
    let (seed, bob_seed) = (made[0].clone(), made[1].clone());
    let made = chain.step(
        Plan::new(
            "13 seed reclaim",
            "Bob's seed is closed next to the issuer's; Bob signs and gets the deposit",
        )
        .spending(&seed, Call::typed(Entry::SeedReclaim, Vec::new()))
        .spending(
            &bob_seed,
            Call::typed(Entry::SeedReclaimDelegator, vec![signed_by(handles.bob)]),
        )
        .creating([seed_of(issuer)])
        .returning_a_deposit_to(handles.bob),
        0,
    )?;
    let seed = made[0].clone();

    assert_eq!(chain.steps.len(), 13);
    assert_eq!(chain.minted, SUPPLY, "the whole supply was minted");
    assert_eq!(chain.allowance(), 0);
    assert!(chain.fees <= request.fee_cap_total);

    // The forbidden moves. Each spends one covenant coin and the issuer's last change coin.
    let transfer_of_10 = |name: &str, what: &str, signer: u8| {
        let next = vec![Kcc20State::new(bob, 10)];
        Plan::new(name, what)
            .spending(
                &alice_10_coin,
                Call::typed(
                    Entry::Transfer,
                    vec![
                        Arg::States(next.clone()),
                        owner_witness(signer, EntryRole::Leader),
                    ],
                ),
            )
            .creating(next.into_iter().map(State::from))
    };
    chain.probe(Probe {
        forbidden: transfer_of_10(
            "B1 transfer without the owner's signature",
            "Alice's 10 tokens are moved to Bob with a witness signed by Bob's key, not Alice's",
            handles.bob,
        ),
        honest: transfer_of_10(
            "B1 honest twin",
            "Alice moves her 10 tokens to Bob and signs",
            handles.alice,
        ),
        input: 0,
        expected: Expected::rule("K-38").at_line(69),
    })?;

    let split_of_3 = |name: &str, what: &str, kept: i64| {
        let next = vec![Kcc20State::new(alice, kept), Kcc20State::new(bob, 1)];
        Plan::new(name, what)
            .spending(
                &alice_3_coin,
                Call::typed(
                    Entry::Transfer,
                    vec![
                        Arg::States(next.clone()),
                        owner_witness(handles.alice, EntryRole::Leader),
                    ],
                ),
            )
            .creating(next.into_iter().map(State::from))
    };
    chain.probe(Probe {
        forbidden: split_of_3(
            "B2 more tokens out than in",
            "Alice signs a transfer of her 3-token coin into 3 tokens for herself and 1 for Bob: \
             4 out of 3",
            3,
        ),
        honest: split_of_3(
            "B2 honest twin",
            "Alice moves 1 of her 3 tokens to Bob and keeps 2",
            2,
        ),
        input: 0,
        expected: Expected::rule("K-37").at_line(175),
    })?;

    let seed_create = |name: &str, what: &str, amount: i64| {
        let created = Kcc20State::new(bob, amount);
        Plan::new(name, what)
            .spending(
                &seed,
                Call::typed(Entry::SeedCreate, vec![Arg::State(created.clone())]),
            )
            .creating([seed_of(issuer), created.into()])
    };
    chain.probe(Probe {
        forbidden: seed_create(
            "B3 the seed creates a coin that already holds tokens",
            "the issuer's seed creates a token coin for Bob that holds 5 tokens nobody minted",
            5,
        ),
        honest: seed_create(
            "B3 honest twin",
            "the issuer's seed creates a zero-token coin for Bob",
            0,
        ),
        input: 0,
        expected: Expected::rule("S-12").at_line(132),
    })?;
    assert_eq!(chain.probes.len(), 3);

    let totals = json!({
        "fees": chain.fees,
        "locked_at_peak": chain.locked_at_peak,
        "locked_at_the_end": chain.locked(),
        "deposits_returned": chain.deposits_returned,
        "change_at_the_end": chain.payer.value,
        "tokens_minted": chain.minted,
    });
    Ok(Run {
        covenant: chain.covenant.expect("the launch").to_string(),
        steps: chain.steps,
        probes: chain.probes,
        totals,
        table: chain.table,
        unsettled_steps: chain.unsettled_steps,
        unsettled_probes: chain.unsettled_probes,
    })
}

/// The transaction ids and the signature scripts of a list of transactions of a chain file.
fn ids_and_signature_scripts(transactions: &[Value]) -> Vec<(String, Vec<String>)> {
    transactions
        .iter()
        .map(|tx| {
            let id = tx["transaction_id"].as_str().expect("an id").to_string();
            let scripts = tx["inputs"]
                .as_array()
                .expect("inputs")
                .iter()
                .map(|input| {
                    input["signature_script"]
                        .as_str()
                        .expect("a signature script")
                        .to_string()
                })
                .collect();
            (id, scripts)
        })
        .collect()
}

/// Checks a chain document by its own fields, as a reader of the file can, without the
/// objects it was written from: every input spends the funding coin or the named output of an
/// earlier step, with the id of that step and the value, script and covenant id of that
/// output; no step spends a coin twice and a probe spends only coins no step spent; every fee
/// is what the inputs hold above the outputs; the totals are those of the steps.
fn assert_the_document_is_consistent(chain: &Value) {
    let steps = chain["steps"].as_array().expect("steps");
    let probes = chain["probes"].as_array().expect("probes");
    let funding = &chain["funding"];
    let coin_fields = ["value", "script_public_key_version", "script_public_key"];
    let mut spent: Vec<(String, u64)> = Vec::new();
    let mut fees = 0u64;
    for (position, tx) in steps.iter().chain(probes).enumerate() {
        let name = tx["name"].as_str().expect("a name");
        let is_step = position < steps.len();
        let earlier = &steps[..position.min(steps.len())];
        let mut total_in = 0u64;
        for input in tx["inputs"].as_array().expect("inputs") {
            let spends = &input["spends"];
            let from = &spends["from"];
            if from == "funding" {
                for field in ["transaction_id", "index"] {
                    assert_eq!(input[field], funding[field], "{name}: the funding {field}");
                }
                for field in coin_fields {
                    assert_eq!(spends[field], funding[field], "{name}: the funding {field}");
                }
                assert!(spends["covenant_id"].is_null(), "{name}: the funding coin");
            } else {
                let source = earlier
                    .iter()
                    .find(|step| step["name"] == from["step"])
                    .unwrap_or_else(|| panic!("{name}: {} is no earlier step", from["step"]));
                let index = from["output"].as_u64().expect("an output index");
                let output = &source["outputs"][index as usize];
                assert!(
                    output.is_object(),
                    "{name}: no output {index} in {}",
                    from["step"]
                );
                assert_eq!(
                    input["transaction_id"], source["transaction_id"],
                    "{name}: the id of the step an input spends from"
                );
                assert_eq!(input["index"], index, "{name}: the index an input spends");
                for field in coin_fields {
                    assert_eq!(spends[field], output[field], "{name}: the spent {field}");
                }
                assert_eq!(
                    spends["covenant_id"], output["covenant_binding"]["covenant_id"],
                    "{name}: the spent covenant id"
                );
            }
            let coin = (
                input["transaction_id"].as_str().expect("an id").to_string(),
                input["index"].as_u64().expect("an index"),
            );
            assert!(!spent.contains(&coin), "{name}: spends a coin a step spent");
            if is_step {
                spent.push(coin);
            }
            total_in += spends["value"].as_u64().expect("a value");
        }
        let total_out: u64 = tx["outputs"]
            .as_array()
            .expect("outputs")
            .iter()
            .map(|output| output["value"].as_u64().expect("a value"))
            .sum();
        let fee = tx["fee"].as_u64().expect("a fee");
        assert_eq!(
            total_in.checked_sub(total_out),
            Some(fee),
            "{name}: the fee"
        );
        if is_step {
            fees += fee;
        }
    }

    // What the steps leave: the unspent covenant coins, the deposits and the last change.
    let (mut locked, mut deposits, mut change) = (0u64, 0u64, 0u64);
    for step in steps {
        let id = step["transaction_id"].as_str().expect("an id");
        for (index, output) in step["outputs"]
            .as_array()
            .expect("outputs")
            .iter()
            .enumerate()
        {
            let value = output["value"].as_u64().expect("a value");
            let unspent = !spent.contains(&(id.to_string(), index as u64));
            match output["role"].as_str().expect("a role") {
                "covenant" if unspent => locked += value,
                "covenant" => {}
                "deposit" => {
                    assert!(unspent, "a deposit is not spent by the run");
                    deposits += value;
                }
                "change" if unspent => change += value,
                "change" => {}
                other => panic!("an output with the role `{other}`"),
            }
        }
    }
    let totals = &chain["totals"];
    assert_eq!(totals["fees"], fees, "the fees of the steps");
    assert_eq!(
        totals["locked_at_the_end"], locked,
        "the unspent covenant coins"
    );
    assert_eq!(totals["deposits_returned"], deposits, "the deposits");
    assert_eq!(
        totals["change_at_the_end"], change,
        "the one unspent change coin"
    );
    assert!(fees <= chain["fee_cap_total"].as_u64().expect("a cap"));
    // Nothing is lost: the funding coin is the fees and what is left.
    assert_eq!(
        funding["value"].as_u64(),
        Some(fees + locked + deposits + change),
        "the funding coin is the fees, the covenant coins, the deposits and the change"
    );
}

/// A finished chain: the document of the chain file and the table for a reader.
struct Built {
    chain: Value,
    table: String,
}

/// Checks the request against the keys and the node, puts the keys behind the handles and
/// builds the chain twice. Nothing is written.
fn build(
    harness: &Harness,
    request: &Request,
    secrets: &Secrets,
    handles: Handles,
) -> Result<Built, String> {
    if request.network != NETWORK {
        return Err(format!(
            "the request is for network `{}`; this builder is for `{NETWORK}` only",
            request.network
        ));
    }
    let gate_network = harness.node.params.network_name();
    if gate_network != GATE_NETWORK {
        return Err(format!(
            "the node rules are those of `{gate_network}`, not of `{GATE_NETWORK}`"
        ));
    }
    if request.feerate < MIN_FEERATE {
        return Err(format!(
            "the fee rate of {} sompi per gram is below {MIN_FEERATE}",
            request.feerate
        ));
    }
    if request.coin_value == 0 {
        return Err("the coin value is 0".to_string());
    }
    let issuer_script = pay_to_public_key_script(&x_only_of(&secrets.issuer));
    if request.funding.script_public_key != issuer_script {
        return Err(format!(
            "the funding coin is not locked to the key of {ISSUER_KEY_ENV}: its script is not the \
             pay-to-public-key script of that key (a wrong key file or a wrong coin)"
        ));
    }

    keys::register_key(handles.issuer, secrets.issuer);
    keys::register_key(handles.bob, secrets.bob);
    keys::register_key(handles.alice, secrets.alice);
    assert_eq!(keys::x_only(handles.issuer), x_only_of(&secrets.issuer));
    assert_eq!(keys::x_only(handles.bob), x_only_of(&secrets.bob));
    assert_eq!(keys::x_only(handles.alice), x_only_of(&secrets.alice));

    let terms = Terms {
        harness,
        handles,
        coin_value: request.coin_value,
        feerate: request.feerate,
    };
    let run = run_once(terms, request)?;

    // Deterministic: a second build gives the same transactions, signatures included.
    let again = run_once(terms, request)?;
    for (first, second, part) in [
        (&run.steps, &again.steps, "steps"),
        (&run.probes, &again.probes, "probes"),
    ] {
        assert_eq!(
            ids_and_signature_scripts(first),
            ids_and_signature_scripts(second),
            "two builds give the same transaction ids and signature scripts ({part})"
        );
    }
    assert_eq!(run, again, "two builds give the same chain");

    let fee_rule = fee_rule_sentence(run.unsettled_steps, run.unsettled_probes);
    if run.unsettled_steps + run.unsettled_probes > 0 {
        println!(
            "the fee did not settle for {} of the 13 steps and {} of the 3 forbidden moves; \
             their fees are above the product of the fee rule",
            run.unsettled_steps, run.unsettled_probes
        );
    }
    let party = |handle: u8| {
        let key = keys::x_only(handle);
        json!({
            "x_only_public_key": hex(&key),
            "script_public_key": hex(pay_to_public_key_script(&key).script()),
        })
    };
    let chain = json!({
        "format": CHAIN_FORMAT,
        "network": NETWORK,
        "built_at_utc": utc_now(),
        "nothing_was_sent": true,
        "token_name": request.token_name,
        "coin_value": request.coin_value,
        "feerate": request.feerate,
        "fee_rule": fee_rule,
        "fee_cap_total": request.fee_cap_total,
        "funding": request.funding.json(),
        "parties": {
            "issuer": party(handles.issuer),
            "alice": party(handles.alice),
            "bob": party(handles.bob),
        },
        "covenant_id": run.covenant,
        "steps": run.steps,
        "probes": run.probes,
        "totals": run.totals,
    });
    assert_the_document_is_consistent(&chain);

    let mut table = String::new();
    let _ = writeln!(
        table,
        "KCC-20 reference token on {NETWORK}: the chain of a real run, built offline. NOTHING WAS \
         SENT."
    );
    let _ = writeln!(
        table,
        "Token name (a label, nothing on chain carries it): {}",
        request.token_name
    );
    let _ = writeln!(
        table,
        "Funding coin {}:{} of {} KAS. Every covenant coin holds {} KAS.",
        hex(&request.funding.transaction_id),
        request.funding.index,
        kas(request.funding.value),
        kas(request.coin_value)
    );
    let _ = writeln!(
        table,
        "Fee rate {} sompi per gram; {fee_rule}. Cap on all fees: {} KAS.",
        request.feerate,
        kas(request.fee_cap_total)
    );
    let _ = writeln!(
        table,
        "Every step was accepted by scripts, consensus on submission, the mempool and inside a \
         block."
    );
    let _ = writeln!(table, "Covenant id: {}", run.covenant);
    let _ = writeln!(table);
    let _ = writeln!(
        table,
        "{:<22} | what happens / coins after the step",
        "step"
    );
    let _ = writeln!(table, "{}", "-".repeat(100));
    table.push_str(&run.table);
    let _ = writeln!(table, "{}", "-".repeat(100));
    for (title, field) in [
        ("fees, all steps", "fees"),
        ("locked in covenant coins, peak", "locked_at_peak"),
        ("locked in covenant coins, end", "locked_at_the_end"),
        ("deposits returned to keys", "deposits_returned"),
        ("change of the issuer at the end", "change_at_the_end"),
    ] {
        let _ = writeln!(
            table,
            "  {title:<34} {} KAS",
            kas(run.totals[field].as_u64().expect("a total"))
        );
    }
    let _ = writeln!(
        table,
        "  {:<34} {}",
        "tokens minted", run.totals["tokens_minted"]
    );
    Ok(Built { chain, table })
}

/// The path of the table that goes with a chain file: the same name with `.txt` appended.
fn table_path(chain_path: &Path) -> PathBuf {
    let mut name = chain_path.as_os_str().to_os_string();
    name.push(".txt");
    PathBuf::from(name)
}

/// Writes a new file; an existing file is an error and is left as it is.
fn write_new(path: &Path, text: &str) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("{} cannot be created: {error}", path.display()))?;
    file.write_all(text.as_bytes())
        .map_err(|error| format!("{} cannot be written: {error}", path.display()))
}

/// Writes the chain file and its table so that a failure leaves neither of them. Both texts
/// go into temporary files with short names in the directory of the output; then the table is
/// given its name and the chain file its name, the chain file last. Neither name may be
/// taken. On any failure everything this call created is removed again, so that an error of
/// this function always means: there is no chain file.
fn write_chain_and_table(output: &Path, chain_text: &str, table_text: &str) -> Result<(), String> {
    let table = table_path(output);
    let directory = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let temporary =
        |kind: &str| directory.join(format!("launch-real-{}-{kind}.tmp", std::process::id()));
    let (chain_temporary, table_temporary) = (temporary("chain"), temporary("table"));
    // A file gets its name only when the name is free.
    let place = |from: &Path, to: &Path| -> Result<(), String> {
        if to.exists() {
            return Err(format!(
                "{} exists already; it is not overwritten",
                to.display()
            ));
        }
        fs::rename(from, to)
            .map_err(|error| format!("{} cannot be given its name: {error}", to.display()))
    };
    let mut table_in_place = false;
    let written = write_new(&chain_temporary, chain_text)
        .and_then(|()| write_new(&table_temporary, table_text))
        .and_then(|()| place(&table_temporary, &table))
        .and_then(|()| {
            table_in_place = true;
            place(&chain_temporary, output)
        });
    let Err(error) = written else {
        return Ok(());
    };
    // The chain file never got its name. Remove the rest.
    let mut left = Vec::new();
    for path in [&chain_temporary, &table_temporary] {
        if path.exists() && fs::remove_file(path).is_err() {
            left.push(path.display().to_string());
        }
    }
    if table_in_place && fs::remove_file(&table).is_err() {
        left.push(table.display().to_string());
    }
    if left.is_empty() {
        Err(error)
    } else {
        Err(format!(
            "{error}; these files of the failed attempt could not be removed: {}",
            left.join(", ")
        ))
    }
}

/// Builds the chain and writes the chain file and its table. Neither file may exist. Nothing
/// is written unless the whole chain was built, and an error means that there is no chain
/// file.
fn build_and_write(
    harness: &Harness,
    request: &Request,
    secrets: &Secrets,
    handles: Handles,
    output: &Path,
) -> Result<Built, String> {
    let table = table_path(output);
    for path in [output, table.as_path()] {
        if path.exists() {
            return Err(format!(
                "{} exists already; it is not overwritten",
                path.display()
            ));
        }
    }
    let built = build(harness, request, secrets, handles)?;
    let text = serde_json::to_string_pretty(&built.chain).expect("json") + "\n";
    write_chain_and_table(output, &text, &built.table)?;
    Ok(built)
}

/// What the main test does.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// The self-test with made-up keys.
    SelfTest,
    /// A real run from the request the environment names.
    RealRun,
    /// Nothing: the harness is in mutation mode and nobody asked for a chain.
    Nothing,
    /// A failure with this reason: a chain was asked for and cannot be built.
    Refuse(String),
}

/// Decides from the environment alone: whether the harness is in plain mode, whether
/// `KCC20_LAUNCH_INPUT` names a request, and which of the other variables of a real run are
/// set. A run that was asked for a chain never ends well without one: a variable of a real
/// run without the request is a failure, and so is a request in mutation mode.
fn decide(plain: bool, input_is_set: bool, others_set: &[&str]) -> Decision {
    match (input_is_set, plain) {
        (true, true) => Decision::RealRun,
        (true, false) => Decision::Refuse(format!(
            "{INPUT_ENV} is set, but the harness is in mutation mode (a CHECKS_* variable is \
             set): there are no node verdicts to build a chain on"
        )),
        (false, _) if !others_set.is_empty() => Decision::Refuse(format!(
            "{INPUT_ENV} is not set, but {} is: a real run needs the request file",
            others_set.join(", ")
        )),
        (false, true) => Decision::SelfTest,
        (false, false) => Decision::Nothing,
    }
}

/// A real run: the request, the keys and the output are named by the environment.
fn real_run(input: &Path) -> Result<PathBuf, String> {
    let path_of = |variable: &str| -> Result<PathBuf, String> {
        match std::env::var_os(variable) {
            Some(value) if !value.is_empty() => Ok(PathBuf::from(value)),
            _ => Err(format!("{variable} is not set")),
        }
    };
    let output = path_of(OUTPUT_ENV)?;
    let files = KeyFiles {
        issuer: path_of(ISSUER_KEY_ENV)?,
        bob: path_of(BOB_KEY_ENV)?,
        alice: path_of(ALICE_KEY_ENV)?,
    };
    let text = fs::read_to_string(input)
        .map_err(|error| format!("{INPUT_ENV}: the request cannot be read: {error}"))?;
    let request = parse_request(&text)?;
    let repository = repository();
    let secrets = load_keys(
        &files,
        Some(&Forbidden {
            repository: &repository,
            output: &output,
        }),
    )?;
    let harness = Harness::pinned();
    let built = build_and_write(&harness, &request, &secrets, REAL, &output)?;
    println!(
        "chain written to {} ({} steps, {} probes, fees {} KAS)",
        output.display(),
        built.chain["steps"].as_array().map_or(0, Vec::len),
        built.chain["probes"].as_array().map_or(0, Vec::len),
        kas(built.chain["totals"]["fees"].as_u64().unwrap_or(0)),
    );
    Ok(output)
}

// ---------------------------------------------------------------------------------------
// The self-test: made-up keys and a made-up funding coin
// ---------------------------------------------------------------------------------------

/// A made-up secret key that is not a repeated byte: BLAKE3 of a label, as hex.
fn made_up_key_hex(label: &str) -> String {
    hex(blake3::hash(format!("launch_real self-test key: {label}").as_bytes()).as_bytes())
}

/// A fresh directory under the target directory with three made-up key files.
fn made_up_key_files() -> (tempfile::TempDir, KeyFiles) {
    let parent = Path::new(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(parent).expect("the temporary directory of the target directory");
    let directory = tempfile::Builder::new()
        .prefix("launch-real-")
        .tempdir_in(parent)
        .expect("a fresh directory");
    let file = |name: &str, label: &str| -> PathBuf {
        let path = directory.path().join(name);
        // White space around the 64 characters is allowed.
        fs::write(&path, format!("{}\n", made_up_key_hex(label))).expect("a key file");
        path
    };
    let files = KeyFiles {
        issuer: file("issuer.key", "issuer"),
        bob: file("bob.key", "bob"),
        alice: file("alice.key", "alice"),
    };
    (directory, files)
}

/// A request with a made-up funding coin of 30 KAS locked to `owner`, 1 KAS covenant coins and
/// a cap of 15 KAS on the fees.
fn made_up_request(owner: &SecretKey, feerate: u64) -> Request {
    Request {
        network: NETWORK.to_string(),
        token_name: "self-test".to_string(),
        coin_value: SOMPI_PER_KAS,
        feerate,
        fee_cap_total: 15 * SOMPI_PER_KAS,
        funding: Funding {
            transaction_id: *blake3::hash(b"launch_real self-test funding coin").as_bytes(),
            index: 0,
            value: 30 * SOMPI_PER_KAS,
            script_public_key: pay_to_public_key_script(&x_only_of(owner)),
        },
    }
}

/// The self-test at one fee rate: 13 accepted steps, three refused probes at the expected
/// rules, fees within the cap. Writes the chain file and its table into the result directory.
fn self_test_at(harness: &Harness, secrets: &Secrets, feerate: u64) -> Value {
    let request = made_up_request(&secrets.issuer, feerate);
    let built = build(harness, &request, secrets, SELF_TEST)
        .unwrap_or_else(|error| panic!("the self-test at fee rate {feerate} fails: {error}"));
    let chain = &built.chain;

    let steps = chain["steps"].as_array().expect("steps");
    assert_eq!(steps.len(), 13);
    let mut fees = 0u64;
    println!("self-test, fee rate {feerate} sompi per gram");
    for step in steps {
        assert_eq!(step["expect"], "accepted");
        assert_eq!(step["version"], 1, "a covenant transaction is version 1");
        for check in ["scripts", "consensus", "mempool", "block"] {
            assert_eq!(step["gate"][check], true, "{}: {check}", step["name"]);
        }
        assert!(step["gate"]["refusal"].is_null());
        let fee = step["fee"].as_u64().expect("a fee");
        let floor = step["fee_floor"].as_u64().expect("a floor");
        let fee_mass = step["masses"]["fee_mass"].as_u64().expect("a fee mass");
        let storage = step["masses"]["calculated_storage_mass"]
            .as_u64()
            .expect("a storage mass");
        assert_eq!(fee, feerate * fee_mass.max(storage), "{}", step["name"]);
        assert!(fee >= floor);
        assert_eq!(step["mass"], storage);
        fees += fee;
        println!(
            "  {:<24} fee {:>10} sompi  floor {:>9}  fee mass {:>6}  storage mass {:>6}  \
             compute mass {:>6}  transient mass {:>6}",
            step["name"].as_str().unwrap_or("?"),
            fee,
            floor,
            fee_mass,
            storage,
            step["masses"]["compute_mass"],
            step["masses"]["transient_mass"],
        );
    }
    assert_eq!(chain["totals"]["fees"], fees);
    assert!(fees <= request.fee_cap_total, "the fees are within the cap");
    assert_eq!(chain["totals"]["tokens_minted"], SUPPLY);
    // Every fee of the self-test settled, and the fee rule of the file says so.
    assert_eq!(chain["fee_rule"], fee_rule_sentence(0, 0));
    println!("  totals: {}", chain["totals"]);

    let probes = chain["probes"].as_array().expect("probes");
    let expected = [
        ("B1 transfer without the owner's signature", "K-38"),
        ("B2 more tokens out than in", "K-37"),
        (
            "B3 the seed creates a coin that already holds tokens",
            "S-12",
        ),
    ];
    assert_eq!(probes.len(), expected.len());
    let last_step = steps[12]["name"].as_str().expect("a name");
    for (probe, (name, rule)) in probes.iter().zip(expected) {
        assert_eq!(probe["name"], name);
        assert_eq!(probe["expect"], "refused");
        for check in ["scripts", "consensus", "mempool", "block"] {
            assert_eq!(probe["gate"][check], false, "{name}: {check}");
        }
        let refusal = &probe["gate"]["refusal"];
        assert_eq!(refusal["layer"], "scripts");
        assert_eq!(refusal["input"], 0);
        assert_eq!(refusal["rule"], rule);
        // The second input of every probe is the issuer's change of the last step.
        let inputs = probe["inputs"].as_array().expect("inputs");
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[1]["spends"]["from"]["step"], last_step);
        println!(
            "  {name}: layer {}, input {}, rule {}, message {}; fee {} sompi",
            refusal["layer"], refusal["input"], refusal["rule"], refusal["message"], probe["fee"]
        );
    }

    // No secret key in the file or in the table.
    let text = serde_json::to_string_pretty(chain).expect("json") + "\n";
    for label in ["issuer", "bob", "alice"] {
        assert!(!text.contains(&made_up_key_hex(label)));
        assert!(!built.table.contains(&made_up_key_hex(label)));
    }
    assert!(!text.contains('\r'));

    let directory = checks::results::results_dir();
    fs::create_dir_all(&directory).expect("the result directory");
    let path = directory.join(format!("launch-real-selftest-{feerate}.chain.json"));
    fs::write(&path, text).expect("the chain file of the self-test");
    fs::write(table_path(&path), &built.table).expect("the table of the self-test");
    built.chain
}

fn self_test() {
    let harness = Harness::pinned();
    let (_directory, files) = made_up_key_files();
    let secrets = load_keys(&files, None).expect("the made-up keys");
    let high = self_test_at(&harness, &secrets, 955);
    let low = self_test_at(&harness, &secrets, 100);
    // The fee rate changes the change outputs and with them every transaction id. The covenant
    // id is derived from the funding outpoint and the two covenant outputs of the launch, so
    // it is the same at both fee rates.
    assert_eq!(high["covenant_id"], low["covenant_id"]);
    assert_ne!(
        high["steps"][0]["transaction_id"],
        low["steps"][0]["transaction_id"]
    );
    assert_eq!(high["parties"], low["parties"]);
    assert!(high["totals"]["fees"].as_u64() > low["totals"]["fees"].as_u64());
}

// ---------------------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------------------

/// The chain of a real run when the environment names a request, otherwise the self-test.
#[test]
fn the_chain_is_built_and_judged_by_the_node_rules() {
    // The chain is of the pinned contracts as a node judges them. In the mutation mode of the
    // harness there is no fee floor and no node verdict to build a chain on: without any
    // variable of a real run the test returns at once, with one it fails.
    let set = |variable: &str| std::env::var_os(variable).filter(|value| !value.is_empty());
    let others_set: Vec<&str> = [OUTPUT_ENV, ISSUER_KEY_ENV, BOB_KEY_ENV, ALICE_KEY_ENV]
        .into_iter()
        .filter(|variable| set(variable).is_some())
        .collect();
    let input = set(INPUT_ENV);
    let plain = checks::mutation::mode().is_plain();
    match decide(plain, input.is_some(), &others_set) {
        Decision::Nothing => {}
        Decision::SelfTest => self_test(),
        Decision::RealRun => {
            let input = input.expect("the decision is a real run");
            if let Err(error) = real_run(Path::new(&input)) {
                panic!("no chain was written: {error}");
            }
        }
        Decision::Refuse(reason) => panic!("no chain was written: {reason}"),
    }
}

#[test]
fn a_run_that_was_asked_for_a_chain_never_ends_well_without_one() {
    let keys = [ISSUER_KEY_ENV, BOB_KEY_ENV, ALICE_KEY_ENV];
    // Nothing of a real run in the environment: the self-test, or nothing in mutation mode.
    assert_eq!(decide(true, false, &[]), Decision::SelfTest);
    assert_eq!(decide(false, false, &[]), Decision::Nothing);
    // The request in plain mode: a real run, whatever else is set (a missing variable is an
    // error of the run itself).
    assert_eq!(decide(true, true, &[]), Decision::RealRun);
    assert_eq!(decide(true, true, &[OUTPUT_ENV]), Decision::RealRun);
    // A variable of a real run without the request: a failure in both modes, never the
    // self-test and never a silent return.
    for others in [
        &[OUTPUT_ENV][..],
        &keys[..1],
        &keys[1..2],
        &keys[2..],
        &keys[..],
    ] {
        for plain in [true, false] {
            let Decision::Refuse(reason) = decide(plain, false, others) else {
                panic!("{others:?} without the request is not refused (plain mode: {plain})");
            };
            assert!(
                reason.starts_with("KCC20_LAUNCH_INPUT is not set"),
                "{reason}"
            );
            assert!(reason.contains(others[0]), "{reason}");
        }
    }
    // The request in mutation mode: a failure, not a silent return.
    for others in [&[][..], &[OUTPUT_ENV][..], &keys[..]] {
        let Decision::Refuse(reason) = decide(false, true, others) else {
            panic!("a request in mutation mode is not refused");
        };
        assert!(reason.contains("mutation mode"), "{reason}");
    }
}

#[test]
fn a_failed_write_leaves_neither_the_chain_file_nor_the_table() {
    let parent = Path::new(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(parent).expect("the temporary directory of the target directory");
    let directory = tempfile::Builder::new()
        .prefix("launch-real-write-")
        .tempdir_in(parent)
        .expect("a fresh directory");
    let names_in_the_directory = || -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(directory.path())
            .expect("the directory")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    };

    // A name of 252 characters: the chain file can have it, its table (four characters more)
    // cannot. The table fails, so the chain file must not appear either.
    let long = directory.path().join("c".repeat(252));
    let error = write_chain_and_table(&long, "{}\n", "a table\n")
        .expect_err("a table name that is too long is an error");
    assert!(error.contains("cannot be given its name"), "{error}");
    assert!(!long.exists(), "no chain file");
    assert!(!table_path(&long).exists(), "no table");
    assert_eq!(
        names_in_the_directory(),
        Vec::<String>::new(),
        "nothing is left"
    );

    // A table in the way: no chain file, and the table is left as it was.
    let output = directory.path().join("run.chain.json");
    fs::write(table_path(&output), "kept").expect("a table in the way");
    let error = write_chain_and_table(&output, "{}\n", "a table\n")
        .expect_err("a table in the way is an error");
    assert!(error.contains("exists already"), "{error}");
    assert!(!output.exists(), "no chain file");
    assert_eq!(
        fs::read_to_string(table_path(&output)).expect("the table"),
        "kept"
    );
    assert_eq!(names_in_the_directory(), ["run.chain.json.txt"]);

    // A chain file in the way: it is left as it was, and no table appears next to it.
    let taken = directory.path().join("taken.chain.json");
    fs::write(&taken, "kept").expect("a chain file in the way");
    let error = write_chain_and_table(&taken, "{}\n", "a table\n")
        .expect_err("a chain file in the way is an error");
    assert!(error.contains("exists already"), "{error}");
    assert_eq!(fs::read_to_string(&taken).expect("the chain file"), "kept");
    assert!(
        !table_path(&taken).exists(),
        "no table next to a chain file in the way"
    );

    // Both names free: both files, with their texts, and no temporary file.
    let free = directory.path().join("free.chain.json");
    write_chain_and_table(&free, "{}\n", "a table\n").expect("both names are free");
    assert_eq!(fs::read_to_string(&free).expect("the chain file"), "{}\n");
    assert_eq!(
        fs::read_to_string(table_path(&free)).expect("the table"),
        "a table\n"
    );
    assert_eq!(
        names_in_the_directory(),
        [
            "free.chain.json",
            "free.chain.json.txt",
            "run.chain.json.txt",
            "taken.chain.json"
        ]
    );
}

#[test]
fn a_funding_coin_of_another_key_is_refused() {
    if !checks::mutation::mode().is_plain() {
        return;
    }
    let harness = Harness::pinned();
    let (_directory, files) = made_up_key_files();
    let secrets = load_keys(&files, None).expect("the made-up keys");
    // The coin is locked to Bob's key, not to the issuer's.
    let request = made_up_request(&secrets.bob, 955);
    let error = build(&harness, &request, &secrets, SELF_TEST)
        .err()
        .expect("a coin of another key is refused");
    assert!(error.contains("funding coin is not locked"), "{error}");
    assert!(error.contains(ISSUER_KEY_ENV), "{error}");
}

#[test]
fn a_request_for_another_network_or_below_the_smallest_fee_rate_is_refused() {
    if !checks::mutation::mode().is_plain() {
        return;
    }
    let harness = Harness::pinned();
    let (_directory, files) = made_up_key_files();
    let secrets = load_keys(&files, None).expect("the made-up keys");
    let mut request = made_up_request(&secrets.issuer, 955);
    request.network = "mainnet".to_string();
    let error = build(&harness, &request, &secrets, SELF_TEST)
        .err()
        .expect("another network is refused");
    assert!(error.contains("network"), "{error}");

    let request = made_up_request(&secrets.issuer, 99);
    let error = build(&harness, &request, &secrets, SELF_TEST)
        .err()
        .expect("a fee rate below 100 is refused");
    assert!(error.contains("fee rate"), "{error}");

    let request = made_up_request(&secrets.issuer, 955);
    let mainnet = Harness::pinned().with_node(node_gate::params::GateParams::mainnet());
    let error = build(&mainnet, &request, &secrets, SELF_TEST)
        .err()
        .expect("node rules of another network are refused");
    assert!(error.contains("node rules"), "{error}");
}

#[test]
fn two_equal_keys_are_refused() {
    if !checks::mutation::mode().is_plain() {
        return;
    }
    let (_directory, files) = made_up_key_files();
    fs::copy(&files.issuer, &files.bob).expect("the issuer's key as Bob's");
    let error = load_keys(&files, None)
        .err()
        .expect("two equal keys are refused");
    assert!(error.contains("the same key"), "{error}");
    assert!(error.contains(ISSUER_KEY_ENV) && error.contains(BOB_KEY_ENV));
    assert!(!error.contains(&made_up_key_hex("issuer")));
}

#[test]
fn a_cap_below_the_fees_is_an_error_and_no_file_is_written() {
    if !checks::mutation::mode().is_plain() {
        return;
    }
    let harness = Harness::pinned();
    let (directory, files) = made_up_key_files();
    let secrets = load_keys(&files, None).expect("the made-up keys");
    // 2 KAS covers the first two steps at this fee rate and not the third.
    let mut request = made_up_request(&secrets.issuer, 955);
    request.fee_cap_total = 2 * SOMPI_PER_KAS;
    let output = directory.path().join("capped.chain.json");
    let error = build_and_write(&harness, &request, &secrets, SELF_TEST, &output)
        .err()
        .expect("fees above the cap are refused");
    assert!(error.contains("above the cap"), "{error}");
    assert!(error.starts_with("03 transfer"), "{error}");
    assert!(!output.exists(), "no chain file");
    assert!(!table_path(&output).exists(), "no table");

    // The cap is a bound on the sum: one sompi below the fees of the 13 steps stops the last
    // step, a cap equal to them does not.
    let uncapped = made_up_request(&secrets.issuer, 955);
    let fees = build(&harness, &uncapped, &secrets, SELF_TEST)
        .expect("the run under the cap")
        .chain["totals"]["fees"]
        .as_u64()
        .expect("the fees");
    request.fee_cap_total = fees - 1;
    let error = build_and_write(&harness, &request, &secrets, SELF_TEST, &output)
        .err()
        .expect("fees one sompi above the cap are refused");
    assert!(error.contains("above the cap"), "{error}");
    assert!(error.starts_with("13 seed reclaim"), "{error}");
    assert!(!output.exists(), "no chain file");
    request.fee_cap_total = fees;
    let built = build_and_write(&harness, &request, &secrets, SELF_TEST, &output)
        .expect("fees equal to the cap pass");
    assert_eq!(built.chain["totals"]["fees"], fees);
    let written = fs::read_to_string(&output).expect("the chain file");
    let read_back: Value = serde_json::from_str(&written).expect("the chain file is JSON");
    assert_eq!(
        read_back, built.chain,
        "the file holds the chain that was built"
    );
    assert!(written.ends_with("}\n") && !written.contains('\r'));
    assert!(
        table_path(&output).exists(),
        "the table next to the chain file"
    );

    // An output that exists already is not overwritten, whatever the request.
    fs::write(&output, "kept").expect("a file in the way");
    let error = build_and_write(&harness, &uncapped, &secrets, SELF_TEST, &output)
        .err()
        .expect("an existing output is refused");
    assert!(error.contains("exists already"), "{error}");
    assert_eq!(fs::read_to_string(&output).expect("the file"), "kept");

    // Neither is a table that exists already.
    let other = directory.path().join("other.chain.json");
    fs::write(table_path(&other), "kept").expect("a table in the way");
    let error = build_and_write(&harness, &uncapped, &secrets, SELF_TEST, &other)
        .err()
        .expect("an existing table is refused");
    assert!(error.contains("exists already"), "{error}");
    assert!(
        !other.exists(),
        "no chain file next to a table that was in the way"
    );
}

#[test]
fn a_bad_key_file_gives_an_error_without_its_content() {
    if !checks::mutation::mode().is_plain() {
        return;
    }
    let (directory, mut files) = made_up_key_files();
    let cases = [
        // Not hex at all.
        "this-is-not-a-key-GARBAGE-zzzz".to_string(),
        // Hex of the wrong length.
        "0123456789abcdefFEDCBA98".to_string(),
        // 64 hex characters that are no valid secret key.
        "0".repeat(64),
        // A valid key followed by more text.
        format!("{} trailing-GARBAGE", made_up_key_hex("issuer")),
    ];
    for (index, garbage) in cases.iter().enumerate() {
        let path = directory.path().join(format!("bad-{index}.key"));
        fs::write(&path, garbage).expect("a bad key file");
        files.alice = path;
        let error = load_keys(&files, None)
            .err()
            .expect("a bad key file is refused");
        assert!(error.contains(ALICE_KEY_ENV), "{error}");
        assert!(!error.contains(garbage.as_str()), "{error}");
        for word in [
            "GARBAGE",
            "0123456789abcdef",
            "0000",
            &made_up_key_hex("issuer"),
        ] {
            assert!(!error.contains(word), "{error}");
        }
    }
    files.alice = directory.path().join("missing.key");
    let error = load_keys(&files, None)
        .err()
        .expect("a missing key file is refused");
    assert!(error.contains(ALICE_KEY_ENV), "{error}");
}

#[test]
fn a_real_run_takes_no_key_file_from_the_repository_or_from_the_output_path() {
    if !checks::mutation::mode().is_plain() {
        return;
    }
    // The made-up key files lie under the target directory, inside the repository.
    let (directory, files) = made_up_key_files();
    let repository = repository();
    let elsewhere = std::env::temp_dir().join("launch-real-no-such-directory");
    let error = load_keys(
        &files,
        Some(&Forbidden {
            repository: &repository,
            output: &elsewhere.join("chain.json"),
        }),
    )
    .err()
    .expect("a key file inside the repository is refused");
    assert!(error.contains("inside the repository"), "{error}");
    assert!(error.contains(ISSUER_KEY_ENV), "{error}");

    // With another directory as "the repository" the same files pass, unless one of them is
    // where the chain or its table is to be written.
    let other = resolved(&elsewhere);
    let error = load_keys(
        &files,
        Some(&Forbidden {
            repository: &other,
            output: &files.bob,
        }),
    )
    .err()
    .expect("a key file at the path of the chain file is refused");
    assert!(error.contains("is to be written to"), "{error}");
    assert!(error.contains(BOB_KEY_ENV), "{error}");

    let chain = directory.path().join("alice.chain.json");
    let at_the_table = KeyFiles {
        issuer: files.issuer.clone(),
        bob: files.bob.clone(),
        alice: table_path(&chain),
    };
    fs::copy(&files.alice, &at_the_table.alice).expect("Alice's key at the path of the table");
    let error = load_keys(
        &at_the_table,
        Some(&Forbidden {
            repository: &other,
            output: &chain,
        }),
    )
    .err()
    .expect("a key file at the path of the table is refused");
    assert!(error.contains(ALICE_KEY_ENV), "{error}");

    load_keys(
        &files,
        Some(&Forbidden {
            repository: &other,
            output: &directory.path().join("chain.json"),
        }),
    )
    .map(|_| ())
    .expect("key files outside the repository and away from the output pass");
}

#[test]
fn a_request_is_read_as_the_format_describes_it() {
    if !checks::mutation::mode().is_plain() {
        return;
    }
    let text = r#"{
        "format": "kcc20-launch-request/1",
        "network": "testnet-10",
        "read_at_utc": "2026-10-11T12:00:00Z",
        "node": "wss://example.invalid",
        "token_name": "a label",
        "coin_value": 100000000,
        "feerate": 955,
        "fee_cap_total": 1500000000,
        "funding": {
            "transaction_id": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "index": 2,
            "value": 3000000000,
            "script_public_key_version": 0,
            "script_public_key": "20aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"
        }
    }"#;
    let request = parse_request(text).expect("a request of the format");
    assert_eq!(request.network, "testnet-10");
    assert_eq!(request.token_name, "a label");
    assert_eq!(request.coin_value, SOMPI_PER_KAS);
    assert_eq!(request.feerate, 955);
    assert_eq!(request.fee_cap_total, 15 * SOMPI_PER_KAS);
    assert_eq!(request.funding.index, 2);
    assert_eq!(request.funding.value, 30 * SOMPI_PER_KAS);
    assert_eq!(request.funding.transaction_id[..2], [0x00, 0x11]);
    assert_eq!(request.funding.script_public_key.script().len(), 34);
    let funding = request.funding.json();
    assert_eq!(funding["owner"], "issuer");
    assert_eq!(
        funding["transaction_id"],
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    );

    let other_format = text.replace("kcc20-launch-request/1", "kcc20-launch-request/2");
    assert!(parse_request(&other_format).is_err());
    let no_cap = text.replace("fee_cap_total", "fee_cap");
    assert!(parse_request(&no_cap).is_err());
    let odd_hex = text.replace("\"20aaaa", "\"0aaaa");
    assert!(parse_request(&odd_hex).is_err());

    // The clock text has the form of the format.
    let now = utc_now();
    assert_eq!(now.len(), 20, "{now}");
    assert!(now.ends_with('Z') && now.as_bytes()[10] == b'T', "{now}");
}
