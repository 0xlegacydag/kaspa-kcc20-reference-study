//! A declarative description of one transaction and its assembly.
//!
//! A [`Scenario`] is plain data: the coins being spent, what each of them is asked to do,
//! the outputs, and the transaction fields. [`Scenario::assemble`] turns it into a
//! `Transaction` and the list of spent coins. The assembler validates NOTHING: it never asks
//! whether the coin's script matches the redeem script pushed, whether the declared states
//! equal the locked ones, whether there are too many inputs, or whether a signature is good.
//! Any of these can be made wrong on purpose and the transaction still comes out.
//!
//! Order of assembly:
//!
//! 1. coins and inputs with empty signature scripts, outputs, transaction fields;
//! 2. the unsigned transaction is shown to every closure of the scenario (this is where
//!    signatures are made: all outputs exist already);
//! 3. signature scripts are written and the transaction id is recomputed.
//!
//! The same scenario can be assembled against different families (for example one with a
//! replaced bytecode): scripts and hashes are taken from the family at assembly time.

use std::fmt;
use std::sync::Arc;

use argent::codec::ArtifactValue;
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::mass::ComputeBudget;
use kaspa_consensus_core::subnets::SubnetworkId;
use kaspa_consensus_core::tx::{
    ComputeCommit, CovenantBinding, MutableTransaction, PopulatedTransaction, ScriptPublicKey,
    Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::pay_to_script_hash_script;

use crate::error::{Error, Result};
use crate::family::{Contract, Entry, EntryRole, Family};
use crate::keys::SigningContext;
use crate::raw::{self, CallParts};
use crate::states::{Kcc20State, State, kcc20_state_value, kcc20_states_value};

/// Transaction version of every scenario unless changed: the first version with covenants
/// (rusty-kaspa a41a333 consensus/core/src/constants.rs:20, `TX_VERSION_TOCCATA`).
pub const DEFAULT_TX_VERSION: u16 = 1;

/// DAA score written into every spent coin unless changed, as the reference's examples do
/// (kcc20-reference c8a0871 src/bin/kcc20/tests.rs:321-327).
pub const DEFAULT_COIN_DAA_SCORE: u64 = 1;

/// A closure that computes bytes from the finished, unsigned transaction.
pub type TxFn = Arc<dyn Fn(&SigningContext<'_>) -> Vec<u8> + Send + Sync>;

/// A closure that computes one argument, as a codec value, from the finished, unsigned
/// transaction.
pub type ValueFn = Arc<dyn Fn(&SigningContext<'_>) -> ArtifactValue + Send + Sync>;

/// A closure that changes the parts of a signature script just before they are joined.
pub type PartsPatch = Arc<dyn Fn(&mut CallParts) + Send + Sync>;

/// Bytes that are either known now or computed from the finished transaction. The second
/// form is how signatures enter a scenario: with any key, scheme and signature hash type.
#[derive(Clone)]
pub enum LateBytes {
    /// Bytes known when the scenario is written.
    Fixed(Vec<u8>),
    /// Bytes computed when the scenario is assembled, after all inputs and outputs exist.
    FromTx(TxFn),
}

impl LateBytes {
    /// Bytes known in advance.
    pub fn fixed(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Fixed(bytes.into())
    }

    /// No bytes at all.
    pub fn empty() -> Self {
        Self::Fixed(Vec::new())
    }

    /// Bytes computed from the unsigned transaction and the index of the input.
    pub fn from_tx(f: impl Fn(&SigningContext<'_>) -> Vec<u8> + Send + Sync + 'static) -> Self {
        Self::FromTx(Arc::new(f))
    }

    /// The bytes for the given transaction and input.
    pub fn resolve(&self, ctx: &SigningContext<'_>) -> Vec<u8> {
        match self {
            Self::Fixed(bytes) => bytes.clone(),
            Self::FromTx(f) => f(ctx),
        }
    }

    /// The same bytes passed through `f` afterwards: the way to damage a real signature
    /// (flip a bit, cut a byte, replace the type byte) without re-implementing it.
    pub fn map(self, f: impl Fn(Vec<u8>) -> Vec<u8> + Send + Sync + 'static) -> Self {
        Self::from_tx(move |ctx| f(self.resolve(ctx)))
    }
}

impl fmt::Debug for LateBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fixed(bytes) => write!(f, "Fixed({} bytes)", bytes.len()),
            Self::FromTx(_) => f.write_str("FromTx(..)"),
        }
    }
}

impl From<Vec<u8>> for LateBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Fixed(bytes)
    }
}

/// One user argument of a typed call.
#[derive(Clone)]
pub enum Arg {
    /// Any codec value.
    Value(ArtifactValue),
    /// A `byte[]`, `sig` or `pubkey` argument, possibly computed from the transaction
    /// (a witness, a signature).
    Bytes(LateBytes),
    /// A `KCC20State` argument: the recipient state DECLARED to `mint` or `create`.
    State(Kcc20State),
    /// A `KCC20State[]` argument: the next states DECLARED to `transfer`.
    States(Vec<Kcc20State>),
    /// Any codec value computed from the finished transaction.
    Computed(ValueFn),
}

impl Arg {
    /// An `int` argument.
    pub fn int(value: i64) -> Self {
        Self::Value(ArtifactValue::Int(value))
    }

    /// A `byte[]`, `pubkey` or `sig` argument known in advance.
    pub fn bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(LateBytes::fixed(bytes))
    }

    /// The codec value of the argument for the given transaction and input.
    pub fn resolve(&self, ctx: &SigningContext<'_>) -> ArtifactValue {
        match self {
            Self::Value(value) => value.clone(),
            Self::Bytes(bytes) => ArtifactValue::Bytes(bytes.resolve(ctx)),
            Self::State(state) => kcc20_state_value(state),
            Self::States(states) => kcc20_states_value(states),
            Self::Computed(f) => f(ctx),
        }
    }
}

impl fmt::Debug for Arg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(value) => f.debug_tuple("Value").field(value).finish(),
            Self::Bytes(bytes) => f.debug_tuple("Bytes").field(bytes).finish(),
            Self::State(state) => f.debug_tuple("State").field(state).finish(),
            Self::States(states) => f.debug_tuple("States").field(states).finish(),
            Self::Computed(_) => f.write_str("Computed(..)"),
        }
    }
}

/// What a contract input is asked to do.
#[derive(Clone, Debug)]
pub enum Call {
    /// An entry with its user arguments. The codec encodes them, the family appends the
    /// hidden arguments and the dispatch tag. The entry need not belong to the contract of
    /// the coin: the tag and the argument layout are taken from the entry's own contract.
    Typed { entry: Entry, args: Vec<Arg> },
    /// The bytes in front of the redeem push, given as they are (argument pushes and tag
    /// push, or anything else).
    Raw(LateBytes),
}

impl Call {
    /// A typed call.
    pub fn typed(entry: Entry, args: Vec<Arg>) -> Self {
        Self::Typed { entry, args }
    }

    /// The entry of a typed call.
    pub fn entry(&self) -> Option<Entry> {
        match self {
            Self::Typed { entry, .. } => Some(*entry),
            Self::Raw(_) => None,
        }
    }
}

/// A coin locked to one of the three contracts, and the call that spends it.
#[derive(Clone)]
pub struct ContractInput {
    /// Free text for reports ("leader: Bob, threshold borrow").
    pub label: String,
    /// The state the coin is said to hold. It decides the contract, the default redeem
    /// script and the default script public key.
    pub state: State,
    /// Value of the coin in sompi.
    pub value: u64,
    /// Covenant id carried by the coin, or none.
    pub covenant_id: Option<Hash>,
    /// Outpoint of the coin.
    pub outpoint: TransactionOutpoint,
    /// The entry called and its arguments.
    pub call: Call,
    /// Sequence number of the input.
    pub sequence: u64,
    /// Compute commitment of the input: a compute budget of 0 unless changed.
    pub compute_commit: ComputeCommit,
    /// DAA score of the block that created the coin.
    pub block_daa_score: u64,
    /// Whether the coin comes from a coinbase transaction.
    pub is_coinbase: bool,
    /// Override: a change applied to the parts of the signature script (arguments, tag,
    /// redeem push) just before they are joined.
    pub patch: Option<PartsPatch>,
    /// Override: the redeem script actually pushed, instead of the one of `state`.
    pub pushed_redeem: Option<Vec<u8>>,
    /// Override: the script public key actually locking the coin, instead of
    /// pay-to-script-hash of the redeem script of `state`.
    pub locking_script: Option<ScriptPublicKey>,
    /// Override: the whole signature script. `call`, `patch` and `pushed_redeem` are then
    /// not used.
    pub signature_script: Option<LateBytes>,
}

impl ContractInput {
    /// A coin with the given state and call; sequence 0, compute budget 0, DAA score 1, not a
    /// coinbase coin, no overrides.
    pub fn new(
        state: impl Into<State>,
        value: u64,
        covenant_id: Option<Hash>,
        outpoint: TransactionOutpoint,
        call: Call,
    ) -> Self {
        Self {
            label: String::new(),
            state: state.into(),
            value,
            covenant_id,
            outpoint,
            call,
            sequence: 0,
            compute_commit: ComputeBudget(0).into(),
            block_daa_score: DEFAULT_COIN_DAA_SCORE,
            is_coinbase: false,
            patch: None,
            pushed_redeem: None,
            locking_script: None,
            signature_script: None,
        }
    }

    /// The same input with a label for reports.
    pub fn labelled(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// The contract of the coin.
    pub fn contract(&self) -> Contract {
        self.state.contract()
    }

    /// Sets the parts patch. See [`ContractInput::patch`].
    pub fn set_patch(&mut self, patch: impl Fn(&mut CallParts) + Send + Sync + 'static) {
        self.patch = Some(Arc::new(patch));
    }

    /// The user arguments of a typed call.
    ///
    /// # Panics
    ///
    /// Panics when the call is raw.
    pub fn args_mut(&mut self) -> &mut Vec<Arg> {
        match &mut self.call {
            Call::Typed { args, .. } => args,
            Call::Raw(_) => {
                panic!("the call of this input is raw bytes, it has no typed arguments")
            }
        }
    }

    /// The states DECLARED to `transfer` (the first `KCC20State[]` argument).
    ///
    /// # Panics
    ///
    /// Panics when the call has no such argument.
    pub fn declared_states_mut(&mut self) -> &mut Vec<Kcc20State> {
        self.args_mut()
            .iter_mut()
            .find_map(|arg| match arg {
                Arg::States(states) => Some(states),
                _ => None,
            })
            .expect("the call has no KCC20State[] argument")
    }

    /// The recipient state DECLARED to `mint` or `create` (the first `KCC20State` argument).
    ///
    /// # Panics
    ///
    /// Panics when the call has no such argument.
    pub fn declared_state_mut(&mut self) -> &mut Kcc20State {
        self.args_mut()
            .iter_mut()
            .find_map(|arg| match arg {
                Arg::State(state) => Some(state),
                _ => None,
            })
            .expect("the call has no KCC20State argument")
    }

    /// The argument that authorizes the spend: the witness of `transfer` and
    /// `transfer_delegator`, the owner signature of `PublicMint.reclaim` and of the two
    /// `reclaim_delegator` entries. It is the last bytes argument of those calls.
    ///
    /// # Panics
    ///
    /// Panics when the call is raw, when it names an entry that takes neither a witness nor
    /// a signature (`mint`, `create`, the two `split` entries, `reclaim_into`,
    /// `TokenSeed.reclaim`), or when it has no bytes argument. The public key of a `split`
    /// is not a witness; see [`ContractInput::new_owner_mut`].
    pub fn witness_mut(&mut self) -> &mut LateBytes {
        match self.call.entry() {
            Some(
                Entry::Transfer
                | Entry::TransferDelegator
                | Entry::MintReclaim
                | Entry::MintReclaimDelegator
                | Entry::SeedReclaimDelegator,
            )
            | None => {}
            Some(entry) => panic!("`{entry}` takes neither a witness nor a signature"),
        }
        self.last_bytes_arg_mut()
    }

    /// The `new_owner` public key of `PublicMint.split` and `TokenSeed.split`: the last bytes
    /// argument of those calls.
    ///
    /// # Panics
    ///
    /// Panics when the call is raw, when it names another entry, or when it has no bytes
    /// argument.
    pub fn new_owner_mut(&mut self) -> &mut LateBytes {
        match self.call.entry() {
            Some(Entry::MintSplit | Entry::SeedSplit) | None => {}
            Some(entry) => panic!("`{entry}` has no `new_owner` argument"),
        }
        self.last_bytes_arg_mut()
    }

    /// The last bytes argument of a typed call.
    fn last_bytes_arg_mut(&mut self) -> &mut LateBytes {
        self.args_mut()
            .iter_mut()
            .rev()
            .find_map(|arg| match arg {
                Arg::Bytes(bytes) => Some(bytes),
                _ => None,
            })
            .expect("the call has no bytes argument")
    }
}

impl fmt::Debug for ContractInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContractInput")
            .field("label", &self.label)
            .field("state", &self.state)
            .field("value", &self.value)
            .field("covenant_id", &self.covenant_id)
            .field("outpoint", &self.outpoint)
            .field("call", &self.call)
            .field("sequence", &self.sequence)
            .field("compute_commit", &self.compute_commit)
            .field("block_daa_score", &self.block_daa_score)
            .field("is_coinbase", &self.is_coinbase)
            .field("patch", &self.patch.as_ref().map(|_| ".."))
            .field("pushed_redeem", &self.pushed_redeem.as_ref().map(Vec::len))
            .field("locking_script", &self.locking_script)
            .field("signature_script", &self.signature_script)
            .finish()
    }
}

/// A coin that is not locked to one of the three contracts: a funding coin, an authority of
/// the pay-to-script-hash owner scheme, any other script.
#[derive(Clone, Debug)]
pub struct OrdinaryInput {
    /// Free text for reports.
    pub label: String,
    /// The script public key locking the coin.
    pub script_public_key: ScriptPublicKey,
    /// Value of the coin in sompi.
    pub value: u64,
    /// Covenant id carried by the coin, or none.
    pub covenant_id: Option<Hash>,
    /// Outpoint of the coin.
    pub outpoint: TransactionOutpoint,
    /// The signature script, fixed or computed from the finished transaction.
    pub signature_script: LateBytes,
    /// Sequence number of the input.
    pub sequence: u64,
    /// Compute commitment of the input: a compute budget of 0 unless changed.
    pub compute_commit: ComputeCommit,
    /// DAA score of the block that created the coin.
    pub block_daa_score: u64,
    /// Whether the coin comes from a coinbase transaction.
    pub is_coinbase: bool,
}

impl OrdinaryInput {
    /// A coin with the given script and signature script; no covenant id, sequence 0, compute
    /// budget 0, DAA score 1, not a coinbase coin.
    pub fn new(
        script_public_key: ScriptPublicKey,
        value: u64,
        outpoint: TransactionOutpoint,
        signature_script: LateBytes,
    ) -> Self {
        Self {
            label: String::new(),
            script_public_key,
            value,
            covenant_id: None,
            outpoint,
            signature_script,
            sequence: 0,
            compute_commit: ComputeBudget(0).into(),
            block_daa_score: DEFAULT_COIN_DAA_SCORE,
            is_coinbase: false,
        }
    }

    /// The same input with a label for reports.
    pub fn labelled(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// The same input with a covenant id on its coin.
    pub fn with_covenant_id(mut self, covenant_id: Hash) -> Self {
        self.covenant_id = Some(covenant_id);
        self
    }
}

/// One input of a scenario.
#[derive(Clone, Debug)]
pub enum InputSpec {
    Contract(ContractInput),
    Ordinary(OrdinaryInput),
}

impl InputSpec {
    /// Value of the spent coin in sompi.
    pub fn value(&self) -> u64 {
        match self {
            Self::Contract(input) => input.value,
            Self::Ordinary(input) => input.value,
        }
    }
}

/// An output locked to one of the three contracts.
///
/// The state here is the state actually LOCKED into the output. The state DECLARED to the
/// entry lives in the arguments of the call and is independent of it.
#[derive(Clone, Debug)]
pub struct ContractOutput {
    /// The state locked into the output.
    pub state: State,
    /// Value of the output in sompi.
    pub value: u64,
    /// The covenant binding of the output, or none.
    pub binding: Option<CovenantBinding>,
    /// Override: the script public key actually written, instead of pay-to-script-hash of
    /// the redeem script of `state`.
    pub locking_script: Option<ScriptPublicKey>,
}

impl ContractOutput {
    /// An output with the given state, value and binding.
    pub fn new(state: impl Into<State>, value: u64, binding: Option<CovenantBinding>) -> Self {
        Self {
            state: state.into(),
            value,
            binding,
            locking_script: None,
        }
    }
}

/// An output with a script given as it is.
#[derive(Clone, Debug)]
pub struct PlainOutput {
    /// The script public key of the output.
    pub script_public_key: ScriptPublicKey,
    /// Value of the output in sompi.
    pub value: u64,
    /// The covenant binding of the output, or none.
    pub binding: Option<CovenantBinding>,
}

impl PlainOutput {
    /// An output without a covenant binding.
    pub fn new(script_public_key: ScriptPublicKey, value: u64) -> Self {
        Self {
            script_public_key,
            value,
            binding: None,
        }
    }
}

/// One output of a scenario.
#[derive(Clone, Debug)]
pub enum OutputSpec {
    Contract(ContractOutput),
    Plain(PlainOutput),
}

impl OutputSpec {
    /// Value of the output in sompi.
    pub fn value(&self) -> u64 {
        match self {
            Self::Contract(output) => output.value,
            Self::Plain(output) => output.value,
        }
    }

    /// The covenant binding of the output.
    pub fn binding_mut(&mut self) -> &mut Option<CovenantBinding> {
        match self {
            Self::Contract(output) => &mut output.binding,
            Self::Plain(output) => &mut output.binding,
        }
    }

    /// The value of the output.
    pub fn value_mut(&mut self) -> &mut u64 {
        match self {
            Self::Contract(output) => &mut output.value,
            Self::Plain(output) => &mut output.value,
        }
    }
}

/// One transaction, described.
#[derive(Clone, Debug)]
pub struct Scenario {
    /// Name for reports.
    pub name: String,
    /// The inputs, in transaction order.
    pub inputs: Vec<InputSpec>,
    /// The outputs, in transaction order.
    pub outputs: Vec<OutputSpec>,
    /// Transaction version: 1 unless changed.
    pub version: u16,
    /// Lock time: 0 unless changed.
    pub lock_time: u64,
    /// Subnetwork: the native one unless changed.
    pub subnetwork_id: SubnetworkId,
    /// Gas: 0 unless changed.
    pub gas: u64,
    /// Payload: empty unless changed.
    pub payload: Vec<u8>,
    /// The storage mass the transaction commits to: 0 unless changed.
    pub storage_mass: u64,
}

impl Scenario {
    /// An empty version-1 transaction on the native subnetwork.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            version: DEFAULT_TX_VERSION,
            lock_time: 0,
            subnetwork_id: SubnetworkId::default(),
            gas: 0,
            payload: Vec::new(),
            storage_mass: 0,
        }
    }

    /// Appends a contract input and returns its index.
    pub fn push_contract_input(&mut self, input: ContractInput) -> usize {
        self.inputs.push(InputSpec::Contract(input));
        self.inputs.len() - 1
    }

    /// Appends an ordinary input and returns its index.
    pub fn push_ordinary_input(&mut self, input: OrdinaryInput) -> usize {
        self.inputs.push(InputSpec::Ordinary(input));
        self.inputs.len() - 1
    }

    /// Appends a contract output and returns its index.
    pub fn push_contract_output(&mut self, output: ContractOutput) -> usize {
        self.outputs.push(OutputSpec::Contract(output));
        self.outputs.len() - 1
    }

    /// Appends a plain output and returns its index.
    pub fn push_plain_output(&mut self, output: PlainOutput) -> usize {
        self.outputs.push(OutputSpec::Plain(output));
        self.outputs.len() - 1
    }

    /// The contract input at `index`.
    ///
    /// # Panics
    ///
    /// Panics when there is no such input or it is an ordinary one.
    pub fn contract_input(&self, index: usize) -> &ContractInput {
        match self.inputs.get(index) {
            Some(InputSpec::Contract(input)) => input,
            Some(InputSpec::Ordinary(_)) => {
                panic!("input {index} of `{}` is an ordinary input", self.name)
            }
            None => panic!("`{}` has no input {index}", self.name),
        }
    }

    /// The contract input at `index`, to be changed.
    ///
    /// # Panics
    ///
    /// Panics when there is no such input or it is an ordinary one.
    pub fn contract_input_mut(&mut self, index: usize) -> &mut ContractInput {
        match self.inputs.get_mut(index) {
            Some(InputSpec::Contract(input)) => input,
            Some(InputSpec::Ordinary(_)) => {
                panic!("input {index} of `{}` is an ordinary input", self.name)
            }
            None => panic!("`{}` has no input {index}", self.name),
        }
    }

    /// The ordinary input at `index`, to be changed.
    ///
    /// # Panics
    ///
    /// Panics when there is no such input or it is a contract input.
    pub fn ordinary_input_mut(&mut self, index: usize) -> &mut OrdinaryInput {
        match self.inputs.get_mut(index) {
            Some(InputSpec::Ordinary(input)) => input,
            Some(InputSpec::Contract(_)) => {
                panic!("input {index} of `{}` is a contract input", self.name)
            }
            None => panic!("`{}` has no input {index}", self.name),
        }
    }

    /// The contract output at `index`, to be changed.
    ///
    /// # Panics
    ///
    /// Panics when there is no such output or it is a plain one.
    pub fn contract_output_mut(&mut self, index: usize) -> &mut ContractOutput {
        match self.outputs.get_mut(index) {
            Some(OutputSpec::Contract(output)) => output,
            Some(OutputSpec::Plain(_)) => {
                panic!("output {index} of `{}` is a plain output", self.name)
            }
            None => panic!("`{}` has no output {index}", self.name),
        }
    }

    /// The plain output at `index`, to be changed.
    ///
    /// # Panics
    ///
    /// Panics when there is no such output or it is a contract output.
    pub fn plain_output_mut(&mut self, index: usize) -> &mut PlainOutput {
        match self.outputs.get_mut(index) {
            Some(OutputSpec::Plain(output)) => output,
            Some(OutputSpec::Contract(_)) => {
                panic!("output {index} of `{}` is a contract output", self.name)
            }
            None => panic!("`{}` has no output {index}", self.name),
        }
    }

    /// Index of the first contract input whose typed call names `entry`.
    pub fn input_calling(&self, entry: Entry) -> Option<usize> {
        self.inputs.iter().position(|input| match input {
            InputSpec::Contract(input) => input.call.entry() == Some(entry),
            InputSpec::Ordinary(_) => false,
        })
    }

    /// Sum of the values of the spent coins (wrapping: the assembler does not judge).
    pub fn total_in(&self) -> u64 {
        self.inputs
            .iter()
            .fold(0u64, |sum, input| sum.wrapping_add(input.value()))
    }

    /// Sum of the values of the outputs (wrapping: the assembler does not judge).
    pub fn total_out(&self) -> u64 {
        self.outputs
            .iter()
            .fold(0u64, |sum, output| sum.wrapping_add(output.value()))
    }

    /// Builds the transaction, the list of spent coins and a description of every input.
    ///
    /// Fails only when bytes cannot be produced: the codec refuses a typed value, or a push
    /// is larger than the script builder allows. It never fails because the transaction
    /// would be invalid.
    pub fn assemble(&self, family: &Family) -> Result<Assembled> {
        // Step 1: coins, inputs without signature scripts, outputs.
        let mut utxos = Vec::with_capacity(self.inputs.len());
        let mut inputs = Vec::with_capacity(self.inputs.len());
        let mut honest_redeems = Vec::with_capacity(self.inputs.len());
        for spec in &self.inputs {
            match spec {
                InputSpec::Contract(input) => {
                    let redeem = family.redeem_script(&input.state)?;
                    let script_public_key = input
                        .locking_script
                        .clone()
                        .unwrap_or_else(|| pay_to_script_hash_script(&redeem));
                    utxos.push(UtxoEntry::new(
                        input.value,
                        script_public_key,
                        input.block_daa_score,
                        input.is_coinbase,
                        input.covenant_id,
                    ));
                    inputs.push(TransactionInput::new_with_mass(
                        input.outpoint,
                        Vec::new(),
                        input.sequence,
                        input.compute_commit,
                    ));
                    honest_redeems.push(Some(redeem));
                }
                InputSpec::Ordinary(input) => {
                    utxos.push(UtxoEntry::new(
                        input.value,
                        input.script_public_key.clone(),
                        input.block_daa_score,
                        input.is_coinbase,
                        input.covenant_id,
                    ));
                    inputs.push(TransactionInput::new_with_mass(
                        input.outpoint,
                        Vec::new(),
                        input.sequence,
                        input.compute_commit,
                    ));
                    honest_redeems.push(None);
                }
            }
        }
        let mut outputs = Vec::with_capacity(self.outputs.len());
        for spec in &self.outputs {
            outputs.push(match spec {
                OutputSpec::Contract(output) => {
                    let script_public_key = match &output.locking_script {
                        Some(script) => script.clone(),
                        None => family.script_public_key(&output.state)?,
                    };
                    TransactionOutput::with_covenant(
                        output.value,
                        script_public_key,
                        output.binding,
                    )
                }
                OutputSpec::Plain(output) => TransactionOutput::with_covenant(
                    output.value,
                    output.script_public_key.clone(),
                    output.binding,
                ),
            });
        }
        let tx = Transaction::new(
            self.version,
            inputs,
            outputs,
            self.lock_time,
            self.subnetwork_id,
            self.gas,
            self.payload.clone(),
        );
        tx.set_storage_mass(self.storage_mass);

        // Step 2: every closure sees the same unsigned transaction.
        let unsigned = MutableTransaction::with_entries(tx, utxos.clone());
        let mut signature_scripts = Vec::with_capacity(self.inputs.len());
        let mut infos = Vec::with_capacity(self.inputs.len());
        for (input_index, (spec, honest_redeem)) in
            self.inputs.iter().zip(honest_redeems).enumerate()
        {
            let ctx = SigningContext {
                tx: &unsigned,
                input_index,
            };
            match spec {
                InputSpec::Contract(input) => {
                    let pushed_redeem = input
                        .pushed_redeem
                        .clone()
                        .or(honest_redeem)
                        .expect("contract inputs have a redeem script");
                    let signature_script = match &input.signature_script {
                        Some(script) => script.resolve(&ctx),
                        None => {
                            let mut parts = match &input.call {
                                Call::Typed { entry, args } => {
                                    let values: Vec<ArtifactValue> =
                                        args.iter().map(|arg| arg.resolve(&ctx)).collect();
                                    family.call_parts(*entry, &values, &pushed_redeem)?
                                }
                                Call::Raw(bytes) => CallParts {
                                    arguments: vec![bytes.resolve(&ctx)],
                                    tag: Vec::new(),
                                    redeem: raw::push_redeem(&pushed_redeem)?,
                                },
                            };
                            if let Some(patch) = &input.patch {
                                patch(&mut parts);
                            }
                            parts.signature_script()
                        }
                    };
                    infos.push(InputInfo {
                        index: input_index,
                        label: input.label.clone(),
                        kind: InputKind::Contract {
                            contract: input.contract(),
                            entry: input.call.entry(),
                            role: input.call.entry().map(Entry::role),
                            redeem_script: pushed_redeem,
                        },
                        signature_script_opcodes: raw::count_opcodes(&signature_script),
                    });
                    signature_scripts.push(signature_script);
                }
                InputSpec::Ordinary(input) => {
                    let signature_script = input.signature_script.resolve(&ctx);
                    infos.push(InputInfo {
                        index: input_index,
                        label: input.label.clone(),
                        kind: InputKind::Ordinary,
                        signature_script_opcodes: raw::count_opcodes(&signature_script),
                    });
                    signature_scripts.push(signature_script);
                }
            }
        }

        // Step 3: signature scripts in, transaction id recomputed.
        let mut tx = unsigned.tx;
        for (input, signature_script) in tx.inputs.iter_mut().zip(signature_scripts) {
            input.signature_script = signature_script;
        }
        tx.finalize();
        Ok(Assembled {
            name: self.name.clone(),
            tx,
            utxos,
            inputs: infos,
        })
    }
}

/// What kind of coin an input spends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputKind {
    /// A coin of one of the three contracts.
    Contract {
        /// The contract of the coin, by the state the scenario gives it.
        contract: Contract,
        /// The entry called, when the call is typed.
        entry: Option<Entry>,
        /// Leader or delegate, when the call is typed.
        role: Option<EntryRole>,
        /// The redeem script the scenario pushes for this input: the one of the coin's state,
        /// or the `pushed_redeem` override. A whole-signature-script override does not
        /// change this field.
        redeem_script: Vec<u8>,
    },
    /// Any other coin.
    Ordinary,
}

/// A description of one assembled input, for reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputInfo {
    /// Index of the input in the transaction.
    pub index: usize,
    /// The label given in the scenario.
    pub label: String,
    /// Contract coin or ordinary coin.
    pub kind: InputKind,
    /// Number of opcodes in the signature script, or `None` when it does not parse. The
    /// engine logs one line per opcode, so this is the number of log lines the signature
    /// script takes before the coin's own script starts.
    pub signature_script_opcodes: Option<usize>,
}

impl InputInfo {
    /// The contract of the coin, when it is a contract coin.
    pub fn contract(&self) -> Option<Contract> {
        match &self.kind {
            InputKind::Contract { contract, .. } => Some(*contract),
            InputKind::Ordinary => None,
        }
    }

    /// The entry called, when the input is a contract coin with a typed call.
    pub fn entry(&self) -> Option<Entry> {
        match &self.kind {
            InputKind::Contract { entry, .. } => *entry,
            InputKind::Ordinary => None,
        }
    }
}

/// An assembled scenario: the transaction, the coins it spends, and what each input is.
#[derive(Clone, Debug)]
pub struct Assembled {
    /// Name of the scenario.
    pub name: String,
    /// The transaction, with signature scripts and a current id.
    pub tx: Transaction,
    /// The spent coins, one per input, in input order.
    pub utxos: Vec<UtxoEntry>,
    /// A description of every input, in input order.
    pub inputs: Vec<InputInfo>,
}

impl Assembled {
    /// The transaction together with its coins, in the form script engines take.
    pub fn populated(&self) -> PopulatedTransaction<'_> {
        PopulatedTransaction::new(&self.tx, self.utxos.clone())
    }

    /// Writes a compute budget into every input, in input order. The transaction id of a
    /// version-1 transaction does not cover the budgets, and neither do its signatures.
    ///
    /// Returns an error when the number of budgets differs from the number of inputs.
    pub fn set_compute_budgets(&mut self, budgets: &[u16]) -> Result<()> {
        if budgets.len() != self.tx.inputs.len() {
            return Err(Error::Scenario(format!(
                "{} budgets given for {} inputs",
                budgets.len(),
                self.tx.inputs.len()
            )));
        }
        for (input, budget) in self.tx.inputs.iter_mut().zip(budgets) {
            input.compute_commit = ComputeBudget(*budget).into();
        }
        self.tx.finalize();
        Ok(())
    }
}
