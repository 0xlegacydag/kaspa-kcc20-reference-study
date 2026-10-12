//! One honest transaction per entry, as a starting point for changes.
//!
//! Every function returns a [`Scenario`] that the reference's own runner accepts. The caller
//! then changes whatever the check is about (a declared amount, a locked state, a witness, a
//! binding, a value, the bytes of the call) and assembles it.
//!
//! The shapes follow the reference's tests (kcc20-reference c8a0871 src/bin/kcc20/tests.rs,
//! public_mint/tests.rs, public_mint/tests/lifecycle.rs): the same synthetic covenant id and
//! the same token amounts. They differ from them in the parties, on purpose: wherever a shape
//! has two roles (spender and recipient, minter and recipient, a coin and the covenant that
//! owns it) or several outputs, each gets a key or a state of its own, so that a mix-up of
//! two roles or of two outputs changes the bytes. Where the reference gives two roles the
//! same key, the doc comment of the function says so.
//!
//! Two value profiles:
//!
//! - [`Profile::Script`]: 1000-sompi coins and, where the authors use one, a 2000-sompi
//!   funding coin locked by `OP_TRUE`; the values follow the reference's tests. The profile is
//!   for the script engine alone: it asks no block and no mempool.
//! - [`Profile::Realistic`]: coin values given by the caller, and a funding coin locked to a
//!   public key and spent with a real Schnorr signature, with a change output and a fee.
//!
//! Layout of every shape: contract inputs first (outpoints `outpoint(1, i)`), then an
//! authority input if the owner scheme needs one (`outpoint(2, 0)`), then the funding input
//! (`outpoint(3, 0)`); contract outputs first, then plain outputs, then the change output.

use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    CovenantBinding, ScriptPublicKey, TransactionId, TransactionOutpoint,
};
use kaspa_txscript::opcodes::codes::{OpCheckSig, OpTrue};
use kaspa_txscript::pay_to_script_hash_script;
use kaspa_txscript::script_builder::ScriptBuilder;

use crate::family::{Entry, EntryRole};
use crate::keys::{self, ALICE, BOB, CAROL, FUNDER};
use crate::raw;
use crate::scenario::{
    Arg, Call, ContractInput, ContractOutput, LateBytes, OrdinaryInput, PlainOutput, Scenario,
};
use crate::states::{
    BORROW_HASH_CHAIN, BORROW_SCHNORR_SIGNATURE, Kcc20State, OWNER_COVENANT_ID, OWNER_P2PK_SCHNORR,
    OWNER_P2PKH_ECDSA, OWNER_P2PKH_SCHNORR, OWNER_P2SH, PublicMintState, TokenSeedState,
};
use crate::witness;

/// The synthetic covenant id every shape uses, as the reference's tests do
/// (kcc20-reference c8a0871 src/bin/kcc20/tests.rs:50-52).
pub const COVENANT_ID_BYTES: [u8; 32] = [0x11; 32];

/// Coin value of the script profile (kcc20-reference c8a0871 src/bin/kcc20/main.rs:19).
pub const SCRIPT_COIN_VALUE: u64 = 1_000;
/// Value of the `OP_TRUE` funding coin of the script profile
/// (kcc20-reference c8a0871 src/bin/kcc20/public_mint.rs:30-39).
pub const SCRIPT_FUNDING_VALUE: u64 = 2_000;
/// Value of a coin split off a minter or a seed in the script profile
/// (kcc20-reference c8a0871 src/bin/kcc20/public_mint/tests/lifecycle.rs:55, 188).
pub const SCRIPT_SPLIT_VALUE: u64 = 321;

/// Sompi per KAS.
pub const SOMPI_PER_KAS: u64 = 100_000_000;

/// The next guard revealed by the hash-chain borrow shape.
pub const CHAIN_NEXT_GUARD: [u8; 32] = [0x42; 32];

/// The synthetic covenant id as a hash.
pub fn covenant_id() -> Hash {
    Hash::from_bytes(COVENANT_ID_BYTES)
}

/// The id of a second, unrelated covenant: the owner of the token coin in the shapes of owner
/// scheme 0x04, carried there by an ordinary input.
pub const OWNING_COVENANT_ID_BYTES: [u8; 32] = [0x33; 32];

/// The id of the owning covenant as a hash.
pub fn owning_covenant_id() -> Hash {
    Hash::from_bytes(OWNING_COVENANT_ID_BYTES)
}

/// A synthetic outpoint: transaction id `seed` repeated 32 times
/// (kcc20-reference c8a0871 src/bin/kcc20/support.rs:21-23).
pub fn outpoint(seed: u8, index: u32) -> TransactionOutpoint {
    TransactionOutpoint::new(TransactionId::from_bytes([seed; 32]), index)
}

/// The script `OP_TRUE`, version 0: the authors' funding coin.
pub fn op_true_script() -> ScriptPublicKey {
    ScriptPublicKey::from_vec(0, vec![OpTrue])
}

/// A pay-to-public-key script for an x-only key, version 0: `<32-byte key> OP_CHECKSIG`.
pub fn pay_to_public_key_script(x_only_key: &[u8; 32]) -> ScriptPublicKey {
    let script = ScriptBuilder::new()
        .add_data(x_only_key)
        .and_then(|builder| builder.add_op(OpCheckSig))
        .expect("a 32-byte push and one opcode always fit a script")
        .drain();
    ScriptPublicKey::from_vec(0, script)
}

/// The redeem script of the authority used by the pay-to-script-hash owner shape: `OP_TRUE`
/// (kcc20-reference c8a0871 src/bin/kcc20/tests.rs:236-258).
pub const AUTHORITY_REDEEM_SCRIPT: [u8; 1] = [OpTrue];

/// Values of the realistic profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Realistic {
    /// Value of every contract coin and of every new contract output, in sompi.
    pub coin_value: u64,
    /// Value of the funding coin, in sompi.
    pub funding_value: u64,
    /// Fee left to the miner, in sompi. The change output gets the rest.
    pub fee: u64,
    /// Seed of the key that owns the funding coin and receives the change.
    pub funding_key: u8,
}

impl Default for Realistic {
    /// 10 KAS per contract coin, a 100 KAS funding coin, a fee of 0.001 KAS (100,000 sompi).
    ///
    /// These are starting values, not a claim about what a node accepts. With them the largest
    /// masses over all honest shapes are about 20,600 (compute), 53,300 (transient) and 11,300
    /// (storage) grams by the consensus calculator with mainnet parameters; the test
    /// `realistic_defaults_keep_every_mass_below_the_standard_cap` pins the three numbers.
    fn default() -> Self {
        Self {
            coin_value: 10 * SOMPI_PER_KAS,
            funding_value: 100 * SOMPI_PER_KAS,
            fee: SOMPI_PER_KAS / 1_000,
            funding_key: FUNDER,
        }
    }
}

/// How coin values and funding are chosen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Profile {
    /// Script-only values: 1000-sompi coins, `OP_TRUE` funding where a shape has one.
    Script,
    /// Caller-chosen values and a signed pay-to-public-key funding coin with change.
    Realistic(Realistic),
}

impl Profile {
    /// Value of a contract coin.
    pub fn coin_value(&self) -> u64 {
        match self {
            Self::Script => SCRIPT_COIN_VALUE,
            Self::Realistic(values) => values.coin_value,
        }
    }

    /// Value of a coin split off a minter or a seed.
    pub fn split_value(&self) -> u64 {
        match self {
            Self::Script => SCRIPT_SPLIT_VALUE,
            Self::Realistic(values) => values.coin_value,
        }
    }
}

/// Appends the funding of the profile.
///
/// Script profile: an `OP_TRUE` coin with an empty signature script, only for the shapes
/// where the authors have one. Realistic profile: always a pay-to-public-key coin spent with
/// a Schnorr signature over the whole transaction, and a change output to the same key.
///
/// # Panics
///
/// Panics in the realistic profile when the inputs do not cover the outputs and the fee.
fn finish(mut scenario: Scenario, profile: &Profile, authors_use_funding: bool) -> Scenario {
    match profile {
        Profile::Script => {
            if authors_use_funding {
                scenario.push_ordinary_input(
                    OrdinaryInput::new(
                        op_true_script(),
                        SCRIPT_FUNDING_VALUE,
                        outpoint(3, 0),
                        LateBytes::empty(),
                    )
                    .labelled("funding (OP_TRUE)"),
                );
            }
        }
        Profile::Realistic(values) => {
            let key_seed = values.funding_key;
            let script = pay_to_public_key_script(&keys::x_only(key_seed));
            let signature_script = LateBytes::from_tx(move |ctx| {
                raw::push(&keys::schnorr_signature(
                    ctx,
                    &keys::keypair(key_seed),
                    SIG_HASH_ALL,
                ))
                .expect("a 65-byte push always fits a script")
            });
            scenario.push_ordinary_input(
                OrdinaryInput::new(
                    script.clone(),
                    values.funding_value,
                    outpoint(3, 0),
                    signature_script,
                )
                .labelled("funding (pay to public key)"),
            );
            let change = scenario
                .total_in()
                .checked_sub(scenario.total_out())
                .and_then(|rest| rest.checked_sub(values.fee))
                .unwrap_or_else(|| {
                    panic!(
                        "`{}`: the inputs do not cover the outputs and the fee",
                        scenario.name
                    )
                });
            scenario.push_plain_output(PlainOutput::new(script, change));
        }
    }
    scenario
}

/// A binding to the leader at input 0 under the synthetic covenant id.
fn bound_to_leader() -> Option<CovenantBinding> {
    Some(CovenantBinding::new(0, covenant_id()))
}

/// One KCC20 coin of a transfer and the witness that spends it.
struct TokenCoin {
    label: String,
    state: Kcc20State,
    witness: LateBytes,
}

/// A transfer: the first coin leads with `transfer`, the others join with
/// `transfer_delegator`; every output is bound to the leader. The declared next states equal
/// the locked ones.
fn transfer_scenario(
    name: String,
    profile: &Profile,
    coins: Vec<TokenCoin>,
    authority: Option<OrdinaryInput>,
    next_states: Vec<Kcc20State>,
    output_values: Vec<u64>,
) -> Scenario {
    let mut scenario = Scenario::new(name);
    for (index, coin) in coins.into_iter().enumerate() {
        let call = if index == 0 {
            Call::typed(
                Entry::Transfer,
                vec![Arg::States(next_states.clone()), Arg::Bytes(coin.witness)],
            )
        } else {
            Call::typed(Entry::TransferDelegator, vec![Arg::Bytes(coin.witness)])
        };
        scenario.push_contract_input(
            ContractInput::new(
                coin.state,
                profile.coin_value(),
                Some(covenant_id()),
                outpoint(1, index as u32),
                call,
            )
            .labelled(coin.label),
        );
    }
    if let Some(authority) = authority {
        scenario.push_ordinary_input(authority);
    }
    for (state, value) in next_states.into_iter().zip(output_values) {
        scenario.push_contract_output(ContractOutput::new(state, value, bound_to_leader()));
    }
    finish(scenario, profile, false)
}

/// `KCC20.transfer` on the normal path with `inputs` token coins and `outputs` token outputs,
/// every owner a Schnorr key (kcc20-reference c8a0871 src/bin/kcc20/tests.rs:771-811).
///
/// Coin `k` holds 100 tokens and belongs to the key with seed `0xaa + k` (Alice and the keys
/// after hers). Output `k` belongs to the key with seed `0xbb + k` (Bob and the keys after
/// his); the outputs share the total, the first one taking the remainder. No two outputs
/// hold the same state, so a declared state checked against another output than its own does
/// not pass unseen. The reference's test gives every output to one key.
///
/// # Panics
///
/// Panics when `inputs` or `outputs` is 0. Counts above 3 are built without complaint (the
/// contract refuses them, the shape does not).
pub fn transfer(profile: &Profile, inputs: usize, outputs: usize) -> Scenario {
    assert!(
        inputs > 0 && outputs > 0,
        "a transfer shape needs at least one input and one output"
    );
    let coins = (0..inputs)
        .map(|index| {
            let seed = ALICE + index as u8;
            let role = if index == 0 {
                EntryRole::Leader
            } else {
                EntryRole::Delegate
            };
            TokenCoin {
                label: format!("token coin {index}, owner key {seed:#04x}"),
                state: Kcc20State::new(keys::x_only(seed), 100),
                witness: witness::owner_key(seed, role, SIG_HASH_ALL),
            }
        })
        .collect();
    let total = 100 * inputs as i64;
    let next_states = (0..outputs)
        .map(|index| {
            let share = total / outputs as i64
                + if index == 0 {
                    total % outputs as i64
                } else {
                    0
                };
            Kcc20State::new(keys::x_only(BOB + index as u8), share)
        })
        .collect();
    let output_values = match profile {
        Profile::Script => {
            let total = SCRIPT_COIN_VALUE * inputs as u64;
            (0..outputs)
                .map(|index| {
                    total / outputs as u64
                        + if index == 0 {
                            total % outputs as u64
                        } else {
                            0
                        }
                })
                .collect()
        }
        Profile::Realistic(values) => vec![values.coin_value; outputs],
    };
    transfer_scenario(
        format!("transfer {inputs} to {outputs}"),
        profile,
        coins,
        None,
        next_states,
        output_values,
    )
}

/// The leader and the delegate of the reference's borrowed receive: Bob's coin (200 tokens,
/// amount threshold 10) leads on the borrow path without a signature, Alice's coin (100
/// tokens) joins and signs; Bob's coin gains `increase` tokens
/// (kcc20-reference c8a0871 src/bin/kcc20/tests.rs:189-215).
fn borrowed_coins_and_states(increase: i64) -> (Vec<TokenCoin>, Vec<Kcc20State>) {
    let bob = Kcc20State::new(keys::x_only(BOB), 200).with_threshold(10);
    let alice = Kcc20State::new(keys::x_only(ALICE), 100);
    let coins = vec![
        TokenCoin {
            label: "leader: Bob, borrow path".to_string(),
            state: bob.clone(),
            witness: witness::borrow_threshold(),
        },
        TokenCoin {
            label: "delegate: Alice, owner key".to_string(),
            state: alice.clone(),
            witness: witness::owner_key(ALICE, EntryRole::Delegate, SIG_HASH_ALL),
        },
    ];
    (
        coins,
        vec![
            bob.with_amount(200 + increase),
            alice.with_amount(100 - increase),
        ],
    )
}

/// The three borrow policies of KCC-20.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BorrowKind {
    /// Borrow scheme 0x01: the increase must exceed the threshold in the guard.
    Threshold,
    /// Borrow scheme 0x02: the guard key signs.
    Signature,
    /// Borrow scheme 0x03: a one-time key signs and the guard advances along a hash chain.
    HashChain,
}

/// `KCC20.transfer` on the borrow path together with `KCC20.transfer_delegator`: Alice adds
/// tokens to Bob's coin, which leads without Bob's signature
/// (kcc20-reference c8a0871 src/bin/kcc20/tests.rs:577-585, 655-661, 672-681).
///
/// - `Threshold`: threshold 10, Alice adds 11.
/// - `Signature`: the guard is Carol's key, Carol signs, Alice adds 1.
/// - `HashChain`: the guard commits to [`CHAIN_NEXT_GUARD`] and Carol's key; Carol signs,
///   the successor holds the next guard, Alice adds 1.
pub fn borrow(profile: &Profile, kind: BorrowKind) -> Scenario {
    let (name, increase) = match kind {
        BorrowKind::Threshold => ("borrow by threshold", 11),
        BorrowKind::Signature => ("borrow by guard signature", 1),
        BorrowKind::HashChain => ("borrow by hash chain", 1),
    };
    let (mut coins, mut next_states) = borrowed_coins_and_states(increase);
    match kind {
        BorrowKind::Threshold => {}
        BorrowKind::Signature => {
            let guard = keys::x_only(CAROL);
            coins[0].state = coins[0]
                .state
                .clone()
                .with_borrow(BORROW_SCHNORR_SIGNATURE, guard);
            next_states[0] = next_states[0]
                .clone()
                .with_borrow(BORROW_SCHNORR_SIGNATURE, guard);
            coins[0].witness = witness::borrow_signature(CAROL, SIG_HASH_ALL);
        }
        BorrowKind::HashChain => {
            let guard = witness::chain_guard(&CHAIN_NEXT_GUARD, CAROL);
            coins[0].state = coins[0].state.clone().with_borrow(BORROW_HASH_CHAIN, guard);
            next_states[0] = next_states[0]
                .clone()
                .with_borrow(BORROW_HASH_CHAIN, CHAIN_NEXT_GUARD);
            coins[0].witness = witness::borrow_hash_chain(CHAIN_NEXT_GUARD, CAROL, SIG_HASH_ALL);
        }
    }
    let output_values = vec![profile.coin_value(); 2];
    transfer_scenario(
        name.to_string(),
        profile,
        coins,
        None,
        next_states,
        output_values,
    )
}

/// The `owner` field, the witness and, for the script-hash and the covenant-id scheme, the
/// authority input of one owner scheme, for Alice's key
/// (kcc20-reference c8a0871 src/bin/kcc20/tests.rs:224-276).
///
/// The authority of both schemes is a pay-to-script-hash coin of `OP_TRUE`. For scheme 0x03
/// its script hash is the owner and the witness names its input. For scheme 0x04 it carries
/// the covenant id that is the owner, [`OWNING_COVENANT_ID_BYTES`], and the witness names
/// nothing: the contract counts the inputs of that covenant
/// (kcc20-reference c8a0871 contracts/kcc20.ag:72-74).
///
/// # Panics
///
/// Panics for a scheme outside 0x00..=0x04.
fn owner_setup(
    profile: &Profile,
    scheme: u8,
    role: EntryRole,
    authority_input_index: u8,
) -> ([u8; 32], LateBytes, Option<OrdinaryInput>) {
    match scheme {
        OWNER_P2PK_SCHNORR => (
            keys::x_only(ALICE),
            witness::owner_key(ALICE, role, SIG_HASH_ALL),
            None,
        ),
        OWNER_P2PKH_SCHNORR => (
            witness::public_key_hash(&keys::x_only(ALICE)),
            witness::owner_key_hash_schnorr(ALICE, role, SIG_HASH_ALL),
            None,
        ),
        OWNER_P2PKH_ECDSA => (
            witness::public_key_hash(&keys::compressed(ALICE)),
            witness::owner_key_hash_ecdsa(ALICE, role, SIG_HASH_ALL),
            None,
        ),
        OWNER_P2SH => {
            let script = pay_to_script_hash_script(&AUTHORITY_REDEEM_SCRIPT);
            let owner: [u8; 32] = script.script()[2..34]
                .try_into()
                .expect("a pay-to-script-hash script holds a 32-byte hash");
            let signature_script =
                raw::push(&AUTHORITY_REDEEM_SCRIPT).expect("a one-byte push always fits a script");
            let authority = OrdinaryInput::new(
                script,
                profile.coin_value(),
                outpoint(2, 0),
                LateBytes::fixed(signature_script),
            )
            .labelled("authority (pay to script hash of OP_TRUE)");
            (
                owner,
                witness::owner_script_hash(authority_input_index, role),
                Some(authority),
            )
        }
        OWNER_COVENANT_ID => {
            let signature_script =
                raw::push(&AUTHORITY_REDEEM_SCRIPT).expect("a one-byte push always fits a script");
            let authority = OrdinaryInput::new(
                pay_to_script_hash_script(&AUTHORITY_REDEEM_SCRIPT),
                profile.coin_value(),
                outpoint(2, 0),
                LateBytes::fixed(signature_script),
            )
            .with_covenant_id(owning_covenant_id())
            .labelled("a coin of the owning covenant (pay to script hash of OP_TRUE)");
            (
                OWNING_COVENANT_ID_BYTES,
                witness::owner_covenant_id(role),
                Some(authority),
            )
        }
        other => panic!("there is no honest shape for owner scheme {other:#04x}"),
    }
}

/// A transfer whose leader (`role == Leader`) or delegate (`role == Delegate`) coin uses the
/// given owner scheme (kcc20-reference c8a0871 src/bin/kcc20/tests.rs:398-413).
///
/// - Leader: Alice's coin (100 tokens) with the scheme moves to a plain coin of Bob, so the
///   output is never the script of the coin that is spent. (With scheme 0x00 this is the
///   transaction of `transfer(profile, 1, 1)` under another name.)
/// - Delegate: the threshold borrow of [`borrow`], with the scheme on Alice's delegate coin.
///
/// For the schemes 0x03 and 0x04 an authority input follows the token inputs. For scheme
/// 0x04 the token coin is owned by another covenant, [`OWNING_COVENANT_ID_BYTES`], and the
/// authority input is a coin of that covenant. The reference's own test of this scheme makes
/// the token's covenant id the owner; that shape is [`transfer_owned_by_its_own_covenant`].
///
/// # Panics
///
/// Panics for a scheme outside 0x00..=0x04.
pub fn transfer_with_owner_scheme(profile: &Profile, role: EntryRole, scheme: u8) -> Scenario {
    match role {
        EntryRole::Leader => {
            let (owner, witness, authority) = owner_setup(profile, scheme, role, 1);
            let coins = vec![TokenCoin {
                label: format!("leader: Alice, owner scheme {scheme:#04x}"),
                state: Kcc20State::new(keys::x_only(ALICE), 100).with_owner(scheme, owner),
                witness,
            }];
            transfer_scenario(
                format!("transfer, leader owner scheme {scheme:#04x}"),
                profile,
                coins,
                authority,
                vec![Kcc20State::new(keys::x_only(BOB), 100)],
                vec![profile.coin_value()],
            )
        }
        EntryRole::Delegate => {
            let (owner, witness, authority) = owner_setup(profile, scheme, role, 2);
            let (mut coins, next_states) = borrowed_coins_and_states(11);
            coins[1].label = format!("delegate: Alice, owner scheme {scheme:#04x}");
            coins[1].state = coins[1].state.clone().with_owner(scheme, owner);
            coins[1].witness = witness;
            transfer_scenario(
                format!("transfer, delegate owner scheme {scheme:#04x}"),
                profile,
                coins,
                authority,
                next_states,
                vec![profile.coin_value(); 2],
            )
        }
    }
}

/// The reference's own shape of owner scheme 0x04: the owner of the token coin is the token's
/// covenant id itself (kcc20-reference c8a0871 src/bin/kcc20/tests.rs:259-266).
///
/// The coin carries the id that owns it: no second covenant and no authority input are
/// involved, and the witness is empty. The shape is kept apart from [`all`];
/// [`transfer_with_owner_scheme`] uses two covenants.
///
/// - Leader: the coin (100 tokens) moves to a plain coin of Bob.
/// - Delegate: the threshold borrow of [`borrow`], with the scheme on the delegate coin.
pub fn transfer_owned_by_its_own_covenant(profile: &Profile, role: EntryRole) -> Scenario {
    let owned = |state: Kcc20State| state.with_owner(OWNER_COVENANT_ID, COVENANT_ID_BYTES);
    let witness = witness::owner_covenant_id(role);
    match role {
        EntryRole::Leader => {
            let coins = vec![TokenCoin {
                label: "leader: owned by the token's own covenant".to_string(),
                state: owned(Kcc20State::new(keys::x_only(ALICE), 100)),
                witness,
            }];
            transfer_scenario(
                "transfer, leader owned by its own covenant".to_string(),
                profile,
                coins,
                None,
                vec![Kcc20State::new(keys::x_only(BOB), 100)],
                vec![profile.coin_value()],
            )
        }
        EntryRole::Delegate => {
            let (mut coins, next_states) = borrowed_coins_and_states(11);
            coins[1].label = "delegate: owned by the token's own covenant".to_string();
            coins[1].state = owned(coins[1].state.clone());
            coins[1].witness = witness;
            transfer_scenario(
                "transfer, delegate owned by its own covenant".to_string(),
                profile,
                coins,
                None,
                next_states,
                vec![profile.coin_value(); 2],
            )
        }
    }
}

/// `PublicMint.mint`: Alice's minter (25 remaining, 10 per mint) mints 10 tokens to Bob
/// (kcc20-reference c8a0871 src/bin/kcc20/public_mint/tests.rs:16-75; there the owner of the
/// minter and the recipient are one key, here they are two, so that the two roles cannot be
/// swapped unseen).
pub fn mint(profile: &Profile) -> Scenario {
    let minter = PublicMintState::new(keys::x_only(ALICE), 25, 10);
    let recipient = Kcc20State::new(keys::x_only(BOB), 10);
    let mut scenario = Scenario::new("mint");
    scenario.push_contract_input(
        ContractInput::new(
            minter.clone(),
            profile.coin_value(),
            Some(covenant_id()),
            outpoint(1, 0),
            Call::typed(Entry::Mint, vec![Arg::State(recipient.clone())]),
        )
        .labelled("minter: Alice, 25 remaining, 10 per mint; recipient: Bob"),
    );
    scenario.push_contract_output(ContractOutput::new(
        minter.with_remaining(15),
        profile.coin_value(),
        bound_to_leader(),
    ));
    scenario.push_contract_output(ContractOutput::new(
        recipient,
        profile.coin_value(),
        bound_to_leader(),
    ));
    finish(scenario, profile, true)
}

/// `PublicMint.split`: Alice's minter (25 remaining) hands 7 of its allowance to a new minter
/// of Bob (kcc20-reference c8a0871 src/bin/kcc20/public_mint/tests/lifecycle.rs:56-83).
pub fn mint_split(profile: &Profile) -> Scenario {
    let minter = PublicMintState::new(keys::x_only(ALICE), 25, 10);
    let take = 7;
    let mut scenario = Scenario::new("minter split");
    scenario.push_contract_input(
        ContractInput::new(
            minter.clone(),
            profile.coin_value(),
            Some(covenant_id()),
            outpoint(1, 0),
            Call::typed(
                Entry::MintSplit,
                vec![Arg::int(take), Arg::bytes(keys::x_only(BOB))],
            ),
        )
        .labelled("minter: Alice, 25 remaining"),
    );
    scenario.push_contract_output(ContractOutput::new(
        minter.clone().with_remaining(25 - take),
        profile.coin_value(),
        bound_to_leader(),
    ));
    scenario.push_contract_output(ContractOutput::new(
        minter.with_remaining(take).with_owner(keys::x_only(BOB)),
        profile.split_value(),
        bound_to_leader(),
    ));
    finish(scenario, profile, true)
}

/// `PublicMint.reclaim`: Alice closes her exhausted minter and takes its sompi
/// (kcc20-reference c8a0871 src/bin/kcc20/public_mint/tests/lifecycle.rs:142-176).
pub fn mint_reclaim(profile: &Profile) -> Scenario {
    let minter = PublicMintState::new(keys::x_only(ALICE), 0, 10);
    let mut scenario = Scenario::new("minter reclaim");
    scenario.push_contract_input(
        ContractInput::new(
            minter,
            profile.coin_value(),
            Some(covenant_id()),
            outpoint(1, 0),
            Call::typed(
                Entry::MintReclaim,
                vec![Arg::Bytes(witness::signature(ALICE, SIG_HASH_ALL))],
            ),
        )
        .labelled("minter: Alice, exhausted"),
    );
    scenario.push_plain_output(PlainOutput::new(
        pay_to_public_key_script(&keys::x_only(ALICE)),
        profile.coin_value(),
    ));
    finish(scenario, profile, false)
}

/// `PublicMint.reclaim_into` with `PublicMint.reclaim_delegator`: Alice's minter (18
/// remaining) absorbs Bob's minter (4 remaining); Bob signs and takes his coin's sompi
/// (kcc20-reference c8a0871 src/bin/kcc20/public_mint/tests/lifecycle.rs:109-138).
pub fn mint_reclaim_into(profile: &Profile) -> Scenario {
    let survivor = PublicMintState::new(keys::x_only(ALICE), 18, 10);
    let retiring = PublicMintState::new(keys::x_only(BOB), 4, 10);
    let mut scenario = Scenario::new("minter reclaim into");
    scenario.push_contract_input(
        ContractInput::new(
            survivor.clone(),
            profile.coin_value(),
            Some(covenant_id()),
            outpoint(1, 0),
            Call::typed(Entry::MintReclaimInto, Vec::new()),
        )
        .labelled("surviving minter: Alice, 18 remaining"),
    );
    scenario.push_contract_input(
        ContractInput::new(
            retiring,
            profile.split_value(),
            Some(covenant_id()),
            outpoint(1, 1),
            Call::typed(
                Entry::MintReclaimDelegator,
                vec![Arg::Bytes(witness::signature(BOB, SIG_HASH_ALL))],
            ),
        )
        .labelled("retiring minter: Bob, 4 remaining"),
    );
    scenario.push_contract_output(ContractOutput::new(
        survivor.with_remaining(22),
        profile.coin_value(),
        bound_to_leader(),
    ));
    scenario.push_plain_output(PlainOutput::new(
        pay_to_public_key_script(&keys::x_only(BOB)),
        profile.split_value(),
    ));
    finish(scenario, profile, false)
}

/// `TokenSeed.create`: Alice's seed creates a zero-token coin for Bob that anybody may pay
/// into (amount threshold 0) (kcc20-reference c8a0871
/// src/bin/kcc20/public_mint/tests/lifecycle.rs:217-240).
pub fn seed_create(profile: &Profile) -> Scenario {
    let seed = TokenSeedState::new(keys::x_only(ALICE));
    let recipient = Kcc20State::new(keys::x_only(BOB), 0).with_threshold(0);
    let mut scenario = Scenario::new("seed create");
    scenario.push_contract_input(
        ContractInput::new(
            seed.clone(),
            profile.coin_value(),
            Some(covenant_id()),
            outpoint(1, 0),
            Call::typed(Entry::SeedCreate, vec![Arg::State(recipient.clone())]),
        )
        .labelled("seed: Alice"),
    );
    scenario.push_contract_output(ContractOutput::new(
        seed,
        profile.coin_value(),
        bound_to_leader(),
    ));
    scenario.push_contract_output(ContractOutput::new(
        recipient,
        profile.coin_value(),
        bound_to_leader(),
    ));
    finish(scenario, profile, true)
}

/// `TokenSeed.split`: Alice's seed creates a second seed for Bob
/// (kcc20-reference c8a0871 src/bin/kcc20/public_mint/tests/lifecycle.rs:189-214).
pub fn seed_split(profile: &Profile) -> Scenario {
    let seed = TokenSeedState::new(keys::x_only(ALICE));
    let mut scenario = Scenario::new("seed split");
    scenario.push_contract_input(
        ContractInput::new(
            seed.clone(),
            profile.coin_value(),
            Some(covenant_id()),
            outpoint(1, 0),
            Call::typed(Entry::SeedSplit, vec![Arg::bytes(keys::x_only(BOB))]),
        )
        .labelled("seed: Alice"),
    );
    scenario.push_contract_output(ContractOutput::new(
        seed.clone(),
        profile.coin_value(),
        bound_to_leader(),
    ));
    scenario.push_contract_output(ContractOutput::new(
        seed.with_owner(keys::x_only(BOB)),
        profile.split_value(),
        bound_to_leader(),
    ));
    finish(scenario, profile, true)
}

/// `TokenSeed.reclaim` with `TokenSeed.reclaim_delegator`: Alice's seed survives, Bob's seed
/// is closed; Bob signs and takes his coin's sompi
/// (kcc20-reference c8a0871 src/bin/kcc20/public_mint/tests/lifecycle.rs:300-327).
pub fn seed_reclaim(profile: &Profile) -> Scenario {
    let survivor = TokenSeedState::new(keys::x_only(ALICE));
    let retiring = TokenSeedState::new(keys::x_only(BOB));
    let mut scenario = Scenario::new("seed reclaim");
    scenario.push_contract_input(
        ContractInput::new(
            survivor.clone(),
            profile.coin_value(),
            Some(covenant_id()),
            outpoint(1, 0),
            Call::typed(Entry::SeedReclaim, Vec::new()),
        )
        .labelled("surviving seed: Alice"),
    );
    scenario.push_contract_input(
        ContractInput::new(
            retiring,
            profile.split_value(),
            Some(covenant_id()),
            outpoint(1, 1),
            Call::typed(
                Entry::SeedReclaimDelegator,
                vec![Arg::Bytes(witness::signature(BOB, SIG_HASH_ALL))],
            ),
        )
        .labelled("retiring seed: Bob"),
    );
    scenario.push_contract_output(ContractOutput::new(
        survivor,
        profile.coin_value(),
        bound_to_leader(),
    ));
    scenario.push_plain_output(PlainOutput::new(
        pay_to_public_key_script(&keys::x_only(BOB)),
        profile.split_value(),
    ));
    finish(scenario, profile, false)
}

/// The honest shape that exercises `entry`, and the index of the input that calls it.
pub fn for_entry(profile: &Profile, entry: Entry) -> (Scenario, usize) {
    let scenario = match entry {
        Entry::Transfer => transfer(profile, 1, 1),
        Entry::TransferDelegator => borrow(profile, BorrowKind::Threshold),
        Entry::Mint => mint(profile),
        Entry::MintSplit => mint_split(profile),
        Entry::MintReclaim => mint_reclaim(profile),
        Entry::MintReclaimInto | Entry::MintReclaimDelegator => mint_reclaim_into(profile),
        Entry::SeedCreate => seed_create(profile),
        Entry::SeedSplit => seed_split(profile),
        Entry::SeedReclaim | Entry::SeedReclaimDelegator => seed_reclaim(profile),
    };
    let input_index = scenario
        .input_calling(entry)
        .expect("every honest shape calls the entry it is made for");
    (scenario, input_index)
}

/// The honest shapes of the crate: 9 transfers (1..=3 inputs by 1..=3 outputs), 10 owner
/// scheme transfers (5 schemes, leader and delegate), 3 borrows, 4 minter shapes and 3 seed
/// shapes. [`transfer_owned_by_its_own_covenant`] is not among them.
pub fn all(profile: &Profile) -> Vec<Scenario> {
    let mut shapes = Vec::new();
    for inputs in 1..=3 {
        for outputs in 1..=3 {
            shapes.push(transfer(profile, inputs, outputs));
        }
    }
    for role in [EntryRole::Leader, EntryRole::Delegate] {
        for scheme in OWNER_P2PK_SCHNORR..=OWNER_COVENANT_ID {
            shapes.push(transfer_with_owner_scheme(profile, role, scheme));
        }
    }
    for kind in [
        BorrowKind::Threshold,
        BorrowKind::Signature,
        BorrowKind::HashChain,
    ] {
        shapes.push(borrow(profile, kind));
    }
    shapes.extend([
        mint(profile),
        mint_split(profile),
        mint_reclaim(profile),
        mint_reclaim_into(profile),
        seed_create(profile),
        seed_split(profile),
        seed_reclaim(profile),
    ]);
    shapes
}
