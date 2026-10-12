//! Typed states of the three contracts and the scheme constants of KCC-20.
//!
//! A typed state holds the fields a user writes (the "authored" fields). The fields the
//! compiler adds in front of them (`gen__kcc20_template` and friends) are filled by
//! [`crate::family::Family`], because their values depend on the bytecode of the family.
//!
//! The types do not restrict values: a state with any scheme byte and any amount can be
//! written down, encoded and locked into an output. Whether a contract accepts it is for
//! the engine to say.

use std::collections::BTreeMap;

use argent::codec::ArtifactValue;

use crate::family::Contract;

/// Owner scheme: `owner` is a 32-byte x-only public key, the witness a Schnorr signature
/// (kcc20-reference c8a0871 contracts/kcc20.ag:3, 45-50).
pub const OWNER_P2PK_SCHNORR: u8 = 0x00;
/// Owner scheme: `owner` is BLAKE3 of an x-only public key (kcc20.ag:4, 51-57).
pub const OWNER_P2PKH_SCHNORR: u8 = 0x01;
/// Owner scheme: `owner` is BLAKE3 of a 33-byte compressed public key (kcc20.ag:5, 58-64).
pub const OWNER_P2PKH_ECDSA: u8 = 0x02;
/// Owner scheme: `owner` is the script hash of a pay-to-script-hash input of the same
/// transaction (kcc20.ag:6, 65-71).
pub const OWNER_P2SH: u8 = 0x03;
/// Owner scheme: `owner` is a covenant id carried by an input of the same transaction
/// (kcc20.ag:7, 72-74).
pub const OWNER_COVENANT_ID: u8 = 0x04;

/// Borrow scheme: nobody may add tokens to the coin without its owner (kcc20.ag:12, 132-133).
pub const BORROW_DISABLED: u8 = 0x00;
/// Borrow scheme: anybody may add more than the threshold in `borrow_guard[0..8]`
/// (kcc20.ag:13, 134-140).
pub const BORROW_AMOUNT_THRESHOLD: u8 = 0x01;
/// Borrow scheme: the key in `borrow_guard` signs the addition (kcc20.ag:14, 141-147).
pub const BORROW_SCHNORR_SIGNATURE: u8 = 0x02;
/// Borrow scheme: `borrow_guard` is a link of a hash chain of one-time keys
/// (kcc20.ag:15, 148-165).
pub const BORROW_HASH_CHAIN: u8 = 0x03;

/// First witness byte of `KCC20.transfer`: the owner authorizes the spend (kcc20.ag:9, 126-127).
pub const PATH_NORMAL: u8 = 0x00;
/// First witness byte of `KCC20.transfer`: the borrow policy authorizes it (kcc20.ag:10, 128-179).
pub const PATH_BORROW: u8 = 0x01;

/// The authored state of a KCC20 token coin (`KCC20State`, kcc20.ag:80-87).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Kcc20State {
    pub amount: i64,
    pub owner: [u8; 32],
    pub owner_scheme: u8,
    pub borrow_scheme: u8,
    pub borrow_guard: [u8; 32],
    pub extension_commitment: [u8; 32],
}

impl Kcc20State {
    /// A coin owned by an x-only public key, with borrowing disabled and a zero extension
    /// commitment: the plain token coin of the reference's examples
    /// (kcc20-reference c8a0871 src/bin/kcc20/main.rs:34-44).
    pub fn new(owner: [u8; 32], amount: i64) -> Self {
        Self {
            amount,
            owner,
            owner_scheme: OWNER_P2PK_SCHNORR,
            borrow_scheme: BORROW_DISABLED,
            borrow_guard: [0; 32],
            extension_commitment: [0; 32],
        }
    }

    /// The same state with another amount.
    pub fn with_amount(mut self, amount: i64) -> Self {
        self.amount = amount;
        self
    }

    /// The same state with another owner and owner scheme.
    pub fn with_owner(mut self, owner_scheme: u8, owner: [u8; 32]) -> Self {
        self.owner_scheme = owner_scheme;
        self.owner = owner;
        self
    }

    /// The same state with another borrow policy.
    pub fn with_borrow(mut self, borrow_scheme: u8, borrow_guard: [u8; 32]) -> Self {
        self.borrow_scheme = borrow_scheme;
        self.borrow_guard = borrow_guard;
        self
    }

    /// The same state with the amount-threshold borrow policy: the threshold as eight
    /// little-endian bytes followed by 24 zero bytes, as the reference writes it
    /// (kcc20-reference c8a0871 src/bin/kcc20/main.rs:23-32). Meant for thresholds >= 0.
    pub fn with_threshold(self, threshold: i64) -> Self {
        let mut guard = [0u8; 32];
        guard[..8].copy_from_slice(&threshold.to_le_bytes());
        self.with_borrow(BORROW_AMOUNT_THRESHOLD, guard)
    }

    /// The same state with another extension commitment.
    pub fn with_extension(mut self, extension_commitment: [u8; 32]) -> Self {
        self.extension_commitment = extension_commitment;
        self
    }

    /// The authored fields as codec values, keyed by field name.
    pub fn authored(&self) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([
            ("amount".to_string(), ArtifactValue::Int(self.amount)),
            (
                "owner".to_string(),
                ArtifactValue::Bytes(self.owner.to_vec()),
            ),
            (
                "owner_scheme".to_string(),
                ArtifactValue::Byte(self.owner_scheme),
            ),
            (
                "borrow_scheme".to_string(),
                ArtifactValue::Byte(self.borrow_scheme),
            ),
            (
                "borrow_guard".to_string(),
                ArtifactValue::Bytes(self.borrow_guard.to_vec()),
            ),
            (
                "extension_commitment".to_string(),
                ArtifactValue::Bytes(self.extension_commitment.to_vec()),
            ),
        ])
    }
}

/// The authored state of a PublicMint coin (`PublicMintState`,
/// kcc20-reference c8a0871 contracts/public_mint.ag:5-10).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicMintState {
    pub remaining: i64,
    pub mint_amount: i64,
    pub owner: [u8; 32],
    pub extension_commitment: [u8; 32],
}

impl PublicMintState {
    /// A minter with a zero extension commitment.
    pub fn new(owner: [u8; 32], remaining: i64, mint_amount: i64) -> Self {
        Self {
            remaining,
            mint_amount,
            owner,
            extension_commitment: [0; 32],
        }
    }

    /// The same state with another remaining allowance.
    pub fn with_remaining(mut self, remaining: i64) -> Self {
        self.remaining = remaining;
        self
    }

    /// The same state with another owner.
    pub fn with_owner(mut self, owner: [u8; 32]) -> Self {
        self.owner = owner;
        self
    }

    /// The same state with another extension commitment.
    pub fn with_extension(mut self, extension_commitment: [u8; 32]) -> Self {
        self.extension_commitment = extension_commitment;
        self
    }

    /// The authored fields as codec values, keyed by field name.
    pub fn authored(&self) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([
            ("remaining".to_string(), ArtifactValue::Int(self.remaining)),
            (
                "mint_amount".to_string(),
                ArtifactValue::Int(self.mint_amount),
            ),
            (
                "owner".to_string(),
                ArtifactValue::Bytes(self.owner.to_vec()),
            ),
            (
                "extension_commitment".to_string(),
                ArtifactValue::Bytes(self.extension_commitment.to_vec()),
            ),
        ])
    }
}

/// The authored state of a TokenSeed coin (`TokenSeedState`,
/// kcc20-reference c8a0871 contracts/token_seed.ag:5-8).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TokenSeedState {
    pub owner: [u8; 32],
    pub extension_commitment: [u8; 32],
}

impl TokenSeedState {
    /// A seed with a zero extension commitment.
    pub fn new(owner: [u8; 32]) -> Self {
        Self {
            owner,
            extension_commitment: [0; 32],
        }
    }

    /// The same state with another owner.
    pub fn with_owner(mut self, owner: [u8; 32]) -> Self {
        self.owner = owner;
        self
    }

    /// The same state with another extension commitment.
    pub fn with_extension(mut self, extension_commitment: [u8; 32]) -> Self {
        self.extension_commitment = extension_commitment;
        self
    }

    /// The authored fields as codec values, keyed by field name.
    pub fn authored(&self) -> BTreeMap<String, ArtifactValue> {
        BTreeMap::from([
            (
                "owner".to_string(),
                ArtifactValue::Bytes(self.owner.to_vec()),
            ),
            (
                "extension_commitment".to_string(),
                ArtifactValue::Bytes(self.extension_commitment.to_vec()),
            ),
        ])
    }
}

/// The authored state of a coin of any of the three contracts.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum State {
    Kcc20(Kcc20State),
    PublicMint(PublicMintState),
    TokenSeed(TokenSeedState),
}

impl State {
    /// The contract whose script holds this state.
    pub fn contract(&self) -> Contract {
        match self {
            Self::Kcc20(_) => Contract::Kcc20,
            Self::PublicMint(_) => Contract::PublicMint,
            Self::TokenSeed(_) => Contract::TokenSeed,
        }
    }

    /// The authored fields as codec values, keyed by field name.
    pub fn authored(&self) -> BTreeMap<String, ArtifactValue> {
        match self {
            Self::Kcc20(state) => state.authored(),
            Self::PublicMint(state) => state.authored(),
            Self::TokenSeed(state) => state.authored(),
        }
    }

    /// The KCC20 state inside, if this is one.
    pub fn as_kcc20(&self) -> Option<&Kcc20State> {
        match self {
            Self::Kcc20(state) => Some(state),
            _ => None,
        }
    }

    /// The KCC20 state inside, if this is one.
    pub fn as_kcc20_mut(&mut self) -> Option<&mut Kcc20State> {
        match self {
            Self::Kcc20(state) => Some(state),
            _ => None,
        }
    }

    /// The PublicMint state inside, if this is one.
    pub fn as_public_mint(&self) -> Option<&PublicMintState> {
        match self {
            Self::PublicMint(state) => Some(state),
            _ => None,
        }
    }

    /// The PublicMint state inside, if this is one.
    pub fn as_public_mint_mut(&mut self) -> Option<&mut PublicMintState> {
        match self {
            Self::PublicMint(state) => Some(state),
            _ => None,
        }
    }

    /// The TokenSeed state inside, if this is one.
    pub fn as_token_seed(&self) -> Option<&TokenSeedState> {
        match self {
            Self::TokenSeed(state) => Some(state),
            _ => None,
        }
    }

    /// The TokenSeed state inside, if this is one.
    pub fn as_token_seed_mut(&mut self) -> Option<&mut TokenSeedState> {
        match self {
            Self::TokenSeed(state) => Some(state),
            _ => None,
        }
    }
}

impl From<Kcc20State> for State {
    fn from(state: Kcc20State) -> Self {
        Self::Kcc20(state)
    }
}

impl From<PublicMintState> for State {
    fn from(state: PublicMintState) -> Self {
        Self::PublicMint(state)
    }
}

impl From<TokenSeedState> for State {
    fn from(state: TokenSeedState) -> Self {
        Self::TokenSeed(state)
    }
}

/// The value of a list of KCC20 states as the codec expects a `KCC20State[]` argument:
/// an array of records.
pub fn kcc20_states_value(states: &[Kcc20State]) -> ArtifactValue {
    ArtifactValue::Array(
        states
            .iter()
            .map(|state| ArtifactValue::Object(state.authored()))
            .collect(),
    )
}

/// The value of one KCC20 state as the codec expects a `KCC20State` argument: a record.
pub fn kcc20_state_value(state: &Kcc20State) -> ArtifactValue {
    ArtifactValue::Object(state.authored())
}
