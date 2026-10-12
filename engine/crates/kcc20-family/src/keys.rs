//! Fixed keys and deterministic signatures.
//!
//! Every key is derived from one seed byte: the secret key is that byte repeated 32 times, as
//! in the reference's own examples (kcc20-reference c8a0871 src/bin/kcc20/support.rs:15-19).
//! These keys are public knowledge and exist only for synthetic coins.
//!
//! Signatures are deterministic: Schnorr signatures are made without auxiliary randomness
//! and ECDSA signatures follow RFC 6979, so the same scenario always assembles to the same
//! bytes.
//!
//! One exception to "every key is a repeated byte": [`register_key`] puts a secret key the
//! caller read from elsewhere behind a seed byte, which is then only a handle. Everything
//! that takes a seed ([`keypair`], [`x_only`], the witnesses) uses the registered key from
//! then on.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use kaspa_consensus_core::hashing::sighash::{
    SigHashReusedValuesUnsync, calc_ecdsa_signature_hash, calc_schnorr_signature_hash,
};
use kaspa_consensus_core::hashing::sighash_type::SigHashType;
use kaspa_consensus_core::tx::{MutableTransaction, Transaction};
use secp256k1::{All, Keypair, Message, SECP256K1, Secp256k1, SecretKey};

/// Seed of the first demo owner.
pub const ALICE: u8 = 0xaa;
/// Seed of the second demo owner.
pub const BOB: u8 = 0xbb;
/// Seed of the key used for borrow guards and as a "wrong key".
pub const CAROL: u8 = 0xcc;
/// Seed of a second spare key.
pub const DAVE: u8 = 0xdd;
/// Seed of the key that owns the funding coin of the realistic value profile.
pub const FUNDER: u8 = 0xf5;

/// The process-wide signing and verification context.
fn secp() -> &'static Secp256k1<All> {
    SECP256K1
}

/// The seeds with a fixed meaning in the checks. No key can be registered behind them.
const FIXED_SEEDS: [u8; 5] = [ALICE, BOB, CAROL, DAVE, FUNDER];

/// The keys registered behind a handle, for the whole process.
static REGISTERED: Mutex<BTreeMap<u8, SecretKey>> = Mutex::new(BTreeMap::new());

/// Puts `secret_key` behind `handle`: from now on [`keypair`]`(handle)` is the pair of that
/// key instead of the pair of the repeated byte, in every thread of the process.
///
/// This is for a run that signs with keys read from files, where the rest of the crate
/// still addresses keys by a seed byte. The key is kept in memory until the process ends, in
/// a table that is one for the whole process: any code in the process that calls
/// [`keypair`]`(handle)` gets the key pair, and a key pair gives out its secret key. Nothing
/// in this crate prints a registered key or stores it anywhere else.
///
/// Registering the same key behind the same handle again changes nothing.
///
/// # Panics
///
/// Panics when `handle` is one of the fixed seeds ([`ALICE`], [`BOB`], [`CAROL`], [`DAVE`],
/// [`FUNDER`]), and when the handle already holds a different key. Neither message shows a
/// key.
pub fn register_key(handle: u8, secret_key: SecretKey) {
    assert!(
        !FIXED_SEEDS.contains(&handle),
        "handle {handle:#04x} is a fixed seed of the checks; no key can be registered behind it"
    );
    let mut registered = REGISTERED.lock().unwrap_or_else(PoisonError::into_inner);
    let differs = registered
        .get(&handle)
        .is_some_and(|held| *held != secret_key);
    if differs {
        // The guard is released first, so that the table is not left poisoned.
        drop(registered);
        panic!("handle {handle:#04x} already holds a different key");
    }
    registered.insert(handle, secret_key);
}

/// The key pair behind `seed`: the registered key when [`register_key`] was called for this
/// byte, otherwise the pair whose secret key is `seed` repeated 32 times.
///
/// # Panics
///
/// Panics for seed 0 without a registered key: a repeated zero byte is not a valid secret key.
pub fn keypair(seed: u8) -> Keypair {
    let registered = REGISTERED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&seed)
        .copied();
    let secret_key = registered.unwrap_or_else(|| {
        SecretKey::from_slice(&[seed; 32]).expect("a repeated non-zero byte is a valid secret key")
    });
    Keypair::from_secret_key(secp(), &secret_key)
}

/// The 32-byte x-only public key of [`keypair`]`(seed)`: the form Schnorr checks use.
pub fn x_only(seed: u8) -> [u8; 32] {
    keypair(seed).x_only_public_key().0.serialize()
}

/// The 33-byte compressed public key of [`keypair`]`(seed)`: the form ECDSA checks use.
pub fn compressed(seed: u8) -> [u8; 33] {
    keypair(seed).public_key().serialize()
}

/// What a signing closure sees: the finished transaction without signature scripts, with the
/// coins it spends, and the index of the input being signed.
///
/// For a version-1 transaction the signature hash covers neither signature scripts nor compute
/// budgets (rusty-kaspa a41a333 consensus/core/src/hashing/sighash.rs:245-280), so a signature
/// made here stays valid when those are filled in afterwards.
#[derive(Clone, Copy)]
pub struct SigningContext<'a> {
    pub tx: &'a MutableTransaction<Transaction>,
    pub input_index: usize,
}

/// A 64-byte Schnorr signature of the input by `key`, over the signature hash of the given
/// type, without the trailing type byte.
pub fn schnorr_signature_bytes(
    ctx: &SigningContext<'_>,
    key: &Keypair,
    hash_type: SigHashType,
) -> [u8; 64] {
    let digest = calc_schnorr_signature_hash(
        &ctx.tx.as_verifiable(),
        ctx.input_index,
        hash_type,
        &SigHashReusedValuesUnsync::new(),
    );
    let message = Message::from_digest(digest.as_bytes());
    *secp().sign_schnorr_no_aux_rand(&message, key).as_ref()
}

/// A Schnorr signature as scripts expect it: 64 signature bytes followed by the signature
/// hash type byte (65 bytes).
pub fn schnorr_signature(
    ctx: &SigningContext<'_>,
    key: &Keypair,
    hash_type: SigHashType,
) -> Vec<u8> {
    let mut signature = schnorr_signature_bytes(ctx, key, hash_type).to_vec();
    signature.push(hash_type.to_u8());
    signature
}

/// A 64-byte compact ECDSA signature of the input by `key`, without the trailing type byte.
pub fn ecdsa_signature_bytes(
    ctx: &SigningContext<'_>,
    key: &Keypair,
    hash_type: SigHashType,
) -> [u8; 64] {
    let digest = calc_ecdsa_signature_hash(
        &ctx.tx.as_verifiable(),
        ctx.input_index,
        hash_type,
        &SigHashReusedValuesUnsync::new(),
    );
    let message = Message::from_digest(digest.as_bytes());
    secp()
        .sign_ecdsa(&message, &key.secret_key())
        .serialize_compact()
}

/// An ECDSA signature as scripts expect it: 64 compact bytes followed by the signature hash
/// type byte (65 bytes).
pub fn ecdsa_signature(ctx: &SigningContext<'_>, key: &Keypair, hash_type: SigHashType) -> Vec<u8> {
    let mut signature = ecdsa_signature_bytes(ctx, key, hash_type).to_vec();
    signature.push(hash_type.to_u8());
    signature
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A secret key that is not a repeated byte: BLAKE3 of a label.
    fn made_up(label: &str) -> SecretKey {
        SecretKey::from_slice(blake3::hash(label.as_bytes()).as_bytes())
            .expect("a hash is a valid secret key")
    }

    fn repeated(seed: u8) -> [u8; 32] {
        let secret_key = SecretKey::from_slice(&[seed; 32]).expect("a valid secret key");
        Keypair::from_secret_key(secp(), &secret_key)
            .x_only_public_key()
            .0
            .serialize()
    }

    // Every test of this module uses handles of its own: the table is one per process.

    #[test]
    fn an_unregistered_seed_is_the_repeated_byte() {
        for seed in [ALICE, BOB, CAROL, DAVE, FUNDER, 0x01, 0x15, 0xfe] {
            assert_eq!(x_only(seed), repeated(seed), "seed {seed:#04x}");
        }
    }

    #[test]
    fn a_registered_key_replaces_the_repeated_byte_for_its_handle_only() {
        let key = made_up("keys: a registered key");
        let expected = Keypair::from_secret_key(secp(), &key)
            .x_only_public_key()
            .0
            .serialize();
        assert_eq!(x_only(0x71), repeated(0x71));
        register_key(0x71, key);
        assert_eq!(x_only(0x71), expected);
        assert_eq!(&compressed(0x71)[1..], &expected[..]);
        assert_ne!(x_only(0x71), repeated(0x71));
        assert_eq!(x_only(0x72), repeated(0x72));
        // The same key once more is not an error.
        register_key(0x71, key);
        assert_eq!(x_only(0x71), expected);
    }

    #[test]
    #[should_panic(expected = "already holds a different key")]
    fn a_handle_cannot_change_its_key() {
        register_key(0x73, made_up("keys: the first key"));
        register_key(0x73, made_up("keys: the second key"));
    }

    #[test]
    #[should_panic(expected = "is a fixed seed of the checks")]
    fn a_fixed_seed_cannot_be_registered() {
        register_key(CAROL, made_up("keys: a key for a fixed seed"));
    }

    #[test]
    fn a_refused_registration_leaves_the_table_usable() {
        register_key(0x74, made_up("keys: kept"));
        let refused = std::panic::catch_unwind(|| register_key(0x74, made_up("keys: refused")));
        assert!(refused.is_err());
        register_key(0x75, made_up("keys: after the refusal"));
        assert_ne!(x_only(0x75), repeated(0x75));
    }
}
