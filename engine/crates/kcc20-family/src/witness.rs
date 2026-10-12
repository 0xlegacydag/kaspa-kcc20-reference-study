//! The witnesses of the KCC-20 owner and borrow schemes.
//!
//! A leader (`KCC20.transfer`) starts its witness with a path byte; a delegate
//! (`KCC20.transfer_delegator`) gives the owner witness alone
//! (kcc20-reference c8a0871 contracts/kcc20.ag:122-127, 188-195). Layouts
//! (kcc20.ag:45-74, 132-165):
//!
//! | scheme | witness after the path byte |
//! |---|---|
//! | owner 0x00, key | Schnorr signature 64 + type byte |
//! | owner 0x01, hash of an x-only key | key 32, signature 65 |
//! | owner 0x02, hash of a compressed key | key 33, ECDSA signature 64 + type byte |
//! | owner 0x03, script hash | one byte: index of the authority input |
//! | owner 0x04, covenant id | nothing |
//! | borrow 0x01, threshold | nothing |
//! | borrow 0x02, signature | Schnorr signature 65 by the guard key |
//! | borrow 0x03, hash chain | next guard 32, one-time key 32, signature 65 |
//!
//! Every function returns [`LateBytes`]: the signature is made when the scenario is
//! assembled, over the finished transaction. To damage a witness, use [`LateBytes::map`].

use kaspa_consensus_core::hashing::sighash_type::SigHashType;

use crate::family::EntryRole;
use crate::keys::{self, ecdsa_signature, schnorr_signature};
use crate::scenario::LateBytes;
use crate::states::{PATH_BORROW, PATH_NORMAL};

/// BLAKE3 of a public key: the `owner` field of the two key-hash owner schemes
/// (kcc20.ag:36-38). Plain BLAKE3, no key and no domain.
pub fn public_key_hash(public_key: &[u8]) -> [u8; 32] {
    *blake3::hash(public_key).as_bytes()
}

/// The hash-chain guard that commits to the next guard and to the one-time key that may
/// advance it: BLAKE3(next guard, x-only key) (kcc20.ag:160-164).
pub fn chain_guard_for_key(next_guard: &[u8; 32], x_only_key: &[u8; 32]) -> [u8; 32] {
    let mut preimage = next_guard.to_vec();
    preimage.extend(x_only_key);
    *blake3::hash(&preimage).as_bytes()
}

/// [`chain_guard_for_key`] for the fixed key with the given seed.
pub fn chain_guard(next_guard: &[u8; 32], key_seed: u8) -> [u8; 32] {
    chain_guard_for_key(next_guard, &keys::x_only(key_seed))
}

/// The path byte a leader puts in front of an owner witness; a delegate puts nothing.
fn owner_prefix(role: EntryRole) -> Vec<u8> {
    match role {
        EntryRole::Leader => vec![PATH_NORMAL],
        EntryRole::Delegate => Vec::new(),
    }
}

/// A bare 65-byte Schnorr signature by the key of `key_seed`: a `sig` argument of the reclaim
/// entries, or the signature script payload of a pay-to-public-key coin.
pub fn signature(key_seed: u8, hash_type: SigHashType) -> LateBytes {
    LateBytes::from_tx(move |ctx| schnorr_signature(ctx, &keys::keypair(key_seed), hash_type))
}

/// Owner scheme 0x00: a Schnorr signature by the owner key.
pub fn owner_key(key_seed: u8, role: EntryRole, hash_type: SigHashType) -> LateBytes {
    LateBytes::from_tx(move |ctx| {
        let mut witness = owner_prefix(role);
        witness.extend(schnorr_signature(ctx, &keys::keypair(key_seed), hash_type));
        witness
    })
}

/// Owner scheme 0x01: the x-only public key and a Schnorr signature by it.
pub fn owner_key_hash_schnorr(key_seed: u8, role: EntryRole, hash_type: SigHashType) -> LateBytes {
    LateBytes::from_tx(move |ctx| {
        let mut witness = owner_prefix(role);
        witness.extend(keys::x_only(key_seed));
        witness.extend(schnorr_signature(ctx, &keys::keypair(key_seed), hash_type));
        witness
    })
}

/// Owner scheme 0x02: the compressed public key and an ECDSA signature by it.
pub fn owner_key_hash_ecdsa(key_seed: u8, role: EntryRole, hash_type: SigHashType) -> LateBytes {
    LateBytes::from_tx(move |ctx| {
        let mut witness = owner_prefix(role);
        witness.extend(keys::compressed(key_seed));
        witness.extend(ecdsa_signature(ctx, &keys::keypair(key_seed), hash_type));
        witness
    })
}

/// Owner scheme 0x03: the index of the input that spends the authority script.
pub fn owner_script_hash(authority_input_index: u8, role: EntryRole) -> LateBytes {
    let mut witness = owner_prefix(role);
    witness.push(authority_input_index);
    LateBytes::Fixed(witness)
}

/// Owner scheme 0x04: nothing after the path byte.
pub fn owner_covenant_id(role: EntryRole) -> LateBytes {
    LateBytes::Fixed(owner_prefix(role))
}

/// Borrow scheme 0x01: the path byte alone.
pub fn borrow_threshold() -> LateBytes {
    LateBytes::Fixed(vec![PATH_BORROW])
}

/// Borrow scheme 0x02: a Schnorr signature by the guard key.
pub fn borrow_signature(key_seed: u8, hash_type: SigHashType) -> LateBytes {
    LateBytes::from_tx(move |ctx| {
        let mut witness = vec![PATH_BORROW];
        witness.extend(schnorr_signature(ctx, &keys::keypair(key_seed), hash_type));
        witness
    })
}

/// Borrow scheme 0x03: the next guard, the one-time key and a Schnorr signature by it.
pub fn borrow_hash_chain(next_guard: [u8; 32], key_seed: u8, hash_type: SigHashType) -> LateBytes {
    LateBytes::from_tx(move |ctx| {
        let mut witness = vec![PATH_BORROW];
        witness.extend(next_guard);
        witness.extend(keys::x_only(key_seed));
        witness.extend(schnorr_signature(ctx, &keys::keypair(key_seed), hash_type));
        witness
    })
}
