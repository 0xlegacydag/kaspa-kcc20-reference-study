//! Ordinary coins for test transactions: fixed keys, the three standard lock scripts, and
//! signatures for one input at a time.
//!
//! Nothing here touches another input. `kaspa_consensus_core::sign::sign` is not used: it
//! overwrites the signature script and the compute commitment of every input
//! (rusty-kaspa a41a333 consensus/core/src/sign.rs:83-103). Schnorr signatures are made
//! without auxiliary randomness, so the same key and transaction always give the same
//! bytes.
//!
//! The keys are derived from one byte and are public knowledge. Test use only.

use kaspa_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_ecdsa_signature_hash, calc_schnorr_signature_hash},
        sighash_type::SigHashType,
    },
    tx::{ScriptPublicKey, VerifiableTransaction},
};
use kaspa_txscript::{
    EngineFlags,
    opcodes::codes::{OpCheckSig, OpCheckSigECDSA, OpData32, OpData33},
    pay_to_script_hash_script,
    script_builder::{ScriptBuilder, ScriptBuilderResult},
};
use secp256k1::{Keypair, Message, SECP256K1, SecretKey};

/// A key pair derived from one seed byte.
#[derive(Clone, Debug)]
pub struct TestKey {
    keypair: Keypair,
}

impl TestKey {
    /// The key for `seed`: the secret key is the byte `0x01` followed by 31 copies of
    /// `seed`, which is a valid secp256k1 scalar for every seed.
    pub fn from_seed(seed: u8) -> Self {
        let mut secret = [seed; 32];
        secret[0] = 0x01;
        let keypair = Keypair::from_seckey_slice(SECP256K1, &secret).expect("a scalar starting with 0x01 is below the group order");
        Self { keypair }
    }

    /// The 32 secret key bytes.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.keypair.secret_bytes()
    }

    /// The 32-byte x-only public key used by Schnorr pay-to-pubkey scripts.
    pub fn schnorr_public_key(&self) -> [u8; 32] {
        self.keypair.x_only_public_key().0.serialize()
    }

    /// The 33-byte compressed public key used by ECDSA pay-to-pubkey scripts.
    pub fn ecdsa_public_key(&self) -> [u8; 33] {
        self.keypair.public_key().serialize()
    }

    /// Schnorr pay-to-pubkey lock: `OpData32 <x-only key> OpCheckSig`, 34 bytes, version 0
    /// (crypto/txscript/src/standard.rs:19-23, script_class.rs:59-63).
    pub fn p2pk_script_public_key(&self) -> ScriptPublicKey {
        let mut script = Vec::with_capacity(34);
        script.push(OpData32);
        script.extend_from_slice(&self.schnorr_public_key());
        script.push(OpCheckSig);
        ScriptPublicKey::from_vec(0, script)
    }

    /// ECDSA pay-to-pubkey lock: `OpData33 <compressed key> OpCheckSigECDSA`, 35 bytes,
    /// version 0 (standard.rs:26-30, script_class.rs:68-72).
    pub fn p2pk_ecdsa_script_public_key(&self) -> ScriptPublicKey {
        let mut script = Vec::with_capacity(35);
        script.push(OpData33);
        script.extend_from_slice(&self.ecdsa_public_key());
        script.push(OpCheckSigECDSA);
        ScriptPublicKey::from_vec(0, script)
    }

    /// The 65-byte signature item for one input: a 64-byte Schnorr signature over the
    /// input's sighash followed by the sighash type byte
    /// (`calc_schnorr_signature_hash`, consensus/core/src/hashing/sighash.rs:245-280).
    pub fn schnorr_signature(&self, tx: &impl VerifiableTransaction, input_index: usize, hash_type: SigHashType) -> Vec<u8> {
        let reused_values = SigHashReusedValuesUnsync::new();
        let hash = calc_schnorr_signature_hash(tx, input_index, hash_type, &reused_values);
        let message = Message::from_digest(hash.as_bytes());
        let signature = SECP256K1.sign_schnorr_no_aux_rand(&message, &self.keypair);
        let mut item = signature.as_ref().to_vec();
        item.push(hash_type.to_u8());
        item
    }

    /// The 65-byte signature item for one input: a 64-byte compact ECDSA signature over
    /// the input's ECDSA sighash followed by the sighash type byte
    /// (`calc_ecdsa_signature_hash`, sighash.rs:282-292). Deterministic (RFC 6979).
    pub fn ecdsa_signature(&self, tx: &impl VerifiableTransaction, input_index: usize, hash_type: SigHashType) -> Vec<u8> {
        let reused_values = SigHashReusedValuesUnsync::new();
        let hash = calc_ecdsa_signature_hash(tx, input_index, hash_type, &reused_values);
        let message = Message::from_digest(hash.as_bytes());
        let secret_key = SecretKey::from_keypair(&self.keypair);
        let signature = SECP256K1.sign_ecdsa(&message, &secret_key);
        let mut item = signature.serialize_compact().to_vec();
        item.push(hash_type.to_u8());
        item
    }

    /// The complete signature script that spends a Schnorr pay-to-pubkey coin: one push
    /// of the signature item, 66 bytes.
    pub fn p2pk_signature_script(&self, tx: &impl VerifiableTransaction, input_index: usize, hash_type: SigHashType) -> Vec<u8> {
        push_data(&self.schnorr_signature(tx, input_index, hash_type))
    }

    /// The complete signature script that spends an ECDSA pay-to-pubkey coin: one push
    /// of the signature item, 66 bytes.
    pub fn p2pk_ecdsa_signature_script(&self, tx: &impl VerifiableTransaction, input_index: usize, hash_type: SigHashType) -> Vec<u8> {
        push_data(&self.ecdsa_signature(tx, input_index, hash_type))
    }
}

/// The flags scripts are built with: post-Toccata limits, so that a push longer than 520
/// bytes is accepted by the script builder (crypto/txscript/src/script_builder.rs:184-201).
pub fn builder_flags() -> EngineFlags {
    EngineFlags { covenants_enabled: true, ..Default::default() }
}

/// A script fragment that pushes `data` as one item, in the canonical encoding.
///
/// Panics when `data` is longer than the engine's element limit of 1,000,000 bytes.
pub fn push_data(data: &[u8]) -> Vec<u8> {
    try_push_data(data).expect("an item within the element size limit")
}

/// Like `push_data`, returning the builder's error instead of panicking.
pub fn try_push_data(data: &[u8]) -> ScriptBuilderResult<Vec<u8>> {
    Ok(ScriptBuilder::with_flags(builder_flags()).add_data(data)?.drain())
}

/// Pay-to-script-hash lock for `redeem_script`: `OpBlake2b OpData32 <hash> OpEqual`,
/// 35 bytes, version 0 (`pay_to_script_hash_script`, standard.rs:51-55).
pub fn p2sh_script_public_key(redeem_script: &[u8]) -> ScriptPublicKey {
    pay_to_script_hash_script(redeem_script)
}

/// The signature script that spends a pay-to-script-hash coin: `arguments` copied as they
/// are (already encoded pushes), then one push of the redeem script.
pub fn p2sh_signature_script(arguments: &[u8], redeem_script: &[u8]) -> Vec<u8> {
    let mut script = arguments.to_vec();
    script.extend_from_slice(&push_data(redeem_script));
    script
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_txscript::script_class::ScriptClass;

    #[test]
    fn keys_are_fixed_and_distinct() {
        let a = TestKey::from_seed(1);
        let b = TestKey::from_seed(2);
        assert_eq!(a.secret_bytes()[0], 0x01);
        assert_eq!(a.secret_bytes()[1..], [1u8; 31]);
        assert_eq!(a.schnorr_public_key(), TestKey::from_seed(1).schnorr_public_key());
        assert_ne!(a.schnorr_public_key(), b.schnorr_public_key());
        // Every seed gives a valid key.
        for seed in 0..=u8::MAX {
            let _ = TestKey::from_seed(seed);
        }
    }

    #[test]
    fn lock_scripts_have_the_standard_classes() {
        let key = TestKey::from_seed(7);
        assert_eq!(ScriptClass::from_script(&key.p2pk_script_public_key()), ScriptClass::PubKey);
        assert_eq!(key.p2pk_script_public_key().script().len(), 34);
        assert_eq!(ScriptClass::from_script(&key.p2pk_ecdsa_script_public_key()), ScriptClass::PubKeyECDSA);
        assert_eq!(key.p2pk_ecdsa_script_public_key().script().len(), 35);
        assert_eq!(ScriptClass::from_script(&p2sh_script_public_key(&[0x51])), ScriptClass::ScriptHash);
    }

    #[test]
    fn pushes_are_canonical() {
        assert_eq!(push_data(&[]), vec![0x00]);
        assert_eq!(push_data(&[0x51]), vec![0x01, 0x51]);
        assert_eq!(push_data(&[0xaa; 65])[0], 0x41);
        // 600 bytes need OpPushData2; the default builder flags would refuse them.
        let long = push_data(&[0xbb; 600]);
        assert_eq!(&long[..3], &[0x4d, 0x58, 0x02]);
        assert_eq!(p2sh_signature_script(&[0x51], &[0x52]), vec![0x51, 0x01, 0x52]);
    }
}
