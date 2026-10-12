//! The three contracts of the KCC-20 reference as one family.
//!
//! A [`Family`] answers, for KCC20, PublicMint and TokenSeed: what is the bytecode, where is
//! the state inside it, what is the template hash, what is the redeem script and the script
//! public key of a coin with a given state, and what are the bytes of a call.
//!
//! The contracts refer to each other only through template hashes: every state starts with
//! `gen__kcc20_template`, PublicMint and TokenSeed also carry their own hash, and
//! `PublicMint.mint` / `TokenSeed.create` receive the KCC20 prefix and suffix as two hidden
//! arguments. That is why one contract's bytecode can be replaced (see
//! [`Family::with_bytecode`]) and the family stays consistent without recompiling anything:
//! the new hash flows into the state fields and the hidden arguments.
//!
//! What is taken from Argent and SilverScript: the artifact types and the codec (encoding of
//! states and of call arguments). What is written here: everything that decides which bytes
//! go where.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::OnceLock;

use argent::artifact::{
    Artifact, HiddenParamPurposeArtifact, HiddenParamSubjectArtifact, RuntimeFieldRoleArtifact,
    SilAbiArtifact, SilContractArtifact, SilEntryArtifact, template_hash,
};
use argent::codec::{ArtifactValue, encode_entry_sig_script, encode_runtime_state_script};
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_txscript::pay_to_script_hash_script;

use crate::error::{Error, Result};
use crate::raw::{self, CallParts};
use crate::refdata;
use crate::states::State;

/// One of the three contracts of the reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Contract {
    Kcc20,
    PublicMint,
    TokenSeed,
}

impl Contract {
    /// The three contracts, in the order used for indexing.
    pub const ALL: [Contract; 3] = [Contract::Kcc20, Contract::PublicMint, Contract::TokenSeed];

    /// Name of the contract in the artifact.
    pub fn name(self) -> &'static str {
        match self {
            Self::Kcc20 => "KCC20",
            Self::PublicMint => "PublicMint",
            Self::TokenSeed => "TokenSeed",
        }
    }

    /// File name of the generated SilverScript source in `fixtures/public-mint/sil`.
    pub fn sil_file_name(self) -> &'static str {
        match self {
            Self::Kcc20 => "KCC20.sil",
            Self::PublicMint => "PublicMint.sil",
            Self::TokenSeed => "TokenSeed.sil",
        }
    }

    /// Prefix of the rule ids of this contract in the rule inventory (`K-01`, `M-01`, `S-01`).
    pub fn rule_prefix(self) -> char {
        match self {
            Self::Kcc20 => 'K',
            Self::PublicMint => 'M',
            Self::TokenSeed => 'S',
        }
    }

    /// Position of the contract in [`Contract::ALL`].
    pub fn index(self) -> usize {
        match self {
            Self::Kcc20 => 0,
            Self::PublicMint => 1,
            Self::TokenSeed => 2,
        }
    }

    /// The contract with the given artifact name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|contract| contract.name() == name)
    }
}

impl std::fmt::Display for Contract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Whether an entry leads its covenant group or joins one led by another input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryRole {
    Leader,
    Delegate,
}

/// One of the eleven entries of the three contracts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Entry {
    /// `KCC20.transfer`: the next states (`KCC20State[]`) and a witness (`byte[]`).
    Transfer,
    /// `KCC20.transfer_delegator`: a witness (`byte[]`).
    TransferDelegator,
    /// `PublicMint.mint`: the recipient state (`KCC20State`), plus two hidden arguments.
    Mint,
    /// `PublicMint.split`: the allowance to take (`int`) and the new owner (`pubkey`).
    MintSplit,
    /// `PublicMint.reclaim`: the owner's signature (`sig`).
    MintReclaim,
    /// `PublicMint.reclaim_into`: no arguments.
    MintReclaimInto,
    /// `PublicMint.reclaim_delegator`: the owner's signature (`sig`).
    MintReclaimDelegator,
    /// `TokenSeed.create`: the recipient state (`KCC20State`), plus two hidden arguments.
    SeedCreate,
    /// `TokenSeed.split`: the new owner (`pubkey`).
    SeedSplit,
    /// `TokenSeed.reclaim`: no arguments.
    SeedReclaim,
    /// `TokenSeed.reclaim_delegator`: the owner's signature (`sig`).
    SeedReclaimDelegator,
}

impl Entry {
    /// The eleven entries, in the order of the contracts and of their dispatchers.
    pub const ALL: [Entry; 11] = [
        Entry::Transfer,
        Entry::TransferDelegator,
        Entry::Mint,
        Entry::MintSplit,
        Entry::MintReclaim,
        Entry::MintReclaimInto,
        Entry::MintReclaimDelegator,
        Entry::SeedCreate,
        Entry::SeedSplit,
        Entry::SeedReclaim,
        Entry::SeedReclaimDelegator,
    ];

    /// The contract that declares the entry.
    pub fn contract(self) -> Contract {
        match self {
            Self::Transfer | Self::TransferDelegator => Contract::Kcc20,
            Self::Mint
            | Self::MintSplit
            | Self::MintReclaim
            | Self::MintReclaimInto
            | Self::MintReclaimDelegator => Contract::PublicMint,
            Self::SeedCreate | Self::SeedSplit | Self::SeedReclaim | Self::SeedReclaimDelegator => {
                Contract::TokenSeed
            }
        }
    }

    /// Name of the entry in the artifact.
    pub fn name(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::TransferDelegator => "transfer_delegator",
            Self::Mint => "mint",
            Self::MintSplit | Self::SeedSplit => "split",
            Self::MintReclaim | Self::SeedReclaim => "reclaim",
            Self::MintReclaimInto => "reclaim_into",
            Self::MintReclaimDelegator | Self::SeedReclaimDelegator => "reclaim_delegator",
            Self::SeedCreate => "create",
        }
    }

    /// Leader or delegate, as the sources declare it (`entry` or `delegate`).
    pub fn role(self) -> EntryRole {
        match self {
            Self::TransferDelegator | Self::MintReclaimDelegator | Self::SeedReclaimDelegator => {
                EntryRole::Delegate
            }
            _ => EntryRole::Leader,
        }
    }

    /// The entry of `contract` with the given artifact name.
    pub fn from_name(contract: Contract, name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|entry| entry.contract() == contract && entry.name() == name)
    }
}

impl std::fmt::Display for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.contract().name(), self.name())
    }
}

/// The three contracts with their bytecode, template hashes and ABI.
#[derive(Clone, Debug)]
pub struct Family {
    /// The artifact the family was made from. When a bytecode was replaced, its `sil_abi`
    /// carries the new bytecode and template hash and the rest of the artifact is stale.
    artifact: Artifact,
    /// The contracts whose bytecode was replaced, in the order of replacement.
    replaced: Vec<Contract>,
}

impl Family {
    /// The family of the published artifact, read once per process.
    ///
    /// # Panics
    ///
    /// Panics when the reference is not available; see [`refdata::pinned_artifact`].
    pub fn pinned() -> &'static Family {
        static FAMILY: OnceLock<Family> = OnceLock::new();
        FAMILY.get_or_init(|| {
            Family::from_artifact(refdata::pinned_artifact().clone()).unwrap_or_else(|error| {
                panic!("the pinned artifact does not describe the KCC-20 family: {error}")
            })
        })
    }

    /// A family over any artifact of the same application, for example one rebuilt from
    /// changed sources. Runs Argent's consistency check and requires the three contracts and
    /// their eleven entries.
    pub fn from_artifact(artifact: Artifact) -> Result<Self> {
        artifact.check_consistency()?;
        let family = Self {
            artifact,
            replaced: Vec::new(),
        };
        for contract in Contract::ALL {
            let abi = family
                .artifact
                .sil_abi
                .contract(contract.name())
                .ok_or(Error::MissingContract(contract.name()))?;
            let span_end = abi.compiled.state_span.offset + abi.compiled.state_span.len;
            if abi.compiled.bytecode.len() < span_end {
                return Err(Error::BytecodeTooShort {
                    contract: contract.name(),
                    len: abi.compiled.bytecode.len(),
                    span_end,
                });
            }
        }
        for entry in Entry::ALL {
            let contract = entry.contract();
            if family.contract_abi(contract).entry(entry.name()).is_none() {
                return Err(Error::MissingEntry {
                    contract: contract.name(),
                    entry: entry.name(),
                });
            }
        }
        Ok(family)
    }

    /// The same family with the bytecode of ONE contract replaced by the given bytes.
    ///
    /// The state span is kept, and the template hash of the contract is recomputed from the
    /// new bytes exactly as SilverScript does: BLAKE3 over the 8-byte length of the prefix,
    /// the prefix, the 8-byte length of the suffix and the suffix, where prefix and suffix are
    /// the bytes before and after the state span
    /// (silverscript 3ed9733 silverscript-abi/src/lib.rs:103-110, 301-304). The other
    /// contracts are not touched; they meet the new hash through their state fields and
    /// through the hidden arguments of `mint` and `create`.
    ///
    /// Two things the caller must know:
    ///
    /// - Every contract embeds its own prefix and suffix lengths as constants. A replacement
    ///   of another length makes those constants stale; a same-length patch does not.
    /// - The result is no longer an Argent artifact (its template plan and id describe the
    ///   old bytes), so [`Family::artifact`] returns `None` for it.
    pub fn with_bytecode(&self, contract: Contract, bytecode: Vec<u8>) -> Result<Self> {
        let mut family = self.clone();
        let compiled = &mut family
            .artifact
            .sil_abi
            .contracts
            .get_mut(contract.name())
            .ok_or(Error::MissingContract(contract.name()))?
            .compiled;
        let span_end = compiled.state_span.offset + compiled.state_span.len;
        if bytecode.len() < span_end {
            return Err(Error::BytecodeTooShort {
                contract: contract.name(),
                len: bytecode.len(),
                span_end,
            });
        }
        compiled.template_hash = template_hash(
            &bytecode[..compiled.state_span.offset],
            &bytecode[span_end..],
        );
        compiled.bytecode = bytecode;
        if !family.replaced.contains(&contract) {
            family.replaced.push(contract);
        }
        Ok(family)
    }

    /// The contracts whose bytecode was replaced by [`Family::with_bytecode`]: empty for a
    /// family made from an artifact, one contract after one replacement.
    pub fn replaced(&self) -> &[Contract] {
        &self.replaced
    }

    /// The Argent artifact behind the family, for use with Argent's own tools. `None` once a
    /// bytecode was replaced.
    pub fn artifact(&self) -> Option<&Artifact> {
        self.replaced.is_empty().then_some(&self.artifact)
    }

    /// The SilverScript ABI of the family: entries, parameters, state layouts, bytecode.
    pub fn abi(&self) -> &SilAbiArtifact {
        &self.artifact.sil_abi
    }

    /// The ABI of one contract.
    pub fn contract_abi(&self, contract: Contract) -> &SilContractArtifact {
        self.artifact
            .sil_abi
            .contract(contract.name())
            .expect("the family was checked to hold its three contracts")
    }

    /// The ABI of one entry: dispatch tag and parameters, hidden ones included.
    pub fn entry_abi(&self, entry: Entry) -> &SilEntryArtifact {
        self.contract_abi(entry.contract())
            .entry(entry.name())
            .expect("the family was checked to hold its eleven entries")
    }

    /// The compiled script of a contract with a zero-filled state.
    pub fn bytecode(&self, contract: Contract) -> &[u8] {
        &self.contract_abi(contract).compiled.bytecode
    }

    /// Byte range of the state inside the script of a contract.
    pub fn state_span(&self, contract: Contract) -> Range<usize> {
        let span = self.contract_abi(contract).compiled.state_span;
        span.offset..span.offset + span.len
    }

    /// The bytes of the script in front of the state.
    pub fn prefix(&self, contract: Contract) -> &[u8] {
        &self.bytecode(contract)[..self.state_span(contract).start]
    }

    /// The bytes of the script behind the state.
    pub fn suffix(&self, contract: Contract) -> &[u8] {
        &self.bytecode(contract)[self.state_span(contract).end..]
    }

    /// The template hash of a contract: the value the scripts compare against, and the value
    /// of the `gen__<contract>_template` state fields.
    pub fn template_hash(&self, contract: Contract) -> [u8; 32] {
        self.contract_abi(contract).compiled.template_hash
    }

    /// The four bytes that select an entry in the dispatcher of its contract.
    pub fn dispatch_tag(&self, entry: Entry) -> [u8; 4] {
        self.entry_abi(entry).dispatch_tag.into_bytes()
    }

    /// All fields of a state as the codec expects them: the authored fields plus the
    /// compiler-owned ones, each filled with the template hash of the contract the artifact
    /// names for it (argent 9a9f4b1 crates/argent-runtime/src/lib.rs:1510-1537 and
    /// crates/argent-artifact/src/lib.rs:1605-1615).
    pub fn runtime_state(&self, state: &State) -> Result<BTreeMap<String, ArtifactValue>> {
        let contract = state.contract();
        let mut values = state.authored();
        let plan = self
            .artifact
            .argent
            .template_plan
            .runtime_states
            .iter()
            .find(|plan| plan.contract == contract.name());
        for field in plan
            .map(|plan| plan.field_roles.as_slice())
            .unwrap_or_default()
        {
            let RuntimeFieldRoleArtifact::Template { contract: subject } = &field.role else {
                return Err(Error::Unsupported(format!(
                    "state field `{}` of `{contract}` has a role other than `template`",
                    field.name
                )));
            };
            let subject = Contract::from_name(subject).ok_or_else(|| {
                Error::Unsupported(format!(
                    "state field `{}` of `{contract}` names the unknown contract `{subject}`",
                    field.name
                ))
            })?;
            values.insert(
                field.name.clone(),
                ArtifactValue::Bytes(self.template_hash(subject).to_vec()),
            );
        }
        Ok(values)
    }

    /// The encoded state of a coin, as the SilverScript codec writes it
    /// (silverscript 3ed9733 silverscript-abi/src/lib.rs:518-538).
    pub fn state_bytes(&self, state: &State) -> Result<Vec<u8>> {
        let contract = self.contract_abi(state.contract());
        Ok(encode_runtime_state_script(
            self.abi(),
            &contract.runtime_state,
            &self.runtime_state(state)?,
        )?)
    }

    /// The redeem script of a coin: prefix, encoded state, suffix.
    pub fn redeem_script(&self, state: &State) -> Result<Vec<u8>> {
        let contract = state.contract();
        let state_bytes = self.state_bytes(state)?;
        let mut script = Vec::with_capacity(
            self.prefix(contract).len() + state_bytes.len() + self.suffix(contract).len(),
        );
        script.extend_from_slice(self.prefix(contract));
        script.extend_from_slice(&state_bytes);
        script.extend_from_slice(self.suffix(contract));
        Ok(script)
    }

    /// The script public key of a coin: pay-to-script-hash of its redeem script, version 0
    /// (rusty-kaspa a41a333 crypto/txscript/src/standard.rs:34-38, 51-55).
    pub fn script_public_key(&self, state: &State) -> Result<ScriptPublicKey> {
        Ok(pay_to_script_hash_script(&self.redeem_script(state)?))
    }

    /// The hidden arguments of an entry, in ABI order. Only `PublicMint.mint` and
    /// `TokenSeed.create` have any: the KCC20 prefix and suffix. Resolved as Argent's runtime
    /// does for an actor of the same application
    /// (argent 9a9f4b1 crates/argent-runtime/src/lib.rs:553-578, 860-867).
    pub fn hidden_args(&self, entry: Entry) -> Result<Vec<ArtifactValue>> {
        let contract = entry.contract();
        let actor = self
            .artifact
            .argent
            .actors
            .iter()
            .find(|actor| actor.abi.contract == contract.name());
        let Some(artifact_entry) = actor.and_then(|actor| {
            actor
                .entries
                .iter()
                .find(|candidate| candidate.abi.entry == entry.name())
        }) else {
            return Ok(Vec::new());
        };
        let mut args = Vec::with_capacity(artifact_entry.hidden_params.len());
        for hidden in &artifact_entry.hidden_params {
            let HiddenParamSubjectArtifact::Actor { actor: subject } = &hidden.subject else {
                return Err(Error::Unsupported(format!(
                    "hidden argument `{}` of `{entry}` is not about an actor",
                    hidden.name
                )));
            };
            let subject = self
                .artifact
                .argent
                .actors
                .iter()
                .find(|actor| &actor.name == subject)
                .and_then(|actor| Contract::from_name(&actor.abi.contract))
                .ok_or_else(|| {
                    Error::Unsupported(format!(
                        "hidden argument `{}` of `{entry}` names an unknown actor",
                        hidden.name
                    ))
                })?;
            args.push(match hidden.purpose {
                HiddenParamPurposeArtifact::TemplatePrefixBytes => {
                    ArtifactValue::Bytes(self.prefix(subject).to_vec())
                }
                HiddenParamPurposeArtifact::TemplateSuffixBytes => {
                    ArtifactValue::Bytes(self.suffix(subject).to_vec())
                }
                HiddenParamPurposeArtifact::TemplatePrefixLen => {
                    ArtifactValue::Int(self.prefix(subject).len() as i64)
                }
                HiddenParamPurposeArtifact::TemplateSuffixLen => {
                    ArtifactValue::Int(self.suffix(subject).len() as i64)
                }
                HiddenParamPurposeArtifact::TemplateHash => {
                    ArtifactValue::Bytes(self.template_hash(subject).to_vec())
                }
                other => {
                    return Err(Error::Unsupported(format!(
                        "hidden argument `{}` of `{entry}` has the purpose {other:?}",
                        hidden.name
                    )));
                }
            });
        }
        Ok(args)
    }

    /// The bytes of a call in front of the redeem script: one or more pushes per argument
    /// (the user arguments followed by the hidden ones), then the push of the dispatch tag.
    /// Encoded by the SilverScript codec (silverscript 3ed9733
    /// silverscript-abi/src/lib.rs:483-516), in the order Argent's runtime uses
    /// (argent 9a9f4b1 crates/argent-runtime/src/resolve.rs:680-701).
    ///
    /// The codec refuses values that do not fit the parameter types (a signature that is not
    /// 65 bytes long, for example). Bytes it refuses to produce are written with [`crate::raw`].
    pub fn call_bytes(&self, entry: Entry, user_args: &[ArtifactValue]) -> Result<Vec<u8>> {
        let contract = entry.contract();
        let mut args = user_args.to_vec();
        args.extend(self.hidden_args(entry)?);
        Ok(encode_entry_sig_script(
            self.abi(),
            contract.name(),
            self.contract_abi(contract),
            entry.name(),
            self.entry_abi(entry),
            &args,
        )?)
    }

    /// The same call split into its parts: every argument push, the tag push, and the
    /// canonical push of the given redeem script. Each part can then be changed by hand.
    pub fn call_parts(
        &self,
        entry: Entry,
        user_args: &[ArtifactValue],
        redeem_script: &[u8],
    ) -> Result<CallParts> {
        let mut pushes = raw::split_pushes(&self.call_bytes(entry, user_args)?)?;
        let tag = pushes
            .pop()
            .ok_or_else(|| Error::Script("the codec produced an empty call".to_string()))?;
        Ok(CallParts {
            arguments: pushes,
            tag,
            redeem: raw::push_redeem(redeem_script)?,
        })
    }

    /// The whole signature script of a contract input: the call bytes followed by the
    /// canonical push of the redeem script of the coin being spent
    /// (rusty-kaspa a41a333 crypto/txscript/src/standard.rs:63-70, with the covenant flags
    /// that lift the 520-byte element limit).
    pub fn signature_script(
        &self,
        entry: Entry,
        user_args: &[ArtifactValue],
        coin_state: &State,
    ) -> Result<Vec<u8>> {
        let mut script = self.call_bytes(entry, user_args)?;
        script.extend(raw::push_redeem(&self.redeem_script(coin_state)?)?);
        Ok(script)
    }
}
