//! Signatures on the script engine: what each of the eight signature rules of the three
//! contracts answers to signature material that is empty, malformed, misplaced or stale.
//!
//! The eight rules and the eleven places they are compiled to:
//!
//! | Rule | Entry | Key |
//! |---|---|---|
//! | K-38 | `KCC20.transfer`, `transfer_delegator` | the coin's owner field |
//! | K-41 | `KCC20.transfer`, `transfer_delegator` | x-only key in the witness (K-40) |
//! | K-44 | `KCC20.transfer`, `transfer_delegator` | compressed key in the witness (K-43) |
//! | K-52 | `KCC20.transfer`, borrow path | the coin's borrow guard |
//! | K-55 | `KCC20.transfer`, borrow path | one-time key in the witness (K-54) |
//! | M-35 | `PublicMint.reclaim` | the minter's owner field |
//! | M-57 | `PublicMint.reclaim_delegator` | the minter's owner field |
//! | S-43 | `TokenSeed.reclaim_delegator` | the seed's owner field |
//!
//! An earlier suite of checks, not published here, ran these rules on a debug engine that
//! was handed typed arguments. The script engine treats an empty signature differently from
//! every other signature: the check pushes false without looking at the key and without the
//! charge of a signature check.
//!
//! Every case starts from an honest transaction of the realistic value profile: 10 KAS
//! coins, a funding coin spent with a real signature, change, and a fee a default mempool
//! takes. So every transaction has a second input and a change output, and the honest
//! transaction of each of the eleven places passes the consensus rules of a submission and
//! the policy of a default mempool. Only the signature material of one input is replaced;
//! signatures of the other inputs are made after the change. A refused case is a twin: the
//! honest transaction is accepted, a node gets to the scripts of both sides, the named input
//! is refused as stated and every other input still passes.
//!
//! For every case the script units of the input are recorded. A signature check costs
//! 100,000 units and every honest input here uses less than 200,000, so the units say
//! whether the engine charged the check: it does so after reading the type byte and before
//! it parses key and signature, and not at all for an empty signature.
//!
//! The groups:
//!
//! - (a) the empty signature, also on a coin whose owner field is no key;
//! - (b) other lengths, zero bytes, numbers out of range, and type bytes: the ones outside
//!   the six the engine knows, and one of the six that is not the type that was signed;
//! - (c) a valid signature of another key, for another input, made before an output
//!   changed, or made by the other signature scheme;
//! - (d) ECDSA: the parity of the key, strings that are no key, an altered signature;
//! - (e) the key hash that binds a key in the witness to the coin;
//! - (f) the hash chain: a key that is not the one of the link, a link shown twice;
//! - (g) owner scheme 0x03: the signature is asked for by the script of the authority coin,
//!   an ordinary input of its own.
//!
//! Nothing is accepted but the honest controls, each with a correct signature of the key
//! that is asked for. The last test writes all observations to `signature-matrix.json` next
//! to the result files.

use std::sync::OnceLock;

use checks::{Case, Expected, Outcome, results};
use kaspa_consensus_core::hashing::sighash_type::{SIG_HASH_ALL, SIG_HASH_NONE, SigHashType};
use kaspa_consensus_core::tx::MutableTransaction;
use kaspa_txscript::{opcodes::codes::OpCheckSig, pay_to_script_hash_script};
use kcc20_family::{
    EntryRole, Family, Scenario,
    keys::{self, ALICE, BOB, CAROL, DAVE, SigningContext},
    raw,
    scenario::LateBytes,
    shapes::{self, BorrowKind, CHAIN_NEXT_GUARD, Profile, Realistic},
    states::{OWNER_P2PKH_ECDSA, OWNER_P2PKH_SCHNORR, OWNER_P2SH, PATH_BORROW, PATH_NORMAL},
    witness,
};
use node_gate::ErrorClass;
use serde::Serialize;

/// Script units of one signature check on every network
/// (rusty-kaspa a41a333 crypto/txscript/src/lib.rs:130-135).
const SIGNATURE_CHECK_UNITS: u64 = 100_000;

/// The signature scheme of a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum Scheme {
    Schnorr,
    Ecdsa,
}

/// Where the input of a site stops when its signature is not 65 bytes long.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OtherLength {
    /// At the signature rule itself: an error of the engine at the signature opcode, or for
    /// the empty signature the failed verify of the rule.
    SignatureRule,
    /// At this rule of the entry's body, which fixes the length of the witness.
    Witness(&'static str),
    /// At this argument size check of the entry.
    Argument(&'static str),
}

impl OtherLength {
    /// The rule that refuses, when it is not the signature rule.
    fn rule(self) -> Option<&'static str> {
        match self {
            Self::SignatureRule => None,
            Self::Witness(rule) | Self::Argument(rule) => Some(rule),
        }
    }
}

/// One place where a contract checks a signature.
struct Site {
    /// The signature rule.
    rule: &'static str,
    /// Contract and entry.
    entry: &'static str,
    /// First line of the rule in the generated source of the contract.
    line: u32,
    /// Where the input stops when the signature is not 65 bytes long.
    other_length: OtherLength,
    /// The honest transaction.
    shape: fn() -> Scenario,
    /// The input that runs the rule.
    input: usize,
    /// Seed of the key the rule asks for.
    signer: u8,
    scheme: Scheme,
    /// KCC20: the bytes of the witness in front of the signature. `None`: the signature
    /// is an argument of its own (`PublicMint`, `TokenSeed`).
    witness_prefix: Option<fn() -> Vec<u8>>,
}

/// The realistic profile with a fee of 0.05 KAS: above the fee floor of a default mempool
/// for every transaction of this file, so that the honest transactions pass the policy of
/// a default mempool.
fn profile() -> Profile {
    Profile::Realistic(Realistic {
        fee: shapes::SOMPI_PER_KAS / 20,
        ..Realistic::default()
    })
}

fn transfer_one_to_one() -> Scenario {
    shapes::transfer(&profile(), 1, 1)
}

fn threshold_borrow() -> Scenario {
    shapes::borrow(&profile(), BorrowKind::Threshold)
}

fn key_hash_leader() -> Scenario {
    shapes::transfer_with_owner_scheme(&profile(), EntryRole::Leader, OWNER_P2PKH_SCHNORR)
}

fn key_hash_delegate() -> Scenario {
    shapes::transfer_with_owner_scheme(&profile(), EntryRole::Delegate, OWNER_P2PKH_SCHNORR)
}

fn ecdsa_leader() -> Scenario {
    shapes::transfer_with_owner_scheme(&profile(), EntryRole::Leader, OWNER_P2PKH_ECDSA)
}

fn ecdsa_delegate() -> Scenario {
    shapes::transfer_with_owner_scheme(&profile(), EntryRole::Delegate, OWNER_P2PKH_ECDSA)
}

fn signature_borrow() -> Scenario {
    shapes::borrow(&profile(), BorrowKind::Signature)
}

fn hash_chain_borrow() -> Scenario {
    shapes::borrow(&profile(), BorrowKind::HashChain)
}

fn minter_reclaim() -> Scenario {
    shapes::mint_reclaim(&profile())
}

fn minter_merge() -> Scenario {
    shapes::mint_reclaim_into(&profile())
}

fn seed_merge() -> Scenario {
    shapes::seed_reclaim(&profile())
}

fn nothing() -> Vec<u8> {
    Vec::new()
}

fn normal_path() -> Vec<u8> {
    vec![PATH_NORMAL]
}

fn borrow_path() -> Vec<u8> {
    vec![PATH_BORROW]
}

fn x_only_key() -> Vec<u8> {
    keys::x_only(ALICE).to_vec()
}

fn normal_path_and_x_only_key() -> Vec<u8> {
    [normal_path(), x_only_key()].concat()
}

fn compressed_key() -> Vec<u8> {
    keys::compressed(ALICE).to_vec()
}

fn normal_path_and_compressed_key() -> Vec<u8> {
    [normal_path(), compressed_key()].concat()
}

fn borrow_path_next_guard_and_key() -> Vec<u8> {
    [
        borrow_path(),
        CHAIN_NEXT_GUARD.to_vec(),
        keys::x_only(CAROL).to_vec(),
    ]
    .concat()
}

/// Index of the ECDSA leader in [`SITES`].
const ECDSA_LEADER: usize = 4;
/// Index of the key-hash leader and delegate in [`SITES`].
const KEY_HASH_LEADER: usize = 2;
const KEY_HASH_DELEGATE: usize = 3;
const ECDSA_DELEGATE: usize = 5;
/// Index of the signature borrow in [`SITES`].
const GUARD_SIGNATURE: usize = 6;
/// Index of the hash-chain borrow in [`SITES`].
const HASH_CHAIN: usize = 7;

static SITES: [Site; 11] = [
    Site {
        rule: "K-38",
        entry: "KCC20.transfer",
        line: 69,
        other_length: OtherLength::SignatureRule,
        shape: transfer_one_to_one,
        input: 0,
        signer: ALICE,
        scheme: Scheme::Schnorr,
        witness_prefix: Some(normal_path),
    },
    Site {
        rule: "K-38",
        entry: "KCC20.transfer_delegator",
        line: 69,
        other_length: OtherLength::SignatureRule,
        shape: threshold_borrow,
        input: 1,
        signer: ALICE,
        scheme: Scheme::Schnorr,
        witness_prefix: Some(nothing),
    },
    Site {
        rule: "K-41",
        entry: "KCC20.transfer",
        line: 79,
        other_length: OtherLength::Witness("K-39"),
        shape: key_hash_leader,
        input: 0,
        signer: ALICE,
        scheme: Scheme::Schnorr,
        witness_prefix: Some(normal_path_and_x_only_key),
    },
    Site {
        rule: "K-41",
        entry: "KCC20.transfer_delegator",
        line: 79,
        other_length: OtherLength::Witness("K-39"),
        shape: key_hash_delegate,
        input: 1,
        signer: ALICE,
        scheme: Scheme::Schnorr,
        witness_prefix: Some(x_only_key),
    },
    Site {
        rule: "K-44",
        entry: "KCC20.transfer",
        line: 86,
        other_length: OtherLength::Witness("K-42"),
        shape: ecdsa_leader,
        input: 0,
        signer: ALICE,
        scheme: Scheme::Ecdsa,
        witness_prefix: Some(normal_path_and_compressed_key),
    },
    Site {
        rule: "K-44",
        entry: "KCC20.transfer_delegator",
        line: 86,
        other_length: OtherLength::Witness("K-42"),
        shape: ecdsa_delegate,
        input: 1,
        signer: ALICE,
        scheme: Scheme::Ecdsa,
        witness_prefix: Some(compressed_key),
    },
    Site {
        rule: "K-52",
        entry: "KCC20.transfer",
        line: 192,
        other_length: OtherLength::SignatureRule,
        shape: signature_borrow,
        input: 0,
        signer: CAROL,
        scheme: Scheme::Schnorr,
        witness_prefix: Some(borrow_path),
    },
    Site {
        rule: "K-55",
        entry: "KCC20.transfer",
        line: 210,
        other_length: OtherLength::Witness("K-53"),
        shape: hash_chain_borrow,
        input: 0,
        signer: CAROL,
        scheme: Scheme::Schnorr,
        witness_prefix: Some(borrow_path_next_guard_and_key),
    },
    Site {
        rule: "M-35",
        entry: "PublicMint.reclaim",
        line: 249,
        other_length: OtherLength::Argument("M-31"),
        shape: minter_reclaim,
        input: 0,
        signer: ALICE,
        scheme: Scheme::Schnorr,
        witness_prefix: None,
    },
    Site {
        rule: "M-57",
        entry: "PublicMint.reclaim_delegator",
        line: 324,
        other_length: OtherLength::Argument("M-50"),
        shape: minter_merge,
        input: 1,
        signer: BOB,
        scheme: Scheme::Schnorr,
        witness_prefix: None,
    },
    Site {
        rule: "S-43",
        entry: "TokenSeed.reclaim_delegator",
        line: 254,
        other_length: OtherLength::Argument("S-36"),
        shape: seed_merge,
        input: 1,
        signer: BOB,
        scheme: Scheme::Schnorr,
        witness_prefix: None,
    },
];

/// A signature of `input_index` as scripts take it: 64 bytes and the type byte.
fn sign(ctx: &SigningContext<'_>, scheme: Scheme, key: u8, hash_type: SigHashType) -> Vec<u8> {
    let key = keys::keypair(key);
    match scheme {
        Scheme::Schnorr => keys::schnorr_signature(ctx, &key, hash_type),
        Scheme::Ecdsa => keys::ecdsa_signature(ctx, &key, hash_type),
    }
}

/// The signature of input `input` of the scenario as it stands now, as fixed bytes.
fn signature_over(
    scenario: &Scenario,
    input: usize,
    scheme: Scheme,
    key: u8,
    hash_type: SigHashType,
) -> Vec<u8> {
    let assembled = scenario
        .assemble(Family::pinned())
        .expect("the scenario assembles");
    let tx = MutableTransaction::with_entries(assembled.tx, assembled.utxos);
    let ctx = SigningContext {
        tx: &tx,
        input_index: input,
    };
    sign(&ctx, scheme, key, hash_type)
}

/// Who signs what.
#[derive(Clone, Copy, Debug)]
enum Signer {
    /// The key the rule asks for signs this input with the given type.
    Owner(SigHashType),
    /// The same signature as fixed bytes, made from the assembled transaction: the control
    /// of the case whose signature was made before an output changed.
    OwnerAsFixedBytes,
    /// Another key signs this input.
    Stranger,
    /// The key the rule asks for signs this input by the other scheme: ECDSA where the rule
    /// checks Schnorr, Schnorr where it checks ECDSA.
    OwnerWithTheOtherScheme,
    /// The key the rule asks for signs the last input of the transaction, the funding
    /// input, instead of its own.
    OwnerForAnotherInput,
    /// The key the rule asks for signed this input before the change output lost one
    /// sompi.
    OwnerBeforeAnOutputChanged,
}

/// What is done to the 65 bytes of the signature afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reshape {
    Keep,
    /// No bytes at all.
    Empty,
    /// The type byte 01 alone.
    TypeByteAlone,
    /// The 64 signature bytes without the type byte.
    WithoutTypeByte,
    /// The 65 bytes and one more type byte 01.
    OneByteMore,
    /// 65 zero bytes.
    ZeroBytes,
    /// 64 zero bytes and the type byte 01.
    ZeroSignature,
    /// 64 bytes ff and the type byte 01: numbers above the field and above the group order.
    AllOnes,
    /// The type byte replaced.
    TypeByte(u8),
}

impl Reshape {
    fn apply(self, mut signature: Vec<u8>) -> Vec<u8> {
        match self {
            Self::Keep => signature,
            Self::Empty => Vec::new(),
            Self::TypeByteAlone => vec![SIG_HASH_ALL.to_u8()],
            Self::WithoutTypeByte => {
                signature.pop();
                signature
            }
            Self::OneByteMore => {
                signature.push(SIG_HASH_ALL.to_u8());
                signature
            }
            Self::ZeroBytes => vec![0; 65],
            Self::ZeroSignature => {
                let mut zero = vec![0; 64];
                zero.push(SIG_HASH_ALL.to_u8());
                zero
            }
            Self::AllOnes => {
                let mut ones = vec![0xff; 64];
                ones.push(SIG_HASH_ALL.to_u8());
                ones
            }
            Self::TypeByte(byte) => {
                *signature.last_mut().expect("a signature has a type byte") = byte;
                signature
            }
        }
    }

    /// Whether the result is not 65 bytes long.
    fn changes_the_length(self) -> bool {
        matches!(
            self,
            Self::Empty | Self::TypeByteAlone | Self::WithoutTypeByte | Self::OneByteMore
        )
    }
}

/// Puts `signature`, reshaped, where the rule of `site` reads its signature.
///
/// A KCC20 witness is a byte string of any length, so the bytes are written as they are.
/// The `sig` argument of the two other contracts is written by the codec only when it is
/// 65 bytes long; another length replaces the push of the argument by hand.
fn put_signature(scenario: &mut Scenario, site: &Site, signature: LateBytes, reshape: Reshape) {
    let input = scenario.contract_input_mut(site.input);
    match site.witness_prefix {
        Some(prefix) => {
            *input.witness_mut() = LateBytes::from_tx(move |ctx| {
                let mut witness = prefix();
                witness.extend(reshape.apply(signature.resolve(ctx)));
                witness
            });
        }
        None => {
            *input.witness_mut() = signature;
            if reshape != Reshape::Keep {
                input.set_patch(move |parts| {
                    let pushed = &parts.arguments[0];
                    assert_eq!(pushed.len(), 66, "the signature is the first argument");
                    assert_eq!(pushed[0], 65, "pushed with its length in front");
                    parts.arguments[0] =
                        raw::push(&reshape.apply(pushed[1..].to_vec())).expect("a short push");
                });
            }
        }
    }
}

/// Replaces the signature material of the site's input.
fn replace_signature(scenario: &mut Scenario, site: &Site, signer: Signer, reshape: Reshape) {
    let (scheme, key) = (site.scheme, site.signer);
    let signature = match signer {
        Signer::Owner(hash_type) => {
            LateBytes::from_tx(move |ctx| sign(ctx, scheme, key, hash_type))
        }
        Signer::OwnerAsFixedBytes => LateBytes::fixed(signature_over(
            scenario,
            site.input,
            scheme,
            key,
            SIG_HASH_ALL,
        )),
        Signer::Stranger => LateBytes::from_tx(move |ctx| sign(ctx, scheme, DAVE, SIG_HASH_ALL)),
        Signer::OwnerWithTheOtherScheme => {
            let other = match scheme {
                Scheme::Schnorr => Scheme::Ecdsa,
                Scheme::Ecdsa => Scheme::Schnorr,
            };
            LateBytes::from_tx(move |ctx| sign(ctx, other, key, SIG_HASH_ALL))
        }
        Signer::OwnerForAnotherInput => {
            let other = scenario.inputs.len() - 1;
            assert_ne!(other, site.input, "the funding input is another input");
            LateBytes::from_tx(move |ctx| {
                let ctx = SigningContext {
                    tx: ctx.tx,
                    input_index: other,
                };
                sign(&ctx, scheme, key, SIG_HASH_ALL)
            })
        }
        Signer::OwnerBeforeAnOutputChanged => {
            let stale = signature_over(scenario, site.input, scheme, key, SIG_HASH_ALL);
            let change = scenario.outputs.last_mut().expect("a change output");
            *change.value_mut() -= 1;
            LateBytes::fixed(stale)
        }
    };
    put_signature(scenario, site, signature, reshape);
}

/// What the input is expected to answer.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Answer {
    Accept,
    /// A rule of the contract refuses with a failed verify.
    Rule(&'static str),
    /// The engine refuses the signature material at the signature opcode.
    Engine(&'static str),
    /// An ordinary input is refused by its own script, with this error of the engine.
    OwnScript(&'static str),
}

/// A change made to an honest scenario.
type Change = Box<dyn Fn(&mut Scenario)>;

/// One case: a site, a change, and what is expected.
struct Cell {
    site: &'static Site,
    group: &'static str,
    material: String,
    honest: Scenario,
    /// `None`: the honest scenario itself is the case.
    change: Option<Change>,
    answer: Answer,
    /// Whether the engine is expected to charge a signature check.
    charged: bool,
    note: Option<&'static str>,
}

impl Cell {
    fn id(&self) -> String {
        format!(
            "signature/{} {}/({}) {}",
            self.site.rule, self.site.entry, self.group, self.material
        )
    }

    fn changed(&self) -> Scenario {
        let mut scenario = self.honest.clone();
        if let Some(change) = &self.change {
            change(&mut scenario);
        }
        scenario
    }
}

/// The answer the engine is expected to give to a reshaped or misplaced signature.
fn expected_answer(site: &Site, honest: &Scenario, signer: Signer, reshape: Reshape) -> Answer {
    if reshape.changes_the_length()
        && let Some(rule) = site.other_length.rule()
    {
        return Answer::Rule(rule);
    }
    match reshape {
        Reshape::Keep => match signer {
            Signer::Owner(_) | Signer::OwnerAsFixedBytes => Answer::Accept,
            _ => Answer::Rule(site.rule),
        },
        Reshape::Empty | Reshape::ZeroSignature => Answer::Rule(site.rule),
        Reshape::TypeByteAlone | Reshape::OneByteMore => Answer::Engine("InvalidSignature"),
        Reshape::WithoutTypeByte => {
            // The last of the 64 signature bytes is read as the type byte.
            let signature =
                signature_over(honest, site.input, site.scheme, site.signer, SIG_HASH_ALL);
            if SigHashType::from_u8(signature[63]).is_ok() {
                Answer::Engine("InvalidSignature")
            } else {
                Answer::Engine("InvalidSigHashType")
            }
        }
        Reshape::ZeroBytes => Answer::Engine("InvalidSigHashType"),
        // One of the six types that is not the type that was signed: another message.
        Reshape::TypeByte(byte) if SigHashType::from_u8(byte).is_ok() => Answer::Rule(site.rule),
        Reshape::TypeByte(_) => Answer::Engine("InvalidSigHashType"),
        // The Schnorr parser takes any 64 bytes and the verification says no; the ECDSA
        // parser refuses numbers that are not below the group order.
        Reshape::AllOnes => match site.scheme {
            Scheme::Schnorr => Answer::Rule(site.rule),
            Scheme::Ecdsa => Answer::Engine("InvalidSignature"),
        },
    }
}

/// A case that replaces the signature material and nothing else.
fn replaced(
    site: &'static Site,
    group: &'static str,
    material: &str,
    signer: Signer,
    reshape: Reshape,
) -> Cell {
    let honest = (site.shape)();
    let answer = expected_answer(site, &honest, signer, reshape);
    let charged = match &answer {
        Answer::Accept => true,
        Answer::Rule(rule) => *rule == site.rule && reshape != Reshape::Empty,
        Answer::Engine(variant) => *variant != "InvalidSigHashType",
        Answer::OwnScript(_) => false,
    };
    Cell {
        site,
        group,
        material: material.to_string(),
        honest,
        change: Some(Box::new(move |scenario| {
            replace_signature(scenario, site, signer, reshape)
        })),
        answer,
        charged,
        note: None,
    }
}

/// One observation, as it is written to the matrix.
#[derive(Clone, Debug, Serialize)]
struct Row {
    rule: &'static str,
    entry: &'static str,
    scheme: Scheme,
    group: &'static str,
    material: String,
    input: usize,
    verdict: &'static str,
    variant: Option<String>,
    class: Option<ErrorClass>,
    refused_by: Option<String>,
    refusing_rule: Option<String>,
    at_rule: Option<String>,
    sil_line: Option<u32>,
    opcode: Option<String>,
    byte_offset: Option<usize>,
    script_units: u64,
    signature_check_charged: bool,
    transaction_accepted_by_scripts: bool,
    transaction_accepted_by_consensus: bool,
    transaction_accepted_by_mempool: bool,
    note: Option<&'static str>,
}

impl Row {
    fn of(cell: &Cell, outcome: &Outcome) -> Self {
        let run = outcome.inputs[cell.site.input]
            .alone
            .as_ref()
            .expect("the input was run");
        let refusal = run.refusal.as_ref();
        Self {
            rule: cell.site.rule,
            entry: cell.site.entry,
            scheme: cell.site.scheme,
            group: cell.group,
            material: cell.material.clone(),
            input: cell.site.input,
            verdict: if run.ok { "accepted" } else { "refused" },
            variant: run.error_variant().map(str::to_string),
            class: run.class,
            refused_by: run.refused_by().map(str::to_string),
            refusing_rule: run.rule().map(str::to_string),
            at_rule: refusal.and_then(|refusal| refusal.at_rule.clone()),
            sil_line: run.sil_line(),
            opcode: refusal.and_then(|refusal| refusal.opcode.clone()),
            byte_offset: refusal.and_then(|refusal| refusal.byte_offset),
            script_units: run.used_script_units,
            signature_check_charged: run.used_script_units >= SIGNATURE_CHECK_UNITS,
            transaction_accepted_by_scripts: outcome.scripts.accepted
                && outcome.scripts.accepted_under_committed_budgets == Some(true),
            transaction_accepted_by_consensus: outcome.consensus.accepted,
            transaction_accepted_by_mempool: outcome.mempool.accepted,
            note: cell.note,
        }
    }
}

/// Runs the case, holds the engine's answer against the expected one and returns what was
/// observed.
///
/// An accepted case must be accepted as a whole: by the scripts of every input, under the
/// smallest budgets, and by the consensus rules of a submission. A refused case is a twin
/// in which the site's input is refused as expected and every other input passes.
fn evaluate(cell: &Cell) -> Row {
    let site = cell.site;
    let mut case = Case::new(cell.id());
    if let Some(note) = cell.note {
        case = case.note(note);
    }
    let outcome = match (&cell.answer, &cell.change) {
        (Answer::Accept, _) => {
            let outcome = case.expect_accept(&cell.changed());
            assert!(
                outcome.consensus.accepted,
                "`{}`: the consensus rules refuse the transaction: {:?}",
                cell.id(),
                outcome.consensus.refusal
            );
            outcome
        }
        (answer, Some(change)) => {
            let refusal = match answer {
                Answer::Rule(rule) if *rule == site.rule => Expected::rule(*rule)
                    .at_line(site.line)
                    .of_class(ErrorClass::ContractRefused),
                Answer::Rule(rule) => Expected::rule(*rule).of_class(ErrorClass::ContractRefused),
                Answer::Engine(variant) => Expected::engine(*variant)
                    .at_line(site.line)
                    .of_class(ErrorClass::MalformedSignatureMaterial),
                Answer::OwnScript(variant) => Expected::engine(*variant),
                Answer::Accept => unreachable!("handled above"),
            };
            let mut expected = vec![(site.input, refusal)];
            expected.extend(
                (0..cell.honest.inputs.len())
                    .filter(|input| *input != site.input)
                    .map(|input| (input, Expected::pass())),
            );
            case.twin_inputs(&cell.honest, |scenario| change(scenario), &expected)
                .changed
        }
        (_, None) => panic!("`{}`: a refusal needs a change", cell.id()),
    };
    let row = Row::of(cell, &outcome);
    assert_eq!(
        row.signature_check_charged,
        cell.charged,
        "`{}`: {} script units",
        cell.id(),
        row.script_units
    );
    assert!(
        row.script_units < 2 * SIGNATURE_CHECK_UNITS,
        "`{}`: more than one signature check",
        cell.id()
    );
    if let Answer::Engine(_) = cell.answer {
        // The engine's own refusal is the signature opcode itself, one opcode in front of
        // the verify of the rule.
        let opcode = match site.scheme {
            Scheme::Schnorr => "OpCheckSig",
            Scheme::Ecdsa => "OpCheckSigECDSA",
        };
        assert_eq!(row.opcode.as_deref(), Some(opcode), "`{}`", cell.id());
        assert_eq!(row.refusing_rule, None, "`{}`", cell.id());
    }
    row
}

fn honest_cells() -> Vec<Cell> {
    let honest = SITES.iter().map(|site| Cell {
        site,
        group: "control",
        material: "honest".to_string(),
        honest: (site.shape)(),
        change: None,
        answer: Answer::Accept,
        charged: true,
        note: None,
    });
    let fixed = SITES.iter().map(|site| {
        replaced(
            site,
            "control",
            "the signature as fixed bytes, in the transaction it was made for",
            Signer::OwnerAsFixedBytes,
            Reshape::Keep,
        )
    });
    honest.chain(fixed).collect()
}

/// 32 bytes that are no x-only public key, and with the prefix 02 no compressed one: the
/// curve has no point with x = 0.
const NO_KEY: [u8; 32] = [0; 32];

fn empty_cells() -> Vec<Cell> {
    let mut cells: Vec<Cell> = SITES
        .iter()
        .map(|site| {
            replaced(
                site,
                "a",
                "empty signature",
                Signer::Owner(SIG_HASH_ALL),
                Reshape::Empty,
            )
        })
        .collect();
    // The engine looks at the key only when there is a signature to check: a coin whose
    // owner field is no key refuses a well-formed signature with an error of the engine
    // and an empty one like any other coin.
    let leader = &SITES[0];
    cells.push(special(
        leader,
        "a",
        "owner field is no key, signature of 65 bytes",
        |scenario| set_owner(scenario, 0, NO_KEY),
        Answer::Engine("InvalidPubkey"),
        true,
    ));
    cells.push(special(
        leader,
        "a",
        "owner field is no key, empty signature",
        move |scenario| {
            set_owner(scenario, 0, NO_KEY);
            put_signature(scenario, leader, LateBytes::empty(), Reshape::Empty);
        },
        Answer::Rule("K-38"),
        false,
    ));
    cells
}

fn length_cells() -> Vec<Cell> {
    let materials = [
        ("one byte, the type 01", Reshape::TypeByteAlone),
        ("64 bytes, no type byte", Reshape::WithoutTypeByte),
        ("66 bytes", Reshape::OneByteMore),
        ("65 zero bytes", Reshape::ZeroBytes),
        ("64 zero bytes and the type 01", Reshape::ZeroSignature),
        ("64 bytes ff and the type 01", Reshape::AllOnes),
        (
            "valid signature of type 01 with the type byte 02",
            Reshape::TypeByte(SIG_HASH_NONE.to_u8()),
        ),
    ];
    let mut cells = Vec::new();
    for site in &SITES {
        for (material, reshape) in materials {
            cells.push(replaced(
                site,
                "b",
                material,
                Signer::Owner(SIG_HASH_ALL),
                reshape,
            ));
        }
    }
    cells
}

fn type_byte_cells() -> Vec<Cell> {
    let mut cells = Vec::new();
    for site in &SITES {
        for byte in [0x00, 0x03, 0x05, 0x80, 0xff] {
            cells.push(replaced(
                site,
                "b",
                &format!("valid signature, type byte {byte:02x}"),
                Signer::Owner(SIG_HASH_ALL),
                Reshape::TypeByte(byte),
            ));
        }
    }
    cells
}

fn misplaced_cells() -> Vec<Cell> {
    let materials = [
        ("valid signature of another key", Signer::Stranger),
        (
            "the owner's signature for another input",
            Signer::OwnerForAnotherInput,
        ),
        (
            "the owner's signature made before an output changed",
            Signer::OwnerBeforeAnOutputChanged,
        ),
        (
            "the owner's signature by the other signature scheme",
            Signer::OwnerWithTheOtherScheme,
        ),
    ];
    let mut cells = Vec::new();
    for site in &SITES {
        for (material, signer) in materials {
            cells.push(replaced(site, "c", material, signer, Reshape::Keep));
        }
    }
    // The other input above is the funding coin, which differs in script and value. Here
    // it is a second token coin of the same owner with the same state: the two coins have
    // one script and one value and differ in the outpoint alone.
    cells.push(Cell {
        site: &SITES[1],
        group: "c",
        material: "the owner's signature for a coin alike in all but the outpoint".to_string(),
        honest: two_coins_alike(),
        change: Some(Box::new(|scenario| {
            *scenario.contract_input_mut(1).witness_mut() = LateBytes::from_tx(|ctx| {
                let ctx = SigningContext {
                    tx: ctx.tx,
                    input_index: 0,
                };
                sign(&ctx, Scheme::Schnorr, ALICE, SIG_HASH_ALL)
            });
        })),
        answer: Answer::Rule("K-38"),
        charged: true,
        note: None,
    });
    // A coin with a signature borrow has two keys, each for one path.
    let guarded = &SITES[GUARD_SIGNATURE];
    cells.push(special(
        guarded,
        "c",
        "the coin's owner signs on the borrow path, where the guard key is asked",
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                witness::borrow_signature(BOB, SIG_HASH_ALL);
        },
        Answer::Rule("K-52"),
        true,
    ));
    cells.push(special(
        guarded,
        "c",
        "the guard key signs on the normal path, where the owner is asked",
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                witness::owner_key(CAROL, EntryRole::Leader, SIG_HASH_ALL);
        },
        Answer::Rule("K-38"),
        true,
    ));
    cells
}

/// A transfer of two token coins of Alice that hold the same state.
fn two_coins_alike() -> Scenario {
    let mut scenario = shapes::transfer(&profile(), 2, 1);
    set_owner(&mut scenario, 1, keys::x_only(ALICE));
    *scenario.contract_input_mut(1).witness_mut() =
        witness::owner_key(ALICE, EntryRole::Delegate, SIG_HASH_ALL);
    scenario
}

/// A case with a change and an answer of its own.
fn special(
    site: &'static Site,
    group: &'static str,
    material: &str,
    change: impl Fn(&mut Scenario) + 'static,
    answer: Answer,
    charged: bool,
) -> Cell {
    Cell {
        site,
        group,
        material: material.to_string(),
        honest: (site.shape)(),
        change: Some(Box::new(change)),
        answer,
        charged,
        note: None,
    }
}

/// The order of the secp256k1 group minus `s`: the other `s` of the same ECDSA signature.
fn negated_scalar(s: &[u8]) -> [u8; 32] {
    secp256k1::SecretKey::from_slice(s)
        .expect("the s of a signature is a scalar")
        .negate()
        .secret_bytes()
}

/// The order of the secp256k1 group: as an `s` it is one above the largest scalar.
const GROUP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Offsets in the witness of the ECDSA leader: path byte, 33-byte key, 64 signature bytes,
/// type byte.
const ECDSA_KEY: std::ops::Range<usize> = 1..34;
const ECDSA_R: std::ops::Range<usize> = 34..66;
const ECDSA_S: std::ops::Range<usize> = 66..98;

/// The honest witness of the ECDSA leader, changed by `f`.
fn ecdsa_witness(f: impl Fn(&mut Vec<u8>) + Send + Sync + 'static) -> LateBytes {
    witness::owner_key_hash_ecdsa(ALICE, EntryRole::Leader, SIG_HASH_ALL).map(move |mut bytes| {
        f(&mut bytes);
        bytes
    })
}

/// Gives the ECDSA leader's coin to the hash of `key` and shows `key` in the witness, with
/// Alice's signature behind it.
fn ecdsa_coin_of(scenario: &mut Scenario, key: [u8; 33]) {
    let input = scenario.contract_input_mut(0);
    input.state.as_kcc20_mut().expect("a token coin").owner = witness::public_key_hash(&key);
    *input.witness_mut() = ecdsa_witness(move |bytes| bytes[ECDSA_KEY].copy_from_slice(&key));
}

fn other_parity(mut key: [u8; 33]) -> [u8; 33] {
    key[0] ^= 0x01;
    key
}

fn ecdsa_cells() -> Vec<Cell> {
    let site = &SITES[ECDSA_LEADER];
    let alice = keys::compressed(ALICE);
    let mut cells = Vec::new();
    cells.push(special(
        site,
        "d",
        "key of the other parity, coin still owned by the right key",
        move |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                ecdsa_witness(|bytes| bytes[ECDSA_KEY.start] ^= 0x01);
        },
        Answer::Rule("K-43"),
        false,
    ));
    cells.push(special(
        site,
        "d",
        "key of the other parity, coin owned by that key",
        move |scenario| ecdsa_coin_of(scenario, other_parity(alice)),
        Answer::Rule("K-44"),
        true,
    ));
    let mut above_the_field = [0xff; 33];
    above_the_field[0] = 0x02;
    cells.push(special(
        site,
        "d",
        "33 bytes, x above the field, coin owned by that string",
        move |scenario| ecdsa_coin_of(scenario, above_the_field),
        Answer::Engine("InvalidPubkey"),
        true,
    ));
    let mut zero_x = [0x00; 33];
    zero_x[0] = 0x02;
    cells.push(special(
        site,
        "d",
        "33 bytes, x = 0, coin owned by that string",
        move |scenario| ecdsa_coin_of(scenario, zero_x),
        Answer::Engine("InvalidPubkey"),
        true,
    ));
    let mut wrong_prefix = alice;
    wrong_prefix[0] = 0x05;
    cells.push(special(
        site,
        "d",
        "33 bytes, prefix 05, coin owned by that string",
        move |scenario| ecdsa_coin_of(scenario, wrong_prefix),
        Answer::Engine("InvalidPubkey"),
        true,
    ));
    cells.push(special(
        site,
        "d",
        "right key, s replaced by the group order minus s",
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() = ecdsa_witness(|bytes| {
                let high = negated_scalar(&bytes[ECDSA_S]);
                bytes[ECDSA_S].copy_from_slice(&high);
            });
        },
        Answer::Rule("K-44"),
        true,
    ));
    cells.push(special(
        site,
        "d",
        "right key, one bit of r flipped",
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                ecdsa_witness(|bytes| bytes[ECDSA_R.start + 7] ^= 0x10);
        },
        Answer::Rule("K-44"),
        true,
    ));
    cells.push(special(
        site,
        "d",
        "right key, s = the group order",
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                ecdsa_witness(|bytes| bytes[ECDSA_S].copy_from_slice(&GROUP_ORDER));
        },
        Answer::Engine("InvalidSignature"),
        true,
    ));
    cells.push(special(
        site,
        "d",
        "right key, signature in DER",
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() = ecdsa_witness(|bytes| {
                let type_byte = bytes.pop().expect("a type byte");
                let compact = bytes.split_off(ECDSA_R.start);
                let der = secp256k1::ecdsa::Signature::from_compact(&compact)
                    .expect("a compact signature")
                    .serialize_der();
                bytes.extend_from_slice(&der);
                bytes.push(type_byte);
            });
        },
        Answer::Rule("K-42"),
        false,
    ));
    cells
}

/// BLAKE2b-256 without a key: the hash the engine uses for pay-to-script-hash.
fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new().hash_length(32).hash(data);
    hash.as_bytes().try_into().expect("32 bytes")
}

fn set_owner(scenario: &mut Scenario, input: usize, owner: [u8; 32]) {
    scenario
        .contract_input_mut(input)
        .state
        .as_kcc20_mut()
        .expect("a token coin")
        .owner = owner;
}

fn binding_cells() -> Vec<Cell> {
    let mut cells = Vec::new();
    // Another key pair shows its key and signs: everything about the signature is right,
    // only the key is not the one the coin names.
    for (index, role, rule) in [
        (KEY_HASH_LEADER, EntryRole::Leader, "K-40"),
        (KEY_HASH_DELEGATE, EntryRole::Delegate, "K-40"),
    ] {
        let site = &SITES[index];
        cells.push(special(
            site,
            "e",
            "key and valid signature of another key pair",
            move |scenario| {
                *scenario.contract_input_mut(site.input).witness_mut() =
                    witness::owner_key_hash_schnorr(DAVE, role, SIG_HASH_ALL);
            },
            Answer::Rule(rule),
            false,
        ));
    }
    for (index, role, rule) in [
        (ECDSA_LEADER, EntryRole::Leader, "K-43"),
        (ECDSA_DELEGATE, EntryRole::Delegate, "K-43"),
    ] {
        let site = &SITES[index];
        cells.push(special(
            site,
            "e",
            "key and valid signature of another key pair",
            move |scenario| {
                *scenario.contract_input_mut(site.input).witness_mut() =
                    witness::owner_key_hash_ecdsa(DAVE, role, SIG_HASH_ALL);
            },
            Answer::Rule(rule),
            false,
        ));
    }
    // The right key and signature; the coin names the key by another hash of it.
    let x_only = keys::x_only(ALICE);
    let compressed = keys::compressed(ALICE);
    let other_hashes: [(usize, &'static str, &'static str, [u8; 32]); 6] = [
        (
            KEY_HASH_LEADER,
            "K-40",
            "owner is BLAKE2b-256 of the key",
            blake2b_256(&x_only),
        ),
        (
            KEY_HASH_LEADER,
            "K-40",
            "owner is BLAKE3 of the key under a zero key",
            *blake3::keyed_hash(&[0; 32], &x_only).as_bytes(),
        ),
        (
            KEY_HASH_LEADER,
            "K-40",
            "owner is BLAKE3 of the compressed form of the key",
            witness::public_key_hash(&compressed),
        ),
        (
            ECDSA_LEADER,
            "K-43",
            "owner is BLAKE2b-256 of the key",
            blake2b_256(&compressed),
        ),
        (
            ECDSA_LEADER,
            "K-43",
            "owner is BLAKE3 of the key under a zero key",
            *blake3::keyed_hash(&[0; 32], &compressed).as_bytes(),
        ),
        (
            ECDSA_LEADER,
            "K-43",
            "owner is BLAKE3 of the x-only form of the key",
            witness::public_key_hash(&x_only),
        ),
    ];
    for (index, rule, material, owner) in other_hashes {
        let site = &SITES[index];
        cells.push(special(
            site,
            "e",
            material,
            move |scenario| set_owner(scenario, site.input, owner),
            Answer::Rule(rule),
            false,
        ));
    }
    // 32 bytes that are no key, named by their hash: the case passes the key hash rule and
    // stops in the signature opcode behind it.
    cells.push(special(
        &SITES[KEY_HASH_LEADER],
        "e",
        "32 bytes that are no key, coin owned by their hash",
        |scenario| {
            set_owner(scenario, 0, witness::public_key_hash(&NO_KEY));
            *scenario.contract_input_mut(0).witness_mut() =
                witness::owner_key_hash_schnorr(ALICE, EntryRole::Leader, SIG_HASH_ALL).map(
                    |mut bytes| {
                        bytes[1..33].copy_from_slice(&NO_KEY);
                        bytes
                    },
                );
        },
        Answer::Engine("InvalidPubkey"),
        true,
    ));
    cells
}

/// The end of the two-step chain of group (f).
const CHAIN_END: [u8; 32] = [0x43; 32];

/// The hash-chain borrow with another link: the coin holds `guard`, the witness reveals
/// `next` and the key of `key`, which signs; the successor holds `next`.
fn chain_step(guard: [u8; 32], next: [u8; 32], key: u8) -> Scenario {
    let mut scenario = hash_chain_borrow();
    set_guard(&mut scenario, guard);
    reveal(&mut scenario, next, key);
    scenario
}

fn set_guard(scenario: &mut Scenario, guard: [u8; 32]) {
    scenario
        .contract_input_mut(0)
        .state
        .as_kcc20_mut()
        .expect("a token coin")
        .borrow_guard = guard;
}

/// Reveals `next` and the key of `key` and puts `next` into the successor.
fn reveal(scenario: &mut Scenario, next: [u8; 32], key: u8) {
    let input = scenario.contract_input_mut(0);
    input.declared_states_mut()[0].borrow_guard = next;
    *input.witness_mut() = witness::borrow_hash_chain(next, key, SIG_HASH_ALL);
    scenario
        .contract_output_mut(0)
        .state
        .as_kcc20_mut()
        .expect("a token output")
        .borrow_guard = next;
}

fn chain_cells() -> Vec<Cell> {
    let site = &SITES[HASH_CHAIN];
    let mut cells = Vec::new();
    cells.push(special(
        site,
        "f",
        "key and valid signature of a key that is not the one of the link",
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                witness::borrow_hash_chain(CHAIN_NEXT_GUARD, DAVE, SIG_HASH_ALL);
        },
        Answer::Rule("K-54"),
        false,
    ));
    cells.push(special(
        site,
        "f",
        "right key and signature, another next guard revealed",
        |scenario| {
            let mut other = CHAIN_NEXT_GUARD;
            other[31] ^= 0x01;
            reveal(scenario, other, CAROL);
        },
        Answer::Rule("K-54"),
        false,
    ));
    // A chain of two links: the first is opened by Carol's key, the second by Dave's.
    let second = witness::chain_guard(&CHAIN_END, DAVE);
    let first = witness::chain_guard(&second, CAROL);
    cells.push(Cell {
        site,
        group: "control",
        material: "first link of a chain of two".to_string(),
        honest: chain_step(first, second, CAROL),
        change: None,
        answer: Answer::Accept,
        charged: true,
        note: None,
    });
    cells.push(Cell {
        site,
        group: "control",
        material: "second link of a chain of two".to_string(),
        honest: chain_step(second, CHAIN_END, DAVE),
        change: None,
        answer: Answer::Accept,
        charged: true,
        note: None,
    });
    cells.push(Cell {
        site,
        group: "f",
        material: "the first link shown again to the successor, signed anew".to_string(),
        honest: chain_step(second, CHAIN_END, DAVE),
        change: Some(Box::new(move |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                witness::borrow_hash_chain(second, CAROL, SIG_HASH_ALL);
        })),
        answer: Answer::Rule("K-54"),
        charged: false,
        note: None,
    });
    cells.push(Cell {
        site,
        group: "f",
        material: "the first link shown again, the successor keeping its guard".to_string(),
        honest: chain_step(second, CHAIN_END, DAVE),
        change: Some(Box::new(move |scenario| reveal(scenario, second, CAROL))),
        answer: Answer::Rule("K-54"),
        charged: false,
        note: None,
    });
    cells
}

/// The authority input of group (g): not a rule of a contract but the place where the
/// signature of owner scheme 0x03 is checked. K-46 compares the script of this coin with
/// the owner field of the token coin (`KCC20.sil` line 90).
static AUTHORITY: Site = Site {
    rule: "K-46",
    entry: "KCC20.transfer, the authority's own input",
    line: 90,
    other_length: OtherLength::SignatureRule,
    shape: transfer_by_a_signing_authority,
    input: 1,
    signer: CAROL,
    scheme: Scheme::Schnorr,
    witness_prefix: None,
};

/// The redeem script of an authority that asks for a signature: `<Carol's key> OP_CHECKSIG`.
fn authority_redeem_script() -> Vec<u8> {
    let mut script = raw::push(&keys::x_only(CAROL)).expect("a 32-byte push");
    script.push(OpCheckSig);
    script
}

/// Writes the signature script of the authority input: `pushes`, then its redeem script.
fn set_authority_pushes(scenario: &mut Scenario, pushes: LateBytes) {
    scenario
        .ordinary_input_mut(AUTHORITY.input)
        .signature_script = LateBytes::from_tx(move |ctx| {
        let mut script = pushes.resolve(ctx);
        script.extend(raw::push(&authority_redeem_script()).expect("a short push"));
        script
    });
}

/// The push of a Schnorr signature of the input by the key of `key`.
fn pushed_signature(key: u8) -> LateBytes {
    LateBytes::from_tx(move |ctx| {
        raw::push(&sign(ctx, Scheme::Schnorr, key, SIG_HASH_ALL)).expect("a 65-byte push")
    })
}

/// The transfer of a token coin of owner scheme 0x03 whose owner is the hash of
/// [`authority_redeem_script`]: input 0 is the token coin, input 1 the authority coin, signed
/// by Carol, input 2 the funding coin.
fn transfer_by_a_signing_authority() -> Scenario {
    let mut scenario =
        shapes::transfer_with_owner_scheme(&profile(), EntryRole::Leader, OWNER_P2SH);
    let lock = pay_to_script_hash_script(&authority_redeem_script());
    let owner: [u8; 32] = lock.script()[2..34]
        .try_into()
        .expect("a pay-to-script-hash script holds a 32-byte hash");
    set_owner(&mut scenario, 0, owner);
    scenario
        .ordinary_input_mut(AUTHORITY.input)
        .script_public_key = lock;
    set_authority_pushes(&mut scenario, pushed_signature(CAROL));
    scenario
}

fn authority_cells() -> Vec<Cell> {
    vec![
        Cell {
            site: &AUTHORITY,
            group: "control",
            material: "honest".to_string(),
            honest: transfer_by_a_signing_authority(),
            change: None,
            answer: Answer::Accept,
            charged: true,
            note: None,
        },
        special(
            &AUTHORITY,
            "g",
            "the authority's signature is empty",
            |scenario| {
                let empty = raw::push(&[]).expect("an empty push");
                set_authority_pushes(scenario, LateBytes::fixed(empty));
            },
            Answer::OwnScript("EvalFalse"),
            false,
        ),
        special(
            &AUTHORITY,
            "g",
            "valid signature of another key on the authority input",
            |scenario| set_authority_pushes(scenario, pushed_signature(DAVE)),
            Answer::OwnScript("EvalFalse"),
            true,
        ),
        special(
            &AUTHORITY,
            "g",
            "the authority input pushes its script and no signature",
            |scenario| set_authority_pushes(scenario, LateBytes::empty()),
            Answer::OwnScript("InvalidStackOperation"),
            false,
        ),
    ]
}

/// The groups of cases, in the order of the matrix.
const CONTROL: usize = 0;
const EMPTY: usize = 1;
const LENGTHS: usize = 2;
const TYPE_BYTES: usize = 3;
const MISPLACED: usize = 4;
const ECDSA: usize = 5;
const BINDING: usize = 6;
const CHAIN: usize = 7;
const AUTHORITY_SCRIPT: usize = 8;

const GROUPS: [fn() -> Vec<Cell>; 9] = [
    honest_cells,
    empty_cells,
    length_cells,
    type_byte_cells,
    misplaced_cells,
    ecdsa_cells,
    binding_cells,
    chain_cells,
    authority_cells,
];

static ROWS: [OnceLock<Vec<Row>>; 9] = [const { OnceLock::new() }; 9];

/// The observations of one group. Every case is run once, by whichever test asks first.
fn rows_of(group: usize) -> &'static [Row] {
    ROWS[group].get_or_init(|| GROUPS[group]().iter().map(evaluate).collect())
}

fn refused_with(row: &Row, variant: &str) -> bool {
    row.verdict == "refused" && row.variant.as_deref() == Some(variant)
}

#[test]
fn the_honest_transactions_pass_and_each_site_pays_for_one_signature_check() {
    let rows = rows_of(CONTROL);
    assert_eq!(rows.len(), 2 * SITES.len());
    for row in rows {
        assert_eq!(row.verdict, "accepted", "{row:?}");
        // One signature check and less than another one beside it: so the units of a run
        // tell whether the check was charged.
        assert!(
            (SIGNATURE_CHECK_UNITS + 1..2 * SIGNATURE_CHECK_UNITS).contains(&row.script_units),
            "{row:?}"
        );
        // A real transaction: the scripts, the consensus rules and a default mempool.
        assert!(row.transaction_accepted_by_scripts, "{row:?}");
        assert!(row.transaction_accepted_by_consensus, "{row:?}");
        assert!(row.transaction_accepted_by_mempool, "{row:?}");
    }
}

#[test]
fn a_an_empty_signature_fails_a_verify_and_is_not_charged_a_signature_check() {
    let (rows, no_key) = rows_of(EMPTY).split_at(SITES.len());
    for (site, row) in SITES.iter().zip(rows) {
        // Never an engine error, never the charge of a signature check.
        assert!(refused_with(row, "VerifyError"), "{row:?}");
        assert_eq!(row.class, Some(ErrorClass::ContractRefused), "{row:?}");
        assert!(!row.signature_check_charged, "{row:?}");
        match site.other_length {
            // The opcode pushed false; the verify behind it is the refusal.
            OtherLength::SignatureRule => {
                assert_eq!(row.refusing_rule.as_deref(), Some(site.rule), "{row:?}");
                assert_eq!(row.opcode.as_deref(), Some("OpVerify"), "{row:?}");
                assert_eq!(row.sil_line, Some(site.line), "{row:?}");
            }
            OtherLength::Witness(rule) => {
                assert_eq!(row.refusing_rule.as_deref(), Some(rule), "{row:?}");
                assert_eq!(row.opcode.as_deref(), Some("OpVerify"), "{row:?}");
            }
            // The size check of the argument, in front of the body of the entry.
            OtherLength::Argument(rule) => {
                assert_eq!(row.refusing_rule.as_deref(), Some(rule), "{row:?}");
                assert_eq!(row.opcode.as_deref(), Some("OpNumEqualVerify"), "{row:?}");
                assert_eq!(row.sil_line, None, "{row:?}");
            }
        }
    }

    // The key is not looked at when the signature is empty.
    let [with_signature, without] = no_key else {
        panic!("two cases");
    };
    assert!(
        refused_with(with_signature, "InvalidPubkey"),
        "{with_signature:?}"
    );
    assert!(with_signature.signature_check_charged, "{with_signature:?}");
    assert!(refused_with(without, "VerifyError"), "{without:?}");
    assert_eq!(
        without.refusing_rule.as_deref(),
        Some("K-38"),
        "{without:?}"
    );
    assert!(!without.signature_check_charged, "{without:?}");
}

#[test]
fn b_a_malformed_signature_is_refused_by_a_rule_or_by_the_engine() {
    let rows = rows_of(LENGTHS);
    assert_eq!(rows.len(), 7 * SITES.len());
    for (site, rows) in SITES.iter().zip(rows.chunks(7)) {
        let [
            type_alone,
            no_type_byte,
            one_more,
            zero_bytes,
            zero_signature,
            all_ones,
            another_type,
        ] = rows
        else {
            panic!("seven materials per site");
        };
        match site.other_length.rule() {
            // The engine's parser reads the last byte as the type, charges the check, and
            // then refuses the rest.
            None => {
                assert!(
                    refused_with(type_alone, "InvalidSignature"),
                    "{type_alone:?}"
                );
                assert!(refused_with(one_more, "InvalidSignature"), "{one_more:?}");
                assert!(type_alone.signature_check_charged && one_more.signature_check_charged);
                assert!(!no_type_byte.signature_check_charged, "{no_type_byte:?}");
                assert_eq!(
                    no_type_byte.class,
                    Some(ErrorClass::MalformedSignatureMaterial),
                    "{no_type_byte:?}"
                );
            }
            Some(rule) => {
                for row in [type_alone, no_type_byte, one_more] {
                    assert_eq!(row.refusing_rule.as_deref(), Some(rule), "{row:?}");
                    assert!(!row.signature_check_charged, "{row:?}");
                }
            }
        }
        // The materials of 65 bytes. Zero bytes end in the type byte 00; 64 zero bytes
        // with a type are a well-formed signature that does not verify.
        assert!(
            refused_with(zero_bytes, "InvalidSigHashType"),
            "{zero_bytes:?}"
        );
        assert!(!zero_bytes.signature_check_charged, "{zero_bytes:?}");
        assert_eq!(zero_signature.refusing_rule.as_deref(), Some(site.rule));
        assert!(zero_signature.signature_check_charged, "{zero_signature:?}");
        // Numbers out of range: no signature for Schnorr, no well-formed one for ECDSA.
        match site.scheme {
            Scheme::Schnorr => assert_eq!(all_ones.refusing_rule.as_deref(), Some(site.rule)),
            Scheme::Ecdsa => assert!(refused_with(all_ones, "InvalidSignature"), "{all_ones:?}"),
        }
        assert!(all_ones.signature_check_charged, "{all_ones:?}");
        // The type byte is part of what is signed.
        assert_eq!(another_type.refusing_rule.as_deref(), Some(site.rule));
        assert!(another_type.signature_check_charged, "{another_type:?}");
    }
}

#[test]
fn b_a_type_byte_outside_the_six_is_refused_before_the_signature_is_looked_at() {
    let rows = rows_of(TYPE_BYTES);
    assert_eq!(rows.len(), 5 * SITES.len());
    for row in rows {
        assert!(refused_with(row, "InvalidSigHashType"), "{row:?}");
        assert_eq!(row.class, Some(ErrorClass::MalformedSignatureMaterial));
        assert!(!row.signature_check_charged, "{row:?}");
    }
}

#[test]
fn c_a_valid_signature_for_something_else_fails_the_verify_of_the_rule() {
    let (rows, others) = rows_of(MISPLACED).split_at(4 * SITES.len());
    let [alike, owner_for_guard, guard_for_owner] = others else {
        panic!("three cases");
    };
    assert!(refused_with(alike, "VerifyError"), "{alike:?}");
    assert_eq!(alike.refusing_rule.as_deref(), Some("K-38"), "{alike:?}");
    assert!(refused_with(owner_for_guard, "VerifyError"));
    assert_eq!(owner_for_guard.refusing_rule.as_deref(), Some("K-52"));
    assert!(refused_with(guard_for_owner, "VerifyError"));
    assert_eq!(guard_for_owner.refusing_rule.as_deref(), Some("K-38"));
    assert_eq!(guard_for_owner.sil_line, Some(69), "{guard_for_owner:?}");
    for (site, rows) in SITES.iter().zip(rows.chunks(4)) {
        for row in rows {
            assert!(refused_with(row, "VerifyError"), "{row:?}");
            assert_eq!(row.refusing_rule.as_deref(), Some(site.rule), "{row:?}");
            assert_eq!(row.sil_line, Some(site.line), "{row:?}");
            assert!(row.signature_check_charged, "{row:?}");
        }
    }
}

#[test]
fn d_ecdsa_takes_one_key_and_one_form_of_the_signature() {
    // Alice's compressed key starts with 02 or 03; the honest control spends with it.
    let alice = keys::compressed(ALICE);
    assert!(alice[0] == 0x02 || alice[0] == 0x03);
    let control = &rows_of(CONTROL)[ECDSA_LEADER];
    assert_eq!((control.rule, control.verdict), ("K-44", "accepted"));

    let rows = rows_of(ECDSA);
    let by: Vec<(&str, Option<&str>, bool)> = rows
        .iter()
        .map(|row| {
            let by = row.refusing_rule.as_deref().or(row.variant.as_deref());
            (row.material.as_str(), by, row.signature_check_charged)
        })
        .collect();
    assert_eq!(
        by,
        [
            (
                "key of the other parity, coin still owned by the right key",
                Some("K-43"),
                false
            ),
            (
                "key of the other parity, coin owned by that key",
                Some("K-44"),
                true
            ),
            (
                "33 bytes, x above the field, coin owned by that string",
                Some("InvalidPubkey"),
                true
            ),
            (
                "33 bytes, x = 0, coin owned by that string",
                Some("InvalidPubkey"),
                true
            ),
            (
                "33 bytes, prefix 05, coin owned by that string",
                Some("InvalidPubkey"),
                true
            ),
            (
                "right key, s replaced by the group order minus s",
                Some("K-44"),
                true
            ),
            ("right key, one bit of r flipped", Some("K-44"), true),
            (
                "right key, s = the group order",
                Some("InvalidSignature"),
                true
            ),
            ("right key, signature in DER", Some("K-42"), false),
        ]
    );
    for row in rows {
        assert_eq!(row.verdict, "refused", "{row:?}");
    }
}

#[test]
fn e_the_key_in_the_witness_must_hash_to_the_owner_by_plain_blake3() {
    let (rows, no_key) = rows_of(BINDING).split_at(10);
    for row in rows {
        // The hash is compared before any signature is looked at.
        let binding = match row.rule {
            "K-41" => "K-40",
            "K-44" => "K-43",
            other => panic!("no key hash in front of {other}"),
        };
        assert!(refused_with(row, "VerifyError"), "{row:?}");
        assert_eq!(row.refusing_rule.as_deref(), Some(binding), "{row:?}");
        assert!(!row.signature_check_charged, "{row:?}");
    }
    let [no_key] = no_key else {
        panic!("one case");
    };
    assert!(refused_with(no_key, "InvalidPubkey"), "{no_key:?}");
    assert!(no_key.signature_check_charged, "{no_key:?}");
}

#[test]
fn f_a_link_of_the_hash_chain_opens_one_guard_and_only_once() {
    let rows = rows_of(CHAIN);
    let (controls, refused): (Vec<&Row>, Vec<&Row>) =
        rows.iter().partition(|row| row.group == "control");
    assert_eq!((controls.len(), refused.len()), (2, 4));
    for row in controls {
        assert_eq!(row.verdict, "accepted", "{row:?}");
    }
    for row in refused {
        // The link is compared before the signature of the one-time key is looked at.
        assert!(refused_with(row, "VerifyError"), "{row:?}");
        assert_eq!(row.refusing_rule.as_deref(), Some("K-54"), "{row:?}");
        assert_eq!(row.sil_line, Some(205), "{row:?}");
        assert!(!row.signature_check_charged, "{row:?}");
    }
}

#[test]
fn g_with_owner_scheme_03_the_script_of_the_authority_coin_checks_the_signature() {
    let [honest, empty, stranger, no_signature] = rows_of(AUTHORITY_SCRIPT) else {
        panic!("four cases");
    };
    assert_eq!(honest.verdict, "accepted");
    assert!(honest.transaction_accepted_by_consensus);

    // The token coin's own script passes in all three (the twin asserts it): K-46 compares
    // the script of the authority coin with the owner field. The refusal comes from the
    // authority input, which is run like every other input.
    for row in [empty, stranger, no_signature] {
        assert_eq!((row.rule, row.input, row.verdict), ("K-46", 1, "refused"));
        assert_eq!(row.refusing_rule, None, "{row:?}");
        assert!(!row.transaction_accepted_by_scripts, "{row:?}");
        assert!(!row.transaction_accepted_by_consensus, "{row:?}");
    }
    // An empty signature costs the authority input no signature check.
    assert!(!empty.signature_check_charged, "{empty:?}");
    assert!(stranger.signature_check_charged, "{stranger:?}");
}

/// One site of the matrix.
#[derive(Serialize)]
struct SiteRecord {
    rule: &'static str,
    entry: &'static str,
    scheme: Scheme,
    sil_line: u32,
    input: usize,
}

/// The document `signature-matrix.json`.
#[derive(Serialize)]
struct Matrix<'a> {
    layout: u32,
    about: &'static str,
    signature_check_units: u64,
    signature_check_charged_means: &'static str,
    sites: Vec<SiteRecord>,
    rows: Vec<&'a Row>,
}

#[test]
fn the_signature_matrix_is_written() {
    let rows: Vec<&Row> = (0..GROUPS.len()).flat_map(rows_of).collect();

    // Nothing is accepted but the honest controls: two per site, the two links of the hash
    // chain and the transfer by the authority.
    let accepted: Vec<&&Row> = rows
        .iter()
        .filter(|row| row.verdict == "accepted")
        .collect();
    for row in &accepted {
        assert_eq!(row.group, "control", "{row:?}");
        assert!(row.transaction_accepted_by_scripts, "{row:?}");
        assert!(row.transaction_accepted_by_consensus, "{row:?}");
    }
    assert_eq!(accepted.len(), 2 * SITES.len() + 2 + 1);
    for row in rows.iter().filter(|row| row.verdict == "refused") {
        assert!(!row.transaction_accepted_by_scripts, "{row:?}");
        assert!(!row.transaction_accepted_by_consensus, "{row:?}");
    }
    assert_eq!(rows.len(), 244);

    let matrix = Matrix {
        layout: 1,
        about: "Signature rules of KCC20, PublicMint and TokenSeed on the script engine: one \
                row per rule, entry and signature material. Every row is the run of the named \
                input by itself, without a budget limit.",
        signature_check_units: SIGNATURE_CHECK_UNITS,
        signature_check_charged_means: "script_units >= signature_check_units; every honest \
                                        input uses less than two checks' worth",
        sites: SITES
            .iter()
            .chain([&AUTHORITY])
            .map(|site| SiteRecord {
                rule: site.rule,
                entry: site.entry,
                scheme: site.scheme,
                sil_line: site.line,
                input: site.input,
            })
            .collect(),
        rows,
    };
    let path = results::write_document("signature-matrix.json", &matrix);
    assert!(path.ends_with("signature-matrix.json"));
}
