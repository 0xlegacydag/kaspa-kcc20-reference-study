//! The bytes of a call, on the script engine.
//!
//! A call of a contract is the signature script of the input: one push per argument, the
//! push of the 4-byte dispatch tag, the push of the redeem script. The codec only writes
//! well-formed calls, so the checks the compiler generates in front of every entry (the
//! dispatcher, the width of every argument, the equal element counts of the columns of
//! `KCC20.transfer`) can only be met by bytes written by hand. This file writes them:
//!
//! 1. every rule that only hand-made call bytes reach, as a twin: the honest call passes,
//!    the smallest change of bytes is refused by exactly that rule;
//! 2. the six columns of `KCC20.transfer` disagreeing with each other;
//! 3. what the engine itself asks of a signature script: pushes only, the redeem script
//!    last, a clean stack at the end, and what happens when a push is missing, added or
//!    belongs to another entry, another contract or another coin, with and without a valid
//!    signature of the owner next to it;
//! 4. the encodings the engine tolerates: the same call with longer push opcodes and longer
//!    number bytes is accepted, the transaction id stays, the signature script differs;
//! 5. the two hidden arguments of `PublicMint.mint` and `TokenSeed.create` (the prefix and
//!    the suffix of the KCC20 script) changed, cut, swapped and replaced.
//!
//! No signature covers a signature script. Everything changed here is changed after the
//! honest transaction was signed, the way a third party would do it: the signatures inside
//! the calls stay the honest ones.
//!
//! Every case is recorded twice: by the test harness of `crates/checks` in the result file
//! of this binary, and in the table [`OBSERVED`] below, which holds what refused, the
//! engine's error, the source line and the script units used up to the stop. The table is
//! what the engine answered; the rule named in each case is what the case claims. A case
//! fails when the two differ. With `-- --nocapture` every observed row is printed in the
//! form of the table.

use checks::{Case, Expected, Outcome, judge_accept, judge_twin, run};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kcc20_family::{
    Contract, Entry, EntryRole, Scenario,
    keys::{self, ALICE},
    raw::{self, CallParts, PushForm},
    scenario::{Call, LateBytes},
    shapes::{self, Profile, Realistic},
    witness,
};

/// One observed answer: the case, what refused (`accepted` for a call that passes), the
/// variant of the engine's error, the first line of the source statement the engine stopped
/// in, and the script units the input had used when it stopped.
type Row = (&'static str, &'static str, &'static str, Option<u32>, u64);

/// What the engine answered, case by case.
#[rustfmt::skip]
const OBSERVED: &[Row] = &[
    ("reach/K-01 tag 00000000", "K-01", "EarlyReturn", None, 8103),
    ("reach/K-03 amounts column of 17 bytes", "K-03", "VerifyError", None, 8187),
    ("reach/K-04 owners column of 65 bytes", "K-04", "VerifyError", None, 8255),
    ("reach/K-05 three owners for two amounts", "K-05", "VerifyError", None, 8286),
    ("reach/K-07 three owner schemes for two amounts", "K-07", "VerifyError", None, 8260),
    ("reach/K-09 three borrow schemes for two amounts", "K-09", "VerifyError", None, 8265),
    ("reach/K-10 borrow guards column of 65 bytes", "K-10", "VerifyError", None, 8333),
    ("reach/K-11 three borrow guards for two amounts", "K-11", "VerifyError", None, 8364),
    ("reach/K-12 extension commitments column of 65 bytes", "K-12", "VerifyError", None, 8401),
    ("reach/K-13 three extension commitments for two amounts", "K-13", "VerifyError", None, 8432),
    ("reach/M-01 tag 00000000", "M-01", "EarlyReturn", None, 4091),
    ("reach/M-02 amount in nine bytes", "M-02", "VerifyError", None, 4086),
    ("reach/M-03 owner of 33 bytes", "M-03", "VerifyError", None, 4113),
    ("reach/M-03 owner of 31 bytes", "M-03", "VerifyError", None, 4111),
    ("reach/M-04 owner scheme as an empty push", "M-04", "VerifyError", None, 4112),
    ("reach/M-04 owner scheme of two bytes", "M-04", "VerifyError", None, 4115),
    ("reach/M-05 borrow scheme as an empty push", "M-05", "VerifyError", None, 4114),
    ("reach/M-05 borrow scheme of two bytes", "M-05", "VerifyError", None, 4117),
    ("reach/M-06 borrow guard of 33 bytes", "M-06", "VerifyError", None, 4150),
    ("reach/M-06 borrow guard of 31 bytes", "M-06", "VerifyError", None, 4148),
    ("reach/M-07 extension commitment of 33 bytes", "M-07", "VerifyError", None, 4183),
    ("reach/M-07 extension commitment of 31 bytes", "M-07", "VerifyError", None, 4181),
    ("reach/M-22 take in nine bytes", "M-22", "VerifyError", None, 4090),
    ("reach/M-23 new owner of 33 bytes", "M-23", "VerifyError", None, 4117),
    ("reach/M-23 new owner of 31 bytes", "M-23", "VerifyError", None, 4115),
    ("reach/M-31 empty signature", "M-31", "VerifyError", None, 4084),
    ("reach/M-31 signature without its type byte, 64 bytes", "M-31", "VerifyError", None, 4149),
    ("reach/M-31 signature with one more byte, 66 bytes", "M-31", "VerifyError", None, 4151),
    ("reach/M-50 empty signature", "M-50", "VerifyError", None, 4092),
    ("reach/M-50 signature without its type byte, 64 bytes", "M-50", "VerifyError", None, 4157),
    ("reach/M-50 signature with one more byte, 66 bytes", "M-50", "VerifyError", None, 4159),
    ("reach/S-01 tag 00000000", "S-01", "EarlyReturn", None, 2759),
    ("reach/S-02 amount in nine bytes", "S-02", "VerifyError", None, 2758),
    ("reach/S-03 owner of 33 bytes", "S-03", "VerifyError", None, 2783),
    ("reach/S-03 owner of 31 bytes", "S-03", "VerifyError", None, 2781),
    ("reach/S-04 owner scheme as an empty push", "S-04", "VerifyError", None, 2782),
    ("reach/S-04 owner scheme of two bytes", "S-04", "VerifyError", None, 2785),
    ("reach/S-05 borrow scheme as an empty push", "S-05", "VerifyError", None, 2784),
    ("reach/S-05 borrow scheme of two bytes", "S-05", "VerifyError", None, 2787),
    ("reach/S-06 borrow guard of 33 bytes", "S-06", "VerifyError", None, 2820),
    ("reach/S-06 borrow guard of 31 bytes", "S-06", "VerifyError", None, 2818),
    ("reach/S-07 extension commitment of 33 bytes", "S-07", "VerifyError", None, 2853),
    ("reach/S-07 extension commitment of 31 bytes", "S-07", "VerifyError", None, 2851),
    ("reach/S-20 new owner of 33 bytes", "S-20", "VerifyError", None, 2786),
    ("reach/S-20 new owner of 31 bytes", "S-20", "VerifyError", None, 2784),
    ("reach/S-36 empty signature", "S-36", "VerifyError", None, 2760),
    ("reach/S-36 signature without its type byte, 64 bytes", "S-36", "VerifyError", None, 2825),
    ("reach/S-36 signature with one more byte, 66 bytes", "S-36", "VerifyError", None, 2827),
    ("columns/two amounts, three owners", "K-05", "VerifyError", None, 8286),
    ("columns/amounts column of 7 bytes", "K-03", "VerifyError", None, 8177),
    ("columns/amounts column of 9 bytes", "K-03", "VerifyError", None, 8179),
    ("columns/amounts one element short", "K-05", "VerifyError", None, 8246),
    ("columns/amounts empty", "K-05", "VerifyError", None, 8234),
    ("columns/owners one element short", "K-05", "VerifyError", None, 8222),
    ("columns/owners empty", "K-05", "VerifyError", None, 8187),
    ("columns/owner schemes one element short", "K-07", "VerifyError", None, 8258),
    ("columns/owner schemes empty", "K-07", "VerifyError", None, 8255),
    ("columns/borrow schemes one element short", "K-09", "VerifyError", None, 8263),
    ("columns/borrow schemes empty", "K-09", "VerifyError", None, 8260),
    ("columns/borrow guards one element short", "K-11", "VerifyError", None, 8300),
    ("columns/borrow guards empty", "K-11", "VerifyError", None, 8265),
    ("columns/extension commitments one element short", "K-13", "VerifyError", None, 8368),
    ("columns/extension commitments empty", "K-13", "VerifyError", None, 8333),
    ("columns/the owners column as two pushes", "K-05", "VerifyError", None, 8238),
    ("columns/all empty, one real output", "K-24", "VerifyError", Some(160), 8309),
    ("columns/all empty, two real outputs", "K-24", "VerifyError", Some(160), 8309),
    ("engine/OpNop in front of the arguments",
        "engine: SignatureScriptNotPushOnly", "SignatureScriptNotPushOnly", None, 0),
    ("engine/OpDup between the arguments and the tag",
        "engine: SignatureScriptNotPushOnly", "SignatureScriptNotPushOnly", None, 0),
    ("engine/OpDrop between the tag and the redeem script",
        "engine: SignatureScriptNotPushOnly", "SignatureScriptNotPushOnly", None, 0),
    ("engine/OpNop after the redeem script",
        "engine: SignatureScriptNotPushOnly", "SignatureScriptNotPushOnly", None, 0),
    ("engine/OpReserved in front of the arguments",
        "engine: OpcodeReserved", "OpcodeReserved", None, 0),
    ("missing push/transfer without the witness",
        "engine: InvalidState", "InvalidState", None, 8165),
    ("missing push/transfer without the amounts column",
        "engine: InvalidState", "InvalidState", None, 8167),
    ("missing push/transfer without the owner schemes column",
        "engine: InvalidState", "InvalidState", None, 8167),
    ("missing push/transfer_delegator without its witness",
        "engine: InvalidState", "InvalidState", None, 8104),
    ("missing push/mint without the suffix", "engine: InvalidState", "InvalidState", None, 4076),
    ("missing push/mint without the amount", "engine: InvalidState", "InvalidState", None, 4076),
    ("missing push/mint without both hidden arguments",
        "engine: InvalidState", "InvalidState", None, 4076),
    ("missing push/create without the suffix", "engine: InvalidState", "InvalidState", None, 2748),
    ("missing push/create without the amount", "engine: InvalidState", "InvalidState", None, 2748),
    ("missing push/create without both hidden arguments",
        "engine: InvalidState", "InvalidState", None, 2748),
    ("missing push/PublicMint.split without its last argument",
        "engine: InvalidState", "InvalidState", None, 4080),
    ("missing push/PublicMint.reclaim without its last argument",
        "engine: InvalidState", "InvalidState", None, 4084),
    ("missing push/PublicMint.reclaim_delegator without its last argument",
        "engine: InvalidState", "InvalidState", None, 4092),
    ("missing push/TokenSeed.split without its last argument",
        "engine: InvalidState", "InvalidState", None, 2752),
    ("missing push/TokenSeed.reclaim_delegator without its last argument",
        "engine: InvalidState", "InvalidState", None, 2760),
    ("extra push/transfer with one more item below the arguments",
        "final stack", "CleanStack", None, 144833),
    ("extra push/transfer_delegator with one more item below the arguments",
        "final stack", "CleanStack", None, 137037),
    ("extra push/mint with one more item below the arguments",
        "final stack", "CleanStack", None, 54318),
    ("extra push/PublicMint.reclaim with one more item below the arguments",
        "final stack", "CleanStack", None, 104324),
    ("extra push/create with one more item below the arguments",
        "final stack", "CleanStack", None, 43786),
    ("extra push/TokenSeed.reclaim with one more item below the arguments",
        "final stack", "CleanStack", None, 12770),
    ("no call/KCC20 redeem script alone",
        "engine: InvalidStackOperation", "InvalidStackOperation", None, 8095),
    ("no call/PublicMint redeem script alone",
        "engine: InvalidStackOperation", "InvalidStackOperation", None, 4071),
    ("no call/TokenSeed redeem script alone",
        "engine: InvalidStackOperation", "InvalidStackOperation", None, 2743),
    ("other entry/transfer arguments under the tag of transfer_delegator, lone coin",
        "K-68", "VerifyError", Some(254), 8236),
    ("other entry/transfer arguments under the tag of transfer_delegator, first of two",
        "K-69", "VerifyError", Some(255), 8269),
    ("other entry/transfer_delegator witness under the tag of transfer",
        "engine: InvalidState", "InvalidState", None, 8166),
    ("other entry/mint arguments under the tag of PublicMint.split",
        "M-23", "VerifyError", None, 7970),
    ("other entry/mint arguments under the tag of PublicMint.reclaim",
        "M-31", "VerifyError", None, 7971),
    ("other entry/mint arguments under the tag of PublicMint.reclaim_into",
        "M-36", "VerifyError", Some(260), 4153),
    ("other entry/mint arguments under the tag of PublicMint.reclaim_delegator",
        "M-50", "VerifyError", None, 7979),
    ("other entry/PublicMint.split arguments under the tag of mint",
        "engine: InvalidState", "InvalidState", None, 4076),
    ("other entry/create arguments under the tag of TokenSeed.split",
        "S-20", "VerifyError", None, 6639),
    ("other entry/create arguments under the tag of TokenSeed.reclaim",
        "S-26", "VerifyError", Some(207), 2821),
    ("other entry/create arguments under the tag of TokenSeed.reclaim_delegator",
        "S-36", "VerifyError", None, 6647),
    ("signed, other tag/a lone minter's reclaim as reclaim_delegator",
        "M-51", "VerifyError", Some(311), 4223),
    ("signed, other tag/a retiring minter's reclaim_delegator as reclaim",
        "M-32", "VerifyError", Some(243), 4216),
    ("signed, other tag/a retiring seed's reclaim_delegator as reclaim",
        "S-27", "VerifyError", Some(208), 2856),
    ("signed, other tag/a delegate's signature in a call of transfer",
        "K-14", "VerifyError", Some(129), 8360),
    ("signed, other arguments/the two declared owners exchanged",
        "K-66", "VerifyError", Some(239), 127199),
    ("other contract/KCC20 coin under the tag of PublicMint.mint",
        "K-01", "EarlyReturn", None, 8103),
    ("other contract/PublicMint coin under the tag of KCC20.transfer",
        "M-01", "EarlyReturn", None, 4091),
    ("other contract/PublicMint coin under the tag of TokenSeed.create",
        "M-01", "EarlyReturn", None, 4091),
    ("other contract/TokenSeed coin under the tag of PublicMint.mint",
        "S-01", "EarlyReturn", None, 2759),
    ("tag length/transfer tag of 3 bytes", "K-01", "EarlyReturn", None, 8101),
    ("tag length/transfer tag of 5 bytes", "K-01", "EarlyReturn", None, 8105),
    ("tag length/transfer tag of an empty push", "K-01", "EarlyReturn", None, 8095),
    ("tag length/transfer without a tag push", "K-01", "EarlyReturn", None, 8227),
    ("redeem push/an empty push after the redeem script", "P2SH wrapper", "EvalFalse", None, 32),
    ("redeem push/the tag pushed again after the redeem script",
        "P2SH wrapper", "EvalFalse", None, 40),
    ("redeem push/half a push after the redeem script",
        "engine: MalformedPush", "MalformedPush", None, 0),
    ("redeem push/omitted", "P2SH wrapper", "EvalFalse", None, 40),
    ("redeem push/one byte of the redeem script changed", "P2SH wrapper", "EvalFalse", None, 8094),
    ("redeem push/omitted, TokenSeed.reclaim", "P2SH wrapper", "EvalFalse", None, 40),
    ("redeem push/pushed twice", "K-01", "EarlyReturn", None, 16157),
    ("redeem push/the tag pushed twice in front of it", "K-04", "VerifyError", None, 8178),
    ("redeem push/an empty signature script", "P2SH wrapper", "InvalidStackOperation", None, 0),
    ("redeem push/the whole signature script of the other token coin",
        "P2SH wrapper", "EvalFalse", None, 8094),
    ("other coin/the leader's call on the delegate", "K-14", "VerifyError", Some(129), 8360),
    ("other coin/the delegate's call on the leader", "K-69", "VerifyError", Some(255), 8268),
    ("other coin/a delegate's call on the other delegate, two owners",
        "K-38", "VerifyError", Some(69), 137036),
    ("other coin/a delegate's call on the other delegate, one owner",
        "K-38", "VerifyError", Some(69), 137036),
    ("other coin/the seed's create call on the minter", "M-01", "EarlyReturn", None, 4091),
    ("other coin/the minter's mint call on the seed", "S-01", "EarlyReturn", None, 2759),
    ("other coin/the retiring minter's call on the retiring seed",
        "S-43", "VerifyError", Some(254), 112730),
    ("other coin/the retiring seed's call on the retiring minter",
        "M-57", "VerifyError", Some(324), 118740),
    ("other coin/the surviving minter's call on the retiring minter",
        "M-37", "VerifyError", Some(261), 4188),
    ("other coin/the surviving seed's call on the retiring seed",
        "S-27", "VerifyError", Some(208), 2856),
    ("encoding/transfer with OP_PUSHDATA1", "accepted", "-", None, 144833),
    ("encoding/transfer with OP_PUSHDATA2", "accepted", "-", None, 144833),
    ("encoding/transfer with OP_PUSHDATA4", "accepted", "-", None, 144833),
    ("encoding/transfer, leader of two coins with OP_PUSHDATA1", "accepted", "-", None, 155738),
    ("encoding/transfer, leader of two coins with OP_PUSHDATA2", "accepted", "-", None, 155738),
    ("encoding/transfer, leader of two coins with OP_PUSHDATA4", "accepted", "-", None, 155738),
    ("encoding/transfer_delegator with OP_PUSHDATA1", "accepted", "-", None, 137037),
    ("encoding/transfer_delegator with OP_PUSHDATA2", "accepted", "-", None, 137037),
    ("encoding/transfer_delegator with OP_PUSHDATA4", "accepted", "-", None, 137037),
    ("encoding/mint with OP_PUSHDATA1", "accepted", "-", None, 54318),
    ("encoding/mint with OP_PUSHDATA2", "accepted", "-", None, 54318),
    ("encoding/mint with OP_PUSHDATA4", "accepted", "-", None, 54318),
    ("encoding/PublicMint.reclaim with OP_PUSHDATA1", "accepted", "-", None, 104324),
    ("encoding/PublicMint.reclaim with OP_PUSHDATA2", "accepted", "-", None, 104324),
    ("encoding/PublicMint.reclaim with OP_PUSHDATA4", "accepted", "-", None, 104324),
    ("encoding/PublicMint.reclaim_into with OP_PUSHDATA1", "accepted", "-", None, 28010),
    ("encoding/PublicMint.reclaim_into with OP_PUSHDATA2", "accepted", "-", None, 28010),
    ("encoding/PublicMint.reclaim_into with OP_PUSHDATA4", "accepted", "-", None, 28010),
    ("encoding/create with OP_PUSHDATA1", "accepted", "-", None, 43786),
    ("encoding/create with OP_PUSHDATA2", "accepted", "-", None, 43786),
    ("encoding/create with OP_PUSHDATA4", "accepted", "-", None, 43786),
    ("encoding/TokenSeed.reclaim_delegator with OP_PUSHDATA1", "accepted", "-", None, 112731),
    ("encoding/TokenSeed.reclaim_delegator with OP_PUSHDATA2", "accepted", "-", None, 112731),
    ("encoding/TokenSeed.reclaim_delegator with OP_PUSHDATA4", "accepted", "-", None, 112731),
    ("encoding/transfer, the tag alone with OP_PUSHDATA1", "accepted", "-", None, 144833),
    ("encoding/transfer, the redeem script alone with OP_PUSHDATA4", "accepted", "-", None, 144833),
    ("encoding/transfer, the witness alone with OP_PUSHDATA2", "accepted", "-", None, 144833),
    ("number/mint amount 10 as 01 0a", "accepted", "-", None, 54318),
    ("number/mint amount 10 in two bytes", "accepted", "-", None, 54325),
    ("number/mint amount 10 in eight bytes", "accepted", "-", None, 54367),
    ("number/mint amount as negative zero", "M-12", "VerifyError", Some(136), 8141),
    ("number/split take 7 in eight bytes", "accepted", "-", None, 22746),
    ("number/create amount zero as one zero byte", "accepted", "-", None, 43791),
    ("number/create amount zero as negative zero, 01 80", "accepted", "-", None, 43791),
    ("number/create amount zero as eight zero bytes", "accepted", "-", None, 43819),
    ("number/create amount zero as negative zero in eight bytes", "accepted", "-", None, 43819),
    ("number/create amount zero as negative zero in nine bytes", "S-02", "VerifyError", None, 2758),
    ("number/create borrow scheme 0x01 as 01 01", "accepted", "-", None, 43786),
    ("number/transfer declared amount zero as negative zero", "accepted", "-", None, 144833),
    ("hidden/mint suffix, first byte changed", "M-20", "VerifyError", Some(174), 37195),
    ("hidden/mint suffix, a byte in the middle changed", "M-20", "VerifyError", Some(174), 37195),
    ("hidden/mint suffix, last byte changed", "M-20", "VerifyError", Some(174), 37195),
    ("hidden/mint suffix, last byte cut", "M-20", "VerifyError", Some(174), 37189),
    ("hidden/mint suffix, one byte appended", "M-20", "VerifyError", Some(174), 37201),
    ("hidden/mint suffix empty", "M-20", "VerifyError", Some(174), 13876),
    ("hidden/mint prefix changed", "M-20", "VerifyError", Some(174), 37195),
    ("hidden/mint prefix empty", "M-20", "VerifyError", Some(174), 37186),
    ("hidden/mint prefix of two bytes", "M-20", "VerifyError", Some(174), 37201),
    ("hidden/mint prefix and suffix swapped", "M-20", "VerifyError", Some(174), 37195),
    ("hidden/mint the same bytes cut at another place", "M-20", "VerifyError", Some(174), 37195),
    ("hidden/mint suffix of PublicMint", "M-20", "VerifyError", Some(174), 25093),
    ("hidden/mint suffix of TokenSeed", "M-20", "VerifyError", Some(174), 21217),
    ("hidden/create suffix, first byte changed", "S-18", "VerifyError", Some(154), 26664),
    ("hidden/create suffix, a byte in the middle changed", "S-18", "VerifyError", Some(154), 26664),
    ("hidden/create suffix, last byte changed", "S-18", "VerifyError", Some(154), 26664),
    ("hidden/create suffix, last byte cut", "S-18", "VerifyError", Some(154), 26658),
    ("hidden/create suffix, one byte appended", "S-18", "VerifyError", Some(154), 26670),
    ("hidden/create suffix empty", "S-18", "VerifyError", Some(154), 3348),
    ("hidden/create prefix changed", "S-18", "VerifyError", Some(154), 26664),
    ("hidden/create prefix empty", "S-18", "VerifyError", Some(154), 26655),
    ("hidden/create prefix of two bytes", "S-18", "VerifyError", Some(154), 26670),
    ("hidden/create prefix and suffix swapped", "S-18", "VerifyError", Some(154), 26664),
    ("hidden/create the same bytes cut at another place", "S-18", "VerifyError", Some(154), 26664),
    ("hidden/create suffix of PublicMint", "S-18", "VerifyError", Some(154), 14562),
    ("hidden/create suffix of TokenSeed", "S-18", "VerifyError", Some(154), 10686),
];

// Positions of the argument pushes of `KCC20.transfer`.
const AMOUNTS: usize = 0;
const OWNERS: usize = 1;
const OWNER_SCHEMES: usize = 2;
const BORROW_SCHEMES: usize = 3;
const BORROW_GUARDS: usize = 4;
const EXTENSIONS: usize = 5;
const WITNESS: usize = 6;

/// The six columns of `next_states` with the width of one element.
const COLUMNS: [(usize, &str, usize); 6] = [
    (AMOUNTS, "amounts", 8),
    (OWNERS, "owners", 32),
    (OWNER_SCHEMES, "owner schemes", 1),
    (BORROW_SCHEMES, "borrow schemes", 1),
    (BORROW_GUARDS, "borrow guards", 32),
    (EXTENSIONS, "extension commitments", 32),
];

// Positions of the argument pushes of `PublicMint.mint` and `TokenSeed.create`.
const AMOUNT: usize = 0;
const OWNER: usize = 1;
const OWNER_SCHEME: usize = 2;
const BORROW_SCHEME: usize = 3;
const BORROW_GUARD: usize = 4;
const EXTENSION: usize = 5;
const PREFIX: usize = 6;
const SUFFIX: usize = 7;

/// The canonical push of `data`.
fn push(data: &[u8]) -> Vec<u8> {
    raw::push(data).expect("a push of this size fits a script")
}

/// The data of one push, whatever its opcode form.
fn data_of(part: &[u8]) -> Vec<u8> {
    match part {
        [0x00] => Vec::new(),
        [0x4f] => vec![0x81],
        [opcode @ 0x51..=0x60] => vec![opcode - 0x50],
        [0x4c, _, data @ ..] => data.to_vec(),
        [0x4d, _, _, data @ ..] => data.to_vec(),
        [0x4e, _, _, _, _, data @ ..] => data.to_vec(),
        [len @ 0x01..=0x4b, data @ ..] if usize::from(*len) == data.len() => data.to_vec(),
        other => panic!("not one push: {} bytes", other.len()),
    }
}

/// The honest scenario with the parts of the signature script of `input` changed.
fn patched(
    honest: &Scenario,
    input: usize,
    patch: impl Fn(&mut CallParts) + Send + Sync + 'static,
) -> Scenario {
    let mut scenario = honest.clone();
    scenario.contract_input_mut(input).set_patch(patch);
    scenario
}

/// The data of argument `index` changed and pushed again in the canonical form.
fn argument_changed(
    honest: &Scenario,
    input: usize,
    index: usize,
    change: impl Fn(Vec<u8>) -> Vec<u8> + Send + Sync + 'static,
) -> Scenario {
    patched(honest, input, move |parts| {
        let data = change(data_of(&parts.arguments[index]));
        parts.arguments[index] = push(&data);
    })
}

/// The push of argument `index` replaced by the given script bytes.
fn argument_replaced(honest: &Scenario, input: usize, index: usize, script: Vec<u8>) -> Scenario {
    patched(honest, input, move |parts| {
        parts.arguments[index] = script.clone();
    })
}

/// The push of the tag replaced by the given script bytes.
fn tag_replaced(honest: &Scenario, input: usize, script: Vec<u8>) -> Scenario {
    patched(honest, input, move |parts| parts.tag = script.clone())
}

/// The tag of `entry` in place of the honest one.
fn tag_of(honest: &Scenario, input: usize, entry: Entry) -> Scenario {
    tag_replaced(honest, input, push(&checks::family().dispatch_tag(entry)))
}

/// `count` zero bytes appended.
fn longer(count: usize) -> impl Fn(Vec<u8>) -> Vec<u8> + Send + Sync + 'static {
    move |mut data| {
        data.resize(data.len() + count, 0);
        data
    }
}

/// The last `count` bytes cut off.
fn shorter(count: usize) -> impl Fn(Vec<u8>) -> Vec<u8> + Send + Sync + 'static {
    move |mut data| {
        data.truncate(data.len() - count);
        data
    }
}

/// Zero bytes appended up to `len` bytes: the same number in more bytes.
fn padded(len: usize) -> impl Fn(Vec<u8>) -> Vec<u8> + Send + Sync + 'static {
    move |mut data| {
        data.resize(len, 0);
        data
    }
}

/// Exactly these bytes.
fn exactly(bytes: &[u8]) -> impl Fn(Vec<u8>) -> Vec<u8> + Send + Sync + 'static {
    let bytes = bytes.to_vec();
    move |_| bytes.clone()
}

/// One byte changed.
fn flipped(index: usize) -> impl Fn(Vec<u8>) -> Vec<u8> + Send + Sync + 'static {
    move |mut data| {
        data[index] ^= 0x01;
        data
    }
}

/// The bytes in front of the redeem push of an input, as the honest scenario assembles
/// them: argument pushes and tag push, signatures included.
fn call_bytes_of(scenario: &Scenario, input: usize) -> Vec<u8> {
    let assembled = scenario
        .assemble(checks::family())
        .expect("an honest scenario assembles");
    let mut pushes = raw::split_pushes(&assembled.tx.inputs[input].signature_script)
        .expect("an honest signature script is a list of pushes");
    pushes.pop();
    pushes.concat()
}

/// The call of `input` replaced by the given bytes; the redeem push stays the coin's own.
fn with_call_bytes(honest: &Scenario, input: usize, bytes: Vec<u8>) -> Scenario {
    let mut scenario = honest.clone();
    scenario.contract_input_mut(input).call = Call::Raw(LateBytes::fixed(bytes));
    scenario
}

/// One push in the given opcode form; unchanged when the data does not fit the form.
fn in_form(part: &[u8], form: PushForm) -> Vec<u8> {
    raw::push_as(form, &data_of(part)).unwrap_or_else(|| part.to_vec())
}

/// Every push of the signature script of `input` in the given opcode form.
fn all_pushes_in_form(honest: &Scenario, input: usize, form: PushForm) -> Scenario {
    patched(honest, input, move |parts| {
        for argument in &mut parts.arguments {
            *argument = in_form(argument, form);
        }
        parts.tag = in_form(&parts.tag, form);
        parts.redeem = in_form(&parts.redeem, form);
    })
}

/// Whether `label` is the id of a rule of the inventory.
fn is_rule_id(label: &str) -> bool {
    ["K-", "M-", "S-"].iter().any(|prefix| {
        label.strip_prefix(prefix).is_some_and(|number| {
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        })
    })
}

/// Whether the test harness of `crates/checks` runs in its mutation mode: on a weakened
/// contract, or on a selection of the cases. The table holds the answers of the pinned
/// contracts, so a case then goes to the helper of the harness with its claim alone, and the
/// harness records what it sees.
fn another_family_runs() -> bool {
    !checks::mutation::mode().is_plain()
}

/// What a case claims about its refusal: the rule or the short name of what refuses, with
/// the engine's error and the source line of the table.
fn claim(id: &str, by: &str) -> Expected {
    let mut expected = if is_rule_id(by) {
        Expected::rule(by)
    } else {
        Expected::refused_by(by)
    };
    if let Some(row) = OBSERVED.iter().find(|row| row.0 == id) {
        expected.engine = Some(row.2.to_string());
        expected.sil_line = row.3;
    }
    expected
}

/// The cases of one test. A mismatch is collected, so that one run shows all of them.
struct Log {
    failures: Vec<String>,
}

impl Log {
    fn new() -> Self {
        Self {
            failures: Vec::new(),
        }
    }

    /// Compares an observed row with the table. Prints the row in the form of the table.
    fn pinned(&mut self, id: &str, by: &str, variant: &str, line: Option<u32>, units: u64) -> bool {
        println!("ROW (\"{id}\", \"{by}\", \"{variant}\", {line:?}, {units}),");
        match OBSERVED.iter().find(|row| row.0 == id) {
            Some(row) if (row.1, row.2, row.3, row.4) == (by, variant, line, units) => true,
            Some(row) => {
                self.failures.push(format!(
                    "{id}: the table says {row:?}, \
                     observed ({by:?}, {variant:?}, {line:?}, {units})"
                ));
                false
            }
            None => {
                self.failures
                    .push(format!("{id}: no row in the table of observed answers"));
                false
            }
        }
    }

    /// A twin: the honest scenario passes, the changed one is refused at `input` by `by`
    /// (a rule id, or the short name of what refused).
    fn refused(
        &mut self,
        id: &str,
        note: &str,
        honest: &Scenario,
        changed: &Scenario,
        input: usize,
        by: &str,
    ) {
        if another_family_runs() {
            Case::new(id).note(note).twin(
                honest,
                |scenario| *scenario = changed.clone(),
                input,
                claim(id, by),
            );
            return;
        }
        let outcome = run(changed);
        let Some(observed) = outcome.inputs[input].alone.as_ref() else {
            self.failures.push(format!("{id}: the input was not run"));
            return;
        };
        if observed.ok {
            println!(
                "ROW (\"{id}\", \"accepted\", \"-\", None, {}),",
                observed.used_script_units
            );
            self.failures.push(format!(
                "{id}: expected a refusal by {by}, the input PASSES"
            ));
            return;
        }
        let observed_by = observed.refused_by().unwrap_or("-").to_string();
        let variant = observed.error_variant().unwrap_or("-").to_string();
        let line = observed.sil_line();
        let in_table = self.pinned(id, &observed_by, &variant, line, observed.used_script_units);
        if observed_by != by {
            self.failures.push(format!(
                "{id}: expected a refusal by {by}; it was: {}",
                observed.describe()
            ));
            return;
        }
        if !in_table {
            return;
        }
        let expected = claim(id, by);
        if let Err(failure) = judge_twin(&run(honest), &outcome, &[(input, expected.clone())]) {
            self.failures.push(format!("{id}: {failure}"));
            return;
        }
        Case::new(id).note(note).twin(
            honest,
            |scenario| *scenario = changed.clone(),
            input,
            expected,
        );
    }

    /// The changed call passes like the honest one, in a transaction with the same id and
    /// another signature script at `input`.
    fn accepted(
        &mut self,
        id: &str,
        note: &str,
        honest: &Scenario,
        changed: &Scenario,
        input: usize,
    ) -> Option<Outcome> {
        if another_family_runs() {
            Case::new(id).note(note).expect_accept(changed);
            return None;
        }
        let honest_outcome = run(honest);
        let outcome = run(changed);
        let Some(observed) = outcome.inputs[input].alone.as_ref() else {
            self.failures.push(format!("{id}: the input was not run"));
            return None;
        };
        if !observed.ok {
            self.failures.push(format!(
                "{id}: expected to pass; it was: {}",
                observed.describe()
            ));
            return None;
        }
        if !self.pinned(id, "accepted", "-", None, observed.used_script_units) {
            return None;
        }
        if let Err(failure) = judge_accept(&honest_outcome).and(judge_accept(&outcome)) {
            self.failures.push(format!("{id}: {failure}"));
            return None;
        }
        let honest_tx = &honest_outcome.assembled.tx;
        let tx = &outcome.assembled.tx;
        if tx.id() != honest_tx.id() {
            self.failures
                .push(format!("{id}: the transaction id changed"));
            return None;
        }
        if tx.inputs[input].signature_script == honest_tx.inputs[input].signature_script {
            self.failures
                .push(format!("{id}: the signature script did not change"));
            return None;
        }
        Case::new(id).note(note).expect_accept(changed);
        Some(outcome)
    }

    /// Fails the test when a case differed from its claim or from the table.
    fn finish(self) {
        assert!(
            self.failures.is_empty(),
            "{} case(s) differ:\n{}",
            self.failures.len(),
            self.failures.join("\n")
        );
    }
}

/// The honest transfer of most cases: one coin of 100 tokens into two coins.
fn transfer_1_2() -> Scenario {
    shapes::transfer(&Profile::Script, 1, 2)
}

// ---------------------------------------------------------------------------------------
// 1. Rules that only hand-made call bytes reach
// ---------------------------------------------------------------------------------------

#[test]
fn an_unknown_tag_ends_in_the_dispatcher() {
    let mut log = Log::new();
    for (rule, honest) in [
        ("K-01", transfer_1_2()),
        ("M-01", shapes::mint(&Profile::Script)),
        ("S-01", shapes::seed_create(&Profile::Script)),
    ] {
        log.refused(
            &format!("reach/{rule} tag 00000000"),
            "the four tag bytes replaced by zeros, every other byte honest",
            &honest,
            &tag_replaced(&honest, 0, push(&[0; 4])),
            0,
            rule,
        );
    }
    log.finish();
}

#[test]
fn every_column_check_of_transfer_is_reachable() {
    let honest = transfer_1_2();
    let mut log = Log::new();
    for (rule, column, extra, what) in [
        ("K-03", AMOUNTS, 1, "amounts column of 17 bytes"),
        ("K-04", OWNERS, 1, "owners column of 65 bytes"),
        ("K-05", OWNERS, 32, "three owners for two amounts"),
        (
            "K-07",
            OWNER_SCHEMES,
            1,
            "three owner schemes for two amounts",
        ),
        (
            "K-09",
            BORROW_SCHEMES,
            1,
            "three borrow schemes for two amounts",
        ),
        ("K-10", BORROW_GUARDS, 1, "borrow guards column of 65 bytes"),
        (
            "K-11",
            BORROW_GUARDS,
            32,
            "three borrow guards for two amounts",
        ),
        (
            "K-12",
            EXTENSIONS,
            1,
            "extension commitments column of 65 bytes",
        ),
        (
            "K-13",
            EXTENSIONS,
            32,
            "three extension commitments for two amounts",
        ),
    ] {
        log.refused(
            &format!("reach/{rule} {what}"),
            "zero bytes appended to one column, the other five honest",
            &honest,
            &argument_changed(&honest, 0, column, longer(extra)),
            0,
            rule,
        );
    }
    log.finish();
}

#[test]
fn every_width_check_of_mint_and_create_is_reachable() {
    let mut log = Log::new();
    for (honest, rules) in [
        (
            shapes::mint(&Profile::Script),
            ["M-02", "M-03", "M-04", "M-05", "M-06", "M-07"],
        ),
        (
            shapes::seed_create(&Profile::Script),
            ["S-02", "S-03", "S-04", "S-05", "S-06", "S-07"],
        ),
    ] {
        let mut case = |rule: &str, what: &str, changed: Scenario| {
            log.refused(
                &format!("reach/{rule} {what}"),
                "one argument push of another width, every other byte honest",
                &honest,
                &changed,
                0,
                rule,
            );
        };
        case(
            rules[0],
            "amount in nine bytes",
            argument_changed(&honest, 0, AMOUNT, padded(9)),
        );
        for (rule, index, name) in [
            (rules[1], OWNER, "owner"),
            (rules[4], BORROW_GUARD, "borrow guard"),
            (rules[5], EXTENSION, "extension commitment"),
        ] {
            case(
                rule,
                &format!("{name} of 33 bytes"),
                argument_changed(&honest, 0, index, longer(1)),
            );
            case(
                rule,
                &format!("{name} of 31 bytes"),
                argument_changed(&honest, 0, index, shorter(1)),
            );
        }
        for (rule, index, name) in [
            (rules[2], OWNER_SCHEME, "owner scheme"),
            (rules[3], BORROW_SCHEME, "borrow scheme"),
        ] {
            case(
                rule,
                &format!("{name} as an empty push"),
                argument_changed(&honest, 0, index, exactly(&[])),
            );
            case(
                rule,
                &format!("{name} of two bytes"),
                argument_changed(&honest, 0, index, longer(1)),
            );
        }
    }
    log.finish();
}

#[test]
fn every_width_check_of_the_two_splits_is_reachable() {
    let mut log = Log::new();
    let note = "one argument push of another width, every other byte honest";

    let honest = shapes::mint_split(&Profile::Script);
    log.refused(
        "reach/M-22 take in nine bytes",
        note,
        &honest,
        &argument_changed(&honest, 0, 0, padded(9)),
        0,
        "M-22",
    );
    log.refused(
        "reach/M-23 new owner of 33 bytes",
        note,
        &honest,
        &argument_changed(&honest, 0, 1, longer(1)),
        0,
        "M-23",
    );
    log.refused(
        "reach/M-23 new owner of 31 bytes",
        note,
        &honest,
        &argument_changed(&honest, 0, 1, shorter(1)),
        0,
        "M-23",
    );

    let honest = shapes::seed_split(&Profile::Script);
    log.refused(
        "reach/S-20 new owner of 33 bytes",
        note,
        &honest,
        &argument_changed(&honest, 0, 0, longer(1)),
        0,
        "S-20",
    );
    log.refused(
        "reach/S-20 new owner of 31 bytes",
        note,
        &honest,
        &argument_changed(&honest, 0, 0, shorter(1)),
        0,
        "S-20",
    );
    log.finish();
}

#[test]
fn a_signature_argument_that_is_not_65_bytes_is_refused_by_the_width_rule_of_its_entry() {
    let mut log = Log::new();
    for (rule, honest, input) in [
        ("M-31", shapes::mint_reclaim(&Profile::Script), 0),
        ("M-50", shapes::mint_reclaim_into(&Profile::Script), 1),
        ("S-36", shapes::seed_reclaim(&Profile::Script), 1),
    ] {
        for (what, changed) in [
            (
                "empty signature",
                argument_changed(&honest, input, 0, exactly(&[])),
            ),
            (
                "signature without its type byte, 64 bytes",
                argument_changed(&honest, input, 0, shorter(1)),
            ),
            (
                "signature with one more byte, 66 bytes",
                argument_changed(&honest, input, 0, longer(1)),
            ),
        ] {
            log.refused(
                &format!("reach/{rule} {what}"),
                "the owner's real signature, pushed in another width",
                &honest,
                &changed,
                input,
                rule,
            );
        }
    }
    log.finish();
}

// ---------------------------------------------------------------------------------------
// 2. The six columns of KCC20.transfer disagreeing
// ---------------------------------------------------------------------------------------

#[test]
fn columns_that_disagree_are_refused_in_front_of_the_body() {
    let mut log = Log::new();
    let two = transfer_1_2();
    let one = shapes::transfer(&Profile::Script, 1, 1);

    log.refused(
        "columns/two amounts, three owners",
        "16 bytes of amounts, 96 bytes of owners",
        &two,
        &argument_changed(&two, 0, OWNERS, longer(32)),
        0,
        "K-05",
    );
    log.refused(
        "columns/amounts column of 7 bytes",
        "one declared state whose amount lost its last byte",
        &one,
        &argument_changed(&one, 0, AMOUNTS, shorter(1)),
        0,
        "K-03",
    );
    log.refused(
        "columns/amounts column of 9 bytes",
        "one declared state whose amount has one byte more",
        &one,
        &argument_changed(&one, 0, AMOUNTS, longer(1)),
        0,
        "K-03",
    );

    // Each column one element short in turn; the amounts column decides the count, so a
    // short amounts column is noticed at the first column compared with it.
    for ((column, name, width), rule) in COLUMNS
        .into_iter()
        .zip(["K-05", "K-05", "K-07", "K-09", "K-11", "K-13"])
    {
        log.refused(
            &format!("columns/{name} one element short"),
            "two declared states, one column holds one element",
            &two,
            &argument_changed(&two, 0, column, shorter(width)),
            0,
            rule,
        );
        log.refused(
            &format!("columns/{name} empty"),
            "two declared states, one column is an empty push",
            &two,
            &argument_changed(&two, 0, column, exactly(&[])),
            0,
            rule,
        );
    }

    // A column in two pushes: seven column pushes where six belong, every later one read
    // one place off.
    log.refused(
        "columns/the owners column as two pushes",
        "each of the two owners in a push of its own",
        &two,
        &patched(&two, 0, |parts| {
            let owners = data_of(&parts.arguments[OWNERS]);
            let mut pushes = push(&owners[..32]);
            pushes.extend(push(&owners[32..]));
            parts.arguments[OWNERS] = pushes;
        }),
        0,
        "K-05",
    );

    // All six columns empty: the columns agree (no declared state), the body counts the
    // outputs.
    let all_empty = |honest: &Scenario| {
        patched(honest, 0, |parts| {
            for (column, _, _) in COLUMNS {
                parts.arguments[column] = push(&[]);
            }
        })
    };
    log.refused(
        "columns/all empty, one real output",
        "no declared state, one output bound to the leader",
        &one,
        &all_empty(&one),
        0,
        "K-24",
    );
    log.refused(
        "columns/all empty, two real outputs",
        "no declared state, two outputs bound to the leader",
        &two,
        &all_empty(&two),
        0,
        "K-24",
    );
    log.finish();
}

// ---------------------------------------------------------------------------------------
// 3. What the engine asks of a signature script
// ---------------------------------------------------------------------------------------

#[test]
fn a_signature_script_holds_pushes_only() {
    let honest = transfer_1_2();
    let mut log = Log::new();
    let not_push_only = "engine: SignatureScriptNotPushOnly";
    log.refused(
        "engine/OpNop in front of the arguments",
        "opcode 0x61 as the first byte of the signature script",
        &honest,
        &patched(&honest, 0, |parts| parts.arguments.insert(0, vec![0x61])),
        0,
        not_push_only,
    );
    log.refused(
        "engine/OpDup between the arguments and the tag",
        "opcode 0x76 after the witness push",
        &honest,
        &patched(&honest, 0, |parts| parts.arguments.push(vec![0x76])),
        0,
        not_push_only,
    );
    log.refused(
        "engine/OpDrop between the tag and the redeem script",
        "opcode 0x75 after the tag push",
        &honest,
        &patched(&honest, 0, |parts| parts.tag.push(0x75)),
        0,
        not_push_only,
    );
    log.refused(
        "engine/OpNop after the redeem script",
        "opcode 0x61 as the last byte of the signature script",
        &honest,
        &patched(&honest, 0, |parts| parts.redeem.push(0x61)),
        0,
        not_push_only,
    );
    log.refused(
        "engine/OpReserved in front of the arguments",
        "opcode 0x50 counts as a push opcode and cannot be executed",
        &honest,
        &patched(&honest, 0, |parts| parts.arguments.insert(0, vec![0x50])),
        0,
        "engine: OpcodeReserved",
    );
    log.finish();
}

#[test]
fn a_missing_argument_push_shifts_every_other_argument() {
    let mut log = Log::new();
    let note = "one push fewer than the entry takes: the entry reads its arguments by depth";

    let honest = transfer_1_2();
    log.refused(
        "missing push/transfer without the witness",
        note,
        &honest,
        &patched(&honest, 0, |parts| {
            parts.arguments.remove(WITNESS);
        }),
        0,
        "engine: InvalidState",
    );
    log.refused(
        "missing push/transfer without the amounts column",
        note,
        &honest,
        &patched(&honest, 0, |parts| {
            parts.arguments.remove(AMOUNTS);
        }),
        0,
        "engine: InvalidState",
    );
    log.refused(
        "missing push/transfer without the owner schemes column",
        note,
        &honest,
        &patched(&honest, 0, |parts| {
            parts.arguments.remove(OWNER_SCHEMES);
        }),
        0,
        "engine: InvalidState",
    );

    let honest = shapes::transfer(&Profile::Script, 2, 1);
    log.refused(
        "missing push/transfer_delegator without its witness",
        note,
        &honest,
        &patched(&honest, 1, |parts| parts.arguments.clear()),
        1,
        "engine: InvalidState",
    );

    for (name, honest) in [
        ("mint", shapes::mint(&Profile::Script)),
        ("create", shapes::seed_create(&Profile::Script)),
    ] {
        log.refused(
            &format!("missing push/{name} without the suffix"),
            note,
            &honest,
            &patched(&honest, 0, |parts| {
                parts.arguments.remove(SUFFIX);
            }),
            0,
            "engine: InvalidState",
        );
        log.refused(
            &format!("missing push/{name} without the amount"),
            note,
            &honest,
            &patched(&honest, 0, |parts| {
                parts.arguments.remove(AMOUNT);
            }),
            0,
            "engine: InvalidState",
        );
        log.refused(
            &format!("missing push/{name} without both hidden arguments"),
            note,
            &honest,
            &patched(&honest, 0, |parts| parts.arguments.truncate(PREFIX)),
            0,
            "engine: InvalidState",
        );
    }

    for (name, honest, input) in [
        ("PublicMint.split", shapes::mint_split(&Profile::Script), 0),
        (
            "PublicMint.reclaim",
            shapes::mint_reclaim(&Profile::Script),
            0,
        ),
        (
            "PublicMint.reclaim_delegator",
            shapes::mint_reclaim_into(&Profile::Script),
            1,
        ),
        ("TokenSeed.split", shapes::seed_split(&Profile::Script), 0),
        (
            "TokenSeed.reclaim_delegator",
            shapes::seed_reclaim(&Profile::Script),
            1,
        ),
    ] {
        log.refused(
            &format!("missing push/{name} without its last argument"),
            note,
            &honest,
            &patched(&honest, input, |parts| {
                parts.arguments.pop();
            }),
            input,
            "engine: InvalidState",
        );
    }
    log.finish();
}

#[test]
fn an_extra_push_in_front_is_refused_by_the_final_stack_rule() {
    let mut log = Log::new();
    for (name, honest, input) in [
        ("transfer", transfer_1_2(), 0),
        (
            "transfer_delegator",
            shapes::transfer(&Profile::Script, 2, 1),
            1,
        ),
        ("mint", shapes::mint(&Profile::Script), 0),
        (
            "PublicMint.reclaim",
            shapes::mint_reclaim(&Profile::Script),
            0,
        ),
        ("create", shapes::seed_create(&Profile::Script), 0),
        (
            "TokenSeed.reclaim",
            shapes::seed_reclaim(&Profile::Script),
            0,
        ),
    ] {
        log.refused(
            &format!("extra push/{name} with one more item below the arguments"),
            "the entry runs to its end; one item too many is left on the stack",
            &honest,
            &patched(&honest, input, |parts| {
                parts.arguments.insert(0, push(&[0x07]))
            }),
            input,
            "final stack",
        );
    }
    log.finish();
}

#[test]
fn a_redeem_script_with_nothing_in_front_stops_at_its_first_opcode() {
    let mut log = Log::new();
    for (name, honest) in [
        ("KCC20", transfer_1_2()),
        ("PublicMint", shapes::mint(&Profile::Script)),
        ("TokenSeed", shapes::seed_create(&Profile::Script)),
    ] {
        log.refused(
            &format!("no call/{name} redeem script alone"),
            "no argument push and no tag push",
            &honest,
            &patched(&honest, 0, |parts| {
                parts.arguments.clear();
                parts.tag.clear();
            }),
            0,
            "engine: InvalidStackOperation",
        );
    }
    log.finish();
}

#[test]
fn the_tag_of_another_entry_of_the_same_contract_meets_that_entry_s_checks() {
    let mut log = Log::new();
    let note = "the arguments of one entry under the tag of another";

    let lone = transfer_1_2();
    log.refused(
        "other entry/transfer arguments under the tag of transfer_delegator, lone coin",
        note,
        &lone,
        &tag_of(&lone, 0, Entry::TransferDelegator),
        0,
        "K-68",
    );
    let pair = shapes::transfer(&Profile::Script, 2, 1);
    log.refused(
        "other entry/transfer arguments under the tag of transfer_delegator, first of two",
        note,
        &pair,
        &tag_of(&pair, 0, Entry::TransferDelegator),
        0,
        "K-69",
    );
    log.refused(
        "other entry/transfer_delegator witness under the tag of transfer",
        note,
        &pair,
        &tag_of(&pair, 1, Entry::Transfer),
        1,
        "engine: InvalidState",
    );

    let mint = shapes::mint(&Profile::Script);
    for (entry, by) in [
        (Entry::MintSplit, "M-23"),
        (Entry::MintReclaim, "M-31"),
        (Entry::MintReclaimInto, "M-36"),
        (Entry::MintReclaimDelegator, "M-50"),
    ] {
        log.refused(
            &format!("other entry/mint arguments under the tag of {entry}"),
            note,
            &mint,
            &tag_of(&mint, 0, entry),
            0,
            by,
        );
    }
    let split = shapes::mint_split(&Profile::Script);
    log.refused(
        "other entry/PublicMint.split arguments under the tag of mint",
        note,
        &split,
        &tag_of(&split, 0, Entry::Mint),
        0,
        "engine: InvalidState",
    );

    let create = shapes::seed_create(&Profile::Script);
    for (entry, by) in [
        (Entry::SeedSplit, "S-20"),
        (Entry::SeedReclaim, "S-26"),
        (Entry::SeedReclaimDelegator, "S-36"),
    ] {
        log.refused(
            &format!("other entry/create arguments under the tag of {entry}"),
            note,
            &create,
            &tag_of(&create, 0, entry),
            0,
            by,
        );
    }
    log.finish();
}

#[test]
fn a_valid_signature_next_to_changed_call_bytes_opens_nothing() {
    // No signature covers the signature script, so the tag next to an owner's signature can
    // be replaced by anybody. Three entries take one signature and nothing else; the owner's
    // real signature is moved from the entry it was made for to its neighbour.
    let mut log = Log::new();
    let note = "the owner's valid signature, the tag of a neighbouring entry";

    let lone = shapes::mint_reclaim(&Profile::Script);
    log.refused(
        "signed, other tag/a lone minter's reclaim as reclaim_delegator",
        note,
        &lone,
        &tag_of(&lone, 0, Entry::MintReclaimDelegator),
        0,
        "M-51",
    );
    let minters = shapes::mint_reclaim_into(&Profile::Script);
    log.refused(
        "signed, other tag/a retiring minter's reclaim_delegator as reclaim",
        note,
        &minters,
        &tag_of(&minters, 1, Entry::MintReclaim),
        1,
        "M-32",
    );
    let seeds = shapes::seed_reclaim(&Profile::Script);
    log.refused(
        "signed, other tag/a retiring seed's reclaim_delegator as reclaim",
        note,
        &seeds,
        &tag_of(&seeds, 1, Entry::SeedReclaim),
        1,
        "S-27",
    );
    // A delegate that wants to lead: its own valid signature behind a path byte, the six
    // columns of the real leader, the tag of transfer.
    let pair = shapes::transfer(&Profile::Script, 2, 1);
    let mut columns = raw::split_pushes(&call_bytes_of(&pair, 0)).expect("pushes");
    columns.truncate(WITNESS);
    log.refused(
        "signed, other tag/a delegate's signature in a call of transfer",
        "the delegate's signature behind a path byte 0x00, the leader's six columns, the \
         tag of transfer",
        &pair,
        &patched(&pair, 1, move |parts| {
            let mut witness = vec![0x00];
            witness.extend(data_of(&parts.arguments[0]));
            parts.arguments = columns.clone();
            parts.arguments.push(push(&witness));
            parts.tag = push(&checks::family().dispatch_tag(Entry::Transfer));
        }),
        1,
        "K-14",
    );

    // An argument next to the signature: the two declared owners exchanged after the owner
    // signed. The outputs, which the signature covers, are not what the call declares.
    let honest = transfer_1_2();
    log.refused(
        "signed, other arguments/the two declared owners exchanged",
        "the owner's valid signature, the owners column rotated by one element",
        &honest,
        &argument_changed(&honest, 0, OWNERS, |mut owners| {
            owners.rotate_left(32);
            owners
        }),
        0,
        "K-66",
    );
    log.finish();
}

#[test]
fn a_tag_the_contract_does_not_know_ends_in_the_dispatcher() {
    let mut log = Log::new();
    let family = checks::family();

    // The tag of an entry of another contract.
    for (name, honest, entry, rule) in [
        ("KCC20 coin", transfer_1_2(), Entry::Mint, "K-01"),
        (
            "PublicMint coin",
            shapes::mint(&Profile::Script),
            Entry::Transfer,
            "M-01",
        ),
        (
            "PublicMint coin",
            shapes::mint(&Profile::Script),
            Entry::SeedCreate,
            "M-01",
        ),
        (
            "TokenSeed coin",
            shapes::seed_create(&Profile::Script),
            Entry::Mint,
            "S-01",
        ),
    ] {
        log.refused(
            &format!("other contract/{name} under the tag of {entry}"),
            "honest arguments, the tag of an entry of another contract",
            &honest,
            &tag_of(&honest, 0, entry),
            0,
            rule,
        );
    }

    // A tag of another length.
    let honest = transfer_1_2();
    let tag = family.dispatch_tag(Entry::Transfer);
    let mut five = tag.to_vec();
    five.push(0x00);
    for (what, bytes) in [
        ("3 bytes", tag[..3].to_vec()),
        ("5 bytes", five),
        ("an empty push", Vec::new()),
    ] {
        log.refused(
            &format!("tag length/transfer tag of {what}"),
            "the honest tag cut or extended; the comparison is byte for byte",
            &honest,
            &tag_replaced(&honest, 0, push(&bytes)),
            0,
            "K-01",
        );
    }
    log.refused(
        "tag length/transfer without a tag push",
        "the witness takes the place of the tag",
        &honest,
        &tag_replaced(&honest, 0, Vec::new()),
        0,
        "K-01",
    );
    log.finish();
}

#[test]
fn the_redeem_script_is_the_last_push_and_nothing_follows_it() {
    let honest = transfer_1_2();
    let mut log = Log::new();
    let wrapper = "P2SH wrapper";
    log.refused(
        "redeem push/an empty push after the redeem script",
        "the last push is what the coin's script hashes",
        &honest,
        &patched(&honest, 0, |parts| parts.redeem.push(0x00)),
        0,
        wrapper,
    );
    log.refused(
        "redeem push/the tag pushed again after the redeem script",
        "the last push is what the coin's script hashes",
        &honest,
        &patched(&honest, 0, |parts| {
            let tag = parts.tag.clone();
            parts.redeem.extend(tag);
        }),
        0,
        wrapper,
    );
    log.refused(
        "redeem push/half a push after the redeem script",
        "0x05 announces five bytes, one follows",
        &honest,
        &patched(&honest, 0, |parts| parts.redeem.extend([0x05, 0x01])),
        0,
        "engine: MalformedPush",
    );
    log.refused(
        "redeem push/omitted",
        "the tag is the last push",
        &honest,
        &patched(&honest, 0, |parts| parts.redeem.clear()),
        0,
        wrapper,
    );
    log.refused(
        "redeem push/one byte of the redeem script changed",
        "the last byte of the pushed script, an OpEndIf, becomes another opcode",
        &honest,
        &patched(&honest, 0, |parts| {
            let last = parts.redeem.len() - 1;
            parts.redeem[last] ^= 0x01;
        }),
        0,
        wrapper,
    );
    let reclaim = shapes::seed_reclaim(&Profile::Script);
    log.refused(
        "redeem push/omitted, TokenSeed.reclaim",
        "an entry without arguments: the signature script is the tag push alone",
        &reclaim,
        &patched(&reclaim, 0, |parts| parts.redeem.clear()),
        0,
        wrapper,
    );
    log.refused(
        "redeem push/pushed twice",
        "the second copy runs; it finds the first copy where the tag belongs",
        &honest,
        &patched(&honest, 0, |parts| {
            let redeem = parts.redeem.clone();
            parts.redeem.extend(redeem);
        }),
        0,
        "K-01",
    );
    log.refused(
        "redeem push/the tag pushed twice in front of it",
        "one push too many between the arguments and the script: every argument is read \
         one place off",
        &honest,
        &patched(&honest, 0, |parts| {
            let tag = parts.tag.clone();
            parts.tag.extend(tag);
        }),
        0,
        "K-04",
    );

    // The whole signature script replaced.
    let mut empty = honest.clone();
    empty.contract_input_mut(0).signature_script = Some(LateBytes::empty());
    log.refused(
        "redeem push/an empty signature script",
        "no byte at all",
        &honest,
        &empty,
        0,
        "P2SH wrapper",
    );
    let pair = shapes::transfer(&Profile::Script, 2, 1);
    let assembled = pair.assemble(checks::family()).expect("assembles");
    let mut borrowed = pair.clone();
    borrowed.contract_input_mut(1).signature_script = Some(LateBytes::fixed(
        assembled.tx.inputs[0].signature_script.clone(),
    ));
    log.refused(
        "redeem push/the whole signature script of the other token coin",
        "the delegate carries the leader's signature script, redeem script included",
        &pair,
        &borrowed,
        1,
        wrapper,
    );
    log.finish();
}

#[test]
fn the_call_of_one_coin_given_to_another_coin_of_the_family() {
    let mut log = Log::new();
    let note = "the bytes in front of the redeem push copied from another input, \
                signatures included";

    // Leader and delegate of one transfer exchange their calls.
    let pair = shapes::transfer(&Profile::Script, 2, 1);
    log.refused(
        "other coin/the leader's call on the delegate",
        note,
        &pair,
        &with_call_bytes(&pair, 1, call_bytes_of(&pair, 0)),
        1,
        "K-14",
    );
    log.refused(
        "other coin/the delegate's call on the leader",
        note,
        &pair,
        &with_call_bytes(&pair, 0, call_bytes_of(&pair, 1)),
        0,
        "K-69",
    );

    // One delegate's call on the other delegate: the signature of another key.
    let three = shapes::transfer(&Profile::Script, 3, 1);
    log.refused(
        "other coin/a delegate's call on the other delegate, two owners",
        note,
        &three,
        &with_call_bytes(&three, 2, call_bytes_of(&three, 1)),
        2,
        "K-38",
    );

    // The same with one owner for both delegates: the right key signed, for the other coin.
    let mut one_owner = shapes::transfer(&Profile::Script, 3, 1);
    {
        let second = one_owner.contract_input_mut(2);
        second.state.as_kcc20_mut().expect("a token coin").owner = keys::x_only(ALICE + 1);
        *second.witness_mut() = witness::owner_key(ALICE + 1, EntryRole::Delegate, SIG_HASH_ALL);
    }
    log.refused(
        "other coin/a delegate's call on the other delegate, one owner",
        "the owner's own signature, made for the other of his two coins in this transaction",
        &one_owner,
        &with_call_bytes(&one_owner, 2, call_bytes_of(&one_owner, 1)),
        2,
        "K-38",
    );

    // Across contracts: mint and create take the same pushes under different tags.
    let mint = shapes::mint(&Profile::Script);
    let create = shapes::seed_create(&Profile::Script);
    log.refused(
        "other coin/the seed's create call on the minter",
        note,
        &mint,
        &with_call_bytes(&mint, 0, call_bytes_of(&create, 0)),
        0,
        "M-01",
    );
    log.refused(
        "other coin/the minter's mint call on the seed",
        note,
        &create,
        &with_call_bytes(&create, 0, call_bytes_of(&mint, 0)),
        0,
        "S-01",
    );

    // The two reclaim_delegator entries have one tag and one argument: the call of a
    // retiring minter is a well-formed call of a retiring seed, with a signature made for
    // another transaction.
    let seeds = shapes::seed_reclaim(&Profile::Script);
    let minters = shapes::mint_reclaim_into(&Profile::Script);
    log.refused(
        "other coin/the retiring minter's call on the retiring seed",
        note,
        &seeds,
        &with_call_bytes(&seeds, 1, call_bytes_of(&minters, 1)),
        1,
        "S-43",
    );
    log.refused(
        "other coin/the retiring seed's call on the retiring minter",
        note,
        &minters,
        &with_call_bytes(&minters, 1, call_bytes_of(&seeds, 1)),
        1,
        "M-57",
    );

    // The call of the surviving coin is a tag and no signature. Given to the retiring coin
    // as well, it would close that coin without a word of its owner.
    let unsigned = "no signature of the retiring coin's owner anywhere in the transaction";
    log.refused(
        "other coin/the surviving minter's call on the retiring minter",
        unsigned,
        &minters,
        &with_call_bytes(&minters, 1, call_bytes_of(&minters, 0)),
        1,
        "M-37",
    );
    log.refused(
        "other coin/the surviving seed's call on the retiring seed",
        unsigned,
        &seeds,
        &with_call_bytes(&seeds, 1, call_bytes_of(&seeds, 0)),
        1,
        "S-27",
    );
    log.finish();
}

#[test]
fn the_two_reclaim_delegator_entries_share_one_tag() {
    let family = checks::family();
    assert_eq!(
        family.dispatch_tag(Entry::MintReclaimDelegator),
        family.dispatch_tag(Entry::SeedReclaimDelegator),
        "the tag is made of the entry's name and parameters, not of its contract"
    );
    // So a typed call of the minter's entry on the retiring seed is byte for byte the
    // honest call of the seed's own entry.
    let honest = shapes::seed_reclaim(&Profile::Script);
    let mut renamed = honest.clone();
    let arguments = std::mem::take(renamed.contract_input_mut(1).args_mut());
    renamed.contract_input_mut(1).call = Call::typed(Entry::MintReclaimDelegator, arguments);
    let honest = honest.assemble(family).expect("assembles");
    let renamed = renamed.assemble(family).expect("assembles");
    assert_eq!(honest.tx, renamed.tx);
}

// ---------------------------------------------------------------------------------------
// 4. Encodings the engine tolerates
// ---------------------------------------------------------------------------------------

#[test]
fn longer_push_opcodes_are_the_same_call() {
    let mut log = Log::new();
    let note = "every push that fits rewritten with this opcode; data, signatures and the \
                rest of the transaction untouched";
    for (name, honest, input) in [
        ("transfer", transfer_1_2(), 0),
        (
            "transfer, leader of two coins",
            shapes::transfer(&Profile::Script, 2, 1),
            0,
        ),
        (
            "transfer_delegator",
            shapes::transfer(&Profile::Script, 2, 1),
            1,
        ),
        ("mint", shapes::mint(&Profile::Script), 0),
        (
            "PublicMint.reclaim",
            shapes::mint_reclaim(&Profile::Script),
            0,
        ),
        (
            "PublicMint.reclaim_into",
            shapes::mint_reclaim_into(&Profile::Script),
            0,
        ),
        ("create", shapes::seed_create(&Profile::Script), 0),
        (
            "TokenSeed.reclaim_delegator",
            shapes::seed_reclaim(&Profile::Script),
            1,
        ),
    ] {
        for (form, form_name) in [
            (PushForm::PushData1, "OP_PUSHDATA1"),
            (PushForm::PushData2, "OP_PUSHDATA2"),
            (PushForm::PushData4, "OP_PUSHDATA4"),
        ] {
            let changed = all_pushes_in_form(&honest, input, form);
            let outcome = log.accepted(
                &format!("encoding/{name} with {form_name}"),
                note,
                &honest,
                &changed,
                input,
            );
            // The owner's signature inside is the one of the honest call.
            if let Some(outcome) = outcome {
                let honest_script = &run(&honest).assembled.tx.inputs[input].signature_script;
                let script = &outcome.assembled.tx.inputs[input].signature_script;
                let data = |script: &[u8]| -> Vec<Vec<u8>> {
                    raw::split_pushes(script)
                        .expect("pushes")
                        .iter()
                        .map(|part| data_of(part))
                        .collect()
                };
                assert_eq!(data(script), data(honest_script), "{name} {form_name}");
                assert!(script.len() > honest_script.len());

                // The opcode form of a push costs no script units.
                let units = |outcome: &Outcome| {
                    let run = outcome.inputs[input].alone.as_ref();
                    run.expect("the input was run").used_script_units
                };
                assert_eq!(units(&outcome), units(&run(&honest)), "{name} {form_name}");
            }
        }
    }

    // One part at a time, on the transfer.
    let honest = transfer_1_2();
    log.accepted(
        "encoding/transfer, the tag alone with OP_PUSHDATA1",
        "4c 04 and the four tag bytes",
        &honest,
        &patched(&honest, 0, |parts| {
            parts.tag = in_form(&parts.tag, PushForm::PushData1)
        }),
        0,
    );
    log.accepted(
        "encoding/transfer, the redeem script alone with OP_PUSHDATA4",
        "4e bf 0f 00 00 and the script",
        &honest,
        &patched(&honest, 0, |parts| {
            parts.redeem = in_form(&parts.redeem, PushForm::PushData4)
        }),
        0,
    );
    log.accepted(
        "encoding/transfer, the witness alone with OP_PUSHDATA2",
        "4d 42 00 and the path byte with the signature",
        &honest,
        &patched(&honest, 0, |parts| {
            parts.arguments[WITNESS] = in_form(&parts.arguments[WITNESS], PushForm::PushData2)
        }),
        0,
    );
    log.finish();
}

#[test]
fn longer_number_bytes_are_the_same_number() {
    let mut log = Log::new();

    // PublicMint.mint: the amount 10 is the one-opcode push 5a in the honest call.
    let mint = shapes::mint(&Profile::Script);
    for (what, script) in [
        ("as 01 0a", vec![0x01, 0x0a]),
        ("in two bytes", vec![0x02, 0x0a, 0x00]),
        ("in eight bytes", vec![0x08, 0x0a, 0, 0, 0, 0, 0, 0, 0]),
    ] {
        log.accepted(
            &format!("number/mint amount 10 {what}"),
            "the amount argument in more bytes than the shortest form",
            &mint,
            &argument_replaced(&mint, 0, AMOUNT, script),
            0,
        );
    }

    log.refused(
        "number/mint amount as negative zero",
        "01 80 reads as zero: the amount must be greater than zero",
        &mint,
        &argument_replaced(&mint, 0, AMOUNT, vec![0x01, 0x80]),
        0,
        "M-12",
    );

    // PublicMint.split: take 7 is the one-opcode push 57.
    let split = shapes::mint_split(&Profile::Script);
    log.accepted(
        "number/split take 7 in eight bytes",
        "the take argument padded with zero bytes",
        &split,
        &argument_replaced(&split, 0, 0, vec![0x08, 0x07, 0, 0, 0, 0, 0, 0, 0]),
        0,
    );

    // TokenSeed.create: the amount must be zero; the honest push is the empty item.
    let create = shapes::seed_create(&Profile::Script);
    for (what, script) in [
        ("as one zero byte", vec![0x01, 0x00]),
        ("as negative zero, 01 80", vec![0x01, 0x80]),
        ("as eight zero bytes", vec![0x08, 0, 0, 0, 0, 0, 0, 0, 0]),
        (
            "as negative zero in eight bytes",
            vec![0x08, 0, 0, 0, 0, 0, 0, 0, 0x80],
        ),
    ] {
        log.accepted(
            &format!("number/create amount zero {what}"),
            "another byte string that reads as the number zero",
            &create,
            &argument_replaced(&create, 0, AMOUNT, script),
            0,
        );
    }
    log.refused(
        "number/create amount zero as negative zero in nine bytes",
        "nine bytes are no number for the engine; the width check answers first",
        &create,
        &argument_replaced(&create, 0, AMOUNT, vec![0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0x80]),
        0,
        "S-02",
    );

    // A byte argument: the borrow scheme 0x01 of the created coin is the one-opcode push 51.
    log.accepted(
        "number/create borrow scheme 0x01 as 01 01",
        "a one-byte argument with an explicit length byte",
        &create,
        &argument_replaced(&create, 0, BORROW_SCHEME, vec![0x01, 0x01]),
        0,
    );

    // KCC20.transfer takes its amounts as a column of 8-byte elements. Alice's 100 tokens
    // become 100 and 0; the zero is then declared as negative zero, the outputs stay the
    // honest ones. The call is accepted.
    let mut transfer = transfer_1_2();
    for (index, amount) in [(0, 100), (1, 0)] {
        transfer.contract_input_mut(0).declared_states_mut()[index].amount = amount;
        transfer
            .contract_output_mut(index)
            .state
            .as_kcc20_mut()
            .expect("a token output")
            .amount = amount;
    }
    log.accepted(
        "number/transfer declared amount zero as negative zero",
        "the last byte of the amounts column becomes 0x80; outputs honest",
        &transfer,
        &argument_changed(&transfer, 0, AMOUNTS, |mut amounts| {
            amounts[15] = 0x80;
            amounts
        }),
        0,
    );
    log.finish();
}

#[test]
fn a_re_encoded_call_is_a_larger_transaction_with_the_same_id() {
    // A statement about the size and the fee of a transaction of the pinned contracts: a
    // run on other contracts, or without the rules of a node, has nothing to add to it.
    if another_family_runs() {
        return;
    }

    // A one-to-one transfer of a 10 KAS token coin with a signed funding coin and change,
    // paying exactly the fee floor of a default mempool.
    let ten_kas = |fee: u64| {
        let values = Realistic {
            fee,
            ..Realistic::default()
        };
        shapes::transfer(&Profile::Realistic(values), 1, 1)
    };
    let floor = run(&ten_kas(1))
        .mempool
        .minimum_fee
        .expect("the fee floor of a well formed transaction is known");
    let honest = ten_kas(floor);
    let honest_outcome = Case::new("encoding/10 KAS transfer at the fee floor")
        .note("the honest call: a default mempool accepts it")
        .expect_mempool_accept(&honest);

    // Anybody can rewrite the pushes of the token input: no signature covers them. Seven
    // arguments and the tag grow by four bytes each, the redeem push by two.
    let changed = all_pushes_in_form(&honest, 0, PushForm::PushData4);
    let outcome = Case::new("encoding/10 KAS transfer at the fee floor, with OP_PUSHDATA4")
        .note(
            "the same transaction id, 34 bytes more: scripts and consensus accept it, the \
             fee floor of a default mempool is now above the fee",
        )
        .expect_mempool_refused(&changed, "check_minimum_relay_fee");
    assert_eq!(outcome.assembled.tx.id(), honest_outcome.assembled.tx.id());
    assert!(outcome.scripts.accepted && outcome.consensus.accepted);
    assert!(honest_outcome.consensus.block.accepted && outcome.consensus.block.accepted);

    let honest_masses = honest_outcome.masses.as_ref().expect("masses");
    let masses = outcome.masses.as_ref().expect("masses");
    assert_eq!(masses.estimated_size, honest_masses.estimated_size + 34);
    assert_eq!(masses.compute_mass, honest_masses.compute_mass + 34);
    assert!(masses.transient_mass > honest_masses.transient_mass);
    assert_eq!(
        masses.calculated_storage_mass,
        honest_masses.calculated_storage_mass
    );
    assert_eq!(outcome.mempool.fee, Some(floor));
    assert!(outcome.mempool.minimum_fee > Some(floor));
    assert_eq!(honest_outcome.budgets.minimal, outcome.budgets.minimal);
}

// ---------------------------------------------------------------------------------------
// 5. The hidden arguments of mint and create
// ---------------------------------------------------------------------------------------

#[test]
fn the_hidden_prefix_and_suffix_must_be_those_of_the_kcc20_script() {
    let family = checks::family();
    let mut log = Log::new();
    for (name, honest, rule) in [
        ("mint", shapes::mint(&Profile::Script), "M-20"),
        ("create", shapes::seed_create(&Profile::Script), "S-18"),
    ] {
        let suffix_len = family.suffix(Contract::Kcc20).len();
        let mut case = |what: &str, changed: Scenario| {
            log.refused(
                &format!("hidden/{name} {what}"),
                "the outputs stay honest; only the hidden arguments of the call change",
                &honest,
                &changed,
                0,
                rule,
            );
        };
        case(
            "suffix, first byte changed",
            argument_changed(&honest, 0, SUFFIX, flipped(0)),
        );
        case(
            "suffix, a byte in the middle changed",
            argument_changed(&honest, 0, SUFFIX, flipped(suffix_len / 2)),
        );
        case(
            "suffix, last byte changed",
            argument_changed(&honest, 0, SUFFIX, flipped(suffix_len - 1)),
        );
        case(
            "suffix, last byte cut",
            argument_changed(&honest, 0, SUFFIX, shorter(1)),
        );
        case(
            "suffix, one byte appended",
            argument_changed(&honest, 0, SUFFIX, longer(1)),
        );
        case(
            "suffix empty",
            argument_changed(&honest, 0, SUFFIX, exactly(&[])),
        );
        case(
            "prefix changed",
            argument_changed(&honest, 0, PREFIX, flipped(0)),
        );
        case(
            "prefix empty",
            argument_changed(&honest, 0, PREFIX, exactly(&[])),
        );
        case(
            "prefix of two bytes",
            argument_changed(&honest, 0, PREFIX, longer(1)),
        );
        case(
            "prefix and suffix swapped",
            patched(&honest, 0, |parts| parts.arguments.swap(PREFIX, SUFFIX)),
        );
        case(
            "the same bytes cut at another place",
            patched(&honest, 0, |parts| {
                let mut prefix = data_of(&parts.arguments[PREFIX]);
                let mut suffix = data_of(&parts.arguments[SUFFIX]);
                prefix.push(suffix.remove(0));
                parts.arguments[PREFIX] = push(&prefix);
                parts.arguments[SUFFIX] = push(&suffix);
            }),
        );
        for other in [Contract::PublicMint, Contract::TokenSeed] {
            case(
                &format!("suffix of {}", other.name()),
                argument_changed(&honest, 0, SUFFIX, exactly(family.suffix(other))),
            );
        }
    }
    log.finish();
}

// ---------------------------------------------------------------------------------------
// The table itself
// ---------------------------------------------------------------------------------------

#[test]
fn the_table_names_every_case_once_and_every_rule_of_the_list() {
    let mut ids: Vec<&str> = OBSERVED.iter().map(|row| row.0).collect();
    ids.sort_unstable();
    let count = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), count, "a case id appears twice in the table");

    // The 30 rules of the inventory that only hand-made call bytes reach.
    let list = [
        "K-01", "K-03", "K-04", "K-05", "K-07", "K-09", "K-10", "K-11", "K-12", "K-13", "M-01",
        "M-02", "M-03", "M-04", "M-05", "M-06", "M-07", "M-22", "M-23", "M-31", "M-50", "S-01",
        "S-02", "S-03", "S-04", "S-05", "S-06", "S-07", "S-20", "S-36",
    ];
    for rule in list {
        assert!(
            OBSERVED
                .iter()
                .any(|row| row.0.starts_with(&format!("reach/{rule} ")) && row.1 == rule),
            "no twin refused by {rule}"
        );
    }
    let refused_by_a_rule = OBSERVED
        .iter()
        .filter(|row| row.0.starts_with("reach/"))
        .all(|row| is_rule_id(row.1) && row.0.starts_with(&format!("reach/{} ", row.1)));
    assert!(
        refused_by_a_rule,
        "a twin of the list is refused by another rule"
    );
}
