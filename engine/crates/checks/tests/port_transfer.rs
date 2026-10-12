//! KCC20 on the real script engine: normal transfers, the owner and borrow schemes, and the
//! conformance vectors of the standard.
//!
//! The file re-runs three groups of checks of an earlier Python suite, which is not published
//! here and ran the same contracts on a debug engine, one input per call. The groups are
//! named by the first part of the ids of their checks:
//!
//! - `test_transfer` (18 checks): honest transfers, the conservation of the token amount,
//!   and the owner's signature;
//! - `test_schemes` (8 checks, one of them without a transaction): the five owner schemes
//!   and two of the borrow schemes;
//! - `test_conformance` (4 checks): the 22 cases of the KCC-20 conformance vector of the
//!   reference, each as a case of its own.
//!
//! Every sub-case of an earlier check is one case here, with the id of the earlier check
//! attached. Where the earlier check asserted a source line, the case is a twin: the honest
//! transaction passes, one change is made, and the same input is refused by the rule at
//! that line. Where it asserted only "refused", the case states what the engine answers.
//!
//! What differs from the earlier checks, everywhere:
//!
//! - The earlier suite had no check that a transaction pays out no more sompi than it
//!   spends, and most of its transactions paid out more. Here the token coins keep the
//!   values of the earlier checks
//!   and an `OP_TRUE` coin is added as the last input wherever the outputs exceed the
//!   inputs ([`fund`]); such a transaction pays no fee. Every transaction that is expected
//!   to pass is also one the consensus rules of a submission accept ([`accepted`]), and
//!   every twin is one whose scripts a node gets to run on both sides.
//! - The earlier checks used fresh random keys; here the keys are fixed, so that every case
//!   repeats.
//! - Every input of a transaction is run, with its complete signature script. The earlier
//!   suite ran the inputs it asserted and gave the others a bare push of their script.
//!
//! One earlier check is not re-run: `test_the_plain_python_curve_arithmetic_agrees_with_the_sdk`
//! compares two implementations of a public key derivation and runs no transaction; there is
//! no second implementation here. Its id is carried by one structural line with the note
//! `NOT PORTABLE: ..`, written by [`a_compressed_key_is_the_parity_byte_and_the_x_only_key`],
//! which holds the relation the check relied on for the fixed keys. So 29 of the 30 earlier
//! checks of this file are re-run, not 30.
//!
//! What a line asserts: an accept line asserts the scripts of the whole transaction and the
//! consensus rules of a submission ([`accepted`]); no line of this file asks a block or a
//! mempool (the coins are the 1000-sompi coins of the earlier checks). A line whose note
//! holds [`FUNDED`] runs the earlier transaction with one coin added; the note says
//! `DIFFERS FROM PYTHON:` for that reason, and the transaction as the earlier check wrote
//! it is run once for every accepted case ([`assert_refused_as_written`]): its scripts
//! pass and a node refuses it for its amounts before any script.

use checks::{Case, Expected, Outcome, Twin};
use kaspa_consensus_core::{hashing::sighash_type::SIG_HASH_ALL, tx::Transaction};
use kcc20_family::{
    EntryRole, Family, Scenario, State,
    keys::{self, ALICE, BOB, CAROL, SigningContext},
    refdata,
    scenario::{InputSpec, LateBytes, OrdinaryInput},
    shapes::{self, BorrowKind, Profile},
    states::{
        BORROW_HASH_CHAIN, Kcc20State, OWNER_COVENANT_ID, OWNER_P2PKH_ECDSA, OWNER_P2PKH_SCHNORR,
        OWNER_P2SH, PATH_NORMAL,
    },
    witness,
};
use serde_json::{Value, json};

/// Coin value of the earlier checks, in sompi.
const TOKEN_SOMPI: u64 = 1_000;

const TWO_POW_62: i64 = 1 << 62;

/// Said in the note of a case whose transaction has the added funding coin.
const FUNDED: &str = "token coin values as in the earlier check; an OP_TRUE coin, the last \
                      input, pays the sompi by which the outputs exceed the token input. \
                      DIFFERS FROM PYTHON: for the whole transaction only. The transaction \
                      of the earlier check itself, without that coin, pays out more sompi \
                      than it takes in: its scripts answer the same, and a node refuses it \
                      before it runs a script (check_transaction_output_values). For an \
                      accepted case that transaction is run once as written and both facts \
                      are asserted in this test, without a line of its own; for the \
                      refused cases they are asserted for a part of them (the amount \
                      cases, six of the signature cases and the vector cases) by the \
                      test the_added_funding_coin_changes_no_answer_of_a_token_input of \
                      review_ports_token.rs";

/// Said in the note of a case whose transaction is the earlier one, coin for coin.
const AS_IT_WAS: &str = "the transaction of the earlier check, with fixed keys";

/// A plain token coin: `amount` tokens owned by the key with the given seed.
fn token(owner_seed: u8, amount: i64) -> Kcc20State {
    Kcc20State::new(keys::x_only(owner_seed), amount)
}

/// One token coin of a transfer: its state, its value and the witness that spends it.
struct Coin {
    state: Kcc20State,
    value: u64,
    witness: LateBytes,
}

/// Alice's coin of `amount` tokens, spent with her signature as the leader.
fn alice_coin(amount: i64, value: u64) -> Coin {
    Coin {
        state: token(ALICE, amount),
        value,
        witness: witness::owner_key(ALICE, EntryRole::Leader, SIG_HASH_ALL),
    }
}

/// Adds an `OP_TRUE` coin worth the sompi by which the outputs exceed the inputs, if they
/// do. The earlier suite's own plain input is such a coin.
fn fund(mut scenario: Scenario) -> Scenario {
    let missing = scenario.total_out().saturating_sub(scenario.total_in());
    if missing > 0 {
        scenario.push_ordinary_input(
            OrdinaryInput::new(
                shapes::op_true_script(),
                missing,
                shapes::outpoint(3, 0),
                LateBytes::empty(),
            )
            .labelled("funding (OP_TRUE)"),
        );
    }
    scenario
}

/// A transfer with the given token coins and token outputs: the first coin leads, the
/// others join as delegates, every output is bound to the leader, and the states declared
/// to the leader are the states locked into the outputs.
///
/// It is the honest transfer shape of `kcc20-family` with its states, values and witnesses
/// replaced, and funded when the outputs are worth more than the coins.
fn transfer_of(coins: Vec<Coin>, outputs: Vec<(Kcc20State, u64)>) -> Scenario {
    let mut scenario = shapes::transfer(&Profile::Script, coins.len(), outputs.len());
    for (index, coin) in coins.into_iter().enumerate() {
        let input = scenario.contract_input_mut(index);
        input.state = coin.state.into();
        input.value = coin.value;
        *input.witness_mut() = coin.witness;
    }
    for (index, (state, value)) in outputs.into_iter().enumerate() {
        scenario.contract_input_mut(0).declared_states_mut()[index] = state.clone();
        let output = scenario.contract_output_mut(index);
        output.state = state.into();
        output.value = value;
    }
    fund(scenario)
}

/// Alice's coin of `amount` tokens and `value` sompi moved into one coin of `value` sompi
/// per part, each part given as (owner seed, tokens).
fn spend_sized(amount: i64, parts: &[(u8, i64)], value: u64) -> Scenario {
    transfer_of(
        vec![alice_coin(amount, value)],
        parts
            .iter()
            .map(|(owner, amount)| (token(*owner, *amount), value))
            .collect(),
    )
}

/// Alice's coin of 100 tokens moved into the given parts: the base shape of the earlier
/// transfer checks.
fn spend(parts: &[(u8, i64)]) -> Scenario {
    spend_sized(100, parts, TOKEN_SOMPI)
}

/// 100 tokens of Alice into 60 for Bob and 40 for herself: the honest twin of most
/// refusals of the earlier transfer checks.
fn sixty_forty() -> Scenario {
    spend(&[(BOB, 60), (ALICE, 40)])
}

/// Changes token output `index` in the call of the leader and in the output alike.
fn change_token_output(scenario: &mut Scenario, index: usize, change: impl Fn(&mut Kcc20State)) {
    change(&mut scenario.contract_input_mut(0).declared_states_mut()[index]);
    change(
        scenario
            .contract_output_mut(index)
            .state
            .as_kcc20_mut()
            .expect("a token output"),
    );
}

/// The leader witness of the normal path with the given bytes behind the path byte.
fn normal_path(owner_witness: impl AsRef<[u8]>) -> LateBytes {
    let mut witness = vec![PATH_NORMAL];
    witness.extend_from_slice(owner_witness.as_ref());
    LateBytes::fixed(witness)
}

/// Alice's genuine leader witness, passed through `damage` after it was made.
fn damaged_owner_witness(damage: impl Fn(Vec<u8>) -> Vec<u8> + Send + Sync + 'static) -> LateBytes {
    witness::owner_key(ALICE, EntryRole::Leader, SIG_HASH_ALL).map(damage)
}

/// Alice's genuine leader witness for another transaction: the one being assembled after
/// `alter` was applied to it.
fn signed_for_another_transaction(
    alter: impl Fn(&mut Transaction) + Send + Sync + 'static,
) -> LateBytes {
    LateBytes::from_tx(move |ctx| {
        let mut other = ctx.tx.clone();
        alter(&mut other.tx);
        let other_ctx = SigningContext {
            tx: &other,
            input_index: ctx.input_index,
        };
        let mut witness = vec![PATH_NORMAL];
        witness.extend(keys::schnorr_signature(
            &other_ctx,
            &keys::keypair(ALICE),
            SIG_HASH_ALL,
        ));
        witness
    })
}

/// The scripts accept the transaction, and so do the consensus rules a node applies to a
/// submission: the coin values and the funding of the case are those of a transaction a
/// node gets to run.
///
/// Where the transaction carries the funding coin of [`fund`], the transaction of the
/// earlier check itself is run once as well, as it was written
/// ([`assert_refused_as_written`]).
fn accepted(case: Case, scenario: &Scenario) -> Outcome {
    let outcome = case.expect_accept(scenario);
    assert!(
        outcome.consensus.accepted,
        "the scripts pass and the consensus rules refuse:\n{}",
        outcome.describe()
    );
    assert_refused_as_written(scenario);
    outcome
}

/// The scenario without the funding coin [`fund`] added as the last input: the transaction
/// of the earlier check itself. `None` when the scenario has no such coin.
fn as_the_earlier_check_built_it(scenario: &Scenario) -> Option<Scenario> {
    let funded = matches!(
        scenario.inputs.last(),
        Some(InputSpec::Ordinary(input)) if input.label == "funding (OP_TRUE)"
    );
    if !funded {
        return None;
    }
    let mut bare = scenario.clone();
    bare.inputs.pop();
    bare.name = format!("{}, without the funding coin", scenario.name);
    Some(bare)
}

/// An accepted transaction that carries the funding coin, once more as the earlier check
/// wrote it, without that coin: the scripts of its inputs pass, as the earlier check said of
/// the input it ran, and a node refuses the transaction before it runs a script, for outputs
/// worth more than its inputs (`check_transaction_output_values`). No result line is
/// written; the note [`FUNDED`] of the case says what is asserted here.
fn assert_refused_as_written(scenario: &Scenario) {
    let Some(bare) = as_the_earlier_check_built_it(scenario) else {
        return;
    };
    let outcome = checks::run(&bare);
    checks::judge_accept(&outcome).unwrap_or_else(|failure| {
        panic!(
            "`{}`: the scripts of the earlier transaction: {failure}",
            bare.name
        )
    });
    if outcome.scripts_only() {
        return;
    }
    assert!(
        !outcome.consensus.context_accepted,
        "`{}`: a node gets to the scripts of a transaction that creates sompi",
        bare.name
    );
    assert_eq!(
        outcome
            .consensus
            .context_refusal
            .as_ref()
            .map(|refusal| refusal.rule.as_str()),
        Some("check_transaction_output_values"),
        "`{}`: the rule a node refuses the earlier transaction by",
        bare.name
    );
}

/// The debug text of the engine's error for input `input` of the changed side of a twin.
fn engine_words(twin: &Twin, input: usize) -> String {
    twin.changed.inputs[input]
        .alone
        .as_ref()
        .and_then(|run| run.error.as_ref())
        .map(|error| error.debug.clone())
        .expect("the input was run and refused")
}

// ---------------------------------------------------------------------------------------
// test_transfer: honest transfers
// ---------------------------------------------------------------------------------------

#[test]
fn honest_transfers_pass() {
    accepted(
        Case::new("transfer/honest/one coin to one coin of a new owner")
            .py(["test_transfer.HonestTransfer.test_one_coin_to_one_coin_of_a_new_owner"])
            .note(AS_IT_WAS),
        &spend(&[(BOB, 100)]),
    );
    accepted(
        Case::new("transfer/honest/one coin to two coins")
            .py(["test_transfer.HonestTransfer.test_one_coin_to_two_coins"])
            .note(FUNDED),
        &sixty_forty(),
    );
    let three =
        "test_transfer.HonestTransfer.test_one_coin_to_three_coins_the_most_this_reference_allows";
    accepted(
        Case::new("transfer/honest/one coin to three coins")
            .py([three])
            .note(FUNDED),
        &spend(&[(BOB, 60), (CAROL, 30), (ALICE, 10)]),
    );
    // The new coin may be paid into by anybody who adds more than 10 tokens; the coin that
    // is spent had no such policy.
    accepted(
        Case::new("transfer/honest/a borrow policy given on the way")
            .py([
                "test_transfer.HonestTransfer.test_a_coin_can_be_given_a_borrow_policy_on_the_way",
            ])
            .note(AS_IT_WAS),
        &transfer_of(
            vec![alice_coin(100, TOKEN_SOMPI)],
            vec![(token(BOB, 100).with_threshold(10), TOKEN_SOMPI)],
        ),
    );
}

#[test]
fn honest_transfers_of_other_amounts_and_coin_sizes_pass() {
    let cases: [(&str, i64, &[i64], u64, &str); 4] = [
        (
            "1 token into 1 and 0, 1000 sompi",
            1,
            &[1, 0],
            1_000,
            FUNDED,
        ),
        ("0 tokens into 0, 1000 sompi", 0, &[0], 1_000, AS_IT_WAS),
        (
            "2^62 tokens into 2^62 - 1 and 1, 2.5 KAS",
            TWO_POW_62,
            &[TWO_POW_62 - 1, 1],
            250_000_000,
            FUNDED,
        ),
        ("7 tokens into 3 and 4, 1 sompi", 7, &[3, 4], 1, FUNDED),
    ];
    for (name, amount, parts, value, note) in cases {
        let parts: Vec<(u8, i64)> = parts.iter().map(|part| (BOB, *part)).collect();
        accepted(
            Case::new(format!("transfer/honest/other sizes/{name}"))
                .py(["test_transfer.HonestTransfer.test_other_amounts_and_coin_sizes"])
                .note(note),
            &spend_sized(amount, &parts, value),
        );
    }
}

#[test]
fn an_output_may_carry_any_assigned_scheme_byte_and_no_other() {
    let py = "test_transfer.HonestTransfer.test_an_output_may_carry_any_assigned_scheme_byte_and_no_other";
    // The owner field stays Bob's key whatever the scheme byte says, as in the earlier
    // check.
    let with_schemes = |owner_scheme: u8, borrow_scheme: u8| {
        let mut state = token(BOB, 100);
        state.owner_scheme = owner_scheme;
        state.borrow_scheme = borrow_scheme;
        transfer_of(
            vec![alice_coin(100, TOKEN_SOMPI)],
            vec![(state, TOKEN_SOMPI)],
        )
    };
    for owner_scheme in 0x00..=0x04u8 {
        for borrow_scheme in 0x00..=0x03u8 {
            accepted(
                Case::new(format!(
                    "transfer/output schemes/owner {owner_scheme:#04x}, borrow {borrow_scheme:#04x}"
                ))
                .py([py])
                .note(AS_IT_WAS),
                &with_schemes(owner_scheme, borrow_scheme),
            );
        }
    }

    // Lines 58 and 61 are inside two helper functions inlined at lines 170 and 171.
    let honest = with_schemes(0x00, 0x00);
    for owner_scheme in [0x05u8, 0x7f, 0xff] {
        Case::new(format!(
            "transfer/output schemes/owner {owner_scheme:#04x} is not assigned"
        ))
        .py([py])
        .note(AS_IT_WAS)
        .twin(
            &honest,
            |scenario| change_token_output(scenario, 0, |state| state.owner_scheme = owner_scheme),
            0,
            Expected::rule("K-33").at_line(58),
        );
    }
    for borrow_scheme in [0x04u8, 0x7f, 0xff] {
        Case::new(format!(
            "transfer/output schemes/borrow {borrow_scheme:#04x} is not assigned"
        ))
        .py([py])
        .note(AS_IT_WAS)
        .twin(
            &honest,
            |scenario| {
                change_token_output(scenario, 0, |state| state.borrow_scheme = borrow_scheme)
            },
            0,
            Expected::rule("K-34").at_line(61),
        );
    }
}

// ---------------------------------------------------------------------------------------
// test_transfer: conservation of the token amount
// ---------------------------------------------------------------------------------------

#[test]
fn the_token_outputs_add_up_to_the_token_input() {
    let sum_rule = || Expected::rule("K-37").at_line(175);

    let more = "test_transfer.Conservation.test_outputs_summing_to_more_than_the_input_are_refused";
    accepted(
        Case::new("transfer/conservation/60 + 40 of 100")
            .py([more])
            .note(FUNDED),
        &sixty_forty(),
    );
    Case::new("transfer/conservation/60 + 41 of 100")
        .py([more])
        .note(FUNDED)
        .twin(
            &sixty_forty(),
            |scenario| change_token_output(scenario, 1, |state| state.amount = 41),
            0,
            sum_rule(),
        );

    // The rule is an equality: a token cannot vanish either.
    Case::new("transfer/conservation/60 + 39 of 100")
        .py(["test_transfer.Conservation.test_outputs_summing_to_less_are_refused_too"])
        .note(FUNDED)
        .twin(
            &sixty_forty(),
            |scenario| change_token_output(scenario, 1, |state| state.amount = 39),
            0,
            sum_rule(),
        );

    // One output, back to Alice, holding more than the coin that is spent.
    for (name, amount) in [("101", 101), ("2^62", TWO_POW_62)] {
        Case::new(format!("transfer/conservation/one output of {name} of 100"))
            .py(["test_transfer.Conservation.test_one_output_holding_more_is_refused"])
            .note(AS_IT_WAS)
            .twin(
                &spend(&[(ALICE, 100)]),
                |scenario| change_token_output(scenario, 0, |state| state.amount = amount),
                0,
                sum_rule(),
            );
    }
}

#[test]
fn a_negative_output_cannot_pay_for_a_larger_one() {
    // 200 + (-100) still add up to 100. The check of each output comes before the sum rule.
    Case::new("transfer/conservation/200 and -100 of 100")
        .py(["test_transfer.Conservation.test_a_negative_output_cannot_pay_for_a_larger_one"])
        .note(FUNDED)
        .twin(
            &sixty_forty(),
            |scenario| {
                change_token_output(scenario, 0, |state| state.amount = 200);
                change_token_output(scenario, 1, |state| state.amount = -100);
            },
            0,
            Expected::rule("K-32").at_line(169),
        );
}

#[test]
fn the_real_outputs_are_the_declared_states() {
    let py = "test_transfer.Conservation.test_the_real_outputs_must_be_the_declared_states";
    accepted(
        Case::new("transfer/conservation/declared states, control")
            .py([py])
            .note(FUNDED),
        &sixty_forty(),
    );
    // The call names 60 + 40, the second output is locked to 41: the sum rule sees honest
    // numbers. A call over lines 239-242.
    Case::new("transfer/conservation/output locked to 41, declared 40")
        .py([py])
        .note(FUNDED)
        .twin(
            &sixty_forty(),
            |scenario| {
                scenario
                    .contract_output_mut(1)
                    .state
                    .as_kcc20_mut()
                    .expect("a token output")
                    .amount = 41
            },
            0,
            Expected::rule("K-66").at_line(239),
        );
}

// ---------------------------------------------------------------------------------------
// test_transfer: the owner's signature
// ---------------------------------------------------------------------------------------

/// The owner check of scheme 0x00: lines 69-72, inside the helper inlined at line 179.
fn owner_signature_rule() -> Expected {
    Expected::rule("K-38").at_line(69)
}

#[test]
fn the_owners_signature_passes_and_another_keys_does_not() {
    accepted(
        Case::new("transfer/signature/the owner signs")
            .py(["test_transfer.OwnerSignature.test_the_owner_s_signature_passes"])
            .note(FUNDED),
        &sixty_forty(),
    );
    for (name, seed) in [("Bob, who receives", BOB), ("Carol, a stranger", CAROL)] {
        Case::new(format!("transfer/signature/signed by {name}"))
            .py(["test_transfer.OwnerSignature.test_a_genuine_signature_of_another_key_is_refused"])
            .note(FUNDED)
            .twin(
                &sixty_forty(),
                |scenario| {
                    *scenario.contract_input_mut(0).witness_mut() =
                        witness::owner_key(seed, EntryRole::Leader, SIG_HASH_ALL)
                },
                0,
                owner_signature_rule(),
            );
    }
}

#[test]
fn the_owners_signature_for_another_transaction_is_refused() {
    let py = "test_transfer.OwnerSignature.test_the_owner_s_signature_for_another_transaction_is_refused";
    // Alice signed the same spend with Carol as the first recipient: only the script of
    // output 0 differs.
    Case::new("transfer/signature/signed for another recipient")
        .py([py])
        .note(FUNDED)
        .twin(
            &sixty_forty(),
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() =
                    signed_for_another_transaction(|tx| {
                        tx.outputs[0].script_public_key = Family::pinned()
                            .script_public_key(&State::from(token(CAROL, 60)))
                            .expect("the script of a token coin")
                    })
            },
            0,
            owner_signature_rule(),
        );
    // Alice signed the same spend with one sompi more on output 1.
    Case::new("transfer/signature/signed for another coin value")
        .py([py])
        .note(FUNDED)
        .twin(
            &sixty_forty(),
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() =
                    signed_for_another_transaction(|tx| tx.outputs[1].value += 1)
            },
            0,
            owner_signature_rule(),
        );
}

#[test]
fn made_up_and_placeholder_signatures_are_refused() {
    let py = "test_transfer.OwnerSignature.test_made_up_and_placeholder_signatures_are_refused";
    // Sixty-four bytes that are no signature (the earlier check drew them at random), and
    // sixty-four zero bytes, which is what a builder writes before it signs. Length and
    // type byte are those of an honest signature, so the signature check answers "false"
    // and the verify of the rule refuses.
    let made_up: Vec<u8> = (0..64u8)
        .map(|index| index.wrapping_mul(37).wrapping_add(11))
        .collect();
    for (name, bytes) in [("made-up bytes", made_up), ("zero bytes", vec![0u8; 64])] {
        Case::new(format!("transfer/signature/{name}"))
            .py([py])
            .note(FUNDED)
            .twin(
                &sixty_forty(),
                |scenario| {
                    let mut signature = bytes;
                    signature.push(SIG_HASH_ALL.to_u8());
                    *scenario.contract_input_mut(0).witness_mut() = normal_path(signature);
                },
                0,
                owner_signature_rule(),
            );
    }
}

#[test]
fn a_witness_of_the_wrong_length_is_refused() {
    let py = "test_transfer.OwnerSignature.test_a_witness_of_the_wrong_length_is_refused";
    // The earlier check asserted a refusal and no place. The first three are refused by the
    // engine inside the statement at line 69, the fourth by rule K-38 of that statement.

    // 64 bytes behind the path byte: the last signature byte is taken for the type byte.
    let twin = Case::new("transfer/signature/witness without the type byte")
        .py([py])
        .note(format!(
            "{FUNDED}; the earlier check asserted only a refusal; the engine: \
             InvalidSigHashType(81) at OpCheckSig in the statement at KCC20.sil:69, the last \
             byte of this signature read as the type byte"
        ))
        .twin(
            &sixty_forty(),
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() =
                    damaged_owner_witness(|mut witness| {
                        witness.pop();
                        witness
                    })
            },
            0,
            Expected::engine("InvalidSigHashType").at_line(69),
        );
    assert_eq!(engine_words(&twin, 0), "InvalidSigHashType(81)");

    // The same with a signature whose last byte happens to be one of the six type bytes
    // (the earlier check made a fresh signature in every run, so about one run in forty
    // met this): the type byte is accepted and the 63 bytes left are no signature.
    let twin = Case::new("transfer/signature/witness without the type byte, ending in 0x01")
        .py([py])
        .note(format!(
            "{FUNDED}; the earlier check asserted only a refusal; the engine: \
             InvalidSignature(InvalidSignature) at OpCheckSig in the statement at KCC20.sil:69, \
             a signature of 63 bytes"
        ))
        .twin(
            &sixty_forty(),
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() =
                    damaged_owner_witness(|mut witness| {
                        witness.pop();
                        *witness.last_mut().expect("a signature") = SIG_HASH_ALL.to_u8();
                        witness
                    })
            },
            0,
            Expected::engine("InvalidSignature").at_line(69),
        );
    assert_eq!(engine_words(&twin, 0), "InvalidSignature(InvalidSignature)");

    // 66 bytes behind the path byte: the added zero byte is taken for the type byte.
    let twin = Case::new("transfer/signature/witness with one byte more")
        .py([py])
        .note(format!(
            "{FUNDED}; the earlier check asserted only a refusal; the engine: \
             InvalidSigHashType(0) at OpCheckSig in the statement at KCC20.sil:69"
        ))
        .twin(
            &sixty_forty(),
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() =
                    damaged_owner_witness(|mut witness| {
                        witness.push(0x00);
                        witness
                    })
            },
            0,
            Expected::engine("InvalidSigHashType").at_line(69),
        );
    assert_eq!(engine_words(&twin, 0), "InvalidSigHashType(0)");

    // The path byte alone: an empty signature makes the signature check answer "false".
    Case::new("transfer/signature/witness of the path byte alone")
        .py([py])
        .note(format!(
            "{FUNDED}; the earlier check asserted only a refusal; the engine: rule K-38, the \
             verify behind the signature check at KCC20.sil:69"
        ))
        .twin(
            &sixty_forty(),
            |scenario| *scenario.contract_input_mut(0).witness_mut() = normal_path([]),
            0,
            owner_signature_rule(),
        );
}

#[test]
fn an_empty_witness_and_an_unknown_path_byte_are_refused() {
    let py =
        "test_transfer.OwnerSignature.test_an_empty_witness_and_an_unknown_path_byte_are_refused";
    Case::new("transfer/signature/no witness bytes at all")
        .py([py])
        .note(format!(
            "{FUNDED}; the earlier check asserted only a refusal; the engine: rule K-25, the \
             statement at KCC20.sil:161"
        ))
        .twin(
            &sixty_forty(),
            |scenario| *scenario.contract_input_mut(0).witness_mut() = LateBytes::empty(),
            0,
            Expected::rule("K-25").at_line(161),
        );
    // The genuine signature behind a path byte that is not assigned: the last `else` of
    // the path choice.
    Case::new("transfer/signature/path byte 2")
        .py([py])
        .note(FUNDED)
        .twin(
            &sixty_forty(),
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() =
                    damaged_owner_witness(|mut witness| {
                        witness[0] = 0x02;
                        witness
                    })
            },
            0,
            Expected::rule("K-63").at_line(222),
        );
}

#[test]
fn the_owners_signature_does_not_switch_the_sum_rule_off() {
    // The owner signs the inflated transaction itself: the signature is genuine, the sum
    // is not.
    let py =
        "test_transfer.OwnerSignature.test_the_owner_s_signature_does_not_switch_the_sum_rule_off";
    Case::new("transfer/signature/the owner signs 60 + 41 of 100")
        .py([py])
        .note(FUNDED)
        .twin(
            &sixty_forty(),
            |scenario| change_token_output(scenario, 1, |state| state.amount = 41),
            0,
            Expected::rule("K-37").at_line(175),
        );
}

// ---------------------------------------------------------------------------------------
// test_schemes: owner schemes
// ---------------------------------------------------------------------------------------

/// Alice's coin with the given owner scheme moved to a plain coin of Bob: the transaction
/// of the earlier scheme checks, as `kcc20-family` builds it.
fn owner_scheme_transfer(scheme: u8) -> Scenario {
    shapes::transfer_with_owner_scheme(&Profile::Script, EntryRole::Leader, scheme)
}

#[test]
fn a_key_hash_owner_is_the_hash_of_a_schnorr_key() {
    let py = "test_schemes.OwnerSchemes.test_p2pkh_schnorr_owner_is_the_hash_of_a_key";
    let honest = owner_scheme_transfer(OWNER_P2PKH_SCHNORR);
    accepted(
        Case::new("schemes/owner key hash, schnorr/the owner's key and signature")
            .py([py])
            .note(AS_IT_WAS),
        &honest,
    );
    Case::new("schemes/owner key hash, schnorr/another key pair")
        .py([py])
        .note(AS_IT_WAS)
        .twin(
            &honest,
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() =
                    witness::owner_key_hash_schnorr(BOB, EntryRole::Leader, SIG_HASH_ALL)
            },
            0,
            Expected::rule("K-40").at_line(78),
        );
    Case::new("schemes/owner key hash, schnorr/the owner's key, another key's signature")
        .py([py])
        .note(AS_IT_WAS)
        .twin(
            &honest,
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() = LateBytes::from_tx(|ctx| {
                    let mut witness = vec![PATH_NORMAL];
                    witness.extend(keys::x_only(ALICE));
                    witness.extend(keys::schnorr_signature(
                        ctx,
                        &keys::keypair(BOB),
                        SIG_HASH_ALL,
                    ));
                    witness
                })
            },
            0,
            Expected::rule("K-41").at_line(79),
        );
}

#[test]
fn a_key_hash_owner_is_the_hash_of_an_ecdsa_key() {
    let py = "test_schemes.OwnerSchemes.test_p2pkh_ecdsa_owner_is_the_hash_of_an_ecdsa_key";
    let honest = owner_scheme_transfer(OWNER_P2PKH_ECDSA);
    accepted(
        Case::new("schemes/owner key hash, ecdsa/the owner's key and signature")
            .py([py])
            .note(AS_IT_WAS),
        &honest,
    );
    Case::new("schemes/owner key hash, ecdsa/another key pair")
        .py([py])
        .note(AS_IT_WAS)
        .twin(
            &honest,
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() =
                    witness::owner_key_hash_ecdsa(CAROL, EntryRole::Leader, SIG_HASH_ALL)
            },
            0,
            Expected::rule("K-43").at_line(85),
        );
    Case::new("schemes/owner key hash, ecdsa/the owner's key, another key's signature")
        .py([py])
        .note(AS_IT_WAS)
        .twin(
            &honest,
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() = LateBytes::from_tx(|ctx| {
                    let mut witness = vec![PATH_NORMAL];
                    witness.extend(keys::compressed(ALICE));
                    witness.extend(keys::ecdsa_signature(
                        ctx,
                        &keys::keypair(CAROL),
                        SIG_HASH_ALL,
                    ));
                    witness
                })
            },
            0,
            Expected::rule("K-44").at_line(86),
        );
}

#[test]
fn a_compressed_key_is_the_parity_byte_and_the_x_only_key() {
    // What the earlier suite checked of its own curve arithmetic before it signed with
    // ECDSA. No transaction is run. The earlier check itself is not repeated: the structural
    // line below carries its id and says so.
    for seed in [ALICE, BOB, CAROL] {
        let compressed = keys::compressed(seed);
        assert!(matches!(compressed[0], 0x02 | 0x03));
        assert_eq!(compressed[1..], keys::x_only(seed));
    }
    checks::results::record_structural(
        "schemes/the plain Python curve arithmetic: not portable",
        &["test_schemes.OwnerSchemes.test_the_plain_python_curve_arithmetic_agrees_with_the_sdk"],
        "NOT PORTABLE: the earlier check held a second, plain-Python curve multiplication \
         against the SDK and ran no transaction and no engine. No second implementation \
         exists here, so the check has no object and is NOT re-run; this line is not an \
         agreement. What is asserted instead, for the fixed keys of Alice, Bob and Carol: \
         the compressed key is a parity byte 0x02 or 0x03 followed by the x-only key (two \
         helpers of the same key crate).",
    );
}

#[test]
fn a_script_hash_owner_needs_an_input_locked_by_that_script() {
    let py = "test_schemes.OwnerSchemes.test_p2sh_owner_is_a_script_hash_and_needs_such_an_input";
    // Input 1 is a pay-to-script-hash coin of `OP_TRUE`, spent by pushing that script: a
    // spend the earlier engine never ran. The witness names its index.
    let honest = owner_scheme_transfer(OWNER_P2SH);
    accepted(
        Case::new("schemes/owner script hash/the authority is input 1")
            .py([py])
            .note(AS_IT_WAS),
        &honest,
    );
    Case::new("schemes/owner script hash/index 0, the token coin itself")
        .py([py])
        .note(
            "the earlier check asserted only a refusal; the engine: rule K-46, the comparison \
             of the script of input 0 with the owner's script hash at KCC20.sil:90",
        )
        .twin(
            &honest,
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() =
                    witness::owner_script_hash(0, EntryRole::Leader)
            },
            0,
            Expected::rule("K-46").at_line(90),
        );
    let twin = Case::new("schemes/owner script hash/index 2, no such input")
        .py([py])
        .note(
            "the earlier check asserted only a refusal; the engine: InvalidInputIndex(2, 2) at \
             OpTxInputSpk in the statement at KCC20.sil:90, in front of the comparison of rule \
             K-46; no rule of the contract is reached",
        )
        .twin(
            &honest,
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() =
                    witness::owner_script_hash(2, EntryRole::Leader)
            },
            0,
            Expected::engine("InvalidInputIndex").at_line(90),
        );
    assert_eq!(engine_words(&twin, 0), "InvalidInputIndex(2, 2)");
    // Input 1 is a bare `OP_TRUE` coin instead: no input is locked by the owner's script.
    Case::new("schemes/owner script hash/input 1 is locked by another script")
        .py([py])
        .note(AS_IT_WAS)
        .twin(
            &honest,
            |scenario| {
                let other = scenario.ordinary_input_mut(1);
                other.script_public_key = shapes::op_true_script();
                other.signature_script = LateBytes::empty();
            },
            0,
            Expected::rule("K-46").at_line(90),
        );
}

/// The earlier check's transaction of owner scheme 0x04: the token coin is owned by
/// another covenant, and input 1 is a bare `OP_TRUE` coin that carries that covenant's id.
/// (The shape of `kcc20-family` locks that coin to a script hash.)
fn owned_by_another_covenant() -> Scenario {
    let mut scenario = owner_scheme_transfer(OWNER_COVENANT_ID);
    let other = scenario.ordinary_input_mut(1);
    other.script_public_key = shapes::op_true_script();
    other.signature_script = LateBytes::empty();
    other.label = "a coin of the owning covenant (OP_TRUE)".to_string();
    scenario
}

#[test]
fn a_covenant_id_owner_needs_an_input_of_that_covenant() {
    let py = "test_schemes.OwnerSchemes.test_covenant_id_owner_needs_an_input_of_that_covenant";
    let honest = owned_by_another_covenant();
    accepted(
        Case::new("schemes/owner covenant id/an input of the owning covenant takes part")
            .py([py])
            .note(AS_IT_WAS),
        &honest,
    );
    Case::new("schemes/owner covenant id/no input of the owning covenant")
        .py([py])
        .note(AS_IT_WAS)
        .twin(
            &honest,
            |scenario| scenario.ordinary_input_mut(1).covenant_id = None,
            0,
            Expected::rule("K-48").at_line(96),
        );
    Case::new("schemes/owner covenant id/one witness byte behind the path byte")
        .py([py])
        .note(AS_IT_WAS)
        .twin(
            &honest,
            |scenario| *scenario.contract_input_mut(0).witness_mut() = normal_path([0x00]),
            0,
            Expected::rule("K-47").at_line(95),
        );
}

#[test]
fn a_coin_owned_by_its_own_covenant_is_spent_with_no_key() {
    // The coin is itself an input of the covenant that owns it: no key and no other input.
    let py =
        "test_schemes.OwnerSchemes.test_a_coin_owned_by_its_own_covenant_id_is_spent_with_no_key";
    accepted(
        Case::new("schemes/owner covenant id/the coin is owned by its own covenant")
            .py([py])
            .note(AS_IT_WAS),
        &shapes::transfer_owned_by_its_own_covenant(&Profile::Script, EntryRole::Leader),
    );
}

// ---------------------------------------------------------------------------------------
// test_schemes: borrow schemes
// ---------------------------------------------------------------------------------------

#[test]
fn the_signature_borrow_scheme_asks_the_borrow_key_not_the_owner() {
    let py = "test_schemes.BorrowSchemes.test_schnorr_signature_scheme_asks_the_borrow_key_not_the_owner";
    // Bob's coin (200 tokens) leads on the borrow path, its guard is Carol's key; Alice's
    // coin (100 tokens) joins and adds one token.
    let honest = shapes::borrow(&Profile::Script, BorrowKind::Signature);
    accepted(
        Case::new("schemes/borrow signature/signed by the borrow key")
            .py([py])
            .note(AS_IT_WAS),
        &honest,
    );
    for (name, seed) in [
        ("Alice, the sender", ALICE),
        ("Bob, the owner of the coin", BOB),
    ] {
        Case::new(format!("schemes/borrow signature/signed by {name}"))
            .py([py])
            .note(AS_IT_WAS)
            .twin_inputs(
                &honest,
                |scenario| {
                    *scenario.contract_input_mut(0).witness_mut() =
                        witness::borrow_signature(seed, SIG_HASH_ALL)
                },
                &[
                    (0, Expected::rule("K-52").at_line(192)),
                    (1, Expected::pass()),
                ],
            );
    }
}

/// The link the earlier hash-chain check reveals.
const NEXT_GUARD: [u8; 32] = [0x77; 32];
/// A link that does not hash to the guard of the coin.
const WRONG_LINK: [u8; 32] = [0x78; 32];

/// The borrowed receive of the earlier hash-chain check: Bob's coin commits to
/// [`NEXT_GUARD`] and Carol's one-time key, Carol signs, the successor holds the next guard.
fn hash_chain_receive() -> Scenario {
    let mut scenario = shapes::borrow(&Profile::Script, BorrowKind::HashChain);
    let leader = scenario.contract_input_mut(0);
    leader
        .state
        .as_kcc20_mut()
        .expect("a token coin")
        .borrow_guard = witness::chain_guard(&NEXT_GUARD, CAROL);
    *leader.witness_mut() = witness::borrow_hash_chain(NEXT_GUARD, CAROL, SIG_HASH_ALL);
    change_token_output(&mut scenario, 0, |state| state.borrow_guard = NEXT_GUARD);
    scenario
}

#[test]
fn the_hash_chain_scheme_reveals_a_link_and_moves_the_guard_on() {
    let py =
        "test_schemes.BorrowSchemes.test_hash_chain_scheme_reveals_a_link_and_moves_the_guard_on";
    let honest = hash_chain_receive();
    accepted(
        Case::new("schemes/borrow hash chain/the link is revealed and the guard moves on")
            .py([py])
            .note(AS_IT_WAS),
        &honest,
    );
    // The new coin keeps the guard that was just used up.
    let used_guard = witness::chain_guard(&NEXT_GUARD, CAROL);
    Case::new("schemes/borrow hash chain/the guard is not moved on")
        .py([py])
        .note(AS_IT_WAS)
        .twin(
            &honest,
            |scenario| change_token_output(scenario, 0, |state| state.borrow_guard = used_guard),
            0,
            Expected::rule("K-60").at_line(217),
        );
    // Another link is revealed and carried into the new coin. A `require` over lines 205-209.
    Case::new("schemes/borrow hash chain/the revealed link does not hash to the guard")
        .py([py])
        .note(AS_IT_WAS)
        .twin(
            &honest,
            |scenario| {
                *scenario.contract_input_mut(0).witness_mut() =
                    witness::borrow_hash_chain(WRONG_LINK, CAROL, SIG_HASH_ALL);
                change_token_output(scenario, 0, |state| state.borrow_guard = WRONG_LINK);
            },
            0,
            Expected::rule("K-54").at_line(205),
        );
}

// ---------------------------------------------------------------------------------------
// test_conformance: the vectors of the standard
// ---------------------------------------------------------------------------------------

/// The key that stands in for the placeholder owner of the vector's leader coin.
const LEADER: u8 = ALICE;
/// The key of the signed sender coins.
const SENDER: u8 = BOB;
/// The one-time key of the hash-chain cases; the vector's own key has no private key.
const ONE_TIME: u8 = CAROL;

fn conformance_vectors() -> Value {
    refdata::load_conformance_vectors().expect("the conformance vectors of the reference")
}

fn list(value: &Value) -> &[Value] {
    value.as_array().expect("a list")
}

fn int(value: &Value) -> i64 {
    value.as_i64().expect("an integer")
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("a hex string");
    assert!(text.len().is_multiple_of(2), "`{text}` is not whole bytes");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex digits"))
        .collect()
}

fn hex32(value: &Value) -> [u8; 32] {
    hex(value).try_into().expect("32 bytes")
}

fn hex_byte(value: &Value) -> u8 {
    let bytes = hex(value);
    assert_eq!(bytes.len(), 1, "one byte");
    bytes[0]
}

fn case_id(case: &Value) -> &str {
    case["id"].as_str().expect("the id of a vector case")
}

/// A token state as the vector writes one.
fn vector_state(described: &Value) -> Kcc20State {
    Kcc20State {
        amount: int(&described["amount"]),
        owner: hex32(&described["owner_hex"]),
        owner_scheme: hex_byte(&described["owner_scheme_hex"]),
        borrow_scheme: hex_byte(&described["borrow_scheme_hex"]),
        borrow_guard: hex32(&described["borrow_guard_hex"]),
        extension_commitment: hex32(&described["extension_commitment_hex"]),
    }
}

/// `standard_transfer`: one leader on the normal path and the two successors of
/// `transfer_arguments`, with the fields a case lists replaced; one signed sender coin per
/// entry of `delegate_amounts`. As in the earlier check the placeholder owner of the leader
/// is replaced by a real key, which signs unless the case gives the witness bytes.
fn standard_transfer(vectors: &Value, case: Option<&Value>) -> Scenario {
    let common = &vectors["standard_transfer"]["common"];
    let listed = |field: &str| case.and_then(|case| case.get(field));

    let mut leader = vector_state(&common["leader_state"]);
    leader.owner = keys::x_only(LEADER);
    let mut after: Vec<Kcc20State> = list(&vectors["transfer_arguments"]["next_states"])
        .iter()
        .map(vector_state)
        .collect();
    if let Some(amounts) = listed("next_state_amounts") {
        assert_eq!(list(amounts).len(), after.len());
        for (state, amount) in after.iter_mut().zip(list(amounts)) {
            state.amount = int(amount);
        }
    }
    if let Some(schemes) = listed("next_state_owner_schemes_hex") {
        assert_eq!(list(schemes).len(), after.len());
        for (state, scheme) in after.iter_mut().zip(list(schemes)) {
            state.owner_scheme = hex_byte(scheme);
        }
    }
    if let Some(commitments) = listed("next_state_extension_commitments_hex") {
        assert_eq!(list(commitments).len(), after.len());
        for (state, commitment) in after.iter_mut().zip(list(commitments)) {
            state.extension_commitment = hex32(commitment);
        }
    }

    let leader_witness = match listed("witness_hex") {
        Some(witness) => LateBytes::fixed(hex(witness)),
        None => witness::owner_key(LEADER, EntryRole::Leader, SIG_HASH_ALL),
    };
    let mut coins = vec![Coin {
        state: leader,
        value: TOKEN_SOMPI,
        witness: leader_witness,
    }];
    let delegate_amounts = listed("delegate_amounts").unwrap_or(&common["delegate_amounts"]);
    coins.extend(list(delegate_amounts).iter().map(|amount| Coin {
        state: token(SENDER, int(amount)),
        value: TOKEN_SOMPI,
        witness: witness::owner_key(SENDER, EntryRole::Delegate, SIG_HASH_ALL),
    }));

    let mut scenario = transfer_of(
        coins,
        after
            .into_iter()
            .map(|state| (state, TOKEN_SOMPI))
            .collect(),
    );
    scenario.name = format!(
        "conformance, standard transfer: {}",
        case.map_or("common", case_id)
    );
    scenario
}

#[test]
fn the_standard_transfer_vectors_have_the_stated_outcomes() {
    let vectors = conformance_vectors();
    let common = standard_transfer(&vectors, None);
    accepted(
        Case::new("conformance/standard/common")
            .py(["test_conformance.StandardTransfer.test_the_common_transfer_is_accepted"])
            .note(FUNDED),
        &common,
    );

    // Every rejected case and the rule that must refuse it, read against the reason the
    // vector states.
    let refusing: [(&str, &str, u32); 6] = [
        ("negative-amount", "K-32", 169),
        ("unsupported-owner-scheme", "K-33", 58),
        ("invalid-witness-path-byte", "K-63", 222),
        ("extension-commitment-not-preserved", "K-35", 172),
        ("amount-not-preserved", "K-37", 175),
        ("over-max-token-inputs", "K-16", 132),
    ];
    let cases = list(&vectors["standard_transfer"]["cases"]);
    assert_eq!(
        cases.iter().map(case_id).collect::<Vec<_>>(),
        refusing.iter().map(|(id, ..)| *id).collect::<Vec<_>>()
    );

    for (case, (id, rule, line)) in cases.iter().zip(refusing) {
        assert_eq!(case["result"], "reject", "case `{id}`");
        let delegates = case
            .get("delegate_amounts")
            .map_or(0, |amounts| list(amounts).len());
        // The honest twin is the common transfer; for the case with four token inputs it
        // is the largest transfer the contract takes, three token inputs.
        let (honest, note) = if delegates > 0 {
            let three_inputs = json!({
                "id": "three token inputs",
                "delegate_amounts": [100, 100],
                "next_state_amounts": [600, 600],
            });
            (
                standard_transfer(&vectors, Some(&three_inputs)),
                "honest twin: the leader and two sender coins, 1200 tokens into 600 + 600; \
                 three coins of 1000 sompi into two, a fee of 1000 sompi (2000 with the \
                 fourth coin of the vector case)"
                    .to_string(),
            )
        } else {
            (
                common.clone(),
                format!("honest twin: the common transfer; {FUNDED}"),
            )
        };
        let changed = standard_transfer(&vectors, Some(case));
        // The sender coins are signed by their own owner: they pass.
        let mut expected = vec![(0, Expected::rule(rule).at_line(line))];
        expected.extend((1..=delegates).map(|input| (input, Expected::pass())));
        Case::new(format!("conformance/standard/{id}"))
            .py(["test_conformance.StandardTransfer.test_every_case_has_the_stated_outcome"])
            .note(note)
            .twin_inputs(&honest, |scenario| *scenario = changed, &expected);
    }
}

/// `borrowed_receive`: the recipient's coin leads on the borrow path, a signed sender coin
/// of 2000 tokens follows and takes the change.
///
/// For the hash-chain cases the vector's one-time key has no private key. As the earlier
/// check and the reference do: the link the vector reveals is kept, a real one-time key
/// signs, and the leader is committed to the hash of (the intended link, that key).
fn borrowed_receive(vectors: &Value, case: &Value) -> Scenario {
    let common = &vectors["borrowed_receive"]["common"];
    let scheme = hex_byte(&case["borrow_scheme_hex"]);
    let mut leader = Kcc20State {
        amount: int(&common["leader_amount"]),
        owner: hex32(&common["owner_hex"]),
        owner_scheme: hex_byte(&common["owner_scheme_hex"]),
        borrow_scheme: scheme,
        borrow_guard: hex32(&case["leader_borrow_guard_hex"]),
        extension_commitment: hex32(&common["extension_commitment_hex"]),
    };
    let mut successor = leader.clone();
    successor.amount = int(&case["successor_amount"]);
    successor.borrow_guard = hex32(&case["successor_borrow_guard_hex"]);
    if let Some(owner) = case.get("successor_owner_hex") {
        successor.owner = hex32(owner);
    }

    let vector_witness = hex(&case["witness_hex"]);
    let mut leader_witness = LateBytes::fixed(vector_witness.clone());
    if scheme == BORROW_HASH_CHAIN {
        assert_eq!(vector_witness.len(), 130, "path byte, link, key, signature");
        let revealed: [u8; 32] = vector_witness[1..33].try_into().expect("32 bytes");
        let intended = hex32(&vectors["hash_chain"]["links"][1]["x_hex"]);
        let committed = witness::chain_guard(&intended, ONE_TIME);
        leader.borrow_guard = committed;
        if case["successor_borrow_guard_hex"] == case["leader_borrow_guard_hex"] {
            successor.borrow_guard = committed;
        }
        leader_witness = witness::borrow_hash_chain(revealed, ONE_TIME, SIG_HASH_ALL);
    }

    let leader_sompi = case
        .get("leader_kas_value_sompi")
        .map_or(TOKEN_SOMPI, |value| {
            value.as_u64().expect("a value in sompi")
        });
    let successor_sompi = case
        .get("successor_kas_value_sompi")
        .map_or(leader_sompi, |value| {
            value.as_u64().expect("a value in sompi")
        });
    let change = token(SENDER, leader.amount + 2000 - successor.amount);

    let mut scenario = transfer_of(
        vec![
            Coin {
                state: leader,
                value: leader_sompi,
                witness: leader_witness,
            },
            Coin {
                state: token(SENDER, 2000),
                value: TOKEN_SOMPI,
                witness: witness::owner_key(SENDER, EntryRole::Delegate, SIG_HASH_ALL),
            },
        ],
        vec![(successor, successor_sompi), (change, TOKEN_SOMPI)],
    );
    scenario.name = format!("conformance, borrowed receive: {}", case_id(case));
    scenario
}

#[test]
fn the_borrowed_receive_vectors_have_the_stated_outcomes() {
    let py = [
        "test_conformance.BorrowedReceive.test_every_case_has_the_stated_outcome",
        "test_conformance.BorrowedReceive.test_accepted_and_rejected_counts",
    ];
    let vectors = conformance_vectors();
    let cases = list(&vectors["borrowed_receive"]["cases"]);
    assert_eq!(cases.len(), 16);
    let vector_case = |id: &str| {
        cases
            .iter()
            .find(|case| case_id(case) == id)
            .unwrap_or_else(|| panic!("the vector has no case `{id}`"))
    };

    // Every rejected case: the accepted case that is its honest twin, and the rule that
    // must refuse it, read against the reason the vector states. An empty twin id: the
    // case itself with the successor worth what the leader coin is worth.
    let refusing: [(&str, &str, &str, u32); 11] = [
        ("threshold-equal", "threshold-exceeded", "K-61", 219),
        (
            "threshold-negative-unchanged",
            "threshold-negative",
            "K-61",
            219,
        ),
        (
            "threshold-negative-decrease",
            "threshold-negative",
            "K-61",
            219,
        ),
        (
            "threshold-negative-zero-unchanged",
            "threshold-negative-zero",
            "K-61",
            219,
        ),
        (
            "threshold-guard-normalized",
            "threshold-negative",
            "K-60",
            217,
        ),
        ("disabled", "threshold-zero", "K-50", 184),
        (
            "hash-chain-guard-not-advanced",
            "hash-chain-valid",
            "K-60",
            217,
        ),
        ("unassigned-scheme", "threshold-zero", "K-34", 61),
        ("successor-changes-owner", "threshold-exceeded", "K-57", 214),
        ("successor-reduces-kas-value", "", "K-62", 220),
        ("hash-chain-link-mismatch", "hash-chain-valid", "K-54", 205),
    ];

    let mut every_input_passes = 0;
    for case in cases {
        let id = case_id(case);
        let scenario = borrowed_receive(&vectors, case);
        let recorded = Case::new(format!("conformance/borrowed/{id}")).py(py);
        match case["result"].as_str() {
            Some("accept") => {
                let outcome = accepted(
                    recorded
                        .note("the leader coin and the sender coin are worth what the outputs are"),
                    &scenario,
                );
                every_input_passes += usize::from(outcome.scripts_accept());
            }
            Some("reject") => {
                let (_, twin_id, rule, line) = refusing
                    .iter()
                    .find(|(refused, ..)| *refused == id)
                    .unwrap_or_else(|| panic!("no refusing rule is written down for `{id}`"));
                let (honest, note) = if twin_id.is_empty() {
                    let mut kept = case.clone();
                    kept.as_object_mut()
                        .expect("a vector case is an object")
                        .remove("successor_kas_value_sompi");
                    (
                        borrowed_receive(&vectors, &kept),
                        "honest twin: the same case with the successor worth what the leader \
                         coin is worth; the changed side pays a fee of one sompi"
                            .to_string(),
                    )
                } else {
                    (
                        borrowed_receive(&vectors, vector_case(twin_id)),
                        format!("honest twin: the accepted vector case `{twin_id}`"),
                    )
                };
                // The leader is refused by the stated rule; the sender coin asks its own
                // owner, who signed, and passes.
                let twin = recorded.note(note).twin_inputs(
                    &honest,
                    |changed| *changed = scenario,
                    &[
                        (0, Expected::rule(*rule).at_line(*line)),
                        (1, Expected::pass()),
                    ],
                );
                every_input_passes += usize::from(twin.changed.scripts_accept());
            }
            other => panic!("case `{id}`: unknown outcome {other:?}"),
        }
    }

    // The count of the earlier check: five of the sixteen transactions pass on every input.
    let stated = cases
        .iter()
        .filter(|case| case["result"] == "accept")
        .count();
    assert_eq!(every_input_passes, stated);
    assert_eq!(every_input_passes, 5);
}
