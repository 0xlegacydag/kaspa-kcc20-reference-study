//! The rule and the source line the test harness of `crates/checks` names, held against the
//! lines an earlier suite of checks asserted.
//!
//! That suite, which is not published here, ran the same contracts on a debug engine that
//! reports the source line of a refusal directly. Here the line is derived: the script
//! engine's stop position gives a byte offset in the redeem script, the compiler's debug
//! information gives the statement at that offset, the rule inventory gives the rule. If the
//! two ways agree on many refusals of different kinds, the derivation can be trusted where no
//! earlier line exists.
//!
//! Every case is a twin: the honest shape passes, one change is made, and the named input
//! is refused by the named rule at the named line. The ids of the earlier checks are
//! recorded with each result line.
//!
//! The cases cover all three contracts and the kinds of statement a refusal can come from:
//! a one-line `require`, a `require` over several lines, an output validation call, a
//! statement inside an inlined helper function, a loop body, and the engine's own checked
//! addition.

use checks::{Case, Expected, Twin};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kcc20_family::{
    Contract, Entry, EntryRole, Scenario,
    keys::{self, ALICE, BOB, CAROL},
    refdata,
    scenario::{Arg, Call, ContractInput, LateBytes, PlainOutput},
    shapes::{self, BorrowKind, Profile},
    states::{Kcc20State, PublicMintState},
    witness,
};

const KCC20: &str = "KCC20.sil";
const PUBLIC_MINT: &str = "PublicMint.sil";
const TOKEN_SEED: &str = "TokenSeed.sil";

/// Another token family: the value the earlier suite used for a foreign extension
/// commitment.
const OTHER_FAMILY: [u8; 32] = [0xee; 32];

const I64_MAX: i64 = i64::MAX;
const TWO_POW_62: i64 = 1 << 62;

/// One refusal the earlier suite asserted by its source line.
struct Asserted {
    input: usize,
    /// The rule of the inventory at that line.
    rule: &'static str,
    /// The engine error variant, when the refusal is not a failed check of the script.
    engine: Option<&'static str>,
    file: &'static str,
    line: u32,
}

/// A rule of the contract refused at `file:line`.
fn refused(input: usize, rule: &'static str, file: &'static str, line: u32) -> Asserted {
    Asserted {
        input,
        rule,
        engine: None,
        file,
        line,
    }
}

/// The engine refused the data of the statement at `file:line`, at the opcode of `rule`.
fn engine_error(
    input: usize,
    variant: &'static str,
    rule: &'static str,
    file: &'static str,
    line: u32,
) -> Asserted {
    Asserted {
        input,
        rule,
        engine: Some(variant),
        file,
        line,
    }
}

/// Runs the twin and holds the attributed rule, file and line against the asserted ones.
/// `passing` lists the inputs the earlier suite asserted to pass in the changed scenario.
fn check(
    case: &str,
    py_ids: &[&str],
    honest: &Scenario,
    change: impl FnOnce(&mut Scenario),
    asserted: &[Asserted],
    passing: &[usize],
) -> Twin {
    let mut expected: Vec<(usize, Expected)> = asserted
        .iter()
        .map(|asserted| {
            let expected = match asserted.engine {
                Some(variant) if asserted.rule.is_empty() => {
                    Expected::engine(variant).at_line(asserted.line)
                }
                Some(variant) => Expected::engine(variant)
                    .at_rule(asserted.rule)
                    .at_line(asserted.line),
                None => Expected::rule(asserted.rule).at_line(asserted.line),
            };
            (asserted.input, expected)
        })
        .collect();
    expected.extend(passing.iter().map(|input| (*input, Expected::pass())));

    let twin = Case::new(case)
        .py(py_ids.iter().copied())
        .twin_inputs(honest, change, &expected);
    for asserted in asserted {
        let run = twin.changed.inputs[asserted.input]
            .alone
            .as_ref()
            .expect("the input was run");
        let sil = run
            .refusal
            .as_ref()
            .and_then(|refusal| refusal.sil.as_ref())
            .expect("the refusal has a source line");
        assert_eq!(sil.file, asserted.file, "case `{case}`");
        assert_eq!(sil.line, asserted.line, "case `{case}`");
    }
    twin
}

fn script() -> Profile {
    Profile::Script
}

// ---------------------------------------------------------------------------------------
// PublicMint
// ---------------------------------------------------------------------------------------

#[test]
fn minter_merge_the_survivor_keeps_its_sompi() {
    check(
        "line/PublicMint 288 survivor deposit",
        &["A_minter.test_a_minter.ReclaimInto.test_02_survivor_deposit_plus_and_minus_one"],
        &shapes::mint_reclaim_into(&script()),
        |scenario| scenario.contract_output_mut(0).value = 999,
        &[refused(0, "M-48", PUBLIC_MINT, 288)],
        &[1],
    );
}

#[test]
fn minter_merge_the_retiring_minter_is_of_the_same_family() {
    check(
        "line/PublicMint 280 retiring family",
        &["A_minter.test_a_minter.ReclaimInto.test_03_retiring_of_another_family"],
        &shapes::mint_reclaim_into(&script()),
        |scenario| {
            scenario
                .contract_input_mut(1)
                .state
                .as_public_mint_mut()
                .unwrap()
                .extension_commitment = OTHER_FAMILY
        },
        &[refused(0, "M-46", PUBLIC_MINT, 280)],
        &[1],
    );
}

#[test]
fn minter_merge_the_retiring_minter_has_the_same_per_mint_limit() {
    check(
        "line/PublicMint 279 retiring per-mint limit",
        &[
            "A_minter.test_a_minter.ReclaimInto.test_04_retiring_with_another_per_mint_limit",
            "test_lifecycle.MinterLifecycle.test_minters_with_different_per_mint_limits_do_not_merge",
        ],
        &shapes::mint_reclaim_into(&script()),
        |scenario| {
            scenario
                .contract_input_mut(1)
                .state
                .as_public_mint_mut()
                .unwrap()
                .mint_amount = 11
        },
        &[refused(0, "M-45", PUBLIC_MINT, 279)],
        &[1],
    );
}

#[test]
fn minter_merge_the_successor_keeps_the_owner() {
    check(
        "line/PublicMint 300 successor owner",
        &["A_minter.test_a_minter.ReclaimInto.test_05_successor_with_another_owner"],
        &shapes::mint_reclaim_into(&script()),
        |scenario| {
            scenario
                .contract_output_mut(0)
                .state
                .as_public_mint_mut()
                .unwrap()
                .owner = keys::x_only(CAROL)
        },
        &[refused(0, "M-49", PUBLIC_MINT, 300)],
        &[1],
    );
}

#[test]
fn minter_merge_takes_exactly_two_minters() {
    check(
        "line/PublicMint 260 three minters",
        &["A_minter.test_a_minter.ReclaimInto.test_07_three_minters"],
        &shapes::mint_reclaim_into(&script()),
        |scenario| {
            scenario.push_contract_input(ContractInput::new(
                PublicMintState::new(keys::x_only(BOB), 3, 10),
                shapes::SCRIPT_SPLIT_VALUE,
                Some(shapes::covenant_id()),
                shapes::outpoint(1, 2),
                Call::typed(
                    Entry::MintReclaimDelegator,
                    vec![Arg::Bytes(witness::signature(BOB, SIG_HASH_ALL))],
                ),
            ));
            scenario.push_plain_output(PlainOutput::new(
                shapes::pay_to_public_key_script(&keys::x_only(BOB)),
                shapes::SCRIPT_SPLIT_VALUE,
            ));
            scenario
                .contract_output_mut(0)
                .state
                .as_public_mint_mut()
                .unwrap()
                .remaining = 25;
        },
        &[refused(0, "M-36", PUBLIC_MINT, 260)],
        &[1, 2],
    );
}

#[test]
fn minter_merge_the_sum_stays_inside_64_bits() {
    // The honest twin adds up to exactly the largest number; one more overflows in the
    // engine's checked addition. No `require` is involved.
    let mut honest = shapes::mint_reclaim_into(&script());
    honest
        .contract_input_mut(0)
        .state
        .as_public_mint_mut()
        .unwrap()
        .remaining = TWO_POW_62;
    honest
        .contract_input_mut(1)
        .state
        .as_public_mint_mut()
        .unwrap()
        .remaining = TWO_POW_62 - 1;
    honest
        .contract_output_mut(0)
        .state
        .as_public_mint_mut()
        .unwrap()
        .remaining = I64_MAX;
    check(
        "line/PublicMint 281 allowance overflow",
        &["A_minter.test_a_minter.ReclaimInto.test_08_sum_past_the_int64_range"],
        &honest,
        |scenario| {
            scenario
                .contract_input_mut(1)
                .state
                .as_public_mint_mut()
                .unwrap()
                .remaining = TWO_POW_62
        },
        &[engine_error(0, "NumberTooBig", "M-47", PUBLIC_MINT, 281)],
        &[1],
    );
}

#[test]
fn minter_merge_the_retiring_owner_signs() {
    let py_ids = [
        "A_minter.test_a_minter.ReclaimInto.test_09_retiring_signature",
        "test_lifecycle.MinterLifecycle.test_the_retiring_minter_asks_its_own_owner",
    ];
    check(
        "line/PublicMint 324 signature of the survivor's key",
        &py_ids,
        &shapes::mint_reclaim_into(&script()),
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() = witness::signature(ALICE, SIG_HASH_ALL)
        },
        &[refused(1, "M-57", PUBLIC_MINT, 324)],
        &[0],
    );
    // Sixty-five zero bytes: the last one is not a signature hash type. The engine refuses
    // inside the same statement, in the signature check itself, one opcode in front of the
    // verify of the rule.
    check(
        "line/PublicMint 324 sixty-five zero bytes",
        &py_ids[..1],
        &shapes::mint_reclaim_into(&script()),
        |scenario| *scenario.contract_input_mut(1).witness_mut() = LateBytes::fixed(vec![0u8; 65]),
        &[engine_error(1, "InvalidSigHashType", "", PUBLIC_MINT, 324)],
        &[0],
    );
}

#[test]
fn minter_split_takes_at_most_half() {
    check(
        "line/PublicMint 197 take 13 of 25",
        &[
            "A_minter.test_a_minter.Split.test_02_half_boundary",
            "test_lifecycle.MinterLifecycle.test_anyone_splits_off_up_to_half_of_the_allowance",
        ],
        &shapes::mint_split(&script()),
        |scenario| {
            scenario.contract_input_mut(0).args_mut()[0] = Arg::int(13);
            scenario
                .contract_output_mut(0)
                .state
                .as_public_mint_mut()
                .unwrap()
                .remaining = 12;
            scenario
                .contract_output_mut(1)
                .state
                .as_public_mint_mut()
                .unwrap()
                .remaining = 13;
        },
        &[refused(0, "M-27", PUBLIC_MINT, 197)],
        &[],
    );
}

#[test]
fn minter_split_the_retained_minter_keeps_its_sompi() {
    check(
        "line/PublicMint 212 retained deposit",
        &["A_minter.test_a_minter.Split.test_04_retained_deposit_plus_and_minus_one"],
        &shapes::mint_split(&script()),
        |scenario| scenario.contract_output_mut(0).value = 999,
        &[refused(0, "M-28", PUBLIC_MINT, 212)],
        &[],
    );
}

#[test]
fn mint_the_continuation_keeps_the_owner() {
    check(
        "line/PublicMint 161 continuation owner",
        &["A_minter.test_a_minter.Mint.test_01_continuation_owner_changed"],
        &shapes::mint(&script()),
        |scenario| {
            scenario
                .contract_output_mut(0)
                .state
                .as_public_mint_mut()
                .unwrap()
                .owner = keys::x_only(CAROL)
        },
        &[refused(0, "M-19", PUBLIC_MINT, 161)],
        &[],
    );
}

#[test]
fn mint_the_new_coin_holds_what_the_call_names() {
    // The call names 10 tokens, the output is locked to 11. The statement spans lines
    // 174-180; the earlier suite asserted its first line.
    check(
        "line/PublicMint 174 minted coin differs from the call",
        &["test_public_mint.PublicMint.test_the_new_coin_must_hold_what_the_call_names"],
        &shapes::mint(&script()),
        |scenario| {
            scenario
                .contract_output_mut(1)
                .state
                .as_kcc20_mut()
                .unwrap()
                .amount = 11
        },
        &[refused(0, "M-21", PUBLIC_MINT, 174)],
        &[],
    );
}

#[test]
fn minter_reclaim_needs_an_exhausted_minter() {
    check(
        "line/PublicMint 248 allowance left",
        &["test_lifecycle.MinterLifecycle.test_the_owner_takes_the_deposit_of_an_exhausted_minter"],
        &shapes::mint_reclaim(&script()),
        |scenario| {
            scenario
                .contract_input_mut(0)
                .state
                .as_public_mint_mut()
                .unwrap()
                .remaining = 1
        },
        &[refused(0, "M-34", PUBLIC_MINT, 248)],
        &[],
    );
}

// ---------------------------------------------------------------------------------------
// TokenSeed
// ---------------------------------------------------------------------------------------

/// Changes the recipient state of `TokenSeed.create` in the call and in the output alike.
fn change_created_coin(scenario: &mut Scenario, change: impl Fn(&mut Kcc20State)) {
    change(scenario.contract_input_mut(0).declared_state_mut());
    change(
        scenario
            .contract_output_mut(1)
            .state
            .as_kcc20_mut()
            .expect("the created token coin"),
    );
}

#[test]
fn seed_create_makes_an_empty_coin() {
    check(
        "line/TokenSeed 132 created amount -1",
        &[
            "B_seed.test_b_seed.Create.test_recipient_amount_minus_one",
            "test_token_seed.TokenSeedCreate.test_a_coin_holding_tokens_cannot_be_created",
        ],
        &shapes::seed_create(&script()),
        |scenario| change_created_coin(scenario, |state| state.amount = -1),
        &[refused(0, "S-12", TOKEN_SEED, 132)],
        &[],
    );
}

#[test]
fn seed_create_checks_the_scheme_bytes_in_helper_functions() {
    // Lines 66 and 69 are inside two helper functions that the compiler inlines at lines
    // 134 and 135 of the entry. The earlier suite asserted the line inside the helper.
    let twin = check(
        "line/TokenSeed 66 owner scheme 5",
        &["B_seed.test_b_seed.Create.test_recipient_owner_scheme_out_of_range"],
        &shapes::seed_create(&script()),
        |scenario| change_created_coin(scenario, |state| state.owner_scheme = 0x05),
        &[refused(0, "S-14", TOKEN_SEED, 66)],
        &[],
    );
    let refusal = twin.changed.inputs[0]
        .alone
        .as_ref()
        .unwrap()
        .refusal
        .as_ref()
        .unwrap();
    // The text is that of line 66 as it stands in the checkout of the reference.
    let line_66 = refdata::pinned_sil_source(Contract::TokenSeed)
        .lines()
        .nth(65)
        .expect("the generated source has line 66")
        .trim();
    assert_eq!(refusal.sil.as_ref().unwrap().text, line_66);
    assert_eq!(
        refusal.inventory_line.as_deref(),
        Some("134 -> 66"),
        "the inventory names the call site and the helper line"
    );
    assert_eq!(refusal.entry.as_deref(), Some("create"));

    check(
        "line/TokenSeed 69 borrow scheme 4",
        &["B_seed.test_b_seed.Create.test_recipient_borrow_scheme_out_of_range"],
        &shapes::seed_create(&script()),
        |scenario| change_created_coin(scenario, |state| state.borrow_scheme = 0x04),
        &[refused(0, "S-15", TOKEN_SEED, 69)],
        &[],
    );
}

#[test]
fn seed_create_keeps_the_seed() {
    check(
        "line/TokenSeed 136 seed deposit",
        &[
            "B_seed.test_b_seed.Create.test_seed_keeps_its_sompi",
            "test_token_seed.TokenSeedCreate.test_the_seed_stays_exactly_as_it_was",
        ],
        &shapes::seed_create(&script()),
        |scenario| scenario.contract_output_mut(0).value = 999,
        &[refused(0, "S-16", TOKEN_SEED, 136)],
        &[],
    );
    // A `require` over lines 138-141.
    check(
        "line/TokenSeed 138 seed owner",
        &[
            "B_seed.test_b_seed.Create.test_seed_keeps_its_owner",
            "test_token_seed.TokenSeedCreate.test_the_seed_stays_exactly_as_it_was",
        ],
        &shapes::seed_create(&script()),
        |scenario| {
            scenario
                .contract_output_mut(0)
                .state
                .as_token_seed_mut()
                .unwrap()
                .owner = keys::x_only(CAROL)
        },
        &[refused(0, "S-17", TOKEN_SEED, 138)],
        &[],
    );
}

#[test]
fn seed_create_the_new_coin_holds_what_the_call_names() {
    check(
        "line/TokenSeed 154 created coin differs from the call",
        &["test_token_seed.TokenSeedCreate.test_the_new_coin_must_hold_what_the_call_names"],
        &shapes::seed_create(&script()),
        |scenario| {
            scenario
                .contract_output_mut(1)
                .state
                .as_kcc20_mut()
                .unwrap()
                .amount = 1000
        },
        &[refused(0, "S-19", TOKEN_SEED, 154)],
        &[],
    );
}

#[test]
fn seed_split_keeps_the_seed_and_adds_one_of_the_family() {
    check(
        "line/TokenSeed 181 retained deposit",
        &["B_seed.test_b_seed.Split.test_retained_seed_keeps_its_sompi"],
        &shapes::seed_split(&script()),
        |scenario| scenario.contract_output_mut(0).value = 999,
        &[refused(0, "S-23", TOKEN_SEED, 181)],
        &[],
    );
    check(
        "line/TokenSeed 196 added seed of another family",
        &[
            "B_seed.test_b_seed.Split.test_added_seed_of_the_same_family",
            "test_lifecycle.SeedLifecycle.test_anyone_adds_a_second_seed_of_the_same_family",
        ],
        &shapes::seed_split(&script()),
        |scenario| {
            scenario
                .contract_output_mut(1)
                .state
                .as_token_seed_mut()
                .unwrap()
                .extension_commitment = OTHER_FAMILY
        },
        &[refused(0, "S-25", TOKEN_SEED, 196)],
        &[],
    );
}

#[test]
fn seed_reclaim_keeps_the_survivor_and_asks_the_retiring_owner() {
    check(
        "line/TokenSeed 225 survivor deposit",
        &["B_seed.test_b_seed.Reclaim.test_survivor_keeps_its_sompi"],
        &shapes::seed_reclaim(&script()),
        |scenario| scenario.contract_output_mut(0).value = 999,
        &[refused(0, "S-34", TOKEN_SEED, 225)],
        &[1],
    );
    check(
        "line/TokenSeed 224 retiring family",
        &["B_seed.test_b_seed.Reclaim.test_retiring_seed_of_another_family"],
        &shapes::seed_reclaim(&script()),
        |scenario| {
            scenario
                .contract_input_mut(1)
                .state
                .as_token_seed_mut()
                .unwrap()
                .extension_commitment = OTHER_FAMILY
        },
        &[refused(0, "S-33", TOKEN_SEED, 224)],
        &[1],
    );
    check(
        "line/TokenSeed 254 signature of the survivor's key",
        &[
            "B_seed.test_b_seed.Reclaim.test_retiring_seed_asks_its_owner",
            "test_lifecycle.SeedLifecycle.test_a_retiring_seed_gives_its_deposit_back_while_another_seed_survives",
        ],
        &shapes::seed_reclaim(&script()),
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() = witness::signature(ALICE, SIG_HASH_ALL)
        },
        &[refused(1, "S-43", TOKEN_SEED, 254)],
        &[0],
    );
}

// ---------------------------------------------------------------------------------------
// KCC20
// ---------------------------------------------------------------------------------------

/// Changes output `index` of a transfer in the call and in the output alike.
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

#[test]
fn transfer_the_outputs_add_up_to_the_inputs() {
    check(
        "line/KCC20 175 one token more",
        &["test_transfer.Conservation.test_one_output_holding_more_is_refused"],
        &shapes::transfer(&script(), 1, 1),
        |scenario| change_token_output(scenario, 0, |state| state.amount += 1),
        &[refused(0, "K-37", KCC20, 175)],
        &[],
    );
}

#[test]
fn transfer_no_output_is_negative() {
    // 150 + (-50) still add up to 100. The check is in the body of the loop over the
    // outputs; the second copy of the loop body refuses.
    let twin = check(
        "line/KCC20 169 negative output",
        &["test_transfer.Conservation.test_a_negative_output_cannot_pay_for_a_larger_one"],
        &shapes::transfer(&script(), 1, 2),
        |scenario| {
            change_token_output(scenario, 0, |state| state.amount = 150);
            change_token_output(scenario, 1, |state| state.amount = -50);
        },
        &[refused(0, "K-32", KCC20, 169)],
        &[],
    );
    let refusal = twin.changed.inputs[0]
        .alone
        .as_ref()
        .unwrap()
        .refusal
        .as_ref()
        .unwrap();
    assert_eq!(
        refusal.byte_offset,
        Some(1990),
        "the copy of the loop body for the second output"
    );
}

#[test]
fn transfer_the_real_outputs_are_the_declared_states() {
    // The call names 50 + 50, the second output is locked to 51. A call over lines 239-242.
    check(
        "line/KCC20 239 output differs from the call",
        &["test_transfer.Conservation.test_the_real_outputs_must_be_the_declared_states"],
        &shapes::transfer(&script(), 1, 2),
        |scenario| {
            scenario
                .contract_output_mut(1)
                .state
                .as_kcc20_mut()
                .unwrap()
                .amount = 51
        },
        &[refused(0, "K-66", KCC20, 239)],
        &[],
    );
}

#[test]
fn transfer_the_owner_signs() {
    // Lines 69-72, inside the helper function inlined at line 179 (leader) and line 267
    // (delegate).
    let leader = check(
        "line/KCC20 69 leader signed by another key",
        &[
            "test_transfer.OwnerSignature.test_a_genuine_signature_of_another_key_is_refused",
            "C_token.test_c_token.SignatureTypes.test_a_signature_of_another_key_stays_refused_with_each_type",
        ],
        &shapes::transfer(&script(), 1, 1),
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                witness::owner_key(CAROL, EntryRole::Leader, SIG_HASH_ALL)
        },
        &[refused(0, "K-38", KCC20, 69)],
        &[],
    );
    let refusal = leader.changed.inputs[0]
        .alone
        .as_ref()
        .unwrap()
        .refusal
        .as_ref()
        .unwrap();
    assert_eq!(refusal.byte_offset, Some(2249));
    assert_eq!(refusal.sil.as_ref().unwrap().end_line, 72);

    let delegate = check(
        "line/KCC20 69 delegate signed by another key",
        &["test_borrow.BorrowedReceive.test_the_sender_still_has_to_sign"],
        &shapes::borrow(&script(), BorrowKind::Threshold),
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() =
                witness::owner_key(CAROL, EntryRole::Delegate, SIG_HASH_ALL)
        },
        &[refused(1, "K-38", KCC20, 69)],
        &[0],
    );
    let refusal = delegate.changed.inputs[1]
        .alone
        .as_ref()
        .unwrap()
        .refusal
        .as_ref()
        .unwrap();
    assert_eq!(
        refusal.byte_offset,
        Some(3837),
        "the copy of the owner check in transfer_delegator"
    );
    assert_eq!(refusal.entry.as_deref(), Some("transfer_delegator"));
}

#[test]
fn transfer_the_key_hash_scheme_checks_the_key_then_the_signature() {
    let honest = shapes::transfer_with_owner_scheme(
        &script(),
        EntryRole::Leader,
        kcc20_family::states::OWNER_P2PKH_SCHNORR,
    );
    let py_ids = [
        "test_schemes.OwnerSchemes.test_p2pkh_schnorr_owner_is_the_hash_of_a_key",
        "C_token.test_c_token.DelegateOwnerSchemes.test_p2pkh_schnorr_delegate",
    ];
    check(
        "line/KCC20 78 another key pair",
        &py_ids,
        &honest,
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                witness::owner_key_hash_schnorr(CAROL, EntryRole::Leader, SIG_HASH_ALL)
        },
        &[refused(0, "K-40", KCC20, 78)],
        &[],
    );
    check(
        "line/KCC20 79 the owner's key, another key's signature",
        &py_ids,
        &honest,
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() = LateBytes::from_tx(|ctx| {
                let mut witness = vec![kcc20_family::states::PATH_NORMAL];
                witness.extend(keys::x_only(ALICE));
                witness.extend(keys::schnorr_signature(
                    ctx,
                    &keys::keypair(CAROL),
                    SIG_HASH_ALL,
                ));
                witness
            })
        },
        &[refused(0, "K-41", KCC20, 79)],
        &[],
    );
}

#[test]
fn transfer_has_at_most_three_token_outputs() {
    check(
        "line/KCC20 156 four token outputs",
        &["C_token.test_c_token.Bounds.test_four_token_outputs_are_refused"],
        &shapes::transfer(&script(), 1, 3),
        |scenario| *scenario = shapes::transfer(&script(), 1, 4),
        &[refused(0, "K-22", KCC20, 156)],
        &[],
    );
}

#[test]
fn transfer_the_first_token_input_leads() {
    // The second token input runs the leader entry.
    check(
        "line/KCC20 129 second input leads",
        &[
            "test_delegator.LeaderAndDelegator.test_the_second_token_input_cannot_run_the_leader_entry",
        ],
        &shapes::transfer(&script(), 2, 1),
        |scenario| {
            let declared = scenario.contract_input_mut(0).declared_states_mut().clone();
            scenario.contract_input_mut(1).call = Call::typed(
                Entry::Transfer,
                vec![
                    Arg::States(declared),
                    Arg::Bytes(witness::owner_key(
                        ALICE + 1,
                        EntryRole::Leader,
                        SIG_HASH_ALL,
                    )),
                ],
            );
        },
        &[refused(1, "K-14", KCC20, 129)],
        &[],
    );
    // A lone token input runs the delegate entry.
    check(
        "line/KCC20 254 lone input as delegate",
        &[
            "test_delegator.LeaderAndDelegator.test_a_lone_token_input_cannot_run_the_delegator_entry",
        ],
        &shapes::transfer(&script(), 1, 1),
        |scenario| {
            scenario.contract_input_mut(0).call = Call::typed(
                Entry::TransferDelegator,
                vec![Arg::Bytes(witness::owner_key(
                    ALICE,
                    EntryRole::Delegate,
                    SIG_HASH_ALL,
                ))],
            );
        },
        &[refused(0, "K-68", KCC20, 254)],
        &[],
    );
}

#[test]
fn transfer_the_token_sums_stay_inside_64_bits() {
    // Inputs: the largest number minus one, plus one. One more and the engine's checked
    // addition refuses at the leader.
    let mut honest = shapes::transfer(&script(), 2, 1);
    honest
        .contract_input_mut(0)
        .state
        .as_kcc20_mut()
        .unwrap()
        .amount = I64_MAX - 1;
    honest
        .contract_input_mut(1)
        .state
        .as_kcc20_mut()
        .unwrap()
        .amount = 1;
    change_token_output(&mut honest, 0, |state| state.amount = I64_MAX);
    check(
        "line/KCC20 165 input sum overflow",
        &["C_token.test_c_token.Bounds.test_two_inputs_summing_past_i64_too"],
        &honest,
        |scenario| {
            scenario
                .contract_input_mut(0)
                .state
                .as_kcc20_mut()
                .unwrap()
                .amount = I64_MAX
        },
        &[engine_error(0, "NumberTooBig", "K-30", KCC20, 165)],
        &[],
    );

    // Outputs: the largest number, declared as (largest - 1) + 1. One more overflows.
    let mut honest = shapes::transfer(&script(), 1, 2);
    honest
        .contract_input_mut(0)
        .state
        .as_kcc20_mut()
        .unwrap()
        .amount = I64_MAX;
    change_token_output(&mut honest, 0, |state| state.amount = I64_MAX - 1);
    change_token_output(&mut honest, 1, |state| state.amount = 1);
    check(
        "line/KCC20 173 output sum overflow",
        &[
            "C_token.test_c_token.Bounds.test_outputs_summing_past_i64_are_refused_by_the_engine_s_overflow_check",
        ],
        &honest,
        |scenario| change_token_output(scenario, 0, |state| state.amount = I64_MAX),
        &[engine_error(0, "NumberTooBig", "K-36", KCC20, 173)],
        &[],
    );
}

#[test]
fn borrow_the_policy_of_the_coin_decides() {
    // Borrowing disabled on the coin that is paid into.
    check(
        "line/KCC20 184 borrowing disabled",
        &["test_borrow.BorrowedReceive.test_a_coin_with_borrowing_disabled_cannot_be_paid_into"],
        &shapes::borrow(&script(), BorrowKind::Threshold),
        |scenario| {
            let disable = |state: &mut Kcc20State| {
                state.borrow_scheme = kcc20_family::states::BORROW_DISABLED;
                state.borrow_guard = [0; 32];
            };
            disable(scenario.contract_input_mut(0).state.as_kcc20_mut().unwrap());
            change_token_output(scenario, 0, disable);
        },
        &[refused(0, "K-50", KCC20, 184)],
        &[1],
    );
    // Exactly the threshold of 10 is not more than the threshold.
    check(
        "line/KCC20 219 increase equal to the threshold",
        &["test_borrow.BorrowedReceive.test_adding_exactly_the_threshold_or_less_is_refused"],
        &shapes::borrow(&script(), BorrowKind::Threshold),
        |scenario| {
            change_token_output(scenario, 0, |state| state.amount = 210);
            change_token_output(scenario, 1, |state| state.amount = 90);
        },
        &[refused(0, "K-61", KCC20, 219)],
        &[1],
    );
    // One byte behind the path byte.
    check(
        "line/KCC20 186 threshold witness with an extra byte",
        &["test_borrow.BorrowedReceive.test_the_threshold_scheme_takes_no_extra_witness_bytes"],
        &shapes::borrow(&script(), BorrowKind::Threshold),
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                LateBytes::fixed(vec![kcc20_family::states::PATH_BORROW, 0x00])
        },
        &[refused(0, "K-51", KCC20, 186)],
        &[1],
    );
}

#[test]
fn borrow_the_hash_chain_link_must_hash_to_the_guard() {
    // A revealed link that does not hash to the guard of the coin, carried over into the
    // successor. A `require` over lines 205-209.
    const WRONG_LINK: [u8; 32] = [0x78; 32];
    check(
        "line/KCC20 205 wrong hash chain link",
        &[
            "test_schemes.BorrowSchemes.test_hash_chain_scheme_reveals_a_link_and_moves_the_guard_on",
        ],
        &shapes::borrow(&script(), BorrowKind::HashChain),
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() =
                witness::borrow_hash_chain(WRONG_LINK, CAROL, SIG_HASH_ALL);
            change_token_output(scenario, 0, |state| state.borrow_guard = WRONG_LINK);
        },
        &[refused(0, "K-54", KCC20, 205)],
        &[1],
    );
}

#[test]
fn transfer_an_unknown_path_byte_is_refused() {
    let honest = shapes::transfer(&script(), 1, 1);
    let honest_witness = honest.contract_input(0).call.clone();
    let Call::Typed { args, .. } = honest_witness else {
        panic!("the shape has a typed call")
    };
    let Some(Arg::Bytes(witness)) = args.last().cloned() else {
        panic!("the last argument is the witness")
    };
    check(
        "line/KCC20 222 path byte 2",
        &[
            "test_transfer.OwnerSignature.test_an_empty_witness_and_an_unknown_path_byte_are_refused",
        ],
        &honest,
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() = witness.map(|mut bytes| {
                bytes[0] = 0x02;
                bytes
            })
        },
        &[refused(0, "K-63", KCC20, 222)],
        &[],
    );
}
