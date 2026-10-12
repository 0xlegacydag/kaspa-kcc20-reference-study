//! Cases that stop at rules of TokenSeed at which no other case of the suite stops.
//!
//! A run that neutralises every refusing opcode in turn can only judge the opcodes at which
//! some case stops. The cases of this file stop at:
//!
//! - `S-22` (`split`: exactly two outputs are bound to the seed),
//! - `S-31` (`reclaim`: exactly one output is bound to the survivor),
//! - `S-32` (`reclaim`: every continuation of the covenant is bound to the survivor),
//! - `S-38` (`reclaim_delegator`: the caller is not the first input of the covenant),
//! - `S-42` (`reclaim_delegator`: no output is bound to the retiring seed).
//!
//! Each gets a twin here: the honest transaction passes, and one change stops the judged
//! input exactly at the rule. No case of this suite stops at `S-29` or at `S-40`.
//!
//! One test names the opcodes of TokenSeed at which cases of the suite are refused and which
//! belong to no rule: what each of them is.
//!
//! Cases for three rules of the borrow path of `KCC20.transfer` follow: `K-56` (the spent
//! coin's own borrow scheme is an assigned one), `K-58` and `K-59` (the successor keeps the
//! owner scheme and the borrow scheme).
//!
//! The last two tests run two of these cases on contracts the tests change themselves: the
//! case that stops at `S-32` and `S-42` with one and with both of the two opcodes replaced,
//! and the case that stops at `K-56` with that opcode replaced, where it stops at `K-59`.

use checks::{Case, Expected, Harness, judge_accept, judge_inputs, mutation::mutant_family};
use kaspa_consensus_core::{hashing::sighash_type::SIG_HASH_ALL, tx::CovenantBinding};
use kcc20_family::{
    Contract, Entry, Family, Scenario, SourceMap,
    keys::{self, ALICE, CAROL},
    scenario::{Arg, Call, ContractOutput, OutputSpec, PlainOutput},
    shapes::{self, BorrowKind, Profile},
    states::{
        BORROW_DISABLED, BORROW_SCHNORR_SIGNATURE, Kcc20State, OWNER_COVENANT_ID,
        OWNER_P2PKH_SCHNORR, TokenSeedState,
    },
    witness,
};

/// A binding to input `input` under the covenant of the shapes.
fn bound_to(input: u16) -> Option<CovenantBinding> {
    Some(CovenantBinding::new(input, shapes::covenant_id()))
}

/// `TokenSeed.split`: Alice's seed and a funding coin in; her seed and a new seed of Bob out.
fn split() -> Scenario {
    shapes::seed_split(&Profile::Script)
}

/// `TokenSeed.reclaim` with `reclaim_delegator`: Alice's seed (input 0) survives, Bob's seed
/// (input 1) retires; output 0 is the survivor, output 1 pays Bob.
fn reclaim() -> Scenario {
    shapes::seed_reclaim(&Profile::Script)
}

/// Makes the survivor (input 0) call `reclaim_delegator` with its own owner's signature.
fn survivor_calls_the_delegate_entry(scenario: &mut Scenario) {
    scenario.contract_input_mut(0).call = Call::typed(
        Entry::SeedReclaimDelegator,
        vec![Arg::Bytes(witness::signature(ALICE, SIG_HASH_ALL))],
    );
}

// ---------------------------------------------------------------------------------------
// S-22: split binds exactly two outputs
// ---------------------------------------------------------------------------------------

#[test]
fn split_with_three_bound_outputs_stops_at_the_output_count() {
    let honest = split();
    Case::new("S-22/split/a third seed bound to the seed")
        .note(
            "one more seed, of Carol, bound to the splitting seed: three outputs carry its \
             authorization, the entry asks for two",
        )
        .twin(
            &honest,
            |scenario| {
                scenario.push_contract_output(ContractOutput::new(
                    TokenSeedState::new(keys::x_only(CAROL)),
                    shapes::SCRIPT_SPLIT_VALUE,
                    bound_to(0),
                ));
            },
            0,
            Expected::rule("S-22").at_line(170),
        );
}

#[test]
fn split_with_one_bound_output_stops_at_the_output_count() {
    let honest = split();
    Case::new("S-22/split/the added seed is not bound")
        .note(
            "the added seed keeps its script and value and loses its binding: one output \
             carries the seed's authorization",
        )
        .twin(
            &honest,
            |scenario| *scenario.outputs[1].binding_mut() = None,
            0,
            Expected::rule("S-22").at_line(170),
        );
}

// ---------------------------------------------------------------------------------------
// S-31: reclaim binds exactly one output
// ---------------------------------------------------------------------------------------

#[test]
fn reclaim_with_two_bound_outputs_stops_at_the_output_count() {
    let honest = reclaim();
    Case::new("S-31/reclaim/the payout is bound to the survivor too")
        .note(
            "the plain output paying the retiring owner gets the survivor's binding: two \
             outputs continue the covenant under the survivor",
        )
        .twin_inputs(
            &honest,
            |scenario| *scenario.outputs[1].binding_mut() = bound_to(0),
            &[
                (0, Expected::rule("S-31").at_line(218)),
                (1, Expected::pass()),
            ],
        );
}

#[test]
fn reclaim_with_no_bound_output_stops_at_the_output_count() {
    let honest = reclaim();
    Case::new("S-31/reclaim/the survivor's output is not bound")
        .note(
            "the survivor's output keeps its script and value and loses its binding: the \
             covenant would end with both seeds",
        )
        .twin_inputs(
            &honest,
            |scenario| *scenario.outputs[0].binding_mut() = None,
            &[
                (0, Expected::rule("S-31").at_line(218)),
                (1, Expected::pass()),
            ],
        );
}

// ---------------------------------------------------------------------------------------
// S-32 and S-42: no continuation under the retiring seed
// ---------------------------------------------------------------------------------------

#[test]
fn an_output_bound_to_the_retiring_seed_stops_both_seeds() {
    let honest = reclaim();
    Case::new("S-32 S-42/reclaim/the payout is bound to the retiring seed")
        .note(
            "the plain output paying the retiring owner gets the retiring seed's binding. \
             The survivor still authorizes one output and counts two of the covenant; the \
             retiring seed authorizes one where a delegate authorizes none",
        )
        .twin_inputs(
            &honest,
            |scenario| *scenario.outputs[1].binding_mut() = bound_to(1),
            &[
                (0, Expected::rule("S-32").at_line(222)),
                (1, Expected::rule("S-42").at_line(252)),
            ],
        );
}

#[test]
fn a_third_output_bound_to_the_retiring_seed_stops_both_seeds() {
    let honest = {
        // One sompi each for a third output, taken from the payout.
        let mut scenario = reclaim();
        *scenario.outputs[1].value_mut() -= 1;
        scenario.push_plain_output(PlainOutput::new(
            shapes::pay_to_public_key_script(&keys::x_only(CAROL)),
            1,
        ));
        scenario
    };
    Case::new("S-32 S-42/reclaim/a second seed appears under the retiring seed")
        .note(
            "the third output, a plain one-sompi output in the honest twin, becomes a seed \
             of Carol bound to the retiring seed",
        )
        .twin_inputs(
            &honest,
            |scenario| {
                scenario.outputs[2] = OutputSpec::Contract(ContractOutput::new(
                    TokenSeedState::new(keys::x_only(CAROL)),
                    1,
                    bound_to(1),
                ));
            },
            &[
                (0, Expected::rule("S-32").at_line(222)),
                (1, Expected::rule("S-42").at_line(252)),
            ],
        );
}

// ---------------------------------------------------------------------------------------
// S-38: the delegate entry is not for the first seed
// ---------------------------------------------------------------------------------------

#[test]
fn the_first_seed_calling_the_delegate_entry_stops_at_its_position() {
    let honest = reclaim();
    Case::new("S-38/reclaim_delegator/the survivor calls the delegate entry")
        .note(
            "both seeds call reclaim_delegator, each with its owner's signature; the \
             survivor's output stays bound to it",
        )
        .twin_inputs(
            &honest,
            survivor_calls_the_delegate_entry,
            &[
                (0, Expected::rule("S-38").at_line(242)),
                (1, Expected::pass()),
            ],
        );
}

#[test]
fn two_seeds_cannot_both_retire() {
    let honest = reclaim();
    Case::new("S-38/reclaim_delegator/both seeds retire and nothing continues")
        .note(
            "both seeds call reclaim_delegator with their owners' signatures and both \
             deposits are paid out to plain outputs: no output is bound to either; the \
             second seed passes and the first stops at its position rule",
        )
        .twin_inputs(
            &honest,
            |scenario| {
                survivor_calls_the_delegate_entry(scenario);
                let value = scenario.outputs[0].value();
                scenario.outputs[0] = OutputSpec::Plain(PlainOutput::new(
                    shapes::pay_to_public_key_script(&keys::x_only(ALICE)),
                    value,
                ));
            },
            &[
                (0, Expected::rule("S-38").at_line(242)),
                (1, Expected::pass()),
            ],
        );
}

// ---------------------------------------------------------------------------------------
// Refusals at opcodes of TokenSeed that belong to no rule
// ---------------------------------------------------------------------------------------

#[test]
fn the_opcodes_without_a_rule_are_engine_stops_in_front_of_a_rule() {
    let map = SourceMap::pinned().contract(Contract::TokenSeed);
    let inventory = SourceMap::pinned();

    // (offset, the opcode there, the rule whose refusing opcode follows, that opcode's offset)
    type Stop = (usize, &'static str, Option<(&'static str, usize)>);
    let stops: [Stop; 6] = [
        // The first opcode of the script moves the dispatch tag away: nothing was pushed.
        (0, "OpToAltStack", None),
        // The first argument pick of `create`, in front of the size check of the amount.
        (144, "OpPick", Some(("S-02", 148))),
        // The pick of `new_owner` in `split`, in front of its size check.
        (428, "OpPick", Some(("S-20", 432))),
        // The pick of `owner_signature` in `reclaim_delegator`, in front of its size check.
        (972, "OpPick", Some(("S-36", 976))),
        // The cut of the leader's signature script, in front of the lock comparison.
        (1043, "OpTxInputScriptSigSubstr", Some(("S-39", 1059))),
        // The signature check itself, one opcode in front of its verify.
        (1333, "OpCheckSig", Some(("S-43", 1334))),
    ];
    for (offset, name, next_rule) in stops {
        let opcode = map
            .opcode_at(offset)
            .unwrap_or_else(|| panic!("no opcode of TokenSeed starts at byte {offset}"));
        assert_eq!(opcode.name, name, "the opcode at byte {offset}");
        assert!(
            map.rule_at(offset).is_none(),
            "byte {offset} is the refusing opcode of no rule"
        );
        if let Some((rule, rule_offset)) = next_rule {
            let record = inventory.rule(rule).expect("a rule of the inventory");
            assert_eq!(record.offsets, vec![rule_offset], "the opcode of {rule}");
            assert!(offset < rule_offset);
            let between = map
                .opcodes()
                .iter()
                .filter(|opcode| opcode.offset > offset && opcode.offset < rule_offset)
                .filter(|opcode| map.rule_at(opcode.offset).is_some())
                .count();
            assert_eq!(
                between, 0,
                "no other refusing opcode lies between byte {offset} and {rule}"
            );
        }
    }
    checks::results::record_structural(
        "structure/TokenSeed opcodes without a rule at which cases of the suite stop",
        &[],
        "0 OpToAltStack (the tag, with nothing pushed); 144, 428, 972 OpPick of the first \
         argument of create, split and reclaim_delegator, in front of S-02, S-20 and S-36; \
         1043 OpTxInputScriptSigSubstr in front of S-39; 1333 OpCheckSig in front of S-43",
    );
}

// ---------------------------------------------------------------------------------------
// KCC20, the borrow path: K-56, K-58 and K-59
// ---------------------------------------------------------------------------------------

/// A borrowed receive by threshold: Bob's coin (input 0) leads on the borrow path, Alice's
/// coin (input 1) adds 11 tokens; output 0 is Bob's successor.
fn borrowed_receive() -> Scenario {
    shapes::borrow(&Profile::Script, BorrowKind::Threshold)
}

/// Changes the successor of the leading coin, in the call and in the output alike.
fn change_successor(scenario: &mut Scenario, change: impl Fn(&mut Kcc20State)) {
    change(&mut scenario.contract_input_mut(0).declared_states_mut()[0]);
    change(
        scenario
            .contract_output_mut(0)
            .state
            .as_kcc20_mut()
            .expect("output 0 is a token coin"),
    );
}

#[test]
fn a_leading_coin_with_an_unassigned_borrow_scheme_stops_on_the_borrow_path() {
    // The leading coin is written with a borrow scheme that is none of the four. Its
    // successor keeps the honest scheme, so the case does not stop at the range rule of the
    // declared states.
    let honest = borrowed_receive();
    for scheme in [0x04_u8, 0xff] {
        Case::new(format!(
            "K-56/borrow path/the spent coin has borrow scheme 0x{scheme:02x}"
        ))
        .note(
            "the leading coin itself carries a borrow scheme that is none of the four; the \
             declared successor and its output are unchanged",
        )
        .twin(
            &honest,
            |scenario| {
                scenario
                    .contract_input_mut(0)
                    .state
                    .as_kcc20_mut()
                    .expect("input 0 is a token coin")
                    .borrow_scheme = scheme;
            },
            0,
            Expected::rule("K-56").at_line(212),
        );
    }
}

#[test]
fn a_borrowed_receive_keeps_the_owner_scheme_of_the_coin() {
    let honest = borrowed_receive();
    for (scheme, name) in [
        (OWNER_P2PKH_SCHNORR, "a key hash"),
        (OWNER_COVENANT_ID, "a covenant id"),
    ] {
        Case::new(format!(
            "K-58/borrow path/the successor reads the owner bytes as {name}"
        ))
        .note(
            "the successor keeps the 32 owner bytes and takes another valid owner scheme, \
             in the call and in the output alike",
        )
        .twin_inputs(
            &honest,
            |scenario| change_successor(scenario, |state| state.owner_scheme = scheme),
            &[
                (0, Expected::rule("K-58").at_line(215)),
                (1, Expected::pass()),
            ],
        );
    }
}

#[test]
fn a_borrowed_receive_keeps_the_borrow_scheme_of_the_coin() {
    let honest = borrowed_receive();
    for (scheme, name) in [
        (BORROW_DISABLED, "borrowing off"),
        (BORROW_SCHNORR_SIGNATURE, "the guard read as a key"),
    ] {
        Case::new(format!("K-59/borrow path/the successor has {name}"))
            .note(
                "the successor keeps the 32 guard bytes and takes another valid borrow \
                 scheme, in the call and in the output alike",
            )
            .twin_inputs(
                &honest,
                |scenario| change_successor(scenario, |state| state.borrow_scheme = scheme),
                &[
                    (0, Expected::rule("K-59").at_line(216)),
                    (1, Expected::pass()),
                ],
            );
    }
}

// ---------------------------------------------------------------------------------------
// Two of the cases above on contracts with refusing opcodes replaced
// ---------------------------------------------------------------------------------------

/// The family of the run with the refusing opcodes of `rules` neutralised.
fn family_without(rules: &[&str]) -> Family {
    let mut family: Option<Family> = None;
    for id in rules {
        let rule = SourceMap::pinned()
            .rule(id)
            .expect("a rule of the inventory");
        assert_eq!(rule.offsets.len(), 1, "{id} has one refusing opcode");
        let spec = format!("{}@{}", rule.contract.name(), rule.offsets[0]);
        let base = family.as_ref().unwrap_or(checks::family());
        let (changed, _) = mutant_family(base, &spec).expect("a refusing opcode");
        family = Some(changed);
    }
    family.expect("at least one rule")
}

/// How `scenario` is answered on the pinned contracts without `rules`.
fn judged_without(
    rules: &[&str],
    scenario: &Scenario,
    expected: &[(usize, Expected)],
) -> Result<(), String> {
    let outcome = Harness::pinned()
        .with_family(family_without(rules))
        .run(scenario);
    if expected.is_empty() {
        judge_accept(&outcome)
    } else {
        judge_inputs(&outcome, expected)
    }
}

#[test]
fn the_case_for_s_32_and_s_42_with_one_and_with_both_opcodes_replaced() {
    // The contracts are changed here by the test itself; a run that changes them as well
    // has nothing to ask of it.
    if !checks::mutation::mode().is_plain() {
        return;
    }
    // On the pinned contracts the case with the payout bound to the retiring seed is
    // refused twice, by S-32 on the survivor and by S-42 on the retiring seed. With the
    // opcode of one of the two replaced the other still refuses its own input; with both
    // replaced this transaction passes.
    let mut changed = reclaim();
    *changed.outputs[1].binding_mut() = bound_to(1);

    judged_without(
        &["S-32"],
        &changed,
        &[
            (0, Expected::pass()),
            (1, Expected::rule("S-42").at_line(252)),
        ],
    )
    .expect("without S-32 the survivor passes and the retiring seed refuses at S-42");
    judged_without(
        &["S-42"],
        &changed,
        &[
            (0, Expected::rule("S-32").at_line(222)),
            (1, Expected::pass()),
        ],
    )
    .expect("without S-42 the retiring seed passes and the survivor refuses at S-32");
    judged_without(&["S-32", "S-42"], &changed, &[])
        .expect("without both rules the transaction passes");

    checks::results::record_structural(
        "structure/the case for S-32 and S-42 with one and with both opcodes replaced",
        &[],
        "reclaim with the payout bound to the retiring seed, on TokenSeed with OpVerify made \
         OpDrop: at 929 (S-32) input 0 passes and input 1 stops at S-42; at 1328 (S-42) \
         input 1 passes and input 0 stops at S-32; at both the transaction passes",
    );
}

#[test]
fn the_case_for_k_56_with_the_opcode_replaced_stops_at_the_successor_rule() {
    if !checks::mutation::mode().is_plain() {
        return;
    }
    // The case for K-56 above, on changed contracts: with the opcode of K-56 replaced it
    // stops at K-59, where the successor does not keep the scheme of the coin; with both
    // opcodes replaced it passes.
    let mut changed = borrowed_receive();
    changed
        .contract_input_mut(0)
        .state
        .as_kcc20_mut()
        .expect("input 0 is a token coin")
        .borrow_scheme = 0x04;

    judged_without(
        &["K-56"],
        &changed,
        &[
            (0, Expected::rule("K-59").at_line(216)),
            (1, Expected::pass()),
        ],
    )
    .expect("without K-56 the leading coin stops at K-59");
    judged_without(&["K-56", "K-59"], &changed, &[])
        .expect("without K-56 and K-59 the transaction passes");

    // The same coin with a successor that keeps the unassigned scheme: the range rule of
    // the declared states answers first, on the pinned contracts.
    let mut keeping = changed.clone();
    change_successor(&mut keeping, |state| state.borrow_scheme = 0x04);
    judge_inputs(
        &checks::run(&keeping),
        &[(0, Expected::rule("K-34").at_line(61))],
    )
    .expect("a declared borrow scheme 0x04 stops at K-34");

    checks::results::record_structural(
        "structure/the case for K-56 with the opcode replaced, and with a successor of scheme 0x04",
        &[],
        "a leading coin with borrow scheme 0x04 on the borrow path, on KCC20 with OpVerify \
         made OpDrop: at 2548 (K-56) input 0 stops at K-59; at 2548 and 2601 the transaction \
         passes; on the pinned contracts, with the successor keeping scheme 0x04, input 0 \
         stops at K-34 in front of the path",
    );
}
