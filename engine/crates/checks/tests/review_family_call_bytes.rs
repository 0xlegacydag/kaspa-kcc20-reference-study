//! Where an earlier suite of checks and the script engine must differ. The earlier suite
//! was written for the debug engine of the Kaspa Python SDK and is not published here; the
//! ids of its checks are kept as labels.
//!
//! The earlier suite handed the arguments of an entry to a debug engine directly. The
//! signature script it wrote next to them was never executed, and the lock of the spent
//! coin was never compared with the script that ran; its own checks
//! `test_engine_limits.NotChecked.*` pin exactly that. On the script engine the bytes of
//! the signature script are the call. This file runs the same signature scripts and
//! records the answers side by side:
//!
//! | signature script | earlier suite, honest arguments | script engine |
//! |---|---|---|
//! | 40 bytes of junk, then the redeem script | pass | refused by the dispatcher, K-01 |
//! | the redeem script alone | pass | refused at the first opcode of the script |
//! | honest call, coin locked to another state | pass | refused by the coin's own script |
//!
//! With the arguments of a wrong key the earlier suite named line 69 of `KCC20.sil` (the
//! owner's signature) for all of them; the engine never reaches that line, because the
//! bytes that would carry the signature are not there.
//!
//! None of the three is a defect of the test harness of `crates/checks`, of the contracts
//! or of the debug engine, which is not asked to do what a node does. They are the reason a
//! line asserted by the earlier suite can only be
//! compared with the engine when the signature script is the honest encoding of the
//! arguments.

use checks::{Case, Expected, expect_accept, run};
use kaspa_txscript::pay_to_script_hash_script;
use kcc20_family::{
    Family, Scenario,
    keys::{self, ALICE},
    raw,
    scenario::{Call, LateBytes},
    shapes::{self, Profile},
};
use node_gate::ErrorClass;

const PY_BYTES: &str = "test_engine_limits.NotChecked.test_the_bytes_of_the_call_are_not_what_runs";
const PY_LOCK: &str = "test_engine_limits.NotChecked.test_the_active_coin_s_lock_is_not_compared_with_the_script_that_runs";

/// The transfer of the earlier checks: Alice's 100 tokens become 60 for Bob and 40 for
/// Alice.
fn honest() -> Scenario {
    let mut scenario = shapes::transfer(&Profile::Script, 1, 2);
    let alice = keys::x_only(ALICE);
    for (index, amount) in [(0, 60), (1, 40)] {
        scenario.contract_input_mut(0).declared_states_mut()[index].amount = amount;
        let output = scenario
            .contract_output_mut(index)
            .state
            .as_kcc20_mut()
            .expect("a token output");
        output.amount = amount;
        if index == 1 {
            output.owner = alice;
        }
    }
    scenario.contract_input_mut(0).declared_states_mut()[1].owner = alice;
    scenario
}

#[test]
fn the_honest_encoding_of_the_call_passes() {
    expect_accept(
        Case::new("review/call bytes, the real call").py([PY_BYTES]),
        &honest(),
    );
}

#[test]
fn junk_in_front_of_the_redeem_script_is_refused_by_the_dispatcher() {
    // One push of 40 bytes where the arguments and the tag belong. The script takes the
    // last item in front of it for the tag; no entry has that tag.
    let mut scenario = honest();
    scenario.contract_input_mut(0).call =
        Call::Raw(LateBytes::fixed(raw::push(&[0x5a; 40]).expect("a push")));
    let outcome = Case::new("review/call bytes, junk")
        .py([PY_BYTES])
        .note("the earlier suite: pass with honest arguments, KCC20.sil:69 with a wrong key")
        .expect_refused(&scenario, 0, Expected::rule("K-01"));
    let run = outcome.inputs[0].alone.as_ref().unwrap();
    assert_eq!(run.error_variant(), Some("EarlyReturn"));
    assert_eq!(run.sil_line(), None, "the dispatcher has no source line");
    let refusal = run.refusal.as_ref().unwrap();
    assert_eq!(refusal.byte_offset, Some(4028));
    assert_eq!(refusal.place.as_deref(), Some("dispatcher"));
}

#[test]
fn the_redeem_script_alone_is_refused_at_its_first_opcode() {
    // Nothing in front of the redeem script: the script starts by moving the tag to the
    // other stack, and there is no item to move.
    let mut scenario = honest();
    scenario.contract_input_mut(0).call = Call::Raw(LateBytes::empty());
    let outcome = run(&scenario);
    let assembled = &outcome.assembled;
    assert_eq!(assembled.inputs[0].signature_script_opcodes, Some(1));

    let outcome = Case::new("review/call bytes, nothing but the script")
        .py([PY_BYTES])
        .note("the earlier suite: pass with honest arguments, KCC20.sil:69 with a wrong key")
        .expect_refused(
            &scenario,
            0,
            Expected::engine("InvalidStackOperation").of_class(ErrorClass::EngineRefusedData),
        );
    let run = outcome.inputs[0].alone.as_ref().unwrap();
    let refusal = run.refusal.as_ref().unwrap();
    assert_eq!(refusal.byte_offset, Some(0));
    assert_eq!(refusal.opcode.as_deref(), Some("OpToAltStack"));
    assert_eq!(refusal.place.as_deref(), Some("state frame"));
    assert_eq!(refusal.rule, None);
    assert_eq!(run.sil_line(), None);
}

#[test]
fn a_coin_locked_to_another_state_is_refused_by_its_own_script() {
    // The coin is locked to the script of a coin holding a million tokens; the signature
    // script pushes the script of the coin holding 100, and the owner signs the transaction
    // as it is (the signature covers the lock of the coin). The earlier suite accepted
    // this.
    let family = Family::pinned();
    let mut scenario = honest();
    let mut rich = scenario.contract_input(0).state.clone();
    rich.as_kcc20_mut().expect("a token coin").amount = 1_000_000;
    scenario.contract_input_mut(0).locking_script = Some(pay_to_script_hash_script(
        &family.redeem_script(&rich).expect("a redeem script"),
    ));
    let outcome = Case::new("review/coin locked to another state, honest call")
        .py([PY_LOCK])
        .note("the earlier suite: pass")
        .expect_refused(&scenario, 0, Expected::refused_by("P2SH wrapper"));
    let run = outcome.inputs[0].alone.as_ref().unwrap();
    assert_eq!(run.error_variant(), Some("EvalFalse"));
    assert_eq!(run.class, Some(ErrorClass::ScriptFormat));
    assert_eq!(run.rule(), None);
    assert_eq!(
        run.refusal.as_ref().unwrap().engine_precondition.as_deref(),
        Some("E-03")
    );
}
