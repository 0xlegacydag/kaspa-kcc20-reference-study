//! The ways a test harness can report something that did not happen, each with a case
//! that would show it in the test harness of `crates/checks`.
//!
//! - A refusal for the wrong reason: a signature that was made before the change.
//! - An accept that is not an accept: one input judged instead of all, a budget that was
//!   not applied, engine flags that are not the node's.
//! - An assembler that repairs what a test set apart: the declared and the locked state of
//!   an output, the state, the lock and the pushed script of a coin.
//! - A rule inventory that leaves a refusing opcode without a name.
//! - An assembler that differs from the authors' builder as soon as a transaction field is
//!   not zero.

use argent_runtime::{ArgValue, EntryCall, InputSigScript, TxBuilder, TxContext};
use checks::{Budgets, Case, Expected, Harness, judge_accept, judge_twin, run};
use kaspa_consensus_core::{
    hashing::sighash_type::SIG_HASH_ALL,
    tx::{Transaction, UtxoEntry},
};
use kaspa_txscript::pay_to_script_hash_script;
use kcc20_family::{
    Contract, EntryRole, Family, Scenario, SourceMap,
    keys::{self, CAROL, SigningContext},
    raw,
    scenario::{Call, InputSpec, OutputSpec},
    shapes::{self, BorrowKind, Profile, Realistic},
    sourcemap::Place,
    states::State,
    witness,
};
use node_gate::{ErrorClass, GateParams};

fn script() -> Profile {
    Profile::Script
}

// ---------------------------------------------------------------------------------------
// Signatures are made after the change
// ---------------------------------------------------------------------------------------

#[test]
fn a_change_the_signature_covers_is_signed_again() {
    // One sompi less on an output: the owner's signature (type ALL) covers the value. If
    // the changed transaction carried the signature of the honest one, the owner check
    // would refuse; with a signature made after the change the transfer still passes.
    let honest = shapes::transfer(&script(), 1, 2);
    let mut changed = honest.clone();
    changed.contract_output_mut(1).value -= 1;

    let honest_outcome = run(&honest);
    let changed_outcome = run(&changed);
    judge_accept(&honest_outcome).expect("the honest transfer passes");
    judge_accept(&changed_outcome).expect("the transfer with a smaller output value passes");

    let honest_script = &honest_outcome.assembled.tx.inputs[0].signature_script;
    let changed_script = &changed_outcome.assembled.tx.inputs[0].signature_script;
    let honest_pushes = raw::split_pushes(honest_script).expect("pushes");
    let changed_pushes = raw::split_pushes(changed_script).expect("pushes");
    assert_eq!(honest_pushes.len(), changed_pushes.len());
    let differing: Vec<usize> = (0..honest_pushes.len())
        .filter(|index| honest_pushes[*index] != changed_pushes[*index])
        .collect();
    // The witness is the last argument: behind it come the tag and the redeem script.
    assert_eq!(
        differing,
        vec![honest_pushes.len() - 3],
        "only the witness differs: the signature was made anew"
    );

    // The same change with the honest witness kept: now the signature is stale and the
    // owner check refuses. This is the refusal a harness that signed too early would give
    // to every twin.
    let stale_witness =
        raw::split_pushes(honest_script).expect("pushes")[honest_pushes.len() - 3].clone();
    let mut stale = changed.clone();
    stale.contract_input_mut(0).set_patch(move |parts| {
        let last = parts.arguments.len() - 1;
        parts.arguments[last] = stale_witness.clone();
    });
    Case::new("review/stale signature of the honest twin").expect_refused(
        &stale,
        0,
        Expected::rule("K-38").at_line(69),
    );
}

// ---------------------------------------------------------------------------------------
// An accept is an accept of every input, under the node's flags and budgets
// ---------------------------------------------------------------------------------------

#[test]
fn a_refused_delegate_denies_the_accept_although_the_leader_passes() {
    let mut scenario = shapes::borrow(&script(), BorrowKind::Threshold);
    *scenario.contract_input_mut(1).witness_mut() =
        witness::owner_key(CAROL, EntryRole::Delegate, SIG_HASH_ALL);
    let outcome = run(&scenario);

    assert!(outcome.inputs[0].alone.as_ref().unwrap().ok);
    assert!(!outcome.inputs[1].alone.as_ref().unwrap().ok);
    assert!(judge_accept(&outcome).is_err());
    assert!(!outcome.scripts.accepted);
    assert_eq!(outcome.scripts.refused_inputs, vec![1]);
    assert_eq!(
        outcome.scripts.accepted_under_committed_budgets,
        Some(false)
    );
    assert!(!outcome.consensus.accepted);
    assert!(!outcome.consensus.block.accepted);
    assert!(!outcome.mempool.accepted);
    // The node names the input that failed.
    assert_eq!(
        outcome
            .consensus
            .refusal
            .as_ref()
            .and_then(|refusal| refusal.input),
        Some(1)
    );
}

#[test]
fn the_budget_of_an_ordinary_input_is_applied_too() {
    // The realistic profile spends a funding coin with a real signature. One budget unit
    // less on that input alone, and a node refuses the transaction for it.
    let scenario = shapes::transfer(&Profile::Realistic(Realistic::default()), 1, 1);
    let measured = run(&scenario);
    judge_accept(&measured).expect("the honest transfer passes");
    let minimal = measured.minimal_budgets().expect("every input is measured");
    assert_eq!(minimal.len(), 2);
    assert!(
        minimal[1] >= 10,
        "a signature check costs ten budget units: {minimal:?}"
    );

    let mut short = minimal.clone();
    short[1] -= 1;
    let outcome = Case::new("review/funding input one budget unit short")
        .on(Harness::pinned().with_budgets(Budgets::Exactly(short)))
        .expect_inputs(
            &scenario,
            &[
                (0, Expected::pass()),
                (
                    1,
                    Expected::engine("ExceededCommittedScriptUnits")
                        .of_class(ErrorClass::ResourceLimit),
                ),
            ],
        );
    assert!(!outcome.consensus.accepted);
    assert_eq!(
        outcome.inputs[1].alone.as_ref().map(|run| run.ok),
        Some(true),
        "without a limit the funding input passes"
    );
}

#[test]
fn before_the_fork_nothing_of_a_covenant_transaction_is_accepted() {
    // The engine flags follow the node. A node in front of the fork that brought covenants
    // must not accept a call of a contract: if the harness had the flags switched on by
    // itself, this transfer would pass.
    let before = GateParams::testnet10().with_daa_score(1_000);
    assert!(!before.toccata_active());
    assert!(!before.engine_flags().covenants_enabled);

    let scenario = shapes::transfer(&script(), 1, 1);
    let outcome = Harness::pinned().with_node(before).run(&scenario);
    assert!(judge_accept(&outcome).is_err(), "{}", outcome.describe());
    assert!(!outcome.consensus.accepted, "{}", outcome.describe());
    assert!(!outcome.consensus.block.accepted);
    assert!(!outcome.mempool.accepted);
    let token_input = outcome.inputs[0].alone.as_ref();
    assert!(
        token_input.is_none_or(|run| !run.ok),
        "{}",
        outcome.describe()
    );
}

#[test]
fn a_refusal_is_named_alike_with_and_without_a_budget_limit() {
    // Budgets fixed by the caller: the run under the limit is judged. A generous limit
    // must give the same rule, line and opcode as the run without a limit.
    let mut scenario = shapes::transfer(&script(), 1, 1);
    scenario.contract_input_mut(0).declared_states_mut()[0].amount += 1;
    scenario
        .contract_output_mut(0)
        .state
        .as_kcc20_mut()
        .unwrap()
        .amount += 1;
    let outcome = Case::new("review/sum rule under a generous budget")
        .on(Harness::pinned().with_budgets(Budgets::Exactly(vec![500])))
        .expect_refused(&scenario, 0, Expected::rule("K-37").at_line(175));
    let alone = outcome.inputs[0].alone.as_ref().unwrap();
    let committed = outcome.inputs[0].committed.as_ref().unwrap();
    assert_eq!(alone.refusal, committed.refusal);
    assert_eq!(alone.stop, committed.stop);
    assert_eq!(alone.used_script_units, committed.used_script_units);
}

// ---------------------------------------------------------------------------------------
// The assembler keeps apart what a scenario sets apart
// ---------------------------------------------------------------------------------------

#[test]
fn the_declared_state_and_the_locked_state_of_an_output_do_not_follow_each_other() {
    let family = Family::pinned();
    let honest = shapes::transfer(&script(), 1, 1);
    let honest_tx = honest.assemble(family).expect("the shape assembles").tx;
    let honest_pushes = raw::split_pushes(&honest_tx.inputs[0].signature_script).expect("pushes");
    let witness_index = honest_pushes.len() - 3;

    // Only the declared state changes: the output keeps its script.
    let mut declared = honest.clone();
    declared.contract_input_mut(0).declared_states_mut()[0].amount = 77;
    let declared_tx = declared.assemble(family).expect("assembles").tx;
    assert_eq!(declared_tx.outputs, honest_tx.outputs);
    assert_ne!(
        declared_tx.inputs[0].signature_script,
        honest_tx.inputs[0].signature_script
    );

    // Only the locked state changes: the call keeps every push but the witness, whose
    // signature covers the new output script.
    let mut locked = honest.clone();
    locked
        .contract_output_mut(0)
        .state
        .as_kcc20_mut()
        .unwrap()
        .amount = 77;
    let locked_tx = locked.assemble(family).expect("assembles").tx;
    let OutputSpec::Contract(output) = &locked.outputs[0] else {
        panic!("a transfer has a token output")
    };
    assert_eq!(
        locked_tx.outputs[0].script_public_key,
        family.script_public_key(&output.state).expect("script")
    );
    assert_ne!(
        locked_tx.outputs[0].script_public_key,
        honest_tx.outputs[0].script_public_key
    );
    let locked_pushes = raw::split_pushes(&locked_tx.inputs[0].signature_script).expect("pushes");
    assert_eq!(locked_pushes.len(), honest_pushes.len());
    for index in 0..honest_pushes.len() {
        assert_eq!(
            locked_pushes[index] == honest_pushes[index],
            index != witness_index,
            "push {index}"
        );
    }
}

#[test]
fn the_state_the_lock_and_the_pushed_script_of_a_coin_do_not_follow_each_other() {
    let family = Family::pinned();
    let honest = shapes::transfer(&script(), 1, 1);
    let state = honest.contract_input(0).state.clone();
    let honest_redeem = family.redeem_script(&state).expect("redeem script");
    let mut other_state = state.clone();
    other_state.as_kcc20_mut().unwrap().amount = 101;
    let other_redeem = family.redeem_script(&other_state).expect("redeem script");
    let last_push = |tx: &Transaction| {
        checks::attribution::pushed_redeem_script(&tx.inputs[0].signature_script)
            .expect("the signature script ends with a push")
    };

    // A lock of its own: the pushed script stays the one of the state.
    let mut relocked = honest.clone();
    relocked.contract_input_mut(0).locking_script = Some(pay_to_script_hash_script(&other_redeem));
    let assembled = relocked.assemble(family).expect("assembles");
    assert_eq!(
        assembled.utxos[0].script_public_key,
        pay_to_script_hash_script(&other_redeem)
    );
    assert_eq!(last_push(&assembled.tx), honest_redeem);

    // A pushed script of its own: the lock stays the one of the state.
    let mut repushed = honest.clone();
    repushed.contract_input_mut(0).pushed_redeem = Some(other_redeem.clone());
    let assembled = repushed.assemble(family).expect("assembles");
    assert_eq!(
        assembled.utxos[0].script_public_key,
        pay_to_script_hash_script(&honest_redeem)
    );
    assert_eq!(last_push(&assembled.tx), other_redeem);

    // Both of them are refused by the test of the coin's own script, never by a rule.
    for (case, scenario) in [
        ("review/coin locked to another state", &relocked),
        ("review/another state pushed", &repushed),
    ] {
        Case::new(case).expect_refused(scenario, 0, Expected::refused_by("P2SH wrapper"));
    }

    // The state itself changed: lock and pushed script follow together, the coin simply is
    // another coin.
    let mut moved = honest.clone();
    moved.contract_input_mut(0).state = other_state.clone();
    let assembled = moved.assemble(family).expect("assembles");
    assert_eq!(
        assembled.utxos[0].script_public_key,
        family.script_public_key(&other_state).expect("script")
    );
    assert_eq!(last_push(&assembled.tx), other_redeem);
}

// ---------------------------------------------------------------------------------------
// The rule inventory names every refusing opcode
// ---------------------------------------------------------------------------------------

#[test]
fn every_verify_and_return_opcode_of_the_three_scripts_has_a_rule() {
    // A refusal at an opcode without a rule is reported by its place only ("statement",
    // "glue"). That is honest, but a check that expects a rule id can then never pass, and
    // one that expects a place cannot tell two such opcodes apart.
    let mut unnamed = Vec::new();
    let mut named = 0;
    for contract in Contract::ALL {
        let map = SourceMap::pinned().contract(contract);
        for opcode in map.opcodes() {
            if matches!(map.place_at(opcode.offset), Place::Frame) {
                continue;
            }
            if !(opcode.name.ends_with("Verify") || opcode.name == "OpReturn") {
                continue;
            }
            match map.rule_at(opcode.offset) {
                Some(_) => named += 1,
                None => unnamed.push(map.describe(opcode.offset)),
            }
        }
    }
    assert!(unnamed.is_empty(), "{unnamed:#?}");
    // The inventory lists 201 refusing opcodes. Six of them are the engine's checked
    // additions (K-30, K-36, M-47); the other 195 are the verify and return opcodes.
    assert_eq!(named, 195);
}

// ---------------------------------------------------------------------------------------
// The assembler and the authors' builder with transaction fields that are not zero
// ---------------------------------------------------------------------------------------

/// Builds the scenario through the authors' builder, as the differential test of the
/// family crate does.
fn build_with_the_authors_builder(scenario: &Scenario) -> (Transaction, Vec<UtxoEntry>) {
    let artifact = Family::pinned()
        .artifact()
        .expect("the pinned family is an Argent artifact");
    let builder = TxBuilder::new(artifact).expect("a builder for the artifact");
    let mut context = TxContext::new()
        .lock_time(scenario.lock_time)
        .lane(scenario.subnetwork_id, scenario.gas)
        .payload(scenario.payload.clone());
    let mut utxos = Vec::new();
    for input in &scenario.inputs {
        match input {
            InputSpec::Contract(input) => {
                let actor = input.contract().name();
                let utxo = builder
                    .covenant_utxo(
                        actor,
                        input.state.authored(),
                        input.value,
                        input.block_daa_score,
                        input.is_coinbase,
                        input.covenant_id,
                    )
                    .expect("a coin of the actor");
                utxos.push(utxo.clone());
                let Call::Typed { entry, args } = &input.call else {
                    panic!("only typed calls can be given to the builder");
                };
                let args = args.clone();
                let call = EntryCall::new(entry.name()).args_with(move |tx, input_index| {
                    let ctx = SigningContext { tx, input_index };
                    args.iter()
                        .map(|arg| ArgValue::Value(arg.resolve(&ctx)))
                        .collect()
                });
                context = context.actor_input(
                    actor,
                    input.state.authored(),
                    call,
                    input.outpoint,
                    utxo,
                    input.sequence,
                );
            }
            InputSpec::Ordinary(input) => {
                let utxo = UtxoEntry::new(
                    input.value,
                    input.script_public_key.clone(),
                    input.block_daa_score,
                    input.is_coinbase,
                    input.covenant_id,
                );
                utxos.push(utxo.clone());
                let script = input.signature_script.clone();
                let script = InputSigScript::with_transaction(move |tx, input_index| {
                    script.resolve(&SigningContext { tx, input_index })
                });
                context = context.input(input.outpoint, utxo, script, input.sequence);
            }
        }
    }
    for output in &scenario.outputs {
        context = match output {
            OutputSpec::Contract(output) => context.actor_output(
                output.state.contract().name(),
                output.state.authored(),
                output.binding.expect("an actor output has a binding"),
                output.value,
            ),
            OutputSpec::Plain(output) => context.output(
                output.script_public_key.clone(),
                output.binding,
                output.value,
            ),
        };
    }
    (builder.build(&context).expect("the builder accepts"), utxos)
}

#[test]
fn lock_time_sequence_and_payload_reach_the_signed_bytes_as_in_the_authors_builder() {
    // The differential test of the family crate compares the honest shapes, whose lock
    // time, sequences and payload are all zero or empty. A signature covers all three, so
    // an assembler that signed before it wrote one of them would only show here.
    let family = Family::pinned();
    for mut scenario in [
        shapes::transfer(&Profile::Realistic(Realistic::default()), 2, 2),
        shapes::mint_reclaim_into(&Profile::Realistic(Realistic::default())),
        shapes::borrow(&script(), BorrowKind::HashChain),
    ] {
        scenario.lock_time = 77;
        scenario.payload = vec![0xca, 0xfe, 0x01];
        for (index, input) in scenario.inputs.iter_mut().enumerate() {
            let sequence = 5 + index as u64;
            match input {
                InputSpec::Contract(input) => input.sequence = sequence,
                InputSpec::Ordinary(input) => input.sequence = sequence,
            }
        }

        let ours = scenario.assemble(family).expect("the scenario assembles");
        let (theirs, their_utxos) = build_with_the_authors_builder(&scenario);
        let name = &scenario.name;
        assert_eq!(ours.utxos, their_utxos, "`{name}`");
        assert_eq!(ours.tx.lock_time, 77);
        assert_eq!(ours.tx.payload, theirs.payload);
        assert_eq!(ours.tx.inputs.len(), theirs.inputs.len());
        for (index, (our_input, their_input)) in
            ours.tx.inputs.iter().zip(&theirs.inputs).enumerate()
        {
            assert_eq!(our_input.sequence, 5 + index as u64);
            assert_eq!(our_input.sequence, their_input.sequence);
            assert!(
                our_input.signature_script == their_input.signature_script,
                "`{name}` input {index}: signature script"
            );
        }
        assert_eq!(ours.tx.outputs, theirs.outputs, "`{name}`");
        assert_eq!(ours.tx.id(), theirs.id(), "`{name}`");

        // And the fields do matter to the signatures: the same shape with a zero lock time
        // has another witness.
        let mut zero = scenario.clone();
        zero.lock_time = 0;
        let zero = zero.assemble(family).expect("the scenario assembles");
        assert_ne!(
            zero.tx
                .inputs
                .iter()
                .map(|input| input.signature_script.clone())
                .collect::<Vec<_>>(),
            ours.tx
                .inputs
                .iter()
                .map(|input| input.signature_script.clone())
                .collect::<Vec<_>>(),
            "`{name}`"
        );
    }
}

#[test]
fn the_keys_of_the_probe_are_the_fixed_ones() {
    // The cases above rely on Carol being a key that owns nothing in the shapes.
    let carol = keys::x_only(CAROL);
    for shape in shapes::all(&script()) {
        for input in &shape.inputs {
            if let InputSpec::Contract(input) = input {
                let owner = match &input.state {
                    State::Kcc20(state) => state.owner,
                    State::PublicMint(state) => state.owner,
                    State::TokenSeed(state) => state.owner,
                };
                assert_ne!(owner, carol, "`{}`", shape.name);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// What the twin helper does not ask
// ---------------------------------------------------------------------------------------

/// The twin helper asks that a node gets to run the scripts of both sides of a pair; a
/// case about the engine alone says so with `Case::scripts_only`.
#[test]
fn a_twin_needs_an_honest_side_that_a_node_gets_to_run() {
    // A transfer whose outputs carry more sompi than its input: one coin of 1000 sompi
    // in, two outputs of 1000 sompi out. A node refuses this transaction before it runs a
    // script, so what its scripts would say is not what a node answers.
    let mut honest = shapes::transfer(&script(), 1, 2);
    honest.contract_output_mut(0).value = shapes::SCRIPT_COIN_VALUE;
    honest.contract_output_mut(1).value = shapes::SCRIPT_COIN_VALUE;
    let honest_outcome = run(&honest);
    assert!(honest_outcome.scripts.accepted);
    assert!(!honest_outcome.consensus.context_accepted);
    assert_eq!(
        honest_outcome
            .consensus
            .context_refusal
            .as_ref()
            .map(|refusal| refusal.rule.as_str()),
        Some("check_transaction_output_values")
    );

    // One token more on the first output, declared and locked alike.
    let mut changed = honest.clone();
    changed.contract_input_mut(0).declared_states_mut()[0].amount += 1;
    changed
        .contract_output_mut(0)
        .state
        .as_kcc20_mut()
        .unwrap()
        .amount += 1;
    let changed_outcome = run(&changed);

    let verdict = judge_twin(
        &honest_outcome,
        &changed_outcome,
        &[(0, Expected::rule("K-37").at_line(175))],
    );
    assert!(
        verdict.is_err(),
        "the twin is accepted although a node refuses its honest side with SpendTooHigh \
         before any script runs: neither side shows what the rule does at a node"
    );
    // Asked about the engine alone, the pair is a twin.
    checks::judge_twin_scripts_only(
        &honest_outcome,
        &changed_outcome,
        &[(0, Expected::rule("K-37").at_line(175))],
    )
    .expect("the scripts refuse the changed side by the sum rule");
}

// ---------------------------------------------------------------------------------------
// A budget that ends inside a statement is not the statement refusing
// ---------------------------------------------------------------------------------------

#[test]
fn a_budget_that_ends_inside_a_statement_names_no_rule_and_satisfies_no_line() {
    // A mint without a budget: the 9,999 free units end while the script reads its own
    // signature script, inside the statement of line 161. The record names the place and
    // gives the refusal to the engine; an expectation of that line alone does not hold.
    let scenario = shapes::mint(&script());
    let outcome = Case::new("review/mint without a budget")
        .on(Harness::pinned().with_budgets(Budgets::Exactly(vec![0, 0])))
        .expect_inputs(
            &scenario,
            &[
                (
                    0,
                    Expected::engine("ExceededCommittedScriptUnits")
                        .of_class(ErrorClass::ResourceLimit),
                ),
                (1, Expected::pass()),
            ],
        );
    let committed = outcome.inputs[0].committed.as_ref().unwrap();
    let refusal = committed.refusal.as_ref().unwrap();
    assert_eq!(refusal.refused_by, "engine: ExceededCommittedScriptUnits");
    assert_eq!(refusal.rule, None);
    assert_eq!(refusal.at_rule, None);
    assert_eq!(refusal.contract.as_deref(), Some("PublicMint"));
    assert_eq!(refusal.entry.as_deref(), Some("mint"));
    assert_eq!(refusal.byte_offset, Some(376));
    assert_eq!(committed.sil_line(), Some(161));
    assert!(checks::judge_input(&outcome, 0, &Expected::line(161)).is_err());
    assert!(checks::judge_input(&outcome, 0, &Expected::rule("M-19")).is_err());
    assert!(
        outcome.inputs[0].alone.as_ref().unwrap().ok,
        "without a limit the mint passes"
    );
}
