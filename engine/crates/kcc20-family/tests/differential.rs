//! Our assembler against Argent's `TxBuilder`: the same honest shape, built both ways, must
//! give the same bytes.
//!
//! `TxBuilder` is the tool the reference's authors build their transactions with. It cannot
//! build invalid shapes, which is why this crate has its own assembler; but for honest shapes
//! the two must agree, or one of them misreads the artifact.
//!
//! The scenario is translated into a `TxContext` mechanically, with the same closures for
//! witnesses and signatures (signatures are deterministic, so equal inputs give equal bytes).

mod common;

use argent_runtime::{ArgValue, BuilderResult, EntryCall, InputSigScript, TxBuilder, TxContext};
use kaspa_consensus_core::mass::ComputeBudget;
use kaspa_consensus_core::tx::{ComputeCommit, Transaction, UtxoEntry};
use kcc20_family::keys::SigningContext;
use kcc20_family::scenario::{Call, InputSpec, OutputSpec, Scenario};
use kcc20_family::shapes::{self, Profile, Realistic};
use kcc20_family::{Entry, Family};

/// Builds the scenario through Argent's builder, as the reference's tests do
/// (kcc20-reference c8a0871 src/bin/kcc20/public_mint/tests.rs:45-73). Returns the built
/// transaction (already executed by the builder, with the budgets it measured) and the coins.
fn build_with_argent(
    scenario: &Scenario,
    family: &Family,
) -> BuilderResult<(Transaction, Vec<UtxoEntry>)> {
    let artifact = family
        .artifact()
        .expect("the pinned family is an Argent artifact");
    let builder = TxBuilder::new(artifact)?;
    let mut context = TxContext::new()
        .lock_time(scenario.lock_time)
        .lane(scenario.subnetwork_id, scenario.gas)
        .payload(scenario.payload.clone());
    let mut utxos = Vec::new();
    for input in &scenario.inputs {
        match input {
            InputSpec::Contract(input) => {
                let actor = input.contract().name();
                let utxo = builder.covenant_utxo(
                    actor,
                    input.state.authored(),
                    input.value,
                    input.block_daa_score,
                    input.is_coinbase,
                    input.covenant_id,
                )?;
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
            OutputSpec::Contract(output) => {
                let binding = output
                    .binding
                    .expect("the builder refuses an actor output without a binding");
                context.actor_output(
                    output.state.contract().name(),
                    output.state.authored(),
                    binding,
                    output.value,
                )
            }
            OutputSpec::Plain(output) => context.output(
                output.script_public_key.clone(),
                output.binding,
                output.value,
            ),
        };
    }
    Ok((builder.build(&context)?, utxos))
}

/// Compares one shape built both ways.
fn assert_same_bytes(scenario: &Scenario, family: &Family) {
    let name = &scenario.name;
    let ours = scenario
        .assemble(family)
        .unwrap_or_else(|error| panic!("`{name}` does not assemble: {error}"));
    let (theirs, their_utxos) = build_with_argent(scenario, family)
        .unwrap_or_else(|error| panic!("`{name}`: the builder refuses: {error}"));

    // The coins: value, script public key, DAA score, coinbase flag, covenant id.
    assert_eq!(ours.utxos, their_utxos, "`{name}`: spent coins");
    // The signature scripts, byte for byte.
    assert_eq!(
        ours.tx.inputs.len(),
        theirs.inputs.len(),
        "`{name}`: number of inputs"
    );
    for (index, (our_input, their_input)) in ours.tx.inputs.iter().zip(&theirs.inputs).enumerate() {
        assert_eq!(
            our_input.previous_outpoint, their_input.previous_outpoint,
            "`{name}` input {index}: outpoint"
        );
        assert_eq!(
            our_input.sequence, their_input.sequence,
            "`{name}` input {index}: sequence"
        );
        assert!(
            our_input.signature_script == their_input.signature_script,
            "`{name}` input {index}: signature script"
        );
    }
    // The outputs: value, script public key, covenant binding.
    assert_eq!(ours.tx.outputs, theirs.outputs, "`{name}`: outputs");
    // The transaction fields.
    assert_eq!(ours.tx.version, theirs.version, "`{name}`: version");
    assert_eq!(ours.tx.lock_time, theirs.lock_time);
    assert_eq!(ours.tx.subnetwork_id, theirs.subnetwork_id);
    assert_eq!(ours.tx.gas, theirs.gas);
    assert_eq!(ours.tx.payload, theirs.payload);
    assert_eq!(ours.tx.storage_mass(), theirs.storage_mass());
    // The id of a version-1 transaction covers neither signature scripts nor budgets.
    assert_eq!(ours.tx.id(), theirs.id(), "`{name}`: transaction id");

    // The one explained difference: compute budgets. Our assembler leaves the budget the
    // scenario states (0); the builder runs every input and writes the smallest budget that
    // covers the measured script units (argent 9a9f4b1 crates/argent-runtime/src/lib.rs:
    // 1911-1915). After the same runner has processed our transaction, nothing differs.
    for input in &ours.tx.inputs {
        assert_eq!(
            input.compute_commit,
            ComputeCommit::ComputeBudget(ComputeBudget(0)),
            "`{name}`"
        );
    }
    let ours_after_runner =
        common::run_authors(&ours).unwrap_or_else(|error| panic!("`{name}` is refused: {error}"));
    assert_eq!(
        ours_after_runner, theirs,
        "`{name}`: whole transaction after the runner"
    );
}

#[test]
fn each_of_the_eleven_entries_matches_the_builder() {
    let family = Family::pinned();
    for entry in Entry::ALL {
        let (scenario, _) = shapes::for_entry(&Profile::Script, entry);
        assert_same_bytes(&scenario, family);
    }
}

#[test]
fn every_honest_shape_matches_the_builder_in_the_script_profile() {
    let family = Family::pinned();
    for scenario in shapes::all(&Profile::Script) {
        assert_same_bytes(&scenario, family);
    }
}

#[test]
fn every_honest_shape_matches_the_builder_in_the_realistic_profile() {
    let family = Family::pinned();
    for scenario in shapes::all(&Profile::Realistic(Realistic::default())) {
        assert_same_bytes(&scenario, family);
    }
}

#[test]
fn the_shape_owned_by_its_own_covenant_matches_the_builder() {
    // The reference's own shape of owner scheme 0x04, which is not among the 29.
    let family = Family::pinned();
    for profile in [Profile::Script, Profile::Realistic(Realistic::default())] {
        for role in [
            kcc20_family::EntryRole::Leader,
            kcc20_family::EntryRole::Delegate,
        ] {
            assert_same_bytes(
                &shapes::transfer_owned_by_its_own_covenant(&profile, role),
                family,
            );
        }
    }
}

#[test]
fn the_builder_writes_a_budget_where_a_signature_is_checked() {
    // Pins the explained difference with a number, so that a change in either tool shows up:
    // one signature check costs 100,000 script units, 9,999 are free, a budget unit is
    // 10,000 (rusty-kaspa a41a333 consensus/core/src/mass/units.rs:4-7, 22-24).
    let family = Family::pinned();
    let scenario = shapes::transfer(&Profile::Script, 1, 1);
    let (theirs, _) = build_with_argent(&scenario, family).expect("the builder accepts");
    let budget = theirs.inputs[0]
        .compute_commit
        .compute_budget()
        .expect("a version-1 input carries a compute budget");
    // Observed: 12 units. Ten of them are the signature check, the rest is script work.
    assert_eq!(budget, 12);
    // A mint checks no signature and its funding coin is OP_TRUE.
    let (theirs, _) =
        build_with_argent(&shapes::mint(&Profile::Script), family).expect("the builder accepts");
    let budgets: Vec<u16> = theirs
        .inputs
        .iter()
        .map(|input| input.compute_commit.compute_budget().expect("a budget"))
        .collect();
    assert_eq!(budgets, [5, 0]);
}
