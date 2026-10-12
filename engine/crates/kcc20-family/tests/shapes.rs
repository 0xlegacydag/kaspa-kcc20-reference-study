//! Every honest shape is accepted by the reference authors' own runner.

mod common;

use std::collections::BTreeSet;

use kaspa_consensus_core::mass::ComputeBudget;
use kaspa_consensus_core::tx::ComputeCommit;
use kcc20_family::scenario::{InputKind, InputSpec, OutputSpec};
use kcc20_family::shapes::{self, BorrowKind, Profile, Realistic};
use kcc20_family::{Entry, EntryRole, Family};

fn profiles() -> [Profile; 2] {
    [Profile::Script, Profile::Realistic(Realistic::default())]
}

#[test]
fn there_are_twenty_nine_honest_shapes_with_distinct_names() {
    for profile in profiles() {
        let shapes = shapes::all(&profile);
        assert_eq!(shapes.len(), 29);
        let names: BTreeSet<&str> = shapes.iter().map(|shape| shape.name.as_str()).collect();
        assert_eq!(names.len(), 29, "shape names are distinct");
    }
}

#[test]
fn the_authors_runner_accepts_every_honest_shape_in_the_script_profile() {
    let family = Family::pinned();
    let no_budget = ComputeCommit::ComputeBudget(ComputeBudget(0));
    for shape in shapes::all(&Profile::Script) {
        let assembled = shape
            .assemble(family)
            .unwrap_or_else(|error| panic!("`{}` does not assemble: {error}", shape.name));
        assert_eq!(assembled.tx.version, 1);
        assert!(
            assembled
                .tx
                .inputs
                .iter()
                .all(|input| input.compute_commit == no_budget),
            "`{}`: the assembler commits no budget on its own",
            shape.name
        );
        common::run_authors(&assembled)
            .unwrap_or_else(|error| panic!("`{}` is refused: {error}", shape.name));
    }
}

#[test]
fn the_authors_runner_accepts_every_honest_shape_in_the_realistic_profile() {
    // Here the funding coin is locked to a public key, so the runner also checks a real
    // signature on an ordinary input that commits to the covenant outputs.
    let family = Family::pinned();
    for shape in shapes::all(&Profile::Realistic(Realistic::default())) {
        let assembled = shape
            .assemble(family)
            .unwrap_or_else(|error| panic!("`{}` does not assemble: {error}", shape.name));
        common::run_authors(&assembled)
            .unwrap_or_else(|error| panic!("`{}` is refused: {error}", shape.name));
    }
}

#[test]
fn every_entry_has_a_shape_and_the_shape_calls_it() {
    let family = Family::pinned();
    for profile in profiles() {
        for entry in Entry::ALL {
            let (shape, input_index) = shapes::for_entry(&profile, entry);
            let assembled = shape.assemble(family).expect("the shape assembles");
            let info = &assembled.inputs[input_index];
            assert_eq!(info.index, input_index);
            assert_eq!(
                info.entry(),
                Some(entry),
                "`{}` input {input_index}",
                shape.name
            );
            assert_eq!(info.contract(), Some(entry.contract()));
            let InputKind::Contract {
                role,
                redeem_script,
                ..
            } = &info.kind
            else {
                panic!(
                    "`{}` input {input_index} is not a contract input",
                    shape.name
                );
            };
            assert_eq!(*role, Some(entry.role()));
            assert_eq!(redeem_script.len(), family.bytecode(entry.contract()).len());
            // The description above is what the scenario says. The bytes say the same:
            // the coin is locked to the hash of the script the call pushes last, and the
            // push in front of it is the dispatch tag of the entry, which the selector of
            // the contract compares byte for byte.
            let pushes =
                kcc20_family::raw::split_pushes(&assembled.tx.inputs[input_index].signature_script)
                    .expect("a signature script of pushes");
            assert!(pushes.len() >= 2, "`{}`", shape.name);
            assert_eq!(
                pushes[pushes.len() - 1],
                kcc20_family::raw::push_redeem(redeem_script).expect("a push")
            );
            assert_eq!(
                pushes[pushes.len() - 2],
                kcc20_family::raw::push(&family.dispatch_tag(entry)).expect("a push"),
                "`{}` input {input_index}: the tag in front of the redeem script",
                shape.name
            );
            assert_eq!(
                assembled.utxos[input_index].script_public_key,
                kaspa_txscript::pay_to_script_hash_script(redeem_script)
            );
            // A delegate never sits at input 0 in an honest shape, a leader always does.
            assert_eq!(
                input_index == 0,
                entry.role() == EntryRole::Leader,
                "{entry}"
            );
            common::run_authors(&assembled)
                .unwrap_or_else(|error| panic!("`{}` is refused: {error}", shape.name));
        }
    }
}

#[test]
fn the_authors_runner_commits_these_budgets() {
    // What the runner writes into the inputs after measuring them, per entry, in the script
    // profile. These are observations of the authors' tool, pinned so that a change of a
    // shape, of the artifact or of the engine's prices shows up here.
    let family = Family::pinned();
    let observed: [(Entry, &[u16]); 11] = [
        (Entry::Transfer, &[12]),
        (Entry::TransferDelegator, &[7, 13]),
        (Entry::Mint, &[5, 0]),
        (Entry::MintSplit, &[2, 0]),
        (Entry::MintReclaim, &[10]),
        (Entry::MintReclaimInto, &[2, 11]),
        (Entry::MintReclaimDelegator, &[2, 11]),
        (Entry::SeedCreate, &[4, 0]),
        (Entry::SeedSplit, &[0, 0]),
        (Entry::SeedReclaim, &[1, 11]),
        (Entry::SeedReclaimDelegator, &[1, 11]),
    ];
    for (entry, expected) in observed {
        let (shape, _) = shapes::for_entry(&Profile::Script, entry);
        let tx = common::run_authors(&shape.assemble(family).expect("the shape assembles"))
            .expect("the shape is accepted");
        let budgets: Vec<u16> = tx
            .inputs
            .iter()
            .map(|input| {
                input
                    .compute_commit
                    .compute_budget()
                    .expect("a version-1 input carries a budget")
            })
            .collect();
        assert_eq!(budgets, expected, "{entry} (`{}`)", shape.name);
    }
}

#[test]
fn script_profile_uses_its_stated_values() {
    // 1000-sompi contract coins; an OP_TRUE funding coin of 2000 sompi only where the
    // authors have one; no change output.
    for shape in shapes::all(&Profile::Script) {
        for input in &shape.inputs {
            match input {
                InputSpec::Contract(input) => assert!(
                    matches!(input.value, 1_000 | 321),
                    "`{}`: coin value {}",
                    shape.name,
                    input.value
                ),
                InputSpec::Ordinary(input) => {
                    assert!(
                        matches!(input.value, 1_000 | 2_000),
                        "`{}`: ordinary coin value {}",
                        shape.name,
                        input.value
                    )
                }
            }
        }
        assert!(
            shape.total_in() >= shape.total_out(),
            "`{}` does not create sompi",
            shape.name
        );
    }
    let funded: Vec<String> = shapes::all(&Profile::Script)
        .into_iter()
        .filter(|shape| {
            shape.inputs.iter().any(|input| match input {
                InputSpec::Ordinary(input) => input.script_public_key == shapes::op_true_script(),
                InputSpec::Contract(_) => false,
            })
        })
        .map(|shape| shape.name)
        .collect();
    assert_eq!(
        funded,
        ["mint", "minter split", "seed create", "seed split"]
    );
}

#[test]
fn realistic_profile_pays_exactly_the_fee_and_returns_the_change() {
    let values = Realistic::default();
    let funding_script =
        shapes::pay_to_public_key_script(&kcc20_family::keys::x_only(values.funding_key));
    for shape in shapes::all(&Profile::Realistic(values.clone())) {
        assert_eq!(
            shape.total_in() - shape.total_out(),
            values.fee,
            "`{}`",
            shape.name
        );
        // The funding input is the last input and the change output the last output.
        match shape.inputs.last() {
            Some(InputSpec::Ordinary(input)) => {
                assert_eq!(input.script_public_key, funding_script, "`{}`", shape.name);
                assert_eq!(input.value, values.funding_value);
            }
            _ => panic!("`{}` has no funding input", shape.name),
        }
        match shape.outputs.last() {
            Some(OutputSpec::Plain(output)) => {
                assert_eq!(output.script_public_key, funding_script, "`{}`", shape.name);
                assert!(output.binding.is_none());
            }
            _ => panic!("`{}` has no change output", shape.name),
        }
        for input in &shape.inputs {
            if let InputSpec::Contract(input) = input {
                assert_eq!(input.value, values.coin_value, "`{}`", shape.name);
            }
        }
    }
}

#[test]
fn realistic_funding_signature_is_a_real_one() {
    // Change one output after assembly: the funding input's signature (type ALL) no longer
    // covers the transaction, and the authors' runner refuses exactly that input.
    let family = Family::pinned();
    let shape = shapes::mint(&Profile::Realistic(Realistic::default()));
    let funding_index = shape.inputs.len() - 1;
    let mut assembled = shape.assemble(family).expect("the shape assembles");
    let change_index = assembled.tx.outputs.len() - 1;
    assembled.tx.outputs[change_index].value -= 1;
    assembled.tx.finalize();
    let (input_index, error) = common::refused_input(&assembled);
    assert_eq!(input_index, funding_index);
    assert_eq!(error, kaspa_txscript_errors::TxScriptError::EvalFalse);
}

#[test]
fn assembly_is_deterministic() {
    // Schnorr signatures are made without auxiliary randomness: the same scenario gives the
    // same bytes every time.
    let family = Family::pinned();
    for profile in profiles() {
        for shape in [
            shapes::borrow(&profile, BorrowKind::HashChain),
            shapes::transfer(&profile, 3, 3),
            shapes::mint_reclaim_into(&profile),
        ] {
            let first = shape.assemble(family).expect("the shape assembles");
            let second = shape.assemble(family).expect("the shape assembles");
            assert_eq!(first.tx, second.tx, "`{}`", shape.name);
            assert_eq!(first.utxos, second.utxos);
            assert_eq!(first.inputs, second.inputs);
            assert_eq!(first.tx.id(), second.tx.id());
        }
    }
}

#[test]
fn a_scenario_is_data_that_can_be_changed_before_assembly() {
    // The transaction fields of a scenario reach the transaction unchanged, whatever they are.
    let family = Family::pinned();
    let mut shape = shapes::transfer(&Profile::Script, 1, 1);
    shape.version = 7;
    shape.lock_time = 123;
    shape.gas = 5;
    shape.payload = vec![1, 2, 3];
    shape.storage_mass = 77;
    shape.contract_input_mut(0).sequence = 9;
    shape.contract_input_mut(0).compute_commit = ComputeBudget(12).into();
    let assembled = shape
        .assemble(family)
        .expect("the assembler does not judge");
    assert_eq!(assembled.tx.version, 7);
    assert_eq!(assembled.tx.lock_time, 123);
    assert_eq!(assembled.tx.gas, 5);
    assert_eq!(assembled.tx.payload, [1, 2, 3]);
    assert_eq!(assembled.tx.storage_mass(), 77);
    assert_eq!(assembled.tx.inputs[0].sequence, 9);
    assert_eq!(
        assembled.tx.inputs[0].compute_commit,
        ComputeCommit::ComputeBudget(ComputeBudget(12))
    );
}

#[test]
fn a_computed_argument_sees_the_finished_transaction() {
    // `Arg::Computed` builds a whole codec value from the unsigned transaction. Here it
    // re-creates the witness of the honest shape, so the result must be the honest bytes.
    use std::sync::Arc;

    use argent::codec::ArtifactValue;
    use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
    use kcc20_family::keys;
    use kcc20_family::scenario::Arg;
    use kcc20_family::states::PATH_NORMAL;

    let family = Family::pinned();
    let honest = shapes::transfer(&Profile::Script, 1, 1);
    let mut computed = honest.clone();
    let args = computed.contract_input_mut(0).args_mut();
    *args.last_mut().expect("transfer has a witness argument") = Arg::Computed(Arc::new(|ctx| {
        assert_eq!(ctx.input_index, 0);
        assert_eq!(
            ctx.tx.tx.outputs.len(),
            1,
            "all outputs exist when the closure runs"
        );
        assert!(
            ctx.tx.tx.inputs[0].signature_script.is_empty(),
            "the transaction is unsigned"
        );
        let mut witness = vec![PATH_NORMAL];
        witness.extend(keys::schnorr_signature(
            ctx,
            &keys::keypair(keys::ALICE),
            SIG_HASH_ALL,
        ));
        ArtifactValue::Bytes(witness)
    }));
    assert_eq!(
        computed
            .assemble(family)
            .expect("the scenario assembles")
            .tx,
        honest.assemble(family).expect("the shape assembles").tx
    );
}

#[test]
fn realistic_defaults_keep_every_mass_below_the_standard_cap() {
    // The default values of the realistic profile are meant as a sane starting point. This
    // pins what the consensus mass calculator (mainnet parameters) says about the 29 honest
    // shapes with those values, after the authors' runner has written the budgets: every mass
    // stays far below 100,000 grams.
    use kaspa_consensus_core::config::params::MAINNET_PARAMS;
    use kaspa_consensus_core::mass::MassCalculator;
    use kaspa_consensus_core::tx::PopulatedTransaction;

    let family = Family::pinned();
    let calculator = MassCalculator::new_with_consensus_params(&MAINNET_PARAMS);
    let (mut compute, mut transient, mut storage) = (0, 0, 0);
    for shape in shapes::all(&Profile::Realistic(Realistic::default())) {
        let assembled = shape.assemble(family).expect("the shape assembles");
        let tx = common::run_authors(&assembled).expect("the shape is accepted");
        let masses = calculator.calc_non_contextual_masses(&tx);
        let populated = PopulatedTransaction::new(&tx, assembled.utxos.clone());
        let contextual = calculator
            .calc_contextual_masses(&populated)
            .expect("the storage mass is defined");
        compute = compute.max(masses.compute_mass);
        transient = transient.max(masses.transient_mass);
        storage = storage.max(contextual.storage_mass);
    }
    assert_eq!((compute, transient, storage), (20_602, 53_328, 11_309));
}

/// The KCC20 states of the contract outputs of a shape, in output order.
fn token_output_states(shape: &kcc20_family::Scenario) -> Vec<kcc20_family::Kcc20State> {
    shape
        .outputs
        .iter()
        .filter_map(|output| match output {
            OutputSpec::Contract(output) => output.state.as_kcc20().cloned(),
            OutputSpec::Plain(_) => None,
        })
        .collect()
}

/// The KCC20 states of the contract inputs of a shape, in input order.
fn token_input_states(shape: &kcc20_family::Scenario) -> Vec<kcc20_family::Kcc20State> {
    shape
        .inputs
        .iter()
        .filter_map(|input| match input {
            InputSpec::Contract(input) => input.state.as_kcc20().cloned(),
            InputSpec::Ordinary(_) => None,
        })
        .collect()
}

#[test]
fn the_token_outputs_of_a_shape_are_told_apart_from_each_other_and_from_the_coins_spent() {
    // Two outputs with one state are one script: a declared state held against the wrong
    // output would pass. An output with the state of a spent coin is that coin's script: a
    // check that compared the output with the coin instead of with the declared state would
    // pass. No transfer shape has either.
    for profile in profiles() {
        for shape in shapes::all(&profile) {
            let outputs = token_output_states(&shape);
            let inputs = token_input_states(&shape);
            for first in 0..outputs.len() {
                for second in first + 1..outputs.len() {
                    assert_ne!(
                        outputs[first], outputs[second],
                        "`{}`: outputs {first} and {second}",
                        shape.name
                    );
                }
            }
            for (index, output) in outputs.iter().enumerate() {
                assert!(
                    !inputs.contains(output),
                    "`{}`: token output {index} has the state of a spent token coin",
                    shape.name
                );
            }
        }
    }
}

#[test]
fn the_minter_and_the_recipient_of_a_mint_are_two_keys() {
    for profile in profiles() {
        let mint = shapes::mint(&profile);
        let minter = mint
            .contract_input(0)
            .state
            .as_public_mint()
            .expect("a minter")
            .owner;
        let recipient = token_output_states(&mint);
        assert_eq!(recipient.len(), 1);
        assert_ne!(minter, recipient[0].owner);
    }
}

#[test]
fn the_covenant_id_scheme_is_shown_with_two_covenants() {
    use kcc20_family::states::OWNER_COVENANT_ID;

    let family = Family::pinned();
    for profile in profiles() {
        for (role, token_input) in [(EntryRole::Leader, 0), (EntryRole::Delegate, 1)] {
            let shape = shapes::transfer_with_owner_scheme(&profile, role, OWNER_COVENANT_ID);
            let coin = shape.contract_input(token_input);
            let owner = coin.state.as_kcc20().expect("a token coin").owner;
            // The coin does not carry the id that owns it ...
            assert_eq!(owner, shapes::OWNING_COVENANT_ID_BYTES);
            assert_ne!(coin.covenant_id, Some(shapes::owning_covenant_id()));
            // ... exactly one other input does, and it is not a coin of the three contracts.
            let carriers: Vec<usize> = shape
                .inputs
                .iter()
                .enumerate()
                .filter(|(_, input)| match input {
                    InputSpec::Contract(input) => {
                        input.covenant_id == Some(shapes::owning_covenant_id())
                    }
                    InputSpec::Ordinary(input) => {
                        input.covenant_id == Some(shapes::owning_covenant_id())
                    }
                })
                .map(|(index, _)| index)
                .collect();
            let authority = match role {
                EntryRole::Leader => 1,
                EntryRole::Delegate => 2,
            };
            assert_eq!(carriers, vec![authority], "`{}`", shape.name);
            assert!(matches!(shape.inputs[authority], InputSpec::Ordinary(_)));

            // Without that coin's covenant id the authors' runner refuses the token input.
            let mut alone = shape.clone();
            alone.ordinary_input_mut(authority).covenant_id = None;
            let assembled = alone.assemble(family).expect("the shape assembles");
            let (refused, error) = common::refused_input(&assembled);
            assert_eq!(refused, token_input, "`{}`", shape.name);
            assert_eq!(error, kaspa_txscript_errors::TxScriptError::VerifyError);
        }
    }
}

#[test]
fn the_reference_shape_of_a_coin_owned_by_its_own_covenant_is_kept() {
    // The reference's own test of owner scheme 0x04: the coin carries the covenant id that
    // owns it and no other input takes part. It is not one of the 29 shapes.
    let family = Family::pinned();
    for profile in profiles() {
        let names: Vec<String> = shapes::all(&profile)
            .into_iter()
            .map(|shape| shape.name)
            .collect();
        for (role, token_input) in [(EntryRole::Leader, 0), (EntryRole::Delegate, 1)] {
            let shape = shapes::transfer_owned_by_its_own_covenant(&profile, role);
            assert!(!names.contains(&shape.name));
            let coin = shape.contract_input(token_input);
            assert_eq!(
                Some(coin.state.as_kcc20().expect("a token coin").owner),
                coin.covenant_id.map(|id| id.as_bytes())
            );
            let assembled = shape.assemble(family).expect("the shape assembles");
            common::run_authors(&assembled)
                .unwrap_or_else(|error| panic!("`{}` is refused: {error}", shape.name));
        }
    }
}

#[test]
fn the_witness_and_the_new_owner_of_a_call_are_two_different_arguments() {
    use kcc20_family::scenario::LateBytes;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let profile = Profile::Script;
    // A split takes a public key and no witness.
    for mut split in [shapes::mint_split(&profile), shapes::seed_split(&profile)] {
        let name = split.name.clone();
        let LateBytes::Fixed(new_owner) = split.contract_input_mut(0).new_owner_mut().clone()
        else {
            panic!("`{name}`: the new owner is a fixed key");
        };
        assert_eq!(
            new_owner,
            kcc20_family::keys::x_only(kcc20_family::keys::BOB)
        );
        let asked_for_a_witness = catch_unwind(AssertUnwindSafe(|| {
            split.contract_input_mut(0).witness_mut();
        }));
        assert!(asked_for_a_witness.is_err(), "`{name}` has no witness");
    }
    // Entries that take neither: nothing to hand out.
    for mut shape in [
        shapes::mint(&profile),
        shapes::seed_create(&profile),
        shapes::mint_reclaim_into(&profile),
        shapes::seed_reclaim(&profile),
    ] {
        let name = shape.name.clone();
        for ask in [0, 1] {
            let refused = catch_unwind(AssertUnwindSafe(|| {
                let input = shape.contract_input_mut(0);
                if ask == 0 {
                    input.witness_mut();
                } else {
                    input.new_owner_mut();
                }
            }));
            assert!(refused.is_err(), "`{name}` input 0, question {ask}");
        }
    }
    // Entries with a witness or a signature hand it out, and have no new owner.
    let mut with_witness = vec![
        (shapes::transfer(&profile, 1, 1), 0),
        (shapes::borrow(&profile, BorrowKind::Threshold), 1),
        (shapes::mint_reclaim(&profile), 0),
        (shapes::mint_reclaim_into(&profile), 1),
        (shapes::seed_reclaim(&profile), 1),
    ];
    for (shape, input) in &mut with_witness {
        shape.contract_input_mut(*input).witness_mut();
        let name = shape.name.clone();
        let asked_for_a_new_owner = catch_unwind(AssertUnwindSafe(|| {
            shape.contract_input_mut(*input).new_owner_mut();
        }));
        assert!(asked_for_a_new_owner.is_err(), "`{name}` input {input}");
    }
}
