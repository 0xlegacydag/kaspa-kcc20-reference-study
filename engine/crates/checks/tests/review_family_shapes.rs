//! Do the honest shapes exercise what their names say?
//!
//! A shape is described as data ("this input calls `KCC20.transfer`, its owner scheme is
//! 0x02"). Whether the assembled bytes make the engine run that entry and that branch is a
//! separate question. It is answered here without the description and without the opcode
//! log: one opcode of the contract is replaced, and the shape must notice exactly when it
//! runs that opcode.
//!
//! - An entry is switched off by turning its final `OpTrue` into `OpFalse`. Every input
//!   that is said to call the entry must then end with a false stack, and every other input
//!   of every honest shape must still pass.
//! - A branch of the owner check or of the borrow policy is marked by turning the first
//!   check of the branch into `OpReturn`. Only the shape of that scheme and role may stop
//!   there.
//!
//! The last part looks at the keys of the shapes: where two roles hold the same key or the
//! same state, a mix-up of the two roles cannot be seen.

use std::panic::{AssertUnwindSafe, catch_unwind};

use checks::{Case, Harness, Outcome, judge_accept};
use kaspa_txscript::opcodes::codes::{OpFalse, OpReturn, OpTrue, OpVerify};
use kcc20_family::{
    Contract, Entry, EntryRole, Family, Scenario, SourceMap,
    keys::{self, BOB},
    scenario::{Arg, Call, InputSpec, LateBytes, OutputSpec},
    shapes::{self, BorrowKind, Profile},
    states::{
        OWNER_COVENANT_ID, OWNER_P2PK_SCHNORR, OWNER_P2PKH_ECDSA, OWNER_P2PKH_SCHNORR, OWNER_P2SH,
    },
};

fn script() -> Profile {
    Profile::Script
}

/// The pinned family with one byte of one contract replaced.
fn family_with_byte(contract: Contract, offset: usize, expected: u8, replacement: u8) -> Family {
    let family = Family::pinned();
    let mut bytecode = family.bytecode(contract).to_vec();
    assert_eq!(
        bytecode[offset], expected,
        "{contract} byte {offset} is not the opcode this test replaces"
    );
    bytecode[offset] = replacement;
    family
        .with_bytecode(contract, bytecode)
        .expect("a replacement of the same length")
}

/// The pinned family with `entry` switched off: its last opcode, the `OpTrue` that leaves
/// the result on the stack, becomes `OpFalse`.
fn family_without_entry(entry: Entry) -> Family {
    let map = SourceMap::pinned().contract(entry.contract());
    let range = map
        .entries()
        .iter()
        .find(|range| range.name == entry.name())
        .unwrap_or_else(|| panic!("the compiler recorded no range for {entry}"));
    let last = map
        .opcode_at(range.end - 1)
        .expect("an entry ends with an opcode");
    assert_eq!(
        last.offset,
        range.end - 1,
        "{entry} ends with a one-byte opcode"
    );
    family_with_byte(entry.contract(), last.offset, OpTrue, OpFalse)
}

/// Whether input `index` of the scenario is said to call `entry`.
fn calls(scenario: &Scenario, index: usize, entry: Entry) -> bool {
    match &scenario.inputs[index] {
        InputSpec::Contract(input) => input.call.entry() == Some(entry),
        InputSpec::Ordinary(_) => false,
    }
}

#[test]
fn every_input_of_every_honest_shape_runs_the_entry_it_names() {
    let shapes = shapes::all(&script());
    for entry in Entry::ALL {
        let harness = Harness::pinned().with_family(family_without_entry(entry));
        let mut callers = 0;
        let mut without_a_coin_of_the_contract = 0;
        for shape in &shapes {
            // A shape without a coin of the entry's contract meets the changed bytecode only
            // through a template hash; one such shape per entry is enough to see that the
            // family stays consistent.
            let spends_the_contract = shape.inputs.iter().any(|input| match input {
                InputSpec::Contract(input) => input.contract() == entry.contract(),
                InputSpec::Ordinary(_) => false,
            });
            if !spends_the_contract {
                without_a_coin_of_the_contract += 1;
                if without_a_coin_of_the_contract > 1 {
                    continue;
                }
            }
            let outcome = harness.run(shape);
            for index in 0..shape.inputs.len() {
                let run = outcome.inputs[index]
                    .alone
                    .as_ref()
                    .expect("every input is run");
                if calls(shape, index, entry) {
                    callers += 1;
                    assert!(
                        !run.ok,
                        "`{}` input {index} is said to call {entry}, but passes with {entry} \
                         switched off",
                        shape.name
                    );
                    assert_eq!(
                        run.refused_by(),
                        Some("final stack"),
                        "`{}` input {index}: {}",
                        shape.name,
                        run.describe()
                    );
                    assert_eq!(run.error_variant(), Some("EvalFalse"));
                } else {
                    assert!(
                        run.ok,
                        "`{}` input {index} does not call {entry}, but fails with {entry} \
                         switched off: {}",
                        shape.name,
                        run.describe()
                    );
                }
            }
        }
        assert!(callers > 0, "no honest shape calls {entry}");
    }
}

/// The first check of every branch of the owner check, in the copy `transfer` runs and in
/// the copy `transfer_delegator` runs (rules K-38, K-40, K-43, K-46 and K-47 of the rule
/// inventory).
const OWNER_BRANCHES: [(u8, usize, usize); 5] = [
    (OWNER_P2PK_SCHNORR, 2249, 3837),
    (OWNER_P2PKH_SCHNORR, 2284, 3872),
    (OWNER_P2PKH_ECDSA, 2329, 3917),
    (OWNER_P2SH, 2385, 3973),
    (OWNER_COVENANT_ID, 2401, 3989),
];

/// Asserts that input `input` stops at the marker at `offset` and nowhere else.
fn assert_stops_at_marker(outcome: &Outcome, input: usize, offset: usize, what: &str) {
    let run = outcome.inputs[input]
        .alone
        .as_ref()
        .expect("every input is run");
    assert!(
        !run.ok,
        "{what}: `{}` passes, so it never ran the marked opcode",
        outcome.scenario
    );
    assert_eq!(
        run.error_variant(),
        Some("EarlyReturn"),
        "{what}: {}",
        run.describe()
    );
    assert_eq!(
        run.refusal.as_ref().and_then(|refusal| refusal.byte_offset),
        Some(offset),
        "{what}: {}",
        run.describe()
    );
}

#[test]
fn every_owner_scheme_shape_runs_the_branch_of_its_scheme_and_role() {
    let roles = [EntryRole::Leader, EntryRole::Delegate];
    for (marked_scheme, leader_offset, delegate_offset) in OWNER_BRANCHES {
        for marked_role in roles {
            let (offset, token_input) = match marked_role {
                EntryRole::Leader => (leader_offset, 0),
                EntryRole::Delegate => (delegate_offset, 1),
            };
            let harness = Harness::pinned().with_family(family_with_byte(
                Contract::Kcc20,
                offset,
                OpVerify,
                OpReturn,
            ));
            for role in roles {
                for (scheme, _, _) in OWNER_BRANCHES {
                    let shape = shapes::transfer_with_owner_scheme(&script(), role, scheme);
                    let outcome = harness.run(&shape);
                    let what = format!(
                        "marker in the {marked_role:?} branch of scheme {marked_scheme:#04x}"
                    );
                    if role == marked_role && scheme == marked_scheme {
                        assert_stops_at_marker(&outcome, token_input, offset, &what);
                    } else {
                        judge_accept(&outcome).unwrap_or_else(|failure| {
                            panic!("{what}: `{}` must not reach it: {failure}", shape.name)
                        });
                    }
                }
            }
        }
    }
}

#[test]
fn every_borrow_shape_runs_the_branch_of_its_policy() {
    // A check that only the branch of the policy holds: K-51 (the threshold policy takes no
    // witness bytes), K-52 (the guard key signs), K-54 (the link hashes to the guard). The
    // comparison of the increase with the threshold (K-61) is behind the branches and runs
    // for all three policies, with a threshold of zero for the two that have none.
    let branches = [
        (BorrowKind::Threshold, 2455),
        (BorrowKind::Signature, 2485),
        (BorrowKind::HashChain, 2538),
    ];
    for (marked, offset) in branches {
        let harness = Harness::pinned().with_family(family_with_byte(
            Contract::Kcc20,
            offset,
            OpVerify,
            OpReturn,
        ));
        for (kind, _) in branches {
            let outcome = harness.run(&shapes::borrow(&script(), kind));
            let what = format!("marker in the branch of {marked:?}");
            if kind == marked {
                assert_stops_at_marker(&outcome, 0, offset, &what);
            } else {
                judge_accept(&outcome).unwrap_or_else(|failure| {
                    panic!("{what}: the {kind:?} shape must not reach it: {failure}")
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Keys and states per role
// ---------------------------------------------------------------------------------------

/// The KCC20 state declared to `mint` or `create` by input 0.
fn declared_recipient(scenario: &Scenario) -> kcc20_family::Kcc20State {
    let Call::Typed { args, .. } = &scenario.contract_input(0).call else {
        panic!("the shape has a typed call")
    };
    args.iter()
        .find_map(|arg| match arg {
            Arg::State(state) => Some(state.clone()),
            _ => None,
        })
        .expect("the call names a recipient state")
}

#[test]
fn the_shapes_with_two_parties_give_them_different_keys() {
    // The splits, the merges, the seed's create and the plain transfers name two
    // different owners, so the continuation and the new coin cannot be swapped unseen.
    let split = shapes::mint_split(&script());
    let retained = split.outputs[0].clone();
    let added = split.outputs[1].clone();
    let (OutputSpec::Contract(retained), OutputSpec::Contract(added)) = (retained, added) else {
        panic!("a split has two contract outputs")
    };
    assert_ne!(
        retained.state.as_public_mint().unwrap().owner,
        added.state.as_public_mint().unwrap().owner
    );

    let create = shapes::seed_create(&script());
    assert_ne!(
        create
            .contract_input(0)
            .state
            .as_token_seed()
            .unwrap()
            .owner,
        declared_recipient(&create).owner
    );

    for merge in [
        shapes::mint_reclaim_into(&script()),
        shapes::seed_reclaim(&script()),
    ] {
        let owner = |index: usize| match &merge.contract_input(index).state {
            kcc20_family::State::PublicMint(state) => state.owner,
            kcc20_family::State::TokenSeed(state) => state.owner,
            kcc20_family::State::Kcc20(state) => state.owner,
        };
        assert_ne!(owner(0), owner(1), "`{}`", merge.name);
    }

    let transfer = shapes::transfer(&script(), 3, 1);
    let owners: Vec<[u8; 32]> = (0..3)
        .map(|index| {
            transfer
                .contract_input(index)
                .state
                .as_kcc20()
                .unwrap()
                .owner
        })
        .collect();
    assert!(owners[0] != owners[1] && owners[1] != owners[2] && owners[0] != owners[2]);
    let OutputSpec::Contract(output) = &transfer.outputs[0] else {
        panic!("a transfer has a token output")
    };
    assert!(!owners.contains(&output.state.as_kcc20().unwrap().owner));
}

/// The mint shape mints to a key that is not the minter's own. With one key in both
/// roles the shape could not tell the two owners apart.
#[test]
fn the_mint_shape_gives_the_minter_and_the_recipient_different_owners() {
    let mint = shapes::mint(&script());
    let minter = mint.contract_input(0).state.as_public_mint().unwrap().owner;
    assert_ne!(
        minter,
        declared_recipient(&mint).owner,
        "a mix-up of the minter's owner and the recipient's owner cannot be seen in this shape"
    );
}

/// The token outputs of a transfer shape differ from one another, so that each declared
/// state fits one output only.
#[test]
fn the_outputs_of_a_transfer_shape_are_pairwise_different() {
    let mut equal_pairs = Vec::new();
    for inputs in 1..=3 {
        for outputs in 2..=3 {
            let shape = shapes::transfer(&script(), inputs, outputs);
            let states: Vec<_> = shape
                .outputs
                .iter()
                .filter_map(|output| match output {
                    OutputSpec::Contract(output) => Some(output.state.clone()),
                    OutputSpec::Plain(_) => None,
                })
                .collect();
            for first in 0..states.len() {
                for second in first + 1..states.len() {
                    if states[first] == states[second] {
                        equal_pairs.push(format!("{}: outputs {first} and {second}", shape.name));
                    }
                }
            }
        }
    }
    assert!(
        equal_pairs.is_empty(),
        "outputs that cannot be told apart, so that a declared state checked against the \
         wrong output would pass: {equal_pairs:#?}"
    );
}

/// The coin of the covenant-id owner shape is owned by another covenant than the one it
/// carries, so that an input of the owning covenant has to take part. The shape in which
/// the owner is the token's own covenant id is `shapes::transfer_owned_by_its_own_covenant`.
#[test]
fn the_covenant_id_owner_shape_is_owned_by_another_covenant() {
    for (role, token_input) in [(EntryRole::Leader, 0), (EntryRole::Delegate, 1)] {
        let shape = shapes::transfer_with_owner_scheme(&script(), role, OWNER_COVENANT_ID);
        let coin = shape.contract_input(token_input);
        assert_ne!(
            Some(coin.state.as_kcc20().unwrap().owner),
            coin.covenant_id.map(|id| id.as_bytes()),
            "`{}`: the coin carries the covenant id that owns it, so the shape does not show \
             an input of the owning covenant taking part",
            shape.name
        );
    }
}

/// The leader shape of the key scheme (0x00) moves the coin to a state that is not the
/// state of the spent coin.
#[test]
fn the_leader_shape_of_the_key_scheme_moves_the_coin_to_another_state() {
    let shape =
        shapes::transfer_with_owner_scheme(&script(), EntryRole::Leader, OWNER_P2PK_SCHNORR);
    let OutputSpec::Contract(output) = &shape.outputs[0] else {
        panic!("a transfer has a token output")
    };
    assert_ne!(
        shape.contract_input(0).state,
        output.state,
        "input and output are the same state and so the same script: a check that compared \
         the output with the spent coin instead of with the declared state would pass"
    );
}

// ---------------------------------------------------------------------------------------
// What a record says an input is
// ---------------------------------------------------------------------------------------

/// The contract and the entry a record names for an input are read from the bytes that
/// ran; what the scenario says about the input is kept next to them.
#[test]
fn a_passing_input_is_not_recorded_as_an_entry_that_never_ran() {
    // The coin is said to hold a token state and its call is said to be `transfer`, but it
    // is locked by OP_TRUE and spent with an empty signature script. No opcode of KCC20
    // runs. The accept is right, and the record of it must not name KCC20.transfer.
    let mut scenario = shapes::transfer(&script(), 1, 1);
    let input = scenario.contract_input_mut(0);
    input.locking_script = Some(shapes::op_true_script());
    input.signature_script = Some(LateBytes::empty());

    let outcome = Case::new("review/a token input that runs no token code")
        .unrecorded()
        .expect_accept(&scenario);
    let record = &outcome.inputs[0];
    assert!(record.alone.as_ref().unwrap().ok);
    assert_eq!(record.signature_script_len, 0);
    assert!(
        !(record.contract.as_deref() == Some("KCC20")
            && record.entry.as_deref() == Some("transfer")),
        "the result line of an accepted input says {} although the coin is locked by OP_TRUE: \
         a count of the entries that accepting checks exercised would include it",
        record.what()
    );
    assert_eq!(
        (record.contract.as_deref(), record.entry.as_deref()),
        (None, None)
    );
    assert_eq!(
        (
            record.stated_contract.as_deref(),
            record.stated_entry.as_deref()
        ),
        (Some("KCC20"), Some("transfer"))
    );
    assert!(!record.runs_what_is_stated());
}

/// `witness_mut` hands out the witness of a call and nothing else. The last bytes argument
/// of a split is the new owner's key, which is no witness.
#[test]
fn witness_mut_is_not_an_argument_that_is_no_witness() {
    // `split` of both contracts takes a public key and no witness. A check that means to
    // damage "the witness" of a split must not get the new owner instead (the codec
    // accepts any other 32 bytes there): asking a split for its witness is a mistake of
    // the test and stops it.
    for mut scenario in [shapes::mint_split(&script()), shapes::seed_split(&script())] {
        let name = scenario.name.clone();
        let asked_for_a_witness = catch_unwind(AssertUnwindSafe(|| {
            scenario.contract_input_mut(0).witness_mut().clone()
        }));
        if let Ok(LateBytes::Fixed(bytes)) = &asked_for_a_witness {
            assert_ne!(
                bytes,
                &keys::x_only(BOB).to_vec(),
                "`{name}`: witness_mut handed out the new_owner argument"
            );
        }
        assert!(
            asked_for_a_witness.is_err(),
            "`{name}`: a split has no witness to hand out"
        );
        // The key has a name of its own.
        let LateBytes::Fixed(new_owner) = scenario.contract_input_mut(0).new_owner_mut().clone()
        else {
            panic!("`{name}`: the new owner is computed from the transaction")
        };
        assert_eq!(new_owner, keys::x_only(BOB).to_vec());
    }
}
