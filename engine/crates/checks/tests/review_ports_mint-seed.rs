//! Review probe: the refusals of `port_minter.rs` and `port_seed.rs`, tested by removal.
//!
//! A port says "this change is refused by rule X at line N". The test harness of
//! `crates/checks` derives rule and line from the position at which the engine stopped.
//! This file tests the reason independently of that position:
//!
//! 1. On the pinned family the changed transaction is refused at the input, the rule and
//!    the line the port names, and the byte offset is one the rule inventory lists for the
//!    rule.
//! 2. The family is rebuilt with that one opcode neutralised (`OpVerify` by `OpDrop`,
//!    `OpEqualVerify` and `OpNumEqualVerify` by `Op2Drop`). On that family the honest side
//!    still passes, and the changed transaction either passes or is refused somewhere
//!    else. A refusal that stays where it was would mean the port names a rule that is not
//!    the reason.
//!
//! What the changed transaction answers without the rule is pinned per case: `Passes` shows
//! that the named rule was the only one in the way (and, for the reclaim flows, that the
//! signature of the changed transaction is a good one), `RefusedBy` names the next rule.
//!
//! Further probes:
//!
//! - the signatures of the reclaim flows are made over the changed transaction, and a
//!   signature of the wrong key is a valid signature of that key;
//! - the transaction a chained case spends from is the one the harness ran, and the steps
//!   of the lifecycle chain of `port_seed.rs` link by the coins they create and spend;
//! - the accepted mints of the port, in coin values a block and a default mempool take;
//! - the control of the count rules (the same token coin beside the leader, not of its
//!   covenant) as a transaction whose scripts all pass.
//!
//! The same removal can be made for every case of a port at once with the mutation mode of
//! the harness (`CHECKS_MUTANT=<Contract>@<byte offset>`, `CHECKS_OBSERVE=1`,
//! `CHECKS_FAST=1`, `CHECK_RESULTS_DIR` set to a directory of its own): run once per
//! refusing opcode a port names, it shows for every rule refusal of the port whether it
//! passes or moves to a later rule.

use checks::{Harness, Outcome, RunOutcome, judge_accept, run};
use kaspa_consensus_core::{Hash, hashing::sighash_type::SIG_HASH_ALL, tx::CovenantBinding};
use kaspa_txscript::opcodes::codes::{Op2Drop, OpDrop, OpEqualVerify, OpNumEqualVerify, OpVerify};
use kcc20_family::{
    Contract, Entry, EntryRole, Family, Scenario, SourceMap,
    keys::{self, ALICE, BOB, CAROL},
    raw,
    scenario::{
        Arg, Call, ContractInput, ContractOutput, InputSpec, LateBytes, OrdinaryInput, OutputSpec,
        PlainOutput,
    },
    shapes::{self, BorrowKind, Profile, Realistic},
    states::{
        BORROW_HASH_CHAIN, Kcc20State, OWNER_COVENANT_ID, OWNER_P2PKH_SCHNORR, PublicMintState,
        TokenSeedState,
    },
    witness,
};

/// Another token family: the extension commitment the earlier checks used.
const OTHER_FAMILY: [u8; 32] = [0xee; 32];
/// Another covenant: the id the earlier checks gave a coin outside the seed's family.
const OTHER_COVENANT: [u8; 32] = [0x22; 32];

fn script() -> Profile {
    Profile::Script
}

// ---------------------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------------------

/// What the changed transaction answers at the judged input once the rule is neutralised.
enum After {
    /// The input passes: the rule was the only one in the way.
    Passes,
    /// The input is refused by this rule or engine check, at another place.
    RefusedBy(&'static str),
}

fn judged(outcome: &Outcome, input: usize) -> &RunOutcome {
    outcome.inputs[input]
        .alone
        .as_ref()
        .expect("the input was run")
}

/// The pinned family with the checking opcode at `offset` of `contract` replaced by a drop
/// of the items it would have judged.
fn family_without_check(contract: Contract, offset: usize) -> Result<Family, String> {
    let family = Family::pinned();
    let mut bytecode = family.bytecode(contract).to_vec();
    let opcode = bytecode[offset];
    bytecode[offset] = if opcode == OpVerify {
        OpDrop
    } else if opcode == OpEqualVerify || opcode == OpNumEqualVerify {
        Op2Drop
    } else {
        return Err(format!(
            "byte {offset} ({opcode:#04x}) is not a checking opcode"
        ));
    };
    family
        .with_bytecode(contract, bytecode)
        .map_err(|error| format!("the weakened family: {error}"))
}

/// One removal probe. `Ok` holds a description of what was seen.
fn removal(
    honest: Option<&Scenario>,
    changed: &Scenario,
    input: usize,
    rule: &str,
    line: Option<u32>,
    after: &After,
) -> Result<String, String> {
    // 1. The pinned family: the refusal the port names.
    if let Some(honest) = honest {
        judge_accept(&run(honest)).map_err(|failure| format!("the honest side: {failure}"))?;
    }
    let pinned = run(changed);
    let refused = judged(&pinned, input);
    if refused.ok {
        return Err(format!("input {input} passes on the pinned family"));
    }
    let refusal = refused
        .refusal
        .as_ref()
        .ok_or("the refusal is not attributed")?;
    if refusal.rule.as_deref() != Some(rule) {
        return Err(format!("refused otherwise: {}", refused.describe()));
    }
    let seen_line = refusal.sil.as_ref().map(|sil| sil.line);
    if seen_line != line {
        return Err(format!("line {seen_line:?}, the port names {line:?}"));
    }
    let offset = refusal.byte_offset.ok_or("the refusal has no offset")?;
    let record = SourceMap::pinned()
        .rule(rule)
        .ok_or("the rule is not in the inventory")?;
    if !record.offsets.contains(&offset) {
        return Err(format!(
            "byte {offset} is not an offset of {rule} in the inventory ({:?})",
            record.offsets
        ));
    }
    let contract = record.contract;
    if refusal.contract.as_deref() != Some(contract.name()) {
        return Err(format!(
            "the input runs {:?}, the rule is of {}",
            refusal.contract,
            contract.name()
        ));
    }

    // 2. The same two transactions on the family without that check.
    let harness = Harness::pinned().with_family(family_without_check(contract, offset)?);
    if let Some(honest) = honest {
        judge_accept(&harness.run(honest))
            .map_err(|failure| format!("without {rule} the honest side fails: {failure}"))?;
    }
    let weakened = harness.run(changed);
    let moved = judged(&weakened, input);
    let seen = match &moved.refusal {
        None => "passes".to_string(),
        Some(next) => format!(
            "is refused by {} at byte {:?}, line {:?}",
            next.refused_by,
            next.byte_offset,
            next.sil.as_ref().map(|sil| sil.line)
        ),
    };
    let report = format!("{rule} at byte {offset}; without it input {input} {seen}");
    if let Some(next) = &moved.refusal
        && next.byte_offset == Some(offset)
        && next.contract == refusal.contract
    {
        return Err(format!("the refusal did not move: {report}"));
    }
    match after {
        After::Passes if moved.ok => Ok(report),
        After::Passes => Err(format!("expected to pass: {report}")),
        After::RefusedBy(by) => match &moved.refusal {
            Some(next) if next.refused_by == *by => Ok(report),
            _ => Err(format!("expected a refusal by {by}: {report}")),
        },
    }
}

/// Runs probes one after the other and reports all failures together.
#[derive(Default)]
struct Probes {
    done: usize,
    failures: Vec<String>,
}

impl Probes {
    #[allow(clippy::too_many_arguments)]
    fn twin(
        &mut self,
        name: &str,
        honest: &Scenario,
        change: impl FnOnce(&mut Scenario),
        input: usize,
        rule: &str,
        line: u32,
        after: After,
    ) {
        let mut changed = honest.clone();
        change(&mut changed);
        self.record(
            name,
            removal(Some(honest), &changed, input, rule, Some(line), &after),
        );
    }

    /// A probe of a transaction that has no honest side in the port.
    fn alone(
        &mut self,
        name: &str,
        changed: &Scenario,
        input: usize,
        rule: &str,
        line: u32,
        after: After,
    ) {
        self.record(
            name,
            removal(None, changed, input, rule, Some(line), &after),
        );
    }

    fn record(&mut self, name: &str, result: Result<String, String>) {
        self.done += 1;
        match result {
            Ok(report) => println!("probe `{name}`: {report}"),
            Err(failure) => {
                println!("probe `{name}` FAILED: {failure}");
                self.failures.push(format!("{name}: {failure}"));
            }
        }
    }

    fn finish(self, at_least: usize) {
        assert!(
            self.failures.is_empty(),
            "{} of {} probes failed:\n{}",
            self.failures.len(),
            self.done,
            self.failures.join("\n")
        );
        assert!(self.done >= at_least, "only {} probes ran", self.done);
    }
}

// ---------------------------------------------------------------------------------------
// The shapes of the minter port
// ---------------------------------------------------------------------------------------

fn minter_in(scenario: &mut Scenario, input: usize) -> &mut PublicMintState {
    scenario
        .contract_input_mut(input)
        .state
        .as_public_mint_mut()
        .expect("a minter coin")
}

fn minter_out(scenario: &mut Scenario, output: usize) -> &mut PublicMintState {
    scenario
        .contract_output_mut(output)
        .state
        .as_public_mint_mut()
        .expect("a minter output")
}

fn token_out(scenario: &mut Scenario, output: usize) -> &mut Kcc20State {
    scenario
        .contract_output_mut(output)
        .state
        .as_kcc20_mut()
        .expect("a token output")
}

fn change_minted_coin(scenario: &mut Scenario, change: impl Fn(&mut Kcc20State)) {
    change(scenario.contract_input_mut(0).declared_state_mut());
    change(token_out(scenario, 1));
}

fn funding_coin() -> OrdinaryInput {
    OrdinaryInput::new(
        shapes::op_true_script(),
        shapes::SCRIPT_FUNDING_VALUE,
        shapes::outpoint(3, 0),
        LateBytes::empty(),
    )
    .labelled("funding (OP_TRUE)")
}

fn merge() -> Scenario {
    shapes::mint_reclaim_into(&script())
}

fn split_of(remaining: i64, take: i64) -> Scenario {
    let mut scenario = shapes::mint_split(&script());
    set_take(&mut scenario, remaining, take);
    scenario
}

fn set_take(scenario: &mut Scenario, remaining: i64, take: i64) {
    minter_in(scenario, 0).remaining = remaining;
    scenario.contract_input_mut(0).args_mut()[0] = Arg::int(take);
    minter_out(scenario, 0).remaining = remaining - take;
    minter_out(scenario, 1).remaining = take;
}

fn mint_of(remaining: i64, limit: i64, amount: i64) -> Scenario {
    let mut scenario = shapes::mint(&script());
    let minter = minter_in(&mut scenario, 0);
    minter.remaining = remaining;
    minter.mint_amount = limit;
    let continuation = minter_out(&mut scenario, 0);
    continuation.remaining = remaining - amount;
    continuation.mint_amount = limit;
    change_minted_coin(&mut scenario, |state| state.amount = amount);
    scenario
}

fn deposit_mint(remaining: i64, amount: i64, deposit: u64) -> Scenario {
    let mut scenario = mint_of(remaining, 10, amount);
    scenario.contract_input_mut(0).value = deposit;
    scenario.contract_output_mut(0).value = deposit;
    change_minted_coin(&mut scenario, |state| state.owner = keys::x_only(CAROL));
    scenario
}

fn reclaim_of(remaining: i64, deposit: u64) -> Scenario {
    let mut scenario = shapes::mint_reclaim(&script());
    minter_in(&mut scenario, 0).remaining = remaining;
    scenario.contract_input_mut(0).value = deposit;
    scenario.plain_output_mut(0).value = deposit;
    scenario
}

fn retiring_first(scenario: &mut Scenario) {
    scenario.inputs.swap(0, 1);
    scenario.contract_output_mut(0).binding = Some(CovenantBinding::new(1, shapes::covenant_id()));
}

fn third_minter(scenario: &mut Scenario) {
    scenario.push_contract_input(
        ContractInput::new(
            PublicMintState::new(keys::x_only(BOB), 3, 10),
            shapes::SCRIPT_SPLIT_VALUE,
            Some(shapes::covenant_id()),
            shapes::outpoint(1, 2),
            Call::typed(
                Entry::MintReclaimDelegator,
                vec![Arg::Bytes(witness::signature(BOB, SIG_HASH_ALL))],
            ),
        )
        .labelled("a third minter: Bob, 3 remaining"),
    );
    scenario.push_plain_output(PlainOutput::new(
        shapes::pay_to_public_key_script(&keys::x_only(BOB)),
        shapes::SCRIPT_SPLIT_VALUE,
    ));
}

fn token_coin_of_bob(index: u32, covenant: Hash) -> ContractInput {
    ContractInput::new(
        Kcc20State::new(keys::x_only(BOB), 5),
        shapes::SCRIPT_COIN_VALUE,
        Some(covenant),
        shapes::outpoint(1, index),
        Call::typed(
            Entry::TransferDelegator,
            vec![Arg::Bytes(witness::owner_key(
                BOB,
                EntryRole::Delegate,
                SIG_HASH_ALL,
            ))],
        ),
    )
    .labelled("a token coin: Bob, 5 tokens")
}

fn minter_coin_of_bob(index: u32, remaining: i64) -> ContractInput {
    ContractInput::new(
        PublicMintState::new(keys::x_only(BOB), remaining, 10),
        shapes::SCRIPT_SPLIT_VALUE,
        Some(shapes::covenant_id()),
        shapes::outpoint(1, index),
        Call::typed(
            Entry::MintReclaimDelegator,
            vec![Arg::Bytes(witness::signature(BOB, SIG_HASH_ALL))],
        ),
    )
    .labelled("a minter coin: Bob")
}

fn seed_coin_of_bob(index: u32) -> ContractInput {
    ContractInput::new(
        TokenSeedState::new(keys::x_only(BOB)),
        shapes::SCRIPT_COIN_VALUE,
        Some(shapes::covenant_id()),
        shapes::outpoint(1, index),
        Call::typed(
            Entry::SeedReclaimDelegator,
            vec![Arg::Bytes(witness::signature(BOB, SIG_HASH_ALL))],
        ),
    )
    .labelled("a seed: Bob")
}

// ---------------------------------------------------------------------------------------
// The shapes of the seed port
// ---------------------------------------------------------------------------------------

fn empty_coin() -> Kcc20State {
    Kcc20State::new(keys::x_only(BOB), 0)
}

fn set_created_coin(scenario: &mut Scenario, recipient: Kcc20State) {
    *scenario.contract_input_mut(0).declared_state_mut() = recipient.clone();
    scenario.contract_output_mut(1).state = recipient.into();
}

fn create(recipient: Kcc20State) -> Scenario {
    let mut scenario = shapes::seed_create(&script());
    set_created_coin(&mut scenario, recipient);
    scenario
}

fn seed_split() -> Scenario {
    shapes::seed_split(&script())
}

fn seed_reclaim() -> Scenario {
    shapes::seed_reclaim(&script())
}

fn funded_seed_reclaim() -> Scenario {
    let mut scenario = seed_reclaim();
    scenario.push_ordinary_input(funding_coin());
    scenario
}

fn seed_output(scenario: &mut Scenario, index: usize) -> &mut TokenSeedState {
    scenario
        .contract_output_mut(index)
        .state
        .as_token_seed_mut()
        .expect("a seed output")
}

fn bound_to_leader() -> Option<CovenantBinding> {
    Some(CovenantBinding::new(0, shapes::covenant_id()))
}

fn pay_to(key_seed: u8, value: u64) -> PlainOutput {
    PlainOutput::new(
        shapes::pay_to_public_key_script(&keys::x_only(key_seed)),
        value,
    )
}

fn pay_into(receiving: Kcc20State, payer: u8, added: i64) -> Scenario {
    let mut scenario = shapes::borrow(&script(), BorrowKind::Threshold);
    let paying = Kcc20State::new(keys::x_only(payer), 100);
    let after = vec![
        receiving.clone().with_amount(receiving.amount + added),
        paying.clone().with_amount(100 - added),
    ];
    let leader = scenario.contract_input_mut(0);
    leader.state = receiving.into();
    *leader.declared_states_mut() = after.clone();
    let delegate = scenario.contract_input_mut(1);
    delegate.state = paying.into();
    *delegate.witness_mut() = witness::owner_key(payer, EntryRole::Delegate, SIG_HASH_ALL);
    for (index, state) in after.into_iter().enumerate() {
        scenario.contract_output_mut(index).state = state.into();
    }
    scenario
}

// ---------------------------------------------------------------------------------------
// Removal probes: port_minter.rs
// ---------------------------------------------------------------------------------------

#[test]
fn the_minter_refusals_are_made_by_the_rules_the_port_names() {
    let mut probes = Probes::default();
    let merge = merge();

    // A_minter.ReclaimInto
    let mut funded = merge.clone();
    funded.push_ordinary_input(funding_coin());
    probes.twin(
        "merge/deposit: successor one sompi more",
        &funded,
        |scenario| scenario.contract_output_mut(0).value = 1_001,
        0,
        "M-48",
        288,
        After::Passes,
    );
    probes.twin(
        "merge/retiring minter of another family",
        &merge,
        |scenario| minter_in(scenario, 1).extension_commitment = OTHER_FAMILY,
        0,
        "M-46",
        280,
        After::Passes,
    );
    probes.twin(
        "merge/retiring minter with a per-mint limit of 11",
        &merge,
        |scenario| minter_in(scenario, 1).mint_amount = 11,
        0,
        "M-45",
        279,
        After::Passes,
    );
    probes.twin(
        "merge/successor owned by Carol",
        &merge,
        |scenario| minter_out(scenario, 0).owner = keys::x_only(CAROL),
        0,
        "M-49",
        300,
        After::Passes,
    );
    // The retiring minter placed first, judged at the survivor, with two successors, 22 and 36.
    probes.twin(
        "merge/retiring minter first, successor 22: the survivor",
        &merge,
        retiring_first,
        1,
        "M-37",
        261,
        After::RefusedBy("M-49"),
    );
    probes.twin(
        "merge/retiring minter first, successor 36: the survivor",
        &merge,
        |scenario| {
            retiring_first(scenario);
            minter_out(scenario, 0).remaining = 36;
        },
        1,
        "M-37",
        261,
        After::Passes,
    );
    // Bob's signature at his new place, input 0, is a good one: only the place rule refuses.
    probes.twin(
        "merge/retiring minter first: the retiring minter",
        &merge,
        retiring_first,
        0,
        "M-52",
        312,
        After::Passes,
    );
    probes.twin(
        "merge/three minters, successor 25",
        &merge,
        |scenario| {
            third_minter(scenario);
            minter_out(scenario, 0).remaining = 25;
        },
        0,
        "M-36",
        260,
        After::RefusedBy("M-49"),
    );
    probes.twin(
        "merge/three minters, successor 22",
        &merge,
        third_minter,
        0,
        "M-36",
        260,
        After::Passes,
    );
    for (name, key) in [
        ("merge/signature: the survivor's key", ALICE),
        ("merge/signature: a stranger's key", CAROL),
    ] {
        probes.twin(
            name,
            &merge,
            |scenario| {
                *scenario.contract_input_mut(1).witness_mut() =
                    witness::signature(key, SIG_HASH_ALL)
            },
            1,
            "M-57",
            324,
            After::Passes,
        );
    }
    // The size rule of the argument has no source line; behind it the signature rule waits.
    let mut empty_argument = merge.clone();
    empty_argument
        .contract_input_mut(1)
        .set_patch(|parts| parts.arguments = vec![raw::push(&[]).expect("an empty push")]);
    probes.record(
        "merge/no signature: an empty argument",
        removal(
            Some(&merge),
            &empty_argument,
            1,
            "M-50",
            None,
            &After::RefusedBy("M-57"),
        ),
    );

    // test_lifecycle.MinterLifecycle (in port_seed.rs), with other numbers: a reclaim while
    // an allowance is left.
    probes.twin(
        "lifecycle/minter reclaim/an allowance of 4 is left",
        &reclaim_of(0, 5_000),
        |scenario| minter_in(scenario, 0).remaining = 4,
        0,
        "M-34",
        248,
        After::Passes,
    );

    // A_minter.Split
    probes.twin(
        "split/take 0",
        &split_of(25, 7),
        |scenario| set_take(scenario, 25, 0),
        0,
        "M-26",
        196,
        After::Passes,
    );
    probes.twin(
        "split/take 13 of 25",
        &split_of(25, 12),
        |scenario| set_take(scenario, 25, 13),
        0,
        "M-27",
        197,
        After::Passes,
    );
    probes.twin(
        "split/deposit: retained one sompi less",
        &split_of(25, 7),
        |scenario| scenario.contract_output_mut(0).value = 999,
        0,
        "M-28",
        212,
        After::Passes,
    );
    probes.twin(
        "split/outputs swapped, values 321 and 1000",
        &split_of(25, 7),
        |scenario| scenario.outputs.swap(0, 1),
        0,
        "M-28",
        212,
        After::RefusedBy("M-29"),
    );
    let mut equal_values = split_of(25, 7);
    equal_values.contract_output_mut(1).value = 1_000;
    probes.twin(
        "split/outputs swapped, values 1000 and 1000",
        &equal_values,
        |scenario| scenario.outputs.swap(0, 1),
        0,
        "M-29",
        224,
        After::RefusedBy("M-30"),
    );
    probes.twin(
        "split/retained minter owned by Carol",
        &split_of(25, 7),
        |scenario| minter_out(scenario, 0).owner = keys::x_only(CAROL),
        0,
        "M-29",
        224,
        After::Passes,
    );

    // A_minter.Mint and test_public_mint
    let deposit = deposit_mint(25, 10, 7_000);
    probes.twin(
        "mint/continuation owned by Carol",
        &deposit,
        |scenario| minter_out(scenario, 0).owner = keys::x_only(CAROL),
        0,
        "M-19",
        161,
        After::Passes,
    );
    probes.twin(
        "mint/deposit: continuation one sompi more",
        &deposit,
        |scenario| scenario.contract_output_mut(0).value = 7_001,
        0,
        "M-18",
        149,
        After::Passes,
    );
    let mint = mint_of(25, 10, 10);
    probes.twin(
        "mint/limit: 11 with a limit of 10",
        &mint,
        |scenario| *scenario = mint_of(25, 10, 11),
        0,
        "M-13",
        137,
        After::Passes,
    );
    probes.twin(
        "mint/allowance: 6 of 5",
        &mint_of(5, 10, 5),
        |scenario| *scenario = mint_of(5, 10, 6),
        0,
        "M-14",
        138,
        After::Passes,
    );
    probes.twin(
        "mint/amount 0",
        &mint,
        |scenario| *scenario = mint_of(25, 10, 0),
        0,
        "M-12",
        136,
        After::Passes,
    );
    probes.twin(
        "mint/continuation: 16 after 10 of 25",
        &mint,
        |scenario| minter_out(scenario, 0).remaining = 16,
        0,
        "M-19",
        161,
        After::Passes,
    );
    probes.twin(
        "mint/new coin locked to 1000 tokens, the call names 10",
        &mint,
        |scenario| token_out(scenario, 1).amount = 1_000,
        0,
        "M-21",
        174,
        After::Passes,
    );
    probes.twin(
        "mint/new coin of another family",
        &mint,
        |scenario| change_minted_coin(scenario, |state| state.extension_commitment = OTHER_FAMILY),
        0,
        "M-15",
        139,
        After::Passes,
    );
    // The script handed over is not the token script; the output is. Without the template
    // comparison the output comparison of the same statement refuses.
    probes.twin(
        "mint/token script in the call with one bit flipped",
        &mint,
        |scenario| {
            scenario.contract_input_mut(0).set_patch(|parts| {
                let suffix = parts.arguments.last_mut().expect("the suffix argument");
                *suffix.last_mut().expect("the suffix has bytes") ^= 1;
            })
        },
        0,
        "M-20",
        174,
        After::RefusedBy("M-21"),
    );
    probes.twin(
        "mint/a second token coin",
        &mint,
        |scenario| {
            scenario.push_contract_output(ContractOutput::new(
                Kcc20State::new(keys::x_only(BOB), 1_000),
                shapes::SCRIPT_COIN_VALUE,
                Some(CovenantBinding::new(0, shapes::covenant_id())),
            ));
            scenario.ordinary_input_mut(1).value = 3_000;
        },
        0,
        "M-11",
        130,
        After::Passes,
    );
    probes.twin(
        "mint/token coin of the covenant instead of the funding coin",
        &mint,
        |scenario| {
            scenario.inputs[1] = InputSpec::Contract(token_coin_of_bob(1, shapes::covenant_id()))
        },
        0,
        "M-10",
        127,
        After::Passes,
    );

    // A_minter.SingleInputCounts: the cases without an honest side in the port.
    let mut split_and_minter = split_of(25, 7);
    split_and_minter
        .inputs
        .insert(1, InputSpec::Contract(minter_coin_of_bob(1, 4)));
    probes.alone(
        "single/split: minter coin of the covenant",
        &split_and_minter,
        0,
        "M-24",
        187,
        After::Passes,
    );
    let mut reclaim_and_token = reclaim_of(0, 1_000);
    reclaim_and_token.inputs.insert(
        1,
        InputSpec::Contract(token_coin_of_bob(1, shapes::covenant_id())),
    );
    probes.alone(
        "single/reclaim: token coin of the covenant",
        &reclaim_and_token,
        0,
        "M-32",
        243,
        After::Passes,
    );
    let mut merge_and_token = merge.clone();
    merge_and_token
        .inputs
        .push(InputSpec::Contract(token_coin_of_bob(
            2,
            shapes::covenant_id(),
        )));
    probes.alone(
        "single/merge: token coin of the covenant as third input",
        &merge_and_token,
        0,
        "M-36",
        260,
        After::Passes,
    );

    // test_lifecycle.MinterLifecycle (in port_seed.rs)
    let reclaim = shapes::mint_reclaim(&script());
    probes.twin(
        "lifecycle/minter reclaim/signed by Bob",
        &reclaim,
        |scenario| {
            *scenario.contract_input_mut(0).witness_mut() = witness::signature(BOB, SIG_HASH_ALL)
        },
        0,
        "M-35",
        249,
        After::Passes,
    );
    probes.twin(
        "lifecycle/minter split/the new minter mints 1000000 at a time",
        &shapes::mint_split(&script()),
        |scenario| minter_out(scenario, 1).mint_amount = 1_000_000,
        0,
        "M-30",
        236,
        After::Passes,
    );
    probes.twin(
        "lifecycle/minter merge/18 and 4 make 23",
        &merge,
        |scenario| minter_out(scenario, 0).remaining = 23,
        0,
        "M-49",
        300,
        After::Passes,
    );

    probes.finish(12);
}

// ---------------------------------------------------------------------------------------
// Removal probes: port_seed.rs
// ---------------------------------------------------------------------------------------

#[test]
fn the_seed_refusals_are_made_by_the_rules_the_port_names() {
    let mut probes = Probes::default();
    let honest_create = create(empty_coin());

    // B_seed.Create and test_token_seed
    probes.twin(
        "b_seed/create/recipient amount -1",
        &honest_create,
        |scenario| set_created_coin(scenario, empty_coin().with_amount(-1)),
        0,
        "S-12",
        132,
        After::Passes,
    );
    probes.twin(
        "token_seed/create/amount 2^62",
        &honest_create,
        |scenario| set_created_coin(scenario, empty_coin().with_amount(1 << 62)),
        0,
        "S-12",
        132,
        After::Passes,
    );
    probes.twin(
        "b_seed/create/owner scheme 0x05",
        &create(empty_coin().with_owner(OWNER_COVENANT_ID, keys::x_only(BOB))),
        |scenario| set_created_coin(scenario, empty_coin().with_owner(0x05, keys::x_only(BOB))),
        0,
        "S-14",
        66,
        After::Passes,
    );
    probes.twin(
        "b_seed/create/owner scheme 0xff",
        &create(empty_coin().with_owner(OWNER_COVENANT_ID, keys::x_only(BOB))),
        |scenario| set_created_coin(scenario, empty_coin().with_owner(0xff, keys::x_only(BOB))),
        0,
        "S-14",
        66,
        After::Passes,
    );
    probes.twin(
        "b_seed/create/borrow scheme 0x04",
        &create(empty_coin().with_borrow(BORROW_HASH_CHAIN, [0; 32])),
        |scenario| set_created_coin(scenario, empty_coin().with_borrow(0x04, [0; 32])),
        0,
        "S-15",
        69,
        After::Passes,
    );
    probes.twin(
        "b_seed/create/recipient of another family",
        &honest_create,
        |scenario| set_created_coin(scenario, empty_coin().with_extension(OTHER_FAMILY)),
        0,
        "S-13",
        133,
        After::Passes,
    );
    probes.twin(
        "b_seed/create/seed output value 999",
        &honest_create,
        |scenario| scenario.contract_output_mut(0).value = 999,
        0,
        "S-16",
        136,
        After::Passes,
    );
    probes.twin(
        "b_seed/create/seed output owned by a stranger",
        &honest_create,
        |scenario| seed_output(scenario, 0).owner = keys::x_only(CAROL),
        0,
        "S-17",
        138,
        After::Passes,
    );
    probes.twin(
        "b_seed/create/a second token coin bound to the seed",
        &honest_create,
        |scenario| {
            scenario.push_contract_output(ContractOutput::new(
                Kcc20State::new(keys::x_only(CAROL), 1000),
                shapes::SCRIPT_COIN_VALUE,
                bound_to_leader(),
            ));
        },
        0,
        "S-11",
        126,
        After::Passes,
    );
    probes.twin(
        "token_seed/create/the output holds 1000 tokens, the call names none",
        &honest_create,
        |scenario| scenario.contract_output_mut(1).state = empty_coin().with_amount(1000).into(),
        0,
        "S-19",
        154,
        After::Passes,
    );
    // The three coins of the family beside a create: the seed's own answer.
    for (name, coin) in [
        (
            "b_seed/create/a token coin of the covenant beside the seed",
            token_coin_of_bob(2, shapes::covenant_id()),
        ),
        (
            "b_seed/create/a seed of the covenant beside the seed",
            seed_coin_of_bob(2),
        ),
        (
            "b_seed/create/a minter of the covenant beside the seed",
            minter_coin_of_bob(2, 25),
        ),
    ] {
        probes.twin(
            name,
            &honest_create,
            |scenario| {
                scenario.push_contract_input(coin);
            },
            0,
            "S-10",
            123,
            After::Passes,
        );
    }

    // B_seed.Split and test_lifecycle.SeedLifecycle
    let split = seed_split();
    probes.twin(
        "b_seed/split/retained seed value 1001",
        &split,
        |scenario| scenario.contract_output_mut(0).value = 1001,
        0,
        "S-23",
        181,
        After::Passes,
    );
    probes.twin(
        "b_seed/split/retained seed owned by a stranger",
        &split,
        |scenario| seed_output(scenario, 0).owner = keys::x_only(CAROL),
        0,
        "S-24",
        183,
        After::Passes,
    );
    probes.twin(
        "b_seed/split/added output is a token coin holding 0",
        &split,
        |scenario| {
            scenario.contract_output_mut(1).state = Kcc20State::new(keys::x_only(BOB), 0).into()
        },
        0,
        "S-25",
        196,
        After::Passes,
    );
    probes.twin(
        "lifecycle/seed split/a second seed of another family",
        &split,
        |scenario| seed_output(scenario, 1).extension_commitment = OTHER_FAMILY,
        0,
        "S-25",
        196,
        After::Passes,
    );
    probes.twin(
        "b_seed/split/a seed of the covenant beside the seed",
        &split,
        |scenario| {
            scenario.push_contract_input(seed_coin_of_bob(2));
        },
        0,
        "S-21",
        167,
        After::Passes,
    );

    // B_seed.Reclaim
    let reclaim = seed_reclaim();
    probes.twin(
        "b_seed/reclaim/survivor value 999",
        &reclaim,
        |scenario| scenario.contract_output_mut(0).value = 999,
        0,
        "S-34",
        225,
        After::Passes,
    );
    probes.twin(
        "b_seed/reclaim/survivor value 1001",
        &funded_seed_reclaim(),
        |scenario| scenario.contract_output_mut(0).value = 1001,
        0,
        "S-34",
        225,
        After::Passes,
    );
    probes.twin(
        "b_seed/reclaim/survivor owned by a stranger",
        &reclaim,
        |scenario| seed_output(scenario, 0).owner = keys::x_only(CAROL),
        0,
        "S-35",
        227,
        After::Passes,
    );
    probes.twin(
        "b_seed/reclaim/retiring seed of another family",
        &reclaim,
        |scenario| {
            scenario
                .contract_input_mut(1)
                .state
                .as_token_seed_mut()
                .expect("the retiring seed")
                .extension_commitment = OTHER_FAMILY
        },
        0,
        "S-33",
        224,
        After::Passes,
    );
    probes.twin(
        "b_seed/reclaim/retiring seed signed by the survivor's key",
        &reclaim,
        |scenario| {
            *scenario.contract_input_mut(1).witness_mut() = witness::signature(ALICE, SIG_HASH_ALL)
        },
        1,
        "S-43",
        254,
        After::Passes,
    );
    probes.twin(
        "b_seed/reclaim/retiring seed with 64 zero bytes and hash type 01",
        &reclaim,
        |scenario| {
            let mut signature = vec![0u8; 64];
            signature.push(SIG_HASH_ALL.to_u8());
            *scenario.contract_input_mut(1).witness_mut() = LateBytes::fixed(signature)
        },
        1,
        "S-43",
        254,
        After::Passes,
    );
    // One coin of the covenant where two are asked for: behind the count the engine refuses
    // at line 209 (CovenantsError), or the place rule refuses (line 242).
    probes.twin(
        "b_seed/reclaim/a single seed recreating itself",
        &reclaim,
        |scenario| {
            scenario.inputs.truncate(1);
            scenario.outputs.truncate(1);
        },
        0,
        "S-26",
        207,
        After::RefusedBy("engine: CovenantsError"),
    );
    probes.twin(
        "b_seed/reclaim/survivor removed, the retiring seed runs reclaim_delegator",
        &funded_seed_reclaim(),
        |scenario| {
            scenario.inputs.remove(0);
        },
        0,
        "S-37",
        241,
        After::RefusedBy("S-38"),
    );
    probes.twin(
        "b_seed/reclaim/survivor removed, the retiring seed runs reclaim",
        &funded_seed_reclaim(),
        |scenario| {
            scenario.inputs.remove(0);
            scenario.contract_input_mut(0).call = Call::typed(Entry::SeedReclaim, Vec::new());
        },
        0,
        "S-26",
        207,
        After::RefusedBy("engine: CovenantsError"),
    );
    probes.twin(
        "b_seed/reclaim/a lone seed, its owner signs and takes the deposit",
        &reclaim,
        |scenario| {
            scenario.inputs.remove(0);
            scenario.outputs.remove(0);
        },
        0,
        "S-37",
        241,
        After::RefusedBy("S-38"),
    );
    probes.twin(
        "lifecycle/seed reclaim/a lone seed runs reclaim_delegator, its owner signs",
        &reclaim,
        |scenario| {
            scenario.inputs.truncate(1);
            scenario.outputs = vec![OutputSpec::Plain(pay_to(ALICE, shapes::SCRIPT_COIN_VALUE))];
            scenario.contract_input_mut(0).call = Call::typed(
                Entry::SeedReclaimDelegator,
                vec![Arg::Bytes(witness::signature(ALICE, SIG_HASH_ALL))],
            );
        },
        0,
        "S-37",
        241,
        After::RefusedBy("S-38"),
    );

    // B_seed.CreatorChoosesOwnerAndPolicy: the token contract refuses.
    probes.twin(
        "b_seed/policy/a stranger cannot add to a coin with borrowing off",
        &pay_into(empty_coin().with_threshold(0), CAROL, 1),
        |scenario| *scenario = pay_into(empty_coin(), CAROL, 1),
        0,
        "K-50",
        184,
        After::Passes,
    );

    // A coin the earlier checks carried along without running it.
    let mut beside_another_covenant = honest_create.clone();
    beside_another_covenant
        .push_contract_input(token_coin_of_bob(2, Hash::from_bytes(OTHER_COVENANT)));
    probes.alone(
        "b_seed/create/a token coin of another covenant beside the seed: that coin",
        &beside_another_covenant,
        2,
        "K-68",
        254,
        After::RefusedBy("K-69"),
    );

    probes.finish(12);
}

// ---------------------------------------------------------------------------------------
// The signatures of the reclaim flows
// ---------------------------------------------------------------------------------------

/// The 65-byte signature the retiring input of `scenario` carries once assembled: the first
/// push of its signature script.
fn assembled_signature(scenario: &Scenario, input: usize) -> Vec<u8> {
    let assembled = scenario
        .assemble(Family::pinned())
        .expect("the scenario assembles");
    let script = &assembled.tx.inputs[input].signature_script;
    assert_eq!(script[0], 65, "the first push holds 65 bytes");
    script[1..66].to_vec()
}

#[test]
fn a_signature_of_the_wrong_key_is_a_valid_signature_of_that_key() {
    // The ports say of these refusals: a valid signature over this transaction by a key
    // that is not the owner's. Give the coin to the signing key and the same signature
    // call passes; so the refusal was about the key, not about the signed bytes.
    let mut merge = merge();
    *merge.contract_input_mut(1).witness_mut() = witness::signature(ALICE, SIG_HASH_ALL);
    assert!(!judged(&run(&merge), 1).ok, "Alice signs for Bob's minter");
    minter_in(&mut merge, 1).owner = keys::x_only(ALICE);
    judge_accept(&run(&merge)).expect("the retiring minter is Alice's and Alice signs");

    let mut reclaim = seed_reclaim();
    *reclaim.contract_input_mut(1).witness_mut() = witness::signature(ALICE, SIG_HASH_ALL);
    assert!(!judged(&run(&reclaim), 1).ok, "Alice signs for Bob's seed");
    reclaim
        .contract_input_mut(1)
        .state
        .as_token_seed_mut()
        .expect("the retiring seed")
        .owner = keys::x_only(ALICE);
    judge_accept(&run(&reclaim)).expect("the retiring seed is Alice's and Alice signs");

    let mut close = shapes::mint_reclaim(&script());
    *close.contract_input_mut(0).witness_mut() = witness::signature(BOB, SIG_HASH_ALL);
    assert!(!judged(&run(&close), 0).ok, "Bob signs for Alice's minter");
    minter_in(&mut close, 0).owner = keys::x_only(BOB);
    judge_accept(&run(&close)).expect("the minter is Bob's and Bob signs");
}

#[test]
fn a_signature_made_before_the_change_is_refused_by_the_signature_rule() {
    // The twins of the ports sign after the change. A signature made before it is refused
    // by the signature rule of the retiring coin; had a port carried such a signature, its
    // case would have named that rule and not the rule under test.
    let merge = merge();
    let stale = assembled_signature(&merge, 1);
    let mut funded = merge.clone();
    funded.push_ordinary_input(funding_coin());
    judge_accept(&run(&funded)).expect("signed after the funding coin was added");
    *funded.contract_input_mut(1).witness_mut() = LateBytes::fixed(stale);
    let outcome = run(&funded);
    let retiring = judged(&outcome, 1);
    assert_eq!(retiring.rule(), Some("M-57"), "{}", retiring.describe());
    assert_eq!(retiring.sil_line(), Some(324));
    assert!(judged(&outcome, 0).ok, "the survivor asks for no signature");

    let reclaim = seed_reclaim();
    let stale = assembled_signature(&reclaim, 1);
    let mut funded = funded_seed_reclaim();
    judge_accept(&run(&funded)).expect("signed after the funding coin was added");
    *funded.contract_input_mut(1).witness_mut() = LateBytes::fixed(stale);
    let outcome = run(&funded);
    let retiring = judged(&outcome, 1);
    assert_eq!(retiring.rule(), Some("S-43"), "{}", retiring.describe());
    assert_eq!(retiring.sil_line(), Some(254));
}

// ---------------------------------------------------------------------------------------
// Whole transactions
// ---------------------------------------------------------------------------------------

#[test]
fn the_chained_spend_names_the_mint_the_harness_ran() {
    // `port_minter.rs` spends output 1 of the mint by the id of the mint as the scenario
    // assembles it. The harness commits budgets before it runs a transaction; this holds
    // the two ids against each other.
    let mint = mint_of(25, 10, 10);
    let assembled = mint
        .assemble(Family::pinned())
        .expect("the honest mint assembles");
    let outcome = run(&mint);
    println!(
        "the mint: assembled id {}, id of the transaction the harness ran {} (recorded {})",
        assembled.tx.id(),
        outcome.committed_tx.id(),
        outcome.tx_id
    );
    assert_eq!(
        assembled.tx.id(),
        outcome.committed_tx.id(),
        "the transfer of the port spends an outpoint of another transaction id"
    );
}

/// [`mint_of`] in the coin values of `profile`.
fn mint_in(profile: &Profile, remaining: i64, limit: i64, amount: i64) -> Scenario {
    let mut scenario = shapes::mint(profile);
    let minter = minter_in(&mut scenario, 0);
    minter.remaining = remaining;
    minter.mint_amount = limit;
    let continuation = minter_out(&mut scenario, 0);
    continuation.remaining = remaining - amount;
    continuation.mint_amount = limit;
    change_minted_coin(&mut scenario, |state| state.amount = amount);
    scenario
}

#[test]
fn the_accepted_mints_in_coin_values_a_node_takes() {
    // The accepted mints of `port_minter.rs` in 10 KAS coins with a signed funding coin,
    // change and a fee of 0.05 KAS: a block and a default mempool take each of them. (The
    // port has a section `realistic/..` of its own, with the six variants below and more,
    // each paying exactly the mempool's fee floor.)
    let realistic = Profile::Realistic(Realistic {
        fee: shapes::SOMPI_PER_KAS / 20,
        ..Realistic::default()
    });
    let bob = keys::x_only(BOB);
    let mut with_threshold = mint_in(&realistic, 25, 10, 10);
    change_minted_coin(&mut with_threshold, |state| {
        *state = Kcc20State::new(bob, 10).with_threshold(3)
    });
    let mut to_key_hash = mint_in(&realistic, 25, 10, 10);
    change_minted_coin(&mut to_key_hash, |state| {
        *state =
            Kcc20State::new(bob, 10).with_owner(OWNER_P2PKH_SCHNORR, witness::public_key_hash(&bob))
    });
    for (name, scenario) in [
        ("10 of 25, limit 10", mint_in(&realistic, 25, 10, 10)),
        ("3 of 25, limit 10", mint_in(&realistic, 25, 10, 3)),
        ("5 of 5, limit 10", mint_in(&realistic, 5, 10, 5)),
        (
            "2^62 of 2^62, limit 2^62",
            mint_in(&realistic, 1 << 62, 1 << 62, 1 << 62),
        ),
        ("a new coin with a borrow threshold of 3", with_threshold),
        ("a new coin owned by the hash of a key", to_key_hash),
    ] {
        let outcome = run(&scenario);
        judge_accept(&outcome).unwrap_or_else(|failure| panic!("mint {name}: {failure}"));
        assert!(
            outcome.consensus.block.accepted,
            "mint {name}: a block refuses it: {:?}",
            outcome.consensus.block.refusal
        );
        assert!(
            outcome.mempool.accepted,
            "mint {name}: the mempool refuses it: {:?}",
            outcome.mempool.first_refusal
        );
    }
}

#[test]
fn a_token_coin_of_another_covenant_beside_a_leader_can_be_a_transaction_a_node_runs() {
    // The control of the earlier checks of the count rules is the same token coin outside
    // the covenant beside the leader. The ports record that control as a refused
    // transaction: `port_seed.rs` gives the coin of another covenant the joining entry,
    // which cannot pass alone in its covenant; `port_minter.rs` leaves the coin without a
    // covenant and without a call. With the entry a lone coin of a covenant runs
    // (`transfer`, signed by its owner, into an output of its own covenant) the control is
    // a transaction whose scripts all pass and whose amounts a node accepts; the same coin
    // and output under the covenant id of the leader is refused by the count rule.
    // (Both ports run this pair as the control of their count-rule checks: the lines
    // `.. control, a token coin under another covenant id` and `.. joined, the same token
    // coin under the .. covenant id`. The lines described above stand in the ports as the
    // earlier control run as written.)
    let other = Hash::from_bytes(OTHER_COVENANT);
    let transfer = shapes::transfer(&script(), 1, 1);
    for (name, leader, rule, line) in [
        ("seed create", create(empty_coin()), "S-10", 123),
        ("seed split", seed_split(), "S-21", 167),
        ("minter split", split_of(25, 7), "M-24", 187),
        ("minter reclaim", reclaim_of(0, 1_000), "M-32", 243),
        ("minter mint", deposit_mint(25, 10, 7_000), "M-10", 127),
        ("minter merge", merge(), "M-36", 260),
    ] {
        let beside = |covenant: Hash| {
            let mut scenario = leader.clone();
            let input = scenario.inputs.len();
            let output = scenario.outputs.len();
            scenario.inputs.push(transfer.inputs[0].clone());
            scenario.outputs.push(transfer.outputs[0].clone());
            let coin = scenario.contract_input_mut(input);
            coin.covenant_id = Some(covenant);
            coin.outpoint = shapes::outpoint(1, 2);
            scenario.contract_output_mut(output).binding = Some(CovenantBinding::new(
                input.try_into().expect("a small input index"),
                covenant,
            ));
            (scenario, input)
        };

        let (control, coin) = beside(other);
        let control = run(&control);
        judge_accept(&control)
            .unwrap_or_else(|failure| panic!("{name}: the control is refused: {failure}"));
        assert!(
            control.consensus.accepted,
            "{name}: {:?}",
            control.consensus.refusal
        );
        assert_eq!(control.inputs[coin].entry.as_deref(), Some("transfer"));

        let (joined, _) = beside(shapes::covenant_id());
        let joined = run(&joined);
        assert!(
            joined.consensus.context_accepted,
            "{name}: a node gets to the scripts"
        );
        let refused = judged(&joined, 0);
        assert_eq!(refused.rule(), Some(rule), "{name}: {}", refused.describe());
        assert_eq!(refused.sil_line(), Some(line), "{name}");
    }
}

// ---------------------------------------------------------------------------------------
// The lifecycle chains
// ---------------------------------------------------------------------------------------

/// Script, value and covenant of the coin output `output` of `scenario` creates.
fn created(scenario: &Scenario, output: usize) -> (Vec<u8>, u64, Option<Hash>) {
    let assembled = scenario
        .assemble(Family::pinned())
        .expect("the scenario assembles");
    let coin = &assembled.tx.outputs[output];
    (
        coin.script_public_key.script().to_vec(),
        coin.value,
        coin.covenant.map(|binding| binding.covenant_id),
    )
}

/// Script, value and covenant of the coin input `input` of `scenario` spends.
fn spent(scenario: &Scenario, input: usize) -> (Vec<u8>, u64, Option<Hash>) {
    let assembled = scenario
        .assemble(Family::pinned())
        .expect("the scenario assembles");
    let coin = &assembled.utxos[input];
    (
        coin.script_public_key.script().to_vec(),
        coin.amount,
        coin.covenant_id,
    )
}

fn owner_spends(coin: Kcc20State, owner: u8, to: u8) -> Scenario {
    let mut scenario = shapes::transfer(&script(), 1, 1);
    let next = Kcc20State::new(keys::x_only(to), coin.amount);
    let input = scenario.contract_input_mut(0);
    input.state = coin.into();
    *input.declared_states_mut() = vec![next.clone()];
    *input.witness_mut() = witness::owner_key(owner, EntryRole::Leader, SIG_HASH_ALL);
    scenario.contract_output_mut(0).state = next.into();
    scenario
}

#[test]
fn the_steps_of_the_lifecycle_chains_link_by_their_coins() {
    // The ports run the steps of a lifecycle as separate transactions with given coins, as
    // the earlier checks did. A chain it is only if the coin a step spends is the coin the
    // step before it creates: same script, same value, same covenant.
    // port_seed.rs, "life of a coin" and "policy": the created coin is paid into, then
    // spent by its owner.
    let open = empty_coin().with_threshold(0);
    let creation = create(open.clone());
    let payment = pay_into(open.clone(), ALICE, 30);
    let spend = owner_spends(open.clone().with_amount(30), BOB, ALICE);
    assert_eq!(
        created(&creation, 1),
        spent(&payment, 0),
        "the payment goes into the created coin"
    );
    assert_eq!(
        created(&payment, 0),
        spent(&spend, 0),
        "the owner spends the coin that was paid into"
    );
    assert_eq!(
        created(&creation, 1),
        spent(&pay_into(open, CAROL, 1), 0),
        "the stranger adds to the created coin"
    );
}
