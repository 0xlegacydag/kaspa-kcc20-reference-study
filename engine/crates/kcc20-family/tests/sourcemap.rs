//! The source map: opcode offsets, source lines from the compiler, rules from the inventory.
//!
//! Two independent descriptions of the same scripts meet here. The rule inventory names the
//! refusing opcodes of every rule and, where the rule has a place in the generated source, its
//! lines; the lines of the source map come from the SilverScript compiler's own debug
//! information. Where they name the same opcode they must name the same line.
//!
//! No line of the reference's sources is written in this file: where a test needs the text of
//! a line, it reads the line from the checkout of the reference.

use std::collections::BTreeMap;

use kcc20_family::sourcemap::{
    Place, SourceMap, disassemble, last_redeem_opcode_index, load_rule_inventory,
    rule_inventory_path,
};
use kcc20_family::{Contract, Family, refdata};

/// The lines `first..=last` of a contract's generated source as the checkout of the reference
/// holds them, each one trimmed, joined by one space: the form of a statement text in the
/// source map.
fn checkout_lines(contract: Contract, first: usize, last: usize) -> String {
    let text = refdata::pinned_sil_source(contract)
        .lines()
        .skip(first - 1)
        .take(last + 1 - first)
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        !text.is_empty(),
        "{contract}: no text in lines {first}-{last} of the source"
    );
    text
}

/// Whether `line` lies in a line reference of the inventory: `129`, `136-141`, or
/// `170 -> 58` (a call site and the line inside the called function).
fn inventory_names_line(reference: &str, first_line: u32, last_line: u32) -> bool {
    reference.split("->").map(str::trim).any(|part| {
        let mut bounds = part
            .split('-')
            .map(|bound| bound.trim().parse::<u32>().expect("a line number"));
        let from = bounds.next().expect("a line number");
        let to = bounds.next().unwrap_or(from);
        // The statement of the map and the lines of the inventory overlap.
        from <= last_line && first_line <= to
    })
}

#[test]
fn the_rule_inventory_holds_173_rules() {
    assert!(
        rule_inventory_path().ends_with("data/rule-inventory.json")
            || rule_inventory_path().ends_with("data\\rule-inventory.json")
    );
    let rules = load_rule_inventory().expect("the rule inventory is readable");
    assert_eq!(rules.len(), 173);
    let mut per_contract: BTreeMap<Contract, usize> = BTreeMap::new();
    for rule in &rules {
        *per_contract.entry(rule.contract).or_default() += 1;
        assert!(
            rule.id.starts_with(rule.contract.rule_prefix()),
            "{} belongs to {}",
            rule.id,
            rule.contract
        );
    }
    assert_eq!(per_contract[&Contract::Kcc20], 73);
    assert_eq!(per_contract[&Contract::PublicMint], 57);
    assert_eq!(per_contract[&Contract::TokenSeed], 43);
}

#[test]
fn the_disassembly_covers_every_byte_of_the_three_scripts() {
    let family = Family::pinned();
    let map = SourceMap::pinned();
    for (contract, opcode_count) in [
        (Contract::Kcc20, 3299),
        (Contract::PublicMint, 1612),
        (Contract::TokenSeed, 1049),
    ] {
        let contract_map = map.contract(contract);
        assert_eq!(contract_map.bytecode(), family.bytecode(contract));
        let opcodes = contract_map.opcodes();
        assert_eq!(opcodes.len(), opcode_count, "{contract}: number of opcodes");
        let mut offset = 0;
        for (index, opcode) in opcodes.iter().enumerate() {
            assert_eq!(opcode.index, index);
            assert_eq!(opcode.offset, offset, "{contract}: opcodes are contiguous");
            assert_eq!(opcode.code, family.bytecode(contract)[offset]);
            assert_eq!(contract_map.opcode_at(offset), Some(opcode));
            assert_eq!(
                contract_map.opcode_at(offset + opcode.len - 1),
                Some(opcode),
                "a data byte belongs to its push"
            );
            assert_eq!(contract_map.opcode_by_index(index), Some(opcode));
            offset += opcode.len;
        }
        assert_eq!(offset, family.bytecode(contract).len());
        assert_eq!(contract_map.opcode_at(offset), None);
        // A materialized redeem script has the same opcode boundaries as the template.
        assert_eq!(
            disassemble(family.bytecode(contract)).expect("the script parses"),
            opcodes
        );
    }
}

#[test]
fn every_rule_offset_holds_the_opcode_the_inventory_names() {
    let map = SourceMap::pinned();
    let mut offsets = 0;
    for contract in Contract::ALL {
        let contract_map = map.contract(contract);
        for rule in contract_map.rules() {
            // The inventory gives the ordinal of every refusing opcode next to its offset.
            let mut ordinals: Vec<u64> = rule.record["op_index"]
                .as_array()
                .expect("op_index")
                .iter()
                .map(|value| value.as_u64().expect("an ordinal"))
                .collect();
            for reach in rule.record["also_reached_from"]
                .as_array()
                .expect("also_reached_from")
            {
                ordinals.extend(
                    reach["op_index"]
                        .as_array()
                        .expect("op_index")
                        .iter()
                        .map(|value| value.as_u64().expect("an ordinal")),
                );
            }
            assert_eq!(ordinals.len(), rule.offsets.len(), "{}", rule.id);
            for (offset, ordinal) in rule.offsets.iter().zip(ordinals) {
                let opcode = contract_map
                    .opcode_at(*offset)
                    .unwrap_or_else(|| panic!("{}: no opcode at byte {offset}", rule.id));
                assert_eq!(
                    opcode.offset, *offset,
                    "{}: byte {offset} is the first byte of an opcode",
                    rule.id
                );
                assert_eq!(
                    opcode.index as u64, ordinal,
                    "{} at byte {offset}: ordinal",
                    rule.id
                );
                assert_eq!(
                    Some(&opcode.name),
                    rule.check_opcode.as_ref(),
                    "{} at byte {offset}",
                    rule.id
                );
                assert_eq!(
                    contract_map.rule_at(*offset).map(|found| found.id.as_str()),
                    Some(rule.id.as_str())
                );
                offsets += 1;
            }
        }
    }
    assert_eq!(
        offsets, 201,
        "refusing opcodes named by the inventory, over all entries that reach them"
    );
}

#[test]
fn compiler_lines_agree_with_the_inventory_lines() {
    // For every refusing opcode: the statement the compiler recorded for it overlaps the
    // lines the inventory gives. Rules without a source line (the argument size checks and
    // the dispatcher, which the compiler adds on its own) must have no statement at all.
    let map = SourceMap::pinned();
    let (mut with_line, mut without_line) = (0, 0);
    for contract in Contract::ALL {
        let contract_map = map.contract(contract);
        for rule in contract_map.rules() {
            for offset in &rule.offsets {
                let line = contract_map.line_at(*offset);
                match (&rule.sil_line, line) {
                    (Some(reference), Some(line)) => {
                        assert!(
                            inventory_names_line(reference, line.line, line.end_line),
                            "{} at byte {offset}: inventory {reference}, compiler {}-{}: {}",
                            rule.id,
                            line.line,
                            line.end_line,
                            line.text
                        );
                        with_line += 1;
                    }
                    (None, None) => without_line += 1,
                    (reference, line) => panic!(
                        "{} at byte {offset}: inventory line {reference:?}, compiler line {line:?}",
                        rule.id
                    ),
                }
            }
        }
    }
    // 38 = the dispatcher and the argument size checks of the three contracts (14 + 13 + 11).
    assert_eq!((with_line, without_line), (163, 38));
}

#[test]
fn every_statement_step_points_into_the_source() {
    let map = SourceMap::pinned();
    for contract in Contract::ALL {
        let contract_map = map.contract(contract);
        let line_count = contract_map.source().lines().count() as u32;
        assert!(!contract_map.steps().is_empty());
        for step in contract_map.steps() {
            assert!(step.start <= step.end && step.end <= contract_map.bytecode().len());
            assert!(
                1 <= step.line && step.line <= step.end_line && step.end_line <= line_count,
                "{contract}: {step:?}"
            );
            if step.start < step.end {
                assert!(
                    contract_map.entry_at(step.start).is_some(),
                    "{contract}: a statement lies inside an entry: {step:?}"
                );
            }
        }
    }
}

#[test]
fn entries_lie_behind_their_dispatch_tags() {
    // In front of every entry the dispatcher compares the tag: OpDup, push of the four tag
    // bytes, OpEqual, OpIf, OpDrop. The entry range of the compiler starts right behind it.
    let family = Family::pinned();
    let map = SourceMap::pinned();
    let mut entries = 0;
    for contract in Contract::ALL {
        let contract_map = map.contract(contract);
        let bytecode = contract_map.bytecode();
        for entry in contract_map.entries() {
            let abi = family
                .contract_abi(contract)
                .entry(&entry.name)
                .unwrap_or_else(|| panic!("{contract} has an entry `{}`", entry.name));
            let tag = abi.dispatch_tag.into_bytes();
            let mut selector = vec![0x76, 0x04];
            selector.extend(tag);
            selector.extend([0x87, 0x63, 0x75]);
            assert_eq!(
                bytecode[entry.start - selector.len()..entry.start],
                selector[..],
                "{contract}.{}",
                entry.name
            );
            assert!(matches!(
                contract_map.place_at(entry.start - 1),
                Place::Dispatcher
            ));
            entries += 1;
        }
    }
    assert_eq!(entries, 11);
}

#[test]
fn places_tell_the_parts_of_a_script_apart() {
    let map = SourceMap::pinned();
    let kcc20 = map.contract(Contract::Kcc20);
    // Byte 0 is OpToAltStack, bytes 1..146 the state.
    assert_eq!(kcc20.place_at(0), Place::Frame);
    assert_eq!(kcc20.place_at(145), Place::Frame);
    assert_eq!(kcc20.place_at(146), Place::Dispatcher);
    // K-01: OpReturn at the end of the dispatcher.
    assert_eq!(kcc20.place_at(4028), Place::Dispatcher);
    // K-03: an argument size check in front of the first statement of transfer.
    assert_eq!(kcc20.place_at(171), Place::Prologue { entry: "transfer" });
    // K-37: the sum rule, a statement of its own.
    match kcc20.place_at(2203) {
        Place::Statement { entry, line } => {
            assert_eq!(entry, "transfer");
            assert_eq!((line.line, line.end_line), (175, 175));
            assert_eq!(line.text, checkout_lines(Contract::Kcc20, 175, 175));
        }
        other => panic!("unexpected place {other:?}"),
    }
    // K-38 in transfer_delegator: the same source lines, inside the inlined owner check.
    match kcc20.place_at(3837) {
        Place::Statement { entry, line } => {
            assert_eq!(entry, "transfer_delegator");
            // Lines 69-72 are in the helper function, not in the entry: the line reported is
            // the line of the innermost statement, wherever it was inlined from.
            assert_eq!((line.line, line.end_line), (69, 72));
            assert_eq!(line.text, checkout_lines(Contract::Kcc20, 69, 72));
        }
        other => panic!("unexpected place {other:?}"),
    }
    // The OpElse right behind it is branch glue, after that statement.
    match kcc20.place_at(3838) {
        Place::Glue { entry, after } => {
            assert_eq!(entry, "transfer_delegator");
            assert_eq!((after.line, after.end_line), (69, 72));
        }
        other => panic!("unexpected place {other:?}"),
    }
    // The last opcode of an entry (OpTrue) is its clean-up.
    assert_eq!(
        kcc20.place_at(4026),
        Place::Epilogue {
            entry: "transfer_delegator"
        }
    );

    let mint = map.contract(Contract::PublicMint);
    // M-13: the per-mint limit.
    match mint.place_at(245) {
        Place::Statement { entry, line } => {
            assert_eq!(entry, "mint");
            assert_eq!(line.line, 137);
            assert_eq!(line.text, checkout_lines(Contract::PublicMint, 137, 137));
        }
        other => panic!("unexpected place {other:?}"),
    }
    assert_eq!(map.rule("M-13").expect("M-13").offsets, [245]);
    assert_eq!(map.rule("K-38").expect("K-38").offsets, [2249, 3837]);
    assert!(map.rule("X-01").is_none());
}

#[test]
fn a_byte_is_described_in_one_line() {
    let map = SourceMap::pinned();
    let kcc20 = map.contract(Contract::Kcc20);
    let statement = format!("line 175: {}", checkout_lines(Contract::Kcc20, 175, 175));
    assert_eq!(
        kcc20.describe(2203),
        [
            "KCC20 byte 2203",
            "opcode #1717 OpVerify",
            "transfer",
            statement.as_str(),
            "rule K-37"
        ]
        .join(" | ")
    );
    assert_eq!(
        kcc20.describe(171),
        "KCC20 byte 171 | opcode #29 OpNumEqualVerify | transfer | argument size checks | rule K-03"
    );
    assert_eq!(
        kcc20.describe(4028),
        "KCC20 byte 4028 | opcode #3296 OpReturn | dispatcher | rule K-01"
    );
    assert_eq!(
        kcc20.describe(0),
        "KCC20 byte 0 | opcode #0 OpToAltStack | state frame"
    );
    assert_eq!(kcc20.describe(4031), "KCC20 byte 4031 | outside the script");
    // Glue and clean-up name the statement they follow or the entry they close.
    assert_eq!(
        kcc20.describe(4026),
        "KCC20 byte 4026 | opcode #3294 OpTrue | transfer_delegator | clean-up"
    );
}

#[test]
fn the_opcode_log_formula_counts_the_coin_script() {
    // 9 pushes in the signature script, 3 opcodes of the coin script, and the log ends on the
    // opcode with ordinal 1717 of the redeem script: 9 + 3 + 1717 + 1 lines.
    assert_eq!(last_redeem_opcode_index(1730, 9), Some(1717));
    assert_eq!(last_redeem_opcode_index(13, 9), Some(0));
    assert_eq!(
        last_redeem_opcode_index(12, 9),
        None,
        "the log ended in the coin script"
    );
}
