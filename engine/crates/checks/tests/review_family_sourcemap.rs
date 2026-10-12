//! What the source map takes from the compiler's debug information.
//!
//! The lines the test harness of `crates/checks` reports come from the statement steps of
//! the SilverScript debug information: a byte range and a source span per statement. Those
//! are held against the rule inventory here for every refusing opcode, by the exact first
//! line. Only line numbers are compared here.
//!
//! The innermost statement of a byte is the one with the narrowest range, and a map in
//! which two statements share a range is refused when it is built. The call depth and the
//! markers of inlined calls that the debug information also carries are copied and decide
//! nothing.

use std::collections::BTreeMap;

use kcc20_family::{Contract, SourceMap, sourcemap::StepKind};

/// The first line of a line reference of the inventory: `129`, `136-141`, or the line
/// inside the called function of `170 -> 58`.
fn first_line(reference: &str) -> u32 {
    let own = reference.rsplit("->").next().unwrap_or(reference).trim();
    own.split('-')
        .next()
        .and_then(|line| line.trim().parse().ok())
        .unwrap_or_else(|| panic!("no line in `{reference}`"))
}

#[test]
fn every_refusing_opcode_has_the_first_line_the_inventory_names() {
    // Two rules are filed under another line than the statement starts at; an earlier
    // suite of checks, not published here, asserted the line of the statement for both.
    //
    // - K-61: the inventory names lines 218-219 (the subtraction and the comparison); the
    //   refusing opcode belongs to the `require` of line 219.
    // - M-47: the inventory names line 283 (the field with the addition); the statement, a
    //   state literal, starts at line 281.
    let known = BTreeMap::from([("K-61", 219), ("M-47", 281)]);

    let mut compared = 0;
    let mut without_line = 0;
    for contract in Contract::ALL {
        let map = SourceMap::pinned().contract(contract);
        for rule in map.rules() {
            for offset in &rule.offsets {
                let statement = map.line_at(*offset).map(|line| line.line);
                match &rule.sil_line {
                    None => {
                        assert_eq!(statement, None, "{} at byte {offset}", rule.id);
                        without_line += 1;
                    }
                    Some(reference) => {
                        let expected = known
                            .get(rule.id.as_str())
                            .copied()
                            .unwrap_or_else(|| first_line(reference));
                        assert_eq!(
                            statement,
                            Some(expected),
                            "{} at byte {offset}: the inventory names `{reference}`",
                            rule.id
                        );
                        compared += 1;
                    }
                }
            }
        }
    }
    // 201 refusing opcodes: 38 of the dispatchers and the argument size checks have no line.
    assert_eq!((compared, without_line), (163, 38));
}

#[test]
fn no_two_statements_share_a_byte_range() {
    // `ContractMap::step_at` picks the narrowest statement. Two statements with the same
    // range would make that a guess; `SourceMap::build` refuses such a map, so the pinned
    // one has none.
    for contract in Contract::ALL {
        let map = SourceMap::pinned().contract(contract);
        let mut ranges: BTreeMap<(usize, usize), Vec<u32>> = BTreeMap::new();
        for step in map.steps() {
            if step.kind == StepKind::Statement && step.start < step.end {
                ranges
                    .entry((step.start, step.end))
                    .or_default()
                    .push(step.line);
            }
        }
        let ties: Vec<_> = ranges.iter().filter(|(_, lines)| lines.len() > 1).collect();
        assert!(ties.is_empty(), "{contract}: {ties:?}");
    }
}
