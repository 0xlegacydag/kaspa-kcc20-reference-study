//! The ids of checks of an earlier suite that a case of this crate may name.
//!
//! That suite was written in Python for the debug engine of the Kaspa Python SDK and is
//! not published here: its ids are labels. A case may name the checks it repeats
//! ([`crate::Case::py`]);
//! the ids end up in the result files, where a comparison of result files is keyed by
//! them. A misspelt id would drop or misfile a case without any sign, so the ids are held
//! against a list, `data/python-check-ids.txt` in this crate. The list holds the ids a
//! case of this crate may name; it is not a list of every check of that suite.

use std::collections::BTreeSet;
use std::sync::OnceLock;

/// The list as it is in the crate: one id per line; lines starting with `#` are comments.
const LIST: &str = include_str!("../data/python-check-ids.txt");

/// Every id of the list.
pub fn all() -> &'static BTreeSet<&'static str> {
    static IDS: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    IDS.get_or_init(|| {
        LIST.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect()
    })
}

/// Whether `id` is in the list, letter for letter.
pub fn is_known(id: &str) -> bool {
    all().contains(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_holds_distinct_well_formed_ids() {
        let lines: Vec<&str> = LIST
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        assert_eq!(lines.len(), 185);
        assert_eq!(all().len(), 185, "no id is listed twice");
        // Three or four parts joined by dots; the last one starts with `test_`.
        for id in all() {
            let parts: Vec<&str> = id.split('.').collect();
            assert!(
                (3..=4).contains(&parts.len()) && parts.iter().all(|part| !part.is_empty()),
                "{id}"
            );
            assert!(parts.last().unwrap().starts_with("test_"), "{id}");
        }
    }

    #[test]
    fn an_id_is_known_only_letter_for_letter() {
        let id = "test_transfer.Conservation.test_one_output_holding_more_is_refused";
        assert!(is_known(id));
        assert!(!is_known(
            "test_transfer.Conservation.test_one_output_holding_more_is_refused "
        ));
        assert!(!is_known(
            "test_transfer.Conservation.test_one_output_holding_more_refused"
        ));
        assert!(!is_known(""));
    }
}
