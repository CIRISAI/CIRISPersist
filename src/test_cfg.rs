//! v54.1.0 (CIRISPersist#1026) — **one answer to "is this attribute line
//! test-only?" for the text strippers that remain.**
//!
//! Six from-disk gates cut test code out of a file by text before they scan
//! (docs/FROM_DISK_GATES.md, "Hand-written test-code strippers"). Each spelled
//! its own test for the attribute that starts a test-only item, and most knew
//! only `#[cfg(test)]`: v54.0.0's I14 false red was a `#[cfg(all(test, …))]`
//! module read as production. A stripper that misses a test-only form reads
//! test code as production, which is a false red for a gate that refuses a
//! call, and a FALSE GREEN for one that requires a non-test caller
//! (`supersets.rs::every_cited_processor_has_a_non_test_caller`).
//!
//! The vocabulary is `utils/test-gated.yml`'s, the ast-grep util the ported
//! rules use; `rules/cfg-test-forms.yml` refuses any other spelling of a
//! test-only cfg in the tree, and a recognised one split over lines, so a
//! line-at-a-time reader sees every test-only attribute there is.

/// Whether `line` starts (leading whitespace ignored) with a cfg attribute
/// that holds only in a test build: `#[cfg(test)]` or `#[cfg(all(test, …))]`.
/// The item may follow on the same line. `any(test, …)`, `not(test)` and
/// `all(any(test, …), …)` hold in production builds and are not test-only
/// here; a stripper that also drops those (the `test-anchor` seams) says so at
/// its call site.
pub(crate) fn is_test_only_cfg(line: &str) -> bool {
    let t = line.trim_start();
    if !t.starts_with("#[") {
        return false;
    }
    // The first attribute: up to the `]` that closes `#[`.
    let mut depth = 0i32;
    let mut end = None;
    for (i, c) in t.char_indices() {
        match c {
            '[' | '(' => depth += 1,
            ']' | ')' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(end) = end else { return false };
    let attr: String = t[..=end].chars().filter(|c| !c.is_whitespace()).collect();
    attr == "#[cfg(test)]" || attr.starts_with("#[cfg(all(test,")
}

#[test]
fn i693_the_test_only_cfg_vocabulary() {
    for yes in [
        "#[cfg(test)]",
        "    #[cfg(test)]",
        "#[cfg(all(test, feature = \"sqlite\"))]",
        "#[cfg(all(test, any(feature = \"sqlite\", feature = \"postgres\")))]",
        "#[cfg( all( test , feature = \"x\" ) )]",
        "#[cfg(test)] mod t { fn f() {} }",
    ] {
        assert!(is_test_only_cfg(yes), "I693 {yes} is test-only");
    }
    for no in [
        "#[cfg(any(test, feature = \"test-anchor\"))]",
        "#[cfg(not(test))]",
        "#[cfg(feature = \"test-anchor\")]",
        "#[cfg(all(any(test, feature = \"test-anchor\"), feature = \"sqlite\"))]",
        "#[cfg(all(feature = \"x\", test))]",
        "// #[cfg(test)]",
        "#[cfg(testing)]",
        "#[cfg(feature = \"x\")] // #[cfg(test)]",
        "#[cfg(all(test",
    ] {
        assert!(!is_test_only_cfg(no), "I693 {no} is not test-only");
    }
}
