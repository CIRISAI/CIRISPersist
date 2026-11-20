//! v62.0.0 (v62 P8-fix16; lead ruling (a)) — **I3523b: every production writer
//! of `federation_attestations` stores the row's restatement key.**
//!
//! The Live read hides a restated prior through V300's `restatement_key`
//! column (`attestation_query::lifecycle_predicate`). The column is written
//! beside the row by `sqlite_stamp_restatement_key` / `pg_stamp_restatement_key`
//! (P8-fix14). A writer that inserted a row without the stamp would leave
//! `NULL`: that row could never hide or be hidden, silently. This from-disk
//! gate makes the omission red:
//!
//! - **the text:** `src/store/sqlite.rs` and `src/store/postgres.rs` with
//!   comments blanked (line comments outside string literals; doc comments
//!   are line comments) and every item under a test-only cfg removed,
//!   `crate::test_cfg::is_test_only_cfg` deciding (`#[cfg(test)]`,
//!   `#[cfg(all(test, ..))]`), wherever the item stands in the file (a
//!   column-0 test `impl` precedes production code in `postgres.rs`, so a
//!   cut at the first test cfg would read nothing);
//! - **the writers:** every production `fn` whose body holds an
//!   `INSERT … INTO federation_attestations (` (sqlite) or `INTO
//!   cirislens.federation_attestations (` (postgres), the `_form_refused`
//!   side table aside;
//! - **the rule:** each such body calls its dialect's stamp helper. A floor
//!   of three writers per dialect keeps the scan from passing vacuously.
//! - **the mutation:** the same check over the text with ONE writer's stamp
//!   call removed must name that writer (a gate that cannot fail is a
//!   report).

#![cfg(test)]

/// One dialect's file, insert anchor and stamp call.
struct Dialect {
    file: &'static str,
    insert: &'static str,
    stamp: &'static str,
}

const DIALECTS: [Dialect; 2] = [
    Dialect {
        file: "src/store/sqlite.rs",
        insert: "INTO federation_attestations (",
        stamp: "sqlite_stamp_restatement_key(",
    },
    Dialect {
        file: "src/store/postgres.rs",
        insert: "INTO cirislens.federation_attestations (",
        stamp: "pg_stamp_restatement_key(",
    },
];

/// The fewest writers each dialect must show (store_planned_attestation, the
/// plane-row writer, the local-row writer).
const WRITER_FLOOR: usize = 3;

fn read(file: &str) -> String {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(file);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// `line` with a `//` comment outside string literals cut off. A `"` inside
/// the line toggles the literal state (escaped quotes kept inside); a raw
/// multi-line string is not tracked, which only ever keeps MORE text.
fn strip_line_comment(line: &str, in_str: &mut bool) -> String {
    let b: Vec<char> = line.chars().collect();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if *in_str {
            out.push(c);
            if c == '\\' && i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                *in_str = false;
            }
            i += 1;
            continue;
        }
        if c == '/' && i + 1 < b.len() && b[i + 1] == '/' {
            break;
        }
        // A char literal (`'"'`, `'{'`) is not a string delimiter.
        if c == '\'' && i + 2 < b.len() && b[i + 2] == '\'' {
            out.extend(&b[i..i + 3]);
            i += 3;
            continue;
        }
        if c == '"' {
            *in_str = true;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// The net `{` minus `}` of `line`, outside string and char literals.
fn brace_delta(line: &str, in_str: &mut bool) -> (i64, bool) {
    let b: Vec<char> = line.chars().collect();
    let (mut d, mut opened, mut i) = (0i64, false, 0);
    while i < b.len() {
        let c = b[i];
        if *in_str {
            if c == '\\' {
                i += 2;
                continue;
            }
            if c == '"' {
                *in_str = false;
            }
            i += 1;
            continue;
        }
        match c {
            '"' => *in_str = true,
            // A char literal: `'{'`, `'}'` or an escape such as `'\\''`.
            '\'' if i + 2 < b.len() && b[i + 2] == '\'' => {
                i += 3;
                continue;
            }
            '{' => {
                d += 1;
                opened = true;
            }
            '}' => d -= 1,
            _ => {}
        }
        i += 1;
    }
    (d, opened)
}

/// The production text: comments blanked, and every item under a test-only
/// cfg removed (the attribute line, the attributes after it, and the item up
/// to its matching close brace or its terminating `;`).
pub(super) fn production_text(src: &str) -> String {
    let mut in_str = false;
    let lines: Vec<String> = src
        .lines()
        .map(|l| strip_line_comment(l, &mut in_str))
        .collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < lines.len() {
        if crate::test_cfg::is_test_only_cfg(&lines[i]) {
            // Skip the attribute(s), then the item.
            let mut j = i;
            while j < lines.len() && lines[j].trim_start().starts_with("#[") {
                j += 1;
            }
            let mut depth = 0i64;
            let mut opened = false;
            let mut in_s = false;
            while j < lines.len() {
                let (d, o) = brace_delta(&lines[j], &mut in_s);
                depth += d;
                opened |= o;
                let ends_bodiless = !opened && lines[j].trim_end().ends_with(';');
                j += 1;
                if (opened && depth <= 0) || ends_bodiless {
                    break;
                }
            }
            i = j;
            continue;
        }
        out.push_str(&lines[i]);
        out.push('\n');
        i += 1;
    }
    out
}

/// `(fn name, body)` of every fn in `prod` whose body contains `needle`.
fn fns_containing<'a>(prod: &'a str, needle: &str) -> Vec<(String, &'a str)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(off) = prod[from..].find(needle) {
        let at = from + off;
        // The enclosing fn: the last `fn ` header before `at`.
        let head = prod[..at]
            .rfind("fn ")
            .unwrap_or_else(|| panic!("no fn encloses the insert at byte {at}"));
        let name: String = prod[head + 3..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        // The body: from the first `{` after the header to its match.
        let open = head + prod[head..].find('{').expect("a fn body");
        let mut depth = 0i64;
        let mut end = prod.len();
        let mut in_s = false;
        let mut pos = open;
        for line in prod[open..].split_inclusive('\n') {
            let (d, _) = brace_delta(line, &mut in_s);
            depth += d;
            pos += line.len();
            if depth <= 0 {
                end = pos;
                break;
            }
        }
        if !out.iter().any(|(n, _): &(String, &str)| *n == name) {
            out.push((name, &prod[open..end]));
        }
        from = end.max(at + needle.len());
    }
    out
}

/// The writers of `d` in `src` (production text) that do not call the stamp.
fn unstamped(d: &Dialect, src: &str) -> (usize, Vec<String>) {
    let prod = production_text(src);
    // `INTO federation_attestations_form_refused` never matches: the anchor
    // ends in ` (`.
    let writers: Vec<(String, &str)> = fns_containing(&prod, d.insert);
    let missing = writers
        .iter()
        .filter(|(_, body)| !body.contains(d.stamp))
        .map(|(n, _)| n.clone())
        .collect();
    (writers.len(), missing)
}

#[test]
fn i3523b_every_attestation_writer_stores_the_restatement_key() {
    for d in &DIALECTS {
        let (n, missing) = unstamped(d, &read(d.file));
        assert!(
            n >= WRITER_FLOOR,
            "I3523b {}: the scan found {n} federation_attestations writer(s); the floor is \
             {WRITER_FLOOR} (the extractor collapsed?)",
            d.file
        );
        assert!(
            missing.is_empty(),
            "I3523b {}: these writers insert into federation_attestations without storing \
             the row's restatement key ({}): {missing:?}",
            d.file,
            d.stamp
        );
    }
}

/// The mutation: the check over the file with ONE writer's stamp call
/// removed must name that writer.
#[test]
fn i3523b_the_gate_turns_red_when_a_writer_drops_the_key() {
    for d in &DIALECTS {
        let prod = production_text(&read(d.file));
        let writers = fns_containing(&prod, d.insert);
        let (victim, body) = writers
            .first()
            .unwrap_or_else(|| panic!("I3523b {}: no writer to mutate", d.file));
        let at = prod.find(*body).expect("the body is a slice of the text");
        let call = at + body.find(d.stamp).expect("the writer stamps today");
        // Rename the call in the victim's body only (the production text is
        // a fixed point of the stripper).
        let mutated = format!("{}MUTATED_{}", &prod[..call], &prod[call..]);
        let (_, missing) = unstamped(d, &mutated);
        assert_eq!(
            missing,
            vec![victim.clone()],
            "I3523b {}: dropping {victim}'s stamp must turn the gate red",
            d.file
        );
    }
}

/// The stripper drops a test-only item wherever it stands, and keeps the
/// production code after it.
#[test]
fn i3523b_the_stripper_drops_test_items_anywhere() {
    let src =
        "fn a() {}\n#[cfg(test)]\nimpl X {\n    fn t() { INTO federation_attestations ( }\n}\n\
               #[cfg(all(test, feature = \"sqlite\"))]\nmod m;\n\
               fn b() { let s = \"// not a comment\"; } // a comment\nfn c() {}\n";
    let p = production_text(src);
    assert!(
        p.contains("fn a()") && p.contains("fn b()") && p.contains("fn c()"),
        "{p}"
    );
    assert!(!p.contains("INTO federation_attestations"), "{p}");
    assert!(!p.contains("mod m;"), "{p}");
    assert!(p.contains("\"// not a comment\""), "{p}");
    assert!(!p.contains("a comment\n"), "{p}");
}
