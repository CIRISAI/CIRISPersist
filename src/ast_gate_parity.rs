//! v53.2.0 (CIRISPersist#1026) — **the ported gates' two counts agree.**
//!
//! Six from-disk gates have an ast-grep port: a rule in `rules/` whose
//! per-file match counts `scripts/ast_gates.sh` holds equal to
//! `rules/expected.json`. Each gate keeps its Rust text witness for a release;
//! this module counts the same call sites by text (comments stripped) and
//! holds them equal to the same `expected.json`. So the AST count and the text
//! count agree through one committed file, and a call ast-grep cannot see (in
//! a macro's token tree, say) shows up here as a disagreement, not as a
//! silently lower count. Inventory: `docs/FROM_DISK_GATES.md`.
//!
//! Read from this crate's own `CARGO_MANIFEST_DIR`, never another checkout.

use std::collections::{BTreeMap, BTreeSet};

/// rule id → (the called function, the enclosing fns it must sit in; empty =
/// anywhere in the file).
const PORTED: &[(&str, &str, &[&str])] = &[
    (
        "i110-check-consent-scope-tokens",
        "check_consent_scope_tokens",
        &[],
    ),
    ("i119-check-media-source", "check_media_source", &[]),
    (
        "i26-cached-content-master",
        "resolve_persisted_content_master_cached",
        &[],
    ),
    (
        "i26-uncached-content-master",
        "resolve_persisted_content_master",
        &[],
    ),
    (
        "i448-prev-head-check",
        "check_prev_head_names_held",
        &["supersede_group_row"],
    ),
    (
        "scores-read-log",
        "log_scores_read",
        &["list_scores", "resolve_scores"],
    ),
];

fn root() -> &'static std::path::Path {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// `src` with comments blanked to spaces (lengths kept) and string literal
/// contents blanked, so neither a commented-out call nor a call name inside a
/// SQL string counts, and braces inside strings do not unbalance a body.
fn code_only(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                out[i] = b' ';
                i += 1;
            }
        } else if b[i..].starts_with(b"/*") {
            let mut depth = 0;
            while i < b.len() {
                if b[i..].starts_with(b"/*") {
                    depth += 1;
                    out[i] = b' ';
                    out[i + 1] = b' ';
                    i += 2;
                } else if b[i..].starts_with(b"*/") {
                    depth -= 1;
                    out[i] = b' ';
                    out[i + 1] = b' ';
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    if b[i] != b'\n' {
                        out[i] = b' ';
                    }
                    i += 1;
                }
            }
        } else if b[i] == b'\'' && i + 2 < b.len() && (b[i + 2] == b'\'' || b[i + 1] == b'\\') {
            // A char literal ('"', '{', '\n'): blank its content.
            let end = b[i + 1..]
                .iter()
                .position(|c| *c == b'\'')
                .map_or(b.len(), |p| i + 1 + p);
            for o in &mut out[i + 1..end] {
                *o = b' ';
            }
            i = end + 1;
        } else if b[i] == b'"' || b[i..].starts_with(b"r#\"") || b[i..].starts_with(b"r\"") {
            let hashes = if b[i] == b'r' {
                b[i + 1..].iter().take_while(|c| **c == b'#').count()
            } else {
                0
            };
            let raw = b[i] == b'r';
            i += if raw { 2 + hashes } else { 1 };
            while i < b.len() {
                if !raw && b[i] == b'\\' {
                    out[i] = b' ';
                    if i + 1 < b.len() && b[i + 1] != b'\n' {
                        out[i + 1] = b' ';
                    }
                    i += 2;
                    continue;
                }
                if b[i] == b'"'
                    && b[i + 1..]
                        .iter()
                        .take(hashes)
                        .filter(|c| **c == b'#')
                        .count()
                        == hashes
                {
                    i += 1 + hashes;
                    break;
                }
                if b[i] != b'\n' {
                    out[i] = b' ';
                }
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    String::from_utf8(out).expect("blanking keeps UTF-8 (multi-byte only inside blanked spans)")
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Calls of `name` in `code`: `name(` not preceded by an identifier byte.
fn calls(code: &str, name: &str) -> usize {
    let needle = format!("{name}(");
    code.match_indices(&needle)
        .filter(|(at, _)| *at == 0 || !is_ident(code.as_bytes()[at - 1]))
        .count()
}

/// The bodies (`{ … }`, brace-matched) of every `fn <name>` in `code`.
fn fn_bodies<'a>(code: &'a str, name: &str) -> Vec<&'a str> {
    let needle = format!("fn {name}");
    let b = code.as_bytes();
    let mut out = Vec::new();
    for (at, _) in code.match_indices(&needle) {
        let after = at + needle.len();
        if after < b.len() && is_ident(b[after]) {
            continue;
        }
        let Some(open) = code[after..].find('{').map(|p| after + p) else {
            continue;
        };
        let mut depth = 0usize;
        for (j, c) in b.iter().enumerate().skip(open) {
            match c {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        out.push(&code[open..=j]);
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    out
}

fn expected() -> BTreeMap<String, BTreeMap<String, usize>> {
    let text = std::fs::read_to_string(root().join("rules/expected.json"))
        .expect("read rules/expected.json");
    let json: serde_json::Value = serde_json::from_str(&text).expect("rules/expected.json is JSON");
    json.as_object()
        .expect("object")
        .iter()
        .filter(|(k, _)| !k.starts_with('_'))
        .map(|(rule, files)| {
            let files = files
                .as_object()
                .expect("rule → {file: count}")
                .iter()
                .map(|(f, n)| (f.clone(), n.as_u64().expect("count") as usize))
                .collect();
            (rule.clone(), files)
        })
        .collect()
}

#[test]
fn the_rust_text_counts_equal_the_ast_grep_expectations() {
    let expected = expected();
    let ported: BTreeSet<&str> = PORTED.iter().map(|(id, ..)| *id).collect();
    let listed: BTreeSet<&str> = expected.keys().map(String::as_str).collect();
    assert_eq!(
        ported, listed,
        "every ported rule has expectations, and no others"
    );
    let mut red = Vec::new();
    for (id, name, inside) in PORTED {
        for (file, want) in &expected[*id] {
            let code = code_only(&std::fs::read_to_string(root().join(file)).expect("read source"));
            let have: usize = if inside.is_empty() {
                calls(&code, name)
            } else {
                inside
                    .iter()
                    .flat_map(|f| fn_bodies(&code, f))
                    .map(|body| calls(body, name))
                    .sum()
            };
            if have != *want {
                red.push(format!(
                    "{id}: {file} has {have} by text, expected.json says {want}"
                ));
            }
        }
    }
    assert!(
        red.is_empty(),
        "the text count and the AST expectation disagree:\n{}",
        red.join("\n")
    );
}

#[test]
fn the_text_counter_ignores_comments_and_strings() {
    let code = code_only(
        "fn a() { x(); // x();\n /* x(); */ let s = \"x()\"; let r = r#\"x(\"#; y_x(); }\nfn b() { x(); }",
    );
    assert_eq!(calls(&code, "x"), 2, "{code}");
    assert_eq!(fn_bodies(&code, "a").len(), 1);
    assert_eq!(calls(fn_bodies(&code, "a")[0], "x"), 1);
    assert_eq!(fn_bodies(&code, "ab").len(), 0);
}
