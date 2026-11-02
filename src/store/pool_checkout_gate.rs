//! v61 (CIRISPersist#1166) — **every Postgres checkout is the bounded one.**
//!
//! v59.1.2 bounded a pooled checkout at its wait and made starvation a typed
//! `PoolExhausted`, but only for the doors that went through
//! `PostgresBackend::checkout`. Every other site called the pool's own
//! `get()`, which waits without a bound: on a starved pool those sites hung
//! instead of erroring (outbound, read, telemetry, cirisnode, the ledgers,
//! the engine, the Python surface, the audit Merkle store's own get). v61
//! routes all of them through `store::postgres::checkout_bounded`, and this
//! gate keeps it that way.
//!
//! It reads every `src/**/*.rs` from disk (tests included: a test that
//! checks out a client the old way would model a door that no longer
//! exists), blanks comments and string literals so a mention is not a call,
//! drops whitespace so a call split over lines is still one call, and
//! refuses any `pool().get()`, `.pool.get()` or bare `pool.get()` outside
//! `checkout_bounded` itself. The shape follows the pre-commit hook's bare
//! `Row::get` ban: a spelling that is the defect, refused wherever it
//! appears, with the one approved site named.
//!
//! The `pool()` accessor stays public (a host's `LISTEN`/`NOTIFY` and the
//! integration tests outside `src/` hold the pool itself); the gate is about
//! this crate's own checkouts.

use std::path::{Path, PathBuf};

/// The one function a bare pooled `get()` may live in, and its file.
const THE_CHECKOUT: (&str, &str) = ("src/store/postgres.rs", "fn checkout_bounded(");

/// The bare spellings of a pooled checkout, whitespace removed.
const BARE: [&str; 3] = ["pool().get()", ".pool.get()", "pool.get()"];

/// `src` with comments and string/char literal contents blanked (byte
/// length and newlines kept). A lifetime's `'` is not a quote.
fn blank(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0usize;
    let blank_to = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in &mut out[from..to] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let end = b[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .map_or(b.len(), |p| i + p);
                blank_to(&mut out, i, end);
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let (mut j, mut depth) = (i + 2, 1usize);
                while j < b.len() && depth > 0 {
                    if b[j] == b'/' && b.get(j + 1) == Some(&b'*') {
                        depth += 1;
                        j += 2;
                    } else if b[j] == b'*' && b.get(j + 1) == Some(&b'/') {
                        depth -= 1;
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                blank_to(&mut out, i, j);
                i = j;
            }
            b'"' => {
                // A raw string's hashes are not tracked: the crate forbids
                // raw strings in the scanned backends, and elsewhere a raw
                // string holding a quote is rare enough to fail loudly.
                let mut j = i + 1;
                while j < b.len() && b[j] != b'"' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                blank_to(&mut out, i + 1, j.min(b.len()));
                i = j + 1;
            }
            b'\'' => {
                // `'a'` / `'\n'` are char literals; `'a` is a lifetime.
                let close = if b.get(i + 1) == Some(&b'\\') {
                    b[i + 2..]
                        .iter()
                        .position(|&c| c == b'\'')
                        .map(|p| i + 2 + p)
                } else if b.get(i + 2) == Some(&b'\'') {
                    Some(i + 2)
                } else {
                    None
                };
                match close {
                    Some(c) => {
                        blank_to(&mut out, i + 1, c);
                        i = c + 1;
                    }
                    None => i += 1,
                }
            }
            _ => i += 1,
        }
    }
    String::from_utf8(out).expect("blanking keeps UTF-8 (only ASCII bytes change)")
}

/// The byte range of the body of the first `fn` whose signature starts at
/// `sig` in `code`, braces included.
fn fn_body(code: &str, sig: &str) -> Option<(usize, usize)> {
    let at = code.find(sig)?;
    let open = at + code[at..].find('{')?;
    let mut depth = 0usize;
    for (k, c) in code[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((open, open + k + 1));
                }
            }
            _ => {}
        }
    }
    None
}

/// Every bare checkout in `code` (already blanked), as 1-based lines.
fn bare_checkouts(code: &str) -> Vec<usize> {
    // Whitespace removed, with each kept byte's line.
    let mut flat = String::with_capacity(code.len());
    let mut lines = Vec::with_capacity(code.len());
    let mut line = 1usize;
    for c in code.chars() {
        if c == '\n' {
            line += 1;
        }
        if !c.is_whitespace() {
            flat.push(c);
            lines.push(line);
        }
    }
    let bytes = flat.as_bytes();
    let mut hits = Vec::new();
    for pat in BARE {
        let mut from = 0;
        while let Some(p) = flat[from..].find(pat) {
            let at = from + p;
            from = at + pat.len();
            // `pool.get()` must be the WHOLE receiver: not the tail of
            // `.pool.get()` or `x_pool.get()` (each counted by its own form
            // or not a pool), and `pool().get()` is its own form.
            if pat == "pool.get()" {
                let before = at.checked_sub(1).map(|i| bytes[i]);
                if matches!(before, Some(c) if c == b'.' || c == b'_' || c.is_ascii_alphanumeric())
                {
                    continue;
                }
            }
            hits.push(lines[at.min(lines.len() - 1)]);
        }
    }
    hits.sort_unstable();
    hits
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// **The gate.** No bare pooled `get()` anywhere in `src/` outside
/// [`THE_CHECKOUT`], which holds them all.
#[test]
fn every_postgres_checkout_is_the_bounded_one_1166() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();
    assert!(
        files.len() > 200,
        "the scan reached {} files under src/ — it would pass vacuously",
        files.len()
    );
    let mut offenders = Vec::new();
    let mut approved = 0usize;
    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .expect("under root")
            .to_string_lossy()
            .replace('\\', "/");
        let mut code = blank(&super::tree_read::read(path));
        if rel == THE_CHECKOUT.0 {
            let (a, b) = fn_body(&code, THE_CHECKOUT.1)
                .unwrap_or_else(|| panic!("{} has no `{}`", THE_CHECKOUT.0, THE_CHECKOUT.1));
            approved = bare_checkouts(&code[a..b]).len();
            let blanked: String = code[a..b]
                .chars()
                .map(|c| if c == '\n' { '\n' } else { ' ' })
                .collect();
            code.replace_range(a..b, &blanked);
        }
        for line in bare_checkouts(&code) {
            offenders.push(format!("  {rel}:{line}"));
        }
    }
    super::tree_read::assert_unmoved();
    assert_eq!(
        approved, 3,
        "`checkout_bounded` should hold the crate's only pooled gets (one per timer arm); \
         found {approved} — the gate's anchor moved"
    );
    assert!(
        offenders.is_empty(),
        "CIRISPersist#1166: a bare pooled checkout waits without a bound and hangs on a starved \
         pool. Use `PostgresBackend::checkout` (or `store::postgres::checkout_bounded` for a \
         holder of the bare pool):\n{}",
        offenders.join("\n")
    );
}

/// The gate sees a call split over lines, and not a mention in a comment or
/// a string.
#[test]
fn the_gate_reads_calls_not_mentions() {
    let planted =
        "fn f() {\n    let c = self\n        .pool()\n        .get()\n        .await;\n}\n";
    assert_eq!(bare_checkouts(&blank(planted)), vec![3]);
    let field = "fn f() { let c = self.pool.get().await; }";
    assert_eq!(bare_checkouts(&blank(field)), vec![1]);
    let local = "fn f() { let c = pool\n.get().await; }";
    assert_eq!(bare_checkouts(&blank(local)), vec![1]);
    let mentions = "fn f() {\n    // self.pool().get()\n    /* pool.get() */\n    let s = \"pool.get()\";\n}\n";
    assert!(bare_checkouts(&blank(mentions)).is_empty());
    let other = "fn f() { let c = my_pool.get(); let d = self.checkout().await; }";
    assert!(bare_checkouts(&blank(other)).is_empty());
}
