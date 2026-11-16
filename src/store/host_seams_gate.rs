//! v62.0.0 (slice A) — I1796, from disk: **node code reaches time, the
//! executor, blocking dispatch and shutdown only through `src/host/`.**
//!
//! FSD WASM_NODE §4.1 rule 2 / §5.1. A raw `Utc::now()`, `Instant::now`,
//! `SystemTime::now`, `tokio::spawn`, `tokio::time::*`, `spawn_blocking`,
//! `.block_on(`, `Handle::current` or a target `cfg` in node code is a read or
//! a spawn the host cannot answer: it panics, or fails to resolve, on
//! `wasm32-unknown-unknown`, and a fixed clock or a single-thread executor
//! cannot reach it. The gate scans every production line of `src/` outside
//! `src/host/` (the seams' own native defaults), `src/ffi/` and `src/bin/`
//! (host bindings and host tools).
//!
//! Each surviving site is VETTED below with its reason; a vetted site that no
//! longer occurs is also red, so the list cannot rot into a suppression file.
//! Test code is cut first: items under `#[cfg(test)]` / `#[cfg(all(test, …))]`
//! (`crate::test_cfg`), files declared through one, and — as this gate's own
//! choice, since the feature is a compile-time-fenced test seam — items under
//! `feature = "test-anchor"`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::pool_checkout_gate::{blank, rust_files};

/// The raw spellings, matched on comment- and string-blanked text with all
/// whitespace removed (rustfmt splits chains).
const RAW: &[(&str, &str)] = &[
    ("Utc::now()", "wall clock: host::clock::now()"),
    ("Local::now()", "wall clock: host::clock::now()"),
    ("SystemTime::now", "wall clock: host::clock::now()"),
    (
        "Instant::now",
        "monotonic clock: host::clock::monotonic_now()",
    ),
    ("tokio::spawn(", "spawn: host::rt::spawn"),
    ("tokio::task::spawn(", "spawn: host::rt::spawn"),
    (
        "spawn_blocking(",
        "blocking: host::rt::{dispatch_blocking, try_dispatch_blocking}",
    ),
    ("tokio::time::sleep", "timer: host::rt::sleep"),
    ("tokio::time::timeout", "timer: host::rt::timeout"),
    ("tokio::time::interval", "timer: host::rt::sleep in a loop"),
    (".block_on(", "sync-over-async: .await"),
    ("Handle::current()", "a captured runtime: the seam"),
    (
        "tokio::signal",
        "signals: host::Lifecycle + ffi::native_host",
    ),
    ("cfg(unix)", "target cfg: a host capability"),
    ("cfg(windows)", "target cfg: a host capability"),
    ("cfg(target_os", "target cfg: a host capability"),
    ("cfg(not(target_os", "target cfg: a host capability"),
];

/// `(file under src/, raw spelling, count, reason)`. A review event to add.
const VETTED: &[(&str, &str, usize, &str)] = &[
    (
        "store/postgres.rs",
        "tokio::time::timeout",
        1,
        "checkout_bounded's running-copy arm (#1231): postgres is host-only, and the arm \
         must use the RUNNING copy's tokio, never a seam a foreign copy could walk",
    ),
    (
        "store/postgres_runtime_connect.rs",
        "tokio::time::sleep",
        2,
        "the #1231 persist-runtime timer: persist's own tokio, reached through a vtable \
         persist's .so built; postgres is host-only",
    ),
    (
        "store/test_backend.rs",
        ".block_on(",
        1,
        "the test constructor (#1002): pub for consumers' tests, on its own thread and \
         runtime, never on a node path",
    ),
    (
        "store/postgres.rs",
        "cfg(unix)",
        1,
        "tokio-postgres' `Host::Unix` socket DSN exists only on unix; postgres is host-only",
    ),
    (
        "store/sqlite_conn_model.rs",
        "cfg(target_os",
        1,
        "the cgroup memory-limit read that sizes the page cache (another v62 slice: the \
         SQLite memory profile becomes a host capability)",
    ),
    (
        "store/sqlite_conn_model.rs",
        "cfg(not(target_os",
        1,
        "the cgroup read's no-cgroup arm (same slice)",
    ),
    (
        "debug/mod.rs",
        "SystemTime::now",
        1,
        "the debug-tools panic hook: must not take the clock seam's lock while panicking",
    ),
    (
        "federation/genesis/scratch.rs",
        ".block_on(",
        1,
        "the genesis scratch release on drop (P9's scratch leg): its own slice, not v62-A",
    ),
];

fn is_test_anchor_cfg(line: &str) -> bool {
    let t: String = line
        .trim_start()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    t.starts_with("#[cfg(feature=\"test-anchor\")]")
        || t.starts_with("#[cfg(any(test,feature=\"test-anchor\"))]")
}

fn starts_test_item(line: &str) -> bool {
    crate::test_cfg::is_test_only_cfg(line) || is_test_anchor_cfg(line)
}

/// Byte offset where 0-based `line` starts.
fn line_starts(src: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(src.match_indices('\n').map(|(i, _)| i + 1))
        .collect()
}

/// `blanked` with every test item cut (newlines kept), plus the names of the
/// modules declared `mod x;` under a test cfg.
fn production(orig: &str) -> (String, Vec<String>) {
    let mut b = blank(orig).into_bytes();
    let starts = line_starts(orig);
    let lines: Vec<&str> = orig.lines().collect();
    let mut declared = Vec::new();
    let mut li = 0usize;
    while li < lines.len() {
        if !starts_test_item(lines[li]) || b[starts[li]..].iter().all(|c| *c == b' ') {
            li += 1;
            continue;
        }
        // From the attribute: skip `#[…]` groups, then the item to its `;`
        // or its balanced `{}`.
        let from = starts[li];
        let mut i = from;
        let mut depth = 0i32;
        let mut end = b.len();
        let mut in_attr = false;
        while i < b.len() {
            match b[i] {
                b'#' if depth == 0 && b.get(i + 1) == Some(&b'[') => {
                    in_attr = true;
                }
                b'[' if in_attr => depth += 1,
                b']' if in_attr => {
                    depth -= 1;
                    if depth == 0 {
                        in_attr = false;
                    }
                }
                b';' if !in_attr && depth == 0 => {
                    let decl = String::from_utf8_lossy(&b[from..i]).to_string();
                    if let Some(name) = decl.split_whitespace().skip_while(|w| *w != "mod").nth(1) {
                        declared.push(name.trim().to_owned());
                    }
                    end = i + 1;
                    break;
                }
                b'{' if !in_attr => depth += 1,
                b'}' if !in_attr => {
                    depth -= 1;
                    if depth == 0 {
                        end = i + 1;
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        for c in &mut b[from..end] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
        li += 1;
    }
    (String::from_utf8(b).expect("blank keeps utf-8"), declared)
}

fn test_only_paths(file: &Path, declared: &[String]) -> Vec<PathBuf> {
    let dir = file.parent().expect("parent");
    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let base = if matches!(stem, "mod" | "lib" | "main") {
        dir.to_path_buf()
    } else {
        dir.join(stem)
    };
    declared
        .iter()
        .flat_map(|m| [base.join(format!("{m}.rs")), base.join(m).join("mod.rs")])
        .collect()
}

/// Every raw hit in node production code: `(file, spelling) → lines`.
fn raw_hits() -> BTreeMap<(String, &'static str), Vec<usize>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    files.sort();
    assert!(
        files.len() > 400,
        "I1796: the scan reached {} files",
        files.len()
    );

    let mut prod = BTreeMap::new();
    let mut test_only: BTreeSet<PathBuf> = BTreeSet::new();
    for f in &files {
        let orig = std::fs::read_to_string(f).expect("read");
        let (text, declared) = production(&orig);
        test_only.extend(test_only_paths(f, &declared));
        prod.insert(f.clone(), text);
    }
    // A test-only directory module makes its whole subtree test-only.
    let dirs: Vec<PathBuf> = test_only
        .iter()
        .filter(|p| p.ends_with("mod.rs"))
        .filter_map(|p| p.parent().map(Path::to_path_buf))
        .collect();

    let mut hits: BTreeMap<(String, &'static str), Vec<usize>> = BTreeMap::new();
    for (f, text) in &prod {
        let rel = f
            .strip_prefix(&root)
            .expect("under src")
            .to_string_lossy()
            .to_string();
        if test_only.contains(f)
            || dirs.iter().any(|d| f.starts_with(d))
            || rel.starts_with("host/")
            || rel.starts_with("ffi/")
            || rel.starts_with("bin/")
        {
            continue;
        }
        for (n, line) in text.lines().enumerate() {
            let squashed: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            for (raw, _) in RAW {
                let mut from = 0;
                while let Some(p) = squashed[from..].find(raw) {
                    let at = from + p;
                    let prev = squashed[..at].chars().last();
                    // `Utc::now()` but not `crate::host::clock::now()`;
                    // `tokio::spawn(` but not `foo_tokio::spawn(`.
                    let word_start = !prev.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
                    if word_start || raw.starts_with('.') {
                        hits.entry((rel.clone(), *raw)).or_default().push(n + 1);
                    }
                    from = at + raw.len();
                }
            }
        }
    }
    hits
}

/// **I1796.** Node production code holds no raw clock read, spawn, timer,
/// blocking dispatch, `block_on`, captured runtime, signal handler or target
/// `cfg` outside the vetted sites.
#[test]
fn i1796_node_code_reaches_the_host_only_through_the_seams() {
    let hits = raw_hits();
    let mut red = Vec::new();
    for ((file, raw), lines) in &hits {
        let vetted = VETTED.iter().find(|(f, r, _, _)| f == file && r == raw);
        match vetted {
            Some((_, _, n, _)) if *n == lines.len() => {}
            Some((_, _, n, _)) => red.push(format!(
                "{file}: `{raw}` ×{} (vetted ×{n}) at lines {lines:?}",
                lines.len()
            )),
            None => {
                let why = RAW.iter().find(|(r, _)| r == raw).map_or("", |(_, w)| *w);
                red.push(format!("{file}: `{raw}` at lines {lines:?} — {why}"));
            }
        }
    }
    for (file, raw, _, _) in VETTED {
        if !hits.contains_key(&((*file).to_owned(), *raw)) {
            red.push(format!(
                "vetted site {file}: `{raw}` no longer occurs — remove it from VETTED"
            ));
        }
    }
    assert!(
        red.is_empty(),
        "I1796: node code bypasses the host seams:\n  {}",
        red.join("\n  ")
    );
}

/// **I1796 (the stripper is not blind).** Each raw spelling is found in a
/// production line, and none in a test item, a comment or a string — so a
/// green gate is a clean tree, not a scanner that sees nothing.
#[test]
fn i1796_the_scanner_sees_production_and_only_production() {
    let src = "fn a() { let t = chrono::Utc::now(); tokio::spawn(f()); }\n\
               // Utc::now() in a comment\n\
               fn b() { let s = \"tokio::spawn(\"; }\n\
               #[cfg(test)]\n\
               mod tests { fn c() { std::time::Instant::now(); } }\n\
               #[cfg(all(test, feature = \"sqlite\"))]\n\
               mod more;\n\
               fn d() { handle.block_on(x); crate::host::clock::now(); }\n";
    let (text, declared) = production(src);
    assert_eq!(declared, vec!["more".to_owned()]);
    let squashed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(squashed.matches("Utc::now()").count(), 1, "{text}");
    assert_eq!(squashed.matches("tokio::spawn(").count(), 1, "{text}");
    assert_eq!(squashed.matches("Instant::now").count(), 0, "{text}");
    assert_eq!(squashed.matches(".block_on(").count(), 1, "{text}");
    // And on the real tree: the seams' own native defaults are seen.
    let clock_rs = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/host/clock.rs"),
    )
    .unwrap();
    let (text, _) = production(&clock_rs);
    assert!(
        text.contains("Utc::now()"),
        "I1796: the scanner must see the native default's Utc::now() in host/clock.rs"
    );
}
