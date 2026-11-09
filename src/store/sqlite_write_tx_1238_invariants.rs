//! v61.1.0 (CIRISPersist#1238, Edge's darwin×sqlite cohabitation failure):
//! I1660–I1663. **Every SQLite write transaction begins `IMMEDIATE`.**
//!
//! **The hazard.** rusqlite's `Connection::transaction()` is `BEGIN DEFERRED`.
//! A read-then-write body (`store_planned_key_record` reads
//! `sqlite_next_key_serve_position`, then INSERTs) holds a read snapshot when
//! it reaches its first write, and SQLite does not run the busy handler for
//! that lock upgrade. With another PROCESS on the same file holding the write
//! lock, the upgrade fails `SQLITE_BUSY` at once: `busy_timeout = 30000` never
//! applied. Edge: one process holding `BEGIN IMMEDIATE` for 2 s made
//! `register_self_federation_key` fail `federation_backend` in 1–3 ms, 3 of 3;
//! 4 processes × 15 registrations gave 23 failures.
//!
//! **The fix.** `store::sqlite_conn_model::write_tx` is the one way a write
//! transaction begins, and it begins `IMMEDIATE`: the write lock is taken at
//! `BEGIN`, where the busy handler does run, so a second writer waits.
//!
//! - **I1660** (sqlite, a real file) — a second connection holds `BEGIN
//!   IMMEDIATE` for 1 s on a thread; the key-record door (read-then-write)
//!   and the attestation door each complete AFTER the holder releases, and
//!   succeed. RED with `database is locked` when `write_tx` is deferred.
//! - **I1661** (from disk, every feature set) — no bare `.transaction()`, no
//!   `unchecked_transaction()`, no `TransactionBehavior::Deferred`, no
//!   `transaction_with_behavior` with any other behaviour, and no `"BEGIN"`
//!   string that is not `BEGIN IMMEDIATE`/`EXCLUSIVE`, anywhere in `src/`,
//!   outside [`ALLOWED`]'s read-only sites, each named with its reason. The
//!   helper itself is pinned to `Immediate`. Plus a self-test of the scanner.
//! - **I1662** (`ffi::pyo3` tests) — a backend error reaches Python with its
//!   detail in the message, led by the `federation_backend` kind token.
//! - **I1663** (`store::sqlite_conn_model` gate) — no closure handed to the
//!   read door in `sqlite.rs` writes: a write class never runs on a reader.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::pool_checkout_gate::{blank, rust_files};

// ── I1661: from disk, every write transaction is IMMEDIATE ────────────────

/// A spelling that opens a transaction other than `BEGIN IMMEDIATE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Form {
    /// `.transaction()` not awaited: rusqlite's `BEGIN DEFERRED`. (An
    /// awaited one is tokio-postgres, whose `BEGIN` has no lock upgrade.)
    Bare,
    /// `.unchecked_transaction()`: the `&Connection` form of `BEGIN DEFERRED`.
    Unchecked,
    /// `TransactionBehavior::Deferred`, however it is passed.
    Deferred,
    /// `transaction_with_behavior(…)` whose argument is not literally
    /// `TransactionBehavior::Immediate` or `::Exclusive`.
    NotImmediate,
    /// A string literal that is a `BEGIN` but not `BEGIN IMMEDIATE` /
    /// `BEGIN EXCLUSIVE` (`execute_batch("BEGIN")`, `"BEGIN; …"`).
    BeginLiteral,
}

impl Form {
    fn describe(self) -> &'static str {
        match self {
            Form::Bare => "bare `.transaction()` (BEGIN DEFERRED)",
            Form::Unchecked => "`.unchecked_transaction()` (BEGIN DEFERRED)",
            Form::Deferred => "`TransactionBehavior::Deferred`",
            Form::NotImmediate => "`transaction_with_behavior` not passed `Immediate`",
            Form::BeginLiteral => "a `\"BEGIN\"` string that is not `BEGIN IMMEDIATE`",
        }
    }
}

/// A deferred `BEGIN` that may stay deferred, and why. Each must be found
/// exactly once: a site that moved or went away makes its row stale, and a
/// stale row is a licence nobody reviewed. Adding a row is a review event:
/// the reason must say why the transaction never writes, or why no second
/// writer can share its file.
struct Allowed {
    file: &'static str,
    /// The `fn` (or `const`) the site sits in.
    item: &'static str,
    form: Form,
    reason: &'static str,
}

const ALLOWED: &[Allowed] = &[
    Allowed {
        file: "src/store/sqlite.rs",
        item: "stream_chunks",
        form: Form::Unchecked,
        reason: "READ-ONLY: on the read door (a `SQLITE_OPEN_READ_ONLY` reader); the listing, \
                 the STH and the stream row are one snapshot (I37). It never writes, so it \
                 never upgrades.",
    },
    Allowed {
        file: "src/store/sqlite.rs",
        item: "list_trace_summaries",
        form: Form::Unchecked,
        reason: "READ-ONLY: on the read door; the two phases read one snapshot (v53.1.5). It \
                 never writes, so it never upgrades.",
    },
    Allowed {
        file: "src/store/sqlite.rs",
        item:
            "v141_rebuild_backfills_admitted_at_and_preserves_every_index_trigger_and_referrer_828",
        form: Form::BeginLiteral,
        reason: "TEST: the V004 deferred-FK witness, on a private connection to a scratch \
                 database no other connection writes.",
    },
    Allowed {
        file: "src/store/sqlite_conn_model.rs",
        item: "WRITE_VERBS",
        form: Form::BeginLiteral,
        reason: "TEST: the conn-model gate's write-verb vocabulary, a token it searches for, \
                 never SQL it runs.",
    },
    Allowed {
        file: "src/store/sqlite_write_tx_1238_invariants.rs",
        item: "deferred_begins",
        form: Form::BeginLiteral,
        reason: "TEST: this scanner's own token, the prefix it strips from each literal.",
    },
];

/// The helper, whitespace removed: it must begin `IMMEDIATE`.
const THE_HELPER: (&str, &str) = (
    "src/store/sqlite_conn_model.rs",
    "pubfnwrite_tx(conn:&mutConnection)->rusqlite::Result<rusqlite::Transaction<'_>>{\
     conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)}",
);

/// The 1-based line of byte `at` in `code`, and the `fn`/`const` item it
/// sits in (the nearest one declared before it).
fn locate(code: &str, at: usize) -> (usize, String) {
    let before = &code[..at];
    let line = before.matches('\n').count() + 1;
    let bytes = before.as_bytes();
    let mut best: Option<(usize, String)> = None;
    for kw in ["fn ", "const "] {
        let mut end = before.len();
        while let Some(p) = before[..end].rfind(kw) {
            end = p;
            let boundary =
                p == 0 || !(bytes[p - 1] == b'_' || bytes[p - 1].is_ascii_alphanumeric());
            let name: String = before[p + kw.len()..]
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if boundary && !name.is_empty() && name != "fn" {
                if best.as_ref().is_none_or(|(q, _)| p > *q) {
                    best = Some((p, name));
                }
                break;
            }
        }
    }
    (line, best.map_or_else(|| "<file>".to_owned(), |(_, n)| n))
}

/// Every deferred `BEGIN` in `src`: (line, enclosing item, form). Comments
/// are blanked, so a mention is not a call; whitespace is dropped for the
/// call forms, so a call rustfmt split over lines is still one call.
fn deferred_begins(src: &str) -> Vec<(usize, String, Form)> {
    let code = blank(src);
    // Whitespace removed, with the byte offset in `code` of each kept byte.
    let mut flat = String::with_capacity(code.len());
    let mut offset = Vec::with_capacity(code.len());
    for (i, c) in code.char_indices() {
        if !c.is_whitespace() {
            flat.push(c);
            for k in 0..c.len_utf8() {
                offset.push(i + k);
            }
        }
    }
    let mut hits = Vec::new();
    let find = |pat: &str, hits: &mut Vec<(usize, String, Form)>, form: Form| {
        let mut from = 0;
        while let Some(p) = flat[from..].find(pat) {
            let at = from + p;
            from = at + pat.len();
            let rest = &flat[from..];
            let hit = match form {
                Form::Bare => !rest.starts_with(".await"),
                Form::NotImmediate => {
                    // rustfmt may leave a trailing comma on a wrapped argument.
                    let arg = rest.split(')').next().unwrap_or("").trim_end_matches(',');
                    !(arg.ends_with("TransactionBehavior::Immediate")
                        || arg.ends_with("TransactionBehavior::Exclusive"))
                }
                _ => true,
            };
            if hit {
                let (line, item) = locate(&code, offset[at]);
                hits.push((line, item, form));
            }
        }
    };
    find(".transaction()", &mut hits, Form::Bare);
    find(".unchecked_transaction()", &mut hits, Form::Unchecked);
    find("TransactionBehavior::Deferred", &mut hits, Form::Deferred);
    find(".transaction_with_behavior(", &mut hits, Form::NotImmediate);

    // String literals: `code` keeps each literal's quotes and blanks its
    // contents (byte offsets kept), so the quotes pair up in order and
    // `src` between them is the literal's own text.
    let quotes: Vec<usize> = code
        .bytes()
        .enumerate()
        .filter(|(_, b)| *b == b'"')
        .map(|(i, _)| i)
        .collect();
    for pair in quotes.chunks_exact(2) {
        let text = src[pair[0] + 1..pair[1]].trim_start();
        let Some(after) = text.strip_prefix("BEGIN") else {
            continue;
        };
        // `BEGINNING` is a word, not a statement.
        if after
            .chars()
            .next()
            .is_some_and(|c| c == '_' || c.is_ascii_alphanumeric())
        {
            continue;
        }
        let mode = after.trim_start();
        if mode.starts_with("IMMEDIATE") || mode.starts_with("EXCLUSIVE") {
            continue;
        }
        let (line, item) = locate(&code, pair[0]);
        hits.push((line, item, Form::BeginLiteral));
    }
    hits.sort();
    hits
}

/// **I1661 — the gate.** No transaction anywhere in `src/` begins other than
/// `IMMEDIATE`, outside [`ALLOWED`]; every allowed site is present exactly
/// once; and the helper every write body begins with is pinned to
/// `Immediate`. Tests are scanned too: a test that opens a deferred write
/// transaction models a door that no longer exists.
#[test]
fn every_sqlite_write_transaction_is_immediate_1238() {
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
    let mut seen: BTreeMap<(String, String, Form), usize> = BTreeMap::new();
    let mut rusqlite_files = 0usize;
    let mut helper_pinned = false;
    let mut helper_calls_in_sqlite_rs = 0usize;
    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .expect("under root")
            .to_string_lossy()
            .replace('\\', "/");
        let src = super::tree_read::read(path);
        let flat: String = blank(&src).split_whitespace().collect();
        if flat.contains("rusqlite") {
            rusqlite_files += 1;
        }
        if rel == THE_HELPER.0 && flat.contains(THE_HELPER.1) {
            helper_pinned = true;
        }
        if rel == "src/store/sqlite.rs" {
            helper_calls_in_sqlite_rs = flat.matches("write_tx(").count();
        }
        for (line, item, form) in deferred_begins(&src) {
            if ALLOWED
                .iter()
                .any(|a| a.file == rel && a.item == item && a.form == form)
            {
                *seen.entry((rel.clone(), item, form)).or_default() += 1;
            } else {
                offenders.push(format!("  {rel}:{line} in `{item}`: {}", form.describe()));
            }
        }
    }
    super::tree_read::assert_unmoved();
    // 53 files under src/ named rusqlite when this gate was written.
    assert!(
        rusqlite_files >= 40,
        "parser floor: only {rusqlite_files} files under src/ name rusqlite — the scan \
         did not reach the sqlite backends"
    );
    assert!(
        helper_pinned,
        "CIRISPersist#1238: `{}`'s `write_tx` must be exactly \
         `conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)`",
        THE_HELPER.0
    );
    // 66 write transactions in sqlite.rs when this gate was written.
    assert!(
        helper_calls_in_sqlite_rs >= 60,
        "only {helper_calls_in_sqlite_rs} `write_tx(` calls in sqlite.rs; its write bodies \
         begin through the helper"
    );
    assert!(
        offenders.is_empty(),
        "CIRISPersist#1238: a deferred transaction that reads before it writes gets SQLITE_BUSY \
         at once when another process holds the write lock, and busy_timeout never applies. \
         Begin it with `store::sqlite_conn_model::write_tx` (BEGIN IMMEDIATE); a read-only \
         transaction on the read door belongs in ALLOWED with its reason:\n{}",
        offenders.join("\n")
    );
    let stale: Vec<String> = ALLOWED
        .iter()
        .filter_map(|a| {
            let n = seen
                .get(&(a.file.to_owned(), a.item.to_owned(), a.form))
                .copied()
                .unwrap_or(0);
            (n != 1).then(|| {
                format!(
                    "  {}::{} {:?} found {n}× ({})",
                    a.file, a.item, a.form, a.reason
                )
            })
        })
        .collect();
    assert!(
        stale.is_empty(),
        "ALLOWED rows must each match exactly one site (delete or re-file them):\n{}",
        stale.join("\n")
    );
}

/// I1661 — the scanner sees every form, split or not, names the enclosing
/// item, and ignores an awaited (tokio-postgres) `.transaction()`, the
/// helper, a mention in a comment or a string, and `BEGIN IMMEDIATE`.
#[test]
fn the_deferred_begin_scanner_reads_calls_not_mentions_1238() {
    let planted = "fn bare(conn: &mut Connection) {\n    let tx = conn\n        .transaction()?;\n}\n\
                   fn unchecked(conn: &Connection) { let tx = conn.unchecked_transaction()?; }\n\
                   fn deferred(conn: &mut Connection) {\n    let tx = conn.transaction_with_behavior(\n        \
                   rusqlite::TransactionBehavior::Deferred,\n    )?;\n}\n\
                   fn passed(conn: &mut Connection, b: TransactionBehavior) { conn.transaction_with_behavior(b)?; }\n\
                   fn literal(conn: &Connection) { conn.execute_batch(\"BEGIN; INSERT INTO t VALUES (1); COMMIT\")?; }\n\
                   const WORDS: &[&str] = &[\"BEGIN\"];\n";
    let got = deferred_begins(planted);
    let forms: Vec<(usize, &str, Form)> =
        got.iter().map(|(l, i, f)| (*l, i.as_str(), *f)).collect();
    assert_eq!(
        forms,
        vec![
            (3, "bare", Form::Bare),
            (5, "unchecked", Form::Unchecked),
            (7, "deferred", Form::NotImmediate),
            (8, "deferred", Form::Deferred),
            (11, "passed", Form::NotImmediate),
            (12, "literal", Form::BeginLiteral),
            (13, "WORDS", Form::BeginLiteral),
        ],
        "{got:?}"
    );

    let clean = "fn pg(client: &mut Client) {\n    let tx = client\n        .transaction()\n        .await?;\n}\n\
                 fn helper(conn: &mut Connection) { let tx = write_tx(conn)?; }\n\
                 fn immediate(conn: &mut Connection) {\n    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;\n    \
                 conn.execute_batch(\"BEGIN IMMEDIATE\")?;\n    conn.execute_batch(\"  BEGIN EXCLUSIVE;\")?;\n}\n\
                 fn mentions() {\n    // conn.transaction()? and \"BEGIN\"\n    /* conn.unchecked_transaction() */\n    \
                 let s = \"conn.transaction()\";\n    let t = \"BEGINNING\";\n    let u = \"begin tx\";\n    \
                 let v = client.build_transaction();\n}\n";
    assert_eq!(deferred_begins(clean), Vec::new());
}

// ── I1660: two connections, one file ──────────────────────────────────────

#[cfg(feature = "sqlite")]
mod behaviour {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::attestation_type;
    use crate::federation::{FederationDirectory, SignedAttestation};
    use crate::store::backend::Backend;
    use crate::store::sqlite::SqliteBackend;
    use std::time::{Duration, Instant};

    /// How long the other connection holds the write lock.
    const HOLD: Duration = Duration::from_millis(1_000);

    /// A real file: two connections must share one database, which an
    /// in-memory database cannot give them.
    fn temp_db_path(tag: &str) -> (std::path::PathBuf, String) {
        let dir = std::env::temp_dir().join(format!("ciris-1238-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("I1660 temp dir");
        let db = dir.join("store.db").to_string_lossy().into_owned();
        (dir, db)
    }

    async fn migrated(tag: &str) -> (std::path::PathBuf, String, SqliteBackend) {
        let (dir, path) = temp_db_path(tag);
        let backend = SqliteBackend::open(&path).await.expect("I1660 open");
        backend.run_migrations().await.expect("I1660 migrate");
        (dir, path, backend)
    }

    /// Another connection to `path` — not the backend's writer, so the
    /// backend's mutex does not serialize it: the file lock is all there is,
    /// as between two processes — takes `BEGIN IMMEDIATE` on its own thread
    /// and holds it for `hold`. Returns the instant the lock was HELD and a
    /// handle yielding the instant just before it was released.
    fn hold_write_lock(path: &str, hold: Duration) -> (Instant, std::thread::JoinHandle<Instant>) {
        let path = path.to_owned();
        let (tx, rx) = std::sync::mpsc::channel::<Instant>();
        let h = std::thread::spawn(move || {
            let conn = rusqlite::Connection::open(&path).expect("I1660 holder opens the file");
            conn.execute_batch("BEGIN IMMEDIATE")
                .expect("I1660 holder takes the write lock");
            tx.send(Instant::now()).expect("I1660 signal");
            std::thread::sleep(hold);
            let released = Instant::now();
            conn.execute_batch("COMMIT").expect("I1660 holder commits");
            released
        });
        let held_at = rx.recv().expect("I1660 holder held the lock");
        (held_at, h)
    }

    /// The door completed only after the holder let go, having waited at
    /// least the hold — the busy handler ran.
    fn assert_waited(door: &str, held_at: Instant, released: Instant, done: Instant) {
        assert!(
            done >= released,
            "I1660 {door}: completed before the other connection released its write lock"
        );
        assert!(
            done.duration_since(held_at) >= HOLD,
            "I1660 {door}: completed {:?} after the lock was taken, under the {HOLD:?} hold",
            done.duration_since(held_at)
        );
    }

    /// **I1660 (the key-record door)** — `put_public_key` plans, then
    /// `store_planned_key_record` reads `sqlite_next_key_serve_position` and
    /// INSERTs in one transaction: the read-then-write Edge's
    /// `register_self_federation_key` fails. With another connection holding
    /// the write lock, it waits the lock out and lands. RED (`database is
    /// locked`, in about a millisecond) when `write_tx` begins deferred.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn i1660_a_read_then_write_key_record_waits_out_a_held_write_lock() {
        let (dir, path, backend) = migrated("key").await;
        let key = "i1660-fresh-key";

        let (held_at, holder) = hold_write_lock(&path, HOLD);
        // Panics with the backend error (SQLITE_BUSY, "database is locked")
        // if the door failed instead of waiting.
        ts::register_hybrid_key(&backend, key).await;
        let done = Instant::now();
        let released = holder.join().expect("I1660 holder thread");
        assert_waited("key record", held_at, released, done);

        // Fully qualified: `Backend` has a `lookup_public_key` too.
        let held = FederationDirectory::lookup_public_key(&backend, key)
            .await
            .expect("I1660 lookup")
            .expect("I1660: the key record landed");
        assert_eq!(held.key_id, key);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// **I1660 (the attestation door)** — `put_attestation` on the same
    /// shape: the attester is registered before the hold, the row is put
    /// during it, and it lands after the wait.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn i1660_put_attestation_waits_out_a_held_write_lock() {
        let (dir, path, backend) = migrated("attestation").await;
        let attester = "i1660-attester";
        ts::register_hybrid_key(&backend, attester).await;

        let id = uuid::Uuid::new_v4().to_string();
        let env = serde_json::json!({ "dimension": "i1660:probe:v1", "n": id });
        let mut row = ts::bare_attestation(&id, attester, attester, &env);
        row.attestation_type = attestation_type::SCORES.into();
        row.weight = None;
        // A whole-second instant a minute back, as the #1225 fixture does.
        let when =
            chrono::DateTime::<chrono::Utc>::from_timestamp(chrono::Utc::now().timestamp() - 60, 0)
                .expect("I1660 instant");
        row.asserted_at = when;
        row.scrub_timestamp = when;
        row.subject_key_ids = vec!["i1660-subject".to_owned()];
        ts::seal_row_in_place(attester, &mut row);

        let (held_at, holder) = hold_write_lock(&path, HOLD);
        let put =
            FederationDirectory::put_attestation(&backend, SignedAttestation { attestation: row })
                .await;
        let done = Instant::now();
        let released = holder.join().expect("I1660 holder thread");
        if let Err(e) = &put {
            panic!(
                "I1660 attestation: the door failed after {:?} instead of waiting out the \
                 held write lock: {e}",
                done.duration_since(held_at)
            );
        }
        assert_waited("attestation", held_at, released, done);

        assert!(
            FederationDirectory::get_attestation(&backend, &id)
                .await
                .expect("I1660 read back")
                .is_some(),
            "I1660: the attestation landed"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
