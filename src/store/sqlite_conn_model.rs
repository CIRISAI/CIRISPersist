//! **The SQLite connection model** (CIRISPersist#829) —
//! `FSD/SQLITE_CONNECTION_MODEL.md`.
//!
//! One writer connection (the `Arc<Mutex<Connection>>` `sqlite.rs` has
//! always had) plus a pool of `N` read-only connections under WAL, and every
//! call — read or write, and the *wait* for its connection — dispatched off
//! the tokio worker onto the blocking pool **when a runtime is current**,
//! inline otherwise. The "otherwise" is CIRISPersist#158's property, kept:
//! a cohabiting consumer's statically-linked copy of persist runs on a
//! foreign worker whose tokio thread-local is unset, and `spawn_blocking`
//! there panics where `Handle::try_current()` merely says no.
//!
//! The classification table ([`SQLITE_CONN_CLASSES`]) and the from-disk gate
//! that enforces it live in the test module below. The gate is a partition
//! in both directions over every production `fn` in `sqlite.rs` that touches
//! a connection: nothing may be unclassified, nothing filed as a `Read` may
//! reach the writer or a write verb, and no row may name an fn that no
//! longer exists. `SQLITE_OPEN_READ_ONLY` on every reader is the dynamic
//! net under the static one — a misfiled write fails loudly in the first
//! test that reaches it instead of writing on the wrong connection.

// ── the classification table and its gate ─────────────────────────────────

/// Which connection a production `fn` in `sqlite.rs` is allowed to reach.
/// FSD/SQLITE_CONNECTION_MODEL.md §5.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnClass {
    /// `self.read(…)` only. Never the writer, never a write verb.
    Read,
    /// `self.write(…)`. May also `self.read(…)` for a non-atomic pre-check.
    Write,
    /// Free fn taking `&Connection`, called from inside a closure; no write
    /// verb in its body.
    HelperRead,
    /// Free fn taking a connection or transaction that writes. May only be
    /// called from a `Write` body.
    HelperWrite,
}

/// **The table.** Every production `fn` in `src/store/sqlite.rs` that touches
/// a connection, by name, with its class. Keyed by name: where a name occurs
/// twice (`lookup_public_key`, `list_attestations_for`) every occurrence
/// must carry the same class, and the gate checks each occurrence.
///
/// Filed by what the body does, not what the name says (§5): `has_blob`,
/// `get_blob` and `get_blob_range` bump `access_count` inside a transaction
/// and are `Write`.
#[cfg(test)]
pub(crate) const SQLITE_CONN_CLASSES: &[(&str, ConnClass)] = &[];

#[cfg(test)]
mod gate {
    use super::{ConnClass, SQLITE_CONN_CLASSES};
    use std::collections::{BTreeMap, BTreeSet};

    fn sqlite_rs() -> String {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/store/sqlite.rs");
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    /// The production text: everything before the first column-0
    /// `#[cfg(test)]`. `sqlite.rs` keeps every test module at the end of the
    /// file, and the parser floor below (`PARSER_FLOOR`) is what stops this
    /// cut from ever returning an empty universe and passing vacuously.
    fn production_text(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for line in text.lines() {
            if line.starts_with("#[cfg(test)]") {
                break;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// One production `fn`: name, 1-based first line, indent, and body text
    /// with `//` comment lines removed.
    #[derive(Debug)]
    pub(super) struct Func {
        pub name: String,
        pub line: usize,
        pub indent: usize,
        pub body: String,
    }

    fn fn_header(line: &str) -> Option<(usize, String)> {
        let indent = line.len() - line.trim_start().len();
        let mut t = line.trim_start();
        for prefix in ["pub(crate) ", "pub(super) ", "pub "] {
            if let Some(rest) = t.strip_prefix(prefix) {
                t = rest;
            }
        }
        if let Some(rest) = t.strip_prefix("async ") {
            t = rest;
        }
        let rest = t.strip_prefix("fn ")?;
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        (!name.is_empty()).then_some((indent, name))
    }

    /// Every production fn with a body, in source order.
    pub(super) fn functions(prod: &str) -> Vec<Func> {
        let lines: Vec<&str> = prod.lines().collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let Some((indent, name)) = fn_header(lines[i]) else {
                i += 1;
                continue;
            };
            // Signature ends on the first line ending in `{`; a line ending
            // in `;` first means a bodiless declaration.
            let mut j = i;
            let mut body_start = None;
            while j < lines.len() {
                let l = lines[j].trim_end();
                if l.ends_with('{') {
                    body_start = Some(j);
                    break;
                }
                if l.ends_with(';') {
                    break;
                }
                j += 1;
            }
            let Some(bs) = body_start else {
                i += 1;
                continue;
            };
            let mut depth: i64 = 0;
            let mut k = bs;
            while k < lines.len() {
                depth +=
                    lines[k].matches('{').count() as i64 - lines[k].matches('}').count() as i64;
                if depth <= 0 {
                    break;
                }
                k += 1;
            }
            let body = lines[i..=k.min(lines.len() - 1)]
                .iter()
                .filter(|l| !l.trim_start().starts_with("//"))
                .map(|l| format!("{l}\n"))
                .collect();
            out.push(Func {
                name,
                line: i + 1,
                indent,
                body,
            });
            i = k + 1;
        }
        out
    }

    /// The tokens by which a body reaches a connection at all.
    const TOUCH: &[&str] = &[
        "self.conn",
        "conn.lock()",
        "conn_handle()",
        "conn: &Connection",
        "conn: &mut Connection",
        "conn: &rusqlite::Connection",
        "conn: &mut rusqlite::Connection",
        "Arc<Mutex<Connection>>",
        "tx: &Transaction",
        "tx: &rusqlite::Transaction",
        "self.read(",
        "self.write(",
        "self.readers",
    ];

    /// The tokens that mean "this body writes". Case-sensitive on purpose:
    /// the SQL in this file is upper-case, the enum values that share a
    /// spelling (`'deletes'`, `'update'`) are not.
    const WRITE_VERBS: &[&str] = &[
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        "REPLACE ",
        "CREATE ",
        "DROP ",
        "ALTER ",
        "VACUUM",
        ".execute(",
        ".transaction(",
        "execute_batch(",
        "unchecked_transaction(",
        "BEGIN",
        "COMMIT",
    ];

    /// The writer path, which a `Read` may never mention.
    const WRITER_TOKENS: &[&str] = &["self.conn", "conn.lock()", "conn_handle()", "self.write("];

    pub(super) fn touches_connection(body: &str) -> bool {
        TOUCH.iter().any(|t| body.contains(t))
    }

    pub(super) fn write_verb_in(body: &str) -> Option<&'static str> {
        WRITE_VERBS.iter().copied().find(|v| body.contains(v))
    }

    /// Parser floor. `sqlite.rs` had 404 production fns and 285 that touch a
    /// connection when this gate was written; a parser that finds far fewer
    /// has broken, and a broken parser must red the build rather than
    /// report an empty universe as "all classified".
    const PARSER_FLOOR: (usize, usize) = (350, 250);

    pub(super) fn universe() -> Vec<Func> {
        let prod = production_text(&sqlite_rs());
        let all = functions(&prod);
        assert!(
            all.len() >= PARSER_FLOOR.0,
            "parser floor: found only {} production fns in sqlite.rs (floor {})",
            all.len(),
            PARSER_FLOOR.0
        );
        let touching: Vec<Func> = all
            .into_iter()
            .filter(|f| touches_connection(&f.body))
            .collect();
        assert!(
            touching.len() >= PARSER_FLOOR.1,
            "parser floor: found only {} connection-touching fns (floor {})",
            touching.len(),
            PARSER_FLOOR.1
        );
        touching
    }

    fn table() -> BTreeMap<&'static str, ConnClass> {
        let mut m = BTreeMap::new();
        for (name, class) in SQLITE_CONN_CLASSES {
            assert!(
                m.insert(*name, *class).is_none(),
                "SQLITE_CONN_CLASSES lists `{name}` twice"
            );
        }
        m
    }

    // ── I4: the partition, both directions ──────────────────────────────

    #[test]
    fn every_connection_touching_fn_in_sqlite_rs_is_classified() {
        let table = table();
        let missing: Vec<String> = universe()
            .iter()
            .filter(|f| !table.contains_key(f.name.as_str()))
            .map(|f| format!("  sqlite.rs:{} {}", f.line, f.name))
            .collect();
        assert!(
            missing.is_empty(),
            "{} production fn(s) in sqlite.rs touch a connection and are not in \
             SQLITE_CONN_CLASSES (FSD/SQLITE_CONNECTION_MODEL.md §5):\n{}",
            missing.len(),
            missing.join("\n")
        );
    }

    #[test]
    fn no_conn_class_row_is_stale() {
        let names: BTreeSet<String> = universe().into_iter().map(|f| f.name).collect();
        let stale: Vec<&str> = SQLITE_CONN_CLASSES
            .iter()
            .map(|(n, _)| *n)
            .filter(|n| !names.contains(*n))
            .collect();
        assert!(
            stale.is_empty(),
            "SQLITE_CONN_CLASSES names fn(s) that no longer touch a connection in \
             sqlite.rs (delete the row or re-file it): {stale:?}"
        );
    }

    #[test]
    fn every_read_is_on_the_reader_path_and_writes_nothing() {
        let table = table();
        let helper_writes: Vec<&str> = SQLITE_CONN_CLASSES
            .iter()
            .filter(|(_, c)| *c == ConnClass::HelperWrite)
            .map(|(n, _)| *n)
            .collect();
        let mut bad = Vec::new();
        for f in universe() {
            if table.get(f.name.as_str()) != Some(&ConnClass::Read) {
                continue;
            }
            if !f.body.contains("self.read(") {
                bad.push(format!("  {}:{} does not use self.read(", f.name, f.line));
            }
            for t in WRITER_TOKENS {
                if f.body.contains(t) {
                    bad.push(format!(
                        "  {}:{} reaches the writer via `{t}`",
                        f.name, f.line
                    ));
                }
            }
            if let Some(v) = write_verb_in(&f.body) {
                bad.push(format!(
                    "  {}:{} contains write verb `{}`",
                    f.name,
                    f.line,
                    v.trim()
                ));
            }
            for h in &helper_writes {
                if f.body.contains(&format!("{h}(")) {
                    bad.push(format!("  {}:{} calls HelperWrite `{h}`", f.name, f.line));
                }
            }
        }
        assert!(
            bad.is_empty(),
            "{} Read-classified fn(s) in sqlite.rs are not pure reads on the reader path:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }

    #[test]
    fn every_write_is_on_the_writer_path_and_helpers_are_what_they_say() {
        let table = table();
        let mut bad = Vec::new();
        for f in universe() {
            match table.get(f.name.as_str()) {
                Some(ConnClass::Write) => {
                    if !f.body.contains("self.write(") {
                        bad.push(format!(
                            "  Write {}:{} does not use self.write(",
                            f.name, f.line
                        ));
                    }
                }
                Some(ConnClass::HelperRead) => {
                    if f.indent != 0 {
                        bad.push(format!(
                            "  HelperRead {}:{} is not a free fn",
                            f.name, f.line
                        ));
                    }
                    if let Some(v) = write_verb_in(&f.body) {
                        bad.push(format!(
                            "  HelperRead {}:{} contains write verb `{}`",
                            f.name,
                            f.line,
                            v.trim()
                        ));
                    }
                }
                Some(ConnClass::HelperWrite) if f.indent != 0 => {
                    bad.push(format!(
                        "  HelperWrite {}:{} is not a free fn",
                        f.name, f.line
                    ));
                }
                _ => {}
            }
        }
        assert!(bad.is_empty(), "{}", bad.join("\n"));
    }

    /// The four classes are the whole alphabet; the table may use nothing
    /// else, and a class nobody files under is a class the gate does not
    /// exercise — this is the row that says so out loud.
    #[test]
    fn the_class_alphabet_is_the_four_documented_classes() {
        const ALL: [ConnClass; 4] = [
            ConnClass::Read,
            ConnClass::Write,
            ConnClass::HelperRead,
            ConnClass::HelperWrite,
        ];
        for (name, class) in SQLITE_CONN_CLASSES {
            assert!(
                ALL.contains(class),
                "`{name}` filed under unknown class {class:?}"
            );
        }
    }

    /// The only door to a connection is the dispatcher: no production line
    /// in `sqlite.rs` locks the writer directly. The handle accessors
    /// (`conn_handle`, `from_conn_handle`) clone the `Arc`; they never lock.
    #[test]
    fn no_production_line_in_sqlite_rs_locks_a_connection_directly() {
        let prod = production_text(&sqlite_rs());
        let hits: Vec<String> = prod
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim_start().starts_with("//"))
            .filter(|(_, l)| l.contains("conn.lock()") || l.contains("conn_handle().lock()"))
            .map(|(i, l)| format!("  sqlite.rs:{} {}", i + 1, l.trim()))
            .collect();
        assert!(
            hits.is_empty(),
            "{} production line(s) in sqlite.rs lock a connection directly instead of \
             going through SqliteBackend::read / ::write:\n{}",
            hits.len(),
            hits.join("\n")
        );
    }
}

// ── the behavioural witnesses ─────────────────────────────────────────────

#[cfg(test)]
mod witnesses {
    use crate::federation::FederationDirectory;
    use crate::store::backend::Backend;
    use crate::store::sqlite::SqliteBackend;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    pub(super) fn temp_db_path(tag: &str) -> String {
        let dir = std::env::temp_dir().join(format!("ciris-829-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("store.db").to_string_lossy().into_owned()
    }

    /// Hold the WRITER mutex from a plain thread for `hold`, signalling once
    /// it is held. This is the CIRISEdge#547 shape: the connection holder is
    /// off in a page fault and everyone else is behind it.
    fn hold_writer(backend: &SqliteBackend, hold: Duration) -> std::thread::JoinHandle<()> {
        let writer = backend.conn_handle();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let h = std::thread::spawn(move || {
            let guard = writer.lock();
            tx.send(()).unwrap();
            std::thread::sleep(hold);
            drop(guard);
        });
        rx.recv().unwrap();
        h
    }

    async fn point_read(backend: &SqliteBackend) {
        let got = FederationDirectory::get_attestation(backend, "absent-829")
            .await
            .expect("point read");
        assert!(got.is_none());
    }

    // ── I2 ─────────────────────────────────────────────────────────────
    /// With the writer connection held for 2 s, a read completes in well
    /// under that. Before #829 the read is the same connection, so it takes
    /// the full 2 s (and blocks its worker for all of it).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_completes_while_the_writer_connection_is_held() {
        let path = temp_db_path("held-writer");
        let backend = SqliteBackend::open(&path).await.unwrap();
        backend.run_migrations().await.unwrap();

        let holder = hold_writer(&backend, Duration::from_secs(2));
        let t0 = Instant::now();
        point_read(&backend).await;
        let took = t0.elapsed();
        holder.join().unwrap();
        assert!(
            took < Duration::from_millis(750),
            "a read waited {took:?} behind the held writer connection — the read pool is \
             not serving reads (FSD/SQLITE_CONNECTION_MODEL.md I2)"
        );
    }

    // ── I3 (zero-reader arm) ───────────────────────────────────────────
    /// One worker thread. A read that must WAIT for the writer (in-memory
    /// has no readers, so this is the fallback arm) must not stall the
    /// runtime: a 10 ms sleep spawned alongside it fires within 250 ms.
    /// Before #829 the wait is a `parking_lot` lock on the only worker, and
    /// the timer cannot be polled until the read returns ~1 s later.
    #[test]
    fn runtime_keeps_spinning_while_an_in_memory_read_waits_on_the_writer() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let backend = Arc::new(SqliteBackend::open_in_memory().await.unwrap());
            backend.run_migrations().await.unwrap();
            let holder = hold_writer(&backend, Duration::from_secs(1));

            let t0 = Instant::now();
            let read = tokio::spawn({
                let b = backend.clone();
                async move {
                    point_read(&b).await;
                    t0.elapsed()
                }
            });
            let tick = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                t0.elapsed()
            });
            let fired = tick.await.unwrap();
            let read_took = read.await.unwrap();
            holder.join().unwrap();
            assert!(
                read_took >= Duration::from_millis(900),
                "premise: the read was supposed to wait behind the held writer, took {read_took:?}"
            );
            assert!(
                fired < Duration::from_millis(250),
                "a 10 ms sleep fired after {fired:?} — the read's wait for the connection \
                 stalled the runtime's only worker (FSD/SQLITE_CONNECTION_MODEL.md I3)"
            );
        });
    }

    // ── I5 (#158 preserved) ────────────────────────────────────────────
    /// A read and a write driven with NO tokio runtime on the thread both
    /// complete. This is the property v3.14.0 bought by going inline, and it
    /// must survive the dispatcher: `Handle::try_current()` says no, the
    /// call runs inline.
    fn block_on_without_a_runtime<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn noop_raw() -> RawWaker {
            fn clone(_: *const ()) -> RawWaker {
                noop_raw()
            }
            fn noop(_: *const ()) {}
            static VT: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
            RawWaker::new(std::ptr::null(), &VT)
        }
        // SAFETY: the vtable functions are all no-ops over a null data
        // pointer; nothing is dereferenced.
        #[allow(unsafe_code)]
        let waker = unsafe { Waker::from_raw(noop_raw()) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn sqlite_path_runs_with_no_tokio_runtime_on_the_thread() {
        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "premise: this test must run with no runtime current"
        );
        let path = temp_db_path("no-runtime");
        block_on_without_a_runtime(async {
            let backend = SqliteBackend::open(&path).await.unwrap();
            backend.run_migrations().await.unwrap();
            point_read(&backend).await;
            // A write, too — the dispatcher is one function for both.
            let lease = FederationDirectory::try_acquire_shared_instance(
                &backend,
                "reticulum:829",
                std::process::id() as i32,
                "no-runtime-host",
                None,
            )
            .await
            .expect("write with no runtime");
            assert!(lease.is_some(), "first acquire wins");
        });
    }
}
