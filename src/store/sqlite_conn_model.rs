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

use std::sync::Arc;

use parking_lot::{Condvar, Mutex};
use rusqlite::{Connection, OpenFlags};

// ── the read pool ─────────────────────────────────────────────────────────

/// Environment override for the reader count consulted by
/// [`crate::store::sqlite::SqliteBackend::open`]. `0` is legal and means
/// "no pool": reads fall back to the writer mutex, still off the runtime.
/// It exists so an operator can A/B the pool without a rebuild and so a
/// defect in the pool has a one-line kill switch (FSD §3.2).
pub const READERS_ENV: &str = "CIRIS_PERSIST_SQLITE_READERS";

/// Prepared statements each reader keeps. Sized for the shapes a node cycles
/// through: on a production-sized canonical copy `sqlite3_prepare_v2` was 24% of
/// CPU, because the hot attestation reads re-parsed the same text on each call.
const READER_STATEMENT_CACHE: usize = 128;

// ── page cache and mmap (CIRISPersist#1246) ────────────────────────────────

/// Environment override for every connection's `PRAGMA mmap_size`, in bytes.
/// `0` turns memory-mapped reads off. A value that does not parse as a `u64`
/// refuses the open: a typo must not silently become the default.
pub const MMAP_BYTES_ENV: &str = "CIRIS_PERSIST_SQLITE_MMAP_BYTES";

/// Environment override for every connection's page cache, in KiB (applied
/// as `PRAGMA cache_size = -<KiB>`). Must parse as a `u32` of at least 1;
/// anything else refuses the open.
pub const CACHE_KIB_ENV: &str = "CIRIS_PERSIST_SQLITE_CACHE_KIB";

/// The mmap ceiling when the process has no tighter memory limit: 1 GiB.
pub const DEFAULT_MMAP_BYTES: u64 = 1 << 30;

/// The page cache per connection: 32 MiB. SQLite's default is about 2 MB,
/// so on canonical-1 (a multi-GB store, 4 readers) `sqlite3_step` re-read
/// its pages from the OS page cache through `pread`: 11–15% of CPU in
/// `__x64_sys_pread64` (#1246). The cache is allocated as pages are read,
/// not at open; the ceiling is `(readers + 1) × 32 MiB`.
pub const DEFAULT_CACHE_KIB: u32 = 32 * 1024;

/// The tuning every SqliteBackend connection (each reader and the writer)
/// applies at open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliteTuning {
    /// `PRAGMA mmap_size`, bytes. SQLite clamps it to its compile-time
    /// `SQLITE_MAX_MMAP_SIZE` and to the file's size.
    pub mmap_bytes: u64,
    /// `PRAGMA cache_size = -cache_kib`.
    pub cache_kib: u32,
}

/// The default mmap size for a process whose memory limit is `limit` bytes:
/// [`DEFAULT_MMAP_BYTES`], or a quarter of the limit when that is smaller.
/// Mapped pages are page cache, which a pread-based read also fills and the
/// container is charged for either way; the quarter keeps a small container
/// (canonical-1 runs in 2 GiB: 512 MiB) from holding most of its limit in
/// mapped pages it has to reclaim from.
pub fn default_mmap_bytes(limit: Option<u64>) -> u64 {
    match limit {
        Some(l) => DEFAULT_MMAP_BYTES.min(l / 4),
        None => DEFAULT_MMAP_BYTES,
    }
}

/// This process's cgroup memory limit, if it has one: cgroup v2
/// `memory.max` for its own cgroup (or the namespace root, as inside a
/// container), else cgroup v1 `memory.limit_in_bytes`. `None` on non-Linux,
/// when unlimited, or when nothing can be read.
pub fn cgroup_memory_limit() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        fn read_limit(path: &str) -> Option<u64> {
            let text = std::fs::read_to_string(path).ok()?;
            let t = text.trim();
            if t == "max" {
                return None;
            }
            let n: u64 = t.parse().ok()?;
            // cgroup v1 reports "unlimited" as a page-rounded i64::MAX.
            (n < (1u64 << 62)).then_some(n)
        }
        if let Ok(cg) = std::fs::read_to_string("/proc/self/cgroup") {
            if let Some(rel) = cg.lines().find_map(|l| l.strip_prefix("0::")) {
                let rel = rel.trim().trim_end_matches('/');
                if !rel.is_empty() {
                    if let Some(n) = read_limit(&format!("/sys/fs/cgroup{rel}/memory.max")) {
                        return Some(n);
                    }
                }
            }
        }
        read_limit("/sys/fs/cgroup/memory.max")
            .or_else(|| read_limit("/sys/fs/cgroup/memory/memory.limit_in_bytes"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Resolve the tuning from the two knobs (`mmap` for [`MMAP_BYTES_ENV`],
/// `cache` for [`CACHE_KIB_ENV`]) and the process memory limit. Pure, so the
/// rules are witnessed without touching the environment.
pub fn resolve_tuning(
    mmap: Option<&str>,
    cache: Option<&str>,
    limit: Option<u64>,
) -> Result<SqliteTuning, String> {
    let mmap_bytes = match mmap {
        None => default_mmap_bytes(limit),
        Some(v) => v.trim().parse::<u64>().map_err(|_| {
            format!("{MMAP_BYTES_ENV}={v:?} is not a byte count (a u64; 0 turns mmap off)")
        })?,
    };
    let cache_kib = match cache {
        None => DEFAULT_CACHE_KIB,
        Some(v) => match v.trim().parse::<u32>() {
            Ok(n) if n >= 1 => n,
            _ => {
                return Err(format!(
                    "{CACHE_KIB_ENV}={v:?} is not a page-cache size (a KiB count of at least 1)"
                ))
            }
        },
    };
    Ok(SqliteTuning {
        mmap_bytes,
        cache_kib,
    })
}

/// [`resolve_tuning`] from this process's environment and cgroup limit.
pub fn tuning_from_env() -> Result<SqliteTuning, String> {
    let mmap = std::env::var(MMAP_BYTES_ENV).ok();
    let cache = std::env::var(CACHE_KIB_ENV).ok();
    resolve_tuning(mmap.as_deref(), cache.as_deref(), cgroup_memory_limit())
}

/// Apply `t` to one connection. Both are per-connection state.
pub fn apply_tuning(conn: &Connection, t: &SqliteTuning) -> Result<(), rusqlite::Error> {
    conn.execute_batch(&format!(
        "PRAGMA mmap_size = {};\nPRAGMA cache_size = -{};",
        t.mmap_bytes, t.cache_kib
    ))
}

/// FSD §3.2 — `available_parallelism().clamp(2, 8)`, or [`READERS_ENV`].
pub fn default_reader_count() -> usize {
    if let Some(n) = std::env::var(READERS_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
    {
        return n;
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .clamp(2, 8)
}

/// `N` read-only connections to one SQLite file, handed out one at a time.
///
/// A free list under a `parking_lot::Mutex` plus a `Condvar`; `acquire`
/// blocks the calling thread until a connection is free, which is why it
/// is only ever called from inside [`dispatch_blocking`]'s closure. No
/// tokio primitive is involved so it works with no runtime on the thread.
///
/// `size() == 0` is the in-memory / borrowed-handle case (FSD §4): there is
/// nothing to acquire and the backend reads on its writer instead.
pub struct ReadPool {
    free: Mutex<Vec<Connection>>,
    available: Condvar,
    size: usize,
}

impl std::fmt::Debug for ReadPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadPool")
            .field("size", &self.size)
            .field("idle", &self.idle())
            .finish()
    }
}

/// CIRISPersist#1261 — make the writer create the WAL's `-wal` and `-shm`
/// files before any read-only reader opens. `journal_mode = WAL` alone does
/// not create them; the first connection to TOUCH the database does. On
/// Linux a read-only reader may create them itself, but Apple's SQLite
/// (macOS, iOS) refuses: the reader's first file access fails with
/// SQLITE_CANTOPEN, errno ENOENT. 61.2.2 made that access happen inside
/// [`ReadPool::open`] (#1246's per-reader `cache_size`), so every
/// file-backed open failed on macOS. One read on the writer opens the WAL
/// index and leaves both files in place for as long as the writer lives.
pub fn materialize_wal(writer: &Connection) -> rusqlite::Result<()> {
    writer
        .query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        })
        .map(|_| ())
}

/// The `sqlite open readers` error: reader index, step, SQLite's extended
/// result code, path. (The OS errno would need `sqlite3_system_errno` on the
/// raw handle, which is `unsafe`; persist is `#![deny(unsafe_code)]`.)
fn reader_open_error(reader: usize, step: &str, path: &str, e: &rusqlite::Error) -> String {
    let ext = match e {
        rusqlite::Error::SqliteFailure(f, _) => f.extended_code.to_string(),
        _ => "n/a".to_string(),
    };
    format!("reader {reader} {step}: {e} (extended code {ext}, path {path:?})")
}

impl ReadPool {
    /// A pool with no readers. Reads on a backend holding this pool go to
    /// the writer.
    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            free: Mutex::new(Vec::new()),
            available: Condvar::new(),
            size: 0,
        })
    }

    /// Open `n` read-only connections to `path`. The writer MUST already
    /// be open and have set `journal_mode = WAL`: a read-only connection
    /// cannot change the journal mode, and a reader that opened first would
    /// find a rollback-journal database and hold every later writer to it.
    ///
    /// Per-connection PRAGMAs are re-applied here because they are
    /// per-connection state (`foreign_keys` is the one people forget);
    /// `query_only = ON` is a second fence behind `SQLITE_OPEN_READ_ONLY`.
    ///
    /// CIRISPersist#1261 — the caller must also have run
    /// [`materialize_wal`] on the writer: a read-only connection cannot
    /// create the `-wal`/`-shm` files on Apple's SQLite.
    ///
    /// The error names the reader, the step that failed, SQLite's extended
    /// result code and the path.
    pub fn open(path: &str, n: usize, tuning: &SqliteTuning) -> Result<Arc<Self>, String> {
        let mut free = Vec::with_capacity(n);
        for i in 0..n {
            let conn = Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_URI,
            )
            .map_err(|e| reader_open_error(i, "open", path, &e))?;
            let step = |what: &'static str, r: rusqlite::Result<()>| {
                r.map_err(|e| reader_open_error(i, what, path, &e))
            };
            step(
                "pragmas",
                conn.execute_batch(
                    "PRAGMA foreign_keys = ON;\n\
                     PRAGMA busy_timeout = 30000;\n\
                     PRAGMA query_only = ON;",
                ),
            )?;
            // #1246 — page cache and mmap, the same as the writer's.
            step("tuning", apply_tuning(&conn, tuning))?;
            // #784 — per-connection state, like the pragmas above.
            step(
                "key_digest fn",
                crate::federation::key_digest::register_sqlite_fn(&conn),
            )?;
            // A rendered attestation query varies by shape, not by value, so
            // its text repeats. The cache must hold every live shape or a
            // cycling read re-parses each call; rusqlite's default is 16.
            conn.set_prepared_statement_cache_capacity(READER_STATEMENT_CACHE);
            free.push(conn);
        }
        Ok(Arc::new(Self {
            free: Mutex::new(free),
            available: Condvar::new(),
            size: n,
        }))
    }

    /// Number of reader connections this pool was opened with.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Readers not currently checked out. Diagnostic; racy by nature.
    pub fn idle(&self) -> usize {
        self.free.lock().len()
    }

    /// Check out a reader, blocking the calling thread until one is free.
    ///
    /// # Panics
    /// On an empty pool (`size() == 0`) — the backend never calls this on
    /// one, and a caller that does has mis-wired the fallback.
    pub fn acquire(&self) -> ReadGuard<'_> {
        assert!(self.size > 0, "ReadPool::acquire on an empty pool");
        let mut free = self.free.lock();
        while free.is_empty() {
            self.available.wait(&mut free);
        }
        let conn = free.pop().expect("non-empty after wait");
        ReadGuard {
            pool: self,
            conn: Some(conn),
        }
    }
}

/// A checked-out reader; returns itself to the pool on drop.
pub struct ReadGuard<'a> {
    pool: &'a ReadPool,
    conn: Option<Connection>,
}

impl std::ops::Deref for ReadGuard<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("reader present until drop")
    }
}

impl Drop for ReadGuard<'_> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            // FSD §3.5 — a reader that goes back with a transaction open is
            // a reader pinning a WAL snapshot against every checkpoint. No
            // read closure opens one; this is the assertion that keeps it so.
            debug_assert!(
                conn.is_autocommit(),
                "a read closure returned its reader with a transaction open"
            );
            let mut free = self.pool.free.lock();
            free.push(conn);
            drop(free);
            self.pool.available.notify_one();
        }
    }
}

// ── the dispatcher ────────────────────────────────────────────────────────

/// Run `f` off the async runtime when there is one, inline when there is
/// not (FSD §3.3).
///
/// `Handle::try_current()` is the same thread-local read
/// `tokio::task::spawn_blocking` performs, but it returns `Err` where
/// `spawn_blocking` panics with `there is no reactor running`. That is the
/// whole of CIRISPersist#158's concern, answered: a cohabiting consumer's
/// statically-linked copy of persist on a foreign worker takes the inline
/// arm, exactly as v3.14.0 → v43.0.0 always did.
///
/// A panic inside `f` is re-raised on the caller (`resume_unwind`) so the
/// observable behaviour matches the inline arm. A join cancelled by runtime
/// shutdown has no value to return; it panics naming the cause, and the
/// caller's task is being torn down regardless.
pub async fn dispatch_blocking<R, F>(f: F) -> R
where
    R: Send + 'static,
    F: FnOnce() -> R + Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.spawn_blocking(f).await {
            Ok(r) => r,
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => panic!("sqlite blocking task cancelled by runtime shutdown: {e}"),
        },
        Err(_) => f(),
    }
}

// ── the write transaction ─────────────────────────────────────────────────

/// CIRISPersist#1238 — **the one way a SQLite write transaction begins:
/// `BEGIN IMMEDIATE`.**
///
/// rusqlite's `Connection::transaction()` is `BEGIN DEFERRED`: the
/// transaction takes no lock until its first statement, and a read-then-write
/// body (`store_planned_key_record` reads `sqlite_next_key_serve_position`,
/// then INSERTs) holds a SHARED read snapshot when it reaches the write.
/// SQLite does not run the busy handler for that read-to-write upgrade (a
/// waiting reader could deadlock the writer it waits on), so when another
/// PROCESS on the same file holds the write lock the upgrade fails
/// `SQLITE_BUSY` at once and `busy_timeout = 30000` never applies. Edge saw
/// every multi-process writer on one file fail in 1–3 ms.
///
/// `BEGIN IMMEDIATE` takes the write lock at `BEGIN`, before any read, and a
/// `BEGIN` that finds the lock held DOES run the busy handler: the second
/// writer waits up to the busy timeout instead of failing.
///
/// Read-only transactions stay deferred (`unchecked_transaction` on the read
/// door, where the connection is `SQLITE_OPEN_READ_ONLY`). The from-disk gate
/// `every_sqlite_write_transaction_is_immediate_1238` refuses a bare
/// `.transaction()` anywhere a rusqlite connection is in scope, and names
/// each deferred read-only site with its reason.
pub fn write_tx(conn: &mut Connection) -> rusqlite::Result<rusqlite::Transaction<'_>> {
    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
}

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
    /// The two doors and the two handle accessors — `read`, `write`,
    /// `conn_handle`, `read_pool_handle`. They hand out or dispatch on a
    /// connection rather than use one; the gate pins the set by name.
    Door,
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
pub(crate) const SQLITE_CONN_CLASSES: &[(&str, ConnClass)] = &[
    // v61 (CIRISPersist#934, S4b) — the group supersede executor.
    ("store_planned_supersede", ConnClass::Write),
    // v61 (CIRISPersist#934, S4b) — the family executor.
    ("store_planned_family", ConnClass::Write),
    ("store_family_signature", ConnClass::Write),
    ("store_planned_family_revocation", ConnClass::Write),
    ("store_planned_family_widening", ConnClass::Write),
    // v61 (CIRISPersist#934, S4b) — the identity-occurrence executor.
    ("store_planned_occurrence", ConnClass::Write),
    ("store_planned_local_occurrence", ConnClass::Write),
    // v61 (CIRISPersist#934, S4b) — the transport-destination executor.
    ("store_planned_destination", ConnClass::Write),
    ("store_planned_signed_destination", ConnClass::Write),
    // v61 (CIRISPersist#934, S4a) — the byte writes' executor.
    ("store_planned_blob", ConnClass::Write),
    ("store_planned_announcement", ConnClass::Write),
    ("store_planned_dag", ConnClass::Write),
    ("store_planned_dag_over_held", ConnClass::Write),
    ("store_planned_seal", ConnClass::Write),
    ("sqlite_insert_dag_links", ConnClass::HelperWrite),
    // v61 (CIRISPersist#934, S4a) — the blob plane's executor.
    ("store_planned_chunk_batch", ConnClass::Write),
    ("read_stream_chunk_hashes", ConnClass::Read),
    ("store_stream_sth", ConnClass::Write),
    ("store_delivery_receipt", ConnClass::Write),
    ("store_holding_claim", ConnClass::Write),
    ("store_stream_dek", ConnClass::Write),
    ("store_stream_dek_grants", ConnClass::Write),
    // v61 (CIRISPersist#934, S4a) — the directory executor and the trust
    // revocation's two steps.
    ("store_planned_peer_record", ConnClass::Write),
    ("store_known_wire_hash", ConnClass::Write),
    ("store_purge_execution", ConnClass::Write),
    ("trust_granter", ConnClass::Read),
    ("store_trust_revocation", ConnClass::Write),
    // v61 (CIRISPersist#934, S4a) — the Backend doors' and the gated reads'
    // executors.
    ("store_planned_trace_erasure", ConnClass::Write),
    ("store_planned_fountain_content", ConnClass::Write),
    ("read_attestation_log_page", ConnClass::Read),
    ("read_naming_page", ConnClass::Read),
    // v61.1.0 (CIRISPersist#1163, #1190) — the narrowed serve-stream page.
    ("read_serve_stream_page", ConnClass::Read),
    ("read_key_registration_history", ConnClass::Read),
    ("read_renditions", ConnClass::Read),
    ("read_attestations", ConnClass::Read),
    // v61 (CIRISPersist#934, S4a) — the accord and evidence executors:
    // the cursor maxima and the held-proof read are reads; every store is a
    // write (one `self.write`, its transaction inside).
    ("last_accord_proposal_created_at", ConnClass::Read),
    ("last_accord_participation_arrival", ConnClass::Read),
    ("held_location_proof", ConnClass::Read),
    ("store_planned_accord_proposal", ConnClass::Write),
    ("store_planned_accord_participation", ConnClass::Write),
    ("store_planned_accord_decision", ConnClass::Write),
    ("store_planned_location_proof", ConnClass::Write),
    ("store_planned_location_proof_withdrawal", ConnClass::Write),
    ("store_planned_touch_claim", ConnClass::Write),
    ("store_planned_witness", ConnClass::Write),
    // #846 (§6.1) — the adopt floor: row + declared binding + holder claim in
    // one transaction.
    ("aggregate_audit_chain", ConnClass::Read),
    ("aggregate_llm_costs", ConnClass::Read),
    ("aggregate_scoring_factors_rollup_batch", ConnClass::Read),
    ("aggregate_scoring_factors_uncached", ConnClass::Read),
    ("aggregate_scrub_stats", ConnClass::Read),
    // v53.0.0 (#975) — the row-type census: one GROUP BY, read-only.
    ("attestation_type_census", ConnClass::Read),
    // v60.0.0 (CIRISPersist#934 step 3) — the key-record executor: every
    // key-record write door's one transaction.
    ("store_planned_key_record", ConnClass::Write),
    // v60.0.0 (CIRISPersist#1105) — the family-scoped holdings read.
    ("read_key_plane_wire_hashes", ConnClass::Read),
    ("attestations_binding_content", ConnClass::Read),
    // v61.4.0 (CIRISPersist#1260) — the takedown binding read.
    (
        "attestations_binding_content_with_placements",
        ConnClass::Read,
    ),
    ("backfill_trace_dedup_shard_keys", ConnClass::Write),
    ("backfill_revocation_subject_digests", ConnClass::Write),
    ("blackhole_list", ConnClass::Read),
    ("blackhole_prune_expired", ConnClass::Write),
    ("blackhole_record_hit", ConnClass::Write),
    ("blackhole_remove", ConnClass::Write),
    ("blackhole_upsert", ConnClass::Write),
    ("blob_cohort_scope", ConnClass::Read),
    ("blob_crypto_tier", ConnClass::Read),
    // #846 (§5) — the row's author / cohort / community, columns only.
    ("blob_provenance", ConnClass::Read),
    ("cancel_outbound", ConnClass::Write),
    ("claim_pending_outbound", ConnClass::Write),
    ("clear_active_halt", ConnClass::Write),
    ("communities_containing", ConnClass::Read),
    ("community_dek_bind_blob_epoch", ConnClass::Write),
    ("community_dek_blob_binding", ConnClass::Read),
    ("community_dek_blob_epoch", ConnClass::Read),
    ("community_dek_bump_epoch", ConnClass::Write),
    ("community_dek_communities", ConnClass::Read),
    ("community_dek_current_epoch", ConnClass::Read),
    ("community_dek_epoch_object_count", ConnClass::Read),
    ("community_dek_epochs", ConnClass::Read),
    ("community_dek_evict_epoch_objects", ConnClass::Write),
    ("community_dek_get_self_retention", ConnClass::Read),
    ("community_dek_has_member_grant", ConnClass::Read),
    ("community_dek_key_state", ConnClass::Read),
    ("community_dek_member_grant_recipients", ConnClass::Read),
    ("community_dek_member_grant_wrap", ConnClass::Read),
    ("community_dek_member_grants_for_epoch", ConnClass::Read),
    ("community_dek_minted_at", ConnClass::Read),
    ("community_dek_put_member_grant", ConnClass::Write),
    ("community_dek_put_member_grants", ConnClass::Write),
    ("community_dek_put_self_retention", ConnClass::Write),
    ("community_dek_retain_past_epochs", ConnClass::Read),
    ("community_dek_set_key_state", ConnClass::Write),
    ("community_dek_set_retain_past_epochs", ConnClass::Write),
    // v49.0.0 (#908) — the signers the authorized roster fold judges.
    ("community_roster_signers", ConnClass::Read),
    // v49.0.0 (#910) — the family twin.
    ("family_roster_signers", ConnClass::Read),
    ("conn_handle", ConnClass::Door),
    ("conscience_override_rates", ConnClass::Read),
    ("corpus_shape", ConnClass::Read),
    ("count_identity_changes", ConnClass::Read),
    ("count_overrides", ConnClass::Read),
    ("count_traces", ConnClass::Read),
    ("cross_agent_divergence", ConnClass::Read),
    ("delete_blob", ConnClass::Write),
    ("enqueue_outbound", ConnClass::Write),
    ("enter_mesh", ConnClass::Write),
    ("evict_fountain_content_hard_delete", ConnClass::Write),
    ("evict_fountain_content_to_tier", ConnClass::Write),
    ("evict_known_wire_hashes_before", ConnClass::Write),
    ("evict_scope_blobs", ConnClass::Write),
    ("execute_attestation_query", ConnClass::Read),
    ("factor_rollup_present", ConnClass::Read),
    ("fetch_trace_events_page", ConnClass::Read),
    ("fountain_manifest_row", ConnClass::Read),
    ("get_accord_decision", ConnClass::Read),
    ("get_accord_proposal", ConnClass::Read),
    ("get_active_halt", ConnClass::Read),
    ("get_aggregation", ConnClass::Read),
    ("get_at_rest_grant", ConnClass::Read),
    ("get_attestation", ConnClass::Read),
    ("get_blob", ConnClass::Write),
    ("get_blob_range", ConnClass::Write),
    ("get_calibration_bundle_by_version", ConnClass::Read),
    ("get_current_calibration_bundle", ConnClass::Read),
    ("get_detection_events", ConnClass::Read),
    ("get_edge_detection_events", ConnClass::Read),
    ("get_fountain_content", ConnClass::Read),
    ("get_goal", ConnClass::Read),
    ("get_installed_storage_budget", ConnClass::Read),
    ("get_repository_statistics", ConnClass::Read),
    ("get_scope_blob", ConnClass::Write),
    ("get_trace_detail", ConnClass::Read),
    ("get_trace_summary", ConnClass::Read),
    ("store_planned_trust_grant", ConnClass::Write),
    ("has_blob", ConnClass::Write),
    ("hash_chain_gaps", ConnClass::Read),
    ("heartbeat_shared_instance", ConnClass::Write),
    ("index_stored_record", ConnClass::Write),
    ("insert_trace_events_batch", ConnClass::Write),
    ("insert_trace_llm_calls_batch", ConnClass::Write),
    ("known_wire_hash_contains", ConnClass::Read),
    ("last_witness_epoch_for_peer", ConnClass::Read),
    ("latest_stream_sth", ConnClass::Read),
    ("list_accord_participations", ConnClass::Read),
    ("list_accord_proposals_by_anchor", ConnClass::Read),
    ("list_accord_proposals_by_payload", ConnClass::Read),
    ("list_aggregations_at_level", ConnClass::Read),
    ("list_all_transport_destinations_unfolded", ConnClass::Read),
    ("list_announced_peers", ConnClass::Read),
    ("list_at_rest_blobs_for_recipients", ConnClass::Read),
    ("list_at_rest_grant_recipients", ConnClass::Read),
    ("list_at_rest_grants", ConnClass::Read),
    ("list_attestations", ConnClass::Read),
    // v47.2.0 (#853) — composers naming a target, by `references_attestation_id`.
    ("list_attestations_referencing", ConnClass::Read),
    // v53.1.5 — the composers naming a set of targets (V107 / V178 seeks).
    // v56.0.0 (#1001): the dimension, type and typed reads beside it are
    // retired onto `execute_attestation_query`.
    ("list_composers_referencing_any", ConnClass::Read),
    // v53.1.6 — the citation / targeted seeks (V180, V150).
    ("list_attestations_by_dimension_citing", ConnClass::Read),
    // v56.0.0 (#1001): `read::ReadEngine::list_attestations_for` — the cursor-paged
    // subject read (#135/#150), NOT the retired `FederationDirectory` wide read of
    // the same name, which left the trait (demoted to test-anchor) in this cut.
    ("list_attestations_for", ConnClass::Read),
    // v55.0.0 (CIRISPersist#989) — V190's attester-free citation seek (the
    // holder directory's candidates).
    ("list_attestations_citing_by_dimension", ConnClass::Read),
    ("list_targeted_by_dimension_prefix", ConnClass::Read),
    ("list_attestations_for_migration", ConnClass::Read),
    ("list_attestations_since", ConnClass::Read),
    ("list_canonical_servers", ConnClass::Read),
    ("list_canonical_withdrawals", ConnClass::Read),
    ("list_communities_for_member", ConnClass::Read),
    ("list_community_membership_revocations_for", ConnClass::Read),
    ("list_community_membership_widenings_for", ConnClass::Read),
    ("list_family_membership_widenings_for", ConnClass::Read),
    ("read_consent_peer_rows", ConnClass::Read),
    // v44.6.0 (#857, V147) — the consent_peer_set_for projection read; same class as its twin.
    // v45.0.0 (#871) — the rendition index read and the puller's budget
    // read; plain SELECTs on the reader path.
    // v46.0.0 (#876) — the derivation input is a plain SELECT on the reader
    // path; the repair is a single guarded UPDATE on the writer's.
    ("community_dek_minters_granting", ConnClass::Read),
    // v50.0.0 (#916) — what a member holds: a plain SELECT on the reader path.
    ("community_dek_member_grant_epochs", ConnClass::Read),
    ("rebind_stranded_blob_epochs", ConnClass::Write),
    // v46.3.0 (#884) — the content-axis half of `minter_of_blob` is one
    // SELECT on the reader path (the community half delegates to
    // `community_dek_blob_epoch`, itself Read).
    ("minter_of_blob", ConnClass::Read),
    ("read_consent_revocation_candidates", ConnClass::Read),
    ("list_stored_delivery_receipts_for", ConnClass::Read),
    ("read_expired_attestation_ids", ConnClass::Read),
    ("list_families_for_member", ConnClass::Read),
    ("list_family_membership_revocations_for", ConnClass::Read),
    ("list_federation_keys", ConnClass::Read),
    ("list_fountain_decay_candidates", ConnClass::Read),
    ("list_goals", ConnClass::Read),
    ("list_group_versions", ConnClass::Read),
    ("list_hard_case_events", ConnClass::Read),
    ("list_held_fountain_content", ConnClass::Read),
    ("read_hybrid_pending", ConnClass::Read),
    ("list_identity_occurrence_revocations_for", ConnClass::Read),
    ("list_identity_occurrences_for", ConnClass::Read),
    ("list_installed_storage_budgets", ConnClass::Read),
    ("list_keys_by_identity_type", ConnClass::Read),
    ("list_known_wire_hashes_since", ConnClass::Read),
    ("read_live_consent_grant_candidates", ConnClass::Read),
    ("list_llm_calls", ConnClass::Read),
    ("list_local_tier_attestations", ConnClass::Read),
    ("list_location_proofs_for", ConnClass::Read),
    ("list_outbound", ConnClass::Read),
    ("list_revocations", ConnClass::Read),
    ("list_scope_blob_symbols", ConnClass::Write),
    ("list_signed_accord_quorum_evidence_since", ConnClass::Read),
    ("list_signed_communities_since", ConnClass::Read),
    (
        "list_signed_community_membership_revocations_since",
        ConnClass::Read,
    ),
    (
        "list_signed_community_membership_widenings_since",
        ConnClass::Read,
    ),
    ("list_signed_families_since", ConnClass::Read),
    (
        "list_signed_family_membership_revocations_since",
        ConnClass::Read,
    ),
    (
        "list_signed_family_membership_widenings_since",
        ConnClass::Read,
    ),
    ("list_signed_identity_occurrences_for", ConnClass::Read),
    ("list_signed_location_proofs_since", ConnClass::Read),
    ("list_signed_transport_destinations_for", ConnClass::Read),
    ("list_signed_transport_destinations_since", ConnClass::Read),
    ("list_tasks", ConnClass::Read),
    ("list_trace_summaries", ConnClass::Read),
    (
        "list_transport_destinations_by_destination_unfolded",
        ConnClass::Read,
    ),
    ("list_transport_destinations_for_unfolded", ConnClass::Read),
    ("list_trusted_keys", ConnClass::Read),
    ("list_wholeness_witnesses_for_peer", ConnClass::Read),
    ("list_widening_candidates", ConnClass::Read),
    ("list_wire_hashes_since", ConnClass::Read),
    ("list_witness_peer_ids", ConnClass::Read),
    ("load_content_kem_private_halves", ConnClass::Read),
    ("load_or_init_content_kem_identity", ConnClass::Write),
    // v50.0.0 (#920) — the row load/init moved out of
    // `load_or_init_content_master`, which now only resolves it.
    ("load_or_init_content_master_row", ConnClass::Write),
    ("lookup_canonical_withdrawal", ConnClass::Read),
    ("lookup_community", ConnClass::Read),
    ("lookup_family", ConnClass::Read),
    ("lookup_freshness_floor", ConnClass::Read),
    ("lookup_identity_for_occurrence", ConnClass::Read),
    (
        "list_identity_occurrences_by_occurrence_key",
        ConnClass::Read,
    ),
    // v52.0.0 (#930) — the V161 append, a free fn over the writer's
    // transaction, called from both occurrence doors.
    ("sqlite_append_occurrence_history", ConnClass::HelperWrite),
    // v52.0.0 (#930) — the occurrence history (V161), read by the node-bearing fold.
    (
        "list_identity_occurrence_history_by_occurrence",
        ConnClass::Read,
    ),
    ("lookup_keys_for_identity", ConnClass::Read),
    ("lookup_public_key", ConnClass::Read),
    ("lookup_role_withdrawal", ConnClass::Read),
    ("lookup_shared_instance_lease", ConnClass::Read),
    ("lookup_signed_community", ConnClass::Read),
    // v51.0.0 (CIRISPersist#938) — the witness plane (V159).
    ("list_lineage_head_cosigns_for", ConnClass::Read),
    ("store_lineage_head_cosign", ConnClass::Write),
    ("lookup_signed_record_by_content_hash", ConnClass::Read),
    ("lookup_trust", ConnClass::Read),
    ("mark_ack_received", ConnClass::Write),
    ("mark_replay_resolved", ConnClass::Write),
    ("mark_transport_delivered", ConnClass::Write),
    ("mark_transport_failed", ConnClass::Write),
    ("match_ack_to_outbound", ConnClass::Read),
    ("next_key_admission_position", ConnClass::Read),
    ("outbound_status", ConnClass::Read),
    ("peer_metadata_for", ConnClass::Read),
    ("pinned_blob_bytes", ConnClass::Read),
    ("purge_attestation_projections", ConnClass::Write),
    ("put_at_rest_grant", ConnClass::Write),
    ("put_at_rest_grants", ConnClass::Write),
    // #848 §13–§14 (V146, PR #850 review) — the emission ledger and the
    // pending-content index.
    ("community_dek_key_grant_dirty", ConnClass::Read),
    ("community_dek_key_grant_watermark", ConnClass::Read),
    ("community_dek_mark_key_grant_emitted", ConnClass::Write),
    // v53.0.0 (CIRISPersist#969) — the stream-epoch DEK (V168).
    ("stream_key_state", ConnClass::Read),
    ("stream_dek_list", ConnClass::Read),
    ("stream_dek_close", ConnClass::Write),
    ("evict_selected_room_epochs", ConnClass::Write),
    ("stream_dek_grants", ConnClass::Read),
    ("stream_dek_grants_for_recipient", ConnClass::Read),
    ("stream_dek_key_grant_watermark", ConnClass::Read),
    ("stream_dek_mark_key_grant_emitted", ConnClass::Write),
    ("stream_dek_list_key_grant_dirty", ConnClass::Read),
    ("stream_dek_list_for_recipients", ConnClass::Read),
    ("community_dek_list_key_grant_dirty", ConnClass::Read),
    ("blob_key_grant_dirty", ConnClass::Read),
    ("blob_key_grant_watermark", ConnClass::Read),
    ("blob_mark_key_grant_emitted", ConnClass::Write),
    ("blob_list_key_grant_dirty", ConnClass::Read),
    ("key_grant_pending_put", ConnClass::Write),
    ("key_grant_pending_list", ConnClass::Read),
    ("key_grant_pending_delete", ConnClass::Write),
    // v52.0.0 (#957) — the chunk floor's ONE body, batched: ONE write
    // transaction for a run of chunks. `put_blob_chunk_floor` is its batch of
    // one and touches no connection; `put_blob_chunk_with_scope`,
    // `adopt_sealed_chunk_at` and `adopt_sealed_chunks_at` delegate to them.
    // #957 — one item's append, a free fn over the writer's savepoint.
    ("sqlite_append_chunk_item", ConnClass::HelperWrite),
    ("repair_minter_sentinel", ConnClass::Write),
    // v51.3.0 (#947) — the sealed-DAG promotion: one write transaction.
    ("promote_adopted_manifest_to_dag", ConnClass::Write),
    // v52.0.0 (CIRISPersist#954) — the nested manifest's relation and the
    // abandoned stream.
    ("manifest_children", ConnClass::Read),
    ("record_manifest_child", ConnClass::Write),
    ("abandon_stream_floor", ConnClass::Write),
    ("blob_head", ConnClass::Read),
    ("stream_chunks", ConnClass::Read),
    ("stream_chunk_at", ConnClass::Read),
    ("stream_positions_of_chunk", ConnClass::Read),
    // v53.1.0 (CIRISPersist#979) — the V176 chunk↔manifest relation: two
    // reads, the helper the seal and the promote call inside their
    // transaction, and the test seam that edits the rows (a write door).
    ("dag_manifests_of_chunk", ConnClass::Read),
    ("dag_chunks_of_manifest", ConnClass::Read),
    ("sqlite_link_dag_chunks", ConnClass::HelperWrite),
    ("test_dag_link", ConnClass::Write),
    // v54.0.0 (#994) — the V176 backfill: the candidate list, the exact
    // check-and-link in one transaction, and the stream-row test seam.
    ("list_unlinked_chunk_dags", ConnClass::Read),
    ("link_dag_chunks_if_exact", ConnClass::Write),
    ("test_drop_stream_chunk_row", ConnClass::Write),
    // v54.0.0 (#994, Codex on PR #1050) — the V185 resume cursor.
    ("dag_link_backfill_cursor", ConnClass::Read),
    ("set_dag_link_backfill_cursor", ConnClass::Write),
    // v54.0.0 (#995 row 2) — the scrub re-hydration CAS and its test seam.
    ("test_seam_drop_key_additional_scrubs", ConnClass::Write),
    // v54.0.0 (#995 row 4, V184) — the rooms of a shared plaintext blob.
    ("blob_associations", ConnClass::Read),
    // v54.0.0 (#996) — the outbound queue's status-grouped COUNT.
    ("outbound_counts", ConnClass::Read),
    // v54.1.0 (CIRISPersist#1046) — the steward purge plane (V187): the
    // selection reads, the ledger header + tombstone writes, the delete doors
    // `purge_finalize` drives, and the #1043 legacy-row test seam.
    ("purge_scan_attestations", ConnClass::Read),
    ("purge_trace_ids_for_llm_model", ConnClass::Read),
    ("purge_trace_ids_signed_by", ConnClass::Read),
    ("purge_trace_row_counts", ConnClass::Read),
    ("purge_execution", ConnClass::Read),
    ("purge_tombstones_of", ConnClass::Read),
    ("purge_tombstoned", ConnClass::Read),
    ("purge_tombstone_notices", ConnClass::Read),
    ("list_purge_executions_since", ConnClass::Read),
    ("purge_delete_tombstoned_attestation", ConnClass::Write),
    ("purge_delete_tombstoned_trace", ConnClass::Write),
    ("purge_mark_finalized", ConnClass::Write),
    ("test_seam_set_attestation_asserted_at", ConnClass::Write),
    ("test_seam_set_key_identity_type", ConnClass::Write),
    ("test_seam_set_attestation_type", ConnClass::Write),
    ("test_seam_drop_purge_tombstone", ConnClass::Write),
    ("test_seam_factor_rollup_trace_counts", ConnClass::Read),
    // v55.0.0 (CIRISPersist#952) — the incremental plaintext DAG finalize.
    // v55.0.0 (CIRISPersist#989) — announce a holding claim for a held row.
    ("put_calibration_bundle", ConnClass::Write),
    ("put_edge_detection_event", ConnClass::Write),
    ("put_identity_occurrence_revocation_local", ConnClass::Write),
    ("put_installed_storage_budget", ConnClass::Write),
    // v50.0.0 (#928, V157) — the recorded admission depth of a `withdraws`.
    ("withdraws_admission_depth", ConnClass::Read),
    ("trust_direction_held_among", ConnClass::Read),
    ("put_scope_blob", ConnClass::Write),
    ("read", ConnClass::Door),
    ("read_classifications", ConnClass::Read),
    ("read_features", ConnClass::Read),
    ("read_measured", ConnClass::Read),
    ("read_pool_handle", ConnClass::Door),
    ("rebuild_signed_wire_index", ConnClass::Write),
    ("record_announced_peer", ConnClass::Write),
    ("record_canonical_withdrawal", ConnClass::Write),
    ("record_role_withdrawal", ConnClass::Write),
    ("refresh_factor_rollup", ConnClass::Write),
    ("register_accord_public_key", ConnClass::Write),
    ("release_shared_instance_lease", ConnClass::Write),
    ("remove_peer_record", ConnClass::Write),
    ("remove_transport_destination", ConnClass::Write),
    // #845 (I55) — the portable-default repair: a writable_schema rewrite
    // of sqlite_master, run after the migrations.
    ("repair_portable_defaults_with", ConnClass::Write),
    // #840 (I44) — the V070 checksum repair: a conditional UPDATE on the
    // schema-history table, run before refinery validates it.
    ("repair_v070_checksum", ConnClass::Write),
    ("replay_abandoned", ConnClass::Write),
    ("revocations_for_subject", ConnClass::Read),
    // #845 (I55) — the nine documented steps, in one transaction: a free fn
    // handed the writer's connection from inside `repair_portable_defaults_with`.
    ("rewrite_portable_defaults_in_tx", ConnClass::HelperWrite),
    ("run_migrations", ConnClass::Write),
    ("run_migrations_through", ConnClass::Write),
    ("sample_public_keys", ConnClass::Read),
    ("scoring_ingest_watermark_ms", ConnClass::Read),
    ("seal_stream", ConnClass::Write),
    ("set_active_halt", ConnClass::Write),
    ("store_planned_consent_role", ConnClass::Write),
    ("sqlite_load_stream_chunk_hashes", ConnClass::HelperRead),
    // v60.1.0 (CIRISPersist#1070 item 3) — the bytes floor's tombstone read
    // INSIDE a byte door's write transaction (a read; the caller writes).
    ("sqlite_tombstone_at_write", ConnClass::HelperRead),
    ("sqlite_refuse_tombstoned_at_write", ConnClass::HelperRead),
    ("sqlite_next_key_serve_position", ConnClass::HelperRead),
    ("sqlite_next_plane_position", ConnClass::HelperRead),
    (
        "sqlite_project_attestation_subjects",
        ConnClass::HelperWrite,
    ),
    ("sqlite_project_consent_peer_set", ConnClass::HelperWrite),
    // v54.1.0 (Codex round 3 on PR #1057) — the Art. 17 detection tombstone,
    // shared by the DSAR erasure and the steward purge's trace delete.
    ("sqlite_tombstone_detection_events", ConnClass::HelperWrite),
    (
        "sqlite_drop_orphaned_thought_signatures",
        ConnClass::HelperWrite,
    ),
    // v45.0.0 (#871) — the V149 `blob_renditions` projection, a free fn over
    // the writer's connection called from the three attestation doors.
    ("sqlite_project_rendition_row", ConnClass::HelperWrite),
    ("sqlite_update_peer_field", ConnClass::Write),
    ("sqlite_upsert_wire_index", ConnClass::HelperWrite),
    // v55.0.0 (CIRISPersist#989) — the three claim doors' shared INSERT.
    ("sqlite_insert_holding_claim", ConnClass::HelperWrite),
    ("store_planned_local_attestation", ConnClass::Write),
    // v56.0.0 (CIRISPersist#934 step 1) — the attestation plane's executor
    // (`AttestationStore`): its two reads and its writes. The doors that held
    // these statements (`put_attestation_with_origin`,
    // `attach_attestation_pqc_signature`, `sqlite_write_local_attestation`) are
    // calls into the shared plans now and touch no connection.
    ("attesting_identity_type", ConnClass::Read),
    ("composer_replay_held", ConnClass::Read),
    ("delete_attestation", ConnClass::Write),
    // v61 (CC 2.6.2) — the open-time pass's compare-and-delete + ledger row.
    ("set_aside_form_refused", ConnClass::Write),
    ("repair_withdraws_depth", ConnClass::Write),
    // v59.0.0 (#1099) — the V199 self-roster receipts.
    ("note_self_roster_proposal", ConnClass::Write),
    // v61.3.0 (CIRISPersist#1252) — the V214 cosign ledgers, the group
    // pointer read, and the I1739 test seam (a `#[cfg(test)]` method).
    ("cosign_receipt", ConnClass::Read),
    ("list_open_cosign_receipts", ConnClass::Read),
    ("settle_cosign_receipt", ConnClass::Write),
    ("list_cosign_signatures", ConnClass::Read),
    ("drop_cosign_rows", ConnClass::Write),
    ("note_cosign_alias", ConnClass::Write),
    ("cosign_alias", ConnClass::Read),
    ("list_cosign_aliases", ConnClass::Read),
    ("read_group_plane_object", ConnClass::Read),
    ("test_seed_wire_index", ConnClass::Write),
    // CIRISPersist#1198 — the V213 vote windows.
    ("vote_window_first_held", ConnClass::Read),
    // v59.0.0 (sealed-transport floor) — the eager key-plane rehome at open.
    ("rehome_key_plane_at_open", ConnClass::Read),
    ("legacy_community_trust_grants_at_open", ConnClass::Read),
    // v61 (the canonical's read storm) — ANALYZE once on a never-analyzed
    // store, then `PRAGMA optimize`: both write sqlite_stat1, on the writer.
    ("plan_statistics_at_open", ConnClass::Write),
    ("list_open_self_roster_proposals", ConnClass::Read),
    ("list_settled_self_roster_proposals", ConnClass::Read),
    ("settle_self_roster_proposal", ConnClass::Write),
    ("store_pqc_completion", ConnClass::Write),
    ("store_planned_attestation", ConnClass::Write),
    ("store_planned_reseal", ConnClass::Write),
    // v57.0.0 (CIRISPersist#988 items 2, 3) — the hard_case and detection
    // doors' executors, the legacy rehomes, the projection rebuild, and the
    // writers they share. `record_hard_case` and `put_detection_event` are
    // calls into the shared plans now and touch no connection.
    ("store_planned_hard_case", ConnClass::Write),
    ("rehome_legacy_hard_case_events", ConnClass::Write),
    ("store_planned_detection", ConnClass::Write),
    ("trace_agent_id_hash", ConnClass::Read),
    ("detection_row_ids_for_agent", ConnClass::Read),
    ("rehome_legacy_detection_events", ConnClass::Write),
    ("projection_rebuild", ConnClass::Write),
    (
        "sqlite_insert_local_attestation_row",
        ConnClass::HelperWrite,
    ),
    ("sqlite_store_hard_case", ConnClass::HelperWrite),
    // v61.1.0 (61.1 review H3) — reads the occupant's signer inside the
    // hard_case write transaction it is handed (a helper over that `tx`).
    ("sqlite_hard_case_signer", ConnClass::HelperRead),
    ("sqlite_record_hard_case_in_tx", ConnClass::HelperWrite),
    ("sqlite_project_hard_case", ConnClass::HelperWrite),
    ("sqlite_project_detection", ConnClass::HelperWrite),
    // v60.0.0 (CIRISPersist#988 item 1) — the ledger projection's writer and
    // its rebuild (into a scratch table, rolled back).
    ("sqlite_project_ledger", ConnClass::HelperWrite),
    ("sqlite_ledger_projection_rebuild", ConnClass::HelperWrite),
    // v60.0.0 (CIRISPersist#988 item 4) — the goals projection's writer (the
    // refold, on the executor's transaction) and its rebuild; the legacy
    // goal reads and removals the rehome drives.
    ("sqlite_project_goal", ConnClass::HelperWrite),
    ("sqlite_goal_projection_rebuild", ConnClass::HelperWrite),
    ("legacy_goals", ConnClass::Read),
    ("delete_legacy_goal", ConnClass::Write),
    // v58.0.0 (CIRISPersist#991) — the key plane's rows and projections.
    ("sqlite_key_plane_present", ConnClass::HelperRead),
    ("sqlite_plane_rows", ConnClass::HelperRead),
    ("sqlite_key_projection_rebuild", ConnClass::HelperRead),
    (
        "sqlite_revocation_projection_rebuild",
        ConnClass::HelperRead,
    ),
    (
        "sqlite_occurrence_projection_rebuild",
        ConnClass::HelperRead,
    ),
    ("rehome_legacy_key_plane", ConnClass::Write),
    // v61 (CIRISPersist#991) — the group plane's executor.
    ("group_plane_present", ConnClass::Read),
    ("read_group_object", ConnClass::Read),
    ("unlinked_group_objects", ConnClass::Read),
    ("link_group_plane_row", ConnClass::Write),
    ("drop_group_projection_row", ConnClass::Write),
    ("read_group_plane", ConnClass::Read),
    ("store_planned_revocation", ConnClass::Write),
    ("index_stored_key_row", ConnClass::Read),
    ("sqlite_render_table", ConnClass::HelperRead),
    ("sqlite_erase_cited_rows", ConnClass::HelperWrite),
    ("sqlite_store_erasure_withdraws", ConnClass::HelperWrite),
    ("sqlite_v196_pending", ConnClass::HelperRead),
    ("sqlite_put_erasure_execution", ConnClass::HelperWrite),
    ("sqlite_record_erasure", ConnClass::HelperWrite),
    ("sqlite_detection_tombstone_instant", ConnClass::HelperRead),
    (
        "sqlite_tombstone_detection_projection",
        ConnClass::HelperWrite,
    ),
    // The test-only raw-SQL seam the projection witnesses tamper with.
    ("test_execute", ConnClass::Write),
    ("test_count", ConnClass::Read),
    // v57.0.0 (CIRISPersist#934 step 2) — the community plane's executor
    // (`CommunityStore`). The doors that held these statements
    // (`put_community_at_door`, the three roster doors) are calls into the
    // shared plans now and touch no connection.
    ("store_planned_community", ConnClass::Write),
    ("store_planned_community_revocation", ConnClass::Write),
    ("store_planned_community_widening", ConnClass::Write),
    ("stream_consistency_proof", ConnClass::Read),
    ("stream_inclusion_proof", ConnClass::Read),
    ("sweep_ack_timeouts", ConnClass::Write),
    ("sweep_candidates", ConnClass::Read),
    ("sweep_expired_claims", ConnClass::Write),
    ("sweep_ttl_expired", ConnClass::Write),
    ("temporal_drift", ConnClass::Read),
    ("try_acquire_shared_instance", ConnClass::Write),
    ("write", ConnClass::Door),
    ("write_classifications", ConnClass::Write),
    ("write_features", ConnClass::Write),
];

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
            // v54.1.0 (#1026): `#[cfg(all(test, …))]` at column 0 starts
            // the test half as well.
            if !line.starts_with(char::is_whitespace) && crate::test_cfg::is_test_only_cfg(line) {
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
        /// 1-based last line of the body.
        pub end: usize,
        pub indent: usize,
        /// Body text with `//` comment lines removed.
        pub body: String,
        /// `body` with ALL whitespace removed. rustfmt splits `self.read(`
        /// into `self\n.read(` in a chained expression, so every token that
        /// names a door or a connection is matched against this, never
        /// against `body`.
        pub squashed: String,
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
            let body: String = lines[i..=k.min(lines.len() - 1)]
                .iter()
                .filter(|l| !l.trim_start().starts_with("//"))
                .map(|l| format!("{l}\n"))
                .collect();
            let squashed = squash(&body);
            out.push(Func {
                name,
                line: i + 1,
                end: k.min(lines.len() - 1) + 1,
                indent,
                body,
                squashed,
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
        "self.read_measured(",
        "self.write(",
        "backend.read(",
        "backend.write(",
        "self.readers",
    ];

    /// The read door, as a body reaches it (methods say `self`, the two
    /// free async fns that take the backend say `backend`).
    /// `read_measured` (CIRISPersist#1014) is `read` plus the decoded-envelope
    /// byte count; it reaches the reader through `self.read(` and is filed `Read`.
    const DOOR_READ: &[&str] = &["self.read(", "self.read_measured(", "backend.read("];
    /// The write door, likewise.
    const DOOR_WRITE: &[&str] = &["self.write(", "backend.write("];
    /// The fixed set of `Door`-class fns (FSD §5).
    const DOORS: &[&str] = &["read", "write", "conn_handle", "read_pool_handle"];

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
        // CIRISPersist#1238 — the IMMEDIATE write transaction, by the helper
        // every write body now begins with and by the driver's own spelling.
        "write_tx(",
        ".transaction_with_behavior(",
        "execute_batch(",
        // NOT `unchecked_transaction(`: it is the `&Connection` form of
        // BEGIN, and on the reader path the connection is
        // `SQLITE_OPEN_READ_ONLY`, so it can only ever open a READ
        // transaction — the one way a Read fn takes two statements from the
        // same snapshot (I37: `stream_chunks` lists the chunks and the STH
        // together). `.transaction(` needs `&mut Connection` and so cannot
        // occur on the reader path at all.
        "BEGIN",
        "COMMIT",
    ];

    /// The writer path, which a `Read` may never mention.
    const WRITER_TOKENS: &[&str] = &[
        "self.conn",
        "conn.lock()",
        "conn_handle()",
        "self.write(",
        "backend.write(",
    ];

    /// Remove all whitespace, so a token matches however rustfmt wrapped it.
    pub(super) fn squash(s: &str) -> String {
        s.split_whitespace().collect()
    }

    pub(super) fn touches_connection(squashed: &str) -> bool {
        TOUCH.iter().any(|t| squashed.contains(&squash(t)))
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
            .filter(|f| touches_connection(&f.squashed))
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
            if !DOOR_READ.iter().any(|d| f.squashed.contains(d)) {
                bad.push(format!(
                    "  {}:{} does not use the read door",
                    f.name, f.line
                ));
            }
            for t in WRITER_TOKENS {
                if f.squashed.contains(&squash(t)) {
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
                if f.squashed.contains(&format!("{h}(")) {
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
                    if !DOOR_WRITE.iter().any(|d| f.squashed.contains(d)) {
                        bad.push(format!(
                            "  Write {}:{} does not use the write door",
                            f.name, f.line
                        ));
                    }
                }
                Some(ConnClass::Door) => {
                    if !DOORS.contains(&f.name.as_str()) {
                        bad.push(format!(
                            "  Door {}:{} is not one of {DOORS:?}",
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

    // ── I1663 (CIRISPersist#1238): no write runs on a read connection ───

    /// Whether `recv` (blanked text, trailing whitespace trimmed) ends in the
    /// whole identifier `name`, not the tail of a longer one.
    fn ends_with_ident(recv: &str, name: &str) -> bool {
        recv.strip_suffix(name).is_some_and(|head| {
            !head
                .chars()
                .next_back()
                .is_some_and(|c| c == '_' || c.is_ascii_alphanumeric())
        })
    }

    /// Every closure handed to the read door in `code`: the 1-based line of
    /// the call and the text of its parenthesised argument. Comments and
    /// string contents are blanked (byte offsets kept) for the parenthesis
    /// count only; the text returned is `code`'s own, SQL included, so a
    /// write verb in a string is seen. rustfmt's `self\n.read(` is one call.
    pub(super) fn read_door_closures(code: &str) -> Vec<(usize, String)> {
        let blanked = crate::store::pool_checkout_gate::blank(code);
        let bytes = blanked.as_bytes();
        let mut out = Vec::new();
        for door in [".read(", ".read_measured("] {
            let mut from = 0;
            while let Some(p) = blanked[from..].find(door) {
                let at = from + p;
                from = at + door.len();
                let recv = blanked[..at].trim_end();
                if !(ends_with_ident(recv, "self") || ends_with_ident(recv, "backend")) {
                    continue;
                }
                let open = at + door.len() - 1;
                let mut depth = 0i64;
                let mut close = None;
                for (k, &c) in bytes.iter().enumerate().skip(open) {
                    match c {
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                close = Some(k);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                let close = close.unwrap_or_else(|| {
                    panic!("unbalanced read-door call at byte {at}: the scanner is broken")
                });
                let line = code[..at].matches('\n').count() + 1;
                out.push((line, code[open..=close].to_owned()));
            }
        }
        out.sort_by_key(|(line, _)| *line);
        out
    }

    /// **I1663 (the dispatcher half).** The read door hands its closure a
    /// reader, `SQLITE_OPEN_READ_ONLY` with `query_only = ON`, so a write
    /// there fails at run time — but only on the run that reaches it. The
    /// partition above files a whole `fn` by its class and lets a `Write`
    /// take a read-door pre-check, which means nothing yet asked what runs
    /// INSIDE that pre-check. This does: no closure handed to `self.read(`,
    /// `self.read_measured(` or `backend.read(` anywhere in `sqlite.rs`'s
    /// production text carries a write verb, the write transaction helper or
    /// a call to a `HelperWrite`.
    #[test]
    fn no_read_door_closure_in_sqlite_rs_writes_1238() {
        // Comment-only lines blanked to empty, so line numbers stay true.
        let code: String = production_text(&sqlite_rs())
            .lines()
            .map(|l| {
                if l.trim_start().starts_with("//") {
                    "\n".to_owned()
                } else {
                    format!("{l}\n")
                }
            })
            .collect();
        let closures = read_door_closures(&code);
        // 237 read-door closures when this gate was written.
        assert!(
            closures.len() >= 150,
            "parser floor: found only {} read-door closures in sqlite.rs",
            closures.len()
        );
        let helper_writes: Vec<&str> = SQLITE_CONN_CLASSES
            .iter()
            .filter(|(_, c)| *c == ConnClass::HelperWrite)
            .map(|(n, _)| *n)
            .collect();
        let mut bad = Vec::new();
        for (line, text) in &closures {
            if let Some(v) = write_verb_in(text) {
                bad.push(format!(
                    "  sqlite.rs:{line} runs `{}` on a reader",
                    v.trim()
                ));
            }
            let squashed = squash(text);
            for h in &helper_writes {
                if squashed.contains(&format!("{h}(")) {
                    bad.push(format!(
                        "  sqlite.rs:{line} calls HelperWrite `{h}` on a reader"
                    ));
                }
            }
        }
        assert!(
            bad.is_empty(),
            "CIRISPersist#1238: {} read-door closure(s) in sqlite.rs write; a reader is \
             read-only, so the write fails on the first run that reaches it. Move it to \
             `self.write(…)`:\n{}",
            bad.len(),
            bad.join("\n")
        );
    }

    /// I1663 — the closure scanner sees a split call and its SQL, ignores a
    /// mention in a comment or a string and a receiver that only ends in
    /// `self`, and returns the whole argument however it nests.
    #[test]
    fn the_read_door_closure_scanner_reads_calls_1238() {
        let planted = "fn f() {\n    let x = self\n        .read(move |conn| {\n            \
                       conn.execute(\"INSERT INTO t (a) VALUES (?1)\", p(1))\n        })\n        \
                       .await;\n}\n";
        let got = read_door_closures(planted);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, 3, "the line of `.read(`");
        assert!(
            got[0].1.ends_with("})"),
            "the whole argument: {:?}",
            got[0].1
        );
        assert_eq!(write_verb_in(&got[0].1), Some("INSERT "));

        let measured =
            "fn g() { backend.read_measured(|c| c.query_row(\"SELECT 1\", [], |r| r.get(0))) }";
        let got = read_door_closures(measured);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(write_verb_in(&got[0].1), None, "a SELECT is a read");

        let not_calls = "fn h() {\n    // self.read(|c| c.execute(\"DELETE \"))\n    \
                         let s = \"self.read(\";\n    myself.read(|c| c.execute(\"DELETE \"));\n}\n";
        assert!(read_door_closures(not_calls).is_empty());

        // A `)` inside the closure's SQL does not end the argument early.
        let paren_in_sql = "fn k() { self.read(|c| c.query_row(\"SELECT ')'\", [], f)); self.write(|c| c.execute(\"UPDATE t\")); }";
        let got = read_door_closures(paren_in_sql);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(
            write_verb_in(&got[0].1),
            None,
            "the write door is not the read door"
        );
    }

    /// The four classes are the whole alphabet; the table may use nothing
    /// else, and a class nobody files under is a class the gate does not
    /// exercise — this is the row that says so out loud.
    #[test]
    fn the_class_alphabet_is_the_four_documented_classes() {
        const ALL: [ConnClass; 5] = [
            ConnClass::Read,
            ConnClass::Write,
            ConnClass::HelperRead,
            ConnClass::HelperWrite,
            ConnClass::Door,
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
        // The two doors are the only places allowed to lock: `read`'s
        // zero-reader fallback and `write`. Their line ranges are exempt;
        // everything else that locks is a bypass.
        let doors: Vec<(usize, usize)> = functions(&prod)
            .into_iter()
            .filter(|f| f.indent == 4 && (f.name == "read" || f.name == "write"))
            .map(|f| (f.line, f.end))
            .collect();
        assert_eq!(
            doors.len(),
            2,
            "expected exactly the read and write doors, found {doors:?}"
        );
        let hits: Vec<String> = prod
            .lines()
            .enumerate()
            .filter(|(i, _)| !doors.iter().any(|(a, b)| (a..=b).contains(&&(i + 1))))
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

    fn wal_files(path: &str) -> (bool, bool) {
        (
            std::path::Path::new(&format!("{path}-wal")).exists(),
            std::path::Path::new(&format!("{path}-shm")).exists(),
        )
    }

    /// I1723 (CIRISPersist#1261) — `journal_mode = WAL` alone leaves no
    /// `-wal`/`-shm` on disk; [`super::materialize_wal`] on the writer
    /// creates both. Apple's SQLite will not let a read-only reader create
    /// them, so they must exist before `ReadPool::open` runs. The "before"
    /// half pins that the property is measured, not vacuous.
    #[test]
    fn i1723_the_writer_creates_the_wal_files_before_any_reader() {
        let path = temp_db_path("i1723");
        let w = rusqlite::Connection::open(&path).unwrap();
        let w = SqliteBackend::apply_connection_settings(w).unwrap();
        assert_eq!(
            wal_files(&path),
            (false, false),
            "journal_mode = WAL already created -wal/-shm: the witness measures nothing"
        );
        super::materialize_wal(&w).unwrap();
        assert_eq!(
            wal_files(&path),
            (true, true),
            "the writer must leave -wal and -shm for the read-only readers (#1261)"
        );
    }

    /// I1724 (CIRISPersist#1261) — a file-backed open with readers succeeds
    /// on a NEW file and again on RESTART, and every reader reads. On macOS
    /// (the darwin CI job) this is the reproduction: 61.2.2 refused both
    /// with "sqlite open readers: unable to open database file".
    #[tokio::test]
    async fn i1724_a_file_backed_open_with_readers_succeeds_fresh_and_on_restart() {
        let path = temp_db_path("i1724");
        for round in ["fresh", "restart"] {
            let b = SqliteBackend::open_with_readers(path.clone(), 3)
                .await
                .unwrap_or_else(|e| panic!("{round} open: {e}"));
            assert_eq!(b.read_pool_handle().size(), 3, "{round}");
            for _ in 0..3 {
                let n: rusqlite::Result<i64> = b
                    .read(|c| c.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0)))
                    .await;
                n.unwrap_or_else(|e| panic!("{round} read: {e}"));
            }
            drop(b);
        }
    }

    /// I1725 (CIRISPersist#1261 ask 2) — a reader that cannot open says
    /// which step failed, SQLite's extended result code and the path.
    #[test]
    fn i1725_a_reader_open_failure_names_the_step_the_code_and_the_path() {
        let dir = std::env::temp_dir().join(format!("ciris-1725-{}", uuid::Uuid::new_v4()));
        let path = dir
            .join("absent")
            .join("store.db")
            .to_string_lossy()
            .into_owned();
        let e = match super::ReadPool::open(
            &path,
            1,
            &super::SqliteTuning {
                mmap_bytes: super::DEFAULT_MMAP_BYTES,
                cache_kib: super::DEFAULT_CACHE_KIB,
            },
        ) {
            Ok(_) => panic!("a read-only open of a path in a missing directory succeeded"),
            Err(e) => e,
        };
        assert!(e.contains("reader 0 open:"), "{e}");
        assert!(
            e.contains("extended code 14"),
            "SQLITE_CANTOPEN's code: {e}"
        );
        assert!(e.contains(&format!("{path:?}")), "the path: {e}");
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

    /// v50.0.0 (#920 review) — the content-master row init derives the root
    /// through `dispatch_blocking`, so a first-ever row init polled with NO
    /// tokio runtime on the thread completes rather than panicking (a bare
    /// `spawn_blocking` panics there).
    #[test]
    fn the_content_master_row_init_runs_with_no_tokio_runtime_on_the_thread() {
        use crate::federation::BlobStorage as _;
        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "premise: this test must run with no runtime current"
        );
        let path = temp_db_path("no-runtime-content-master");
        block_on_without_a_runtime(async {
            let backend = SqliteBackend::open(&path).await.unwrap();
            backend.run_migrations().await.unwrap();
            let row = backend
                .load_or_init_content_master_row()
                .await
                .expect("row init with no runtime");
            assert!(
                row.key_kind == "software" || row.key_kind == "hardware",
                "got {:?}",
                row.key_kind
            );
        });
    }

    // ── the pool's own witnesses (written with the pool; RED by absence) ──

    /// Hold ONE reader inside a read closure for `hold`, signalling once the
    /// reader is checked out. Runs as its own task so the caller can act
    /// while it is held.
    fn hold_a_reader(backend: &Arc<SqliteBackend>, hold: Duration) -> tokio::task::JoinHandle<()> {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let b = backend.clone();
        let task = tokio::spawn(async move {
            b.read(move |conn| {
                // A real statement on the held reader, then the hold.
                let one: i64 = conn.query_row("SELECT 1", [], |r| r.get(0)).unwrap();
                assert_eq!(one, 1);
                tx.send(()).unwrap();
                std::thread::sleep(hold);
            })
            .await;
        });
        rx.recv().unwrap();
        task
    }

    // ── I1 ─────────────────────────────────────────────────────────────
    /// OCCUPANCY. With one of two readers held inside a long read, a second
    /// read completes on the other reader, promptly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_completes_while_one_reader_is_held_in_a_long_query() {
        let path = temp_db_path("held-reader");
        let backend = Arc::new(SqliteBackend::open_with_readers(&path, 2).await.unwrap());
        backend.run_migrations().await.unwrap();
        assert_eq!(backend.read_pool_handle().size(), 2);

        let holder = hold_a_reader(&backend, Duration::from_secs(2));
        assert_eq!(
            backend.read_pool_handle().idle(),
            1,
            "premise: exactly one reader is checked out"
        );
        let t0 = Instant::now();
        point_read(&backend).await;
        let took = t0.elapsed();
        holder.await.unwrap();
        assert!(
            took < Duration::from_millis(750),
            "a read waited {took:?} behind a held reader with a second reader idle \
             (FSD/SQLITE_CONNECTION_MODEL.md I1)"
        );
        assert_eq!(
            backend.read_pool_handle().idle(),
            2,
            "both readers returned"
        );
    }

    // ── I3 (reader arm) ────────────────────────────────────────────────
    /// One worker, ONE reader. A read that must wait for the held reader
    /// waits on the blocking pool, not on the worker: the 10 ms sleep fires.
    #[test]
    fn runtime_keeps_spinning_while_a_read_waits_on_a_reader() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let path = temp_db_path("reader-wait");
            let backend = Arc::new(SqliteBackend::open_with_readers(&path, 1).await.unwrap());
            backend.run_migrations().await.unwrap();
            let holder = hold_a_reader(&backend, Duration::from_secs(1));

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
            holder.await.unwrap();
            assert!(
                read_took >= Duration::from_millis(900),
                "premise: the read was supposed to wait for the held reader, took {read_took:?}"
            );
            assert!(
                fired < Duration::from_millis(250),
                "a 10 ms sleep fired after {fired:?} — the wait for a reader stalled the \
                 runtime's only worker (FSD/SQLITE_CONNECTION_MODEL.md I3)"
            );
        });
    }

    // ── I6 ─────────────────────────────────────────────────────────────
    /// Readers cannot write. A write attempted on a reader is refused with
    /// SQLITE_READONLY — the dynamic net under the static gate.
    #[tokio::test]
    async fn reader_connections_refuse_writes() {
        let path = temp_db_path("readonly");
        let backend = SqliteBackend::open_with_readers(&path, 2).await.unwrap();
        backend.run_migrations().await.unwrap();
        let err = backend
            .read(|conn| conn.execute_batch("CREATE TABLE t829_must_not_exist (x INTEGER)"))
            .await
            .expect_err("a reader must refuse DDL");
        assert!(
            matches!(
                &err,
                rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ReadOnly
            ),
            "expected SQLITE_READONLY, got {err:?}"
        );
        // And the writer confirms nothing happened.
        let n: i64 = backend
            .write(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name = 't829_must_not_exist'",
                    [],
                    |r| r.get(0),
                )
            })
            .await
            .unwrap();
        assert_eq!(n, 0);
    }

    // ── I7 ─────────────────────────────────────────────────────────────
    /// A write on the writer is visible to the next read on a reader with
    /// no explicit sync: WAL readers start a fresh snapshot per statement.
    #[tokio::test]
    async fn readers_see_the_writers_committed_rows() {
        let path = temp_db_path("visibility");
        let backend = SqliteBackend::open_with_readers(&path, 2).await.unwrap();
        backend.run_migrations().await.unwrap();
        let mode: String = backend
            .read(|conn| conn.query_row("PRAGMA journal_mode", [], |r| r.get(0)))
            .await
            .unwrap();
        assert_eq!(mode, "wal", "readers must see the WAL the writer set");
        for i in 0..20 {
            let lease = FederationDirectory::try_acquire_shared_instance(
                &backend,
                &format!("instance-{i}"),
                std::process::id() as i32,
                "vis-host",
                None,
            )
            .await
            .unwrap();
            assert!(lease.is_some());
            let count: i64 = backend
                .read(|conn| {
                    conn.query_row("SELECT COUNT(*) FROM shared_instance_leases", [], |r| {
                        r.get(0)
                    })
                })
                .await
                .unwrap();
            assert_eq!(count, i + 1, "reader saw a stale snapshot after write {i}");
        }
        assert_eq!(backend.read_pool_handle().idle(), 2);
    }

    // ── I8 ─────────────────────────────────────────────────────────────
    /// In-memory has zero readers (a private `:memory:` database is
    /// invisible to a second connection) and reads still work; borrowed-
    /// handle views likewise; `from_handles` SHARES a pool rather than
    /// opening one; `readers = 0` on a file is the documented kill switch.
    #[tokio::test]
    async fn in_memory_and_borrowed_views_have_zero_readers_and_from_handles_shares() {
        let mem = SqliteBackend::open_in_memory().await.unwrap();
        mem.run_migrations().await.unwrap();
        assert_eq!(mem.read_pool_handle().size(), 0);
        point_read(&mem).await;

        let view = SqliteBackend::from_conn_handle(mem.conn_handle());
        assert_eq!(view.read_pool_handle().size(), 0);
        point_read(&view).await;

        let path = temp_db_path("handles");
        let file = SqliteBackend::open_with_readers(&path, 3).await.unwrap();
        file.run_migrations().await.unwrap();
        let shared = SqliteBackend::from_handles(file.conn_handle(), file.read_pool_handle());
        assert!(Arc::ptr_eq(
            &shared.read_pool_handle(),
            &file.read_pool_handle()
        ));
        assert_eq!(shared.read_pool_handle().size(), 3);
        point_read(&shared).await;

        let off = SqliteBackend::open_with_readers(&path, 0).await.unwrap();
        assert_eq!(
            off.read_pool_handle().size(),
            0,
            "readers = 0 is the kill switch"
        );
        point_read(&off).await;

        let mem_by_path = SqliteBackend::open_with_readers(":memory:", 4)
            .await
            .unwrap();
        assert_eq!(mem_by_path.read_pool_handle().size(), 0);
        let uri = format!(
            "file:mem829-{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4()
        );
        let mem_by_uri = SqliteBackend::open_with_readers(uri, 4).await.unwrap();
        assert_eq!(mem_by_uri.read_pool_handle().size(), 0);
    }

    // ── FSD §8: the measurement ────────────────────────────────────────
    /// The issue's shape, in-process and interleaved: a synthetic corpus of
    /// ~24k `observation:` rows + 12 `config:` + 3k `capacity:` from ONE
    /// attester; two tasks looping the filtered `list_attestations`
    /// (attester pinned, `observation:` prefix, limit 10 000 — the
    /// reconcile tick); and a point read (`get_attestation`) probed every
    /// 5 ms for 8 s on a two-worker runtime. Arms alternate on the SAME
    /// corpus file: A = `readers = 0` (the single-connection model: every
    /// read behind the writer mutex), B = the default pool. Three rounds
    /// each, A B A B A B, so a co-tenant hitting one round cannot pass for a
    /// verdict.
    ///
    /// `cargo nextest run --features sqlite --run-ignored ignored-only \
    ///    -E 'test(read_pool_bench)' --no-capture`
    #[test]
    #[ignore = "bench: ~1 min, prints a table; FSD/SQLITE_CONNECTION_MODEL.md §8"]
    fn read_pool_bench() {
        use crate::ceg::ReadEngine;
        use crate::read::AttestationFilter;

        const OBS: usize = 24_000;
        const CAP: usize = 3_000;
        const CFG: usize = 12;
        const ROUNDS: usize = 3;
        const PROBE_SECS: u64 = 8;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let path = temp_db_path("bench");

        // Corpus, once, on the writer.
        rt.block_on(async {
            let backend = SqliteBackend::open_with_readers(&path, 0).await.unwrap();
            backend.run_migrations().await.unwrap();
            backend
                .write(move |conn| -> rusqlite::Result<()> {
                    let tx = super::write_tx(conn)?;
                    for k in ["bench-attester", "occ"] {
                        tx.execute(
                            "INSERT INTO federation_keys (\
                                key_id, pubkey_ed25519_base64, algorithm, identity_type, \
                                identity_ref, valid_from, registration_envelope, \
                                original_content_hash, scrub_signature_classical, \
                                scrub_key_id, scrub_timestamp, persist_row_hash\
                             ) VALUES (?1, 'AAAA', 'hybrid', 'agent', ?1, ?2, '{}', \
                                      x'00', '', ?1, ?2, '0')",
                            rusqlite::params![k, "2026-01-01T00:00:00+00:00"],
                        )?;
                    }
                    let mut ins = tx.prepare(
                        "INSERT INTO federation_attestations (\
                            attestation_id, attesting_key_id, attested_key_id, \
                            attestation_type, weight, asserted_at, expires_at, \
                            attestation_envelope, original_content_hash, \
                            scrub_signature_classical, scrub_signature_pqc, scrub_key_id, \
                            scrub_timestamp, pqc_completed_at, persist_row_hash, \
                            subject_key_ids, withdraws_admission_rule, cohort_scope, tier, \
                            promoted_at, additional_scrubs\
                         ) VALUES (?1, 'bench-attester', 'occ', 'scores', 1.0, ?2, NULL, ?3, \
                                  x'', 'sig', NULL, 'bench-attester', ?2, NULL, '0', '[]', \
                                  NULL, 'federation', 'federation', NULL, '[]')",
                    )?;
                    let mut n = 0usize;
                    for (count, dim) in [
                        (OBS, "observation:reachability:v1"),
                        (CFG, "config:node:v1"),
                        (CAP, "capacity:storage:v1"),
                    ] {
                        for _ in 0..count {
                            n += 1;
                            let id = format!("att-{n:06}");
                            let at = format!(
                                "2026-06-{:02}T{:02}:{:02}:{:02}Z",
                                1 + (n / 86_400) % 28,
                                (n / 3600) % 24,
                                (n / 60) % 60,
                                n % 60
                            );
                            let env = serde_json::json!({
                                "id": id, "dimension": dim, "score": 1.0,
                                "payload": {"seq": n, "note": "synthetic corpus for #829"}
                            })
                            .to_string();
                            ins.execute(rusqlite::params![id, at, env])?;
                        }
                    }
                    drop(ins);
                    tx.commit()
                })
                .await
                .unwrap();
        });

        fn pct(sorted: &[Duration], p: f64) -> Duration {
            let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
            sorted[i.min(sorted.len() - 1)]
        }

        let run_arm = |readers: usize| -> (usize, Duration, Duration, Duration, usize) {
            rt.block_on(async {
                let backend = Arc::new(
                    SqliteBackend::open_with_readers(&path, readers)
                        .await
                        .unwrap(),
                );
                let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let scans = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let mut loops = Vec::new();
                for _ in 0..2 {
                    let b = backend.clone();
                    let stop = stop.clone();
                    let scans = scans.clone();
                    loops.push(tokio::spawn(async move {
                        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                            let page = b
                                .list_attestations(
                                    AttestationFilter {
                                        attesting_key_id: Some("bench-attester".into()),
                                        dimension_prefixes: vec!["observation:".into()],
                                        ..Default::default()
                                    },
                                    None,
                                    10_000,
                                    crate::scope::CallerScope::Unauthenticated,
                                )
                                .await
                                .unwrap();
                            assert_eq!(page.items.len(), 10_000);
                            scans.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }));
                }
                // Let the scans get going before probing.
                tokio::time::sleep(Duration::from_millis(200)).await;
                let mut samples = Vec::new();
                let t_end = Instant::now() + Duration::from_secs(PROBE_SECS);
                while Instant::now() < t_end {
                    let t0 = Instant::now();
                    let got = FederationDirectory::get_attestation(backend.as_ref(), "att-000007")
                        .await
                        .unwrap();
                    samples.push(t0.elapsed());
                    assert!(got.is_some());
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                for l in loops {
                    l.await.unwrap();
                }
                samples.sort();
                (
                    samples.len(),
                    pct(&samples, 0.50),
                    pct(&samples, 0.95),
                    *samples.last().unwrap(),
                    scans.load(std::sync::atomic::Ordering::Relaxed),
                )
            })
        };

        let default_n = super::default_reader_count();
        println!();
        println!(
            "read_pool_bench — corpus {OBS}+{CFG}+{CAP} rows, one attester, 2 scan loops \
                  (limit 10000), point read probed every 5 ms for {PROBE_SECS}s, 2 workers"
        );
        println!(
            "{:<6} {:>8} {:>6} {:>12} {:>12} {:>12} {:>6}",
            "round", "readers", "n", "p50", "p95", "max", "scans"
        );
        for round in 1..=ROUNDS {
            for (label, readers) in [("A", 0usize), ("B", default_n)] {
                let (n, p50, p95, max, scans) = run_arm(readers);
                println!(
                    "{:<6} {:>8} {:>6} {:>12?} {:>12?} {:>12?} {:>6}",
                    format!("{round}{label}"),
                    readers,
                    n,
                    p50,
                    p95,
                    max,
                    scans
                );
            }
        }
    }

    /// FSD §3.2 — the default is `available_parallelism().clamp(2, 8)` unless
    /// the environment overrides it. Asserted only when it is not overridden,
    /// and the override arm is asserted through `open` on a file.
    #[tokio::test]
    async fn default_reader_count_is_clamped_and_open_honours_it() {
        if std::env::var(super::READERS_ENV).is_err() {
            let n = super::default_reader_count();
            assert!(
                (2..=8).contains(&n),
                "default reader count {n} outside [2, 8]"
            );
            let path = temp_db_path("default-n");
            let backend = SqliteBackend::open(&path).await.unwrap();
            assert_eq!(backend.read_pool_handle().size(), n);
        }
    }
}

// ── CIRISPersist#1246: page cache and mmap ────────────────────────────────

#[cfg(test)]
mod tuning_1246_tests {
    use super::{
        apply_tuning, default_mmap_bytes, resolve_tuning, tuning_from_env, SqliteTuning,
        DEFAULT_CACHE_KIB, DEFAULT_MMAP_BYTES,
    };
    use crate::store::sqlite::SqliteBackend;

    const GIB: u64 = 1 << 30;

    /// I1720 — the defaults, the memory-limit scaling, and the knobs:
    /// a malformed knob is refused, never read as the default.
    #[test]
    fn i1720_tuning_rules() {
        let d = resolve_tuning(None, None, None).unwrap();
        assert_eq!(
            d,
            SqliteTuning {
                mmap_bytes: GIB,
                cache_kib: 32 * 1024
            }
        );
        assert_eq!(DEFAULT_MMAP_BYTES, GIB);
        assert_eq!(DEFAULT_CACHE_KIB, 32 * 1024);
        // canonical-1's 2 GiB container: a quarter of it.
        assert_eq!(default_mmap_bytes(Some(2 * GIB)), GIB / 2);
        assert_eq!(
            resolve_tuning(None, None, Some(2 * GIB))
                .unwrap()
                .mmap_bytes,
            GIB / 2
        );
        // A large limit does not raise the ceiling.
        assert_eq!(default_mmap_bytes(Some(64 * GIB)), GIB);
        // The knobs win over the default and over the limit.
        let t = resolve_tuning(Some("0"), Some("65536"), Some(2 * GIB)).unwrap();
        assert_eq!(t.mmap_bytes, 0, "0 turns mmap off");
        assert_eq!(t.cache_kib, 65536);
        assert_eq!(
            resolve_tuning(Some(" 268435456 "), None, None)
                .unwrap()
                .mmap_bytes,
            256 << 20
        );
        for bad in ["1G", "-1", "", "abc", "1.5"] {
            let e = resolve_tuning(Some(bad), None, None).unwrap_err();
            assert!(
                e.contains("CIRIS_PERSIST_SQLITE_MMAP_BYTES"),
                "{bad:?}: {e}"
            );
        }
        for bad in ["0", "-5", "", "32M", "4294967296"] {
            let e = resolve_tuning(None, Some(bad), None).unwrap_err();
            assert!(e.contains("CIRIS_PERSIST_SQLITE_CACHE_KIB"), "{bad:?}: {e}");
        }
    }

    /// `PRAGMA mmap_size` returns no row on a database with no file (an
    /// in-memory one), so that reads back as `None`.
    fn read_mmap(conn: &rusqlite::Connection) -> Option<u64> {
        use rusqlite::OptionalExtension;
        conn.query_row("PRAGMA mmap_size", [], |r| r.get::<_, i64>(0))
            .optional()
            .unwrap()
            .map(|n| n as u64)
    }

    fn read_tuning(conn: &rusqlite::Connection) -> (u64, i64) {
        let mmap = read_mmap(conn).expect("a file-backed connection reports mmap_size");
        let cache: i64 = conn
            .query_row("PRAGMA cache_size", [], |r| r.get(0))
            .unwrap();
        (mmap, cache)
    }

    /// I1721 — a file-backed open applies the tuning to the writer and to
    /// EVERY reader (all held at once, so no reader is read twice), and the
    /// pool still reads what the writer committed.
    #[tokio::test]
    async fn i1721_open_applies_tuning_to_writer_and_every_reader() {
        let want = tuning_from_env().expect("this process's knobs parse");
        let path = super::witnesses::temp_db_path("1246");
        let backend = SqliteBackend::open_with_readers(&path, 3).await.unwrap();
        {
            let w = backend.conn_handle();
            let w = w.lock();
            assert_eq!(
                read_tuning(&w),
                (want.mmap_bytes, -(want.cache_kib as i64)),
                "writer"
            );
            w.execute_batch("CREATE TABLE t1246 (x INTEGER); INSERT INTO t1246 VALUES (1246);")
                .unwrap();
        }
        let pool = backend.read_pool_handle();
        assert_eq!(pool.size(), 3);
        let guards: Vec<_> = (0..3).map(|_| pool.acquire()).collect();
        for (i, g) in guards.iter().enumerate() {
            assert_eq!(
                read_tuning(g),
                (want.mmap_bytes, -(want.cache_kib as i64)),
                "reader {i}"
            );
            let x: i64 = g
                .query_row("SELECT x FROM t1246", [], |r| r.get(0))
                .unwrap();
            assert_eq!(x, 1246, "reader {i} sees the writer's commit with mmap on");
        }
    }

    /// I1722 — `apply_tuning` sets exactly what it is given (both pragmas,
    /// mmap off included), and an in-memory open is left at SQLite's
    /// defaults: mmap does not apply to a private in-memory database.
    #[tokio::test]
    async fn i1722_apply_tuning_is_exact_and_in_memory_is_untouched() {
        let conn = rusqlite::Connection::open(super::witnesses::temp_db_path("1246b")).unwrap();
        let t = SqliteTuning {
            mmap_bytes: 64 << 20,
            cache_kib: 4096,
        };
        apply_tuning(&conn, &t).unwrap();
        assert_eq!(read_tuning(&conn), (64 << 20, -4096));
        apply_tuning(
            &conn,
            &SqliteTuning {
                mmap_bytes: 0,
                cache_kib: 1,
            },
        )
        .unwrap();
        assert_eq!(read_tuning(&conn), (0, -1));

        let mem = SqliteBackend::open_in_memory().await.unwrap();
        let w = mem.conn_handle();
        let w = w.lock();
        assert!(
            matches!(read_mmap(&w), None | Some(0)),
            "in-memory: no mmap"
        );
        let cache: i64 = w.query_row("PRAGMA cache_size", [], |r| r.get(0)).unwrap();
        assert_ne!(
            cache,
            -(DEFAULT_CACHE_KIB as i64),
            "in-memory: SQLite's default cache"
        );
    }
}
