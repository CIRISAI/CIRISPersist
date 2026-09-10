# FSD: The SQLite Connection Model — CIRISPersist

**Status:** Adopted (CIRISPersist#829, the v43.0.0 → next-minor headline)
**Author:** Eric Moore (CIRIS Team) with Claude
**Created:** 2026-09-09
**Repo:** `~/CIRISPersist`
**Risk:** Storage-layer, node-local. No on-disk format change, no wire
change. Post-2.9.0 persist is the sole DB opener, so the connection model
is persist's to change **unilaterally**; consumers see only latency.

---

## 1. Why this exists

`src/store/sqlite.rs` is 45k lines and its module doc was wrong about the
one thing that decides how the file behaves under load. It said:

> **Async adapter**: `tokio::task::spawn_blocking` wraps every SQL call.

Twenty lines below, a comment records that this stopped being true in
v3.14.0 (CIRISPersist#158). In v43.0.0 the file has **351 `conn.lock()`
sites and 20 `spawn_blocking` sites**, one `Arc<Mutex<Connection>>`, and
WAL on. The premise the doc gave for the single connection —

> Phase 1 has one ingest writer per process … contention on the mutex is
> structurally negligible

— described a lens landing traces. It does not describe a node that serves
a read API off the same engine, which is every server node today.

The cost was measured downstream before it was measured here.
CIRISServer#575: two 30 s reconcile loops whose ticks call the filtered
`list_attestations` (inline, under the mutex) stall the node's own
`GET /v1/identity` from p50 1.1 ms to **780 ms — ~700×, zero non-200s**.
CIRISEdge#547 is the same mechanism carried to its end: the connection
holder is in `state=D` page-faulting a corpus scan, every other runtime
thread is in `futex_wait` behind it, health times out, and the node never
recovers. **Two stalls and one hang, in two repos, from one connection.**

This document is the connection model as it is now, and the record of why
the previous one was wrong. It exists *before* the code because the
previous doc was the thing that was wrong.

## 2. The model as it was (v3.14.0 → v43.0.0)

```
                 ┌──────────────────────────┐
  async caller ──┤ conn.lock()  (parking_lot)├── one rusqlite::Connection
  async caller ──┤   inline, no yield         │   journal_mode = WAL
  async caller ──┤   on the tokio worker      │
                 └──────────────────────────┘
```

- **One connection**, writer and reader alike, behind one sync mutex.
- **Inline-sync**: every call ran the SQL on whichever tokio worker polled
  it, with no `.await` point on the sqlite path. A 700 ms scan occupied a
  worker for 700 ms; on a 2-vCPU node that is half the runtime.
- **The mutex wait was also inline**: `parking_lot::Mutex::lock()` in an
  async fn parks the *worker thread*. A reader waiting for the connection
  did not just delay its own caller — it consumed a worker that was
  serving unrelated requests. This is why more workers (CIRISServer#446,
  #501) did not help: more workers is more threads in `futex_wait`.
- WAL was on, but WAL's concurrency (many readers alongside one writer)
  is a property of *separate connections*. With one connection there were
  no separate readers for WAL to serve. The pragma bought crash
  durability and nothing else.

### 2.1 Why v3.14.0 removed `spawn_blocking`, and why that reason still binds

#158 was real and its rationale is preserved, not overridden.
`tokio::task::spawn_blocking` reads a **thread-local** — the current
runtime of the tokio crate *that compiled the call*. Under the
cohabitation path (CIRISPersist#157) a consumer wheel statically links its
own copy of persist, compiled against its own tokio; when that copy's
`spawn_blocking` runs on a persist-owned worker, its thread-local is unset
and it panics with `there is no reactor running`. Five fixes were tried
(a `Handle` field — ABI break; a `OnceLock<Handle>` — per-DSO statics; a
`#[no_mangle]` accessor — `RTLD_LOCAL`; `RTLD_GLOBAL` — `Handle`'s
private layout is not stable across tokio patches). The inline rewrite was
the fifth: stop calling tokio primitives at all.

What v3.14.0 did not consider is the sixth option: **ask the thread-local
instead of assuming it.** `tokio::runtime::Handle::try_current()` is the
same thread-local read, but it returns `Err` where `spawn_blocking` would
panic. §3.3 builds on exactly that. The #158 property — *persist's sqlite
path never panics for lack of a runtime* — is kept as invariant I5 and has
a witness that drives the backend from a hand-rolled executor with no
tokio runtime on the thread at all.

## 3. The model as it is now (#829)

```
                             ┌───────────────────────────────┐
  write ── spawn_blocking ───┤ writer  Mutex<Connection>      │ READ_WRITE|CREATE
                             │   PRAGMA setup, migrations,    │ journal_mode = WAL
                             │   every tx that writes         │
                             └───────────────────────────────┘
                             ┌───────────────────────────────┐
  read  ── spawn_blocking ───┤ ReadPool: N × Connection       │ each READ_ONLY,
  read  ── spawn_blocking ───┤   free-list + condvar          │ foreign_keys = ON,
  read  ── spawn_blocking ───┤   acquire → run → return       │ busy_timeout,
                             └───────────────────────────────┘ query_only = ON
```

### 3.1 One writer, N readers

- The **writer** is the existing `Arc<parking_lot::Mutex<Connection>>`,
  opened exactly as before (`Connection::open`, then the PRAGMA block).
  It is the only connection that ever writes, runs migrations, or changes a
  database-level PRAGMA. `conn_handle()` / `from_conn_handle()` — the
  public surface sibling modules ride on — keep returning it.
- The **readers** are `N` additional connections to the same file, each
  opened `SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX | SQLITE_OPEN_URI`
  **after** the writer has set `journal_mode = WAL` (a read-only
  connection cannot change the journal mode, so the order is load-bearing).
  Per-connection PRAGMAs are re-applied on each reader because they are
  per-connection state: `foreign_keys = ON`, `busy_timeout = 30000`, plus
  `query_only = ON` as a second fence behind the open flag. `journal_mode`,
  `synchronous`, `wal_autocheckpoint`, `journal_size_limit` are not set on
  readers: the first is a database property the writer already set; the
  others govern writes and checkpoints, which readers never perform.
- The pool is hand-rolled: `parking_lot::Mutex<Vec<Connection>>` as a
  free list plus a `parking_lot::Condvar`. `acquire` pops a connection or
  waits on the condvar; the guard pushes it back and `notify_one`s on
  drop. No tokio primitive is involved, so it works with no runtime on
  the thread (§2.1). It is not `r2d2`/`deadpool`: those add a dependency
  and a runtime coupling for a data structure that is thirty lines.
- **Read-only is the safety net for misclassification.** A method filed
  as a read that tries to write gets `SQLITE_READONLY` — a loud error in
  the first test that reaches it, not a silent write on the wrong
  connection. The classification gate (§5) is the static check; the open
  flag is the dynamic one. Both are needed: the gate cannot see through a
  helper in another file, the flag cannot see a method no test reaches.

### 3.2 Pool size

Default `N = available_parallelism().clamp(2, 8)`. Two is the floor
because one reader cannot demonstrate the property this exists for (a
held reader must not block the next). Eight is the ceiling because each
connection carries its own page cache (SQLite's default ~2 MiB) and a
Pi-class node gains nothing past the point where readers outnumber the
cores that could run them; a reader blocked on a page fault (CIRISEdge#547)
still leaves N−1 readers serving.

Override: `SqliteBackend::open_with_readers(path, n)`, or the environment
variable `CIRIS_PERSIST_SQLITE_READERS` read by `open`. `0` is legal and
means "no pool" — reads fall back to the writer mutex (still off the
runtime, §3.3). It exists so an operator can A/B the pool without a
rebuild, and so a bug in the pool has a one-line kill switch.

### 3.3 Off the runtime, when there is one

Every read and every write goes through one dispatcher:

```rust
match tokio::runtime::Handle::try_current() {
    Ok(h)  => h.spawn_blocking(move || f(conn)).await   // off the worker
    Err(_) => f(conn)                                   // #158: no runtime, run inline
}
```

- With a runtime current, the SQL — *and the wait for the connection* —
  runs on tokio's blocking pool. The worker that polled the call is free
  to poll something else. This is the half of the defect that
  "restore `spawn_blocking`" alone would fix.
- With no runtime current (the cohabitation copy on a foreign worker, or
  any caller driving the future by hand), the call runs inline exactly as
  v3.14.0 did. It cannot panic: `try_current` is the same thread-local
  read `spawn_blocking` would have done, asked politely.
- A panic inside the closure is re-raised on the caller with
  `resume_unwind`, so the observable behaviour matches the inline case.
  A join cancelled by runtime shutdown is a panic naming the cause; there
  is no value to return and the caller's task is being torn down anyway.

**Writes move too.** The runtime-stall half of #829 applies to writes
identically — a write waiting for the writer mutex behind a long
transaction parks its worker just as a read did — and #158's reason for
not doing this is answered by the fallback above. Writes keep the single
writer mutex; that is what SQLite's one-writer rule needs, and what
`BEGIN IMMEDIATE`/`transaction()` bodies assume.

### 3.4 What stays on the writer

- Anything inside a transaction that writes, including its reads — a
  check-then-act (`has_blob`'s access-count touch, `register_accord_public_key`'s
  insert-then-classify, the lease acquire) must see its own uncommitted
  state and be atomic under the one mutex it was written for.
- `run_migrations` / `run_migrations_through`, the PRAGMA block, `VACUUM`,
  `wal_checkpoint`, any `ATTACH`.
- Anything that reads `last_insert_rowid()` / `changes()` — connection
  state that is only meaningful on the connection that wrote. (There are
  no such sites in `sqlite.rs` today; the rule is stated so the next one
  goes to the right place.)
- Read-named methods that write. `get_blob`, `get_blob_range`, `has_blob`
  bump `access_count`/`last_accessed_at` in a transaction; they are writes
  and the table (§5) files them as such.

### 3.5 Read-after-write visibility

A reader connection with no open transaction starts a fresh WAL snapshot
on every statement, and that snapshot includes every frame the writer has
committed. So `put_x().await` followed by `get_x().await` on the same
backend sees the row, on any reader. Read closures never leave a
transaction open — the pool guard `debug_assert!`s `is_autocommit()` when
a reader is returned, because a reader holding a snapshot is also a
reader pinning the WAL against checkpoint (the #768 liveness note).
Witnessed by I7 (twenty write-then-read rounds, every read on a reader).

## 4. The in-memory case

`open_in_memory()` — used by hundreds of tests and by sovereign-mode dev
scratch — gets **a pool of zero readers; reads fall back to the writer
connection**, dispatched exactly as §3.3 (off the runtime when there is
one).

The alternative was a shared-cache URI
(`file:<unique>?mode=memory&cache=shared`) so N connections see one
in-memory database. Rejected, for this cut, because shared-cache is a
different concurrency model, not a smaller instance of WAL: locking is
per-table, a reader can receive `SQLITE_LOCKED` (which `busy_timeout`
does not retry — it needs `sqlite3_unlock_notify`), `journal_mode = WAL`
is silently `memory`, and the mode is documented by SQLite as
discouraged. Hundreds of green tests would become hundreds of tests of a
mode production never runs. Every witness of the pool itself is
file-backed (`tempfile`), which is the mode production does run.

The same zero-reader fallback applies to `from_conn_handle(writer)`: a
view built over a borrowed writer has no path to open readers against and
no business opening more file handles per view. Readers are shared, not
duplicated: `SqliteBackend::from_handles(writer, readers)` is the
constructor for a sibling view that should read through the pool, and
`read_pool_handle()` exposes the pool the way `conn_handle()` exposes the
writer. `cirisnode::sqlite`'s directory views (three `from_conn_handle`
sites) are moderation/admission walks inside a write path and stay on the
writer by design (§3.4).

## 5. The classification rule, and the gate that enforces it

Every `fn` in the production text of `src/store/sqlite.rs` that touches a
connection is in `SQLITE_CONN_CLASSES` (`src/store/sqlite_conn_model.rs`),
with one of:

| class | means | the gate checks |
|---|---|---|
| `Read` | uses `self.read(…)` only | never `self.conn`, `self.write(`, `conn.lock()`; body has no write verb (`INSERT`, `UPDATE`, `DELETE`, `REPLACE`, `CREATE`, `DROP`, `ALTER`, `.execute(`, `.transaction(`, `execute_batch(`); calls no `HelperWrite` |
| `Write` | uses `self.write(…)` (may also `self.read(…)` for a pre-check that need not be atomic with the write) | mentions the writer path |
| `HelperRead` | free fn taking `&Connection`, called from inside a closure | no write verb in body |
| `HelperWrite` | free fn taking `&Connection`/`&mut Connection`/`&Transaction` that writes | — |
| `Door` | the two doors and the two handle accessors — `read`, `write`, `conn_handle`, `read_pool_handle` | the set is pinned by name; nothing else may be filed here |

Two free `async fn`s take `&SqliteBackend` rather than a connection and
go through the doors as `backend.read(…)` / `backend.write(…)`
(`check_revocation_anti_rollback_sqlite`, `sqlite_update_peer_field`);
they are filed `Read` / `Write` like any method. Token matching is
whitespace-insensitive because rustfmt splits `self.read(` into
`self\n    .read(` in a chained expression — the first version of the gate
found 200 of 286 fns for exactly that reason, and a parser floor
(≥ 350 production fns, ≥ 250 touching a connection) is what turned that
into a red rather than a quiet pass.

As shipped: **286 rows — Read 155, Write 121, Door 4, HelperRead 3,
HelperWrite 3, unclassified 0.**

The gate is from-disk (the `parity.rs` / `blob_surface_gates.rs` idiom:
read the source as text, strip test modules, scan) and is a **partition in
both directions**: an fn that touches a connection and is not in the table
reds the build naming the fn; a table row naming an fn that no longer
exists reds the build; a `Read` whose body reaches the writer, a write
verb, or a `HelperWrite` reds the build. There is no "unclassified"
bucket — the whole point is that nothing can be silently on the wrong
connection.

The rule for filing: **classify by what the body does, not what the name
says.** `has_blob` writes. `list_*` reads. A method that writes in one
branch is a `Write`.

## 6. The one-by-one review (things that assumed a single connection)

Filled in as the build proceeded; every row is a place the author
had to look, not a list of things that were broken.

| site | assumption | disposition |
|---|---|---|
| `SharedInstanceLease` (`try_acquire_shared_instance`, `heartbeat_shared_instance`, `release_shared_instance`, `get_shared_instance`) | "exactly one winner" from a single-statement upsert | atomicity is the statement's, not the connection's; acquire/heartbeat/release are `Write`; `get_shared_instance` is a `Read` and observes the committed lease like any other reader |
| `insert_trace_events_batch` — `MAX(admitted_at)` read inside the tx | the read must see concurrent batches | inside the write tx on the writer — unchanged |
| `register_accord_public_key` — insert-then-read-on-no-op | same connection sees the row that won | one `Write` closure — unchanged |
| `get_blob` / `get_blob_range` / `has_blob` | read-named; write `access_count` in a tx | `Write` (§3.4) |
| `sqlite_load_stream_chunk_hashes(&Arc<Mutex<Connection>>, …)` | took the writer handle by reference | now takes `&Connection` (`HelperRead`); its three callers run it inside `self.read(…)` |
| `check_revocation_anti_rollback_sqlite(&Arc<Mutex<Connection>>, …)` | same | now takes `&SqliteBackend` and reads through `backend.read(…)` (`Read`); the write it guards happens after it on the writer — the window between was already there, since the check and the insert were two lock acquisitions |
| `sqlite_update_peer_field(backend, …)` | free fn that opened a tx on the writer | `backend.write(…)` (`Write`) |
| `sqlite_next_key_serve_position` / `sqlite_next_plane_position` | `MAX(position)` reads called from inside write closures to allocate the next position | `HelperRead` by body; every production caller is a `Write` closure, so the allocation stays under the writer mutex. `next_key_admission_position` (the door for callers that do NOT yet hold the writer) became `async` and reads on a reader — it never held the lock across the following write |
| `put_revocation` / `put_accord_proposal` / `put_accord_participation` — `MAX(admitted_at | created_at | server_arrival_at)` read before the INSERT | the comment claimed "read under the same connection lock as the INSERT" | it was not: the block released the guard before the write closure took it. The read now runs on a reader; the comment is corrected. Folding the read into the write closure (as `insert_trace_events_batch` does) is the real fix for the two-writer tie and is out of scope here |
| `sqlite_upsert_wire_index` / `sqlite_project_attestation_subjects` / `sqlite_project_consent_peer_set` | take `&Connection`/`&Transaction` and write | `HelperWrite`; the gate refuses any `Read` body that names them |
| `index_stored_record` | `sqlite_upsert_wire_index(&conn.lock(), …)` inside an `async` block | one `self.write(…)` |
| `load_or_init_content_master` — local closure over `&Arc<Mutex<Connection>>` | read-before-insert-then-re-read on one handle | nested `fn(&Connection)` run through `self.read(…)` twice; the INSERT between them is `ON CONFLICT DO NOTHING` on the writer and the re-read is the authority, as before |
| `reanchor_*` / `list_scores` / `list_attestation_log` / `record_announced_peer` / `list_announced_peers` / `resolve_scores` (the 20 `spawn_blocking` sites) | already off the runtime, still on the one connection | rewritten to the doors; their `join` error arms are gone (the dispatcher re-raises a panic and never returns a join error) |
| `has_blob` / `get_blob` / `get_blob_range` | `let mut conn` + `transaction()` | `Write` (§3.4) — filed by body |
| `get_attestation` (FederationDirectory) and `list_attestations_for` / `lookup_public_key` (two impls each) | same name, two bodies | keyed by name; both occurrences must carry one class and the gate checks each |
| `run_migrations_through` (test-anchor) | refinery needs `&mut Connection` | writer |
| `PRAGMA table_info` reads | none in production text (test-only) | — |
| `last_insert_rowid` / `changes()` | none in `sqlite.rs` | rule stated in §3.4 |
| `TEMP` tables | none | — |
| `from_conn_handle` views (`cirisnode::sqlite` ×3, `engine.rs`, `ffi/pyo3.rs`) | one connection per view | zero readers, reads fall back to the writer (§4); reads through the pool need `from_handles` |
| Sibling modules that lock `conn_handle()` themselves (`audit/sqlite.rs` 22 sites, `retention`, `telemetry`, `scheduled_tasks`, `secrets`, `ledgers`, `cirisnode`, …) | inline, single connection | **out of scope for #829** — they are not `sqlite.rs` and the issue's stall is `sqlite.rs`'s `list_*` family. Recorded here so the next cut has the list; the same `read`/`write` dispatcher is what they should adopt |

## 7. Invariants

- **I1 — Occupancy.** With one reader connection held inside a long
  query, a second read on the same backend completes.
  `read_completes_while_one_reader_is_held_in_a_long_query`.
- **I2 — Held writer does not block readers.** With the writer mutex held
  (the CIRISEdge#547 shape), a read completes.
  `read_completes_while_the_writer_connection_is_held`.
- **I3 — Runtime liveness.** A read that waits (on a held reader, or on
  the writer in the zero-reader case) does not stall the runtime: a
  concurrent `tokio::time::sleep(10 ms)` on a one-worker runtime fires
  within 250 ms while the read is in flight.
  `runtime_keeps_spinning_while_a_read_waits_on_a_reader`,
  `runtime_keeps_spinning_while_an_in_memory_read_waits_on_the_writer`.
- **I4 — Classification is a partition.** §5's gate. Mutation M1 (below):
  routing one `Read` back to the writer reds it.
- **I5 — No runtime, no panic** (#158 preserved). A read and a write
  driven by an executor with no tokio runtime on the thread both complete.
  `sqlite_path_runs_with_no_tokio_runtime_on_the_thread`.
- **I6 — Readers cannot write.** A write attempted on a reader connection
  is refused with `SQLITE_READONLY`. `reader_connections_refuse_writes`.
- **I7 — Readers see committed writes.** A write on the writer is visible
  to the next read on any reader with no explicit sync.
  `readers_see_the_writers_committed_rows`.
- **I8 — In-memory and borrowed views have zero readers and stay green;
  `from_handles` shares.** The pool reports `0` for `open_in_memory`,
  `from_conn_handle`, `readers = 0`, `":memory:"` and a `file:…mode=memory`
  URI; `from_handles` returns the same `Arc`; the whole existing sqlite
  suite runs on the zero-reader path.
  `in_memory_and_borrowed_views_have_zero_readers_and_from_handles_shares`.
- **I9 — The default is bounded.** `default_reader_count()` is in `[2, 8]`
  when the environment does not override it, and `open` uses it.
  `default_reader_count_is_clamped_and_open_honours_it`.

### 7.1 Mutations (the witnesses were tested, not just the fix)

- **M1** — `get_attestation` routed through `self.write(…)` instead of
  `self.read(…)`. RED: the I4 gate (`get_attestation reaches the writer via
  self.write(`), I2 (the read waited 2.000 s behind the held writer), and
  the reader arm of I3 (its premise — the read must wait on the reader —
  no longer held). 12/15 otherwise green; reverted.
- **M2** — `dispatch_blocking` forced onto its inline arm. RED: both I3
  witnesses (the 10 ms sleep fired after ~1.0 s on the in-memory arm and
  the reader arm alike). 13/15 otherwise green; reverted.

## 8. The measurement

The issue's shape: a synthetic corpus of 24 000 `observation:` + 12
`config:` + 3 000 `capacity:` attestation rows from ONE attester; two tasks
looping the filtered `list_attestations` (attester pinned, `observation:`
prefix, limit 10 000 — the reconcile tick); a point read
(`get_attestation`) probed every 5 ms for 8 s on a two-worker runtime.
p50/p95 of the point read, before and after, **interleaved A/B in one
process on one corpus file** (a blocked run cannot tell a regression from
a co-tenant; see `feedback_interleave_ab_perf_runs`). Arm A opens the
backend with `readers = 0` — the single-connection model exactly: same
writer, every read behind the same mutex. Arm B is the default pool.

`cargo nextest run --features sqlite --run-ignored ignored-only -E 'test(read_pool_bench)' --no-capture`
— `store::sqlite_conn_model::witnesses::read_pool_bench`.

### 8.1 Results (debug profile, 32-core box, default pool = 8 readers)

| round | readers | probes (n) | p50 | p95 | max | scans in 8 s |
|---|---:|---:|---:|---:|---:|---:|
| 1A | 0 | 41 | 180.5 ms | 347.5 ms | 380.4 ms | 44 |
| 1B | 8 | 1220 | 249 µs | 346 µs | 3.9 ms | 76 |
| 2A | 0 | 34 | 179.5 ms | 334.0 ms | 499.5 ms | 37 |
| 2B | 8 | 1199 | 265 µs | 465 µs | 19.8 ms | 66 |
| 3A | 0 | 32 | 183.3 ms | 336.4 ms | 513.7 ms | 35 |
| 3B | 8 | 1218 | 258 µs | 387 µs | 4.7 ms | 65 |

Three things the table says, in order of importance:

1. **p50 ~700× lower** with the pool (≈180 ms → ≈250 µs), the same ratio
   CIRISServer#575 measured on the canonical (1.1 ms → 780 ms). The point
   read no longer waits for a scan to finish.
2. **The probe loop itself was starved on arm A** — 32–41 probes in 8 s
   against ~1200 — which is the "nothing fails, it hangs" the issue
   describes: an uptime check on arm A would have called the node healthy.
3. **Scan throughput rose** (35–44 → 65–76 per 8 s) because the two loops
   run on two readers instead of taking turns on one connection.

Absolute numbers are debug-profile and box-specific; the ratio is the
finding. Arm A is not byte-for-byte v43.0.0 — v43.0.0 also ran the wait
*inline on the worker*, which this harness cannot show as latency (it is
I3's domain); arm A reproduces the serialization, which is the half that
produced the numbers above.

## 9. What this does not do

- It does not make any single query faster. A 700 ms scan is still 700 ms;
  it no longer costs anyone else 700 ms.
- It does not pool writers. SQLite has one.
- It does not change the sibling modules (§6, last row).
- It does not touch Postgres, whose `deadpool` pool already had this
  shape; the parity gate (`store::parity`) sees `read`/`write` as
  `Plumbing`, which is what they are.
