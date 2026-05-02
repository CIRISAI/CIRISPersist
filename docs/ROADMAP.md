# Roadmap — v0.1.21 → v0.4.x

**Status:** dependency waterfall. Positions in the Gantt below
indicate **sequence**, not delivery dates. Each milestone ships
when its dependencies are green; phases are gated by their
predecessor, work within a phase parallelizes where shown.

Companion docs:
- [`docs/FEDERATION_DIRECTORY.md`](./FEDERATION_DIRECTORY.md) — v0.2.0+ federation directory contract (registry-aligned)
- [`docs/V0.2.0_VERIFY_SUBSUMPTION.md`](./V0.2.0_VERIFY_SUBSUMPTION.md) — verify subsumption plan (now v0.2.x; doc filename retained for git-history continuity)
- [`docs/COHABITATION.md`](./COHABITATION.md) — v0.1.14+ runtime keyring authority (foundation; v0.2.0 builds on it)

---

## Unified dependency graph

```mermaid
gantt
    title CIRIS Persist roadmap — dependencies, not timelines
    dateFormat X
    axisFormat %s

    section v0.1.21 — SQLite Backend Phase 1 parity
    Translate migrations/sqlite/lens/V001 + V003 (postgres → sqlite)  :v121a, 0, 1
    SqliteBackend skeleton (rusqlite + spawn_blocking adapter)        :v121b, after v121a, 1
    insert_trace_events_batch (ON CONFLICT DO NOTHING)                :v121c1, after v121b, 1
    insert_trace_llm_calls_batch                                      :v121c2, after v121b, 1
    lookup_public_key + sample_public_keys                            :v121c3, after v121b, 1
    run_migrations (refinery sqlite)                                  :v121c4, after v121b, 1
    Mirror postgres test suite against SqliteBackend                  :v121d, after v121c1 v121c2 v121c3 v121c4, 1
    Cargo.toml feature wiring + store/mod.rs export                   :v121e, after v121d, 1
    CHANGELOG + v0.1.21 release                                       :v121f, after v121e, 1

    section v0.2.0 — Federation Directory (schema + trait + bootstrap)
    federation_keys schema + V004 migration SQL           :v20a, after v121f, 1
    FederationDirectory trait + serde types               :v20b, after v121f, 1
    Memory backend impl                                   :v20c1, after v20b, 1
    Postgres backend impl                                 :v20c2, after v20a v20b, 1
    SQLite backend impl                                   :v20c3, after v20a v20b, 1
    Bootstrap migration (persist-steward self-signed row) :v20d, after v20c2 v20c3, 1
    Write-authority guards (rate limit + per-primitive quota) :v20e, after v20c2 v20c3, 1
    persist_row_hash on row reads                         :v20f, after v20c2 v20c3, 1
    Fixture JSON for registry serde validation            :v20g, after v20c1, 1
    persist-steward fingerprint published                 :v20h, after v20d, 1
    Cut v0.2.0-pre1 (registry-unblock milestone)          :v20i, after v20d v20e v20f v20g v20h, 1
    Tests + CHANGELOG + v0.2.0 final release              :v20j, after v20i, 1

    section v0.2.x — Verify Subsumption (CIRISPersist#4)
    Pin bump ciris-verify-core 1.8.0 → 1.8.4              :v2xa, after v20j, 1
    Existing test suite green vs new pin                  :v2xb, after v2xa, 1
    Cryptographic proxies (sign / public_key / attest)    :v2xc1, after v2xb, 1
    License + integrity proxies                           :v2xc2, after v2xb, 1
    Build-manifest proxies (with implicit pubkey lookup)  :v2xc3, after v2xb, 1
    Hybrid-signing proxy                                  :v2xc4, after v2xb, 1
    PyO3 wheel smoke tests                                :v2xd, after v2xc1 v2xc2 v2xc3 v2xc4, 1
    Lens integration tests                                :v2xe, after v2xd, 1
    CHANGELOG + v0.2.x release                            :v2xf, after v2xe, 1

    section v0.3.0 — Federation surface completion
    federation_attestations schema + trait                :v30a, after v2xf, 1
    federation_revocations schema + trait                 :v30b, after v2xf, 1
    Bilateral divergence telemetry                        :v30c, after v2xf, 1
    Registry dual-write integration (full surface)        :v30d, after v30a v30b v30c, 1
    Production-traffic schema soak                        :v30e, after v30d, 1
    as_of: Option<DateTime> on read methods (Policy B)    :v30f, after v30d, 1

    section v0.4.0 — Read-path migration
    Switch lookup_public_key → federation_keys            :v40a, after v30e, 1
    Backfill validation (parity counter)                  :v40b, after v40a, 1
    Experimental schema contract retires                  :v40c, after v40b, 1
    CHANGELOG + v0.4.0 release                            :v40d, after v40c, 1

    section v0.4.x — Deprecation + polish (parallelizable)
    accord_public_keys → read-only view                   :v4xa, after v40d, 1
    PG NOTIFY pubsub (cache coherence)                    :v4xb, after v40d, 1
    Trust-contract diff lands (registry side)             :v4xc, after v40d, 1
```

---

## Phase-by-phase waterfall

### v0.1.21 — SQLite Backend Phase 1 parity

**Gates next phase on:** SQLite is a declared-but-stubbed
feature today (rusqlite pinned since v0.1.9, sqlite feature
flag declared, empty `migrations/sqlite/`). v0.1.21 makes it
real — sovereign-mode (single-node, no Postgres) and Pi-class
deployments per FSD §7 #7 become viable. Lens team requested
parity before v0.2.0.

**Sequential dependencies:**

```
v121a (migrations translated)
  → v121b (SqliteBackend skeleton with rusqlite + spawn_blocking)
  → [v121c1 ║ v121c2 ║ v121c3 ║ v121c4]   (parallel: independent
                                            trait methods)
  → v121d (test parity vs postgres)
  → v121e (Cargo wiring + export)
  → v121f (release)
```

**Parallelizable inside the phase:** the four trait methods
(`v121c1`–`v121c4`) — independent, share only the connection
pool. Memory backend's parity test suite is the spec; SQLite
must produce identical insert / lookup / sample results given
identical inputs.

**Schema translation gotchas (V001):**

- `BIGSERIAL` → `INTEGER PRIMARY KEY AUTOINCREMENT` (single-col
  PK; postgres' composite PK on `(event_id, ts)` collapses to
  `event_id` since SQLite uses rowid for ordering)
- `TIMESTAMPTZ` → `TEXT` (ISO-8601 with timezone — wire-format
  preservation matters per v0.1.8's WireDateTime doctrine)
- `JSONB` → `TEXT` (SQLite has json1 extension for queries; we
  store payload verbatim either way)
- `BOOLEAN` → `INTEGER` (0/1; SQLite has no native bool)
- `DOUBLE PRECISION` / `NUMERIC(10,6)` → `REAL`
- `CREATE SCHEMA cirislens` + `cirislens.table` → drop schema
  prefix; SQLite has no schemas
- `IS DISTINCT FROM` → `IS NOT`
- TimescaleDB hypertable creation → skip entirely
- `DEFAULT NOW()` → `DEFAULT CURRENT_TIMESTAMP`

---

### v0.2.0 — Federation Directory (registry-unblock milestone)

**Gates next phase on:** federation directory schema + trait + bootstrap
row land in production, unblocking CIRISRegistry's v1.4 scaffolding
(already shipped against the original v0.2.0-pre1 expectation per
[`CIRISRegistry/docs/FEDERATION_CLIENT.md`](https://github.com/CIRISAI/CIRISRegistry/blob/main/docs/FEDERATION_CLIENT.md)).
Re-sequenced 2026-05-02 (was v0.3.0; verify subsumption was at v0.2.0
and slid to v0.2.x).

**Sequential dependencies:**

```
v121f (v0.1.21 ships)
  → [v20a (schema SQL) ║ v20b (trait + types)]
  → [v20c1 (memory) ║ v20c2 (postgres) ║ v20c3 (sqlite)]   (parallel
                                                            backend impls;
                                                            postgres + sqlite
                                                            need schema first)
  → [v20d (bootstrap) ║ v20e (write guards) ║
     v20f (persist_row_hash) ║ v20g (fixtures) ║
     v20h (steward fingerprint)]                           (parallel polish
                                                            on top of backends)
  → v20i (cut v0.2.0-pre1; registry unblock)
  → v20j (tests + CHANGELOG + final)
```

**Parallelizable inside the phase:**
- `v20a` (schema SQL) and `v20b` (trait + serde types) — independent.
- `v20c1`/`v20c2`/`v20c3` — three backend impls share only the
  trait surface; can be developed concurrently. Memory backend has
  no schema dependency (in-process maps); postgres + sqlite need
  the migration files.
- `v20d`-`v20h` — independent polish items on top of the backends.

**Pre1 cut criterion**: minimum surface needed to unblock registry's
R_BACKFILL — schema + trait + at least one backend (postgres) +
bootstrap row + steward fingerprint + fixture JSON. v0.2.0 final adds
remaining backends, write-authority guards, and full test coverage.

---

### v0.2.x — Verify Subsumption

**Gates next phase on:** `Engine` exposes verify-shaped proxy
methods. With v0.2.0 federation directory already live, the
`verify_build_manifest` proxy ships with implicit `trusted_pubkey`
lookup against `federation_keys` from day one — no later overload
shuffle.

**Sequential dependencies:**

```
v20j (v0.2.0 final ships)
  → v2xa (pin bump) → v2xb (test green vs new pin)
  → [v2xc1 ║ v2xc2 ║ v2xc3 ║ v2xc4]   (parallel proxy method groups)
  → v2xd (smoke tests)
  → v2xe (lens integration)
  → v2xf (release)
```

**Parallelizable inside the phase:** the four proxy method
groups (`v2xc1`–`v2xc4`) — independent `Engine` methods, no
shared state on the persist side, separate test surfaces.

---

### v0.3.0 — Federation surface completion

**Gates next phase on:** full read+write surface of the
federation directory has been exercised against real production
attestation patterns from registry's dual-write deployment;
divergence telemetry has been quiet long enough to retire the
experimental schema contract.

**Sequential dependencies:**

```
v2xf (v0.2.x verify subsumption ships)
  → [v30a (attestations) ║
     v30b (revocations) ║
     v30c (divergence telemetry)]   (parallel — three independent extensions)
  → v30d (registry dual-write integration)   (needs the full surface)
  → v30e (production-traffic schema soak)
  → v30f (as_of: Option<DateTime> for Policy B)
```

**Parallelizable inside the phase:** `v30a`, `v30b`, `v30c` —
independent schemas/instrumentation on top of v0.2.0's `federation_keys`
table and trait.

**Cross-team gate:** `v30d` requires registry's
`FEDERATION_DUAL_WRITE_ENABLED` deployment. Registry decides
their version cadence on their own side; persist doesn't block
on a specific registry version, just on the dual-write hop being
live somewhere.

---

### v0.4.0 — Read-path migration

**Gates next phase on:** `lookup_public_key` reads from
`federation_keys` first, with full backfill from
`accord_public_keys`. Schema becomes stable (v0.3.x experimental
contract retires); breaking changes from v0.4.0+ follow standard
semver-major rules.

**Sequential dependencies:**

```
v30e (schema soak green)
  → v40a (switch lookup_public_key)
  → v40b (parity-counter validation)
  → v40c (retire experimental contract)
  → v40d (release)
```

**Parallelizable inside the phase:** none — the read-path flip
is a single ordered handoff.

---

### v0.4.x — Deprecation + polish

**Gates next phase on:** N/A (terminal phase for the federation
directory work). v0.5.0+ scope is determined by what consumers
need next.

**Sequential dependencies:**

```
v40d (v0.4.0 ships)
  → [v4xa (accord_public_keys deprecated to view) ║
     v4xb (PG NOTIFY pubsub) ║
     v4xc (trust-contract diff on registry side)]
```

**Parallelizable inside the phase:** all three — independent
deliverables. `v4xc` is registry-side work; persist contributes
review only.

---

## Critical path

The strict dependency chain — where any delay propagates to the
final milestone:

```
v121a → v121b → v121c* → v121d → v121e → v121f
  → v20a/b → v20c* → v20d/e/f/g/h → v20i → v20j
  → v2xa → v2xb → v2xc* → v2xd → v2xe → v2xf
  → v30a/b/c → v30d → v30e → v30f
  → v40a → v40b → v40c → v40d
  → v4xa/b/c (terminal)
```

Items separated by `║` in the phase waterfalls above are *off
the critical path within their phase* — they can slip without
extending the phase, as long as their phase's join point
(`v20d`, `v30g`, `v3xd`, etc.) starts when its predecessors are
all green.

---

## What this roadmap does NOT promise

- **No delivery dates.** Phase ordering is gated by code being
  green and consumers being ready, not by calendar.
- **No work-effort estimates.** Different items in the same
  phase have different scope; the roadmap is for sequencing, not
  capacity planning.
- **No promise that every v0.3.x item ships in a single release.**
  v0.3.x is a series of patch releases; attestations might land
  in v0.3.1, revocations in v0.3.2, etc. The phase ends when
  `v30e` (production soak) is green, which gates the v0.4.0 cut.
- **No promise about post-v0.4.x scope.** This roadmap is
  bounded by the federation-directory work. v0.5.0+ is open.
