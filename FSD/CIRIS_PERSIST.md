# FSD: CIRISPersist — Unified Rust persistence for the CIRIS federation

**Status:** Proposed
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.7
**Created:** 2026-04-30
**Repo:** `~/CIRISPersist` (this document is the spec; code lands in this repo)
**Risk:** Architectural. Phase 1 is a single-component cutover (lens trace ingest) with no agent changes. Phases 2 and 3 are subsumption of agent persistence under the same crate, no flag-day required at any phase.

---

## 1. Why this exists

The CIRIS architecture has two services that, viewed honestly, are the same job at different scales:

- **CIRISAgent** maintains a local Ed25519-signed audit chain (`audit_log` table) and a TSDB of service correlations (`service_correlations`), plus runtime state (`tasks`, `thoughts`), a memory graph (`graph_nodes`, `graph_edges`), and governance tables (`tickets`, `dsar_*`, `deferral_*`, `wa_cert`). All of it is written today in pure Python via `sqlite3` / `psycopg2` with a hand-rolled dialect adapter.
- **CIRISLens** ingests Ed25519-signed reasoning traces from agents, verifies signatures at the Rust edge (`cirislens-core` via PyO3), scrubs PII, and writes them to TimescaleDB hypertables (`accord_traces` today; `trace_events` + `trace_llm_calls` after the 2.7.8 cutover).

The Proof-of-Benefit Federation FSD (`CIRISLens/FSD/PROOF_OF_BENEFIT_FEDERATION.md` §3.1) makes this overlap explicit: lens-side ingest+verify+scrub+score is "a function any peer can run on data the peer already has." The lens role isn't an authority — it's a *function*. Once that's true, both roles want the same primitives: signed event persistence with an audit chain, TSDB-shaped time-series, schema-versioned migrations, sqlite + postgres backends, multi-occurrence atomicity, and a verification path that can run in-process.

The other agent DBs (CIRISAgent runtime state, CIRISRegistry, CIRISPortal) are moving to **Spock logical replication** for HA. That's the right primitive for relational state with row-level multi-master. It is **not** the right primitive for traces: TimescaleDB chunk compression conflicts with logical-decoding output plugins, the federation goal is content-addressed signature-preserving peer replication (PoB §5.1), and trace volume favors batch COPY over row-by-row WAL streaming.

So traces want their own substrate. **And — this is the key claim — the substrate that's right for traces is right for the agent's entire persistence layer, not just `audit_log` + `service_correlations`.** Memory-safe at the parsing edge, no Python GIL contention with the H3ERE pipeline, embeddable in both the lens binary and the agent process, fork-survivable, native sqlite+postgres without a translation kludge, iOS-clean without an Apple-tracker workaround. The destination is a single `ciris-persist` crate that backs every CIRIS persistence table; we get there in three phases that each stand on their own.

## 2. Scope

This FSD specifies a Rust crate, **`ciris-persist`**, that ultimately owns **all CIRIS persistence except external-service DBs** (CIRISRegistry, CIRISPortal). Delivered in three phases, each independently shippable:

| Phase | Tables / surfaces brought under the crate |
|---|---|
| **Phase 1** (immediate) | Lens: `accord_traces` → `trace_events` + `trace_llm_calls`; `accord_public_keys`. Wire format ingest, Ed25519 verify, PII scrub. |
| **Phase 2** (federation-trigger) | Agent: `audit_log`, `audit_roots`, `audit_signing_keys`, `service_correlations`. The signed-events-and-time-series subset of agent persistence. |
| **Phase 3** (long-tail) | Agent: `tasks`, `thoughts`, `graph_nodes`, `graph_edges`, `tickets`, `dsar_*`, `deferral_*`, `wa_cert`, `feedback_mappings`, `consolidation_locks`, `queue_status` — runtime state, memory graph, governance. |
| **Out of scope** | CIRISRegistry, CIRISPortal — external services with their own DBs and replication strategies. |

The phases are differentiated by **migration risk**, not by architectural separation:

- **Phase 1** is a single-component cutover (the lens), no agent change.
- **Phase 2** brings agent-side append-only, signed, batch-friendly tables under the crate. Easy because dual-write/dual-read on append-only tables is mechanical.
- **Phase 3** brings mutable relational state (UPDATEs, DELETEs, FKs, multi-occurrence atomicity, latency-sensitive interactive queries). Harder because dual-write requires consistency coordination across mutations.

We commit to all three phases; we sequence them so each one stands on its own; the crate's API surface is designed from Phase 1 to support Phase 3 without future rewrites.

## 3. Phase 1 — Lens trace persistence

**Outcome:** the lens cutover from `accord_traces` (per-thought row collapse) to `trace_events` + `trace_llm_calls` (per-broadcast event log, FSD/TRACE_EVENT_LOG_PERSISTENCE.md compliant) lands in `ciris-persist`, not in `CIRISLens/api/accord_api.py`. The Python layer becomes a thin entry point at most.

### 3.1 Crate shape

```
ciris-persist/
  Cargo.toml
  src/
    lib.rs
    schema/                     # serde structs — single source of truth for the wire
      complete_trace.rs         # CompleteTrace + TraceComponent
      events.rs                 # ReasoningEvent variants, LLM_CALL
      audit.rs                  # AuditEntry (Phase 2 surface, defined now)
      runtime.rs                # Task, Thought, GraphNode, GraphEdge (Phase 3 surface, defined now)
      version.rs                # trace_schema_version gate
    verify/
      ed25519.rs                # signature verification
      canonical.rs              # canonical JSON bytes (sort_keys, separators)
      chain.rs                  # audit-anchor verification
    scrub/
      mod.rs                    # passthrough to existing cirislens-core scrubber
    store/
      backend.rs                # trait Backend
      postgres.rs               # tokio-postgres + deadpool, TimescaleDB-aware (Phase 1)
      sqlite.rs                 # rusqlite (Phase 2 — define trait now, defer impl)
      journal.rs                # redb local append-only journal for outage tolerance
      migrate.rs                # numbered .sql runner
    server/
      ingest.rs                 # axum HTTP listener for /api/v1/accord/events
      health.rs
    ffi/
      pyo3.rs                   # Python entry points (Phase 1: receive_and_persist; Phase 2+: agent DAOs)
      c.rs                      # C ABI (Phase 2 — for iOS client)
  bins/
    cirislens-ingest.rs         # standalone Rust server (Phase 1 deployment shape A)
  migrations/
    postgres/
      lens/                     # Phase 1 migrations
        001_trace_events.sql    # the 027 migration, renumbered as crate-owned 001
        002_audit_anchor_cols.sql
      agent/                    # Phase 2 + 3 migrations (rehomed from agent repo)
    sqlite/
      lens/                     # empty in Phase 1
      agent/                    # Phase 2 + 3
```

**Feature flags:**
- `postgres` — tokio-postgres backend (Phase 1 default for lens)
- `sqlite` — rusqlite backend (Phase 2)
- `pyo3` — Python bindings (FastAPI calls in for transition window; agent uses in Phase 2+3)
- `server` — axum HTTP listener (lens deployment, Phase 1 path A)
- `c-abi` — C ABI bindings (Phase 2, for iOS client)
- `peer-replicate` — Reticulum gossip hook (Phase 2)

Lens compiles with `postgres + server + pyo3`. Phase 1 lens cutover starts with `pyo3` mode (FastAPI hands raw bytes to Rust); follow-up flips to `server` mode (Rust binds the port directly).

### 3.2 Schema — `trace_events` with audit anchor

Carries forward `CIRISLens/sql/027_trace_events.sql` verbatim, plus three columns from the `ACTION_RESULT` component's audit anchor:

```sql
ALTER TABLE cirislens.trace_events
  ADD COLUMN audit_sequence_number BIGINT,    -- agent audit_log.sequence_number
  ADD COLUMN audit_entry_hash      TEXT,      -- agent audit_log.entry_hash (sha256)
  ADD COLUMN audit_signature       TEXT;      -- agent's Ed25519 signature on the audit entry

CREATE INDEX trace_events_audit_seq
  ON cirislens.trace_events (audit_sequence_number)
  WHERE audit_sequence_number IS NOT NULL;
```

Populated only on the row where `event_type = 'ACTION_RESULT'`. The agent already broadcasts these fields (TRACE_WIRE_FORMAT.md §5.9) — no agent change required. Other rows leave the columns NULL. The anchor lets a verifier recompute the per-action chain link without dragging the full audit log across the wire.

`trace_llm_calls` and `accord_public_keys` keep their existing shapes.

### 3.3 Wire format ingest

Strict serde-deserialized structs against `TRACE_WIRE_FORMAT.md` §1–§10. No `serde_json::Value`-then-extract. Reject batches whose `trace_schema_version` is not in the supported set (currently `{"2.7.0"}`) with structured 422.

Per batch:

1. Deserialize envelope → `BatchEnvelope { events, trace_level, trace_schema_version, batch_timestamp, consent_timestamp, signature, signing_key_id, … }`.
2. Verify Ed25519 signature against canonical payload bytes (sort_keys + `(,:)` separators) using `accord_public_keys` lookup. Reject on mismatch.
3. If `trace_level = full_traces`, run PII scrub via existing `cirislens-core` scrubber (no behavior change). Hold the **pre-scrub canonical bytes** in memory through this step (one extra `Vec<u8>` per component, dropped at step 5) — needed for step 3.5's hash. At `generic` and `detailed`, scrubbing may still mutate sub-fields per the scrubber's own policy; the contract just doesn't *require* it. In every case, `data_pre_scrub == data_post_scrub` is the no-op path — the next step still runs over them.
4. **(NEW v0.1.3) Sign per-component envelope. Always.** Every persisted row gets cryptographic provenance, every trace level, every deployment. The signing key is **never null** — `ciris-keyring` (CIRISVerify's Rust crate) guarantees there is always a key to sign with, hardware-backed where available, software-backed otherwise. For each component:
   - `original_content_hash = sha256(canonical(component.data_pre_scrub))`
   - `scrub_signature = ed25519_sign(canonical(component.data_post_scrub))` via the deployment's keyring-resident signing key.
   - `scrub_key_id = signer.key_id()`
   - `scrub_timestamp = Utc::now()`

   **Same-key principle across deployments**:
   - **Lens deployment** (Phase 1 — this FSD): the key is owned by the lens, identifier conventionally `lens-scrub-v1` (or per-deployment scheme). Generated once via `ciris-keyring` bootstrap, stored under the OS keyring (Secret Service / Keychain / DPAPI / Keystore) backed by hardware where available.
   - **Agent deployment** (Phase 2+, FSD §4): the key is *the same key the agent already uses for its wire-format §8 signature*. There is no separate "agent-scrub key" vs "agent-audit key" — one identity, one signing key, two attestations (per-action audit chain + per-component scrub envelope). The agent's existing keyring entry is reused; persist looks it up by id rather than minting a new one.

   The signing call is on the hot path. Cost: one Ed25519 sign per component (~30 µs hardware-backed, ~100 µs software-backed) — bounded by component count per batch (typical: 12-16). For the agent's default `batch_size = 10` events × ~14 components = ~140 sign calls per batch; at hardware speeds, single-digit milliseconds added to the per-batch latency budget. Acceptable.

   **Why this matters (mission alignment).** Before v0.1.3, the `pii_scrubbed = true` boolean column was the only attestation that scrubbing happened. Trivially forgeable by anyone with DB write. After v0.1.3, every persisted row carries cryptographic proof that *this specific* deployment handled *this specific* payload at *this specific* time, verifiable by any peer with the published public key.

   PoB §3.1 — "the lens role is a function any peer can run on data the peer already has" — becomes *cryptographically attestable* rather than socially trusted. The federation primitive's substrate now has bilateral cryptography: the agent's wire-format §8 signature proves authorship; the v0.1.3 scrub envelope proves handling. A peer fetching a row can verify both ends.

   MISSION.md §2 — `scrub/` constraint "PII never crosses the persistence boundary at trace levels where it isn't warranted" — flips from a *trust* claim to a *verifiable* claim. The unconditional nature is load-bearing: special-casing by trace_level (e.g., "skip signing at generic since there's no PII to attest about") would create a path where a misconfigured deployment claims to be at GENERIC while emitting unverified content. Every level signs; uniform contract; no special cases (MISSION.md §3 anti-pattern #3 — "no bypass branches; admin keys, agent keys, and federation peer keys all verify by the same path").

   The hash + signature also closes a privacy-bridging gap: a lens configured at higher `trace_level` than its scrubber permits cannot pretend it scrubbed when it didn't. A downstream auditor with the `original_content_hash` + `scrub_signature` + the deployment's public key + the bytes that ended up in storage can verify the deployment's attestation without needing the original content.

5. For each event in batch:
   - Decompose `CompleteTrace.components` → one `trace_events` row per component, keyed by `(agent_id_hash, trace_id, thought_id, event_type, attempt_index, ts)`. (THREAT_MODEL.md AV-9: `agent_id_hash` is the dedup-key prefix from v0.1.2 onward.)
   - Map `LLM_CALL` components → `trace_llm_calls` rows, linked via `parent_event_id`.
   - Capture audit anchor on `ACTION_RESULT` rows.
   - Capture scrub envelope (`original_content_hash`, `scrub_signature`, `scrub_key_id`, `scrub_timestamp`) on every row when step 3.5 produced one.
6. Batch INSERT via parameterized `INSERT ... VALUES (...) ON CONFLICT DO NOTHING` for `trace_events`, separate batch for `trace_llm_calls`. Per-batch transaction; on conflict `(agent_id_hash, trace_id, thought_id, event_type, attempt_index, ts)` do nothing (adapter retries are safe). (`COPY ... FROM STDIN BINARY` is the long-term shape per FSD original wording; `INSERT VALUES + ON CONFLICT` works for the agent's default `batch_size=10` and supports the conflict path natively.)

### 3.4 Robustness primitives

These land in Phase 1 and carry through Phases 2 and 3:

1. **Bounded ingest queue.** `tokio::sync::mpsc` channel, capacity ~1024 batches. Producer (axum handler / PyO3 entry) blocks on full queue; persister side is the single consumer that owns Postgres.
2. **Local journal.** `redb` append-only file at `/var/lib/cirislens/journal.redb`. If Postgres is unreachable on a batch, the batch is journaled and the persister reschedules. On startup, replay any journaled batches before accepting new traffic. Append-only event semantics make this trivially safe.
3. **Schema-version gate.** Reject `trace_schema_version` not in `SUPPORTED_VERSIONS` with HTTP 422 + `{"detail": "schema_unsupported_version", ...}`. (v0.1.2 AV-15: HTTP-surfaced errors carry stable `kind()` tokens; verbose form to tracing logs only.)
4. **Idempotency.** Unique index on `(agent_id_hash, trace_id, thought_id, event_type, attempt_index, ts)`; `ON CONFLICT DO NOTHING`. Adapter retries can't double-insert. (v0.1.2 THREAT_MODEL.md AV-9: `agent_id_hash` is the dedup-key prefix so cross-agent dedup-tuple reuse cannot DOS a victim's traces.)
5. **Backpressure.** Full queue → HTTP 429 with `Retry-After`. Agent-side already retries.
6. **Memory-safe parse.** No `serde_json::Value` anywhere in the hot path. Concrete structs from §3.1 schema/ module. Body-size cap `MAX_INGEST_BODY_BYTES = 8 MiB` at the axum router (v0.1.2 AV-7); `data` recursion-depth cap `MAX_DATA_DEPTH = 32` (v0.1.2 AV-6); `MAX_ATTEMPT_INDEX = 1024` typed bound (v0.1.3 AV-17).
7. **(NEW v0.1.3) Always-present signing key, isolated in `ciris-keyring`.** The signing key is **never null**. CIRISVerify guarantees `ciris-keyring` always has a key for the configured `key_id` — generated on first call, hardware-backed where available (Linux Secret Service / TPM 2.0; macOS Keychain / Secure Enclave; iOS / Android StrongBox; Windows DPAPI / TPM), software-backed via `SoftwareSigner` fallback otherwise. Persist depends directly on `ciris-keyring` (CIRISVerify's Rust crate); the consuming Python process (FastAPI, agent) never holds the signing-key seed in memory — the bytes never cross the FFI boundary.

   `Engine` construction takes `signing_key_id` as a **required** parameter. The ctor calls into the keyring's bootstrap path internally — idempotent: returns the existing key if it exists, generates a new seed and stores it if not. The lens / agent then publishes the corresponding public key to the registry / lens-discovery layer. There is no "no-signing" mode; the substrate's contract assumes every row carries provenance.

   **The same key is the deployment's Reticulum identity** when the `peer-replicate` feature lands (FSD §4.4 / Phase 2.3). Reticulum's destination is `SHA256(public_key)[..16]` — addressing IS identity (PoB §3.2). Persist's `Signer::public_key()` is the source-of-truth that the future Reticulum integration reads to compute the destination. No separate "network address" key; the substrate's signing key is the federation identity.

   On the agent (Phase 2+ deployments, FSD §4): persist points at the agent's existing wire-format §8 signing key by id — same key, no new keyring entries. The agent's identity stays single-keyed.

   **One key, three roles** (PoB §3.2 made operational): the same Ed25519 key is *also* the deployment's Reticulum destination address (SHA256-prefix of the public key — addressing IS identity, no translation layer) *and* the public-key entry the deployment publishes to the registry. Compromise the key, you compromise all three roles simultaneously: cryptographic provenance, federation transport address, and registry identity. That tripled cost-asymmetry strengthens the case for hardware-backed keyring entries — the residual on `SoftwareSigner` (named in §3.4 #7 below) is the same residual as "lose your federation standing entirely."

   (Secondary mitigation against THREAT_MODEL.md AV-25 "scrub-key compromise"; the `SoftwareSigner` fallback is acceptable for dev / sovereign deployments without hardware backing, and is named as a residual risk in §8 of the threat model.)

   Mission alignment: MISSION.md §2 — `ffi/` "every divergence between iOS and server reasoning is a place the Federated Ratchet can be silently broken — different bug surfaces, different invariants, different PII boundaries. One core; many shells." The keyring dep is the realization of that on the key-storage axis. MISSION.md §3 anti-pattern #3 ("no bypass branches; same path for every key") is realized by the always-present-signing rule: there is no "skip signing" code path to attack.

### 3.5 Migration / cutover

- **No agent changes** required (§3.6 confirms).
- **Lens deploy:**
  1. Apply `migrations/postgres/lens/001_trace_events.sql` (which is `CIRISLens/sql/027_trace_events.sql` verbatim).
  2. Apply `migrations/postgres/lens/002_audit_anchor_cols.sql`.
  3. Deploy lens with `cirislens-api` linking `ciris-persist` via PyO3. FastAPI's `/api/v1/accord/events` handler calls `ciris_persist::receive_and_persist(bytes)` instead of the existing 92-column `accord_traces` INSERT path.
  4. `accord_traces` table stays readable for pre-cutover history; **no writes** to it from cutover forward.
  5. Drop `scrubber_compare.py` + delta-log sink (per "no more delta log" decision).
- **No dual-write window.** Per "we need this richer data more than we need 100% data promises." Pre-cutover history stays in `accord_traces`; post-cutover lives in `trace_events`. Union queries treat legacy as single-event `attempt_index=0, step_point=action_complete` summary rows.
- **Rollback path:** redeploy previous lens image. The new tables remain (additive migration); the old write path resumes against `accord_traces`. Backup baseline is `~/RATCHET/lens-backups/cirislens_20260430_020409.sql.gz` (verified, off-host).

### 3.6 What the agent has to change in Phase 1

**Nothing.** The Ed25519 hash chain already lives in the agent's `audit_log` table (`sequence_number`, `previous_hash`, `entry_hash`, `signature`, `signing_key_id`). The audit-chain anchor is already broadcast on every `ACTION_RESULT` event (TRACE_WIRE_FORMAT.md §5.9: `audit_entry_id`, `audit_sequence_number`, `audit_entry_hash`, `audit_signature`). The wire format ships with `trace_schema_version: "2.7.0"` and `attempt_index` per `(thought_id, event_type)` (TRACE_WIRE_FORMAT.md §6) — both already 2.7.8-shipping. The lens-side change is purely additive: add three columns on `trace_events`, capture them on the `ACTION_RESULT` row.

**Future agent ask (Phase 2 only, conditional):** if peer-to-peer trace replication needs per-event tamper-evidence without dragging the full batch, broadcast a chain link on every intermediate event (`DMA_RESULTS`, `LLM_CALL`, etc.) — not just on `ACTION_RESULT`. Held until peer replication is real work, not speculative.

### 3.7 v0.1.3 schema additions — scrub envelope columns

`migrations/postgres/lens/V003__scrub_envelope.sql` (additive ALTER TABLE; no backfill):

```sql
ALTER TABLE cirislens.trace_events
    ADD COLUMN IF NOT EXISTS original_content_hash TEXT,
    ADD COLUMN IF NOT EXISTS scrub_signature       TEXT,
    ADD COLUMN IF NOT EXISTS scrub_key_id          TEXT,
    ADD COLUMN IF NOT EXISTS scrub_timestamp       TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS trace_events_scrub_key
    ON cirislens.trace_events (scrub_key_id, ts DESC)
    WHERE scrub_signature IS NOT NULL;
```

| Column | Shape | What it proves |
|---|---|---|
| `original_content_hash` | TEXT — sha256 hex of `canonical(data_pre_scrub)` | Anyone with the original content can verify it was the input to scrubbing. The deployment doesn't need to retain the original — the hash is enough for spot-check audit. At GENERIC trace-level (no PII to scrub) this equals `sha256(canonical(data_post_scrub))` since pre==post; that's expected. |
| `scrub_signature` | TEXT — base64 of `ed25519_sign(canonical(data_post_scrub))` | The deployment processed *this exact* post-scrub payload at *this exact* time — verifiable by any peer with the deployment's published public key. |
| `scrub_key_id` | TEXT — the deployment's `signing_key_id` | Identifies which deployment (or which key generation under that deployment) signed. On the lens this is `lens-scrub-v1` (or per-deployment scheme); on the agent (Phase 2+) this is the agent's existing wire-format §8 signing key id. |
| `scrub_timestamp` | TIMESTAMPTZ | When the scrub+sign happened. The window between the trace's `completed_at` and `scrub_timestamp` bounds how long the unscrubbed bytes existed in deployment memory — useful for forensics / SLA. |

**Every v0.1.3+ row has all four columns populated.** Step 3.4 robustness primitive #7 makes the signing key always-present, so the persist pipeline always produces an envelope. There is no "row without a scrub envelope" code path going forward.

**Pre-v0.1.3 rows** (the lens's existing pre-cutover history in `accord_traces`, plus any v0.1.0 → v0.1.2 rows that may have landed in `trace_events` during early integration) have NULLs in all four envelope columns. They pre-date the contract; that's a historical artifact, not an ongoing one. Queries that need the envelope-attestation guarantee filter on `WHERE scrub_signature IS NOT NULL`. Operationally, pre-v0.1.3 rows hit retention drop within the lens's standard 30-day window, so the NULL-envelope cohort is bounded.

Schema-version of the *crate* bumps to `0.1.3`; schema-version of the *wire format* (`trace_schema_version`) stays `2.7.0`. The wire format isn't changing — the persistence layer is adding cryptographic provenance to its own handling.

## 4. Phase 2 — Subsumption of agent signed-events persistence

**Outcome:** the agent's `audit_log`, `audit_roots`, `audit_signing_keys`, and `service_correlations` writes flow through `ciris-persist` (PyO3-bound from inside the agent process), reusing the same Backend trait, same migrations runner, same verification code, same wire format definitions. No agent flag-day; the existing Python DAOs continue to read until they're individually migrated.

### 4.1 Scope additions

| Added in Phase 2 | Mechanism |
|---|---|
| `audit_log` writes via `ciris-persist` | PyO3: `ciris_persist::audit::append(entry)` replaces `add_audit_entry()` |
| `audit_roots` Merkle root computation | Rust impl, PyO3-callable |
| `service_correlations` writes (TSDB) | PyO3: `ciris_persist::tsdb::record(correlation)` |
| sqlite backend (`store/sqlite.rs`) | rusqlite; matches agent's existing iOS thread-local quirk via per-thread `Arc<Connection>` |
| C ABI for iOS client | `ffi/c.rs` feature flag; iOS Resources persistence path uses it instead of bundled Python |
| Per-event chain extension (conditional) | If federation replication needs it, ask agent to broadcast chain links on every event |

### 4.2 What stays Python on the agent through Phase 2

Through Phase 2: `tasks`, `thoughts`, `graph_nodes`, `graph_edges`, `tickets`, `dsar_*`, `deferral_*`, `wa_cert`, identity, auth, queue_status, feedback_mappings, consolidation_locks. These are runtime state, memory graph, and governance plumbing — not signed events, not time-series. The Python DAOs in `ciris_engine/logic/persistence/models/` keep their current shape during Phase 2. The `db/dialect.py` adapter shrinks (it no longer has to handle audit_log + service_correlations) but doesn't go away.

**Phase 3 brings these under the crate** — see §5.

### 4.3 iOS client implications

The current `client/iosApp/Resources/app/ciris_engine/logic/persistence/` ships a copy of the Python persistence module and a bundled SQLite. With `ciris-persist` exposing a C ABI, the iOS client links the Rust crate directly for Phase 2's signed-events surface. The full removal of bundled Python on iOS lands in Phase 3 — see §5.8.

### 4.4 Federation replication hook

Phase 2's `peer-replicate` feature flag exposes a downstream channel — start with Postgres `LISTEN`/`NOTIFY` on `trace_events_inserted`; future swap to a Reticulum Resource-transfer subscriber. Each persisted event becomes one notification. PoB §5.1 (gossip topology) is then a subscriber library on top, not a refactor of `ciris-persist`.

### 4.5 Per-event chain extension (open question)

If/when federation replication wants per-event tamper-evidence without batch-level verification, the agent broadcasts a chain link (`prev_event_hash`, `event_hash`) on every intermediate event, not just `ACTION_RESULT`. The lens captures it on every `trace_events` row. Cost: ~64 bytes/row + write coordination on the chain head per agent. Benefit: any single-row tampering detectable without re-fetching the batch envelope. Decision deferred to when peer replication is real.

## 5. Phase 3 — Subsumption of agent runtime state, memory graph, and governance

**Outcome:** the agent's entire `ciris_engine/logic/persistence/` module is backed by `ciris-persist`. The Python DAOs become thin Rust-binding shims; the dialect adapter goes away; the iOS thread-local kludge goes away; the bundled Python persistence on the iOS client is removed. At the end of Phase 3 there is one persistence binary across lens and agent, and the §3.1 collapse from PoB is operationally real.

This is the longest-tail piece of the work. It is also the most disruptive — every reasoning-loop hot path on the agent touches `tasks` / `thoughts` / `graph_nodes`. We sequence it last because the gain compounds (each table done is one less DAO churning) and because Phases 1+2 prove the crate's API surface in the lower-risk surfaces before the crate touches the agent's interactive query path.

### 5.1 Scope additions

| Added in Phase 3 | Notes |
|---|---|
| `tasks` (mutable, multi-occurrence, signed) | The signing fields (`signed_by`, `signature`, `signed_at`) ride on the same Ed25519 path as Phase 2 audit chain. |
| `thoughts` (FK→tasks, multi-occurrence) | Hot-path interactive queries. Latency budget tighter than batch ingest. |
| `graph_nodes`, `graph_edges` (memory graph, multi-scope) | Includes encrypted attributes (secrets management integration). The encryption boundary stays where it is; the persistence layer remains unaware of plaintext. |
| `tickets`, `dsar_*`, `deferral_*` | Governance / WBD plumbing. Lower volume but full referential integrity needs. |
| `wa_cert`, identity, authentication_store | Auth tables. Special care: secrets in row form. |
| `queue_status`, `feedback_mappings`, `consolidation_locks` | Runtime coordination tables. |
| `analytics.py` aggregations | Read-side migrates to Rust queries with serde-derived response structs. |

### 5.2 Why Phase 3 is structurally different from Phases 1+2

| Property | Phase 1 + 2 (signed events / TSDB) | Phase 3 (runtime state / graph / governance) |
|---|---|---|
| Mutability | Append-only | Mutable (UPDATE, DELETE) |
| Referential integrity | None (events are independent) | FKs (`thoughts.source_task_id` → `tasks.task_id`), edge constraints |
| Multi-occurrence atomicity | Not relevant | `try_claim_shared_task` race-claim semantics, `__shared__` namespace |
| Query shape | Batch INSERT, time-bounded scans | Interactive lookups, graph traversal, top-K aggregates |
| Latency budget | Throughput-bound (batch COPY) | Latency-bound (single-row reads in the H3ERE hot path) |
| Backend quirks | TimescaleDB hypertables (lens) | Apple's `SQLiteDatabaseTracking` (iOS); psycopg2 connection pooling (server) |
| Migration risk | Dual-write trivial (idempotent on `(trace_id, …, attempt_index)`) | Dual-write requires consistency coordination across mutations |
| Test parity | Verify-and-store contract is small | The agent's persistence test suite is the load-bearing validator |

The crate's design has to absorb all of this without bifurcating into "Phase 1+2 ciris-persist" vs "Phase 3 ciris-persist." That's the constraint that's been guiding the Backend trait shape from §3.1.

### 5.3 What goes away

- `ciris_engine/logic/persistence/db/dialect.py` (374 lines). Each backend speaks its native dialect; no `?`→`%s` or `INSERT OR REPLACE`→`ON CONFLICT` translation needed.
- `ciris_engine/logic/persistence/db/core.py`'s iOS thread-local connection cache (~1094 lines, much trimmed). Rust threading is explicit; the same crate runs cleanly on iOS via the C ABI without Apple's `SQLiteDatabaseTracking` ever firing.
- `ciris_engine/logic/persistence/db/retry.py`'s sqlite/postgres-error classification. Both `rusqlite` and `tokio-postgres` expose typed error variants; retry policy lives next to the backend impl.
- The pydantic row-mapping layer in `utils.py` (236 lines). Serde-derived structs replace it; mapping happens at compile time, not on every row.

The Python `models/` package shrinks to thin call-through shims that exist only for ABI stability during the migration; once every caller is on the Rust types, the shims go away.

### 5.4 What stays

- The schemas. `ciris_engine/schemas/persistence/postgres/tables.py` and `…/sqlite/tables.py` continue to exist as Pydantic schemas for cross-language clients (web client, iOS Kotlin generation). They become *generated from* the Rust types, not hand-maintained alongside.
- The migration files. `migrations/sqlite/001_initial_schema.sql` etc. are SQL — they move under the `ciris-persist` crate (`migrations/sqlite/agent/`) but their content is unchanged at migration-cutover time.
- The multi-occurrence semantics. `agent_occurrence_id` namespace, `__shared__` coordination, `try_claim_shared_task` atomicity — all preserved. Implementation moves to Rust transactions.

### 5.5 Migration approach

Per-table cutover, one table at a time, with the agent's existing test suite as the gate. The order:

1. **Lowest-FK-fanout first.** `feedback_mappings`, `consolidation_locks`, `queue_status` — no FKs in or out. Cut these over to validate the round-trip Python→Rust→Python pattern with minimal blast radius.
2. **Governance tables next.** `wa_cert`, `tickets`, `dsar_*`, `deferral_*`. Lower volume, well-tested, mostly write-once-read-rarely.
3. **Memory graph.** `graph_nodes`, `graph_edges`. The traversal queries are the hardest part; this is also where the secrets-management integration lives, so the encryption boundary needs careful handling.
4. **Tasks.** Multi-occurrence atomicity is the load-bearing concern. `try_claim_shared_task` becomes a Rust transactional primitive.
5. **Thoughts.** Last because thoughts are the hottest path on the H3ERE pipeline; we want the rest of the persistence layer warmed up before we touch this.

Each step is a separate PR, each gated on the agent's persistence test suite passing in a CI matrix that runs both the Python-DAO and Rust-DAO paths against sqlite + postgres.

### 5.6 Multi-occurrence atomicity preserved

The `try_claim_shared_task` race-claim semantics (`ciris_engine/logic/persistence/models/tasks.py`) translate to a Rust transactional primitive:

```rust
pub fn try_claim_shared_task(
    backend: &impl Backend,
    task_type: &str,
    occurrence_id: &str,
    channel_id: &str,
    description: &str,
    priority: u8,
    now: DateTime<Utc>,
) -> Result<(Task, bool), Error>;
```

Returns `(task, was_created)` matching the existing Python signature. `__shared__` namespace and the per-task-type unique constraint are preserved verbatim in the SQL migration. The atomicity guarantee strengthens — Rust's transaction handling is harder to subvert than Python's contextual `with conn:` patterns.

### 5.7 Secrets-manager integration

The agent's secrets manager encrypts sensitive values inside graph_node `attributes_json` before storage and decrypts on read. The encryption boundary is *above* the persistence layer — `ciris-persist` sees ciphertext, never plaintext. Phase 3 preserves this:

- The Rust API for `add_graph_node` takes the (already-encrypted) attributes blob as opaque JSONB.
- The Python secrets manager (`ciris_engine/logic/secrets/`) stays Python; its hooks fire above the Rust call.
- No new key handling enters the persistence crate.

### 5.8 iOS endpoint

By Phase 3, the iOS client links the Rust crate via the C ABI from Phase 2. The bundled Python persistence at `client/iosApp/Resources/app/ciris_engine/logic/persistence/` is removed. The iOS Kotlin/Swift schemas continue to be generated, but from the Rust types via `cbindgen` / `swift-bridge` rather than from the Python pydantic models.

### 5.9 Trigger conditions

Phase 3 starts when **all** of the following are true:

1. Phase 2 (`audit_log` + `service_correlations`) is operational on production agents and has been stable for ≥30 days.
2. Federation peer-replicate is wired (Phase 2.3) — i.e. the §3.1 collapse has a concrete operational reason to be complete, not just an architectural one.
3. The agent's persistence test suite has been audited for table-by-table parity gates (i.e. we can prove a single table's cutover doesn't regress others).
4. There is a clear consumer benefit — for example, the iOS client's bundled Python persistence becoming the iOS deployment-size bottleneck, or interactive query latency on the H3ERE hot path becoming measurable Python-overhead.

We do not start Phase 3 because the architecture wants it. We start when there is a measured, named operational reason that justifies the migration risk.

### 5.10 Timeline shape (not commitment)

| Step | Effort | Gates on |
|---|---|---|
| 5.1 Lowest-fanout tables (feedback_mappings, consolidation_locks, queue_status) | days | Phase 2 stable |
| 5.2 Governance (wa_cert, tickets, dsar_*, deferral_*) | weeks | 5.1 stable |
| 5.3 Memory graph (graph_nodes, graph_edges + secrets integration) | weeks | 5.2 stable |
| 5.4 Tasks (multi-occurrence atomicity) | weeks | 5.3 stable |
| 5.5 Thoughts (hot path) | weeks | 5.4 stable |
| 5.6 Remove Python DAO shims; remove dialect adapter; remove iOS Python persistence | days | 5.5 stable |

End-state: `ciris_engine/logic/persistence/` directory contains a Rust-binding shim file and nothing else. Every CIRIS federation primitive that needs durable state — agent, lens, registry, bridge, and any future peer — shares this one persistence binary. (Originally framed as the "CIRIS Trinity" of agent + manager + lens; the federation has since grown past three primitives, and persist's substrate role is the shared property.)

## 6. Non-goals

- **No new cryptographic primitive.** Ed25519 + sha256 + the existing canonical-bytes contract.
- **No same-release flag-day at any phase.** Migration is per-table, opt-in, dual-write-tolerant. Phase 3 explicitly sequences table-by-table with parity gates.
- **No new wire format.** TRACE_WIRE_FORMAT.md is canonical; this crate consumes it.
- **No SQLAlchemy / ORM.** Backend trait is intentionally thin — direct rusqlite / tokio-postgres beneath it. The agent's Python side avoided ORMs for good reasons we honor.
- **No replacement of CIRISRegistry / CIRISPortal.** Those run their own DBs and have their own replication / governance stories.
- **No replacement of secrets-manager encryption.** The encryption boundary stays above the persistence layer; ciris-persist stays unaware of plaintext.
- **No relitigation of multi-occurrence semantics.** `agent_occurrence_id` namespacing, `__shared__` coordination, `try_claim_shared_task` race-claim — preserved verbatim through Phase 3.
- **No replacement of the agent's reasoning-loop business logic.** This crate owns *persistence*, not the H3ERE pipeline, not the conscience faculties, not the DMA implementations. Those stay where they are; we just back their state.

## 7. Open questions

1. **Repo home.** This FSD lives at `~/CIRISPersist/FSD/`. Is the crate a separate repo from the start, or does it live inside `CIRISLens/cirislens-core/persist/` until Phase 2 begins? Separate repo signals "not lens-specific anymore" earlier; in-tree means fewer moving parts during Phase 1. Lean: separate repo, since it's the same shape decision PoB §3.1 already made.
2. **PyO3 receive entrypoint shape (Phase 1).** `receive_and_persist(bytes) -> Result<BatchSummary, Error>` — synchronous from Python's perspective, internally async. Or expose async via `pyo3-asyncio`? Lean: synchronous, simpler, FastAPI handler runs in a thread anyway.
3. **redb vs sled vs flat journal.** redb is live-maintained, single-file, simpler API; sled is older and unmaintained; flat append-only file is smallest dep. Lean: redb.
4. **Schema-version policy.** Single supported version (`"2.7.0"`) or supported set (`{"2.7.0"}` initially, additive)? Lean: supported set with a `SUPPORTED_VERSIONS` constant; reject anything outside.
5. **Audit chain extension to per-event.** Held until federation replication is real. Documented in §4.5.
6. **Spock interaction.** Other CIRIS DBs use Spock for HA. The lens trace DB doesn't (TimescaleDB compression incompatibility). For Phase 2 agent's `audit_log` — does it sit under Spock, or under `ciris-persist`'s peer-replicate channel? Open. Probably both: Spock for site-internal HA, `ciris-persist` channel for federation replication.
7. **TimescaleDB feature gate.** Pure-Postgres deployments (some Phase 2 agents) won't have TimescaleDB. Make `create_hypertable` calls conditional on extension presence; fall back to a partitioned table or plain time-indexed.
8. **Schema generation direction.** Today: pydantic Python schemas are hand-maintained, sqlite vs postgres `tables.py` files exist in parallel. Phase 3 decision: do we generate Pydantic from Rust (one source of truth, Rust-side) or keep them in parallel with a contract test? Lean: generate from Rust, since that's what 5.4 → 5.5 → 5.6 makes possible.
9. **Phase 3 trigger threshold.** §5.9 lists four conditions; we should pre-commit to a measurable threshold for at least one (e.g. iOS deployment size, or H3ERE hot-path latency attribution to Python persistence). Otherwise Phase 3 risks being deferred indefinitely.
10. **Multi-occurrence test fixtures.** Phase 3 changes the substrate for `try_claim_shared_task` from Python's transactional pattern to a Rust transaction. The existing test fixtures (`tests/test_task_persistence_fix.py`, `tests/wa_minting_persistence_bug_test.py`) need to be reviewed to ensure they're testing semantics, not Python-implementation-detail.
11. **Graph traversal query shape.** `graph_nodes` + `graph_edges` are queried with multi-hop joins (memory recall, scope-bounded subgraph extraction). Phase 3 needs to decide whether the Rust crate exposes these as composable queries or as named procedures (`recall_subgraph(node_id, max_depth, scope)`). Lean: named procedures — the call sites are few and well-known; exposing a composable query DSL is overhead.
12. **Web-client / iOS schema generation tooling.** Today the iOS Kotlin schemas are generated from OpenAPI (FastAPI) and from the agent's pydantic models. After Phase 3, generation flips to running off Rust types. Tool choice: `cbindgen` for C ABI + Swift, `ts-rs` for TypeScript, generated Pydantic via `pydantic-core` reflection. Spec the toolchain before 5.6 lands.

## 8. Phased delivery

| Phase | Scope | Trigger |
|---|---|---|
| **1.0** | Lens cutover via `ciris-persist` PyO3 from `cirislens-api` | Tonight / this week |
| **1.1** | Standalone `cirislens-ingest` binary; FastAPI dropped from trace hot path | After 1.0 stable, before federation peer-replicate |
| **2.0** | `audit_log` + `audit_roots` + `audit_signing_keys` writes via PyO3 from agent | When peer-to-peer trace replication is on the roadmap |
| **2.1** | `service_correlations` writes via PyO3 | After 2.0 stable |
| **2.2** | sqlite backend; iOS C ABI (signed-events surface only) | When iOS client is ready to consume Rust |
| **2.3** | `peer-replicate` Reticulum hook | When PoB §3.2 transport lands |
| **3.1** | Lowest-FK-fanout tables (`feedback_mappings`, `consolidation_locks`, `queue_status`) | Phase 2 stable for ≥30 days; iOS / latency trigger named (§5.9) |
| **3.2** | Governance tables (`wa_cert`, `tickets`, `dsar_*`, `deferral_*`) | 3.1 stable |
| **3.3** | Memory graph (`graph_nodes`, `graph_edges`) + secrets integration | 3.2 stable |
| **3.4** | Tasks (multi-occurrence atomicity) | 3.3 stable |
| **3.5** | Thoughts (H3ERE hot path) | 3.4 stable |
| **3.6** | Remove Python DAO shims, dialect adapter, iOS bundled Python | 3.5 stable |

Phase 1 is committed work for this cycle. Phase 2 items are individually opt-in — each is a self-contained migration with its own readiness gate. Phase 3 starts only when §5.9's trigger conditions are met. The crate's API surface is designed in Phase 1 to support all of Phases 2 and 3 without future rewrites; we're not adding feature flags for surfaces we'd be ashamed of.

## 9. References

- `~/CIRISLens/FSD/PROOF_OF_BENEFIT_FEDERATION.md` §3.1 — the architectural collapse this FSD operationalizes
- `~/CIRISAgent/FSD/TRACE_WIRE_FORMAT.md` — canonical wire shape (`trace_schema_version: "2.7.0"`, attempt_index, audit anchor on ACTION_RESULT §5.9)
- `~/CIRISAgent/FSD/TRACE_EVENT_LOG_PERSISTENCE.md` — lens-side persistence design that Phase 1 implements
- `~/CIRISLens/sql/027_trace_events.sql` — the migration that becomes `migrations/postgres/lens/001_trace_events.sql` in this crate
- `~/CIRISAgent/ciris_engine/logic/persistence/` — the Python persistence module Phases 2 and 3 subsume
- `~/CIRISAgent/ciris_engine/logic/persistence/migrations/sqlite/001_initial_schema.sql` — current `audit_log`, `audit_roots`, `audit_signing_keys`, `service_correlations`, `tasks`, `thoughts`, `graph_nodes`, `graph_edges`, etc. shapes
- `~/CIRISAgent/ciris_engine/logic/persistence/README.md` — multi-occurrence and TSDB documentation Phase 3 must preserve
- `~/CIRISLens/CLAUDE.md` — lens project conventions; Coherence Ratchet detection / Accord API surface
- `~/CIRISLens/cirislens-core/` — existing Rust crate that becomes the verify+scrub portion of `ciris-persist`'s `verify/` and `scrub/` modules

## 10. Closing note

The agent already has a hash chain. The lens already has a Rust ingest edge. The wire format already carries the chain anchor on every action. **The work this FSD specifies is recognition of a structural alignment, not new construction.** Phase 1 is the lens cutover we have on the runway tonight, written into a crate that has the right shape from the start. Phase 2 is the §3.1 collapse made operational on the agent's signed-events and TSDB tables, no flag-day in sight. Phase 3 carries the collapse all the way through the agent's runtime-state, memory-graph, and governance tables — the architectural endpoint where every CIRIS federation primitive that needs durable state shares one persistence binary. We commit to the destination; we sequence the work so each phase stands on its own; we start Phase 3 only when there's a named operational reason that justifies the migration risk.
