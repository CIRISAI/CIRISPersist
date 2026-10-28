# FSD: CIRISPersist — Unified Rust persistence for the CIRIS federation

**Status:** Implemented. Lens trace ingest, the agent's signed-event tables, the agent's runtime-state / memory-graph / governance tables, and the CIRISNodeCore federation-consensus substrate (Appendix A) all run through this crate. The surfaces that are not implemented are listed in §8.
**Repo:** `CIRISAI/CIRISPersist`. The other files in `FSD/` specify individual surfaces in detail.

---

## 1. Why this exists

Two CIRIS roles do the same job at different scales:

- **CIRISAgent** keeps a local Ed25519-signed audit chain (`audit_log`), a time series of service correlations (`service_correlations`), runtime state (`tasks`, `thoughts`), a memory graph (`graph_nodes`, `graph_edges`), and governance tables (`tickets`, deferral reports, `wa_cert`).
- **CIRISLens** ingests Ed25519-signed reasoning traces from agents, verifies the signatures, scrubs PII, and stores them (`trace_events` + `trace_llm_calls`).

The Proof-of-Benefit Federation FSD (`CIRISLens/FSD/PROOF_OF_BENEFIT_FEDERATION.md` §3.1) states the overlap: lens-side ingest, verify, scrub and score is "a function any peer can run on data the peer already has." The lens role is a *function*, not an authority. Both roles therefore need the same primitives: signed event persistence with an audit chain, time series, schema-versioned migrations, sqlite and postgres backends, multi-occurrence atomicity, and a verification path that runs in-process.

Logical replication (Spock) suits relational state with row-level multi-master. It does not suit traces: the federation replicates content-addressed, signature-preserving rows between peers (PoB §5.1), and trace volume favours batch writes over row-by-row WAL streaming.

So traces have their own substrate, and the same substrate backs the agent's whole persistence layer: memory-safe at the parsing edge, no Python GIL contention with the H3ERE pipeline, embeddable in the lens process and the agent process, fork-survivable, native sqlite and postgres without a dialect-translation layer. That substrate is the `ciris-persist` crate.

## 2. Scope

**`ciris-persist`** is a Rust crate that owns **all CIRIS persistence except external-service databases** (CIRISRegistry, CIRISPortal). It covers three groups of tables:

| Group | Tables / surfaces |
|---|---|
| **Lens trace persistence** (§3) | `trace_events`, `trace_llm_calls`, `accord_public_keys`. Wire-format ingest, Ed25519 verify, PII scrub, per-row scrub envelope. |
| **Agent signed events and time series** (§4) | `audit_log` (feature `cirisaudit`), `service_correlations` (feature `cirislens_correlations`). Append-only, signed, batch-friendly. |
| **Agent runtime state, memory graph, governance** (§5) | `tasks`, `thoughts`, `scheduled_tasks`, `graph_nodes`, `graph_edges`, `tickets`, deferral reports, `wa_cert`, `feedback_mappings`, maintenance locks and the other `cirislens_*` / `cirisgraph` feature-gated tables. These are the absorbed agent tables: mutable relational state with UPDATEs, DELETEs, foreign keys and multi-occurrence atomicity. |
| **Out of scope** | CIRISRegistry, CIRISPortal — external services with their own databases and replication. |

The groups differ in **mutability and write pattern**, not in architecture. They share one `Backend` trait, one migration runner, one verification path and one set of wire-format types. Each agent table group is behind its own Cargo feature, so a deployment compiles only the tables it uses.

## 3. Lens trace persistence

Lens trace ingest runs in `ciris-persist`: the per-broadcast event log (`trace_events` + `trace_llm_calls`, per `FSD/TRACE_EVENT_LOG_PERSISTENCE.md`) is written by this crate, and the lens Python layer is a thin entry point.

### 3.1 Crate shape

The top-level modules under `src/`:

| Module | Role |
|---|---|
| `schema/` | serde structs for the trace wire format; `version.rs` holds the `trace_schema_version` gate (`SUPPORTED_VERSIONS`). |
| `verify/` | Ed25519 and hybrid (Ed25519 + ML-DSA-65) signature verification; canonical JSON bytes. |
| `scrub/`, `pipeline/` | PII scrub and the post-ingest filter pipeline (`FSD/POST_INGEST_FILTER_PIPELINE.md`). |
| `ingest.rs`, `queue.rs`, `journal.rs` | The ingest path, the bounded ingest queue and the `redb` outage journal (§3.4). |
| `store/` | The `Backend` trait and its two implementations: `postgres.rs` (tokio-postgres + deadpool) and `sqlite.rs` (rusqlite; `FSD/SQLITE_CONNECTION_MODEL.md`). Migrations run through `refinery`. |
| `audit/`, `correlations/` | Agent signed events and time series (§4). |
| `tasks/`, `thoughts/`, `graph/`, `tickets/`, `wa_cert/`, `feedback_mappings/`, … | Agent runtime state, memory graph and governance tables (§5), one module per table group. |
| `federation/`, `ceg/`, `scope/`, `read/`, `cache/` | The federation directory and attestation planes, the data access surface and its caller scoping (`FSD/V4_0_DATA_ACCESS_SURFACE.md`, `FSD/FEDERATION_TRUST_INTERFACE.md`). |
| `cirisnode/` | The CIRISNodeCore federation-consensus substrate (Appendix A). |
| `secrets/` | The federated SecretsService (`FSD/POST_INGEST_FILTER_PIPELINE.md` §7). |
| `server/` | The axum HTTP listener (feature `server`). |
| `ffi/` | Python bindings (PyO3). |
| `engine.rs` | `Engine`, the facade every consumer holds. |

Migrations live in `migrations/postgres/lens/` and `migrations/sqlite/lens/`, numbered `VNNN__name.sql`, one per backend for every schema change (`FSD/MIGRATION_IMMUTABILITY.md`).

**Feature flags (main ones):**
- `postgres` — tokio-postgres backend.
- `sqlite` — rusqlite backend.
- `pyo3` / `pyo3-sqlite` — Python bindings over the postgres or sqlite backend.
- `server` — axum HTTP listener.
- `tls` — TLS for postgres connections.
- `classify`, `scrub`, `extract`, `scrub-ner`, `scrub-ort` — pipeline stages.
- `secrets`, `secrets-server`, `secrets-client` — the SecretsService.
- `cirisaudit`, `cirisgraph`, `cirisnode`, `telemetry`, and one `cirislens_*` feature per agent table group.
- `test-anchor` — the test-anchor genesis minter (`FSD/TEST_ANCHOR_BLOCK_MINTER.md`).

The lens deploys with `postgres + pyo3` (FastAPI hands the raw request bytes to Rust); the `server` feature adds an axum listener the host can mount so Rust serves the endpoint itself.

### 3.2 Schema — `trace_events` with audit anchor

`V001__trace_events.sql` creates `trace_events` (carried from `CIRISLens/sql/027_trace_events.sql`) with three columns from the `ACTION_RESULT` component's audit anchor:

```sql
-- inside CREATE TABLE cirislens.trace_events (...)
    audit_sequence_number BIGINT,    -- agent audit_log.sequence_number
    audit_entry_hash      TEXT,      -- agent audit_log.entry_hash (sha256)
    audit_signature       TEXT,      -- agent's signature on the audit entry

CREATE INDEX trace_events_audit_seq
  ON cirislens.trace_events (audit_sequence_number)
  WHERE audit_sequence_number IS NOT NULL;
```

The columns are populated only on the row where `event_type = 'ACTION_RESULT'`; the agent broadcasts these fields (TRACE_WIRE_FORMAT.md §5.9). Other rows leave them NULL. The anchor lets a verifier recompute the per-action chain link without fetching the full audit log.

`trace_llm_calls` and `accord_public_keys` are created in the same migration. Persist runs on plain PostgreSQL and SQLite with ordinary tables and `ts` indexes; it has no TimescaleDB dependency (§7 #7).

### 3.3 Wire format ingest

Strict serde-deserialized structs against `TRACE_WIRE_FORMAT.md` §1–§10. No `serde_json::Value`-then-extract. Batches whose `trace_schema_version` is not in `SUPPORTED_VERSIONS` (`"2.7.0"`, `"2.7.9"`, `"2.7.legacy"`, `"3.0.0"`) are rejected with a structured 422.

Per batch:

1. Deserialize envelope → `BatchEnvelope { events, trace_level, trace_schema_version, batch_timestamp, consent_timestamp, signature, signing_key_id, … }`.
2. Verify Ed25519 signature against canonical payload bytes (sort_keys + `(,:)` separators) using `accord_public_keys` lookup. Reject on mismatch.
3. If `trace_level = full_traces`, run PII scrub via existing `cirislens-core` scrubber (no behavior change). Hold the **pre-scrub canonical bytes** in memory through this step (one extra `Vec<u8>` per component, dropped at step 5) — needed for step 3.5's hash. At `generic` and `detailed`, scrubbing may still mutate sub-fields per the scrubber's own policy; the contract just doesn't *require* it. In every case, `data_pre_scrub == data_post_scrub` is the no-op path — the next step still runs over them.
4. **Sign the per-component envelope (step 3.5). Always.** Every persisted row gets cryptographic provenance, at every trace level, in every deployment. The signing key is **never null** — `ciris-keyring` (CIRISVerify's Rust crate) guarantees there is always a key to sign with, hardware-backed where available, software-backed otherwise. For each component:
   - `original_content_hash = sha256(canonical(component.data_pre_scrub))`
   - `scrub_signature = ed25519_sign(canonical(component.data_post_scrub))` via the deployment's keyring-resident signing key.
   - `scrub_key_id = signer.key_id()`
   - `scrub_timestamp = Utc::now()`

   **Same-key principle across deployments**:
   - **Lens deployment** (§3): the key is owned by the lens, identifier conventionally `lens-scrub-v1` (or a per-deployment scheme). Generated once via `ciris-keyring` bootstrap, stored under the OS keyring (Secret Service / Keychain / DPAPI / Keystore), hardware-backed where available.
   - **Agent deployment** (§4): the key is *the same key the agent uses for its wire-format §8 signature*. There is no separate "agent-scrub key" and "agent-audit key" — one identity, one signing key, two attestations (per-action audit chain + per-component scrub envelope). Persist looks the agent's existing keyring entry up by id rather than minting a new one.

   The signing call is on the hot path. Cost: one Ed25519 sign per component (~30 µs hardware-backed, ~100 µs software-backed), bounded by the component count per batch (typically 12–16). For the agent's default `batch_size = 10` events × ~14 components, that is ~140 sign calls per batch — single-digit milliseconds at hardware speeds.

   **Why this matters (mission alignment).** A `pii_scrubbed = true` boolean is forgeable by anyone with database write access. The scrub envelope is cryptographic proof that *this* deployment handled *this* payload at *this* time, verifiable by any peer with the published public key.

   PoB §3.1 — "the lens role is a function any peer can run on data the peer already has" — becomes *cryptographically attestable* rather than socially trusted. The agent's wire-format §8 signature proves authorship; the scrub envelope proves handling. A peer fetching a row can verify both.

   MISSION.md §2 — `scrub/` constraint "PII never crosses the persistence boundary at trace levels where it isn't warranted" — flips from a *trust* claim to a *verifiable* claim. The unconditional nature is load-bearing: special-casing by trace_level (e.g., "skip signing at generic since there's no PII to attest about") would create a path where a misconfigured deployment claims to be at GENERIC while emitting unverified content. Every level signs; uniform contract; no special cases (MISSION.md §3 anti-pattern #3 — "no bypass branches; admin keys, agent keys, and federation peer keys all verify by the same path").

   The hash + signature also closes a privacy-bridging gap: a lens configured at higher `trace_level` than its scrubber permits cannot pretend it scrubbed when it didn't. A downstream auditor with the `original_content_hash` + `scrub_signature` + the deployment's public key + the bytes that ended up in storage can verify the deployment's attestation without needing the original content.

5. For each event in batch:
   - Decompose `CompleteTrace.components` → one `trace_events` row per component, keyed by `(agent_id_hash, trace_id, thought_id, event_type, attempt_index, ts)`. (THREAT_MODEL.md AV-9: `agent_id_hash` is the dedup-key prefix.)
   - Map `LLM_CALL` components → `trace_llm_calls` rows, linked via `parent_event_id`.
   - Capture the audit anchor on `ACTION_RESULT` rows.
   - Capture the scrub envelope (`original_content_hash`, `scrub_signature`, `scrub_key_id`, `scrub_timestamp`) on every row.
6. Batch INSERT via parameterized `INSERT ... VALUES (...) ON CONFLICT DO NOTHING` for `trace_events`, with a separate batch for `trace_llm_calls`. One transaction per batch; a conflict on `(agent_id_hash, trace_id, thought_id, event_type, attempt_index, ts)` does nothing, so adapter retries are safe.

### 3.4 Robustness primitives

These apply to every table group:

1. **Bounded ingest queue.** `tokio::sync::mpsc` channel, capacity ~1024 batches. Producer (axum handler / PyO3 entry) blocks on full queue; persister side is the single consumer that owns Postgres.
2. **Local journal.** `redb` append-only file at `/var/lib/cirislens/journal.redb`. If Postgres is unreachable on a batch, the batch is journaled and the persister reschedules. On startup, replay any journaled batches before accepting new traffic. Append-only event semantics make this trivially safe.
3. **Schema-version gate.** Reject `trace_schema_version` not in `SUPPORTED_VERSIONS` with HTTP 422 + `{"detail": "schema_unsupported_version", ...}`. (THREAT_MODEL.md AV-15: HTTP-surfaced errors carry stable `kind()` tokens; the verbose form goes to tracing logs only.)
4. **Idempotency.** Unique index on `(agent_id_hash, trace_id, thought_id, event_type, attempt_index, ts)`; `ON CONFLICT DO NOTHING`. Adapter retries cannot double-insert. (THREAT_MODEL.md AV-9: `agent_id_hash` is the dedup-key prefix, so one agent reusing another's dedup tuple cannot suppress the victim's traces.)
5. **Backpressure.** Full queue → HTTP 429 with `Retry-After`. The agent retries.
6. **Memory-safe parse.** No `serde_json::Value` in the hot path; concrete structs from the `schema/` module. Body-size cap `MAX_INGEST_BODY_BYTES = 8 MiB` at the axum router (AV-7); `data` recursion-depth cap `MAX_DATA_DEPTH = 32` (AV-6); `MAX_ATTEMPT_INDEX = 1024` typed bound (AV-17).
7. **Always-present signing key, isolated in `ciris-keyring`.** The signing key is **never null**. CIRISVerify guarantees `ciris-keyring` always has a key for the configured `key_id` — generated on first call, hardware-backed where available (Linux Secret Service / TPM 2.0; macOS Keychain / Secure Enclave; iOS / Android StrongBox; Windows DPAPI / TPM), software-backed via `SoftwareSigner` fallback otherwise. Persist depends directly on `ciris-keyring` (CIRISVerify's Rust crate); the consuming Python process (FastAPI, agent) never holds the signing-key seed in memory — the bytes never cross the FFI boundary.

   `Engine` construction takes `signing_key_id` as a **required** parameter. The ctor calls into the keyring's bootstrap path internally — idempotent: returns the existing key if it exists, generates a new seed and stores it if not. The lens / agent then publishes the corresponding public key to the registry / lens-discovery layer. There is no "no-signing" mode; the substrate's contract assumes every row carries provenance.

   **The same key is the deployment's federation identity.** Under Reticulum addressing the destination is `SHA256(public_key)[..16]` — addressing is identity (PoB §3.2). Persist's `Signer::public_key()` is the source of truth a transport reads to compute that destination; there is no separate "network address" key.

   On the agent (§4): persist points at the agent's existing wire-format §8 signing key by id — same key, no new keyring entries. The agent's identity stays single-keyed.

   **One key, three roles** (PoB §3.2): the same key signs row provenance, derives the transport address, and is the public-key entry the deployment publishes to the registry. Compromising the key compromises all three at once. That is the case for hardware-backed keyring entries: the residual risk of the `SoftwareSigner` fallback is the risk of losing the deployment's federation standing entirely.

   (Secondary mitigation against THREAT_MODEL.md AV-25 "scrub-key compromise"; the `SoftwareSigner` fallback is acceptable for dev / sovereign deployments without hardware backing, and is named as a residual risk in §8 of the threat model.)

   Mission alignment: MISSION.md §2 — `ffi/` "every divergence between iOS and server reasoning is a place the Federated Ratchet can be silently broken — different bug surfaces, different invariants, different PII boundaries. One core; many shells." The keyring dep is the realization of that on the key-storage axis. MISSION.md §3 anti-pattern #3 ("no bypass branches; same path for every key") is realized by the always-present-signing rule: there is no "skip signing" code path to attack.

### 3.5 Lens integration

- The lens's `/api/v1/accord/events` handler hands the raw request bytes to `Engine.receive_and_persist(bytes)` (PyO3). Persist parses, verifies, scrubs, signs and stores the batch; the lens does not write trace rows itself. With the `server` feature, persist binds the HTTP port directly.
- The legacy `accord_traces` table is read-only history; persist never writes it. Union queries treat a legacy row as a single-event summary row (`attempt_index = 0`, `step_point = action_complete`).
- Read patterns rely on `ts` indexes on both backends.
- The lens integration guide is `docs/INTEGRATION_LENS.md`.

### 3.6 What the agent has to change

**Nothing.** The Ed25519 hash chain lives in the agent's `audit_log` table (`sequence_number`, `previous_hash`, `entry_hash`, `signature`, `signing_key_id`). The audit-chain anchor is broadcast on every `ACTION_RESULT` event (TRACE_WIRE_FORMAT.md §5.9: `audit_entry_id`, `audit_sequence_number`, `audit_entry_hash`, `audit_signature`). The wire format carries `trace_schema_version` and `attempt_index` per `(thought_id, event_type)` (TRACE_WIRE_FORMAT.md §6). The lens side captures the anchor on the `ACTION_RESULT` row.

Per-event chain links (a chain link on every intermediate event, not just `ACTION_RESULT`) are an open question; see §4.5.

### 3.7 Schema — scrub envelope columns

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
| `scrub_key_id` | TEXT — the deployment's `signing_key_id` | Identifies which deployment (or which key generation under that deployment) signed. On the lens this is `lens-scrub-v1` (or a per-deployment scheme); on the agent it is the agent's wire-format §8 signing key id. |
| `scrub_timestamp` | TIMESTAMPTZ | When the scrub+sign happened. The window between the trace's `completed_at` and `scrub_timestamp` bounds how long the unscrubbed bytes existed in deployment memory — useful for forensics / SLA. |

**Every row persist writes has all four columns populated.** §3.4 robustness primitive #7 makes the signing key always present, so the pipeline always produces an envelope. There is no code path that writes a row without one.

**Limit:** rows written before the envelope columns existed (legacy history, including `accord_traces`) have NULLs in all four. Queries that need the envelope guarantee filter on `WHERE scrub_signature IS NOT NULL`. Those rows age out under the lens's 30-day retention window.

The envelope is a persistence-layer property; it does not change the wire format or `trace_schema_version`.

## 4. Agent signed-events persistence

The agent's `audit_log` and `service_correlations` writes go through `ciris-persist` (PyO3-bound inside the agent process), on the same `Backend` trait, migration runner, verification code and wire-format definitions as lens ingest.

### 4.1 Surfaces

| Surface | Mechanism |
|---|---|
| `audit_log` (feature `cirisaudit`) | `src/audit/` — append, verify and Merkle-store the agent's signed audit chain (`V014__cirislens_audit_log.sql`; archives in `V049`). |
| Audit Merkle roots | `src/audit/merkle_store.rs` (`FSD/FEDERATION_TRUST_INTERFACE.md` §4.4). |
| `service_correlations` (feature `cirislens_correlations`) | `src/correlations/` (`V026__cirislens_service_correlations.sql`). |
| sqlite backend | `src/store/sqlite.rs` — one writer connection plus a read pool (`FSD/SQLITE_CONNECTION_MODEL.md`). |

### 4.2 Agent tables in persist

The agent's signed-event tables (§4.1) and its runtime-state, memory-graph and governance tables (§5) are all persist tables. Each group is behind its own Cargo feature (§3.1), so an agent compiles the groups it uses.

### 4.3 iOS client implications

The iOS client runs the agent through the Python wheel (BeeWare); persist ships an iOS device wheel (`FSD/PLATFORM_ARCHITECTURE.md` §3.1, §3.5). The C ABI (feature `c-abi`) is declared but gates no code; see §8.

### 4.4 Federation replication hook

Peer replication runs on the federation plane, not on a database notification channel: signed rows travel between peers through the federation directory, the outbound queue and the transport (`FSD/FEDERATION_TRUST_INTERFACE.md`; the audit Merkle store is §4.4 there). PoB §5.1 gossip topology is a consumer of that surface, not a change to the storage layer. The `peer-replicate` Cargo feature is declared but gates no code; see §8.

### 4.5 Per-event chain extension (open question)

Should the agent broadcast a chain link (`prev_event_hash`, `event_hash`) on every intermediate event, not just `ACTION_RESULT`, with the lens capturing it on every `trace_events` row? Cost: ~64 bytes/row plus write coordination on each agent's chain head. Benefit: tampering with a single row is detectable without re-fetching the batch envelope. Not implemented; the open question has no tracking issue.

## 5. Agent runtime state, memory graph, and governance

The agent's runtime state, memory graph and governance tables are persist tables. Every reasoning-loop hot path on the agent touches `tasks` / `thoughts` / `graph_nodes`, so these surfaces carry the tightest latency budget in the crate.

### 5.1 Scope

| Table group | Notes |
|---|---|
| `tasks` (mutable, multi-occurrence, signed) | The signing fields (`signed_by`, `signature`, `signed_at`) use the same signing path as the audit chain. |
| `thoughts` (FK→tasks, multi-occurrence) | Hot-path interactive queries. Latency budget tighter than batch ingest. |
| `graph_nodes`, `graph_edges` (feature `cirisgraph`; memory graph, multi-scope) | Attributes may carry values the agent's secrets manager encrypted; persist stores them opaque (§5.7). |
| `tickets`, `deferral_reports` | Governance / WBD plumbing. Lower volume, full referential integrity. **Naming note (CIRISPersist#31):** agent-local deferrals are distinct from CIRISNodeCore's federation-consensus deferral Contributions (Appendix A); the persist namespace keeps the two apart. |
| `wa_cert`, `revoked_service_tokens` (feature `cirislens_service_token_revocation`) | Auth tables. Special care: secrets in row form. |
| `scheduled_tasks`, `feedback_mappings`, `maintenance_locks` (the generalised `consolidation_locks`), `creation_ceremonies`, `continuity_awareness`, `sequence`, `occurrence` | Runtime coordination tables. |

These are the agent table absorptions tracked under CIRISPersist#59, each behind its own `cirislens_*` feature.

### 5.2 How these tables differ from the signed-event tables

| Property | Signed events / time series (§3, §4) | Runtime state / graph / governance (§5) |
|---|---|---|
| Mutability | Append-only | Mutable (UPDATE, DELETE) |
| Referential integrity | None (events are independent) | FKs (`thoughts.source_task_id` → `tasks.task_id`), edge constraints |
| Multi-occurrence atomicity | Not relevant | `try_claim_shared_task` race-claim semantics, `__shared__` namespace |
| Query shape | Batch INSERT, time-bounded scans | Interactive lookups, graph traversal, top-K aggregates |
| Latency budget | Throughput-bound | Latency-bound (single-row reads in the H3ERE hot path) |
| Test parity | Verify-and-store contract is small | The agent's persistence test suite is the load-bearing validator |

One crate absorbs both shapes without bifurcating; the `Backend` trait is shared by all of them.

### 5.3 What the agent no longer carries

- A sqlite/postgres dialect adapter. Each backend speaks its native dialect; no `?`→`%s` or `INSERT OR REPLACE`→`ON CONFLICT` translation.
- A thread-local connection cache for iOS. Rust threading is explicit (`FSD/SQLITE_CONNECTION_MODEL.md`).
- Backend-error classification for retries. `rusqlite` and `tokio-postgres` expose typed error variants; retry policy lives next to the backend.
- A per-row pydantic mapping layer. Serde-derived structs map rows at compile time.

### 5.4 What stays

- Cross-language schemas. Pydantic schemas for other clients (web client, iOS) remain on the agent side.
- Multi-occurrence semantics: the `agent_occurrence_id` namespace, `__shared__` coordination and `try_claim_shared_task` atomicity, implemented as Rust transactions.

### 5.5 Migration approach

Each table group is its own migration pair (`migrations/postgres/lens/` and `migrations/sqlite/lens/`, e.g. `V024__cirislens_tasks.sql`, `V025__cirislens_thoughts.sql`) and its own Cargo feature. `legacy_migration` (feature `cirislens_legacy_migration`) reads an agent's pre-persist graph database into persist.

### 5.6 Multi-occurrence atomicity

`try_claim_shared_task` is a transactional primitive on `TaskService`:

```rust
fn try_claim_shared_task(
    &self,
    task: Task,
) -> impl Future<Output = Result<ClaimResult<Task>, Error>> + Send;
```

A clean insert returns `ClaimResult::Stored(task)` with the row this caller wrote; a conflict returns `ClaimResult::AlreadyClaimed(task)` carrying the existing row. Both arms name the same `task_id`. The `__shared__` namespace and the per-task-type uniqueness live in the SQL migration.

### 5.7 Secrets-manager integration

The agent's secrets manager encrypts sensitive values inside graph-node attributes before storage and decrypts them on read. That encryption boundary is *above* the persistence layer: persist stores the attributes blob opaque and never sees the plaintext. The federated SecretsService persist itself offers (`FSD/POST_INGEST_FILTER_PIPELINE.md` §7) is a separate surface.

### 5.8 iOS endpoint

The iOS client links persist through the Python wheel built for iOS (`FSD/PLATFORM_ARCHITECTURE.md` §3.1). A C ABI for a Rust-native iOS link is not implemented (§8).

## 6. Non-goals

- **No new cryptographic primitive.** Ed25519, ML-DSA-65 (hybrid signatures), sha256 and the existing canonical-bytes contract.
- **No flag-day migration.** Each agent table group moves on its own migration pair and Cargo feature.
- **No new trace wire format.** TRACE_WIRE_FORMAT.md is canonical; this crate consumes it.
- **No ORM.** The `Backend` trait is thin — direct rusqlite / tokio-postgres beneath it.
- **No replacement of CIRISRegistry / CIRISPortal.** Those run their own databases and have their own replication and governance.
- **No replacement of the agent's secrets-manager encryption.** That encryption boundary stays above the persistence layer (§5.7).
- **No change to multi-occurrence semantics.** `agent_occurrence_id` namespacing, `__shared__` coordination and the `try_claim_shared_task` race-claim are preserved.
- **No reasoning-loop business logic.** This crate owns *persistence*, not the H3ERE pipeline, the conscience faculties or the DMA implementations.

## 7. Design decisions and open questions

The numbering is stable; other documents cite items by number.

1. **Repo home.** Decided: a separate repo (`CIRISAI/CIRISPersist`), the same shape decision PoB §3.1 made.
2. **PyO3 receive entry point.** Decided: `Engine.receive_and_persist(body, pre_verified=False)` is synchronous from Python's perspective and async inside; it returns a summary dict.
3. **Journal store.** Decided: `redb` (single file, maintained, simple API).
4. **Schema-version policy.** Decided: a supported set, the `SUPPORTED_VERSIONS` constant (§3.3); anything outside is rejected.
5. **Per-event audit chain extension.** Open; see §4.5.
6. **Spock interaction.** Open: whether a deployment's agent tables also sit under site-internal logical replication (Spock) for HA, alongside persist's federation replication. Persist does not depend on Spock.
7. **TimescaleDB feature gate.** Decided: persist does not use TimescaleDB (CIRISPersist#222). The runtime is plain PostgreSQL + SQLite. The only residue is dormant DDL in two shipped migrations (V001's hypertable call and V079's continuous aggregate), each guarded on the extension's presence and left byte-for-byte unchanged because shipped migrations are immutable (`FSD/MIGRATION_IMMUTABILITY.md`); V081 replaces V079's aggregate with a plain rollup table on both backends.
8. **Schema generation direction.** Open: whether the agent's pydantic schemas are generated from persist's Rust types or kept in parallel with a contract test.
9. *(Withdrawn — concerned the start condition for moving the agent's runtime-state tables, which have moved.)*
10. **Multi-occurrence test fixtures.** The agent's `try_claim_shared_task` fixtures test semantics; persist's own witnesses cover the Rust transaction on both backends (§5.6).
11. **Graph traversal query shape.** Decided: named procedures on `GraphService` (`traverse_k_hop`, `query_nodes`, `get_edges_for_node`, counts) rather than a composable query DSL.
12. **Client schema generation tooling.** Open: the toolchain for generating web-client and iOS schemas from Rust types.

## 8. Delivery status

| Surface | Status |
|---|---|
| Lens trace ingest via PyO3 (`receive_and_persist`) | Implemented |
| HTTP listener (`server` feature) | Implemented (library listener; there is no standalone `cirislens-ingest` binary) |
| Agent `audit_log`, audit Merkle store, `service_correlations` | Implemented |
| sqlite backend | Implemented |
| Agent runtime state, memory graph, governance tables (§5.1) | Implemented, one feature per table group |
| CIRISNodeCore federation-consensus substrate (Appendix A) | Implemented (feature `cirisnode`) |
| Federation replication | Implemented on the federation plane (§4.4) |

**Not implemented:**
- **C ABI** (feature `c-abi`) — declared in `Cargo.toml`, gates no code.
- **`peer-replicate` hook** (feature `peer-replicate`) — declared in `Cargo.toml`, gates no code; replication runs on the federation plane instead (§4.4).
- **`audit_roots` / `audit_signing_keys` tables** — persist has no tables of these names; audit roots are kept by the Merkle store (§4.1).
- **Per-event chain links** — open question (§4.5).

## 9. References

- `~/CIRISLens/FSD/PROOF_OF_BENEFIT_FEDERATION.md` §3.1 — the architectural collapse this FSD operationalizes
- `~/CIRISAgent/FSD/TRACE_WIRE_FORMAT.md` — canonical wire shape (`trace_schema_version`, attempt_index, audit anchor on ACTION_RESULT §5.9)
- `~/CIRISAgent/FSD/TRACE_EVENT_LOG_PERSISTENCE.md` — the lens-side persistence design §3 implements
- `~/CIRISLens/sql/027_trace_events.sql` — the origin of `migrations/postgres/lens/V001__trace_events.sql`
- `~/CIRISAgent/ciris_engine/logic/persistence/` — the agent persistence module whose tables persist holds
- `~/CIRISAgent/ciris_engine/logic/persistence/README.md` — multi-occurrence and time-series documentation
- `~/CIRISLens/CLAUDE.md` — lens project conventions; Coherence Ratchet detection / Accord API surface
- `docs/INTEGRATION_LENS.md` — the lens integration guide

## 10. Closing note

The agent has a hash chain. The lens has a Rust ingest edge. The wire format carries the chain anchor on every action. This crate recognises a structural alignment: every CIRIS federation primitive that needs durable state — agent, lens, node — shares one persistence substrate, on postgres or sqlite.

---

## Appendix A — Federation-consensus substrate (CIRISNodeCore)

**Status:** Implemented in `src/cirisnode/` (feature `cirisnode`); closes CIRISPersist#30. Every federation-consensus class is a hybrid-signed `scores` row on the attestation plane (CC 3.1.9); the module's own tables hold only projections and local bookkeeping (§A.4).

### A.1 Why a separate table class

CIRISNodeCore (`CIRISAI/CIRISNodeCore`; `MISSION.md` §2 enumerates 11 federation primitives) is the second-tier consensus layer. Its classes — Identity, Commons Credits, Expertise, Vote, Contribution, Truth-Grounding, Weighted Aggregate, Moderation, Slashing, Witness-Diversity, Reconsideration — are **federation-consensus records**.

They are **structurally distinct** from the agent-local tables of §5 (`tasks`, `thoughts`, `deferral_reports`, …). The agent-local tables hold one agent's runtime state; the federation-consensus records hold the federation's consensus output across many agents and witnesses. Same crate, different write paths, different audit semantics. Both carry "deferral" as a domain term; the persist namespace keeps them apart (CIRISPersist#31).

CIRISNodeCore consumes persist as substrate, the same pattern CIRISLensCore uses: it holds the `Engine` handle and never opens its own database connection.

### A.2 Write surfaces (typed methods on `Engine`)

Signed attestations are the only state. Each class is a dimension (CC 3.1.9) on a hybrid-signed `scores` row, admitted by the attestation plane's door and replicated like any row (`src/cirisnode/rows.rs`):

| Class | Dimension | Attester → attested |
|---|---|---|
| Contribution (CC 2.1) | `contribution:{subject_kind}:v1` | the author → the author |
| Takedown notice | `takedown_notice:{basis}:v1` (CC 3.1.1) | the claimant (duty-holder) |
| Vote | `vote:{contribution_id}:v1` | the voter → the contribution's author |
| Moderation event | `moderation:{allegation_type}:v1` | the accuser → the accused |
| Slashing | `slashing:{outcome}:v1` | the adjudicator → the accused |
| Reconsideration filing | `reconsideration:{grounds}:v1` | the filer → the slashed party |
| Reconsideration ruling | `reconsideration:{grounds}:v1` + `outcome` | the review-holder → the same |
| Credits balance | `credits:{domain}:{language}:{subject}:v1` | this node → the contributor |
| Expertise balance | `expertise:{domain}:{language}:v1` | this node → the contributor |

Every leaf carries CC 3.1.7's trailing version segment (`:v1`).

The `Engine` write methods plan the row and sign it with the engine's own key: `cirisnode_put_contribution`, `cirisnode_cast_vote`, `cirisnode_put_moderation_event`, `cirisnode_put_slashing_attestation`, `cirisnode_put_reconsideration_request`, `cirisnode_put_reconsideration_attestation`, `cirisnode_update_credits_ledger`, `cirisnode_update_expertise_ledger`, and `cirisnode_process_takedown_admission`. Inputs (`ContributionInput`, `VoteInput`, `ModerationInput`, `SlashingInput`, `ReconsiderationRequestInput`, `ReconsiderationRulingInput`, `CreditsUpdate`, `ExpertiseUpdate`) carry no id, author or signature — persist supplies those. The Python surface exposes the same names, taking JSON bodies. A wrapped key travels only on the key-grant plane (`key_grant:{axis}:v1`); a Contribution cannot carry one. A typed envelope of the older shape offered at a door is refused by name (`rows::refusal`).

Moderation and takedown emissions are gated: the signer must hold the duty as itself (a subject of the target content or a named moderator of the target community) or be reached by a steward-bound duty-holder through a live `delegates_to` chain bearing the governing scope (`moderate` / `takedown`). Otherwise the row is not stored and the error kind is `cirisnode_delegated_scope_unauthorized`.

### A.3 Read surfaces

| Read | Purpose |
|---|---|
| `cirisnode_routable_contributors(domain, language)` | Contributors with non-zero Expertise in `(domain, language)`, filtered to the Active tier — `MISSION.md` §3.3 deferral routing. |
| `cirisnode_read_vote_weight(...)` | `Credits × expertise_multiplier × active_tier_multiplier` for vote weighting (`CIRISNodeCore/SCHEMA.md` §5.2). |
| `cirisnode_list_contributions`, `cirisnode_list_votes`, `cirisnode_list_takedowns_for_filtered_json` | Cursor-paged listings over the `scores` rows. |
| `cirisnode_get_credits_ledger(contributor_id)`, `cirisnode_get_expertise_ledger(contributor_id)` | Point lookups on the ledger projections. |

**Not implemented:** a pending-versus-canonical audit-chain split read (`pending_audit_chain` / `canonical_audit_chain`); no tracking issue.

### A.4 Schema migration shape

The `cirisnode` schema (postgres; table-name prefix on sqlite) holds what is not a claim:

- `credits_ledger`, `expertise_ledger` — **projections**: each row is the fold of this node's `credits:` / `expertise:` rows, with an `attestation_id` naming the row it came from. A ledger row written before the rows existed has a NULL `attestation_id` until `cirisnode_rehome_ledgers` re-emits it as a row.
- Promotion records (`V012__cirisnode_promotion_attestations.sql`) and `federation_delivery_attestations` — local bookkeeping.
- `scheduled_takedown_actions` — the executed-takedown schedule; `legal_basis` uses CC 3.3.2's wire strings (`dmca512`, `dsa_article16`).

`V011__cirisnode_consensus.sql` creates the schema; `V203__cirisnode_silos_onto_scores.sql` drops the per-class typed tables (`contributions`, `votes`, `moderation_events`, `slashing_attestations`, `reconsideration_requests`, `reconsideration_attestations`) in favour of the `scores` rows above.

### A.5 Sequencing

The `cirisnode` Cargo feature gates the module and its Python surface; deployments that do not need the federation-consensus path leave it off. Contribution and Vote are the base classes (`CIRISNodeCore/MISSION.md` §3.3 deferral routing); every other class builds on them.

### A.6 Sibling issues

- `CIRISPersist#31` — agent-local deferrals versus federation-consensus deferral Contributions (the naming note in §5.1).
- `CIRISAI/CIRISEdge` — `MessageType` wire types for these classes (tracked in the edge repo).
- `CIRISAI/CIRISNodeCore/SCHEMA.md` + `MISSION.md` — the upstream spec this appendix accepts as input.

---
