# PUBLIC_SCHEMA_CONTRACT.md

CIRISPersist's `cirislens` schema is the analytical substrate for every
federation peer that reads persist's data — lens science scripts,
partner sites, registry dashboards, sovereign-mode operators. Today
those consumers connect with the same DSN as the write path, which
works but conflates privilege levels and gives no contract about which
columns persist guarantees vs. which are internal.

This doc + the `cirislens_reader` role provisioned by V005 fix that.

## Scope

This contract applies to columns visible through the `cirislens_reader`
PostgreSQL role (see `migrations/postgres/lens/V005__readonly_role.sql`).
Connect with a login user that has `GRANT cirislens_reader` and you
get SELECT on every table in this contract. Write paths stay
exclusively `Engine.receive_and_persist` (trace ingest) and
`Engine.put_*` (federation directory) — there is no public write
contract.

## Stability tiers

- **`stable`** — semver-guaranteed. Removal or type change requires a
  major version bump *and* a deprecation window of one minor version
  minimum. Downstream code can rely on these existing across patch and
  minor versions of persist.
- **`stable-ro`** — server-computed; downstream may read but writes
  are ignored. Examples: `persist_row_hash` (computed by persist's
  canonicalizer on every write; consumers store + string-compare for
  cache divergence). Same stability guarantees as `stable`.
- **`internal`** — no stability guarantee. May change shape, semantics,
  or disappear at any minor version without notice. Downstream code
  that depends on `internal` columns is buying breakage on every
  upgrade. Persist may revoke SELECT on `internal` columns from
  `cirislens_reader` at a future minor; analytical paths should rely
  only on `stable` / `stable-ro` columns.

## Tables

### `cirislens.trace_events`

Per-event row for the agent's reasoning chain. One row per agent step
per attempt. Time-series via `ts`; deduped on
`(agent_id_hash, trace_id, thought_id, event_type, attempt_index, ts)`.

| Column                    | Type        | Tier      | Notes |
|---------------------------|-------------|-----------|-------|
| `event_id`                | bigserial   | stable    | Persist-assigned monotonic id. |
| `trace_id`                | text        | stable    | Per-trace identifier from the agent. |
| `thought_id`              | text        | stable    | Per-thought identifier within a trace. |
| `task_id`                 | text        | stable    | Optional; null when not present on wire. |
| `step_point`              | text        | stable    | Wire-format §3 step taxonomy. |
| `event_type`              | text        | stable    | Reasoning event taxonomy (`PERFORM_ASPDMA_THOUGHT`, etc.). |
| `attempt_index`           | int         | stable    | Per-event retry index; 0 for first attempt. |
| `ts`                      | timestamptz | stable    | Event timestamp from agent (TimescaleDB hypertable key). |
| `agent_name`              | text        | stable    | Human-readable agent identifier. |
| `agent_id_hash`           | text        | stable    | Cryptographic agent identifier; load-bearing for AV-9 dedup. |
| `cognitive_state`         | text        | stable    | Agent cognitive state at event time. |
| `trace_level`             | text        | stable    | `generic` \| `detailed` \| `full_traces`. |
| `payload`                 | jsonb       | stable    | Event-specific structured data. Schema varies by `event_type`. |
| `cost_llm_calls`          | int         | stable    | Number of LLM calls for this event. |
| `cost_tokens`             | int         | stable    | Total tokens (prompt + completion). |
| `cost_usd`                | float8      | stable    | Cost in USD; double precision. |
| `signature`               | text        | stable    | Per-event signature (Ed25519, base64). |
| `signing_key_id`          | text        | stable    | Key identifier; chain to `federation_keys.key_id`. |
| `signature_verified`      | bool        | stable    | True iff persist verified `signature` against `signing_key_id` at ingest. |
| `schema_version`          | text        | stable    | Wire-format version (`2.7.0`, `2.7.9`, etc.). |
| `pii_scrubbed`            | bool        | stable    | True iff persist's scrubber callback ran on `payload`. |
| `audit_sequence_number`   | bigint      | internal  | Audit-chain sequence number; persist-internal hashing. |
| `audit_entry_hash`        | text        | internal  | Hash-chain entry; persist-internal forensic field. |
| `audit_signature`         | text        | internal  | Audit signature; persist-internal forensic field. |

### `cirislens.trace_llm_calls`

Per-LLM-call rows linked to a parent `trace_events` row by `trace_id`
+ `parent_event_type` + `parent_attempt_index` (v2.7.9 wire format).

| Column                  | Type        | Tier     | Notes |
|-------------------------|-------------|----------|-------|
| `call_id`               | bigserial   | stable   | Persist-assigned monotonic id. |
| `trace_id`              | text        | stable   | Joins to `trace_events.trace_id`. |
| `thought_id`            | text        | stable   | Joins to `trace_events.thought_id`. |
| `task_id`               | text        | stable   | Optional. |
| `parent_event_id`       | bigint      | stable   | FK-shape join to `trace_events.event_id` when computable. |
| `parent_event_type`     | text        | stable   | v2.7.9: parent event taxonomy. |
| `parent_attempt_index`  | int         | stable   | v2.7.9: parent's `attempt_index`. |
| `attempt_index`         | int         | stable   | LLM call's own retry index. |
| `ts`                    | timestamptz | stable   | Call timestamp (hypertable key). |
| `duration_ms`           | float8      | stable   | Wall-clock latency. |
| `handler_name`          | text        | stable   | Handler that issued the call. |
| `service_name`          | text        | stable   | Inference provider service identifier. |
| `model`                 | text        | stable   | Model name (`claude-opus-4-7`, `gpt-5`, etc.). |
| `base_url`              | text        | stable   | Inference endpoint base URL. |
| `response_model`        | text        | stable   | Pydantic response model class name. |
| `prompt_tokens`         | int         | stable   | Provider-reported prompt tokens. |
| `completion_tokens`     | int         | stable   | Provider-reported completion tokens. |
| `prompt_bytes`          | int         | stable   | Wire bytes for prompt. |
| `completion_bytes`      | int         | stable   | Wire bytes for completion. |
| `cost_usd`              | float8      | stable   | Cost in USD; double precision. |
| `status`                | text        | stable   | `ok` \| `error` \| `timeout` \| etc. |
| `error_class`           | text        | stable   | Exception class on `status != 'ok'`. |
| `attempt_count`         | int         | stable   | Total attempts including retries. |
| `retry_count`           | int         | stable   | Retry-only count. |
| `prompt_hash`           | text        | stable   | SHA-256 of prompt; cache-key analytics. |
| `prompt`                | text        | stable   | Full prompt text (scrubbed at `trace_level >= detailed`). |
| `response_text`         | text        | stable   | Full response text (scrubbed at `trace_level >= detailed`). |

### `cirislens.federation_keys`

Federation public-key directory. Hybrid Ed25519 + ML-DSA-65 per
[`docs/FEDERATION_DIRECTORY.md`](FEDERATION_DIRECTORY.md).

| Column                       | Type        | Tier     | Notes |
|------------------------------|-------------|----------|-------|
| `key_id`                     | text        | stable   | Primary key. Joins to `signature_key_id` on traces. |
| `pubkey_ed25519_base64`      | text        | stable   | 32 raw bytes base64 → 44 chars. |
| `pubkey_ml_dsa_65_base64`    | text        | stable   | 1952 raw bytes base64 → ~2604 chars; null until cold-path PQC fill-in completes. |
| `algorithm`                  | text        | stable   | Always `'hybrid'` (CHECK constraint). |
| `identity_type`              | text        | stable   | `agent` \| `primitive` \| `steward` \| `partner`. |
| `identity_ref`               | text        | stable   | Shape varies by `identity_type`; see V004 schema header. |
| `valid_from`                 | timestamptz | stable   | Validity start. |
| `valid_until`                | timestamptz | stable   | Validity end; null = no expiry. |
| `registration_envelope`      | jsonb       | stable   | Canonical bytes that were signed. Forensic preservation. |
| `original_content_hash`      | bytea       | stable   | SHA-256 of canonical envelope. |
| `scrub_signature_classical`  | text        | stable   | Ed25519 signature, base64 (88 chars). |
| `scrub_signature_pqc`        | text        | stable   | ML-DSA-65 signature, base64; null until cold-path fills in. |
| `scrub_key_id`               | text        | stable   | FK to `federation_keys.key_id`; chains to root via DEFERRABLE FK. |
| `scrub_timestamp`            | timestamptz | stable   | When the row was signed. |
| `pqc_completed_at`           | timestamptz | stable   | When PQC components were attached; null while hybrid-pending. |
| `persist_row_hash`           | text        | stable-ro| Server-computed; consumers store + string-compare for cache divergence. |

### `cirislens.federation_attestations`

"Key A vouches for / witnesses / refers / delegates-to key B".

| Column                       | Type        | Tier     | Notes |
|------------------------------|-------------|----------|-------|
| `attestation_id`             | uuid        | stable   | Primary key. |
| `attesting_key_id`           | text        | stable   | FK to `federation_keys.key_id`. |
| `attested_key_id`            | text        | stable   | FK to `federation_keys.key_id`. |
| `attestation_type`           | text        | stable   | `vouches_for` \| `witnesses` \| `referred` \| `delegated_to` \| (consumer extensions). |
| `weight`                     | numeric     | stable   | Attester-supplied weight; null = consumer policy decides. |
| `asserted_at`                | timestamptz | stable   | When the attestation was made. |
| `expires_at`                 | timestamptz | stable   | Expiry; null = no expiry. |
| `attestation_envelope`       | jsonb       | stable   | Canonical bytes that were signed. |
| `original_content_hash`      | bytea       | stable   | SHA-256 of canonical envelope. |
| `scrub_signature_classical`  | text        | stable   | Ed25519 signature, base64. |
| `scrub_signature_pqc`        | text        | stable   | ML-DSA-65 signature; null until cold-path fills in. |
| `scrub_key_id`               | text        | stable   | FK to `federation_keys.key_id`. |
| `scrub_timestamp`            | timestamptz | stable   | When the row was signed. |
| `pqc_completed_at`           | timestamptz | stable   | When PQC was attached; null while hybrid-pending. |
| `persist_row_hash`           | text        | stable-ro| Server-computed canonical hash. |

### `cirislens.federation_revocations`

Append-only revocation log. Consumers compute "is K revoked at T?" by
querying revocations of K with `effective_at <= T` and applying their
own consensus policy.

| Column                       | Type        | Tier     | Notes |
|------------------------------|-------------|----------|-------|
| `revocation_id`              | uuid        | stable   | Primary key. |
| `revoked_key_id`             | text        | stable   | FK to `federation_keys.key_id`. |
| `revoking_key_id`            | text        | stable   | FK to `federation_keys.key_id`. |
| `reason`                     | text        | stable   | Free-form; consumers parse if they care. |
| `revoked_at`                 | timestamptz | stable   | When the revocation was issued. |
| `effective_at`               | timestamptz | stable   | When it takes effect; may be past (retroactive) or future (scheduled). |
| `revocation_envelope`        | jsonb       | stable   | Canonical bytes that were signed. |
| `original_content_hash`      | bytea       | stable   | SHA-256 of canonical envelope. |
| `scrub_signature_classical`  | text        | stable   | Ed25519 signature, base64. |
| `scrub_signature_pqc`        | text        | stable   | ML-DSA-65 signature; null until cold-path fills in. |
| `scrub_key_id`               | text        | stable   | FK to `federation_keys.key_id`. |
| `scrub_timestamp`            | timestamptz | stable   | When the row was signed. |
| `pqc_completed_at`           | timestamptz | stable   | When PQC was attached; null while hybrid-pending. |
| `persist_row_hash`           | text        | stable-ro| Server-computed canonical hash. |

### `cirislens.accord_public_keys` *(deprecated, retires at v0.4.0)*

Legacy lens-canonical pubkey directory. v0.2.0+ writes to
`federation_keys`; the verify path dual-reads both tables (federation
first, accord fallback). v0.4.0 retires this table.

| Column              | Type        | Tier        | Notes |
|---------------------|-------------|-------------|-------|
| `key_id`            | text        | deprecated  | PK; mirrors `federation_keys.key_id`. |
| `public_key_base64` | text        | deprecated  | Ed25519 only; PQC was never on this table. |
| `algorithm`         | text        | deprecated  | Free-form; `federation_keys.algorithm` is canonical. |
| `description`       | text        | deprecated  | Operator label. |
| `created_at`        | timestamptz | deprecated  | Mirrors `federation_keys.valid_from`. |
| `expires_at`        | timestamptz | deprecated  | Mirrors `federation_keys.valid_until`. |
| `revoked_at`        | timestamptz | deprecated  | Use `federation_revocations` instead. |
| `revoked_reason`    | text        | deprecated  | Use `federation_revocations.reason`. |
| `added_by`          | text        | deprecated  | No equivalent in `federation_keys`. |

**Migration**: at or before v0.4.0, point any reader at
`federation_keys` and treat `accord_public_keys` rows older than the
v0.2.0 cutover as historical-only. v0.3.x's persist dual-reads both
tables for verify, so the read path is unaffected by retiring the
legacy table.

## Legacy lens migration: `accord_traces` → `trace_events` + `trace_llm_calls`

Lens's pre-v0.2.x `accord_traces` table (renamed from `covenant_traces`
in lens migration 022) stored one wide row per trace with denormalized
columns for every IDMA / CSDMA / DSDMA / conscience field. v0.2.x+
splits these into `trace_events` (one row per agent step) +
`trace_llm_calls` (one row per LLM call). Lens analytical scripts
that still query `accord_traces` shapes can migrate using this
mapping:

| `accord_traces` column          | `trace_events` / `trace_llm_calls` location | Notes |
|---------------------------------|----------------------------------------------|-------|
| `trace_id`                      | `trace_events.trace_id` + `trace_llm_calls.trace_id` | Direct. |
| `thought_id`                    | `trace_events.thought_id`                    | Direct. |
| `agent_id_hash`                 | `trace_events.agent_id_hash`                 | Direct. |
| `agent_name`                    | `trace_events.agent_name`                    | Direct. |
| `timestamp`                     | `trace_events.ts`                            | Renamed `ts` for hypertable consistency. |
| `idma_k_eff`                    | `trace_events.payload->>'k_eff'`             | On `event_type='PERFORM_ASPDMA_THOUGHT'` rows. |
| `idma_correlation_risk`         | `trace_events.payload->>'correlation_risk'`  | Same row as `k_eff`. |
| `idma_fragility_flag`           | `trace_events.payload->>'fragility_flag'`    | Same row. |
| `idma_phase`                    | `trace_events.payload->>'phase'`             | Same row. |
| `csdma_plausibility_score`      | `trace_events.payload->>'plausibility'`      | On `event_type='CSDMA_RESULT'` rows. |
| `dsdma_domain_alignment`        | `trace_events.payload->>'domain_alignment'`  | On `event_type='DSDMA_RESULT'` rows. |
| `conscience_passed`             | `trace_events.payload->>'passed'`            | On `event_type='CONSCIENCE_RESULT'` rows. |
| `action_was_overridden`         | `trace_events.payload->>'overridden'`        | On `event_type='CONSCIENCE_RESULT'` rows. |
| `entropy_score`                 | `trace_events.payload->>'entropy'`           | On conscience rows. |
| `coherence_score`               | `trace_events.payload->>'coherence'`         | On conscience rows. |
| `opt_veto_entropy_ratio`        | `trace_events.payload->>'opt_veto_entropy_ratio'` | On conscience rows. |
| `signature_verified`            | `trace_events.signature_verified`            | Direct (column-typed bool, not JSONB). |

Numeric fields stored under `payload` JSONB extract via
`(payload->>'field')::numeric` or `(payload->>'field')::float8`
depending on the analysis. Several `accord_traces` columns
(timestamps, `cost_*` rollups) project across multiple `trace_events`
rows; aggregate by `(trace_id, thought_id)` to reconstruct
trace-scope analytics.

## What's NOT in this contract

- **Lens-owned derived tables**: alerts, capacity scores, ledgers,
  metrics, logs (`coherence_ratchet_alerts`, `case_law_candidates`,
  `pdma_events`, `wbd_deferrals`, `creator_ledger`, `sunset_ledger`,
  `agent_metrics`, `agent_logs`). Those live in `cirislens_derived`
  schema (lens-authored); persist doesn't touch them. The
  `cirislens_reader` role does not grant SELECT on
  `cirislens_derived` — lens manages that schema's privileges.
- **Write paths**. There is no public write contract. Writes go
  through `Engine.receive_and_persist` (trace ingest) or
  `Engine.put_*` (federation directory). Direct INSERT/UPDATE/DELETE
  against `cirislens` tables is not supported and the
  `cirislens_reader` role explicitly does not grant it.
- **Audit-chain reconstruction**. The `audit_*` columns on
  `trace_events` are persist-internal forensic fields. Reconstructing
  the audit chain externally requires persist's canonicalizer +
  signing key access; that's not a public surface.

## Versioning

This contract is part of persist's public API surface. Changes
follow the semver discipline above (`stable` → major bump for
breaking change, with at least one minor's deprecation window).
Persist's CHANGELOG entries call out any column tier changes; consumers
can monitor by pinning persist version and reading the changelog
between bumps.

Schema migrations land in `migrations/postgres/lens/V*.sql`; the
column inventory in this doc is the source of truth for what's
guaranteed.
