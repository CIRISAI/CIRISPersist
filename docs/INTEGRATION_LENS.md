# Lens Integration Guide — `ciris-persist`

**Audience:** the CIRISLens team. Lens hands every inbound trace batch to
`ciris_persist.Engine.receive_and_persist(bytes)` instead of writing rows
itself ([FSD §3.5](../FSD/CIRIS_PERSIST.md)). Persist parses, verifies,
scrubs, signs and stores the batch; lens keeps its scrubber and its derived
analytics.

Every persisted row carries a cryptographic scrub envelope (FSD §3.3 step 3.5;
THREAT_MODEL.md AV-24), so `Engine` always requires a `signing_key_id`. See §11.

---

## TL;DR

```python
from ciris_persist import Engine
from cirislens_core.scrub import scrub_envelope_dict  # your scrubber

ENGINE = Engine(
    dsn=os.environ["CIRISLENS_DB_URL"],
    signing_key_id="lens-scrub-v1",   # REQUIRED
    scrubber=lambda envelope: (scrub_envelope_dict(envelope), 0),
)

# One-time, at deploy: publish the lens's public key. The same key signs
# every row's scrub envelope and is the key the registry stores
# (PoB §3.2 — addressing IS identity).
publish_to_registry("lens-scrub-v1", ENGINE.public_key_b64())

# Every request:
@app.post("/api/v1/accord/events")
async def accept_events(request: Request) -> dict:
    body = await request.body()
    try:
        return ENGINE.receive_and_persist(body)  # → BatchSummary dict
    except ValueError as e:
        # schema / verify / scrub rejection
        raise HTTPException(status_code=422, detail=str(e))
    except RuntimeError as e:
        # backend / IO failure
        raise HTTPException(status_code=503, detail=str(e),
                            headers={"Retry-After": "5"})
```

Agent verifying keys live in the federation directory (§3).

---

## 1. Install

### Option A — pre-built wheel (recommended)

```bash
pip install ciris-persist
```

The wheel is built `abi3-py311`: one wheel works for Python 3.11 and later.

### Option B — build from source

To track `main` between releases, or for a platform without a published
wheel:

```bash
pip install maturin
git clone https://github.com/CIRISAI/CIRISPersist
cd CIRISPersist
maturin build --release --strip
pip install target/wheels/ciris_persist-*.whl
```

`pyproject.toml` `[tool.maturin] features` names the wheel's feature set. The
Rust toolchain is pinned in `rust-toolchain.toml`. openssl is built from
source via the `vendored` feature, so no system `libssl-dev` is required.

---

## 2. Migrations

The migrations are embedded in the wheel and run automatically, idempotently,
when you construct an `Engine`. They create and extend the `cirislens` schema,
including:

- `cirislens.trace_events` — one row per `@streaming_step` broadcast
- `cirislens.trace_llm_calls` — one row per LLM provider invocation
- `cirislens.federation_keys` — the federation public-key directory
- `cirislens.accord_public_keys` — the legacy lens audit-chain key directory

Persist runs on plain PostgreSQL (and SQLite); it uses no PostgreSQL
extensions. Retention is a persist-side, pressure-gated sweeper
(`MaintenanceService::run_retention`) driven by per-table policies in
`retention_policies` (V076); lens does not delete from persist's tables.

### Multi-worker boot contract

`Engine(...)` construction is **safe to call concurrently** from multiple
worker processes (uvicorn `--workers N`, gunicorn, Kubernetes replica sets)
against the same DSN. The first worker takes a session-scoped Postgres
advisory lock (`pg_advisory_lock(0x6369_7269_7370_7372)` — the bytes spell
`"cirispsr"`, so it is greppable in `pg_locks`); the others block until the
first finishes its migration phase, then find nothing to apply and proceed.

The lock is held *only* during the migration phase — short on a fresh
database, near-instant when migrations no-op. Pool setup and keyring
bootstrap afterwards are per-worker.

```
worker A:  connect → take advisory lock → migrations → release → keyring → ready
worker B:  connect → blocks here ───────────────────^ wakes  → keyring → ready
worker C:  connect → blocks ──────────────────────────^ wakes → keyring → ready
```

**Readiness probe timeout.** On a cold database with many migrations, give the
*first* worker time to finish before the orchestrator declares replicas
unhealthy. A 30s `initialDelaySeconds` is a safe default.

**SQLSTATE diagnostics.** Migration-phase errors carry the Postgres SQLSTATE:
`store: migration: [SQLSTATE] detail`. Common codes:

- `42P07` — "relation already exists" (the schema was mutated externally
  mid-flight)
- `40P01` — deadlock detected (re-run; Postgres has released the locks)
- `08006` — connection terminated (transient; retry Engine construction)
- `42501` — permission denied (the DSN user lacks DDL rights)

THREAT_MODEL.md AV-26 is the background.

---

## 3. Register agent public keys

Trace verification looks the signer up by `signature_key_id` in
`federation_keys` (`lookup_public_key`; an expired row does not match).
Register each agent's key there as a `SignedKeyRecord`:

```python
ENGINE.register_federation_key(signed_key_record_json)  # verify-then-store
# or, during the hybrid-pending (Ed25519-only) window:
ENGINE.put_public_key(signed_key_record_json)
```

`register_federation_key` hybrid-verifies the record's scrub signature
(Ed25519 + ML-DSA-65, Strict) before storing; any failure stores nothing.
`put_public_key` accepts a hybrid-pending record whose PQC half is attached
later. Both are idempotent on identical content.

`register_public_key(signature_key_id, public_key_b64, agent_id_hash=None)`
writes the separate **lens audit-chain directory** (`accord_public_keys`). It
is idempotent on the same key and refuses a rotation (a different key for an
existing id raises). The trace verify path does not read it.

Key rotation is never automatic under attacker control (MISSION.md §6
anti-pattern #3); THREAT_MODEL.md AV-11 covers it.

---

## 4. The FastAPI handler

```python
@app.post("/api/v1/accord/events")
async def accept_events(request: Request):
    body = await request.body()          # bytes, not parsed
    try:
        summary = ENGINE.receive_and_persist(body)
    except ValueError as e:
        # schema / verify / scrub rejection
        raise HTTPException(status_code=422, detail=str(e))
    except RuntimeError as e:
        # backend / IO failure (Postgres unreachable, etc.)
        raise HTTPException(status_code=503, detail=str(e),
                            headers={"Retry-After": "5"})
    return summary
```

`summary` is a `BatchSummary` dict:

```python
{
    "envelopes_processed": 1,
    "trace_events_inserted": 12,
    "trace_events_conflicted": 0,    # ← non-zero on agent retries
    "trace_llm_calls_inserted": 5,
    "scrubbed_fields": 3,
    "signatures_verified": 1,
}
```

Surface these numbers on your operations dashboard. A regression shows up as
`trace_events_inserted` dropping, or `trace_events_conflicted` climbing
without `signatures_verified` matching.

### Error → HTTP mapping

| Exception | Maps to | Cause |
|---|---|---|
| `ValueError("schema: …")` | **422** | malformed JSON, schema-version mismatch, missing required field, bad `attempt_index` |
| `ValueError("verify: …")` | **422** (or **401** for unknown key) | signature mismatch, malformed signature, unknown signing key |
| `ValueError("scrub: …")` / `ValueError("scrub_treatment_mismatch", …)` | **422** (rejected scrubber output) or **500** (scrubber bug) | the scrubber altered the envelope's shape, or did not state a treatment a `full_traces` batch requires (§5) |
| `RuntimeError("store: …")` | **503** with `Retry-After` | Postgres unreachable, IO error |
| `LensQueryError` | **500** | a Rust panic caught at the FFI boundary |

Match TRACE_WIRE_FORMAT.md §1: the agent retries on any non-200. 422 is
fatal for that batch (the agent should not retry); 503 is transient.

---

## 5. Scrubber wiring

Wire `cirislens-core`'s scrubber through the `Engine` constructor. The
callable receives the full `BatchEnvelope` as a dict and returns one of three
shapes (`ScrubberOutcome` in `ciris_persist.pyi`):

| Shape | Meaning |
|---|---|
| `(scrubbed, modified_count)` | Reported as `ner_ran=False`, no model digest. Refused on a `full_traces` batch. |
| `(scrubbed, modified_count, ner_ran, model_digest)` | The callable states what it did. Required for `full_traces`. |
| `(scrubbed, modified_count, ner_ran, model_digest, applied_trace_level)` | Also states the level the content was actually treated at; persist relabels the envelope to match. The level may only be **reduced**. |

```python
from cirislens_core.scrub import scrub_envelope_dict

def my_scrubber(envelope: dict):
    scrubbed, count = scrub_envelope_dict(envelope)
    return scrubbed, count, True, MODEL_DIGEST

ENGINE = Engine(dsn=DSN, signing_key_id="lens-scrub-v1", scrubber=my_scrubber)
```

A count is not evidence of a named-entity pass — `0` means both "NER ran and
found nothing" and "no NER ran" — so persist never infers `ner_ran` from it.
A legacy 2-tuple callable handed a `full_traces` batch is refused with
`ValueError("scrub_treatment_mismatch", ...)`; stage a model and return
`ner_ran=True`, or treat at `detailed` and say so with the 5-tuple.

Rules the engine enforces on scrubber output:

- MUST NOT alter `trace_schema_version`
- MUST NOT alter `trace_level`, except to reduce it via the 5-tuple's
  `applied_trace_level`
- MUST NOT alter the `events[]` length or per-event discriminants
- MAY mutate any content text inside `data` blobs

At `trace_level: generic` there is no content text to scrub
(TRACE_WIRE_FORMAT.md §7), and the engine skips the callback. Without a
scrubber the engine uses `NullScrubber`, which is correct *only* at `generic`.
Production at `detailed` / `full_traces` MUST wire a real scrubber.

---

## 6. What's stored where

| Wire field | Lands on | Notes |
|---|---|---|
| `BatchEnvelope.events[i].trace.{trace_id,thought_id,task_id,…}` | `trace_events` per-component row | one row per `components[]` entry |
| component `data` dict | `trace_events.payload` JSONB | stored **verbatim** (the agent's testimony) |
| `data.attempt_index` | `trace_events.attempt_index` (denorm) | typed `int`, dedup-key tail |
| `ACTION_RESULT.audit_*` | `trace_events.audit_sequence_number/audit_entry_hash/audit_signature` | only on the seal row (FSD §3.2); `audit_signature` is optional |
| `ACTION_RESULT.{llm_calls,tokens_total,cost_cents}` | `cost_llm_calls/cost_tokens/cost_usd` (denorm) | `cost_cents → cost_usd` divided by 100 |
| `LLM_CALL` components | additional row in `trace_llm_calls` | linked to parent via `parent_event_id` |
| top-level `signature` + `signature_key_id` | every row of the trace | identical across rows of the same trace |
| the trace's ML-DSA-65 half | `signature_ml_dsa_65`, `pubkey_ml_dsa_65`, `pqc_key_id` (V083) | hybrid-verified with the Ed25519 `signature` |
| top-level `agent_id_hash` | `trace_events.agent_id_hash` | per-agent partitioning |

The dedup key is `(trace_id, thought_id, event_type, attempt_index, ts)` —
`ON CONFLICT DO NOTHING` makes the agent's retries safe (FSD §3.4 robustness
primitive #4). `docs/PUBLIC_SCHEMA_CONTRACT.md` lists which columns are
stable for readers.

---

## 7. Schema-version gate

`trace_schema_version` is a hard gate. A batch whose version is not in the
supported set is rejected with HTTP 422 and detail
`"unsupported trace_schema_version"`:

```python
import ciris_persist as cp
print(cp.SUPPORTED_SCHEMA_VERSIONS)  # → ["2.7.0", "2.7.9", "2.7.legacy", "3.0.0"]
```

The set is `crate::schema::version::SUPPORTED_VERSIONS`. Supporting a new
agent schema version is a persist release; roll the lens before agents flip
the version.

---

## 8. Legacy `accord_traces` history

Lens's pre-persist `accord_traces` table stays readable for history; nothing
writes to it. Do not truncate it. Read-side queries that need uniform history
union it with the new tables (FSD §3.5: legacy rows become single-event
`attempt_index=0, step_point=action_complete` summary rows in the union).
`docs/PUBLIC_SCHEMA_CONTRACT.md` maps each `accord_traces` column to its
`trace_events` / `trace_llm_calls` location.

---

## 9. Operational notes

- **Per-batch transactions.** Each batch is one transaction (FSD §3.3
  step 5). Scaling the lens API horizontally behind a load balancer is fine:
  each worker is independently transactional and `ON CONFLICT` handles dedup.
  Do not fan out by `trace_id`; let the dedup index do the work.
- **Connection pool.** Each process builds one pool inside its process
  singleton `Engine` (`docs/COHABITATION.md`); worker processes do not share
  a pool.
- **Bytes in, dict out.** FastAPI `await request.body()` gives you `bytes`.
  Do not `json.loads` first — the engine signature-verifies *exactly* the
  bytes the agent shipped, and pre-parsing breaks byte-exact
  canonicalization for non-ASCII payloads.
- **Backpressure.** The PyO3 path is synchronous; the FastAPI worker's
  threadpool is the queue. For bounded in-process backpressure with a
  journal-on-failure path, the `server` Cargo feature provides the same
  pipeline behind a Rust (axum) HTTP edge with a `redb`-backed journal and
  429 + `Retry-After` on saturation.

---

## 10. Testing

The fixture-based integration tests in
[`tests/wire_format_fixtures.rs`](../tests/wire_format_fixtures.rs) exercise
real signed traces from CIRISAgent (`tests/fixtures/wire/`) — schema parsing,
decomposition into rows, dedup-key uniqueness, canonicalization determinism.
They run in CI on every PR.

Lens-side smoke test recipe:

```python
# tests/integration/test_engine.py
import ciris_persist as cp

def test_round_trip(tmp_postgres_dsn, agent_signed_key_record):
    engine = cp.Engine(dsn=tmp_postgres_dsn, signing_key_id="lens-test")
    engine.put_public_key(agent_signed_key_record)
    body = sign_with(agent_keypair, sample_complete_trace())
    summary = engine.receive_and_persist(body)
    assert summary["signatures_verified"] == 1
    assert summary["trace_events_inserted"] > 0
```

Use plain `postgres:16`, the image CI uses.

---

## 11. Scrub-signing pipeline

Every persisted row carries a cryptographic scrub envelope:
`(original_content_hash, scrub_signature, scrub_key_id, scrub_timestamp)`.
**Always populated, every component, every trace level.** There is no
"skip signing" path.

### Key custody

- The scrub key lives in `ciris-keyring` (CIRISVerify's Rust crate) — OS
  keyring backing (Secret Service / Keychain / DPAPI / Keystore), hardware
  where available (TPM, Secure Enclave, StrongBox). The Python process never
  holds the seed bytes; the seed never crosses the FFI boundary.
- Persist signs every row internally as part of step 3.5 (FSD §3.3); lens
  holds no signing key of its own.
- `Engine(signing_key_id=...)` is required. It generates the key on first run
  through `get_platform_signer(alias)` and returns the existing key after
  that.
- For a node that already has a provisioned identity, pass
  `identity_dir` + `keystore_alias` to open it from its keystore: a missing
  identity is an error, never a new identity (`create_identity_if_missing=True`
  is for provisioning tools only).
- `engine.public_key_b64()` returns the base64 Ed25519 public key to publish
  to the registry.

### One key, three roles (PoB §3.2)

The signing key is **also** the deployment's transport address and its
registry-published key:

1. Cryptographic provenance (signs the scrub envelope)
2. Federation transport address
3. Registry identity (the public key consumers look up)

Compromising the key compromises all three roles at once — a strong argument
for hardware-backed keyring entries over a software fallback in production.

### Per-batch latency

Signing is per component per batch: one sign per component. For the agent's
default `batch_size = 10` events × ~14 components that is ~140 sign calls per
batch — single-digit milliseconds at hardware speed.

### What downstream peers verify

A peer fetching rows from the lens (or any auditor with read access) checks:

```
verify(
    scrub_signature,
    canonical(payload),                  # JSONB column post-scrub
    registry.public_key_for(scrub_key_id)
)
```

Two signatures, two claims: the agent's wire-format §8 signature proves
authorship of the original; the lens's scrub envelope proves handling. PoB
§3.1 — "the lens role is a function any peer can run on data the peer already
has" — is cryptographically attestable, not socially trusted.

Rows written before the scrub envelope existed carry NULLs in the four
envelope columns. Queries that need the provenance guarantee filter on
`WHERE scrub_signature IS NOT NULL`.

---

## 11.5. Keyring storage (READ THIS if no TPM)

Without hardware key storage (TPM / Secure Enclave / StrongBox / DPAPI), the
software signer keeps its seed on the filesystem. If that path is inside the
container's writable layer, *every restart bootstraps a new keypair* and the
one-key-three-roles invariant (PoB §3.2) breaks silently: the registry
pubkey, the scrub-envelope signer and the transport address all churn
together.

### The problem

`ciris-keyring`'s `Ed25519SoftwareSigner` resolves its seed path in this
order:

1. `$CIRIS_DATA_DIR/{alias}.key` — explicit env var
2. Platform default — Linux: `~/.local/share/ciris-verify/{alias}.key`,
   macOS: `~/Library/Application Support/ai.ciris.verify/{alias}.key`,
   Windows: `%LOCALAPPDATA%\ciris-verify\{alias}.key`
3. `./<alias>.key` (current directory) — last-resort fallback

Default container layouts put `~/.local/share/...` inside the writable image
layer. `docker rm` + `docker run` wipes it.

### The fix (one env + one mount)

```yaml
# docker-compose.yml (or k8s manifest equivalent)
services:
  api:
    image: ghcr.io/cirisai/cirislens-api:latest
    environment:
      - CIRIS_DATA_DIR=/var/lib/cirislens/keyring
    volumes:
      - cirislens-keyring:/var/lib/cirislens/keyring

volumes:
  cirislens-keyring:
    driver: local
```

The first deploy generates the seed (or reads an existing one) into the
persistent volume; every restart after reads the same seed → same pubkey →
stable identity. `local` driver volumes inherit the container user's
permissions.

### What persist checks at construction

At `Engine` construction persist asks the signer for its **authoritative**
storage location (`HardwareSigner::storage_descriptor()` in ciris-keyring —
every signer reports where it actually stored the seed; persist does no path
prediction) and dispatches on it:

1. Logs the signer variant (`hardware_backed=true|false`,
   `variant=hardware|software`).
2. **`SoftwareFile { path }`**: checks `path` against an ephemeral-path
   heuristic (`/home/`, `/root/`, `/tmp/`, `/var/cache/`, `/var/tmp/`). On a
   match it emits a loud `tracing::warn!`:

   ```
   WARN ciris-persist: SoftwareSigner seed path looks ephemeral.
        path=/home/cirislens/.local/share/ciris-verify/lens-scrub-v1.key
        Container writable layers / /tmp / /home are wiped on
        restart, which churns the deployment identity (breaks
        one-key-three-roles per PoB §3.2). Mount a persistent
        volume and set CIRIS_DATA_DIR=<volume-mount-point>.
   ```

3. **`SoftwareOsKeyring { scope: User }`** (e.g. Linux secret-service in a
   user session): warns separately — user-scope entries disappear at logout
   and are not suitable for longitudinal-score primitives.
4. **`InMemory`**: warns hard — the key dies with the process. Dev/test only.
5. **`Hardware`**: info-level only. HSM-backed keys are stable by
   construction.
6. Exposes, for `/health` and readiness probes:
   - `Engine.keyring_path() -> Optional[str]` — the authoritative filesystem
     path (or `None` for HSM-only / OS-keyring / RAM-only).
   - `Engine.keyring_storage_kind() -> str` — a stable token
     (`hardware_hsm_only`, `hardware_wrapped_blob`, `software_file`,
     `software_os_keyring_user`, `software_os_keyring_system`,
     `software_os_keyring_unknown`, `in_memory`).

THREAT_MODEL.md AV-27 is the background.

### Suppressing the warn

Once you have audited that the path is on persistent storage (or a
non-default mount point trips the heuristic), set:

```
CIRIS_PERSIST_KEYRING_PATH_OK=1
```

The warn line drops; the info-level path log stays.

### Cohabitation: persist bootstraps the keyring

When several CIRIS primitives share a host (lens + bridge in one container,
agent + lens on one VM), persist owns the runtime keyring bootstrap. The full
doctrine is in [`docs/COHABITATION.md`](COHABITATION.md); for lens:

1. **Multi-worker is safe.** `uvicorn --workers N` workers serialize cold
   start through a filesystem `flock` at
   `${CIRIS_DATA_DIR}/.persist-bootstrap.lock`. The first worker
   bootstraps; the others see the existing key. POSIX `flock` releases on FD
   close (including panic), so a worker crash does not strand the lock.
2. **Combined deployments use a shared volume + shared alias.** See
   `docs/COHABITATION.md` for docker-compose / k8s examples.
3. **Same alias = same identity** per PoB §3.2. Lens and a co-hosted bridge
   resolve the same `signing_key_id` to share one identity.

A single-worker deployment is unaffected — the flock is a no-op without
contention.

---

## 12. Scope

- **Lens-derived tables** (`cirislens_derived`) are lens-authored; persist
  provisions the schema but does not own their contents.
- **No public write contract.** Writes go through `Engine` methods
  (`receive_and_persist`, the federation `put_*` / `register_*` doors);
  direct SQL writes against `cirislens` are not supported.
- The `c-abi` and `peer-replicate` Cargo features are declared with no
  implementation behind them. Federation replication runs through persist's
  replication doors (`WIRE_VOCABULARY_KINDS.md` Part 2), not a lens-side
  path.

---

## 13. Contact / source-of-truth

- Crate repo: https://github.com/CIRISAI/CIRISPersist
- FSD: [`FSD/CIRIS_PERSIST.md`](../FSD/CIRIS_PERSIST.md)
- Mission alignment: [`MISSION.md`](../MISSION.md)
- Wire format: [`context/TRACE_WIRE_FORMAT.md`](../context/TRACE_WIRE_FORMAT.md)
- Latest release: https://github.com/CIRISAI/CIRISPersist/releases/latest

If this guide drifts from what the crate does, the *crate* is the source of
truth — open an issue and we will reconcile.
