# Lens Integration Guide — `ciris-persist` v0.1.3

> **BREAKING CHANGE from v0.1.2:** `Engine.__init__` now requires a
> `signing_key_id` parameter. The v0.1.2 "no-key" path is gone — every
> persisted row carries a cryptographic scrub envelope (FSD §3.3 step
> 3.5; THREAT_MODEL.md AV-24). See §11 below for the migration shape.

**Audience:** the CIRISLens team. You're swapping the 92-column
`accord_traces` `INSERT` path in `api/accord_api.py` for
`ciris_persist.Engine.receive_and_persist(bytes)` per
[FSD §3.5](../FSD/CIRIS_PERSIST.md).

**Time to integrate (estimated):** half a day, including pulling the
wheel, applying migrations, swapping one FastAPI handler, dropping
two files, and registering one public key per agent.

---

## TL;DR

```python
# api/accord_api.py (after, v0.1.3)
from ciris_persist import Engine
from cirislens_core.scrub import scrub_envelope_dict  # your existing scrubber

ENGINE = Engine(
    dsn=os.environ["CIRISLENS_DB_URL"],
    signing_key_id="lens-scrub-v1",   # REQUIRED in v0.1.3
    scrubber=lambda envelope: (scrub_envelope_dict(envelope), 0),
)

# One-time, at deploy: publish the lens's public key. Same key that
# signs every row's scrub envelope; same key that becomes the lens's
# Reticulum destination (when Phase 2.3 lands); same key the registry
# stores. PoB §3.2 — addressing IS identity.
publish_to_registry("lens-scrub-v1", ENGINE.public_key_b64())

# One-time, on agent registration:
ENGINE.register_public_key(
    signature_key_id="agent-8a0b70302aae",   # → key_id column
    public_key_b64=agent.public_key_b64,     # → public_key_base64 column
    algorithm="Ed25519",                      # default; explicit is documentation
    description="Datum production agent",     # optional, for admin tooling
    added_by="lens-bootstrap",                # optional, for audit
    # expires_at="2027-04-16T00:00:00Z",     # optional; matches Accord renewal
)

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

That replaces the current write path. **Drop**:

- `CIRISLens/api/scrubber_compare.py`
- the delta-log sink (per FSD §3.5 — "no more delta log")

**Keep**: pre-cutover history in `accord_traces`. Don't truncate or
drop. Read-side queries that need uniform history can union with the
new tables (FSD §3.5: legacy rows become single-event
`attempt_index=0, step_point=action_complete` summary rows in the
union).

---

## 1. Install

### Option A — pre-built wheel (recommended)

The maturin abi3-py311 wheel is published as a CI artifact on every
green build. Pull from the latest `v0.1.x` GitHub release:

```bash
pip install ciris_persist-0.1.1-cp311-abi3-manylinux_2_28_x86_64.whl
```

`abi3-py311` means one wheel works for Python 3.11, 3.12, 3.13, and
forward — you don't ship per-Python-minor-version wheels.

### Option B — build from source

If you need to track `main` between releases, or if your runtime
isn't `linux-x86_64`/`manylinux_2_28`:

```bash
pip install maturin
git clone https://github.com/CIRISAI/CIRISPersist
cd CIRISPersist
maturin build --release --strip --features pyo3
pip install target/wheels/ciris_persist-*.whl
```

Build deps: Rust 1.75+ (1.95 is what CI uses), a C toolchain, and
nothing else. openssl is built from source via the `vendored`
feature, so no system `libssl-dev` is required.

---

## 2. Migrations

Apply once per database. The migrations are embedded in the wheel
and run automatically when you construct an `Engine`:

```python
ENGINE = Engine(dsn="...")  # ← runs V001 + V002 idempotently
```

This creates / extends the `cirislens` schema:

- `cirislens.trace_events` — one row per `@streaming_step` broadcast
- `cirislens.trace_llm_calls` — one row per LLM provider invocation
- `cirislens.accord_public_keys` — verification key directory

If the `timescaledb` extension is present, `trace_events` and
`trace_llm_calls` become hypertables automatically. Pure-Postgres
deployments work fine; the hypertable creation is gated on the
extension's presence (FSD §7 #7).

### Operational tuning (apply post-migration)

`V001` does **not** install compression/retention policies — they're
operational tuning, and TimescaleDB 2.18+ split storage into
rowstore vs. columnstore in a way that varies across the supported
range. Apply them yourself per your retention policy:

```sql
-- TimescaleDB ≥ 2.18 (columnstore-aware):
ALTER TABLE cirislens.trace_events
  SET (timescaledb.enable_columnstore = true);
SELECT add_compression_policy('cirislens.trace_events',
    INTERVAL '7 days', if_not_exists => TRUE);
SELECT add_retention_policy('cirislens.trace_events',
    INTERVAL '30 days', if_not_exists => TRUE);

-- Same pair for trace_llm_calls (3 days compression, 14 days retention).
```

Keep this in your existing `cirislens-deploy/` repo as a
post-migration step.

### Multi-worker boot contract (v0.1.5+)

`Engine(...)` construction is **safe to call concurrently** from
multiple worker processes (uvicorn `--workers N`, gunicorn,
Kubernetes replica sets) against the same DSN. The first worker
acquires a session-scoped Postgres advisory lock
(`pg_advisory_lock(0x6369_7269_7370_7372)` — bytes spell
`"cirispsr"` so it's greppable in `pg_locks`); subsequent workers
block on the lock until the first worker finishes its migration
phase, then wake up, see "no migrations to apply", and proceed.

The lock is held *only* during the migration phase — typically
~50–200ms on a fresh DB, much shorter on subsequent boots when
migrations no-op. The pool prep + keyring bootstrap that follows
is per-worker and unblocked.

```
worker A:  connect → take advisory lock → V001 + V003 → release → keyring → ready
worker B:  connect → blocks here ──────────────────────^ wakes  → keyring → ready
worker C:  connect → blocks ─────────────────────────────^ wakes → keyring → ready
```

**Readiness probe timeout.** If your container probe is tight
(`<5s`) and you have many migrations to run on a cold-start
deployment, give the *first* worker enough time to complete the
migration phase before the orchestrator declares all replicas
unhealthy and restarts them. A 30s `initialDelaySeconds` is the
safe default; production lens deployments running v0.1.5+ on
already-migrated DBs see boots complete in well under a second.

**SQLSTATE diagnostics.** Migration-phase errors now carry the
underlying Postgres SQLSTATE in the error display. Format is
`store: migration: [SQLSTATE] detail`. Common codes:

- `42P07` — "relation already exists" (was the pre-v0.1.5 race
  signature; should not appear at v0.1.5+ unless schema is
  externally mutated mid-flight)
- `40P01` — deadlock detected (re-run the migration; Postgres has
  already released the locks)
- `08006` — connection terminated (transient; lens should retry
  Engine construction)
- `42501` — permission denied (the DSN user lacks DDL rights;
  check role grants)

THREAT_MODEL.md AV-26 is the full background.

---

## 3. Register agent public keys

Verification needs the agent's Ed25519 public key. Today the lens
gets that from each agent's startup `POST <endpoint>/accord/agents/register`
handshake (TRACE_WIRE_FORMAT.md §8). Store the key once on receipt:

```python
ENGINE.register_public_key(
    signature_key_id=request.signature_key_id,   # → key_id column
    public_key_b64=request.public_key_b64,        # → public_key_base64 column
    algorithm="Ed25519",                          # default; explicit is doc
    description=f"agent {request.agent_id_hash[:16]}…",  # admin-tool friendly
    expires_at=request.expires_at,                # optional ISO-8601
    added_by="lens-accord-handshake",             # optional, for audit
)
```

### v0.1.2 — schema reconciliation note

The crate now writes the **lens-canonical `accord_public_keys` shape**
verbatim:
`(key_id PK, public_key_base64, algorithm, description,
 created_at, expires_at, revoked_at, revoked_reason, added_by)`.

If your lens already applied `sql/011 + sql/022`, V001 is a no-op
on your DB (every `CREATE TABLE IF NOT EXISTS` short-circuits).
Existing rows + queries against `key_id` / `public_key_base64`
keep working unchanged. The crate's Python API reads those columns
under the friendly Python names `signature_key_id` / `public_key_b64`,
which the wire format already calls them.

`register_public_key` is idempotent — re-registering the same
`signature_key_id` is a no-op (`ON CONFLICT (key_id) DO NOTHING`).
For genuine **key rotation**, set `revoked_at` + `revoked_reason`
on the old row via the lens's existing admin tooling, then call
`register_public_key` with a new `signature_key_id`. Mission
constraint (MISSION.md §3 anti-pattern #3): no automated key
rotation under attacker control. Explicit
`rotate_public_key(rotation_proof=signed_by_old_key)` API is v0.2.x
scope (THREAT_MODEL.md AV-11).

`lookup_public_key` filters on `revoked_at IS NULL AND (expires_at
IS NULL OR expires_at > NOW())` — both gates the lens already
enforced.

The current production agent (`release/2.7.8`) ships
`signature_key_id` prefix `agent-...`; the four captured fixtures
in `tests/fixtures/wire/2.7.0/` are all under
`agent-8a0b70302aae`.

---

## 4. The FastAPI handler swap

### Before

The existing handler in `api/accord_api.py` does (paraphrased):

```python
@app.post("/api/v1/accord/events")
async def accept_events(request: Request):
    body = await request.json()
    validate_envelope(body)              # ← partial schema check
    for event in body["events"]:
        verify_signature(event)          # ← Ed25519 in cirislens-core
        scrubbed = scrub(event)          # ← cirislens-core scrubber
        write_accord_traces(scrubbed)    # ← 92-column INSERT
    return {"status": "ok"}
```

### After

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

Surface those numbers to your operations dashboard. A regression
shows up as `trace_events_inserted` dropping or
`trace_events_conflicted` climbing without `signatures_verified`
matching.

### Error → HTTP mapping

| Exception | Maps to | Cause |
|---|---|---|
| `ValueError("schema: …")` | **422** | malformed JSON, schema-version mismatch, missing required field, bad `attempt_index` |
| `ValueError("verify: …")` | **422** (or **401** for unknown key) | signature mismatch, malformed signature, unknown signing key |
| `ValueError("scrub: …")` | **422** (scrubber rejected schema-altering output) or **500** (scrubber bug) | your scrubber returned a dict that altered `trace_schema_version` / `trace_level` / `events[]` shape |
| `RuntimeError("store: …")` | **503** with `Retry-After` | Postgres unreachable, IO error |

Match TRACE_WIRE_FORMAT.md §1: agent retries on any non-200 up to
`10 × batch_size` events deep. 422 is fatal-for-this-batch (agent
should not retry); 503 is transient (agent will retry).

---

## 5. Scrubber wiring

The lens already has `cirislens-core`'s scrubber for non-`generic`
trace levels. Wire it through the `Engine` constructor:

```python
from cirislens_core.scrub import scrub_envelope_dict

def my_scrubber(envelope: dict) -> tuple[dict, int]:
    """
    Receives the full BatchEnvelope as a dict.
    Returns (scrubbed_envelope, modified_field_count).
    """
    scrubbed, count = scrub_envelope_dict(envelope)
    return scrubbed, count

ENGINE = Engine(dsn=DSN, scrubber=my_scrubber)
```

Hard rules the engine enforces on scrubber output:

- MUST NOT alter `trace_schema_version`
- MUST NOT alter `trace_level`
- MUST NOT alter the `events[]` length or per-event discriminants
- MAY mutate any content text inside `data` blobs

Violations raise `ValueError` from `receive_and_persist`. Skip the
callback at `trace_level: generic` — there's no content text to
scrub by design (TRACE_WIRE_FORMAT.md §7), and the engine bypasses
the callback there automatically.

If you don't pass a scrubber, the engine uses `NullScrubber` —
which is correct *only* at `generic` and emits a `tracing::warn!`
at higher trace levels. Production at `detailed`/`full_traces` MUST
wire a real scrubber.

---

## 6. What's stored where

| Wire field | Lands on | Notes |
|---|---|---|
| `BatchEnvelope.events[i].trace.{trace_id,thought_id,task_id,…}` | `trace_events` per-component row | one row per `components[]` entry |
| component `data` dict | `trace_events.payload` JSONB | stored **verbatim** (the agent's testimony) |
| `data.attempt_index` | `trace_events.attempt_index` (denorm) | typed `int`, dedup-key tail |
| `ACTION_RESULT.audit_*` | `trace_events.audit_sequence_number/audit_entry_hash/audit_signature` | only on the seal row (FSD §3.2); `audit_signature` is Optional in production |
| `ACTION_RESULT.{llm_calls,tokens_total,cost_cents}` | `cost_llm_calls/cost_tokens/cost_usd` (denorm) | `cost_cents → cost_usd` divided by 100 |
| `LLM_CALL` components | additional row in `trace_llm_calls` | linked to parent via `parent_event_id` |
| top-level `signature` + `signature_key_id` | every row of the trace | identical across rows of the same trace |
| top-level `agent_id_hash` | `trace_events.agent_id_hash` | for per-agent partitioning |

The dedup key is
`(trace_id, thought_id, event_type, attempt_index, ts)` —
`ON CONFLICT DO NOTHING` makes the agent's retries safe (FSD §3.4
robustness primitive #4).

---

## 7. Schema-version gate

`SUPPORTED_SCHEMA_VERSIONS = ["2.7.0"]` in v0.1.1. If a future agent
ships `"2.8.0"` (per TRACE_EVENT_LOG_PERSISTENCE.md §8), v0.1.1
will reject those batches with HTTP 422 and detail
`"unsupported trace_schema_version"`. The lens upgrade is a crate
version bump:

```python
import ciris_persist as cp
print(cp.SUPPORTED_SCHEMA_VERSIONS)  # → ["2.7.0"]
```

When v0.2.x adds `"2.8.0"` to the supported set, this constant
extends to `["2.7.0", "2.8.0"]`. Roll the lens before the agents
flip the schema version.

---

## 8. Cutover plan

Per FSD §3.5:

1. Apply migrations (automatic on first `Engine()`).
2. Deploy lens with `ciris_persist` linked. Single-replica deploy
   — the per-batch transaction discipline assumes one writer.
3. `accord_traces` stays readable for pre-cutover history; **no
   writes** to it from cutover forward. Don't truncate.
4. Drop `scrubber_compare.py` + delta-log sink.
5. Watch `summary.signatures_verified` vs
   `summary.trace_events_inserted` for the first hour. They should
   move in lockstep (one signature per CompleteTrace; one trace
   produces N component rows).

**No dual-write window** — per the FSD's "we need this richer data
more than we need 100% data promises" stance. Pre-cutover history
lives in `accord_traces` forever; post-cutover lives in
`trace_events` forever. Union queries treat legacy as single-event
summary rows.

**Rollback**: redeploy the previous lens image. `trace_events` and
`trace_llm_calls` remain (additive migration); the old write path
resumes against `accord_traces`.

---

## 9. Operational notes

- **Single writer**: the per-batch transaction discipline (FSD §3.3
  step 5) assumes one process is the persister. If you horizontally
  scale the lens API behind a load balancer, that's fine — each
  worker is independently transactional, and ON CONFLICT handles
  the dedup. But don't fan out by trace_id; let the LB hash by
  request and let the dedup index do the work.
- **TimescaleDB optional**: hypertables make compression+retention
  cleaner. If you don't have the extension, the tables are plain
  Postgres; compression is your concern.
- **Connection pool**: deadpool-postgres, default sizing. If your
  lens is multi-worker (gunicorn/uvicorn workers), each worker
  builds its own pool inside its own `Engine` instance. That's
  intentional — the pool is per-process, not shared via Python.
- **Bytes in, dict out**: FastAPI `await request.body()` gives you
  `bytes`. Don't `json.loads` first — the engine parses internally
  and signature-verifies *exactly* the bytes the agent shipped.
  Pre-parsing breaks byte-exact canonicalization for non-ASCII
  payloads.
- **No queue**: v0.1.x's PyO3 path is synchronous. The lens
  FastAPI worker's threadpool is the queue. If you need bounded
  in-process backpressure with a journal-on-failure path, switch
  to the [standalone axum server shape](../README.md#quickstart--rust-standalone-server-phase-11-deployment-shape)
  (Phase 1.1) — that's the same pipeline behind a Rust HTTP edge,
  with `redb`-backed journal and 429+`Retry-After` on saturation.

---

## 10. Testing

The fixture-based integration tests in
[`tests/wire_format_fixtures.rs`](../tests/wire_format_fixtures.rs)
exercise real signed traces from CIRISAgent `release/2.7.8` —
schema parsing, decompose into rows, dedup-key uniqueness,
canonicalization determinism. They run in CI on every PR.

Lens-side smoke test recipe:

```python
# tests/integration/test_engine.py
import ciris_persist as cp
import os, json

def test_round_trip(tmp_postgres_dsn, agent_keypair):
    engine = cp.Engine(dsn=tmp_postgres_dsn)
    engine.register_public_key(
        signature_key_id="agent-test",
        public_key_b64=agent_keypair.public_b64,
    )
    body = sign_with(agent_keypair, sample_complete_trace())
    summary = engine.receive_and_persist(body)
    assert summary["signatures_verified"] == 1
    assert summary["trace_events_inserted"] > 0
```

Use the same Postgres image CI uses (`timescale/timescaledb:latest-pg16`)
to catch TimescaleDB version drift early.

---

## 11. v0.1.3 — scrub-signing pipeline (BREAKING from v0.1.2)

Every persisted row now carries a cryptographic scrub envelope:
`(original_content_hash, scrub_signature, scrub_key_id, scrub_timestamp)`.
**Always populated, every component, every trace level.** No
"skip signing" code path; the v0.1.2 no-key API is gone.

### What the lens drops

- `pii_scrubber._signing_key` — the scrub key now lives in
  `ciris-keyring` (CIRISVerify's Rust crate). The Python process
  never holds the seed bytes; the seed never crosses the FFI boundary.
- `accord_api.py`'s `sign_content(...)` call — persist signs every
  row internally as part of step 3.5 (FSD §3.3).
- `lens_signing_keys` table — superseded by `ciris-keyring`'s OS
  keyring backing (Secret Service / Keychain / DPAPI / Keystore;
  hardware-backed where available — TPM, Secure Enclave, StrongBox).

### What the lens gains

- `Engine(signing_key_id="lens-scrub-v1", ...)` REQUIRED at ctor.
  Idempotent — generates the key on first run via ciris-keyring's
  `get_platform_signer(alias)`, returns existing on subsequent runs.
- `engine.public_key_b64()` — base64-encoded Ed25519 public key for
  publishing to the registry. Same key that signs every row.

### One key, three roles (PoB §3.2)

The signing key is **also** the deployment's Reticulum destination
(`SHA256(public_key)[..16]`, when Phase 2.3 lands) and the
registry-published public key. One key, three roles:

1. Cryptographic provenance (signs scrub envelope)
2. Federation transport address (Reticulum destination, Phase 2.3)
3. Registry identity (the public key consumers look up)

Compromise the key, you compromise all three roles simultaneously.
That triples the cost-asymmetry — strong argument for
hardware-backed keyring entries (TPM, Secure Enclave) over
software-fallback in production.

### Per-batch latency tax

Signing happens per-component per-batch. Cost: one Ed25519 sign per
component (~30 µs hardware-backed, ~100 µs software-backed). For
the agent's default `batch_size = 10` events × ~14 components =
~140 sign calls per batch; at hardware speed, single-digit
milliseconds added per batch. Acceptable.

### What downstream peers verify

A peer fetching rows from the lens (Phase 2.3 federation; or any
auditor with DB read access today) verifies:

```
ed25519_verify(
    scrub_signature,
    canonical(payload),                  # JSONB column post-scrub
    registry.public_key_for(scrub_key_id)
)
```

Bilateral cryptography: agent's wire-format §8 signature proves
authorship of the original; the lens's v0.1.3 scrub envelope proves
handling. PoB §3.1 — "the lens role is a function any peer can run
on data the peer already has" — becomes cryptographically
attestable, not socially trusted.

### Migration from v0.1.2 → v0.1.3

If your lens is already running v0.1.2 in production:

1. Apply the V003 migration (additive ALTER TABLE — no data loss):
   ```sql
   ALTER TABLE cirislens.trace_events
       ADD COLUMN IF NOT EXISTS original_content_hash TEXT,
       ADD COLUMN IF NOT EXISTS scrub_signature       TEXT,
       ADD COLUMN IF NOT EXISTS scrub_key_id          TEXT,
       ADD COLUMN IF NOT EXISTS scrub_timestamp       TIMESTAMPTZ;
   ```
   Migrations run automatically on `Engine()` construction; or apply
   directly if your admin path needs the bump first.
2. Update `Engine(...)` ctor to add `signing_key_id="lens-scrub-v1"`.
3. Add the deploy-time `publish_to_registry` call.
4. Pre-v0.1.3 rows have NULLs in the four envelope columns. That's
   expected — they pre-date the contract. Queries needing the
   provenance guarantee filter on `WHERE scrub_signature IS NOT NULL`.

The recommended path for lenses that haven't yet started v0.1.2
integration: **skip v0.1.2, jump straight to v0.1.3**. Avoids the
double-handler-rewrite that would otherwise happen.

---

## 11.5. v0.1.7 — Keyring storage (READ THIS if no TPM)

**Production lens cutover hit this exact failure**, so it gets a
loud section here. tl;dr: if your deployment doesn't have hardware
key-attestation (TPM / Secure Enclave / StrongBox / DPAPI), the
SoftwareSigner falls back to a filesystem path. If that path is
inside the container's writable layer, *every restart bootstraps
a new keypair* and the one-key-three-roles invariant (PoB §3.2)
breaks silently. Your registry pubkey, your scrub envelope signer,
and your future Reticulum address all churn together.

### The problem

`ciris-keyring`'s `Ed25519SoftwareSigner` resolves its seed-storage
path in this order:

1. `$CIRIS_DATA_DIR/{alias}.key` — explicit env var
2. Platform default — Linux: `~/.local/share/ciris-verify/{alias}.key`,
   macOS: `~/Library/Application Support/ai.ciris.verify/{alias}.key`,
   Windows: `%LOCALAPPDATA%\ciris-verify\{alias}.key`
3. `./<alias>.key` (current directory) — last-resort fallback

Default Docker container layouts put `~/.local/share/...` inside
the writable image layer. `docker rm` + `docker run` wipes it.
Result: silent identity churn.

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

After `docker compose up -d --force-recreate`, the next deploy:

1. Generates a fresh seed once (or reads any existing seed) into
   the persistent volume
2. Every subsequent restart reads the same seed → same pubkey →
   stable lens identity

Permission: container user `cirislens` (uid 1000). `local`
driver volumes inherit container user perms by default; should
just work.

### How v0.1.9 catches this for you

At Engine construction, persist queries the **authoritative**
storage descriptor via ciris-keyring v1.8.0's
`HardwareSigner::storage_descriptor()` (no prediction shim) and
dispatches on the typed enum:

1. Logs the signer variant (`hardware_backed=true|false`,
   `variant=hardware|software`).
2. **`SoftwareFile { path }`**: checks `path` against an
   ephemeral-path heuristic (`/home/`, `/root/`, `/tmp/`,
   `/var/cache/`, `/var/tmp/`). If matched, emits a loud
   `tracing::warn!`:

   ```
   WARN ciris-persist: SoftwareSigner seed path looks ephemeral.
        path=/home/cirislens/.local/share/ciris-verify/lens-scrub-v1.key
        Container writable layers / /tmp / /home are wiped on
        restart, which churns the deployment identity (breaks
        one-key-three-roles per PoB §3.2). Mount a persistent
        volume and set CIRIS_DATA_DIR=<volume-mount-point>.
   ```

3. **`SoftwareOsKeyring { scope: User }`** (Linux secret-service in
   user session, etc.): warns separately — user-scope entries
   disappear at logout, NOT suitable for longitudinal-score
   primitives.
4. **`InMemory`**: warns hard — RAM-only signer means the key dies
   with the process. Only valid for dev/test.
5. **`Hardware`**: info-level only. HSM-backed keys are stable by
   construction.
6. Exposes:
   - `Engine.keyring_path() -> Optional[str]` — authoritative
     filesystem path (or `None` for HSM-only / OS-keyring / RAM-only).
   - `Engine.keyring_storage_kind() -> str` — stable token
     (`hardware_hsm_only`, `hardware_wrapped_blob`,
     `software_file`, `software_os_keyring_user`,
     `software_os_keyring_system`, `software_os_keyring_unknown`,
     `in_memory`). Wire either or both into your `/health` so
     probes can verify the deployment posture without grepping
     logs.

### Suppressing the warn

Once you've audited that the predicted path is on persistent
storage (or you're using a non-default mount point that the
heuristic flags as a false positive), set:

```
CIRIS_PERSIST_KEYRING_PATH_OK=1
```

The warn line drops; the info-level path log stays so ops still
have visibility.

### Authoritative storage path (v0.1.9+)

The path persist surfaces is **authoritative**, not predicted. It
comes directly from ciris-keyring v1.8.0's
`HardwareSigner::storage_descriptor()` trait method, which every
signer impl implements with full knowledge of where it actually
stored the seed. No vendored path-resolution logic to drift; no
caveat.

Persist v0.1.7 + v0.1.8 had a predicted-path shim that replicated
upstream's private `default_key_dir()`; that's gone in v0.1.9.

---

## 12. What's NOT in v0.1.x

- **Phase 2** (agent's `audit_log` + `service_correlations`): the
  Backend trait shape is sealed for it, but the methods return
  `Error::NotImplemented` until the agent flips. No lens action.
- **Phase 3** (agent runtime state, memory graph, governance):
  same — trait sealed, defaults to NotImplemented.
- **Reticulum peer-replicate**: gated behind the `peer-replicate`
  feature, not built today. Phase 2.3.
- **iOS / Android FFI**: works for the agent's mobile client when
  Phase 2 lands. Lens doesn't touch.

If you need any of those before v0.2.x cuts, tell the
ciris-persist maintainer (Eric) so the trigger condition gets
revisited.

---

## 13. Contact / source-of-truth

- Crate repo: https://github.com/CIRISAI/CIRISPersist
- FSD: [`FSD/CIRIS_PERSIST.md`](../FSD/CIRIS_PERSIST.md)
- Mission alignment: [`MISSION.md`](../MISSION.md)
- Wire format: [`context/TRACE_WIRE_FORMAT.md`](../context/TRACE_WIRE_FORMAT.md)
- Latest release: https://github.com/CIRISAI/CIRISPersist/releases/latest

If something in this guide drifts from what the crate actually
does, the *crate* is the source of truth. Open an issue against the
repo and we'll reconcile.
