# Lens Integration Guide — `ciris-persist` v0.1.1

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
# api/accord_api.py (after)
from ciris_persist import Engine
from cirislens_core.scrub import scrub_envelope_dict  # your existing scrubber

ENGINE = Engine(
    dsn=os.environ["CIRISLENS_DB_URL"],
    scrubber=lambda envelope: (scrub_envelope_dict(envelope), 0),
)

# One-time, on agent registration:
ENGINE.register_public_key(
    signature_key_id="agent-8a0b70302aae",
    public_key_b64=agent.public_key_b64,
    agent_id_hash="8a0b70302aaeb401...",
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

---

## 3. Register agent public keys

Verification needs the agent's Ed25519 public key. Today the lens
gets that from each agent's startup `POST <endpoint>/accord/agents/register`
handshake (TRACE_WIRE_FORMAT.md §8). Store the key once on receipt:

```python
ENGINE.register_public_key(
    signature_key_id=request.signature_key_id,   # e.g. "agent-8a0b70302aae"
    public_key_b64=request.public_key_b64,        # 32 bytes Ed25519 in base64
    agent_id_hash=request.agent_id_hash,          # optional but recommended
)
```

`register_public_key` is idempotent (re-registering the same key id
is a no-op). Re-registering a *different* key for the same id is
treated as the agent's choice — no rotation alarm yet; that's a
follow-up for v0.2.x.

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

## 11. What's NOT in v0.1.x

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

## 12. Contact / source-of-truth

- Crate repo: https://github.com/CIRISAI/CIRISPersist
- FSD: [`FSD/CIRIS_PERSIST.md`](../FSD/CIRIS_PERSIST.md)
- Mission alignment: [`MISSION.md`](../MISSION.md)
- Wire format: [`context/TRACE_WIRE_FORMAT.md`](../context/TRACE_WIRE_FORMAT.md)
- Latest release: https://github.com/CIRISAI/CIRISPersist/releases/latest

If something in this guide drifts from what the crate actually
does, the *crate* is the source of truth. Open an issue against the
repo and we'll reconcile.
