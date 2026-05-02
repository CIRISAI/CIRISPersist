# CIRISPersist

Unified Rust persistence for the CIRIS federation — signed events, time-series, runtime state.

**Status: 0.1.0 — Phase 1 lens-ready.** The Phase 1 ingest pipeline is end-to-end testable
and lands the lens cutover from `accord_traces` (per-thought row collapse) to
`trace_events` + `trace_llm_calls` (per-broadcast event log) per
[FSD §3.5](FSD/CIRIS_PERSIST.md). Phase 2 (agent's `audit_log` + `service_correlations`)
and Phase 3 (runtime state + memory graph + governance) reuse the same Backend trait
without restructuring.

This crate is the operational form of the architectural collapse the
[Proof-of-Benefit Federation FSD](context/PROOF_OF_BENEFIT_FEDERATION.md) §3.1
specifies: lens-side ingest+verify+scrub+store and agent-side
audit-chain+TSDB+runtime persistence are *the same job at different scales*.
We carve the work into three phases — each independently shippable, each
gated on a measured operational reason — with a single crate API designed
from Phase 1 to support all three without rewrites.

## Reading order

If you have **5 minutes:** [`MISSION.md`](MISSION.md) and
[`FSD/CIRIS_PERSIST.md`](FSD/CIRIS_PERSIST.md) §1, §2, §3.6.

If you have **20 minutes:** the FSD top-to-bottom plus
[`FSD/PLATFORM_ARCHITECTURE.md`](FSD/PLATFORM_ARCHITECTURE.md).

If you are **integrating with the lens (Phase 1):** the FSD §3 in full plus
[`context/TRACE_WIRE_FORMAT.md`](context/TRACE_WIRE_FORMAT.md) and the
[`tests/wire_format_fixtures.rs`](tests/wire_format_fixtures.rs)
integration suite (real signed traces from agent `release/2.7.8`).

If you are **planning Phase 2/3:** the FSD §4–§5 plus
[`context/agent_persistence_README.md`](context/agent_persistence_README.md).

## Phases

| Phase | Surface | Trigger |
|---|---|---|
| **1** *(0.1.0 — shipping)* | Lens trace ingest: `trace_events`, `trace_llm_calls`, `accord_public_keys`. Ed25519 verify, PII scrub, batch persist via TimescaleDB hypertables. | Now. |
| **2** | Agent signed-events + TSDB: `audit_log`, `audit_roots`, `audit_signing_keys`, `service_correlations`. PyO3 from inside the agent process. | When peer-to-peer trace replication is on the roadmap. |
| **3** | Agent runtime state, memory graph, governance: `tasks`, `thoughts`, `graph_nodes`, `graph_edges`, `tickets`, `dsar_*`, `deferral_*`, `wa_cert`, `feedback_mappings`, `consolidation_locks`, `queue_status`. | When ≥30 days of Phase 2 stability + a named operational reason. |

Out of scope: `CIRISRegistry`, `CIRISPortal` — external services with their own DBs and replication strategies.

## Layout

```
.github/workflows/ci.yml      CI matrix (linux x86_64 + arm64, darwin-arm64,
                              ios device + sim, lint, license-audit, pyo3 wheel)
FSD/                          FSD + crate-recommendations + platform-architecture
MISSION.md                    Mission Driven Development alignment for this crate
context/                      Vendored upstream specs (PoB, wire format, accord,
                              agent persistence README, lens migration)
migrations/postgres/lens/     Phase 1 SQL — V001__trace_events.sql,
                              V002__audit_anchor_cols.sql
src/
├── schema/                   Wire-format types (no untyped Value in hot paths)
├── verify/                   Canonical bytes (Python-compat) + Ed25519 strict-verify
├── scrub/                    Scrubber trait + NullScrubber + CallbackScrubber
├── store/                    Backend trait + decompose + Postgres + memory impls
├── ingest.rs                 Pipeline orchestrator: parse → verify → scrub →
                              decompose → backend insert
├── journal.rs                redb append-only outage journal
├── queue.rs                  Bounded mpsc + single-consumer persister + 429 backpressure
├── server/                   axum HTTP listener (POST /api/v1/accord/events, /health)
└── ffi/pyo3.rs               PyO3 Engine class for FastAPI integration
tests/
├── fixtures/wire/2.7.0/      Real signed-trace fixtures from CIRISAgent release/2.7.8
└── wire_format_fixtures.rs   Integration tests against the fixtures
python/ciris_persist/         Python package (maturin abi3-py311 build)
pyproject.toml                maturin build config
deny.toml                     cargo-deny — license-deny enforcement (AGPL family +
                              MIT/Apache/BSD permissive)
Cargo.toml
```

## Feature flags

| Flag | Phase | Adds |
|---|---|---|
| `postgres` | 1 | tokio-postgres + deadpool-postgres + refinery migrations |
| `server` | 1 | axum HTTP listener for `/api/v1/accord/events` and `/health` |
| `pyo3` | 1 | Python bindings (FastAPI / agent in-process); implies `postgres` |
| `sqlite` | 2 | rusqlite backend (agent + iOS) |
| `c-abi` | 2 | C ABI for iOS client |
| `peer-replicate` | 2 | Reticulum gossip hook |

## Quickstart — lens FastAPI integration

```python
import ciris_persist as cp

engine = cp.Engine(dsn="postgres://lens:lens@localhost:5432/cirislens")
engine.register_public_key(
    signature_key_id="agent-8a0b70302aae",
    public_key_b64="<base64-encoded 32-byte Ed25519 verifying key>",
    agent_id_hash="8a0b70302aaeb401...",
)

# In FastAPI handler:
summary = engine.receive_and_persist(request_body_bytes)
# → {"envelopes_processed": 1, "trace_events_inserted": 12, ...}
```

## Quickstart — Rust standalone server (Phase 1.1 deployment shape)

```rust
use std::sync::Arc;
use ciris_persist::{
    server, spawn_persister, Journal,
    scrub::NullScrubber,
    store::PostgresBackend,
    verify::PythonJsonDumpsCanonicalizer,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(PostgresBackend::connect(&std::env::var("CIRIS_DB_URL")?).await?);
    backend.run_migrations().await?;

    let journal = Arc::new(Journal::open("/var/lib/cirislens/journal.redb")?);
    let handle = spawn_persister(
        ciris_persist::DEFAULT_QUEUE_DEPTH,
        backend,
        Arc::new(PythonJsonDumpsCanonicalizer),
        Arc::new(NullScrubber),
        journal.clone(),
    );

    let app = server::router(server::AppState { handle, journal });
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

## Mission Driven Development

Every component, every test, every PR cites against
[`MISSION.md`](MISSION.md). The methodology is from
`~/CIRISAgent/FSD/MISSION_DRIVEN_DEVELOPMENT.md`. Three structural
legs (LOGIC, SCHEMAS, PROTOCOLS) supporting one purposeful seat
(MISSION = Accord Meta-Goal M-1).

Test coverage organized by mission category (MISSION.md §4):

| Category | Coverage |
|---|---|
| Schema parity | Wire-format round-trips, real-fixture deserialization, dedup-key derivation |
| Verify rejection | Schema version, attempt_index sign, signature mismatch, unknown key, malformed sig, wrong key |
| Canonicalization parity | 14 byte-exact fixtures vs `python json.dumps`; JCS-divergence test |
| Idempotency | Dedup tuple, repeat batches, intra-batch duplicates |
| Backpressure | Full queue → 429 + Retry-After |
| Power-cycle resilience | Journal append/replay survives reopen; halt-on-error preserves order |
| Backend parity | Memory impl conformance suite (postgres conformance gated on CI DSN) |

## License

AGPL-3.0-or-later. CIRIS Accord canonical text at
[`context/accord_1.2b.txt`](context/accord_1.2b.txt) (v1.2-Beta, dated 2025-04-16,
expires 2027-04-16 absent renewal).

License-locked mission preservation: anyone reasoning about whether a
CIRIS-derived deployment preserves M-1 alignment can see and audit every line of
the persistence path. Closed-source forks are forbidden by the license, which
makes the federation primitive's audit story *structurally enforceable*, not
merely socially expected.
