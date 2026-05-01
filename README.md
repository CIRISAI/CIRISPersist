# CIRISPersist

Unified Rust persistence for the CIRIS Trinity — signed events, time-series, runtime state.

**Status:** Phase 1 — Proposed (FSD only, no implementation yet). See [`FSD/CIRIS_PERSIST.md`](FSD/CIRIS_PERSIST.md).

This crate is the operational form of the architectural collapse the
[Proof-of-Benefit Federation FSD](context/PROOF_OF_BENEFIT_FEDERATION.md) §3.1
specifies: lens-side ingest+verify+scrub+store and agent-side
audit-chain+TSDB+runtime persistence are *the same job at different scales*.
We carve the work into three phases — each independently shippable, each
gated on a measured operational reason — with a single crate API designed
from Phase 1 to support all three without rewrites.

## Phases

| Phase | Surface | Trigger |
|---|---|---|
| **1** | Lens trace ingest: `trace_events`, `trace_llm_calls`, `accord_public_keys`. Ed25519 verify, PII scrub, batch persist via TimescaleDB hypertables. | Now. |
| **2** | Agent signed-events + TSDB: `audit_log`, `audit_roots`, `audit_signing_keys`, `service_correlations`. PyO3 from inside the agent process. | When peer-to-peer trace replication is on the roadmap. |
| **3** | Agent runtime state, memory graph, governance: `tasks`, `thoughts`, `graph_nodes`, `graph_edges`, `tickets`, `dsar_*`, `deferral_*`, `wa_cert`, `feedback_mappings`, `consolidation_locks`, `queue_status`. | When ≥30 days of Phase 2 stability + a named operational reason. |

Out of scope: `CIRISRegistry`, `CIRISPortal` — external services with their own DBs and replication strategies.

## Layout

```
FSD/                           # CIRISPersist FSD (this crate's spec)
context/                       # vendored upstream specs — PoB, wire format,
                               # accord, agent persistence README, lens migration
src/                           # crate sources (Phase 1 not yet implemented)
migrations/                    # numbered SQL — phase- and backend-scoped (created
                               # when Phase 1 implementation lands)
Cargo.toml
```

## Feature flags

| Flag | Phase | Adds |
|---|---|---|
| `postgres` | 1 | tokio-postgres + deadpool-postgres backend |
| `server` | 1 | axum HTTP listener for `/api/v1/accord/events` |
| `pyo3` | 1 | Python bindings (FastAPI / agent in-process) |
| `sqlite` | 2 | rusqlite backend (agent + iOS) |
| `c-abi` | 2 | C ABI for iOS client |
| `peer-replicate` | 2 | Reticulum gossip hook |

## Reading order

If you have **5 minutes:** [`FSD/CIRIS_PERSIST.md`](FSD/CIRIS_PERSIST.md) §1, §2, §3.6.

If you have **20 minutes:** the FSD top-to-bottom plus
[`context/PROOF_OF_BENEFIT_FEDERATION.md`](context/PROOF_OF_BENEFIT_FEDERATION.md) §3.1.

If you are **implementing Phase 1:** the FSD §3 in full plus
[`context/TRACE_WIRE_FORMAT.md`](context/TRACE_WIRE_FORMAT.md) and
[`context/TRACE_EVENT_LOG_PERSISTENCE.md`](context/TRACE_EVENT_LOG_PERSISTENCE.md).

If you are **planning Phase 3:** the FSD §5 plus
[`context/agent_persistence_README.md`](context/agent_persistence_README.md).

## License

AGPL-3.0-or-later. CIRIS Accord canonical text at [`context/accord_1.2b.txt`](context/accord_1.2b.txt) (v1.2-Beta, dated 2025-04-16, expires 2027-04-16 absent renewal).
