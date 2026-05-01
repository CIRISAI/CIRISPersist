# Context

Vendored upstream specifications and reference material. Frozen copies — the
authoritative versions live in their respective repos. Update by re-copying
when an upstream changes meaningfully.

| File | Source | Purpose |
|---|---|---|
| `PROOF_OF_BENEFIT_FEDERATION.md` | `~/CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md` | The architectural collapse §3.1 specifies — why this crate spans agent + lens, not just lens. |
| `TRACE_WIRE_FORMAT.md` | `~/CIRISAgent/FSD/TRACE_WIRE_FORMAT.md` | Wire-shape ground truth for Phase 1 ingest. `trace_schema_version: "2.7.0"`, `attempt_index`, audit anchor on ACTION_RESULT (§5.9). |
| `TRACE_EVENT_LOG_PERSISTENCE.md` | `~/CIRISAgent/FSD/TRACE_EVENT_LOG_PERSISTENCE.md` | Lens-side persistence design Phase 1 implements. |
| `lens_027_trace_events.sql` | `~/CIRISLens/sql/027_trace_events.sql` | The migration that becomes `migrations/postgres/lens/001_trace_events.sql` once Phase 1 implementation lands. |
| `agent_persistence_README.md` | `~/CIRISAgent/ciris_engine/logic/persistence/README.md` | What Phase 3 is subsuming. Multi-occurrence, TSDB integration, secrets management, and the dialect-adapter shape this crate replaces. |
| `accord_1.2b.txt` | `~/CIRISAgent/ciris_engine/data/accord_1.2b.txt` | CIRIS Accord canonical text. Book IX (Federated Ratchet, Coherent Intersection Hypothesis) is the constitutional grounding for what this crate persists and verifies. |

## Note on staleness

When upstream changes:
- TRACE_WIRE_FORMAT.md or TRACE_EVENT_LOG_PERSISTENCE.md → re-copy and bump
  `trace_schema_version` handling in `src/schema/version.rs`.
- 027_trace_events.sql (renamed at upstream) → re-copy; the corresponding
  `migrations/postgres/lens/001_trace_events.sql` stays the canonical version
  this crate runs.
- accord_1.2b.txt → renewal is a 2027-04-16 event, scheduled.
- agent_persistence_README.md → re-copy when Phase 3 migration plan changes.
- PROOF_OF_BENEFIT_FEDERATION.md → re-copy on every revision; this is the
  living architectural spec.
