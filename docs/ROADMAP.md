# Roadmap — CIRISPersist

**Status:** current as of v2.0.0 (2026-05-22). Positions indicate
*sequence*, not dates — each milestone ships when its work is green.

CIRISPersist's 0.x → 1.x history — SQLite/Postgres parity, the
federation directory, CIRISVerify subsumption, the ~22-substrate
absorption of the agent's storage services, the change-feed, the
hash-chained audit log, hardware-backed secrets-at-rest, and the
in-process cohabitation `Engine` — is recorded in
[`CHANGELOG.md`](../CHANGELOG.md). This document is the forward
roadmap from 2.0.

---

## 2.0 — Federation Ready  *(this release)*

The release that consolidates CIRISPersist onto the **CIRIS 3.0
federation line**. Not a new headline feature — a milestone marking
that persist's federation surface is shipped, stable, concurrency-
hardened, and fully CI-tested.

- **CIRISVerify v3.0.1 pin** — `ciris-verify-core` / `ciris-keyring` /
  `ciris-crypto` on the 3.0 line; persist tracks the federation-wide
  major.
- **The federation surface, stable** — `root_binding` (cold-start
  binding rooting against `federation_keys`, not TOFU),
  `provenance_chain` (the verify-consumable recursive-provenance
  read), `current_rust_engine()` (the co-resident `Arc<Engine>`
  bridge). Shipped across v1.12–v1.13 — the persist side of the
  CIRIS 3.0 critical path (`CIRISVerify#28`).
- **Concurrency hardening** — the master-key bootstrap race fixed
  (V043 partial unique index DB-enforcing one active master key;
  race-safe `rotate_master_key`); the audit chain confirmed
  concurrency-safe; the telemetry-rollup timestamp bug fixed.
- **#91 relay skip-verify** (opt-in `VerifyMode` + the
  `verification_source` provenance column) and **#93
  `audit_service()`** — the last consumer-facing facades.
- **Every substrate CI-tested** — `cirisaudit`, `secrets`,
  `cirisnode`, `cirisgraph`, `telemetry` added to the CI test +
  clippy matrix; no substrate's backend ships unexercised.

## 2.1 — Encryption at Rest

Persist-managed, 100% backend-agnostic **content encryption at
rest** — the locked design in
[`FSD/ENCRYPTED_AT_REST.md`](../FSD/ENCRYPTED_AT_REST.md): encrypt
every substrate's *content* (AES-256-GCM via CIRISVerify) while
keeping a plaintext, signed, queryable projection. The capability — a
federation that measures reasoning quality without reading reasoning
content — is uniquely available to CIRIS because the privacy boundary
and the queryability boundary are the same architectural line.

Six sequenced phases (FSD §9): V042-final shredding → `ReadEngine`
rewrite → ingest-path encrypt → read-path decrypt + signature
re-verify → migration of existing plaintext → docs/threat-model.
Gated on the nine boundary-map judgement calls (FSD §3.12).

## Beyond

- `IngestPipeline` skip-verify refinement — trust a caller-supplied
  `VerifyOutcome` rather than a mode flag, once the relay hot path
  has production telemetry.
- Substrate coverage tracks the CIRISAgent absorption track to
  completion.

---

This document is rewritten when a milestone ships or the next is
scoped. If it drifts from [`CHANGELOG.md`](../CHANGELOG.md) and the
open issues, it is wrong — fix the document.
