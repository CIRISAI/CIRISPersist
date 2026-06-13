-- V074 — SharedInstanceLease: cross-process leader election for a named
--        Reticulum (or other) singleton (CIRISPersist#210, CIRISEdge#100).
--        SQLite dialect. Postgres parity: postgres/lens/V074.
--
-- Multi-worker FastAPI/uvicorn deployments each call init_edge_runtime
-- and race to bind the same Reticulum UDP socket → 5/7 EADDRINUSE. The
-- clean fix is RNS shared-instance mode: one process owns the sockets,
-- siblings attach. This table is the leader-election substrate — persist
-- already owns cross-process atomic state (cf. the revocation-quorum
-- pattern), so liveness (heartbeat age) is a DB query, not a brittle
-- flock with no crash detection.
--
-- Atomicity lives in try_acquire_shared_instance, not the DDL: a single
-- UPSERT (INSERT … ON CONFLICT DO UPDATE … WHERE heartbeat-is-stale) so
-- two siblings racing can never both win. TIMESTAMPTZ → TEXT (RFC-3339,
-- UTC — lexical order == chronological, so the staleness comparison is a
-- plain string `<`). Refinery wraps this in its own transaction.

CREATE TABLE shared_instance_leases (
    instance_name        TEXT PRIMARY KEY,
    owner_pid            INTEGER NOT NULL,
    owner_hostname       TEXT NOT NULL,
    acquired_at          TEXT NOT NULL,   -- RFC-3339 UTC
    last_heartbeat_at    TEXT NOT NULL,   -- RFC-3339 UTC
    lease_version        INTEGER NOT NULL DEFAULT 1
);

-- Operators / liveness sweeps query by heartbeat age.
CREATE INDEX shared_instance_leases_heartbeat_idx
    ON shared_instance_leases (last_heartbeat_at);
