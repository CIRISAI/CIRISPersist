-- V074 — SharedInstanceLease: cross-process leader election for a named
--        Reticulum (or other) singleton (CIRISPersist#210, CIRISEdge#100).
--        Postgres dialect. SQLite parity: sqlite/lens/V074.
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
-- INSERT … ON CONFLICT (instance_name) DO UPDATE … WHERE the existing
-- heartbeat is stale, so two siblings racing can never both win (the
-- loser's DO UPDATE WHERE sees the just-written fresh heartbeat → 0 rows
-- → None). TIMESTAMPTZ; the caller passes a client-computed staleness
-- threshold so acquired_at / heartbeat / comparison share one clock.

CREATE TABLE IF NOT EXISTS cirislens.shared_instance_leases (
    instance_name        TEXT PRIMARY KEY,
    owner_pid            INTEGER NOT NULL,
    owner_hostname       TEXT NOT NULL,
    acquired_at          TIMESTAMPTZ NOT NULL,
    last_heartbeat_at    TIMESTAMPTZ NOT NULL,
    -- increments on each acquire/steal — lets heartbeat detect a takeover
    -- (our row's version moved on, so our lease was stolen).
    lease_version        BIGINT NOT NULL DEFAULT 1
);

-- Operators / liveness sweeps query by heartbeat age.
CREATE INDEX IF NOT EXISTS shared_instance_leases_heartbeat_idx
    ON cirislens.shared_instance_leases (last_heartbeat_at);
