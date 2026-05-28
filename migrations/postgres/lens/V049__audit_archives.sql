-- V049 — audit_archives table (v2.7.0, CIRISPersist#107).
--
-- Engine retention primitive `Engine::archive_audit_range` writes
-- chain-anchored archive blobs here, then truncates the live
-- `cirislens.audit_log` to entries outside the archived range. The
-- chain stays unbroken because the live row immediately after the
-- archived range keeps its `prev_hash` pointing at the (now-archived)
-- last entry; the archive blob preserves the truncated rows for
-- offline chain verification.
--
-- # Schema shape
--
--   archive_id      UUID  — content-addressable; SHA-256 of canonical bytes
--   tenant_id       TEXT  — per-tenant chain (archives never cross tenants;
--                           the API enforces single-tenant per call)
--   from_ts         TIMESTAMPTZ — inclusive lower bound (entries.recorded_at >= from_ts)
--   to_ts           TIMESTAMPTZ — exclusive upper bound (entries.recorded_at <  to_ts)
--   rows_archived   BIGINT — exact count of rows captured
--   chain_anchor    BYTEA(32) — entry_hash of the LAST archived row (the value
--                               that the next live row's prev_hash points at;
--                               anchors the archive to the live chain)
--   archive_bytes   BYTEA — canonical JSON serialization of Vec<AuditEntry>
--   created_at      TIMESTAMPTZ — archive creation wall clock
--
-- # Why a dedicated table (vs. federation_blobs)
--
-- federation_blobs requires a `holds_bytes` attestation envelope with
-- a federation_keys FK on `attesting_key_id`. The retention primitive
-- runs at deployment cadence (lens-core's retention policy enforcer);
-- it doesn't carry an attestation envelope. A focused table without
-- the attestation overhead is the right shape for an internal archive
-- whose only consumer is the persist-side verifier.
--
-- # AV-51 tenant isolation
--
-- `tenant_id` is required (NOT NULL); the archive_audit_range API
-- refuses ranges spanning multiple tenants. Cross-tenant archives are
-- emitted as multiple calls — one ArchiveHandle per tenant.

BEGIN;

CREATE TABLE IF NOT EXISTS cirislens.audit_archives (
    archive_id     UUID        PRIMARY KEY,
    tenant_id      TEXT        NOT NULL,
    from_ts        TIMESTAMPTZ NOT NULL,
    to_ts          TIMESTAMPTZ NOT NULL,
    rows_archived  BIGINT      NOT NULL CHECK (rows_archived >= 0),
    chain_anchor   BYTEA       NOT NULL CHECK (octet_length(chain_anchor) = 32),
    archive_bytes  BYTEA       NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (from_ts < to_ts)
);

CREATE INDEX IF NOT EXISTS audit_archives_tenant_range
    ON cirislens.audit_archives (tenant_id, from_ts, to_ts);

-- Time-range scan support for the archive_audit_range read.
-- `recorded_at` is already indexed by V014's audit_log_recorded_at.
-- No new index needed on the live audit_log here.

COMMENT ON TABLE cirislens.audit_archives IS
    'v2.7.0 (CIRISPersist#107) — chain-anchored audit-log archive blobs. Engine::archive_audit_range writes one row per archived range; the chain_anchor BYTEA holds the entry_hash of the last archived row so verifiers can walk the chain across an archive. archive_bytes carries the canonical JSON of the archived AuditEntry rows.';

COMMIT;
