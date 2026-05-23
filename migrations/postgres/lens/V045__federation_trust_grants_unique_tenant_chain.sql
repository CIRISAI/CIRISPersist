-- V045 — UNIQUE(tenant_id, chain_event_id) on federation_trust_grants
-- (2.0.x, CIRISPersist v2.0.1 PG-test honesty closure).
--
-- # Why this constraint exists
--
-- `audit_log.sequence_number` is `UNIQUE(tenant_id, sequence_number)`
-- — per-tenant, not global. Phase E (`grant_trust`) reuses the
-- sequence_number as the `chain_event_id` it stamps onto every
-- `federation_trust_grants` projection row. V021 (the original Phase
-- A schema) only indexed `(chain_event_id)`; nothing in the schema
-- forbade two grants in different tenants sharing a chain_event_id.
--
-- The downstream API path —
-- `AuditService::lookup_grant_id_by_chain_event` — was originally
-- written `query_opt … WHERE chain_event_id = $1`, which expected 0
-- or 1 row. On a multi-tenant DB (or a CI run where multiple PG
-- tests share the same database), the query observed multiple rows
-- and surfaced `unexpected number of rows`. The trait now takes
-- `tenant_id` alongside `chain_event_id` (matching the audit_log
-- key shape); this index makes the schema enforce the same invariant
-- the API now relies on.
--
-- This mirrors the V021 merkle_leaves shape:
--     UNIQUE (tenant_id, chain_event_id)
-- — the same per-tenant key the audit chain itself uses.
--
-- # Backfill safety
--
-- Production federation_trust_grants rows have never had cross-tenant
-- chain_event_id collisions: every grant_trust call is tenant-scoped,
-- and the V020/V021 trust-grant invariant
-- `UNIQUE (grantee_key, granter_key, purpose, scope)` constrains
-- per-grantee duplication. The constraint is added without a
-- backfill step because no production row can violate it; if any did
-- (e.g. a Phase I backfill that crossed tenants on the same
-- sequence_number — none in 2.0.x), CREATE UNIQUE INDEX would surface
-- it loudly.
--
-- # Refinery wraps each migration in a transaction.

CREATE UNIQUE INDEX IF NOT EXISTS federation_trust_grants_tenant_chain
    ON cirislens.federation_trust_grants (tenant_id, chain_event_id);

COMMENT ON INDEX cirislens.federation_trust_grants_tenant_chain IS
    'v2.0.x — UNIQUE(tenant_id, chain_event_id). Mirrors the per-tenant key shape audit_log uses (UNIQUE(tenant_id, sequence_number)) and merkle_leaves uses (UNIQUE(tenant_id, chain_event_id)). Makes lookup_grant_id_by_chain_event query_opt single-row contract enforceable at the schema level.';
