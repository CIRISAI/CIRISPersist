-- V045 — UNIQUE(tenant_id, chain_event_id) on federation_trust_grants
-- (SQLite parity for the PG V045 of the same name).
--
-- Rationale + design notes: see
-- migrations/postgres/lens/V045__federation_trust_grants_unique_tenant_chain.sql
-- (`tenant_id, chain_event_id` is the per-tenant key shape audit_log
-- uses; the API now relies on it being unique).
--
-- SQLite tests historically passed without this constraint because
-- each test gets a fresh in-memory DB so cross-tenant collisions
-- couldn't surface. Once multiple tenants share a SQLite file in
-- production, the schema needs to encode the invariant the API
-- requires.

CREATE UNIQUE INDEX IF NOT EXISTS federation_trust_grants_tenant_chain
    ON federation_trust_grants (tenant_id, chain_event_id);
