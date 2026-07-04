-- V092 — #370 §Q pin-INSTALL surface (CC 6.1.5.2 B2/B3/B5) (Postgres dialect).
--
-- #356 shipped `build_storage_budget_v1` / `verify_storage_budget_v1` as
-- wire-negotiation objects only (verified-at-ingest, nothing stored), so a
-- verified `StorageBudgetV1` could not GOVERN eviction. This migration adds
-- the one small table that makes an owner's accepted budget durable pin
-- STATE: `Engine::install_storage_budget_v1` verifies the bound-hybrid
-- signature (PQC-mandatory, CC 5.3.2.4.3.1 store-path — verify BEFORE
-- persistence) and upserts here; the disk-pressure eviction sweep reads it
-- back to order candidates CACHE-BEFORE-PINNED (B5) and to hold the
-- `pin_reserve_bytes` floor.
--
-- # Shape
--
-- One row per owner `node_id` (the budget is a single-owner
-- self-declaration, CC 5.3.2.3 anti-rollback aspect). `revision` is
-- monotonic: the upsert is CONDITIONAL (`WHERE installed.revision <
-- EXCLUDED.revision`) so a lower-or-equal revision from the same node_id is
-- refused ATOMICALLY at the row — §Q B3 anti-rollback cannot be raced past
-- the Engine-side check. `scopes` / `pinned_class` are denormalized copies
-- of the wire fields (queryability); `wire` is the signed wire JSON
-- VERBATIM so any consumer can re-verify the installed budget end-to-end
-- (persist never re-derives signed bytes).
--
-- # What this table is NOT (§Q B6 / N5 — CIRISPersist#359)
--
-- Pin state governs CAPACITY eviction only. The revocation path
-- (`evict_fountain_content_hard_delete`) takes `(content_id, corpus_kind)`
-- and reads NOTHING from this table — pinning never defeats revocation.
-- That pin-blindness is locked by tests/fountain_content.rs (j)/(k).
--
-- No TimescaleDB (operator directive): plain postgres:16, ordinary table.
-- No explicit BEGIN/COMMIT — refinery wraps each migration in a transaction.

CREATE TABLE IF NOT EXISTS cirislens.storage_budget_installed (
    -- The owner node this budget binds (StorageBudgetV1.node_id).
    node_id       TEXT PRIMARY KEY,
    -- Monotonic revision; higher supersedes, lower/equal is refused
    -- (§Q B3 anti-rollback).
    revision      BIGINT NOT NULL CHECK (revision >= 0),
    -- Epoch keying (CC 5.1).
    epoch_id      TEXT NOT NULL,
    -- Denormalized per-cohort_scope allotments:
    -- [{cohort_scope, budget_bytes, pin_reserve_bytes}, ...].
    -- NEVER self/family (B3 suppression — enforced at verify).
    scopes        JSONB NOT NULL,
    -- Denormalized corpus subject_kinds the owner elects to pin (B2-ii).
    pinned_class  JSONB NOT NULL,
    -- The signed StorageBudgetV1 wire JSON VERBATIM (payload + both
    -- signature halves) — re-verifiable at any time.
    wire          JSONB NOT NULL,
    -- When this revision was accepted locally (caller-supplied so both
    -- dialects agree byte-for-byte on the row).
    installed_at  TIMESTAMPTZ NOT NULL
);
