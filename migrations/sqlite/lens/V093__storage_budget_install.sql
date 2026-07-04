-- V092 — #370 §Q pin-INSTALL surface (CC 6.1.5.2 B2/B3/B5) (SQLite dialect).
--
-- Postgres parity: postgres/lens/V092. See that file for the full design
-- rationale. One row per owner node_id; conditional monotonic-revision
-- upsert = §Q B3 anti-rollback enforced atomically at the row; `wire` is
-- the signed StorageBudgetV1 wire JSON VERBATIM (re-verifiable). Pin state
-- governs CAPACITY eviction only — the revocation path
-- (`evict_fountain_content_hard_delete`) never reads this table (§Q B6/N5,
-- CIRISPersist#359).
--
-- SQLite dialect: bare table name (no schema), TEXT RFC-3339 timestamp,
-- `json_valid()` CHECKs in place of JSONB.
--
-- No explicit BEGIN/COMMIT — refinery wraps each migration in a transaction.

CREATE TABLE IF NOT EXISTS storage_budget_installed (
    -- The owner node this budget binds (StorageBudgetV1.node_id).
    node_id       TEXT PRIMARY KEY,
    -- Monotonic revision; higher supersedes, lower/equal is refused
    -- (§Q B3 anti-rollback).
    revision      INTEGER NOT NULL CHECK (revision >= 0),
    -- Epoch keying (CC 5.1).
    epoch_id      TEXT NOT NULL,
    -- Denormalized per-cohort_scope allotments (JSON array; never
    -- self/family — B3 suppression, enforced at verify).
    scopes        TEXT NOT NULL CHECK (json_valid(scopes)),
    -- Denormalized corpus subject_kinds the owner elects to pin (B2-ii).
    pinned_class  TEXT NOT NULL CHECK (json_valid(pinned_class)),
    -- The signed StorageBudgetV1 wire JSON VERBATIM.
    wire          TEXT NOT NULL CHECK (json_valid(wire)),
    -- RFC-3339; caller-supplied for cross-dialect parity.
    installed_at  TEXT NOT NULL
);
