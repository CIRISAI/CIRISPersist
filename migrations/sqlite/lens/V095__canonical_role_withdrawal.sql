-- V095 — #377 canonical-role WITHDRAW/SUPERSEDE tombstone (CC 3.4.7.1 /
-- FSD Trust Root) (SQLite dialect).
--
-- Postgres parity: postgres/lens/V095. See that file for the full design
-- rationale. The `canonical` add-gate (#372) is monotonic and anti-entropy
-- (`apply_replicated_key_record`, #375) re-runs it, so withdrawal MUST be a
-- durable TOMBSTONE the gate consults ("anchor-scrubbed AND not
-- withdrawn-by-quorum") — a hard un-set would be silently re-added on the next
-- replication round. Authority is a verified accord live-quorum AccordDecision
-- (V091 / #302, m-of-n); `authority_decision_digest` is the authorizing
-- proposal digest. `superseded_by` names the successor key_id for a supersede
-- (old→new link), NULL for a plain withdraw. Idempotent record.
--
-- SQLite dialect: bare table name (no schema), TEXT RFC-3339 timestamp.
--
-- No explicit BEGIN/COMMIT — refinery wraps each migration in a transaction.

CREATE TABLE IF NOT EXISTS canonical_role_withdrawal (
    -- The withdrawn canonical node (the `federation_keys.key_id` whose
    -- `canonical` role is tombstoned).
    key_id                    TEXT PRIMARY KEY,
    -- RFC-3339; caller-supplied for cross-dialect parity.
    withdrawn_at              TEXT NOT NULL,
    -- The authorizing accord AccordDecision proposal digest (V091 / #302).
    authority_decision_digest TEXT NOT NULL,
    -- The successor key_id for a SUPERSEDE (old→new link); NULL for a plain
    -- WITHDRAW.
    superseded_by             TEXT,
    -- Substrate row hash (canonical SHA-256 of the stored row).
    persist_row_hash          TEXT NOT NULL
);
