-- V104 — #424 GENERIC accord-conferred-role WITHDRAW/SUPERSEDE tombstones
-- (SQLite dialect; postgres/lens/V104 is the parity file).
--
-- The #377 lesson, generalized: an accord-conferred role's ADD gate is
-- monotonic and anti-entropy re-runs it, so withdrawal MUST be a durable
-- TOMBSTONE the gate consults — a hard un-set is silently re-added on the next
-- replication round. V095 built that for `canonical` (its own table, kept
-- as-is — no data migration); THIS table is the shared primitive every LATER
-- accord-conferred role uses, starting with `infra:attest` (#422's ADD gate,
-- #424's WITHDRAW). Authority is the same verified accord live-quorum re-tally
-- (#377's verify_canonical_authority_over_roster, op-parameterized).
--
-- PK (role, key_id): a canonical withdraw of key X and an infra withdraw of
-- key X are DISTINCT tombstones.

CREATE TABLE IF NOT EXISTS federation_role_withdrawals (
    -- The withdrawn role token (e.g. `infra:attest` — types::roles::*).
    role                      TEXT NOT NULL,
    -- The `federation_keys.key_id` whose role is tombstoned.
    key_id                    TEXT NOT NULL,
    -- RFC-3339; caller-supplied for cross-dialect parity.
    withdrawn_at              TEXT NOT NULL,
    -- The authorizing accord AccordDecision proposal digest (V091 / #302).
    authority_decision_digest TEXT NOT NULL,
    -- The successor key_id for a SUPERSEDE (old→new link); NULL for a plain
    -- WITHDRAW.
    superseded_by             TEXT,
    -- Substrate row hash (canonical SHA-256 of the stored row).
    persist_row_hash          TEXT NOT NULL,
    PRIMARY KEY (role, key_id)
);
