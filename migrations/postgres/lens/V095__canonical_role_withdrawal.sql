-- V095 — #377 canonical-role WITHDRAW/SUPERSEDE tombstone (CC 3.4.7.1 /
-- FSD Trust Root) (Postgres dialect).
--
-- v13.0.0 (#372) made the `canonical` identity_type role monotonic / add-only
-- via `check_canonical_role_admission`: the role is admitted IFF the record is
-- anchor-scrub-signed by a HUMANITY_ACCORD holder (A1/B1/C1). That is correct
-- for ADD, but the two DESTRUCTIVE Trust Root ops (withdraw a canonical server,
-- supersede/rotate its key) had no substrate primitive.
--
-- # Why a TOMBSTONE, not a hard un-set (load-bearing)
--
-- The add-gate is monotonic and the anti-entropy path
-- (`apply_replicated_key_record`, #375) re-runs it. A hard drop of the
-- `canonical` role would be silently RE-ADDED on the next replication round
-- from a peer still holding the old anchor-scrubbed record. So withdrawal is a
-- durable, quorum-verified revocation-class row that
-- `check_canonical_role_admission` CONSULTS: the gate becomes
-- "anchor-scrubbed AND not withdrawn-by-quorum." Same revocation-wins ordering
-- as #370 B6 (pin-blind hard-delete; revocation wins) and #161 revocation
-- state.
--
-- # Authority
--
-- A withdraw/supersede is authorized by a verified accord live-quorum
-- `AccordDecision` (V091 / #302) whose `authorized == true` and whose
-- `proposal.payload_sha256` commits to the canonical persist-computed
-- withdrawal payload (an m-of-n family tally the server verified at #302 store
-- time). `authority_decision_digest` records the authorizing proposal digest
-- for audit. Asymmetric by design: a single accord holder may ADD (1-of-N
-- conferral) but not WITHDRAW (m-of-N).
--
-- # Shape
--
-- One row per withdrawn canonical `key_id`. `superseded_by` is the successor
-- key_id for a supersede (the old→new audit link); NULL for a plain withdraw.
-- Idempotent record — a re-record of the same withdrawal is a no-op.
--
-- No TimescaleDB (operator directive): plain postgres:16, ordinary table.
-- No explicit BEGIN/COMMIT — refinery wraps each migration in a transaction.

CREATE TABLE IF NOT EXISTS cirislens.canonical_role_withdrawal (
    -- The withdrawn canonical node (the `federation_keys.key_id` whose
    -- `canonical` role is tombstoned).
    key_id                    TEXT PRIMARY KEY,
    -- When the withdrawal was recorded.
    withdrawn_at              TIMESTAMPTZ NOT NULL,
    -- The authorizing accord `AccordDecision` proposal digest (V091 /
    -- #302) — the audit anchor for the m-of-n quorum that authorized it.
    authority_decision_digest TEXT NOT NULL,
    -- The successor key_id for a SUPERSEDE (old→new link); NULL for a plain
    -- WITHDRAW.
    superseded_by             TEXT,
    -- Substrate row hash (canonical SHA-256 of the stored row).
    persist_row_hash          TEXT NOT NULL
);
