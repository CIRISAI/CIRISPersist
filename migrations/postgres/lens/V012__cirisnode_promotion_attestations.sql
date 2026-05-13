-- V012 — CIRISNodeCore canonical-promotion attestations
-- (v0.7.2, CIRISPersist#32).
--
-- Closes the v0.7.0 write-side gap: NodeCoreService had no method to
-- flip is_canonical FALSE → TRUE on existing federation-consensus
-- rows. v0.7.2 adds `put_promotion_attestation` which transactionally:
--   1. INSERTs a row into cirisnode.promotion_attestations
--   2. UPDATEs the target row(s)' is_canonical = TRUE +
--      canonicalized_at = NOW()
--
-- Per issue #32 Option B framing: promotion is itself a signed
-- federation event on the audit chain. Readers querying canonical-
-- tier rows have a forensic trail back to the attestation that
-- flipped them via `attested_by` + `attestation_id` joins.
--
-- # Target row classes
--
-- The 5 V011 tables that ship with an is_canonical column:
--   - cirisnode.contributions
--   - cirisnode.votes
--   - cirisnode.moderation_events
--   - cirisnode.slashing_attestations
--   - cirisnode.reconsideration_attestations
-- (reconsideration_requests does NOT have is_canonical — request
-- lifecycle is request → attestation; the attestation carries the
-- canonical decision.)

BEGIN;

CREATE TABLE IF NOT EXISTS cirisnode.promotion_attestations (
    -- ULID per CIRISNodeCore/SCHEMA.md §2.2. UUID column type.
    attestation_id                UUID PRIMARY KEY,

    -- Which row class this attestation promotes. CHECK against the
    -- 5-variant enum.
    target_kind                   TEXT NOT NULL
        CHECK (target_kind IN (
            'contribution',
            'vote',
            'moderation_event',
            'slashing_attestation',
            'reconsideration_attestation'
        )),

    -- Bulk targets — one attestation can promote N rows of the same
    -- target_kind. Array per the issue #32 ask ("bulk-promote per
    -- attestation").
    target_ids                    UUID[] NOT NULL,

    -- §2.2 ContributorId-shaped identity of the consensus crate
    -- (CIRISNodeCore) that signed this attestation — base64url
    -- Ed25519 public key. Must match signature.ed25519 signer
    -- (verified by ingest path; see src/cirisnode/verify.rs).
    attested_by                   TEXT NOT NULL,

    -- Aggregate evidence — the threshold-crossing details the
    -- consensus crate used to decide promotion. Free-form JSONB so
    -- per-policy shapes nest cleanly (e.g., vote tallies, witness
    -- counts, time windows).
    aggregate_evidence            JSONB NOT NULL,

    -- §3 attested_at — caller-asserted wall-clock.
    attested_at                   TIMESTAMPTZ NOT NULL,

    -- Standard CIRISPersist audit envelope (matches V011 shape).
    signature                     TEXT NOT NULL,
    signing_key_id                TEXT NOT NULL,
    signature_verified            BOOLEAN NOT NULL DEFAULT FALSE,
    original_content_hash         BYTEA,
    scrub_signature_classical     TEXT,
    scrub_signature_pqc           TEXT,
    scrub_key_id                  TEXT,
    scrub_timestamp               TIMESTAMPTZ,
    pqc_completed_at              TIMESTAMPTZ,
    persist_row_hash              TEXT NOT NULL,

    -- Lifecycle.
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS promotion_attestations_target_kind
    ON cirisnode.promotion_attestations (target_kind);
CREATE INDEX IF NOT EXISTS promotion_attestations_attested_by
    ON cirisnode.promotion_attestations (attested_by);
CREATE INDEX IF NOT EXISTS promotion_attestations_attested_at
    ON cirisnode.promotion_attestations (attested_at);
-- GIN index for "which attestations name this target_id?" reverse
-- lookups during truth-grounding-loop audits.
CREATE INDEX IF NOT EXISTS promotion_attestations_target_ids_gin
    ON cirisnode.promotion_attestations USING GIN (target_ids);

COMMENT ON TABLE cirisnode.promotion_attestations IS
    'v0.7.2 (CIRISPersist#32) — signed federation-consensus attestation that promotes target rows from is_canonical=FALSE to is_canonical=TRUE. Transactionally written alongside the UPDATE on the target rows; readers query the GIN index on target_ids for "what promoted this row?" audits.';

COMMIT;
