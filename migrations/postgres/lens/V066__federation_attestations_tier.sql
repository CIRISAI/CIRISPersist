-- V066 — federation_attestations local/federation tier model
-- (CIRISPersist#171; CEG 0.15 §10.1.3 local-tier signature deferral +
-- §10.1.5 the pinned shared-attestation contract;
-- FSD/V4_4_SHARED_ATTESTATION_SURFACE.md §3/§7).
--
-- v4.0 gave federation_attestations a scope-aware READ surface; this is
-- the foundation of the WRITE+promote half. Every row is now tiered:
--
--   * `local`      — producer-only-authority self-attestation, signature
--                    DEFERRED (CEG §10.1.3). Visible ONLY to the producing
--                    occurrence (the tier read-gate, AV-59). The deferred
--                    scrub envelope is represented by **empty-sentinel**
--                    values (scrub_signature_classical = '', etc.) — the
--                    same empty-sentinel discipline key_grant revocation
--                    uses — so this migration stays PURELY ADDITIVE (no
--                    NOT-NULL relaxation, no table rebuild on either
--                    backend; PG/SQLite parity).
--   * `federation` — hybrid-signed (Ed25519 + ML-DSA-65), federation-
--                    visible. The status-quo `put_attestation` shape AND
--                    the target of `attestation_promote` (local→federation,
--                    JCS-signed per CEG §0.9 / CIRISVerify v4.11.0).
--
-- DEFAULT 'federation' so every existing row keeps its exact meaning
-- (all current rows are signed/federation). No backfill.
--
-- The load-bearing invariant (AV-60): tier = 'federation' ⟹ a non-empty
-- classical signature. Nothing crosses to federation-visible unsigned.

ALTER TABLE cirislens.federation_attestations
    ADD COLUMN IF NOT EXISTS tier TEXT NOT NULL DEFAULT 'federation'
        CHECK (tier IN ('local', 'federation'));

ALTER TABLE cirislens.federation_attestations
    ADD COLUMN IF NOT EXISTS promoted_at TIMESTAMPTZ NULL;

-- federation ⟹ signed. A `local` row may carry the empty-sentinel scrub
-- envelope (deferred); a `federation` row (born signed OR promoted) MUST
-- carry a non-empty classical signature. Same DROP-IF-EXISTS + ADD guard
-- the V054/V064 constraint swaps use, so re-running the chain is
-- idempotent.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'federation_attestations_federation_tier_signed'
          AND conrelid = 'cirislens.federation_attestations'::regclass
    ) THEN
        ALTER TABLE cirislens.federation_attestations
            DROP CONSTRAINT federation_attestations_federation_tier_signed;
    END IF;

    ALTER TABLE cirislens.federation_attestations
        ADD CONSTRAINT federation_attestations_federation_tier_signed
            CHECK (tier = 'local' OR scrub_signature_classical <> '');
END$$;

-- Serve the §5 overdue-promotion scan + the local self-read path.
-- Partial on tier = 'local' — the working set is small (un-promoted
-- producer-authority rows), federation rows are excluded.
CREATE INDEX IF NOT EXISTS federation_attestations_local_tier
    ON cirislens.federation_attestations (tier)
    WHERE tier = 'local';

COMMENT ON COLUMN cirislens.federation_attestations.tier IS
    'v4.4 (CIRISPersist#171, CEG §10.1.3/§10.1.5) — local (producer-only authority, signature deferred, visible only to the producing occurrence) | federation (hybrid-signed, federation-visible). DEFAULT federation. CHECK federation_attestations_federation_tier_signed enforces federation ⟹ non-empty classical signature (AV-60).';

COMMENT ON COLUMN cirislens.federation_attestations.promoted_at IS
    'v4.4 (CIRISPersist#171) — set by attestation_promote at the local→federation transition (the federation-emit moment). NULL for natively-federation rows and un-promoted local rows. Persist-internal — NOT part of the JCS canonical signing bytes (CEG §10.1.5.3 must #2).';
