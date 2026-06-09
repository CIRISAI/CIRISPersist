-- V066 — federation_attestations local/federation tier model, SQLite
-- dialect (CIRISPersist#171; CEG 0.15 §10.1.3 / §10.1.5;
-- FSD/V4_4_SHARED_ATTESTATION_SURFACE.md §3/§7).
--
-- Postgres parity (postgres/lens/V066). Every row is now tiered local |
-- federation; `local` = producer-only-authority self-attestation with a
-- DEFERRED signature (CEG §10.1.3), visible only to the producing
-- occurrence. The deferred scrub envelope is represented by
-- empty-sentinel values (NOT NULL), so this migration is PURELY ADDITIVE
-- — two ADD COLUMNs, no table rebuild (the NOT-NULL scrub columns are
-- untouched; local rows write '' / x'' sentinels). The federation ⟹
-- signed invariant (AV-60), a cross-column rule SQLite can't express as
-- an added table CHECK, is enforced by BEFORE INSERT/UPDATE triggers per
-- the V054/V064 discipline.
--
-- Type mapping vs PG: TIMESTAMPTZ → TEXT (RFC3339).

-- tier — column-level CHECK (single-column, admitted on ADD COLUMN).
ALTER TABLE federation_attestations
    ADD COLUMN tier TEXT NOT NULL DEFAULT 'federation'
        CHECK (tier IN ('local', 'federation'));

-- promoted_at — set at the local→federation transition; persist-internal.
ALTER TABLE federation_attestations
    ADD COLUMN promoted_at TEXT;

-- federation ⟹ non-empty classical signature (AV-60). Cross-column →
-- triggers (SQLite has no ALTER ADD CONSTRAINT). ABORT when a row at
-- federation tier carries an empty classical signature.
DROP TRIGGER IF EXISTS federation_attestations_federation_tier_signed_ins;
DROP TRIGGER IF EXISTS federation_attestations_federation_tier_signed_upd;

CREATE TRIGGER federation_attestations_federation_tier_signed_ins
    BEFORE INSERT ON federation_attestations
    FOR EACH ROW
    WHEN (NEW.tier = 'federation' AND NEW.scrub_signature_classical = '')
    BEGIN
        SELECT RAISE(ABORT, 'federation_attestations: tier=federation requires a non-empty scrub_signature_classical (federation ⟹ signed; CEG §10.1.5 AV-60). A deferred-signature row must be tier=local.');
    END;

CREATE TRIGGER federation_attestations_federation_tier_signed_upd
    BEFORE UPDATE ON federation_attestations
    FOR EACH ROW
    WHEN (NEW.tier = 'federation' AND NEW.scrub_signature_classical = '')
    BEGIN
        SELECT RAISE(ABORT, 'federation_attestations: tier=federation requires a non-empty scrub_signature_classical (federation ⟹ signed; CEG §10.1.5 AV-60). A deferred-signature row must be tier=local.');
    END;

-- Serve the §5 overdue-promotion scan + the local self-read path.
CREATE INDEX IF NOT EXISTS federation_attestations_local_tier
    ON federation_attestations (tier)
    WHERE tier = 'local';
