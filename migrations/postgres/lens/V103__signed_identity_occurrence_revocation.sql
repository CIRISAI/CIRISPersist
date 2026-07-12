-- v16.0.0 (CIRISPersist#421) — the revocation half of the #418 signed-occurrence
-- discipline: store the detached signature container alongside the typed
-- projection so the replication plane can carry + re-publish revocations
-- byte-exact (the same argument as V102 for occurrences). Nullable: rows
-- written before this cut (and trusted-local writes) carry NULL — the signed
-- read returns only signed-put rows.
ALTER TABLE cirislens.federation_identity_occurrence_revocations
    ADD COLUMN IF NOT EXISTS attesting_key_id TEXT;
ALTER TABLE cirislens.federation_identity_occurrence_revocations
    ADD COLUMN IF NOT EXISTS signed_envelope JSONB;
ALTER TABLE cirislens.federation_identity_occurrence_revocations
    ADD COLUMN IF NOT EXISTS signature JSONB;
