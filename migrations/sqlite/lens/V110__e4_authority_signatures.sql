-- V110 (CIRISPersist#502 E4 followup) — persist the authority signature the
-- E4 gate already verifies-then-discards. `put_family` / `put_community` /
-- `put_family_membership_revocation` / `put_community_membership_revocation` /
-- `put_location_proof` hybrid-Strict-verify `SignedFamily` / `SignedCommunity`
-- / `SignedFamilyMembershipRevocation` / `SignedCommunityMembershipRevocation`
-- / `SignedLocationProof`'s `authority_key_id` +
-- `scrub_signature_{classical,pqc}` against the authority's REGISTERED
-- pubkeys (v21.0.0, CIRISPersist#502 E4) — but then discard all 3 fields:
-- the stored row had no home for them, so the durable record could not prove
-- its own authorship, and any future re-serve of the `Signed*` wrapper would
-- carry empty signature fields. SQLite dialect. Postgres parity:
-- postgres/lens/V110.
--
-- Same column shape as `federation_revocations.scrub_signature_{classical,
-- pqc}` (V004) — `authority_key_id` stands in for that table's
-- `scrub_key_id`, un-FK'd: unlike `federation_revocations`/`federation_keys`,
-- these 5 planes' authority need not be a key the record itself references
-- (see `SignedLocationProof::authority_key_id`'s doc — "typically the
-- subject itself... but not enforced to be").
--
-- Nullable on all 3: existing rows are unaffected, and every
-- `put_family_local` genesis-bake row (`family_key_id` is keyless by design —
-- see `Family::signing_envelope`'s doc) is legitimately unsigned and leaves
-- them NULL going forward too.

ALTER TABLE federation_families ADD COLUMN authority_key_id TEXT;
ALTER TABLE federation_families ADD COLUMN scrub_signature_classical TEXT;
ALTER TABLE federation_families ADD COLUMN scrub_signature_pqc TEXT;

ALTER TABLE federation_communities ADD COLUMN authority_key_id TEXT;
ALTER TABLE federation_communities ADD COLUMN scrub_signature_classical TEXT;
ALTER TABLE federation_communities ADD COLUMN scrub_signature_pqc TEXT;

ALTER TABLE federation_family_membership_revocations ADD COLUMN authority_key_id TEXT;
ALTER TABLE federation_family_membership_revocations ADD COLUMN scrub_signature_classical TEXT;
ALTER TABLE federation_family_membership_revocations ADD COLUMN scrub_signature_pqc TEXT;

ALTER TABLE federation_community_membership_revocations ADD COLUMN authority_key_id TEXT;
ALTER TABLE federation_community_membership_revocations ADD COLUMN scrub_signature_classical TEXT;
ALTER TABLE federation_community_membership_revocations ADD COLUMN scrub_signature_pqc TEXT;

ALTER TABLE federation_location_proofs ADD COLUMN authority_key_id TEXT;
ALTER TABLE federation_location_proofs ADD COLUMN scrub_signature_classical TEXT;
ALTER TABLE federation_location_proofs ADD COLUMN scrub_signature_pqc TEXT;
