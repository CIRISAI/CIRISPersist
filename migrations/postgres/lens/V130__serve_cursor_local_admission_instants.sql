-- V130 — the receiver's own position for EVERY remaining serve cursor, PostgreSQL dialect
-- v36.0.0 (CIRISPersist#668)
--
-- SQLITE PARITY: migrations/sqlite/lens/V130__serve_cursor_local_admission_instants.sql
--
-- See the sqlite twin for the full reasoning. In short: V123/V126, applied to
-- the whole remaining family at once. Twelve tables' serve cursors filtered
-- and ordered on a producer-carried instant, so a row replicated late sorted
-- behind every consumer's cursor and was never served again. Each gains
--
--     admitted_at — THIS node's serve position on the row: receiver-stamped,
--                   never read from the wire, never in any content hash,
--                   allocated through `monotonic_admission_instant`, and
--                   moved FORWARD by any consumer-visible UPDATE door
--                   (transport retire, attestation promote/co-scrub) so a
--                   consumer past the row learns it changed (#707's class,
--                   closed at definition time on these planes).
--
-- DIALECT DIVERGENCE FROM THE SQLITE TWIN, deliberate and matching V123/V126:
-- postgres can enforce NOT NULL after the backfill and does — a writer that
-- forgets to stamp fails loudly at INSERT instead of silently falling back —
-- while sqlite cannot alter nullability in place and leaves the column
-- nullable with the Rust writer as the enforcement point. Each tree is
-- internally coherent: the indexes here are on the bare column because it is
-- NOT NULL, the sqlite indexes are on `COALESCE(admitted_at, <legacy>)`
-- because there it can be NULL, and each backend's query matches its own
-- index.
--
-- Every index is on `(admitted_at, <tie-break id columns>)` rather than the
-- instant alone, because the cursor resumes on the `(instant, id)` PAIR
-- (#668): a page ordered by `(instant, id)` and resumed by instant alone
-- skips the remainder of any tie larger than one page.

-- ── operational planes (V071) — cursor was `asserted_at` ────────────────────

ALTER TABLE cirislens.federation_organizations
    ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;
UPDATE cirislens.federation_organizations
    SET admitted_at = asserted_at WHERE admitted_at IS NULL;
ALTER TABLE cirislens.federation_organizations
    ALTER COLUMN admitted_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS federation_organizations_admitted
    ON cirislens.federation_organizations (admitted_at, attestation_id);

ALTER TABLE cirislens.federation_org_memberships
    ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;
UPDATE cirislens.federation_org_memberships
    SET admitted_at = asserted_at WHERE admitted_at IS NULL;
ALTER TABLE cirislens.federation_org_memberships
    ALTER COLUMN admitted_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS federation_org_memberships_admitted
    ON cirislens.federation_org_memberships (admitted_at, attestation_id);

ALTER TABLE cirislens.federation_partner_records
    ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;
UPDATE cirislens.federation_partner_records
    SET admitted_at = asserted_at WHERE admitted_at IS NULL;
ALTER TABLE cirislens.federation_partner_records
    ALTER COLUMN admitted_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS federation_partner_records_admitted
    ON cirislens.federation_partner_records (admitted_at, attestation_id);

-- ── E4 keyless-declaration planes (#504) ────────────────────────────────────

ALTER TABLE cirislens.federation_families
    ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;
UPDATE cirislens.federation_families
    SET admitted_at = founded_at WHERE admitted_at IS NULL;
ALTER TABLE cirislens.federation_families
    ALTER COLUMN admitted_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS federation_families_admitted
    ON cirislens.federation_families (admitted_at, family_key_id);

ALTER TABLE cirislens.federation_communities
    ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;
UPDATE cirislens.federation_communities
    SET admitted_at = founded_at WHERE admitted_at IS NULL;
ALTER TABLE cirislens.federation_communities
    ALTER COLUMN admitted_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS federation_communities_admitted
    ON cirislens.federation_communities (admitted_at, community_key_id);

-- The location-proof PK is (subject_key_id, asserted_at) — one subject holds
-- MANY proofs — so the row-unique tie-break is (subject_key_id,
-- persist_row_hash), matching `ServedLocationProof::resume_pair`.
ALTER TABLE cirislens.federation_location_proofs
    ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;
UPDATE cirislens.federation_location_proofs
    SET admitted_at = asserted_at WHERE admitted_at IS NULL;
ALTER TABLE cirislens.federation_location_proofs
    ALTER COLUMN admitted_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS federation_location_proofs_admitted
    ON cirislens.federation_location_proofs
       (admitted_at, subject_key_id, persist_row_hash);

ALTER TABLE cirislens.federation_family_membership_revocations
    ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;
UPDATE cirislens.federation_family_membership_revocations
    SET admitted_at = removed_at WHERE admitted_at IS NULL;
ALTER TABLE cirislens.federation_family_membership_revocations
    ALTER COLUMN admitted_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS federation_family_membership_revocations_admitted
    ON cirislens.federation_family_membership_revocations
       (admitted_at, family_key_id, removed_identity_key_id);

ALTER TABLE cirislens.federation_community_membership_revocations
    ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;
UPDATE cirislens.federation_community_membership_revocations
    SET admitted_at = removed_at WHERE admitted_at IS NULL;
ALTER TABLE cirislens.federation_community_membership_revocations
    ALTER COLUMN admitted_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS federation_community_membership_revocations_admitted
    ON cirislens.federation_community_membership_revocations
       (admitted_at, community_key_id, removed_identity_key_id);

-- ── primary signed planes (#507c) ───────────────────────────────────────────

ALTER TABLE cirislens.federation_identity_occurrences
    ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;
UPDATE cirislens.federation_identity_occurrences
    SET admitted_at = asserted_at WHERE admitted_at IS NULL;
ALTER TABLE cirislens.federation_identity_occurrences
    ALTER COLUMN admitted_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS federation_identity_occurrences_admitted
    ON cirislens.federation_identity_occurrences
       (admitted_at, identity_key_id, occurrence_key_id);

ALTER TABLE cirislens.federation_identity_occurrence_revocations
    ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;
UPDATE cirislens.federation_identity_occurrence_revocations
    SET admitted_at = revoked_at WHERE admitted_at IS NULL;
ALTER TABLE cirislens.federation_identity_occurrence_revocations
    ALTER COLUMN admitted_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS federation_identity_occurrence_revocations_admitted
    ON cirislens.federation_identity_occurrence_revocations
       (admitted_at, identity_key_id, occurrence_key_id);

ALTER TABLE cirislens.transport_destinations
    ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;
UPDATE cirislens.transport_destinations
    SET admitted_at = asserted_at WHERE admitted_at IS NULL;
ALTER TABLE cirislens.transport_destinations
    ALTER COLUMN admitted_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS transport_destinations_admitted
    ON cirislens.transport_destinations
       (admitted_at, occurrence_key_id, transport_kind);

-- The attestation plane's legacy cursor was already half local —
-- `COALESCE(promoted_at, asserted_at)`, because the promote sweep is this
-- plane's admission into the federation stream — so the backfill keeps that
-- exact expression. The promote sweep now ALSO re-stamps `admitted_at`
-- through the allocator, superseding `promoted_at` as the cursor key while
-- `promoted_at` keeps every other job it had.
ALTER TABLE cirislens.federation_attestations
    ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;
UPDATE cirislens.federation_attestations
    SET admitted_at = COALESCE(promoted_at, asserted_at) WHERE admitted_at IS NULL;
ALTER TABLE cirislens.federation_attestations
    ALTER COLUMN admitted_at SET NOT NULL;
CREATE INDEX IF NOT EXISTS federation_attestations_admitted
    ON cirislens.federation_attestations (admitted_at, attestation_id);
