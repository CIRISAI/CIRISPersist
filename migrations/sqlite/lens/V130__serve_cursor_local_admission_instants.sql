-- V130 — the receiver's own position for EVERY remaining serve cursor, SQLite dialect
-- v36.0.0 (CIRISPersist#668)
--
-- POSTGRES PARITY: migrations/postgres/lens/V130__serve_cursor_local_admission_instants.sql
--
-- WHAT AND WHY
-- ------------
-- This is V123 and V126, applied to the whole family at once.
--
-- Sixteen `list_*_since` cursors page this node's planes to consumers. #655
-- (V123) and #682 (V126) converted two of them — revocations and key records —
-- to key on `admitted_at`, THIS node's admission position, instead of the
-- producer's signed instant. The other twelve tables still filtered and
-- ordered on a producer-carried instant (`asserted_at` / `founded_at` /
-- `removed_at` / `revoked_at`), so on every one of those planes:
--
--     A row signed in January replicates late and is admitted here in
--     February, after a consumer's cursor has already passed January. The
--     consumer asks for `> February`, the row sorts under January, and it is
--     never served to that consumer again. Not late — NEVER.
--
-- One migration for all twelve rather than twelve patches, because the value
-- of the family is that a reviewer who learns one cursor has learned all of
-- them (#668's own argument for a single cut).
--
--     admitted_at — THIS node's serve position on the row. Receiver-stamped,
--                   never read from the wire, never part of the record's
--                   bytes or any content hash, allocated through
--                   `monotonic_admission_instant` so a backward clock step
--                   cannot strand a row below a cursor that has already
--                   passed. Unlike V126's column (whose prose fixes it as
--                   "when THIS node admitted the row"), this family's column
--                   is defined from birth as the SERVE POSITION: a
--                   consumer-visible rewrite through an UPDATE door
--                   (transport retire, attestation promote/co-scrub) moves
--                   it forward through the same allocator, so a consumer
--                   whose cursor has passed the row learns it changed —
--                   #707's defect class, closed at definition time instead
--                   of after the fact.
--
-- BACKFILL
-- --------
-- Existing rows are stamped with the instant their cursor used to order by.
-- Best available answer and an honest one: for rows already stored, that
-- instant IS the only ordering this node ever had, so nothing reachable
-- becomes unreachable and no consumer's saved cursor goes backward.
--
-- SQLite cannot add a NOT NULL column to a populated table without a DEFAULT
-- and cannot alter nullability in place, so each column is added nullable and
-- left nullable; the Rust writer is the enforcement point on this dialect and
-- every read COALESCEs to the legacy instant. The postgres parity file sets
-- NOT NULL after its backfill, exactly as V123/V126 did.
--
-- INDEXES
-- -------
-- Each index is on the EXPRESSION the cursor reads — `COALESCE(admitted_at,
-- <legacy instant>)` — and on `(expr, <tie-break id columns>)` rather than the
-- instant alone, because the cursor resumes on the `(instant, id)` PAIR
-- (#668): a page ordered by `(instant, id)` and resumed by instant alone
-- skips the remainder of any tie larger than one page.

-- ── operational planes (V071) — cursor was `asserted_at` ────────────────────

ALTER TABLE federation_organizations ADD COLUMN admitted_at TEXT;
UPDATE federation_organizations SET admitted_at = asserted_at WHERE admitted_at IS NULL;
CREATE INDEX IF NOT EXISTS federation_organizations_admitted
    ON federation_organizations (COALESCE(admitted_at, asserted_at), attestation_id);

ALTER TABLE federation_org_memberships ADD COLUMN admitted_at TEXT;
UPDATE federation_org_memberships SET admitted_at = asserted_at WHERE admitted_at IS NULL;
CREATE INDEX IF NOT EXISTS federation_org_memberships_admitted
    ON federation_org_memberships (COALESCE(admitted_at, asserted_at), attestation_id);

ALTER TABLE federation_partner_records ADD COLUMN admitted_at TEXT;
UPDATE federation_partner_records SET admitted_at = asserted_at WHERE admitted_at IS NULL;
CREATE INDEX IF NOT EXISTS federation_partner_records_admitted
    ON federation_partner_records (COALESCE(admitted_at, asserted_at), attestation_id);

-- ── E4 keyless-declaration planes (#504) ────────────────────────────────────

ALTER TABLE federation_families ADD COLUMN admitted_at TEXT;
UPDATE federation_families SET admitted_at = founded_at WHERE admitted_at IS NULL;
CREATE INDEX IF NOT EXISTS federation_families_admitted
    ON federation_families (COALESCE(admitted_at, founded_at), family_key_id);

ALTER TABLE federation_communities ADD COLUMN admitted_at TEXT;
UPDATE federation_communities SET admitted_at = founded_at WHERE admitted_at IS NULL;
CREATE INDEX IF NOT EXISTS federation_communities_admitted
    ON federation_communities (COALESCE(admitted_at, founded_at), community_key_id);

-- The location-proof PK is (subject_key_id, asserted_at) — one subject holds
-- MANY proofs — so the row-unique tie-break is (subject_key_id,
-- persist_row_hash), matching `ServedLocationProof::resume_pair`.
ALTER TABLE federation_location_proofs ADD COLUMN admitted_at TEXT;
UPDATE federation_location_proofs SET admitted_at = asserted_at WHERE admitted_at IS NULL;
CREATE INDEX IF NOT EXISTS federation_location_proofs_admitted
    ON federation_location_proofs
       (COALESCE(admitted_at, asserted_at), subject_key_id, persist_row_hash);

ALTER TABLE federation_family_membership_revocations ADD COLUMN admitted_at TEXT;
UPDATE federation_family_membership_revocations
    SET admitted_at = removed_at WHERE admitted_at IS NULL;
CREATE INDEX IF NOT EXISTS federation_family_membership_revocations_admitted
    ON federation_family_membership_revocations
       (COALESCE(admitted_at, removed_at), family_key_id, removed_identity_key_id);

ALTER TABLE federation_community_membership_revocations ADD COLUMN admitted_at TEXT;
UPDATE federation_community_membership_revocations
    SET admitted_at = removed_at WHERE admitted_at IS NULL;
CREATE INDEX IF NOT EXISTS federation_community_membership_revocations_admitted
    ON federation_community_membership_revocations
       (COALESCE(admitted_at, removed_at), community_key_id, removed_identity_key_id);

-- ── primary signed planes (#507c) ───────────────────────────────────────────

ALTER TABLE federation_identity_occurrences ADD COLUMN admitted_at TEXT;
UPDATE federation_identity_occurrences SET admitted_at = asserted_at WHERE admitted_at IS NULL;
CREATE INDEX IF NOT EXISTS federation_identity_occurrences_admitted
    ON federation_identity_occurrences
       (COALESCE(admitted_at, asserted_at), identity_key_id, occurrence_key_id);

ALTER TABLE federation_identity_occurrence_revocations ADD COLUMN admitted_at TEXT;
UPDATE federation_identity_occurrence_revocations
    SET admitted_at = revoked_at WHERE admitted_at IS NULL;
CREATE INDEX IF NOT EXISTS federation_identity_occurrence_revocations_admitted
    ON federation_identity_occurrence_revocations
       (COALESCE(admitted_at, revoked_at), identity_key_id, occurrence_key_id);

ALTER TABLE transport_destinations ADD COLUMN admitted_at TEXT;
UPDATE transport_destinations SET admitted_at = asserted_at WHERE admitted_at IS NULL;
CREATE INDEX IF NOT EXISTS transport_destinations_admitted
    ON transport_destinations
       (COALESCE(admitted_at, asserted_at), occurrence_key_id, transport_kind);

-- The attestation plane's legacy cursor was already half local —
-- `COALESCE(promoted_at, asserted_at)`, because the promote sweep is this
-- plane's admission into the federation stream — so the backfill and the
-- fallback keep that exact expression. The promote sweep now ALSO re-stamps
-- `admitted_at` through the allocator, superseding `promoted_at` as the
-- cursor key while `promoted_at` keeps every other job it had.
ALTER TABLE federation_attestations ADD COLUMN admitted_at TEXT;
UPDATE federation_attestations
    SET admitted_at = COALESCE(promoted_at, asserted_at) WHERE admitted_at IS NULL;
CREATE INDEX IF NOT EXISTS federation_attestations_admitted
    ON federation_attestations
       (COALESCE(admitted_at, promoted_at, asserted_at), attestation_id);
