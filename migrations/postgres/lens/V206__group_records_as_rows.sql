-- V206 — the group records and the membership planes become rows; their six
-- tables become projections.
-- Postgres dialect. v61 (CIRISPersist#991 planes 2 and 3; CC 3.1.3,
-- CC 3.1.3.2, CC 2.4; CLM-planes-as-rows, CLM-cosigned-rows).
--
-- SQLite PARITY: migrations/sqlite/lens/V206__group_records_as_rows.sql
--
-- WHY
-- ---
-- A family's or community's record (`group:roster:v1`), a widening
-- (`membership:widening:v1`) and a revocation (`membership:removal:v1`, or
-- `membership:resignation:v1` when the leaving member signs it) are `scores`
-- rows on the attestation plane from v61, each minted by persist from the
-- signed object it verified (`federation::group_plane`), its co-signatures
-- carried as the row's `additional_scrubs`. The six tables stay, as the
-- projections of those rows, rebuildable from the rows alone
-- (`silo_projection::check_projection_rebuild`).
--
-- HOW
-- ---
-- `attestation_id` names the row each projection row comes from.
--
-- ON DELETE SET NULL, not CASCADE (the V198 precedent): deleting a row must
-- never delete a group or a roster event with it; a projection row left
-- without its row reads as held-without-a-row, which the rebuild gate names.
--
-- A pre-v61 signed row carries NULL until the rehome at open mints its row
-- (`rehome_group_records`); an Ed25519-only one stays NULL, held, counted at
-- open and named by the gate. A trusted-local (unsigned) record is the node's
-- own write and is outside the projection. The partial indexes make the
-- "any left?" probe free.

ALTER TABLE cirislens.federation_families
    ADD COLUMN IF NOT EXISTS attestation_id TEXT
        REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

CREATE UNIQUE INDEX IF NOT EXISTS federation_families_by_attestation
    ON cirislens.federation_families (attestation_id);

CREATE INDEX IF NOT EXISTS federation_families_without_row
    ON cirislens.federation_families (family_key_id) WHERE attestation_id IS NULL;

ALTER TABLE cirislens.federation_communities
    ADD COLUMN IF NOT EXISTS attestation_id TEXT
        REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

CREATE UNIQUE INDEX IF NOT EXISTS federation_communities_by_attestation
    ON cirislens.federation_communities (attestation_id);

CREATE INDEX IF NOT EXISTS federation_communities_without_row
    ON cirislens.federation_communities (community_key_id) WHERE attestation_id IS NULL;

ALTER TABLE cirislens.federation_family_membership_revocations
    ADD COLUMN IF NOT EXISTS attestation_id TEXT
        REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

CREATE UNIQUE INDEX IF NOT EXISTS federation_family_membership_revocations_by_attestation
    ON cirislens.federation_family_membership_revocations (attestation_id);

CREATE INDEX IF NOT EXISTS federation_family_membership_revocations_without_row
    ON cirislens.federation_family_membership_revocations (family_key_id, removed_identity_key_id, effective_at) WHERE attestation_id IS NULL;

ALTER TABLE cirislens.federation_community_membership_revocations
    ADD COLUMN IF NOT EXISTS attestation_id TEXT
        REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

CREATE UNIQUE INDEX IF NOT EXISTS federation_community_membership_revocations_by_attestation
    ON cirislens.federation_community_membership_revocations (attestation_id);

CREATE INDEX IF NOT EXISTS federation_community_membership_revocations_without_row
    ON cirislens.federation_community_membership_revocations (community_key_id, removed_identity_key_id, effective_at) WHERE attestation_id IS NULL;

ALTER TABLE cirislens.federation_family_membership_widenings
    ADD COLUMN IF NOT EXISTS attestation_id TEXT
        REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

CREATE UNIQUE INDEX IF NOT EXISTS federation_family_membership_widenings_by_attestation
    ON cirislens.federation_family_membership_widenings (attestation_id);

CREATE INDEX IF NOT EXISTS federation_family_membership_widenings_without_row
    ON cirislens.federation_family_membership_widenings (family_key_id, member_key_id, effective_at) WHERE attestation_id IS NULL;

ALTER TABLE cirislens.federation_community_membership_widenings
    ADD COLUMN IF NOT EXISTS attestation_id TEXT
        REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL;

CREATE UNIQUE INDEX IF NOT EXISTS federation_community_membership_widenings_by_attestation
    ON cirislens.federation_community_membership_widenings (attestation_id);

CREATE INDEX IF NOT EXISTS federation_community_membership_widenings_without_row
    ON cirislens.federation_community_membership_widenings (community_key_id, member_key_id, effective_at) WHERE attestation_id IS NULL;
