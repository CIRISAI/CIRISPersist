-- V156 — the membership listing plane (CC 2 `listed`)
-- v49.0.0 (CIRISPersist#912, FSD ROOM_ROSTER_AUTHORITY.md §11)
--
-- SQLITE PARITY: migrations/sqlite/lens/V156__community_membership_listings.sql
-- (that file's header carries the reasoning; this one carries the DDL).
--
-- federation_community_membership_listings: one member's signed `listed`
-- choice per (room, member, effective_at); forward-only; `public` or NULL.

CREATE TABLE IF NOT EXISTS cirislens.federation_community_membership_listings (
    community_key_id          TEXT NOT NULL
        REFERENCES cirislens.federation_communities(community_key_id),
    member_key_id             TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),
    effective_at              TIMESTAMPTZ NOT NULL,
    listed                    TEXT CHECK (listed IS NULL OR listed = 'public'),
    persist_row_hash          TEXT NOT NULL,
    authority_key_id          TEXT,
    scrub_signature_classical TEXT,
    scrub_signature_pqc       TEXT,
    admitted_at               TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_key_id, member_key_id, effective_at)
);
CREATE INDEX IF NOT EXISTS federation_community_membership_listings_by_member
    ON cirislens.federation_community_membership_listings (member_key_id);
CREATE INDEX IF NOT EXISTS federation_community_membership_listings_admitted
    ON cirislens.federation_community_membership_listings
       (admitted_at, community_key_id, member_key_id, effective_at);
