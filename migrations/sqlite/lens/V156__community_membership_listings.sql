-- V156 — the membership listing plane (CC 2 `listed`)
-- v49.0.0 (CIRISPersist#912, FSD ROOM_ROSTER_AUTHORITY.md §11)
--
-- POSTGRES PARITY: migrations/postgres/lens/V156__community_membership_listings.sql
--
-- # Why
--
-- CC 2's `listed` is a per-membership opt-in to public roster visibility,
-- value `public` only, default absent (a PRIVATE roster — never globally
-- enumerable), and a one-way disclosure the MEMBER chooses. Nothing stored it:
-- the only truthful rendering a client had was to say nothing.
--
-- # What changes
--
-- `federation_community_membership_listings` — one row per (room, member,
-- effective_at): the member's signed choice at that instant. Forward-only:
-- clearing is a later row with `listed` NULL; the latest row at or before an
-- instant decides. Rooms only (`community` / `affiliations` share
-- `federation_communities`); families and `self` have no listing plane.
--
-- The CHECK is the store's copy of the door's `envelope_listed_bad_value`
-- rule: `public` or NULL, nothing else. The door (every backend) refuses a
-- signer other than the member; the table cannot see that and does not try.

CREATE TABLE federation_community_membership_listings (
    community_key_id          TEXT NOT NULL REFERENCES federation_communities(community_key_id),
    member_key_id             TEXT NOT NULL REFERENCES federation_keys(key_id),
    effective_at              TEXT NOT NULL,
    listed                    TEXT CHECK (listed IS NULL OR listed = 'public'),
    persist_row_hash          TEXT NOT NULL,
    authority_key_id          TEXT,
    scrub_signature_classical TEXT,
    scrub_signature_pqc       TEXT,
    admitted_at               TEXT NOT NULL,
    PRIMARY KEY (community_key_id, member_key_id, effective_at)
);
CREATE INDEX federation_community_membership_listings_by_member
    ON federation_community_membership_listings (member_key_id);
CREATE INDEX federation_community_membership_listings_admitted
    ON federation_community_membership_listings
       (admitted_at, community_key_id, member_key_id, effective_at);
