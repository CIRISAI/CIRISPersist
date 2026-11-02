-- V209 — the member listing retires with no successor. SQLite dialect. v61
-- (CIRISPersist#991; the steward's final ruling: no outward member listing,
-- and CC removes `listed`).
--
-- POSTGRES PARITY: migrations/postgres/lens/V209__member_listing_retired.sql
--
-- WHY
-- ---
-- V156 made CC 2's per-membership `listed` opt-in a signed plane
-- (`federation_community_membership_listings`, the 19th wire kind,
-- `CommunityMembershipListing`), and `listed_members` served it to
-- non-members. The ruling removes the outward listing, so nothing reads the
-- plane and nothing may serve it. The kind joined `RETIRED_FRAMED`. A row
-- kept with no reader would be a member's disclosure that this node stores
-- and never honours, so the table goes. A from-disk count of five upgraded
-- local nodes found no rows.
--
-- HOW
-- ---
-- The kind's wire-index rows (V111 `signed_wire_index`) and peer
-- advertisements (V134 `known_wire_hashes`) are deleted, then the table is
-- dropped. Nothing references it. Forward-only, like every migration here.

DELETE FROM signed_wire_index WHERE kind = 'CommunityMembershipListing';

DELETE FROM known_wire_hashes WHERE kind = 'CommunityMembershipListing';

DROP TABLE IF EXISTS federation_community_membership_listings;
