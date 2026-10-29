-- V207 — the six framed group kinds retire; their rows ride the attestation
-- plane. SQLite dialect. v61 (CIRISPersist#991; CC 3.1.3, CC 3.1.3.2).
--
-- POSTGRES PARITY: migrations/postgres/lens/V207__group_framed_kinds_retired.sql
--
-- WHY
-- ---
-- A family's or community's record and its widening and revocation planes are
-- `group:roster:v1` / `membership:{widening,removal,resignation}:v1` rows
-- (V206): they are served, advertised and fetched as `Attestation` entries.
-- The framed kinds `Family`, `Community`, `FamilyMembershipRevocation`,
-- `CommunityMembershipRevocation`, `CommunityMembershipWidening` and
-- `FamilyMembershipWidening` joined `RETIRED_FRAMED`: nothing indexes, serves
-- or fetches them any more.
--
-- HOW
-- ---
-- Their wire-index rows (V111 `signed_wire_index`) and any peer advertisement
-- of them (V134 `known_wire_hashes`) are deleted: a kind with no door has
-- nothing to serve and nothing to fetch. The six tables stay, as the rows'
-- projections. Forward-only, like every migration here.

DELETE FROM signed_wire_index
 WHERE kind IN ('Family', 'Community', 'FamilyMembershipRevocation',
                'CommunityMembershipRevocation', 'CommunityMembershipWidening',
                'FamilyMembershipWidening');

DELETE FROM known_wire_hashes
 WHERE kind IN ('Family', 'Community', 'FamilyMembershipRevocation',
                'CommunityMembershipRevocation', 'CommunityMembershipWidening',
                'FamilyMembershipWidening');
