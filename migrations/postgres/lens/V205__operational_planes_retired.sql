-- V205 — the three operational planes retire onto affiliation rows.
-- Postgres dialect. v60.0.0 (CIRISPersist#1036 item 4; CC 3.3.9 rc9,
-- CIRISConstitution#161).
--
-- SQLITE PARITY: migrations/sqlite/lens/V205__operational_planes_retired.sql
--
-- WHY
-- ---
-- An organisation is an affiliation. CC 3.3.9 moves the three operational
-- subject_kinds onto the rows every community already uses: an
-- `organization` is a community record at `cohort_scope: affiliations`, an
-- `org_membership` is a `membership:{stage}` seat plus a hierarchy
-- `delegates_to` edge, and a `partner_record` is a
-- `licensure:{community_key_id}:v1` row carrying the typed licence payload
-- (`operational::PartnerRecord`, in the attestation store). Their typed
-- tables, write doors and replication kinds (`Organization`,
-- `OrgMembership`, `PartnerRecord`, now in `RETIRED_FRAMED`) go in the same
-- cut. No Portal data exists to migrate (operator ruling, v60 plan S6).
--
-- HOW
-- ---
-- * The three tables (V071, V072 steward-signature columns, V130/V141
--   serve positions) are dropped. Nothing references them: no foreign key
--   points at them and no trigger reads them, so the drops fire nothing.
--   Their own indexes go with them.
-- * The wire-index rows of the three kinds (V111 `signed_wire_index`) and
--   any peer advertisement of them (V134 `known_wire_hashes`) are deleted: a
--   kind with no door has nothing to serve and nothing to fetch.
-- Forward-only, like every migration here.

DROP TABLE cirislens.federation_partner_records;
DROP TABLE cirislens.federation_org_memberships;
DROP TABLE cirislens.federation_organizations;

DELETE FROM cirislens.signed_wire_index
 WHERE kind IN ('Organization', 'OrgMembership', 'PartnerRecord');

DELETE FROM cirislens.known_wire_hashes
 WHERE kind IN ('Organization', 'OrgMembership', 'PartnerRecord');
