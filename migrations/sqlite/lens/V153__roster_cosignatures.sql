-- V153 — co-signatures on the three membership-row planes
-- v49.0.0 (CIRISPersist#908, FSD ROOM_ROSTER_AUTHORITY.md §3)
--
-- POSTGRES PARITY: migrations/postgres/lens/V153__roster_cosignatures.sql
--
-- # Why
--
-- The CC admits a membership change by the group's `consensus_protocol`
-- evaluated over the change's SIGNATURES; `majority`, `unanimous` and
-- `quorum:M/N` need several. Each row carried exactly one signer. The signed
-- wire types gain `cosignatures` — hybrid scrubs by further signers over the
-- SAME `signing_envelope()` — and the door verifies every one.
--
-- # What changes
--
-- A `cosignatures` column (a JSON array of `RosterCosignature`, `'[]'` for a
-- single-signed or pre-V153 row) on the widening, community-revocation and
-- family-revocation tables. The signed since-reads serve it, so a co-signed
-- row replicates byte-exact; an empty array is omitted on the wire, so a
-- single-signed row's bytes and content hash are unchanged. Additive — a
-- plain ADD COLUMN with a constant default, no rebuild.
ALTER TABLE federation_community_membership_widenings
    ADD COLUMN cosignatures TEXT NOT NULL DEFAULT '[]';
ALTER TABLE federation_community_membership_revocations
    ADD COLUMN cosignatures TEXT NOT NULL DEFAULT '[]';
ALTER TABLE federation_family_membership_revocations
    ADD COLUMN cosignatures TEXT NOT NULL DEFAULT '[]';
