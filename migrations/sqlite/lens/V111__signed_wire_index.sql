-- V111 (CIRISPersist#507b) — the shared signed-wire content-hash index.
-- SQLite dialect. Postgres parity: postgres/lens/V111.
--
-- ONE table covers every kind CIRISEdge serves: the 5 primary signed planes
-- (Key/Attestation/IdentityOccurrence/TransportDestination/
-- IdentityOccurrenceRevocation, CIRISPersist#507c), the 5 E4
-- keyless-declaration planes (Family/Community/LocationProof/
-- FamilyMembershipRevocation/CommunityMembershipRevocation, #504), and the
-- operational trio (Organization/OrgMembership/PartnerRecord) — 13 of the 14
-- `replication_policy::EnvelopeKind`s (`Revocation`, the key-level
-- revocation plane, is out of #507's scope).
--
-- `kind`          — the `EnvelopeKind::as_str()` token (e.g. "Key",
--                    "Attestation", "Family"); NOT a foreign key, just the
--                    wire-vocabulary string pinned by `REPLICATION_POLICY_HASH`.
-- `content_hash`  — lowercase-hex sha256 over `serde_json::to_vec` of the
--                    exact record the corresponding `list_signed_*_since` /
--                    `list_attestations_since` read returns (the lockstep
--                    fact edge's fetch-map hash is built to match).
-- `record_key`    — a kind-specific JSON object (e.g. `{"key_id": "..."}`,
--                    `{"identity_key_id": "...", "occurrence_key_id": "..."}`)
--                    sufficient for `lookup_signed_record_by_content_hash` to
--                    reload the record without a second index.
--
-- Maintained at each signed-record write chokepoint (see
-- `federation::wire_index`); `rebuild_signed_wire_index` is the
-- upgrade/backfill path for rows written before this migration. Refinery
-- wraps this in its own transaction.

CREATE TABLE signed_wire_index (
    kind            TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    record_key      TEXT NOT NULL,
    PRIMARY KEY (kind, content_hash)
);
