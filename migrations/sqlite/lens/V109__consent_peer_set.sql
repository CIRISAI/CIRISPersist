-- V109 (CIRISPersist#502 E7) — the `consent_peer_set` projection: the
-- node's LIVE `consent:replication:v1` peer grants, revocation-folded.
-- SQLite dialect. Postgres parity: postgres/lens/V109.
--
-- `consent:replication:v1` is a directed `scores` attestation: the node
-- attests it (`attesting_key_id` = node), and the peers it consents to
-- replicate to ride `subject_key_ids`. CIRISServer's
-- `replication_peers_from_consent` (`src/peer.rs`, `CONSENT_DIMENSION =
-- "consent:replication:v1"`) read this via `list_attestations_by(node) →
-- filter dimension == CONSENT_DIMENSION → flat_map(subject_key_ids)` — but
-- never folded a subsequent `withdraws`/`recants` against the grant, so a
-- peer whose consent was revoked kept receiving replication forever
-- (server-side `TODO(consent revocation)`).
--
-- `put_attestation` maintains this table IN the same write as the
-- attestation insert (mirrors the V106 `attestation_subjects` projection;
-- see `sqlite_project_consent_peer_set`):
--   - a `consent:replication:v1` grant upserts one row per
--     `subject_key_ids[]` peer, `(node_key_id, peer_key_id)` keyed;
--   - a `withdraws`/`recants` whose `references_attestation_id` names a
--     grant DELETEs every row this projection sourced from that grant
--     (matched on `source_attestation_id`).
--
-- DERIVED / rebuildable: this table is a read accelerator over
-- `federation_attestations`, not new authority — droppable and
-- reconstructable at any time from a full replay of the
-- `consent:replication:v1` grants and their withdraws/recants. A server
-- read becomes a trivial already-revocation-filtered SELECT.
CREATE TABLE consent_peer_set (
    node_key_id             TEXT NOT NULL,
    peer_key_id             TEXT NOT NULL,
    source_attestation_id   TEXT NOT NULL,
    asserted_at             TEXT NOT NULL,   -- RFC-3339 UTC
    PRIMARY KEY (node_key_id, peer_key_id)
);
