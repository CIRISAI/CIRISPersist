-- V147 (CIRISPersist#857, FSD/CONSENT_BY_HUMANS.md §4) — the
-- `consent_peer_set_for` projection: a HUMAN-authored
-- `consent:replication:v1` grant names, in its payload's `for_key_id`, the
-- machine whose traces it is for. This table is that projection: one row per
-- `subject_key_ids[]` peer, keyed `(author_key_id, for_key_id, peer_key_id)`,
-- maintained IN the same write as the attestation insert and deleted by the
-- same revocation fold as V109's `consent_peer_set` (see
-- `sqlite_project_consent_peer_set`). SQLite dialect. Postgres parity:
-- postgres/lens/V147.
--
-- V109 is untouched: its key `(node_key_id, peer_key_id)` would collide for a
-- human granting two agents to one peer, and `list_consent_peers`'s exact
-- semantics are a contract. `list_consent_peers_for(k)` reads THIS table;
-- `consent_peers_by_principals(k)` unions the two, filtered to live stewards.
CREATE TABLE consent_peer_set_for (
    author_key_id           TEXT NOT NULL,
    for_key_id              TEXT NOT NULL,
    peer_key_id             TEXT NOT NULL,
    source_attestation_id   TEXT NOT NULL,
    asserted_at             TEXT NOT NULL,   -- RFC-3339 UTC
    PRIMARY KEY (author_key_id, for_key_id, peer_key_id)
);
CREATE INDEX consent_peer_set_for_by_for_key
    ON consent_peer_set_for (for_key_id);
CREATE INDEX consent_peer_set_for_by_source
    ON consent_peer_set_for (source_attestation_id);
