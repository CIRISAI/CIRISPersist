-- V152 — `consent_peer_set` is keyed by the machine a grant is FOR
-- v48.0.0 (CIRISPersist#905, ask 2)
--
-- POSTGRES PARITY: migrations/postgres/lens/V152__consent_peer_set_for_key.sql
--
-- # Why
--
-- V109 keyed the projection `(node_key_id, peer_key_id)`, written with
-- INSERT OR REPLACE: one live grant per (author, peer). Since v44.6.0
-- (#857, V147) a HUMAN authors the grants that cover a machine, naming the
-- machine in `for_key_id` — and a human bound to two machine keys (the split
-- install: node + actor) authors two grants toward one peer. The second
-- displaced the first here while `consent_peer_set_for` kept both, so the
-- attester-keyed readers (`list_live_consent_grants_by`, the promotion
-- sweep, CIRISServer's `live_consent_grants_for_machine`) disagreed with
-- `consent_peers_by_principals` about which grants are live — and withdrawing
-- the second silently dropped the human's peer row although the first still
-- stood.
--
-- # What changes
--
-- `for_key_id` joins the key: `(node_key_id, for_key_id, peer_key_id)`. A
-- grant that names no `for_key_id` (a machine's own self-grant) is keyed on
-- its author — the pre-#857 shape, unchanged. Backfilled from the source
-- attestation's envelope (`for_key_id` at the top level or under `payload`),
-- falling back to `node_key_id`. `list_consent_peers` (DISTINCT peers) and
-- every by-source delete are unchanged in meaning. Rebuilt under the
-- `_new` + RENAME shape: no FKs in either direction (V141's header).
CREATE TABLE consent_peer_set_new (
    node_key_id             TEXT NOT NULL,
    for_key_id              TEXT NOT NULL,
    peer_key_id             TEXT NOT NULL,
    source_attestation_id   TEXT NOT NULL,
    asserted_at             TEXT NOT NULL,
    PRIMARY KEY (node_key_id, for_key_id, peer_key_id)
);
INSERT OR REPLACE INTO consent_peer_set_new
    (node_key_id, for_key_id, peer_key_id, source_attestation_id, asserted_at)
SELECT c.node_key_id,
       COALESCE(json_extract(a.attestation_envelope, '$.for_key_id'),
                json_extract(a.attestation_envelope, '$.payload.for_key_id'),
                c.node_key_id),
       c.peer_key_id, c.source_attestation_id, c.asserted_at
  FROM consent_peer_set c
  LEFT JOIN federation_attestations a ON a.attestation_id = c.source_attestation_id;
DROP TABLE consent_peer_set;
ALTER TABLE consent_peer_set_new RENAME TO consent_peer_set;
CREATE INDEX consent_peer_set_by_source ON consent_peer_set (source_attestation_id);
