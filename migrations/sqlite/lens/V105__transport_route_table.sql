-- V105 — CIRISPersist#443: transport_destinations becomes a well-formed
--        superseding route table. SQLite dialect. Postgres parity:
--        postgres/lens/V105.
--
-- The V078/V101 PK was (occurrence_key_id, transport_kind, destination) — an
-- append-only multi-claim set: a route CHANGE (dest-hash rotation) has a
-- different `destination`, so it inserted a NEW row and the stale route lived
-- forever. #443 makes the authoritative key (occurrence_key_id,
-- transport_kind) and demotes `destination` to a NOT NULL payload column: one
-- route per (peer, kind), superseded in place.
--
-- New columns:
--   epoch            — the durable monotonic supersession counter (the edge
--                      RootedPeer.epoch finally has a home). Supersession is
--                      (epoch, asserted_at)-lexicographic, so mesh convergence
--                      no longer rides wall clocks alone.
--   retired_at       — the replicated tombstone: a route retired via a signed
--                      put (higher epoch) stays retired against older gossip.
--   attesting_key_id / signed_envelope / signature — the detached signature
--                      container of a SIGNED put (the V102/V103 discipline),
--                      byte-exact for replication re-publish. NULL for
--                      trusted-local rows.
--
-- Collapse rule for pre-existing duplicate rows per (occ, kind): keep the
-- newest `asserted_at`; tie-break = lexicographically greatest `destination`
-- (deterministic across backends).
--
-- SQLite can't ALTER a PRIMARY KEY, so recreate the table (the V101 pattern):
-- new table → copy collapsed rows → drop → rename → recreate index. Refinery
-- wraps this in its own transaction.

CREATE TABLE transport_destinations_new (
    occurrence_key_id               TEXT NOT NULL,
    transport_kind                  TEXT NOT NULL,
    destination                     TEXT NOT NULL,   -- payload since V105 (#443)
    asserted_at                     TEXT NOT NULL,   -- RFC-3339 UTC
    last_seen_at                    TEXT,            -- RFC-3339 UTC, advisory
    transport_ed25519_pubkey_base64 TEXT,            -- V098 (#397)
    transport_x25519_pubkey_base64  TEXT,            -- V099 (#411)
    binding_provenance              TEXT NOT NULL DEFAULT 'rooted',  -- V100 (#413)
    epoch                           INTEGER NOT NULL DEFAULT 0,      -- V105 (#443)
    retired_at                      TEXT,            -- V105 (#443), RFC-3339 UTC
    attesting_key_id                TEXT,            -- V105 (#443)
    signed_envelope                 TEXT,            -- V105 (#443), byte-exact JSON
    signature                       TEXT,            -- V105 (#443), hybrid detached sig
    PRIMARY KEY (occurrence_key_id, transport_kind)
);

INSERT INTO transport_destinations_new
    (occurrence_key_id, transport_kind, destination, asserted_at, last_seen_at,
     transport_ed25519_pubkey_base64, transport_x25519_pubkey_base64, binding_provenance)
SELECT
     occurrence_key_id, transport_kind, destination, asserted_at, last_seen_at,
     transport_ed25519_pubkey_base64, transport_x25519_pubkey_base64, binding_provenance
FROM (
    SELECT *, ROW_NUMBER() OVER (
        PARTITION BY occurrence_key_id, transport_kind
        ORDER BY asserted_at DESC, destination DESC
    ) AS rn
    FROM transport_destinations
)
WHERE rn = 1;

DROP TABLE transport_destinations;
ALTER TABLE transport_destinations_new RENAME TO transport_destinations;

CREATE INDEX transport_destinations_by_occurrence
    ON transport_destinations (occurrence_key_id);
