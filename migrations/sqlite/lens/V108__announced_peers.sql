-- V108 (CIRISPersist#469) — the seeder bridge: announced/advisory LAN peers as
-- NON-canonical, UNTRUSTED discovery bookmarks.
--
-- A self-consistent LAN announce that does NOT root in the directory
-- (`root_binding` → UnknownKeyId) is admitted by edge as an Advisory routing
-- hint only; before V108 it left no directory-visible trace, so the server's
-- `GET /v1/federation/peers` never surfaced it (CIRISEdge#362).
--
-- DELIBERATELY A SEPARATE TABLE, NOT a `federation_keys` row / identity_type:
-- invariant 2 of #469 ("must never satisfy a quorum/authority check") is
-- enforced BY CONSTRUCTION — no admission, quorum, rooting, or
-- list_keys_by_identity_type path can see this table, so no exclusion audit of
-- existing authority queries is needed. NO FK to federation_keys: the whole
-- point is that this key is NOT in the directory. A bookmark is superseded on
-- the READ side (anti-join in list_announced_peers) the moment the same key_id
-- roots for real — no hook in the put_public_key admission gate.
CREATE TABLE announced_peers (
    key_id                  TEXT PRIMARY KEY,
    pubkey_ed25519_base64   TEXT NOT NULL,
    pubkey_ml_dsa_65_base64 TEXT,             -- announce may carry the PQC half
    -- The identity_type CLAIMED by the announce. Advisory display data only —
    -- unverified, never an authority input.
    claimed_identity_type   TEXT,
    first_seen_at           TEXT NOT NULL,    -- RFC-3339 UTC
    last_seen_at            TEXT NOT NULL,    -- RFC-3339 UTC, refreshed per announce
    announce_count          INTEGER NOT NULL DEFAULT 1
);
