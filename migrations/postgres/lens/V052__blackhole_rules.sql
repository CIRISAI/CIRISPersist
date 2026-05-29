-- V052 — `cirislens.blackhole_rules` durable per-identity deny-list
-- (v3.2.0, CIRISPersist#120). Unblocks CIRISEdge v0.15.0 routing-table
-- FFI (CIRISEdge#33) — the send-path "should I drop envelopes addressed
-- to / received from this Reticulum identity?" check.
--
-- # Why a sibling table (not columns on federation_keys)
--
-- A blackhole entry is keyed by a 16-byte Reticulum *identity hash*,
-- not by a federation `key_id`. The two namespaces are independent:
--
--   * `federation_keys.key_id` is the federation-shared cryptographic
--     identity (Ed25519+ML-DSA-65 hybrid pubkey).
--   * A Reticulum identity hash is a transport-layer address.
--     CIRISEdge's `ReticulumTransport` looks it up on every recv/send.
--
-- The same operator may want to blackhole a Reticulum identity it
-- has never bound to a federation_keys row (e.g., a peer broadcasting
-- noise before any cryptographic relationship was ever established).
-- Coupling the two would conflate "this transport address is hostile"
-- with "this cryptographic identity is hostile" — different concerns,
-- different lifetimes.
--
-- # No CHECK on identity_hash length
--
-- The issue specifies 16 bytes (Reticulum's current destination-hash
-- size), but the constraint lives at the API surface (`BlackholeRules`
-- trait — `Error::InvalidArgument` when `identity_hash.len() != 16`).
-- A SQL-side CHECK would force a schema rewrite if Reticulum ever
-- widens the hash format. The API guard is sufficient defense-in-
-- depth for direct-SQL bypass (operators with raw SQL access are
-- already inside the trust boundary).
--
-- # `(until) WHERE until IS NOT NULL` partial index
--
-- `prune_expired` walks rows whose `until` is non-NULL and in the
-- past. Permanent rules (until IS NULL) are the common case and
-- never participate in the prune scan. Partial index on the non-NULL
-- subset keeps the prune fast even at federation scale.
--
-- # `hits` is commutative; not transactional
--
-- `record_hit` is a single-statement `UPDATE … SET hits = hits + 1`.
-- A race between two writers double-incrementing is the desired
-- behavior — the counter is a hot-path observation field, not a
-- consensus value. Persist does NOT batch on the caller's behalf;
-- callers concerned about latency may accumulate hits client-side
-- and flush periodically.

BEGIN;

CREATE TABLE IF NOT EXISTS cirislens.blackhole_rules (
    -- 16-byte Reticulum identity hash (PK). API-layer guard enforces
    -- length; no SQL-side CHECK so a future Reticulum width change is
    -- a no-migration concern.
    identity_hash    BYTEA       NOT NULL PRIMARY KEY,

    -- Soft-expiry. NULL = permanent rule; the operator must remove it
    -- explicitly. Non-NULL = expire at this wall-clock (the partial
    -- index supports `prune_expired` without scanning permanents).
    until            TIMESTAMPTZ NULL,

    -- Operator-readable reason. Free-form; persist does not parse.
    reason           TEXT        NULL,

    -- First-banned-at wall-clock. Preserved across `upsert` so
    -- operators can ask "how long has this rule been in effect?".
    added_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Hot-path observation counter. `record_hit` increments. Preserved
    -- across re-upsert (a re-upsert means "operator changed the reason
    -- / expiry", NOT "reset the counter").
    hits             BIGINT      NOT NULL DEFAULT 0,

    -- Server-computed AV-row-hash (V004 discipline — sorted-keys
    -- canonicalization, sha256, hex). Recomputed on every mutation
    -- except `record_hit` (which is a single-counter increment with
    -- no operator-meaning change — hashing would force every send-
    -- path call to re-canonicalize for no audit benefit).
    persist_row_hash TEXT        NOT NULL
);

-- `prune_expired` hot-path index. Partial: permanent rules
-- (until IS NULL) are NOT indexed here, keeping the index small
-- even when the bulk of rules are permanent.
CREATE INDEX IF NOT EXISTS idx_blackhole_until
    ON cirislens.blackhole_rules (until)
    WHERE until IS NOT NULL;

COMMENT ON TABLE cirislens.blackhole_rules IS
    'v3.2.0 (CIRISPersist#120) — operator-driven per-identity deny-list keyed by 16-byte Reticulum identity_hash. Sibling to federation_keys (no FK; transport identities exist independently of cryptographic identities). until=NULL means permanent. hits is a non-transactional observation counter; record_hit is commutative.';

COMMIT;
