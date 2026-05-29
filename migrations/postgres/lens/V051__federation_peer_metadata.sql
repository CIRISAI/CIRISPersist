-- V051 — `federation_peer_metadata` sibling table (v3.1.0, CIRISPersist#117).
--
-- Lands the peer-mutation surface CIRISEdge v0.13.0 stubbed under
-- UniFFI's `PEER_MUTATION_FOLLOWUP` constant — the six operator-driven
-- writes (`add_peer_record`, `remove_peer_record`, `update_peer_alias`,
-- `update_peer_trust`, `update_peer_notes`, `update_peer_policy`).
--
-- # Sibling table, not in-place columns
--
-- `alias`, `trust`, `notes`, `policy_blob`, `transport_identity` are
-- **operator-local per-instance metadata** — one deployment's view of
-- a peer differs from another's (per CIRIS Accord §I operator-autonomy
-- framing). `federation_keys` carries the *federation-shared* identity
-- (pubkey + scrub envelope + identity_type — content that every
-- federation member sees identically). Mixing the two confuses the
-- trust boundary.
--
-- Sibling table with `key_id` PK + FK to `federation_keys ON DELETE
-- CASCADE` is the cleanest shape:
--   - `add_peer_record` inserts both rows in one transaction
--     (federation_keys row + this row with default trust='untrusted').
--   - `remove_peer_record(hard=false)` marks `removed_at`; reads
--     filter via `WHERE removed_at IS NULL`.
--   - `remove_peer_record(hard=true)` deletes the federation_keys row;
--     this row cascades.
--   - `update_*` methods bump `updated_at` + recompute
--     `persist_row_hash`.
--
-- # `transport_identity` is opaque to persist
--
-- The UniFFI-side `add_peer_record(... transport_identity)` carries
-- the opaque transport address / id (Reticulum destination hash, host
-- + port, etc.). Persist stores it verbatim; consumers parse if they
-- care. NULL when no transport is known (e.g., the peer was added by
-- pubkey-only attestation flow).
--
-- # `policy_blob` is opaque to persist
--
-- JSONB on Postgres so consumers can index against it operator-side
-- via expression indexes if they want, but persist itself never
-- introspects the shape. The CIRISEdge UniFFI `PeerPolicy` type is
-- the operator-facing shape; persist just round-trips the JSON.
--
-- # `trust` is a typed closed-set enum
--
-- CHECK constraint pins the vocabulary to `'untrusted' | 'trusted' |
-- 'restricted' | 'blocked'` — mirroring the Rust `TrustClass` enum's
-- `as_wire_str()`. Direct-SQL bypass still cannot land a malformed
-- value; defense-in-depth behind the typed
-- `FederationDirectory::update_peer_trust(TrustClass)` API.

BEGIN;

CREATE TABLE IF NOT EXISTS cirislens.federation_peer_metadata (
    -- Per-instance operator view of a federation peer. One row per
    -- federation_keys row that the operator has marked as a peer.
    -- (federation_keys rows that have NO sibling row in this table
    -- are "known by identity but not operator-managed as a peer" —
    -- e.g., transitively-discovered keys.)
    key_id              TEXT        NOT NULL PRIMARY KEY
        REFERENCES cirislens.federation_keys(key_id) ON DELETE CASCADE,

    -- Operator-local display name. Free-form; persist does not parse
    -- or constrain. NULL when no alias has been set.
    alias               TEXT        NULL,

    -- Operator's trust class for this peer. CHECK enforces the
    -- closed-set vocabulary so direct-SQL bypass cannot land a
    -- malformed value; the Rust `TrustClass` enum's `as_wire_str()`
    -- maps onto these constants 1:1.
    trust               TEXT        NOT NULL DEFAULT 'untrusted'
        CHECK (trust IN ('untrusted', 'trusted', 'restricted', 'blocked')),

    -- Operator-local notes (free-form). NULL when not set.
    notes               TEXT        NULL,

    -- Opaque consumer-defined policy blob. JSONB so operator-side
    -- expression indexes are possible; persist never introspects.
    policy_blob         JSONB       NULL,

    -- Opaque transport identity (Reticulum destination hash, host:port,
    -- ...). Carried verbatim from `add_peer_record(... transport_identity)`.
    -- NULL when no transport is known.
    transport_identity  TEXT        NULL,

    -- Soft-remove marker. NULL = live; non-NULL = `remove_peer_record`
    -- was called with `hard=false` at this wall-clock. Reads filter
    -- on `IS NULL` for the typical operator view; observability paths
    -- can still surface removed rows.
    removed_at          TIMESTAMPTZ NULL,

    -- Persist write-time wall-clock; separate from update bumps below.
    inserted_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Bumped on every `update_*` call. Lets operators see "when did
    -- I last touch this peer's metadata".
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Server-computed AV-row-hash (V004 discipline — sorted-keys
    -- canonicalization, sha256, hex). Recomputed on every mutation.
    persist_row_hash    TEXT        NOT NULL
);

-- ─── Indexes (operator hot paths) ──────────────────────────────────

-- "List my trusted peers" — partial index on live rows only.
CREATE INDEX IF NOT EXISTS idx_fpm_trust
    ON cirislens.federation_peer_metadata (trust)
    WHERE removed_at IS NULL;

-- "Look this peer up by the alias I gave it" — partial index, NULL
-- aliases skipped.
CREATE INDEX IF NOT EXISTS idx_fpm_alias
    ON cirislens.federation_peer_metadata (alias)
    WHERE alias IS NOT NULL;

COMMENT ON TABLE cirislens.federation_peer_metadata IS
    'v3.1.0 (CIRISPersist#117) — operator-local per-instance peer metadata. Sibling to federation_keys (FK with ON DELETE CASCADE). Carries alias/trust/notes/policy_blob/transport_identity for the six FederationDirectory::*_peer_* mutation methods that back CIRISEdge v0.13.0 UniFFI peer-mgmt. trust is enum-typed via CHECK; rest is opaque to persist.';

COMMIT;
