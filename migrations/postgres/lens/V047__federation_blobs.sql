-- V047 — Content-addressable federation_blobs storage (CIRISPersist#103).
--
-- Adds the byte-storage substrate that SHA-256 evidence_refs[]
-- elsewhere in the federation resolve to. Companion to CIRISEdge#21
-- (ContentFetch transport) and CIRISRegistry#18 (agent_files:*
-- attestation surface).
--
-- # Architectural shape
--
-- The federation directory already names what exists (federation_keys
-- / federation_attestations / federation_revocations). This migration
-- adds where the BYTES live, content-addressed by SHA-256:
--
--   federation_blobs(sha256 PK) ←─── holds_bytes:sha256:<prefix>
--       │                              attestations on
--       │                              federation_attestations
--       │                              (auto-emitted by put_blob)
--       ▼
--   Inline bytes / S3 URI / external URL — caller's policy decides
--   the cutover threshold (default 1 MB; configurable via Engine
--   builder).
--
-- # Schema (per issue body)
--
--   sha256        BYTEA PRIMARY KEY     — exactly 32 bytes
--   storage_kind  TEXT NOT NULL         — 'inline' | 's3' | 'external_url'
--   bytes_inline  BYTEA NULL            — present iff storage_kind='inline'
--   external_ref  TEXT NULL             — S3 URI / external URL otherwise
--   size_bytes    BIGINT NOT NULL       — full content size
--   media_type    TEXT NULL             — informational; app/octet-stream default
--   first_seen_at TIMESTAMPTZ NOT NULL  — DEFAULT NOW()
--   regions_held  TEXT[] NOT NULL       — DEFAULT '{}' per-region replication
--
-- # CHECKs (defense in depth — API enforces, schema catches drift)
--
--   - sha256 length = 32 bytes
--   - storage_kind enum
--   - inline iff bytes_inline present
--   - external_ref present iff storage_kind in ('s3','external_url')
--   - size_bytes >= 0
--
-- # GC discipline (v0.1)
--
-- This migration ships **without** GC. Blobs persist forever. The
-- trait deliberately exposes NO `delete_blob`. A future migration
-- will add reference counting + a `prune_blobs(min_age)` API; until
-- then operators run space-management policy outside persist.
--
-- # Spock replication
--
-- The `federation_blobs` table joins the default repset (federation
-- substrate tier). No special replication rules — blobs cohere via
-- the SHA PK and are write-once.

-- ── federation_blobs table ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cirislens.federation_blobs (
    -- Content address. SHA-256 over the byte payload. Exactly 32
    -- bytes (256 bits). Length CHECK is defense in depth — the
    -- put_blob API path hashes the bytes and rejects mismatches
    -- before reaching the DB; the CHECK catches direct-DB writes.
    sha256        BYTEA PRIMARY KEY
        CHECK (octet_length(sha256) = 32),

    -- How the bytes are stored. 'inline' = bytes_inline column;
    -- 's3' = external_ref carries an S3 URI; 'external_url' =
    -- external_ref carries a plain HTTP(S) URL.
    storage_kind  TEXT NOT NULL
        CHECK (storage_kind IN ('inline', 's3', 'external_url')),

    -- Inline byte payload. Present iff storage_kind='inline'.
    -- bytes_inline.length() does NOT have to equal size_bytes (a
    -- larger blob could be inlined for a small deployment, or the
    -- caller could be lying — the size_bytes is the routing hint,
    -- not the authoritative length; put_blob enforces consistency).
    bytes_inline  BYTEA,

    -- External reference. S3 URI (s3://bucket/key) or HTTP(S) URL.
    -- Present iff storage_kind in ('s3','external_url').
    external_ref  TEXT,

    -- Full payload size in bytes. Used by routing logic to decide
    -- whether to fetch inline vs stream externally.
    size_bytes    BIGINT NOT NULL CHECK (size_bytes >= 0),

    -- Informational. Caller-supplied; persist does not validate the
    -- string. Defaults to NULL — the wire shape treats that as
    -- "application/octet-stream".
    media_type    TEXT,

    -- First-seen timestamp. Wall-clock at insert time.
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Per-region replication tracking. Free-form region names; the
    -- federation deployer's regional naming convention applies.
    -- Empty array = no region-specific tracking yet.
    regions_held  TEXT[] NOT NULL DEFAULT '{}',

    -- Defense-in-depth: storage_kind ↔ which column carries the body.
    -- Mirrors the put_blob API rejection so a direct-DB write that
    -- skips the API path can't land an inconsistent row either.
    CONSTRAINT federation_blobs_storage_kind_columns_match
        CHECK (
            (storage_kind = 'inline'
                AND bytes_inline IS NOT NULL
                AND external_ref IS NULL)
            OR
            (storage_kind IN ('s3', 'external_url')
                AND bytes_inline IS NULL
                AND external_ref IS NOT NULL)
        )
);

-- size_bytes index for "what blobs are bigger than X" routing decisions.
CREATE INDEX IF NOT EXISTS federation_blobs_size_bytes
    ON cirislens.federation_blobs (size_bytes);

-- first_seen_at index for time-window queries (newest blobs, etc.).
CREATE INDEX IF NOT EXISTS federation_blobs_first_seen_at
    ON cirislens.federation_blobs (first_seen_at DESC);

COMMENT ON TABLE cirislens.federation_blobs IS
    'v2.3 (CIRISPersist#103) — Content-addressable byte storage. SHA-256-keyed; storage_kind chooses inline vs s3 vs external_url. Holders are tracked via holds_bytes:sha256:<8-hex-prefix> attestations on federation_attestations (auto-emitted by put_blob). No GC in v0.1; blobs persist forever (deferred to a follow-up issue).';

COMMENT ON COLUMN cirislens.federation_blobs.sha256 IS
    'SHA-256 content hash, 32 bytes raw. Primary key — put_blob is idempotent on SHA collision (first-write-wins on storage_kind).';

COMMENT ON COLUMN cirislens.federation_blobs.storage_kind IS
    'How the bytes are stored: inline (bytes_inline) | s3 (external_ref) | external_url (external_ref). First-write-wins on conflict — see put_blob doc.';
