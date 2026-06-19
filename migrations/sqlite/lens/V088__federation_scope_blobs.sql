-- V088 — CC 1.13.3 anonymous-tier scope-native-privacy symbol store,
--        SQLite dialect (CIRISPersist#243 parts 1+2, v9.1.0).
--
-- Postgres parity (postgres/lens/V088): BYTEA → BLOB, BIGINT → INTEGER,
-- TIMESTAMPTZ → TEXT (ISO8601, RFC 3339). SQLite has no DEFAULT NOW();
-- the application supplies admitted_at / last_accessed_at on the put path
-- (see put_scope_blob in store/sqlite.rs), exactly as the federation_blobs
-- V053 access-tracking path does.
--
-- See postgres/lens/V088 for the full rationale: a store for
-- caller-pre-encrypted (XChaCha20-Poly1305) RaptorQ symbols at
-- community/family/self scope (FSD §2.4); persist stores opaque ciphertext
-- only (verify stays v6.2.0 — zero verify-crypto dependency in this slice);
-- PK (record_id, symbol_index); LRU + capacity eviction (no trust-scoring).

CREATE TABLE IF NOT EXISTS federation_scope_blobs (
    -- FSD §2.4 HMAC-SHA3-256 record identifier (32 bytes).
    record_id        BLOB NOT NULL,
    -- 0..N symbol index within the record (N=20 default).
    symbol_index     INTEGER NOT NULL CHECK (symbol_index >= 0),
    -- XChaCha20-Poly1305 nonce (24 bytes, CSPRNG, caller-supplied).
    nonce            BLOB NOT NULL,
    -- Pre-encrypted symbol bytes (opaque to the substrate).
    ciphertext       BLOB NOT NULL,
    -- Poly1305 tag (16 bytes, caller-supplied).
    tag              BLOB NOT NULL,
    -- The community DEK epoch the symbol was sealed under.
    group_dek_epoch  INTEGER NOT NULL CHECK (group_dek_epoch >= 0),
    -- Write wall-clock (ISO8601; audit + secondary eviction tiebreak).
    admitted_at      TEXT NOT NULL,
    -- LRU signal (ISO8601): most-recent read wall-clock. Bumped on read.
    last_accessed_at TEXT NOT NULL,
    PRIMARY KEY (record_id, symbol_index)
);

-- Admission-order index (audit / oldest-first scans).
CREATE INDEX IF NOT EXISTS idx_federation_scope_blobs_admitted
    ON federation_scope_blobs (admitted_at ASC);

-- LRU eviction index: the capacity sweeper scans ASC so the index returns
-- coldest (oldest-read) symbols first — single index walk, no re-sort.
CREATE INDEX IF NOT EXISTS idx_federation_scope_blobs_accessed
    ON federation_scope_blobs (last_accessed_at ASC);
