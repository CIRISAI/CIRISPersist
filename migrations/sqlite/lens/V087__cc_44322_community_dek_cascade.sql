-- V087 — CC 4.4.3.2.1 / 4.4.3.2.2 community DEK cascade + rotation-on-
--        removal (CIRISPersist#237 v9.0.0 G5) — SQLite dialect. Postgres
--        parity: postgres/lens/V087. See that file for the full design
--        rationale (one shared per-epoch DEK, infrastructure opt-out,
--        rotation-on-removal Option-A forward secrecy, v2-only).
--
-- A community is "a stream its members subscribe to, cryptographically"
-- (CC 4.4.3.2.1): ONE DEK shared across all emissions in a
-- `(community_key_id, epoch)`, wrapped to each member ONCE at epoch
-- creation. Member removal bumps the epoch; the next emission mints a
-- fresh DEK wrapped only to remaining members (flat re-wrap, NOT TreeKEM).
-- All wraps are wrap_algorithm: v2 — NEVER v1. Substrate state, never
-- federates. Refinery wraps this migration in its own transaction.

-- ── current epoch per community ────────────────────────────────────
CREATE TABLE IF NOT EXISTS federation_community_dek_epoch (
    community_key_id  TEXT PRIMARY KEY,
    epoch             INTEGER NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    rotated_at        TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);

-- ── per-epoch community DEK self-retention (OQ-4, per epoch) ────────
CREATE TABLE IF NOT EXISTS federation_community_dek (
    community_key_id  TEXT NOT NULL,
    epoch             INTEGER NOT NULL CHECK (epoch >= 0),
    wrap_algorithm    TEXT NOT NULL
        CHECK (wrap_algorithm IN ('aes256_gcm_content_master')),
    wrapped_dek       TEXT NOT NULL,
    created_at        TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    PRIMARY KEY (community_key_id, epoch)
);

-- ── per-member epoch DEK grants (v2-only; fail-secure exclude) ──────
CREATE TABLE IF NOT EXISTS federation_community_dek_member_grants (
    community_key_id      TEXT NOT NULL,
    epoch                 INTEGER NOT NULL CHECK (epoch >= 0),
    member_key_id         TEXT NOT NULL,
    wrap_algorithm        TEXT NOT NULL
        CHECK (wrap_algorithm IN ('x25519_mlkem768_aes256_gcm_hkdf_sha256')),
    wrapped_dek           TEXT NOT NULL,
    created_at            TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    PRIMARY KEY (community_key_id, epoch, member_key_id)
);

CREATE INDEX IF NOT EXISTS federation_community_dek_member_grants_by_member
    ON federation_community_dek_member_grants (member_key_id);

-- ── blob → community/epoch binding ─────────────────────────────────
CREATE TABLE IF NOT EXISTS federation_community_blob_epoch (
    at_rest_sha256    BLOB PRIMARY KEY
        CHECK (length(at_rest_sha256) = 32),
    community_key_id  TEXT NOT NULL,
    epoch             INTEGER NOT NULL CHECK (epoch >= 0),
    created_at        TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);
