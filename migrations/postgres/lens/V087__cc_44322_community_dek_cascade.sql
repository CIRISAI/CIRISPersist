-- V087 — CC 4.4.3.2.1 / 4.4.3.2.2 community DEK cascade + rotation-on-
--        removal (CIRISPersist#237 v9.0.0 G5). SQLite parity: sqlite/lens/V087.
--
-- The CryptoTier::CommunityDek tier. Unlike the self/family
-- InvisibleEncrypted tier (a FRESH per-write DEK, V070), a community is
-- "a stream its members subscribe to, cryptographically" (CC 4.4.3.2.1):
-- ONE DEK shared across all emissions in a `(community_key_id, epoch)`,
-- wrapped to each member ONCE at epoch creation (per-emission cost O(1),
-- not O(members)). The blob bodies are AES-256-GCM-sealed under the epoch
-- DEK into the same self-describing CRBLOB envelope V070 uses and stored
-- in federation_blobs keyed on the ciphertext SHA-256.
--
-- Community content is NOT structurally invisible (suppresses_holds_bytes
-- is false) — it emits holds_bytes:sha256:* with cleartext provenance so
-- non-member holders make an informed keep/evict decision; the DEK is the
-- SOLE confidentiality boundary.
--
-- INFRASTRUCTURE OPT-OUT (CC 4.4.3.2.1, normative): a community with
-- cohort_subkind: infrastructure (ciris-canonical / governance roots)
-- opts OUT — Commons-tier plaintext, holds_bytes, NO DEK, no rows here.
-- The trust root must be publicly auditable. The cascade asserts this in
-- code; no infra community ever gets a federation_community_dek row.
--
-- ROTATION-ON-REMOVAL (CC 4.4.3.2.2, Option-A forward secrecy): on member
-- removal (put_community_membership_revocation) the community DEK epoch is
-- bumped (federation_community_dek_epoch.epoch += 1). The NEXT emission
-- mints a FRESH DEK for the new epoch wrapped only to the remaining
-- members — a removed member's keys cannot unwrap it. Forward-only: blobs
-- already sealed under the old epoch keep their grants (the removed member
-- keeps what they could already read; they receive no NEW community
-- content). This is a FLAT per-member re-wrap, deliberately NOT MLS
-- TreeKEM — full CC 5.1 TreeKEM (multicast/removal-coalescing) is the RET
-- transport layer's concern, not the substrate's.
--
-- This is substrate state, NOT a wire attestation — it never federates,
-- carries no signature (the secrets-path model, MISSION §1.4). All wraps
-- are wrap_algorithm: v2 (x25519_mlkem768_aes256_gcm_hkdf_sha256, FIPS
-- 203 hybrid) — NEVER v1 (CC 4.4.3.4.1 / CC 5.2 harvest-now-decrypt-later).
-- Refinery wraps this migration in its own transaction.

-- ── current epoch per community ────────────────────────────────────
-- The rotation counter. Bumped on member removal; the cascade reads it to
-- decide which `(community_key_id, epoch)` DEK to seal under. A community
-- with no row yet is epoch 0 (the cascade upserts on first emission).
CREATE TABLE IF NOT EXISTS cirislens.federation_community_dek_epoch (
    community_key_id  TEXT PRIMARY KEY,
    -- Monotonic; +1 on each member removal. The current sealing epoch.
    epoch             BIGINT NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    -- When the epoch last advanced (rotation audit).
    rotated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── per-epoch community DEK self-retention ─────────────────────────
-- One row per `(community_key_id, epoch)`: persist's own content-master
-- wrap of the shared epoch DEK, so read_for_community_viewer can recover
-- the DEK (the V070 OQ-4 self-retention discipline, applied per-epoch
-- rather than per-write). wrapped_dek is base64 of
-- nonce(12) || aes256_gcm(content_master, dek). Minted once per epoch
-- (first emission in the epoch); first-write-wins on the PK.
CREATE TABLE IF NOT EXISTS cirislens.federation_community_dek (
    community_key_id  TEXT NOT NULL,
    epoch             BIGINT NOT NULL CHECK (epoch >= 0),
    -- Always 'aes256_gcm_content_master' (persist self-retention of the
    -- epoch DEK). The per-member delivery wraps live in the grants table.
    wrap_algorithm    TEXT NOT NULL
        CHECK (wrap_algorithm IN ('aes256_gcm_content_master')),
    wrapped_dek       TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_key_id, epoch)
);

-- ── per-member epoch DEK grants ────────────────────────────────────
-- The cascade fan-out: one row per `(community_key_id, epoch, member
-- occurrence)` — the shared epoch DEK wrapped to that member's
-- encryption_pubkeys via wrap_algorithm: v2. Written ONCE at epoch
-- creation (O(members) once per epoch, not per emission). A member with
-- no valid ML-KEM-768 gets NO row (fail-secure exclude; the cascade emits
-- hard_case:recipient_excluded) — never plaintext, never v1.
CREATE TABLE IF NOT EXISTS cirislens.federation_community_dek_member_grants (
    community_key_id      TEXT NOT NULL,
    epoch                 BIGINT NOT NULL CHECK (epoch >= 0),
    -- The member occurrence's federation key_id (an occurrence key).
    member_key_id         TEXT NOT NULL,
    -- Always 'x25519_mlkem768_aes256_gcm_hkdf_sha256' (v2 hybrid). The
    -- CHECK is the substrate's v2-ONLY guarantee — no v1 row can exist.
    wrap_algorithm        TEXT NOT NULL
        CHECK (wrap_algorithm IN ('x25519_mlkem768_aes256_gcm_hkdf_sha256')),
    -- The KeyGrantWrapV2 JSON envelope.
    wrapped_dek           TEXT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_key_id, epoch, member_key_id)
);

-- "which epochs is this member granted on?" (read-side authorization).
CREATE INDEX IF NOT EXISTS federation_community_dek_member_grants_by_member
    ON cirislens.federation_community_dek_member_grants (member_key_id);

-- ── blob → community/epoch binding ─────────────────────────────────
-- Maps a stored at-rest ciphertext to the `(community_key_id, epoch)`
-- whose DEK sealed it, so a read recovers the right epoch DEK. A blob is
-- sealed under exactly one epoch (the one current at emission time);
-- later rotation does NOT re-seal it (forward-only).
CREATE TABLE IF NOT EXISTS cirislens.federation_community_blob_epoch (
    at_rest_sha256    BYTEA PRIMARY KEY
        CHECK (octet_length(at_rest_sha256) = 32),
    community_key_id  TEXT NOT NULL,
    epoch             BIGINT NOT NULL CHECK (epoch >= 0),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
