-- V168 — one DEK per (stream, epoch) for self/family chunk streams
-- v53.0.0 (CIRISPersist#969, FSD BLOB_ENCRYPTION_AT_REST.md §12.12,
-- BLOB_REPLICATION.md §14.1)
--
-- SQLITE PARITY: migrations/sqlite/lens/V168__stream_epoch_deks.sql
-- (that file's header carries the reasoning; this one carries the DDL).
CREATE TABLE IF NOT EXISTS cirislens.federation_stream_deks (
    stream_id             TEXT NOT NULL,
    epoch                 BIGINT NOT NULL CHECK (epoch >= 0),
    owner_key_id          TEXT NOT NULL,
    cohort_scope          TEXT NOT NULL CHECK (cohort_scope IN ('self', 'family')),
    group_key_id          TEXT NOT NULL,
    self_retention_wrap   TEXT NOT NULL,
    minted_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at             TIMESTAMPTZ,
    terminated_at         TIMESTAMPTZ,
    key_grant_emitted_at  TIMESTAMPTZ,
    PRIMARY KEY (stream_id, epoch)
);

CREATE TABLE IF NOT EXISTS cirislens.federation_stream_dek_grants (
    stream_id         TEXT NOT NULL,
    epoch             BIGINT NOT NULL CHECK (epoch >= 0),
    sealer_key_id     TEXT NOT NULL,
    recipient_key_id  TEXT NOT NULL,
    wrap_algorithm    TEXT NOT NULL
        CHECK (wrap_algorithm IN ('x25519_mlkem768_aes256_gcm_hkdf_sha256')),
    wrapped_dek       TEXT NOT NULL,
    cohort_scope      TEXT NOT NULL CHECK (cohort_scope IN ('self', 'family')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (stream_id, epoch, sealer_key_id, recipient_key_id)
);

CREATE INDEX IF NOT EXISTS federation_stream_dek_grants_recipient
    ON cirislens.federation_stream_dek_grants (recipient_key_id, cohort_scope);
