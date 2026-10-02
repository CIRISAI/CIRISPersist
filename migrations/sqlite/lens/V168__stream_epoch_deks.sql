-- V168 — one DEK per (stream, epoch) for self/family chunk streams, SQLite dialect
-- v53.0.0 (CIRISPersist#969, FSD BLOB_ENCRYPTION_AT_REST.md §12.12,
-- BLOB_REPLICATION.md §14.1)
--
-- POSTGRES PARITY: migrations/postgres/lens/V168__stream_epoch_deks.sql
--
-- WHAT AND WHY
-- ------------
-- A self/family chunk used to be a whole blob: a fresh DEK per chunk and a
-- content-axis key_grant set per chunk, so a 1024-chunk file carried 1024
-- wraps per recipient. CC 5.3.3.1 seals a stream under ONE DEK per
-- (stream_id, epoch) with the STREAM nonce (prefix ‖ counter ‖ last_flag);
-- CC part 5 §5.1 distributes that key O(N) per epoch. These two tables hold
-- it: the epoch's DEK (self-retained under this node's content master, the
-- way federation_community_dek holds a community epoch) and its recipient
-- wraps (this node's fan-out AND every admitted key_grant:stream:v1 set — a
-- union, never reduced).
--
-- federation_stream_deks has a row only for streams THIS node sealed. A
-- peer's stream is known through the grant table alone.
--
-- closed_at     — no further DATA chunk may be sealed under the epoch (a
--                 forced roll at the nonce cap, or a removal roll). The
--                 terminator may still be appended.
-- terminated_at — the epoch's last_flag chunk is stored; nothing more may be
--                 appended under it (the append-resistance half of CC
--                 5.3.3.1). The chunk floor stamps it in the terminator's own
--                 transaction.
-- key_grant_emitted_at — the V146 emission ledger, as on federation_community_dek.

CREATE TABLE IF NOT EXISTS federation_stream_deks (
    stream_id             TEXT NOT NULL,
    epoch                 INTEGER NOT NULL CHECK (epoch >= 0),
    -- The stream's owner: the writer's derived key, the only party that
    -- seals under this DEK (single sender, CC 5.3.3.1 / I41).
    owner_key_id          TEXT NOT NULL,
    cohort_scope          TEXT NOT NULL CHECK (cohort_scope IN ('self', 'family')),
    -- The self identity or the family key the stream is sealed for.
    group_key_id          TEXT NOT NULL,
    self_retention_wrap   TEXT NOT NULL,
    minted_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    closed_at             TEXT,
    terminated_at         TEXT,
    key_grant_emitted_at  TEXT,
    PRIMARY KEY (stream_id, epoch)
);

-- One v2 wrap per (stream, epoch, sealer, recipient occurrence). `sealer_key_id`
-- is the party that signed the set (or sealed, on this node): a reader takes a
-- wrap only from a sealer that speaks for the stream's owner, so a set for a
-- stream id this node holds under another owner grants nothing.
CREATE TABLE IF NOT EXISTS federation_stream_dek_grants (
    stream_id         TEXT NOT NULL,
    epoch             INTEGER NOT NULL CHECK (epoch >= 0),
    sealer_key_id     TEXT NOT NULL,
    recipient_key_id  TEXT NOT NULL,
    wrap_algorithm    TEXT NOT NULL
        CHECK (wrap_algorithm IN ('x25519_mlkem768_aes256_gcm_hkdf_sha256')),
    wrapped_dek       TEXT NOT NULL,
    cohort_scope      TEXT NOT NULL CHECK (cohort_scope IN ('self', 'family')),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    PRIMARY KEY (stream_id, epoch, sealer_key_id, recipient_key_id)
);

-- The retroactive-ADD walk lists the epochs a recipient set holds.
CREATE INDEX IF NOT EXISTS federation_stream_dek_grants_recipient
    ON federation_stream_dek_grants (recipient_key_id, cohort_scope);
