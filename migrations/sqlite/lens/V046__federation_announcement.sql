-- V046 — Federation Announcement substrate, SQLite dialect
-- (CIRISPersist#101).
--
-- Postgres parity (postgres/lens/V046): same column additions on
-- cirisnode_contributions, same federation_delivery_attestations
-- table shape per FSD §3.2.1 ratified wire contract, same
-- constitutional CHECKs.
--
-- Dialect translations:
--   PostgreSQL                       → SQLite
--   ─────────────────────────────────────────────────────────────────
--   UUID FK                          → TEXT FK (36-char hyphenated)
--   BYTEA                            → BLOB
--   TIMESTAMPTZ NOT NULL DEFAULT NOW() → TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
--   `IS DISTINCT FROM`               → `IS NOT`
--   table-level ADD CONSTRAINT CHECK → BEFORE INSERT/UPDATE TRIGGER
--                                      with RAISE(ABORT)
--   octet_length(bytea) CHECK        → length(blob) CHECK (SQLite
--                                      length() on BLOB returns bytes)
--
-- The `subject_kind` column already exists on cirisnode_contributions
-- with no enum CHECK (free-form TEXT), so the new value
-- 'federation_announcement' rides existing storage.

-- ── New columns on cirisnode_contributions ─────────────────────────

ALTER TABLE cirisnode_contributions
    ADD COLUMN announcement_priority TEXT
        CHECK (announcement_priority IS NULL OR announcement_priority IN (
            'informational',
            'advisory',
            'urgent',
            'accord_carrier'
        ));

ALTER TABLE cirisnode_contributions
    ADD COLUMN announcement_authority_class TEXT
        CHECK (announcement_authority_class IS NULL OR announcement_authority_class IN (
            'bootstrap_seed',
            'root_wa',
            'wa_quorum',
            'humanity_accord'
        ));

-- SQLite does not support `ALTER TABLE … ADD CONSTRAINT`. The three
-- multi-column CHECKs that PG carries on the table-level land as
-- single-column CHECKs above plus TRIGGER-based enforcement of the
-- cross-column constitutional asymmetry below (the table-level CHECK
-- semantic on PG; same observable behavior on SQLite — write-time
-- rejection with the cirisnode_contributions table refusing the row).
--
-- A BEFORE INSERT/UPDATE trigger that RAISEs ABORT mirrors the PG
-- CHECK constraint's write-time admission: the row never lands when
-- the constitutional asymmetry is violated.

CREATE TRIGGER IF NOT EXISTS cirisnode_contributions_accord_carrier_asymmetry_ins
    BEFORE INSERT ON cirisnode_contributions
    FOR EACH ROW
    WHEN (
        -- AccordCarrier MUST be HumanityAccord-signed.
        (NEW.announcement_priority = 'accord_carrier'
            AND (NEW.announcement_authority_class IS NULL
                 OR NEW.announcement_authority_class <> 'humanity_accord'))
        OR
        -- HumanityAccord MAY ONLY sign AccordCarrier.
        (NEW.announcement_authority_class = 'humanity_accord'
            AND (NEW.announcement_priority IS NULL
                 OR NEW.announcement_priority <> 'accord_carrier'))
        OR
        -- federation_announcement subject_kind requires both columns.
        (NEW.subject_kind = 'federation_announcement'
            AND (NEW.announcement_priority IS NULL
                 OR NEW.announcement_authority_class IS NULL))
        OR
        -- Non-announcement subject_kinds must have both columns NULL.
        (NEW.subject_kind <> 'federation_announcement'
            AND (NEW.announcement_priority IS NOT NULL
                 OR NEW.announcement_authority_class IS NOT NULL))
    )
    BEGIN
        SELECT RAISE(ABORT, 'cirisnode_contributions: announcement_priority/authority_class constitutional asymmetry violation (FSD §4.5)');
    END;

CREATE TRIGGER IF NOT EXISTS cirisnode_contributions_accord_carrier_asymmetry_upd
    BEFORE UPDATE ON cirisnode_contributions
    FOR EACH ROW
    WHEN (
        (NEW.announcement_priority = 'accord_carrier'
            AND (NEW.announcement_authority_class IS NULL
                 OR NEW.announcement_authority_class <> 'humanity_accord'))
        OR
        (NEW.announcement_authority_class = 'humanity_accord'
            AND (NEW.announcement_priority IS NULL
                 OR NEW.announcement_priority <> 'accord_carrier'))
        OR
        (NEW.subject_kind = 'federation_announcement'
            AND (NEW.announcement_priority IS NULL
                 OR NEW.announcement_authority_class IS NULL))
        OR
        (NEW.subject_kind <> 'federation_announcement'
            AND (NEW.announcement_priority IS NOT NULL
                 OR NEW.announcement_authority_class IS NOT NULL))
    )
    BEGIN
        SELECT RAISE(ABORT, 'cirisnode_contributions: announcement_priority/authority_class constitutional asymmetry violation (FSD §4.5)');
    END;

CREATE INDEX IF NOT EXISTS contributions_announcement_priority
    ON cirisnode_contributions (announcement_priority)
    WHERE announcement_priority IS NOT NULL;

CREATE INDEX IF NOT EXISTS contributions_announcement_authority_class
    ON cirisnode_contributions (announcement_authority_class)
    WHERE announcement_authority_class IS NOT NULL;

-- ── federation_delivery_attestations table (FSD §3.2.1) ────────────

CREATE TABLE IF NOT EXISTS cirisnode_federation_delivery_attestations (
    announcement_id              TEXT NOT NULL
        REFERENCES cirisnode_contributions(contribution_id) ON DELETE RESTRICT,

    -- SHA-256 (32 bytes) of the canonical Contribution envelope.
    announcement_canonical_hash  BLOB NOT NULL
        CHECK (length(announcement_canonical_hash) = 32),

    peer_key_id                  TEXT NOT NULL,

    peer_pubkey_ed25519_base64   TEXT NOT NULL,

    received_at                  TEXT NOT NULL,

    transport_id                 TEXT NOT NULL
        CHECK (transport_id IN ('reticulum', 'tcp_tls', 'http_over_tls', 'other')),

    -- Mandatory Ed25519 signature (64 bytes).
    signature_classical          BLOB NOT NULL
        CHECK (length(signature_classical) = 64),

    -- Optional ML-DSA-65 signature (3309 bytes when present).
    signature_pqc                BLOB
        CHECK (signature_pqc IS NULL OR length(signature_pqc) = 3309),

    inserted_at                  TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    signature_verified           INTEGER NOT NULL DEFAULT 0,  -- 0/1
    persist_row_hash             TEXT NOT NULL,

    PRIMARY KEY (announcement_id, peer_key_id)
);

CREATE INDEX IF NOT EXISTS federation_delivery_attestations_peer
    ON cirisnode_federation_delivery_attestations (peer_key_id);

CREATE INDEX IF NOT EXISTS federation_delivery_attestations_received_at
    ON cirisnode_federation_delivery_attestations (received_at);
