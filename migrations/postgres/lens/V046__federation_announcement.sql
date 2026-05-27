-- V046 — Federation Announcement substrate (CIRISPersist#101).
--
-- Lands two pieces per FSD `~/CIRISNodeCore/FSD/FEDERATION_ANNOUNCEMENT.md`:
--
--   1. The `federation_announcement` subject_kind extension to the
--      canonical-chain `cirisnode.contributions` table (FSD §2.3).
--      Two new typed columns (`announcement_priority`,
--      `announcement_authority_class`) project the FSD §2.1 payload
--      enums out of JSONB into indexed columns so the constitutional
--      asymmetry CHECK + read-side filters don't dig into JSONB on
--      every row.
--
--   2. The new `cirisnode.federation_delivery_attestations` table —
--      ratified wire shape from FSD §3.2.1 (locked 2026-05-27, was
--      open question #3, now CLOSED). PK
--      `(announcement_id, peer_key_id)`. Row mirrors the FSD's
--      `DeliveryAttestation` Rust struct one-to-one.
--
-- # Why ship both in V046 (and not split V046 / V047)
--
-- The two pieces ship together as the "FederationAnnouncement
-- substrate" cut: the FSD §3.2 substrate contract specifies persist
-- as the durable store for both the announcements AND the per-peer
-- attestations. Splitting them would leave §3.2 half-met (durable
-- announcements with no reach observable) for the gap between
-- migrations. Single migration keeps the contract atomic.
--
-- # subject_kind addition (FSD §2.3)
--
-- `cirisnode.contributions.subject_kind` is a free-form TEXT column
-- (no CHECK enum), so the new value `'federation_announcement'`
-- rides the existing column without a type change. The
-- FederationAnnouncementPayload (FSD §2.1) is stored as JSONB on
-- the existing `payload` column.
--
-- # The constitutional wire-format asymmetry (FSD §4.5)
--
-- A `federation_announcement` of priority `accord_carrier` is the
-- federation-tier kill switch. Per FSD §4.5, only `humanity_accord`
-- authority class may sign it; and `humanity_accord` may ONLY sign
-- `accord_carrier`. Both halves of the rule are enforced by CHECK
-- constraints below — write-time admission rejects mismatches with
-- SQLSTATE 23514, which `map_pg_error` translates to
-- `Error::InvalidArgument` (the persist Rust admission path also
-- catches the same rule via
-- `enforce_constitutional_asymmetry`, returning the more specific
-- `FederationAnnouncementAuthorityMismatch` variant; both guards
-- run in defense in depth).
--
-- # delivery_attestation schema (FSD §3.2.1 ratified contract)
--
-- The FSD locks the wire shape; this row mirrors it one-to-one:
--
--   announcement_id                   (Contribution::id → UUID FK)
--   announcement_canonical_hash       (BYTEA, exactly 32 bytes)
--   peer_key_id                       (TEXT — federation_keys.key_id ref)
--   peer_pubkey_ed25519_base64        (TEXT, denormalized for offline verify)
--   received_at                       (TIMESTAMPTZ)
--   transport_id                      (TEXT enum — 4 variants, CHECK)
--   signature_classical               (BYTEA, exactly 64 bytes Ed25519)
--   signature_pqc                     (BYTEA, optional ML-DSA-65)
--
-- Plus the standard CIRISPersist audit-row columns:
--
--   inserted_at                       (TIMESTAMPTZ, persist-side wall clock)
--   signature_verified                (BOOLEAN, set TRUE after verify pass)
--   persist_row_hash                  (TEXT, canonical row hash)
--
-- PK is composite `(announcement_id, peer_key_id)` so a peer cannot
-- double-attest one announcement structurally. FK on
-- `announcement_id` → `cirisnode.contributions(contribution_id)`
-- with ON DELETE RESTRICT — announcements are durable; orphaning
-- attestations would silently lose delivery evidence.
--
-- Refinery wraps each migration in a transaction.

-- ── New columns on contributions ───────────────────────────────────

ALTER TABLE cirisnode.contributions
    ADD COLUMN IF NOT EXISTS announcement_priority TEXT
        CHECK (announcement_priority IS NULL OR announcement_priority IN (
            'informational',
            'advisory',
            'urgent',
            'accord_carrier'
        )),
    ADD COLUMN IF NOT EXISTS announcement_authority_class TEXT
        CHECK (announcement_authority_class IS NULL OR announcement_authority_class IN (
            'bootstrap_seed',
            'root_wa',
            'wa_quorum',
            'humanity_accord'
        ));

-- The constitutional asymmetry (FSD §4.5): `accord_carrier` priority
-- MUST be paired with `humanity_accord` authority. Wire-isolation —
-- the federation governance hierarchy CANNOT sign AccordCarrier.
--
-- PostgreSQL `ALTER TABLE ... ADD CONSTRAINT` lacks an `IF NOT EXISTS`
-- syntax — drive idempotence through a DO block consulting
-- `pg_catalog.pg_constraint`. Required for the AV-26 multi-worker
-- boot race (qa_harness scenario H) where the cirisnode schema
-- survives a `schema_history` table drop and the migration re-applies
-- against a partially-populated catalog.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'contributions_accord_carrier_humanity_accord_only'
          AND conrelid = 'cirisnode.contributions'::regclass
    ) THEN
        ALTER TABLE cirisnode.contributions
            ADD CONSTRAINT contributions_accord_carrier_humanity_accord_only
                CHECK (
                    announcement_priority IS DISTINCT FROM 'accord_carrier'
                    OR announcement_authority_class = 'humanity_accord'
                );
    END IF;
END$$;

-- And the dual constraint: `humanity_accord` MAY ONLY sign
-- `accord_carrier`. Out-of-role for any other priority.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'contributions_humanity_accord_accord_carrier_only'
          AND conrelid = 'cirisnode.contributions'::regclass
    ) THEN
        ALTER TABLE cirisnode.contributions
            ADD CONSTRAINT contributions_humanity_accord_accord_carrier_only
                CHECK (
                    announcement_authority_class IS DISTINCT FROM 'humanity_accord'
                    OR announcement_priority = 'accord_carrier'
                );
    END IF;
END$$;

-- And: when `subject_kind = 'federation_announcement'` both new
-- columns MUST be populated. When `subject_kind <>
-- 'federation_announcement'` both MUST be NULL.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'contributions_announcement_columns_match_subject_kind'
          AND conrelid = 'cirisnode.contributions'::regclass
    ) THEN
        ALTER TABLE cirisnode.contributions
            ADD CONSTRAINT contributions_announcement_columns_match_subject_kind
                CHECK (
                    (subject_kind = 'federation_announcement'
                      AND announcement_priority IS NOT NULL
                      AND announcement_authority_class IS NOT NULL)
                    OR
                    (subject_kind <> 'federation_announcement'
                      AND announcement_priority IS NULL
                      AND announcement_authority_class IS NULL)
                );
    END IF;
END$$;

CREATE INDEX IF NOT EXISTS contributions_announcement_priority
    ON cirisnode.contributions (announcement_priority)
    WHERE announcement_priority IS NOT NULL;

CREATE INDEX IF NOT EXISTS contributions_announcement_authority_class
    ON cirisnode.contributions (announcement_authority_class)
    WHERE announcement_authority_class IS NOT NULL;

COMMENT ON COLUMN cirisnode.contributions.announcement_priority IS
    'v2.1 (CIRISPersist#101) — populated iff subject_kind = ''federation_announcement''. AnnouncementPriority per FSD/FEDERATION_ANNOUNCEMENT.md §2.1.';

COMMENT ON COLUMN cirisnode.contributions.announcement_authority_class IS
    'v2.1 (CIRISPersist#101) — populated iff subject_kind = ''federation_announcement''. AuthorityClass per FSD §2.1. CHECK constraint enforces the constitutional asymmetry: accord_carrier <=> humanity_accord (FSD §4.5).';

-- ── federation_delivery_attestations table (FSD §3.2.1) ────────────

CREATE TABLE IF NOT EXISTS cirisnode.federation_delivery_attestations (
    -- FK to the federation_announcement Contribution row. ON DELETE
    -- RESTRICT — announcements are durable; deleting one with live
    -- attestations would orphan delivery evidence.
    announcement_id              UUID NOT NULL
        REFERENCES cirisnode.contributions(contribution_id) ON DELETE RESTRICT,

    -- SHA-256 of the full canonicalized Contribution envelope of
    -- the announcement (INCLUDING its authority signature). Pins
    -- the exact bytes the peer received. Per FSD §3.2.1 + Q1
    -- ratification: ID for indexing, hash for content verification.
    announcement_canonical_hash  BYTEA NOT NULL
        CHECK (octet_length(announcement_canonical_hash) = 32),

    -- The peer that is acknowledging receipt — federation_keys.key_id
    -- (NOT an opaque peer address per FSD §3.2.1).
    peer_key_id                  TEXT NOT NULL,

    -- Base64 of the peer's Ed25519 pubkey, denormalized for offline
    -- verification convenience. MUST match
    -- federation_keys[peer_key_id].pubkey_ed25519_base64. Persist
    -- does NOT enforce this match server-side via FK because
    -- federation_keys lives in `cirislens.*` (cross-schema FK is
    -- inadvisable) and the directory-lookup gate is the verify
    -- path's responsibility.
    peer_pubkey_ed25519_base64   TEXT NOT NULL,

    -- When the peer's edge accepted the validated announcement
    -- (authority-class verified + signature verified). Per FSD
    -- §3.2.1 Q3 ratification: edge-validated-receipt, not
    -- application-layer-acceptance, for v0.1.
    received_at                  TIMESTAMPTZ NOT NULL,

    -- Transport medium per FSD §3.2.1 Q2 ratification (medium tag
    -- only, no sub-path / interface).
    transport_id                 TEXT NOT NULL
        CHECK (transport_id IN ('reticulum', 'tcp_tls', 'http_over_tls', 'other')),

    -- MANDATORY classical Ed25519 signature (64 bytes raw) over
    -- DeliveryAttestation::canonical_bytes (domain
    -- `ciris-edge-delivery-attestation-v1`).
    signature_classical          BYTEA NOT NULL
        CHECK (octet_length(signature_classical) = 64),

    -- OPTIONAL PQC ML-DSA-65 signature over
    -- `canonical_bytes || signature_classical` per persist's AV-33
    -- bound-signature convention. 3309 bytes raw (FIPS 204 final);
    -- length check below is advisory (admits NULL).
    signature_pqc                BYTEA
        CHECK (signature_pqc IS NULL OR octet_length(signature_pqc) = 3309),

    -- Persist-side audit columns. Insert-time wall clock; verify
    -- gate result; canonical row hash for cache-divergence checks.
    inserted_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    signature_verified           BOOLEAN NOT NULL DEFAULT FALSE,
    persist_row_hash             TEXT NOT NULL,

    -- Composite PK enforces "one attestation per (announcement,
    -- peer)" structurally. Idempotent on replay per FSD §3.2.1
    -- "AV: replayed attestation" — the writer translates a
    -- unique-violation into a no-op.
    PRIMARY KEY (announcement_id, peer_key_id)
);

-- (announcement_id) is the leading-edge column of the PK and so
-- already has an index. Add (peer_key_id) for the "what has this
-- peer attested" read path.
CREATE INDEX IF NOT EXISTS federation_delivery_attestations_peer
    ON cirisnode.federation_delivery_attestations (peer_key_id);

CREATE INDEX IF NOT EXISTS federation_delivery_attestations_received_at
    ON cirisnode.federation_delivery_attestations (received_at);

COMMENT ON TABLE cirisnode.federation_delivery_attestations IS
    'v2.1 (CIRISPersist#101) — per-peer Mandatory-delivery attestation paired with each federation_announcement Contribution. Wire shape locked per FSD/FEDERATION_ANNOUNCEMENT.md §3.2.1 (ratified 2026-05-27). Surface for RATCHET reach verification (FSD §3.2). Writes come from CIRISEdge through persist''s put_delivery_attestation; persist verifies the hybrid signature against federation_keys[peer_key_id] before INSERT.';
