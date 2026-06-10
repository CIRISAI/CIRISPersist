-- V071 — CEG 1.0-RC2 §5.6.8.13 operational-data subject_kinds
--        (CIRISRegistry#70, CIRISPersist#65, v5.1.0) — SQLite dialect.
--        Postgres parity: postgres/lens/V071. See that file for the full
--        rationale (federate-the-projection principle, Commons tier /
--        plaintext, first-class indexed business ids, stable-id
--        partition-tolerant resolution, append-only withdrawn_at).
--
-- JSONB → TEXT (serde JSON); TIMESTAMPTZ → TEXT (RFC-3339); BIGINT →
-- INTEGER; BOOLEAN → INTEGER (0/1). The four admission checks (skew-bound,
-- no-payment-processor, role/quorum authority, set-semantics-sorted) live
-- in the put_* methods, not the DDL.

CREATE TABLE federation_organizations (
    attestation_id            TEXT NOT NULL PRIMARY KEY,
    org_id                    TEXT NOT NULL,
    name                      TEXT NOT NULL,
    org_type                  TEXT NOT NULL,
    parent_org_id             TEXT,
    partner_id                TEXT,
    status                    TEXT NOT NULL,
    asserted_at               TEXT NOT NULL,   -- RFC-3339
    valid_until               TEXT,            -- RFC-3339
    attesting_key_id          TEXT NOT NULL,
    signed_envelope           TEXT NOT NULL,   -- serde JSON
    ed25519_signature_base64  TEXT NOT NULL,
    mldsa65_signature_base64  TEXT,
    withdrawn_at              TEXT,            -- null = in force
    persist_row_hash          TEXT NOT NULL
);

CREATE INDEX federation_organizations_by_org_id
    ON federation_organizations (org_id);

CREATE TABLE federation_org_memberships (
    attestation_id            TEXT NOT NULL PRIMARY KEY,
    user_id                   TEXT NOT NULL,
    org_id                    TEXT NOT NULL,
    role                      TEXT NOT NULL,
    status                    TEXT NOT NULL,
    asserted_at               TEXT NOT NULL,
    valid_until               TEXT,
    attesting_key_id          TEXT NOT NULL,
    signed_envelope           TEXT NOT NULL,
    ed25519_signature_base64  TEXT NOT NULL,
    mldsa65_signature_base64  TEXT,
    withdrawn_at              TEXT,
    persist_row_hash          TEXT NOT NULL
);

CREATE INDEX federation_org_memberships_by_user_org
    ON federation_org_memberships (user_id, org_id);

CREATE INDEX federation_org_memberships_by_org
    ON federation_org_memberships (org_id);

CREATE TABLE federation_partner_records (
    attestation_id            TEXT NOT NULL PRIMARY KEY,
    license_id                TEXT NOT NULL,
    partner_id                TEXT NOT NULL,
    org_id                    TEXT NOT NULL,
    license_type              TEXT NOT NULL,
    max_autonomy_tier         TEXT NOT NULL,
    requires_supervisor       INTEGER NOT NULL,  -- 0/1
    deployment_limit          INTEGER NOT NULL,
    offline_grace_hours       INTEGER NOT NULL,
    status                    TEXT NOT NULL,
    revision                  INTEGER NOT NULL,  -- monotonic per license_id
    issued_at                 TEXT NOT NULL,
    expires_at                TEXT NOT NULL,
    asserted_at               TEXT NOT NULL,
    signed_envelope           TEXT NOT NULL,
    withdrawn_at              TEXT,
    persist_row_hash          TEXT NOT NULL
);

CREATE INDEX federation_partner_records_by_license_id
    ON federation_partner_records (license_id);
