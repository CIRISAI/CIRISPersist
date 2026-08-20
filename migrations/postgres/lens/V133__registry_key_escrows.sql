-- V133: the `registry_key_escrows` consumer-table family (CIRISPersist#752,
-- decided on #751 — "if it is in registry, it needs to be in server").
--
-- The CIRISRegistry -> CIRISServer fold's one storage ask: registry's
-- `key_escrows` working index (rust-registry db/escrows.rs), folded onto
-- persist's consumer-table pattern. Constitutionally this is the CC
-- 4.4.3.2.8 `archive_custody` shape: a steward-bound CUSTODIAN role whose
-- authorization rides `delegates_to` (CC 2.4.1.2) and whose recovery verb
-- is `key_grant` emission (CC 3.3.2) — both on EXISTING planes, because CC
-- 1.7's 1+4 lockdown forbids a new attestation_type. This table is the
-- custodian's working index (who escrows what, expiry, status) and must
-- never become a shadow claims plane.
--
-- escrow_type carries registry's vocabulary as strings (the proto's
-- ESCROW_STEWARD / ESCROW_ATTORNEY / ESCROW_DUAL_CUSTODY): a steward L3C
-- holds the encrypted key / legal escrow per company requirements / two
-- stewards required to recover.
--
-- No BEGIN/COMMIT: refinery wraps each migration in its own transaction (V019 rule).

CREATE TABLE cirislens.key_escrows (
    escrow_id  TEXT NOT NULL PRIMARY KEY,
    key_id     TEXT NOT NULL,
    org_id     TEXT NOT NULL,
    escrow_type TEXT NOT NULL,
    custodian  TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    CONSTRAINT key_escrows_type CHECK (escrow_type IN ('steward', 'attorney', 'dual_custody')),
    CONSTRAINT key_escrows_status CHECK (status IN ('active', 'recovered', 'revoked', 'expired'))
);

CREATE INDEX idx_key_escrows_org ON cirislens.key_escrows (org_id);
CREATE INDEX idx_key_escrows_key ON cirislens.key_escrows (key_id);

COMMENT ON TABLE cirislens.key_escrows IS
    'CC 4.4.3.2.8 archive_custody working index (CIRISPersist#752): custody metadata, never key material, never a claims plane.';
