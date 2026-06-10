-- V071 — CEG 1.0-RC2 §5.6.8.13 operational-data subject_kinds
--        (CIRISRegistry#70, CIRISPersist#65, v5.1.0).
--
-- Cross-region operational Portal data — organizations, memberships,
-- licenses/partners — federates as signed CEG envelopes carried by the
-- same anti-entropy carrier as trust data (CIRISEdge#65 v2 wire). The
-- §5.6.8.13 governing principle: federate only the trust/authz-minimal
-- projection; PII + business detail stay region-local (Registry emit-side
-- discipline, NOT a substrate filter — the substrate stores what is signed).
--
-- All three are Commons tier (§8.1.13.3) — PLAINTEXT at rest; the
-- projection is world-readable by design. No holds_bytes suppression, no
-- DEK cascade.
--
-- First-class indexed business ids per §5.6.8.13:
--   organization     → org_id
--   org_membership   → (user_id, org_id)
--   partner_record   → license_id
-- These drive the stable-id current-state resolution (group by business id,
-- withdraws forward-only, latest asserted_at, tie-break smallest
-- attestation_id). Resolution MUST NOT require supersedes-chain
-- completeness — supersedes is audit-only (partition tolerance).
--
-- The signed envelope + signature halves are stored so the role-authority
-- resolver (org/membership) can rebuild MembershipGrant inputs and the
-- M-of-N quorum (partner_record) can re-verify byte-identical JCS bytes.
-- Append-only; withdrawn_at marks a record no longer in force (null =
-- current). No DROP of existing tables.

-- ── organization ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cirislens.federation_organizations (
    -- Server-assigned envelope identity; the §6.1 tie-break key.
    attestation_id        TEXT NOT NULL PRIMARY KEY,

    -- FIRST-CLASS business id (§5.6.8.13) — indexed; stable-id grouping key.
    org_id                TEXT NOT NULL,

    -- Trust/authz-minimal projection fields.
    name                  TEXT NOT NULL,
    org_type              TEXT NOT NULL,           -- internal|partner|licensee|community
    parent_org_id         TEXT,
    partner_id            TEXT,
    status                TEXT NOT NULL,           -- active|suspended|deactivated

    asserted_at           TIMESTAMPTZ NOT NULL,    -- §0.5; LWW ordering field
    valid_until           TIMESTAMPTZ,

    -- The key that signed this envelope (role-gated admit actor).
    attesting_key_id      TEXT NOT NULL,

    -- The signed envelope (JCS basis) + bound hybrid signature halves.
    signed_envelope       JSONB NOT NULL,
    ed25519_signature_base64  TEXT NOT NULL,
    mldsa65_signature_base64  TEXT,

    -- null = currently in force; set = withdrawn (forward-only, no DELETE).
    withdrawn_at          TIMESTAMPTZ,

    persist_row_hash      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS federation_organizations_by_org_id
    ON cirislens.federation_organizations (org_id);

-- ── org_membership ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cirislens.federation_org_memberships (
    attestation_id        TEXT NOT NULL PRIMARY KEY,

    -- FIRST-CLASS composite business id (§5.6.8.13) — indexed.
    user_id               TEXT NOT NULL,
    org_id                TEXT NOT NULL,

    role                  TEXT NOT NULL,           -- org_admin|key_manager|operator|viewer
    status                TEXT NOT NULL,           -- active|deactivated

    asserted_at           TIMESTAMPTZ NOT NULL,
    valid_until           TIMESTAMPTZ,

    attesting_key_id      TEXT NOT NULL,

    signed_envelope       JSONB NOT NULL,
    ed25519_signature_base64  TEXT NOT NULL,
    mldsa65_signature_base64  TEXT,

    withdrawn_at          TIMESTAMPTZ,

    persist_row_hash      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS federation_org_memberships_by_user_org
    ON cirislens.federation_org_memberships (user_id, org_id);

-- The role-authority resolver loads the current membership set for one
-- org (all users) — index org_id alone for that read path.
CREATE INDEX IF NOT EXISTS federation_org_memberships_by_org
    ON cirislens.federation_org_memberships (org_id);

-- ── partner_record ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cirislens.federation_partner_records (
    attestation_id        TEXT NOT NULL PRIMARY KEY,

    -- FIRST-CLASS business id (§5.6.8.13) — indexed; stable-id grouping key.
    license_id            TEXT NOT NULL,

    partner_id            TEXT NOT NULL,
    org_id                TEXT NOT NULL,
    license_type          TEXT NOT NULL,

    max_autonomy_tier     TEXT NOT NULL,           -- A0..A4
    requires_supervisor   BOOLEAN NOT NULL,
    deployment_limit      BIGINT NOT NULL,
    offline_grace_hours   BIGINT NOT NULL,
    status                TEXT NOT NULL,           -- active|suspended|revoked

    -- MONOTONIC per license_id — admission REJECTS any decrease
    -- (F-AV-ROLLBACK; the §10.1.6 monotonic_quorum merge orders on this).
    revision              BIGINT NOT NULL,

    issued_at             TIMESTAMPTZ NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL,
    asserted_at           TIMESTAMPTZ NOT NULL,

    -- The signed envelope (full record — it federates whole; carries the
    -- set-semantics capability/restriction arrays). The M-of-N steward
    -- quorum signatures verify against the JCS bytes of this envelope.
    signed_envelope       JSONB NOT NULL,

    withdrawn_at          TIMESTAMPTZ,

    persist_row_hash      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS federation_partner_records_by_license_id
    ON cirislens.federation_partner_records (license_id);
