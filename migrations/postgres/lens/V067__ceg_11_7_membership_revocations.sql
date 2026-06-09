-- V067 — CEG §11.7.1 Option-A forward-secrecy removal/revocation
--        substrate primitives (CIRISPersist#161 Asks 1-3, v4.8.0).
--
-- V059 (identity_occurrence + family) and V060 (community) landed the
-- ADMISSION side append-only, with no way to express "this binding /
-- membership is currently revoked." V059's header note assumed an
-- occurrence withdraws could ride the existing federation_revocations
-- table — but that table revokes a KEY globally (revoked_key_id), not a
-- *binding* or a *membership*, and it carries no witness_set for the
-- family/community multi-vouch consensus_protocol path. So removal needs
-- its own surface. These three tables supersede that assumption.
--
-- CEG §11.7.1 (Option-A forward secrecy): "when a member leaves a family
-- (or an occurrence is revoked from a self-collective), the removed
-- party retains existing key_grants for historical content; the
-- substrate stops wrapping new key_grants on subsequent content." That
-- stop-wrapping rule needs a substrate-side "is currently revoked"
-- primitive; these tables provide it. The producer-side enforcement gate
-- (CIRISPersist#161 Ask 4) is deferred until the at-rest ADD key_grant
-- cascade (#152) lands — there is no ADD cascade to make symmetric yet.
--
-- Append-only, symmetric to the V059/V060 admission tables. A revocation
-- is a NEW row that supersedes the binding; effective state =
-- (admitted AND NOT EXISTS matching revocation with effective_at <= now).
-- witness_set is the vouch set: single-vouch for self (CEG §11.7.4 — the
-- revoking occurrence OR the identity_key_id), multi-vouch for
-- family/community per the consensus_protocol (Registry-validated,
-- CIRISRegistry#52). persist_row_hash is server-computed.

-- ─── identity_occurrence revocations ───────────────────────────────
--
-- Revokes a single (identity_key_id, occurrence_key_id) V059 binding.
-- PK on the binding pair — one revocation per binding (idempotent
-- re-revoke). The binding's admission row in
-- federation_identity_occurrences is left intact; the active-state read
-- (V4.8 list_identity_occurrences_active) excludes pairs that have a
-- matching row here with effective_at <= now().

CREATE TABLE IF NOT EXISTS cirislens.federation_identity_occurrence_revocations (
    identity_key_id     TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),
    occurrence_key_id   TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),

    -- §0.5 canonical timestamps. revoked_at = when the ceremony issued
    -- it; effective_at = when it takes effect (may be future-dated).
    revoked_at          TIMESTAMPTZ NOT NULL,
    effective_at        TIMESTAMPTZ NOT NULL,

    reason              TEXT,

    -- Vouch set (array of federation_keys.key_id). Single-vouch for self
    -- per §11.7.4. Stored as a JSON array; members are NOT FK'd (mirrors
    -- the family/community members roster shape).
    witness_set         JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(witness_set) = 'array'),

    persist_row_hash    TEXT NOT NULL,

    PRIMARY KEY (identity_key_id, occurrence_key_id)
);

-- Active-state computation: "is this binding revoked as of now?" The PK
-- already covers by-identity prefix lookup (list_*_revocations_for); this
-- index serves the effective_at <= now() filter.
CREATE INDEX IF NOT EXISTS federation_identity_occurrence_revocations_effective
    ON cirislens.federation_identity_occurrence_revocations (effective_at);

-- Reverse lookup: "is this occurrence revoked from its identity?" (the
-- CallerAdmission singleton-fallback resolution path).
CREATE INDEX IF NOT EXISTS federation_identity_occurrence_revocations_by_occurrence
    ON cirislens.federation_identity_occurrence_revocations (occurrence_key_id);

-- ─── family membership revocations ─────────────────────────────────
--
-- Removes one identity from a family roster. PK on
-- (family_key_id, removed_identity_key_id). The family's V059 members
-- JSONB roster is left intact; the active-membership read filters here.

CREATE TABLE IF NOT EXISTS cirislens.federation_family_membership_revocations (
    family_key_id            TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),
    removed_identity_key_id  TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),

    removed_at               TIMESTAMPTZ NOT NULL,
    effective_at             TIMESTAMPTZ NOT NULL,

    reason                   TEXT,

    -- Multi-vouch per the family's consensus_protocol (Registry-validated
    -- per CIRISRegistry#52 Ask 2). JSON array of key_ids.
    witness_set              JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(witness_set) = 'array'),

    persist_row_hash         TEXT NOT NULL,

    PRIMARY KEY (family_key_id, removed_identity_key_id)
);

CREATE INDEX IF NOT EXISTS federation_family_membership_revocations_effective
    ON cirislens.federation_family_membership_revocations (effective_at);

-- "which families has this identity been removed from?" (CallerAdmission
-- family_key_ids honest-resolution filter).
CREATE INDEX IF NOT EXISTS federation_family_membership_revocations_by_member
    ON cirislens.federation_family_membership_revocations (removed_identity_key_id);

-- ─── community membership revocations ──────────────────────────────
--
-- Symmetric to family. Removes one identity from a community roster.

CREATE TABLE IF NOT EXISTS cirislens.federation_community_membership_revocations (
    community_key_id         TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),
    removed_identity_key_id  TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),

    removed_at               TIMESTAMPTZ NOT NULL,
    effective_at             TIMESTAMPTZ NOT NULL,

    reason                   TEXT,

    witness_set              JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(witness_set) = 'array'),

    persist_row_hash         TEXT NOT NULL,

    PRIMARY KEY (community_key_id, removed_identity_key_id)
);

CREATE INDEX IF NOT EXISTS federation_community_membership_revocations_effective
    ON cirislens.federation_community_membership_revocations (effective_at);

CREATE INDEX IF NOT EXISTS federation_community_membership_revocations_by_member
    ON cirislens.federation_community_membership_revocations (removed_identity_key_id);
