-- V067 — CEG §11.7.1 Option-A forward-secrecy removal/revocation
--        substrate primitives (CIRISPersist#161 Asks 1-3, v4.8.0) —
--        SQLite dialect. Postgres parity: postgres/lens/V067. See that
--        file for the full design rationale + the V059 "withdraws
--        suffices" reconciliation note.
--
-- Append-only, symmetric to the V059/V060 admission tables. A revocation
-- is a NEW row that supersedes the binding; effective state =
-- (admitted AND NOT EXISTS matching revocation with effective_at <= now).
-- witness_set / timestamps are JSON TEXT / RFC-3339 TEXT (the SQLite
-- convention; postgres uses JSONB / TIMESTAMPTZ). persist_row_hash is
-- server-computed.
--
-- Refinery wraps this migration in its own transaction — no explicit
-- BEGIN/COMMIT (matches the V059/V060 convention).

-- ── identity_occurrence revocations ────────────────────────────────
CREATE TABLE federation_identity_occurrence_revocations (
    identity_key_id     TEXT NOT NULL REFERENCES federation_keys(key_id),
    occurrence_key_id   TEXT NOT NULL REFERENCES federation_keys(key_id),
    revoked_at          TEXT NOT NULL,   -- RFC-3339
    effective_at        TEXT NOT NULL,   -- RFC-3339
    reason              TEXT,
    witness_set         TEXT NOT NULL DEFAULT '[]'   -- JSON array
        CHECK (json_valid(witness_set) AND json_type(witness_set) = 'array'),
    persist_row_hash    TEXT NOT NULL,
    PRIMARY KEY (identity_key_id, occurrence_key_id)
);

CREATE INDEX federation_identity_occurrence_revocations_effective
    ON federation_identity_occurrence_revocations (effective_at);

CREATE INDEX federation_identity_occurrence_revocations_by_occurrence
    ON federation_identity_occurrence_revocations (occurrence_key_id);

-- ── family membership revocations ──────────────────────────────────
CREATE TABLE federation_family_membership_revocations (
    family_key_id            TEXT NOT NULL REFERENCES federation_keys(key_id),
    removed_identity_key_id  TEXT NOT NULL REFERENCES federation_keys(key_id),
    removed_at               TEXT NOT NULL,   -- RFC-3339
    effective_at             TEXT NOT NULL,   -- RFC-3339
    reason                   TEXT,
    witness_set              TEXT NOT NULL DEFAULT '[]'   -- JSON array
        CHECK (json_valid(witness_set) AND json_type(witness_set) = 'array'),
    persist_row_hash         TEXT NOT NULL,
    PRIMARY KEY (family_key_id, removed_identity_key_id)
);

CREATE INDEX federation_family_membership_revocations_effective
    ON federation_family_membership_revocations (effective_at);

CREATE INDEX federation_family_membership_revocations_by_member
    ON federation_family_membership_revocations (removed_identity_key_id);

-- ── community membership revocations ───────────────────────────────
CREATE TABLE federation_community_membership_revocations (
    community_key_id         TEXT NOT NULL REFERENCES federation_keys(key_id),
    removed_identity_key_id  TEXT NOT NULL REFERENCES federation_keys(key_id),
    removed_at               TEXT NOT NULL,   -- RFC-3339
    effective_at             TEXT NOT NULL,   -- RFC-3339
    reason                   TEXT,
    witness_set              TEXT NOT NULL DEFAULT '[]'   -- JSON array
        CHECK (json_valid(witness_set) AND json_type(witness_set) = 'array'),
    persist_row_hash         TEXT NOT NULL,
    PRIMARY KEY (community_key_id, removed_identity_key_id)
);

CREATE INDEX federation_community_membership_revocations_effective
    ON federation_community_membership_revocations (effective_at);

CREATE INDEX federation_community_membership_revocations_by_member
    ON federation_community_membership_revocations (removed_identity_key_id);
