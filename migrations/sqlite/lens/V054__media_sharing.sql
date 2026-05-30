-- V054 — Media-sharing substrate, SQLite dialect (CIRISPersist#134).
--
-- Postgres parity (postgres/lens/V054):
--   - cirisnode_contributions gains the same three nullable columns +
--     CHECKs on each column's value vocabulary.
--   - The cross-column CHECK from PG ("subject_kind = 'X' IFF columns
--     populated") lands here as BEFORE INSERT/UPDATE triggers with
--     RAISE(ABORT), matching V046's approach for the accord-carrier
--     asymmetry (SQLite has no ALTER TABLE … ADD CONSTRAINT).
--   - scheduled_takedown_actions table parallels its PG sibling with
--     TIMESTAMPTZ → TEXT, UUID FK → TEXT FK.

-- ── New columns on cirisnode_contributions ─────────────────────────

ALTER TABLE cirisnode_contributions
    ADD COLUMN media_content_sha256 TEXT
        CHECK (media_content_sha256 IS NULL
               OR (length(media_content_sha256) = 64
                   AND media_content_sha256 GLOB '[0-9a-f]*'));

ALTER TABLE cirisnode_contributions
    ADD COLUMN key_grant_recipient_key_id TEXT;

ALTER TABLE cirisnode_contributions
    ADD COLUMN takedown_legal_basis TEXT
        CHECK (takedown_legal_basis IS NULL OR takedown_legal_basis IN (
            'dmca_512',
            'dsa_article_16',
            'tvec_terrorist',
            'ncmec_csam',
            'gifct_cip',
            'community_standards',
            'perceptual_hash_csam',
            'osa_illegal_content',
            'avmsd_age_inappropriate',
            'court_order'
        ));

-- Cross-column subject_kind asymmetry — BEFORE INSERT/UPDATE triggers
-- with RAISE(ABORT). Mirrors V046's accord-carrier asymmetry trigger
-- shape.

CREATE TRIGGER IF NOT EXISTS cirisnode_contributions_takedown_asymmetry_ins
    BEFORE INSERT ON cirisnode_contributions
    FOR EACH ROW
    WHEN (
        (NEW.subject_kind = 'takedown_notice'
            AND (NEW.media_content_sha256 IS NULL
                 OR NEW.takedown_legal_basis IS NULL))
        OR
        (NEW.subject_kind <> 'takedown_notice'
            AND NEW.takedown_legal_basis IS NOT NULL)
    )
    BEGIN
        SELECT RAISE(ABORT, 'cirisnode_contributions: takedown_notice subject_kind requires media_content_sha256 + takedown_legal_basis; other subject_kinds must leave takedown_legal_basis NULL');
    END;

CREATE TRIGGER IF NOT EXISTS cirisnode_contributions_takedown_asymmetry_upd
    BEFORE UPDATE ON cirisnode_contributions
    FOR EACH ROW
    WHEN (
        (NEW.subject_kind = 'takedown_notice'
            AND (NEW.media_content_sha256 IS NULL
                 OR NEW.takedown_legal_basis IS NULL))
        OR
        (NEW.subject_kind <> 'takedown_notice'
            AND NEW.takedown_legal_basis IS NOT NULL)
    )
    BEGIN
        SELECT RAISE(ABORT, 'cirisnode_contributions: takedown_notice subject_kind requires media_content_sha256 + takedown_legal_basis; other subject_kinds must leave takedown_legal_basis NULL');
    END;

CREATE TRIGGER IF NOT EXISTS cirisnode_contributions_key_grant_asymmetry_ins
    BEFORE INSERT ON cirisnode_contributions
    FOR EACH ROW
    WHEN (
        (NEW.subject_kind = 'key_grant'
            AND (NEW.media_content_sha256 IS NULL
                 OR NEW.key_grant_recipient_key_id IS NULL))
        OR
        (NEW.subject_kind <> 'key_grant'
            AND NEW.key_grant_recipient_key_id IS NOT NULL)
    )
    BEGIN
        SELECT RAISE(ABORT, 'cirisnode_contributions: key_grant subject_kind requires media_content_sha256 + key_grant_recipient_key_id; other subject_kinds must leave key_grant_recipient_key_id NULL');
    END;

CREATE TRIGGER IF NOT EXISTS cirisnode_contributions_key_grant_asymmetry_upd
    BEFORE UPDATE ON cirisnode_contributions
    FOR EACH ROW
    WHEN (
        (NEW.subject_kind = 'key_grant'
            AND (NEW.media_content_sha256 IS NULL
                 OR NEW.key_grant_recipient_key_id IS NULL))
        OR
        (NEW.subject_kind <> 'key_grant'
            AND NEW.key_grant_recipient_key_id IS NOT NULL)
    )
    BEGIN
        SELECT RAISE(ABORT, 'cirisnode_contributions: key_grant subject_kind requires media_content_sha256 + key_grant_recipient_key_id; other subject_kinds must leave key_grant_recipient_key_id NULL');
    END;

CREATE INDEX IF NOT EXISTS contributions_media_content_sha256
    ON cirisnode_contributions (media_content_sha256)
    WHERE media_content_sha256 IS NOT NULL;

CREATE INDEX IF NOT EXISTS contributions_key_grant_recipient_key_id
    ON cirisnode_contributions (key_grant_recipient_key_id)
    WHERE key_grant_recipient_key_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS contributions_takedown_legal_basis
    ON cirisnode_contributions (takedown_legal_basis)
    WHERE takedown_legal_basis IS NOT NULL;

-- ── scheduled_takedown_actions ─────────────────────────────────────

CREATE TABLE IF NOT EXISTS cirisnode_scheduled_takedown_actions (
    notice_contribution_id    TEXT NOT NULL PRIMARY KEY
        REFERENCES cirisnode_contributions(contribution_id) ON DELETE RESTRICT,

    scheduled_eviction_at     TEXT NOT NULL,

    status                    TEXT NOT NULL
        CHECK (status IN ('pending', 'evicted', 'counter_noticed', 'expired')),

    inserted_at               TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);

CREATE INDEX IF NOT EXISTS idx_scheduled_takedowns_pending
    ON cirisnode_scheduled_takedown_actions (scheduled_eviction_at)
    WHERE status = 'pending';
