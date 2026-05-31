-- V056 — CEG 0.6 cohort_scope + consent_record + identity_canonical_binding
--        + SLA watchers — SQLite dialect (CIRISPersist#146/#150, v3.9.0).
--
-- Postgres parity (postgres/lens/V056):
--   - federation_attestations gains cohort_scope (TEXT NOT NULL
--     DEFAULT 'self' CHECK in 7-value closed set).
--   - cirisnode_contributions gains 3 consent_record columns + cross-
--     column CHECK trigger (SQLite has no ALTER TABLE … ADD
--     CONSTRAINT; matches V054 discipline).
--   - cirisnode_consent_sla_watch table.
--   - cirisnode_revocation_promotion_watch table.
--   - identity_canonical_binding table.
--
-- See migrations/postgres/lens/V056 for the full design rationale.

-- ── 1. federation_attestations.cohort_scope ────────────────────────

-- Default 'federation' preserves pre-v3.9.0 semantic.
ALTER TABLE federation_attestations
    ADD COLUMN cohort_scope TEXT NOT NULL DEFAULT 'federation'
        CHECK (cohort_scope IN (
            'self', 'family', 'community',
            'affiliations', 'species', 'biosphere', 'federation'
        ));

CREATE INDEX IF NOT EXISTS federation_attestations_cohort_scope
    ON federation_attestations (cohort_scope)
    WHERE cohort_scope != 'federation';

-- ── 2. consent_record subject_kind columns ─────────────────────────

ALTER TABLE cirisnode_contributions
    ADD COLUMN consent_record_subject_key_id TEXT;

ALTER TABLE cirisnode_contributions
    ADD COLUMN consent_record_stance TEXT
        CHECK (consent_record_stance IS NULL
               OR consent_record_stance IN ('granted', 'revoked', 'expired'));

ALTER TABLE cirisnode_contributions
    ADD COLUMN consent_record_bilateral_pair_id TEXT;

-- Cross-column CHECK via triggers (V054 discipline).
CREATE TRIGGER IF NOT EXISTS contributions_consent_record_insert_check
BEFORE INSERT ON cirisnode_contributions
FOR EACH ROW
BEGIN
    SELECT
        CASE
            WHEN NEW.subject_kind = 'consent_record'
                 AND (NEW.consent_record_subject_key_id IS NULL
                      OR NEW.consent_record_stance IS NULL)
            THEN RAISE(ABORT, 'consent_record subject_kind requires consent_record_subject_key_id + consent_record_stance')
            WHEN NEW.subject_kind <> 'consent_record'
                 AND (NEW.consent_record_subject_key_id IS NOT NULL
                      OR NEW.consent_record_stance IS NOT NULL)
            THEN RAISE(ABORT, 'consent_record columns must be NULL when subject_kind <> consent_record')
        END;
END;

CREATE INDEX IF NOT EXISTS contributions_consent_record_subject_key_id
    ON cirisnode_contributions (consent_record_subject_key_id)
    WHERE consent_record_subject_key_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS contributions_consent_record_stance
    ON cirisnode_contributions (consent_record_stance)
    WHERE consent_record_stance IS NOT NULL;

-- ── 3. consent_sla_watch ───────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cirisnode_consent_sla_watch (
    target_contribution_id    TEXT NOT NULL
        REFERENCES cirisnode_contributions(contribution_id) ON DELETE CASCADE,
    subject_key_id            TEXT NOT NULL,
    revocation_at             TEXT NOT NULL,
    deadline_at               TEXT NOT NULL,
    status                    TEXT NOT NULL
        CHECK (status IN ('pending', 'complete', 'breached')),
    inserted_at               TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    PRIMARY KEY (target_contribution_id, subject_key_id)
);

CREATE INDEX IF NOT EXISTS idx_consent_sla_watch_pending
    ON cirisnode_consent_sla_watch (deadline_at)
    WHERE status = 'pending';

-- ── 4. revocation_promotion_watch ──────────────────────────────────

CREATE TABLE IF NOT EXISTS cirisnode_revocation_promotion_watch (
    revocation_contribution_id TEXT NOT NULL PRIMARY KEY
        REFERENCES cirisnode_contributions(contribution_id) ON DELETE CASCADE,
    admitted_at                TEXT NOT NULL,
    promotion_deadline_at      TEXT NOT NULL,
    status                     TEXT NOT NULL
        CHECK (status IN ('pending', 'promoted', 'overdue')),
    inserted_at                TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);

CREATE INDEX IF NOT EXISTS idx_revocation_promotion_watch_pending
    ON cirisnode_revocation_promotion_watch (promotion_deadline_at)
    WHERE status = 'pending';

-- ── 5. identity_canonical_binding ──────────────────────────────────

CREATE TABLE IF NOT EXISTS identity_canonical_binding (
    canonical_hash       TEXT NOT NULL PRIMARY KEY,
    federation_key_id    TEXT NOT NULL
        REFERENCES federation_keys(key_id) ON DELETE CASCADE,
    bound_at             TEXT NOT NULL,
    binding_attestation_id TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE SET NULL,
    inserted_at          TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);

CREATE INDEX IF NOT EXISTS idx_identity_canonical_binding_federation_key_id
    ON identity_canonical_binding (federation_key_id);
