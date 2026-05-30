-- V054 — Media-sharing substrate (CIRISPersist#134, v3.6.0).
--
-- Lands two new `subject_kind` values on the canonical-chain
-- `cirisnode.contributions` table:
--
--   1. `takedown_notice` — a content-claimant asserting that bytes
--      under the named SHA-256 must be evicted from holders' storage
--      (DMCA §512, EU DSA art. 16, TVEC, NCMEC, GIFCT-CIP, OSA, etc.).
--      Persist receives the notice and:
--        a. emits a `withdraws` attestation against every live
--           `holds_bytes` row for that SHA (via `process_takedown_admission`),
--        b. if the basis requires immediate eviction (NCMEC CSAM / GIFCT
--           CIP / OSA illegal-content / court order / perceptual-hash CSAM),
--           also calls `evict_actor` for each holder,
--        c. if the basis admits a counter-notice window (DMCA §512 /
--           DSA art. 16), schedules the eviction in
--           `cirisnode.scheduled_takedown_actions` (10 / 14 day window
--           per the persist defaults documented in
--           `src/cirisnode/media_sharing.rs`).
--
--   2. `key_grant` — a key-distribution envelope binding a wrapped DEK
--      to a recipient `key_id` over a `content_sha256` (or scope tier).
--      Persist persists the envelope; consumers index by recipient or
--      content. Bond-sale composition + registry-license issuance share
--      this row shape per the [[project_one_key_primitive]] memory.
--
-- # Column additions
--
-- Three nullable columns on `cirisnode.contributions`:
--   - `media_content_sha256`  (hex-64, indexed)
--   - `key_grant_recipient_key_id` (TEXT, indexed)
--   - `takedown_legal_basis`  (TEXT, indexed)
--
-- Each gets a partial index, gated on NOT NULL, so the
-- `list_takedowns_for(sha) / list_key_grants_for(recipient) /
-- list_key_grants_for_content(sha, recipient)` reads are O(log N) on
-- the populated subset and pay zero overhead for non-media rows.
--
-- # CHECK discipline (mirroring V046's accord_carrier asymmetry)
--
-- Two table-level CHECKs enforce that the columns are populated iff
-- the subject_kind matches:
--   - takedown_notice <=> media_content_sha256 + takedown_legal_basis NOT NULL
--   - key_grant       <=> media_content_sha256 + key_grant_recipient_key_id NOT NULL
--
-- Direct-SQL bypass cannot land a malformed row. The typed Rust
-- extractors at `extract_takedown_notice_payload` /
-- `extract_key_grant_payload` catch the same rule before the DB layer
-- with a more specific error variant.

-- ── New columns on contributions ───────────────────────────────────

ALTER TABLE cirisnode.contributions
    ADD COLUMN IF NOT EXISTS media_content_sha256 TEXT NULL
        CHECK (media_content_sha256 IS NULL
               OR media_content_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN IF NOT EXISTS key_grant_recipient_key_id TEXT NULL,
    ADD COLUMN IF NOT EXISTS takedown_legal_basis TEXT NULL
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

-- The takedown_notice cross-column CHECK: subject_kind = 'takedown_notice'
-- IFF media_content_sha256 + takedown_legal_basis both populated.
-- Mirrors V046's announcement_columns_match_subject_kind discipline.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'contributions_takedown_columns_match_subject_kind'
          AND conrelid = 'cirisnode.contributions'::regclass
    ) THEN
        ALTER TABLE cirisnode.contributions
            ADD CONSTRAINT contributions_takedown_columns_match_subject_kind
                CHECK (
                    (subject_kind = 'takedown_notice'
                      AND media_content_sha256 IS NOT NULL
                      AND takedown_legal_basis IS NOT NULL)
                    OR
                    (subject_kind <> 'takedown_notice'
                      AND takedown_legal_basis IS NULL)
                );
    END IF;
END$$;

-- The key_grant cross-column CHECK: subject_kind = 'key_grant' IFF
-- media_content_sha256 + key_grant_recipient_key_id both populated.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'contributions_key_grant_columns_match_subject_kind'
          AND conrelid = 'cirisnode.contributions'::regclass
    ) THEN
        ALTER TABLE cirisnode.contributions
            ADD CONSTRAINT contributions_key_grant_columns_match_subject_kind
                CHECK (
                    (subject_kind = 'key_grant'
                      AND media_content_sha256 IS NOT NULL
                      AND key_grant_recipient_key_id IS NOT NULL)
                    OR
                    (subject_kind <> 'key_grant'
                      AND key_grant_recipient_key_id IS NULL)
                );
    END IF;
END$$;

-- Partial indexes — populated only for media-sharing rows; pay no
-- overhead for the canonical-chain general case.
CREATE INDEX IF NOT EXISTS contributions_media_content_sha256
    ON cirisnode.contributions (media_content_sha256)
    WHERE media_content_sha256 IS NOT NULL;

CREATE INDEX IF NOT EXISTS contributions_key_grant_recipient_key_id
    ON cirisnode.contributions (key_grant_recipient_key_id)
    WHERE key_grant_recipient_key_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS contributions_takedown_legal_basis
    ON cirisnode.contributions (takedown_legal_basis)
    WHERE takedown_legal_basis IS NOT NULL;

COMMENT ON COLUMN cirisnode.contributions.media_content_sha256 IS
    'v3.6.0 (CIRISPersist#134) — populated iff subject_kind IN (''takedown_notice'', ''key_grant''). Hex-64 SHA-256 of the content body.';

COMMENT ON COLUMN cirisnode.contributions.key_grant_recipient_key_id IS
    'v3.6.0 (CIRISPersist#134) — populated iff subject_kind = ''key_grant''. The federation_keys.key_id of the recipient.';

COMMENT ON COLUMN cirisnode.contributions.takedown_legal_basis IS
    'v3.6.0 (CIRISPersist#134) — populated iff subject_kind = ''takedown_notice''. Closed-set LegalBasis vocabulary per src/cirisnode/media_sharing.rs.';

-- ── scheduled_takedown_actions ─────────────────────────────────────
--
-- Holds the pending eviction state for counter-notice-eligible
-- takedowns. EvictionSweeper consults this table at each cycle and
-- evicts rows where `scheduled_eviction_at <= now AND status =
-- 'pending'`. The counter-notice arrival side polls for `recants`
-- attestations against the original takedown_notice contribution_id
-- and flips status to 'counter_noticed'.

CREATE TABLE IF NOT EXISTS cirisnode.scheduled_takedown_actions (
    -- The takedown_notice Contribution this action is scheduled for.
    -- One row per notice; the PK enforces this so concurrent
    -- registrations are idempotent.
    notice_contribution_id    UUID PRIMARY KEY
        REFERENCES cirisnode.contributions(contribution_id) ON DELETE RESTRICT,

    -- Wall-clock the sweeper compares against. Counter-notice window
    -- end. Persist defaults: 10 days (DMCA §512), 14 days (DSA art. 16).
    -- Window length lives in code (src/cirisnode/media_sharing.rs),
    -- not the table — the caller computes the deadline before insert.
    scheduled_eviction_at     TIMESTAMPTZ NOT NULL,

    -- Closed-set status vocabulary.
    --   pending          — waiting on the counter-notice window
    --   evicted          — the sweeper has applied the eviction
    --   counter_noticed  — the holder filed a counter-notice; eviction
    --                      stayed
    --   expired          — bookkeeping for actions whose deadline
    --                      passed but the sweeper hasn't yet run
    status                    TEXT NOT NULL
        CHECK (status IN ('pending', 'evicted', 'counter_noticed', 'expired')),

    inserted_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Sweeper scan index: pending actions whose deadline has passed.
CREATE INDEX IF NOT EXISTS idx_scheduled_takedowns_pending
    ON cirisnode.scheduled_takedown_actions (scheduled_eviction_at)
    WHERE status = 'pending';

COMMENT ON TABLE cirisnode.scheduled_takedown_actions IS
    'v3.6.0 (CIRISPersist#134) — counter-notice scheduling. EvictionSweeper consults at each cycle. Counter-notice carrier shape upstream-blocked on CIRISNodeCore#24.';
