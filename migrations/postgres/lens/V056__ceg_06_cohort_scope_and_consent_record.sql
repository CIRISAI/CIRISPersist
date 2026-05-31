-- V056 — CEG 0.6 cohort_scope substrate enforcement + consent_record
--        subject_kind admission + identity_canonical_binding index +
--        consent SLA watcher state (CIRISPersist#146/#150, v3.9.0).
--
-- # What lands
--
-- 1. `federation_attestations.cohort_scope` TEXT NOT NULL DEFAULT 'self'
--    CHECK in closed-set {self, family, community, affiliations,
--    species, biosphere, federation} per CEG §4.2.4 + §8.1.8.
--    `global` is intentionally NOT a value — it's a feed-name in
--    §8.1.8 that aggregates {species, biosphere, federation}; not a
--    wire enum value. Producers writing `global` get rejected at the
--    admission gate.
--
-- 2. `cirisnode_contributions` gains three nullable columns for
--    `subject_kind = 'consent_record'` (CEG §5.6.8.7):
--    - consent_record_subject_key_id TEXT
--    - consent_record_stance TEXT CHECK IN ('granted','revoked','expired')
--    - consent_record_bilateral_pair_id TEXT
--    Plus cross-column CHECK enforcing subject_kind asymmetry
--    (mirrors V054's discipline for takedown_notice + key_grant).
--
-- 3. `cirislens.cirisnode_consent_sla_watch` (NEW) — SLA watcher
--    state. One row per (T, subject) where subject emitted
--    consent:state:revoked or admitted withdraws against T.
--    `deletion_sla_days` from T.attestations.latest determines
--    `deadline_at`. Watcher background task scans pending rows past
--    deadline → emits hard_case:consent_sla_breach (CEG §8.1.11.3).
--
-- 4. `cirislens.cirisnode_revocation_promotion_watch` (NEW) —
--    revocation-promotion-overdue watcher state per CEG §10.1.3.
--    One row per local-tier revocation pending promotion.
--
-- 5. `cirislens.identity_canonical_binding` (NEW) — proxy-chain
--    index for CEG §3.2.3 rule (3) admission of withdraws. Populated
--    when delegates_to(canonical_hash → agent_key, scope:[consent_revocation])
--    is admitted (CEG 0.6 §3.2.3 + §6.5 canonical-hash subject case).

-- ── 1. federation_attestations.cohort_scope ────────────────────────

-- Default 'federation' preserves pre-v3.9.0 semantic — legacy
-- attestations were effectively federation-scope (no cohort_scope
-- declaration meant the content was federation-tier visible).
-- Producers writing new content explicitly tag self/family/etc.
ALTER TABLE cirislens.federation_attestations
    ADD COLUMN IF NOT EXISTS cohort_scope TEXT NOT NULL DEFAULT 'federation';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'federation_attestations_cohort_scope_closed_set'
          AND conrelid = 'cirislens.federation_attestations'::regclass
    ) THEN
        ALTER TABLE cirislens.federation_attestations
            ADD CONSTRAINT federation_attestations_cohort_scope_closed_set
                CHECK (cohort_scope IN (
                    'self', 'family', 'community',
                    'affiliations', 'species', 'biosphere', 'federation'
                ));
    END IF;
END$$;

-- Partial index — only non-self rows (the dominant case where
-- cross-cohort_scope queries hit). cohort_scope='self' should never
-- emit federation_attestations to remote peers; substrate-local-only.
-- Partial index over non-federation rows — federation-scope is the
-- common case post-migration. Narrower cohort_scope (self/family/
-- community) is the read-filter hot path.
CREATE INDEX IF NOT EXISTS federation_attestations_cohort_scope
    ON cirislens.federation_attestations (cohort_scope)
    WHERE cohort_scope != 'federation';

COMMENT ON COLUMN cirislens.federation_attestations.cohort_scope IS
    'v3.9.0 (CIRISPersist#150, CEG §4.2.4). Closed-set producer-side visibility scope. Default ''federation'' (pre-v3.9.0 backward-compat). Orthogonal to subject_key_ids[] (revocability authority). §8.1.8 feed compositions filter by this column.';

-- ── 2. consent_record subject_kind columns ─────────────────────────

ALTER TABLE cirisnode.contributions
    ADD COLUMN IF NOT EXISTS consent_record_subject_key_id TEXT NULL,
    ADD COLUMN IF NOT EXISTS consent_record_stance TEXT NULL
        CHECK (consent_record_stance IS NULL
               OR consent_record_stance IN ('granted', 'revoked', 'expired')),
    ADD COLUMN IF NOT EXISTS consent_record_bilateral_pair_id TEXT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'contributions_consent_record_columns_match_subject_kind'
          AND conrelid = 'cirisnode.contributions'::regclass
    ) THEN
        ALTER TABLE cirisnode.contributions
            ADD CONSTRAINT contributions_consent_record_columns_match_subject_kind
                CHECK (
                    (subject_kind = 'consent_record'
                      AND consent_record_subject_key_id IS NOT NULL
                      AND consent_record_stance IS NOT NULL)
                    OR
                    (subject_kind <> 'consent_record'
                      AND consent_record_subject_key_id IS NULL
                      AND consent_record_stance IS NULL)
                );
    END IF;
END$$;

CREATE INDEX IF NOT EXISTS contributions_consent_record_subject_key_id
    ON cirisnode.contributions (consent_record_subject_key_id)
    WHERE consent_record_subject_key_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS contributions_consent_record_stance
    ON cirisnode.contributions (consent_record_stance)
    WHERE consent_record_stance IS NOT NULL;

COMMENT ON COLUMN cirisnode.contributions.consent_record_subject_key_id IS
    'v3.9.0 (CIRISPersist#146 Ask 5, CEG §5.6.8.7). Populated iff subject_kind = ''consent_record''. The subject_key_id this consent record names (federation_keys.key_id OR canonical-hash).';

-- ── 3. cirisnode_consent_sla_watch ─────────────────────────────────

CREATE TABLE IF NOT EXISTS cirislens.cirisnode_consent_sla_watch (
    -- The target Contribution this SLA covers (the one whose
    -- deletion the SLA promises after revocation). One row per
    -- (target, subject) tuple.
    target_contribution_id    UUID NOT NULL
        REFERENCES cirisnode.contributions(contribution_id) ON DELETE CASCADE,
    subject_key_id            TEXT NOT NULL,
    -- When the subject's revocation was admitted.
    revocation_at             TIMESTAMPTZ NOT NULL,
    -- When the SLA deadline expires (revocation_at + sla_days).
    deadline_at               TIMESTAMPTZ NOT NULL,
    -- Closed-set status vocabulary.
    --   pending   — watcher hasn't fired; deadline not yet passed
    --   complete  — producer emitted consent:deletion_complete in time
    --   breached  — watcher emitted hard_case:consent_sla_breach
    status                    TEXT NOT NULL
        CHECK (status IN ('pending', 'complete', 'breached')),
    inserted_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (target_contribution_id, subject_key_id)
);

-- Watcher scan index: pending rows whose deadline has passed.
CREATE INDEX IF NOT EXISTS idx_consent_sla_watch_pending
    ON cirislens.cirisnode_consent_sla_watch (deadline_at)
    WHERE status = 'pending';

COMMENT ON TABLE cirislens.cirisnode_consent_sla_watch IS
    'v3.9.0 (CIRISPersist#146 Ask 3, CEG §8.1.11.3). Background-task watcher state. EvictionSweeper-shape loop emits hard_case:consent_sla_breach when deadline_at <= NOW() and status = ''pending''.';

-- ── 4. cirisnode_revocation_promotion_watch ────────────────────────

CREATE TABLE IF NOT EXISTS cirislens.cirisnode_revocation_promotion_watch (
    -- The revocation Contribution awaiting promotion to federation
    -- tier per CEG §10.1.3.
    revocation_contribution_id UUID NOT NULL
        REFERENCES cirisnode.contributions(contribution_id) ON DELETE CASCADE,
    -- When the revocation was admitted at local tier.
    admitted_at                TIMESTAMPTZ NOT NULL,
    -- When promotion was expected by default (admitted_at + window).
    promotion_deadline_at      TIMESTAMPTZ NOT NULL,
    status                     TEXT NOT NULL
        CHECK (status IN ('pending', 'promoted', 'overdue')),
    inserted_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (revocation_contribution_id)
);

CREATE INDEX IF NOT EXISTS idx_revocation_promotion_watch_pending
    ON cirislens.cirisnode_revocation_promotion_watch (promotion_deadline_at)
    WHERE status = 'pending';

COMMENT ON TABLE cirislens.cirisnode_revocation_promotion_watch IS
    'v3.9.0 (CIRISPersist#146 Ask 3 + §10.1.3). Watcher state for local-tier revocations awaiting promotion to federation tier. Emits hard_case:revocation_promotion_overdue:v1 on deadline pass.';

-- ── 5. identity_canonical_binding ──────────────────────────────────

CREATE TABLE IF NOT EXISTS cirislens.identity_canonical_binding (
    -- The canonical-hash identifier (e.g. sha256("discord:user_id:12345"))
    -- per CEG §0.6 hex canonicalization.
    canonical_hash       TEXT NOT NULL PRIMARY KEY,
    -- The federation_keys.key_id that has been recognized as the
    -- federation-enrolled identity behind the canonical-hash subject.
    federation_key_id    TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id) ON DELETE CASCADE,
    -- When the binding was admitted (the identity:canonical_binding
    -- attestation's asserted_at).
    bound_at             TIMESTAMPTZ NOT NULL,
    -- The attestation_id of the identity:canonical_binding row that
    -- established the binding. NULL allowed when the binding is
    -- inferred from a delegates_to chain rather than a direct claim.
    binding_attestation_id UUID NULL
        REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE SET NULL,
    inserted_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_identity_canonical_binding_federation_key_id
    ON cirislens.identity_canonical_binding (federation_key_id);

COMMENT ON TABLE cirislens.identity_canonical_binding IS
    'v3.9.0 (CIRISPersist#146 Ask 6, CEG §3.2.3 rule 3 + §4.2.2). Index of canonical-hash subjects bound to federation-enrolled identities. Populated when an identity:canonical_binding attestation is admitted. Consulted at withdraws admission to admit rule-3 proxy-chain revocations.';
