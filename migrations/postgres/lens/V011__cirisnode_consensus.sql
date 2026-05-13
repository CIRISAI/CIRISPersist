-- V011 — CIRISNodeCore federation-consensus substrate
-- (v0.7.0, FSD CIRIS_PERSIST.md Appendix A.4).
--
-- Companion to CIRISNodeCore's typed-write surface. Persist becomes
-- the federation-stable host for federation-consensus row classes
-- (Contribution / Vote / Ledger / Moderation / Slashing /
-- Reconsideration) — distinct from the lens/agent/bridge substrate
-- on cirislens.* and cirislens_secrets.*.
--
-- # Tables (under the `cirisnode` schema)
--
-- - cirisnode.contributions                    — Contribution envelope rows
-- - cirisnode.votes                            — VoteEnvelope rows
-- - cirisnode.credits_ledger                   — derived Credits balances
-- - cirisnode.expertise_ledger                 — derived Expertise balances
-- - cirisnode.moderation_events                — accusation chain
-- - cirisnode.slashing_attestations            — adjudication outcomes
-- - cirisnode.reconsideration_requests         — reverse-prior-slashing
-- - cirisnode.reconsideration_attestations     — reconsideration outcomes
--
-- # Common discipline
--
-- Every row carries the same CIRISPersist audit-envelope columns we
-- standardized in V004 federation_keys + V001 trace_events:
--   - signature                  (Ed25519, base64)
--   - signing_key_id             (FK→federation_keys.key_id)
--   - signature_verified         (set by ingest path)
--   - original_content_hash      (sha256 hex of canonical pre-scrub)
--   - scrub_signature_classical  (Ed25519 over canonical bytes)
--   - scrub_signature_pqc        (ML-DSA-65, cold-path PQC fill-in)
--   - scrub_key_id               (steward signing key)
--   - scrub_timestamp            (federation steward asserted-at)
--   - pqc_completed_at           (when scrub_signature_pqc landed)
--   - persist_row_hash           (row-shape integrity)
--
-- All seven tables ship with the IF NOT EXISTS discipline (idempotent
-- multi-worker boot, v0.6.1-α3 lesson learned).

BEGIN;

CREATE SCHEMA IF NOT EXISTS cirisnode;

-- ── contributions — the common Contribution envelope ────────────────

CREATE TABLE IF NOT EXISTS cirisnode.contributions (
    -- ULID per CIRISNodeCore/SCHEMA.md §2.2. UUID column type so
    -- pg-side queries can index on the binary form; the wire shape
    -- accepts ULID strings + parses to UUID at insert time.
    contribution_id               UUID PRIMARY KEY,

    -- §3.1 discriminator. CHECK against the 7-variant enum.
    contribution_type             TEXT NOT NULL
        CHECK (contribution_type IN (
            'deferral_request',
            'deferral_response',
            'proposal',
            'wa_candidacy',
            'expertise_attestation',
            'moderation_event',
            'reconsideration_request'
        )),

    -- §2.5 cell — domain + language + subject_kind.
    domain                        TEXT NOT NULL,
    language                      TEXT NOT NULL,
    subject_kind                  TEXT NOT NULL,

    -- §2.2 ContributorId — base64url Ed25519 public key. Must match
    -- signature.ed25519 signer (verified by ingest path).
    author_id                     TEXT NOT NULL,

    -- §3 payload + envelope-level fields. JSONB so per-subject-kind
    -- shapes nest cleanly without per-payload columns.
    payload                       JSONB NOT NULL,

    -- §3.6 witness_set (for high-stakes contributions). JSONB or NULL.
    witness_set                   JSONB,

    -- §3 submitted_at — caller-asserted wall-clock.
    submitted_at                  TIMESTAMPTZ NOT NULL,

    -- Standard CIRISPersist audit envelope (matches V004 / V001 shape).
    signature                     TEXT NOT NULL,
    signing_key_id                TEXT NOT NULL,
    signature_verified            BOOLEAN NOT NULL DEFAULT FALSE,
    original_content_hash         BYTEA,
    scrub_signature_classical     TEXT,
    scrub_signature_pqc           TEXT,
    scrub_key_id                  TEXT,
    scrub_timestamp               TIMESTAMPTZ,
    pqc_completed_at              TIMESTAMPTZ,
    persist_row_hash              TEXT NOT NULL,

    -- §13.2 pending vs canonical split. Set to TRUE when the
    -- contribution has passed the canonical-audit-chain gate.
    is_canonical                  BOOLEAN NOT NULL DEFAULT FALSE,
    canonicalized_at              TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS contributions_type        ON cirisnode.contributions (contribution_type);
CREATE INDEX IF NOT EXISTS contributions_cell        ON cirisnode.contributions (domain, language);
CREATE INDEX IF NOT EXISTS contributions_author      ON cirisnode.contributions (author_id);
CREATE INDEX IF NOT EXISTS contributions_submitted   ON cirisnode.contributions (submitted_at);
CREATE INDEX IF NOT EXISTS contributions_canonical   ON cirisnode.contributions (is_canonical, canonicalized_at)
    WHERE is_canonical = TRUE;

COMMENT ON TABLE cirisnode.contributions IS
    'v0.7.0 (CIRISPersist#30 Appendix A.4) — federation-consensus Contribution envelope. Discriminated by contribution_type + subject_kind. CIRISNodeCore Primitive 5.';

-- ── votes — VoteEnvelope ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cirisnode.votes (
    -- §5 VoteEnvelope; ULID.
    vote_id                       UUID PRIMARY KEY,

    -- Subject of the vote — almost always a contribution_id. NULL
    -- on votes that target non-Contribution subjects (rare; allowed
    -- for §5 free-form polls).
    contribution_id               UUID REFERENCES cirisnode.contributions(contribution_id),

    voter_id                      TEXT NOT NULL,
    domain                        TEXT NOT NULL,
    language                      TEXT NOT NULL,

    -- §5 vote payload (yes/no/abstain + rationale + cell-weighted
    -- multipliers carried per the SCHEMA.md spec).
    payload                       JSONB NOT NULL,

    cast_at                       TIMESTAMPTZ NOT NULL,

    -- Audit envelope.
    signature                     TEXT NOT NULL,
    signing_key_id                TEXT NOT NULL,
    signature_verified            BOOLEAN NOT NULL DEFAULT FALSE,
    original_content_hash         BYTEA,
    scrub_signature_classical     TEXT,
    scrub_signature_pqc           TEXT,
    scrub_key_id                  TEXT,
    scrub_timestamp               TIMESTAMPTZ,
    pqc_completed_at              TIMESTAMPTZ,
    persist_row_hash              TEXT NOT NULL,

    is_canonical                  BOOLEAN NOT NULL DEFAULT FALSE,
    canonicalized_at              TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS votes_contribution ON cirisnode.votes (contribution_id)
    WHERE contribution_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS votes_voter        ON cirisnode.votes (voter_id);
CREATE INDEX IF NOT EXISTS votes_cell         ON cirisnode.votes (domain, language);
CREATE INDEX IF NOT EXISTS votes_cast_at      ON cirisnode.votes (cast_at);

COMMENT ON TABLE cirisnode.votes IS
    'v0.7.0 — VoteEnvelope rows. Voting on Contributions; weighted by Credits × expertise_multiplier × active_tier_multiplier per SCHEMA.md §5.2.';

-- ── credits_ledger — derived Credits balances ───────────────────────

CREATE TABLE IF NOT EXISTS cirisnode.credits_ledger (
    contributor_id                TEXT NOT NULL,
    domain                        TEXT NOT NULL,
    language                      TEXT NOT NULL,
    subject                       TEXT NOT NULL,

    -- Balance + per-Contribution attribution. Negative values are
    -- allowed for slashing outcomes per SCHEMA.md §10.
    balance                       DOUBLE PRECISION NOT NULL DEFAULT 0,

    -- Most-recent contribution_id that affected this row.
    last_update_contribution      UUID REFERENCES cirisnode.contributions(contribution_id),

    -- Lifecycle.
    last_updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (contributor_id, domain, language, subject)
);

CREATE INDEX IF NOT EXISTS credits_contributor ON cirisnode.credits_ledger (contributor_id);
CREATE INDEX IF NOT EXISTS credits_cell        ON cirisnode.credits_ledger (domain, language);

COMMENT ON TABLE cirisnode.credits_ledger IS
    'v0.7.0 — derived Credits balances per (contributor, cell, subject). SCHEMA.md §10.';

-- ── expertise_ledger — derived Expertise balances ───────────────────

CREATE TABLE IF NOT EXISTS cirisnode.expertise_ledger (
    contributor_id                TEXT NOT NULL,
    domain                        TEXT NOT NULL,
    language                      TEXT NOT NULL,

    -- Expertise value in [0, 1] per SCHEMA.md §10. Used as multiplier
    -- on the vote-weight computation.
    expertise                     DOUBLE PRECISION NOT NULL DEFAULT 0
        CHECK (expertise >= 0 AND expertise <= 1),

    -- §3.8 active-tier flag — only Active contributors count for
    -- routing. Updated by the consensus pass that promotes active
    -- attestations through the canonical-chain gate.
    is_active                     BOOLEAN NOT NULL DEFAULT FALSE,

    -- Lifecycle.
    last_updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_update_contribution      UUID REFERENCES cirisnode.contributions(contribution_id),
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (contributor_id, domain, language)
);

CREATE INDEX IF NOT EXISTS expertise_contributor ON cirisnode.expertise_ledger (contributor_id);
CREATE INDEX IF NOT EXISTS expertise_cell        ON cirisnode.expertise_ledger (domain, language);
CREATE INDEX IF NOT EXISTS expertise_routable    ON cirisnode.expertise_ledger (domain, language, is_active)
    WHERE expertise > 0 AND is_active = TRUE;

COMMENT ON TABLE cirisnode.expertise_ledger IS
    'v0.7.0 — derived Expertise balances per (contributor, cell). Routing-eligibility lookup uses the partial index for the WHERE is_active path.';

-- ── moderation_events — accusation chain ────────────────────────────

CREATE TABLE IF NOT EXISTS cirisnode.moderation_events (
    moderation_id                 UUID PRIMARY KEY,

    -- Who is being accused.
    target_contributor            TEXT NOT NULL,

    -- Who is filing.
    accuser_id                    TEXT NOT NULL,

    -- §8 payload — what they did, evidence refs, etc.
    payload                       JSONB NOT NULL,

    filed_at                      TIMESTAMPTZ NOT NULL,

    -- Audit envelope.
    signature                     TEXT NOT NULL,
    signing_key_id                TEXT NOT NULL,
    signature_verified            BOOLEAN NOT NULL DEFAULT FALSE,
    original_content_hash         BYTEA,
    scrub_signature_classical     TEXT,
    scrub_signature_pqc           TEXT,
    scrub_key_id                  TEXT,
    scrub_timestamp               TIMESTAMPTZ,
    pqc_completed_at              TIMESTAMPTZ,
    persist_row_hash              TEXT NOT NULL,

    is_canonical                  BOOLEAN NOT NULL DEFAULT FALSE,
    canonicalized_at              TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS moderation_target   ON cirisnode.moderation_events (target_contributor);
CREATE INDEX IF NOT EXISTS moderation_accuser  ON cirisnode.moderation_events (accuser_id);
CREATE INDEX IF NOT EXISTS moderation_filed_at ON cirisnode.moderation_events (filed_at);

COMMENT ON TABLE cirisnode.moderation_events IS
    'v0.7.0 — Primitive 8 ModerationEvent. Accusation chain; per-event adjudication results land in slashing_attestations.';

-- ── slashing_attestations — adjudication outcomes ───────────────────

CREATE TABLE IF NOT EXISTS cirisnode.slashing_attestations (
    slashing_id                   UUID PRIMARY KEY,

    -- The moderation_event being adjudicated.
    moderation_id                 UUID NOT NULL REFERENCES cirisnode.moderation_events(moderation_id),

    -- Adjudicator.
    adjudicator_id                TEXT NOT NULL,

    -- §8 outcome payload — direction (sustain / dismiss / partial),
    -- magnitude, attestation rationale.
    payload                       JSONB NOT NULL,

    attested_at                   TIMESTAMPTZ NOT NULL,

    -- Audit envelope.
    signature                     TEXT NOT NULL,
    signing_key_id                TEXT NOT NULL,
    signature_verified            BOOLEAN NOT NULL DEFAULT FALSE,
    original_content_hash         BYTEA,
    scrub_signature_classical     TEXT,
    scrub_signature_pqc           TEXT,
    scrub_key_id                  TEXT,
    scrub_timestamp               TIMESTAMPTZ,
    pqc_completed_at              TIMESTAMPTZ,
    persist_row_hash              TEXT NOT NULL,

    is_canonical                  BOOLEAN NOT NULL DEFAULT FALSE,
    canonicalized_at              TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS slashing_moderation   ON cirisnode.slashing_attestations (moderation_id);
CREATE INDEX IF NOT EXISTS slashing_adjudicator  ON cirisnode.slashing_attestations (adjudicator_id);
CREATE INDEX IF NOT EXISTS slashing_attested_at  ON cirisnode.slashing_attestations (attested_at);

COMMENT ON TABLE cirisnode.slashing_attestations IS
    'v0.7.0 — SlashingAttestation outcomes. One row per adjudication; the consensus pass derives credits_ledger / expertise_ledger updates from these.';

-- ── reconsideration_requests — reverse-prior-slashing ──────────────

CREATE TABLE IF NOT EXISTS cirisnode.reconsideration_requests (
    request_id                    UUID PRIMARY KEY,

    -- The slashing being reconsidered.
    slashing_id                   UUID NOT NULL REFERENCES cirisnode.slashing_attestations(slashing_id),

    requester_id                  TEXT NOT NULL,

    -- §9 payload — grounds for reconsideration, new evidence.
    payload                       JSONB NOT NULL,

    requested_at                  TIMESTAMPTZ NOT NULL,

    -- Audit envelope.
    signature                     TEXT NOT NULL,
    signing_key_id                TEXT NOT NULL,
    signature_verified            BOOLEAN NOT NULL DEFAULT FALSE,
    original_content_hash         BYTEA,
    scrub_signature_classical     TEXT,
    scrub_signature_pqc           TEXT,
    scrub_key_id                  TEXT,
    scrub_timestamp               TIMESTAMPTZ,
    pqc_completed_at              TIMESTAMPTZ,
    persist_row_hash              TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS reconsideration_req_slashing  ON cirisnode.reconsideration_requests (slashing_id);
CREATE INDEX IF NOT EXISTS reconsideration_req_requester ON cirisnode.reconsideration_requests (requester_id);

COMMENT ON TABLE cirisnode.reconsideration_requests IS
    'v0.7.0 — Primitive 11 ReconsiderationRequest. Reverses a prior SlashingAttestation.';

-- ── reconsideration_attestations — reconsideration outcomes ────────

CREATE TABLE IF NOT EXISTS cirisnode.reconsideration_attestations (
    reconsideration_id            UUID PRIMARY KEY,

    request_id                    UUID NOT NULL REFERENCES cirisnode.reconsideration_requests(request_id),

    adjudicator_id                TEXT NOT NULL,

    -- §9 outcome — uphold / reverse / partial, rationale.
    payload                       JSONB NOT NULL,

    attested_at                   TIMESTAMPTZ NOT NULL,

    -- Audit envelope.
    signature                     TEXT NOT NULL,
    signing_key_id                TEXT NOT NULL,
    signature_verified            BOOLEAN NOT NULL DEFAULT FALSE,
    original_content_hash         BYTEA,
    scrub_signature_classical     TEXT,
    scrub_signature_pqc           TEXT,
    scrub_key_id                  TEXT,
    scrub_timestamp               TIMESTAMPTZ,
    pqc_completed_at              TIMESTAMPTZ,
    persist_row_hash              TEXT NOT NULL,

    is_canonical                  BOOLEAN NOT NULL DEFAULT FALSE,
    canonicalized_at              TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS reconsideration_att_request    ON cirisnode.reconsideration_attestations (request_id);
CREATE INDEX IF NOT EXISTS reconsideration_att_adjudicator ON cirisnode.reconsideration_attestations (adjudicator_id);

COMMENT ON TABLE cirisnode.reconsideration_attestations IS
    'v0.7.0 — ReconsiderationAttestation outcomes. When canonical-and-reverse, the consensus pass undoes the original SlashingAttestation`s ledger effects.';

COMMIT;
