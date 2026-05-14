-- V011 — CIRISNodeCore federation-consensus substrate, SQLite dialect
-- (v0.9.4, CIRISPersist#40).
--
-- Postgres parity (postgres/lens/V011): same 7 tables, same audit
-- envelope shape, same FK topology. SQLite has no schema namespace —
-- tables are flat-prefixed `cirisnode_*` to match the v0.6.x naming.
--
-- Dialect translations:
--
--   PostgreSQL                       → SQLite
--   ─────────────────────────────────────────────────────────────────
--   UUID                             → TEXT (36-char hyphenated)
--   BYTEA (original_content_hash)    → BLOB
--   JSONB payload / witness_set      → TEXT (canonical JSON)
--   TIMESTAMPTZ                      → TEXT (RFC 3339)
--   DOUBLE PRECISION balance         → REAL
--   BOOLEAN is_canonical             → INTEGER 0/1 (CHECK)
--   NOW()                            → datetime('now', 'subsec')
--   Partial index ON cond            → CREATE INDEX … WHERE (same)

-- ── contributions — Contribution envelope ─────────────────────────

CREATE TABLE IF NOT EXISTS cirisnode_contributions (
    contribution_id               TEXT PRIMARY KEY,
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
    domain                        TEXT NOT NULL,
    language                      TEXT NOT NULL,
    subject_kind                  TEXT NOT NULL,
    author_id                     TEXT NOT NULL,
    payload                       TEXT NOT NULL,
    witness_set                   TEXT,
    submitted_at                  TEXT NOT NULL,
    signature                     TEXT NOT NULL,
    signing_key_id                TEXT NOT NULL,
    signature_verified            INTEGER NOT NULL DEFAULT 0,
    original_content_hash         BLOB,
    scrub_signature_classical     TEXT,
    scrub_signature_pqc           TEXT,
    scrub_key_id                  TEXT,
    scrub_timestamp               TEXT,
    pqc_completed_at              TEXT,
    persist_row_hash              TEXT NOT NULL,
    is_canonical                  INTEGER NOT NULL DEFAULT 0,
    canonicalized_at              TEXT
);

CREATE INDEX IF NOT EXISTS contributions_type      ON cirisnode_contributions (contribution_type);
CREATE INDEX IF NOT EXISTS contributions_cell      ON cirisnode_contributions (domain, language);
CREATE INDEX IF NOT EXISTS contributions_author    ON cirisnode_contributions (author_id);
CREATE INDEX IF NOT EXISTS contributions_submitted ON cirisnode_contributions (submitted_at);
CREATE INDEX IF NOT EXISTS contributions_canonical ON cirisnode_contributions (is_canonical, canonicalized_at)
    WHERE is_canonical = 1;

-- ── votes — VoteEnvelope ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cirisnode_votes (
    vote_id                       TEXT PRIMARY KEY,
    contribution_id               TEXT REFERENCES cirisnode_contributions(contribution_id),
    voter_id                      TEXT NOT NULL,
    domain                        TEXT NOT NULL,
    language                      TEXT NOT NULL,
    payload                       TEXT NOT NULL,
    cast_at                       TEXT NOT NULL,
    signature                     TEXT NOT NULL,
    signing_key_id                TEXT NOT NULL,
    signature_verified            INTEGER NOT NULL DEFAULT 0,
    original_content_hash         BLOB,
    scrub_signature_classical     TEXT,
    scrub_signature_pqc           TEXT,
    scrub_key_id                  TEXT,
    scrub_timestamp               TEXT,
    pqc_completed_at              TEXT,
    persist_row_hash              TEXT NOT NULL,
    is_canonical                  INTEGER NOT NULL DEFAULT 0,
    canonicalized_at              TEXT
);

CREATE INDEX IF NOT EXISTS votes_contribution ON cirisnode_votes (contribution_id)
    WHERE contribution_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS votes_voter        ON cirisnode_votes (voter_id);
CREATE INDEX IF NOT EXISTS votes_cell         ON cirisnode_votes (domain, language);
CREATE INDEX IF NOT EXISTS votes_cast_at      ON cirisnode_votes (cast_at);

-- ── credits_ledger — derived Credits balances ─────────────────────

CREATE TABLE IF NOT EXISTS cirisnode_credits_ledger (
    contributor_id                TEXT NOT NULL,
    domain                        TEXT NOT NULL,
    language                      TEXT NOT NULL,
    subject                       TEXT NOT NULL,
    balance                       REAL NOT NULL DEFAULT 0,
    last_update_contribution      TEXT REFERENCES cirisnode_contributions(contribution_id),
    last_updated_at               TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    created_at                    TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    PRIMARY KEY (contributor_id, domain, language, subject)
);

CREATE INDEX IF NOT EXISTS credits_contributor ON cirisnode_credits_ledger (contributor_id);
CREATE INDEX IF NOT EXISTS credits_cell        ON cirisnode_credits_ledger (domain, language);

-- ── expertise_ledger — derived Expertise balances ─────────────────

CREATE TABLE IF NOT EXISTS cirisnode_expertise_ledger (
    contributor_id                TEXT NOT NULL,
    domain                        TEXT NOT NULL,
    language                      TEXT NOT NULL,
    expertise                     REAL NOT NULL DEFAULT 0
        CHECK (expertise >= 0 AND expertise <= 1),
    is_active                     INTEGER NOT NULL DEFAULT 0,
    last_updated_at               TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    last_update_contribution      TEXT REFERENCES cirisnode_contributions(contribution_id),
    created_at                    TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    PRIMARY KEY (contributor_id, domain, language)
);

CREATE INDEX IF NOT EXISTS expertise_contributor ON cirisnode_expertise_ledger (contributor_id);
CREATE INDEX IF NOT EXISTS expertise_cell        ON cirisnode_expertise_ledger (domain, language);
CREATE INDEX IF NOT EXISTS expertise_routable    ON cirisnode_expertise_ledger (domain, language, is_active)
    WHERE expertise > 0 AND is_active = 1;

-- ── moderation_events — accusation chain ──────────────────────────

CREATE TABLE IF NOT EXISTS cirisnode_moderation_events (
    moderation_id                 TEXT PRIMARY KEY,
    target_contributor            TEXT NOT NULL,
    accuser_id                    TEXT NOT NULL,
    payload                       TEXT NOT NULL,
    filed_at                      TEXT NOT NULL,
    signature                     TEXT NOT NULL,
    signing_key_id                TEXT NOT NULL,
    signature_verified            INTEGER NOT NULL DEFAULT 0,
    original_content_hash         BLOB,
    scrub_signature_classical     TEXT,
    scrub_signature_pqc           TEXT,
    scrub_key_id                  TEXT,
    scrub_timestamp               TEXT,
    pqc_completed_at              TEXT,
    persist_row_hash              TEXT NOT NULL,
    is_canonical                  INTEGER NOT NULL DEFAULT 0,
    canonicalized_at              TEXT
);

CREATE INDEX IF NOT EXISTS moderation_target   ON cirisnode_moderation_events (target_contributor);
CREATE INDEX IF NOT EXISTS moderation_accuser  ON cirisnode_moderation_events (accuser_id);
CREATE INDEX IF NOT EXISTS moderation_filed_at ON cirisnode_moderation_events (filed_at);

-- ── slashing_attestations — adjudication outcomes ─────────────────

CREATE TABLE IF NOT EXISTS cirisnode_slashing_attestations (
    slashing_id                   TEXT PRIMARY KEY,
    moderation_id                 TEXT NOT NULL REFERENCES cirisnode_moderation_events(moderation_id),
    adjudicator_id                TEXT NOT NULL,
    payload                       TEXT NOT NULL,
    attested_at                   TEXT NOT NULL,
    signature                     TEXT NOT NULL,
    signing_key_id                TEXT NOT NULL,
    signature_verified            INTEGER NOT NULL DEFAULT 0,
    original_content_hash         BLOB,
    scrub_signature_classical     TEXT,
    scrub_signature_pqc           TEXT,
    scrub_key_id                  TEXT,
    scrub_timestamp               TEXT,
    pqc_completed_at              TEXT,
    persist_row_hash              TEXT NOT NULL,
    is_canonical                  INTEGER NOT NULL DEFAULT 0,
    canonicalized_at              TEXT
);

CREATE INDEX IF NOT EXISTS slashing_moderation   ON cirisnode_slashing_attestations (moderation_id);
CREATE INDEX IF NOT EXISTS slashing_adjudicator  ON cirisnode_slashing_attestations (adjudicator_id);
CREATE INDEX IF NOT EXISTS slashing_attested_at  ON cirisnode_slashing_attestations (attested_at);

-- ── reconsideration_requests — reverse-prior-slashing ─────────────

CREATE TABLE IF NOT EXISTS cirisnode_reconsideration_requests (
    request_id                    TEXT PRIMARY KEY,
    slashing_id                   TEXT NOT NULL REFERENCES cirisnode_slashing_attestations(slashing_id),
    requester_id                  TEXT NOT NULL,
    payload                       TEXT NOT NULL,
    requested_at                  TEXT NOT NULL,
    signature                     TEXT NOT NULL,
    signing_key_id                TEXT NOT NULL,
    signature_verified            INTEGER NOT NULL DEFAULT 0,
    original_content_hash         BLOB,
    scrub_signature_classical     TEXT,
    scrub_signature_pqc           TEXT,
    scrub_key_id                  TEXT,
    scrub_timestamp               TEXT,
    pqc_completed_at              TEXT,
    persist_row_hash              TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS reconsideration_req_slashing  ON cirisnode_reconsideration_requests (slashing_id);
CREATE INDEX IF NOT EXISTS reconsideration_req_requester ON cirisnode_reconsideration_requests (requester_id);

-- ── reconsideration_attestations — reconsideration outcomes ──────

CREATE TABLE IF NOT EXISTS cirisnode_reconsideration_attestations (
    reconsideration_id            TEXT PRIMARY KEY,
    request_id                    TEXT NOT NULL REFERENCES cirisnode_reconsideration_requests(request_id),
    adjudicator_id                TEXT NOT NULL,
    payload                       TEXT NOT NULL,
    attested_at                   TEXT NOT NULL,
    signature                     TEXT NOT NULL,
    signing_key_id                TEXT NOT NULL,
    signature_verified            INTEGER NOT NULL DEFAULT 0,
    original_content_hash         BLOB,
    scrub_signature_classical     TEXT,
    scrub_signature_pqc           TEXT,
    scrub_key_id                  TEXT,
    scrub_timestamp               TEXT,
    pqc_completed_at              TEXT,
    persist_row_hash              TEXT NOT NULL,
    is_canonical                  INTEGER NOT NULL DEFAULT 0,
    canonicalized_at              TEXT
);

CREATE INDEX IF NOT EXISTS reconsideration_att_request     ON cirisnode_reconsideration_attestations (request_id);
CREATE INDEX IF NOT EXISTS reconsideration_att_adjudicator ON cirisnode_reconsideration_attestations (adjudicator_id);
