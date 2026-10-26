-- V203 — the cirisnode typed silos move onto `scores` rows.
-- SQLite dialect. v60.0.0 (CIRISPersist#988 item 1, #803, #854; CC 3.1.9,
-- CC 3.1.1, CC 3.3.2).
--
-- POSTGRES PARITY: migrations/postgres/lens/V203__cirisnode_silos_onto_scores.sql
--
-- WHY
-- ---
-- Signed attestations are the only state. Every cirisnode class is a
-- dimension CC 3.1.9 registers: a Contribution is the scores row itself
-- (`contribution:{subject_kind}:v1`), a vote is `vote:{contribution_id}:v1`,
-- a moderation event `moderation:{allegation_type}:v1`, a slashing
-- `slashing:{outcome}:v1`, a reconsideration `reconsideration:{grounds}:v1`,
-- a takedown notice `takedown_notice:{basis}:v1`. The rows are hybrid-signed
-- by their contributor and replicate like any row; the typed tables that held
-- self-signed Ed25519-only copies go.
--
-- HOW
-- ---
-- 1. Dropped: contributions, votes, moderation_events, slashing_attestations,
--    reconsideration_requests, reconsideration_attestations, and the two V056
--    watch tables that hung off contributions (nothing reads them). Their
--    rows were self-signed by a contributor key persist cannot re-sign, so
--    they cannot become rows; nothing outside persist wrote these tables.
-- 2. Kept as PROJECTIONS: credits_ledger and expertise_ledger, each row the
--    fold of this node's `credits:` / `expertise:` rows, with an
--    `attestation_id` naming the row it came from. A pre-V203 ledger row has
--    none (NULL) until the rehome re-emits it as a row.
-- 3. Kept as local bookkeeping, unchanged except that the foreign key into
--    the dropped contributions table goes: scheduled_takedown_actions and
--    federation_delivery_attestations (their ids now name rows).
-- 4. The executed takedowns' `legal_basis` takes CC 3.3.2's wire strings
--    (`dmca512`, `dsa_article16`), the spelling the notice row's dimension
--    carries.
--
-- Rebuild shape: each kept table is staged, dropped, and re-created under its
-- final name (no `_new` + RENAME; the V136 lesson about SQLite's deferred-FK
-- counter). Children are dropped before their parents.

CREATE TABLE v203_stage_credits AS
    SELECT contributor_id, domain, language, subject, balance,
           last_update_contribution, last_updated_at, created_at
      FROM cirisnode_credits_ledger;
CREATE TABLE v203_stage_expertise AS
    SELECT contributor_id, domain, language, expertise, is_active,
           last_updated_at, last_update_contribution, created_at
      FROM cirisnode_expertise_ledger;
CREATE TABLE v203_stage_scheduled AS
    SELECT notice_contribution_id, scheduled_eviction_at, status, inserted_at
      FROM cirisnode_scheduled_takedown_actions;
CREATE TABLE v203_stage_delivery AS
    SELECT announcement_id, announcement_canonical_hash, peer_key_id,
           peer_pubkey_ed25519_base64, received_at, transport_id,
           signature_classical, signature_pqc, inserted_at, signature_verified,
           persist_row_hash
      FROM cirisnode_federation_delivery_attestations;

DROP TABLE cirisnode_reconsideration_attestations;
DROP TABLE cirisnode_reconsideration_requests;
DROP TABLE cirisnode_slashing_attestations;
DROP TABLE cirisnode_moderation_events;
DROP TABLE cirisnode_votes;
DROP TABLE cirisnode_credits_ledger;
DROP TABLE cirisnode_expertise_ledger;
DROP TABLE cirisnode_scheduled_takedown_actions;
DROP TABLE cirisnode_federation_delivery_attestations;
DROP TABLE cirisnode_consent_sla_watch;
DROP TABLE cirisnode_revocation_promotion_watch;
DROP TABLE cirisnode_contributions;

CREATE TABLE cirisnode_credits_ledger (
    contributor_id                TEXT NOT NULL,
    domain                        TEXT NOT NULL,
    language                      TEXT NOT NULL,
    subject                       TEXT NOT NULL,
    balance                       REAL NOT NULL DEFAULT 0,
    last_update_contribution      TEXT,
    last_updated_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    created_at                    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    attestation_id                TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE CASCADE,
    PRIMARY KEY (contributor_id, domain, language, subject)
);
CREATE INDEX IF NOT EXISTS credits_contributor ON cirisnode_credits_ledger (contributor_id);
CREATE INDEX IF NOT EXISTS credits_cell        ON cirisnode_credits_ledger (domain, language);
INSERT INTO cirisnode_credits_ledger
    (contributor_id, domain, language, subject, balance,
     last_update_contribution, last_updated_at, created_at)
    SELECT contributor_id, domain, language, subject, balance,
           last_update_contribution, last_updated_at, created_at
      FROM v203_stage_credits;

CREATE TABLE cirisnode_expertise_ledger (
    contributor_id                TEXT NOT NULL,
    domain                        TEXT NOT NULL,
    language                      TEXT NOT NULL,
    expertise                     REAL NOT NULL DEFAULT 0
        CHECK (expertise >= 0 AND expertise <= 1),
    is_active                     INTEGER NOT NULL DEFAULT 0,
    last_updated_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    last_update_contribution      TEXT,
    created_at                    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    attestation_id                TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE CASCADE,
    PRIMARY KEY (contributor_id, domain, language)
);
CREATE INDEX IF NOT EXISTS expertise_contributor ON cirisnode_expertise_ledger (contributor_id);
CREATE INDEX IF NOT EXISTS expertise_cell        ON cirisnode_expertise_ledger (domain, language);
CREATE INDEX IF NOT EXISTS expertise_routable    ON cirisnode_expertise_ledger (domain, language, is_active)
    WHERE expertise > 0 AND is_active = 1;
INSERT INTO cirisnode_expertise_ledger
    (contributor_id, domain, language, expertise, is_active,
     last_updated_at, last_update_contribution, created_at)
    SELECT contributor_id, domain, language, expertise, is_active,
           last_updated_at, last_update_contribution, created_at
      FROM v203_stage_expertise;

CREATE TABLE cirisnode_scheduled_takedown_actions (
    notice_contribution_id    TEXT NOT NULL PRIMARY KEY,
    scheduled_eviction_at     TEXT NOT NULL,
    status                    TEXT NOT NULL
        CHECK (status IN ('pending', 'evicted', 'counter_noticed', 'expired')),
    inserted_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_scheduled_takedowns_pending
    ON cirisnode_scheduled_takedown_actions (scheduled_eviction_at)
    WHERE status = 'pending';
INSERT INTO cirisnode_scheduled_takedown_actions
    (notice_contribution_id, scheduled_eviction_at, status, inserted_at)
    SELECT notice_contribution_id, scheduled_eviction_at, status, inserted_at
      FROM v203_stage_scheduled;

CREATE TABLE cirisnode_federation_delivery_attestations (
    announcement_id              TEXT NOT NULL,
    announcement_canonical_hash  BLOB NOT NULL
        CHECK (length(announcement_canonical_hash) = 32),
    peer_key_id                  TEXT NOT NULL,
    peer_pubkey_ed25519_base64   TEXT NOT NULL,
    received_at                  TEXT NOT NULL,
    transport_id                 TEXT NOT NULL
        CHECK (transport_id IN ('reticulum', 'tcp_tls', 'http_over_tls', 'other')),
    signature_classical          BLOB NOT NULL
        CHECK (length(signature_classical) = 64),
    signature_pqc                BLOB
        CHECK (signature_pqc IS NULL OR length(signature_pqc) = 3309),
    inserted_at                  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')),
    signature_verified           INTEGER NOT NULL DEFAULT 0,
    persist_row_hash             TEXT NOT NULL,
    PRIMARY KEY (announcement_id, peer_key_id)
);
CREATE INDEX IF NOT EXISTS federation_delivery_attestations_peer
    ON cirisnode_federation_delivery_attestations (peer_key_id);
CREATE INDEX IF NOT EXISTS federation_delivery_attestations_received_at
    ON cirisnode_federation_delivery_attestations (received_at);
INSERT INTO cirisnode_federation_delivery_attestations
    (announcement_id, announcement_canonical_hash, peer_key_id,
     peer_pubkey_ed25519_base64, received_at, transport_id, signature_classical,
     signature_pqc, inserted_at, signature_verified, persist_row_hash)
    SELECT announcement_id, announcement_canonical_hash, peer_key_id,
           peer_pubkey_ed25519_base64, received_at, transport_id,
           signature_classical, signature_pqc, inserted_at, signature_verified,
           persist_row_hash
      FROM v203_stage_delivery;

DROP TABLE v203_stage_credits;
DROP TABLE v203_stage_expertise;
DROP TABLE v203_stage_scheduled;
DROP TABLE v203_stage_delivery;

UPDATE purge_executions SET legal_basis = 'dmca512' WHERE legal_basis = 'dmca_512';
UPDATE purge_executions SET legal_basis = 'dsa_article16' WHERE legal_basis = 'dsa_article_16';
