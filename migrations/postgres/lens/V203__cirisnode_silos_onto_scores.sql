-- V203 — the cirisnode typed silos move onto `scores` rows.
-- Postgres dialect. v60.0.0 (CIRISPersist#988 item 1, #803, #854; CC 3.1.9,
-- CC 3.1.1, CC 3.3.2).
--
-- SQLITE PARITY: migrations/sqlite/lens/V203__cirisnode_silos_onto_scores.sql
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
--    CASCADE removes only the foreign-key constraints the kept tables held
--    into contributions, never a kept table.
-- 2. Kept as PROJECTIONS: credits_ledger and expertise_ledger, each row the
--    fold of this node's `credits:` / `expertise:` rows, with an
--    `attestation_id` naming the row it came from. A pre-V203 ledger row has
--    none (NULL) until the rehome re-emits it as a row. The source column
--    names a row id, so it is TEXT like every attestation id (V121).
-- 3. Kept as local bookkeeping: scheduled_takedown_actions and
--    federation_delivery_attestations, their ids now naming rows (TEXT).
-- 4. The executed takedowns' `legal_basis` takes CC 3.3.2's wire strings
--    (`dmca512`, `dsa_article16`), the spelling the notice row's dimension
--    carries.

DROP TABLE IF EXISTS cirisnode.reconsideration_attestations;
DROP TABLE IF EXISTS cirisnode.reconsideration_requests;
DROP TABLE IF EXISTS cirisnode.slashing_attestations;
DROP TABLE IF EXISTS cirisnode.moderation_events;
DROP TABLE IF EXISTS cirisnode.votes;
DROP TABLE IF EXISTS cirislens.cirisnode_consent_sla_watch;
DROP TABLE IF EXISTS cirislens.cirisnode_revocation_promotion_watch;
DROP TABLE IF EXISTS cirisnode.contributions CASCADE;

ALTER TABLE cirisnode.credits_ledger
    ALTER COLUMN last_update_contribution TYPE TEXT USING last_update_contribution::text;
ALTER TABLE cirisnode.credits_ledger
    ADD COLUMN IF NOT EXISTS attestation_id TEXT
        REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE CASCADE;

ALTER TABLE cirisnode.expertise_ledger
    ALTER COLUMN last_update_contribution TYPE TEXT USING last_update_contribution::text;
ALTER TABLE cirisnode.expertise_ledger
    ADD COLUMN IF NOT EXISTS attestation_id TEXT
        REFERENCES cirislens.federation_attestations(attestation_id) ON DELETE CASCADE;

ALTER TABLE cirisnode.scheduled_takedown_actions
    ALTER COLUMN notice_contribution_id TYPE TEXT USING notice_contribution_id::text;

ALTER TABLE cirisnode.federation_delivery_attestations
    ALTER COLUMN announcement_id TYPE TEXT USING announcement_id::text;

UPDATE cirislens.purge_executions SET legal_basis = 'dmca512' WHERE legal_basis = 'dmca_512';
UPDATE cirislens.purge_executions SET legal_basis = 'dsa_article16' WHERE legal_basis = 'dsa_article_16';
