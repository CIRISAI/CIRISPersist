-- V189 (Codex round 3 on PR #1057, CIRISPersist#1047) — a proposer-minted
-- accord nonce names ONE proposal per family, enforced by the database.
-- Postgres dialect. SQLite parity: sqlite/lens/V189.
--
-- Postgres already serialized the single-use check under a transaction-scoped
-- advisory lock; SQLite did not (two backends on one file could both pass a
-- SELECT-then-INSERT). The claim is now a PRIMARY KEY on both dialects: the
-- door inserts `(family_key_id, nonce) -> proposal_digest` in the same
-- transaction as the proposal, and a different digest already holding the
-- pair is the refusal (`AccordProposalNonceReused`).
--
-- Why a claim table and not a UNIQUE index on `accord_proposal`: rows
-- admitted before #1047 (server-issued nonces, V091-V187) may already share a
-- pair, and an index would fail to build on them. Those rows are evidence and
-- are never deleted. The backfill gives each existing pair to its EARLIEST
-- proposal (`created_at`, then `proposal_digest`), deterministically; the
-- other legacy rows stay in `accord_proposal` untouched, and only a NEW
-- proposal is refused under a claimed pair.
CREATE TABLE IF NOT EXISTS cirislens.accord_proposal_nonce_claim (
    family_key_id    TEXT NOT NULL,
    nonce            TEXT NOT NULL,
    proposal_digest  TEXT NOT NULL,
    PRIMARY KEY (family_key_id, nonce)
);

INSERT INTO cirislens.accord_proposal_nonce_claim (family_key_id, nonce, proposal_digest)
SELECT a.family_key_id, a.nonce, a.proposal_digest
  FROM cirislens.accord_proposal a
 WHERE NOT EXISTS (
        SELECT 1 FROM cirislens.accord_proposal b
         WHERE b.family_key_id = a.family_key_id
           AND b.nonce = a.nonce
           AND (b.created_at < a.created_at
                OR (b.created_at = a.created_at AND b.proposal_digest < a.proposal_digest)))
ON CONFLICT (family_key_id, nonce) DO NOTHING;
