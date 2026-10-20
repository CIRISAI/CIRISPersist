-- V199 — the self-roster door's node-local proposal ledger.
-- SQLite dialect. v59.0.0 (CIRISPersist#1099; CC 3.3.6.3,
-- CLM-self-roster-two-paths).
--
-- POSTGRES PARITY: migrations/postgres/lens/V199__self_roster_proposals.sql
--
-- WHY
-- ---
-- An addition to or an eviction from a self's key roster is a PROPOSAL once
-- the roster holds two keys or more: it lands at once by a strict majority of
-- the live roster, or by the lone path after `W_self` (86 400 s) with no
-- strict majority of the other members objecting (`federation::two_path`).
-- The proposal itself is a row on the attestation plane
-- (`objection:proposal:v1`, `federation::self_roster`), so it replicates and
-- every node of the self can answer it. Its WINDOW, though, runs on each
-- node's own clock, from the instant that node first held it — never the
-- signer's `asserted_at`, which the proposer chooses. That instant is a fact
-- about this node, not about the row, so it lives here and is never hashed or
-- served.
--
-- HOW
-- ---
-- One row per proposal this node holds. `received_at` is first-seen and
-- never moves (INSERT OR IGNORE). `settled_at` / `outcome` are written once,
-- when the door executes the proposal (`lands_quorum`, `lands_lone`) or
-- refuses it for good (`proposer_not_on_roster`); an open proposal has both
-- NULL, and the partial index makes the sweep's "which are open?" probe free.
-- ON DELETE CASCADE: a purge that removes the proposal row removes the
-- ledger entry with it (it describes nothing else).

CREATE TABLE IF NOT EXISTS federation_self_roster_proposals (
    attestation_id   TEXT PRIMARY KEY
                     REFERENCES federation_attestations(attestation_id) ON DELETE CASCADE,
    identity_key_id  TEXT NOT NULL,
    received_at      TEXT NOT NULL,
    settled_at       TEXT NULL,
    outcome          TEXT NULL,
    CHECK ((settled_at IS NULL) = (outcome IS NULL))
);

CREATE INDEX IF NOT EXISTS federation_self_roster_proposals_open
    ON federation_self_roster_proposals (identity_key_id, received_at)
    WHERE settled_at IS NULL;
