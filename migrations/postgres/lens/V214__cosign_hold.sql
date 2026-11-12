-- V214 — the cosign hold's node-local ledgers.
-- Postgres dialect. v61.3.0 (CIRISPersist#1252; CC 3.3.4 step 2, CC 3.1.3
-- `cosign:{state}`, CC 2.4).
--
-- SQLITE PARITY: migrations/sqlite/lens/V214__cosign_hold.sql
--
-- WHY
-- ---
-- A widening or removal whose ONLY refusal at the typed door is the
-- consensus shortfall is HELD on the primary signer's node as a
-- `cosign:pending:v1` row (the event with no cosignatures; its id is the
-- quorum key, sha256("ciris-persist/cosign-pending/v1" || JCS(the event with
-- no signature))). Each member's cosignature travels alone as a
-- `cosign:signature:v1` row. Both are rows on the attestation plane, so they
-- replicate to the group's active members. Three facts are about THIS node,
-- not about the rows, so they live here and are never hashed or served:
--
-- 1. `federation_cosign_pending` — when this node first held the pending row
--    (the hold window runs on this node's clock from that instant, CC 3.3.6.3
--    and 4.5.3) and how it was settled (`landed`, `expired`, `withdrawn`).
--    The receipt OUTLIVES the rows: expiry and withdrawal drop the pending
--    and signature rows, and a settled receipt refuses a re-offer. So there
--    is no foreign key to the attestation plane.
-- 2. `federation_cosign_signatures` — which signature rows this node holds
--    for a quorum key, one per signer (UNIQUE): the executor's union input.
-- 3. `federation_cosign_aliases` — an assembled act another node holds under
--    a different `attestation_id` (a different sufficient subset of the same
--    act, or other randomised ML-DSA bytes). Recorded when its offer settles
--    as held (`held_equivalent`), so a `withdraws` naming that id resolves to
--    the row this node holds (CC 2.4.1.1 rule 0).
--
-- HOW
-- ---
-- `received_at` is first-seen and never moves (ON CONFLICT DO NOTHING).
-- `settled_at` / `outcome` are written once; an open receipt has both NULL.
-- One OPEN pending per proposer per group: the partial UNIQUE index refuses a
-- second, as the self-roster door's one-open rule does.

CREATE TABLE IF NOT EXISTS cirislens.federation_cosign_pending (
    quorum_key       TEXT PRIMARY KEY,
    group_kind       TEXT NOT NULL CHECK (group_kind IN ('family', 'community')),
    group_key_id     TEXT NOT NULL,
    proposer_key_id  TEXT NOT NULL,
    received_at      TIMESTAMPTZ NOT NULL,
    settled_at       TIMESTAMPTZ NULL,
    outcome          TEXT NULL,
    CHECK ((settled_at IS NULL) = (outcome IS NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS federation_cosign_pending_one_open
    ON cirislens.federation_cosign_pending (group_kind, group_key_id, proposer_key_id)
    WHERE settled_at IS NULL;

CREATE TABLE IF NOT EXISTS cirislens.federation_cosign_signatures (
    attestation_id   TEXT PRIMARY KEY,
    quorum_key       TEXT NOT NULL,
    signer_key_id    TEXT NOT NULL,
    UNIQUE (quorum_key, signer_key_id)
);

CREATE TABLE IF NOT EXISTS cirislens.federation_cosign_aliases (
    alias_attestation_id  TEXT PRIMARY KEY,
    quorum_key            TEXT NOT NULL,
    held_attestation_id   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS federation_cosign_aliases_quorum
    ON cirislens.federation_cosign_aliases (quorum_key);
