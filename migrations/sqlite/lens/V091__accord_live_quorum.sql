-- V091 — #302 FSD-004 accord live-quorum storage (SQLite dialect).
--
-- Postgres parity: postgres/lens/V091. See that file for the full design
-- rationale. The durable storage substrate for the constitutional
-- kill-switch's decimation-recovery live quorum — the live-quorum sibling
-- of the `federation_keys` accord-holder storage. CIRISVerify ships the
-- stateless machinery (`ciris_verify_core::accord_live_quorum`,
-- CIRISVerify#150); CIRISServer Phase-3 (CIRISServer#122) writes through.
--
-- Persist stores the verify-core canonical objects VERBATIM (never
-- re-derives the bytes) and enforces durable dedup / immutability /
-- fail-closed nonce + active-halt state. The tally is the server's job.
-- Recovery (verify_recovery_supersede, H7) is absent — gated on
-- CIRISAccord#4 (cannot go live until the Constitution sanctions it).
--
-- SQLite dialect: bare table names (no schema), TEXT RFC-3339 timestamps,
-- INTEGER (0/1) booleans, `json_valid()` CHECKs in place of JSONB.
--
-- No explicit BEGIN/COMMIT — refinery wraps each migration in a transaction.

-- ─── accord_proposal (append-only; server-issued) ──────────────────
-- PK = verify-core AccordProposal::digest(). proposal_json verbatim.
-- (action, prior_family_digest) index = H4 coalescing. prior_family_digest
-- is the STANDING family envelope digest (anti-replay anchor C3).
CREATE TABLE IF NOT EXISTS accord_proposal (
    proposal_digest      TEXT PRIMARY KEY,
    family_key_id        TEXT NOT NULL,
    action               TEXT NOT NULL
        CHECK (action IN ('fire', 'roster_change', 'resume')),
    nonce                TEXT NOT NULL,
    window_until         TEXT NOT NULL,            -- RFC-3339
    prior_family_digest  TEXT NOT NULL,
    payload_sha256       TEXT NOT NULL,
    proposal_json        TEXT NOT NULL
        CHECK (json_valid(proposal_json)),
    authority_signature  TEXT
        CHECK (authority_signature IS NULL OR json_valid(authority_signature)),
    persist_row_hash     TEXT NOT NULL,
    created_at           TEXT NOT NULL             -- RFC-3339
);

CREATE INDEX IF NOT EXISTS accord_proposal_by_anchor
    ON accord_proposal (action, prior_family_digest);

CREATE INDEX IF NOT EXISTS accord_proposal_by_family
    ON accord_proposal (family_key_id);

-- ─── accord_participation (append-only; proof-of-life + vote) ───────
-- M6 dedup = PK (proposal_digest, pinned_pubkey) — by PINNED pubkey, not
-- the plaintext member_id. C2: server_arrival_at is authoritative,
-- signed_at advisory. participation_json verbatim (incl. ThresholdSignature),
-- verify-core-verified before insert.
CREATE TABLE IF NOT EXISTS accord_participation (
    proposal_digest      TEXT NOT NULL
        REFERENCES accord_proposal (proposal_digest),
    member_id            TEXT NOT NULL,
    pinned_pubkey        TEXT NOT NULL,
    vote                 TEXT NOT NULL
        CHECK (vote IN ('yes', 'no', 'abstain')),
    window_until         TEXT NOT NULL,            -- RFC-3339
    signed_at            TEXT NOT NULL,            -- RFC-3339 (advisory, C2)
    server_arrival_at    TEXT NOT NULL,            -- RFC-3339 (authoritative, C2)
    participation_json   TEXT NOT NULL
        CHECK (json_valid(participation_json)),
    persist_row_hash     TEXT NOT NULL,
    PRIMARY KEY (proposal_digest, pinned_pubkey)
);

CREATE INDEX IF NOT EXISTS accord_participation_by_proposal
    ON accord_participation (proposal_digest);

-- ─── accord_decision (frozen-L snapshot; IMMUTABLE — M2) ────────────
-- One per proposal; immutable once written. authorized stored as INTEGER
-- (0/1). live_set / steward_signatures / decision_json are JSON text.
CREATE TABLE IF NOT EXISTS accord_decision (
    proposal_digest      TEXT PRIMARY KEY
        REFERENCES accord_proposal (proposal_digest),
    family_key_id        TEXT NOT NULL,
    authorized           INTEGER NOT NULL
        CHECK (authorized IN (0, 1)),
    yes                  INTEGER NOT NULL,
    no                   INTEGER NOT NULL,
    abstain              INTEGER NOT NULL,
    live_set             TEXT NOT NULL
        CHECK (json_valid(live_set)),
    window_until         TEXT NOT NULL,            -- RFC-3339
    steward_signatures   TEXT
        CHECK (steward_signatures IS NULL OR json_valid(steward_signatures)),
    decision_json        TEXT NOT NULL
        CHECK (json_valid(decision_json)),
    persist_row_hash     TEXT NOT NULL,
    decided_at           TEXT NOT NULL             -- RFC-3339
);

-- ─── accord_active_halt (H2 support; mutable state) ─────────────────
-- At most one active CONSTITUTIONAL halt per family; resume deletes the row.
CREATE TABLE IF NOT EXISTS accord_active_halt (
    family_key_id        TEXT PRIMARY KEY,
    active_halt_id       TEXT NOT NULL,
    set_at               TEXT NOT NULL             -- RFC-3339
);

-- ─── accord_issued_nonce (M4 support; fail-closed) ──────────────────
-- Server-issued proposal nonces; an unissued nonce is rejected fail-closed.
CREATE TABLE IF NOT EXISTS accord_issued_nonce (
    family_key_id        TEXT NOT NULL,
    nonce                TEXT NOT NULL,
    issued_at            TEXT NOT NULL,            -- RFC-3339
    PRIMARY KEY (family_key_id, nonce)
);
