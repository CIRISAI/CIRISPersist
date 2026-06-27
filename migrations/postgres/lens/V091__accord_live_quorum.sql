-- V091 — #302 FSD-004 accord live-quorum storage (Postgres dialect).
--
-- The durable storage substrate for the constitutional kill-switch's
-- decimation-recovery live quorum. CIRISVerify shipped the STATELESS
-- machinery in `ciris_verify_core::accord_live_quorum` (CIRISVerify#150 /
-- #98); the CIRISServer Phase-3 runtime (CIRISServer#122) drives it and
-- writes the wire objects + anti-replay state THROUGH persist. Persist is
-- the storage substrate, so the tables are ours — the live-quorum sibling
-- of the `federation_keys` accord-holder storage (V048).
--
-- Persist's job: store the verify-core canonical objects VERBATIM (never
-- re-derive the bytes), enforce durable dedup / immutability / fail-closed
-- nonce + active-halt state. The TALLY (verify_fire_by_live_quorum etc.) is
-- the SERVER runtime's job — it reads these back and computes the verdict;
-- persist stores the inputs (proposal + participations) and the server's
-- frozen `accord_decision`.
--
-- Recovery (`verify_recovery_supersede`, H7) is DELIBERATELY ABSENT from
-- this cut: it bends entrenchment for the captured-roster case and cannot
-- go live until the CIRIS Constitution sanctions it (CIRISAccord#4). The
-- fire / roster_change / resume objects are unaffected.
--
-- No explicit BEGIN/COMMIT — refinery wraps each migration in a transaction.

-- ─── accord_proposal (append-only; server-issued) ──────────────────
--
-- One row per AccordProposal, keyed by its verify-core digest
-- (`AccordProposal::digest()` = hex-SHA256 of the domain-separated
-- canonical bytes). `proposal_json` is the object VERBATIM so the server
-- reads back byte-identical inputs for the tally. The `(action,
-- prior_family_digest)` index serves proposal COALESCING (H4 — collapse
-- duplicate proposals over the same standing roster). `prior_family_digest`
-- is the digest of the STANDING family envelope, the anti-replay anchor
-- (C3) — never the live set L.
CREATE TABLE IF NOT EXISTS cirislens.accord_proposal (
    proposal_digest      TEXT PRIMARY KEY,
    family_key_id        TEXT NOT NULL,
    action               TEXT NOT NULL
        CHECK (action IN ('fire', 'roster_change', 'resume')),
    nonce                TEXT NOT NULL,
    window_until         TIMESTAMPTZ NOT NULL,
    prior_family_digest  TEXT NOT NULL,
    payload_sha256       TEXT NOT NULL,
    proposal_json        JSONB NOT NULL,
    authority_signature  JSONB,
    persist_row_hash     TEXT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS accord_proposal_by_anchor
    ON cirislens.accord_proposal (action, prior_family_digest);

CREATE INDEX IF NOT EXISTS accord_proposal_by_family
    ON cirislens.accord_proposal (family_key_id);

-- ─── accord_participation (append-only; proof-of-life + vote) ───────
--
-- M6 DURABLE DEDUP: the PRIMARY KEY is `(proposal_digest, pinned_pubkey)`
-- — dedup keyed by the PINNED pubkey, NOT the plaintext `member_id` string
-- (a relay cannot double-count a holder by varying the self-attested seat
-- string). Replaces the in-process per-`valid_until` dedup.
--
-- C2 WINDOW CLOCK: `server_arrival_at` is the AUTHORITATIVE arrival time
-- the server stamps on receipt; `signed_at` is advisory display only and is
-- NOT trusted as the window clock. The server filters L membership by
-- `server_arrival_at <= window_until`.
--
-- `participation_json` is the AccordParticipation VERBATIM (incl. the hybrid
-- ThresholdSignature) — persist verifies it (verify-core
-- AccordParticipation::verify against the pinned member + the stored
-- proposal) BEFORE the row lands, then stores it byte-exact for the tally.
CREATE TABLE IF NOT EXISTS cirislens.accord_participation (
    proposal_digest      TEXT NOT NULL
        REFERENCES cirislens.accord_proposal (proposal_digest),
    member_id            TEXT NOT NULL,
    pinned_pubkey        TEXT NOT NULL,
    vote                 TEXT NOT NULL
        CHECK (vote IN ('yes', 'no', 'abstain')),
    window_until         TIMESTAMPTZ NOT NULL,
    signed_at            TIMESTAMPTZ NOT NULL,
    server_arrival_at    TIMESTAMPTZ NOT NULL,
    participation_json   JSONB NOT NULL,
    persist_row_hash     TEXT NOT NULL,
    PRIMARY KEY (proposal_digest, pinned_pubkey)
);

CREATE INDEX IF NOT EXISTS accord_participation_by_proposal
    ON cirislens.accord_participation (proposal_digest);

-- ─── accord_decision (frozen-L snapshot; IMMUTABLE — M2) ────────────
--
-- The server's frozen verdict over the live set L, one per proposal. Once
-- written it is IMMUTABLE (no UPDATE path; a re-PUT with identical content
-- is an idempotent no-op, a differing one is rejected) — the M2
-- transparency-loggable record. `live_set` is the frozen member_id set; the
-- vote breakdown is `yes/no/abstain`; `steward_signatures` carries the
-- 2-of-3 backstop sigs when |L| < L_FLOOR (H6). `decision_json` is the
-- verify-core AccordDecision VERBATIM.
CREATE TABLE IF NOT EXISTS cirislens.accord_decision (
    proposal_digest      TEXT PRIMARY KEY
        REFERENCES cirislens.accord_proposal (proposal_digest),
    family_key_id        TEXT NOT NULL,
    authorized           BOOLEAN NOT NULL,
    yes                  BIGINT NOT NULL,
    no                   BIGINT NOT NULL,
    abstain              BIGINT NOT NULL,
    live_set             JSONB NOT NULL,
    window_until         TIMESTAMPTZ NOT NULL,
    steward_signatures   JSONB,
    decision_json        JSONB NOT NULL,
    persist_row_hash     TEXT NOT NULL,
    decided_at           TIMESTAMPTZ NOT NULL
);

-- ─── accord_active_halt (H2 support; mutable state) ─────────────────
--
-- The currently-active CONSTITUTIONAL halt id per family, fed to
-- `verify_resume_by_live_quorum` (H2: a resume binds `payload_sha256 ==
-- sha256(active_halt_id)`). Resuming halt-X clears X as active (the row is
-- deleted), so a replayed resume against a no-longer-active halt fails
-- closed. At most one active halt per family.
CREATE TABLE IF NOT EXISTS cirislens.accord_active_halt (
    family_key_id        TEXT PRIMARY KEY,
    active_halt_id       TEXT NOT NULL,
    set_at               TIMESTAMPTZ NOT NULL
);

-- ─── accord_issued_nonce (M4 support; fail-closed) ──────────────────
--
-- The set of server-issued proposal nonces. A proposal / participation
-- referencing a nonce NOT in this set is rejected fail-closed (an attacker
-- cannot mint a proposal against an unissued nonce). Append-only.
CREATE TABLE IF NOT EXISTS cirislens.accord_issued_nonce (
    family_key_id        TEXT NOT NULL,
    nonce                TEXT NOT NULL,
    issued_at            TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (family_key_id, nonce)
);
