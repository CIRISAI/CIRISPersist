-- V132: the `ledgers` consumer-table family (CIRISPersist#754, CC 3.3.10.1 rc4.3).
--
-- The working INDEX for owner-serialized, cohort-witnessed ledgers — heads,
-- checkpoints, entry-range pointers, fork evidence. Constitutionally NOT an
-- envelope plane (CC 1.7 lockdown: no new attestation_type, no new envelope
-- field): the chain itself rides `evidence_refs[]` blobs on `scores` rows in
-- the `ledger:*` dimension family, staged on CIRISConstitution#92. These
-- tables let a node answer "what is this ledger's head / latest witnessed
-- checkpoint / where are its entries" without replaying blobs.
--
-- The balance columns are TEXT decimal strings, not BIGINT: the conservation
-- fold is integer-only over i128 (CC 3.3.10.1 L7) and BIGINT tops out at
-- i64 — a type that silently caps the fold's own arithmetic would be the
-- wrong kind of quiet.
--
-- No BEGIN/COMMIT: refinery wraps each migration in its own transaction (V019 rule).

CREATE TABLE cirislens.ledger_heads (
    ledger_id           TEXT NOT NULL PRIMARY KEY,
    owner_key_id        TEXT NOT NULL,
    unit                TEXT NOT NULL,
    standard_version    TEXT NOT NULL,
    -- NULL until the first head lands: "registered, no head yet" is a real
    -- state and a sentinel value would collapse it into "head at seq 0".
    seq                 BIGINT,
    head_hash           TEXT,
    witness_anchor_ref  TEXT,
    source_envelope_ref TEXT,
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,
    CONSTRAINT ledger_heads_seq_nonneg CHECK (seq IS NULL OR seq >= 0),
    CONSTRAINT ledger_heads_head_pairs CHECK ((seq IS NULL) = (head_hash IS NULL)),
    -- L1: one ledger per (steward-bound identity, unit, standard_version).
    CONSTRAINT ledger_heads_l1_triple UNIQUE (owner_key_id, unit, standard_version)
);

CREATE INDEX idx_ledger_heads_owner ON cirislens.ledger_heads (owner_key_id);

COMMENT ON TABLE cirislens.ledger_heads IS
    'CC 3.3.10.1 L1/L4 working index: one row per ledger triple; head + witness anchor. NOT an envelope plane.';

CREATE TABLE cirislens.ledger_checkpoints (
    ledger_id           TEXT NOT NULL REFERENCES cirislens.ledger_heads (ledger_id),
    seq                 BIGINT NOT NULL,
    balance_minor       TEXT NOT NULL,
    witness_refs        JSONB NOT NULL,
    supersedes_ref      TEXT,
    source_envelope_ref TEXT,
    created_at          TIMESTAMPTZ NOT NULL,
    CONSTRAINT ledger_checkpoints_seq_nonneg CHECK (seq >= 0),
    PRIMARY KEY (ledger_id, seq)
);

COMMENT ON TABLE cirislens.ledger_checkpoints IS
    'CC 3.3.10.1 L5: co-witnessed balance snapshots. Immutable once written — a witnessed fact pins, never flips.';

CREATE TABLE cirislens.ledger_entry_ranges (
    ledger_id       TEXT NOT NULL REFERENCES cirislens.ledger_heads (ledger_id),
    from_seq        BIGINT NOT NULL,
    to_seq          BIGINT NOT NULL,
    blob_ref        TEXT NOT NULL,
    head_hash_at_to TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    CONSTRAINT ledger_entry_ranges_from_nonneg CHECK (from_seq >= 0),
    CONSTRAINT ledger_entry_ranges_ordered CHECK (to_seq >= from_seq),
    PRIMARY KEY (ledger_id, from_seq)
);

CREATE INDEX idx_ledger_entry_ranges_to ON cirislens.ledger_entry_ranges (ledger_id, to_seq);

COMMENT ON TABLE cirislens.ledger_entry_ranges IS
    'CC 3.3.10.1 L2/L6: which evidence_refs blob holds entries [from_seq, to_seq] of a chain.';

-- Deliberately NO foreign key on fork evidence: a proven fork may concern a
-- ledger this node never registered, and refusing the record for lack of a
-- local head row would drop exactly the evidence L8 exists to preserve.
CREATE TABLE cirislens.ledger_fork_evidence (
    evidence_id  TEXT NOT NULL PRIMARY KEY,
    ledger_id    TEXT NOT NULL,
    seq          BIGINT NOT NULL,
    fork_kind    TEXT NOT NULL,
    evidence_json JSONB NOT NULL,
    detected_at  TIMESTAMPTZ NOT NULL,
    CONSTRAINT ledger_fork_evidence_seq_nonneg CHECK (seq >= 0),
    CONSTRAINT ledger_fork_evidence_kind CHECK (fork_kind IN ('double_head', 'witness_contradiction'))
);

CREATE INDEX idx_ledger_fork_evidence_ledger ON cirislens.ledger_fork_evidence (ledger_id);
