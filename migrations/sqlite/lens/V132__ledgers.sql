-- V132: the `ledgers` consumer-table family (CIRISPersist#754, CC 3.3.10.1 rc4.3).
-- SQLite twin of migrations/postgres/lens/V132__ledgers.sql — same tables,
-- same column names, same nullability, same index names.
--
-- Dialect translations (the V034 conventions):
--   TIMESTAMPTZ -> TEXT (RFC 3339)
--   JSONB       -> TEXT
--   BIGINT      -> INTEGER
--   cirislens.<table> -> cirislens_<table>
--
-- balance_minor is a TEXT decimal string in BOTH dialects — the conservation
-- fold is integer-only over i128 (CC 3.3.10.1 L7) and a 64-bit column would
-- silently cap the fold's own arithmetic.
--
-- No BEGIN/COMMIT: refinery wraps each migration in its own transaction (V019 rule).

CREATE TABLE cirislens_ledger_heads (
    ledger_id           TEXT NOT NULL PRIMARY KEY,
    owner_key_id        TEXT NOT NULL,
    unit                TEXT NOT NULL,
    standard_version    TEXT NOT NULL,
    -- NULL until the first head lands: "registered, no head yet" is a real
    -- state and a sentinel value would collapse it into "head at seq 0".
    seq                 INTEGER,
    head_hash           TEXT,
    witness_anchor_ref  TEXT,
    source_envelope_ref TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    CONSTRAINT ledger_heads_seq_nonneg CHECK (seq IS NULL OR seq >= 0),
    CONSTRAINT ledger_heads_head_pairs CHECK ((seq IS NULL) = (head_hash IS NULL)),
    -- L1: one ledger per (steward-bound identity, unit, standard_version).
    CONSTRAINT ledger_heads_l1_triple UNIQUE (owner_key_id, unit, standard_version)
);

CREATE INDEX idx_ledger_heads_owner ON cirislens_ledger_heads (owner_key_id);

CREATE TABLE cirislens_ledger_checkpoints (
    ledger_id           TEXT NOT NULL REFERENCES cirislens_ledger_heads (ledger_id),
    seq                 INTEGER NOT NULL,
    balance_minor       TEXT NOT NULL,
    witness_refs        TEXT NOT NULL,
    supersedes_ref      TEXT,
    source_envelope_ref TEXT,
    created_at          TEXT NOT NULL,
    CONSTRAINT ledger_checkpoints_seq_nonneg CHECK (seq >= 0),
    PRIMARY KEY (ledger_id, seq)
);

CREATE TABLE cirislens_ledger_entry_ranges (
    ledger_id       TEXT NOT NULL REFERENCES cirislens_ledger_heads (ledger_id),
    from_seq        INTEGER NOT NULL,
    to_seq          INTEGER NOT NULL,
    blob_ref        TEXT NOT NULL,
    head_hash_at_to TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    CONSTRAINT ledger_entry_ranges_from_nonneg CHECK (from_seq >= 0),
    CONSTRAINT ledger_entry_ranges_ordered CHECK (to_seq >= from_seq),
    PRIMARY KEY (ledger_id, from_seq)
);

CREATE INDEX idx_ledger_entry_ranges_to ON cirislens_ledger_entry_ranges (ledger_id, to_seq);

-- Deliberately NO foreign key on fork evidence: a proven fork may concern a
-- ledger this node never registered, and refusing the record for lack of a
-- local head row would drop exactly the evidence L8 exists to preserve.
CREATE TABLE cirislens_ledger_fork_evidence (
    evidence_id   TEXT NOT NULL PRIMARY KEY,
    ledger_id     TEXT NOT NULL,
    seq           INTEGER NOT NULL,
    fork_kind     TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    detected_at   TEXT NOT NULL,
    CONSTRAINT ledger_fork_evidence_seq_nonneg CHECK (seq >= 0),
    CONSTRAINT ledger_fork_evidence_kind CHECK (fork_kind IN ('double_head', 'witness_contradiction'))
);

CREATE INDEX idx_ledger_fork_evidence_ledger ON cirislens_ledger_fork_evidence (ledger_id);
