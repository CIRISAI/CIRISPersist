-- V038 — atomic per-identity monotonic sequence primitive
-- (v1.7.1, CIRISPersist#83).
--
-- One row per (identity, stream). `next_sequence` does an atomic
-- INSERT ... ON CONFLICT DO UPDATE ... RETURNING that bumps and
-- returns the counter in a single statement — correct under
-- concurrent callers across occurrences + in-process consumers
-- sharing one Ed25519 identity (PoB §3.2 one-key model).
--
-- Refinery wraps each migration in its own transaction; no
-- explicit BEGIN/COMMIT.

CREATE TABLE cirislens.identity_sequences (
    identity    TEXT NOT NULL,
    stream      TEXT NOT NULL,
    next_value  BIGINT NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (identity, stream)
);

COMMENT ON TABLE cirislens.identity_sequences IS
    'v1.7.1 (CIRISPersist#83) — atomic monotonic sequence counters keyed (identity, stream). next_value is the LAST issued value; the issuing UPSERT bumps then RETURNs.';
