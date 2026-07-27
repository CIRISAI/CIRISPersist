-- V112 (CIRISPersist#519 item 2a-iii) — the `freshness_floor` table.
-- Postgres dialect. SQLite parity: sqlite/lens/V112. See that file for the
-- full rationale.

CREATE TABLE cirislens.freshness_floor (
    target_key_id    TEXT NOT NULL,
    target_kind      TEXT NOT NULL,
    fresh_as_of      TIMESTAMPTZ NOT NULL,
    signer_form      TEXT NOT NULL,
    attesting_key_id TEXT NOT NULL,
    signed_envelope  TEXT NOT NULL,
    signature        TEXT NOT NULL,
    cohort_scope     TEXT NOT NULL,
    PRIMARY KEY (target_key_id, target_kind)
);
