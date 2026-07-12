-- V104 — #424 GENERIC accord-conferred-role WITHDRAW/SUPERSEDE tombstones
-- (Postgres dialect; sqlite/lens/V104 is the parity file — see it for the full
-- design rationale: V095 stays canonical-only, THIS table is the shared
-- primitive for every later accord-conferred role, starting with
-- `infra:attest` (#422 ADD / #424 WITHDRAW)).

CREATE TABLE IF NOT EXISTS cirislens.federation_role_withdrawals (
    role                      TEXT NOT NULL,
    key_id                    TEXT NOT NULL,
    withdrawn_at              TIMESTAMPTZ NOT NULL,
    authority_decision_digest TEXT NOT NULL,
    superseded_by             TEXT,
    persist_row_hash          TEXT NOT NULL,
    PRIMARY KEY (role, key_id)
);
