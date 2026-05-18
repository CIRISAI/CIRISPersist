-- V031 — creation_ceremonies substrate (v1.5.16, CIRISPersist#59 #8).
--
-- SQLite mirror of V031 PG. Dialect translations:
--   TIMESTAMPTZ                → TEXT (RFC 3339)
--   CHECK constraint shape     → unchanged (SQLite supports CHECK)
--
-- Same 14 columns as the PG side and the agent's source schema. No
-- FKs (agent_id references are free-form pointers across substrate
-- boundaries).
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens_creation_ceremonies (
    ceremony_id              TEXT PRIMARY KEY,
    timestamp                TEXT NOT NULL,
    creator_agent_id         TEXT NOT NULL,
    creator_human_id         TEXT NOT NULL,
    wise_authority_id        TEXT NOT NULL,
    new_agent_id             TEXT NOT NULL,
    new_agent_name           TEXT NOT NULL,
    new_agent_purpose        TEXT NOT NULL,
    new_agent_description    TEXT,
    creation_justification   TEXT NOT NULL,
    expected_capabilities    TEXT,
    ethical_considerations   TEXT NOT NULL,
    template_profile_hash    TEXT,
    ceremony_status          TEXT NOT NULL
        CHECK (ceremony_status IN (
            'pending', 'in_progress', 'completed', 'failed', 'revoked'
        ))
);

CREATE INDEX creation_ceremonies_new_agent
    ON cirislens_creation_ceremonies (new_agent_id);

CREATE INDEX creation_ceremonies_creator
    ON cirislens_creation_ceremonies (creator_agent_id, timestamp DESC);

CREATE INDEX creation_ceremonies_wa
    ON cirislens_creation_ceremonies (wise_authority_id, timestamp DESC);

CREATE INDEX creation_ceremonies_timeline
    ON cirislens_creation_ceremonies (timestamp DESC);
