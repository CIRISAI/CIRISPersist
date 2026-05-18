-- V031 — creation_ceremonies substrate (v1.5.16, CIRISPersist#59 #8).
--
-- Eighth of 11 substrate absorptions ending CIRISAgent's direct
-- libsqlite access to `ciris_engine.db`. Absorbs CIRISAgent
-- 2.8.13 `creation_ceremonies` table — identity-creation history
-- (when did agent X create agent Y, who was the human witness,
-- which WA signed off, what's the ethical justification, etc.).
--
-- Write-once-mostly shape: ceremonies are recorded once and
-- typically only revisited for "history of agent creations"
-- queries. The status column does transition (pending →
-- in_progress → completed/failed/revoked) which is why we ship a
-- focused `update_ceremony_status` API on top of the bare
-- record-and-read shape.
--
-- Agent's 14-column shape (SQLite TEXT for all timestamps):
--   ceremony_id              TEXT PRIMARY KEY
--   timestamp                TEXT NOT NULL
--   creator_agent_id         TEXT NOT NULL
--   creator_human_id         TEXT NOT NULL
--   wise_authority_id        TEXT NOT NULL
--   new_agent_id             TEXT NOT NULL
--   new_agent_name           TEXT NOT NULL
--   new_agent_purpose        TEXT NOT NULL
--   new_agent_description    TEXT
--   creation_justification   TEXT NOT NULL
--   expected_capabilities    TEXT          -- JSON-array-shaped string
--   ethical_considerations   TEXT NOT NULL
--   template_profile_hash    TEXT
--   ceremony_status          TEXT NOT NULL
--
-- PG-dialect translations:
--   TEXT timestamp           → TIMESTAMPTZ (`timestamp`)
--   TEXT (ceremony_status)   → TEXT + CHECK over the 5-value
--                              vocabulary `pending | in_progress |
--                              completed | failed | revoked`
--   TEXT expected_capabilities → TEXT (NOT JSONB — agent stores it as
--                                a TEXT-encoded JSON array; preserve
--                                the wire shape across the absorb
--                                boundary so callers ride the same
--                                payload literally).
--
-- No FKs. The agent ID references (`creator_agent_id`,
-- `new_agent_id`, etc.) are free-form pointers — these are
-- federation-wide identities that cross substrate boundaries and
-- aren't constrained at the table layer.
--
-- Refinery wraps each migration in its own transaction; no
-- explicit BEGIN/COMMIT here (V019's fix established this rule).

CREATE TABLE cirislens.creation_ceremonies (
    ceremony_id              TEXT PRIMARY KEY,
    timestamp                TIMESTAMPTZ NOT NULL,
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

-- Hot path #1: point lookup by the newly-created agent's id
-- ("which ceremony brought this agent into being?"). UNIQUE NOT
-- enforced — the same new_agent_id appearing twice across
-- ceremonies would represent a re-creation attempt; the operator
-- workflow expects to see both rows.
CREATE INDEX creation_ceremonies_new_agent
    ON cirislens.creation_ceremonies (new_agent_id);

-- Hot path #2: per-creator history, newest-first ("everything
-- creator X has ever brought into being, latest first").
CREATE INDEX creation_ceremonies_creator
    ON cirislens.creation_ceremonies (creator_agent_id, timestamp DESC);

-- Hot path #3: per-WA audit trail, newest-first ("every ceremony
-- WA Y has signed off, latest first").
CREATE INDEX creation_ceremonies_wa
    ON cirislens.creation_ceremonies (wise_authority_id, timestamp DESC);

-- Hot path #4: global timeline ("every ceremony in the federation,
-- newest-first"). Used by operator dashboards.
CREATE INDEX creation_ceremonies_timeline
    ON cirislens.creation_ceremonies (timestamp DESC);

COMMENT ON TABLE cirislens.creation_ceremonies IS
    'v1.5.16 (CIRISPersist#59 #8) — creation_ceremonies substrate. Absorbs CIRISAgent ciris_engine.db.creation_ceremonies; identity-creation history (typically write-once, occasionally revisited for "history of agent creations" queries). 14 columns matching the agent verbatim. No FKs (agent_id references are free-form pointers across substrate boundaries). ceremony_status CHECK over pending|in_progress|completed|failed|revoked.';
