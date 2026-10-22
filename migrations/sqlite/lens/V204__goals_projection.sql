-- V204 — `goals` becomes the projection of the `goal:{scale}:v1` rows.
-- SQLite dialect. v60.0.0 (CIRISPersist#988 item 4; CC 3.1.9.7, CC 2.4.2).
--
-- POSTGRES PARITY: migrations/postgres/lens/V204__goals_projection.sql
--
-- WHY
-- ---
-- Signed attestations are the only state. A Goal is now its declarer's signed
-- `scores` row on `goal:{scale}:v1`; amendment is `supersedes`, retirement
-- `withdraws`, "never mine" `recants`. The `goals` table stops being written
-- by a typed door and becomes the fold of the goal rows this node holds
-- (`federation::goal_projection`): `goal_id` is the declaration's
-- `attestation_id`, `attestation_id` the head of its amendment chain, and the
-- table is byte-equal to its from-rows rebuild.
--
-- HOW
-- ---
-- `goals` is rebuilt under its final name (it references `federation_keys`
-- and nothing references it, so the drop fires no foreign-key action):
--   * `scope_kind` → `scale`, CC 3.1.9.7's open `{scale}` vocabulary; the
--     v59 `single_declarer` maps to `self`, `cohort` and `federation` keep
--     their spelling. The closed CHECK on the scope goes (the vocabulary is
--     open); the cohort discriminant stays.
--   * `attestation_id` (the head row; CASCADE with it) and `score` (the
--     head's signed score) are added. A pre-V204 row keeps both NULL: a typed
--     goal no row backs, red in the rebuild until the rehome moves it
--     (`Engine::rehome_legacy_goals`).
--   * `inserted_at` is dropped: a write-time clock is not a function of the
--     rows, and the projection must be.
-- The M-1 CHECK on `meta_dimension` stays (defence in depth behind the
-- admission gate).

CREATE TABLE v204_stage_goals AS
    SELECT goal_id, declared_by_key_id, declared_at, goal_text,
           goal_text_canonical, scope_kind, scope_cohort_id, meta_dimension,
           meta_rationale, meta_deliberation, retired_at, persist_row_hash
      FROM goals;

DROP TABLE goals;

CREATE TABLE goals (
    goal_id                TEXT    PRIMARY KEY,
    declared_by_key_id     TEXT    NOT NULL
        REFERENCES federation_keys(key_id) ON DELETE RESTRICT,
    declared_at            TEXT    NOT NULL,
    goal_text              TEXT    NOT NULL,
    goal_text_canonical    TEXT    NOT NULL,
    scale                  TEXT    NOT NULL,
    scope_cohort_id        TEXT,
    meta_dimension         TEXT    NOT NULL
        CHECK (meta_dimension IN (
            'adaptivity', 'coherence', 'flourishing', 'justice',
            'plurality', 'sustainability', 'wonder'
        )),
    meta_rationale         TEXT    NOT NULL,
    meta_deliberation      TEXT,
    retired_at             TEXT,
    persist_row_hash       TEXT    NOT NULL,
    attestation_id         TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE CASCADE,
    score                  REAL,
    CONSTRAINT goals_scope_cohort_discriminant CHECK (
        (scale = 'cohort' AND scope_cohort_id IS NOT NULL)
        OR (scale <> 'cohort' AND scope_cohort_id IS NULL)
    ),
    CONSTRAINT goals_projection_row CHECK (
        (attestation_id IS NULL AND score IS NULL)
        OR (attestation_id IS NOT NULL AND score IS NOT NULL)
    )
);

INSERT INTO goals
    (goal_id, declared_by_key_id, declared_at, goal_text, goal_text_canonical,
     scale, scope_cohort_id, meta_dimension, meta_rationale, meta_deliberation,
     retired_at, persist_row_hash)
    SELECT goal_id, declared_by_key_id, declared_at, goal_text,
           goal_text_canonical,
           CASE scope_kind WHEN 'single_declarer' THEN 'self' ELSE scope_kind END,
           scope_cohort_id, meta_dimension, meta_rationale, meta_deliberation,
           retired_at, persist_row_hash
      FROM v204_stage_goals;

DROP TABLE v204_stage_goals;

CREATE INDEX IF NOT EXISTS goals_declared_by_key_id ON goals (declared_by_key_id);
CREATE INDEX IF NOT EXISTS goals_meta_dimension ON goals (meta_dimension);
CREATE INDEX IF NOT EXISTS goals_retired_at_live ON goals (retired_at) WHERE retired_at IS NULL;
CREATE INDEX IF NOT EXISTS goals_scope_cohort ON goals (scale, scope_cohort_id)
    WHERE scale = 'cohort';
CREATE INDEX IF NOT EXISTS goals_attestation_id ON goals (attestation_id);
