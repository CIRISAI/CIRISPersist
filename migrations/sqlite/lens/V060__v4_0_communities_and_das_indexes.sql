-- V060 — CIRISPersist v4.0 Data Access Surface (FSD §12) — SQLite
--        dialect. Postgres parity: postgres/lens/V060. See that file
--        for the full Part A / Part B design rationale and the
--        schema-reconciliation note on Part B.
--
-- Two concerns in one numbered cut, mirroring the V059 dual-substrate
-- pattern:
--   Part A — the federation_communities substrate (§8.1.13.3).
--   Part B — scope-aware DAS covering indexes for the §4.3 read-side
--            cohort_scope predicate.
--
-- Refinery wraps this migration in its own transaction — no explicit
-- BEGIN/COMMIT (matches the V059 file convention).

-- ── Part A: federation_communities substrate (§8.1.13.3) ───────────
--
-- Structural mirror of V059 federation_families. `members` stored as
-- JSON TEXT (SQLite json1 parses on demand via json_each /
-- json_extract — postgres uses JSONB native). `policy_blob` is
-- nullable JSON TEXT carrying the §8.1.13.3 cohort_scope membership
-- label consumed at CIRISEdge#48-A.
--
-- Semantic difference from V059 family: community content is NOT
-- structurally invisible — `cohort_scope::suppresses_holds_bytes`
-- returns FALSE for community. Read paths federate it normally.
--
-- `consensus_protocol` GLOB checks mirror the postgres regex CHECK and
-- the Rust `check_consensus_protocol_form` admission gate (canonical
-- forms: founder_only | unanimous | majority | quorum:m/n |
-- weighted:rubric | custom:id).

CREATE TABLE federation_communities (
    community_key_id      TEXT PRIMARY KEY,
    community_name        TEXT NOT NULL,
    members               TEXT NOT NULL,   -- JSON-shaped
    founded_at            TEXT NOT NULL,   -- RFC-3339
    consensus_protocol    TEXT NOT NULL,
    policy_blob           TEXT,            -- JSON-shaped or NULL
    persist_row_hash      TEXT NOT NULL,
    CHECK (consensus_protocol GLOB 'founder_only'
        OR consensus_protocol GLOB 'unanimous'
        OR consensus_protocol GLOB 'majority'
        OR consensus_protocol GLOB 'quorum:*/*'
        OR consensus_protocol GLOB 'weighted:?*'
        OR consensus_protocol GLOB 'custom:?*')
);

-- Membership fan-out for list_communities_for_member. SQLite has no
-- JSONB GIN; the substrate scans via json_each (mirrors the V059
-- family read path), so no GIN index here — the postgres @> path is
-- the optimization, sqlite parses on read.

-- ── Part B(i): trace_events cohort_scope + target ──────────────────
--
-- Postgres parity (postgres/lens/V060 Part B(i)): add TWO columns so
-- the §4.3 community-lens read-gate can filter at trace-read time.
-- Default 'federation' + NULL target preserves current behavior for
-- pre-v4.0 rows. (One ADD COLUMN per statement — SQLite's ALTER TABLE
-- adds a single column at a time.)
ALTER TABLE trace_events ADD COLUMN cohort_scope TEXT NOT NULL DEFAULT 'federation';
ALTER TABLE trace_events ADD COLUMN cohort_target_id TEXT;

-- Closed-set enforcement. SQLite cannot ADD a CHECK via ALTER, so the
-- closed set is enforced by BEFORE INSERT / BEFORE UPDATE triggers that
-- RAISE(ABORT, ...) on an out-of-set value — the same trigger
-- discipline V056 used for its cross-column cohort closed-set
-- (`contributions_consent_record_insert_check`). One trigger per
-- mutation verb so both INSERT and UPDATE paths are gated.
CREATE TRIGGER IF NOT EXISTS trace_events_cohort_scope_insert_check
BEFORE INSERT ON trace_events
FOR EACH ROW
WHEN NEW.cohort_scope NOT IN
    ('self','family','community','affiliations','species','biosphere','federation')
BEGIN
    SELECT RAISE(ABORT,
        'trace_events.cohort_scope must be one of self/family/community/affiliations/species/biosphere/federation');
END;

CREATE TRIGGER IF NOT EXISTS trace_events_cohort_scope_update_check
BEFORE UPDATE ON trace_events
FOR EACH ROW
WHEN NEW.cohort_scope NOT IN
    ('self','family','community','affiliations','species','biosphere','federation')
BEGIN
    SELECT RAISE(ABORT,
        'trace_events.cohort_scope must be one of self/family/community/affiliations/species/biosphere/federation');
END;

-- ── Part B(ii): DAS covering indexes ───────────────────────────────
--
-- sqlite has no INCLUDE — index the columns directly. The §4.3
-- predicate is now pure set-membership on (cohort_scope,
-- cohort_target_id), so the covering index LEADS with those two columns
-- (postgres parity), then ts / deployment_domain / trace_id.
-- federation_attestations exposes its subject as `attested_key_id`
-- (V055 reconciliation; see the postgres V060 Part B note).

CREATE INDEX IF NOT EXISTS idx_trace_events_v060_repository_stats
ON trace_events (cohort_scope, cohort_target_id, ts, deployment_domain, trace_id);

CREATE INDEX IF NOT EXISTS idx_federation_attestations_v060_by_target
ON federation_attestations (attested_key_id, cohort_scope, asserted_at DESC);

CREATE INDEX IF NOT EXISTS idx_federation_attestations_v060_emitter_scope
ON federation_attestations (scrub_key_id, cohort_scope);
