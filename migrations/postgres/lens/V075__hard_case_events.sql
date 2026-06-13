-- V075 — hard_case_events: the substrate's hard_case:* emission surface
--        (CIRISPersist#146 Ask 3; CEG §8.1.11.3 / §10.1.3). Postgres dialect.
--        SQLite parity: sqlite/lens/V075.
--
-- CEG separates substrate observability (`hard_case:*`, emitted by persist)
-- from LensCore-composed derived detection (`detection:*`). Until now
-- persist only *gated* (refused) — no surface to *emit* a hard_case
-- primitive. This table is that surface: the consent-SLA watcher (Ask 3)
-- records `hard_case:consent_sla_breach` /
-- `hard_case:consent_revocation_promotion_overdue` rows here, and LensCore
-- composes `detection:consent:*` over them. A general primitive — any
-- future substrate-side hard_case emitter reuses it.
--
-- Durable + queryable + operator-introspectable (CIRISPersist#146 design
-- decision) over a transient change-feed event. Emission is idempotent on
-- `event_id` — a deterministic key the watcher derives from
-- (kind, target, window) so a re-scan never double-emits.

CREATE TABLE IF NOT EXISTS cirislens.hard_case_events (
    event_id          TEXT PRIMARY KEY,
    kind              TEXT NOT NULL,
    target_key_id     TEXT,
    subject_key_id    TEXT,
    detail            JSONB NOT NULL DEFAULT '{}'::jsonb,
    emitted_at        TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS hard_case_events_by_kind_time
    ON cirislens.hard_case_events (kind, emitted_at);
CREATE INDEX IF NOT EXISTS hard_case_events_by_target
    ON cirislens.hard_case_events (target_key_id);
