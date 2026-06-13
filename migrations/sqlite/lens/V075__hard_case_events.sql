-- V075 — hard_case_events: the substrate's hard_case:* emission surface
--        (CIRISPersist#146 Ask 3; CEG §8.1.11.3 / §10.1.3). SQLite dialect.
--        Postgres parity: postgres/lens/V075.
--
-- CEG separates substrate observability (`hard_case:*`, emitted by persist)
-- from LensCore-composed derived detection (`detection:*`). Until now
-- persist only *gated* (refused) — it had no surface to *emit* a hard_case
-- primitive. This table is that surface: the consent-SLA watcher (Ask 3)
-- records `hard_case:consent_sla_breach` /
-- `hard_case:consent_revocation_promotion_overdue` rows here, and LensCore
-- composes `detection:consent:*` over them (parallel CIRISLensCore issue).
-- It is a general primitive — any future substrate-side hard_case emitter
-- (location-proof violation, etc.) uses the same table.
--
-- Durable + queryable + operator-introspectable was the chosen shape over a
-- transient change-feed event (CIRISPersist#146 design decision): a flock
-- can't be SELECTed; an audit-grade observability signal should be. The
-- emission is idempotent on `event_id` (a deterministic key the watcher
-- derives from (kind, target, window) so a re-scan never double-emits).

CREATE TABLE hard_case_events (
    event_id          TEXT PRIMARY KEY,   -- deterministic: dedupes re-scans
    kind              TEXT NOT NULL,      -- the `hard_case:{kind}` suffix (open vocab)
    target_key_id     TEXT,               -- the Contribution / row the case is against
    subject_key_id    TEXT,               -- the subject, where one applies
    detail            TEXT NOT NULL DEFAULT '{}',  -- JSON context (sla_days, deadline, …)
    emitted_at        TEXT NOT NULL       -- RFC-3339 UTC
);

-- LensCore consumes by kind + recency; operators sweep by target.
CREATE INDEX hard_case_events_by_kind_time
    ON hard_case_events (kind, emitted_at);
CREATE INDEX hard_case_events_by_target
    ON hard_case_events (target_key_id);
