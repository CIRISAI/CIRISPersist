-- V128 — server-side admission instant on trace_events
-- (v32.1.0, CIRISPersist#606, PostgreSQL).
--
-- Mirrored by migrations/sqlite/lens/V128__trace_events_admission_instant.sql.
--
-- WHY: the only trace-plane liveness signal a node could build was
-- `MAX(trace_events.ts)`, and `ts` is the PRODUCER's asserted component
-- timestamp carried inside the signed CompleteTrace. So the signal that says
-- "arrival stopped" was derived from a number supplied by the party that
-- stopped arriving. Three failure modes, each of which looks like the
-- instrument working:
--
--   * a producer whose clock runs SLOW pins the plane dark while it is being
--     actively fed — an alarm that fires during correct operation gets muted,
--     and the muted alarm is the one missing during the next real outage;
--   * a producer whose clock runs FAST pins it green forever — one row stamped
--     next week and the plane reads healthy through any subsequent silence;
--   * backfill is indistinguishable from liveness — replaying last month's
--     traces moves `count(*)` and not `MAX(ts)`.
--
-- `admitted_at` is THIS node's observation of its own intake. `ts` keeps its
-- exact meaning (the producer's claim, which is the right answer for retention
-- and for ordering); the two answer different questions and so are two columns,
-- per the axis-fusion rule this substrate applies elsewhere.
--
-- NODE-LOCAL AND UNSIGNED. It is not part of the CEG envelope, is never
-- replicated, and MUST NOT enter any canonicalization or content hash — the
-- same rule that keeps `persist_row_hash`, `pqc_completed_at` and
-- `federation_keys.admitted_at` out of signed bytes. Two nodes holding the same
-- trace legitimately admitted it at different instants; if that reached a
-- digest, one record would hash differently per node.
--
-- NULLABLE, NO BACKFILL, deliberately — and unlike V126 on this dialect it does
-- NOT become NOT NULL afterwards. A node that upgrades has genuinely never
-- observed an admission instant for its history. NULL is a legible zero; a
-- synthesized one would be a fabricated observation, and inventing `ts` here
-- would re-import the exact producer-clock dependency this column exists to
-- remove.
--
-- The index serves BOTH reads that matter, and both are `MAX()`: the liveness
-- aggregate (`newest_admitted_at` on TableUsage) and the writer's own
-- monotonic-allocator probe. Without it, each becomes a scan of the largest
-- table in the schema.

ALTER TABLE cirislens.trace_events ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS trace_events_admitted_at
    ON cirislens.trace_events (admitted_at DESC)
    WHERE admitted_at IS NOT NULL;
