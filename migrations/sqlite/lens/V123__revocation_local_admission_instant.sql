-- V123 — the receiver's own position for the exclusion cursor, SQLite dialect
-- v31.1.0 (CIRISPersist#655, PR #667 round-3 review)
--
-- POSTGRES PARITY: migrations/postgres/lens/V123__revocation_local_admission_instant.sql
--
-- WHAT AND WHY
-- ------------
-- `list_signed_revocations_since` (#655) shipped keyed on `scrub_timestamp` —
-- the instant the PRODUCER signed the revocation. That is the wrong clock for a
-- replication cursor, and the failure is ordinary rather than adversarial:
--
--     A revocation signed in January replicates late and is admitted in
--     February, after a consumer's cursor has already passed January. The
--     consumer asks for `> February`, the row sorts under January, and it is
--     never served to that consumer again. The exclusion is stored and
--     invisible.
--
-- Nothing existing prevents it. `check_revocation_scrub_skew` is a CEILING only
-- (`scrub_timestamp - now <= max_skew`), so an arbitrarily OLD signed instant is
-- admissible; and `check_revocation_anti_rollback` is per-`revoked_key_id`, so it
-- says nothing about a first revocation for a subject this node has not seen.
-- Delayed replication of a revocation for a new subject is exactly the
-- everyday case, and it is precisely the defect #655 exists to close — an
-- exclusion that cannot reach a peer — re-entering through the cursor key
-- rather than through a missing method.
--
-- `scrub_timestamp` stays exactly where it is and keeps every job it had. It is
-- bound into the signed envelope (#659 `revocation_binding`), it is the
-- anti-rollback latch, and it is the producer's assertion about when the
-- statement was made. It simply is not this node's position in its own stream.
--
--     admitted_at — when THIS node admitted the row. Receiver-stamped, never
--                   read from the wire, monotonic in this node's own arrival
--                   order, and therefore the only instant a consumer of THIS
--                   node can safely resume from.
--
-- This is the same correction v31.1.0 made one plane over: the accord evidence
-- cursor keys on a derived local visibility instant
-- (`max(created_at, max(server_arrival_at))`) for the same reason. The rule is
-- the module's own — the receiver re-derives rather than trusts — and it
-- applies to time as much as to authority.
--
-- BACKFILL
-- --------
-- Existing rows are stamped with their `scrub_timestamp`. That is the best
-- available answer and it is honest: for rows already stored, the producer's
-- instant IS the only ordering this node ever had, so nothing that was
-- reachable becomes unreachable. New rows get the true admission instant from
-- the first write after upgrade.
--
-- NOT NULL with no DEFAULT: every writer stamps it explicitly, so a row that
-- reached the table without one is a bug this refuses rather than papers over.
-- SQLite requires a DEFAULT to add a NOT NULL column to a populated table, so
-- the column is added nullable, backfilled, and left nullable — SQLite cannot
-- alter a column's nullability in place, and the Rust writer is the enforcement
-- point on this dialect (the postgres parity file sets NOT NULL).

ALTER TABLE federation_revocations ADD COLUMN admitted_at TEXT;

UPDATE federation_revocations
    SET admitted_at = scrub_timestamp
    WHERE admitted_at IS NULL;

-- The read pattern the cursor uses, spelled to MATCH it exactly.
--
-- The cursor filters and orders on `COALESCE(admitted_at, scrub_timestamp)`,
-- not on the bare column: the backfill above and every writer stamp
-- `admitted_at`, but this dialect cannot add a NOT NULL column to a populated
-- table, so a row that reached the table by some other route would be NULL —
-- and under a bare `admitted_at > ?` such a row sorts nowhere and is silently
-- never served, which is the exact class of disappearance this migration
-- exists to end.
--
-- An index on the bare column would therefore not be used by that query at
-- all. Indexing the EXPRESSION is what makes the defensive COALESCE free
-- rather than a full scan — the alternative was to write a query the index
-- could serve and a comment claiming it did.
CREATE INDEX IF NOT EXISTS federation_revocations_admitted
    ON federation_revocations (COALESCE(admitted_at, scrub_timestamp), revocation_id);
