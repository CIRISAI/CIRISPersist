-- V126 — the receiver's own position for the IDENTITY cursor, SQLite dialect
-- v31.4.0 (CIRISPersist#682)
--
-- POSTGRES PARITY: migrations/postgres/lens/V126__key_record_local_admission_instant.sql
--
-- WHAT AND WHY
-- ------------
-- This is V123 again, one plane over — and on the plane that matters most.
--
-- `list_signed_key_records_since` filters and orders on `scrub_timestamp`, the
-- instant the PRODUCER signed the record. Same defect as #655, verbatim:
--
--     A key record signed in January replicates late and is admitted here in
--     February, after a consumer's cursor has already passed January. The
--     consumer asks for `> February`, the row sorts under January, and it is
--     never served to that consumer again.
--
-- Not late — NEVER. No retry recovers it, because the row's sort position is
-- fixed by someone else's clock and is already behind the reader.
--
-- WHY THIS PLANE IS THE WORST ONE TO GET WRONG
-- --------------------------------------------
-- `federation_keys` is the identity plane. A key record that never reaches a
-- peer is a peer that never learns a key exists — and every other plane's
-- verification resolves against it. The revocation cursor (#655) decides which
-- keys are EXCLUDED; this one decides which keys ARE. An exclusion that does not
-- replicate leaves a revoked key trusted; a registration that does not replicate
-- leaves every signature by that key unverifiable.
--
-- Nothing existing prevents the gap. The scrub-skew check is a CEILING only, so
-- an arbitrarily OLD signed instant is admissible, and there is no per-key
-- latch forcing forward motion on first sight of a subject. Delayed replication
-- of a key this node has not seen before is the everyday case.
--
-- `scrub_timestamp` keeps every job it had: it is bound into the signed envelope
-- (#659 subject binding), it is the anti-rollback comparand on
-- `adopt_scrub_upgrade`, and it is the producer's assertion about when the
-- record was scrubbed. It simply is not this node's position in its own stream.
--
--     admitted_at — when THIS node admitted the row. Receiver-stamped, never
--                   read from the wire, allocated through
--                   `monotonic_admission_instant` so a backward clock step
--                   (VM restore, NTP correction) cannot strand a row below a
--                   cursor that has already passed.
--
-- BACKFILL
-- --------
-- Existing rows are stamped with their `scrub_timestamp`. Best available answer
-- and an honest one: for rows already stored, the producer's instant IS the only
-- ordering this node ever had, so nothing reachable becomes unreachable. New
-- rows get the true admission instant from the first write after upgrade.
--
-- SQLite cannot add a NOT NULL column to a populated table without a DEFAULT,
-- and cannot alter nullability in place, so the column is added nullable and
-- left nullable; the Rust writer is the enforcement point on this dialect. The
-- postgres parity file sets NOT NULL, exactly as V123 did.

ALTER TABLE federation_keys ADD COLUMN admitted_at TEXT;

UPDATE federation_keys
    SET admitted_at = scrub_timestamp
    WHERE admitted_at IS NULL;

-- The read pattern the cursor uses, spelled to MATCH it exactly.
--
-- The cursor filters and orders on `COALESCE(admitted_at, scrub_timestamp)`
-- rather than the bare column, for the reason V123 records: this dialect leaves
-- the column nullable, so a row arriving by some other route would be NULL, and
-- under a bare `admitted_at > ?` such a row sorts nowhere and is silently
-- unservable — reintroducing the very defect this migration closes.
--
-- The index is on the same expression, and on `(expr, key_id)` rather than the
-- instant alone, because the cursor resumes on the PAIR (#668): a page ordered
-- by `(instant, id)` and resumed by instant alone skips the remainder of any tie
-- larger than one page.
CREATE INDEX IF NOT EXISTS federation_keys_admitted
    ON federation_keys (COALESCE(admitted_at, scrub_timestamp), key_id);
