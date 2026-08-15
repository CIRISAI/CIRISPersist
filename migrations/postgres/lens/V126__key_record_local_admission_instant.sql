-- V126 — the receiver's own position for the IDENTITY cursor, PostgreSQL dialect
-- v31.4.0 (CIRISPersist#682)
--
-- SQLITE PARITY: migrations/sqlite/lens/V126__key_record_local_admission_instant.sql
--
-- See the sqlite twin for the full reasoning. In short: this is V123 again, on
-- the plane that matters most.
--
-- `list_signed_key_records_since` filtered and ordered on `scrub_timestamp` —
-- the PRODUCER's clock. A key record signed in January, replicated late and
-- admitted here in February, sorts under January and is never served to a
-- consumer whose cursor has passed it. Not late — never.
--
-- `federation_keys` is the identity plane, so the consequence is the sharpest
-- version of #655's: the revocation cursor decides which keys are EXCLUDED,
-- this one decides which keys ARE, and every other plane's verification
-- resolves against it.
--
-- `scrub_timestamp` is unchanged and keeps every job it had — signed-envelope
-- binding (#659), the `adopt_scrub_upgrade` anti-rollback comparand, the
-- producer's assertion. It is simply not this node's position in its own stream.
--
-- DIALECT DIVERGENCE FROM THE SQLITE TWIN, deliberate and matching V123:
-- postgres can enforce NOT NULL after the backfill and does; sqlite cannot alter
-- nullability in place and leaves it nullable with the Rust writer as the
-- enforcement point. Each tree is internally coherent — the index below is on
-- the bare column because the column is NOT NULL here, while the sqlite index is
-- on `COALESCE(admitted_at, scrub_timestamp)` because there it can be NULL, and
-- each backend's query matches its own index.

ALTER TABLE cirislens.federation_keys
    ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;

UPDATE cirislens.federation_keys
    SET admitted_at = scrub_timestamp
    WHERE admitted_at IS NULL;

ALTER TABLE cirislens.federation_keys
    ALTER COLUMN admitted_at SET NOT NULL;

-- On `(admitted_at, key_id)` rather than the instant alone, because the cursor
-- resumes on the PAIR (#668): a page ordered by `(instant, id)` and resumed by
-- instant alone skips the remainder of any tie larger than one page.
CREATE INDEX IF NOT EXISTS federation_keys_admitted
    ON cirislens.federation_keys (admitted_at, key_id);
