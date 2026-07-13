-- V105 — CIRISPersist#443: transport_destinations becomes a well-formed
--        superseding route table. Postgres dialect. SQLite parity:
--        sqlite/lens/V105.
--
-- The V078/V101 PK was (occurrence_key_id, transport_kind, destination) — an
-- append-only multi-claim set: a route CHANGE (dest-hash rotation) has a
-- different `destination`, so it inserted a NEW row and the stale route lived
-- forever. #443 makes the authoritative key (occurrence_key_id,
-- transport_kind) and demotes `destination` to a NOT NULL payload column: one
-- route per (peer, kind), superseded in place.
--
-- New columns:
--   epoch            — the durable monotonic supersession counter; supersession
--                      is (epoch, asserted_at)-lexicographic.
--   retired_at       — the replicated tombstone: a route retired via a signed
--                      put (higher epoch) stays retired against older gossip.
--   attesting_key_id / signed_envelope / signature — the detached signature
--                      container of a SIGNED put (the V102/V103 discipline).
--                      TEXT (not JSONB) for signed_envelope/signature: the
--                      envelope must round-trip BYTE-EXACT for re-publish, and
--                      JSONB does not preserve the producer's serialization.
--                      NULL for trusted-local rows.
--
-- Collapse rule for pre-existing duplicate rows per (occ, kind): keep the
-- newest `asserted_at`; tie-break = lexicographically greatest `destination`
-- (deterministic across backends — matches the sqlite V105 window collapse).

DELETE FROM cirislens.transport_destinations t
USING (
    SELECT occurrence_key_id, transport_kind, destination,
           ROW_NUMBER() OVER (
               PARTITION BY occurrence_key_id, transport_kind
               ORDER BY asserted_at DESC, destination DESC
           ) AS rn
    FROM cirislens.transport_destinations
) d
WHERE t.occurrence_key_id = d.occurrence_key_id
  AND t.transport_kind    = d.transport_kind
  AND t.destination       = d.destination
  AND d.rn > 1;

-- Drop the old composite PK by its (dynamically resolved, name-agnostic)
-- constraint name — the V101 pattern.
DO $$
DECLARE pk_name text;
BEGIN
    SELECT conname INTO pk_name
    FROM pg_constraint
    WHERE conrelid = 'cirislens.transport_destinations'::regclass
      AND contype = 'p'
    LIMIT 1;
    IF pk_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE cirislens.transport_destinations DROP CONSTRAINT %I', pk_name);
    END IF;
END $$;

ALTER TABLE cirislens.transport_destinations
    ADD PRIMARY KEY (occurrence_key_id, transport_kind);

ALTER TABLE cirislens.transport_destinations
    ADD COLUMN IF NOT EXISTS epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE cirislens.transport_destinations
    ADD COLUMN IF NOT EXISTS retired_at TIMESTAMPTZ;
ALTER TABLE cirislens.transport_destinations
    ADD COLUMN IF NOT EXISTS attesting_key_id TEXT;
ALTER TABLE cirislens.transport_destinations
    ADD COLUMN IF NOT EXISTS signed_envelope TEXT;
ALTER TABLE cirislens.transport_destinations
    ADD COLUMN IF NOT EXISTS signature TEXT;
