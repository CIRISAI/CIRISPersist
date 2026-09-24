-- V152 — `consent_peer_set` is keyed by the machine a grant is FOR
-- v48.0.0 (CIRISPersist#905, ask 2)
--
-- SQLITE PARITY: migrations/sqlite/lens/V152__consent_peer_set_for_key.sql
-- (that file's header carries the reasoning; this one carries the DDL).
ALTER TABLE cirislens.consent_peer_set ADD COLUMN IF NOT EXISTS for_key_id TEXT;
UPDATE cirislens.consent_peer_set c
   SET for_key_id = COALESCE(a.attestation_envelope::jsonb ->> 'for_key_id',
                             a.attestation_envelope::jsonb #>> '{payload,for_key_id}',
                             c.node_key_id)
  FROM cirislens.federation_attestations a
 WHERE a.attestation_id::text = c.source_attestation_id
   AND c.for_key_id IS NULL;
UPDATE cirislens.consent_peer_set SET for_key_id = node_key_id WHERE for_key_id IS NULL;
ALTER TABLE cirislens.consent_peer_set ALTER COLUMN for_key_id SET NOT NULL;
DO $$
DECLARE c RECORD;
BEGIN
    FOR c IN
        SELECT con.conname
          FROM pg_constraint con
          JOIN pg_class      rel ON rel.oid = con.conrelid
          JOIN pg_namespace  nsp ON nsp.oid = rel.relnamespace
         WHERE nsp.nspname = 'cirislens'
           AND rel.relname = 'consent_peer_set'
           AND con.contype = 'p'
    LOOP
        EXECUTE format('ALTER TABLE cirislens.consent_peer_set DROP CONSTRAINT %I', c.conname);
    END LOOP;
END $$;
ALTER TABLE cirislens.consent_peer_set
    ADD PRIMARY KEY (node_key_id, for_key_id, peer_key_id);
CREATE INDEX IF NOT EXISTS consent_peer_set_by_source
    ON cirislens.consent_peer_set (source_attestation_id);
