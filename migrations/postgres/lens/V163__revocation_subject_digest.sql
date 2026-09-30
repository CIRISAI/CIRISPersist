-- V163 (v52.0.0, CIRISPersist#784) — a revocation names its subject by the
-- SHA-256 of the key's RAW Ed25519 public key, not by its `key_id`.
--
-- A `key_id` is `<label>-<fingerprint>`, the label in cleartext, so a
-- revocation that names one publishes the subject's keystore label to every
-- node it reaches. From v52 the subject is `revoked_key_sha256_ed25519_raw`
-- (64 lowercase hex, bound into the signed envelope); `revoked_key_id` is an
-- optional second name, checked against the digest at admission.
--
-- `revoked_key_id` loses NOT NULL and its FK: a digest-only revocation may
-- precede the key record (#784 D1), which deliberately relaxes V004's
-- "cannot revoke a key not in the directory". Existing rows are backfilled
-- from the key they name (every one does: the FK held until now).

DO $$
DECLARE c text;
BEGIN
    FOR c IN
        SELECT con.conname
          FROM pg_constraint con
          JOIN pg_attribute att
            ON att.attrelid = con.conrelid AND att.attnum = ANY (con.conkey)
         WHERE con.conrelid = 'cirislens.federation_revocations'::regclass
           AND con.contype = 'f'
           AND att.attname = 'revoked_key_id'
    LOOP
        EXECUTE format('ALTER TABLE cirislens.federation_revocations DROP CONSTRAINT %I', c);
    END LOOP;
END $$;

ALTER TABLE cirislens.federation_revocations
    ALTER COLUMN revoked_key_id DROP NOT NULL;

ALTER TABLE cirislens.federation_revocations
    ADD COLUMN revoked_key_sha256_ed25519_raw TEXT;

UPDATE cirislens.federation_revocations r
   SET revoked_key_sha256_ed25519_raw =
       encode(sha256(decode(k.pubkey_ed25519_base64, 'base64')), 'hex')
  FROM cirislens.federation_keys k
 WHERE k.key_id = r.revoked_key_id
   AND r.revoked_key_sha256_ed25519_raw IS NULL;

ALTER TABLE cirislens.federation_revocations
    ALTER COLUMN revoked_key_sha256_ed25519_raw SET NOT NULL;

ALTER TABLE cirislens.federation_revocations
    ADD CONSTRAINT federation_revocations_subject_digest_shape
    CHECK (revoked_key_sha256_ed25519_raw ~ '^[0-9a-f]{64}$');

CREATE INDEX IF NOT EXISTS federation_revocations_subject
    ON cirislens.federation_revocations (revoked_key_sha256_ed25519_raw, effective_at DESC);

DROP INDEX IF EXISTS cirislens.federation_revocations_observed_region;
CREATE INDEX IF NOT EXISTS federation_revocations_observed_region
    ON cirislens.federation_revocations (observed_region, revoked_key_sha256_ed25519_raw, scrub_timestamp DESC)
    WHERE observed_region != 'us';
