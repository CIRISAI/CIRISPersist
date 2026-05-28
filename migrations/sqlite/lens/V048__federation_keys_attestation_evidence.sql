-- V048 — Hardware-attestation evidence column on federation_keys,
-- SQLite dialect (CIRISPersist#102 Ask 8, v2.5.0).
--
-- Postgres parity (postgres/lens/V048): same column + same intent,
-- with the following dialect translations:
--
--   PostgreSQL                                  → SQLite
--   ─────────────────────────────────────────────────────────────────
--   JSONB                                       → TEXT (JSON-as-text;
--                                                  persist's standing
--                                                  convention for
--                                                  JSON-on-SQLite)
--   ALTER TABLE ... ADD CONSTRAINT ... CHECK    → BEFORE INSERT/UPDATE
--                                                 triggers (SQLite
--                                                 cannot add a CHECK
--                                                 to an existing
--                                                 table; trigger is
--                                                 the equivalent
--                                                 enforcement point).
--   COMMENT ON COLUMN ...                       → (no equivalent —
--                                                 SQLite has no
--                                                 column-comment
--                                                 facility; docs
--                                                 live in source)
--
-- See postgres/lens/V048 for the architectural rationale.

-- ── Column ──────────────────────────────────────────────────────────

ALTER TABLE federation_keys
    ADD COLUMN attestation_evidence TEXT;

-- ── Trigger: enforce on INSERT ──────────────────────────────────────
--
-- accord_holder rows MUST carry evidence. Non-accord-holder rows
-- MAY have NULL. The trigger fires before the row lands; RAISE(ABORT)
-- maps to a rusqlite SqliteFailure error the admission layer's
-- malformed-input typed-error branch surfaces.

CREATE TRIGGER IF NOT EXISTS federation_keys_accord_holder_requires_attestation_insert
BEFORE INSERT ON federation_keys
FOR EACH ROW
WHEN NEW.identity_type = 'accord_holder'
    AND NEW.attestation_evidence IS NULL
BEGIN
    SELECT RAISE(ABORT,
        'federation_keys_accord_holder_requires_attestation: identity_type=accord_holder rows MUST carry attestation_evidence (v2.5.0 / CIRISPersist#102 Ask 8)'
    );
END;

-- ── Trigger: enforce on UPDATE ──────────────────────────────────────
--
-- The UPDATE case covers the row-mutation path (an accord-holder
-- row that gets identity_type re-classified, or has its evidence
-- cleared by direct SQL). Same RAISE(ABORT) shape as the INSERT
-- trigger.

CREATE TRIGGER IF NOT EXISTS federation_keys_accord_holder_requires_attestation_update
BEFORE UPDATE OF identity_type, attestation_evidence ON federation_keys
FOR EACH ROW
WHEN NEW.identity_type = 'accord_holder'
    AND NEW.attestation_evidence IS NULL
BEGIN
    SELECT RAISE(ABORT,
        'federation_keys_accord_holder_requires_attestation: identity_type=accord_holder rows MUST carry attestation_evidence (v2.5.0 / CIRISPersist#102 Ask 8)'
    );
END;

-- ── Index ───────────────────────────────────────────────────────────
--
-- Partial index on accord-holder rows specifically. Same intent as
-- the PG side — operators auditing accord-holder keys want a focused
-- index. SQLite partial indexes use `WHERE` exactly like Postgres.

CREATE INDEX IF NOT EXISTS federation_keys_accord_holder_evidence
    ON federation_keys (key_id)
    WHERE identity_type = 'accord_holder';
