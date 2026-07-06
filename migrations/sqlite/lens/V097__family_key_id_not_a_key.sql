-- v13.3.0 (CIRISPersist#386) — a **constitutional family is keyless** (see the
-- postgres twin). SQLite cannot ALTER-DROP a FK, so rebuild the table without
-- the `family_key_id REFERENCES federation_keys(key_id)` FK. No child table
-- references federation_families, so a plain rebuild is safe. Preserves all
-- columns (incl. `version` added by V089), the CHECKs, and the entrenched
-- index. The real invariant (members are registered keys) is enforced at write
-- time in `put_family`.
CREATE TABLE federation_families_new (
    family_key_id                   TEXT PRIMARY KEY,
    family_name                     TEXT NOT NULL,
    members                         TEXT NOT NULL DEFAULT '[]'
        CHECK (json_type(members) = 'array'),
    founded_at                      TEXT NOT NULL,
    consensus_protocol              TEXT NOT NULL,
    consensus_protocol_entrenched   INTEGER NOT NULL DEFAULT 0
        CHECK (consensus_protocol_entrenched IN (0, 1)),
    persist_row_hash                TEXT NOT NULL,
    version                         INTEGER NOT NULL DEFAULT 1
);
INSERT INTO federation_families_new
    (family_key_id, family_name, members, founded_at,
     consensus_protocol, consensus_protocol_entrenched, persist_row_hash, version)
SELECT
    family_key_id, family_name, members, founded_at,
    consensus_protocol, consensus_protocol_entrenched, persist_row_hash, version
FROM federation_families;
DROP TABLE federation_families;
ALTER TABLE federation_families_new RENAME TO federation_families;
CREATE INDEX IF NOT EXISTS federation_families_entrenched
    ON federation_families (family_key_id)
    WHERE consensus_protocol_entrenched = 1;
