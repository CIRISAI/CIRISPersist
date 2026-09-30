-- V160 — the children of a nested sealed manifest, and the abandoned stream
-- v52.0.0 (CIRISPersist#954, FSD BLOB_REPLICATION.md §6.6 / BLOB_ENCRYPTION_AT_REST.md §12.12)
--
-- SQLITE PARITY: migrations/sqlite/lens/V160__manifest_children_and_stream_abandon.sql
-- (that file's header carries the reasoning; this one carries the DDL).
CREATE TABLE IF NOT EXISTS cirislens.federation_manifest_children (
    root_sha256    BYTEA NOT NULL,
    child_index    BIGINT NOT NULL CHECK (child_index >= 0),
    child_sha256   BYTEA NOT NULL,
    PRIMARY KEY (root_sha256, child_index)
);

CREATE INDEX IF NOT EXISTS federation_manifest_children_by_child
    ON cirislens.federation_manifest_children (child_sha256);

ALTER TABLE cirislens.federation_streams ADD COLUMN IF NOT EXISTS abandoned_at TIMESTAMPTZ NULL;
