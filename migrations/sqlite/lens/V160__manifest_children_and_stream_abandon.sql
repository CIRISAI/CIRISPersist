-- V160 — the children of a nested sealed manifest, and the abandoned stream
-- v52.0.0 (CIRISPersist#954, FSD BLOB_REPLICATION.md §6.6 / BLOB_ENCRYPTION_AT_REST.md §12.12)
--
-- POSTGRES PARITY: migrations/postgres/lens/V160__manifest_children_and_stream_abandon.sql
--
-- # Why
--
-- A sealed chunk-DAG manifest is one inline row under the 1 MiB cap, which
-- held a file to ~10 400 chunks (~2.5 GiB). A v3 root lists CHILDREN, each an
-- ordinary v2 manifest over a run of chunks, each its own inline row. This
-- table relates a root to its children so eviction, promotion and serving can
-- find them WITHOUT opening anything (a holder that is not a viewer holds
-- them too, I45). One row per (root, index); the seal floor writes them in
-- the root's transaction, and the adopt door records them as they arrive.
--
-- A streaming publish refused midway left its stream open forever: chunk
-- rows, index rows and the per-chunk key-grant sets the owner's devices
-- receive for bytes that will never be sealed. `abandoned_at` tombstones the
-- stream: the id is never reusable (an old STH or receipt cannot collide), and
-- the chunk floor and the seal refuse it by name.
CREATE TABLE IF NOT EXISTS federation_manifest_children (
    root_sha256    BLOB NOT NULL,
    child_index    INTEGER NOT NULL CHECK (child_index >= 0),
    child_sha256   BLOB NOT NULL,
    PRIMARY KEY (root_sha256, child_index)
);

CREATE INDEX IF NOT EXISTS federation_manifest_children_by_child
    ON federation_manifest_children (child_sha256);

ALTER TABLE federation_streams ADD COLUMN abandoned_at TEXT NULL;
