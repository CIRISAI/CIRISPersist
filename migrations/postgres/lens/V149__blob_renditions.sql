-- V149 (CIRISPersist#871, FSD/MEDIA_SOURCE.md §5) — the rendition index.
-- CC 3.3.13: "renditions are separate blobs" — a derived rendition is its own
-- blob with its own digest and `derived_from` naming the original. A row whose
-- `media.derived_from` is set projects ONE row here, in the same write that
-- admits it (put_attestation, the local writer, the promotion door), keyed by
-- the rendition's own digest; the retraction fold that retires the source row
-- deletes it (`source_attestation_id`, the V109 `consent_peer_set` discipline).
-- DERIVED / rebuildable from `federation_attestations`: a read accelerator for
-- "the renditions of this digest", never new authority. Postgres dialect.
-- SQLite parity: sqlite/lens/V149.
CREATE TABLE cirislens.blob_renditions (
    rendition_sha256        BYTEA PRIMARY KEY,   -- the rendition blob's digest
    original_sha256         BYTEA NOT NULL,      -- `media.derived_from`
    format                  TEXT NOT NULL,       -- RFC 6838 essence, as declared
    size                    BIGINT NOT NULL,     -- bytes (CC 5.3.2.5)
    width                   INTEGER,
    height                  INTEGER,
    role                    TEXT NOT NULL,       -- thumbnail|poster|transcode|caption_track|other
    source_attestation_id   TEXT NOT NULL,
    cohort_scope            TEXT NOT NULL
);
CREATE INDEX blob_renditions_by_original
    ON cirislens.blob_renditions (original_sha256, rendition_sha256);
CREATE INDEX blob_renditions_by_source
    ON cirislens.blob_renditions (source_attestation_id);
