-- V089 — #249 Cut G2: rostered-group supersede + versioning (SQLite dialect)
--        (CIRISPersist#249 §3/§8; CIRISServer #249 write+governance ask).
--
-- Postgres parity: postgres/lens/V089. See that file for the design
-- rationale. The Rust substrate surface is `Engine`/`FederationDirectory`
-- supersede_family / supersede_community / list_group_versions and the
-- `federation::cohort::GroupVersion` read type.
--
-- §3 (THE write gap): there is no way to change an entrenched group's
-- consensus_protocol (M/N) or re-baseline its roster — put_family errors on
-- differing content. supersede REPLACES the live row as a NEW version,
-- snapshotting the prior version into an append-only history table (§8).
--
-- `version` is substrate metadata, NOT part of persist_row_hash, so the
-- DEFAULT 1 keeps every legacy row's hash byte-identical (the Family /
-- Community structs do not carry the column).

ALTER TABLE federation_families
    ADD COLUMN version INTEGER NOT NULL DEFAULT 1;

ALTER TABLE federation_communities
    ADD COLUMN version INTEGER NOT NULL DEFAULT 1;

-- ─── append-only group-version history (§8) ────────────────────────
--
-- One row per SUPERSEDED prior version (the live row holds the current
-- version). `snapshot` is the full Family/Community JSON at that version;
-- `authorization` is the membership-change authorization that justified the
-- supersession (the Cut G3 quorum envelope + cosignatures), or NULL.
CREATE TABLE IF NOT EXISTS federation_group_versions (
    cohort            TEXT NOT NULL
        CHECK (cohort IN ('family', 'community')),
    group_key_id      TEXT NOT NULL,
    version           INTEGER NOT NULL,
    snapshot          TEXT NOT NULL
        CHECK (json_valid(snapshot)),
    change_authorization TEXT
        CHECK (change_authorization IS NULL OR json_valid(change_authorization)),
    superseded_at     TEXT NOT NULL,    -- RFC-3339
    persist_row_hash  TEXT NOT NULL,
    PRIMARY KEY (cohort, group_key_id, version)
);

CREATE INDEX IF NOT EXISTS federation_group_versions_by_group
    ON federation_group_versions (cohort, group_key_id);
