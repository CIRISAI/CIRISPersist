-- V089 — #249 Cut G2: rostered-group supersede + versioning (Postgres dialect)
--        (CIRISPersist#249 §3/§8; CIRISServer #249 write+governance ask).
--
-- §3 (THE write gap): there is no way to change an entrenched group's
-- consensus_protocol (M/N) or re-baseline its roster — put_family errors on
-- differing content, and add/revoke can't touch the threshold. So expand
-- 3→5 (which forces quorum:2/3 → quorum:3/5 under the strict-majority rule)
-- is impossible today. `supersede` REPLACES the live row as a NEW version,
-- snapshotting the prior version into an append-only history table (§8 —
-- the accord's recovery/expansion audit trail).
--
-- `version` is substrate metadata, NOT part of persist_row_hash (the Family
-- / Community structs do not carry the column), so DEFAULT 1 keeps every
-- legacy row's hash byte-identical.

ALTER TABLE cirislens.federation_families
    ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1;

ALTER TABLE cirislens.federation_communities
    ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1;

-- ─── append-only group-version history (§8) ────────────────────────
--
-- One row per SUPERSEDED prior version (the live row holds the current
-- version). `snapshot` is the full Family/Community JSONB at that version;
-- `authorization` is the membership-change authorization that justified the
-- supersession (the Cut G3 quorum envelope + cosignatures), or NULL.
CREATE TABLE IF NOT EXISTS cirislens.federation_group_versions (
    cohort            TEXT NOT NULL
        CHECK (cohort IN ('family', 'community')),
    group_key_id      TEXT NOT NULL,
    version           INTEGER NOT NULL,
    snapshot          JSONB NOT NULL,
    change_authorization JSONB,
    superseded_at     TIMESTAMPTZ NOT NULL,
    persist_row_hash  TEXT NOT NULL,
    PRIMARY KEY (cohort, group_key_id, version)
);

CREATE INDEX IF NOT EXISTS federation_group_versions_by_group
    ON cirislens.federation_group_versions (cohort, group_key_id);
