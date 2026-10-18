-- V198 — the key plane becomes rows; its three tables become projections.
-- SQLite dialect. v58.0.0 (CIRISPersist#991 plane 1; CC 3.1.3, CC 3.3.6,
-- CC 2.4.1.1; CLM-planes-as-rows).
--
-- POSTGRES PARITY: migrations/postgres/lens/V198__key_plane_projections.sql
--
-- WHY
-- ---
-- A key's claim of itself (`key:record:v1`), a key-plane revocation
-- (`key:revocation:v1`) and an identity's occurrence record
-- (`identity:occurrence:v1`) are `scores` rows on the attestation plane from
-- v58.0.0, each minted by persist from the signed object it verified
-- (`federation::key_plane`). The three tables stay, as the projections of
-- those rows, written in the row's transaction and rebuildable from the rows
-- alone (`silo_projection::check_projection_rebuild`).
--
-- HOW
-- ---
-- `attestation_id` names the row each projection row comes from.
--
-- ON DELETE SET NULL, not CASCADE (the V194/V195 precedent): a door that
-- deletes a key-plane row must never delete a key, a revocation or an
-- occurrence with it — every row that key signed would become unverifiable,
-- and CC 2.4.1.1 rules that a purge never deletes a key. A projection row left
-- without its row reads as held-without-a-row, which the rebuild gate names.
--
-- A pre-v58 row carries NULL until the first key-plane write after the
-- upgrade rehomes it (a record that proves possession, a revocation, a signed
-- occurrence); a key that cannot prove possession stays NULL, held, and
-- named by the gate. The partial indexes make the "any left?" probe free.

ALTER TABLE federation_keys
    ADD COLUMN attestation_id TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE SET NULL;

CREATE UNIQUE INDEX federation_keys_by_attestation
    ON federation_keys (attestation_id);

CREATE INDEX federation_keys_without_row
    ON federation_keys (key_id) WHERE attestation_id IS NULL;

ALTER TABLE federation_revocations
    ADD COLUMN attestation_id TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE SET NULL;

CREATE UNIQUE INDEX federation_revocations_by_attestation
    ON federation_revocations (attestation_id);

CREATE INDEX federation_revocations_without_row
    ON federation_revocations (revocation_id) WHERE attestation_id IS NULL;

ALTER TABLE federation_identity_occurrences
    ADD COLUMN attestation_id TEXT
        REFERENCES federation_attestations(attestation_id) ON DELETE SET NULL;

CREATE UNIQUE INDEX federation_identity_occurrences_by_attestation
    ON federation_identity_occurrences (attestation_id);

CREATE INDEX federation_identity_occurrences_without_row
    ON federation_identity_occurrences (identity_key_id, occurrence_key_id)
    WHERE attestation_id IS NULL;
