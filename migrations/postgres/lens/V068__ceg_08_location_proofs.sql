-- V068 — CEG 0.8 §5.6.8.11 + §0.8.1 location_proof substrate
--        (CIRISPersist#154 Asks 1/2/3, v4.10.0).
--
-- The §0.8.1-normative privacy primitive: a subject's coarse geographic
-- claim, bounded to H3 resolution ≤ 7 ("rough-only") at admission so the
-- substrate is the second line of defense after client UI gating — a
-- producer cannot over-share precise location even if the client fails.
-- cell_id is the H3 lowercase-hex index (§0.8); the admission gate
-- (put_location_proof) validates canonical form + resolution-redundancy
-- via h3o and rejects resolution > 7 before insert.
--
-- Standalone (no source_attestation_id FK) — the proof row IS the record;
-- subject_key_id FK-anchors to federation_keys like V059/V067. Append-
-- only; withdrawn_at marks a proof no longer in force (null = current).
-- Community content does NOT get holds_bytes suppression or a DEK cascade
-- (the CEG 0.8 community default, distinct from CEG 0.7 self/family).

CREATE TABLE IF NOT EXISTS cirislens.federation_location_proofs (
    subject_key_id        TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),

    -- H3 cell index, lowercase hex (§0.8). Canonical form + validity +
    -- resolution-redundancy are admission-gate enforced (h3o).
    cell_id               TEXT NOT NULL,
    -- 0-15 at the column; the §0.8.1 rough-only gate rejects > 7 at
    -- admission (kept as a SMALLINT range backstop, not the ≤7 rule —
    -- the gate emits the resolution-violation, the DB just sanity-bounds).
    cell_resolution       SMALLINT NOT NULL
        CHECK (cell_resolution BETWEEN 0 AND 15),

    asserted_at           TIMESTAMPTZ NOT NULL,
    valid_until           TIMESTAMPTZ,

    -- Optional TPM / Secure Enclave / StrongBox attestation blob backing
    -- the location claim. NULL for software-only proofs.
    attestation_evidence  BYTEA,

    -- null = currently in force; set = withdrawn (append-only, no DELETE).
    withdrawn_at          TIMESTAMPTZ,

    persist_row_hash      TEXT NOT NULL,

    PRIMARY KEY (subject_key_id, asserted_at)
);

-- "current location proofs for this subject" — the latest_valid lookup
-- the geographic-subkind admission predicate (Ask 4, deferred) walks.
CREATE INDEX IF NOT EXISTS federation_location_proofs_by_subject_live
    ON cirislens.federation_location_proofs (subject_key_id)
    WHERE withdrawn_at IS NULL;

-- "who is in this cell" — the containment / communities_containing(cell)
-- cascade read.
CREATE INDEX IF NOT EXISTS federation_location_proofs_by_cell
    ON cirislens.federation_location_proofs (cell_id);
