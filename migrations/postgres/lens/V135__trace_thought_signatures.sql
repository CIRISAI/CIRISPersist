-- V135 (CIRISPersist#789) — move thought-scoped and key-scoped crypto material
-- OFF the per-event row.
-- Postgres dialect. SQLite twin: sqlite/lens/V135.
--
-- ─── The defect ─────────────────────────────────────────────────────
--
-- `trace_events` stored two pieces of crypto material at the WRONG
-- CARDINALITY, both written once per event row. Measured on the live
-- canonical (106,258 rows, 898 MB table around 80 MB of actual trace
-- payload):
--
--     column                  stored   distinct   unique     waste
--     pubkey_ml_dsa_65        264 MB        321   0.8 MB   263 MB (99.7%)
--     signature_ml_dsa_65     447 MB      7,264  30.5 MB   416 MB (93.2%)
--                                                          ───────
--                                                           679 MB
--
-- Neither column was wrong to EXIST; both were stored against the wrong
-- key. A public key is a property of a signing key, not of an event.
-- Signing is batched per THOUGHT, then the signature was copied onto
-- every event row in that thought.
--
-- The symptom was a read API going deaf after ~22h with a thread parked
-- in D state on `wait_on_page_bit_common` — the working set stopped
-- fitting page cache (1,887 MB against ~1,500 MB available; 1,208 MB
-- deduped). It surfaced as an availability incident three releases after
-- the schema decision, which is why #789 also asks for a cardinality
-- gate: this class does not announce itself at review time.
--
-- NOT a general "crypto stored inline" problem, and the difference
-- matters: `federation_attestations` carries 16,010 distinct signatures
-- over 16,471 rows — genuinely per-row, and untouched here.
--
-- ─── Why this is safe ───────────────────────────────────────────────
--
-- Neither pubkey enters the SIGNED PREIMAGE. All three canonical payload
-- shapes (`canonical_payload_value`, `_v279`, `_legacy`) exclude both,
-- so where a verifier OBTAINS a key cannot change what the signature
-- covers. Dropping the stored copy therefore cannot strand a trace.
--
-- The signature is a TOTAL FUNCTION of `thought_id`: 7,264 signatures,
-- 7,264 thoughts, zero spanning two. So the per-thought table is a
-- normalization, not a heuristic with edge cases.
--
-- ─── The backfill ASSERTS ITSELF ────────────────────────────────────
--
-- `thought_id` is the PRIMARY KEY and the backfill selects DISTINCT
-- (thought_id, signature, pqc_key_id). If any thought ever carried two
-- distinct signatures — the one assumption that would make this lossy —
-- the SELECT yields two rows for it, the PK is violated, and the
-- migration ABORTS before either column is dropped. Refinery wraps each
-- migration in one transaction, so backfill-then-drop is all-or-nothing:
-- there is no state where the columns are gone and the signatures were
-- not saved.
--
-- That ordering is the whole safety argument. This corpus is durable,
-- replicated and kept for posterity; a drop that outran its backfill
-- would not be recoverable.

CREATE TABLE IF NOT EXISTS cirislens.trace_thought_signatures (
    thought_id           TEXT PRIMARY KEY,
    signature_ml_dsa_65  TEXT NOT NULL,
    pqc_key_id           TEXT
);

INSERT INTO cirislens.trace_thought_signatures (thought_id, signature_ml_dsa_65, pqc_key_id)
SELECT DISTINCT thought_id, signature_ml_dsa_65, pqc_key_id
  FROM cirislens.trace_events
 WHERE signature_ml_dsa_65 IS NOT NULL;

-- The partial index names a column being dropped, so it goes first and
-- comes back without that predicate. (Postgres would refuse the drop, and
-- SQLite refuses it explicitly: "error in index ... no such column".)
DROP INDEX IF EXISTS cirislens.trace_events_pqc_key;

ALTER TABLE cirislens.trace_events DROP COLUMN IF EXISTS signature_ml_dsa_65;
ALTER TABLE cirislens.trace_events DROP COLUMN IF EXISTS pubkey_ml_dsa_65;

CREATE INDEX IF NOT EXISTS trace_events_pqc_key
    ON cirislens.trace_events (pqc_key_id, ts DESC);

-- Space returns on VACUUM, which is an operator action: the drop marks the
-- rows dead, it does not shrink the file. On the canonical that is the
-- ~679 MB the incident was about.
