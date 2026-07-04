-- V092 — Counter-RII `consent_role` consumer-query index
-- (CIRISPersist#365, CC 3.4.7.2 `consent-counter`, v12.7.0).
--
-- # No new column — the substrate already shipped in V020
--
-- CC 3.4.7.2 ratified `federation_keys.consent_role` (the Counter-RII
-- consent gate; RATCHET `FSD/COUNTER_RII_DETECTION.md`, Lean
-- `ConsentGate.lean`) and declared it buildable — but the COLUMN
-- already exists: V020 (v1.3.0, the CIRISAgent#760 §RC "consent role
-- lock") added `consent_role TEXT NOT NULL DEFAULT 'unregistered'` with
-- the CHECK vocabulary (unregistered / temporary / partnered /
-- anonymous / authorized_review / peer). CC 3.4.7.2's "non-breaking
-- against the shipped flat soft-delete substrate" wording is literal:
-- the ratified OQ-1 semantics (a subsequent revocation OVERWRITES the
-- prior record; flat, bounded, NO recursive chain embedded in the
-- field) are exactly the V020 column's natural UPDATE semantics.
--
-- v12.7.0 therefore adds NO schema change to the column itself — it
-- puts the field on the wire (`KeyRecord.consent_role`, `None` ⇔ the
-- stored 'unregistered' default), adds the resolver
-- (`consent_role_of` / Engine.consent_role_json) and the OQ-1
-- overwrite surface (`set_consent_role`), and ships this index.
--
-- # What persist owns vs the consumer
--
--   * OQ-1 (non-recursive overwrite-on-revoke) — SUBSTRATE:
--     `set_consent_role` is a flat single-column UPDATE; revoke = reset
--     to 'unregistered'. Chain history, if a deployment wants it, lives
--     in a separate audit surface — never in this field.
--   * OQ-2 (`peer` escapes detection at any trust_mode) and OQ-3
--     (`authorized_review` signal-eligible immediately post-window,
--     no grace) — CONSUMER-applied detection signals (edge
--     `ProbePatternObserver` / RATCHET) on the field persist carries.
--
-- # Excluded from persist_row_hash
--
-- `consent_role` is a MUTABLE operational role marker, not part of the
-- signed registration content — `compute_persist_row_hash` drops it
-- before hashing, so the OQ-1 overwrite never invalidates the
-- registration hash, and pre-existing rows' hashes are untouched.

-- ── Index ───────────────────────────────────────────────────────────
--
-- Partial index on rows that carry an assigned role. A Counter-RII
-- consumer querying "which keys hold the `peer` (OQ-2) /
-- `authorized_review` (OQ-3) role?" wants a focused index, not a
-- full-table scan over a column that is 'unregistered' almost
-- everywhere. Cardinality is small; the partial index documents the
-- access intent.

CREATE INDEX IF NOT EXISTS federation_keys_consent_role
    ON cirislens.federation_keys (consent_role)
    WHERE consent_role <> 'unregistered';

-- ── Comment (V020's column, updated for the CC 3.4.7.2 ratification) ─

COMMENT ON COLUMN cirislens.federation_keys.consent_role IS
    'V020 (CIRISAgent#760 §RC lock) ratified by CC 3.4.7.2 consent-counter (CIRISPersist#365, v12.7.0) — Counter-RII consent_role. Single flat role token (unregistered / temporary / partnered / anonymous / authorized_review / peer) gating Counter-RII probe detection applied by a consumer (edge ProbePatternObserver / RATCHET). Mutable, overwrite-on-revoke (OQ-1) via Engine.set_consent_role; ''unregistered'' = no assigned role (wire None). Excluded from persist_row_hash — NOT part of the signed registration content.';
