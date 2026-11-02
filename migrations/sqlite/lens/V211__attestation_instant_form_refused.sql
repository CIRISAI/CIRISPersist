-- V211 — the holding table for attestation rows refused for the form of a
-- signed instant. SQLite dialect. v61 (CC 2.6.2, the steward's strict ruling).
--
-- POSTGRES PARITY: migrations/postgres/lens/V211__attestation_instant_form_refused.sql
--
-- WHY
-- ---
-- CC 2.6.2: a signed instant is `YYYY-MM-DDTHH:MM:SS.sssZ` and a consumer
-- MUST reject any other form when verifying a signature. The ruling: no
-- cut-over instant and no normalising reader. A stored row another producer
-- signed over another form is refused at read. The open-time pass
-- (`federation::instant_form`) removes each such row from
-- `federation_attestations`, so every read path refuses it by absence on both
-- backends at once and nothing serves it onward, and records it here. No row
-- body is kept: a refused row can never be admitted again, and a copy would
-- be content no erasure door reaches. Rows this node signed are re-signed in
-- the canonical form as a `supersedes` and stay; rows that take something
-- away (retractions, revocations, delegations, the accountability record)
-- stay in force.
--
-- HOW
-- ---
-- One row per refused attestation: its id, its attester, the row hash it
-- carried, the member that failed and its value, and the instant it was
-- refused.

CREATE TABLE IF NOT EXISTS federation_attestations_form_refused (
    attestation_id   TEXT PRIMARY KEY,
    attesting_key_id TEXT NOT NULL,
    persist_row_hash TEXT NOT NULL,
    refused_member   TEXT NOT NULL,
    refused_value    TEXT NOT NULL,
    refused_at       TEXT NOT NULL
);
