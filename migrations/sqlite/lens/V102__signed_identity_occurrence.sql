-- V102 — CIRISPersist#418 (occurrence-KEX arc 2/4): the signed-occurrence
--        columns. SQLite dialect. Postgres parity: postgres/lens/V102.
--
-- Before #418, federation_identity_occurrences admitted the content-tier KEX
-- pubkeys on length/closed-set checks only — a replication peer could fabricate
-- a victim's occurrence (silent content-MITM). put_identity_occurrence now
-- verifies a hybrid signature over the exact producer envelope
-- (verify_transport_binding, CIRISVerify#183). These columns persist the
-- authenticated material so the occurrence is the single signed source of truth
-- for {transport reticulum keys, dest_hash, content-KEM}:
--   attesting_key_id  — the claimed signer (identity's own key or an active
--                       occurrence of it; signer_acts_for).
--   signed_envelope   — the EXACT bytes the producer signed (JSON), what the
--                       signature covers; authority, not the typed projection.
--   signature         — the detached hybrid signature (JSON: ed25519 + ml-dsa).
--   transport_binding — the occurrence's RNS transport binding parsed from the
--                       envelope (JSON), authoritative over the mutable overlay.
--
-- All nullable: pre-#418 rows (all self-written today) grandfather to NULL and
-- are not re-verified; the WIRE (replication) path rejects unsigned from the
-- version bump. Refinery wraps this in its own transaction.

ALTER TABLE federation_identity_occurrences ADD COLUMN attesting_key_id  TEXT;
ALTER TABLE federation_identity_occurrences ADD COLUMN signed_envelope   TEXT;
ALTER TABLE federation_identity_occurrences ADD COLUMN signature         TEXT;
ALTER TABLE federation_identity_occurrences ADD COLUMN transport_binding TEXT;
