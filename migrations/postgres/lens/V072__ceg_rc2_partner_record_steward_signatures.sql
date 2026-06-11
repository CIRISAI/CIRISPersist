-- V072 — CEG 1.0-RC2 §5.6.8.13: persist the partner_record M-of-N steward
--        signature SET (bidirectional partner_record — CIRISPersist#194,
--        CIRISEdge#65 v2 bridge). Postgres dialect; SQLite parity in
--        sqlite/lens/V072.
--
-- v5.1.x stored only the partner_record `signed_envelope` — `put_partner_record`
-- verified the M-of-N steward quorum at admit (verify `verify_partner_record_quorum`)
-- then DISCARDED the signature set. That made partner_record **admit-only** on the
-- Edge v2 bridge: the Responder admits peer-pushed `SignedPartnerRecord` bytes, but
-- the Initiator can't re-emit the wrapper (it lacks the signatures), so its
-- `envelope_hash` in a `SummaryMessage` can't be recomputed from byte-identical
-- bytes and anti-entropy never converges for this kind.
--
-- This stores the steward signature set + the M-of-N threshold alongside the
-- envelope so `list_signed_partner_records_since` can reconstruct the full
-- `SignedPartnerRecord` — both ends of an anti-entropy exchange JCS-hash the same
-- bytes. (Organizations / org_memberships already store their single-signer
-- Ed25519+ML-DSA halves inline and were bidirectional from V071.)
--
-- `steward_signatures` is the serialized `Vec<ThresholdSignature>` (member_id +
-- ed25519/ml-dsa base64 per signer); `threshold` is the M-of-N M. Additive:
-- pre-existing (admit-only era) rows default to an empty set / 0 threshold — they
-- were never re-emitted, so the default is correct and harmless.

ALTER TABLE cirislens.federation_partner_records
    ADD COLUMN IF NOT EXISTS steward_signatures JSONB   NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS threshold          INTEGER NOT NULL DEFAULT 0;
