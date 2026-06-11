-- V072 — CEG 1.0-RC2 §5.6.8.13: persist the partner_record M-of-N steward
--        signature SET (bidirectional partner_record — CIRISPersist#194,
--        CIRISEdge#65 v2 bridge). SQLite dialect. See postgres/lens/V072 for
--        the full rationale.
--
-- v5.1.x verified the steward quorum at admit then discarded the signature set,
-- storing only the envelope → partner_record was admit-only on the Edge v2 bridge
-- (Initiator couldn't re-emit the wrapper to recompute envelope_hash). Store the
-- signature set + threshold so `list_signed_partner_records_since` reconstructs
-- the full `SignedPartnerRecord` and both ends JCS-hash byte-identical bytes.
--
-- `steward_signatures` = serialized `Vec<ThresholdSignature>` (JSON as TEXT);
-- `threshold` = the M-of-N M. Additive; admit-only-era rows default to empty/0
-- (never re-emitted). SQLite ADD COLUMN with a constant NOT NULL DEFAULT is
-- backfilled in place.

ALTER TABLE federation_partner_records ADD COLUMN steward_signatures TEXT NOT NULL DEFAULT '[]';
ALTER TABLE federation_partner_records ADD COLUMN threshold INTEGER NOT NULL DEFAULT 0;
