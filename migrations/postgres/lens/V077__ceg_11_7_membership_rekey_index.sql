-- V077 — CEG §11.7.1 / §10.1.4 membership-change / re-key keystone
--        (CIRISPersist#161 Ask 2/4, v6.1.0) — Postgres dialect. SQLite
--        parity: sqlite/lens/V077.
--
-- The retroactive key-grant ADD re-wrap (orchestrate::rekey_for_newcomers)
-- joins a newcomer occurrence/member into a cohort's at-rest visibility
-- set: for every existing federation_blob_key_grants row a current cohort
-- recipient holds in a scope, it recovers the DEK (via the
-- __persist_self__ content-master self-retention grant) and wraps it to the
-- newcomer. The keystone reuses the V070 grant table + content master — NO
-- new tables. It adds only a supporting index for the new visibility-set
-- read, list_at_rest_blobs_for_recipients:
--
--   SELECT DISTINCT at_rest_sha256 FROM cirislens.federation_blob_key_grants
--   WHERE cohort_scope = $1 AND recipient_key_id = ANY($2);
--
-- The V070 index federation_blob_key_grants_by_recipient is on
-- (recipient_key_id) alone; this composite (cohort_scope, recipient_key_id)
-- lets the scope-filtered membership-add walk seek directly rather than
-- scan-and-filter. Producer-side stop-wrapping on removal needs no schema:
-- the V067 *_active enumeration already drops a removed member from future
-- cascade writes (forward secrecy via the per-write fresh DEK). Retroactive
-- revoke of past grants is intentionally NOT modeled — V067 removal is an
-- append-only revocation the *_active read composes against, and Option-A
-- relies on forward secrecy, not key destruction.
--
-- Refinery wraps this migration in its own transaction.

CREATE INDEX IF NOT EXISTS federation_blob_key_grants_by_scope_recipient
    ON cirislens.federation_blob_key_grants (cohort_scope, recipient_key_id);
