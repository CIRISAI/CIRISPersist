-- V112 (CIRISPersist#519 item 2a-iii) — the `freshness_floor` table: a
-- SIGNED temporal LOWER bound ("this object was demonstrably alive no
-- earlier than fresh_as_of") for any (target_key_id, target_kind) pair.
-- Dual to the existing upper bounds (valid_until / expires_at /
-- deletion_window). SQLite dialect. Postgres parity: postgres/lens/V112.
--
-- merge_rule = monotonic_max: `fresh_as_of` only ever advances — see
-- `put_touch_claim`'s ON-CONFLICT guard (`WHERE excluded.fresh_as_of >
-- freshness_floor.fresh_as_of`), the same anti-rollback discipline
-- `transport_destinations`' epoch guard established (V105/#443). An
-- incoming claim with `fresh_as_of <= stored` is a silent no-op.
--
-- Columns:
--   target_key_id / target_kind — what's being kept alive (an
--                      occurrence_key_id, a canonical key_id, ...);
--                      together the PK. NOT an FK — deliberately generic
--                      across claim families (ownership:* / trust:* /
--                      consent:* / ...).
--   fresh_as_of        — the signed lower bound, RFC-3339 UTC.
--   signer_form        — self_touch | witness_touch | n_of_m_cosigned
--                      (CIRISPersist#519 namespace_supersets.json
--                      freshness_floor.signer_forms).
--   attesting_key_id / signed_envelope / signature — the detached hybrid
--                      signature container (the #418/#443 discipline):
--                      byte-exact `signed_envelope` (TEXT, not a
--                      normalized JSON blob) so it round-trips byte-exact
--                      for replication re-publish; `signature` is the
--                      same [ed25519, ml-dsa-65] container the transport/
--                      occurrence/revocation planes use.
--   cohort_scope       — MANDATORY privacy row: touch-claims are
--                      cohort-scoped + consent-gated, never a global
--                      read-receipt trail (an unrestricted "who touched
--                      what, when" surface is an access-pattern
--                      surveillance hole).
CREATE TABLE freshness_floor (
    target_key_id    TEXT NOT NULL,
    target_kind      TEXT NOT NULL,
    fresh_as_of      TEXT NOT NULL,   -- RFC-3339 UTC
    signer_form      TEXT NOT NULL,
    attesting_key_id TEXT NOT NULL,
    signed_envelope  TEXT NOT NULL,   -- byte-exact JSON
    signature        TEXT NOT NULL,   -- hybrid detached sig, byte-exact JSON
    cohort_scope     TEXT NOT NULL,
    PRIMARY KEY (target_key_id, target_kind)
);
