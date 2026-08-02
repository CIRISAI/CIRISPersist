-- V116 — admit the OBJECTION form into federation_communities.consensus_protocol
-- v24.3.0 (CIRISPersist#574)
--
-- SQLITE PARITY: migrations/sqlite/lens/V116__consensus_protocol_reverse_quorum.sql
-- (same form admitted there — but SQLite bakes table-level CHECKs into
-- CREATE TABLE and has no DROP CONSTRAINT, so its twin is a table rebuild
-- and this one is a discovery-drop plus a re-add.)
--
-- WHAT AND WHY
-- ------------
-- V060 pinned `consensus_protocol` to six forms:
--
--     founder_only | unanimous | majority | quorum:m/n | weighted:r | custom:id
--
-- EVERY ONE OF THEM IS APPROVE-TO-ACT. Each names who must sign BEFORE an
-- action lands. That is the right shape for governing the GROUP — who joins,
-- who holds the charter — and it is the wrong shape for policing the COMMONS.
--
-- Consent protects the private plane structurally: no signed directed grant,
-- no delivery. The commons gets nothing from consent, because in the commons
-- everyone has already consented to look. A community's only two available
-- responses to a federation-scoped row it considers harmful were therefore
-- (a) unilateral action by one member — fast and illegitimate, or (b)
-- approve-first quorum — legitimate and too slow, landing after the harm.
--
-- V116 adds the third:
--
--     reverse_quorum:{m}/{n}:{window_secs}       e.g. reverse_quorum:2/5:86400
--
-- Act-unless-objected. The action takes effect on arrival; any ONE current
-- member may raise a signed, durable, replicable objection; `m` distinct
-- in-window objectors reverse it; and DISMISSING an objection costs m-of-n
-- floored at a strict majority. 1-of-N to protect, m-of-n to undo — the
-- repo's recorded accord-ops invariant, in its reverse-quorum form.
--
-- THIS COLUMN IS ONE OF THREE PLACES THE VOCABULARY IS CLOSED
-- ----------------------------------------------------------
-- The other two are this CHECK's sqlite twin and the Rust shape gate
-- (`federation::types::consensus_protocol::is_canonical_form`, which #574
-- routes through `ReverseQuorumPolicy::parse` so the gate can never admit a
-- string the fold cannot read). All three move together or the form is
-- admitted by one layer and rejected by the next — which is exactly how this
-- migration got written: the Rust gate alone passed, and sqlite raised a
-- CHECK violation on the first real `put_community`.
--
-- The regex is DELIBERATELY stricter than the `quorum:` arm it sits beside:
-- `{m}` and `{n}` and `{window_secs}` are all digit-only, so a malformed
-- window can never reach a row and be silently read as "no window". The
-- semantic constraints a regex cannot express (`0 < m <= n`) live in
-- `ReverseQuorumPolicy::parse`, which is the single parser both the shape
-- gate and the fold run.
--
-- Nothing is removed and no row changes: the six existing forms remain
-- admissible with identical meaning, so every stored community is untouched
-- and this migration is safe to apply under load.
--
-- `federation_families.consensus_protocol` carries NO CHECK (V059 left it
-- unconstrained at the column and V097's rebuild preserved that), so there is
-- deliberately nothing to widen there.
--
-- Dropped by DISCOVERY, not by name — the V114/V115 lesson. V060 names the
-- constraint `federation_communities_consensus_protocol_form`, but a
-- deployment restored from a dump under a different name would otherwise be
-- silently left enforcing the six-form set, making `reverse_quorum:*` a
-- runtime 23514 on exactly the deployments that took the trouble to rename
-- things. Matched on the COLUMN it constrains, which is stable.
--
-- The V060 GIN index on `members` is untouched: DROP CONSTRAINT does not
-- affect indexes.
--
-- Refinery wraps each migration in its own transaction; no explicit
-- BEGIN/COMMIT here.

DO $$
DECLARE
    conname_to_drop text;
BEGIN
    SELECT c.conname INTO conname_to_drop
    FROM pg_constraint c
    JOIN pg_class t     ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = 'cirislens'
      AND t.relname = 'federation_communities'
      AND c.contype = 'c'
      AND c.conkey = ARRAY[
            (SELECT a.attnum FROM pg_attribute a
              WHERE a.attrelid = t.oid AND a.attname = 'consensus_protocol')
          ]::smallint[];

    IF conname_to_drop IS NOT NULL THEN
        EXECUTE format(
            'ALTER TABLE cirislens.federation_communities DROP CONSTRAINT %I',
            conname_to_drop);
    END IF;
END
$$;

ALTER TABLE cirislens.federation_communities
    ADD CONSTRAINT federation_communities_consensus_protocol_form
    CHECK (consensus_protocol ~ '^(founder_only|unanimous|majority|quorum:[0-9]+/[0-9]+|reverse_quorum:[0-9]+/[0-9]+:[0-9]+|weighted:.+|custom:.+)$');
