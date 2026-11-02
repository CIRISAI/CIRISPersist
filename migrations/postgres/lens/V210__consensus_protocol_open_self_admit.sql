-- V210 — admit `open:self_admit` into federation_communities.consensus_protocol.
-- Postgres dialect. v61 (CIRISPersist#1123; CC 4.4.3.2, 4.4.3.4.2, 4.5.13).
--
-- SQLITE PARITY: migrations/sqlite/lens/V210__consensus_protocol_open_self_admit.sql
--
-- WHY
-- ---
-- CC rc14 names open admission by its protocol: a `public` community's record
-- declares `consensus_protocol: open:self_admit` (there is no `admission`
-- field). Under it the group's side of a widening that seats one new key is
-- that key's own signature, and a removal takes two voices (CC 4.5.13). The
-- Rust shape gate (`consensus_protocol::is_canonical_form`) admits the string;
-- this CHECK, last widened by V120, does not, so a conformant public room
-- could not be stored.
--
-- HOW
-- ---
-- The V120 discovery-drop and re-add, with one arm added: the exact string
-- `open:self_admit`. Every other arm is V120's, unchanged, so no stored row
-- changes meaning. `federation_families.consensus_protocol` carries no CHECK
-- (V059); a family naming `open:self_admit` is refused by the Rust gate
-- (`admission::check_family_consensus_protocol_form`), never here.

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
    CHECK (consensus_protocol ~ '^(founder_only|unanimous|majority|open:self_admit|quorum:[0-9]+/[0-9]+|reverse_quorum:[0-9]+/[0-9]+:[0-9]+([+]escalate:[0-9]+:[0-9]+)?|weighted:.+|custom:.+)$');
