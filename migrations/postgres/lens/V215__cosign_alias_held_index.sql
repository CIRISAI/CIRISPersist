-- V215 — the cosign alias table, keyed for the read fold.
-- Postgres dialect. v61.3.0 (CIRISPersist#1252; CC 2.4.1.1 rule 0).
--
-- SQLITE PARITY: migrations/sqlite/lens/V215__cosign_alias_held_index.sql
--
-- The read lifecycle predicate resolves a `withdraws` that names a cosigned
-- act by another node's id through `federation_cosign_aliases`, per row it
-- reads, by the row it holds (`held_attestation_id`). That lookup is a seek,
-- never a scan.

CREATE INDEX IF NOT EXISTS federation_cosign_aliases_held
    ON cirislens.federation_cosign_aliases (held_attestation_id);
