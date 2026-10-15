-- V196 — an erasure's hard case names no subject, and there is no
-- node-local purge basis. SQLite dialect. v58.0.0 (CIRISPersist#1094 item 2;
-- CC 4.5.3 "Erasure at the subject's request", CLM-erasure-subject-route;
-- CIRISConstitution#174).
--
-- POSTGRES PARITY: migrations/postgres/lens/V196__erasure_names_no_subject.sql
--
-- WHY
-- ---
-- v57.0.0 recorded each DSAR erasure as a `hard_case:trace_erasure:v1` row
-- naming the erased agent (`target_key_id`, `detail.agent_id_hash`, the
-- key-scoped door's `detail.signing_key_id`) and, when it hard-deleted a
-- row-backed detection, a `purge_executions` header with the node-local
-- basis `art17_erasure` whose `notice_jcs` WAS that row's envelope. CC 4.5.3
-- (steward ruling 2026-10-15): "A hard case recording an erasure MUST NOT
-- name the subject", and "there is no node-local purge basis for erasure".
-- A hard case naming the subject is the very thing being erased, so it goes.
--
-- This is the ONE place a hard_case row is ever deleted. hard_case is the
-- accountability-record family and no door purges it; the exception is a
-- row whose content an erasure requires gone, deleted once, here. Lead
-- ruling (v58 slice E): v57.0.0 shipped 2026-10-15 with no adopters.
--
-- WHAT
-- ----
-- 1. Every `art17_erasure` header and its tombstones (the header's notice
--    names the subject). The rows those tombstones covered were hard-deleted
--    by v57 and stay deleted.
-- 2. Every `hard_case:trace_erasure:v1` row that names its subject; its
--    `hard_case_events` projection row leaves by ON DELETE CASCADE (V194).
-- 3. Every pre-v57 `hard_case_events` silo row (no backing row) of kind
--    `trace_erasure` that names its subject, so the legacy rehome never turns
--    it into a row.
-- The boot logs the counts it found before this ran (run_migrations).
-- A v58 erasure row is subject-free (`hard_case::trace_erasure_event`) and
-- is untouched.

DELETE FROM purge_tombstones
 WHERE notice_id IN (SELECT notice_id FROM purge_executions
                      WHERE legal_basis = 'art17_erasure');

DELETE FROM purge_executions WHERE legal_basis = 'art17_erasure';

DELETE FROM federation_attestations
 WHERE dimension = 'hard_case:trace_erasure:v1'
   AND (json_extract(attestation_envelope, '$.hard_case.target_key_id') IS NOT NULL
        OR json_extract(attestation_envelope, '$.hard_case.subject_key_id') IS NOT NULL
        OR json_extract(attestation_envelope, '$.hard_case.detail.agent_id_hash') IS NOT NULL
        OR json_extract(attestation_envelope, '$.hard_case.detail.signing_key_id') IS NOT NULL);

DELETE FROM hard_case_events
 WHERE attestation_id IS NULL
   AND kind = 'trace_erasure'
   AND (target_key_id IS NOT NULL
        OR subject_key_id IS NOT NULL
        OR json_extract(detail, '$.agent_id_hash') IS NOT NULL
        OR json_extract(detail, '$.signing_key_id') IS NOT NULL);
