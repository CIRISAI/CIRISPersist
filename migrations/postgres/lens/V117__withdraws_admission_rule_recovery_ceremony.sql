-- V117 — admit rule 5, the CC 3.2 ownerless-lock RECOVERY CEREMONY, into
-- federation_attestations.withdraws_admission_rule — Postgres dialect
-- v25.x (CIRISPersist#578, CIRISConstitution rc3 CC 3.2)
--
-- SQLITE PARITY: migrations/sqlite/lens/V117__withdraws_admission_rule_recovery_ceremony.sql
-- (same widening; that backend has no DROP CONSTRAINT so its twin is a full
-- table rebuild. See it for the same rationale at length.)
--
-- WHAT THIS FIXES — AND IT IS NOT ONLY A NEW RULE NUMBER
-- -----------------------------------------------------
-- V055 wrote `withdraws_admission_rule BETWEEN 1 AND 4` because CEG §3.2.3 had
-- exactly four admission rules. v21.8.0 then added a FIFTH — the ownerless-lock
-- reclaim exception — and stamped `withdraws_admission_rule = 5` on the rows it
-- admitted. That value has never been storable here or on sqlite: the CHECK
-- refuses it, so the write fails at INSERT.
--
-- The memory backend has no CHECK and accepted it, which is why nothing caught
-- this for four minor versions: the reclaim's unit tests called the gate
-- function directly and never stored a row, so the only backend exercised
-- end-to-end was the one that enforces nothing. #578's ceremony witness stores
-- the gated `withdraws` through the REAL `put_attestation` path on all three
-- backends, which surfaced it on the first run.
--
-- WHAT RULE 5 MEANS NOW
-- ---------------------
-- rc3 re-points the recovery path: the gated `withdraws` must carry a
-- `wa_adjudication_ref` naming a CC 4.3 Wise-Authority quorum finding of
-- abandonment or seizure, filed by an issuer with CC 2.4.1.1 rule-(2)/(4)
-- standing, after which the node is UNOWNED until a fresh owner-binding
-- co-signed by the node itself lands. Rule 5 is the audit stamp recording
-- "admitted by the recovery ceremony, not by one of the four ordinary rules" —
-- and `check_post_reclaim_rebinding_admission` reads it back off this column to
-- know the node owes that co-signature. The value being storable is load-bearing
-- twice: once as audit, once as state.
--
-- The range stays CLOSED at 5. A sixth rule widens it deliberately, in a
-- migration, on both backends.
--
-- Idempotent: the constraint is dropped only if present, then re-added only if
-- absent — the same discovery-guard discipline V055 used to add it.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'federation_attestations_withdraws_admission_rule_range'
          AND conrelid = 'cirislens.federation_attestations'::regclass
    ) THEN
        ALTER TABLE cirislens.federation_attestations
            DROP CONSTRAINT federation_attestations_withdraws_admission_rule_range;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'federation_attestations_withdraws_admission_rule_range'
          AND conrelid = 'cirislens.federation_attestations'::regclass
    ) THEN
        ALTER TABLE cirislens.federation_attestations
            ADD CONSTRAINT federation_attestations_withdraws_admission_rule_range
                CHECK (withdraws_admission_rule IS NULL
                       OR withdraws_admission_rule BETWEEN 1 AND 5);
    END IF;
END$$;
