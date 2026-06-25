-- V090 — parity note for postgres/lens/V090 (CIRISPersist#283). NO-OP.
--
-- Postgres V090 extends the `audit_log.action_type` CHECK to admit the
-- LensAudit `consent_event` + `wisdom_based_deferral` vocabulary. SQLite has
-- NOTHING to do here: `cirislens_audit_log.action_type` is `TEXT NOT NULL`
-- with NO CHECK (V014) — it already accepts every action type. The closed
-- vocabulary is enforced postgres-side only, because SQLite cannot
-- `ADD CONSTRAINT ... NOT VALID` and a table rebuild would re-validate legacy
-- rows against the new CHECK. So `action_type` is an opaque producer string
-- on SQLite by design; the audit hash-chain + signature are the integrity
-- gate. After postgres V090 both backends accept the same vocabulary
-- (behavioural parity for every LensAudit call).
--
-- This migration only re-asserts the existing (V014) action_type index
-- `IF NOT EXISTS` so the version sequence stays in lockstep with postgres.
-- No explicit BEGIN/COMMIT — refinery wraps each migration in a transaction.

CREATE INDEX IF NOT EXISTS audit_log_action_type
    ON cirislens_audit_log (action_type);
