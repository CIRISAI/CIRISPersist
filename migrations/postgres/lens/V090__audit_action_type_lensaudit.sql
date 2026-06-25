-- V090 — extend cirislens.audit_log.action_type CHECK to admit the
-- LensAudit consent + wisdom-based-deferral vocabulary (CIRISPersist#283).
--
-- CIRISServer's `LensAudit` emits `consent_event` (`log_consent_event`) and
-- `wisdom_based_deferral` (`log_wbd`). Both are accepted on SQLite (whose
-- `audit_log.action_type` is `TEXT NOT NULL` with no CHECK — see below) but
-- were REJECTED by the postgres CHECK, a backend-parity gap that surfaced as
-- a postgres-only failure in the CIRISConformance audit-accountability test
-- (`test_320`) once CIRISServer#93 seeded the chain so the writes reached the
-- CHECK.
--
-- Additive-only evolution, per the V018/V020 pattern (CIRISAgent#756 Q2):
-- DROP the existing constraint + ADD the extended one; `NOT VALID` lets any
-- legacy rows skip validation (the followup VALIDATE pass can run after a
-- backfill). The audit hash-chain + per-entry signature remain the real
-- integrity gate; this allowlist is the agent-team's closed-vocab
-- accountability control.
--
-- Why postgres-only: SQLite's `audit_log` deliberately carries NO action_type
-- CHECK (V014). SQLite cannot `ADD CONSTRAINT ... NOT VALID`, and a 12-step
-- table rebuild would re-validate EVERY existing row against the new CHECK on
-- the `INSERT ... SELECT` copy — which would fail on any legacy out-of-vocab
-- row. So the closed vocabulary is enforced postgres-side only; SQLite treats
-- `action_type` as an opaque producer string. After this migration both
-- backends accept every action type `LensAudit` emits (behavioural parity for
-- all legitimate calls). See sqlite/lens/V090 (parity note).
--
-- No explicit BEGIN/COMMIT — refinery wraps each migration in a transaction.

ALTER TABLE cirislens.audit_log
    DROP CONSTRAINT IF EXISTS audit_log_action_type_check;

ALTER TABLE cirislens.audit_log
    ADD CONSTRAINT audit_log_action_type_check
    CHECK (action_type IN (
        -- Handler actions (V018)
        'handler_action_speak',
        'handler_action_memorize',
        'handler_action_recall',
        'handler_action_forget',
        'handler_action_tool',
        'handler_action_defer',
        'handler_action_reject',
        'handler_action_ponder',
        'handler_action_observe',
        'handler_action_task_complete',

        -- System events (V018)
        'system_event',
        'security_event',
        'config_change',
        'service_lifecycle',
        'error_event',

        -- Wallet events (V018)
        'wallet_funds_received',
        'wallet_funds_sent',
        'wallet_transfer_failed',
        'wallet_swap_completed',
        'wallet_swap_failed',
        'wallet_security_event',

        -- Trust hierarchy state transitions (V020 — CIRISPersist#47)
        'trust_granted',
        'trust_revoked',

        -- LensAudit consent + wisdom-based deferral (V090 — CIRISPersist#283)
        'consent_event',
        'wisdom_based_deferral'
    ))
    NOT VALID;
