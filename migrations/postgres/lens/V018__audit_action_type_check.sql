-- V018 — CHECK constraint on cirislens.audit_log.action_type
-- (v1.0.0, CIRISAgent#756 Q2 verdict).
--
-- Agent team confirmed: CHECK constraint with additive-migration
-- evolution. This locks the audit event vocabulary to the 21 values
-- in CIRISAgent's `AuditEventType` enum (`ciris_engine/schemas/audit/
-- core.py`). New action types are added by ALTER TABLE with a new
-- CHECK; persist commits to additive-only evolution (no value
-- removal without a major release).
--
-- The 21 values, grouped by class:
--
--   Handler actions (10):
--     handler_action_speak, handler_action_memorize,
--     handler_action_recall, handler_action_forget,
--     handler_action_tool, handler_action_defer,
--     handler_action_reject, handler_action_ponder,
--     handler_action_observe, handler_action_task_complete
--
--   System events (5):
--     system_event, security_event, config_change,
--     service_lifecycle, error_event
--
--   Wallet events (6):
--     wallet_funds_received, wallet_funds_sent,
--     wallet_transfer_failed, wallet_swap_completed,
--     wallet_swap_failed, wallet_security_event
--
-- NOT VALID lets existing rows skip validation (legacy rows from
-- pre-#756 writes may carry values outside this set). Followup
-- VALIDATE pass can run after the agent cutover completes a
-- backfill / archive pass.

BEGIN;

ALTER TABLE cirislens.audit_log
    ADD CONSTRAINT audit_log_action_type_check
    CHECK (action_type IN (
        -- Handler actions
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

        -- System events
        'system_event',
        'security_event',
        'config_change',
        'service_lifecycle',
        'error_event',

        -- Wallet events
        'wallet_funds_received',
        'wallet_funds_sent',
        'wallet_transfer_failed',
        'wallet_swap_completed',
        'wallet_swap_failed',
        'wallet_security_event'
    ))
    NOT VALID;

COMMIT;
