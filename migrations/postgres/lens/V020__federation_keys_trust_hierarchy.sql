-- V020 — Federation trust hierarchy + roles + edge detection events
-- (v1.3.0, CIRISPersist#46 + #47, M2 cut of the v1.3.0 roadmap).
--
-- Absorbs NodeCore's `crate::trust` module surface: persist owns the
-- storage + raw CRUD for the trust hierarchy; NodeCore composes the
-- transitive-resolution policy. NodeCore's local placeholder trait
-- becomes `pub use ciris_persist::federation::FederationDirectory`
-- once this migration ships.
--
-- # What this migration adds
--
-- 1. **Trust hierarchy columns** on `cirislens.federation_keys`
--    (NodeCore#2 / FSD TRUST_HIERARCHY.md §4.1):
--      - `trust_type`         — Temporary / Partnered / Anonymous
--      - `trust_relationship` — Direct / Registry
--      - `trust_domains`      — TEXT[] (required when Registry)
--      - `trusted_at`         — wall-clock at grant time
--      - `trusted_by`         — grantor key_id (MUST differ from key_id)
--      - `expires_at`         — soft-delete sentinel
--
-- 2. **Consent role lock** on `cirislens.federation_keys`
--    (CIRISAgent#760 §RC, Counter-RII OQ-1=A — flat enum, no
--    recursive JSONB):
--      - `consent_role` — unregistered / temporary / partnered /
--        anonymous / authorized_review / peer
--
-- 3. **Per-row role tags** on `cirislens.federation_keys`
--    (CIRISPersist#46 — pipeline + secrets handler enforcement):
--      - `roles` — TEXT[] (e.g. cirislens_pipeline_writer,
--        cirislens_secrets_reader / _writer / _admin)
--
-- 4. **Edge detection events** table for LensCore's
--    UnconsentedExternalProbe / ExcessiveRecursion / ConsentGateLeak
--    detector signals (NodeCore#2 §4.4).
--
-- 5. **Audit vocabulary extension** (CIRISAgent#756 Q4 verdict —
--    state transitions live in the audit chain). Adds two action
--    types to the V018 CHECK constraint:
--      - `trust_granted`
--      - `trust_revoked`
--
-- # Self-trust prevention
--
-- The `trusted_by != key_id` rule is enforced two ways:
--   * Column-level CHECK on `federation_keys` (NOT VALID — existing
--     rows pre-V020 have `trusted_by IS NULL` which the CHECK lets
--     through).
--   * API-layer guard in `FederationDirectory::grant_trust` —
--     `Error::InvalidArgument` when `grant.trusted_by == grant.key`.
--
-- # Registry-requires-domains
--
-- `trust_relationship = 'registry'` rows MUST have a non-empty
-- `trust_domains` array. Enforced by column-level CHECK NOT VALID +
-- API-layer guard in `grant_trust`.
--
-- # Refinery transaction wrapping
--
-- Per V019's header note: refinery wraps each migration in its own
-- transaction. NO explicit BEGIN/COMMIT in this file — nested
-- transactions interact poorly with PG's expression-index parsing.

-- ─── federation_keys: trust hierarchy ──────────────────────────────

ALTER TABLE cirislens.federation_keys
    ADD COLUMN IF NOT EXISTS consent_role TEXT NOT NULL DEFAULT 'unregistered'
        CHECK (consent_role IN (
            'unregistered', 'temporary', 'partnered', 'anonymous',
            'authorized_review', 'peer'
        ));

ALTER TABLE cirislens.federation_keys
    ADD COLUMN IF NOT EXISTS trust_type TEXT NOT NULL DEFAULT 'temporary'
        CHECK (trust_type IN ('temporary', 'partnered', 'anonymous'));

ALTER TABLE cirislens.federation_keys
    ADD COLUMN IF NOT EXISTS trust_relationship TEXT NOT NULL DEFAULT 'direct'
        CHECK (trust_relationship IN ('direct', 'registry'));

ALTER TABLE cirislens.federation_keys
    ADD COLUMN IF NOT EXISTS trust_domains TEXT[];

ALTER TABLE cirislens.federation_keys
    ADD COLUMN IF NOT EXISTS trusted_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE cirislens.federation_keys
    ADD COLUMN IF NOT EXISTS trusted_by TEXT;

ALTER TABLE cirislens.federation_keys
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- Self-trust prevention. NULL allowed (rows pre-V020 have no
-- trusted_by); API-layer enforces IS NOT NULL on new grants.
ALTER TABLE cirislens.federation_keys
    ADD CONSTRAINT federation_keys_no_self_trust
        CHECK (trusted_by IS NULL OR trusted_by <> key_id) NOT VALID;

-- Registry rows require domains. NULL trust_domains + Direct is OK;
-- Registry must have a non-empty array.
ALTER TABLE cirislens.federation_keys
    ADD CONSTRAINT federation_keys_registry_requires_domains
        CHECK (
            trust_relationship <> 'registry'
            OR (trust_domains IS NOT NULL AND array_length(trust_domains, 1) > 0)
        ) NOT VALID;

-- ─── federation_keys: per-row role tags (CIRISPersist#46) ──────────

ALTER TABLE cirislens.federation_keys
    ADD COLUMN IF NOT EXISTS roles TEXT[];

-- ─── Indexes for resolver queries ──────────────────────────────────

CREATE INDEX IF NOT EXISTS federation_keys_trust_relationship
    ON cirislens.federation_keys (trust_relationship);

-- GIN index on trust_domains scoped to Registry rows — the only rows
-- where the column is populated. NodeCore's `resolve_transitive`
-- filters by relationship='registry' + domain membership; this index
-- covers that query without scanning Direct rows.
CREATE INDEX IF NOT EXISTS federation_keys_trust_domains_gin
    ON cirislens.federation_keys USING GIN (trust_domains)
    WHERE trust_relationship = 'registry';

-- Expiry filter — `list_trusted_keys(include_expired=false)` defaults
-- to `WHERE expires_at IS NULL OR expires_at > NOW()`. Partial index
-- on `expires_at IS NOT NULL` keeps the common case (no expiry) off
-- the index.
CREATE INDEX IF NOT EXISTS federation_keys_expires_at
    ON cirislens.federation_keys (expires_at)
    WHERE expires_at IS NOT NULL;

-- ─── edge_detection_events (LensCore detector signals) ─────────────

CREATE TABLE IF NOT EXISTS cirislens.edge_detection_events (
    detection_id           UUID PRIMARY KEY,

    -- Tenant scope — same shape as cirislens.audit_log per AV-51.
    tenant_id              TEXT NOT NULL,

    -- Detector vocabulary. CIRISPersist#46 ships the first three
    -- detectors; new kinds added via additive ALTER + CHECK rewrite.
    detector_kind          TEXT NOT NULL
        CHECK (detector_kind IN (
            'unconsented_external_probe',
            'excessive_recursion',
            'consent_gate_leak'
        )),

    -- The federation_keys.key_id the detection is about (the suspect
    -- principal, not the detector). FK enforces referential
    -- integrity — detection events for unknown keys make no sense.
    subject_key_id         TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),

    observed_at            TIMESTAMPTZ NOT NULL,
    evidence               JSONB NOT NULL,
    severity               TEXT NOT NULL
        CHECK (severity IN ('info', 'warn', 'block')),

    -- Standard CIRISPersist audit envelope.
    signature              TEXT NOT NULL,
    signing_key_id         TEXT NOT NULL,
    signature_verified     BOOLEAN NOT NULL DEFAULT FALSE,
    persist_row_hash       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS edge_detection_events_tenant_observed
    ON cirislens.edge_detection_events (tenant_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS edge_detection_events_subject
    ON cirislens.edge_detection_events (subject_key_id);
CREATE INDEX IF NOT EXISTS edge_detection_events_kind_severity
    ON cirislens.edge_detection_events (detector_kind, severity);

-- ─── audit_log vocabulary extension (CIRISAgent#756 Q4) ────────────
--
-- Add `trust_granted` + `trust_revoked` to the V018 CHECK constraint
-- vocabulary. Per CIRISAgent#756 Q4 verdict, state transitions for
-- the trust hierarchy live in the audit chain — same shape as
-- handler actions / system events / wallet events.
--
-- Pattern matches V018: drop the existing CHECK, replace with an
-- extended one (`NOT VALID` lets legacy rows skip validation).

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
        'trust_revoked'
    ))
    NOT VALID;
