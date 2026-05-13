-- V014 — hash-chained audit log (v0.8.1, CIRISPersist#35).
--
-- Absorbs the agent's GraphAuditService write path. Per-tenant
-- monotonic `sequence_number` + sha256 `prev_hash` chain enforces
-- entry ordering AND tamper-evidence. Each entry's `entry_hash` is
-- the sha256 of canonical(this entry minus signature); the next
-- entry's `prev_hash` MUST equal that. Persist refuses any INSERT
-- that breaks the chain (AV-49) or that violates per-tenant
-- monotonicity (AV-49 / UNIQUE constraint).
--
-- # Why per-tenant chains
--
-- Cross-agent / cross-WA correlation in a single global chain
-- would let one slow signer block the entire federation's audit
-- writes. Per-tenant chains let each principal advance
-- independently while preserving tamper-evidence within their own
-- sequence. The genesis row of each chain has `sequence_number=1`
-- and `prev_hash` set to the all-zero 32-byte sentinel.
--
-- # AV-51 tenant isolation
--
-- Every read takes `tenant_id`. Cross-tenant reads (federation-
-- admin compliance scans) require an explicit federation-admin
-- role tag on the caller's federation_keys row — that gate lands
-- in v0.9.x (auth_tokens). For v0.8.1 every read pins one tenant.

BEGIN;

CREATE TABLE IF NOT EXISTS cirislens.audit_log (
    -- ULID per CIRISNodeCore/SCHEMA.md §2.2 convention. UUID col
    -- type so pg-side queries can index on the binary form.
    entry_id              UUID PRIMARY KEY,

    -- AV-49: per-tenant monotonic. UNIQUE (tenant_id, sequence_number)
    -- pins the order; gap-free is enforced application-side because
    -- the writer holds the previous sequence_number when computing
    -- prev_hash anyway.
    sequence_number       BIGINT NOT NULL CHECK (sequence_number >= 1),

    -- Per-tenant chain selector. Free-form text — agents register
    -- their own tenant_id (typically the agent's identity hash);
    -- federation-WA writers use a WA-namespaced tenant_id.
    tenant_id             TEXT NOT NULL,

    -- §2.2 ContributorId-shaped — Ed25519 pubkey, base64. Persist
    -- verifies the signature against this on INSERT (self-signed
    -- model, same as cirisnode v0.7.1).
    actor_id              TEXT NOT NULL,

    -- Stable token: `task_signed`, `config_changed`, `wa_intervention`,
    -- `consent_revoked`, etc. Free-form so the agent's taxonomy can
    -- evolve without schema migrations; downstream filters can pin.
    action_type           TEXT NOT NULL,

    -- What the action targeted. `subject_kind` is the type label
    -- (`task` / `config` / `memory` / `secret` / …); `subject_id`
    -- is the row id within that namespace.
    subject_kind          TEXT NOT NULL,
    subject_id            TEXT NOT NULL,

    -- Free-form per-action payload. JSONB so per-action shapes nest
    -- cleanly. AV-49: the canonical bytes used for prev_hash /
    -- entry_hash include this payload byte-for-byte.
    payload               JSONB NOT NULL,

    -- AV-49 hash-chain columns. Both are sha256(canonical(entry)) —
    -- 32 bytes binary. The genesis-of-chain row has prev_hash = zeros.
    prev_hash             BYTEA NOT NULL,
    entry_hash            BYTEA NOT NULL,

    -- Caller-asserted wall-clock at signing time.
    recorded_at           TIMESTAMPTZ NOT NULL,

    -- Audit envelope (matches cirisnode / cirisgraph shape).
    signature             TEXT NOT NULL,
    signing_key_id        TEXT NOT NULL,
    signature_verified    BOOLEAN NOT NULL DEFAULT FALSE,
    persist_row_hash      TEXT NOT NULL,

    UNIQUE (tenant_id, sequence_number)
);

CREATE INDEX IF NOT EXISTS audit_log_tenant_seq
    ON cirislens.audit_log (tenant_id, sequence_number);
CREATE INDEX IF NOT EXISTS audit_log_subject
    ON cirislens.audit_log (subject_kind, subject_id);
CREATE INDEX IF NOT EXISTS audit_log_actor
    ON cirislens.audit_log (actor_id);
CREATE INDEX IF NOT EXISTS audit_log_recorded_at
    ON cirislens.audit_log (recorded_at);
CREATE INDEX IF NOT EXISTS audit_log_action_type
    ON cirislens.audit_log (action_type);

COMMENT ON TABLE cirislens.audit_log IS
    'v0.8.1 (CIRISPersist#35) — hash-chained audit log. Per-tenant monotonic sequence_number + sha256 prev_hash chain. Each entry signs over canonical bytes; persist verifies on INSERT and refuses chain breaks. Self-signed identity model: actor_id IS the Ed25519 pubkey (base64).';

COMMIT;
