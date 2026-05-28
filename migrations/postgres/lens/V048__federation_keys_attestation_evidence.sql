-- V048 — Hardware-attestation evidence column on federation_keys
-- (CIRISPersist#102 Ask 8, v2.5.0).
--
-- # Architectural shape
--
-- HUMANITY_ACCORD keys (`identity_type = 'accord_holder'`) MUST live
-- on hardware substrate per FSD-002 §7.3 + FEDERATION_ANNOUNCEMENT
-- §4.5.2. CIRISVerify's `docs/HARDWARE_ATTESTATION.md` (v3.0.1
-- commit 043e64c) deliberately does NOT publish a single
-- `hardware_attested: bool` — per the auth ≠ trust separation, Verify
-- exposes evidence; the consumer (persist) authors the policy.
--
-- Persist stores the evidence as JSONB on `federation_keys.attestation_evidence`:
--
--     {
--       "platform_attestation": <PlatformAttestation JSON>,
--       "nonce_captured_at": "<RFC3339 timestamp>"
--     }
--
-- The serialized `PlatformAttestation` is one of four ciris-keyring
-- variants (Android / iOS / TPM / Software); each variant carries the
-- required fields its hardware class produces (Android: key-attestation
-- cert chain + Play Integrity token + StrongBox flag; iOS: Secure
-- Enclave flag + App Attest + DeviceCheck; TPM: TPMS_ATTEST quote +
-- EK cert + AK pubkey + PCR values + manufacturer + discrete flag).
--
-- # Schema enforcement (defense in depth)
--
-- The admission hook in `src/federation/hardware_attestation.rs` is
-- the load-bearing policy point. The schema's CHECK constraint is
-- defense in depth — catches the case where a row bypasses the
-- admission hook (e.g., direct SQL).
--
--   identity_type = 'accord_holder' ⟹ attestation_evidence IS NOT NULL
--
-- Non-accord-holder rows MAY have attestation_evidence (informational
-- — operators tracking which keys are hardware-bound for non-
-- constitutional reasons), but the column is NULL by default.
--
-- # No active chain validation in v2.5.0
--
-- Persist does NOT validate the attestation cert-chain to manufacturer
-- roots (Android → Google root, TPM → manufacturer CA). That's
-- CIRISVerify#32 Ask 5's local-chain-validation surface; Verify
-- v3.0.1 has NOT shipped it (the `play_integrity.rs` / `tpm_attest.rs` /
-- `app_attest.rs` types in ciris-keyring are request/response shapes
-- that route through the registry today). Persist's structural check
-- ensures the evidence shape is right + the nonce is fresh; registry-
-- side or Verify#32 Ask 5 validation does the chain verification.
-- Persist's storage of the evidence preserves the audit trail.
--
-- # Forward compat with persist_row_hash
--
-- `KeyRecord.attestation_evidence` is `Option<serde_json::Value>` with
-- `skip_serializing_if = "Option::is_none"`. Pre-V048 rows + non-
-- accord-holder rows serialize without the field — the canonical
-- bytes are byte-equal to pre-v2.5.0, so `persist_row_hash` stays
-- stable. Accord-holder rows include the field; their hash reflects
-- the evidence content.

-- ── Column ──────────────────────────────────────────────────────────

ALTER TABLE cirislens.federation_keys
    ADD COLUMN IF NOT EXISTS attestation_evidence JSONB NULL;

-- ── CHECK constraint ────────────────────────────────────────────────
--
-- accord_holder rows MUST carry evidence. Non-accord-holder rows
-- MAY carry it (operators tracking hardware binding for partner /
-- steward keys). The constraint is named so a future amendment
-- (e.g., requiring evidence for `steward` too) can drop + add
-- without an anonymous-constraint lookup dance.

ALTER TABLE cirislens.federation_keys
    ADD CONSTRAINT federation_keys_accord_holder_requires_attestation
        CHECK (
            identity_type <> 'accord_holder'
            OR attestation_evidence IS NOT NULL
        );

-- ── Index ───────────────────────────────────────────────────────────
--
-- Partial index on accord-holder rows specifically — operators
-- auditing "which accord-holder keys exist?" + "what hardware class
-- backs each?" want a focused index, not a full-table scan over
-- a `WHERE identity_type = 'accord_holder' AND attestation_evidence ...`
-- query. Cardinality is tiny (3-6 rows typical per FSD-002 §7.2),
-- but a partial index documents the intent.

CREATE INDEX IF NOT EXISTS federation_keys_accord_holder_evidence
    ON cirislens.federation_keys (key_id)
    WHERE identity_type = 'accord_holder';

-- ── Comments ────────────────────────────────────────────────────────

COMMENT ON COLUMN cirislens.federation_keys.attestation_evidence IS
    'v2.5.0 (CIRISPersist#102 Ask 8) — hardware-attestation evidence captured at key-binding time. REQUIRED for identity_type = ''accord_holder'' rows per FSD-002 §7.3. JSONB shape: {platform_attestation: <PlatformAttestation JSON>, nonce_captured_at: <RFC3339>}. The HardwareAttestationPolicy admission hook validates variant + field presence + nonce freshness; the CHECK constraint here catches direct-SQL bypass. Active cert-chain validation is deferred to CIRISVerify#32 Ask 5.';

COMMENT ON CONSTRAINT federation_keys_accord_holder_requires_attestation
    ON cirislens.federation_keys IS
    'v2.5.0 — defense in depth. accord_holder rows MUST carry attestation_evidence; the admission hook is the load-bearing point, the CHECK constraint is the backstop against direct-SQL writes that skip the admission path.';
