-- V083 — per-trace ML-DSA-65 hybrid signature columns (CIRISPersist#225).
--
-- The trace-tier hybrid hard cut. CEG 1.0-RC7 §10.1.5.1.1 + the hard
-- cut on CIRISVerify#75: no classical-only anywhere — federation root
-- AND operational leaf. The driver is Harvest-Now-Decrypt-Later
-- forge-later against a durable, content-addressed, replicated corpus
-- kept for posterity: a CRQC-era adversary who breaks Ed25519 can mint
-- backdated traces under any historical key and inject them into the
-- permanent record. Content-addressing is no defense (they hash their
-- own forgery). The trace store outlives the classical primitive, so
-- the per-trace producer signature MUST be post-quantum.
--
-- V001 gave trace_events a single classical `signature TEXT`. V003
-- added the storage scrub envelope (`scrub_signature`, single-column
-- at this tier; #224 made the SCRUB sig hybrid via the hardware
-- signer). This migration adds the PRODUCER's per-trace-envelope
-- ML-DSA-65 half, mirroring the federation key split
-- (`scrub_signature_classical` + `scrub_signature_pqc` on
-- `federation_keys`, V004).
--
-- Three columns, all NULLABLE:
--   * signature_ml_dsa_65 — base64 (standard) ML-DSA-65 signature over
--     the SAME canonical bytes the Ed25519 `signature` covers, bound
--     per the HybridVerifier rule (PQC signs `canonical || classical`).
--     ~4412 chars for the 3309-byte FIPS-204-final sig.
--   * pubkey_ml_dsa_65 — base64 (standard) 1952-byte ML-DSA-65 public
--     key the producer asserts on the trace envelope. The Ed25519
--     pubkey is resolved from `accord_public_keys` by `signing_key_id`;
--     that directory is Ed25519-only, so the PQC pubkey rides the
--     envelope and is bound into the hybrid verify (a forged pubkey
--     fails the signature check — it cannot grant trust by itself).
--   * pqc_key_id — the producer's ML-DSA-65 key identifier (provenance;
--     may differ from the Ed25519 `signing_key_id`).
--
-- NULLABLE — NOT `NOT NULL` — is load-bearing:
--   1. The migration must not break the existing classical rows
--      (pre-#225 + the 12,165-trace legacy corpus).
--   2. The legacy `2.7.legacy` import carve-out (`receive_and_persist_
--      pre_verified` / `VerifyMode::TrustPreVerified`) carries the
--      original 1.9.x Ed25519 sig as PROVENANCE only — already imported
--      pre-verified, not re-verifiable; it stays exempt and writes NULL
--      here.
-- Presence for NEW Full-mode federation writes is enforced by the
-- INGEST GATE (`verify_complete_trace_hybrid`), NOT by a column
-- constraint. The gate is where "reject classical-only at admission"
-- lives; a DB CHECK could not distinguish a legacy/pre-verified row
-- from a Full-mode admission.

ALTER TABLE cirislens.trace_events
    ADD COLUMN IF NOT EXISTS signature_ml_dsa_65 TEXT,
    ADD COLUMN IF NOT EXISTS pubkey_ml_dsa_65    TEXT,
    ADD COLUMN IF NOT EXISTS pqc_key_id          TEXT;

-- Observability: which producer PQC keys are landing hybrid traces.
-- Partial index keeps it cheap (only hybrid rows indexed; the legacy
-- classical-only + carve-out rows stay out of it).
CREATE INDEX IF NOT EXISTS trace_events_pqc_key
    ON cirislens.trace_events (pqc_key_id, ts DESC)
    WHERE signature_ml_dsa_65 IS NOT NULL;
