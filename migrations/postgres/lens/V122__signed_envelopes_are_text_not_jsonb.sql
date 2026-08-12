-- V122 — v30.13.0 (CIRISPersist#645): **the signature-covered envelope columns
--        become TEXT, because JSONB is not a byte-preserving container.**
--        Postgres dialect. SQLite needs NO twin: every column named here has
--        been TEXT on SQLite since the day it was created, which is exactly
--        how the divergence went unnoticed — the SQLite leg was always right.
--
-- ── THE RULE, ALREADY WRITTEN DOWN IN THIS REPO ────────────────────────────
-- V105 (transport_destinations, v17.0.0) states it plainly:
--
--     "TEXT (not JSONB) for signed_envelope/signature: the envelope must
--      round-trip BYTE-EXACT for re-publish, and JSONB does not preserve the
--      producer's serialization."
--
-- V112 (freshness_floor) followed it. The eleven columns below predate it and
-- did not. This migration retrofits them.
--
-- ── WHAT WAS MEASURED (not inferred) ──────────────────────────────────────
-- A signed KeyRecord carrying awkward-but-legal JSON was written through the
-- REAL `put_public_key` path and read back through the REAL
-- `lookup_public_key` path on Postgres 16. Submitted vs reloaded:
--
--     submitted: {...,"exp":1e+2,...,"neg":1.5e-3,...}
--     reloaded:  {...,"exp":100,...,"neg":0.0015,...}
--
--     wire_index::content_hash_of(submitted) = bf61b57c4f20e19f…
--     wire_index::content_hash_of(reloaded)  = a6b819b30655da60…
--
-- The content hash CHANGED. That is not a hypothetical: `content_hash_of` is
-- `sha256(serde_json::to_vec(record))` with NO canonicalization step
-- (`src/federation/wire_index.rs`) — it is deliberately the exact bytes the
-- read surface returns, so that persist's hash equals CIRISEdge's by
-- construction. A container that rewrites those bytes breaks that identity:
-- persist advertises `content_hash = H`, a peer fetches by `H`, and the
-- reloaded record no longer hashes to `H`.
--
-- The failing axis is NUMERIC LITERALS. `jsonb` parses numbers into `numeric`,
-- which discards exponent notation (`1e+2` → `100`, `1.5e-3` → `0.0015`).
-- `serde_json` is built here with `arbitrary_precision`, so a Rust-side
-- `Value` PRESERVES the producer's number token verbatim — the TEXT/SQLite leg
-- round-trips these unchanged, and only the JSONB/Postgres leg mangles them.
-- This is a live path, not a corner: Python's `json.dumps` emits `1e-05` for
-- small floats and JavaScript's `JSON.stringify` emits `1.5e-6`, and the
-- producers upstream of these envelopes are Python and JS.
--
-- Axes that were tested and did NOT diverge, recorded so the next reader does
-- not re-litigate them: key ORDER (serde_json's `Map` is a `BTreeMap` here —
-- no `preserve_order` — so both legs re-sort on parse and the container's
-- ordering is invisible), duplicate keys (last-wins on both), `1.0` / `1.000`
-- trailing zeros (`numeric` keeps scale), integers wider than i64/f64,
-- non-ASCII, and escaped solidus.
--
-- ── WHAT THIS MIGRATION CANNOT DO ─────────────────────────────────────────
-- **It cannot recover the producer's bytes for any row already stored.** They
-- were destroyed on the way IN, by the `jsonb` parse, before this column type
-- ever existed; there is no copy of them anywhere in this database. What
-- `USING <col>::text` writes is `jsonb`'s OWN rendering of what it kept —
-- normalized numbers, `jsonb` key order, a space after every `:` and `,`.
--
-- The two halves of that, stated separately because only one is a loss:
--
--   * NUMBER TOKENS — permanently lost for pre-V122 rows. A row whose envelope
--     contained `1e-5` reads back, and will forever read back, as `0.00001`.
--     If such a row's advertised content hash was computed from the producer's
--     bytes, it stays wrong; the remedy is a re-publish from the producer, not
--     a migration. Rows whose envelopes contain no exponent-form number — the
--     overwhelming majority, since most envelopes are all-string — are
--     unaffected and were never damaged.
--
--   * SPACING AND KEY ORDER — NOT a loss. Every read path parses this column
--     with `serde_json::from_str` into a `Value` before it reaches anything
--     that hashes or compares it, and that parse normalizes both. Legacy rows
--     therefore yield the identical `Value`, hence the identical content hash,
--     as rows written after this migration.
--
-- Forward-only, per this repo's refinery discipline: no down migration, and
-- this file is checksum-immutable once shipped.
--
-- ── BACKEND PARITY, THE POINT OF THE EXERCISE ─────────────────────────────
-- After this cut both backends store `serde_json::to_string(&Value)` in a TEXT
-- column and read it back with `serde_json::from_str`. Identical input now
-- produces identical stored bytes on Postgres and SQLite, which is the
-- property the round-trip witness asserts (shared body, both legs).

-- ── 1. federation_keys.registration_envelope (V004:128) ───────────────────
ALTER TABLE cirislens.federation_keys
    ALTER COLUMN registration_envelope TYPE TEXT
        USING registration_envelope::text;

COMMENT ON COLUMN cirislens.federation_keys.registration_envelope IS
    'v30.13.0 (CIRISPersist#645) — TEXT, not JSONB: the exact bytes the '
    'producer signed. See V122 for the measurement and for what pre-V122 rows '
    'lost. SQLite parity: TEXT since V004.';

-- ── 2. federation_attestations.attestation_envelope (V004:223) ────────────
-- This column has DEPENDENTS, so the type change is a four-step dance:
--   * V106's `dimension` — a STORED generated column. Postgres refuses
--     `ALTER COLUMN … TYPE` on a column a generated column reads, so it is
--     dropped and re-added. Dropping it loses nothing: it is derived, and the
--     re-add recomputes every row. The denormalized COPY in
--     `attestation_subjects.dimension` is an ordinary column and is untouched.
--   * V106's GIN on `attestation_envelope->'evidence_refs'` and V107's
--     composer expression index — both re-created over `::jsonb` casts. The
--     text→jsonb cast is IMMUTABLE, which is what makes both a generated
--     column and an expression index legal over it (verified against
--     Postgres 16 before this migration was written, not assumed).
--
-- Re-adding `dimension` moves it to the end of the column list. Nothing reads
-- this table positionally — every row decoder here is by column NAME — so the
-- reorder is invisible. Stated because a `SELECT *` bound by position would
-- have made it a silent wrong answer.
DROP INDEX IF EXISTS cirislens.federation_attestations_evidence_refs_gin;
DROP INDEX IF EXISTS cirislens.federation_attestations_composer_ref;

ALTER TABLE cirislens.federation_attestations
    DROP COLUMN IF EXISTS dimension;

ALTER TABLE cirislens.federation_attestations
    ALTER COLUMN attestation_envelope TYPE TEXT
        USING attestation_envelope::text;

ALTER TABLE cirislens.federation_attestations
    ADD COLUMN dimension TEXT
        GENERATED ALWAYS AS ((attestation_envelope::jsonb)->>'dimension') STORED;

CREATE INDEX federation_attestations_evidence_refs_gin
    ON cirislens.federation_attestations
    USING GIN (((attestation_envelope::jsonb)->'evidence_refs'));

CREATE INDEX IF NOT EXISTS federation_attestations_composer_ref
    ON cirislens.federation_attestations (
        attesting_key_id,
        attestation_type,
        ((attestation_envelope::jsonb)->>'references_attestation_id')
    );

COMMENT ON COLUMN cirislens.federation_attestations.attestation_envelope IS
    'v30.13.0 (CIRISPersist#645) — TEXT, not JSONB. Query sites that need to '
    'reach inside cast explicitly (attestation_envelope::jsonb->>…); the cast '
    'is immutable and the two expression indexes above are built over it. '
    'SQLite parity: TEXT since V004.';

-- ── 3. federation_revocations.revocation_envelope (V004:272) ──────────────
-- NOT in the original audit's list of seven; found by reading V004 rather than
-- the citation. Same table family, same defect, same fix.
ALTER TABLE cirislens.federation_revocations
    ALTER COLUMN revocation_envelope TYPE TEXT
        USING revocation_envelope::text;

COMMENT ON COLUMN cirislens.federation_revocations.revocation_envelope IS
    'v30.13.0 (CIRISPersist#645) — TEXT, not JSONB. V118 reads `revoked_after` '
    'out of this envelope; it is the SIGNED bound, so byte fidelity is load-'
    'bearing. SQLite parity: TEXT since V004.';

-- ── 4. the operational trio (V071:52 / :81 / :126) ────────────────────────
ALTER TABLE cirislens.federation_organizations
    ALTER COLUMN signed_envelope TYPE TEXT
        USING signed_envelope::text;

ALTER TABLE cirislens.federation_org_memberships
    ALTER COLUMN signed_envelope TYPE TEXT
        USING signed_envelope::text;

ALTER TABLE cirislens.federation_partner_records
    ALTER COLUMN signed_envelope TYPE TEXT
        USING signed_envelope::text;

-- ── 5. federation_identity_occurrences (V102:11, :12, :13) ────────────────
-- The audit cited only `signed_envelope`. `signature` and `transport_binding`
-- sit in the SAME `SignedIdentityOccurrence` that `content_hash_of` hashes, so
-- a JSONB rewrite of either moves the same hash. Migrating one of three would
-- have left the plane defective and looking fixed.
ALTER TABLE cirislens.federation_identity_occurrences
    ALTER COLUMN signed_envelope TYPE TEXT
        USING signed_envelope::text;

ALTER TABLE cirislens.federation_identity_occurrences
    ALTER COLUMN signature TYPE TEXT
        USING signature::text;

ALTER TABLE cirislens.federation_identity_occurrences
    ALTER COLUMN transport_binding TYPE TEXT
        USING transport_binding::text;

-- ── 6. federation_identity_occurrence_revocations (V103:10, :11) ──────────
ALTER TABLE cirislens.federation_identity_occurrence_revocations
    ALTER COLUMN signed_envelope TYPE TEXT
        USING signed_envelope::text;

ALTER TABLE cirislens.federation_identity_occurrence_revocations
    ALTER COLUMN signature TYPE TEXT
        USING signature::text;
