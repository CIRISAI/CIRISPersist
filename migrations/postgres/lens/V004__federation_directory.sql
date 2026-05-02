-- V004 — Federation directory schema (v0.2.0).
--
-- Three tables: federation_keys, federation_attestations,
-- federation_revocations. See docs/FEDERATION_DIRECTORY.md §"Schema
-- sketch" for the architectural rationale; this migration is the
-- runtime form.
--
-- Mission alignment (MISSION.md §2 — `store/`): the federation
-- directory is the load-bearing substrate that lets the registry,
-- lens, agent, and any future peer share one pubkey + attestation +
-- revocation directory instead of each maintaining their own. Persist
-- is the substrate; consumers compose policy.
--
-- Cross-team coordination: this migration unblocks
-- CIRISRegistry/docs/FEDERATION_CLIENT.md R_BACKFILL. Schema is
-- experimental during v0.2.x/v0.3.x with two-week deprecation notice
-- contract; stabilizes at v0.4.0 (read-path migration).
--
-- THREAT_MODEL.md AV-14: every row in these tables carries a
-- scrub-signature whose scrub_key_id chains via FK to a
-- federation_keys row. The "registry DB compromise → arbitrary trust
-- anchor" attack disappears because consumers walk the FK chain to a
-- root they have anchored out-of-band, not to a row "Postgres said
-- exists."

CREATE SCHEMA IF NOT EXISTS cirislens;

-- ─── federation_keys ───────────────────────────────────────────────
--
-- Every cryptographic identity in the federation has a row here:
-- agents (their trace-signing keys), primitives (their build-signing
-- keys), stewards (registry, persist, lens, agent — the trust roots),
-- partners (per-org commercial onboarding).
--
-- The bootstrap row (persist-steward) is self-signed
-- (scrub_key_id = key_id); every other row chains to it (or to
-- another out-of-band-anchored steward).

CREATE TABLE IF NOT EXISTS cirislens.federation_keys (
    -- Canonical key identifier. Matches signature_key_id on the wire
    -- for trace verification (continuity with accord_public_keys).
    key_id                TEXT PRIMARY KEY,

    -- Pubkey bytes, base64 standard alphabet (matches
    -- accord_public_keys.public_key_base64 shape).
    pubkey_base64         TEXT NOT NULL,

    -- "ed25519" | "ml-dsa-65" | "hybrid"
    -- (Ed25519+ML-DSA-65 separator-encoded). String-typed (not enum)
    -- for forward compat — new algorithms added by either side
    -- without a schema break.
    algorithm             TEXT NOT NULL,

    -- "agent" | "primitive" | "steward" | "partner"
    -- See docs/FEDERATION_DIRECTORY.md §"Schema sketch" for semantics.
    identity_type         TEXT NOT NULL,

    -- Logical identity reference. Shape varies by identity_type:
    --   agent     → agent_id_hash
    --   primitive → primitive name (ciris-persist, ciris-agent, ...)
    --   steward   → steward role (registry, persist, lens, agent)
    --   partner   → org_id
    identity_ref          TEXT NOT NULL,

    -- Validity window. valid_until=NULL means no expiry.
    valid_from            TIMESTAMPTZ NOT NULL,
    valid_until           TIMESTAMPTZ,

    -- The canonical bytes that were signed when this key was
    -- registered. Stored verbatim for forensic reconstruction.
    registration_envelope JSONB NOT NULL,

    -- v0.1.3 scrub envelope four-tuple. Every row carries its own
    -- cryptographic provenance. Bootstrap rows have
    -- scrub_key_id = key_id (self-signed); all others chain to a
    -- key that exists in this table.
    original_content_hash BYTEA NOT NULL,
    scrub_signature       BYTEA NOT NULL,
    scrub_key_id          TEXT NOT NULL,
    scrub_timestamp       TIMESTAMPTZ NOT NULL,

    -- v0.2.0: server-computed canonical hash, hex-encoded. Returned
    -- on read responses so consumers (per FEDERATION_CLIENT.md
    -- §"Cache shape" persist_row_hash column) can detect cache
    -- divergence by string-comparing without reproducing persist's
    -- canonicalizer. Computed via the PythonJsonDumpsCanonicalizer
    -- shape (sorted keys, no whitespace, ensure_ascii=True) over the
    -- row's user-visible fields. Closes CIRISPersist#7-class
    -- shortest-round-trip drift for the federation read path.
    persist_row_hash      TEXT NOT NULL,

    -- The FK we'd write is (scrub_key_id) REFERENCES
    -- federation_keys(key_id), but Postgres rejects forward-references
    -- on the bootstrap row (it references itself before the row is
    -- inserted). Solve: make the FK DEFERRABLE INITIALLY DEFERRED so
    -- the constraint check happens at COMMIT, not row insert. Bootstrap
    -- row INSERTs successfully because scrub_key_id will exist by
    -- transaction commit time.
    CONSTRAINT scrub_key_must_exist
        FOREIGN KEY (scrub_key_id)
        REFERENCES cirislens.federation_keys(key_id)
        DEFERRABLE INITIALLY DEFERRED
);

-- Lookup-by-identity index. Consumers querying "all keys for this
-- agent" / "all primitive keys" hit this index instead of scanning
-- the table. Composite (identity_type, identity_ref) so the common
-- "all primitives" / "all stewards" prefix queries also use it.
CREATE INDEX IF NOT EXISTS federation_keys_identity
    ON cirislens.federation_keys (identity_type, identity_ref);

-- The scrub_key_id index supports walk-the-trust-chain queries —
-- "which keys did THIS steward sign?" — without a sequential scan.
CREATE INDEX IF NOT EXISTS federation_keys_scrub_key
    ON cirislens.federation_keys (scrub_key_id);

-- ─── federation_attestations ───────────────────────────────────────
--
-- "Key A vouches for / witnesses / refers / delegates-to key B at
-- time T with optional weight W". Many-to-many between keys, every
-- row signed by the attester. Consumers compose trust policy by
-- walking this graph.

CREATE TABLE IF NOT EXISTS cirislens.federation_attestations (
    attestation_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Both ends of the attestation reference federation_keys.
    attesting_key_id      TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),
    attested_key_id       TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),

    -- "vouches_for" | "witnesses" | "referred" | "delegated_to"
    -- String-typed for forward compat (consumers may invent new
    -- types as trust models evolve).
    attestation_type      TEXT NOT NULL,

    -- Attesters carry their own weight signal. NULL = consumer
    -- decides default weight per its policy.
    weight                NUMERIC,

    -- When the attestation was made; when it expires (NULL = no
    -- expiry).
    asserted_at           TIMESTAMPTZ NOT NULL,
    expires_at            TIMESTAMPTZ,

    -- Canonical bytes of the attestation. Used for the join key
    -- between persist's journal and registry's audit_log
    -- (FEDERATION_CLIENT.md §"Audit-log").
    attestation_envelope  JSONB NOT NULL,

    -- v0.1.3 scrub envelope (every row carries provenance).
    original_content_hash BYTEA NOT NULL,
    scrub_signature       BYTEA NOT NULL,
    scrub_key_id          TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),
    scrub_timestamp       TIMESTAMPTZ NOT NULL,

    -- v0.2.0: server-computed canonical hash (see federation_keys).
    persist_row_hash      TEXT NOT NULL
);

-- Read patterns: "all attestations targeting key K" (consumer asks
-- "who vouches for K?"), "all attestations from key K" (consumer
-- asks "which keys does K vouch for?"). Two indexes match those.
CREATE INDEX IF NOT EXISTS federation_attestations_attested
    ON cirislens.federation_attestations (attested_key_id, asserted_at DESC);
CREATE INDEX IF NOT EXISTS federation_attestations_attesting
    ON cirislens.federation_attestations (attesting_key_id, asserted_at DESC);

-- ─── federation_revocations ────────────────────────────────────────
--
-- Append-only revocation log. "Key A revokes key B at time T for
-- reason R, effective at time E". Consumers compute "is K revoked
-- now?" by querying for revocations of K with effective_at <= now()
-- and applying their own consensus policy (e.g., "any unrevoked
-- steward attestation to revoke" / "score-weighted majority").

CREATE TABLE IF NOT EXISTS cirislens.federation_revocations (
    revocation_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    revoked_key_id        TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),
    revoking_key_id       TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),

    -- Free-form. Consumers parse if they care; persist just stores.
    reason                TEXT,

    -- When the revocation was issued vs when it takes effect.
    -- effective_at may be in the past (retroactive) or future
    -- (scheduled).
    revoked_at            TIMESTAMPTZ NOT NULL,
    effective_at          TIMESTAMPTZ NOT NULL,

    revocation_envelope   JSONB NOT NULL,

    -- v0.1.3 scrub envelope.
    original_content_hash BYTEA NOT NULL,
    scrub_signature       BYTEA NOT NULL,
    scrub_key_id          TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),
    scrub_timestamp       TIMESTAMPTZ NOT NULL,

    persist_row_hash      TEXT NOT NULL
);

-- Read pattern: "is K revoked at time T?" walks revocations for K
-- ordered by effective_at.
CREATE INDEX IF NOT EXISTS federation_revocations_revoked
    ON cirislens.federation_revocations (revoked_key_id, effective_at DESC);
