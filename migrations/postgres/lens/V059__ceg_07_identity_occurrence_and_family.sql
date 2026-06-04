-- V059 — CEG 0.7 §5.6.8.8 + §5.6.8.9 identity_occurrence + family
--        substrate tables (CIRISPersist#153 Asks 1-2, v3.12.0).
--
-- Closes the Front-A foundation: the structural primitives that
-- distinguish "participants that ARE me" (identity_occurrence — the
-- user's devices/agents) from "trusted nodes that compose with me"
-- (family — other people's identities + shared household devices).
--
-- The cewp structural-invisibility claim ("self/family content
-- can't carry on the wire in the first place") becomes
-- substrate-enforceable once these tables exist: the at-rest DEK
-- cascade (CIRISPersist#152, gated on these tables) wraps content
-- keys to all currently-admitted occurrences + family members
-- when content lands at cohort_scope: self | family.
--
-- This cut lands the **schema foundation + value-validation
-- admission**. The trust-graph admission gates (self-vouch /
-- single-vouch admission per §5.6.8.8; consensus_protocol signature
-- counting per §5.6.8.9; consensus_protocol_entrenched amendment
-- rejection; retroactive key_grant emission on member-add) need the
-- new tables to exist before they can compose against them, so
-- they're separated into the v3.13+ cut for #153 Ask 3 + #146 Ask 2.

-- ─── §5.6.8.8 federation_identity_occurrences ──────────────────────
--
-- One row per (identity_key_id, occurrence_key_id) binding. An
-- identity may admit unbounded occurrences; the substrate carries no
-- hard cap. `device_class` is the closed-set CHECK matching the spec
-- table; `hardware_attestation` is opaque base64 (TPM / Secure
-- Enclave / StrongBox / SGX blob — consumer-side parsed).
--
-- (identity_key_id, occurrence_key_id) is the primary key — duplicate
-- bindings are idempotent. A withdraws against the row (issued by
-- identity_key_id OR any current occurrence) evicts via the existing
-- federation_revocations table; no new revocation surface required.

CREATE TABLE IF NOT EXISTS cirislens.federation_identity_occurrences (
    identity_key_id       TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),
    occurrence_key_id     TEXT NOT NULL
        REFERENCES cirislens.federation_keys(key_id),

    -- Closed-set per §5.6.8.8 DeviceClass table.
    device_class          TEXT NOT NULL
        CHECK (device_class IN ('phone', 'laptop', 'server', 'embedded',
                                 'agent', 'service')),

    -- Opaque attestation blob (TPM / Secure Enclave / StrongBox / SGX
    -- / etc.). NULL for software-only occurrences.
    hardware_attestation  TEXT,

    -- §0.5 canonical timestamps.
    asserted_at           TIMESTAMPTZ NOT NULL,
    valid_until           TIMESTAMPTZ,

    persist_row_hash      TEXT NOT NULL,

    PRIMARY KEY (identity_key_id, occurrence_key_id)
);

-- Forward lookup: "which occurrences belong to this identity?" (the
-- DEK-cascade fan-out path).
CREATE INDEX IF NOT EXISTS federation_identity_occurrences_by_identity
    ON cirislens.federation_identity_occurrences (identity_key_id);

-- Reverse lookup: "which identity does this occurrence speak for?"
-- (the consumer's "is this key co-self with X?" check). Postgres
-- partial-index predicates MUST only reference IMMUTABLE functions —
-- `NOW()` is STABLE not IMMUTABLE, so the index definition with
-- `OR valid_until > NOW()` was rejected (sqlstate 42P17). The
-- partial covers the common case (indefinite occurrence) and the
-- companion all-rows index below handles expired-row lookups —
-- matching the sqlite V059 shape exactly.
CREATE INDEX IF NOT EXISTS federation_identity_occurrences_by_occurrence_live
    ON cirislens.federation_identity_occurrences (occurrence_key_id)
    WHERE valid_until IS NULL;

CREATE INDEX IF NOT EXISTS federation_identity_occurrences_by_occurrence_all
    ON cirislens.federation_identity_occurrences (occurrence_key_id);

-- ─── §5.6.8.9 federation_families ──────────────────────────────────
--
-- One row per family_key_id. Membership lives in JSONB (the spec
-- shape is a list of {key_id, joined_at, role}); persist stores
-- atomically as a JSON array so the consensus-protocol gate (v3.13+)
-- reads the whole roster + the proposed amendment in one row.
--
-- `consensus_protocol` is OPEN vocabulary per the spec
-- (founder_only / unanimous / majority / quorum:m/n / weighted:rubric
-- / custom:id) — the substrate's value-validation gate
-- (check_consensus_protocol_form, v3.12.0) verifies the string parses
-- into one of the canonical shapes; full signature-counting against
-- the protocol is the v3.13+ admission gate.
--
-- `consensus_protocol_entrenched` is the structural lock that
-- prevents in-protocol amendment of the protocol itself — the
-- HUMANITY_ACCORD canonical instance per §9.

CREATE TABLE IF NOT EXISTS cirislens.federation_families (
    family_key_id                   TEXT PRIMARY KEY
        REFERENCES cirislens.federation_keys(key_id),

    -- Human-readable; non-unique (spec: "Acme Household").
    family_name                     TEXT NOT NULL,

    -- JSONB array of {key_id, joined_at, role?}. Each member entry is
    -- an IDENTITY key (NOT an occurrence key) per the §5.6.8.9
    -- example. Substrate stores the entire roster; the consensus
    -- protocol gate reads it for signature counting.
    members                         JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(members) = 'array'),

    founded_at                      TIMESTAMPTZ NOT NULL,

    -- Open vocab; canonical kinds: founder_only | unanimous | majority
    -- | quorum:m/n | weighted:rubric | custom:id. Substrate's
    -- value-validation gate at v3.12.0 (`check_consensus_protocol_form`)
    -- verifies the string parses; full signature-count enforcement
    -- is the v3.13+ admission gate.
    consensus_protocol              TEXT NOT NULL,

    -- Structural lock: if true, consensus_protocol may NOT be amended
    -- in-protocol. Replacement requires an out-of-band ceremony.
    -- HUMANITY_ACCORD per §9 is the canonical entrenched instance.
    consensus_protocol_entrenched   BOOLEAN NOT NULL DEFAULT FALSE,

    persist_row_hash                TEXT NOT NULL
);

-- Membership lookup: "which families is identity X a member of?"
-- (the DEK-cascade fan-out + the membership-change ceremony's
-- "where else does this change need to propagate?" walk). Functional
-- partial index over the JSONB members array using a GIN expression
-- index — Postgres can match `members @> '[{"key_id": "X"}]'` against
-- this for O(log N).
CREATE INDEX IF NOT EXISTS federation_families_members_gin
    ON cirislens.federation_families USING GIN (members jsonb_path_ops);

-- Entrenched-protocol partial index: "which families are entrenched?"
-- (the §9 HUMANITY_ACCORD-style lookup). Tiny set in practice.
CREATE INDEX IF NOT EXISTS federation_families_entrenched
    ON cirislens.federation_families (family_key_id)
    WHERE consensus_protocol_entrenched = TRUE;
