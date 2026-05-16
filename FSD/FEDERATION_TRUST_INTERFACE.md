# FSD: Federation Trust Interface — purpose-scoped trust grants as signed events

**Status:** Design (draft v1) — kickoff for CIRISPersist v1.5.0.
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.7
**Created:** 2026-05-16
**Risk:** Architectural. Replaces the v1.3.0 trust-column shape on
`federation_keys` with a purpose-scoped grant table backed by signed
audit-chain events. Decentralizes the trust-write surface: any
participant's local directory can emit grants; Registry is no longer
the only authority.

**Cross-coordinates with:**
- **CIRISVerify** — [#23](https://github.com/CIRISAI/CIRISVerify/issues/23) — SOTA upgrade to `ciris-verify-core::transparency` (RFC 6962 + STH + ConsistencyProof + generic `TransparencyLeaf` + `TransparencyStore` abstraction + per-`log_id` scoping). v1.5.0 pins to whichever minor ships this; persist consumes the upgraded primitives as the canonical transparency-log substrate. **Verify is the wellspring; persist consumes; edge consumes** — no parallel Merkle implementations.
- **CIRISNodeCore** — Accord §RC `subject_kind` extension for
  `TrustGrant` (LANDED in [`871ebab`](https://github.com/CIRISAI/CIRISNodeCore/commit/871ebab)); downstream rewire of `crate::trust::resolve_trust` to
  read the new table.
- **CIRISLensCore** — sign-emit path for grants issued by lens-tier
  operators; `verify_hybrid_via_directory` becomes verify-and-check-grant against STH+inclusion-proof.
- **CIRISPortal** — UI surface for human-issued grants (later cut).
- **CIRISPersist#47 / FSD `V020`** — V020 columns (`trust_type`,
  `trust_relationship`, `trust_domains`, `trusted_by`, `trusted_at`,
  `expires_at`) become a transitional shape; this FSD's V021 migration
  decomposes them into the new grant table.

---

## 1. Why this exists

### 1.1 The "everything is an agent" collapse

Post-3.0, every participant in CIRIS is an agent. Identity-type tags
like `agent`, `edge`, `registry`, `steward` collapse: they either
restate the substrate (`agent` is meaningless when everyone is one) or
encode a *role property* the directory's graph topology already
recovers (the steward is whoever signed the first grant in a fresh
directory; no tag needed).

The directory's role-axis becomes a functional triad:

- **`client`** — consumes federation services
- **`proxy`** — relays / brokers / forwards messages and credentials
- **`server`** — provides authoritative services

These are non-exclusive (`roles: ["client", "server"]` is fine). The
existing V020 `roles[]` column carries this list unchanged; only the
strings inside it change.

### 1.1a Trust domain (SPIFFE-aligned)

A **trust domain** is the set of grants a directory has materialized
plus the identities those grants reference. It is the unit of
federation handshake: when two directories peer, they exchange
TrustGrant events to bring each other's trust state into view.
Naming the concept explicitly (matching SPIFFE/SPIRE's usage)
gives the forthcoming gossip FSD a clean boundary object to talk
about; the concept is implicit in this FSD's schema and made
explicit here only as vocabulary.

### 1.1b Why not DIDs / Verifiable Credentials

The W3C VC ecosystem is the obvious industry alternative: a
TrustGrant would be a VerifiableCredential issued by the granter about
the grantee. CIRIS deliberately does not adopt this layer. As of 2026
the DID/VC space is still pre-convergence — 100+ DID methods, no
agreed-upon resolver behavior, persistent interop friction, and an
ecosystem timeline measured in "decade away from ubiquity." More
fundamentally: the hybrid pubkey (Ed25519 + ML-DSA-65) **is already**
the identifier; introducing a `did:` URI scheme on top is layering
indirection over a primitive that doesn't need it. The cryptographic
properties DIDs provide (self-sovereignty, key rotation, signed
claims) are intrinsic to the hybrid-pubkey + audit-chain composition.
CIRIS keeps the cryptography, skips the URI/registry layer.

### 1.2 Trust is purpose-scoped, not flat

A human (or any agent acting in stewarding capacity) trusts other
agents *for specific purposes*. The v1.3.0 trust columns collapse this
to one Boolean-ish axis (`trust_relationship` Direct vs Registry, plus
a flat `trust_domains` list). That's not expressive enough to support
"I trust this server for manifest verification but not for deferral
resolution," which is exactly the dial the 3.0 decentralization model
needs.

Three purposes, each with a purpose-specific scope shape:

| Purpose | Scope shape | Example |
|---|---|---|
| **Technical** | manifest_id / artifact_id / build_channel | "trust K to attest manifests on `stable`" |
| **Deferral** | domain name (the existing V020 `trust_domains` semantics) | "trust K to resolve deferrals in `medical_deferral`" |
| **Contribution** | contribution_kind / proposal_subject_kind | "trust K to issue `registry_vouch` contributions" |

A grant pins (key, purpose, scope). One key can hold N grants from N
granters across M purposes.

### 1.3 Grants are signed federation events, not CRUD calls

A `grant_trust(...)` API that writes directly to the table couples the
trust surface to one host's clock and one host's authority. For
decentralization to work, the same grant must be ingestible by any
peer's local directory and replayable on the audit chain. Therefore:

> A trust grant is a signed Contribution event of kind `TrustGrant`.
> The receiving directory materializes a row in
> `federation_trust_grants` when (and only when) the corresponding
> event has landed in the audit chain.

This makes the audit chain the source of truth for grants. The
directory table is a materialized projection — rebuildable from the
chain at any time. Gossip protocols (forthcoming) carry grants between
directories the same way they carry any other contribution.

---

## 2. Schema

### 2.1 V021 migration — Postgres

```sql
CREATE TABLE federation_trust_grants (
    grant_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    grantee_key        TEXT NOT NULL REFERENCES federation_keys(key),
    granter_key        TEXT NOT NULL REFERENCES federation_keys(key),
    purpose            TEXT NOT NULL
                       CHECK (purpose IN ('technical','deferral','contribution')),
    scope              TEXT NOT NULL,        -- purpose-specific opaque string
    granted_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    revoked_by         TEXT REFERENCES federation_keys(key),
    chain_event_id     BIGINT NOT NULL REFERENCES cirisaudit_events(event_id),
    chain_event_hash   BYTEA NOT NULL,
    CHECK (granter_key != grantee_key),
    CHECK (revoked_at IS NULL OR revoked_by IS NOT NULL),
    UNIQUE (grantee_key, granter_key, purpose, scope)
);

CREATE INDEX idx_ftg_grantee_purpose ON federation_trust_grants
    (grantee_key, purpose, scope) WHERE revoked_at IS NULL;
CREATE INDEX idx_ftg_granter ON federation_trust_grants (granter_key);
CREATE INDEX idx_ftg_chain ON federation_trust_grants (chain_event_id);
```

### 2.2 V021 migration — SQLite

Same shape, BLOB hashes, no `gen_random_uuid()` (caller supplies UUID),
no `TEXT[]` (none used here — scope is a single TEXT per row, by
design). The grant table is dialect-clean in a way V020's trust
columns weren't.

### 2.3 v1.3.0 trust-column deprecation

V020 columns (`trust_type`, `trust_relationship`, `trust_domains`,
`trusted_by`, `trusted_at`, `expires_at`) remain on `federation_keys`
through v1.5.x as a read-only compatibility shim. V022 (cut in v1.6.0)
drops them after one full minor of co-existence.

A V021 backfill emits synthetic `TrustGrant` events for every existing
v1.3.0 trust row:

| v1.3.0 row | Synthetic events emitted |
|---|---|
| `trust_relationship='direct'` (any `trust_type`) | one `TrustGrant` with `purpose='deferral', scope='*'` (legacy wildcard) |
| `trust_relationship='registry'`, `trust_domains=[d1, d2]` | N events: one `(purpose='deferral', scope=d1)`, one `(purpose='deferral', scope=d2)` |

The backfill is one-shot; subsequent grants flow only via the event
path. Backfill events are signed by the legacy `trusted_by` key as
recovered from the V020 column.

---

## 3. Event shape — `TrustGrant` as §RC `subject_kind`

### 3.1 Encoding

Same pattern as `registry_vouch` (Accord §3.2): encoded as
`contribution_type=proposal` with `subject.subject_kind="trust_grant"`.
No new top-level `ContributionType` variant. No coordinated release
across all federation consumers — persist accepts the envelope today
unchanged.

```
contribution_type = proposal
subject.{domain, language, subject_kind = "trust_grant"}
author_id = granter_key
payload = TrustGrantPayload
signature = HybridSignature       // per CIRISNodeCore SCHEMA §2.4
witness_set = Option<WitnessSet>  // per CIRISNodeCore SCHEMA §3.5
```

**Envelope and signature shapes are NOT redefined here.** The
TrustGrant Contribution uses the canonical NodeCore envelope (SCHEMA
§2.4) with `ciris_crypto::HybridSignature` (Ed25519 + ML-DSA-65) as
the author signature. Verification flows through `ciris-verify-core`
unchanged — this FSD adds no crypto surface. Multi-signer consensus
flows through the existing `witness_set` primitive (§3.5 below);
nothing in this FSD reinvents that machinery.

### 3.2 Payload

```rust
pub struct TrustGrantPayload {
    pub grantee_key: String,        // base64 hybrid pubkey
    pub purpose: TrustPurpose,      // Technical | Deferral | Contribution | Service
    pub scope: String,              // purpose-specific (see §3.3)
    pub expires_at: Option<DateTime<Utc>>,
    pub rationale: String,          // free-form, why this grant
}

pub enum TrustPurpose {
    Technical,    // manifest / build / artifact attestation
    Deferral,     // domain-scoped resolver routing
    Contribution, // authorship + voting on chain events
    Service,      // access to advertised peer services (LLM/embedding/tool RPC)
}
```

The `Service` variant gates per-pubkey-addressable peer service
offerings (LLM, embedding, tool) advertised via NodeCore's
`service_announcement` / `service_deprecation` / `service_usage_summary`
Contributions per MESSAGE_TAXONOMY §5/§6.1. Per-invocation RPC rides
edge transport (out of scope here per MESSAGE_TAXONOMY §8); the chain
records announcement + aggregated usage summaries, and the trust grant
gates whether a caller is authorized to invoke the service at all.

The granter is `author_id` (envelope-level). The author's
`HybridSignature` covers the canonical envelope per NodeCore SCHEMA
§2.4. Activation rules (whether the grant requires witnesses) are
§3.5.

### 3.3 Scope by purpose

Scope is an opaque string at the schema layer, but each purpose pins
its shape so consumers can parse. In Cedar policy-engine vocabulary,
the three-tuple of a trust check is `(principal=granter, action=purpose,
resource=scope)` — kept here as a parenthetical for readers with
RBAC/ABAC/ReBAC context.

| Purpose | Scope grammar | Wildcard | Notes |
|---|---|---|---|
| Technical | `manifest:<id>` \| `channel:<name>` \| `artifact:<hash>` | `manifest:*` etc. | Matches CIRISRegistry's manifest IDs |
| Deferral | `<domain>` (free-form lowercase identifier) | `*` | Identical to V020 `trust_domains` entries |
| Contribution | `<contribution_type>` \| `<contribution_type>:<subject_kind>` \| `vote:<contribution_type>:<subject_kind>` | `*` | See enumeration below |
| Service | `service:<kind>` \| `service:<kind>:<resource>` | `*` (high-stakes — witness-set-gated per §3.5) | Authorizes invocation of advertised peer services; resource axis distinguishes specific offerings within a kind |

**Contribution scopes** must align with the NodeCore SCHEMA §3.1
`contribution_type` enum and §3.2 `subject_kind` taxonomy. The grants
issued in the wild SHOULD use canonical strings only:

| Scope string | Maps to | Notes |
|---|---|---|
| `deferral_request` | §3.1 | Routing requests to qualified WAs |
| `deferral_response` | §3.1 | Routed WA's signed response |
| `wa_candidacy` | §3.1 | WA standing self/peer-nominations |
| `expertise_attestation` | §3.1 | Attestation of another contributor's expertise |
| `moderation_event` | §3.1 | Accusation of rogue action |
| `reconsideration_request` | §3.1 | Signed reversal request |
| `proposal:arc_question` | §3.2 §4.1 | Single safety-battery question |
| `proposal:proposed_battery` | §3.2 §4.2 | Whole battery |
| `proposal:prompt_edit` | §3.2 | Edit to canonical prompts |
| `proposal:guide_edit` | §3.2 | Edit to Comprehensive Guide |
| `proposal:accord_edit` | §3.2 | Edit to ACCORD body |
| `proposal:failure_pattern` | §3.2 | Failure-pattern ticket |
| `proposal:registry_vouch` | §3.2 | Registry vouching (FSD/TRUST_HIERARCHY) |
| `proposal:trust_grant` | (this FSD) | The TrustGrant itself — meta-trust |
| `proposal:test_result` | (NEW — needs SCHEMA addition) | Result of running a battery/question against an agent |
| `proposal:improvement` | (NEW — needs SCHEMA addition) | Substrate or content improvement proposals |
| `proposal:gratitude_signal` | (NEW — needs SCHEMA addition; PoB §5.6) | Peer-to-peer credit; acceptance policy hangs on Contribution-purpose trust grants |
| `vote:<any-of-above>` | (votes themselves, per MISSION Primitive 2) | Vote on any votable Contribution |

**All Contribution types must be votable.** The `vote:` prefix
expresses "trust K to cast votes on contributions of this kind/scope"
distinctly from "trust K to author them." A grant of
`proposal:arc_question` authorizes authoring questions; a grant of
`vote:proposal:arc_question` authorizes voting on them. Operators
typically grant both; gating them separately is the seam that lets
policy distinguish proposers from ratifiers.

The three new `subject_kind`s (`test_result`, `improvement`,
`gratitude_signal`) were proposed as upstream blockers in an earlier
draft; **NodeCore §RC landed those plus 12 additional subject_kinds**
in [`871ebab`](https://github.com/CIRISAI/CIRISNodeCore/commit/871ebab)
via the MESSAGE_TAXONOMY FSD. All 15 are now wire-ready.

**Service scopes** are canonical strings under `Service` purpose:

| Scope string | Authorizes |
|---|---|
| `service:llm` | All LLM service offerings |
| `service:llm:<model_id>` | Specific LLM (e.g. `service:llm:claude-opus-4-7`) |
| `service:embedding` | All embedding services |
| `service:embedding:<model_id>` | Specific embedding model |
| `service:tool:<tool_name>` | Specific tool RPC |
| `*` | Wildcard — all services (witness-set-gated per §3.5) |

The `<kind>` axis is open-ended at the schema layer (callers and
service providers agree on canonical kinds per MESSAGE_TAXONOMY §6.1);
the `<resource>` axis distinguishes offerings within a kind. The trust
grant gates whether the grantee may invoke; per-invocation RPC
authorization rides edge transport (CIRISEdge `ServiceRequest` /
`ServiceResponse` `MessageType` — separate issue, non-blocking for
v1.5.0).

Wildcard semantics: a grant with `scope='*'` matches all scopes within
its purpose. Wildcards are a strict trust elevation; consumers should
require explicit operator confirmation before issuing one.

### 3.4 Revocation

Author-only, per the §3.2 `registry_vouch` precedent. The granter
emits a new `TrustGrant` event with the same `(grantee, purpose,
scope)` and `expires_at = now()`. The directory's projection updates
`revoked_at` on the matching row.

Counter-revocations are not supported. Bad-faith grants flow through
the `moderation_event` / `slashing_attestation` path (existing
primitives).

### 3.5 Multi-signer grants via `witness_set`

The CIRIS Accord requires consensus for high-stakes trust changes; a
single-signer grant is insufficient when the grant carries enough
weight to perturb the federation's trust topology. TrustGrant events
ride the existing `witness_set` primitive (NodeCore SCHEMA §3.5) for
this:

- The granter signs the envelope (author signature).
- If the grant exceeds the policy-tunable threshold for its
  `(purpose, scope)` — e.g. a `Technical` grant on `manifest:*`, or
  any wildcard grant, or a `Contribution` grant on `vote:*` — the
  envelope MUST carry a `witness_set` with N qualifying witness
  signatures.
- The directory ingest hook activates the grant row only when the
  witness_set requirement is satisfied. Until then, the chain event
  is recorded but the projection row is in `pending` state
  (`granted_at IS NULL` shorthand).
- Witness qualification: a witness is "qualified to ratify" if it
  itself holds an active grant for the same `(purpose, scope)`
  (a structural co-signing rule — only peers already trusted for X
  can ratify new trust for X).

This composes the existing NodeCore primitive cleanly; no new schema
or wire fields. The threshold table is consumer policy (NodeCore's
`crate::trust` or LensCore's verifier) — Persist materializes the
`pending`/`active` state mechanically.

### 3.6 Conflict resolution

The `UNIQUE (grantee_key, granter_key, purpose, scope)` constraint
means a granter has one live grant per (grantee, purpose, scope).
Re-issuance is an update (extend `expires_at`, refresh
`chain_event_id`). The ingest path detects re-issuance by matching the
unique key and updates rather than inserts.

Ordering: if two events for the same unique key arrive out-of-order,
the one with the later `granted_at` wins. The audit chain's
event_id-monotonic invariant gives us a deterministic ordering for
ties.

---

## 4. Persist API surface

### 4.1 Emit — `Engine.grant_trust(...)`

```rust
impl Engine {
    /// Sign and emit a TrustGrant Contribution event. Returns the
    /// event_id once the chain entry has landed.
    pub async fn grant_trust(
        &self,
        grantee_key: &str,
        purpose: TrustPurpose,
        scope: &str,
        expires_at: Option<DateTime<Utc>>,
        rationale: &str,
    ) -> Result<TrustGrantReceipt, Error>;

    /// Sign and emit a revocation event (TrustGrant with
    /// expires_at = now()).
    pub async fn revoke_trust_grant(
        &self,
        grantee_key: &str,
        purpose: TrustPurpose,
        scope: &str,
    ) -> Result<TrustGrantReceipt, Error>;

    /// Fetch an RFC 6962 inclusion proof for a grant against the
    /// current Signed Tree Head. External verifiers check:
    ///   1. STH signature (engine's hybrid Ed25519+ML-DSA-65)
    ///   2. Inclusion proof: leaf hashes up the sibling path to the
    ///      STH root, matching `root_hash`
    /// Confirms the grant is in the tree without trusting the
    /// directory's projection.
    pub async fn trust_grant_inclusion_proof(
        &self,
        grant_id: Uuid,
    ) -> Result<TrustGrantInclusionProof, Error>;

    /// Fetch an RFC 6962 consistency proof between two tree sizes.
    /// External verifiers check that STH(old_size) → STH(new_size)
    /// is a legal append (no rewrite). Used for cross-period
    /// re-verification.
    pub async fn trust_grant_consistency_proof(
        &self,
        tenant_id: &str,
        old_size: u64,
        new_size: u64,
    ) -> Result<ConsistencyProof, Error>;

    /// Fetch the current Signed Tree Head for a tenant. STH freshness
    /// is the verifier's responsibility (recommended policy: reject
    /// STHs older than the engine's signing cadence + grace).
    pub async fn current_sth(
        &self,
        tenant_id: &str,
    ) -> Result<SignedTreeHead, Error>;
}

pub struct TrustGrantReceipt {
    pub grant_id: Uuid,
    pub chain_event_id: u64,
    pub chain_event_hash: Vec<u8>,
    pub tenant_id: String,                  // log scope
    pub tree_size_at_emit: u64,             // STH size when this grant was sealed
}

/// Inclusion proof against an STH. Types reused from
/// `ciris_verify_core::transparency` (the canonical SOTA primitive;
/// per the CIRIS-wide architecture, all transparency-log primitives
/// live in Verify — persist consumes, does not redefine).
pub struct TrustGrantInclusionProof {
    pub sth: SignedTreeHead,                // ciris_verify_core::transparency
    pub merkle_proof: MerkleProof,          // ciris_verify_core::transparency
    pub leaf_canonical_bytes: Vec<u8>,      // for verifier to re-hash
}

// SignedTreeHead, MerkleProof, ConsistencyProof: see
// ciris_verify_core::transparency. Wire-shape repeated here for
// reference only — the canonical types are imported.
//
// pub struct SignedTreeHead {
//     pub log_id: String,                       // = tenant_id for persist
//     pub tree_size: u64,
//     pub root_hash: [u8; 32],
//     pub timestamp: DateTime<Utc>,
//     pub signature: HybridSignature,           // ciris_crypto
//     pub witness_signatures: Vec<WitnessSignature>,  // reserved
// }
//
// pub struct MerkleProof {
//     pub entry_index: u64,
//     pub leaf_hash: [u8; 32],
//     pub siblings: Vec<(bool, [u8; 32])>,      // (is_right, hash)
//     pub root: [u8; 32],
// }
//
// pub struct ConsistencyProof {
//     pub old_tree_size: u64,
//     pub new_tree_size: u64,
//     pub proof_hashes: Vec<[u8; 32]>,
// }
```

The signer is the engine's local signing key (post-#51 `local_sign`).
The granter field on the event is the local public key. Self-grant
(`granter == grantee`) is rejected at the API boundary, matching the
v1.3.0 `trusted_by != key` integrity rule.

### 4.2 Ingest — automatic on chain landing

When any `TrustGrant` Contribution event lands in `cirisaudit_events`
(via local emit or gossip ingest), a directory hook materializes /
updates the corresponding `federation_trust_grants` row. The hook is
idempotent — same `chain_event_id` arriving twice is a no-op.

No public API for ingest. It runs in the audit-chain commit path,
analogous to how `registry_vouch` rows index automatically today.

### 4.3 Read API

```rust
impl Engine {
    /// Point query — is there a live grant from any granter for
    /// (grantee, purpose, scope)?
    pub async fn lookup_trust_grant(
        &self,
        grantee_key: &str,
        purpose: TrustPurpose,
        scope: &str,
    ) -> Result<Vec<TrustGrantRow>, Error>;

    /// Filter query — all grants matching the filter (intersected).
    pub async fn list_trust_grants(
        &self,
        filter: TrustGrantFilter,
    ) -> Result<Vec<TrustGrantRow>, Error>;
}

pub struct TrustGrantFilter {
    pub grantee_key: Option<String>,
    pub granter_key: Option<String>,
    pub purpose: Option<TrustPurpose>,
    pub scope_prefix: Option<String>,
    pub include_revoked: bool,
    pub include_expired: bool,
}
```

Wildcard matching: `lookup_trust_grant(grantee, Deferral, "medical")`
returns rows with `scope='medical'` AND rows with `scope='*'`. The
caller decides whether a wildcard grant satisfies the question.

Transitive resolution stays out of persist — that's NodeCore's
`resolve_trust` policy layer. Persist provides the rows; NodeCore
applies the §RC transitive-vouching rules.

### 4.4 Merkle transparency layer — per-tenant SOTA trees

Persist's audit chain (per-tenant linear hash chain in `cirisaudit_events`) is augmented with a **per-tenant Merkle tree** for SOTA inclusion + consistency proofs. The transparency-log primitives live in `ciris_verify_core::transparency` per the CIRIS-wide architecture (Verify = wellspring; Persist = next stop); persist implements `AuditLeaf: TransparencyLeaf` and provides PG + SQLite `TransparencyStore` implementations.

**Tree shape per RFC 6962 / Trillian:**

- Binary Merkle tree over leaves, SHA-256
- **Byte prefixes** (RFC 6962 §2.1): `0x00` for leaves, `0x01` for internal nodes. Migrates cleanly from Verify's legacy string prefixes at the audit-chain-bridge boundary (genesis-on-cutover policy already locked).
- One tree per tenant (`log_id = tenant_id`) — matches persist's per-tenant chain isolation (no cross-tenant correlation possible at the Merkle layer either)
- Leaf hash = SHA-256(`0x00` || canonical_bytes(audit_entry))
- Internal node = SHA-256(`0x01` || left || right)
- Odd-leaf promotion (standard RFC 6962)

**Signed Tree Heads — every-append cadence (Sigstore Rekor pattern):**

The engine signs an STH **on every audit-chain append** — one STH per leaf per tenant. Each `AuditService::record_entry` call atomically: (1) records the entry under the existing chain integrity rules; (2) appends a leaf to the tenant's `TransparencyLog<AuditLeaf>`; (3) signs an STH over the new `(tenant_id, tree_size, root_hash, now)` with the engine's local hybrid key (Ed25519 + ML-DSA-65); (4) returns the STH alongside the entry receipt.

Rationale — every-append is the right cadence for CIRIS's governance-paced volume (handfuls of events/tenant/min, not transactional):

- Verifier always has a fresh STH paired with each emit receipt — no separate "fetch current STH" round-trip
- No staleness reasoning required for active tenants
- Witness-compatibility forward — heartbeat option becomes additive when witness protocol lands
- Storage cost is bounded (~200 bytes/STH × emit volume; ~2 MB/tenant/year at 10K leaves)
- Hybrid signing cost (~1 ms/leaf) amortizes over event signing already in the path

STH freshness is the verifier's responsibility — the substrate signs every STH; consumers decide their own window (strict consumers may require seconds; historical replay tooling accepts any STH that covers the leaf). The CIRIS Accord doesn't pin freshness — it's policy.

**Heartbeat STHs** (signed STH at fixed cadence even when idle) — deferred to the witness-cosigning era. The substrate ships every-append in v1.5.0; heartbeat is additive.

```rust
// From ciris_verify_core::transparency
pub struct SignedTreeHead {
    pub log_id: String,              // tenant_id
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    pub timestamp: DateTime<Utc>,
    pub signature: HybridSignature,
    pub witness_signatures: Vec<WitnessSignature>,  // reserved for protocol
}
```

**Storage:**

The Merkle layer is computed on top of `cirisaudit_events` via a parallel `merkle_nodes` table (separate from `federation_trust_grants` — the Merkle layer is universal, not trust-grant-specific). On each audit-chain insert, the corresponding tree updates; STH is signed at cadence and recorded in `merkle_sth_log`.

V021 schema additions:
- `merkle_leaves(tenant_id, leaf_index PRIMARY KEY, chain_event_id, leaf_hash)` — leaf-to-event mapping; chain_event_id is the FK into `cirisaudit_events`
- `merkle_sth_log(tenant_id, tree_size PRIMARY KEY (tenant_id, tree_size), root_hash, timestamp, signature, witness_signatures)` — all signed STHs retained (small; one row per cadence interval)
- `merkle_nodes(tenant_id, level, index_at_level, hash)` — materialized internal nodes for proof generation efficiency. Optional; can be regenerated from leaves on demand. Recommended for production.

**Threat model coverage** (RFC 6962 + STH + ConsistencyProof + per-tenant scoping):

| Threat | Mitigation |
|---|---|
| Log fork / split-view | STH + reserved witness cosigning (protocol future) |
| Retroactive insertion | `ConsistencyProof` verifies STH(n) → STH(m) is an append |
| Selective omission | `InclusionProof` against signed root: "prove K's grant is at index N under STH(size_m)" |
| Stale STH acceptance | Verifier-side freshness policy on STH timestamp |
| Cross-tenant correlation breach | Per-tenant trees (no global root) |
| Cross-subsystem proof collision | RFC 6962 byte prefixes (persist + Verify share the prefix scheme; `log_id` distinguishes the universe) |
| Quantum break on signing | Hybrid Ed25519 + ML-DSA-65 STH signing |
| Quantum break on tree | SHA-256 is PQ-resistant |

**External verifier flow** (the property that justifies the substrate):

1. Verifier fetches `current_sth(tenant_id)` from the directory
2. Verifies STH signature against the engine's published hybrid pubkey
3. Checks STH timestamp is within freshness window
4. Fetches `trust_grant_inclusion_proof(grant_id)` for the grant in question
5. Verifies the inclusion proof against `sth.root_hash`
6. (Optional, for cross-period verification) Fetches `trust_grant_consistency_proof(tenant_id, old_size, new_size)` and verifies append-only between two STHs

At no point does the verifier trust the directory's projection — only signatures + hashes.

---

## 5. Bootstrap — steward is topology, not tag

A fresh directory has zero grants. The first grant signed by any key
*K* establishes *K* as the bootstrap anchor for that directory; *K*
holds an implicit "self-recognized" position recoverable from the
chain's first event with `subject_kind='trust_grant'`.

There is no `is_steward` flag, no special row, no role tag. Operators
who want a known-steward-anchored directory pre-seed it with a grant
signed by their chosen steward key (Registry's published key, a
deployment-template key, a hardware-key, whatever). Subsequent grants
flow normally.

This means: a CIRIS-RED deployment with no steward and no
inherited grants operates in deferral-disabled mode (no trust path to
resolvers), exactly matching the V020 §3.3 "TEMPORARY agents without a
steward" guarantee.

---

## 6. Migration from v1.3.0

### 6.1 v1.4.0 — interim cut

- Ship the SQLite-parity port for v1.3.0's `federation_*` methods
  (CIRISPersist#52) so SQLite directories can hold V020 trust columns.
- Ship the `steward_* → local_*` rename (CIRISPersist#51) with
  deprecated aliases.
- No schema changes. v1.4.0 is the last release on the V020 shape.

### 6.2 v1.5.0 — substrate cut (this FSD)

- V021 migration: `federation_trust_grants` table on both dialects.
- Backfill: V021 emits synthetic `TrustGrant` events for every live
  V020 trust row (signed by the recovered `trusted_by` key).
- Emit / ingest / read API per §4.
- V020 trust columns stay readable; new code reads grants table.
- Bumps minimum CIRISNodeCore version to whatever ships the Accord §RC
  `trust_grant` `subject_kind` addition.

### 6.3 v1.6.0 — V020 column drop

- V022 migration: drop V020 trust columns from `federation_keys`.
- Consumers that still read V020 columns at v1.6.0 release have one
  full minor of notice; the deprecation timeline tracks the CHANGELOG.

### 6.4 NodeCore rewire

`crate::trust::resolve_trust` rewires from
`directory.lookup_trust(key)` to
`directory.list_trust_grants(filter)`. Transitive vouching unchanged
in shape — `registry_vouch` Contributions still drive the transitive
edges; only the trust-grant lookup path changes.

NodeCore ships this in its v0.8.x cut once Persist v1.5.0 is out.

### 6.5 LensCore rewire

`verify_hybrid_via_directory` becomes
`verify_hybrid_and_check_grant(purpose, scope)`: signature check first,
then check that the signer holds a live grant for the purpose+scope of
the trace being verified. LensCore ships this when CIRISLensCore#21's
counter-RII detector wires through.

### 6.6 Portal rewire

Portal builds a "Manage Trust" UI surface that submits signed
`TrustGrant` events to the operator's local Persist (or to Registry's
Persist for CIRISRegistry-anchored deployments). Out of scope for this
FSD — Portal owns the UI design.

---

## 7. Out of scope

- **Gossip transport** — how `TrustGrant` events propagate between
  directories. Same channel as other Contribution events; the
  forthcoming federation-gossip FSD covers it.
- **Portal UI shape** — Portal owns the trust-management surface.
  This FSD pins only the wire format and persist API.
- **Domain taxonomy ownership** — covered by TRUST_HIERARCHY.md §9.
- **Purpose taxonomy evolution** — adding a fourth purpose (e.g.
  `governance`) is a future Accord §RC amendment, not a Persist
  schema change.
- **Threshold policy table** — *which* (purpose, scope) tuples
  require witness_set ratification, and *how many* witnesses are
  qualified. The substrate ships §3.5 mechanically (pending/active
  state on ingest, witness_set verification); the threshold table
  lives in NodeCore's policy layer.

---

## 8. Implementation order

| # | Step | Repo | Dep |
|---|---|---|---|
| 1 | ~~Accord §RC additions: 15 new subject_kinds + MESSAGE_TAXONOMY FSD~~ **LANDED** in NodeCore [`871ebab`](https://github.com/CIRISAI/CIRISNodeCore/commit/871ebab) | CIRISNodeCore | ✅ done |
| 2 | ciris-verify-core::transparency SOTA upgrade (RFC 6962 + STH + ConsistencyProof + generic leaf + storage abstraction + per-log_id) — **[CIRISVerify#23](https://github.com/CIRISAI/CIRISVerify/issues/23)** | CIRISVerify | 🔴 upstream gate for v1.5.0 |
| 3 | V021 migration (Postgres + SQLite) — `federation_trust_grants` + `merkle_leaves` + `merkle_sth_log` + `merkle_nodes` | CIRISPersist | (2) |
| 4 | `AuditLeaf: TransparencyLeaf` impl + `PgTransparencyStore` / `SqliteTransparencyStore` | CIRISPersist | (2) (3) |
| 5 | `TrustGrantPayload` + chain-commit ingest hook (incl. witness_set activation + Merkle tree update + STH cadence trigger) | CIRISPersist | (1) (3) (4) |
| 6 | `grant_trust` / `revoke_trust_grant` emit API + PyO3 wrappers | CIRISPersist | (5) |
| 7 | `lookup_trust_grant` / `list_trust_grants` read API + PyO3 | CIRISPersist | (3) |
| 8 | `trust_grant_inclusion_proof` / `trust_grant_consistency_proof` / `current_sth` proof APIs + PyO3 wrappers | CIRISPersist | (4) (5) |
| 9 | V021 backfill from V020 columns (synthetic TrustGrant events signed by recovered `trusted_by`) | CIRISPersist | (5) (6) |
| 10 | `crate::trust::resolve_trust` rewire to grants table | CIRISNodeCore | (7) |
| 11 | `verify_hybrid_and_check_grant` + STH/inclusion-proof verification | CIRISLensCore | (7) (8) |
| 12 | "Manage Trust" UI | CIRISPortal | (6) |
| 13 | V022 drop of V020 trust columns | CIRISPersist | one minor after (9) |

Steps 1-6 are the v1.5.0 cut. Steps 7-9 land in successive downstream
minors. Step 10 is v1.6.0.

---

## 9. References

- `/home/emoore/CIRISNodeCore/FSD/TRUST_HIERARCHY.md` (v2) — the
  policy layer this substrate supports
- `/home/emoore/CIRISNodeCore/SCHEMA.md` §3.1 / §3.2 — Contribution
  type taxonomy this FSD extends
- CIRISPersist V020 (`federation_keys_trust_hierarchy.sql`) — the
  transitional shape this FSD replaces
- CIRISPersist#51 — `steward_* → local_*` rename (v1.4.0 interim)
- CIRISPersist#52 — SQLite parity for federation_* methods (v1.4.0)
- CIRISAgent#760 — Accord §RC consent_role primitive
- Memory: `project_one_key_primitive.md` — Ed25519+ML-DSA hybrid
  pubkey is the identity ground; trust grants compose over that ground
