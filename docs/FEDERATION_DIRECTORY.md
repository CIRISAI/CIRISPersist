# Federation Directory — persist as substrate, trust as policy

**Status:** architectural contract (v0.2.x track). Companion to
`docs/COHABITATION.md` (cohabitation doctrine — persist as the
runtime keyring authority on a host) and the registry team's
`docs/FEDERATION_CLIENT.md` (the registry-side complement
covering cache layer, steward role, and trust-model selection).
The five open design questions in earlier drafts of this doc
(schema ownership, write authority, consistency model, fail
mode, trust-contract impact) were resolved in the
persist/registry alignment conversation 2026-05; their decisions
are recorded in §"Resolved decisions" below. **Implementation
is the v0.2.0 milestone; the schema is experimental during
v0.2.x per §"v0.2.x experimental schema contract" and
stabilizes at v0.3.0.**

Cross-references:
- PoB §3.1 — federation as peer consensus
- PoB §3.2 — one identity, three roles (steward / signer / verifier)
- PoB §4   — Coherence Stake (starting weight + decay)
- `docs/COHABITATION.md` — runtime keyring authority
- `THREAT_MODEL.md` AV-14 — single-point-of-compromise on
  registry's pubkey store
- CIRISRegistry's `trusted_primitive_keys` / `partner_keys` /
  `registry_signing_keys` schema

---

## TL;DR

Three rules:

1. **Persist stores; consumers compute.** Persist's federation
   tables hold pubkey records, attestations between keys, and
   revocations — every row carrying its own cryptographic
   provenance (v0.1.3 scrub-signing four-tuple). Persist does
   **not** compute trust scores, evaluate policies, or decide
   "is this key trusted to verify message M".
2. **Trust is the consumer's policy.** The registry, lens, agent,
   and any future verifier each compose their own trust model on
   top of persist's reads. Direct trust, referrer chains,
   score-above-threshold, consensus-of-N — all live above persist,
   not inside it.
3. **The trait surface is intentionally narrow.** CRUD + range
   queries on three tables. No `is_trusted()`. No `trust_score()`.
   No policy enums. The moment persist encodes a specific trust
   model, every consumer is locked into it and the federation
   flexibility PoB §3.1 needs is gone.

---

## The problem we're solving

### Today (registry-as-authority)

The CIRISRegistry holds three pubkey stores:

| Table | Holds | Trust anchor |
|---|---|---|
| `trusted_primitive_keys` | Build-signing pubkeys for the 5 primitives (registry, persist, lens, agent, node) | Steward-signed |
| `partner_keys` | Per-org keys for license-tiered partners | Steward-signed |
| `registry_signing_keys` | Registry's own steward keys | Bootstrapped via DNS validation + bond |

Two structural problems:

- **Single-point-of-compromise.** If the registry's database is
  compromised, every primitive's trust anchor is poisoned at once.
  THREAT_MODEL.md AV-14 names this.
- **Authority not earned via measurement.** PoB §3.1 routes trust
  through peer consensus + Coherence Stake; the current registry
  shape routes it through "the steward signed it." That's a
  starting weight (PoB §4 acknowledges this), but it's not where
  PoB wants the system to converge.

### Under PoB (registry-as-peer)

| Today | Under PoB |
|---|---|
| Registry is source of truth for "who is org X" | Pubkeys live in persist's federated directory; registry queries + caches |
| Each primitive's build-signing key registered with the registry | Each primitive self-publishes; registry observes and attests |
| Steward signs license records, revocations, signed responses | Registry remains a high-weight peer (DNS validation + bond gives starting weight); consumers aggregate across peers |
| Revocations registry-issued | Peer-signed; consumers compute consensus |
| License tier (COMMUNITY/PROFESSIONAL/etc.) | Coherence Stake weight composite (steward attestation as one input among many) |

**The piece that survives separate** is the commercial /
regulatory fast-track — partner onboarding, paid-tier billing,
professional license issuance. That's the "starting weight"
lever from PoB §4. Everything else folds into "registry is one
peer; trust is earned via measurement."

---

## Schema sketch

Three tables. Naming uses `federation_*` prefix to distinguish
from `accord_public_keys` (the agent-trace-signing-key table that
already lives in `cirislens` schema). The migration path
(§ "Migration") collapses the two over time.

### `federation_keys`

```
federation_keys
  key_id              text PRIMARY KEY      -- canonical key identifier (matches signature_key_id on the wire)
  pubkey_base64       text NOT NULL         -- Ed25519 raw, ML-DSA-65 raw, or hybrid (separator-encoded)
  algorithm           text NOT NULL         -- "ed25519" | "ml-dsa-65" | "hybrid" (Ed25519+ML-DSA-65)
  identity_type       text NOT NULL         -- "agent" | "primitive" | "steward" | "partner"
  identity_ref        text NOT NULL         -- agent_id_hash (for agents) | primitive_id (for primitives) | org_id (for partners)
  valid_from          timestamptz NOT NULL
  valid_until         timestamptz           -- nullable; null = no expiry
  registration_envelope jsonb NOT NULL      -- canonical bytes that were signed when this key was registered
  -- v0.1.3 scrub-signing four-tuple (every row carries its own provenance)
  original_content_hash bytea NOT NULL      -- sha256 of registration_envelope
  scrub_signature       bytea NOT NULL      -- Ed25519 over original_content_hash
  scrub_key_id          text NOT NULL       -- key that signed THIS row (must exist in federation_keys)
  scrub_timestamp       timestamptz NOT NULL
  --
  CONSTRAINT scrub_key_must_exist FOREIGN KEY (scrub_key_id) REFERENCES federation_keys(key_id)
)
```

**Why every row signs itself:** the registry's DB compromise
problem disappears if every row carries cryptographic provenance.
A consumer reading `federation_keys` doesn't trust the row
because "Postgres said so" — they verify the `scrub_signature`
against the `scrub_key_id`'s pubkey (recursively, terminating at
a key the consumer has independently anchored — the steward,
their local verifier, etc.).

**Bootstrap:** the row that holds the steward's own key is
self-signed (scrub_key_id = key_id). Consumers anchor "trust
the steward" out-of-band (DNS validation, baked-in default,
manual override).

### `federation_attestations`

```
federation_attestations
  attestation_id       uuid PRIMARY KEY
  attesting_key_id     text NOT NULL  REFERENCES federation_keys(key_id)
  attested_key_id      text NOT NULL  REFERENCES federation_keys(key_id)
  attestation_type     text NOT NULL  -- "vouches_for" | "witnesses" | "referred" | "delegated_to"
  weight               numeric        -- optional; attesters carry their own weight signal
  asserted_at          timestamptz NOT NULL
  expires_at           timestamptz    -- nullable
  attestation_envelope jsonb NOT NULL -- canonical bytes that were signed
  -- scrub envelope
  original_content_hash bytea NOT NULL
  scrub_signature       bytea NOT NULL
  scrub_key_id          text NOT NULL  REFERENCES federation_keys(key_id)
  scrub_timestamp       timestamptz NOT NULL
)
```

`attestation_type` is intentionally a string, not an enum.
Consumers may invent new types as their trust models evolve;
persist doesn't gatekeep semantics. Examples:

- `vouches_for` — "I have personally verified this key represents
  identity X" (high-weight, what stewards do)
- `witnesses` — "I observed this key in production traffic at
  time T, no anomalies" (low-weight, what the registry does
  passively)
- `referred` — "I trust the key, and I trust its referrer to
  vouch for it" (transitive trust, weight decays per PoB §4)
- `delegated_to` — "this key may sign on my behalf within scope S"
  (delegation, used by hardware-backed re-signers)

### `federation_revocations`

```
federation_revocations
  revocation_id        uuid PRIMARY KEY
  revoked_key_id       text NOT NULL  REFERENCES federation_keys(key_id)
  revoking_key_id      text NOT NULL  REFERENCES federation_keys(key_id)
  reason               text           -- free-form; consumers parse if they care
  revoked_at           timestamptz NOT NULL
  effective_at         timestamptz NOT NULL  -- when the revocation takes effect (may be retroactive)
  revocation_envelope  jsonb NOT NULL
  -- scrub envelope
  original_content_hash bytea NOT NULL
  scrub_signature       bytea NOT NULL
  scrub_key_id          text NOT NULL  REFERENCES federation_keys(key_id)
  scrub_timestamp       timestamptz NOT NULL
)
```

Append-only. `is_revoked(key, at)` walks the table for the
highest-weight effective revocation; consumers decide what
constitutes "highest weight" by their own policy.

---

## Trait surface

Strictly CRUD + range queries. The trait lives in `src/store/`
alongside the existing `Backend` trait.

```rust
#[async_trait]
pub trait FederationDirectory: Send + Sync {
    // ── Public keys ────────────────────────────────────────────
    async fn put_public_key(
        &self,
        record: SignedKeyRecord,
    ) -> Result<(), DirectoryError>;

    async fn lookup_public_key(
        &self,
        key_id: &str,
    ) -> Result<Option<KeyRecord>, DirectoryError>;

    async fn lookup_keys_for_identity(
        &self,
        identity_ref: &str,
    ) -> Result<Vec<KeyRecord>, DirectoryError>;

    // ── Attestations ───────────────────────────────────────────
    async fn put_attestation(
        &self,
        attestation: SignedAttestation,
    ) -> Result<(), DirectoryError>;

    async fn list_attestations_for(
        &self,
        attested_key_id: &str,
    ) -> Result<Vec<Attestation>, DirectoryError>;

    async fn list_attestations_by(
        &self,
        attesting_key_id: &str,
    ) -> Result<Vec<Attestation>, DirectoryError>;

    // ── Revocations ────────────────────────────────────────────
    async fn put_revocation(
        &self,
        revocation: SignedRevocation,
    ) -> Result<(), DirectoryError>;

    async fn revocations_for(
        &self,
        revoked_key_id: &str,
    ) -> Result<Vec<Revocation>, DirectoryError>;
}
```

### Explicit non-goals

These methods will **not** appear on `FederationDirectory`:

- `is_trusted(key_id) -> bool` — trust is the consumer's policy
- `trust_score(key_id) -> f64` — scoring belongs above persist
- `trust_path(from, to) -> Vec<Attestation>` — graph walks belong
  in consumer policy code (persist's `list_attestations_*` exposes
  the edges; the consumer composes the traversal)
- `evaluate_policy(policy, key_id) -> Verdict` — there is no
  policy DSL in persist
- `register_with_registry(...)` — persist is a peer of the
  registry, not a client of it; the registry is one writer to
  persist's directory among many

---

## How consumers compose policy

Persist's narrow surface is what makes the federation flexible.
Three sketches of trust models a consumer might compose:

### Policy A — direct trust (registry today)

```rust
async fn is_trusted_direct(
    dir: &dyn FederationDirectory,
    key_id: &str,
    steward_key_ids: &[&str],
) -> bool {
    // Trust if any steward has explicitly vouched and the
    // attestation is unrevoked.
    let attestations = dir.list_attestations_for(key_id).await.unwrap_or_default();
    let revocations = dir.revocations_for(key_id).await.unwrap_or_default();
    let now = chrono::Utc::now();

    let revoked = revocations.iter().any(|r| r.effective_at <= now);
    if revoked { return false; }

    attestations.iter().any(|a| {
        a.attestation_type == "vouches_for"
            && steward_key_ids.contains(&a.attesting_key_id.as_str())
            && a.expires_at.is_none_or(|t| t > now)
    })
}
```

### Policy B — referrer chain (PoB §3.1 transitive)

```rust
async fn is_trusted_transitive(
    dir: &dyn FederationDirectory,
    key_id: &str,
    root_keys: &[&str],   // anchored out-of-band
    max_depth: usize,
) -> bool {
    // BFS: from root, walk attestations forward looking for key_id.
    let mut frontier: VecDeque<(String, usize)> =
        root_keys.iter().map(|k| ((*k).to_string(), 0)).collect();
    let mut seen = HashSet::new();

    while let Some((current, depth)) = frontier.pop_front() {
        if depth > max_depth { continue; }
        if !seen.insert(current.clone()) { continue; }
        if current == key_id { return true; }

        let outbound = dir.list_attestations_by(&current).await.unwrap_or_default();
        for a in outbound {
            if a.attestation_type == "vouches_for"
                || a.attestation_type == "referred"
            {
                frontier.push_back((a.attested_key_id, depth + 1));
            }
        }
    }
    false
}
```

### Policy C — score-weighted consensus (PoB §4 Coherence Stake)

```rust
async fn coherence_stake_score(
    dir: &dyn FederationDirectory,
    key_id: &str,
    peer_weights: &HashMap<String, f64>,  // peer_key_id → coherence weight
    decay_per_hop: f64,
) -> f64 {
    // Direct attestations carry full weight; transitive ones decay.
    let mut score = 0.0;
    let mut visited = HashSet::new();
    let mut frontier = vec![(key_id.to_string(), 1.0)];

    while let Some((current, scale)) = frontier.pop() {
        if !visited.insert(current.clone()) { continue; }
        let attestations = dir.list_attestations_for(&current).await.unwrap_or_default();
        for a in attestations {
            if let Some(&w) = peer_weights.get(&a.attesting_key_id) {
                score += w * scale * a.weight.unwrap_or(1.0);
                // Recurse with decayed scale to pick up referrer chains.
                frontier.push((a.attesting_key_id, scale * decay_per_hop));
            }
        }
    }
    score
}
```

Same persist; three radically different trust models. None of the
math lives in persist.

### What the registry conversation actually wants

When the registry team says "interfaces for trusting an agent key
— individually, as a referrer, directly, heuristically above
score X" — those are *registry-side* interfaces the registry
exposes to **its** consumers. The registry's verify endpoint
takes a key_id, fetches edges from persist, runs whatever policy
the registry has chosen, and returns a verdict to the lens (or
agent, or whoever asked). Persist's role is "the registry queries
me; I return rows."

This is the same pattern as today's `Backend::lookup_public_key`,
just with attestation + revocation tables next to it. The
registry is already a happy-path consumer of persist's pubkey
table; federation just extends the surface persist exposes.

---

## Migration

**Phase 1 (additive, no breakage).** Add the three federation
tables alongside `cirislens.accord_public_keys`. Continue serving
trace-signature lookups from `accord_public_keys`. Dual-write
agent keys: every `INSERT` into `accord_public_keys` also writes
a row to `federation_keys` with `identity_type='agent'` and the
same `key_id`.

**Phase 2 (read-path migration).** Switch the
`Backend::lookup_public_key` implementation to read from
`federation_keys` first, falling back to `accord_public_keys`.
Backfill `federation_keys` from `accord_public_keys` for
historical rows. Validate parity with a counter: every
`accord_public_keys` row has a corresponding `federation_keys`
row.

**Phase 3 (deprecate).** Drop dual-writes; `accord_public_keys`
becomes a read-only view over `federation_keys WHERE
identity_type='agent'`.

**Phase 4 (registry consumes).** Registry's
`trusted_primitive_keys` / `partner_keys` / `registry_signing_keys`
all become consumers of persist's `federation_keys`. Registry
keeps its own tables as a write-through cache for low-latency
verification, but persist is the source of truth.

Each phase is a separate persist version. Rough sequencing:

| Persist version | What lands | Registry-side state |
|---|---|---|
| v0.2.0 | `federation_keys` schema + `FederationDirectory` trait + dual-write from existing `accord_public_keys` write paths + write-authority guards (rate limit + quota) | Dual-write peer behind `FEDERATION_DUAL_WRITE_ENABLED` (default off until registry v1.4); experimental schema contract applies |
| v0.2.x | `federation_attestations` + `federation_revocations` schema + trait methods + bilateral divergence telemetry | Registry begins issuing attestations via `federation_attestations.put` instead of writing keys directly |
| v0.3.0 | Read-path migration; `lookup_public_key` reads federation table; v0.2.x experimental contract retires (schema becomes stable) | Registry can flip dual-write default to on; v1.5 cache-coherence polish (PG NOTIFY pubsub) becomes a candidate at this point |
| v0.3.x | `accord_public_keys` deprecated to read-only view over `federation_keys WHERE identity_type='agent'` | Registry's own `trusted_primitive_keys`/`partner_keys`/`registry_signing_keys` become persist consumers; trust-contract diff lands on registry side |

---

## Resolved decisions

The five questions in earlier drafts of this doc have been
resolved through the persist/registry alignment conversation
(2026-05). Each row records the decision and where it sits in
the contract.

| # | Question | Decision |
|---|---|---|
| 1 | Schema ownership — separate `federation_keys` or widen `accord_public_keys` | **Separate.** Migration over 2-3 persist versions. No schema churn on the live `accord_public_keys` table. |
| 2 | Write authority — steward-only or self-publish | **Self-publish + post-hoc attestation.** Each primitive's CI writes its own `federation_keys` row signed by its own steward key. Registry's `RegisterTrustedPrimitiveKey` admin RPC shifts from issuance call to attestation call (writes `federation_attestations` with `attesting_key_id=registry-steward`, `attestation_type="vouches_for"`). |
| 3 | Consistency model | **Eventually-consistent + TTL.** Cache freshness controlled by consumer-side TTL; matches CIRISVerify's existing pubkey-pinning window. No new contract surface. |
| 4 | Fail-mode when persist unreachable | **Fail-open from cache by default**, opt-in fail-closed via `PERSIST_REQUIRED=true`, **plus a hard ceiling**: `max_stale_cache_age_seconds=3600` (default) triggers fail-closed regardless of `PERSIST_REQUIRED`. |
| 5 | Trust contract diff (`docs/TRUST_CONTRACT.md` on registry side) | **At persist v0.3.x.** Path A splits into A1 (registry attests) + A2 (persist witnesses); new Path D for consumer-aggregated multi-peer attestations. Registry team owns the diff. |

---

## Operational contract

These are the operational guarantees both sides commit to. They
sit alongside the schema and trait surface as part of the
v0.2.x→v0.3.x migration contract.

### Write authority — scrub-signature is auth

Persist accepts `federation_keys` writes from any caller whose
row carries a valid scrub-signature whose `scrub_key_id` either
chains to a steward via the FK chain or is itself
out-of-band-anchored. The cryptographic check is the auth check.
No per-primitive API keys; no per-primitive credential issuance.

This preserves the property PoB §3.1 needs: any peer can
self-publish without an issuance handshake. A self-published key
with no attestations has zero trust under any reasonable consumer
policy, so accepting the row is harmless.

Two operational guards on top:

- **Per-source-IP rate limit.** Mirrors registry's existing
  `rate_limiter` shape. Default: 60 writes/minute/IP. Bursts
  beyond drop to 429.
- **Per-primitive write quota.** Default: **10 keys per
  primitive identity per day**, configurable. Keeps storage
  bounded against either accidental rollout loops or deliberate
  spam without artificial gating on legitimate use.

### Cache freshness — TTL + invalidate-on-write

Consumers maintain their own cache. Two coherence mechanisms in
v0.2.x:

- **TTL.** Default 5 minutes. Tunable per consumer; registry
  starts at 5 min as a balance between freshness and load.
- **Invalidate-on-write.** When a consumer is also a writer
  (e.g., registry writing `federation_attestations`), it
  pre-warms its own cache for the affected `key_id` on the
  write path. Covers the common
  "RegisterTrustedPrimitiveKey-derived attestation" path.

**Deferred to v1.5 / persist v0.3.x:** PG NOTIFY pubsub channel
on `federation_keys` insert/update so consumers can subscribe to
peer-published changes without polling. Not in v0.2.x — adds
infrastructure that makes single-node dev painful, and the
5-minute TTL lag is operationally tolerable for the migration
phase.

### Fail-mode — fail-open with hard ceiling

When persist is unreachable, consumers fall back to local cache
by default. Three knobs:

| Setting | Default | Effect |
|---|---|---|
| `PERSIST_REQUIRED` | `false` | When `true`, fail-closed unconditionally on persist outage |
| `max_stale_cache_age_seconds` | `3600` (1h) | Hard ceiling; fail-closed even with `PERSIST_REQUIRED=false` once cache is older than this |
| `cache_age_seconds` (response field) | always emitted | Consumers see how stale their answer is regardless of mode |

The ceiling closes a deliberate-outage attack: an attacker who
DOSes persist to keep a revoked key in cache must keep persist
down longer than `max_stale_cache_age_seconds`, and operators
have a clean telemetry signal ("persist unreachable for >ceiling,
refusing requests") to escalate before then. 1 hour is the
balance — long enough to ride out a real outage, short enough
that "persist unreachable for >1 hour" is unambiguously
page-worthy.

### Bilateral divergence telemetry

Both sides instrument the dual-write hop during the v0.2.x
experimental phase. Divergence between persist's
`federation_keys` row and the consumer's local table on
read-through is signal we want to see fast, not at v0.3.0
cutover.

| Side | Metric | Increments when |
|---|---|---|
| Registry | `federation_dual_write_divergence_total` | Persist's `federation_keys` row differs from registry's local on read-through (e.g., key bytes mismatch, valid_until skew, scrub-signature failure on persist's row) |
| Persist | `federation_directory_writes_total{outcome="ok\|divergent\|rejected"}` | Every write attempt by outcome; `divergent` covers "row would conflict with existing federation_keys row" |

Both surfaced via `/metrics`. Non-zero divergence in v0.2.x is a
schema-bug signal; non-zero divergence in v0.3.x+ is a real
incident.

---

## v0.2.x experimental schema contract

Persist's `federation_keys` (and v0.2.x `federation_attestations`/
`federation_revocations`) ships as **experimental but
production-functional**. The contract:

- **Persist may break the schema during v0.2.x with two-week
  written notice** (CHANGELOG entry + GitHub issue tagged
  `federation-schema-break` + proactive notification to known
  consumers).
- **Registry's dual-write is feature-flagged**
  (`FEDERATION_DUAL_WRITE_ENABLED`, default off until registry
  v1.4). Roll-back is unsetting the flag.
- **Both sides instrument the divergence counter** (above).
  Non-zero divergence triggers investigation, not silent drift.
- **At persist v0.3.0 the experimental contract retires** — the
  schema becomes stable, breaking changes from that point forward
  follow standard semver-major rules.

This arrangement lets real production attestation patterns find
edge cases during the experimental phase (e.g., "what happens
when a primitive rotates its steward key while attestations from
the old key are still in flight") rather than at v0.3.0 cutover
with everyone reading.

---

## Why persist is the right home

Three properties that make persist the right substrate (and the
registry the wrong one):

1. **Persist is already the durability layer.** Trace events,
   journal entries, scrub envelopes — every write goes through
   persist. Adding a federation directory is an additive schema
   change to a system that's already designed for "every row
   carries cryptographic provenance".
2. **Persist already replicates multi-region via Spock.** The
   registry's primary DB is single-region; multi-region durability
   would be net-new infrastructure. Persist has it.
3. **Persist sits *below* every primitive in the stack
   (`docs/COHABITATION.md`).** The registry is one consumer; the
   lens is another; the agent is another; the bridge is another.
   Putting the federation directory in persist means every
   consumer reads from the same substrate. Putting it in the
   registry means every consumer either pulls from the registry
   (creating the SPOC AV-14 names) or builds its own cache (and
   diverges).

These are not arguments to remove the registry's role — the
registry remains the high-weight peer with the steward key and
the commercial onboarding lever (PoB §4 starting weight). They
*are* arguments that the registry's storage layer should be
persist, not its own DB.

---

## What's not in this doc

- **Implementation details.** No PR-ready code; no migration
  SQL; no test plan. Those come once §"Open design questions"
  has answers.
- **Trust model specifics.** Persist is policy-agnostic by
  design; the lens / registry / agent each pick their own.
- **Performance numbers.** Benchmarks for attestation graph
  walks come once we have a concrete consumer policy to
  benchmark against.

This doc is a **surface alignment artifact** — the shape persist
will expose so the registry conversation can move forward without
locking in a specific trust model on either side.
