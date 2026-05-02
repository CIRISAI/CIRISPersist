# Federation Directory — persist as substrate, trust as policy

**Status:** architectural sketch (v0.2.x track). Companion to
`docs/COHABITATION.md` (cohabitation doctrine — persist as the
runtime keyring authority on a host) and to the in-flight
PoB §3.1 federation conversation between persist, registry, lens,
and agent. **This is not yet implemented; this document exists to
align the four primitives on the surface persist will expose so
the registry conversation can move forward without locking in a
specific trust model.**

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

| Persist version | What lands |
|---|---|
| v0.2.0 | `federation_keys` schema + `FederationDirectory` trait + dual-write from existing `accord_public_keys` write paths |
| v0.2.x | `federation_attestations` + `federation_revocations` schema + trait methods |
| v0.3.0 | Read-path migration; `lookup_public_key` reads federation table |
| v0.3.x | Registry begins consuming; deprecation timeline negotiated |

---

## Open design questions

These are gating questions persist needs answers to **before**
implementation. Answers come out of the registry/persist/lens
alignment conversation:

### 1. Schema ownership — separate table or widened existing?

Option A: `federation_keys` is a new table next to
`accord_public_keys`. Migration over 2-3 versions.

Option B: `accord_public_keys` is widened to add
`identity_type` + `identity_ref` + attestation/revocation FK
targets, becomes the federation directory in place.

A is cleaner (no schema churn on a live production table); B is
faster to ship (no migration). Prefer A unless the registry
team has a strong reason for B.

### 2. Write authority — who can write to `federation_keys`?

Option A: only the steward can write (matches today's registry
admin RPC).

Option B: any key can self-publish, and stewards attest *after*
the fact. Persist accepts the row regardless; consumers decide
trust from the attestation graph.

Option B is closer to PoB §3.1 federation. A is closer to
today's operational shape. Prefer B; a self-published key
without any attestations has zero trust under any reasonable
policy, so accepting the row is harmless.

### 3. Consistency model — Spock multi-region replication

Persist replicates via Spock. Registry's read path needs to
handle "key registered in EU, queried from US during replication
lag". Today this Just Works for `trusted_primitive_keys` because
the registry's own DB also replicates via Spock. Under federation,
persist is the source of truth — the registry's local cache may
lag behind persist's authoritative state.

Open question: does the registry's verify endpoint **require** a
consistent read (and pay the cross-region latency), or is
eventually-consistent acceptable (registry caches; cache may serve
a key that was just revoked elsewhere for up to ~replication-lag
seconds)?

PoB §3.1 implies eventually-consistent is fine — peer consensus
self-heals. Today's operations imply consistent is what the
registry promises. This is a doc/contract question, not just a
schema question.

### 4. Failure mode — fail-closed vs fail-open when persist is
unreachable

If the registry can't reach persist, what happens to verify
requests?

- **Fail-closed:** registry returns 503; verify is unavailable
  during the persist outage.
- **Fail-open:** registry serves from local cache (potentially
  stale); verify continues working but may admit revoked keys.

PoB §3.1 implies fail-closed. Today's operations imply fail-open
is what consumers expect. Probably needs a configurable mode +
clear documentation per consumer.

### 5. Trust contract impact — `docs/TRUST_CONTRACT.md` extension

CIRISRegistry's `docs/TRUST_CONTRACT.md` describes "Path A"
(registry's steward signed the manifest), "Path B" (PEP 740
sigstore), and "Path C" (build provenance attestation). Under
federation, "Path A" decomposes into "Path A1" (registry attests)
+ "Path A2" (persist witnesses + stores), and a "Path D" emerges
(consumer aggregates attestations across multiple peers).

The trust contract doc needs to add Path D and split Path A
without breaking the existing semantics for downstream consumers.

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
