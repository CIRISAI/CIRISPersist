# Federation Directory — persist as substrate, trust as policy

The federation directory is persist's store of public keys, attestations
between keys, and revocations. Every row carries its own cryptographic
provenance. Persist stores and serves these rows; consumers (registry, lens,
agent, edge, node) compose trust from them.

Companions: `docs/COHABITATION.md` (persist as the runtime keyring authority on
a host), `docs/PUBLIC_SCHEMA_CONTRACT.md` (the column tiers readers can rely
on), `WIRE_VOCABULARY_KINDS.md` (how directory rows replicate), and the
registry team's `docs/FEDERATION_CLIENT.md` (the registry-side cache layer,
steward role and trust-model selection).

Cross-references:
- PoB §3.1 — federation as peer consensus
- PoB §3.2 — one identity, three roles (steward / signer / verifier)
- PoB §4   — Coherence Stake (starting weight + decay)
- MISSION.md §1.4 — persist stores trust facts; it never confers trust

---

## Trust contract — eventual consistency as a federation primitive

The directory's promise to consumers is **not** "every row is hybrid-signed,
replicated and attested at all times." It is a **layered set of
eventual-consistency commitments** that compose into a trust contract. Each
consumer picks its own latency/security trade-off using persist's
observability signals.

| Layer | Eventual property | Observability signal |
|---|---|---|
| **PQC completion** | Every row becomes hybrid-signed (Ed25519 + ML-DSA-65) | `pqc_completed_at IS NULL` (`is_pqc_pending()`) → hybrid-pending. |
| **Replication** | Every row reaches every peer its kind's audience admits | Replication cursors and wire-index state (`WIRE_VOCABULARY_KINDS.md` Part 2). |
| **Cache freshness** | Every consumer cache refreshes on TTL or invalidate-on-write | The consumer's own cache age. |
| **Peer attestation** | Every legitimate identity accumulates attestations | Attestations about K over time, and who made them. |
| **Revocation propagation** | Every revocation reaches every consumer | `revocations_for(K)` queried at the consumer's chosen freshness. |

### What "eventual" means for a consumer

A consumer composes its verdict by deciding which eventual properties must be
**completed** rather than **pending** for a given decision. Three examples:

**Strict-hybrid policy.** "Trust no signature until PQC has landed." Refuses
pending rows. Highest assurance; slowest path, because the PQC sign,
replication and cache fill must all complete first.

**Soft-hybrid + freshness policy.** "Trust if Ed25519 verifies and the row was
written < 30s ago, OR if PQC has landed." Accepts the window where PQC is in
flight; refuses old rows that should have completed by now.

**Pure attestation-graph policy.** "Trust if K is N-attested by my trust
roots, regardless of K's own signature status." Defers crypto strength to the
attestation layer. Useful for high-volume, low-stakes paths where the
network's collective view matters more than one key's status.

### What persist commits to

There is no single "is this trusted?" answer, but every dimension of trust has
**a publicly observable signal**. Persist commits to:

1. **Every signal is exposed** — `pqc_completed_at`, `persist_row_hash`,
   replication state, attestation reads, revocation reads. No hidden state.
2. **Every eventual property converges** under non-adversarial conditions —
   the PQC sign is kicked off immediately on the cold path (§"Sequencing");
   replication runs through persist's replication doors.
3. **Every divergence is alarm-able** — operators can see "PQC pending too
   long" or "replication lagging" on the metrics surface before silent drift
   becomes a security failure.

Persist does **not** commit to:

- **Strong consistency.** Reads on one node may be behind another. A
  hard-consistency consumer runs its cache at TTL=0 and pays the round trip.
- **Synchronous PQC on every write.** `put_public_key` and `put_attestation`
  accept an Ed25519-signed row with the ML-DSA-65 half attached on the cold
  path. A consumer that needs synchronous hybrid waits for
  `pqc_completed_at IS NOT NULL`, or registers keys through the Strict
  `register_federation_key` door (§"Write authority").
- **Single-trust-policy enforcement.** Consumers compose different policies;
  persist exposes substrate, not verdicts.

The PQC layer can tighten from eventual to synchronous with one policy flip
(§"PQC strategy"); the observable signal stays the same. The other layers
(replication, cache, attestation, revocation) are eventual by design.

---

## TL;DR

1. **Persist stores; consumers compute.** The federation tables hold key
   records, attestations between keys, and revocations — every row carrying
   its own scrub-signing provenance. Persist does **not** compute trust
   scores, evaluate policies, or decide "is this key trusted to verify
   message M" (CC 1.13.4: the substrate stores; it never adjudicates).
2. **Trust is the consumer's policy.** Direct trust, referrer chains,
   score-above-threshold, consensus-of-N — all live above persist.
3. **The trait surface is intentionally narrow.** Writes through admission
   gates; reads by key, by identity, by attester, by subject. No
   `is_trusted()`, no `trust_score()`, no policy enums. The moment persist
   encodes a trust model, every consumer is locked into it and the
   federation flexibility PoB §3.1 needs is gone.

---

## Why the directory lives in persist

A registry-held pubkey store is a single point of compromise: if its database
is compromised, every primitive's trust anchor is poisoned at once, and trust
is "the steward signed it" rather than earned through measurement (PoB §3.1).
Under PoB the registry is a high-weight peer, not the source of truth:

| Registry-as-authority | Registry-as-peer (this design) |
|---|---|
| Registry is the source of truth for "who is org X" | Pubkeys live in persist's federated directory; the registry queries and caches |
| Each primitive's build-signing key is registered with the registry | Each primitive self-publishes; the registry observes and attests |
| Revocations are registry-issued | Revocations are peer-signed; consumers compute consensus |
| License tier decides weight | Coherence Stake weight is a composite; steward attestation is one input among many |

Persist is the right substrate because:

1. **It is already the durability layer.** Every write goes through persist,
   and every row already carries cryptographic provenance.
2. **It replicates.** Directory rows travel between nodes through persist's
   replication doors, so every peer can verify a chain locally.
3. **It sits below every primitive** (`docs/COHABITATION.md`). Registry,
   lens, agent and edge all read the same substrate instead of each pulling
   from the registry or keeping a divergent cache.

The registry keeps its role as the high-weight peer with the steward key and
the commercial onboarding lever (PoB §4 starting weight); its storage layer
is persist.

---

## Schema sketch

Three core tables, prefixed `federation_*`. `cirislens.accord_public_keys` is
the separate legacy lens audit-chain key table; trace verification reads
`federation_keys` only. `docs/PUBLIC_SCHEMA_CONTRACT.md` lists every column
with its stability tier.

### `federation_keys`

```
federation_keys
  key_id                    text PRIMARY KEY  -- matches signature_key_id on the wire
  pubkey_ed25519_base64     text NOT NULL     -- 32 raw bytes
  pubkey_ml_dsa_65_base64   text              -- 1952 raw bytes; NULL while hybrid-pending
  algorithm                 text NOT NULL     -- always 'hybrid' (CHECK)
  identity_type             text NOT NULL     -- a role SET; see "identity_type vocabulary"
  identity_ref              text NOT NULL     -- agent_id_hash | primitive_id | org_id | …
  valid_from                timestamptz NOT NULL
  valid_until               timestamptz       -- NULL = no expiry
  registration_envelope     jsonb NOT NULL    -- the canonical bytes that were signed
  -- scrub-signing provenance (every row carries its own)
  original_content_hash     bytea NOT NULL    -- sha256 of the canonical envelope
  scrub_signature_classical text NOT NULL     -- Ed25519
  scrub_signature_pqc       text              -- ML-DSA-65; NULL while hybrid-pending
  scrub_key_id              text NOT NULL     -- the key that signed THIS row (FK, DEFERRABLE)
  scrub_timestamp           timestamptz NOT NULL
  pqc_completed_at          timestamptz       -- set when the PQC half is attached
  persist_row_hash          text              -- server-computed; see below
```

#### `identity_type` vocabulary (CIRISPersist#102)

`identity_type` is a **role set**: a comma-joined list read by set
membership (CC 3.4.7.1), e.g. `"steward,accord_holder"` or
`"agent,lenscore_detector"`. The column has no `CHECK`. The canonical tokens
live in `crate::federation::types::identity_type` and are re-exported on
`ciris_persist::federation`:

| Token | Role |
|---|---|
| `agent` | Agent trace-signing keys (one per running CIRISAgent occurrence under PoB §3.2's one-key model). |
| `primitive` | Build-signing keys for the substrate binaries. |
| `steward` | Steward keys — trust roots for routine operations. |
| `partner` | Per-org partner keys for commercial onboarding. |
| `accord_holder` | HUMANITY_ACCORD key material — the three hardware-attested, human-held keys (FSD-002 §7.2, 2-of-3). Only these rows may emit `accord:*` attestations (FSD-002 §4.1 + §7.1, the federation's one constitutional asymmetry). |
| `substrate_persist` | Persist's self-report identity. The only emitter for `system:*`, `audit_chain:*`, `corpus_health:*`, `identity_continuity:*`, `federation_directory:*` (CEG §5.3 / §7.2). |
| `witness` | Transparency-log witnesses. The only emitter for `transparency_log:cosigned:*` (CEG §10.3). |
| `trusted_publisher` | Policy J publisher. The only emitter for `content_rating:*` (CEG §11.5.3). |
| `node` | Fabric/infrastructure role (CC 3.4.7.1). A `delegates_to` to a `node`-only identity may carry only `infra:*` scopes, never agency (CC 3.4.7.3, CC 4.4.3.4.3; `check_node_agency_admission`). |
| `lenscore_detector` | The only emitter for `detection:correlated_action:*` and `detection:distributive:access:*` (CC 3.4.8). |

**Reserved-prefix admission** (CIRISPersist#116). `DimensionAdmissionPolicy`
carries `reserved_prefix_rules` — `(prefix → required roles)` — and refuses a
`scores` row on a reserved prefix from an attester without the role
(`Error::ReservedPrefixEmitterMismatch`). The CEG 0.1 `attestation:l{N}:*`
form is refused at admission with
`federation_deprecated_attestation_ladder_form`; there is no configuration
that admits it ([`docs/THREAT_MODEL.md` AV-45](THREAT_MODEL.md)).

**Why every row signs itself.** A consumer reading `federation_keys` does not
trust a row because "Postgres said so". It verifies the scrub signature
against `scrub_key_id`'s keys, recursively, terminating at a key the
consumer has independently anchored.

### Bootstrap — trust anchors and pinning

A provenance chain ends at a **self-signed** row (`scrub_key_id == key_id`).
Consumers anchor that terminus out of band; a self-signed row a peer merely
asserts is not an anchor.

- **The pinned anchor is the HUMANITY_ACCORD holder keyset.** `root_binding`
  (`src/federation/rooting.rs`) walks a key's `scrub_key_id` chain, verifying
  each link's signature, to a self-signed `steward` / `accord_holder`
  terminus — and roots the key only if the terminus's Ed25519 pubkey is one of
  the pinned holder keys
  (`ciris_verify_core::accord_genesis::accord_holder_bootstrap_anchor`). A
  terminus outside that set is `RootingRejection::TerminusNotInAnchor`.
  Chain depth is capped at `MAX_PROVENANCE_DEPTH` (64); cycles are detected.
  A `Confirmed` verdict authenticates provenance; it does not confer trust.
- **The holder rows are baked into the crate.** The
  ceremony-signed, self-signed `accord_holder` records are embedded in the
  crate (`src/federation/genesis/`) and seeded into `federation_keys` at first
  boot, so a fresh node can root peers without fetching anything. Holder
  records are never written from a received bundle; a genesis bundle's roster
  and transport rows are admitted only after `verify_bundle_quorum` checks the
  bundle's authorization against this node's own baked roster.
- **Steward bootstrap rows** are produced by
  `src/bin/derive_persist_steward_bootstrap.rs`: it emits the exact canonical
  bytes the steward's secret key signs (the secret never enters this repo),
  and the resulting self-signed record's fingerprint (hex SHA-256 of the raw
  Ed25519 pubkey) is what consumers pin out of band.

### `persist_row_hash` — server-computed for cache divergence

Every `KeyRecord`, `Attestation` and `Revocation` returned by a read carries
`persist_row_hash: String` — hex SHA-256 over the row's canonical bytes.
**Persist computes it server-side**, so a consumer detects cache divergence
(`CIRISRegistry/docs/FEDERATION_CLIENT.md` §"Cache shape") without
reproducing persist's canonicalizer.

The canonical bytes are
`PythonJsonDumpsCanonicalizer::canonicalize_value(&row_as_value)` — sorted
keys, no whitespace, `ensure_ascii=True`, the same Python-compatible shape
persist uses for trace canonical bytes. Consumers store the hex string
verbatim and string-compare on read-through. This avoids the
"different shortest-round-trip" class of bugs (CIRISPersist#7).

### `federation_attestations`

```
federation_attestations
  attestation_id            uuid PRIMARY KEY
  attesting_key_id          text NOT NULL  REFERENCES federation_keys(key_id)
  attested_key_id           text NOT NULL  REFERENCES federation_keys(key_id)
  attestation_type          text NOT NULL  -- see "attestation_type vocabulary"
  weight                    numeric        -- optional attester-supplied weight
  asserted_at               timestamptz NOT NULL
  expires_at                timestamptz    -- NULL = no expiry
  attestation_envelope      jsonb NOT NULL -- the canonical bytes that were signed
  -- scrub-signing provenance
  original_content_hash     bytea NOT NULL
  scrub_signature_classical text NOT NULL
  scrub_signature_pqc       text
  scrub_key_id              text NOT NULL  REFERENCES federation_keys(key_id)
  scrub_timestamp           timestamptz NOT NULL
  pqc_completed_at          timestamptz
  persist_row_hash          text
```

#### `attestation_type` vocabulary (CIRISPersist#102)

The attestation primitive is **one workhorse plus four structural
primitives** (FSD-002 §2). CC 2.4 closes the row-type slot at these five
(`src/federation/row_type.rs`); an unregistered type is reported
(`persist_attestation_type_unregistered_total{type_stem}`) under the current
`ROW_TYPE_ENFORCEMENT = Report` and refused `attestation_type_unregistered`
once the fleet-wide constant flips to `Enforce`. A retired carrier type is
refused in either mode.

| Value | Role | FSD-002 ref |
|---|---|---|
| `scores` | **The workhorse.** Every claim about an entity — identity, capability, behaviour, state, commitment, positive or negative — is a `scores` row on a named `dimension`. Envelope: `{dimension, score ∈ [-1, +1], confidence ∈ [0, 1], context, evidence_refs[], valid_until?, epistemic_mode?, witness_relation?, stake?}`. | §2.1 |
| `delegates_to` | "A authorizes B to sign on A's behalf within scope S." Bounded scope; default consumer-policy transitive depth = 2. | §2.2.1 |
| `supersedes` | "This row replaces a prior attestation by the same attester." Consumers walking history apply latest-wins per (`attesting_key_id`, `dimension`, `attested_key_id`). | §2.2.2 |
| `withdraws` | "I retract my prior attestation." Does NOT claim the original was false at issuance — good-faith retraction. | §2.2.3 |
| `recants` | "My prior attestation was false at issuance — I admit epistemic error." | §2.2.4 |

**`recants` is wire-distinct from `withdraws`.** No prior wire format (PGP /
SPKI / W3C VC) typed epistemic-error admission as a wire primitive. Persist
keeps them distinct on the wire even where consumer UIs collapse them.

The constants live in `crate::federation::types::attestation_type::{SCORES,
DELEGATES_TO, SUPERSEDES, WITHDRAWS, RECANTS}` and are re-exported on
`ciris_persist::federation`.

#### Dimension admission gate (CIRISPersist#102)

`put_attestation` runs an admission gate before the insert. Two layers apply
to `scores` rows:

**Layer 1 — `accord:*` × `accord_holder` constitutional rule** (FSD-002 §4.1
+ §7.1). A `scores` row whose `dimension` starts with `accord:` is refused
unless the attester's role set contains `accord_holder`:
`Error::AccordDimensionRequiresAccordHolder { dimension, identity_type }`
(token `federation_accord_dimension_requires_accord_holder`). The rule
crosses tables, so no `CHECK` can express it; the admission gate is the
load-bearing point.

**Layer 2 — the four-test operational-language gate** (FSD-002 §1.10.1).
Every accepted `scores` dimension must:

1. **T1 Rules / verdicts separation** — name a measurable mechanism, not a
   verdict. Dimensions containing morally-charged stems (`deception`, `harm`,
   `evil`, `bad_actor`, `trustworthiness`, `malicious`, `lies`) are refused.
2. **T2 Mechanism-descriptive naming** — same enforcement as T1.
3. **T3 Version pinning** — at least one `:v[0-9]+` segment, so a past
   verdict can be re-checked against the rule version it ran under.
4. **T4 Adjudication separation** — a measurement, not a verdict. Same
   enforcement as T1.

Refusals surface as `Error::DimensionRejected { dimension, reason }` (token
`federation_dimension_rejected`); `reason` is `morally_charged_stem` /
`missing_version_segment` / `empty_or_missing_dimension`. Sovereign
deployments extend the stem list through `DimensionAdmissionPolicy`.

The same dimension check on the four structural composers (CC 2.4 ask 3) runs
under the row-type switch above. A structural primitive carries metadata
about the attestation graph rather than epistemic content, which is what lets
a rename chain such as
`delegates_to:correlated_action_v2:from:emergent_deception_v1` reference a
now-banned legacy dimension.

### `federation_revocations`

```
federation_revocations
  revocation_id             uuid PRIMARY KEY
  revoked_key_id            text           -- the key revoked
  revoking_key_id           text NOT NULL  REFERENCES federation_keys(key_id)
  reason                    text           -- free-form
  revoked_at                timestamptz NOT NULL
  effective_at              timestamptz NOT NULL  -- may be retroactive or scheduled
  revoked_after             timestamptz    -- history bound (V118); NULL = all-or-nothing
  revocation_envelope       jsonb NOT NULL
  -- scrub-signing provenance
  original_content_hash     bytea NOT NULL
  scrub_signature_classical text NOT NULL
  scrub_signature_pqc       text
  scrub_key_id              text NOT NULL  REFERENCES federation_keys(key_id)
  scrub_timestamp           timestamptz NOT NULL
  persist_row_hash          text
```

Append-only. A revocation names its subject by the key's raw-pubkey digest as
well as its id, so `revocations_for(K)` finds every revocation of the key K
holds (CIRISPersist#784). `revoked_after` answers a second question — "does a
statement K made at T still stand?" — folded by
`federation::register::resolve_key_statement_standing`; admission refuses a
bound not mirrored in the signed envelope or later than `effective_at`.
Revocations have no hybrid-pending path: they are hybrid-signed at write.
Consumers decide what "revoked at T" means under their own policy.

---

## Trait surface

`FederationDirectory` (`src/federation/mod.rs`) is CRUD plus bounded,
paged reads. An excerpt:

```rust
#[async_trait]
pub trait FederationDirectory: Send + Sync {
    // ── Public keys ────────────────────────────────────────────
    async fn put_public_key(&self, record: SignedKeyRecord) -> Result<(), Error>;
    async fn lookup_public_key(&self, key_id: &str) -> Result<Option<KeyRecord>, Error>;
    async fn lookup_keys_for_identity(&self, identity_ref: &str) -> Result<Vec<KeyRecord>, Error>;

    // ── Attestations ───────────────────────────────────────────
    async fn put_attestation(&self, attestation: SignedAttestation)
        -> Result<AttestationOutcome, Error>;
    // Reads go through `AttestationQuery::to(key)` / `AttestationQuery::by(key)`,
    // paged and bounded (`attestation_query`), never an unbounded list.

    // ── Revocations ────────────────────────────────────────────
    async fn put_revocation(&self, revocation: SignedRevocation) -> Result<(), Error>;
    async fn revocations_for(&self, revoked_key_id: &str) -> Result<Vec<Revocation>, Error>;

    // … PQC attach, hybrid-pending listings, families, communities,
    //   occurrences, trust grants, replication cursors.
}
```

`Engine::register_federation_key` is the canonical key-registration door
(§"Write authority").

### Explicit non-goals

These methods will **not** appear on `FederationDirectory`:

- `is_trusted(key_id) -> bool` — trust is the consumer's policy
- `trust_score(key_id) -> f64` — scoring belongs above persist
- `trust_path(from, to) -> Vec<Attestation>` — graph walks belong in consumer
  policy code (persist's attestation reads expose the edges; the consumer
  composes the traversal)
- `evaluate_policy(policy, key_id) -> Verdict` — there is no policy DSL in
  persist
- `register_with_registry(...)` — persist is a peer of the registry, not a
  client of it; the registry is one writer to persist's directory among many

---

## How consumers compose policy

Persist's narrow surface is what makes the federation flexible. Three
sketches (pseudocode; `attestations_to` / `attestations_by` stand for paging
`AttestationQuery::to` / `AttestationQuery::by`):

### Policy A — direct trust

```rust
async fn is_trusted_direct(dir: &impl FederationDirectory, key_id: &str,
                           steward_key_ids: &[&str]) -> bool {
    let now = chrono::Utc::now();
    let revoked = dir.revocations_for(key_id).await.unwrap_or_default()
        .iter().any(|r| r.effective_at <= now);
    if revoked { return false; }
    attestations_to(dir, key_id).await.iter().any(|a| {
        a.attestation_type == "scores"
            && steward_key_ids.contains(&a.attesting_key_id.as_str())
            && a.expires_at.is_none_or(|t| t > now)
    })
}
```

### Policy B — referrer chain (PoB §3.1 transitive)

```rust
async fn is_trusted_transitive(dir: &impl FederationDirectory, key_id: &str,
                               root_keys: &[&str], max_depth: usize) -> bool {
    let mut frontier: VecDeque<(String, usize)> =
        root_keys.iter().map(|k| ((*k).to_string(), 0)).collect();
    let mut seen = HashSet::new();
    while let Some((current, depth)) = frontier.pop_front() {
        if depth > max_depth || !seen.insert(current.clone()) { continue; }
        if current == key_id { return true; }
        for a in attestations_by(dir, &current).await {
            if a.attestation_type == "scores" || a.attestation_type == "delegates_to" {
                frontier.push_back((a.attested_key_id, depth + 1));
            }
        }
    }
    false
}
```

### Policy C — score-weighted consensus (PoB §4 Coherence Stake)

```rust
async fn coherence_stake_score(dir: &impl FederationDirectory, key_id: &str,
                               peer_weights: &HashMap<String, f64>,
                               decay_per_hop: f64) -> f64 {
    let mut score = 0.0;
    let mut visited = HashSet::new();
    let mut frontier = vec![(key_id.to_string(), 1.0)];
    while let Some((current, scale)) = frontier.pop() {
        if !visited.insert(current.clone()) { continue; }
        for a in attestations_to(dir, &current).await {
            if let Some(&w) = peer_weights.get(&a.attesting_key_id) {
                score += w * scale * a.weight.unwrap_or(1.0);
                frontier.push((a.attesting_key_id, scale * decay_per_hop));
            }
        }
    }
    score
}
```

Same persist; three different trust models. None of the math lives in
persist.

When the registry offers "trust an agent key individually, as a referrer,
directly, or above score X", those are *registry-side* interfaces for the
registry's own consumers. The registry fetches edges from persist, runs its
chosen policy and returns a verdict. Persist's role is "the registry queries
me; I return rows."

---

## Operational contract

### Write authority — scrub-signature is auth

Persist accepts a `federation_keys` write from any caller whose row carries a
valid scrub signature whose `scrub_key_id` either chains to an anchor through
the FK chain or is itself out-of-band-anchored. The cryptographic check is
the auth check. There are no per-primitive API keys and no credential
issuance.

`Engine::register_federation_key` (`src/federation/register.rs`) is the
canonical door. It hybrid-verifies (Ed25519 + ML-DSA-65, Strict) the scrub
signature over the canonical `registration_envelope` against `scrub_key_id`'s
keys — read off the submitted record when it is self-attested
(`scrub_key_id == key_id`, proof of possession), resolved from the directory
otherwise (an unknown signer is refused). The envelope must name the key and
pubkeys it registers, so a signature cannot be lifted onto another row. Any
failure stores nothing. `put_public_key` keeps the soft-PQC window for a
hybrid-pending record.

This preserves the property PoB §3.1 needs: any peer can self-publish
without an issuance handshake. A self-published key with no attestations has
zero trust under any reasonable policy, so accepting the row is harmless.

Volume is bounded by a **per-peer write quota** ahead of the admission stack
(AV-76): an over-quota write is `Error::RateLimited { retry_after_seconds,
reason }`, where `reason` names which quota refused and in which regime.
Admission runs cheapest-first — envelope checks, then one directory read,
then crypto, then DB-walking authority checks — so a row that fails late has
not paid for work it did not need.

### Sequencing — hot-path Ed25519, cold-path ML-DSA-65

The writer contract for a row that enters through a soft-PQC door:

1. Sign the canonical bytes with Ed25519 (synchronous, hot path).
2. Write the row (PQC fields `None`).
3. **Immediately** start the ML-DSA-65 sign on the cold path — not delayed,
   not batched, just off the synchronous request path.
4. Call the matching `attach_*_pqc_signature` when it completes.

`attach_key_pqc_signature` and `attach_attestation_pqc_signature` refuse a
row that is already hybrid-complete, update the PQC fields atomically, set
`pqc_completed_at`, and recompute `persist_row_hash`. Attaching a key's PQC
half is gated at the door (`admission::check_key_pqc_attachment`): the signed
`registration_envelope` must bind the ML-DSA-65 pubkey being attached, and the
row must verify hybrid-Strict afterwards — an unverified public key is not
something a later reader can catch. An attestation attach carries no key
material; its signature is verified at the consumer's policy layer on read.

### PQC strategy

**Hybrid Ed25519 + ML-DSA-65 is the only signing scheme in the federation**
(`algorithm = 'hybrid'` on every key row). Every row converges to fully
hybrid-signed; the soft-PQC window above is the only place a row is
Ed25519-only, and only for keys and attestations. Revocations and Strict
registrations are hybrid at write.

Persist provides the API; the deployer schedules the cadence:

- `list_hybrid_pending_keys(limit)` / `list_hybrid_pending_attestations(limit)`
  feed a worker;
- `Engine.run_pqc_sweep(batch_size)` is the in-process sweep entry point;
- the worker recomputes the bound-signature input, signs with the operator's
  ML-DSA-65 signer, and calls the matching `attach_*_pqc_signature`.

Persist ships no in-band scheduler. A paused sweep shows up as a growing
`pqc_completed_at IS NULL` count.

When the threat model requires it, the runtime policy flips
(`require_pqc_on_write = true`): the kickoff folds into the synchronous path
and the PQC fields become required at write time.

**Consumer cache guidance.** Cache hybrid-complete rows at the normal TTL;
cache hybrid-pending rows at a shorter TTL (e.g. 60 seconds) so a freshly
completed row reaches the consumer quickly; treat a row pending longer than
the deployer's worst-case bound as a monitoring signal, and fail closed under
a strict-hybrid policy.

### Consumer cache and fail mode

Consumers keep their own caches; persist exposes `persist_row_hash` for
divergence checks. The registry-side knobs (`docs/FEDERATION_CLIENT.md` in
CIRISRegistry) are:

- **TTL + invalidate-on-write.** A consumer that is also a writer pre-warms
  its cache for the affected `key_id` on the write path.
- **Fail-open from cache with a hard ceiling.** When persist is unreachable a
  consumer serves from cache by default, can opt into fail-closed, and fails
  closed regardless once its cache is older than a ceiling. The ceiling
  closes the deliberate-outage attack: keeping a revoked key in cache requires
  keeping persist down longer than the ceiling, and operators get a clean
  signal to escalate before then.

---

## Replication

Directory rows replicate through persist's replication doors, not through
database-level replication. Each row class is an `EnvelopeKind` with its own
signer rule, binding, projection and **audience**
(`WIRE_VOCABULARY_KINDS.md` Part 2). Key-plane objects — keys, key
revocations, identity occurrences — travel as rows on the `Attestation` kind;
their framed carriage is retired and an inbound framed object is refused
`federation_envelope_kind_retired`.

Trust-root rows are the floor of the trust graph: the `accord_holder` rows
are baked into every node at build time (§"Bootstrap"), so a
chain ending at a holder is always a local read.

## Transport

| Shape | When it applies |
|---|---|
| **In-process** | A host process links persist: Rust callers use `Engine` and `Engine::federation_directory()`; a sibling cdylib in the same Python process uses `directory_ops_capsule` (`docs/COHABITATION.md`). |
| **Direct DB (read)** | A service reads the `federation_*` tables through the `cirislens_reader` role, relying on the columns `docs/PUBLIC_SCHEMA_CONTRACT.md` marks stable. Writes always go through persist's doors. |
| **Between nodes** | Persist's replication doors (above). |

Persist runs no gRPC server.

### Error surface

| Error | Token | Meaning |
|---|---|---|
| `Error::Conflict(String)` | `federation_conflict` | The write collides with an existing row; the message names it. |
| `Error::RateLimited { retry_after_seconds, reason }` | `federation_rate_limited` | Over a write quota; `reason` names which one. |
| `Error::AccordDimensionRequiresAccordHolder { dimension, identity_type }` | `federation_accord_dimension_requires_accord_holder` | The `accord:*` × `accord_holder` rule. |
| `Error::DimensionRejected { dimension, reason }` | `federation_dimension_rejected` | The four-test operational-language gate. |
| `Error::ReservedPrefixEmitterMismatch` | `federation_reserved_prefix_emitter_mismatch` | A reserved prefix from an attester without the required role. |

All map to caller fault (4xx) at the PyO3 / HTTP surface.
