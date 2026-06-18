# CIRISPersist Threat Model

**Status:** v9.0.0 (CIRIS Constitution 0.1.5 alignment cut; CEG
1.0-RC17 — §19 / §19.7 holonomic substrate). Earlier surface preserved
verbatim: federation
directory (v0.2.0), hybrid Ed25519+ML-DSA-65 PQC posture (v0.2.0),
2.7.9 wire-format extensions (v0.3.0–v0.3.4), per-key DSAR + the
`verify_hybrid` arbitrary-canonical-bytes surface (v0.3.6),
outbound queue / read primitives / panic isolation (v0.4.0–v0.5.3),
graph/audit/TSDB/incident substrates (v0.8.x), cohort_scope
read/write gates (v4.0). The v7.2.0–v8.5.0 cut adds the **store-path
PQC hard cut** (#225) and the **holonomic / forever-memory**
substrate (#227–#231): the fountain content primitive, the §19.1
WholenessWitness corpus + divergence router, and the §19.7
aggregation pyramid — §3.14, AV-59..AV-66.
**v0.1.2 baseline** (AV-1..AV-26) preserved verbatim;
v0.2.0–v0.3.6 attack surface in §3.7..§3.10 (AV-28..AV-39);
holonomic surface in §3.14 (AV-59..AV-66);
constitution-alignment surface in §3.15 (AV-67..AV-72) — PQC-mandatory
federation-tier per-trace ingest (CC 5.3.2.4.3.1), the node/agency
delegation split (CC 4.4.3.4.3 / CC 1.13.5), owner-binding community
membership (CC 3.2), the community-DEK rotation cascade (CC 4.4.3.2.2),
and the four adversarial-review bypasses those gates initially carried.
**RC17 compliance:** persist is COMPLIANT and rolls no §19 crypto —
it calls verify-core's `compute_merkle_root` / `verify_witness` /
`verify_aggregation_meta` / `verify_member_commitment` /
`ejection_verdict`. The §19.1 Merkle scheme was **frozen at RC15**
(NO RFC-6962 `0x00`/`0x01` prefix); CVE-2012-2459 odd-node
malleability is non-exploitable here (every witness /
`member_commitment` root is mandatorily hybrid-signed,
`member_commitment` is verified by full source-id-list recomputation
not partial inclusion proofs, and reconciliation is between
accountable signed equivocation-checked peers — see §3.14). Persist
inherits this and does not roll Merkle. The additive
`EjectAggregatedTierOnly { tier }` `EjectionVerdict` variant
(RC16) is **consumed as of v8.6.0** (verify-core v5.11.0 exposes it):
persist drives the tier-granular pyramid-stratum evict
(`evict_aggregated_tier`) — shed exactly one stratum, finer + coarser
tiers intact, composes with hard-delete (never resurrects erased content).
Updated each minor release.
**Audience:** lens / edge / registry / partner-site integrators,
federation peers, security reviewers.
**Companion:** [`MISSION.md`](../MISSION.md), [`FSD/CIRIS_PERSIST.md`](../FSD/CIRIS_PERSIST.md).
**Inspired by:** [`CIRISVerify/docs/THREAT_MODEL.md`](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/THREAT_MODEL.md) — the structural template.

---

## 1. Scope

### What CIRISPersist Protects

CIRISPersist is the lens-side ingest substrate (Phase 1) and, by trait
shape, the agent-side persistence service (Phase 2/3). It protects:

- **Corpus integrity**: every persisted trace was provably produced
  by the claimed agent at the claimed moment, OR is rejected. There
  is no third state. The federation's PoB §2.4 N_eff measurement
  depends on this — forged traces in the corpus would degrade the
  Sybil-resistance signal the Federated Ratchet rests on.
- **Idempotency**: agent retries (TRACE_WIRE_FORMAT.md §1: up to
  10× batch_size events deep) cannot inflate corpus counts. The
  dedup key `(trace_id, thought_id, event_type, attempt_index, ts)`
  with `ON CONFLICT DO NOTHING` is the structural guarantee.
- **Privacy at trace tier**: PII never crosses the persistence
  boundary at trace levels where it isn't warranted. `generic` is
  content-free by design; `detailed`/`full_traces` route through a
  scrubber boundary.
- **Backpressure honesty**: agents get structured 429 + Retry-After
  on saturation, never silent drop. The agent's own retry buffer
  (TRACE_WIRE_FORMAT.md §1) closes the loop.
- **Outage tolerance**: backend failure does not lose signed
  evidence. The redb journal preserves the agent-shipped bytes
  byte-exact for replay (FSD §3.4 #2).
- **Audit anchor capture**: the agent's per-action audit-chain link
  is captured on every `ACTION_RESULT` row (FSD §3.2). Anchor
  *verification* against the agent-side audit log is Phase 2's
  peer-replicate work.
- **Memory-safe parsing of untrusted bytes**: Rust's static
  guarantees at the wire edge close the recurring CVE class for
  network-facing services (MISSION.md §2 — `server/`).
- **(NEW v0.1.3) Cryptographic provenance of deployment handling**:
  every persisted row carries a four-tuple envelope
  (`original_content_hash`, `scrub_signature`, `scrub_key_id`,
  `scrub_timestamp`) that proves *this specific deployment processed
  this specific payload at this specific time*. Always present —
  every component, every trace level, key never null (FSD §3.3 step
  3.5 + §3.4 robustness primitive #7). The federation primitive
  PoB §3.1 — "the lens role is a function any peer can run on data
  the peer already has" — becomes cryptographically attestable.
  Bilateral cryptography: agent's wire-format §8 signature proves
  authorship, lens's v0.1.3 scrub envelope proves handling.
- **(NEW v0.1.3) Single-key federation identity**: the scrub-signing
  key is also the deployment's Reticulum destination
  (`SHA256(public_key)[..16]`, PoB §3.2 — addressing IS identity)
  and the registry-published public key. One key, three roles.
  No separate "network identity" key; no translation layer
  between cryptographic provenance and federation transport.
- **(NEW v0.2.0) Federation directory substrate**: `federation_keys`
  + `federation_attestations` + `federation_revocations` provide a
  shared pubkey + attestation + revocation directory across the
  federation. Persist holds the substrate; consumers compose
  policy. No `is_trusted()` / `trust_score()` methods; consumers
  walk the attestation graph however they want
  (`docs/FEDERATION_DIRECTORY.md` §"Explicit non-goals").
- **(NEW v0.2.0) Hybrid Ed25519 + ML-DSA-65 signing**: every
  federation row carries a four-tuple bound signature — Ed25519
  classical (always present), ML-DSA-65 PQC (cold-path filled).
  PQC signs `(canonical || classical_sig)` so an attacker who
  breaks Ed25519 cannot strip-and-replace the PQC component.
  Persist owns the cold-path tokio task (v0.3.1) + the sweep
  primitive (v0.3.2) so consumers can't drift on the bound-
  signature contract.
- **(NEW v0.3.0) Deterministic dispatch by `trace_schema_version`**:
  canonical reconstruction picks exactly one path based on the
  signed `trace_schema_version` field. No iterative try-N-shapes
  fallback; no shape-shopping attack surface; no spurious-sig-fail
  SHA-256+verify latency multiplier under load. The dispatch key
  is part of the signed canonical bytes, so an attacker cannot
  forge it without breaking the signature.
- **(NEW v0.3.0) Cross-shape field injection defense**: per-component
  `agent_id_hash` (v0.3.0) and `deployment_profile` (v0.3.4) are
  silently ignored at `trace_schema_version "2.7.0"` — they don't
  enter the 2.7.0 canonical reconstruction even if present on the
  wire. An attacker injecting future-shape fields into a 2.7.0
  envelope produces byte-identical canonical bytes vs no-injection;
  the injection has no effect on signed verification or dedup.
- **(NEW v0.3.4) deployment_profile cohort identity in canonical
  bytes**: `agent_role` / `agent_template` / `deployment_domain` /
  `deployment_type` / `deployment_region` / `deployment_trust_mode`
  ride in the 2.7.9 signed canonical bytes. Cohort labels are
  non-forgeable post-emission; the agent's signature commits to
  them. Lens cohort routing reads denormalized columns on
  `trace_events` with cryptographic provenance.
- **(NEW v0.3.6) Per-key DSAR authorization scope**:
  `Engine.delete_traces_for_agent(agent_id_hash, signature_key_id)`
  scopes deletion to `(agent_id_hash, signing_key_id)`. The
  signature_key_id is the *authorization scope* of the DSAR
  (a request signed by key A is only authorized to delete traces
  signed by key A) — not just an identity filter. No `Option<>`
  back-compat shim; per-key is the only contract.
- **(NEW v0.3.6) verify-via-persist single-source-of-truth**:
  `Engine.verify_hybrid` exposes hybrid Ed25519+ML-DSA-65 verify
  for arbitrary canonical bytes via persist's policy machinery
  (`HybridPolicy::Strict` / `SoftFreshness { window }` /
  `Ed25519Fallback`). Federation peers consume verify through
  persist, not via direct `ciris_crypto` access — the architectural
  closure CIRISPersist#7 named (one canonicalization expectation,
  one policy machinery, no drift across N consumers).

### What CIRISPersist Does NOT Protect (Phase 1)

- **Agent-side key compromise**: if an agent's Ed25519 signing key
  is leaked or coerced, an adversary can produce indistinguishable
  forged traces under that agent's identity. The federation's
  N_eff and σ-decay metrics over time will eventually surface
  anomalies (PoB §2.4 + §5.6), but the persistence layer cannot
  detect forgery from a stolen-but-valid key at write time.
- **Network-edge TLS / certificate infrastructure**: HTTPS termination
  is the lens deployment's concern. CIRISPersist does not pin
  certificates or verify TLS state.
- **Postgres-server compromise**: the persistence backend is
  trusted. If Postgres or the redb journal disk are compromised,
  the threat model breaks.
- **Audit-chain re-verification (Phase 1)**: anchor fields are
  captured but not cross-checked against the agent's audit_log.
  Phase 2 peer-replicate (FSD §4.5) closes this.
- **Pre-cutover corpus integrity**: `accord_traces` retains
  pre-cutover history with whatever properties the previous lens
  pipeline gave it. CIRISPersist makes no claims about that table.
- **Cross-tier privacy bridging**: a `generic`-tier trace co-
  resident in the same DB as a `full_traces` trace is not a
  CIRISPersist concern. Lens-side query authorization is the lens's
  job.
- **Phase 3 surfaces**: agent runtime state, memory graph, and
  governance tables are part of the Backend trait but unimplemented
  in v0.1.x. Their threat model is sketched here for forward
  compat; the active surface is Phase 1.

---

## 2. Adversary Model

### Adversary Capabilities

The adversary is assumed to have:

- **Full source-code access** (AGPL-3.0; public).
- **Ability to mint arbitrary Ed25519 keypairs** and sign anything.
- **Ability to run their own agents** on the network — including
  registering public keys via the standard `accord/agents/register`
  flow.
- **Network access to the lens HTTP endpoint**, including the
  ability to send arbitrary bytes to `/api/v1/accord/events`.
- **Replay capability**: capture any in-transit batch and re-send
  it at any point.
- **Network MITM** between an honest agent and the lens, with
  ability to drop, delay, or modify bytes if not protected by TLS.
- **Limited side-channel observation**: response timing,
  HTTP status codes, error message bodies.
- **Ability to read public CI artifacts**: every test output,
  every published wheel, the deny.toml + dep tree.
- **Compute resources sufficient for classical cryptography** (but
  not for breaking Ed25519 within current physics).

### Adversary Limitations

The adversary is assumed to NOT have:

- **The ability to break Ed25519** within polynomial time on
  classical hardware. (PoB §6 acknowledges quantum risk; ML-DSA-65
  hybridization is Phase 2+.)
- **Compromised the public-key directory**: the lens's
  `accord_public_keys` table. If the directory is owned, every
  signature verification is meaningless. The directory is part of
  the lens deployment trust boundary.
- **Compromised any honest agent's signing key**: if they did, see
  §1 "What CIRISPersist Does NOT Protect (Phase 1)" — that's
  out-of-scope at the persistence layer.
- **Compromised the Postgres backend** that the lens writes to.
- **Compromised the redb journal disk** location (default
  `/var/lib/cirislens/journal.redb`).
- **Physical access** to the lens deployment hardware.
- **Ability to read TLS-encrypted traffic** between the agent and
  the lens. (TLS termination is upstream of CIRISPersist; if it's
  off, that's a deployment misconfiguration.)
- **Quantum compute** capable of breaking Ed25519 today. (Tracked
  in §8 Residual Risks; Phase 2+ adds ML-DSA-65 hybrid signatures
  per PoB §6.)

---

## 3. Attack Vectors

Seventy-two attack vectors organized by adversary goal. AV-1..AV-26
are the v0.1.x baseline (preserved verbatim from the v0.1.2 doc).
AV-27 covers v0.1.7..v0.1.9 keyring-storage hardening. AV-28..AV-39
cover the v0.2.0..v0.3.6 surface (federation directory, hybrid PQC,
cross-shape injection, cohort identity, per-key DSAR,
`verify_hybrid` arbitrary-canonical-bytes). AV-40..AV-58 cover the
v0.4.0..v4.0 surface (outbound queue, legacy schema, read primitives,
panic isolation, §6.1/§7.0/§10.1.2 composition gates, graph/audit/TSDB/
incident substrates, cohort_scope read/write gates). AV-59..AV-66
(§3.14) cover the v7.2.0..v8.5.0 holonomic / forever-memory surface
(store-path PQC hard cut, WholenessWitness equivocation /
divergence-router / anti-rollback / WW-2 leaf filter, aggregation-meta
and member-commitment integrity, rarity-vs-revocation). AV-67..AV-72
(§3.15) cover the v9.0.0 CIRIS Constitution 0.1.5 alignment surface
(PQC-mandatory federation-tier per-trace ingest, the node/agency
delegation split, owner-binding community membership, community-DEK
rotation, and the four adversarial-review bypasses those gates carried).
Each AV lists the attack, the primary mitigation, the secondary
mitigation, and the residual risk.

### 3.1 Forgery — adversary wants their bytes counted as real evidence

#### AV-1: Forged trace from attacker-minted key

**Attack**: Attacker generates a fresh Ed25519 keypair, signs a
synthetic CompleteTrace with it, submits to `/api/v1/accord/events`.

**Mitigation**: Public-key directory lookup before verification.
The `signature_key_id` in the trace must resolve to a registered
key in `cirislens.accord_public_keys`. Unknown keys → typed
`UnknownKey` error → HTTP 422 → zero rows persisted. Attacker
must register their key id through the lens's
`accord/agents/register` flow first, which is gated by the lens's
own admission policy (out of scope for CIRISPersist; it's the
lens's policy lever per Annex E of the Accord).

**Secondary**: Per-agent N_eff drift over time. A fresh-keyed
"agent" with no behavioral history fails the σ-decay floor and PoB
§2.4 codimension before it earns federation standing. CIRISPersist
provides the substrate the lens scoring layer measures over.

**Residual**: An attacker who can register a key id (e.g., as a
sovereign-mode agent) and produce 30 days of N_eff > 9 trace
behavior earns standing. That's *exactly* the cost-asymmetry PoB
§2.1 names — running real ethical-reasoning is what the network
asks of every member.

#### AV-2: Forged trace using compromised legitimate key

**Attack**: Attacker exfiltrates an honest agent's signing key
(via Phase 2/3 secrets-manager compromise, key-material leak in
backups, social engineering, etc.), signs a malicious trace under
that agent's identity.

**Mitigation**: **Out of CIRISPersist's protection scope.** The
persistence layer cannot distinguish a stolen-key signature from a
legitimate one — both verify against the same registered public key
by construction. The federation N_eff / σ time-series provides
*statistical* drift detection (anomalous behavior under a stable
identity), but at write time the lens accepts.

**Secondary**: The agent's audit-log chain (captured as the audit
anchor on every `ACTION_RESULT` row, FSD §3.2) provides
post-incident forensics. Phase 2 peer-replicate (FSD §4.5)
cross-validates the chain link against the agent's local audit_log,
making chain-tampering detectable.

**Residual**: Until Phase 2 closes peer-replicate verification,
key-compromise-then-forgery is undetectable at ingest. The agent's
local secrets manager + hardware-backed key storage (CIRISVerify's
threat model is the relevant document) is the upstream mitigation.

#### AV-3: Replay of captured legitimate batch

**Attack**: Network MITM captures a valid signed batch in transit,
replays it (or a slightly modified copy) to the same lens later.

**Mitigation**: Idempotency on
`(trace_id, thought_id, event_type, attempt_index, ts)` UNIQUE
index. Re-submitting the same batch produces 0 inserts +
N conflicts (verified by `idempotent_replay` test). Inserted-vs-
conflicted counts in `BatchSummary` surface to ops dashboards.

**Secondary**: TLS at the deployment edge prevents capture in
the first place; this is a deployment concern, not CIRISPersist's.

**Residual**: A captured batch *replayed against a different lens
deployment* (e.g., a federation peer that hasn't seen it yet) lands
once, by design. That's what trace replication is supposed to do
(FSD §4.4 / PoB §5.1). Per-peer dedup is each peer's local
guarantee.

#### AV-4: Canonicalization-mismatch attack

**Attack**: Adversary exploits a byte-difference between what the
agent's signer canonicalizes and what the lens's verifier
canonicalizes. Either:
- Submit bytes the lens accepts but the agent never signed
  (verifier produces *different* canonical bytes that happen to
  hash to a valid pre-existing signature — preimage attack on
  Ed25519 is computationally infeasible).
- Submit bytes the agent signed but the lens rejects (DoS — bytes
  the agent has paid to produce get dropped).

**Mitigation**:
- The 14 byte-exact canonicalization parity tests in
  `verify::canonical::tests`. Each cross-checked against
  `python3 -c "import json; json.dumps(...)"` ground truth.
- Pluggable `Canonicalizer` trait so the agent + lens stay in sync
  on conventions (Python `json.dumps(sort_keys=True,
  separators=(',', ':'))` today; RFC 8785 JCS reserved for the
  agent-flips path).
- Real-fixture integration suite (`tests/wire_format_fixtures.rs`)
  exercises actual signed traces from CIRISAgent `release/2.7.8`.

**Secondary**: Ed25519's collision and preimage resistance bound
the "produce different bytes that verify" branch to
2^128 work — practically infeasible.

**Residual**:
- **Float canonicalization drift** (CRATE_RECOMMENDATIONS §2.9).
  Python's `repr(float)` and Rust's `ryu` agree on shortest
  round-trip-able output for the common cases but may differ on
  edge cases. The wire format §8 doesn't include floats in the
  *outer* canonical fields, but per-component `data` payloads
  carry floats (durations, scores). A deliberately constructed
  float in agent-shipped bytes that round-trips through Rust to a
  different string would fail verify silently. Status: not
  triggered by any production fixture; track if a real
  divergence appears in the corpus.
- **Timestamp formatting drift** (`verify::ed25519::format_iso8601`).
  ✓ **CLOSED v0.1.8**. Was: re-format `DateTime<Utc>` via chrono's
  `%.6f%:z` for canonicalization, which always emitted six
  microsecond digits. Python's `datetime.isoformat()` drops the
  fraction entirely when microseconds==0, so a wire timestamp of
  `2026-04-30T00:15:53+00:00` became `2026-04-30T00:15:53.000000+00:00`
  on the verify side, canonical bytes diverged, signature rejected.
  Hit lens production cutover. v0.1.8 closes by adding
  `schema::WireDateTime` — wraps `(raw: String, parsed: DateTime<Utc>)`
  with `Serialize` emitting the raw bytes verbatim. Replaces
  `DateTime<Utc>` in `CompleteTrace.{started_at, completed_at}`
  and `TraceComponent.timestamp`. `canonical_payload_value` now
  reads `.wire()` instead of `format_iso8601(&parsed)`.
  Regression coverage: `tests/av4_timestamp_round_trip.rs` (5
  scenarios including the production-bug zero-microsecond shape).

### 3.2 Denial of Service — adversary wants the lens unable to receive evidence

#### AV-5: Schema-version flood (memory leak DoS) **[v0.1.1 exposure]**

**Attack**: Adversary submits a stream of bodies with malformed
`trace_schema_version` strings (random 64-byte strings, etc.).
Each rejected version path runs `parse_lenient` which
`Box::leak`s the unrecognized string into `&'static str` for
diagnostic purposes (`src/schema/version.rs:94`). Memory grows
unboundedly per request.

**Mitigation in v0.1.1**: **None.** The leak is real and exploitable.

**Recommended hot-fix for v0.1.2**: replace the `Box::leak` path with
an owned `String` variant on `SchemaVersion` (or a separate
`UnrecognizedSchemaVersion` typed-wrapper passed through the error
path). Cost: ~30 minutes; touch `version.rs`, `envelope.rs::from_json`.

**Secondary mitigation today**: deploy behind a rate limiter at the
lens's HTTPS termination layer (nginx, Envoy, etc.) capping
requests-per-source-IP. Mitigates the rate but not the
memory-amplification ratio.

#### AV-6: JSON-bomb / deserialization amplification

**Attack**: Adversary submits a JSON body with deeply nested
structure (`[[[[...]]]]` 10000 deep) or a single key with a
1GB string value. `serde_json` by default has no depth limit and
parses into `serde_json::Value` for the `data` blobs. Memory
allocation amplification.

**Mitigation in v0.1.1**: **Partial.**
- The bounded queue (`DEFAULT_QUEUE_DEPTH=1024`) prevents
  *throughput* amplification — only N bodies in flight at once.
- The schema at the typed level forces concrete struct shapes
  (`BatchEnvelope`, `CompleteTrace`, etc.) — depth-bombs in the
  *envelope* fail at typed deserialize.
- However, the per-component `data` field is
  `serde_json::Map<String, serde_json::Value>` — deeply nested
  JSON inside `data` *will* parse and allocate.

**Recommended hot-fix for v0.1.2**:
- Set max body size at the axum extractor layer:
  `.layer(DefaultBodyLimit::max(8 * 1024 * 1024))` (8 MiB matches
  the largest production fixture's `full_traces` 3 MiB with 2.6×
  headroom).
- Add a recursion-depth guard in the typed accessor that walks
  `data` (e.g., reject `data` JSON deeper than 32 levels).

**Secondary**: deployment-edge body-size limit at the proxy layer.

**Residual**: an attacker with a registered, accepted public key
who submits inflated-but-syntactically-valid bodies pays the
cost-asymmetry PoB §2.1 names — they're spending real LLM cost to
inflate the corpus, and N_eff measurement detects this as
behavioral drift.

#### AV-7: Body-size flood (no max body limit) **[v0.1.1 exposure]**

**Attack**: Adversary submits arbitrarily large bodies. axum's
`Bytes` extractor reads the entire body into memory before queue
submission.

**Mitigation in v0.1.1**: **None at the crate level.** The lens's
deployment-edge proxy (nginx, HAProxy, etc.) typically caps body
size at 1-100 MiB; this is a defense-in-depth gap, not a guaranteed
exposure.

**Recommended hot-fix for v0.1.2**: explicit
`DefaultBodyLimit::max(N)` on the axum router. Match the operational
maximum (3-10 MiB based on production fixture sizes).

#### AV-8: Queue saturation

**Attack**: Adversary floods the endpoint to fill the bounded
mpsc channel.

**Mitigation in v0.1.1**: 429 + Retry-After on `QueueError::Full`.
The agent already retries up to 10× batch_size deep
(TRACE_WIRE_FORMAT.md §1); legitimate flow stays correct under
saturation.

**Secondary**: the persister task is a single consumer with a
journal-on-Postgres-failure path — backpressure surfaces at the
bottleneck (the DB), not at the queue boundary.

**Residual**: an attacker with high request rate denies service to
honest agents. Rate limiting per source IP at the deployment edge
is the standard defense; not CIRISPersist's responsibility.

### 3.3 Corruption — adversary wants false data persisted or true data dropped

#### AV-9: Idempotency-key collision across agents

**Attack**: Two distinct agents submit batches that share
`(trace_id, thought_id, event_type, attempt_index)`. The second
arrival hits ON CONFLICT DO NOTHING and is silently skipped.

**Mitigation in v0.1.1**: **Partial.** The dedup key does NOT
include `agent_id_hash` or `signature_key_id`. The wire-format
spec (TRACE_WIRE_FORMAT.md §3) mandates `trace_id` is "Globally
unique per agent" — `trace-<thought_id>-<YYYYMMDDHHMMSS>` —
relying on `thought_id` being agent-unique. If a malicious agent
reuses another agent's `thought_id` shape, they could DOS the
victim's traces.

**Recommended hot-fix for v0.1.x**: extend the dedup key to
include `agent_id_hash` (or `signing_key_id`) at the SQL UNIQUE
index level. SQL change: drop the existing
`trace_events_dedup` UNIQUE index, recreate as
`(agent_id_hash, trace_id, thought_id, event_type, attempt_index,
ts)`. Migration `V003__dedup_key_includes_agent.sql`. The
in-memory backend's `events` HashMap uses the same key shape.

**Secondary**: each agent's `agent_id_hash` is sha256-prefix of
the agent's pubkey (TRACE_WIRE_FORMAT.md §3). Two distinct
agents producing colliding `trace_id`s + thought_ids requires
hash collision OR coordinated namespace attack — both cost-
asymmetric.

**Residual**: until the dedup key extends, a coordinated
attacker can DOS specific victims by pre-claiming their dedup
tuples.

#### AV-10: Audit anchor injection

**Attack**: Attacker (with a registered key) submits a trace
with crafted `audit_sequence_number`/`audit_entry_hash` that
will conflict with a future legitimate ACTION_RESULT row,
forcing dedup to skip the legitimate one.

**Mitigation in v0.1.1**: **Partial.** The audit anchor fields
are NOT part of the dedup key. They're columns on the
`trace_events` row, populated only on the ACTION_RESULT row. The
dedup key (per AV-9 above) is the trace shape; anchor is
auxiliary. Two ACTION_RESULT rows with same dedup tuple but
different anchors: the second is skipped, anchor mismatch is
post-facto detectable.

**Phase 2** (FSD §4.5 peer-replicate): the agent's audit_log
chain provides cross-validation. A row with an anchor that
doesn't match the agent's claimed chain link → flagged for
review.

**Residual**: under Phase 1, anchor field is captured-but-not-
verified. Treat it as "data preserved for Phase 2 cross-check,"
not "data the lens trusts today."

#### AV-11: Public-key directory poisoning via re-registration **[v0.1.1 design point]**

**Attack**: An attacker who can call `register_public_key` (the
PyO3 Engine method) submits the same `signature_key_id` an
honest agent already registered, but with a different public
key. The current SQL is:

```sql
INSERT INTO cirislens.accord_public_keys
  (signature_key_id, public_key_b64, agent_id_hash)
  VALUES ($1, $2, $3)
  ON CONFLICT (signature_key_id) DO NOTHING
```

ON CONFLICT DO NOTHING means re-registration is silently
ignored — the original key wins. This is the *correct* behavior
for an attacker trying to overwrite, but it's **also the wrong
behavior** if the legitimate agent is rotating keys.

The doc currently says: "Re-registering a *different* key for
the same id is treated as the agent's choice — no rotation alarm
yet; that's a follow-up for v0.2.x."

**Mitigation in v0.1.1**: **The first key wins; subsequent
re-registrations are silently ignored.** That blocks the attacker
*and* blocks legitimate rotation. Asymmetric-bad: the lens
operator's registration tooling needs to manually
`UPDATE accord_public_keys` for legitimate rotation, with whatever
out-of-band authorization gates the lens deployment requires.

**Recommended for v0.2.x**: explicit rotation API. Two methods:
- `register_public_key` — INSERT-only; rejects on conflict.
- `rotate_public_key(signature_key_id, new_key_b64,
  rotation_proof: signed-by-old-key statement)` — verifies the
  rotation request is signed by the *old* key, then updates.
- A `revoked_at` timestamp column already exists in V001 but is
  not exercised; revocation API is a sibling.

**Residual**: today, key rotation requires the lens operator to
issue a manual UPDATE — that's a security feature (no automated
rotation under attacker control), but it's an operational
papercut.

#### AV-12: Schema-version downgrade

**Attack**: An attacker convinces the lens to treat a future
agent's v2.8.0 batch as v2.7.0, exploiting a known v2.7.0 weakness
that v2.8.0 fixed.

**Mitigation in v0.1.1**: **Strong.** `SUPPORTED_VERSIONS` is a
strict allowlist (`["2.7.0"]`). Out-of-set versions hit HTTP 422.
There is no "best-effort" / "downgrade-and-try" branch. To accept
v2.8.0, the lens must upgrade `ciris-persist` to a release that
extends the constant — which is a deliberate operator decision.

**Residual**: when v2.7.0 and v2.8.0 are *both* in
`SUPPORTED_VERSIONS` (the rolling-deploy window per FSD §10
Phase 3), an attacker who can inject the version field could
target the older path. Mitigation at that point: ensure each
version's payload-shape gate is independent — a v2.8.0 payload
labeled v2.7.0 must fail typed deserialize. Track for the actual
version-bump PR.

#### AV-13: Cross-trace JSONB injection (Phase 3 surface)

**Attack**: An attacker submits a `data` blob crafted to
exploit a future SQL query that reaches into the JSONB column.

**Mitigation in v0.1.1**: payload is stored as parameterized
JSONB via tokio-postgres typed binding. There is no string
interpolation of payload content into SQL. SQL injection at the
INSERT layer is structurally not possible.

**Phase 3 risk**: queries that *read* the JSONB (e.g.,
`payload->>'audit_sequence_number'`) need parameterized binding
on the JSONB-path operands too. Track at Phase 3 scope.

### 3.4 Privacy — adversary wants content text exposed at a tier where it isn't warranted

#### AV-14: Scrubber bypass via schema-altering callback

**Attack**: An attacker who controls the lens's scrubber
callable returns a modified envelope that drops `trace_level`
from `full_traces` to `generic`, bypassing the next layer's
content-handling assumptions.

**Mitigation in v0.1.1**: the engine validates scrubber output:
- `trace_schema_version` must match input
- `trace_level` must match input
- `events[]` length and per-event discriminants must match
- Violation → typed `ScrubError::External` → HTTP 422

Only payload *content* is scrubber-mutable.

**Secondary**: if the scrubber itself is compromised, the Python
process security boundary is the upstream concern. CIRISPersist
trusts the callable it was constructed with.

**Residual**: a malicious scrubber that modifies content in
ways that drop *necessary* signal (e.g., zeroing all
`coherence_score` floats) corrupts the corpus without altering
schema. Detection is post-facto via N_eff / PC1 anomaly
detection at the lens scoring layer.

#### AV-15: PII leak via error messages

**Attack**: An error path includes content from the request
body in the error message, leaking PII into logs / HTTP error
responses.

**Mitigation in v0.1.1**: **Partial.** Audit findings:
- `Error::UnsupportedSchemaVersion { got, ... }` includes the
  attacker-submitted version string. **Today this is bounded**
  (typed string from the JSON parse), but if an attacker can
  inject newlines or terminal escape sequences, they leak into
  log output. Sanitize with `.escape_debug()` before logging.
- `Error::FieldTypeMismatch { field, expected, got }` includes
  the type name — never the value. ✓
- `Error::Json(serde_json::Error)` — serde_json's error
  formatter includes ~30 chars of context around the parse
  error. For a `data` blob containing PII, that context could
  leak a fragment. **Mitigate** with a `Display` wrapper that
  strips snippets in production builds.
- `Error::Backend(String)` — Postgres error messages are
  included verbatim. Postgres's error formatter can leak
  schema names + sometimes parameter values. Already public in
  the deployment, but worth keeping out of HTTP 500 response
  bodies.

**Recommended hot-fix for v0.1.2**: introduce a
`Display::sanitize_for_response()` mode that emits only the
typed-error variant name + a stable opaque id, with the full
context kept in tracing-only logs. The HTTP error response
becomes `{"detail": "schema_version_unsupported",
"correlation_id": "uuid"}`; the log keeps the verbose form.

#### AV-16: Side-channel timing on verify

**Attack**: Adversary measures response time differences to
distinguish "unknown key" vs "known key + wrong signature" vs
"known key + right signature, wrong canonical bytes" — gleaning
information about the public-key directory or the
canonicalization pipeline.

**Mitigation in v0.1.1**: **Partial.** Ed25519 `verify_strict` is
constant-time over the signature/key path. However:
- The public-key directory lookup short-circuits on
  unknown-key (returns before signature math runs). Timing leaks
  membership.
- Canonicalization bytes are deterministic per input but
  *length* differs based on payload size — observable.

**Recommended for v0.2.x**: constant-response-time wrapper that
sleeps to a P99 budget on the rejection path. Not free
operationally (latency tax on the happy path too if
implemented naïvely) — track as research-grade hardening.

**Residual**: a network-adjacent attacker can probably enumerate
`signature_key_id`s via timing oracle. The federation primitive
treats `signature_key_id` as public anyway (it's emitted on
every trace), so directory enumeration is not a high-impact leak.

### 3.5 Provenance — adversary wants to forge "deployment handled this" attestation

These vectors are introduced by v0.1.3's always-on scrub-signing
contract (FSD §3.3 step 3.5 + §3.4 robustness primitive #7). The
contract turns the `pii_scrubbed = true` boolean column from a
*trust* claim into a *verifiable* claim — every persisted row
carries cryptographic proof of the deployment's handling.

#### AV-24: Lens-scrub bypass / forgery

**Attack**: An adversary with row-level write access to the
lens's Postgres (compromised lens process, malicious DB
operator, etc.) inserts rows with `pii_scrubbed = true` but no
matching `scrub_signature` — or with a scrub_signature signed by
a key the federation doesn't recognize. Downstream peers reading
these rows treat them as legitimately-handled.

**Mitigation in v0.1.3**: every persisted row from v0.1.3's
pipeline carries a four-tuple envelope (`original_content_hash`,
`scrub_signature`, `scrub_key_id`, `scrub_timestamp`).
Downstream peers verify `ed25519_verify(scrub_signature,
canonical(payload), known_pubkey_for(scrub_key_id))` before
trusting the row's provenance. Rows with NULL envelope columns
or an unrecognized `scrub_key_id` are flagged and not counted
in the federation primitive's N_eff measurement.

The signing key is the deployment's own — a malicious operator
who controls the lens process *also* controls the signing key
(or, with hardware-backing, the keyring access path), and can
mint apparently-valid envelopes. This is the same trust boundary
as agent-side AV-2 (compromised key); the persistence layer
cannot detect bytes signed by the legitimate key under
adversarial control. Downstream PoB N_eff drift detection
(behavioral anomaly over time) is the federation-level
mitigation.

**Secondary**: the lens publishes its public key to the
registry / lens-discovery layer at deploy time. A peer fetching
rows can cross-check `scrub_key_id` against the registry's
roster of legitimate lens keys; rows signed by a key not in the
registry are quarantined.

**Residual**: a compromised lens with legitimate keyring access
can mint envelopes that *look* valid. Detection is statistical
(N_eff drift over time) rather than pointwise — the same residual
the agent-side AV-2 has. PoB §6 framing applies.

#### AV-25: Scrub-key compromise

**Attack**: An adversary extracts the deployment's signing-key
seed from the host's filesystem / memory / debug interface and
mints arbitrary envelopes under that key. Forged "deployment X
processed payload Y at time Z" attestations the federation
treats as legitimate.

**Mitigation in v0.1.3**: `ciris-keyring` (CIRISVerify's Rust
crate) stores the seed in OS-keyring backed by hardware where
available — Linux Secret Service / TPM 2.0; macOS Keychain /
Secure Enclave; iOS / Android StrongBox; Windows DPAPI / TPM.
The Python process never holds the seed bytes; the seed never
crosses the FFI boundary. Hardware-backed deployments require
physical access (and on most platforms, exploitation of an
enclave-grade vulnerability) to extract.

**One key, three roles** (PoB §3.2): the scrub-signing key is
*also* the deployment's Reticulum destination address (Phase 2.3)
*and* the registry-published public key. Compromise the key,
you compromise all three roles simultaneously — cryptographic
provenance, federation transport address, registry identity.
This tripled cost-asymmetry is what makes hardware-backed
keyring entries materially stronger than software-only seeds:
losing the key isn't just "rows you signed are now suspect" but
"your peer-to-peer address is now hijacked AND your registry
entry needs revocation." The federation primitive's
self-application of risk (PoB §2.1: the cost of being a real
member is the cost of *being attacked* if your key leaks)
strengthens the operational case for hardware backing.

**Secondary**: `ciris-keyring`'s `SoftwareSigner` fallback exists
for dev / sovereign deployments without hardware backing. The
seed is in OS-keyring on disk — root access on the host can
extract it. Named residual; mitigation is operational
(avoid software-fallback in production, prefer hardware-attested
deployments).

**Residual**: software-backed deployments have no key isolation
beyond OS keyring file permissions. Mitigations are
deployment-level (full-disk encryption, restrict who has root,
short-lived keys with rotation through the registry's
revocation surface). CIRISVerify's threat model §5 — Security
Levels by Hardware Type — is the authoritative classification
of what each backing tier provides.

#### AV-26: Multi-worker migration race

**Attack surface (operational, not adversarial)**: a lens deployment
spinning up multiple uvicorn workers / replica pods / sidecars
concurrently against a single Postgres instance. Each worker calls
`Engine(...)` on startup, which connects + calls `run_migrations()`.

**Pre-v0.1.5 failure**: the workers raced on Postgres catalog
inserts — TimescaleDB hypertable type registration in `pg_type`,
`IF NOT EXISTS` checks across the V001 + V003 migration set,
refinery's own schema_history bootstrap. The second worker through
hit `42P07 relation already exists` (or, less commonly, deadlock
on `pg_namespace`) which refinery wrapped opaquely as
`"error asserting migrations table — db error"`. Production
deployments saw worker pods fail readiness, restart, race again,
and stay unhealthy until the orchestrator escalated.

This is not a threat in the adversarial sense — there is no
attacker — but it is a real availability vector: a config change
that scales worker count from 1 to N can trigger a stuck-restart
loop on cold deploys. THREAT_MODEL.md catalogues it for the same
reason MISSION.md treats reliability as a mission concern: a
substrate that's unreachable can't carry evidence.

**Mitigation in v0.1.5**: session-scoped Postgres advisory lock
(`pg_advisory_lock(0x6369_7269_7370_7372)` — bytes spell
`"cirispsr"` for grep visibility) acquired on a *dedicated single-
use connection* (not from the pool, so the lock can't taint a
recycled pool conn). The lock is held across refinery's
multi-transaction migration phase. First worker wins immediately;
subsequent workers block on the lock, wake when the first worker's
session closes, and proceed cleanly through the now-no-op migration
phase. Lock auto-releases on connection close — including the
panic-mid-migration case (the connection task observes EOF, the
session ends, the lock goes; no orphaned locks across worker
crashes).

**Diagnostic surface**: v0.1.5 also added `Error::Migration {
sqlstate: Option<String>, detail: String }` so the lens sees
`store: migration: [SQLSTATE] detail` instead of "db error". 42P07
should not appear at v0.1.5+ unless schema is externally mutated
mid-flight; 40P01 (deadlock detected) is the indicator for "retry
construction"; 08006 is "connection lost, retry"; 42501 is
"DSN user lacks DDL rights — config bug, not transient."

**Residual**: a worker holding the lock that is *paused indefinitely*
(SIGSTOP, kernel scheduler starvation, or a tracing tool with a
breakpoint inside the migration phase) leaves concurrent workers
blocked on `pg_advisory_lock`. This is a deployment-operational
concern (orchestrator liveness probes catch it; the held-lock
worker's connection eventually times out per Postgres
`tcp_keepalives` if configured). Out of scope for the
substrate.

**QA harness coverage**: `tests/qa_harness.rs::av26_concurrent_boot_advisory_lock`
spawns 10 concurrent boots against a fresh DB, asserts every one
returns `Ok(())`, and verifies the migration_history table contains
exactly one row per migration script (not 10×N — that would mean
the lock didn't hold). Gated on `CIRIS_PERSIST_TEST_PG_URL`.

### 3.6 Operational / hardening vectors (catalogued in SECURITY_AUDIT_v0.1.2.md §3)

AV-17 through AV-23 were surfaced by the post-v0.1.2 SOTA
gap-analysis pass (Pass 3). The audit document carries the full
prose; the mitigation matrix in §4 below carries the one-line
summary. Briefly:

- **AV-17** — `attempt_index` integer truncation (P0). v0.1.3 caps
  `MAX_ATTEMPT_INDEX = 1024` with `try_into` + typed
  `Error::AttemptIndexOutOfRange`. `overflow-checks = true` on the
  release profile is the defense-in-depth backstop.
- **AV-18** — plaintext Postgres connection (P1). v0.1.3 adds
  optional `tls` feature (`tokio-postgres-rustls`).
- **AV-19** — no graceful shutdown / lost in-flight commits (P1).
  v0.1.3 adds `tokio::signal::ctrl_c` + drain protocol.
- **AV-20** — no `statement_timeout` (P2). Track for v0.2.x.
- **AV-21** — no per-agent rate limiting (P2). Track for v0.2.x;
  PoB §5.6 acceptance-policy adjacent.
- **AV-22** — no clock-skew validation (P2). Track for v0.2.x.
- **AV-23** — `consent_timestamp` range unconstrained (P3). Track.

### 3.7 Federation directory (v0.2.0+)

These vectors emerge from the federation directory schema
(`federation_keys`, `federation_attestations`, `federation_revocations`)
introduced in v0.2.0. The directory provides the substrate consumers
compose policy over (per `docs/FEDERATION_DIRECTORY.md` §"Explicit
non-goals"), so attacks here target either the substrate's integrity
or the consumer's policy assumptions about it.

#### AV-28: Federation_keys directory pubkey poisoning

**Attack**: An attacker with write access to `federation_keys`
submits a `SignedKeyRecord` with a `key_id` that collides with an
existing legitimate registration but a different
`pubkey_ed25519_base64` / `pubkey_ml_dsa_65_base64`. Same-shape as
AV-11 but for the v0.2.0+ federation directory (which is the
authoritative source post-v0.2.0; `accord_public_keys` is dual-read
fallback retiring at v0.4.0).

**Mitigation v0.2.0**: idempotent on `(key_id, persist_row_hash)`.
INSERT with `ON CONFLICT (key_id) DO NOTHING` followed by a
post-insert hash check: if the existing `persist_row_hash` differs
from the submitted record's hash, persist returns
`Error::Conflict("key_id ... already exists with different content")`.
Re-submission of *identical* content is a no-op; submission of
*different* content under the same key_id is a typed Conflict — never
a silent overwrite.

**Secondary**: every row carries its own `scrub_signature_classical`
(+ `scrub_signature_pqc` once cold-path fills). Consumers verify the
scrub envelope against the row's `scrub_key_id` before trusting the
row. A poisoned row with a malformed signature fails consumer-side
verify before the policy layer trusts it.

**Residual**: an attacker who legitimately holds `key_id`'s
scrub-signing key (same trust boundary as AV-2) can mint
apparently-valid envelopes. PoB §6 statistical drift detection is
the federation-level mitigation; persist's substrate cannot
distinguish forged-but-valid signatures pointwise.

#### AV-29: Attestation graph poisoning

**Attack**: An attacker submits attestations or revocations crafted
to mislead consumer-side trust traversal — e.g., circular `scores`
chains on `identity_binding:*` (v2.4.0 vocabulary; was `vouches_for`
pre-2.4.0), attestations with futures-dated `expires_at` to claim
long-lived trust, revocations with retroactive `effective_at` to
invalidate historical traces.

**Mitigation v0.2.0**: persist exposes the edges, never the
traversal. There is no `is_trusted()` / `trust_score()` /
`trust_path()` method; consumers compose whatever policy they want
(majority-attestation, weighted-graph-walk, score-weighted, etc.).
A compromised attestation does not directly cause persist to flip
any consumer's trust state; it adds an edge consumers walk under
their own policy.

**Secondary**: every attestation row carries its own scrub envelope.
Consumers verify per-row before counting the edge. The graph itself
is append-only — revocations are observed, not retroactive deletes —
so poisoning is additive, not destructive.

**Residual**: a consumer with naïve traversal policy
("any-attestation-counts") is exploitable; a consumer with
score-weighted policy that requires N independent attestations is
not. Per the architectural non-goals: *policy is consumer-side*.
Persist's residual is "we expose the edges honestly; bad policies
get bad answers."

#### AV-30: Federation_keys self-FK integrity

**Attack surface (operational, not adversarial)**: the
`federation_keys` table's `scrub_key_id` references
`federation_keys.key_id` — a self-reference. A bootstrap row
references itself before the row physically exists in the table.
Standard `REFERENCES` would reject the INSERT.

**Pre-v0.2.0 failure**: bootstrap impossible without the FK constraint
relaxed.

**Mitigation v0.2.0**: `DEFERRABLE INITIALLY DEFERRED` on the
self-FK. Bootstrap row INSERTs successfully; the constraint check
runs at COMMIT, by which time `scrub_key_id` resolves (the row
exists). Non-bootstrap rows reference an already-committed key,
so the deferred check is no-op.

**Residual**: a malicious operator with DBA-level access could
deferrable-defer-then-rollback to leak intermediate state, but
the trust boundary at that level is "Postgres compromised" (out of
scope per §1) — the substrate cannot defend against the operator
running it. Standard FK semantics resume at COMMIT.

### 3.8 Hybrid PQC posture (v0.2.0+)

These vectors emerge from the hybrid Ed25519 + ML-DSA-65 signing
scheme. The federation's design accepts Ed25519-only rows initially
(hot path), with ML-DSA-65 attached on the cold path
(`docs/FEDERATION_DIRECTORY.md` §"PQC strategy"). The window between
hot-path commit and cold-path PQC fill-in is the hybrid-pending
interval — load-bearing for the trust contract.

#### AV-31: Hybrid-pending exploitation

**Attack**: An attacker who breaks Ed25519 (post-quantum future, or
hypothetical pre-quantum break) forges a row with valid Ed25519 but
no PQC component. Consumers running `HybridPolicy::Ed25519Fallback`
or `SoftFreshness { window: long }` accept the row.

**Mitigation v0.3.6**: `Engine.verify_hybrid` exposes three
explicit policies:
- `Strict` — rejects hybrid-pending rows; requires both signatures.
  Production posture for high-stakes domains.
- `SoftFreshness { window }` — accepts only if `row_age < window`.
  Window is caller-supplied (caller looks up `pqc_completed_at` /
  `created_at` and computes age externally). Bounds the
  acceptance window to the federation's eventual-consistency contract.
- `Ed25519Fallback` — always accepts. Development / sovereign-mode
  posture; NOT for federation production.

The `policy` parameter is per-call; consumers configure per-peer
trust. A peer in a high-stakes domain runs `Strict`; a peer in
general-purpose runs `SoftFreshness` with a window that matches its
sweep cadence (typically 5 min).

**Secondary**: bound signature pattern (PQC over `(canonical ||
classical_sig)`) means breaking Ed25519 alone is insufficient to
forge a fully hybrid-verified row — the attacker would also need to
break ML-DSA-65 OR exploit the hybrid-pending acceptance window.
Strict policy closes both branches.

**Residual**: a peer running `Ed25519Fallback` in production has
no PQC protection. Named residual; deployment-level mitigation is
"don't run Ed25519Fallback in production." Persist's
`verify_hybrid` requires the policy to be passed explicitly — no
silent default — so misconfiguration surfaces in audit.

#### AV-32: Cold-path PQC denial-of-completion

**Attack**: An attacker disrupts the cold-path PQC sweep so rows
stay hybrid-pending longer than the federation's SoftFreshness
window — pushing them into Strict-rejection territory and degrading
availability. Mechanisms: starve the tokio runtime, kill the
cold-path tokio task before completion, deny network to the PQC
signing service, fill the disk so `attach_*_pqc_signature` fails.

**Mitigation v0.3.1+v0.3.2**: per-write cold-path is
fire-and-forget on the engine's tokio runtime — no external
network dependency, no separate signing service, no network blip
to deny. The runtime is the same one serving `receive_and_persist`,
so denying it denies write-path entirely (the attacker can DoS
ingest, but they can't selectively deny PQC fill-in while keeping
hot-path alive).

The v0.3.2 sweep primitive (`Engine.run_pqc_sweep`) provides the
recovery path: any row that misses the per-write cold-path (process
restart, transient sign failure, runtime starvation) is filled by
the next sweep. The `pqc_sweep_on_init=True` constructor default
runs a sweep at boot; production deployments running the sweep
periodically (e.g., once per minute via cron) bound the
hybrid-pending window operationally.

**Secondary**: writer contract documented in
`migrations/postgres/lens/V004__federation_directory.sql` header:
"kick off IMMEDIATELY after Ed25519 sign, not delayed/batched/
scheduled." The contract is enforced by persist owning the
implementation (CIRISPersist#10 closure) — consumers can't
accidentally drop it.

**Residual**: a deployment that runs persist with no cold-path
sweep cadence AND a long SoftFreshness window has a soft window of
acceptance for hybrid-pending rows. Operational concern, not
substrate. Logs (`tracing::info` after each sweep) surface
sweep-completion frequency for ops monitoring.

#### AV-33: Bound-signature stripping

**Attack**: An attacker who breaks Ed25519 strips an existing valid
PQC signature off a legitimate row, replaces with their own
ML-DSA-65 signature over canonical-only bytes (without the
classical sig append), and forges a new row with their fake
classical + their fake PQC.

**Mitigation v0.2.0**: bound signature pattern. PQC signs
`(canonical || classical_sig)`, not just `canonical`. Persist's
`HybridVerifier` rebuilds the bound payload before PQC verify and
rejects if PQC was signed over canonical-only. The attacker who
breaks Ed25519 can produce a valid classical sig, but the PQC
component must be over the *concatenation* — an attacker who
hasn't broken ML-DSA-65 cannot produce that.

**Secondary**: matches CIRISVerify's `HybridSignature` spec
(`ciris-crypto/src/hybrid.rs:191`) and the `ManifestSignature`
shape used by `ciris-build-sign`. Persist consumes the upstream
primitive; bound-signature semantics are enforced at the
ciris-crypto layer, not reimplemented persist-side.

**Residual**: an attacker who breaks BOTH Ed25519 and ML-DSA-65
can mint arbitrary hybrid signatures. That's the "all-quantum-in-
one" scenario; post-quantum-cryptanalysis on ML-DSA is at least as
hard as breaking the underlying lattice problem (PoB §6). The
hybrid scheme bounds the attacker to "break BOTH or break NEITHER"
in the typical case; bound signatures close the AND-instead-of-OR
branch.

### 3.9 Wire-format extensions (v0.3.0..v0.3.4)

These vectors emerge from the 2.7.9 wire-format additions
(per-component `agent_id_hash`, `parent_event_type` /
`parent_attempt_index` on LLM_CALL, `deployment_profile` on the
trace envelope). All are signed canonical fields; cross-shape
injection at the older `2.7.0` version is the structural concern.

#### AV-34: Cross-shape canonical injection

**Attack**: An attacker submits a `2.7.0` envelope that carries
`2.7.9`-shape fields (per-component `agent_id_hash`, or a top-level
`deployment_profile` block). The attacker hopes the lens persists
a row with cohort labels or denormalized agent_id_hash values that
were never part of what the agent signed — corrupting downstream
analytics or AV-9 dedup-tuple identity.

**Mitigation v0.3.0/v0.3.4**: deterministic dispatch by
`trace_schema_version`. At `2.7.0`, the canonical reconstruction
runs the 9-key 2.7.0 path (`canonical_payload_value`); the
per-component `agent_id_hash` field and the `deployment_profile`
block are silently ignored — they don't enter canonical bytes,
don't affect signature verify, don't affect dedup. Two traces (one
without the injected fields, one with) at `2.7.0` produce
byte-identical canonical bytes.

Schema-version-aware decompose at `2.7.9` requires the shape:
`MissingField("deployment_profile")` rejects an envelope claiming
`2.7.9` without the block. Cross-shape injection at the wrong
version is therefore a no-op (2.7.0 ignores the future fields) or
a typed rejection (2.7.9 requires them).

**Secondary**: regression tests
(`v270_ignores_per_component_agent_id_hash_injection`,
`v270_ignores_deployment_profile_injection`) assert byte-identical
canonical bytes with vs. without injection at 2.7.0. Spec
hardening ([CIRISAgent#712](https://github.com/CIRISAI/CIRISAgent/issues/712)
#714) binds the shapes structurally so the agent and lens agree on
which fields belong at which version.

**Residual**: a future schema version that adds a field which IS
honored at `2.7.0` would re-open this surface. The version-bump
review process (per §10 update cadence) catches such changes.

#### AV-35: Schema-version dispatch attack

**Attack** (pre-v0.3.0 / closed retroactively): the pre-v0.3.0
verify path tried multiple canonical shapes in sequence (try-9-field-
then-2-field). An attacker could craft canonical bytes that match
*both* shapes' verify path but mean different things at the dedup
or denormalization layer — getting a trace counted as 2-field for
verify but interpreted as 9-field for storage.

**Mitigation v0.3.0**: deterministic dispatch by
`trace_schema_version`. Each trace contributes to exactly one
canonical-shape verify path. No shape-shopping; no
spurious-sig-fail latency multiplier.

The load-bearing safety property is **verification is bound to the
dispatch arm's canonical**: a signature signed against arm-A's
canonical bytes cannot pass arm-B's verification. The arm
selection happens BEFORE verify, but a wrong-arm selection
deterministically fails verify because the reconstructed canonical
bytes won't match what the agent signed. Forging the routing input
itself buys an attacker nothing — they still need to produce a
signature that verifies against THE arm they routed to, which
requires the signing key.

The dispatch input (`trace_schema_version`) is itself in the
signed canonical bytes at `2.7.0` and `2.7.9` (both 9-field
canonicals carry it as a signed field). At `"2.7.legacy"` the
2-field canonical signs only `{components, trace_level}` — the
version stamp is NOT in those signed bytes. Safety holds anyway
because of the verify-bound-to-arm-canonical property above:
even though the routing input isn't itself signed at the legacy
arm, a legacy-signed trace verifies only against the 2-field
canonical, and the agent's choice to sign that shape is what
binds them to it.

**Secondary**: typed `Error::UnsupportedSchemaVersion` from the
schema-parse layer rejects out-of-allowlist versions before the
verify dispatch runs (AV-12 mitigation overlap).

**v0.4.3 (CIRISPersist#21) restoration of `"2.7.legacy"`**:
`SUPPORTED_VERSIONS` is now `["2.7.0", "2.7.9", "2.7.legacy"]`.
v0.4.0 had dropped `"2.7.legacy"` on a calendar/fleet-migration
framing that didn't fit the federation's decentralized model;
v0.4.3 restored it under the same telemetry-driven sunset rule
`"2.7.0"` already follows
(`federation_canonical_match_total{wire="2.7.legacy"}` 7-day-zero
soak window). Pre-2.7.8.9 emitters that don't stamp
`trace_schema_version` at all dispatch deterministically to the
legacy arm via serde-default — absence is the deterministic
signal, NOT a try-list fallback (TRACE_WIRE_FORMAT.md §8
prohibition on iterative arm-shopping is preserved). The
verify-bound-to-arm-canonical property holds at the legacy arm
identically; safety is unchanged from the v0.3.0 establishment.

**Residual**: when `SUPPORTED_VERSIONS` legitimately holds multiple
versions during a rollout window, all three dispatch arms are live.
Each is independent (no cross-version field reuse); the per-version
review (§10) ensures shape independence.

#### AV-36: LLM_CALL parent-linkage substitution

**Attack** (pre-v0.3.3 / closed retroactively): the pre-v0.3.3
decompose substituted the outer LLM_CALL component's `event_type`
(always `LLM_CALL`) into `trace_llm_calls.parent_event_type` when
the wire-shipped fields were missing. Result: 100% of pre-v0.3.3
2.7.9 corpus rows had `parent_event_type='LLM_CALL'` instead of
the spec-mandated upstream-step taxonomy
(`ASPDMA_RESULT`, `IDMA_RESULT`, `CONSCIENCE_RESULT`, etc.). This
defeated the AV-9 dedup-tuple parent-path identity and RATCHET H3
parent-topology clustering.

**Mitigation v0.3.3**: 2.7.9 strict-parse for the LLM_CALL
component. Missing `parent_event_type` or `parent_attempt_index` →
typed `Error::Schema(MissingField("data.parent_event_type"))`.
Decompose reads from the wire-provided values directly; no
substitution at 2.7.9. At 2.7.0, the historical substitution path
is preserved for backward compatibility (the spec didn't carry the
fields at 2.7.0; substitution is documented as semantically wrong
but operationally equivalent for AV-9 dedup at that version).

**Residual**: pre-v0.3.3 rows in production tables retain the
`parent_event_type='LLM_CALL'` label; RATCHET uses `handler_name`
as the upstream-step linkage workaround per CIRISLens#5. New
traffic post-v0.3.3 + agent `e714ff3c4` lands with the spec-correct
parent linkage.

#### AV-37: deployment_profile cohort-identity injection

**Attack**: An agent declares false `deployment_profile` labels
(`agent_role`, `deployment_domain`, `deployment_type`,
`deployment_trust_mode`) to evade RATCHET cohort routing.
Examples: a high-stakes deployment declares `deployment_domain:
"general"` to avoid the more rigorous detection thresholds applied
to `healthcare` / `legal` / `financial`. A production deployment
declares `deployment_type: "research"` to claim the lower bar that
research applies. A federated peer declares
`deployment_trust_mode: "federated_peer"` while running sovereign-
isolated.

**Mitigation v0.3.4**: `deployment_profile` rides in the 2.7.9
signed canonical bytes (CIRISAgent FSD/TRACE_WIRE_FORMAT.md §3.2 +
§8). The agent's signature commits to the declared labels; an
attacker can't post-hoc rewrite the labels on a row that's already
signed. This is the same authenticity floor as `agent_id_hash`:
the labels are non-forgeable post-emission.

The v0.3.4 strict-parse at 2.7.9 rejects envelopes missing the
block (the v0.3.5 `MissingField("deployment_profile")` gate). All
6 fields are required-on-the-wire — missing fields can't be
"silently defaulted" to evade label rigor.

**Secondary**: lens-side cohort routing applies *behavioral*
detection on top of declared labels — e.g., a row claiming
`deployment_resourcing: scarcity` whose `cost_usd` says
`abundance` is flagged. Persist denormalizes the declared labels
into queryable columns; lens runs cross-checks against the cost
columns the agent also signed.

The `deployment_resourcing` field is intentionally NOT
agent-declared (per CIRISAgent#718 design): it's lens-computed from
`cost_usd` / `tokens` / `model` observation. Agents can lie about
declarative labels but not about emergent operational reality —
the cost columns show what they paid.

**Residual**: an attacker willing to *actually* run high-stakes
behavior under a declared low-stakes label, paying the real cost,
faces the cost-asymmetry PoB §2.1 names. Detection is statistical
over time (lens cohort cross-validation against behavioral
observation); persist's substrate provides the cryptographic floor
that makes the cohort-correctness claim measurable in the first
place.

### 3.10 Legacy schema accommodation (v0.4.3 / v0.4.6)

Vectors emerge from the v0.4.3 restoration of `"2.7.legacy"` to
`SUPPORTED_VERSIONS` (CIRISPersist#21) plus the v0.4.6 graceful-
fallback for `attempt_index` at the legacy / 2.7.0 arms
(CIRISPersist#22). Both changes accommodate pre-2.7.8.9 emitters
that physically cannot be patched (the bridge cannot mutate signed
bytes without invalidating verify). The accommodations are
schema-version-gated, sunset-driven, and bounded by signing-key
control — they don't widen the federation-wide attack surface, but
they do introduce a documented agent-internal fidelity trade-off
worth recording.

#### AV-42: Legacy `attempt_index` dedup-collapse

**Attack**: At `trace_schema_version ∈ {"2.7.0", "2.7.legacy"}`,
components without `data.attempt_index` decompose with
`attempt_index = 0` (v0.4.6 fallback). Multiple retries on the
same `(agent_id_hash, trace_id, thought_id, event_type)` collapse
on the dedup tuple
`(agent_id_hash, trace_id, thought_id, event_type, attempt_index)`
— only the first row lands; subsequent retries hit ON CONFLICT
DO NOTHING and are silently skipped. An attacker controlling the
signing key could in principle exploit this to suppress later
retries with content different from the first.

**Mitigation v0.4.6**: schema-version-gated. 2.7.9 still strict
(`MissingField("attempt_index")` rejects absence in the typed
parse layer); fallback fires only at `2.7.0` and `"2.7.legacy"`.
Malformed values (negative, wrong type, out of range) still error
through the typed paths (AV-17 protection unchanged) — fallback
fires ONLY for the absence case (`MissingField`), not for any
shape that suggests adversarial input.

**Sunset by observed traffic**: the same telemetry-driven rule
that gates `"2.7.0"` and `"2.7.legacy"` themselves
(`federation_canonical_match_total{wire="<dialect>"}` 7-day-zero
soak window) deprecates the dedup-collapse fallback once
2.7.6-era traffic stops. The accommodation is bounded in time by
empirical observation, not committed-to-forever.

**Bounded by signing-key control**: an attacker exploiting this
requires the legitimate signer's key. With the key, they can
already forge any trace — the marginal capability gained is
"compress retry semantics on the dedup tuple," which barely
adds to their existing forgery capability. Cross-agent
collision is closed by `agent_id_hash` in the dedup tuple
(AV-9 mitigation, v0.1.2).

**Why not lens-side fix**: the legacy 2-field canonical signs
`{components, trace_level}`, so `components[].data` IS in the
signed bytes. Synthesizing `data.attempt_index` post-hoc on the
agent or lens side would invalidate the verify the v0.4.3
legacy-restoration just got working. The federation's append-only
contract takes priority over per-row dedup fidelity for legacy
traffic; persist accepts the trade-off and documents it.

**Companion correction (v0.4.6 / CIRISPersist#22)**: prior to
v0.4.6, `decompose`'s `Schema(MissingField)` errors were
mis-classified as `IngestError::Store` at `src/ingest.rs:229`,
sending HTTP 503 + Retry-After (lens convention for transient
backend faults) for what is actually a deterministic schema
mismatch. Agents retried indefinitely on a 4xx shape, creating a
self-DoS amplification surface (legitimate clients hammering
persist on each malformed batch). v0.4.6's typed
`store::Error::Schema(s) → IngestError::Schema(s)` split routes
schema rejects to HTTP 422 (give-up); agents surface to ops
instead of looping. **Net positive on the DoS-amplification
surface**, not previously catalogued as its own AV because the
threat model assumed schema rejects had always routed to 422.

**Residual**: legacy-version retries within one agent collapse on
the dedup key. Cross-agent collision closed by AV-9. Time-bounded
by AV-42 sunset rule (observability-driven). The accommodation
exists because pre-2.7.8.9 traffic is real and unrecoverable
otherwise; the sunset rule is the discipline that prevents
accommodation-creep into permanent technical debt.

### 3.11 Federation read primitives (v0.5.0)

Vectors emerge from the v0.5.0 read surface (CIRISPersist#23 sections
A/B/F/E). The primitives expose typed reads to lens, lens-core, and
sovereign-mode agents — closing the historical `cirislens_reader`
direct-SQL carve-out the v0.2.0+ `fetch_trace_events_page` docstring
named.

#### AV-43: Read-side adversary inference attack

**Attack**: A federation peer with read access to the substrate uses
the v0.5.0 aggregate primitives — `aggregate_scoring_factors`,
`cross_agent_divergence`, `temporal_drift`,
`conscience_override_rates` — to infer per-trace content of another
peer's traces by pattern analysis. Examples: correlating a narrowly-
windowed scoring aggregate against a `cross_agent_divergence` z-score
to deanonymize a specific trace's properties; running per-minute
`coherence_decay_series` queries to reconstruct the timing of
individual decisions.

**Mitigation v0.5.0**: aggregates return computed statistics, not
per-trace content. The smallest-window primitive
(`aggregate_scoring_factors` over a sub-hour window) requires the
caller to apply k-anonymity policy at *their* layer (minimum-cell-size
gates, refusing aggregate computation when `trace_count` is below a
threshold). Persist returns counts truthfully and documents the
window-size dependency.

The aggregate row shapes carry `sample_count` / `trace_count` fields
explicitly so the caller's k-anonymity gate is a one-line check:

```python
agg = engine.aggregate_scoring_factors(...)
if agg["trace_count"] < K_THRESHOLD:
    raise InsufficientSamples(agg["trace_count"])
```

`DivergenceRow.sample_count` and `OverrideRateRow.trace_count` carry
the same gate primitive. `CoherencePoint.trace_count` per bucket
similarly enables per-bucket gating in lens.

**Audience-tier discipline (closed-set + structured detail)**: AV-15
holds — the read primitives' error kinds are closed-set
`&'static str` (`read_invalid_argument`, `read_invalid_cursor`,
`read_backend`, `read_not_implemented`). No raw user-payload bytes
cross the FFI boundary in error paths.

**AV-9 invariant preserved**: every trace-scoped read (sections A/B
trace primitives) returns `agent_id_hash` on the result so callers
authorize per-trace access at their layer. A malicious peer cannot
read another peer's traces via `trace_id` alone; the persist
substrate exposes the rows but the authorization boundary lives at
the consumer (lens API, sovereign-mode agent's own gate).

**Residual**: a federation operator with `cirislens_reader` role (or
its v0.5.1 retirement target — see *Note on full carve-out
retirement* below) running narrow windows can in principle reconstruct
trace patterns. The aggregation primitives don't widen this surface —
the underlying rows were already accessible to that role. The typed
read primitives + AV-15-safe error layer ARE the way to retire the
direct-SQL carve-out; v0.5.0 lands the surface, v0.5.1 retires the
final carve-out (section D / LLM call surface lands then).

**Note on full carve-out retirement (deferred to v0.5.1)**: v0.5.0
ships sections A/B/F/E (TraceSummary listing, trace detail, Coherence
Ratchet inputs, scoring factor aggregates). Sections C/D/G/H/I (task
grouping, LLM call surface, corpus shape, scrub stats, federation
bulk) ship in v0.5.1 after lens validates the v0.5.0 batch in
production. Until v0.5.1, lens still uses direct SQL for LLM call
queries (section D's territory); the `cirislens_reader` role's
lens-side use is deprecated in v0.5.0 but not yet fully retired
because section D doesn't have its typed primitive yet. The
deprecation message points lens-team at section D's pending work.

### 3.12 Outbound queue substrate (v0.4.0)

These vectors emerge from v0.4.0's `cirislens.edge_outbound_queue`
table — the durable substrate for `CIRISEdge::send_durable()`.
Phase 1 durable message types (BuildManifestPublication, DSARRequest/
Response, AttestationGossip, PublicKeyRegistration) ride this table.

#### AV-40: Outbound queue disk exhaustion

**Attack**: An adversary with write access to the federation peer
floods the outbound queue with high-TTL low-priority messages (or
messages routed to unreachable peers that never deliver), filling
the disk and starving legitimate traffic.

**Mitigation v0.4.0**: per-row `body_size_bytes` capped 1..=8 MiB
by schema CHECK; `ttl_seconds > 0` required so every row eventually
abandons; `max_attempts` bounded so retry loops terminate.
`Engine.run_pqc_sweep`-style operational discipline applies —
deployments run `sweep_ttl_expired` periodically, and ops dashboards
alert on `oldest-pending-age` exceeding deployment-level thresholds.

**Secondary**: FK constraint requires both `sender_key_id` and
`destination_key_id` resolve in `federation_keys`. Forging an
outbound row requires forging a federation_keys row first (AV-28
covers that).

**Residual**: a deployment with no sweep cadence + permissive TTL
policies grows its outbound queue without bound. Operational
concern; persist's substrate provides the cleanup primitive
(sweep_ttl_expired) but doesn't enforce the cadence.

#### AV-41: Spoofed in_reply_to ACK matching

**Attack**: An adversary intercepts an outbound envelope (or
observes its body_sha256 via a lossy network path), then sends a
forged ACK envelope claiming to ACK the in-flight row. The
`match_ack_to_outbound` lookup matches on body_sha256; if the ACK
is accepted, the row transitions to `delivered` without the actual
receiver having processed the message.

**Mitigation v0.4.0**: ACK envelopes go through persist's normal
verify pipeline before `mark_ack_received` is called. Verify gates:
- AV-1 (lookup_public_key): the ACK envelope's
  `signature_key_id` must resolve in `federation_keys`
- AV-39 (verify_hybrid via persist): hybrid signature on the ACK
  envelope is verified before content is trusted

The `body_sha256` matches up the in-flight row, but
`mark_ack_received` is only called after the ACK envelope's
signature is verified against the destination peer's pubkey. An
attacker without the destination peer's signing key cannot mint a
valid ACK envelope.

**Secondary**: bound-signature pattern (AV-33) means an attacker
who breaks Ed25519 alone still can't forge a hybrid-verified ACK.

**Residual**: an attacker who compromises the destination peer's
signing key (AV-2 trust boundary) can mint valid-looking ACKs. This
is the same residual as agent-side forgery — out of persist's scope;
upstream key-storage hardening + PoB statistical drift detection are
the federation-level mitigations.

### 3.10 DSAR + verify primitives (v0.3.6)

These vectors emerge from v0.3.6's per-key DSAR primitive
(`Engine.delete_traces_for_agent`) and the `verify_hybrid`
arbitrary-canonical-bytes surface that closes CIRISEdge OQ-11.

#### AV-38: Per-key DSAR scope violation

**Attack** (closed by v0.3.6 BREAKING change vs v0.3.5): a DSAR
request signed by key A is used to delete traces signed by key B
under the same `agent_id_hash`. v0.3.5's
`Engine.delete_traces_for_agent(agent_id_hash, include_federation_key)`
broadened scope to all keys for that agent — any one valid key
could file a DSAR deleting traces from other agent instances
claiming the same logical identity (separate deployments of the
same template with different signing keys).

**Mitigation v0.3.6**: `signature_key_id` is a REQUIRED parameter
(no `Option<>` back-compat shim). Deletion is scoped to
`(agent_id_hash, signing_key_id)` at all three substrate layers:
- `trace_events`: `WHERE agent_id_hash = $1 AND signing_key_id = $2`
- `trace_llm_calls` cascade: joined by `trace_id` from the matching
  `trace_events` set (cross-key traces under the same agent only
  cascade for this DSAR's key)
- `federation_keys` (when `include_federation_key=True`): only the
  one row matching `(agent_id_hash, signature_key_id)` cascades;
  the agent's other registered keys (rotation history) stay alive

The per-key contract is the authorization model itself, not a
filter parameter. CIRISPersist#15 named the gap; v0.3.6's BREAKING
change is the closure. Admin / forensic deletions belong in
standard privileged CRUD, not this primitive — there is no soft
escape hatch.

**Secondary**: lens-side DSAR audit ledger captures the request
envelope + signature verification independent of persist. Persist
returns the row counts; lens persists who-requested-what-when.

**Residual**: if an attacker compromises both `agent_id_hash`'s
specific signing key AND the lens's DSAR-orchestration layer, they
can issue authorized-looking DSAR requests for that one key's
traces. That's compounded compromise (two trust boundaries
breached at once); the per-key contract bounds the blast radius
to the single compromised key, not the agent's entire history.

#### AV-39: verify-via-persist bypass

**Attack** (architectural, addressed by API design): a federation
peer (edge / lens / partner site) calls `ciris_crypto::HybridVerifier`
directly instead of `Engine.verify_hybrid`. Drift surface:
- Different canonicalization expectations (the `data` argument to
  HybridVerifier::verify must match what persist canonicalizes;
  if the peer canonicalizes differently, signatures verify
  differently across peers).
- Bypass of the policy machinery (`HybridPolicy::Strict` /
  `SoftFreshness` / `Ed25519Fallback` enforcement happens
  persist-side; direct ciris_crypto usage skips it).
- Per-deployment policy configuration scattered across N consumer
  codebases instead of localized at persist's API surface.

Same drift surface CIRISPersist#7 closed for canonicalization;
applied to the verify path.

**Mitigation v0.3.6**: `Engine.verify_hybrid` is the federation's
single-source-of-truth for hybrid verify, exposed via PyO3 and
via the underlying `crate::verify::verify_hybrid` Rust function.
Federation peers consume verify through persist; the API design
does not require nor reward direct `ciris_crypto` usage.
Architectural closure (CIRISPersist#7 pattern); not a runtime
gate, but the path of least resistance is verify-via-persist.

The `verify_hybrid` surface accepts arbitrary canonical bytes —
not just CompleteTrace shapes — so peers don't need direct
`ciris_crypto` access for non-trace verify needs (build-manifest
verification, cross-component signing, etc.).

**Secondary**: documented as the closure pattern in
`docs/V0.2.0_VERIFY_SUBSUMPTION.md`. CIRISEdge OQ-11 closure
explicitly cites verify-via-persist as the integration discipline.

**Residual**: a peer that nevertheless implements its own verify
path skips persist's policy machinery. This is a consumer-side
discipline issue, not a substrate enforcement; persist cannot
prevent a determined consumer from forking the code. The
architectural cost (drift, per-consumer policy maintenance) is the
incentive against doing so.

### 3.13 Panic-isolation posture (v0.5.3)

Vectors emerge from running persist as a PyO3 `cdylib` loaded into
long-lived uvicorn workers, not the v0.1.x standalone-bin shape the
original `panic = "abort"` audit (SECURITY_AUDIT_v0.1.2.md §4.2)
assumed. The 2026-05-11 prod wedge (CIRISPersist#24) realized the
failure mode: a single NULL deserialization panicked `Row::get`,
the panic runtime called `abort()` before PyO3's `catch_unwind`
trampoline could fire, and parallel calls SIGABRT'd every uvicorn
worker — taking down `/health` itself.

The v0.5.3 hardening track (CIRISPersist#25 + #26 + #27) replaces
the single layer of "abort fast" with three orthogonal layers of
panic-resistance:

| Layer | What it catches |
|---|---|
| SQL → Rust (`try_get<Option<T>>`) | NULL surfaces as `None`, not panic |
| Rust → FFI (`panic = "unwind"`) | PyO3 trampoline catches Rust panics as `PanicException` |
| FFI → Python (`catch_unwind` + `LensQueryError`) | Panics become normal `Exception` 500s, not `BaseException` worker poisoners |

#### AV-44: Rust panic escalates to process abort

**Attack**: any Rust panic anywhere in the crate (NULL
deserialization, integer overflow on release-overflow-checks, an
`unwrap` on a typed error path, a future SQL edit that breaks an
invariant) triggers process abort, taking down the entire uvicorn
worker pool. Parallel concurrent calls amplify — every worker
SIGABRT'd within milliseconds, `/health` unreachable.

**Mitigation v0.5.3**:

1. **`panic = "unwind"` in the release profile** (Cargo.toml). The
   panic runtime unwinds the stack; PyO3's built-in trampoline
   (pyo3#797) catches the panic via `catch_unwind` and raises
   `PanicException` (a Python `BaseException` subclass). The
   worker process survives; the offending request fails.
2. **Explicit `std::panic::catch_unwind(AssertUnwindSafe(|| ...))`
   wrapping every `#[pyfunction]` body** (v0.5.3 / CIRISPersist#27).
   The catch converts the panic payload to a typed
   `LensQueryError` Python exception that derives from `Exception`
   (not `BaseException`) — uvicorn's normal error handling catches
   it as a 500, not a worker reset.
3. **Crate-wide `Row::get` → `try_get::<_, Option<T>>` sweep**
   (v0.5.3 / CIRISPersist#26). NULL surfaces as `None` at the
   data-decode layer, before it can become a panic candidate.

**Re-evaluation of the original abort rationale**: the
SECURITY_AUDIT_v0.1.2.md §4.2 argument was sound for the v0.1.x
era when persist ran as a standalone binary with a supervisor
restart loop. In that shape, abort-and-restart was a feature —
the journal-replay path picked up cleanly. The cdylib-in-uvicorn
shape (v0.5.x+) inverts the trade-off: process abort means
parallel uvicorn workers all die simultaneously, with no
supervisor below them to coordinate restarts. Unwind preserves the
worker pool; the realized failure mode (SIGABRT cascade) is worse
than the theoretical one the audit prevented (unwind into half-shut
state). The ~3-5% release-binary size increase from unwind tables
is the cost.

**Residual**: a Rust panic inside the SQL driver's tokio runtime
(deep inside `tokio-postgres`) might still escape PyO3's
trampoline if `tokio::spawn`'d before unwinding completes. The
`catch_unwind` wrapper at the PyO3 entry point catches this when
the await returns; in-flight tokio tasks panicking in the
background are logged via `tracing::error` but don't propagate
back to Python. Documented residual; v0.5.3 sweep applies the
defensive layer at every point we control.

#### AV-45: §7.0 admission bypass via deprecated `attestation:l{N}:*` past CEG-0.3 retirement

**Attack**: an adversary emits `SCORES` attestations using the
deprecated L1-L5 wire prefix (`attestation:l1:self_verify`, etc.)
*after* CIRISRegistry retires the dual-acceptance via the CEG §11.2
amendment process. If persist's admission policy still allows the
deprecated form, the adversary's attestations land in the chain
indistinguishable from canonical ones — and downstream consumers
applying CEG §8.1.9 Policy I composition on the canonical-only
mechanism strings silently drop the malicious data, masking the
intrusion.

**Mitigation v3.0.0**:

1. **`AttestationLadderTransitionPolicy` enum on
   `DimensionAdmissionPolicy`** (`src/federation/admission.rs`).
   3.0.0 defaults to `DualAccept` per CEG 0.1→0.2 transition; the
   `RejectDeprecated` variant exists and is regression-tested at the
   admission gate (so the flip is a one-line change, not a refactor).
2. **The `is_deprecated_attestation_ladder_prefix` parser** is a
   runtime-checked match against `attestation:l<digits>:<mechanism>`,
   so a future canonical mechanism named with a leading `l<N>` doesn't
   accidentally match. Tight regex; no semantic confusion.
3. **CEG §11.2 amendment process** is the human-loop gate on the
   flip: persist tracks Registry's CEG release; the 3.1 flip ships
   when Registry retires the deprecated form, not before.

**Residual**: during the 3.0 dual-acceptance window, a producer
emitting only deprecated-form `attestation:l{N}:*` looks valid at
admission but is invisible to a CEG 0.2-strict consumer that only
parses mechanism strings. Documented: producers MUST emit canonical
form going forward (per CEG §13.1); deprecated-form emissions are a
producer-conformance bug, surfaced by CIRISConformance suite, not
substrate enforcement.

#### AV-46: §10.1.2 ContentMiss flood DoS against `list_holders`

**Attack**: an adversary emits forged `WITHDRAWS` attestations
against legitimate `holds_bytes:sha256:{prefix}` rows en masse,
attempting to make every legitimate holder appear withdrawn so
`list_holders` returns empty and federation peers can't locate the
bytes.

**Mitigation v3.0.0**:

1. **WITHDRAWS attestations are admission-gated** by the same
   `put_attestation` path as every other attestation type — the
   attester's `key_id` must exist in `federation_keys`, the
   signature must verify against that row's pubkey, and the
   structural-composer admission rules (CEG §6.1) apply.
2. **WITHDRAWS scope is per-attester** per CEG §6.1: a withdrawal
   from key K only suppresses K's own `holds_bytes` row from
   `list_holders`, never another attester's. The `NOT EXISTS`
   subquery in `list_holders` (`src/store/postgres.rs:2647`) filters
   on `w.attesting_key_id = h.attesting_key_id`. A malicious peer
   can only erase ITSELF from the holders list, not others — the
   asymmetric advantage is zero.
3. **Per-host attestation-rate caps** (deployer-policy, not
   substrate-enforced) bound the volume of withdraw emissions per
   key per window. Persist exposes the count via the existing
   attestation read APIs.

**Residual**: a single compromised federation peer can erase its
own holders entries, reducing federation-wide blob redundancy by
one. Not a DoS in the multi-holder case (the §10.1.2 design assumes
N≥3 holders for federation-tier blobs). Tracked: federation operators
should monitor `count_holders` ground-truth vs effective via
operational dashboards.

#### AV-47: §6.1 dedup-rule replay-protection hole

**Attack**: an adversary replays an old `SUPERSEDES` attestation
against a stale `references_attestation_id` after a newer `RECANTS`
has been emitted, attempting to overwrite the retraction.

**Mitigation v3.0.0**:

1. **Precedence is applied at READ, not WRITE** per CEG §6.1 design
   (audit chain stores all composers honestly; reads project the
   current effective state via `precedence_winner`). A replayed
   `SUPERSEDES` lands in the audit chain (it's an append-only
   record, by design) but doesn't change what `precedence_winner`
   returns.
2. **`precedence_winner` ranks**
   `RECANTS=3 > WITHDRAWS=2 > SUPERSEDES=1` per CEG §6.1 rule 1.
   A `SUPERSEDES` can never outrank a `RECANTS` against the same
   upstream from the same attester regardless of `asserted_at`
   ordering — replay is structurally inert.
3. **Idempotent on identical replay**: the
   `(references_attestation_id, attestation_type, attesting_key_id)`
   triple is the dedup key. A second `put_attestation` with the
   same triple returns `Ok(())` silently — the chain has the original
   row only, no duplicate audit-trail growth from replay flooding.

**Residual**: an attester who issues their OWN `SUPERSEDES` ↔
`RECANTS` ↔ `SUPERSEDES` ↔ `RECANTS` oscillation pollutes their
own composer chain (different signed_at values, different triples).
The precedence still resolves correctly (latest `RECANTS` wins);
the audit-chain growth is bounded by per-key emission rate caps
(AV-46 mitigation 3).

### 3.14 Holonomic substrate & store-path PQC (CEG §19 / §19.7, v7.2.0–v8.5.0)

The §19 holonomic / forever-memory substrate (#225, #227–#231) adds a
durable, replicated, kept-for-posterity content corpus, a WholenessWitness
divergence-detection corpus, and a §19.7 aggregation pyramid. Its threat
surface is dominated by two classes: **harvest-now-decrypt-later (HNDL)
forge-later** against a corpus that outlives the classical primitive, and
**reconciliation / divergence-router abuse** where a forged or stale witness
tries to drive the merge it is only supposed to *detect*. The §19 verifiers
themselves are frozen in `ciris_verify_core::holonomic` (verify v5.10.0);
persist **calls** them (`verify_witness`, `compare_witnesses`,
`verify_aggregation_meta`, `verify_member_commitment`, `ejection_verdict`,
`compute_merkle_root`) and re-rolls no Merkle / preimage / signature logic.
The §19.1 Merkle scheme was **frozen at CEG 1.0-RC15** with no RFC-6962
`0x00`/`0x01` leaf/node prefix; the CVE-2012-2459 odd-node-duplication
malleability is non-exploitable in this construction's uses because (1) every
witness and `member_commitment` root is **mandatorily hybrid-signed** — no
consumer relies on an unsigned root, (2) `member_commitment` is verified by
**full source-id-list recomputation**, never by partial inclusion proofs
against a bare root, and (3) §19.1 reconciliation is between accountable,
signed, equivocation-checked peers. Persist **inherits** this frozen scheme;
it does not roll Merkle and adopts no prefix.

#### AV-59: HNDL forge-later on the durable trace corpus

**Attack**: a CRQC-era adversary who has broken Ed25519 mints a backdated
`CompleteTrace` under any historical key id and injects it into the
permanent, content-addressed, replicated trace corpus. Content-addressing is
no defense — the adversary hashes their own forgery. The corpus is kept for
posterity, so it outlives the classical primitive.

**Mitigation v7.2.0 (#225, the hard cut)**: on `VerifyMode::Full`,
`IngestPipeline::verify_complete_trace` verifies **both** signature halves
via `verify_hybrid` (`HybridPolicy::Strict`) — `verify_trace_hybrid` replaces
the Ed25519-only `verify_trace`. A Full-mode classical-only trace (missing
the ML-DSA-65 half) is **rejected at admission** (`Verify(HybridRequired)`,
token `verify_hybrid_required`) — not warned. There is **no
`require_hybrid: false` posture**. This is the store-path PQC mandate of CEG
§10.1.5.1.1. The producer's ML-DSA-65 pubkey rides the envelope and is bound
into the hybrid verify, so a forged PQC pubkey fails the signature.

**Secondary**: verify-before-mutation ordering is unchanged — the hybrid gate
is step 2, strictly before scrub/decompose/insert; dedup is NOT moved ahead
of verify (that would be an AV-9 suppression/probe oracle). The same hard cut
applies to fountain manifests (`fountain_admit_hybrid_required`) and to
aggregation meta (AV-65).

**Residual**: the `2.7.legacy` import path (`VerifyMode::TrustPreVerified`)
is exempt — it carries the original 1.9.x Ed25519 sig as provenance only
(imported pre-verified, not re-verifiable). The hard cut applies to new
federation writes only. Corpus/bandwidth cost rises ~50× (per-trace sig
~64 B → ~3.4 KB hybrid); accepted as the price of HNDL-completeness.

#### AV-60: WholenessWitness equivocation (two signed roots, one peer)

**Attack**: a peer signs two *different* WholenessWitness roots for the same
epoch — claiming two incompatible views of what it holds — to later
repudiate one of them or to confuse reconciliation.

**Mitigation v8.2.0 (#228/#229)**: over the verified corpus,
`reconcile_peer_witnesses` + `witness::classify_stored` run
`compare_witnesses`; an **Equivocation** verdict **RETAINS both witnesses**
and emits `hard_case:witness_equivocation` (reusing the #146
`record_hard_case` emitter, idempotent on a deterministic `event_id`). The
pair is **NEVER reconciled, merged, or deleted** (§19 N4, non-repudiable) —
the equivocation is preserved as durable accountable evidence, not resolved
away.

**Secondary**: only **verified** witnesses enter the corpus
(`put_wholeness_witness` runs the PQC gate before any row is durable, AV-62),
so an equivocation is always between two signatures the peer provably made;
the re-scan is idempotent (no duplicate hard_case rows).

**Residual**: persist records and flags the equivocation; *acting* on it
(de-rating the peer, federation-governance response) is a downstream
consumer's policy over the `hard_case` stream — the substrate detects and
preserves, it does not adjudicate.

#### AV-61: Witness divergence escalated to drive the quorum-merge

**Attack**: an adversary submits a witness whose root *diverges* from a
peer's and attempts to have that witness **decide** the resulting merge —
e.g. supply a "winning" root or a fragment that resurrects a revoked key or
replaces the `monotonic_quorum` / `revision` outcome. This is the worst-case
bug class: the divergence *detector* being mistaken for a divergence
*resolver*.

**Mitigation v8.2.0 (#228/#229, security-critical)**: a **Divergent**
verdict returns only the directive `WitnessReconcileAction::TriggerQuorumMerge`,
which **carries NO winner and NO root**. The witness triggers the
**pre-existing V058 R1/Q1 quorum-merge** for `revocation` / `partner_record` /
`org_membership` (`QUORUM_MERGE_SUBJECT_KINDS`); the caller fulfils it by
re-running `operational::resolve_monotonic_quorum` / the `revision`
anti-rollback over the **stored rows**. The witness root **never enters that
resolution** — there is **no "reconstitute from any fragment" path**, so a
revoked key cannot be resurrected, and the witness cannot replace
`monotonic_quorum` / `revision`.

**Secondary**: the divergence path is structurally subordinate by
construction — the directive type *cannot* carry a root, so a caller cannot
accidentally let a witness decide a merge. Regression-tested
(`tests/wholeness_witness.rs` (e)): Divergent → `TriggerQuorumMerge` only,
then `resolve_monotonic_quorum` keeps the **REVOKED** record (a revoked key
is not resurrected).

**Residual**: the merge correctness rests on the V058 quorum-merge resolvers
(their own threat surface), not on the witness — which is the intended
trust boundary. The witness only *signals* that a merge should run.

#### AV-62: Witness anti-rollback / eclipse (stale signed witness replay)

**Attack**: an adversary captures a peer's older, validly-signed witness and
replays it as if current — an eclipse/rollback attempt to make the peer's
stale view of its holdings authoritative again.

**Mitigation v8.2.0 (#228/#229)**: `witness::accept_if_monotonic` +
`FederationDirectory::last_witness_epoch_for_peer` enforce a **strict-epoch
monotonic guard** — before a peer's witness is acted on as newer, its
`epoch_id` MUST strictly advance the last accepted epoch for that peer; a
stale or replayed epoch is rejected (§19 N4). Separately,
`put_wholeness_witness` runs **`verify_witness` PQC-before-persist** (N3 /
§10.1.5.1.1): a missing/invalid ML-DSA-65 half is rejected at the gate
(`Error::WitnessAdmit`, token `witness_admit_hybrid_required`) and **nothing
is written** — store-then-quarantine is non-conformant (verify-before-mutation,
AV-9).

**Secondary**: the corpus is pruned to the last-K (`WITNESS_CORPUS_K = 8`)
verified witnesses per peer, idempotent on the PK
`(peer_id, epoch_id, observed_at_unix_ms)`; there is **no `verified` column**
(§19.0 F-5) — the verdict is recomputed at the gate, never read from the wire.

**Residual**: the monotonic guard is per-peer epoch ordering; it does not
defend against a peer that legitimately re-signs an honest stale view at a
*new* epoch (that is the peer's own correctness concern, surfaced via the
divergence path AV-61, not a replay).

#### AV-63: WW-2 deniable-content re-attribution

**Attack**: a naive "gather every CEG envelope this peer holds" sweep would
fold **anonymous-tier** or `cohort_scope: self` rows into the signed,
federating WholenessWitness root — re-attributing deniable / self-private
content to a stable, accountable `peer_id` and leaking it through
`claim_namespaces`.

**Mitigation v8.2.0 (#228/#229)**: `witness::build_local_witness`
(persist's responsibility — persist owns the leaf walk) **FILTERS OUT**
anonymous-tier rows, `cohort_scope: self` rows, and any leaf whose namespace
itself names self/anonymous **BEFORE** computing the Merkle root; the
witness's `claim_namespaces` is drawn only from the survivors, so it
**provably never names anonymous/self** (WW-2 namespace guard, re-checked by
`verify_witness` at admission).

**Secondary**: the namespace guard is enforced on **both** sides — persist
builds clean and `verify_witness` rejects a witness whose namespaces name
self/anonymous, so a hand-crafted malicious witness is also rejected at the
gate (AV-62).

**Residual**: the filter operates on the persist-side classification of a
row's tier/`cohort_scope`; correct tagging at write time is the AV-57/AV-58
write-side surface (a row mis-tagged non-self at write would not be filtered
— but that mis-tag is itself the AV-58 vector, gated separately).

#### AV-64: Forged `aggregation_meta` on the store path

**Attack**: an adversary submits a `put_aggregated_tier` call with a tampered
or unsigned `aggregation_meta` (wrong `member_commitment`, fabricated descent
fields, or a classical-only signature) to plant a forged §19.7 composite in
the forever-memory pyramid.

**Mitigation v8.4.0 (#230)**: `put_aggregated_tier` runs the **§19.7.1
bound-hybrid gate at admission, BEFORE persistence** (verify-before-mutation;
never store-then-quarantine). Persist reconstructs the verify-core wire
`AggregationMetaV1` from the §19.7.1 normative fields + the bound-hybrid
signature (`AggregationMetaVerifyInputsV1`), resolves the aggregator hybrid
pubkeys off the composite manifest envelope (`pubkey_ed25519` /
`pubkey_ml_dsa_65`, bound into the verify), and calls
`ciris_verify_core::holonomic::verify_aggregation_meta`. A **missing/invalid
ML-DSA-65 half is REJECTED** (`aggregation_meta_hybrid_required`, the same
store-path PQC mandate as AV-59, §10.1.5.1.1); a tampered meta
(sig ≠ §19.7.1 preimage) rejects (`aggregation_meta_invalid`); both leave
**ZERO rows**. The composite manifest still rides the existing #225 hybrid
admit gate in the same transaction.

**Secondary**: the storage column stays **opaque** BYTEA/BLOB (V086 unchanged
across the §19.7 freeze — the wire-churn firewall); the verification inputs
are **admission-only and are never persisted**, so a stored row cannot carry
unverified meta that a later read would trust.

**§19.7.3 complete (v8.6.0)**: the `EjectAggregatedTierOnly { tier }`
`EjectionVerdict` variant (CEG RC16) is now **consumed** — verify-core
v5.11.0 exposes it and persist drives the tier-granular single-stratum shed
(`evict_aggregated_tier(aggregate_content_id, tier)` →
`EjectionAction::EjectAggregatedTierOnly(tier)`): it sheds exactly the
tier-`tier` composite's symbols (manifest survives `EnvelopeOnly`) while the
finer (lower-level) AND coarser (higher-level) composites stay intact. It
composes with hard-delete — a stratum already below the floor is unreachable,
so it **never resurrects erased content**. The full §19.7.3 ejection surface
(`Keep` / `EjectToTier` / `EjectAggregatedTierOnly` / `EjectHardDelete`) is
now driven from verify-core.

#### AV-65: Forged aggregation source set (descent integrity)

**Attack**: an adversary calls `descend_aggregated_sources` with a forged set
of source `content_id`s — one that does not re-derive the committed
`member_commitment` — to drive eviction/descent of items that were never
members of the composite (using descent as a force-evict channel).

**Mitigation v8.4.0 (#230)**: `descend_aggregated_sources` loads the stored
aggregation record and calls **`verify_member_commitment` over the
caller-supplied source `content_id`s BEFORE descending** — a forged member
set (one that does not re-derive the committed `member_commitment`) is
**REJECTED** and cannot drive eviction. Sources descend in the canonical
`descend_order` (§19.7.2 lexicographic member-id order), so a returned list
re-derives the parent's `member_commitment` byte-for-byte. This is the
§19.1 Merkle scheme's intended use: **full source-id-list recomputation,
never a partial inclusion proof** against a bare root — which is exactly why
the RC15 no-RFC-6962-prefix freeze leaves CVE-2012-2459 odd-node malleability
non-exploitable here.

**Secondary**: the `member_commitment` is mandatorily hybrid-signed as part
of the composite manifest (AV-64), so the committed root an adversary must
re-derive is itself authenticated; a forged member set fails recomputation
against a root it cannot forge.

**Residual**: descent integrity is a function of the committed member list;
it does not attest *why* a given member was aggregated (the N→1 resampling
compute is edge-side, CIRISEdge#133/#134) — persist verifies membership, not
the codec's resampling fidelity.

#### AV-66: Rarity-driven retention resurrecting revoked content

**Attack**: an adversary inflates a `content_id`'s rarity / `retention_priority`
(e.g. via the swarm rarity reweight packed into the priority byte's top bits)
so that a **revoked / withdrawn** content survives eviction — using rarity as
a channel to keep individually-recoverable content that consent has
withdrawn (the §19.3 N5 erasure-vs-rarity tension).

**Mitigation v8.1.0 / v8.2.0 (#228, N5)**:
`evict_fountain_content_hard_delete` is a **SEPARATE path that never consults
`retention_priority`** — it drops **every** symbol row unconditionally,
leaving the manifest as the always-retained `EnvelopeOnly` provenance. The
tier/keep-count path (`evict_fountain_content_to_tier`) is the *only* consumer
of `retention_priority` (and of any future swarm rarity reweight), so a high
rarity score **cannot reach — let alone resurrect — a revoked content**.
`evict_fountain_content_by_consent` + `fountain::resolve_retention_action`
drive `ciris_verify_core::holonomic::retention_decision` / `ejection_verdict`:
a `Withdrawn` subject (→ `EjectHardDelete`) routes to the hard-delete path
regardless of `is_rare`. **Revocation overrides rarity — by construction, not
by comparison** (revocation is a content-level dominating signal, never a
value competing inside the priority byte).

**Secondary**: N6 — `fountain::holding_claim_counts`
(`holding_claim_counts_toward_rarity`) gates rarity on a possession-proven
holding claim, so an **unverified/unchallenged** holding claim cannot lower
another peer's retention priority (rarity is not a forgeable force-evict
channel either).

**Residual**: hard-delete drops individually-recoverable symbols but the
manifest (and any collective composite the content was folded into, AV-65)
persist as `EnvelopeOnly` / below-the-noise-floor blur — §19.3 N5 requires
**not individually recoverable**, not destruction of the collective gist
(this is by design — "fades but cannot be falsified", §19.7).

### 3.15 Constitution-alignment surface (CIRIS Constitution 0.1.5, v9.0.0)

The v9.0.0 constitution-alignment cut binds persist to the CIRIS
Constitution 0.1.5 substrate clauses. Two of these close attack surfaces
that were previously **unmodeled** at the per-row admission grain, and the
adversarial review of the cut surfaced four bypasses in the new gates —
fixed at root in the same cut (CHANGELOG `## [9.0.0]` F1–F5). The §19
verifiers are unchanged; these vectors are about *admission gating* over
the federation directory + community substrate, not crypto. Note: AV-59
(§3.14) is the **same forge-later class as CC 5.3.2.4.3** named at the
trace-store path — AV-67 below extends that exact mandate from the
fountain/witness/aggregation store-paths to the **bulk federation-tier
attestation testimony corpus**, the single most forge-exposed surface
(CC 5.3.2.4.3's "store at massive scale" CEWP crux); AV-60/AV-61 (witness
divergence) relate to federation-tier reconciliation but are gated by the
§19 PQC witness gate (AV-62), not the per-trace ingest gate.

#### AV-67: Federation-tier forge-later via unverified per-trace ingest (CC 5.3.2.4.3.1)

**Attack**: a CRQC-era adversary who has broken Ed25519 mints a backdated
federation-tier `attestation` under a historical key and writes it to the
durable, content-addressed, replicated testimony corpus via
`put_attestation`. **Pre-v9.0.0, this surface was unmodeled at the
per-trace grain**: `put_attestation` ran only the trust-**threshold**
`AdmissionGate::check_federation` on the *key* and then INSERTed — a
federation-tier row's envelope hybrid signature
(`scrub_signature_classical` / `scrub_signature_pqc`) was merely
**stored**, never *verified* at the per-trace write/replicate path.
Hybrid-verify-at-gate existed only on `register_federation_key` (v8.8.0)
and the fountain store-path (v8.4.0, AV-64) — NOT on the bulk testimony
corpus, the single most forge-exposed surface in the federation. The
`tier = federation` label was trusted. Content-addressing is no defense:
the adversary hashes their own forgery, so the address matches by
construction (CC 5.3.2.4.3).

**Mitigation v9.0.0 (#237, BREAKING, CC 5.3.2.4.3.1)**:
`federation::verify_federation_tier_ingest` is the reusable per-trace gate
— the federation-tier sibling of `register::verify_key_registration` with
byte-for-byte the same verify contract: canonicalize `attestation_envelope`
through the CEG produce gate (`ceg_produce_canonicalize`, JCS post-#871),
cross-check `SHA-256(canonical) == original_content_hash` (canonicalizer
agreement, fail-secure), resolve the attester's **REGISTERED** pubkeys via
`lookup_public_key` (an unknown/unregistered attester ⇒ reject — never
verifies against pubkeys carried on the row alone), then `verify_hybrid`
under `HybridPolicy::Strict` (BOTH Ed25519 over `JCS(envelope)` AND
ML-DSA-65 over the bound `JCS(envelope) ‖ ed25519_sig` REQUIRED). Wired
into `put_attestation` on all three backends, composed with — not
replacing — the trust-threshold `check_federation`, running BEFORE
`persist_row_hash` + INSERT (verify-before-mutation, AV-9;
store-then-quarantine is non-conformant per CC 5.3.2.4.3.1). A rejected
row (classical-only / tampered / canonicalizer-mismatch /
unregistered-attester) leaves zero rows; typed
`Error::FederationTierUnverified` (token
`federation_federation_tier_unverified`).

**Secondary**: **local-tier is EXEMPT** — the gate is a no-op for
`tier = local` rows (CC 5.3.2.2 deferred signature; producer-only
authority, self-read-only), proven by the `tier_ingest_matrix` arm (e):
LOCAL-tier without PQC → ADMITTED (no over-rejection). The gate also
exposed a systemic classical-only-federation-tier-`withdraws` emitter gap
(evict/sweeper/takedown emitters built `tier = federation` WITHDRAWS with
`scrub_signature_pqc: None`); **fixed in the same cut** — the emitter now
hybrid-signs via the engine's PQC-capable `LocalSigner`, and a non-PQC
engine (constructed via `from_shared`) returns a CLEAR typed error rather
than emitting a classical-only or silently-skipped withdraws (fail-honest,
§1.6 MISSION).

**Residual**: **BREAKING** — classical-only federation-tier rows admitted
pre-v9.0.0 are now non-conformant and rejected; non-PQC producers are
confined to local-tier until they complete PQC wiring (intended — the
forge-later mandate is the price of HNDL-completeness, CC 5.2). The
per-trace corpus/bandwidth cost rises with the ML-DSA-65 half exactly as
the trace-store path (AV-59). Verifies against the **registered** key, so
a forged PQC pubkey on the row alone fails.

#### AV-68: Node-only key receiving agency via `delegates_to` (CC 4.4.3.4.3 / CC 1.13.5)

**Attack**: an adversary writes a `delegates_to` whose recipient is a
fabric/infrastructure key (`identity_type: node`, CC 3.4.7.1) but whose
scope grants **agency** (`agency:act_on_behalf` / `:message_io` /
`:reason` / `:decide`, or a legacy unprefixed agency kind) — making a
piece of infrastructure able to reason/act AS a principal, violating
"infrastructure must not have agency" (CC 1.13.5, quoted by CC 4.4.3.4.3
"Partnership WITHOUT agency"). The Constitution pins a reserved two-prefix
delegation scope split (`infra:*` server-class / `agency:*` brain-only) so
a verifier can enforce this cryptographically; pre-v9.0.0 persist did not.

**Mitigation v9.0.0 (#235/#236, CC 4.4.3.4.3 / CC 1.13.5)**:
`federation::admission::check_node_agency_admission`, wired into
`put_attestation` on all three backends alongside the existing
withdraws/delegated-duty gates, verify-before-mutation (AV-9 — a rejected
emission leaves no trace). For a `delegates_to` it resolves the recipient
(`attested_key_id`) via `lookup_public_key`; **only a recipient resolving
to a `node`-ONLY identity is constrained** — its scope set MUST satisfy
`scopes_are_infra_only` (non-empty AND every token starts with `infra:`),
else REJECTED with typed `Error::NodeAgencyForbidden` (token
`federation_node_agency_forbidden`), not stored. The canonical
`identity_type::NODE` token + `delegation_scope` vocabulary (the `infra:*`
/ `agency:*` constants + `LEGACY_AGENCY_KINDS`) are published so
producer + verifier agree byte-for-byte.

**Secondary**: **no over-rejection** — a non-node recipient (an `agent`/
brain key) may legitimately carry `agency:*`, and a `{node, agent}` hybrid
is not node-only, so neither is constrained. An **unresolved** recipient
passes this gate but is independently FK-rejected by every backend's
`put_attestation` (the `attested_key_id` must exist in `federation_keys`),
so an agency delegation to a node key can never be persisted. CIRISServer's
`src/auth/ownership.rs` enforcement becomes a thin wrapper over this
substrate gate.

**Residual**: the gate constrains the *delegation scope*, not what a
recipient does with a key it already controls out-of-band; the wire-format
invariant is "a node-only key's delegation literally cannot carry agency,"
which is the structural property CC 1.13.5 names. **Closed v9.0.0; see
AV-71 for the duplicate-token bypass closed in the same cut.**

#### AV-69: Unowned node/agent admitted to a non-infra community (CC 3.2 / CC 3.4.7.1)

**Attack**: an adversary writes a `put_community` whose roster includes a
`node`- or `agent`-role key with **no owner-binding to an accountable
human** — granting a bare, unowned node standing to speak AS the group.
Per CC 3.2, non-infra community membership is an **authority act** and
CC 1.13.2 requires authority to root in a `user`-role human; pre-v9.0.0
`put_community` ran only `check_consensus_protocol_form` + the geographic
gate and admitted the unowned member.

**Mitigation v9.0.0 (#235, CC 3.2 / CC 3.4.7.1)**:
`federation::admission::check_community_membership_owner_binding`, wired
into `put_community` on all three backends after the geographic gate and
before the write lock / `persist_row_hash` / INSERT (verify-before-mutation,
AV-9). It reuses the `is_owner_bound(K)` predicate (CC 3.4.7.1 — a live,
unrevoked path from `K` to a `user`-role identity); **only members
resolving to `node` or `agent`** are constrained — the first such member
lacking a live owner-binding REJECTS the whole write with typed
`Error::UnownedCommunityMember` (token
`federation_unowned_community_member`), not stored. A `user`-role member
is trivially owner-bound.

**Secondary**: the **infrastructure carve-out** (CC 3.2 "Trust ≠
membership") — a community whose `policy_blob.cohort_subkind ==
"infrastructure"` is exempt (a node MAY trust + serve an infra community
with no owner). The gate is a **precondition**, NOT a substitute for the
community's own `consensus_protocol` vote.

**Residual**: an unresolved or non-node/agent member is out of scope (no
over-rejection). The carve-out's authority is itself gated — **see AV-72
for the self-label bypass closed in the same cut.**

#### AV-70: Community-DEK not rotated on member removal (CC 4.4.3.2.2)

**Attack**: a removed community member retains a valid wrap of the shared
per-community DEK and continues to decrypt **new** community content sealed
after its removal — a forward-secrecy break. Community content
(`cohort_scope: community | affiliations`) is sealed under one shared DEK
(CC 4.4.3.2.1 — "a community is a stream its members subscribe to,
cryptographically"); without rotation, removal is not forward-secret.

**Mitigation v9.0.0 (CC 4.4.3.2.2, Option-A forward secrecy)**:
`put_community_membership_revocation` **bumps the community DEK epoch**
(`community_dek_bump_epoch`) on all three backends as part of the
revocation write. The NEXT emission mints a FRESH DEK for the new epoch
wrapped only to remaining members (`encrypt_and_cascade_community` resolves
the active roster = `lookup_community` ∖ effective revocations); a removed
member's keys can never unwrap it. **Exposure window = zero** — the bump is
part of the revocation write and every subsequent emission reads the bumped
epoch. All wraps are `wrap_algorithm: v2` (`x25519_mlkem768_...`, FIPS-203
hybrid) — NEVER v1 (CC 4.4.3.4.1 / CC 5.2 HNDL); a member without a valid
ML-KEM-768 key is fail-secure **excluded** (no grant, never plaintext) and
surfaced non-silently as `hard_case:recipient_excluded` (CC 5.2). The
`wrap_algorithm` CHECK in V087 makes a v1 row unrepresentable.

**Secondary**: **forward-only** — blobs sealed under the old epoch keep
their grants (the removed member keeps what it could already read; receives
no NEW content). This is a flat per-member re-wrap, deliberately NOT MLS
TreeKEM (full CC 5.1 TreeKEM is the RET transport layer's open question,
not the substrate's). Infrastructure communities (`cohort_subkind:
infrastructure`, governance roots) opt OUT — Commons-tier plaintext, no
DEK (CC 4.4.3.2.1, the trust root must be publicly auditable).

**Residual**: PCS for a *currently-admitted* member's compromised key is
not provided (Option-A is forward-only, CC 1.13.3.1 — MISSION §1.9).
**See AV-72 (F4) for the future-dated-`effective_at` forward-secrecy hole
closed in the same cut.**

#### AV-71: Node-agency gate bypass via duplicate `identity_type` token (CC 1.13.5 / CC 4.4.3.4.3, F1)

**Attack**: an adversary registers a node key with a **duplicate**
`identity_type` token — `"node,node"` or `"node, node"` — then delegates
`agency:*` to it. The v9.0.0 `check_node_agency_admission` (AV-68) decided
"is this recipient node-only?" with `parse_set(identity_type) == [NODE]`,
but `parse_set` does **not** dedup — so `["node","node"] != ["node"]`
**skipped the gate**, letting a pure-`node` key receive agency and
defeating CC 1.13.5.

**Mitigation v9.0.0 (#237 adversarial review, F1)**: the gate now tests
the identity_type **set** via a `HashSet<&str>` (`set.len() == 1 &&
set.contains(NODE)`), robust to duplicate / whitespace / order tokens.

**Secondary**: a genuine `node,agent` hybrid is still ADMITTED (it
legitimately carries agency — no over-reject); regression-tested
(`"node,node"` / `"node, node"` carrying `agency:*` → REJECTED + not
stored) on all three backends.

**Residual**: none for this token-canonicalization class; the set-semantics
match the CC 3.4.7.1 `identity_type`-is-a-set definition.

#### AV-72: Authority/forward-secrecy bypasses in the new community gates (CC 3.2 / CC 4.4.3.2.1 / CC 3.4.7.1 / CC 4.4.3.2.2, F2–F5)

**Attack (four sub-vectors, all closed v9.0.0 by the adversarial review)**:

- **F2 — self-labeled `cohort_subkind: infrastructure`.** Any caller could
  self-label a community `infrastructure` to skip the AV-69 owner-binding
  precondition AND force its content to Commons-plaintext (no DEK,
  AV-70) — both gates honored the label with **no authority check**.
  **Mitigation**: `is_authorized_infrastructure_community` honors the
  carve-out **only if** the community's own key (`community_key_id`, via
  `lookup_public_key`) has an `identity_type` set containing
  **`substrate_persist`** (the reserved governance/substrate authority).
  Used in BOTH gates; **fail-secure** — an unauthorized infra-labeled
  community falls through to the STRICTER non-infra path (owner-binding
  REQUIRED + DEK cascade APPLIES).
- **F3 — `is_owner_bound` honored revoked/expired delegations.** Clause 3
  ("∃ a live `delegates_to(U → k)` from a `user`-role granter") accepted
  ANY `delegates_to` — a `withdraws`/`recants`-retracted or lapsed
  delegation still conferred owner-binding (AV-69 bypass). **Mitigation**:
  an edge is now skipped if the granter has a `withdraws`/`recants`
  against `k` (the §11.10 edge-retraction model, recipient named as
  `attested_key_id`) or if `expires_at <= now`; only a genuinely live edge
  confers owner-binding.
- **F4 — rotation forward-secrecy hole for future-dated `effective_at`.**
  `put_community_membership_revocation` bumped the epoch at write time, but
  `resolve_community_members` only dropped a member once `effective_at <=
  now` — a revocation with `effective_at = now + 30d` bumped the epoch yet
  kept wrapping the "removed" member into the fresh-epoch DEK for the whole
  window, falsifying AV-70's "exposure window = zero." **Mitigation**:
  community membership revocation is now **immediate** — a future-dated
  `effective_at` (beyond a 60s clock-skew tolerance) is REJECTED with typed
  `Error::InvalidArgument` BEFORE any write, on all three backends.
- **F5 — revocation INSERT + `hard_case` emission + epoch bump not
  atomic.** A bump failure after the INSERT committed left a durable
  un-rotated revocation (a silent forward-secrecy gap). **Mitigation**:
  wrapped in ONE transaction per backend (postgres `client.transaction()`;
  sqlite `conn.transaction()` under a single lock); memory is already
  atomic under its state lock.

**Secondary**: each fix has a test that fails without it and passes with
it, on all three backends where the path runs (CHANGELOG `## [9.0.0]`
"Fixed — security review").

**Residual**: these close the v9.0.0 gates' own bypasses; they do not add
new substrate authority — the carve-out authority (`substrate_persist`) is
the same reserved governance role that already owns `system:` /
`audit_chain:` / `corpus_health:` reserved prefixes (§3.7).

---

## 4. Mitigation Matrix

| AV | Attack | Primary Mitigation (v0.1.1) | Secondary | Status | Fix Tracker |
|---|---|---|---|---|---|
| AV-1 | Forged trace from attacker key | Public-key directory lookup | N_eff drift detection (lens-side) | ✓ Mitigated | — |
| AV-2 | Forged trace from compromised key | (out of scope at persistence layer) | Audit anchor + Phase 2 peer-replicate | ⚠ Phase 2 closes | FSD §4.5 |
| AV-3 | Replay of legitimate batch | Idempotency on dedup key | TLS at edge | ✓ Mitigated | — |
| AV-4 | Canonicalization mismatch | Byte-exact parity tests + pluggable canonicalizer + `WireDateTime` preserves wire bytes verbatim through canonicalization | Ed25519 collision resistance | **✓ Mitigated v0.1.8** (timestamp closed; float drift residual untriggered, tracked) | — |
| AV-5 | Schema-version flood (mem leak) | `Cow<'static, str>` (no leak) | (deploy-edge rate limit) | **✓ Mitigated v0.1.2** | — |
| AV-6 | JSON-bomb amplification | `MAX_DATA_DEPTH=32` walker | Bounded queue + typed envelope | **✓ Mitigated v0.1.2** | — |
| AV-7 | Body-size flood | `DefaultBodyLimit::max(8 MiB)` | Deploy-edge proxy | **✓ Mitigated v0.1.2** | — |
| AV-8 | Queue saturation | 429 + Retry-After | Single-consumer transaction discipline | ✓ Mitigated | — |
| AV-9 | Dedup-key collision across agents | `agent_id_hash` in UNIQUE index + ON CONFLICT target | trace_id "globally unique per agent" convention | **✓ Mitigated v0.1.2** | — |
| AV-10 | Audit anchor injection | (anchor not part of dedup key) | Phase 2 peer-replicate validates chain | ⚠ Phase 2 closes | FSD §4.5 |
| AV-11 | Public-key re-registration | First-write-wins (`ON CONFLICT DO NOTHING`) + lens-canonical `revoked_at`/`revoked_reason`/`added_by` audit columns | Manual UPDATE for legitimate rotation | ⚠ No explicit rotation API | v0.2.x |
| AV-12 | Schema-version downgrade | Strict allowlist | Per-version payload gates | ✓ Mitigated | track at version bump |
| AV-13 | JSONB injection | Parameterized typed binding | — | ✓ Mitigated (Phase 3 follow-up) | Phase 3 audit |
| AV-14 | Scrubber bypass via schema-altering callback | Schema-preservation gates | Python process boundary | ✓ Mitigated | — |
| AV-15 | PII leak via errors | Typed `kind()` tokens at HTTP/PyO3 boundary; verbose form to tracing logs only | — | **✓ Mitigated v0.1.2** | — |
| AV-16 | Side-channel timing | Ed25519 verify_strict constant-time | (no constant-response wrapper) | ⚠ Directory enumeration possible | v0.2.x research |
| AV-17 | Integer truncation on `attempt_index` | Typed `MAX_ATTEMPT_INDEX = 1024` + `try_into` bound | `overflow-checks = true` on release profile (defense in depth) | **✓ Mitigated v0.1.3** | — |
| AV-18 | Plaintext Postgres connection | Optional `tls` feature — `tokio-postgres-rustls` | `sslmode=verify-full` via DSN | **✓ Mitigated v0.1.3** | — |
| AV-19 | No graceful shutdown / lost in-flight commits | `tokio::signal::ctrl_c` + drain protocol; producer close → persister drains → exit | Journal preserves bytes-on-failure (FSD §3.4 #2) | **✓ Mitigated v0.1.3** | — |
| AV-20 | No statement_timeout on Postgres | (deferred) | Pool size limits | ⚠ Track | v0.2.x |
| AV-21 | No per-agent rate limiting | (deferred) | Shared-queue 429 backpressure | ⚠ Track; PoB §5.6 acceptance policy adjacent | v0.2.x |
| AV-22 | No clock-skew validation on incoming timestamps | (deferred) | Retention-window absorbs out-of-window data | ⚠ Track | v0.2.x |
| AV-23 | `consent_timestamp` range unconstrained | (deferred) | Schema-required-or-422 gate (TRACE_WIRE_FORMAT.md §1) | ⚠ Track | v0.2.x |
| AV-24 | Lens-scrub bypass / forgery | UNCONDITIONAL signed scrub envelope (FSD §3.3 step 3.5; §3.4 robustness primitive #7) — every component, every level, key never null. `original_content_hash + scrub_signature + scrub_key_id + scrub_timestamp` columns proof the deployment's handling. | Single-key principle — agent uses its existing wire-format §8 key; no separate scrub key to compromise | **✓ Mitigated v0.1.3** | — |
| AV-25 | Scrub-key compromise | Hardware-backed `ciris-keyring` (TPM / Secure Enclave / StrongBox / DPAPI) — seed never leaves the keyring; never crosses the FFI boundary | `SoftwareSigner` fallback for hardware-less deployments (named residual) | ✓ Mitigated where hardware available; ⚠ residual on software-fallback | CIRISVerify hardware-attestation tier governs |
| AV-26 | Multi-worker migration race | Session-scoped `pg_advisory_lock(0x6369_7269_7370_7372)` on dedicated single-use connection in `run_migrations()` — workers serialize on cold-boot, lock auto-releases on session close (incl. panic) | `Error::Migration { sqlstate, detail }` surfaces SQLSTATE for lens-side retry policy | **✓ Mitigated v0.1.5** | — |
| AV-27 | Identity churn via ephemeral keyring storage | Boot-time check via authoritative `HardwareSigner::storage_descriptor()` (ciris-keyring v1.8.0). Typed dispatch: `SoftwareFile` ⇒ ephemeral-path heuristic; `SoftwareOsKeyring{User}` ⇒ logout-bound warn; `InMemory` ⇒ hard warn. `Engine.keyring_path()` + `Engine.keyring_storage_kind()` expose authoritative path / classifier for `/health` | Suppression via `CIRIS_PERSIST_KEYRING_PATH_OK=1` after operator audit; `INTEGRATION_LENS.md §11.5` deployment template guidance | **✓ Mitigated v0.1.7 (predicted) / v0.1.9 (authoritative via upstream trait method)** | — |
| AV-28 | Federation_keys directory pubkey poisoning | Idempotent on `(key_id, persist_row_hash)` — INSERT ON CONFLICT DO NOTHING + post-insert hash check returns typed `Error::Conflict` on key_id collision with differing content; never silent overwrite | Per-row scrub envelope verified consumer-side; PoB §6 statistical drift detection at federation level | **✓ Mitigated v0.2.0** | — |
| AV-29 | Attestation graph poisoning | Persist exposes edges only — no `is_trusted()` / `trust_score()` / `trust_path()`. Consumers compose policy; per-row scrub-envelope verify before counting any edge | Append-only graph (revocations observed, not retroactive deletes); poisoning is additive | ✓ Mitigated by architectural non-goal — consumer-side policy required | — |
| AV-30 | Federation_keys self-FK integrity | `DEFERRABLE INITIALLY DEFERRED` on the self-reference; constraint check at COMMIT, not row insert; bootstrap rows resolve their own FK by transaction commit | Standard FK semantics for non-bootstrap rows | **✓ Mitigated v0.2.0** | — |
| AV-31 | Hybrid-pending exploitation (Ed25519 break + soft-PQC window) | `HybridPolicy::Strict` rejects hybrid-pending; `SoftFreshness { window }` bounds acceptance to `row_age < window`; policy is per-call, no silent default | Bound signature pattern (PQC over `canonical \|\| classical_sig`) requires breaking BOTH algorithms to forge fully-verified rows | **✓ Mitigated v0.3.6** (Strict / Fallback are explicit; SoftFreshness window is caller-supplied) | — |
| AV-32 | Cold-path PQC denial-of-completion | Per-write cold-path on engine's tokio runtime (no external network/service to deny); v0.3.2 sweep primitive (`Engine.run_pqc_sweep`) provides recovery; `pqc_sweep_on_init=True` constructor default runs sweep at boot | Writer contract documented in V004 schema header; persist owns the implementation (CIRISPersist#10) | **✓ Mitigated v0.3.1+v0.3.2** | — |
| AV-33 | Bound-signature stripping (PQC over classical-only) | Hybrid scheme signs PQC over `(canonical \|\| classical_sig)`; persist's `HybridVerifier` rebuilds bound payload before PQC verify and rejects PQC-over-canonical-only | Matches CIRISVerify `HybridSignature` spec; primitive enforced at ciris-crypto layer, not reimplemented persist-side | **✓ Mitigated v0.2.0** | — |
| AV-34 | Cross-shape canonical injection at 2.7.0 | Deterministic dispatch by `trace_schema_version`; per-component `agent_id_hash` (v0.3.0) and `deployment_profile` (v0.3.4) silently ignored at 2.7.0 — don't enter canonical bytes, don't affect dedup; byte-identical canonical with vs. without injection at 2.7.0 | Schema-version-aware decompose at 2.7.9 requires the shape (typed `MissingField` on absence); regression tests assert byte-identity | **✓ Mitigated v0.3.0+v0.3.4** | — |
| AV-35 | Schema-version dispatch attack (try-N-shapes) | v0.3.0 deterministic dispatch — each trace contributes to exactly one canonical-shape verify path; verification is bound to the dispatch arm's canonical (a wrong-arm selection deterministically fails verify); v0.4.3 (`"2.7.legacy"` restoration) preserves the property — even though the routing input isn't itself signed at the legacy arm, a legacy-signed trace verifies only against the 2-field canonical | Typed `Error::UnsupportedSchemaVersion` rejects out-of-allowlist versions before dispatch (AV-12 overlap); telemetry-driven sunset rule (AV-42) bounds the legacy arm's lifetime | **✓ Mitigated v0.3.0; preserved at v0.4.3** | — |
| AV-36 | LLM_CALL parent-linkage substitution | v0.3.3 strict-parse at 2.7.9 — `MissingField("data.parent_event_type")` / `parent_attempt_index` rejects envelopes missing the wire fields; no substitution at 2.7.9 | Pre-v0.3.3 `parent_event_type='LLM_CALL'` rows tagged for RATCHET workaround via `handler_name`; new traffic post-v0.3.3 lands with spec-correct linkage | **✓ Mitigated v0.3.3** | — |
| AV-37 | deployment_profile cohort-identity injection | `deployment_profile` rides in 2.7.9 signed canonical bytes; agent's signature commits to declared labels; strict-parse at 2.7.9 rejects missing block (`MissingField("deployment_profile")`) | `deployment_resourcing` is intentionally lens-computed from cost/tokens/model observation, not agent-declared — labels can lie but emergent operational reality cannot | **✓ Mitigated v0.3.4** | — |
| AV-38 | Per-key DSAR scope violation | v0.3.6 BREAKING: `signature_key_id` is REQUIRED on `delete_traces_for_agent`; deletion is scoped to `(agent_id_hash, signing_key_id)` at all three substrate layers (trace_events, trace_llm_calls cascade, federation_keys cascade); no `Option<>` back-compat shim | Lens-side DSAR audit ledger captures request envelope + signature verification independent of persist | **✓ Mitigated v0.3.6** (broke v0.3.5 shape; v0.3.5 yanked from PyPI) | — |
| AV-39 | verify-via-persist bypass (consumer calls ciris_crypto direct) | `Engine.verify_hybrid` is the federation's single-source-of-truth — accepts arbitrary canonical bytes (not just CompleteTrace shapes), exposes the policy machinery (Strict / SoftFreshness / Ed25519Fallback), is the path of least resistance | Documented as the closure pattern (CIRISPersist#7); `docs/V0.2.0_VERIFY_SUBSUMPTION.md` carries the architectural reasoning | ✓ Architectural closure — not a runtime gate but the design path | — |
| AV-40 | Outbound queue disk exhaustion | Per-row `body_size_bytes ≤ 8 MiB` + `ttl_seconds > 0` + `max_attempts > 0` schema CHECK; `sweep_ttl_expired` operational primitive bounds row lifetime; FK on sender/destination_key_id (AV-28 trust boundary) | Operator-tunable sweep cadence; `oldest-pending-age` ops dashboard | **✓ Mitigated v0.4.0** | — |
| AV-41 | Spoofed in_reply_to ACK matching | ACK envelopes go through persist's normal verify pipeline (AV-1 unknown-key gate + AV-39 verify_hybrid via persist) before `mark_ack_received` is called; `body_sha256` content-derived matching is downstream of signature verify | Bound signature pattern (AV-33) closes Ed25519-alone forgery branch | **✓ Mitigated v0.4.0** | — |
| AV-42 | Legacy `attempt_index` dedup-collapse | v0.4.6 schema-version-gated fallback — only `2.7.0` / `"2.7.legacy"` arms fall back to `attempt_index = 0` on absence (`MissingField`); 2.7.9 still strict; malformed values (negative, wrong type, out of range) still error through AV-17 typed paths; fallback fires for absence ONLY, not for adversarial-shaped values; cross-agent collision closed by `agent_id_hash` in dedup tuple (AV-9) | Telemetry-driven sunset (`federation_canonical_match_total{wire="2.7.legacy"}` 7-day-zero soak); accommodation is time-bounded by empirical observation, not permanent | **✓ Documented residual v0.4.6** (deliberate fidelity trade-off; pre-2.7.8.9 traffic is unrecoverable otherwise — federation's append-only contract takes priority over per-row dedup fidelity for legacy arm) | — |
| AV-43 | Read-side adversary inference attack | v0.5.0 aggregate primitives return computed statistics (counts, means, z-scores, decay-series points), not per-trace content; `sample_count` / `trace_count` fields surface explicitly so callers gate k-anonymity at their layer (one-line check: `if agg.trace_count < K_THRESHOLD: refuse`); error kinds are closed-set `&'static str` (no attacker-controlled strings); AV-9 trace-scoped reads carry `agent_id_hash` so callers authorize per-trace access at their layer | Substrate exposes truthful aggregates; consumer composes k-anonymity policy (lens-side, sovereign-mode agent's own gate) — same architectural-non-goal pattern as AV-29 attestation graph (persist exposes edges, consumers compose policy) | **✓ Documented v0.5.0** (substrate surface; consumer-side policy required for inference resistance) | — |
| AV-44 | Rust panic escalates to process abort | v0.5.3 three-layer panic isolation: (1) `panic = "unwind"` in release profile lets PyO3's `catch_unwind` trampoline fire; (2) explicit `catch_unwind(AssertUnwindSafe)` wrapping every `#[pyfunction]` body converts panic payload to `LensQueryError(Exception)` — derives from `Exception` not `BaseException` so uvicorn catches as 500; (3) crate-wide `Row::get` → `try_get::<_, Option<T>>` sweep surfaces NULL as `None` at the decode layer, before panic candidates form | tracing::error captures every caught panic with payload + site; in-flight tokio tasks panicking in background are logged but don't propagate to Python (documented residual) | **✓ Mitigated v0.5.3** (closes CIRISPersist#24 failure class; original SECURITY_AUDIT_v0.1.2.md §4.2 abort rationale reframed for v0.5.x cdylib-in-uvicorn shape) | — |
| AV-45 | Graph node `attributes` JSONB unbounded write (storage exhaustion / parse-bomb) | v0.8.0 per-call size cap (default 1 MiB; configurable per deployment via `CIRIS_PERSIST_GRAPH_MAX_ATTRIBUTES_BYTES`) checked at `upsert_node` entry — payloads above cap rejected as typed `Error::InvalidArgument("attributes too large")`; per-row hash + signature envelope binds the canonical attributes to the signer, so post-write bloat (e.g. via an UPDATE-around-persist path) breaks signature_verified=TRUE. | JSONB GIN index on attributes carries its own cost-bound — Postgres rejects oversized GIN entries at index time as a backstop. | **✓ Mitigated v0.8.0** | CIRISPersist#34 |
| AV-46 | k-hop graph traversal fan-out abuse (CPU / memory exhaustion via deep recursion) | v0.8.0 absolute `MAX_KHOP_DEPTH = 16` enforced at trait method entry, before the recursive CTE runs; caller-supplied depth above the cap → typed `Error::InvalidArgument("max_depth exceeds bound")` (no silent clamp — caller sees the rejection); CTE itself uses `LIMIT N` per recursion level to bound the fan-out frontier. | Per-edge-type filter required at the trait surface — `traverse_k_hop` does not accept "all edges" wildcards; caller must name the relationship types. | **✓ Mitigated v0.8.0** | CIRISPersist#34 |
| AV-47 | Graph scope leakage (cross-tenant or cross-domain read via missing scope filter) | v0.8.0 every read method on `GraphService` requires `scope` as a non-optional parameter (typed `GraphScope` enum: `Local` / `Identity` / `Environment` / `Community`); SQL queries pin `scope = $N` in WHERE; type system refuses to call the read without naming the scope. | Per-row scope column NOT NULL CHECK at schema layer; legacy or future caller using `Engine` directly cannot bypass the scope filter. | **✓ Mitigated v0.8.0** | CIRISPersist#34 |
| AV-48 | UPSERT-by-version replay (stale write clobbers fresh state) | v0.8.0 `upsert_node` requires caller to pass `expected_version` matching the current row's `version` column; mismatch → typed `Error::Conflict("version stale; expected N got M")`; new row writes start at version=1 and increment on every successful upsert. | `updated_by` + `updated_at` columns + signed `signature` over canonical envelope let downstream audit reconstruct the rightful write order on disputed rows. | **✓ Mitigated v0.8.0** | CIRISPersist#34 |
| AV-49 | Audit-log hash-chain integrity violation (tamper / silent rewrite) | v0.8.1 `record_entry` re-derives `entry_hash` from canonical(entry minus `signature` + minus `entry_hash` itself) and rejects on mismatch with caller-claimed value (`Error::ChainIntegrity`); reads the current tail under `SELECT ... FOR UPDATE` to serialize writers, then asserts `prev_hash` matches tail's `entry_hash` (or `GENESIS_PREV_HASH = [0; 32]` for first-entry-of-tenant) AND `sequence_number = tail_seq + 1`; INSERT only fires when all four gates pass + Ed25519 signature verifies. | `UNIQUE (tenant_id, sequence_number)` schema constraint is the second gate; replay attempts surface as `Error::Conflict` if they slip past the chain check. Signature binds to canonical bytes that INCLUDE `entry_hash` — a chain rewrite that flipped `prev_hash` on downstream entries would invalidate this entry's signature too. | **✓ Mitigated v0.8.1** | CIRISPersist#35 |
| AV-50 | Audit-log chain fork — silent rewrite undetected by point reads | v0.8.1 `verify_chain(tenant_id, from_seq, to_seq)` walks the chain end-to-end and surfaces the FIRST observed break via typed `ChainVerifyOutcome::Break { at_sequence, reason: ChainBreakReason, detail }`. Five break categories: `EntryHashMismatch` (canonical re-derive ≠ stored), `PrevHashMismatch` (prev row's `entry_hash` ≠ this row's `prev_hash`), `SequenceGap` (non-contiguous numbers), `SignatureFailure` (Ed25519 verify fails), `GenesisPrevHashNotZero` (first entry's `prev_hash` ≠ zeros). All five fire independently — first one tripped halts the walk and reports. | Operationally: `verify_chain` is the audit-compliance primitive consumers run on demand or on a schedule. Compatible with both incremental verify (caller pins `from_seq`/`to_seq`) and full-chain verify (`to_sequence = None`). | **✓ Mitigated v0.8.1** | CIRISPersist#35 |
| AV-51 | Audit-log cross-tenant read (compliance scan leaks one tenant's chain to another's auditor) | v0.8.1 `list_entries` requires `AuditFilter.tenant_id: String` (non-empty) — empty `tenant_id` rejects with `Error::InvalidArgument("tenant_id is required (AV-51 — no cross-tenant reads)")` BEFORE any SQL fires. `verify_chain` same gate. Every SQL query pins `tenant_id = $N` in WHERE; the `(tenant_id, sequence_number)` UNIQUE index serves the per-tenant chain natively. | Federation-admin cross-tenant compliance scans (the legitimate cross-tenant use case) require an explicit federation-admin role tag on the caller's `federation_keys` row — that gate lands in v0.9.x (auth_tokens module). v0.8.1 closes the inadvertent cross-tenant leak; intentional cross-tenant compliance is deferred. | **✓ Mitigated v0.8.1** | CIRISPersist#35 |
| AV-52 | Telemetry label cardinality + size abuse (metric-axis explosion, storage exhaustion via unbounded labels JSONB) | v0.8.2 per-call labels JSONB size cap at the trait surface (default 4 KiB; configurable via `CIRIS_PERSIST_TELEMETRY_MAX_LABELS_BYTES`) — payloads above cap reject with `Error::InvalidArgument("labels too large")`. Bulk-record path validates EVERY row's labels BEFORE any I/O fires (no partial-batch landing). The `unique_label_combinations` field on each `MetricSummary` surfaces label-cardinality observability so operators can detect abusive callers post-rollup. | Per-`(tenant, metric_name)` cardinality cap (max 1000 distinct label-sets in 24h) tracked as a deferred enforcement — Postgres has no native cardinality CHECK; the runtime path is the right place. v0.8.x.y patch when a real consumer trips the soft limit. | **✓ Mitigated v0.8.2** (size cap); **⚠ Observability-only** (cardinality cap) | CIRISPersist#36 |
| AV-53 | Consolidation lock starvation (crashed worker holds lock forever, blocks all subsequent rollups for the tenant) | v0.8.2 `consolidate_period` acquires `cirisgraph.consolidation_locks` row via `INSERT … ON CONFLICT DO NOTHING`; on contention checks the existing lock's `locked_at` — if older than `STALE_LOCK_SECONDS = 3600` (1h), atomically breaks + re-acquires via `UPDATE … WHERE locked_at < NOW() - INTERVAL '3600 seconds'` and returns `broke_stale_lock: true` in the outcome (telemetry-actionable signal — operators investigate prior worker's failure mode). Fresh locks block the run with `ran: false` outcome (caller backs off). | Lock release on failure path via `DELETE` so a transient rollup error doesn't leave the lock orphaned for an hour. | **✓ Mitigated v0.8.2** | CIRISPersist#36 |
| AV-54 | TSDB summary chain integrity (TEMPORAL_NEXT edge points at a summary node that doesn't exist — broken temporal traversal across rollups) | v0.8.2 consolidator queries for prior period's summary via `SELECT … WHERE attributes @> {metric_name, tenant_id}` BEFORE inserting the TEMPORAL_NEXT edge; only writes the edge if a matching prior node exists. The cirisgraph.edges schema permits dangling edges by design (V013 — eventual consistency for general graph writes), but the consolidator's write path doesn't exploit that flexibility — it confirms the source summary exists at write time. | Idempotency: re-running consolidation on the same period UPSERTs the summary node (version-bump) without writing a redundant TEMPORAL_NEXT (the prior-period lookup is gated by `period_start < req.period_start` so this period's summary isn't its own predecessor). | **✓ Mitigated v0.8.2** | CIRISPersist#36 |
| AV-55 | Incident state-machine bypass (regressive transition `closed → open` or `resolved → investigating` masks an unresolved issue as still-tracked, or hides a real recurrence as already-handled) | v0.8.3 `transition_state` reads current `state` under `SELECT … FOR UPDATE`, asserts `current.rank() < new.rank()` per the locked monotonic ladder (`open=0 → investigating=1 → resolved=2 → closed=3`), and rejects any regressive or same-state transition with `Error::InvalidTransition`. `resolution_notes` is REQUIRED when transitioning to `Resolved` or `Closed` (else `Error::InvalidArgument`). Same-state transitions also reject (caller must check current state explicitly if that's the intent). | Closed incidents do NOT dedup against new `record_incident` calls — a new occurrence after closure correctly opens a fresh incident row (the dedup probe is gated on `state IN ('open', 'investigating')`). | **✓ Mitigated v0.8.3** | CIRISPersist#37 |
| AV-56 | Incident correlation_keys abuse (unbounded JSONB array exhausts GIN index, or single-key bloat masks attacker-controlled identifiers in operator-facing UI) | v0.8.3 `record_incident` validates `correlation_keys` at the trait surface BEFORE any SQL fires: rejects when `len > MAX_CORRELATION_KEYS = 32` or when any single key's byte-length exceeds `MAX_CORRELATION_KEY_BYTES = 256`. Empty strings also rejected (no implicit "match-anything" key). GIN index on `correlation_keys` JSONB column serves the reverse-lookup path; bounded element count keeps index entries small. | Bounded inputs map to predictable GIN-index growth (`O(incidents × MAX_CORRELATION_KEYS)` worst case); operators sizing storage can plan deterministically. | **✓ Mitigated v0.8.3** | CIRISPersist#37 |
| AV-57 | Read-side cohort_scope escalation via caller-asserted admission (a reader forges `CallerScope::Authenticated { admission: { identity/families/communities = everything } }` to read self/family/community content it isn't a member of) | v4.0 `CallerAdmission` has NO public constructor — the sole way to obtain one is the substrate-side `build_caller_admission(engine, occurrence_key_id)`, which resolves identity / families / communities deterministically from `federation_identity_occurrences` / `federation_families` / `federation_communities`. The PyO3 boundary accepts only an `occurrence_key_id` string; no admission fields cross it. The §4.3 read predicate is pure target-membership: a row is admitted iff its `cohort_target_id` ∈ the reader's substrate-resolved sets — so a forged set cannot be constructed to begin with, and even the "shared cohort with emitter" leak class is eliminated (target-membership, not emitter-join). | Boundary auth (proving the caller controls the occurrence key's private key) is the caller-environment's responsibility (Ed25519 challenge / authenticated channel); persist trusts the boundary on key ownership and enforces visibility from what the chain admitted. Defense in depth: CIRISEdge#48-A re-checks cohort_scope at egress; joint `cohort_scope_double_miss_total` is the alert. | **✓ Mitigated v4.0** (closed by construction — private constructor + substrate-only builder) | CIRISPersist#160 |
| AV-58 | Write-side cohort_scope downgrade (a writer stamps a broader `cohort_scope` / a `cohort_target_id` for a cohort it isn't a member of — e.g. tags `community: C` it isn't in, or `federation` on self content — to broaden visibility) | v4.0 `DimensionAdmissionPolicy::check_write_cohort_scope` (§4.6) runs AFTER the verify gate, BEFORE persist (zero-writes-on-refusal, mirroring `signature_mismatch_rejected_no_writes`): a writer claiming `(family\|community, target)` must have that target ∈ its substrate-resolved admission, else `ScopeRefusalReason::No{Family,Community}Membership`. `self` targets are substrate-stamped from the verified signer (never caller-supplied); broad tiers carry no target. Wired into trace ingest + `put_attestation`. | Symmetric to AV-57 (same `CallerAdmission`, opposite direction). Edge pre-ingest verification is Layer 2; joint `cohort_scope_write_double_miss_total` is the alert. Attestations carry `cohort_scope` but no `cohort_target_id` column in v4.0, so family/community attestation writes are refused (no provable target) — a named follow-up column would relax this. | **✓ Mitigated v4.0** (verify→gate→persist; set-membership) | CIRISPersist#160 |
| AV-59 | HNDL forge-later on the durable trace corpus (backdated trace minted by a CRQC adversary who broke Ed25519) — the trace-store side of the CC 5.3.2.4.3 `tier=federation ⟹ hybrid present` invariant (the per-trace attestation corpus is AV-67) | v7.2.0 `verify_trace_hybrid` hard cut: `VerifyMode::Full` verifies BOTH halves via `verify_hybrid`(`Strict`); classical-only rejected at admission (`verify_hybrid_required`), no `require_hybrid: false` posture (store-path PQC, §10.1.5.1.1 / CC 5.3.2.4.3.1). | Verify-before-mutation step 2, before scrub/insert; dedup not moved ahead of verify; same cut on fountain manifests + aggregation meta. | **✓ Mitigated v7.2.0** (`2.7.legacy` import exempt as provenance-only) | CIRISPersist#225 |
| AV-60 | WholenessWitness equivocation (two signed roots, one peer) | v8.2.0 `reconcile_peer_witnesses`/`classify_stored` run `compare_witnesses`; Equivocation RETAINS both + emits `hard_case:witness_equivocation` (idempotent), NEVER reconciled (§19 N4, non-repudiable). | Only verified witnesses enter the corpus (AV-62 PQC gate); re-scan idempotent. | **✓ Mitigated v8.2.0** (detect + preserve; consumer adjudicates) | CIRISPersist#228 |
| AV-61 | Witness divergence escalated to drive the quorum-merge (witness supplies a winning root / resurrects a revoked key) | v8.2.0 Divergent → `WitnessReconcileAction::TriggerQuorumMerge` carrying NO winner / NO root; triggers the EXISTING V058 quorum-merge over stored rows (`resolve_monotonic_quorum` / `revision`); the witness root NEVER enters resolution — no fragment-pick, no revoked-key resurrection. | Directive type structurally cannot carry a root; tested (Divergent keeps the REVOKED record). | **✓ Mitigated v8.2.0** (witness = detector, not resolver) | CIRISPersist#228/#229 |
| AV-62 | Witness anti-rollback / eclipse (stale signed witness replay) | v8.2.0 `accept_if_monotonic` + `last_witness_epoch_for_peer` strict-epoch monotonic guard (epoch MUST strictly advance, §19 N4); `put_wholeness_witness` runs `verify_witness` PQC-before-persist (`witness_admit_hybrid_required`), zero rows on reject (no store-then-quarantine). | Corpus pruned to last-K (8) verified per peer; no `verified` column (§19.0 F-5 — verdict recomputed at the gate). | **✓ Mitigated v8.2.0** | CIRISPersist#228/#229 |
| AV-63 | WW-2 deniable-content re-attribution (self/anonymous rows swept into a signed federating root) | v8.2.0 `build_local_witness` FILTERS OUT anonymous-tier + `cohort_scope: self` + self/anonymous-namespaced leaves BEFORE the Merkle root; `claim_namespaces` drawn only from survivors (provably never names self/anonymous); `verify_witness` re-checks the namespace guard at admission. | Enforced on both sides (build clean + verify rejects); upstream tagging is the AV-57/58 surface. | **✓ Mitigated v8.2.0** | CIRISPersist#228/#229 |
| AV-64 | Forged `aggregation_meta` on the store path (tampered/unsigned §19.7 composite meta) | v8.4.0 `put_aggregated_tier` runs `verify_aggregation_meta` (§19.7.1 bound-hybrid) BEFORE persist; missing/invalid ML-DSA-65 → `aggregation_meta_hybrid_required` (store-path PQC §10.1.5.1.1), tampered → `aggregation_meta_invalid`; zero rows; composite manifest also rides the #225 admit gate in one tx. | Storage column stays opaque BYTEA/BLOB (V086 unchanged across freeze — wire-churn firewall); verify inputs admission-only, never persisted. | **✓ Mitigated v8.4.0** (`EjectAggregatedTierOnly` tier-granular stratum-shed consumed v8.6.0 — verify v5.11.0) | CIRISPersist#230 |
| AV-65 | Forged aggregation source set (descent as a force-evict channel) | v8.4.0 `descend_aggregated_sources` runs `verify_member_commitment` over the caller's source ids BEFORE descending — a set that doesn't re-derive the committed `member_commitment` is REJECTED; canonical `descend_order` (§19.7.2 lexicographic). Full source-id-list recomputation, never a partial inclusion proof (the §19.1 RC15-freeze CVE-2012-2459 non-exploitability rationale). | `member_commitment` is hybrid-signed in the composite manifest (AV-64) — the root to re-derive is itself authenticated. | **✓ Mitigated v8.4.0** | CIRISPersist#230 |
| AV-66 | Rarity-driven retention resurrecting revoked content (N5) | v8.1.0/v8.2.0 `evict_fountain_content_hard_delete` is a SEPARATE path that NEVER consults `retention_priority` — drops all symbols, manifest stays `EnvelopeOnly`; `resolve_retention_action` drives `retention_decision`/`ejection_verdict` (Withdrawn → `EjectHardDelete` regardless of `is_rare`). Revocation overrides rarity by construction, not by comparison. | N6 `holding_claim_counts` gates rarity on possession-proven claims (unverified claim can't lower another peer's priority). | **✓ Mitigated v8.1.0/v8.2.0** | CIRISPersist#228 |
| AV-67 | Federation-tier forge-later via unverified per-trace ingest (CC 5.3.2.4.3.1 — the CC 5.3.2.4.3 `tier=federation ⟹ hybrid present` invariant enforced at the bulk testimony corpus; same forge-later class as AV-59 at the trace-store path, previously unmodeled at the per-trace `put_attestation` grain) | v9.0.0 `verify_federation_tier_ingest` (`ceg_produce_canonicalize` JCS → `SHA-256 == original_content_hash` → `lookup_public_key` REGISTERED pubkeys → `verify_hybrid`(`Strict`), BOTH halves REQUIRED) wired into `put_attestation` on all three backends BEFORE `persist_row_hash`+INSERT (verify-before-mutation, AV-9); rejected ⇒ zero rows, typed `FederationTierUnverified`. Composed with — not replacing — `check_federation`. | **Local-tier EXEMPT** (CC 5.3.2.2 deferred sig; matrix arm (e) proves no over-reject). Exposed + fixed the classical-only `withdraws` emitter gap (evict/sweeper/takedown now hybrid-sign via `LocalSigner`; non-PQC engine fails honest, no silent skip). | **✓ Mitigated v9.0.0** (BREAKING — classical-only fed rows non-conformant; non-PQC producers local-tier-only) | CIRISPersist#237 |
| AV-68 | Node-only key receiving agency via `delegates_to` (CC 4.4.3.4.3 "Partnership WITHOUT agency" / CC 1.13.5 "infrastructure must not have agency") | v9.0.0 `check_node_agency_admission` wired into `put_attestation` (3 backends, verify-before-mutation): a `delegates_to` to a `node`-ONLY recipient (resolved via `lookup_public_key`, CC 3.4.7.1) MUST be `scopes_are_infra_only` (non-empty, every token `infra:`), else REJECTED `NodeAgencyForbidden` + not stored. Published `identity_type::NODE` + `delegation_scope` (`infra:*`/`agency:*` + `LEGACY_AGENCY_KINDS`). | No over-reject: `agent`/brain key MAY carry `agency:*`; `{node,agent}` hybrid not constrained; unresolved recipient FK-rejected by `put_attestation` anyway. CIRISServer `ownership.rs` becomes a thin wrapper. | **✓ Mitigated v9.0.0** (see AV-71 for the dup-token bypass) | CIRISPersist#235/#236 |
| AV-69 | Unowned node/agent admitted to a non-infra community (CC 3.2 owner-binding gate / CC 3.4.7.1; authority must root in a human, CC 1.13.2) | v9.0.0 `check_community_membership_owner_binding` wired into `put_community` (3 backends) after the geographic gate, before write lock/INSERT (verify-before-mutation): a `node`/`agent` roster member lacking a live `is_owner_bound(K)` path to a `user`-role identity REJECTS the write `UnownedCommunityMember` + not stored. Precondition, NOT a substitute for the `consensus_protocol` vote. | Infra carve-out (CC 3.2 "Trust ≠ membership"): `cohort_subkind: infrastructure` community admits an unowned node. `user` member trivially owner-bound; unresolved/non-node-agent out of scope (no over-reject). | **✓ Mitigated v9.0.0** (see AV-72/F2 self-label, AV-72/F3 revoked-delegation bypasses) | CIRISPersist#235 |
| AV-70 | Community-DEK not rotated on member removal — removed member decrypts NEW community content (CC 4.4.3.2.2 forward secrecy; community-DEK is content's SOLE confidentiality boundary, CC 4.4.3.2.1) | v9.0.0 `put_community_membership_revocation` bumps the community DEK epoch (`community_dek_bump_epoch`, 3 backends) as part of the revocation write; next emission mints a FRESH DEK wrapped only to remaining members (active roster = `lookup_community` ∖ effective revocations); removed member can't unwrap. **Exposure window = zero.** All wraps `wrap_algorithm: v2` (FIPS-203 hybrid) — NEVER v1 (CC 4.4.3.4.1 / CC 5.2 HNDL); keyless member fail-secure EXCLUDED + `hard_case:recipient_excluded` (V087 CHECK makes v1 unrepresentable). | Forward-only (old-epoch blobs keep grants); flat per-member re-wrap, deliberately NOT MLS TreeKEM (CC 5.1, RET-layer OQ). Infra communities opt OUT (Commons plaintext, no DEK — trust root publicly auditable). | **✓ Mitigated v9.0.0** (see AV-72/F4 future-dated `effective_at`, AV-72/F5 atomicity) | CIRISPersist (CC 4.4.3.2.2) |
| AV-71 | Node-agency gate (AV-68) bypass via duplicate `identity_type` token `"node,node"` (CC 1.13.5 / CC 4.4.3.4.3) | v9.0.0 (adversarial review F1) the gate now tests the identity_type **set** via `HashSet<&str>` (`len()==1 && contains(NODE)`), robust to duplicate/whitespace/order — `"node,node"` no longer evades node-only detection. | `node,agent` hybrid still ADMITTED (no over-reject); regression-tested on 3 backends (`"node,node"`/`"node, node"` + `agency:*` → REJECTED + not stored). | **✓ Mitigated v9.0.0** | CIRISPersist#237 (F1) |
| AV-72 | Authority/forward-secrecy bypasses in the new v9.0.0 community gates (CC 3.2 / CC 4.4.3.2.1 / CC 3.4.7.1 / CC 4.4.3.2.2) | v9.0.0 (adversarial review F2–F5): **F2** self-labeled `cohort_subkind: infrastructure` skipped owner-binding + forced plaintext → `is_authorized_infrastructure_community` honors the carve-out ONLY if `community_key_id` is `substrate_persist`-roled (fail-secure to the stricter path). **F3** `is_owner_bound` honored revoked/expired delegations → edge skipped on `withdraws`/`recants` against `k` (§11.10) or `expires_at <= now`. **F4** future-dated `effective_at` kept wrapping a "removed" member → community revocation now immediate (future-dated beyond 60s skew REJECTED before write). **F5** non-atomic revoke+hard_case+bump → ONE transaction per backend. | Each fix has a fails-without/passes-with test on all backends where the path runs; no new substrate authority (`substrate_persist` is the existing reserved governance role, §3.7). | **✓ Mitigated v9.0.0** | CIRISPersist#237 (F2–F5) |

---

## 5. Security Levels by Deployment Tier

| Tier | Backend | FFI | Threat Model |
|---|---|---|---|
| **Server-class lens** (production) | Postgres + TimescaleDB | PyO3 from FastAPI | Full §3 model applies. TLS at edge required. |
| **Standalone Rust server** (Phase 1.1) | Postgres + TimescaleDB | axum native | Same as above; PyO3 attack surface (callback round-trip) absent. |
| **Pi-class sovereign** (Phase 2.3) | SQLite (bundled) + redb | native bin or PyO3 | Reduced attack surface — typically not internet-exposed. Reticulum transport (Phase 2.3) has its own threat model. |
| **iOS bundled** (Phase 2.2) | SQLite (bundled) | swift-bridge | Apple's app sandbox + secure enclave key storage. Threat model dominated by upstream agent's CIRISVerify hardware-attestation tier. |
| **MCU no_std** (Phase 3 stretch) | none — verify-only | reticulum (when no_std) | Out of HTTP-ingest scope; verify-only relay. |

Critical invariant: **all tiers run the same Backend trait, same
canonicalizer, same scrub gates**. A finding in one tier's
implementation is presumed to apply to the same surface in others
unless explicitly excepted.

---

## 6. Security Assumptions

The system depends on these assumptions; if violated, the threat
model breaks.

1. **Lens deployment hardware integrity**: the host running the
   ingest service is not compromised at root. Postgres, redb
   journal, and process memory are trusted.
2. **TLS at the deployment edge**: the lens fronts CIRISPersist
   with HTTPS termination (nginx, ALB, etc.). Plaintext HTTP
   exposes the agent's traffic to MITM (covered by AV-3 / AV-4
   but assumes TLS-or-not-our-problem).
3. **Public-key directory write authorization**: only authorized
   lens operators can call `register_public_key`. The PyO3 entry
   point is callable from any Python process holding the Engine
   instance — the lens deployment must control which processes
   that is.
4. **Postgres write-quorum**: the database accepts writes
   atomically. Multi-AZ Postgres deployments provide this; single-
   instance deployments inherit Postgres's standard durability
   guarantees.
5. **Clock accuracy**: timestamps in trace bodies and database
   rows are within ~5 minutes of real time. Skew degrades AV-3
   replay-window mitigations (the dedup tuple's `ts` becomes
   ambiguous).
6. **Rust runtime memory safety**: no `unsafe` blocks in
   ciris-persist; transitive deps' `unsafe` is constrained by
   their own audits. `cargo audit` clean across 299 deps as of
   v0.1.1.
7. **Wire-format spec stability**: agents and lens agree on
   TRACE_WIRE_FORMAT.md §8 canonicalization conventions. Drift
   between the two is the AV-4 attack vector.
8. **(v0.2.0+) Federation directory write authorization**: only
   authorized federation peers can call `Engine.put_public_key` /
   `put_attestation` / `put_revocation`. Persist accepts what's
   signed; lens orchestrates which federation membership requests
   reach the substrate. Compromised federation directory writes
   are AV-28 / AV-29 blast-radius bounded by per-row scrub envelope
   verification.
9. **(v0.2.0+) Federation steward key isolation**: deployments
   running federation-mirroring (lens, registry, partner sites)
   hold an Ed25519 + ML-DSA-65 steward keypair. Same trust
   boundary as the scrub-signing key (AV-25); compromised steward
   key allows federation-wide minting of apparently-valid
   federation rows.
10. **(v0.3.6+) DSAR signature verification consumer-side**: lens
    verifies the DSAR request envelope's signature against the
    agent's `signature_key_id` BEFORE calling
    `Engine.delete_traces_for_agent`. Persist owns the substrate
    delete; lens owns the audit + signature verification.
    Misconfigured lens-side verify is AV-38 blast-radius bounded
    by per-key scope.
11. **(v0.3.6+) verify-via-persist API discipline**: federation
    peers consume hybrid verify via `Engine.verify_hybrid`, not
    via direct `ciris_crypto::HybridVerifier` access. Architectural
    rather than runtime; AV-39 names the residual.
12. **(v0.3.0+) Clock skew bounded for SoftFreshness**: peers
    running `HybridPolicy::SoftFreshness { window }` need clock
    accuracy within `window/2` to avoid spurious freshness-window
    rejections OR spurious acceptances of overdue rows. Standard
    NTP synchronization at the deployment level.

---

## 7. Fail-Secure Degradation

All failures degrade to MORE restrictive modes, never less. This
is mission constraint MISSION.md §3 anti-pattern #2 ("verify
before persist") + anti-pattern #7 ("never silent drop") made
operational.

| Failure | Behavior | Rationale |
|---|---|---|
| Schema parse failure | HTTP 422; zero rows persisted | Malformed input cannot enter the corpus |
| Schema-version unsupported | HTTP 422 | Out-of-allowlist versions never deserialize past the gate |
| Signature verification failure | HTTP 422; zero rows persisted | Unverified bytes never persist (MISSION.md §3 anti-pattern #2) |
| Unknown signing key | HTTP 422 | Cannot verify → cannot persist |
| Scrubber rejection (schema-altering output) | HTTP 422; zero rows | Schema-altering scrubber output is a contract violation |
| Scrubber rejection (external error) | HTTP 500 | Scrubber bug; ops investigates |
| Postgres unreachable | redb journal append; HTTP 200 (queued for replay) | Outage tolerance per FSD §3.4 #2 |
| Journal append failure | HTTP 500; logged with severity error | Last-line-of-defense exhaustion |
| Queue full | HTTP 429 + Retry-After: 1 | Backpressure honest; agent retries (TRACE_WIRE_FORMAT.md §1) |
| Persister task panicked | HTTP 503 + Retry-After: 5 | Lens shutdown / restart pending |
| Replay handler error during startup | Replay halts; remaining entries stay journaled | Order preserved across restarts |

Critical invariant: **`signature_verified=false` rows do not
exist in the schema.** Decomposition asserts true unconditionally;
unverified bytes never reach the row constructor. Storing
unverified rows would corrupt the corpus PoB §2.4 measurement.

---

## 8. Residual Risks

Risks CIRISPersist mitigates but cannot fully eliminate.

1. **Compromised agent signing key** (AV-2). The persistence layer
   accepts forged-but-correctly-signed bytes. Closure: agent-side
   key storage hardening (CIRISVerify's threat model is
   authoritative); Phase 2 peer-replicate audit-chain validation;
   federation N_eff drift detection over time.

2. **Quantum compromise of Ed25519**. Current quantum compute
   cannot break Ed25519, but Shor's algorithm on a sufficiently
   large quantum computer would. Closure: Phase 2+ ML-DSA-65
   hybrid signatures per PoB §6 — the wire format §8
   canonicalization stays the same; the signature field becomes
   a hybrid `Ed25519 ‖ ML-DSA-65` form.

3. **AV-5 schema-version flood** (v0.1.1 exposure, fix in
   v0.1.2). Until the `Box::leak` path is removed, the lens is
   memory-leaking on malformed input. Mitigate today with
   deployment-edge rate limiting; hot-fix landing.

4. **AV-6 / AV-7 unbounded body / depth** (v0.1.1 exposure, fix
   in v0.1.2). DefaultBodyLimit + recursion-depth guard land in
   the same hot-fix.

5. **AV-9 cross-agent dedup-key collision** (v0.1.1 design point,
   fix in v0.1.x). Extending the dedup key to include
   `agent_id_hash` is a migration; track for v0.1.3.

6. **Float / timestamp canonicalization drift** (AV-4 residual).
   Track production fixtures for any divergence; the parity test
   suite catches what we know about; unknown unknowns are
   exposure.

7. **Public-key rotation under attack** (AV-11). Manual UPDATE
   today; v0.2.x adds explicit `rotate_public_key(rotation_proof)`
   API.

8. **Side-channel timing leakage of directory membership** (AV-16).
   Low-impact (key ids are public), but trackable.

9. **Postgres compromise**. Out of CIRISPersist's protection
   scope; deployment infrastructure concern.

10. **All federation peers compromised simultaneously** (PoB §5.1
    residual). Per Accord NEW-04, no detector is complete. PoB's
    response is topological cost-asymmetry over time, not pointwise
    decidability — a property that cannot be achieved at the
    persistence layer alone.

11. **(v0.2.0+) Compromised federation steward key** (AV-28/29
    via authorized-but-malicious writes). Same trust boundary as
    AV-25; deployment-level mitigation is hardware-backed steward
    keyring + revocation through the federation directory's
    `federation_revocations` channel.

12. **(v0.3.0+) Hybrid-pending acceptance window**. Peers running
    `HybridPolicy::SoftFreshness` accept rows that haven't yet
    completed cold-path PQC fill-in. Window size is a per-peer
    operational decision; mismatched (window vs. sweep cadence)
    yields either spurious rejections (window too short) or
    extended hybrid-pending acceptance (window too long).
    `Engine.run_pqc_sweep` summary logs surface sweep cadence;
    operators tune window accordingly.

13. **(v0.3.4+) deployment_profile self-classification mismatch
    with behavior**. Agents declare cohort labels in the signed
    canonical bytes; an agent willing to *actually* run high-stakes
    behavior under a low-stakes label faces the cost-asymmetry
    PoB §2.1 names. Detection is statistical (lens cohort cross-
    validation against `cost_usd` / `tokens` / `model`); persist's
    substrate provides cryptographic provenance, not behavioral
    inference.

14. **(v0.3.6+) verify-via-persist consumer discipline**. A
    determined consumer can fork the verify path and use
    `ciris_crypto::HybridVerifier` directly, skipping persist's
    policy machinery. Architectural cost (drift, per-consumer
    policy maintenance) is the disincentive; not a runtime gate.

15. **(v0.4.6+) Legacy `attempt_index` dedup-collapse** (AV-42).
    Pre-2.7.8.9 emitters never populate `data.attempt_index`; v0.4.6
    falls back to 0 at the `2.7.0` and `"2.7.legacy"` arms so legacy
    traffic ingests rather than rejects. Within one legacy agent,
    retries on the same `(trace_id, thought_id, event_type)` collapse
    on the dedup tuple — only the first row lands. Bounded by
    signing-key control (cross-agent collision closed by
    `agent_id_hash` in dedup tuple); time-bounded by sunset rule
    (`federation_canonical_match_total{wire="2.7.legacy"}` 7-day-zero
    soak). The accommodation exists because pre-2.7.8.9 traffic is
    real and unrecoverable otherwise (the legacy 2-field canonical
    signs `components[].data`, so synthesizing `attempt_index`
    post-hoc on the agent or lens side invalidates verify); the
    federation's append-only contract takes priority over per-row
    dedup fidelity at the legacy arm. Sunset rule enforces
    accommodation-discipline against drift into permanent technical
    debt.

---

## 9. v0.5.3 Threat Posture Summary

```
v0.1.1 INTEGRATION-BLOCKING EXPOSURES → closed in v0.1.2
  ✓ AV-5  schema-version flood mem leak  (Cow<'static, str>)
  ✓ AV-6  data-blob recursion uncapped   (MAX_DATA_DEPTH=32 walker)
  ✓ AV-7  no crate-level body size limit (DefaultBodyLimit::max(8 MiB))
  ✓ AV-9  dedup key cross-agent collision (agent_id_hash in UNIQUE index)
  ✓ AV-15 error messages leaking verbatim (kind() tokens at FFI boundary)

POST-v0.1.2 OPERATIONAL HARDENING (v0.1.3..v0.1.5)
  ✓ AV-17 attempt_index integer truncation (MAX_ATTEMPT_INDEX=1024)
  ✓ AV-18 plaintext Postgres connection (optional tls feature)
  ✓ AV-19 lost in-flight commits on shutdown (drain protocol)
  ✓ AV-24 lens-scrub bypass / forgery (scrub-envelope contract)
  ✓ AV-25 scrub-key compromise (hardware-backed ciris-keyring)
  ✓ AV-26 multi-worker migration race (advisory lock)
  ✓ AV-27 ephemeral keyring storage (boot-time check + storage_kind classifier)

v0.2.0 FEDERATION DIRECTORY
  ✓ AV-28 federation_keys directory pubkey poisoning (idempotent + hash check)
  ✓ AV-29 attestation graph poisoning (architectural non-goal — consumer policy)
  ✓ AV-30 federation_keys self-FK integrity (DEFERRABLE INITIALLY DEFERRED)

v0.2.0 HYBRID PQC POSTURE
  ✓ AV-31 hybrid-pending exploitation (HybridPolicy enforced per-call)
  ✓ AV-32 cold-path PQC denial-of-completion (per-write spawn + sweep recovery)
  ✓ AV-33 bound-signature stripping (PQC over canonical || classical_sig)

v0.3.0..v0.3.4 WIRE-FORMAT EXTENSIONS
  ✓ AV-34 cross-shape canonical injection (deterministic dispatch + cross-shape ignore)
  ✓ AV-35 schema-version dispatch attack (closed by v0.3.0 deterministic dispatch)
  ✓ AV-36 LLM_CALL parent-linkage substitution (v0.3.3 strict-parse at 2.7.9)
  ✓ AV-37 deployment_profile cohort-identity injection (signed in 2.7.9 canonical)

v0.3.6 DSAR + VERIFY PRIMITIVES
  ✓ AV-38 per-key DSAR scope violation (BREAKING: signature_key_id required)
  ✓ AV-39 verify-via-persist bypass (architectural closure via Engine.verify_hybrid)

v0.4.0 OUTBOUND QUEUE SUBSTRATE
  ✓ AV-40 outbound queue disk exhaustion (per-row size + ttl + max_attempts schema CHECK)
  ✓ AV-41 spoofed in_reply_to ACK matching (verify-pipeline-gated before mark_ack_received)

v0.4.3..v0.4.6 LEGACY ACCOMMODATION
  ✓ AV-35 dispatch attack property preserved at "2.7.legacy" (verify-bound-to-arm-canonical
          holds even though routing input isn't itself signed at the legacy arm)
  ✓ AV-42 legacy attempt_index dedup-collapse (documented residual; schema-version-gated;
          telemetry-driven sunset; bounded by signing-key control)

v0.5.0 FEDERATION READ PRIMITIVES
  ✓ AV-43 read-side adversary inference attack (documented; aggregates return statistics
          not content; consumer-side k-anonymity gate via sample_count / trace_count)

v0.5.3 PANIC-ISOLATION HARDENING
  ✓ AV-44 Rust panic escalates to process abort (closed; panic=unwind + crate-wide
          try_get<Option<T>> sweep + PyO3 catch_unwind + typed LensQueryError(Exception);
          three independent defense layers from SQL → Rust → FFI → Python)

PHASE-2-CLOSES (architecturally deferred)
  ⚠ AV-2  stolen-key forgery (peer-replicate audit chain)
  ⚠ AV-10 audit anchor capture without verification

v0.4.x TRACK (still pending)
  ⚠ AV-11 explicit rotate_public_key(rotation_proof) API
  ⚠ AV-16 side-channel timing on key-directory enumeration
  ⚠ AV-20..AV-23 (statement_timeout, per-agent rate limiting,
                   clock-skew validation, consent_timestamp range)

DESIGN-DECISIONS-PER-MISSION (intentional, not defects)
  ✓ AV-1  identity gating via public-key directory
  ✓ AV-3  idempotency via dedup-key conflict
  ✓ AV-4  canonicalization parity tests + pluggable trait
  ✓ AV-8  429 backpressure honest
  ✓ AV-12 strict schema-version allowlist
  ✓ AV-13 parameterized binding only
  ✓ AV-14 scrubber-output schema gates
  ✓ AV-29 attestation graph: persist exposes edges, consumers compose policy
  ✓ AV-39 verify-via-persist single-source-of-truth (CIRISPersist#7 pattern)

CARGO AUDIT
  ✓ 0 vulnerabilities across deps as of v0.5.3
```

**Seventeen v0.2.0..v0.5.3 attack vectors closed**: federation
directory integrity (AV-28..AV-30), hybrid PQC posture
(AV-31..AV-33), wire-format extensions (AV-34..AV-37), DSAR + verify
primitives (AV-38..AV-39), outbound queue substrate (AV-40..AV-41),
legacy accommodation residual documented (AV-42), federation read
primitives + read-side inference resistance (AV-43), panic-isolation
hardening across all FFI boundary layers (AV-44).

Three architectural-closure patterns repeated across the surface:

1. **Single-source-of-truth substrate** — canonicalization
   (CIRISPersist#7), DSAR primitive (CIRISPersist#10),
   verify_hybrid (CIRISPersist#14). Federation peers consume
   through persist's API; no parallel implementation paths
   to drift across.
2. **Per-key authorization scope** — DSAR (AV-38) and federation
   directory writes (AV-28). The signing key IS the authorization
   scope, not a filter parameter.
3. **Substrate exposes edges; consumer composes policy** —
   attestation graph (AV-29), verify policy (AV-31, AV-39).
   Persist doesn't ship `is_trusted()`; consumers walk the graph
   and pick `HybridPolicy` per-peer.

Phase 2 (peer-replicate audit-chain validation) closes AV-2 / AV-10
architecturally; v0.4.x track holds the residual P2 hardening from
the original v0.1.2 baseline plus the v0.4.0
`accord_public_keys` retirement coordinated with lens.

Federation peers (CIRISEdge, CIRISLens, future partner sites) can
integrate against v0.3.6 with no known integration-blocker. The
breaking change vs v0.3.5 (per-key DSAR) is yanked-and-replaced at
PyPI; only consumer pinning to a yanked v0.3.5 sees breakage.

---

## 10. Update cadence

This document is updated:
- On every minor version (v0.1.x → v0.2.0): comprehensive review.
- On every published security advisory affecting deps: addendum
  in §3 + cargo-audit re-run.
- On every Phase boundary (Phase 1 → 2 → 3): new attack vectors
  added for the new trait surfaces.
- On every wire-format schema-version bump: AV-4 / AV-12 review.

Last updated: 2026-05-28 (**v3.0.0** — AV-45..AV-47 added covering
CEG 0.2 substrate-conformance threats: §7.0 admission bypass via
deprecated `attestation:l{N}:*` past CEG-0.3 retirement, §10.1.2
ContentMiss flood DoS against `list_holders`, §6.1 dedup-rule
replay-protection hole. CEG conformance bundle landed via
CIRISPersist#116; the substrate's role is wire-format gates +
relational fabric per CEG §0.5, NOT Cartesian re-arbitration of
cross-attestation truth). Previous landmarks:

- 2026-05-01: v0.1.2 baseline — AV-5 / AV-6 / AV-7 / AV-9 / AV-15
  closed; Path B schema reconciliation complete.
- 2026-05-01: v0.1.5 — AV-26 multi-worker migration race closed.
- 2026-05-02: v0.1.7..v0.1.9 — AV-27 keyring storage hardening.
- 2026-05-02: v0.2.0 — federation directory + hybrid PQC scheme
  (AV-28..AV-33).
- 2026-05-02: v0.3.0 — deterministic dispatch, cross-shape
  injection defense (AV-34..AV-35).
- 2026-05-02: v0.3.1..v0.3.2 — cold-path PQC fill-in + sweep
  primitive.
- 2026-05-03: v0.3.3 — LLM_CALL parent-linkage strict-parse (AV-36).
- 2026-05-03: v0.3.4 — deployment_profile cohort identity (AV-37).
- 2026-05-03: v0.3.5 — DSAR primitive (per-agent shape; YANKED).
- 2026-05-03: v0.3.6 — per-key DSAR (AV-38) + `verify_hybrid` (AV-39).
