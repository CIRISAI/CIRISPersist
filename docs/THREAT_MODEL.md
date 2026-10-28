# CIRISPersist Threat Model

**Scope:** the attack surface of CIRISPersist as it stands — trace
ingest and verification, the federation directory, hybrid Ed25519 +
ML-DSA-65 signing, the outbound queue and read primitives, the
graph / audit / TSDB / incident substrates, the holonomic
forever-memory substrate (CEG §19 / §19.7, §3.14), the CIRIS
Constitution alignment gates (§3.15), and the bootstrap / Sybil
mesh receive path (§3.16). Each attack vector (`AV-N`) names the
threat, the mitigation in place, the residual risk, and the tests
that witness it. Persist rolls no §19 crypto: it calls verify-core's
`compute_merkle_root` / `verify_witness` / `verify_aggregation_meta`
/ `verify_member_commitment` / `ejection_verdict`. The §19.1 Merkle
scheme carries no RFC-6962 `0x00`/`0x01` prefix; CVE-2012-2459
odd-node malleability is non-exploitable here because every witness
and `member_commitment` root is mandatorily hybrid-signed,
`member_commitment` is verified by full source-id-list recomputation
rather than partial inclusion proofs, and reconciliation is between
accountable, signed, equivocation-checked peers (§3.14). The
`EjectAggregatedTierOnly { tier }` `EjectionVerdict` variant drives
the tier-granular pyramid-stratum evict (`evict_aggregated_tier`):
exactly one stratum is shed, finer and coarser tiers stay intact, and
it composes with hard-delete (erased content is never resurrected).
**Audience:** lens / edge / registry / partner-site integrators,
federation peers, security reviewers.
**Companion:** [`MISSION.md`](../MISSION.md), [`FSD/CIRIS_PERSIST.md`](../FSD/CIRIS_PERSIST.md).
**Inspired by:** [`CIRISVerify/docs/THREAT_MODEL.md`](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/THREAT_MODEL.md) — the structural template.

---

## 1. Scope

### What CIRISPersist Protects

CIRISPersist is the lens-side ingest substrate and, by trait shape,
the agent-side persistence service. It protects:

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
  *verification* against the agent-side audit log is the
  peer-replicate work (FSD §4.5).
- **Memory-safe parsing of untrusted bytes**: Rust's static
  guarantees at the wire edge close the recurring CVE class for
  network-facing services (MISSION.md §2 — `server/`).
- **Cryptographic provenance of deployment handling**:
  every persisted row carries a four-tuple envelope
  (`original_content_hash`, `scrub_signature`, `scrub_key_id`,
  `scrub_timestamp`) that proves *this specific deployment processed
  this specific payload at this specific time*. Always present —
  every component, every trace level, key never null (FSD §3.3 step
  3.5 + §3.4 robustness primitive #7). The federation primitive
  PoB §3.1 — "the lens role is a function any peer can run on data
  the peer already has" — becomes cryptographically attestable.
  Bilateral cryptography: agent's wire-format §8 signature proves
  authorship, the lens's scrub envelope proves handling.
- **Single-key federation identity**: the scrub-signing
  key is also the deployment's Reticulum destination
  (`SHA256(public_key)[..16]`, PoB §3.2 — addressing IS identity)
  and the registry-published public key. One key, three roles.
  No separate "network identity" key; no translation layer
  between cryptographic provenance and federation transport.
- **Federation directory substrate**: `federation_keys`
  + `federation_attestations` + `federation_revocations` provide a
  shared pubkey + attestation + revocation directory across the
  federation. Persist holds the substrate; consumers compose
  policy. No `is_trusted()` / `trust_score()` methods; consumers
  walk the attestation graph however they want
  (`docs/FEDERATION_DIRECTORY.md` §"Explicit non-goals").
- **Hybrid Ed25519 + ML-DSA-65 signing**: every
  federation row carries a four-tuple bound signature — Ed25519
  classical (always present), ML-DSA-65 PQC (cold-path filled).
  PQC signs `(canonical || classical_sig)` so an attacker who
  breaks Ed25519 cannot strip-and-replace the PQC component.
  Persist owns the cold-path tokio task and the sweep
  primitive so consumers can't drift on the bound-
  signature contract.
- **Deterministic dispatch by `trace_schema_version`**:
  canonical reconstruction picks exactly one path based on the
  signed `trace_schema_version` field. No iterative try-N-shapes
  fallback; no shape-shopping attack surface; no spurious-sig-fail
  SHA-256+verify latency multiplier under load. The dispatch key
  is part of the signed canonical bytes, so an attacker cannot
  forge it without breaking the signature.
- **Cross-shape field injection defense**: per-component
  `agent_id_hash` and `deployment_profile` are
  silently ignored at `trace_schema_version "2.7.0"` — they don't
  enter the 2.7.0 canonical reconstruction even if present on the
  wire. An attacker injecting future-shape fields into a 2.7.0
  envelope produces byte-identical canonical bytes vs no-injection;
  the injection has no effect on signed verification or dedup.
- **deployment_profile cohort identity in canonical
  bytes**: `agent_role` / `agent_template` / `deployment_domain` /
  `deployment_type` / `deployment_region` / `deployment_trust_mode`
  ride in the 2.7.9 signed canonical bytes. Cohort labels are
  non-forgeable post-emission; the agent's signature commits to
  them. Lens cohort routing reads denormalized columns on
  `trace_events` with cryptographic provenance.
- **Per-key DSAR authorization scope**:
  `Engine.delete_traces_for_agent(agent_id_hash, signature_key_id)`
  scopes deletion to `(agent_id_hash, signing_key_id)`. The
  signature_key_id is the *authorization scope* of the DSAR
  (a request signed by key A is only authorized to delete traces
  signed by key A) — not just an identity filter. Per-key is the
  only contract.
- **verify-via-persist single-source-of-truth**:
  `Engine.verify_hybrid` exposes hybrid Ed25519+ML-DSA-65 verify
  for arbitrary canonical bytes via persist's policy machinery
  (`HybridPolicy::Strict` / `SoftFreshness { window }` /
  `Ed25519Fallback`). Federation peers consume verify through
  persist, not via direct `ciris_crypto` access (CIRISPersist#7):
  one canonicalization expectation, one policy machinery, no drift
  across N consumers.

### What CIRISPersist Does NOT Protect

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
- **Audit-chain re-verification at ingest**: anchor fields are
  captured but not cross-checked against the agent's audit_log.
  Peer-replicate (FSD §4.5) closes this.
- **Pre-cutover corpus integrity**: `accord_traces` retains
  pre-cutover history with whatever properties the previous lens
  pipeline gave it. CIRISPersist makes no claims about that table.
- **Cross-tier privacy bridging**: a `generic`-tier trace co-
  resident in the same DB as a `full_traces` trace is not a
  CIRISPersist concern. Lens-side query authorization is the lens's
  job.
- **Surfaces not catalogued in §3**: agent runtime state and
  governance tables beyond the substrates catalogued in §3 are
  outside this model.

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
  classical hardware. (PoB §6 acknowledges quantum risk; the hybrid
  Ed25519 + ML-DSA-65 posture in §3.8 and §3.14 answers it.)
- **Compromised the public-key directory**: the lens's
  `accord_public_keys` table. If the directory is owned, every
  signature verification is meaningless. The directory is part of
  the lens deployment trust boundary.
- **Compromised any honest agent's signing key**: if they did, see
  §1 "What CIRISPersist Does NOT Protect" — that's
  out-of-scope at the persistence layer.
- **Compromised the Postgres backend** that the lens writes to.
- **Compromised the redb journal disk** location (default
  `/var/lib/cirislens/journal.redb`).
- **Physical access** to the lens deployment hardware.
- **Ability to read TLS-encrypted traffic** between the agent and
  the lens. (TLS termination is upstream of CIRISPersist; if it's
  off, that's a deployment misconfiguration.)
- **Quantum compute** capable of breaking Ed25519 today. (Tracked
  in §8 Residual Risks; ML-DSA-65 hybrid signatures per PoB §6,
  §3.8.)

---

## 3. Attack Vectors

Attack vectors are organized by adversary goal:

- §3.1–§3.6 — forgery, denial of service, corruption, privacy,
  provenance, and operational hardening (AV-1..AV-27).
- §3.7–§3.10 — federation directory, hybrid PQC, wire-format
  extensions, legacy schema accommodation, per-key DSAR, and
  `verify_hybrid` over arbitrary canonical bytes (AV-28..AV-39, AV-42).
- §3.11–§3.13 — read primitives, the outbound queue, panic isolation,
  and the §6.1 / §7.0 / §10.1.2 composition gates (AV-40..AV-58).
- §3.14 — the holonomic / forever-memory substrate: store-path PQC,
  WholenessWitness equivocation, the divergence router,
  anti-rollback, the WW-2 leaf filter, aggregation-meta and
  member-commitment integrity, rarity versus revocation (AV-59..AV-66).
- §3.15 — the CIRIS Constitution alignment surface: PQC-mandatory
  federation-tier per-trace ingest, the node/agency delegation split,
  steward-binding community membership, community-DEK rotation, and
  the bypasses those gates close (AV-67..AV-72).
- §3.16 — bootstrap / Sybil on the mesh receive path (AV-73..AV-78).

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
(via secrets-manager compromise, key-material leak in
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
post-incident forensics. Peer-replicate (FSD §4.5)
cross-validates the chain link against the agent's local audit_log,
making chain-tampering detectable.

**Residual**: Until peer-replicate verification is in place,
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
- **Timestamp formatting drift** (mitigated). Python's
  `datetime.isoformat()` drops the fraction entirely when
  microseconds == 0, so re-formatting a parsed timestamp would
  emit `.000000` and diverge from the signed bytes.
  `schema::WireDateTime` wraps `(raw: String, parsed: DateTime<Utc>)`
  and serializes the raw wire bytes verbatim; it is the type of
  `CompleteTrace.{started_at, completed_at}` and
  `TraceComponent.timestamp`, and `canonical_payload_value` reads
  `.wire()`. Regression coverage: `tests/av4_timestamp_round_trip.rs`
  (including the zero-microsecond shape).

### 3.2 Denial of Service — adversary wants the lens unable to receive evidence

#### AV-5: Schema-version flood (memory leak DoS)

**Attack**: Adversary submits a stream of bodies with malformed
`trace_schema_version` strings (random 64-byte strings, etc.),
hoping each rejected version string is retained in process memory.

**Mitigation**: `SchemaVersion` wraps a `Cow<'static, str>`
(`src/schema/version.rs`). Recognized versions borrow a static;
an unrecognized string is an owned allocation that drops with the
request. Nothing is leaked, so memory is bounded by request
lifetime.

**Secondary**: a rate limiter at the lens's HTTPS termination layer
(nginx, Envoy, etc.) capping requests per source IP.

#### AV-6: JSON-bomb / deserialization amplification

**Attack**: Adversary submits a JSON body with deeply nested
structure (`[[[[...]]]]` 10000 deep) or a single key with a
1GB string value. `serde_json` by default has no depth limit and
parses into `serde_json::Value` for the `data` blobs. Memory
allocation amplification.

**Mitigation**:
- `DefaultBodyLimit::max(8 MiB)` on the axum router bounds the
  whole body (AV-7).
- The typed envelope (`BatchEnvelope`, `CompleteTrace`, etc.)
  forces concrete struct shapes, so depth-bombs in the envelope
  fail at typed deserialize.
- The per-component `data` field is
  `serde_json::Map<String, serde_json::Value>`; after the typed
  envelope parse, a walker rejects any `data` deeper than
  `MAX_DATA_DEPTH = 32` (`src/schema/mod.rs`) with a typed error.
- The bounded queue (`DEFAULT_QUEUE_DEPTH=1024`) bounds how many
  bodies are in flight at once.

**Secondary**: deployment-edge body-size limit at the proxy layer.

**Residual**: an attacker with a registered, accepted public key
who submits inflated-but-syntactically-valid bodies pays the
cost-asymmetry PoB §2.1 names — they're spending real LLM cost to
inflate the corpus, and N_eff measurement detects this as
behavioral drift.

#### AV-7: Body-size flood (no max body limit)

**Attack**: Adversary submits arbitrarily large bodies. axum's
`Bytes` extractor reads the entire body into memory before queue
submission.

**Mitigation**: `DefaultBodyLimit::max(MAX_INGEST_BODY_BYTES)`
(8 MiB) on the axum router (`src/server/mod.rs`). 8 MiB gives the largest production `full_traces` fixture
(about 3 MiB) 2.6× headroom.

**Secondary**: the lens's deployment-edge proxy (nginx, HAProxy,
etc.) typically caps body size as well.

#### AV-8: Queue saturation

**Attack**: Adversary floods the endpoint to fill the bounded
mpsc channel.

**Mitigation**: 429 + Retry-After on `QueueError::Full`.
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

**Mitigation**: the dedup key includes `agent_id_hash`. The
`trace_events` UNIQUE index and the `ON CONFLICT` target are
`(agent_id_hash, trace_id, thought_id, event_type, attempt_index,
ts)` (`migrations/*/lens/V001__trace_events.sql`), so one agent
cannot pre-claim another agent's dedup tuples.

**Secondary**: each agent's `agent_id_hash` is a sha256 prefix of
the agent's pubkey (TRACE_WIRE_FORMAT.md §3), and the wire-format
spec mandates `trace_id` is "Globally unique per agent"
(`trace-<thought_id>-<YYYYMMDDHHMMSS>`).

**Residual**: a colliding tuple within one agent's own namespace
only affects that agent's own rows.

#### AV-10: Audit anchor injection

**Attack**: Attacker (with a registered key) submits a trace
with crafted `audit_sequence_number`/`audit_entry_hash` that
will conflict with a future legitimate ACTION_RESULT row,
forcing dedup to skip the legitimate one.

**Mitigation**: **Partial.** The audit anchor fields
are NOT part of the dedup key. They're columns on the
`trace_events` row, populated only on the ACTION_RESULT row. The
dedup key (per AV-9 above) is the trace shape; anchor is
auxiliary. Two ACTION_RESULT rows with same dedup tuple but
different anchors: the second is skipped, anchor mismatch is
post-facto detectable.

**Peer-replicate** (FSD §4.5): the agent's audit_log
chain provides cross-validation. A row with an anchor that
doesn't match the agent's claimed chain link → flagged for
review.

**Residual**: the anchor field is captured but not verified at
ingest. Treat it as data preserved for the peer-replicate
cross-check, not data the lens trusts.

#### AV-11: Public-key directory poisoning via re-registration

**Attack**: An attacker who can call `register_public_key` (the
PyO3 Engine method) submits the same `signature_key_id` an
honest agent already registered, but with a different public
key. The SQL is:

```sql
INSERT INTO cirislens.accord_public_keys
  (signature_key_id, public_key_b64, agent_id_hash)
  VALUES ($1, $2, $3)
  ON CONFLICT (signature_key_id) DO NOTHING
```

**Mitigation**: the first key wins; a re-registration is silently
ignored, so an attacker cannot overwrite a registered key. The
`revoked_at` / `revoked_reason` / `added_by` audit columns record
revocation and provenance.

**Residual**: the same rule blocks legitimate rotation on this
table. The lens operator rotates with a manual `UPDATE
accord_public_keys`, behind whatever out-of-band authorization the
deployment requires — no automated rotation under attacker control,
at the cost of an operational step. An explicit rotation API
(`rotate_public_key` with a rotation proof signed by the old key)
is tracked. The federation directory (§3.7) carries its own key
lifecycle.

#### AV-12: Schema-version downgrade

**Attack**: An attacker convinces the lens to treat a future
agent's v2.8.0 batch as v2.7.0, exploiting a known v2.7.0 weakness
that v2.8.0 fixed.

**Mitigation**: **Strong.** `SUPPORTED_VERSIONS` is a
strict allowlist (`src/schema/version.rs`). Out-of-set versions hit
HTTP 422. There is no "best-effort" / "downgrade-and-try" branch.
Accepting a new version requires a `ciris-persist` release that
extends the constant — a deliberate operator decision.

**Residual**: when several versions are in `SUPPORTED_VERSIONS`
at once, an attacker who can inject the version field could target
an older path. The version field is inside the signed canonical
bytes, and dispatch picks exactly one reconstruction per version
(AV-35), so a payload labeled with a different version fails
verification.

#### AV-13: Cross-trace JSONB injection

**Attack**: An attacker submits a `data` blob crafted to
exploit a future SQL query that reaches into the JSONB column.

**Mitigation**: payload is stored as parameterized
JSONB via typed binding. There is no string
interpolation of payload content into SQL. SQL injection at the
INSERT layer is structurally not possible.

**Residual**: queries that *read* the JSONB (e.g.,
`payload->>'audit_sequence_number'`) need parameterized binding
on the JSONB-path operands too.

### 3.4 Privacy — adversary wants content text exposed at a tier where it isn't warranted

#### AV-14: Scrubber bypass via schema-altering callback

**Attack**: An attacker who controls the lens's scrubber
callable returns a modified envelope that drops `trace_level`
from `full_traces` to `generic`, bypassing the next layer's
content-handling assumptions.

**Mitigation**: the engine validates scrubber output:
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

**Mitigation**: errors that cross HTTP or PyO3 carry a stable,
closed-set `kind()` token (`&'static str`) rather than the verbose
`Display` text. The verbose form, which can include
attacker-submitted strings, serde_json parse context around a
`data` fragment, or Postgres error text, stays in tracing-only
logs. Error variants that describe a type mismatch name the type,
never the value.

**Residual**: operators who forward tracing logs to a shared sink
must treat those logs as carrying request-derived fragments.

#### AV-16: Side-channel timing on verify

**Attack**: Adversary measures response time differences to
distinguish "unknown key" vs "known key + wrong signature" vs
"known key + right signature, wrong canonical bytes" — gleaning
information about the public-key directory or the
canonicalization pipeline.

**Mitigation**: **Partial.** Ed25519 `verify_strict` is
constant-time over the signature/key path. However:
- The public-key directory lookup short-circuits on
  unknown-key (returns before signature math runs). Timing leaks
  membership.
- Canonicalization bytes are deterministic per input but
  *length* differs based on payload size — observable.

A constant-response-time wrapper that sleeps to a P99 budget on the
rejection path is tracked as research-grade hardening; implemented
naïvely it taxes the happy path too.

**Residual**: a network-adjacent attacker can probably enumerate
`signature_key_id`s via timing oracle. The federation primitive
treats `signature_key_id` as public anyway (it's emitted on
every trace), so directory enumeration is not a high-impact leak.

### 3.5 Provenance — adversary wants to forge "deployment handled this" attestation

These vectors follow from the always-on scrub-signing
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

**Mitigation**: every persisted row carries a four-tuple envelope (`original_content_hash`,
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

**Mitigation**: `ciris-keyring` (CIRISVerify's Rust
crate) stores the seed in OS-keyring backed by hardware where
available — Linux Secret Service / TPM 2.0; macOS Keychain /
Secure Enclave; iOS / Android StrongBox; Windows DPAPI / TPM.
The Python process never holds the seed bytes; the seed never
crosses the FFI boundary. Hardware-backed deployments require
physical access (and on most platforms, exploitation of an
enclave-grade vulnerability) to extract.

**One key, three roles** (PoB §3.2): the scrub-signing key is
*also* the deployment's Reticulum destination address
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

**Failure without a lock**: the workers race on Postgres catalog
inserts — `IF NOT EXISTS` checks across the migration set and
refinery's own schema_history bootstrap. The second worker through
hits `42P07 relation already exists` (or, less commonly, a deadlock
on `pg_namespace`), the worker pod fails readiness, restarts, races
again, and stays unhealthy.

This is not a threat in the adversarial sense — there is no
attacker — but it is a real availability vector: a config change
that scales worker count from 1 to N can trigger a stuck-restart
loop on cold deploys. THREAT_MODEL.md catalogues it for the same
reason MISSION.md treats reliability as a mission concern: a
substrate that's unreachable can't carry evidence.

**Mitigation**: session-scoped Postgres advisory lock
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

**Diagnostic surface**: `Error::Migration {
sqlstate: Option<String>, detail: String }` so the lens sees
`store: migration: [SQLSTATE] detail`. 42P07
should not appear unless schema is externally mutated
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

AV-17 through AV-23 are operational hardening vectors. The audit
document carries the full prose; the mitigation matrix in §4
carries the one-line summary. Briefly:

- **AV-17** — `attempt_index` integer truncation (P0). Capped at
  `MAX_ATTEMPT_INDEX = 1024` with `try_into` + typed
  `Error::AttemptIndexOutOfRange`. `overflow-checks = true` on the
  release profile is the defense-in-depth backstop.
- **AV-18** — plaintext Postgres connection (P1). Optional `tls`
  feature (`tokio-postgres-rustls`).
- **AV-19** — no graceful shutdown / lost in-flight commits (P1).
  `tokio::signal::ctrl_c` + drain protocol.
- **AV-20** — no `statement_timeout` (P2). Tracked.
- **AV-21** — no per-agent rate limiting (P2). Tracked; PoB §5.6
  acceptance-policy adjacent.
- **AV-22** — no clock-skew validation (P2). Tracked.
- **AV-23** — `consent_timestamp` range unconstrained (P3). Tracked.

### 3.7 Federation directory

These vectors emerge from the federation directory schema
(`federation_keys`, `federation_attestations`, `federation_revocations`).
The directory provides the substrate consumers
compose policy over (per `docs/FEDERATION_DIRECTORY.md` §"Explicit
non-goals"), so attacks here target either the substrate's integrity
or the consumer's policy assumptions about it.

#### AV-28: Federation_keys directory pubkey poisoning

**Attack**: An attacker with write access to `federation_keys`
submits a `SignedKeyRecord` with a `key_id` that collides with an
existing legitimate registration but a different
`pubkey_ed25519_base64` / `pubkey_ml_dsa_65_base64`. Same shape as
AV-11, but for the federation directory, which is the authoritative
key source.

**Mitigation**: idempotent on `(key_id, persist_row_hash)`.
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
chains on `identity_binding:*`, attestations with futures-dated `expires_at` to claim
long-lived trust, revocations with retroactive `effective_at` to
invalidate historical traces.

**Mitigation**: persist exposes the edges, never the
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

**Mitigation**: `DEFERRABLE INITIALLY DEFERRED` on the
self-FK. Bootstrap row INSERTs successfully; the constraint check
runs at COMMIT, by which time `scrub_key_id` resolves (the row
exists). Non-bootstrap rows reference an already-committed key,
so the deferred check is no-op.

**Residual**: a malicious operator with DBA-level access could
deferrable-defer-then-rollback to leak intermediate state, but
the trust boundary at that level is "Postgres compromised" (out of
scope per §1) — the substrate cannot defend against the operator
running it. Standard FK semantics resume at COMMIT.

### 3.8 Hybrid PQC posture

These vectors emerge from the hybrid Ed25519 + ML-DSA-65 signing
scheme. Where a row is admitted Ed25519-first, ML-DSA-65 is
attached on the cold path
(`docs/FEDERATION_DIRECTORY.md` §"PQC strategy"). The window between
hot-path commit and cold-path PQC fill-in is the hybrid-pending
interval — load-bearing for the trust contract. Federation-tier
per-trace ingest requires the hybrid pair at admission (AV-67), and
the store path is PQC-mandatory (AV-59).

#### AV-31: Hybrid-pending exploitation

**Attack**: An attacker who breaks Ed25519 (post-quantum future, or
hypothetical pre-quantum break) forges a row with valid Ed25519 but
no PQC component. Consumers running `HybridPolicy::Ed25519Fallback`
or `SoftFreshness { window: long }` accept the row.

**Mitigation**: `Engine.verify_hybrid` exposes three
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

**Mitigation**: per-write cold-path is
fire-and-forget on the engine's tokio runtime — no external
network dependency, no separate signing service, no network blip
to deny. The runtime is the same one serving `receive_and_persist`,
so denying it denies write-path entirely (the attacker can DoS
ingest, but they can't selectively deny PQC fill-in while keeping
hot-path alive).

The sweep primitive (`Engine.run_pqc_sweep`) provides the
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
implementation (CIRISPersist#10) — consumers can't
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

**Mitigation**: bound signature pattern. PQC signs
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

### 3.9 Wire-format extensions

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

**Mitigation**: deterministic dispatch by
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
review (§10) catches such changes.

#### AV-35: Schema-version dispatch attack

**Attack**: a verify path that tries multiple canonical shapes in
sequence (try-9-field-then-2-field) lets an attacker craft canonical bytes that match
*both* shapes' verify path but mean different things at the dedup
or denormalization layer — getting a trace counted as 2-field for
verify but interpreted as 9-field for storage.

**Mitigation**: deterministic dispatch by
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

**The `"2.7.legacy"` arm** (CIRISPersist#21): `SUPPORTED_VERSIONS`
carries `"2.7.legacy"` under the same telemetry-driven sunset rule
`"2.7.0"` follows (`federation_canonical_match_total{wire="2.7.legacy"}`
7-day-zero soak window). Pre-2.7.8.9 emitters that don't stamp
`trace_schema_version` at all dispatch deterministically to the
legacy arm via serde-default — absence is the deterministic
signal, NOT a try-list fallback (TRACE_WIRE_FORMAT.md §8
prohibition on iterative arm-shopping holds). The
verify-bound-to-arm-canonical property holds at the legacy arm
identically.

**Residual**: when `SUPPORTED_VERSIONS` legitimately holds multiple
versions, every dispatch arm is live.
Each is independent (no cross-version field reuse); the per-version
review (§10) ensures shape independence.

#### AV-36: LLM_CALL parent-linkage substitution

**Attack**: when the wire-shipped parent fields are missing, a
decompose that substitutes the outer LLM_CALL component's
`event_type` (always `LLM_CALL`) into
`trace_llm_calls.parent_event_type` loses the spec-mandated
upstream-step taxonomy (`ASPDMA_RESULT`, `IDMA_RESULT`,
`CONSCIENCE_RESULT`, etc.). That defeats the AV-9 dedup-tuple
parent-path identity and RATCHET H3 parent-topology clustering.

**Mitigation**: 2.7.9 strict-parse for the LLM_CALL
component. Missing `parent_event_type` or `parent_attempt_index` →
typed `Error::Schema(MissingField("data.parent_event_type"))`.
Decompose reads from the wire-provided values directly; no
substitution at 2.7.9. At 2.7.0, the historical substitution path
is preserved for backward compatibility (the spec didn't carry the
fields at 2.7.0; substitution is documented as semantically wrong
but operationally equivalent for AV-9 dedup at that version).

**Residual**: rows persisted before the strict parse retain the
`parent_event_type='LLM_CALL'` label; RATCHET uses `handler_name`
as the upstream-step linkage for those rows (CIRISLens#5). 2.7.9
traffic carries the spec-correct parent linkage.

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

**Mitigation**: `deployment_profile` rides in the 2.7.9
signed canonical bytes (CIRISAgent FSD/TRACE_WIRE_FORMAT.md §3.2 +
§8). The agent's signature commits to the declared labels; an
attacker can't post-hoc rewrite the labels on a row that's already
signed. This is the same authenticity floor as `agent_id_hash`:
the labels are non-forgeable post-emission.

The strict parse at 2.7.9 rejects envelopes missing the
block (`MissingField("deployment_profile")`). All
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

### 3.10 Legacy schema accommodation

These vectors emerge from `"2.7.legacy"` in `SUPPORTED_VERSIONS`
(CIRISPersist#21) and the graceful fallback for `attempt_index` at
the legacy / 2.7.0 arms (CIRISPersist#22). Both accommodate
pre-2.7.8.9 emitters that physically cannot be patched (the bridge
cannot mutate signed bytes without invalidating verify). The
accommodations are schema-version-gated, sunset-driven, and bounded
by signing-key control — they don't widen the federation-wide attack
surface, but they do introduce a documented agent-internal fidelity
trade-off.

#### AV-42: Legacy `attempt_index` dedup-collapse

**Attack**: At `trace_schema_version ∈ {"2.7.0", "2.7.legacy"}`,
components without `data.attempt_index` decompose with
`attempt_index = 0` (legacy fallback). Multiple retries on the
same `(agent_id_hash, trace_id, thought_id, event_type)` collapse
on the dedup tuple
`(agent_id_hash, trace_id, thought_id, event_type, attempt_index)`
— only the first row lands; subsequent retries hit ON CONFLICT
DO NOTHING and are silently skipped. An attacker controlling the
signing key could in principle exploit this to suppress later
retries with content different from the first.

**Mitigation**: schema-version-gated. 2.7.9 still strict
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
(AV-9).

**Why not lens-side fix**: the legacy 2-field canonical signs
`{components, trace_level}`, so `components[].data` IS in the
signed bytes. Synthesizing `data.attempt_index` post-hoc on the
agent or lens side would invalidate verification at the legacy
arm. The federation's append-only
contract takes priority over per-row dedup fidelity for legacy
traffic; persist accepts the trade-off and documents it.

**Companion: schema rejects route to 422** (CIRISPersist#22):
`decompose`'s `Schema(MissingField)` errors map
`store::Error::Schema(s) → IngestError::Schema(s)` and return
HTTP 422 (give-up), not HTTP 503 + Retry-After (the lens convention
for transient backend faults). A deterministic schema mismatch
therefore surfaces to ops instead of putting agents into a retry
loop — no self-DoS amplification from legitimate clients hammering
persist on each malformed batch.

**Residual**: legacy-version retries within one agent collapse on
the dedup key. Cross-agent collision closed by AV-9. Time-bounded
by AV-42 sunset rule (observability-driven). The accommodation
exists because pre-2.7.8.9 traffic is real and unrecoverable
otherwise; the sunset rule is the discipline that prevents
accommodation-creep into permanent technical debt.

### 3.11 Federation read primitives

Vectors emerge from the typed read surface (CIRISPersist#23). The
primitives expose typed reads to lens, lens-core, and sovereign-mode
agents in place of direct SQL under the `cirislens_reader` role.

#### AV-43: Read-side adversary inference attack

**Attack**: A federation peer with read access to the substrate uses
the aggregate primitives — `aggregate_scoring_factors`,
`cross_agent_divergence`, `temporal_drift`,
`conscience_override_rates` — to infer per-trace content of another
peer's traces by pattern analysis. Examples: correlating a narrowly-
windowed scoring aggregate against a `cross_agent_divergence` z-score
to deanonymize a specific trace's properties; running per-minute
`coherence_decay_series` queries to reconstruct the timing of
individual decisions.

**Mitigation**: aggregates return computed statistics, not
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

**Residual**: a federation operator with the `cirislens_reader`
role running narrow windows can in principle reconstruct trace
patterns. The aggregation primitives don't widen this surface — the
underlying rows are already accessible to that role. The typed read
primitives (TraceSummary listing, trace detail, task grouping, LLM
call surface, Coherence Ratchet inputs, scoring-factor aggregates,
corpus shape, scrub stats, federation bulk) together with the
AV-15-safe error layer are the path that replaces direct SQL.

### 3.12 Outbound queue substrate

These vectors emerge from the `cirislens.edge_outbound_queue`
table — the durable substrate for `CIRISEdge::send_durable()`.
Durable message types (BuildManifestPublication, DSARRequest/
Response, AttestationGossip, PublicKeyRegistration) ride this table.

#### AV-40: Outbound queue disk exhaustion

**Attack**: An adversary with write access to the federation peer
floods the outbound queue with high-TTL low-priority messages (or
messages routed to unreachable peers that never deliver), filling
the disk and starving legitimate traffic.

**Mitigation**: per-row `body_size_bytes` capped 1..=8 MiB
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

**Mitigation**: ACK envelopes go through persist's normal
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

### 3.10 DSAR + verify primitives

These vectors emerge from the per-key DSAR primitive
(`Engine.delete_traces_for_agent`) and the `verify_hybrid`
arbitrary-canonical-bytes surface (CIRISEdge OQ-11).

#### AV-38: Per-key DSAR scope violation

**Attack**: a DSAR request signed by key A is used to delete traces
signed by key B under the same `agent_id_hash`. A primitive scoped
to all keys for that agent would let any one valid key file a DSAR
deleting traces from other agent instances claiming the same logical
identity (separate deployments of the same template with different
signing keys).

**Mitigation**: `signature_key_id` is a REQUIRED parameter.
Deletion is scoped to
`(agent_id_hash, signing_key_id)` at all three substrate layers:
- `trace_events`: `WHERE agent_id_hash = $1 AND signing_key_id = $2`
- `trace_llm_calls` cascade: joined by `trace_id` from the matching
  `trace_events` set (cross-key traces under the same agent only
  cascade for this DSAR's key)
- `federation_keys` (when `include_federation_key=True`): only the
  one row matching `(agent_id_hash, signature_key_id)` cascades;
  the agent's other registered keys (rotation history) stay alive

The per-key contract is the authorization model itself, not a
filter parameter (CIRISPersist#15). Admin / forensic deletions belong in
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

**Mitigation**: `Engine.verify_hybrid` is the federation's
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

**Secondary**: verify-via-persist is the documented integration
discipline ([`COHABITATION.md`](COHABITATION.md)); CIRISEdge OQ-11
closure cites it explicitly.

**Residual**: a peer that nevertheless implements its own verify
path skips persist's policy machinery. This is a consumer-side
discipline issue, not a substrate enforcement; persist cannot
prevent a determined consumer from forking the code. The
architectural cost (drift, per-consumer policy maintenance) is the
incentive against doing so.

### 3.13 Panic-isolation posture

Persist runs as a PyO3 `cdylib` loaded into long-lived uvicorn
workers. In that shape a `panic = "abort"` profile turns one panic
into a pool-wide outage: a single NULL deserialization panics
`Row::get`, the panic runtime calls `abort()` before PyO3's
`catch_unwind` trampoline can fire, and parallel calls SIGABRT every
uvicorn worker — taking down `/health` itself (CIRISPersist#24).

Three orthogonal layers of panic-resistance (CIRISPersist#25, #26,
#27) replace "abort fast":

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

**Mitigation**:

1. **`panic = "unwind"` in the release profile** (Cargo.toml). The
   panic runtime unwinds the stack; PyO3's built-in trampoline
   (pyo3#797) catches the panic via `catch_unwind` and raises
   `PanicException` (a Python `BaseException` subclass). The
   worker process survives; the offending request fails.
2. **Explicit `std::panic::catch_unwind(AssertUnwindSafe(|| ...))`
   wrapping every `#[pyfunction]` body** (CIRISPersist#27).
   The catch converts the panic payload to a typed
   `LensQueryError` Python exception that derives from `Exception`
   (not `BaseException`) — uvicorn's normal error handling catches
   it as a 500, not a worker reset.
3. **Crate-wide `Row::get` → `try_get::<_, Option<T>>` sweep**
   (CIRISPersist#26). NULL surfaces as `None` at the
   data-decode layer, before it can become a panic candidate.

**Why unwind, not abort**: SECURITY_AUDIT_v0.1.2.md §4.2 argues for
abort when persist runs as a standalone binary under a supervisor
restart loop — abort-and-restart is a feature there, and the
journal-replay path picks up cleanly. The cdylib-in-uvicorn shape
inverts the trade-off: process abort means parallel uvicorn workers
all die simultaneously, with no supervisor below them to coordinate
restarts. Unwind preserves the worker pool; the SIGABRT cascade is
worse than the unwind-into-half-shut-state risk abort prevents. The
~3-5% release-binary size increase from unwind tables is the cost.

**Residual**: a Rust panic inside the SQL driver's tokio runtime
(deep inside `tokio-postgres`) might still escape PyO3's
trampoline if `tokio::spawn`'d before unwinding completes. The
`catch_unwind` wrapper at the PyO3 entry point catches this when
the await returns; in-flight tokio tasks panicking in the
background are logged via `tracing::error` but don't propagate
back to Python. The defensive layer is applied at every point
persist controls.

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

**Mitigation — the deprecated form is refused at admission**:

1. There is no policy value that admits `attestation:l{N}:*`; no
   dual-acceptance configuration exists, so admitting the deprecated
   form is unreachable by configuration.
2. **The `is_deprecated_attestation_ladder_prefix` parser is a REFUSE
   branch.** It is a runtime-checked match against
   `attestation:l<digits>:<mechanism>`, so a canonical mechanism named
   with a leading `l<N>` is not caught by it.
3. **The refusal is specific, not incidental.** Without the branch,
   the shape would fall through to `missing_version_segment` — a
   refusal that tells a producer their dimension lacks `:v[0-9]+`
   when the real problem is a retired wire shape. The refusal reports
   `federation_deprecated_attestation_ladder_form` and names the
   canonical form to emit instead, so the failure lands on the party
   that can fix it, at the moment they can fix it.

**Residual — none at admission.** The rule is enforced at the
substrate rather than left to a downstream conformance suite.

**The STORED corpus is a separate question.** This gate protects
NEW rows only; rows admitted while the deprecated form was accepted
are still present and still carry it. Consumers reading history must
continue to tolerate it. The same complementarity applies to
`accord_root` (#733): the write door covers new rows and the
consumer's enforcement flag covers the corpus.

#### AV-46: §10.1.2 ContentMiss flood DoS against `list_holders`

**Attack**: an adversary emits forged `WITHDRAWS` attestations
against legitimate `holds_bytes:sha256:{prefix}` rows en masse,
attempting to make every legitimate holder appear withdrawn so
`list_holders` returns empty and federation peers can't locate the
bytes.

**Mitigation**:

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

**Mitigation**:

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

### 3.14 Holonomic substrate & store-path PQC (CEG §19 / §19.7)

The §19 holonomic / forever-memory substrate (#225, #227–#231) adds a
durable, replicated, kept-for-posterity content corpus, a WholenessWitness
divergence-detection corpus, and a §19.7 aggregation pyramid. Its threat
surface is dominated by two classes: **harvest-now-decrypt-later (HNDL)
forge-later** against a corpus that outlives the classical primitive, and
**reconciliation / divergence-router abuse** where a forged or stale witness
tries to drive the merge it is only supposed to *detect*. The §19 verifiers
themselves live in `ciris_verify_core::holonomic`;
persist **calls** them (`verify_witness`, `compare_witnesses`,
`verify_aggregation_meta`, `verify_member_commitment`, `ejection_verdict`,
`compute_merkle_root`) and re-rolls no Merkle / preimage / signature logic.
The §19.1 Merkle scheme is **frozen** (CEG 1.0-RC15) with no RFC-6962
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

**Mitigation (#225)**: on `VerifyMode::Full`,
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

**Mitigation (#228/#229)**: over the verified corpus,
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

**Mitigation (#228/#229, security-critical)**: a **Divergent**
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

**Mitigation (#228/#229)**: `witness::accept_if_monotonic` +
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

**Mitigation (#228/#229)**: `witness::build_local_witness`
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

**Mitigation (#230)**: `put_aggregated_tier` runs the **§19.7.1
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
**ZERO rows**. The composite manifest rides the #225 hybrid
admit gate in the same transaction.

**Secondary**: the storage column is **opaque** BYTEA/BLOB (V086 — the
wire-churn firewall); the verification inputs
are **admission-only and are never persisted**, so a stored row cannot carry
unverified meta that a later read would trust.

**§19.7.3 ejection**: the `EjectAggregatedTierOnly { tier }`
`EjectionVerdict` variant (CEG RC16) drives the tier-granular
single-stratum shed (`evict_aggregated_tier(aggregate_content_id, tier)`
→ `EjectionAction::EjectAggregatedTierOnly(tier)`): it sheds exactly the
tier-`tier` composite's symbols (manifest survives `EnvelopeOnly`) while the
finer (lower-level) AND coarser (higher-level) composites stay intact. It
composes with hard-delete — a stratum already below the floor is unreachable,
so it **never resurrects erased content**. The full §19.7.3 ejection surface
(`Keep` / `EjectToTier` / `EjectAggregatedTierOnly` / `EjectHardDelete`) is
driven from verify-core.

#### AV-65: Forged aggregation source set (descent integrity)

**Attack**: an adversary calls `descend_aggregated_sources` with a forged set
of source `content_id`s — one that does not re-derive the committed
`member_commitment` — to drive eviction/descent of items that were never
members of the composite (using descent as a force-evict channel).

**Mitigation (#230)**: `descend_aggregated_sources` loads the stored
aggregation record and calls **`verify_member_commitment` over the
caller-supplied source `content_id`s BEFORE descending** — a forged member
set (one that does not re-derive the committed `member_commitment`) is
**REJECTED** and cannot drive eviction. Sources descend in the canonical
`descend_order` (§19.7.2 lexicographic member-id order), so a returned list
re-derives the parent's `member_commitment` byte-for-byte. This is the
§19.1 Merkle scheme's intended use: **full source-id-list recomputation,
never a partial inclusion proof** against a bare root — which is exactly why
the no-RFC-6962-prefix scheme leaves CVE-2012-2459 odd-node malleability
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

**Mitigation (#228, N5)**:
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

### 3.15 Constitution-alignment surface (CIRIS Constitution)

These vectors bind persist to the CIRIS Constitution substrate
clauses at the per-row admission grain. AV-67..AV-70 are the gates;
AV-71 and AV-72 are bypasses in those gates and their fixes. The §19
verifiers are unchanged; these vectors are about *admission gating*
over the federation directory + community substrate, not crypto.
AV-59 (§3.14) is the **same forge-later class as CC 5.3.2.4.3** at the
trace-store path — AV-67 extends that mandate from the
fountain/witness/aggregation store-paths to the **bulk federation-tier
attestation testimony corpus**, the single most forge-exposed surface
(CC 5.3.2.4.3's "store at massive scale" CEWP crux). AV-60/AV-61
(witness divergence) relate to federation-tier reconciliation but are
gated by the §19 PQC witness gate (AV-62), not the per-trace ingest
gate.

#### AV-67: Federation-tier forge-later via unverified per-trace ingest (CC 5.3.2.4.3.1)

**Attack**: a CRQC-era adversary who has broken Ed25519 mints a backdated
federation-tier `attestation` under a historical key and writes it to the
durable, content-addressed, replicated testimony corpus via
`put_attestation`. A trust-**threshold** check on the *key* alone
(`AdmissionGate::check_federation`) leaves a federation-tier row's
envelope hybrid signature (`scrub_signature_classical` /
`scrub_signature_pqc`) stored but never *verified* at the per-trace
write/replicate path, and trusts the `tier = federation` label.
Content-addressing is no defense: the adversary hashes their own
forgery, so the address matches by construction (CC 5.3.2.4.3).

**Mitigation (#237, CC 5.3.2.4.3.1)**:
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
into `put_attestation` on both backends, composed with — not
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
LOCAL-tier without PQC → ADMITTED (no over-rejection). Federation-tier
`withdraws` emitted by persist itself (evict/sweeper/takedown) are
hybrid-signed via the engine's PQC-capable `LocalSigner`; a non-PQC
engine (constructed via `from_shared`) returns a CLEAR typed error rather
than emitting a classical-only or silently-skipped withdraws (fail-honest,
§1.6 MISSION).

**Residual**: classical-only federation-tier rows are non-conformant and
rejected; non-PQC producers are confined to local-tier until they
complete PQC wiring (intended — the
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
a verifier can enforce this cryptographically.

**Mitigation (#235/#236, CC 4.4.3.4.3 / CC 1.13.5)**:
`federation::admission::check_node_agency_admission`, wired into
`put_attestation` on both backends alongside the
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
`src/auth/ownership.rs` enforcement is a thin wrapper over this
substrate gate.

**Residual**: the gate constrains the *delegation scope*, not what a
recipient does with a key it already controls out-of-band; the wire-format
invariant is "a node-only key's delegation literally cannot carry agency,"
which is the structural property CC 1.13.5 names. **See AV-71 for the
duplicate-token bypass.**

#### AV-69: Unstewarded node/agent admitted to a non-infra community (CC 3.2 / CC 3.4.7.1)

**Attack**: an adversary writes a `put_community` whose roster includes a
`node`- or `agent`-role key with **no steward-binding to an accountable
human** — granting a bare, unstewarded node standing to speak AS the group.
Per CC 3.2, non-infra community membership is an **authority act** and
CC 1.13.2 requires authority to root in a `user`-role human. Form and
geographic checks alone (`check_consensus_protocol_form` + the geographic
gate) would admit the unstewarded member.

**Mitigation (#235, CC 3.2 / CC 3.4.7.1)**:
`federation::admission::check_community_membership_steward_binding`, wired
into `put_community` on both backends after the geographic gate and
before the write lock / `persist_row_hash` / INSERT (verify-before-mutation,
AV-9). It reuses the `is_steward_bound(K)` predicate (CC 3.4.7.1 — a live,
unrevoked path from `K` to a `user`-role identity); **only members
resolving to `node` or `agent`** are constrained — the first such member
lacking a live steward-binding REJECTS the whole write with typed
`Error::UnstewardedCommunityMember` (token
`federation_unstewarded_community_member`), not stored. A `user`-role member
is trivially steward-bound.

**Secondary**: the **infrastructure carve-out** (CC 3.2 "Trust ≠
membership") — a community whose `policy_blob.cohort_subkind ==
"infrastructure"` is exempt (a node MAY trust + serve an infra community
with no steward). The gate is a **precondition**, NOT a substitute for the
community's own `consensus_protocol` vote.

**Residual**: an unresolved or non-node/agent member is out of scope (no
over-rejection). The carve-out's authority is itself gated — **see AV-72
(F2) for the self-label bypass.**

#### AV-70: Community-DEK not rotated on member removal (CC 4.4.3.2.2)

**Attack**: a removed community member retains a valid wrap of the shared
per-community DEK and continues to decrypt **new** community content sealed
after its removal — a forward-secrecy break. Community content
(`cohort_scope: community | affiliations`) is sealed under one shared DEK
(CC 4.4.3.2.1 — "a community is a stream its members subscribe to,
cryptographically"); without rotation, removal is not forward-secret.

**Mitigation (CC 4.4.3.2.2, Option-A forward secrecy)**:
`put_community_membership_revocation` **bumps the community DEK epoch**
(`community_dek_bump_epoch`) on both backends as part of the
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
**See AV-72 (F4) for the future-dated-`effective_at` forward-secrecy
hole.**

#### AV-71: Node-agency gate bypass via duplicate `identity_type` token (CC 1.13.5 / CC 4.4.3.4.3, F1)

**Attack**: an adversary registers a node key with a **duplicate**
`identity_type` token — `"node,node"` or `"node, node"` — then delegates
`agency:*` to it. Deciding "is this recipient node-only?" with
`parse_set(identity_type) == [NODE]` fails here, because `parse_set` does
**not** dedup — `["node","node"] != ["node"]` would skip the gate and let
a pure-`node` key receive agency, defeating CC 1.13.5.

**Mitigation (#237, F1)**: `check_node_agency_admission` (AV-68) tests
the identity_type **set** via a `HashSet<&str>` (`set.len() == 1 &&
set.contains(NODE)`), robust to duplicate / whitespace / order tokens.

**Secondary**: a genuine `node,agent` hybrid is still ADMITTED (it
legitimately carries agency — no over-reject); regression-tested
(`"node,node"` / `"node, node"` carrying `agency:*` → REJECTED + not
stored) on both backends.

**Residual**: none for this token-canonicalization class; the set-semantics
match the CC 3.4.7.1 `identity_type`-is-a-set definition.

#### AV-72: Authority/forward-secrecy bypasses in the new community gates (CC 3.2 / CC 4.4.3.2.1 / CC 3.4.7.1 / CC 4.4.3.2.2, F2–F5)

**Attack (four sub-vectors, each closed)**:

- **F2 — self-labeled `cohort_subkind: infrastructure`.** A caller who
  self-labels a community `infrastructure` would skip the AV-69
  steward-binding precondition AND force its content to Commons-plaintext
  (no DEK, AV-70) if the gates honored the label with **no authority
  check**.
  **Mitigation**: `is_authorized_infrastructure_community` honors the
  carve-out **only if** the community's own key (`community_key_id`, via
  `lookup_public_key`) has an `identity_type` set containing
  **`substrate_persist`** (the reserved governance/substrate authority).
  Used in BOTH gates; **fail-secure** — an unauthorized infra-labeled
  community falls through to the STRICTER non-infra path (steward-binding
  REQUIRED + DEK cascade APPLIES).
- **F3 — `is_steward_bound` honoring revoked/expired delegations.** Clause 3
  ("∃ a live `delegates_to(U → k)` from a `user`-role granter") must not
  accept ANY `delegates_to` — a `withdraws`/`recants`-retracted or lapsed
  delegation would confer steward-binding (AV-69 bypass). **Mitigation**:
  an edge is skipped if the granter has a `withdraws`/`recants`
  against `k` (the §11.10 edge-retraction model, recipient named as
  `attested_key_id`) or if `expires_at <= now`; only a genuinely live edge
  confers steward-binding.
- **F4 — rotation forward-secrecy hole for future-dated `effective_at`.**
  `put_community_membership_revocation` bumps the epoch at write time, and
  `resolve_community_members` drops a member once `effective_at <= now`. A
  revocation with `effective_at = now + 30d` would bump the epoch yet keep
  wrapping the "removed" member into the fresh-epoch DEK for the whole
  window, falsifying AV-70's "exposure window = zero." **Mitigation**:
  community membership revocation is **immediate** — a future-dated
  `effective_at` (beyond a 60s clock-skew tolerance) is REJECTED with typed
  `Error::InvalidArgument` BEFORE any write, on both backends.
- **F5 — revocation INSERT + `hard_case` emission + epoch bump
  atomicity.** A bump failure after the INSERT committed would leave a
  durable un-rotated revocation (a silent forward-secrecy gap).
  **Mitigation**: all three run in ONE transaction per backend (postgres
  `client.transaction()`; sqlite `conn.transaction()` under a single
  lock).

**Secondary**: each fix has a test that fails without it and passes with
it, on both backends.

**Residual**: these close the community gates' own bypasses; they do not add
new substrate authority — the carve-out authority (`substrate_persist`) is
the same reserved governance role that already owns `system:` /
`audit_chain:` / `corpus_health:` reserved prefixes (§3.7).

---

### 3.16 Bootstrap / Sybil — the mesh receive path (CIRISPersist#543)

This section is the **safe-mesh-genesis** posture: what an *admitted but
untrusted* peer can do, and what stops it.

#### The structural premise — why the put-gates are load-bearing

Canonical servers exist to bootstrap strangers, so admission is
deliberately cheap: `register_federation_key` requires a **self-signed
hybrid proof-of-possession and nothing else**. That proves key *custody* —
not identity, not authorization. Key material is free, so the model must
assume **unlimited admitted identities**.

Three layers that look like they bound this do not, on the receive path:

- **Edge's consent plane is SEND-only.** `apply_envelope_bytes(kind, bytes)`
  never receives the peer id, `on_deliver` applies every delivered envelope
  with no consent check, and the responder auto-factory builds a Responder
  for any admitted peer ("no additional consent is required").
  (CIRISEdge#426.)
- **The server's HTTP admission IS owner-gated** (`/v1/federation/peering`
  `require_owner`, "owner-authored consent ONLY") — and the mesh receive
  path bypasses it entirely.
- **Consent withdrawal is send-side**, so it cannot stop inbound injection.

Net: a Sybil PUSHes an unsolicited `Deliver` of its self-signed KeyRecord →
`apply_key` → auto-registration on the self-signature alone → then
attestation rows → `put_attestation`. **persist's put-gates are the entire
defence.** A gate that leaks here is not "defence-in-depth reduced"; it is
the only depth. AV-73..AV-78 are the gates on this path.

#### AV-73: Third-party reputation forgery via ungated `scores`

**Attack**: a `scores` dimension with no governing duty admits a score from
any registered key. `compose_verdict` counts *distinct attesting keys*
(`witness_diversity: None`), so ≥3 Sybils could fabricate a
`WellEstablished` or `Refuted` verdict about any subject Y — with Y having
no involvement whatsoever.

**Severity**: highest on this path. It is not resource abuse; it is
**trust-graph poisoning that corrupts a third party's walk**. And it fans
out: the bulk read `list_attestations_since` is tier-only and unscoped, and
edge advertises third-party `Global`/`Cohort` rows, so a canonical relays
forged reputation onward to its honest consented recipients.

**Mitigation**: the emitter's standing must bound what it can assert about
a third party. The per-dimension authority model is the substantive
policy here: where a dimension family has a *named* authority (reserved-prefix
rules, duty-holders, witness-target walks) that authority is the gate.

**Residual**: a dimension family with no declared authority still admits
third-party scores from any registered key. The verdict *composition* layer
(`witness_diversity`) remains the second line, and is the correct long-term
home for "N distinct keys are not N distinct people" — distinctness of keys
is not distinctness of principals, and no put-gate can establish the latter.

#### AV-74: Capacity self-inflation behind a dead guard (dimension-vs-type shape)

**Attack**: a CC 3.4.5 self-emission arm keyed only on the
**`attestation_type`** namespace (`capacity:*` as a type) misses the real
wire shape: reputation rides `attestation_type = scores` with
`dimension = capacity:*`. A Sybil could score *itself*, and combined with
AV-73 a Sybil cluster could both inflate itself and score others.

**Compounding defect — evidence-registry unsoundness**: a guard with
**zero callers** (`check_capacity_not_self_attested`) cited by the vendored
`namespace_supersets.json` as a live processor ("confirms scope-away")
asserts an enforcement that does not run. #519's premise is that a mechanically-cited
processor corresponds to code that *runs*; a citation naming dead code
asserts an enforcement that does not exist. **A dead citation is worse than
a missing one** — a missing processor is visible to the completeness gate,
whereas a dead one reads as discharged.

**Mitigation**: the guard is wired at the `check_reserved_prefix_admission`
chokepoint (both backends, pure/no-lookup so it stays in the cheap
tier), and BOTH shapes are refused — type-keyed and dimension-keyed —
while a genuine third-party capacity score still admits. Pinned by the
`{gate} × {backend}` matrix in `federation::bootstrap_admission`
(invariant **B1**), verified in both directions.

**Structural mitigation**: `every_cited_processor_has_a_non_test_caller`
(`federation::namespace::supersets`) makes the evidence registry
*mechanically sound*: every `path#symbol` the manifest cites as a processor
must resolve to a function with **at least one non-test caller**. The bar is
"non-test" deliberately — a function called only from tests enforces nothing
on the live write path, which is precisely this failure mode. A `pub`
helper that computes an authority set from caller-declared data is not
kept, cited or not: it is a loaded gun regardless of who calls it.

**Residual**: the gate covers repo-local citations naming functions; types,
consts and cross-repo citations are classified explicitly
(`NON_FUNCTION_CITATIONS`, `EXPORTED_API_CITATIONS`,
`DELETED_PENDING_REVENDOR`) so each exemption is a reviewable claim rather
than a silent skip.

**The inverse direction (CIRISPersist#586)**: a dead *presence* citation
reads as discharged; a stale *absence* claim reads as an open hole that is
in fact closed — and, worse, an absence claim can be the reason a control is
switched OFF. `UNREGISTERED_GATED_FAMILIES` exists because CC catalogues no
row for some gated families; the day CC lands one, that exemption stops
being a courtesy and starts being an unreviewed bypass of CC 3.1.7 R2. The
asymmetry is structural: a presence claim breaks its own build when the
symbol moves, an absence claim is true when written and nothing re-asks.
`manifest_absence_claims_still_hold` and
`gated_uncatalogued_families_are_still_gated_and_still_uncatalogued`
(`federation::namespace::supersets`) close it, over the *same* definition
predicate the presence gate uses (`source_defines`, extracted and shared so
the two validators cannot answer "does this symbol exist?" differently).
Coverage is derived from the manifest, so a new absence claim cannot enter
the Registry-of-Record without a declared falsifier. **Residual**: only
STRUCTURED absence claims are gated — an `asymmetry_kind: logical_defect`
object carrying `missing_dual`. Prose absence claims are not, deliberately:
of the manifest's 56 repo-local `proposed:` citations, 29 name a symbol that
exists on purpose, so classifying them needs the description field, and
inferring a rule from a description is the section-walk heuristic CC 3.1.7
R2 forbids. A `holds` entry is also a tripwire, not a proof — it fires on
the names persist declared, not on every possible implementation.

#### AV-75: Self-asserted privileged `identity_type` / roles

**Attack**: `verify_key_registration` checks only the PoP self-signature.
Gating privileged claims one at a time at `put_public_key` —
`accord_holder` (hardware attestation), `canonical` (anchor-scrub),
`infra:attest` (#422 co-scrub), co-steward `registry`/`verify` (#440) —
leaves everything else in `identity_type` / `roles` self-assertable,
including types that reserve whole dimension families: `substrate_persist` (`system:`, `audit_chain:`, `corpus_health:`,
`identity_continuity:`, `federation_directory:`), `witness`
(`age_assurance:`, `capacity_assurance:`, `transparency_log:cosigned:`),
`trusted_publisher` (`content_rating:`), `lenscore_detector`
(`detection:*`). A Sybil could thereby assert age, capacity, system or
detection authority **about a third party**.

**Mitigation**: the rule is **closed-set rather than incident-driven**.
`identity_type::AUTHORITY_CONFERRING_IDENTITY_TYPES` enumerates every claim
that unlocks a decision anywhere in the codebase, and
`authority_conferring_set_covers_every_reserved_prefix_rule` proves the set
is a **superset of every identity type any reserved-prefix rule requires** —
so adding a rule that reserves a family to a new type without gating that
type *fails the build*. The enumeration cannot fall behind the rule
table.

**The conferral-mode distinction (why one gate was not enough)**: these
privileges have genuinely different roots, and a gate demanding the wrong
ceremony is as broken as no gate — it fails **closed on legitimate
operators**. `identity_type::conferral_mode` states the mechanism per claim,
exhaustively:

| Mode | Claims | Root |
|---|---|---|
| `HardwareAttested` | `accord_holder` | secure-element custody proof |
| `AnchorScrubbed` | `canonical` | pinned HUMANITY_ACCORD anchor scrub |
| `AccordCoScrubbed` | (none currently) | accord family m-of-n co-scrub |
| `DelegatedFromTrustRoot` | `trusted_publisher`, `lenscore_detector`, `witness` | `delegates_to` from a trust root, resolved at use by `capability_roots_to_trusted_root` |
| `DerivedFromVerifiedState` | `steward`, `partner`, `wise_authority`, `substrate_persist` | authority re-derived from persist's own verified state at each use |

Root IDENTITY (`canonical`) is conferred by ceremony; operational CAPABILITY
flows by delegation from a root the asking node itself trusts. Demanding the
accord's hardware co-scrub for a routine detector or publisher would fail
closed on every legitimate operator. `check_privileged_identity_type_admission`
enforces any `AccordCoScrubbed` claim at every `federation_keys` write
chokepoint, riding the role-generic core
`check_accord_role_admission_over_roster`.

**Why `substrate_persist` is `DerivedFromVerifiedState`**: it is a node's
identity **for itself**. The families it unlocks are the node's own
operational telemetry about its own substrate, and nothing consumes them as
authority over a third party — a Sybil calling itself "the substrate" gains
standing over nobody. Requiring a co-scrub would also be unsatisfiable by
construction: a node registers this identity at its own bootstrap, before
any accord family exists to co-scrub it. *If a `system:*` row ever becomes
an input to a decision about another party, this must move to
`AccordCoScrubbed`.*

**Residual**: `DerivedFromVerifiedState` claims remain self-assertable at
registration by design — the claim is descriptive and every use site
re-derives the authority. That safety property is therefore only as good as
the use-site walks (caller-supplied authority is forgeable authority). Each such walk is
separately tested, but the invariant is distributed rather than enforced at
one chokepoint, and a future use site that trusts the *claim* instead of
re-deriving would silently reopen this.

#### AV-76: Bootstrap amplification via verify ordering + absent write quota

**Attack**: if the ML-DSA-65 hybrid verify — the expensive operation — runs
**last**, after roughly eight DB-walking gates, a row that fails at the
final step still pays for every preceding gate; without a per-peer write
quota, nothing bounds the volume. At bootstrap, where admission is cheap by
design, that is a straightforward amplification vector.

**Mitigation**: cheapest-first ordering (pure predicates → single lookups →
crypto → DB walks) and a per-peer write quota ahead of the gate stack; see
the matrix row and AV-87 for the quota's keying axis.

**Ordering constraint (why this is not a free reorder)**: the gate stack is
not a pure filter — at least one gate *stamps a field a later gate reads*
(`withdraws_admission_rule` is resolved by the withdraws gate and persisted
on the row). Any reordering must preserve those dependencies; a reorder that
"just" moves crypto earlier while breaking a stamp ordering would trade a
DoS vector for a correctness bug.

**Residual**: cost asymmetry at admission is inherent to open bootstrap —
the goal is to make the adversary's cost scale with *their* work, not the
defender's. A quota bounds volume, not per-row cost.

**Dedup placement**: the CEG §6.1 idempotent-replay dedup short-circuit
ends in a bare `return Ok(())`, so placed ahead of crypto it would not
merely reorder gates — it would *skip* every gate below it: the
PQC-mandatory hybrid verify **and** the AV-45 write-path `cohort_scope`
gate. A writer who could name an already-referenced `(attestation_type,
attesting_key_id, references_attestation_id)` triple would receive an
unverified, unauthorized `Ok`. The rule:

> **A dedup short-circuit may return early to REFUSE, never to ACCEPT.**
> Idempotence is a promise about the *effect* of a replay (no second row) —
> never a licence to skip the proof that the replay was admissible at all.

The dedup runs at **tier 4b**: after everything that is a property of the
row's own bytes and the writer's standing (both of which a replay must still
prove), and before the DB-walk authority gates — so a replayed `withdraws`
whose authority has since been revoked stays a silent no-op rather than
flipping to a hard reject.

[`substrate_machine`](../src/federation/substrate_machine.rs) witnesses this
class: it drives op sequences that replay against an existing triple, which
a one-writer-against-a-fresh-row fixture cannot express.

**Reachability (the AV-77 de-admission gate)**: the gate is wired on both backends, proven by
a `{gate} × {backend}` matrix, and reachable by hosts through
`Engine::set_self_key_id` / `self_key_id` plus PyO3 bindings
(`set_self_key_id_through_the_engine_activates_the_deadmission_gate_543`
drives the lifecycle through the Engine handle).

**The class, stated generally**: a mitigation is not shipped when its code path
exists and passes tests. It is shipped when a **host can reach it and observe
that it is on**. *"Accepted but not projected"* is a recurring failure mode
(CIRISPersist#444: a signed route table admitted correctly and never
surfaced), and a witness matrix that configures the substrate directly
cannot detect it. **Test-support fixtures that bypass the host API will
certify an unreachable feature as shipped.**

#### AV-78: The tier column was never written — every local-tier row stored as `federation`

**Defect class** (not an adversary-driven attack; a substrate correctness
failure with security consequences). If `put_attestation`'s `INSERT` omits
the `tier` and `promoted_at` columns, the schema `DEFAULT 'federation'`
overrides every `Tier::Local` row: the backend cannot store a local-tier row
at all, and silently relabels it.

**Why it is in the threat model**: `tier` is a *trust* label, and the
promotion plane (#509, #519) is defined as a projection of consent state onto
it. A row minted local — deferred signature per CC 5.3.2.2, consent-scoped,
never intended to leave the node — would be persisted claiming federation
tier. Reads keyed on tier, the promotion sweep, and the signed since-cursor
planes all consume that column. A label nobody wrote is a label nobody can
trust.

**Mitigation**: both backends bind `tier` and `promoted_at` on insert.

**Witness and its limit**: the differential oracle in
[`substrate_machine`](../src/federation/substrate_machine.rs) compares
backends on the identical submitted row; a disagreement *is* the finding, so
no expected-value table is needed. **A differential oracle is exactly as
wide as its backend set**, and a defect every arm shares is invisible to
it — the non-differential invariants and reading the code are the
complement.

#### AV-77: No in-band response to a bootstrap abuser

**Attack**: not an injection vector but the **absence of a response
surface**. The requirement is that responses to abuse are themselves CEG
attestations, not out-of-band state. The coarsest mechanism that stops an
abuser is the **whole-node accord kill-switch** — a sledgehammer
requiring hardware-attested accord holders, with nothing between "ignore it"
and "halt the node".

What exists and what does not:

- **Encodable, partly wired**: `moderation:{allegation_type}` (duty-gated,
  can target a peer — but records an *event*, not a *sanction*);
  `slashing:{outcome}` (verdict shape + evidence floor wired server-side, but
  **no emit and no act**); `watchlist:{id}` (config wired, matcher deferred);
  `consent:*` withdrawal (the only actually-wired cutoff — and it is
  send-side, so it cannot stop inbound injection).
- **De-admission**: a node-authored de-admission gate refuses writes from a
  key this node has de-admitted, once the host declares the node's own key
  id via `Engine::set_self_key_id` (with no declared id the gate is
  dormant — a node that does not know its own identity has no judgement to
  enforce).
- **No family exists** for bulk row-slashing or quarantine/probation
  (`revocation:{entity_type}` has no key/node type and is advisory).
- `capacity:*` is advisory — no code path denies serve on a low score.

**Mitigation**: persist owns the registry-of-record under #519, so the
families mint here. The smallest coherent set, in dependency order:
**de-admit/evict a key** (the one that actually stops injection),
**row-slashing** (undo AV-73 poison), then **quarantine/probation** and
**quota** as the graduated middle.

**Residual**: minting the families is necessary but not sufficient — a
family with no emit path and no consumer is the `slashing:*` state
(wired shape, no act). Each family needs its emitter, its authority model,
and a consumer that *changes behaviour*, or it is documentation.

#### What is SOUND at bootstrap (bounding the work)

Audited and holding, stated because a threat model that only lists holes
misrepresents the posture:

- `delegates_to` is author-bound and tier-verified.
- Cross-author revocation folds are author-bound.
- Lifecycle / kill-switch require `accord_holder` — hardware-attested, with
  software keys dropped.
- The trace plane is fail-closed behind the dual #379/#386 serve gate.
- Consent prefix-independence (one grant opening the whole non-trace plane)
  is real, but requires an operator to grant *to* the Sybil — it ranks below
  the injection path.

---

## 4. Mitigation Matrix

| AV | Attack | Primary Mitigation | Secondary | Status | Fix Tracker |
|---|---|---|---|---|---|
| AV-1 | Forged trace from attacker key | Public-key directory lookup | N_eff drift detection (lens-side) | ✓ Mitigated | — |
| AV-2 | Forged trace from compromised key | (out of scope at persistence layer) | Audit anchor + peer-replicate | ⚠ Peer-replicate closes | FSD §4.5 |
| AV-3 | Replay of legitimate batch | Idempotency on dedup key | TLS at edge | ✓ Mitigated | — |
| AV-4 | Canonicalization mismatch | Byte-exact parity tests + pluggable canonicalizer + `WireDateTime` preserves wire bytes verbatim through canonicalization | Ed25519 collision resistance | **✓ Mitigated** (timestamp closed; float drift residual untriggered, tracked) | — |
| AV-5 | Schema-version flood (mem leak) | `Cow<'static, str>` (no leak) | (deploy-edge rate limit) | **✓ Mitigated** | — |
| AV-6 | JSON-bomb amplification | `MAX_DATA_DEPTH=32` walker | Bounded queue + typed envelope | **✓ Mitigated** | — |
| AV-7 | Body-size flood | `DefaultBodyLimit::max(8 MiB)` | Deploy-edge proxy | **✓ Mitigated** | — |
| AV-8 | Queue saturation | 429 + Retry-After | Single-consumer transaction discipline | ✓ Mitigated | — |
| AV-9 | Dedup-key collision across agents | `agent_id_hash` in UNIQUE index + ON CONFLICT target | trace_id "globally unique per agent" convention | **✓ Mitigated** | — |
| AV-10 | Audit anchor injection | (anchor not part of dedup key) | Peer-replicate validates chain | ⚠ Peer-replicate closes | FSD §4.5 |
| AV-11 | Public-key re-registration | First-write-wins (`ON CONFLICT DO NOTHING`) + lens-canonical `revoked_at`/`revoked_reason`/`added_by` audit columns | Manual UPDATE for legitimate rotation | ⚠ No explicit rotation API | tracked |
| AV-12 | Schema-version downgrade | Strict allowlist | Per-version payload gates | ✓ Mitigated | track at version bump |
| AV-13 | JSONB injection | Parameterized typed binding | — | ✓ Mitigated (read-path JSONB operands need the same binding) | — |
| AV-14 | Scrubber bypass via schema-altering callback | Schema-preservation gates | Python process boundary | ✓ Mitigated | — |
| AV-15 | PII leak via errors | Typed `kind()` tokens at HTTP/PyO3 boundary; verbose form to tracing logs only | — | **✓ Mitigated** | — |
| AV-16 | Side-channel timing | Ed25519 verify_strict constant-time | (no constant-response wrapper) | ⚠ Directory enumeration possible | tracked (research) |
| AV-17 | Integer truncation on `attempt_index` | Typed `MAX_ATTEMPT_INDEX = 1024` + `try_into` bound | `overflow-checks = true` on release profile (defense in depth) | **✓ Mitigated** | — |
| AV-18 | Plaintext Postgres connection | Optional `tls` feature — `tokio-postgres-rustls` | `sslmode=verify-full` via DSN | **✓ Mitigated** | — |
| AV-19 | No graceful shutdown / lost in-flight commits | `tokio::signal::ctrl_c` + drain protocol; producer close → persister drains → exit | Journal preserves bytes-on-failure (FSD §3.4 #2) | **✓ Mitigated** | — |
| AV-20 | No statement_timeout on Postgres | (deferred) | Pool size limits | ⚠ Track | tracked |
| AV-21 | No per-agent rate limiting | (deferred) | Shared-queue 429 backpressure | ⚠ Track; PoB §5.6 acceptance policy adjacent | tracked |
| AV-22 | No clock-skew validation on incoming timestamps | (deferred) | Retention-window absorbs out-of-window data | ⚠ Track | tracked |
| AV-23 | `consent_timestamp` range unconstrained | (deferred) | Schema-required-or-422 gate (TRACE_WIRE_FORMAT.md §1) | ⚠ Track | tracked |
| AV-24 | Lens-scrub bypass / forgery | UNCONDITIONAL signed scrub envelope (FSD §3.3 step 3.5; §3.4 robustness primitive #7) — every component, every level, key never null. `original_content_hash + scrub_signature + scrub_key_id + scrub_timestamp` columns proof the deployment's handling. | Single-key principle — agent uses its existing wire-format §8 key; no separate scrub key to compromise | **✓ Mitigated** | — |
| AV-25 | Scrub-key compromise | Hardware-backed `ciris-keyring` (TPM / Secure Enclave / StrongBox / DPAPI) — seed never leaves the keyring; never crosses the FFI boundary | `SoftwareSigner` fallback for hardware-less deployments (named residual) | ✓ Mitigated where hardware available; ⚠ residual on software-fallback | CIRISVerify hardware-attestation tier governs |
| AV-26 | Multi-worker migration race | Session-scoped `pg_advisory_lock(0x6369_7269_7370_7372)` on dedicated single-use connection in `run_migrations()` — workers serialize on cold-boot, lock auto-releases on session close (incl. panic) | `Error::Migration { sqlstate, detail }` surfaces SQLSTATE for lens-side retry policy | **✓ Mitigated** | — |
| AV-27 | Identity churn via ephemeral keyring storage | Boot-time check via authoritative `HardwareSigner::storage_descriptor()` (ciris-keyring v1.8.0). Typed dispatch: `SoftwareFile` ⇒ ephemeral-path heuristic; `SoftwareOsKeyring{User}` ⇒ logout-bound warn; `InMemory` ⇒ hard warn. `Engine.keyring_path()` + `Engine.keyring_storage_kind()` expose authoritative path / classifier for `/health` | Suppression via `CIRIS_PERSIST_KEYRING_PATH_OK=1` after operator audit; `INTEGRATION_LENS.md §11.5` deployment template guidance | **✓ Mitigated** | — |
| AV-28 | Federation_keys directory pubkey poisoning | Idempotent on `(key_id, persist_row_hash)` — INSERT ON CONFLICT DO NOTHING + post-insert hash check returns typed `Error::Conflict` on key_id collision with differing content; never silent overwrite | Per-row scrub envelope verified consumer-side; PoB §6 statistical drift detection at federation level | **✓ Mitigated** | — |
| AV-29 | Attestation graph poisoning | Persist exposes edges only — no `is_trusted()` / `trust_score()` / `trust_path()`. Consumers compose policy; per-row scrub-envelope verify before counting any edge | Append-only graph (revocations observed, not retroactive deletes); poisoning is additive | ✓ Mitigated by architectural non-goal — consumer-side policy required | — |
| AV-30 | Federation_keys self-FK integrity | `DEFERRABLE INITIALLY DEFERRED` on the self-reference; constraint check at COMMIT, not row insert; bootstrap rows resolve their own FK by transaction commit | Standard FK semantics for non-bootstrap rows | **✓ Mitigated** | — |
| AV-31 | Hybrid-pending exploitation (Ed25519 break + soft-PQC window) | `HybridPolicy::Strict` rejects hybrid-pending; `SoftFreshness { window }` bounds acceptance to `row_age < window`; policy is per-call, no silent default | Bound signature pattern (PQC over `canonical \|\| classical_sig`) requires breaking BOTH algorithms to forge fully-verified rows | **✓ Mitigated** (Strict / Fallback are explicit; SoftFreshness window is caller-supplied) | — |
| AV-32 | Cold-path PQC denial-of-completion | Per-write cold-path on engine's tokio runtime (no external network/service to deny); sweep primitive (`Engine.run_pqc_sweep`) provides recovery; `pqc_sweep_on_init=True` constructor default runs sweep at boot | Writer contract documented in V004 schema header; persist owns the implementation (CIRISPersist#10) | **✓ Mitigated** | — |
| AV-33 | Bound-signature stripping (PQC over classical-only) | Hybrid scheme signs PQC over `(canonical \|\| classical_sig)`; persist's `HybridVerifier` rebuilds bound payload before PQC verify and rejects PQC-over-canonical-only | Matches CIRISVerify `HybridSignature` spec; primitive enforced at ciris-crypto layer, not reimplemented persist-side | **✓ Mitigated** | — |
| AV-34 | Cross-shape canonical injection at 2.7.0 | Deterministic dispatch by `trace_schema_version`; per-component `agent_id_hash` and `deployment_profile` silently ignored at 2.7.0 — don't enter canonical bytes, don't affect dedup; byte-identical canonical with vs. without injection at 2.7.0 | Schema-version-aware decompose at 2.7.9 requires the shape (typed `MissingField` on absence); regression tests assert byte-identity | **✓ Mitigated** | — |
| AV-35 | Schema-version dispatch attack (try-N-shapes) | deterministic dispatch — each trace contributes to exactly one canonical-shape verify path; verification is bound to the dispatch arm's canonical (a wrong-arm selection deterministically fails verify); the property holds at the `"2.7.legacy"` arm — even though the routing input isn't itself signed at the legacy arm, a legacy-signed trace verifies only against the 2-field canonical | Typed `Error::UnsupportedSchemaVersion` rejects out-of-allowlist versions before dispatch (AV-12 overlap); telemetry-driven sunset rule (AV-42) bounds the legacy arm's lifetime | **✓ Mitigated** | — |
| AV-36 | LLM_CALL parent-linkage substitution | strict-parse at 2.7.9 — `MissingField("data.parent_event_type")` / `parent_attempt_index` rejects envelopes missing the wire fields; no substitution at 2.7.9 | Rows persisted before the strict parse keep `parent_event_type='LLM_CALL'`; RATCHET links them via `handler_name`; 2.7.9 traffic carries spec-correct linkage | **✓ Mitigated** | — |
| AV-37 | deployment_profile cohort-identity injection | `deployment_profile` rides in 2.7.9 signed canonical bytes; agent's signature commits to declared labels; strict-parse at 2.7.9 rejects missing block (`MissingField("deployment_profile")`) | `deployment_resourcing` is intentionally lens-computed from cost/tokens/model observation, not agent-declared — labels can lie but emergent operational reality cannot | **✓ Mitigated** | — |
| AV-38 | Per-key DSAR scope violation | `signature_key_id` is REQUIRED on `delete_traces_for_agent`; deletion is scoped to `(agent_id_hash, signing_key_id)` at all three substrate layers (trace_events, trace_llm_calls cascade, federation_keys cascade) | Lens-side DSAR audit ledger captures request envelope + signature verification independent of persist | **✓ Mitigated** | — |
| AV-39 | verify-via-persist bypass (consumer calls ciris_crypto direct) | `Engine.verify_hybrid` is the federation's single-source-of-truth — accepts arbitrary canonical bytes (not just CompleteTrace shapes), exposes the policy machinery (Strict / SoftFreshness / Ed25519Fallback), is the path of least resistance | Documented as the closure pattern (CIRISPersist#7; `docs/COHABITATION.md`) | ✓ Architectural closure — not a runtime gate but the design path | — |
| AV-40 | Outbound queue disk exhaustion | Per-row `body_size_bytes ≤ 8 MiB` + `ttl_seconds > 0` + `max_attempts > 0` schema CHECK; `sweep_ttl_expired` operational primitive bounds row lifetime; FK on sender/destination_key_id (AV-28 trust boundary) | Operator-tunable sweep cadence; `oldest-pending-age` ops dashboard | **✓ Mitigated** | — |
| AV-41 | Spoofed in_reply_to ACK matching | ACK envelopes go through persist's normal verify pipeline (AV-1 unknown-key gate + AV-39 verify_hybrid via persist) before `mark_ack_received` is called; `body_sha256` content-derived matching is downstream of signature verify | Bound signature pattern (AV-33) closes Ed25519-alone forgery branch | **✓ Mitigated** | — |
| AV-42 | Legacy `attempt_index` dedup-collapse | schema-version-gated fallback — only `2.7.0` / `"2.7.legacy"` arms fall back to `attempt_index = 0` on absence (`MissingField`); 2.7.9 still strict; malformed values (negative, wrong type, out of range) still error through AV-17 typed paths; fallback fires for absence ONLY, not for adversarial-shaped values; cross-agent collision closed by `agent_id_hash` in dedup tuple (AV-9) | Telemetry-driven sunset (`federation_canonical_match_total{wire="2.7.legacy"}` 7-day-zero soak); accommodation is time-bounded by empirical observation, not permanent | **✓ Documented residual** (deliberate fidelity trade-off; pre-2.7.8.9 traffic is unrecoverable otherwise — federation's append-only contract takes priority over per-row dedup fidelity for legacy arm) | — |
| AV-43 | Read-side adversary inference attack | aggregate primitives return computed statistics (counts, means, z-scores, decay-series points), not per-trace content; `sample_count` / `trace_count` fields surface explicitly so callers gate k-anonymity at their layer (one-line check: `if agg.trace_count < K_THRESHOLD: refuse`); error kinds are closed-set `&'static str` (no attacker-controlled strings); AV-9 trace-scoped reads carry `agent_id_hash` so callers authorize per-trace access at their layer | Substrate exposes truthful aggregates; consumer composes k-anonymity policy (lens-side, sovereign-mode agent's own gate) — same architectural-non-goal pattern as AV-29 attestation graph (persist exposes edges, consumers compose policy) | **✓ Documented** (substrate surface; consumer-side policy required for inference resistance) | — |
| AV-44 | Rust panic escalates to process abort | three-layer panic isolation: (1) `panic = "unwind"` in release profile lets PyO3's `catch_unwind` trampoline fire; (2) explicit `catch_unwind(AssertUnwindSafe)` wrapping every `#[pyfunction]` body converts panic payload to `LensQueryError(Exception)` — derives from `Exception` not `BaseException` so uvicorn catches as 500; (3) crate-wide `Row::get` → `try_get::<_, Option<T>>` sweep surfaces NULL as `None` at the decode layer, before panic candidates form | tracing::error captures every caught panic with payload + site; in-flight tokio tasks panicking in background are logged but don't propagate to Python (documented residual) | **✓ Mitigated** (CIRISPersist#24 failure class; see §3.13 for why unwind replaces SECURITY_AUDIT_v0.1.2.md §4.2's abort in the cdylib-in-uvicorn shape) | — |
| AV-45 | Graph node `attributes` JSONB unbounded write (storage exhaustion / parse-bomb) | per-call size cap (default 1 MiB; configurable per deployment via `CIRIS_PERSIST_GRAPH_MAX_ATTRIBUTES_BYTES`) checked at `upsert_node` entry — payloads above cap rejected as typed `Error::InvalidArgument("attributes too large")`; per-row hash + signature envelope binds the canonical attributes to the signer, so post-write bloat (e.g. via an UPDATE-around-persist path) breaks signature_verified=TRUE. | JSONB GIN index on attributes carries its own cost-bound — Postgres rejects oversized GIN entries at index time as a backstop. | **✓ Mitigated** | CIRISPersist#34 |
| AV-46 | k-hop graph traversal fan-out abuse (CPU / memory exhaustion via deep recursion) | absolute `MAX_KHOP_DEPTH = 16` enforced at trait method entry, before the recursive CTE runs; caller-supplied depth above the cap → typed `Error::InvalidArgument("max_depth exceeds bound")` (no silent clamp — caller sees the rejection); CTE itself uses `LIMIT N` per recursion level to bound the fan-out frontier. | Per-edge-type filter required at the trait surface — `traverse_k_hop` does not accept "all edges" wildcards; caller must name the relationship types. | **✓ Mitigated** | CIRISPersist#34 |
| AV-47 | Graph scope leakage (cross-tenant or cross-domain read via missing scope filter) | every read method on `GraphService` requires `scope` as a non-optional parameter (typed `GraphScope` enum: `Local` / `Identity` / `Environment` / `Community`); SQL queries pin `scope = $N` in WHERE; type system refuses to call the read without naming the scope. | Per-row scope column NOT NULL CHECK at schema layer; legacy or future caller using `Engine` directly cannot bypass the scope filter. | **✓ Mitigated** | CIRISPersist#34 |
| AV-48 | UPSERT-by-version replay (stale write clobbers fresh state) | `upsert_node` requires caller to pass `expected_version` matching the current row's `version` column; mismatch → typed `Error::Conflict("version stale; expected N got M")`; new row writes start at version=1 and increment on every successful upsert. | `updated_by` + `updated_at` columns + signed `signature` over canonical envelope let downstream audit reconstruct the rightful write order on disputed rows. | **✓ Mitigated** | CIRISPersist#34 |
| AV-49 | Audit-log hash-chain integrity violation (tamper / silent rewrite) | `record_entry` re-derives `entry_hash` from canonical(entry minus `signature` + minus `entry_hash` itself) and rejects on mismatch with caller-claimed value (`Error::ChainIntegrity`); reads the current tail under `SELECT ... FOR UPDATE` to serialize writers, then asserts `prev_hash` matches tail's `entry_hash` (or `GENESIS_PREV_HASH = [0; 32]` for first-entry-of-tenant) AND `sequence_number = tail_seq + 1`; INSERT only fires when all four gates pass + Ed25519 signature verifies. | `UNIQUE (tenant_id, sequence_number)` schema constraint is the second gate; replay attempts surface as `Error::Conflict` if they slip past the chain check. Signature binds to canonical bytes that INCLUDE `entry_hash` — a chain rewrite that flipped `prev_hash` on downstream entries would invalidate this entry's signature too. | **✓ Mitigated** | CIRISPersist#35 |
| AV-50 | Audit-log chain fork — silent rewrite undetected by point reads | `verify_chain(tenant_id, from_seq, to_seq)` walks the chain end-to-end and surfaces the FIRST observed break via typed `ChainVerifyOutcome::Break { at_sequence, reason: ChainBreakReason, detail }`. Five break categories: `EntryHashMismatch` (canonical re-derive ≠ stored), `PrevHashMismatch` (prev row's `entry_hash` ≠ this row's `prev_hash`), `SequenceGap` (non-contiguous numbers), `SignatureFailure` (Ed25519 verify fails), `GenesisPrevHashNotZero` (first entry's `prev_hash` ≠ zeros). All five fire independently — first one tripped halts the walk and reports. | Operationally: `verify_chain` is the audit-compliance primitive consumers run on demand or on a schedule. Compatible with both incremental verify (caller pins `from_seq`/`to_seq`) and full-chain verify (`to_sequence = None`). | **✓ Mitigated** | CIRISPersist#35 |
| AV-51 | Audit-log cross-tenant read (compliance scan leaks one tenant's chain to another's auditor) | `list_entries` requires `AuditFilter.tenant_id: String` (non-empty) — empty `tenant_id` rejects with `Error::InvalidArgument("tenant_id is required (AV-51 — no cross-tenant reads)")` BEFORE any SQL fires. `verify_chain` same gate. Every SQL query pins `tenant_id = $N` in WHERE; the `(tenant_id, sequence_number)` UNIQUE index serves the per-tenant chain natively. | Federation-admin cross-tenant compliance scans (the legitimate cross-tenant use case) require an explicit federation-admin role tag on the caller's `federation_keys` row; that path is tracked. The inadvertent cross-tenant leak is closed. | **✓ Mitigated** | CIRISPersist#35 |
| AV-52 | Telemetry label cardinality + size abuse (metric-axis explosion, storage exhaustion via unbounded labels JSONB) | per-call labels JSONB size cap at the trait surface (default 4 KiB; configurable via `CIRIS_PERSIST_TELEMETRY_MAX_LABELS_BYTES`) — payloads above cap reject with `Error::InvalidArgument("labels too large")`. Bulk-record path validates EVERY row's labels BEFORE any I/O fires (no partial-batch landing). The `unique_label_combinations` field on each `MetricSummary` surfaces label-cardinality observability so operators can detect abusive callers post-rollup. | Per-`(tenant, metric_name)` cardinality cap (max 1000 distinct label-sets in 24h) tracked as a deferred enforcement — Postgres has no native cardinality CHECK; the runtime path is the right place, to be enforced when a real consumer trips the soft limit. | **✓ Mitigated** (size cap); **⚠ Observability-only** (cardinality cap) | CIRISPersist#36 |
| AV-53 | Consolidation lock starvation (crashed worker holds lock forever, blocks all subsequent rollups for the tenant) | `consolidate_period` acquires `cirisgraph.consolidation_locks` row via `INSERT … ON CONFLICT DO NOTHING`; on contention checks the existing lock's `locked_at` — if older than `STALE_LOCK_SECONDS = 3600` (1h), atomically breaks + re-acquires via `UPDATE … WHERE locked_at < NOW() - INTERVAL '3600 seconds'` and returns `broke_stale_lock: true` in the outcome (telemetry-actionable signal — operators investigate prior worker's failure mode). Fresh locks block the run with `ran: false` outcome (caller backs off). | Lock release on failure path via `DELETE` so a transient rollup error doesn't leave the lock orphaned for an hour. | **✓ Mitigated** | CIRISPersist#36 |
| AV-54 | TSDB summary chain integrity (TEMPORAL_NEXT edge points at a summary node that doesn't exist — broken temporal traversal across rollups) | consolidator queries for prior period's summary via `SELECT … WHERE attributes @> {metric_name, tenant_id}` BEFORE inserting the TEMPORAL_NEXT edge; only writes the edge if a matching prior node exists. The cirisgraph.edges schema permits dangling edges by design (V013 — eventual consistency for general graph writes), but the consolidator's write path doesn't exploit that flexibility — it confirms the source summary exists at write time. | Idempotency: re-running consolidation on the same period UPSERTs the summary node (version-bump) without writing a redundant TEMPORAL_NEXT (the prior-period lookup is gated by `period_start < req.period_start` so this period's summary isn't its own predecessor). | **✓ Mitigated** | CIRISPersist#36 |
| AV-55 | Incident state-machine bypass (regressive transition `closed → open` or `resolved → investigating` masks an unresolved issue as still-tracked, or hides a real recurrence as already-handled) | `transition_state` reads current `state` under `SELECT … FOR UPDATE`, asserts `current.rank() < new.rank()` per the locked monotonic ladder (`open=0 → investigating=1 → resolved=2 → closed=3`), and rejects any regressive or same-state transition with `Error::InvalidTransition`. `resolution_notes` is REQUIRED when transitioning to `Resolved` or `Closed` (else `Error::InvalidArgument`). Same-state transitions also reject (caller must check current state explicitly if that's the intent). | Closed incidents do NOT dedup against new `record_incident` calls — a new occurrence after closure correctly opens a fresh incident row (the dedup probe is gated on `state IN ('open', 'investigating')`). | **✓ Mitigated** | CIRISPersist#37 |
| AV-56 | Incident correlation_keys abuse (unbounded JSONB array exhausts GIN index, or single-key bloat masks attacker-controlled identifiers in operator-facing UI) | `record_incident` validates `correlation_keys` at the trait surface BEFORE any SQL fires: rejects when `len > MAX_CORRELATION_KEYS = 32` or when any single key's byte-length exceeds `MAX_CORRELATION_KEY_BYTES = 256`. Empty strings also rejected (no implicit "match-anything" key). GIN index on `correlation_keys` JSONB column serves the reverse-lookup path; bounded element count keeps index entries small. | Bounded inputs map to predictable GIN-index growth (`O(incidents × MAX_CORRELATION_KEYS)` worst case); operators sizing storage can plan deterministically. | **✓ Mitigated** | CIRISPersist#37 |
| AV-57 | Read-side cohort_scope escalation via caller-asserted admission (a reader forges `CallerScope::Authenticated { admission: { identity/families/communities = everything } }` to read self/family/community content it isn't a member of) | `CallerAdmission` has NO public constructor — the sole way to obtain one is the substrate-side `build_caller_admission(engine, occurrence_key_id)`, which resolves identity / families / communities deterministically from `federation_identity_occurrences` / `federation_families` / `federation_communities`. The PyO3 boundary accepts only an `occurrence_key_id` string; no admission fields cross it. The §4.3 read predicate is pure target-membership: a row is admitted iff its `cohort_target_id` ∈ the reader's substrate-resolved sets — so a forged set cannot be constructed to begin with, and even the "shared cohort with emitter" leak class is eliminated (target-membership, not emitter-join). | Boundary auth (proving the caller controls the occurrence key's private key) is the caller-environment's responsibility (Ed25519 challenge / authenticated channel); persist trusts the boundary on key ownership and enforces visibility from what the chain admitted. Defense in depth: CIRISEdge#48-A re-checks cohort_scope at egress; joint `cohort_scope_double_miss_total` is the alert. | **✓ Mitigated** (closed by construction — private constructor + substrate-only builder) | CIRISPersist#160 |
| AV-58 | Write-side cohort_scope downgrade (a writer stamps a broader `cohort_scope` / a `cohort_target_id` for a cohort it isn't a member of — e.g. tags `community: C` it isn't in, or `federation` on self content — to broaden visibility) | `DimensionAdmissionPolicy::check_write_cohort_scope` (§4.6) runs AFTER the verify gate, BEFORE persist (zero-writes-on-refusal, mirroring `signature_mismatch_rejected_no_writes`): a writer claiming `(family\|community, target)` must have that target ∈ its substrate-resolved admission, else `ScopeRefusalReason::No{Family,Community}Membership`. `self` targets are substrate-stamped from the verified signer (never caller-supplied); broad tiers carry no target. Wired into trace ingest + `put_attestation`. | Symmetric to AV-57 (same `CallerAdmission`, opposite direction). Edge pre-ingest verification is Layer 2; joint `cohort_scope_write_double_miss_total` is the alert. Attestations carry `cohort_scope` but no `cohort_target_id` column, so family/community attestation writes are refused (no provable target) — a named follow-up column would relax this. | **✓ Mitigated** (verify→gate→persist; set-membership) | CIRISPersist#160 |
| AV-59 | HNDL forge-later on the durable trace corpus (backdated trace minted by a CRQC adversary who broke Ed25519) — the trace-store side of the CC 5.3.2.4.3 `tier=federation ⟹ hybrid present` invariant (the per-trace attestation corpus is AV-67) | `verify_trace_hybrid` hard cut: `VerifyMode::Full` verifies BOTH halves via `verify_hybrid`(`Strict`); classical-only rejected at admission (`verify_hybrid_required`), no `require_hybrid: false` posture (store-path PQC, §10.1.5.1.1 / CC 5.3.2.4.3.1). | Verify-before-mutation step 2, before scrub/insert; dedup not moved ahead of verify; same cut on fountain manifests + aggregation meta. | **✓ Mitigated** (`2.7.legacy` import exempt as provenance-only) | CIRISPersist#225 |
| AV-60 | WholenessWitness equivocation (two signed roots, one peer) | `reconcile_peer_witnesses`/`classify_stored` run `compare_witnesses`; Equivocation RETAINS both + emits `hard_case:witness_equivocation` (idempotent), NEVER reconciled (§19 N4, non-repudiable). | Only verified witnesses enter the corpus (AV-62 PQC gate); re-scan idempotent. | **✓ Mitigated** (detect + preserve; consumer adjudicates) | CIRISPersist#228 |
| AV-61 | Witness divergence escalated to drive the quorum-merge (witness supplies a winning root / resurrects a revoked key) | Divergent → `WitnessReconcileAction::TriggerQuorumMerge` carrying NO winner / NO root; triggers the EXISTING V058 quorum-merge over stored rows (`resolve_monotonic_quorum` / `revision`); the witness root NEVER enters resolution — no fragment-pick, no revoked-key resurrection. | Directive type structurally cannot carry a root; tested (Divergent keeps the REVOKED record). | **✓ Mitigated** (witness = detector, not resolver) | CIRISPersist#228/#229 |
| AV-62 | Witness anti-rollback / eclipse (stale signed witness replay) | `accept_if_monotonic` + `last_witness_epoch_for_peer` strict-epoch monotonic guard (epoch MUST strictly advance, §19 N4); `put_wholeness_witness` runs `verify_witness` PQC-before-persist (`witness_admit_hybrid_required`), zero rows on reject (no store-then-quarantine). | Corpus pruned to last-K (8) verified per peer; no `verified` column (§19.0 F-5 — verdict recomputed at the gate). | **✓ Mitigated** | CIRISPersist#228/#229 |
| AV-63 | WW-2 deniable-content re-attribution (self/anonymous rows swept into a signed federating root) | `build_local_witness` FILTERS OUT anonymous-tier + `cohort_scope: self` + self/anonymous-namespaced leaves BEFORE the Merkle root; `claim_namespaces` drawn only from survivors (provably never names self/anonymous); `verify_witness` re-checks the namespace guard at admission. | Enforced on both sides (build clean + verify rejects); upstream tagging is the AV-57/58 surface. | **✓ Mitigated** | CIRISPersist#228/#229 |
| AV-64 | Forged `aggregation_meta` on the store path (tampered/unsigned §19.7 composite meta) | `put_aggregated_tier` runs `verify_aggregation_meta` (§19.7.1 bound-hybrid) BEFORE persist; missing/invalid ML-DSA-65 → `aggregation_meta_hybrid_required` (store-path PQC §10.1.5.1.1), tampered → `aggregation_meta_invalid`; zero rows; composite manifest also rides the #225 admit gate in one tx. | Storage column is opaque BYTEA/BLOB (V086 — wire-churn firewall); verify inputs admission-only, never persisted. | **✓ Mitigated** (`EjectAggregatedTierOnly` drives the tier-granular stratum shed) | CIRISPersist#230 |
| AV-65 | Forged aggregation source set (descent as a force-evict channel) | `descend_aggregated_sources` runs `verify_member_commitment` over the caller's source ids BEFORE descending — a set that doesn't re-derive the committed `member_commitment` is REJECTED; canonical `descend_order` (§19.7.2 lexicographic). Full source-id-list recomputation, never a partial inclusion proof (the §19.1 CVE-2012-2459 non-exploitability rationale). | `member_commitment` is hybrid-signed in the composite manifest (AV-64) — the root to re-derive is itself authenticated. | **✓ Mitigated** | CIRISPersist#230 |
| AV-66 | Rarity-driven retention resurrecting revoked content (N5) | `evict_fountain_content_hard_delete` is a SEPARATE path that NEVER consults `retention_priority` — drops all symbols, manifest stays `EnvelopeOnly`; `resolve_retention_action` drives `retention_decision`/`ejection_verdict` (Withdrawn → `EjectHardDelete` regardless of `is_rare`). Revocation overrides rarity by construction, not by comparison. | N6 `holding_claim_counts` gates rarity on possession-proven claims (unverified claim can't lower another peer's priority). | **✓ Mitigated** | CIRISPersist#228 |
| AV-67 | Federation-tier forge-later via unverified per-trace ingest (CC 5.3.2.4.3.1 — the CC 5.3.2.4.3 `tier=federation ⟹ hybrid present` invariant enforced at the bulk testimony corpus; same forge-later class as AV-59 at the trace-store path, at the per-trace `put_attestation` grain) | `verify_federation_tier_ingest` (`ceg_produce_canonicalize` JCS → `SHA-256 == original_content_hash` → `lookup_public_key` REGISTERED pubkeys → `verify_hybrid`(`Strict`), BOTH halves REQUIRED) wired into `put_attestation` on both backends BEFORE `persist_row_hash`+INSERT (verify-before-mutation, AV-9); rejected ⇒ zero rows, typed `FederationTierUnverified`. Composed with — not replacing — `check_federation`. | **Local-tier EXEMPT** (CC 5.3.2.2 deferred sig; matrix arm (e) proves no over-reject). Persist's own `withdraws` emitters (evict/sweeper/takedown) hybrid-sign via `LocalSigner`; a non-PQC engine fails honest, no silent skip. | **✓ Mitigated** (classical-only fed rows non-conformant; non-PQC producers local-tier-only) | CIRISPersist#237 |
| AV-68 | Node-only key receiving agency via `delegates_to` (CC 4.4.3.4.3 "Partnership WITHOUT agency" / CC 1.13.5 "infrastructure must not have agency") | `check_node_agency_admission` wired into `put_attestation` (both backends, verify-before-mutation): a `delegates_to` to a `node`-ONLY recipient (resolved via `lookup_public_key`, CC 3.4.7.1) MUST be `scopes_are_infra_only` (non-empty, every token `infra:`), else REJECTED `NodeAgencyForbidden` + not stored. Published `identity_type::NODE` + `delegation_scope` (`infra:*`/`agency:*` + `LEGACY_AGENCY_KINDS`). | No over-reject: `agent`/brain key MAY carry `agency:*`; `{node,agent}` hybrid not constrained; unresolved recipient FK-rejected by `put_attestation` anyway. CIRISServer `ownership.rs` is a thin wrapper. | **✓ Mitigated** (see AV-71 for the dup-token bypass) | CIRISPersist#235/#236 |
| AV-69 | Unstewarded node/agent admitted to a non-infra community (CC 3.2 steward-binding gate / CC 3.4.7.1; authority must root in a human, CC 1.13.2) | `check_community_membership_steward_binding` wired into `put_community` (both backends) after the geographic gate, before write lock/INSERT (verify-before-mutation): a `node`/`agent` roster member lacking a live `is_steward_bound(K)` path to a `user`-role identity REJECTS the write `UnstewardedCommunityMember` + not stored. Precondition, NOT a substitute for the `consensus_protocol` vote. | Infra carve-out (CC 3.2 "Trust ≠ membership"): `cohort_subkind: infrastructure` community admits an unstewarded node. `user` member trivially steward-bound; unresolved/non-node-agent out of scope (no over-reject). | **✓ Mitigated** (see AV-72/F2 self-label, AV-72/F3 revoked-delegation bypasses) | CIRISPersist#235 |
| AV-70 | Community-DEK not rotated on member removal — removed member decrypts NEW community content (CC 4.4.3.2.2 forward secrecy; community-DEK is content's SOLE confidentiality boundary, CC 4.4.3.2.1) | `put_community_membership_revocation` bumps the community DEK epoch (`community_dek_bump_epoch`, both backends) as part of the revocation write; next emission mints a FRESH DEK wrapped only to remaining members (active roster = `lookup_community` ∖ effective revocations); removed member can't unwrap. **Exposure window = zero.** All wraps `wrap_algorithm: v2` (FIPS-203 hybrid) — NEVER v1 (CC 4.4.3.4.1 / CC 5.2 HNDL); keyless member fail-secure EXCLUDED + `hard_case:recipient_excluded` (V087 CHECK makes v1 unrepresentable). | Forward-only (old-epoch blobs keep grants); flat per-member re-wrap, deliberately NOT MLS TreeKEM (CC 5.1, RET-layer OQ). Infra communities opt OUT (Commons plaintext, no DEK — trust root publicly auditable). | **✓ Mitigated** (see AV-72/F4 future-dated `effective_at`, AV-72/F5 atomicity) | CIRISPersist (CC 4.4.3.2.2) |
| AV-71 | Node-agency gate (AV-68) bypass via duplicate `identity_type` token `"node,node"` (CC 1.13.5 / CC 4.4.3.4.3) | the gate tests the identity_type **set** via `HashSet<&str>` (`len()==1 && contains(NODE)`), robust to duplicate/whitespace/order — `"node,node"` does not evade node-only detection. | `node,agent` hybrid still ADMITTED (no over-reject); regression-tested on both backends (`"node,node"`/`"node, node"` + `agency:*` → REJECTED + not stored). | **✓ Mitigated** | CIRISPersist#237 (F1) |
| AV-72 | Authority/forward-secrecy bypasses in the community gates (CC 3.2 / CC 4.4.3.2.1 / CC 3.4.7.1 / CC 4.4.3.2.2) | **F2** self-labeled `cohort_subkind: infrastructure` would skip steward-binding + force plaintext → `is_authorized_infrastructure_community` honors the carve-out ONLY if `community_key_id` is `substrate_persist`-roled (fail-secure to the stricter path). **F3** `is_steward_bound` honoring revoked/expired delegations → edge skipped on `withdraws`/`recants` against `k` (§11.10) or `expires_at <= now`. **F4** future-dated `effective_at` would keep wrapping a "removed" member → community revocation is immediate (future-dated beyond 60s skew REJECTED before write). **F5** non-atomic revoke+hard_case+bump → ONE transaction per backend. | Each fix has a fails-without/passes-with test on both backends; no new substrate authority (`substrate_persist` is the existing reserved governance role, §3.7). | **✓ Mitigated** | CIRISPersist#237 (F2–F5) |
| AV-73 | Third-party reputation forgery: a `scores` dimension with no governing duty admits any registered key, so ≥3 Sybils could fabricate a `WellEstablished`/`Refuted` verdict about an uninvolved subject (`compose_verdict` counts distinct attesting KEYS, `witness_diversity: None`) — and it fans out via the tier-only/unscoped `list_attestations_since` + edge's third-party `Global`/`Cohort` advertisement | emitter standing bounds third-party assertion; where a family declares a named authority (reserved-prefix rule, duty-holders, witness-target walk) that authority is the gate | `witness_diversity` at the composition layer is the second line — distinctness of keys is not distinctness of principals, which no put-gate can establish | ⚠ **Partial** — see §3.16 AV-73 | CIRISPersist#543 (1) |
| AV-74 | Capacity self-inflation: a CC 3.4.5 self-emission arm keyed on `attestation_type` misses the real shape (reputation rides `scores` + `dimension = capacity:*`) — and a manifest citation naming a guard with ZERO callers reads as enforcement (evidence-registry unsoundness) | `check_capacity_not_self_attested` wired at the `check_reserved_prefix_admission` chokepoint (both backends, pure/no-lookup); BOTH wire shapes refused, genuine third-party capacity scores still admitted | `every_cited_processor_has_a_non_test_caller` makes the evidence registry mechanically sound (non-test caller required) | **✓ Mitigated** (B1, `{gate}×{backend}`, both directions) | CIRISPersist#543 (2) |
| AV-75 | Self-asserted privileged `identity_type`/roles: gating claims one incident at a time leaves `substrate_persist`/`witness`/`trusted_publisher`/`lenscore_detector` — every one of which reserves a dimension family — self-assertable at registration | CLOSED SET `AUTHORITY_CONFERRING_IDENTITY_TYPES` + `conferral_mode` per claim, each enforced on the plane that confers it | `authority_conferring_set_covers_every_reserved_prefix_rule` proves the set is a superset of every reserved-prefix requirement — a new rule without a gate FAILS THE BUILD | **✓ Mitigated** — CLOSED SET `AUTHORITY_CONFERRING_IDENTITY_TYPES` + a `conferral_mode` per claim, each enforced on the plane that actually confers it: **ceremony** (accord 2-of-3 co-scrub) for root IDENTITY (`canonical`), **delegation** (`delegates_to` from a trust root, resolved at use by `capability_roots_to_trusted_root`) for operational CAPABILITY (`trusted_publisher`, `lenscore_detector`, `witness`), and **derived-at-use** for the graph-conferred set (`steward`/`partner`/`wise_authority`/`substrate_persist`). `authority_conferring_set_covers_every_reserved_prefix_rule` proves the set is a superset of every reserved-prefix requirement — a new rule without a gate FAILS THE BUILD. | CIRISPersist#543 (3) · CIRISConstitution#40 |
| AV-76 | Bootstrap amplification: if ML-DSA-65 hybrid verify runs LAST after ~8 DB-walking gates, a row failing at the final step still pays for all preceding work; without a per-peer write quota nothing bounds volume | cheapest-first tiering (tier 0 prologue → 1 pure envelope → 2 single directory read → 3 crypto → 4 DB-walk authority → 4b §6.1 dedup → 5 hash+INSERT) on both backends, plus a per-peer write quota ahead of the stack | RULE: a dedup short-circuit may return early to REFUSE, never to ACCEPT — the §6.1 dedup sits at tier 4b, after crypto and the AV-45 write-scope gate. See §3.16 AV-76 | ✅ **Shipped** — reorder, quota, and tier-4b dedup placement | CIRISPersist#543 (4) |
| AV-77 | No in-band response to an abuser: between "ignore it" and the whole-node accord kill-switch there is little; `consent:*` withdrawal is send-side so it cannot stop inbound injection | persist owns the registry-of-record (#519), so the families mint here: de-admit/evict (stops injection; node-authored de-admission gate reachable via `Engine::set_self_key_id`) → row-slashing (undoes AV-73 poison) → quarantine/probation + quota (graduated middle) | `moderation:*` records an event not a sanction; `slashing:*` has verdict shape but no emit and no act; `capacity:*` is advisory (no path denies serve) | ⚠ **Partial** — see §3.16 AV-77 | CIRISPersist#543 (5) |
| AV-78 | If `put_attestation`'s INSERT omits the `tier`/`promoted_at` columns, the schema `DEFAULT 'federation'` silently overrides every `Tier::Local` row — a *trust* label nobody wrote, consumed by the promotion plane (#509/#519), tier-keyed reads, and the signed since-cursor planes | both backends bind `tier` and `promoted_at` | `substrate_machine` differential oracle — **a differential oracle is exactly as wide as its backend set**, and a defect every arm shares is invisible to it | ✅ **Shipped** | CIRISPersist#543 / substrate_machine |
| AV-79 | Nonconsensual third-party reputation: an attester≠attested `capacity:*` emitter rule lets ANY registered key publish a capacity score about ANY third party — and bootstrap admission is deliberately cheap, so "any registered key" means "anyone" | `check_capacity_consent_admission` at AV-76 tier 4 on both backends — a federation-tier `capacity:*` claim about S from P is refused without S's live `consent:scope:analyze` covering P (#510 grammar, resolved via `resolve_scoped_consent`; absent record = `Unspecified` = refused, fail-secure) (CIRISConstitution#46) | With no consent edges, third-party capacity scoring is refused everywhere — a bootstrap bypass would be a permanent hole with a temporary name. Local-tier rows exempt (un-replicated working state; `capacity:*` is local-ineligible anyway). The gate bites the node's OWN emit surface (`emit_attestation` → `put_attestation`) | ✅ **Shipped** — B5 `{gate} × {backend}` matrix | CIRISConstitution#46 |
| AV-80 | Deletion-window breach unobserved: a breach judgment that nothing drives (no sweep, no signal) makes "the network itself raises a breach signal" (ciris.ai/contextual-integrity) false; a producer could outlive its own deletion deadline invisibly | `run_deletion_window_watch` sweep feeding the single-sourced classifier, emitting `hard_case:deletion_window_breach` local-tier evidence; replay-idempotent (keyed on the DEADLINE, not the tick); Engine + PyO3 reachable, with the Engine-handle test | EVIDENCE, not a verdict: persist observes; `slashing:*` stays with the WA quorum (a substrate flag can never be sole slashing evidence). Malformed windows are FLAGGED, not skipped | ✅ **Shipped** — ratification asks in CIRISConstitution#47 R1–R4 | CIRISConstitution#47 |
| AV-81 | `delivery_mode` silent demotion: a typed, byte-faithfully carried field whose VALUE is never validated; edge recognizes only `"mandatory"` and demotes everything else — including typos — to may-drop BestEffort, so a producer could believe they demanded delivery while the network quietly stopped promising it ("accepted but not projected", delivery flavor) | closed-vocabulary check at AV-76 tier 1 on both backends; unknown or non-string values refused at the wire naming the field, the value, and the legal set {absent, "mandatory"} | Vocabulary matches edge's implemented semantics exactly (ratification + future-value reservation: CIRISEdge#428). Future values are an additive two-sided contract change, never a silent semantics change | ✅ **Shipped** — B6 `{gate} × {backend}` matrix | CIRISEdge#428 |
| AV-82 | **Not a vulnerability (adjudicated).** Claim (CIRISPersist#569): AV-79's gate matches `capacity:*` only, leaving four verify-owned families (`attestation:registry_consensus`, `attestation:license_validity`, `cert_validity:*`, `rollback_detected:*`) admitting with no consent asked | **CC 3.4.5 dispositions all four families individually**: the first three are artifact-integrity verification ("a forger never consents to verification"); `rollback_detected:{revision_field}` is "an adversarial detector (−1-only polarity), on the abuse-response side of the line by construction". The rule: *consent-before-scoring binds the family that judges agents — `capacity:*` — never the families that verify artifacts.* The gate is `capacity:*`-only | **Gating `rollback_detected:*` would open a hole**: an adversary could opt out of its own rollback detection by declining `analyze` — and abuse-response families are never consent-gated. Verify's `ConsentClass` is a proposal from the measuring side, not a ruling. CC 3.4.5's reciprocity clause makes a declining subject unscoreable outright — `capacity:composite` undefined, every gate needing a capacity verdict fails closed | ✅ **Adjudicated** — witness that these families ADMIT unconsented on both backends, plus `verify_dimension_registry_is_the_only_enumeration` as the standing record (red if verify reclassifies OR if a CC amendment moves a family) | CIRISPersist#569 / CC 3.4.5 |
| AV-83 | **Tier laundering through the crossing.** A door that flips `tier` local→federation without running the put-gates lets a row enter at `tier = "local"` and leave federation-tier past AV-45, AV-77 and the moderation gates. The sharpest instance is a **CC 3.4.5 MUST violation**: a subject that declines analysis "cannot be scored; its `capacity:composite` is undefined and MUST NOT be emitted" — and because `capacity:composite` is `min` over five factors (CC 3.1.8.1), one leaked row certifies five | Two chokepoints, because they close different things. (1) `check_capacity_never_local` — one predicate both the local doors and `put_attestation` ask, wired at AV-76 tier 1 on both backends and both wire shapes; the refusal names the LOCAL-TIER rule, not consent, because the row is inadmissible even WITH a live grant. (2) `check_promotion_admission` — the tier-4 authority stack re-run against the row about to cross, called from `crossing::plan_enter_mesh`, which every backend's `enter_mesh` runs before any mutation. Membership rule: *the crossing re-runs every tier-4 gate whose verdict is a function of state that can have changed since the local write, and that neither mutates the row nor assumes the row is not yet stored* — the consent gate, no-moderator-federate, de-admission, delegated-duty, reserved-prefix, node-agency and user-target-steward gates; NOT the §6.1 dedup (an early ACCEPT), `check_withdraws_admission` (it stamps a hash-covered field) or `check_single_node_owner_admission` (its doc pins "the incoming row is NOT yet stored"). A tier crossing is byte-identical (CC 5.3.2.4.2), so placement never moves at this door | **AV-45 is deliberately NOT in the crossing gate.** An attestation carries a `cohort_scope` with no `cohort_target_id`, so AV-45's predicate refuses `family` / `community` whenever the target is `None`; running it at the crossing would make family/community placements unreachable rather than check them. Placement into a cohort plane goes through `widen_audience` (AV-84). Pinned by `promotion_does_not_prove_cohort_membership_589` | ✅ **Shipped** — B8 `{gate} × {backend}` matrix (capacity refused at the local door on both wire shapes; an ordinary local row still crosses; a DE-ADMITTED author's row refused at the crossing; a refused crossing leaves rows byte-identical; `(federation, self)` refused; a legacy local capacity row refused, then admitted once the subject grants `analyze`), plus the substrate state machine's I2a/I5 | CIRISPersist#589 / CC 3.4.5 |
| AV-84 | **Placing a row into a cohort plane it has no standing in.** A door that places ANY local-tier row — including one authored by and about a peer — at `family`/`community` lets a node in no community publish a stranger's verdict about a third party into the community plane under its own signature | The only way into `family`/`community` is a `supersedes` written by `widen_audience`, which goes through `put_attestation`: AV-45's write-scope gate proves MEMBERSHIP against the cohort the row names (`Audience::Family`/`Community` carry the cohort id; a targeted audience without one is refused as not an audience), and `check_promotion_cohort_standing` — a PURE predicate (no directory read, no `self_key_id`, so it cannot fail open on unset node identity), also at `set_attestation_cohort_scope` — refuses on STANDING: **for `family` / `community`, the row must name no party but its own producer** (`attested_key_id == attesting_key_id` and every `subject_key_ids` entry is the producer). Typed refusal `Error::CohortStandingRefused` / `federation_cohort_standing_refused` carrying `CohortStandingRefusal::{attested_party, named_subject}`, naming the FIELD that carried the foreign party | **A different predicate from AV-45 and must stay one.** AV-45 asks "is the writer in the cohort it named?"; AV-84 asks "is this the producer's own content?" — forcing one implementation onto both is the axis-fusion defect. The read gate on this table uses `attested_key_id` as the membership target, so a family/community attestation is fail-closed at read rather than leaking | ✅ **Shipped** — B9 `{gate} × {backend}` matrix (a third-party row refused at `community` AND `family`, naming its branch; the SAME row still reaches `federation`, so the targeted-cohort arm is not a general third-party ban; a producer's own row still reaches the community plane; refusals byte-identical; the same verdict at the `set_attestation_cohort_scope` door — membership proven first, so the witness exercises standing alone), plus `promotion_cohort_standing_is_not_av45_592` and `promotion_does_not_prove_cohort_membership_589` | CIRISPersist#592 / #589 / #519 / #510 |
| AV-85 | **A write path constructs signed bytes and then mutates the row.** Seven typed columns are bound into the signed envelope (`envelope.row`, CIRISPersist#643), and `check_row_column_binding` refuses any row whose columns diverge from that mirror. A door that changes one of them (e.g. `cohort_scope`) after signing — or re-signs the PRE-change envelope — emits rows every peer's `put_attestation` refuses while returning a local `Ok`. Same shape as #598 (`assemble` sampling `Utc::now()` AFTER signing, for a column the envelope also carried) | `enter_mesh` does not re-sign and does not touch `cohort_scope`: the bytes it stores are the bytes the actor signed, and offering re-stamped bytes as custody is refused by kind (`PromotionMovedThePreimage`, witness W1). A placement-touching write is a RE-SIGN: `set_attestation_cohort_scope` takes an `AttestationReseal` (re-stamped envelope, digest, signature, scrub key and timestamp) built by `RowMirror::restamp_for_scope` from `RowMirror::of` — the same projection the gate compares against, no second spelling — and writes the envelope in the same statement as the placement. `widen_audience` mutates nothing; it writes a NEW `supersedes` through the ordinary emit recipe. The LOCAL door stamps the mirror because persist MINTS those bytes (it assigns `attestation_id` and defaults `attested_key_id`); the caller-signed TRANSIT revocation is excluded, because stamping bytes a caller already signed would be this defect one door over. `check_promotion_admission` includes `check_row_column_binding` | **Residual (BELIEVED open, unwitnessed):** `Family` / `Community` sign their whole record minus `persist_row_hash`, so `members` / `family_name` / `founded_at` / `consensus_protocol` / `policy_blob` are inside the signing preimage, and `add_family_member`, `add_community_member` and `supersede_group_row` mutate them while leaving `authority_key_id` / `scrub_signature_*` untouched; `supersede_family` receives a valid new `SignedFamily` and serializes only `.family`. A grown or superseded roster served by `list_signed_families_since` then carries a signature over a roster that no longer exists, and peers' `verify_family_admission` refuses it. Adjacent: `attach_attestation_pqc_signature` mutates three hash-covered-but-unsigned columns without re-indexing, while `attach_key_pqc_signature` re-indexes (the #547/#640 stale-index class); `blobs::emit_withdraws_attestation_helper` stamps the mirror from a hand-written `json!` literal rather than `RowMirror::of` | ✅ **Shipped** — B11 `exercise_promoted_row_crosses_to_a_peer` on both backends, ending at a SECOND directory's `put_attestation`: local write → crossing → **peer admits**; the negative arm feeds the peer a row whose envelope was signed before its scope changed and requires a refusal naming `cohort_scope`. Mutation-tested at the primitive and at the peer | CIRISPersist#649 / #643 / #598 |
| AV-86 | **The fabric signs an actor's claim.** A crossing that re-signs a local-tier row with THIS NODE's key, overwrites `scrub_key_id` and clears co-scrubs makes the node the only signer of a human's or agent's claim at the moment it becomes federation-visible: the actor's non-repudiable signature is destroyed by the operation meant to publish it. It is also unreplicable whenever the attester is not the node — the wire verifier resolves the base signature against `attesting_key_id`, never `scrub_key_id`. The deeper hazard: a fabric able to re-sign at the crossing is a fabric able to publish, in the actor's name, a row the actor never signed | Two operations. `enter_mesh` (CC 5.3.2.4.2) crosses `local → federation` over the SAME bytes with the ACTOR's signature as the base scrub; the node may only APPEND a co-scrub (`additional_scrubs`, stamped `cosigned_at` OUTSIDE the preimage). `widen_audience` (CC 4.4.3.3.1) reaches a wider audience by a `supersedes` the actor signs, leaving the prior untouched. Custody is a closed enum decided in ONE place (`Engine::custody_for`): a node co-scrub over a row with no actor signature is refused (`NoActorSignature`), custody offered by a non-attester is refused (`CustodyIsNotTheActor`), and an unsigned row whose actor is absent WAITS (`MeshCrossingOutcome::AwaitingActor`) rather than being signed by the fabric. Every signature admitted — actor, node, and each inherited co-scrub — is verified at the crossing under `HybridPolicy::Strict`, so the preserve set equals the verified set (#541/#556). `LocalAttestationInput::bind_for_signing` + `verify_caller_signed_local_row` let a software-held actor key sign at write | **What this does NOT close.** `custody_for` proves the signer IS the attester, not that the attester is who the human thinks they are — that is the ceremony's job, one plane up. A node that holds an actor's software key can still sign as that actor; sign-at-write narrows the window, and cohabitation means an agent's node CAN sign as its agent, by design (CC 4.4 two granters). The fabric cannot do it with its OWN key and have the result accepted | ✅ **Shipped** — W1–W14 (`FSD/PROMOTION_PRESERVES_THE_ACTOR_SIGNATURE.md` §6) at the directory primitive on both backends via `exercise_actor_signature_survives_the_crossing`, each arm naming the mutation that must fail it; plus the #649 witness asserting a crossed row AND its widening admit at a PEER | CIRISPersist FSD/PROMOTION_PRESERVES_THE_ACTOR_SIGNATURE.md / CC 5.3.2.4.2 |
| AV-87 | **A resource control keyed on an axis the caller cannot be distinguished on.** The AV-76 per-peer write quota meters by `attesting_key_id` at tier 0, ahead of any signature check — so the key is what the row CLAIMS. Correct as a flood shield, but it cannot tell a hostile stranger, this node's own owner publishing locally, and an authenticated cohort peer handing over a backlog apart: routed through that door, the owner is metered (CIRISPersist#804) and promoted to a tracked peer bucket, lifting `node_state`'s peer-quota band into `green` on a node talking to itself (CIRISPersist#665). **A control whose key is forgeable at the point it runs can only ever be as generous as it dares be to a liar** | Origin is a property of the CALL, not the row, so it is a parameter: `put_attestation_with_origin` with `put_attestation` (wire — AV-76 unchanged), `put_attestation_authored` (node ceiling only; no peer bucket, no stranger's tail) and `put_attestation_synced` (a shared bulk budget for authenticated cohort peers) as named doors over it. The caller vouches only for WHICH identity its transport authenticated; whether that identity is a cohort-mate is resolved from persist's own family/community rosters, memoized for one burst window. An authenticated stranger falls back to ordinary metering | **What this does NOT close.** The wire door still meters a claimed identity, because at tier 0 there is nothing better to key on — rotation buys a stranger the shared tail rather than a fresh bucket (`UNTRACKED_TAIL_BUDGET_MULTIPLE`). The privileged doors are in-process surfaces, never exposable across a wire | ✅ **Shipped** — budget sizes witnessed against a SIMULATED clock (`admission::local_authorship_804`), door routing witnessed on both backends (`exercise_privileged_sync_door_804`), each with the mutation that must fail it | CIRISPersist#804 / #665 / AV-76 |
| AV-88 | **Unbounded `ContentFetch`: the puller reads to EOF and hashes after.** Without a declared length on the wire, a lying or hostile holder can stream unbounded bytes at a puller (memory / disk exhaustion) before the full-SHA check (CC 5.3.2.5) refuses. AV-7, AV-40 and AV-76 bound the WRITE side; this is the PULL side | `size` is a REQUIRED signed member of every `holds_bytes` claim and every media Source struct (CC 3.3.13: *"`size` (bytes) is REQUIRED — on every blob, not only media"*); the puller caps its read at the declared size and refuses on overrun/underrun BEFORE hashing (CC 5.3.2.5: *"size is checked first"*); persist refuses a claim without a size at every door (`media_source::holds_bytes_claim_size` at ingest, `check_media_source` at the ingest doors, the local doors and the crossing chokepoint, kind `federation_media_source_invalid`, the member named) (CIRISPersist#871) | **What this does NOT close.** Persist supplies the number in the signed bytes a peer already verifies; the cap itself is enforced by the puller (Edge's half of #871). A holder that declares the true size and then stalls is a liveness problem (hop/TTL, #672). `size` bounds ONE fetch; a holder that advertises many blobs is bounded by the per-peer quota (AV-76) | ✅ **Shipped** — I115 (twenty malformed structs refused by name, incl. `size` absent / `0` / `"4096"`, on both backends and at the local door), I117 (a `holds_bytes` claim without `size`, or with `0` / `"12"` / `-1`, refused at ingest on both backends; the put and adopt doors' claims carry the exact stored length; a two-node delivery carries it to the peer), I119 (from disk: the gate at every door). The grammar's unit tests are mutation-checked | CIRISPersist#871 / CIRISConstitution#104 / CC 3.3.13 / CC 5.3.2.5 / CC 5.3.2.6 |
| AV-89 | **Size divergence between the author's descriptor and a holder's claim.** The author's Source struct says one length and a holder's `holds_bytes` claim says another — the holder is lying, or holds a truncated copy under the same sha (which the digest catches, but only AFTER the bytes are read). With bare key ids from `list_holders(sha)` a puller has nothing to compare and picks a holder blind | `list_holders_sized(sha) -> Vec<HolderClaim { key_id, size }>` returns each holder's claimed size beside the author's; a puller refuses a holder whose claim disagrees with the descriptor before any bytes move; persist's own adopt door refuses to announce a claim whose `size` is not the byte length it just stored (`put_blob_with_scope` / `adopt_sealed_blob_at` pass the stored length into the ONE `holds_bytes_attestation_row` definition and the signer signs it). `list_holders(sha)` is unchanged (CIRISPersist#871) | **What this does NOT close.** Two holders that AGREE on a wrong size (colluding, or copies of one truncation) are refused only by the digest — size is *"not a substitute for the digest, only the cheaper check that runs first"* (CC 5.3.2.5). Persist compares at its OWN adopt door only; a holder elsewhere that signs a wrong size is refused by the puller | ✅ **Shipped** — I117d (on sqlite and postgres: a claim whose `size` is not the byte length the door stores is refused at the put and adopt doors before anything is written; the signer refuses a zero size; the true length is admitted), I117b (the put and adopt doors' claims carry the exact stored byte length; `list_holders_sized` returns it; the claim crosses to a peer with the size via the #870 hashes → point reads → apply shape), I116 (`evidence_refs` entries stay bare sha256 strings) | CIRISPersist#871 / CC 3.3.13 / CC 5.3.2.5 / AV-88 |

---

## 5. Security Levels by Deployment Tier

| Tier | Backend | FFI | Threat Model |
|---|---|---|---|
| **Server-class lens** (production) | Postgres | PyO3 from FastAPI | Full §3 model applies. TLS at edge required. |
| **Standalone Rust server** | Postgres | axum native | Same as above; PyO3 attack surface (callback round-trip) absent. |
| **Pi-class sovereign** | SQLite (bundled) + redb | native bin or PyO3 | Reduced attack surface — typically not internet-exposed. Reticulum transport has its own threat model. |
| **iOS bundled** | SQLite (bundled) | swift-bridge | Apple's app sandbox + secure enclave key storage. Threat model dominated by upstream agent's CIRISVerify hardware-attestation tier. |
| **MCU no_std** (planned) | none — verify-only | reticulum (when no_std) | Out of HTTP-ingest scope; verify-only relay. |

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
6. **Rust runtime memory safety**: ciris-persist denies
   `unsafe_code`; the one override is the debug panic-hook's
   symbolization (`src/debug/mod.rs`, `libc::dladdr`). Transitive
   deps' `unsafe` is constrained by their own audits; `cargo deny`
   (licenses + advisories, `deny.toml`) runs in CI.
7. **Wire-format spec stability**: agents and lens agree on
   TRACE_WIRE_FORMAT.md §8 canonicalization conventions. Drift
   between the two is the AV-4 attack vector.
8. **Federation directory write authorization**: only
   authorized federation peers can call `Engine.put_public_key` /
   `put_attestation` / `put_revocation`. Persist accepts what's
   signed; lens orchestrates which federation membership requests
   reach the substrate. Compromised federation directory writes
   are AV-28 / AV-29 blast-radius bounded by per-row scrub envelope
   verification.
9. **Federation steward key isolation**: deployments
   running federation-mirroring (lens, registry, partner sites)
   hold an Ed25519 + ML-DSA-65 steward keypair. Same trust
   boundary as the scrub-signing key (AV-25); compromised steward
   key allows federation-wide minting of apparently-valid
   federation rows.
10. **DSAR signature verification consumer-side**: lens
    verifies the DSAR request envelope's signature against the
    agent's `signature_key_id` BEFORE calling
    `Engine.delete_traces_for_agent`. Persist owns the substrate
    delete; lens owns the audit + signature verification.
    Misconfigured lens-side verify is AV-38 blast-radius bounded
    by per-key scope.
11. **verify-via-persist API discipline**: federation
    peers consume hybrid verify via `Engine.verify_hybrid`, not
    via direct `ciris_crypto::HybridVerifier` access. Architectural
    rather than runtime; AV-39 names the residual.
12. **Clock skew bounded for SoftFreshness**: peers
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
   authoritative); peer-replicate audit-chain validation;
   federation N_eff drift detection over time.

2. **Quantum compromise of Ed25519**. Current quantum compute
   cannot break Ed25519, but Shor's algorithm on a sufficiently
   large quantum computer would. Hybrid Ed25519 + ML-DSA-65
   signatures (PoB §6) are mandatory on the store path (AV-59) and
   for federation-tier ingest (AV-67); the residual is wherever a
   peer runs `HybridPolicy::Ed25519Fallback` (AV-31) and the
   `2.7.legacy` provenance-only import path (AV-59).

3. **Float canonicalization drift** (AV-4 residual). Track
   production fixtures for any divergence; the parity test suite
   catches what we know about; unknown unknowns are exposure.

4. **Public-key rotation on `accord_public_keys`** (AV-11). Manual
   UPDATE; an explicit `rotate_public_key(rotation_proof)` API is
   tracked.

5. **Unbounded inbound volume per agent** (AV-20..AV-23):
   `statement_timeout`, per-agent rate limiting, clock-skew
   validation and `consent_timestamp` range checks are tracked;
   deployment-edge rate limiting covers the gap.

6. **Third-party scores in dimension families with no declared
   authority** (AV-73) and **no graduated in-band sanction**
   (AV-77).

7. **Distributed authority re-derivation** (AV-75). A future use
   site that trusts a `DerivedFromVerifiedState` claim instead of
   re-deriving it would reopen self-assertion.

8. **Side-channel timing leakage of directory membership** (AV-16).
   Low-impact (key ids are public), but trackable.

9. **Postgres compromise**. Out of CIRISPersist's protection
   scope; deployment infrastructure concern.

10. **All federation peers compromised simultaneously** (PoB §5.1
    residual). Per Accord NEW-04, no detector is complete. PoB's
    response is topological cost-asymmetry over time, not pointwise
    decidability — a property that cannot be achieved at the
    persistence layer alone.

11. **Compromised federation steward key** (AV-28/29
    via authorized-but-malicious writes). Same trust boundary as
    AV-25; deployment-level mitigation is hardware-backed steward
    keyring + revocation through the federation directory's
    `federation_revocations` channel.

12. **Hybrid-pending acceptance window**. Peers running
    `HybridPolicy::SoftFreshness` accept rows that haven't yet
    completed cold-path PQC fill-in. Window size is a per-peer
    operational decision; mismatched (window vs. sweep cadence)
    yields either spurious rejections (window too short) or
    extended hybrid-pending acceptance (window too long).
    `Engine.run_pqc_sweep` summary logs surface sweep cadence;
    operators tune window accordingly.

13. **deployment_profile self-classification mismatch
    with behavior**. Agents declare cohort labels in the signed
    canonical bytes; an agent willing to *actually* run high-stakes
    behavior under a low-stakes label faces the cost-asymmetry
    PoB §2.1 names. Detection is statistical (lens cohort cross-
    validation against `cost_usd` / `tokens` / `model`); persist's
    substrate provides cryptographic provenance, not behavioral
    inference.

14. **verify-via-persist consumer discipline**. A
    determined consumer can fork the verify path and use
    `ciris_crypto::HybridVerifier` directly, skipping persist's
    policy machinery. Architectural cost (drift, per-consumer
    policy maintenance) is the disincentive; not a runtime gate.

15. **Legacy `attempt_index` dedup-collapse** (AV-42).
    Pre-2.7.8.9 emitters never populate `data.attempt_index`; persist
    falls back to 0 at the `2.7.0` and `"2.7.legacy"` arms so legacy
    traffic ingests rather than rejects. Within one legacy agent,
    retries on the same `(trace_id, thought_id, event_type)` collapse
    on the dedup tuple — only the first row lands. Bounded by
    signing-key control (cross-agent collision closed by
    `agent_id_hash` in dedup tuple); time-bounded by the sunset rule
    (`federation_canonical_match_total{wire="2.7.legacy"}` 7-day-zero
    soak). The legacy 2-field canonical signs `components[].data`, so
    synthesizing `attempt_index` post-hoc invalidates verify; the
    federation's append-only contract takes priority over per-row
    dedup fidelity at the legacy arm.

16. **Stored deprecated-form attestations** (AV-45). Admission
    refuses `attestation:l{N}:*`; rows admitted while the form was
    accepted remain, and consumers reading history must tolerate
    them.

17. **Unprovable family/community placement of a producer's own
    content** (AV-83, AV-84). An attestation carries no
    `cohort_target_id`, so persist cannot prove a family/community
    placement made without one; the read gate is fail-closed.

---

## 9. Threat posture summary

```
MITIGATED — ingest, parsing, and DoS
  ✓ AV-1  identity gating via public-key directory
  ✓ AV-3  replay absorbed by dedup-key conflict
  ✓ AV-4  canonicalization parity + WireDateTime (float drift tracked)
  ✓ AV-5  schema-version flood (Cow<'static, str>, no leak)
  ✓ AV-6  data-blob recursion (MAX_DATA_DEPTH=32 walker)
  ✓ AV-7  body size (DefaultBodyLimit::max(8 MiB))
  ✓ AV-8  429 backpressure
  ✓ AV-9  dedup key includes agent_id_hash
  ✓ AV-12 strict schema-version allowlist
  ✓ AV-13 parameterized binding only
  ✓ AV-14 scrubber-output schema gates
  ✓ AV-15 kind() tokens at the HTTP / PyO3 boundary
  ✓ AV-17 attempt_index bound (MAX_ATTEMPT_INDEX=1024)
  ✓ AV-18 optional TLS to Postgres
  ✓ AV-19 drain protocol on shutdown
  ✓ AV-44 three-layer panic isolation (try_get → unwind → catch_unwind)

MITIGATED — provenance, keys, and the federation directory
  ✓ AV-24 always-on scrub envelope
  ✓ AV-25 hardware-backed ciris-keyring (software fallback is residual)
  ✓ AV-26 migration advisory lock
  ✓ AV-27 keyring storage classifier at boot
  ✓ AV-28 federation_keys idempotent + hash check
  ✓ AV-29 persist exposes edges; consumers compose policy
  ✓ AV-30 DEFERRABLE self-FK
  ✓ AV-31..AV-33 hybrid policy per call, cold-path sweep, bound signatures
  ✓ AV-38 per-key DSAR scope
  ✓ AV-39 verify-via-persist
  ✓ AV-40, AV-41 outbound queue bounds; ACKs verified before matching

MITIGATED — wire format and legacy
  ✓ AV-34..AV-37 deterministic dispatch, strict 2.7.9 parse, signed cohort labels
  ✓ AV-42 legacy dedup-collapse (documented residual, sunset-bound)
  ✓ AV-43 aggregates expose counts for consumer k-anonymity (documented)

MITIGATED — substrates and composition gates
  ✓ AV-45..AV-58 composition gates, graph / audit-chain / TSDB /
                 incident substrates, cohort_scope read/write gates
                 (AV-52 cardinality cap is observability-only)

MITIGATED — holonomic substrate (CEG §19 / §19.7)
  ✓ AV-59 store-path PQC hard cut
  ✓ AV-60..AV-63 witness equivocation, divergence, anti-rollback, WW-2 filter
  ✓ AV-64, AV-65 aggregation meta and member-commitment integrity
  ✓ AV-66 revocation overrides rarity by construction

MITIGATED — CIRIS Constitution alignment
  ✓ AV-67 PQC-mandatory federation-tier ingest
  ✓ AV-68, AV-71 no agency for node-only keys
  ✓ AV-69 steward-binding community membership
  ✓ AV-70, AV-72 community-DEK rotation and gate bypass fixes

MITIGATED — bootstrap / Sybil and the crossing
  ✓ AV-74 capacity self-inflation
  ✓ AV-75 closed authority-claim set with per-claim conferral mode
  ✓ AV-76 cheapest-first tiering + per-peer quota
  ✓ AV-78 tier column bound on insert
  ✓ AV-79 consent before third-party capacity scoring
  ✓ AV-80 deletion-window breach watch
  ✓ AV-81 closed delivery_mode vocabulary
  ✓ AV-82 adjudicated: artifact-verification families are not consent-gated
  ✓ AV-83..AV-86 crossing gates, cohort standing, no re-sign, actor signature preserved
  ✓ AV-87 origin-aware write doors
  ✓ AV-88, AV-89 size on every blob claim

PARTIAL
  ⚠ AV-73 third-party scores where no authority is declared
  ⚠ AV-77 graduated in-band sanctions (de-admission exists)

CLOSED BY PEER-REPLICATE (not at ingest)
  ⚠ AV-2  stolen-key forgery
  ⚠ AV-10 audit anchor captured without verification

TRACKED
  ⚠ AV-11 explicit rotate_public_key(rotation_proof) API
  ⚠ AV-16 timing-based key-directory enumeration
  ⚠ AV-20..AV-23 statement_timeout, per-agent rate limiting,
                 clock-skew validation, consent_timestamp range
```

Three architectural patterns recur across the surface:

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

---

## 10. Update cadence

This document is revised:
- With every release that adds or changes an attack surface: new
  `AV-N` entries, matrix rows, and §9 posture lines.
- On every published security advisory affecting deps: addendum
  in §3 and a `cargo deny` re-run.
- On every wire-format schema-version bump: AV-4 / AV-12 / AV-35
  review.
- When a tracked or partial vector closes: its body, matrix row,
  and §9 line change together.

AV ids are never reused or renumbered; code and tests cite them.
