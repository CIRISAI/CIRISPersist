# CIRISPersist Threat Model

**Status:** v0.1.1 baseline. Updated each minor release.
**Audience:** lens team integrators, federation peers, security reviewers.
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

Sixteen attack vectors organized by adversary goal. Each lists the
attack, the primary mitigation present in v0.1.1, the secondary
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
  We re-format `DateTime<Utc>` for canonicalization rather than
  round-tripping the original wire string. If an agent emits a
  timestamp shape we don't reproduce byte-exact, verify fails.
  Track in a Phase 1.x patch — preserve the on-the-wire string
  for canonicalization.

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

---

## 4. Mitigation Matrix

| AV | Attack | Primary Mitigation (v0.1.1) | Secondary | Status | Fix Tracker |
|---|---|---|---|---|---|
| AV-1 | Forged trace from attacker key | Public-key directory lookup | N_eff drift detection (lens-side) | ✓ Mitigated | — |
| AV-2 | Forged trace from compromised key | (out of scope at persistence layer) | Audit anchor + Phase 2 peer-replicate | ⚠ Phase 2 closes | FSD §4.5 |
| AV-3 | Replay of legitimate batch | Idempotency on dedup key | TLS at edge | ✓ Mitigated | — |
| AV-4 | Canonicalization mismatch | Byte-exact parity tests + pluggable canonicalizer | Ed25519 collision resistance | ⚠ Float / timestamp drift residual | v0.1.x patch |
| AV-5 | Schema-version flood (mem leak) | **None** | **None** | **❌ EXPOSED** | **v0.1.2 hot-fix** |
| AV-6 | JSON-bomb amplification | Bounded queue + typed envelope | Edge body limit | ⚠ `data` recursion uncapped | v0.1.2 hot-fix |
| AV-7 | Body-size flood | (deployment-edge proxy only) | — | ⚠ No crate-level limit | v0.1.2 hot-fix |
| AV-8 | Queue saturation | 429 + Retry-After | Single-consumer transaction discipline | ✓ Mitigated | — |
| AV-9 | Dedup-key collision across agents | trace_id "globally unique per agent" convention | (agent_id_hash not in dedup key) | ⚠ Cross-agent DOS possible | v0.1.x patch |
| AV-10 | Audit anchor injection | (anchor not part of dedup key) | Phase 2 peer-replicate validates chain | ⚠ Phase 2 closes | FSD §4.5 |
| AV-11 | Public-key re-registration | First-write-wins (ON CONFLICT DO NOTHING) | Manual UPDATE for legitimate rotation | ⚠ No rotation API | v0.2.x |
| AV-12 | Schema-version downgrade | Strict allowlist | Per-version payload gates | ✓ Mitigated | track at version bump |
| AV-13 | JSONB injection | Parameterized typed binding | — | ✓ Mitigated (Phase 3 follow-up) | Phase 3 audit |
| AV-14 | Scrubber bypass via schema-altering callback | Schema-preservation gates | Python process boundary | ✓ Mitigated | — |
| AV-15 | PII leak via errors | Typed error variants | (no sanitization wrapper) | ⚠ Some surfaces leak verbatim | v0.1.2 hot-fix |
| AV-16 | Side-channel timing | Ed25519 verify_strict constant-time | (no constant-response wrapper) | ⚠ Directory enumeration possible | v0.2.x research |

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

---

## 9. v0.1.1 Threat Posture Summary

```
KNOWN EXPOSURES (block hot-fix)
  ❌ AV-5: schema-version flood mem leak (parse_lenient Box::leak)
  ⚠ AV-6: data-blob recursion uncapped
  ⚠ AV-7: no crate-level body size limit
  ⚠ AV-9: dedup key doesn't include agent_id_hash
  ⚠ AV-15: error messages can leak verbatim PII

PHASE-2-CLOSES
  ⚠ AV-2: stolen-key forgery (peer-replicate audit chain)
  ⚠ AV-10: audit anchor capture without verification

DESIGN-DECISIONS-PER-MISSION (intentional, not defects)
  ✓ AV-1: identity gating via public-key directory
  ✓ AV-3: idempotency via dedup-key conflict
  ✓ AV-4: canonicalization parity tests + pluggable trait
  ✓ AV-8: 429 backpressure honest
  ✓ AV-12: strict schema-version allowlist
  ✓ AV-13: parameterized binding only
  ✓ AV-14: scrubber-output schema gates

CARGO AUDIT
  ✓ 0 vulnerabilities across 299 dependencies as of 2026-05-01
```

The integration-blocking exposures are AV-5 (memory leak) and
AV-9 (cross-agent dedup collision). Both are scoped for the
v0.1.2 hot-fix release. The lens team can begin integration
against v0.1.1 with deployment-edge rate limiting in place;
v0.1.2 should land before high-volume production traffic.

---

## 10. Update cadence

This document is updated:
- On every minor version (v0.1.x → v0.2.0): comprehensive review.
- On every published security advisory affecting deps: addendum
  in §3 + cargo-audit re-run.
- On every Phase boundary (Phase 1 → 2 → 3): new attack vectors
  added for the new trait surfaces.
- On every wire-format schema-version bump: AV-4 / AV-12 review.

Last updated: 2026-05-01 (v0.1.1 baseline, pre-AV-5/AV-6/AV-7/AV-9
hot-fix).
