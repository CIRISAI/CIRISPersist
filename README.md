# CIRISPersist

One embeddable Rust crate behind every stateful surface a CIRIS federation
node needs — the signed reasoning-trace log, the hash-chained audit log, the
memory graph, time-series telemetry, secrets-at-rest, federation trust state,
and the CEG §19 holonomic / forever-memory substrate (fountain content,
WholenessWitness, aggregation tiers). Postgres **or** SQLite; in-process via
PyO3 **or** over HTTP.

**Current:** v8.5.0 · CIRISVerify pin **v5.10.0** · CEG **§19 / §19.7 (1.0)**.

## What it is

CIRISPersist is the lowest stateful substrate above
[CIRISVerify](https://github.com/CIRISAI/CIRISVerify). An agent or lens node
links it as a library — `pip install ciris-persist` — and gets every storage
surface it needs from one versioned API instead of ~11 hand-rolled services.
The backend is chosen at `Engine` construction by DSN scheme
(`postgres://…` or `sqlite://…`); **every method works on both**.

## Substrates

| Substrate | Backs |
|---|---|
| trace ingest | signed reasoning-trace event log + LLM-call log |
| `cirisaudit` | hash-chained, per-tenant signed audit log (RFC 6962 Merkle) |
| `cirisgraph` | memory nodes + edges — absorbs MemoryService / ConfigService |
| `telemetry` | metric writes + TSDB rollup |
| `secrets` | federated SecretsService — AES-256-GCM at rest, hardware-backed master key |
| `cirisnode` | CIRISNodeCore federation-consensus substrate |
| `fountain` | fountain-coded content primitive — signed manifest + N+K opaque symbols, tier eviction, authenticated partial reads (CEG §19.3) |
| `wholeness_witness` | §19.1 WholenessWitness corpus — divergence detector that routes to the existing quorum-merge (CEG §19) |
| `content_aggregation` | §19.7 forever-memory aggregation tier — N→1 composites, opaque `aggregation_meta`, descent-integrity (CEG §19.7) |
| `sequence` / `occurrence` | atomic per-identity counters + endpoint-liveness registry |
| lens substrates | tasks, thoughts, correlations, tickets, deferral reports, WA certs, … |

## Honest read

- **Postgres + SQLite at 100% parity.** Every PyO3 method works on both
  backends — including the observability read API and the lens-derived
  schemas — so sovereign-mode (Pi / iOS) deployments are not second-class.
- **In-process cohabitation.** `Engine` is a process-singleton: a CIRIS 3.0
  process hosting the agent + NodeCore + LensCore shares one runtime, one
  pool, one identity — see [docs/COHABITATION.md](docs/COHABITATION.md). The
  public `ffi::pyo3::register(py, m)` hook (#231) lets a host wheel re-export
  the whole persist surface into its own module — one `.so`, one PyO3 type
  registry (CIRISServer one-wheel).
- **Hardware-backed secrets.** The secrets master key is derived — via
  CIRISVerify — from a seed sealed by the platform TPM / Keystore / Secure
  Enclave where one exists, with an honest software fallback where it does
  not.
- **Crypto goes through CIRISVerify.** Persist never rolls its own — signing,
  verification, and key derivation route through `ciris-verify-core` /
  `ciris-keyring` (pinned **v6.0.0**, all six crates flipped in lockstep).
  The §19 holonomic gates (`verify_witness`, `compare_witnesses`,
  `verify_aggregation_meta`, `verify_member_commitment`, `ejection_verdict`,
  `compute_merkle_root`) are all verify-core calls — persist never re-rolls
  Merkle / preimage / signature logic.
- **Holonomic / forever-memory substrate (CEG §19 / §19.7, 1.0).** Persist
  is the store + WholenessWitness-corpus owner + the divergence→quorum-merge
  router. A withdrawn `content_id` is hard-deleted regardless of rarity
  (revocation overrides rarity); a witness equivocation is retained and
  flagged `hard_case:witness_equivocation`, never reconciled. Memory fades
  along one pressure-driven descent but cannot be falsified — the signed
  envelope/manifest is the incorruptible anchor and partials stay
  authenticated against the signed per-symbol hashes.
- **Constitution alignment (0.1.5).** v9.0.0 binds persist to the substrate
  clauses of the [CIRIS Constitution
  0.1.5](https://github.com/CIRISAI/CIRISRegistry/tree/main/FSD/CIRIS_Constitution).
  Federation-tier ingest is **PQC-mandatory** — every `tier = federation`
  write is hybrid-verified (Ed25519 + ML-DSA-65, `Strict`) at the admission
  gate, local-tier exempt (CC 5.3.2.4.3.1; BREAKING — classical-only
  federation rows are non-conformant). A `node`-only key's `delegates_to` may
  carry only `infra:*` scopes, never `agency:*` — *"infrastructure must not
  have agency"* enforced cryptographically (**CC 4.4.3.4.3** / **CC 1.13.5**).
  Non-infra community membership for a node/agent key requires owner-binding
  to a human (CC 3.2 / CC 3.4.7.1), and community content is sealed under a
  per-community DEK rotated zero-window on member removal (CC 4.4.3.2.1 /
  4.4.3.2.2, `wrap_algorithm: v2` only). Privacy stays bounded — cohort scope
  hides *content*, not *contact* (CC 1.13.3.1; see
  [MISSION.md](MISSION.md) §1.9). See
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) §3.15 (AV-67..AV-72).
- **1+4 lockdown.** Persist adds **zero** structural primitives (**CC 1.7** —
  the federation's one workhorse attestation primitive + four structural
  composers). Every substrate above rides `scores` + a `subject_kind` + the
  four composers (`delegates_to` / `supersedes` / `withdraws` / `recants`) —
  the constitution-alignment gates are admission logic over the existing
  `federation_keys` / attestation surface, not new wire shapes.
- **Deliberately not:** no embedded graph DB engine (Postgres / SQLite
  recursive CTEs instead); not a daemon (a library, not a service);
  horizontal sharding is out of scope.

## Performance & SOTA

Measured by the in-repo criterion suite (`benches/` — eleven harnesses run per
commit and published to the
[trend dashboard](https://cirisai.github.io/CIRISPersist/dev/bench/)).
Representative
current numbers:

- **AES-256-GCM** (secrets-at-rest) — ~9.5 GiB/s, via CIRISVerify v2.8.0.
- **Analytics** — V042 covering indexes turn the scoring `ReadEngine` queries
  into index-only scans; `cross_agent_divergence` ~−42% vs. a raw table scan.
- **`next_sequence`** — a durable, async-safe atomic counter increment ~10 µs
  (the SQLite UPSERT itself ~2 µs; the rest is the async wrapper).
- **Cold start** — open + full migration run ~12 ms.

| Capability | SOTA peers | CIRISPersist |
|---|---|---|
| Embedded persistence | ORMs — sqlx, Diesel; per-service DBs | one API, Postgres + SQLite at 100% parity — **at parity** |
| Audit log | Trillian, Rekor, AWS QLDB | RFC 6962 Merkle + post-quantum-signed tree heads — **ahead of typical** |
| Crypto-at-rest | ring, OpenSSL (~3–6 GiB/s AES-GCM) | ~9.5 GiB/s AES-256-GCM via CIRISVerify — **ahead** |
| Post-quantum | mostly classical | hybrid Ed25519 + ML-DSA-65 throughout; Full-mode traces + fountain manifests + aggregation meta reject classical-only at ingest (HNDL hard cut, CEG §10.1.5.1.1) — **ahead** |
| Analytics | DuckDB, ClickHouse (columnar) | row store + query-shaped covering indexes ("poor-man's column store") — **at parity for the fixed query set**; ~2–5× behind a columnar engine on raw ad-hoc scan |
| Horizontal scale | sharded DB services | a library, not a service — **behind** (deployment shape, not algorithm) |

Ahead on post-quantum crypto and the Merkle audit log; at parity on embedded
persistence and on analytics for its closed query set; the one real "behind" —
horizontal scale — is a library-vs-service choice, not an algorithm gap.

## Quick start

```python
import ciris_persist as cp

engine = cp.Engine(dsn="sqlite://./agent.db", signing_key_id="agent-ed25519")
engine.register_consumer("my-adapter", ["cirisgraph"])
summary = engine.receive_and_persist(request_body_bytes)
```

## Docs

| Doc | What |
|---|---|
| [MISSION.md](MISSION.md) | Mission-Driven Development alignment (Accord Meta-Goal M-1) |
| [FSD/CIRIS_PERSIST.md](FSD/CIRIS_PERSIST.md) | Full functional spec |
| [docs/COHABITATION.md](docs/COHABITATION.md) | In-process cohabitation model |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat model (AV-* attack vectors) |
| [docs/PUBLIC_SCHEMA_CONTRACT.md](docs/PUBLIC_SCHEMA_CONTRACT.md) | Stable schema contract |
| [CHANGELOG.md](CHANGELOG.md) | Per-release history |

## License

AGPL-3.0-or-later. The persistence path is auditable line-by-line by design:
closed-source forks are forbidden, which makes the federation primitive's
audit story structurally enforceable, not merely socially expected.
