# CIRISPersist

One embeddable Rust crate behind every stateful surface a CIRIS federation
node needs — the signed reasoning-trace log, the hash-chained audit log, the
memory graph, time-series telemetry, secrets-at-rest, and federation trust
state. Postgres **or** SQLite; in-process via PyO3 **or** over HTTP.

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
| `sequence` / `occurrence` | atomic per-identity counters + endpoint-liveness registry |
| lens substrates | tasks, thoughts, correlations, tickets, deferral reports, WA certs, … |

## Honest read

- **Postgres + SQLite at 100% parity.** Every PyO3 method works on both
  backends — including the observability read API and the lens-derived
  schemas — so sovereign-mode (Pi / iOS) deployments are not second-class.
- **In-process cohabitation.** `Engine` is a process-singleton: a CIRIS 3.0
  process hosting the agent + NodeCore + LensCore shares one runtime, one
  pool, one identity — see [docs/COHABITATION.md](docs/COHABITATION.md).
- **Hardware-backed secrets.** The secrets master key is derived — via
  CIRISVerify — from a seed sealed by the platform TPM / Keystore / Secure
  Enclave where one exists, with an honest software fallback where it does
  not.
- **Crypto goes through CIRISVerify.** Persist never rolls its own — signing,
  verification, and key derivation route through `ciris-verify-core` /
  `ciris-keyring`.
- **Deliberately not:** no embedded graph DB engine (Postgres / SQLite
  recursive CTEs instead); not a daemon (a library, not a service);
  horizontal sharding is out of scope. No direct peer to benchmark against —
  the thing it replaces is per-service ORMs and hand-rolled SQL.

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
