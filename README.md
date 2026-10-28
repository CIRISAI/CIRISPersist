# CIRISPersist

CIRISPersist is the storage layer of the CIRIS federation. It is a Rust crate,
also shipped as a Python wheel, that decides **which claims about identity,
authority and consent may become stored state**, and stores them so that anyone
holding the same rows can re-derive the decision later.

The admission gates are the API. `put_attestation` either stores a row or
refuses it, and a refusal is a typed error that names what was missing. Persist
runs on **PostgreSQL** or **SQLite** (a file, or in memory) and behaves the
same on both, as an enforced invariant: `store::parity` fails the build when one
backend's write door runs a gate, or an order of gates, the other does not
and no declared divergence explains why.

The crate version, dependency pins and release history are in `Cargo.toml` and
[CHANGELOG.md](CHANGELOG.md). This file names no version numbers, so it never
goes stale against them.

## How it works

Everything above a storage layer produces **claims**: an agent's reasoning
trace, a witness's assurance, a peer's replicated row, an operator's action.
Most systems store claims and settle authority elsewhere, in a service that may
or may not be consulted.

Persist settles authority at the write. A claim reaches storage only through the
gate that governs it, and the gate decides by **re-deriving authority from rows
this node already holds and has verified**. It never relies on a flag, a token
or a boolean the caller passes in. There is no "trusted caller" path: in a
federation, no caller's memory is trusted.

So a question such as *may this key assert an age-assurance rung about someone
else?* or *may this key file a record about another person?* is answered at
write time by walking a signed delegation graph to a root that **this node**
trusts.

## What it provides

Four areas, each usable on its own:

| area | what you get |
|---|---|
| **Federation directory and conferral graph** | Hybrid (Ed25519 + ML-DSA-65) key records, `delegates_to` chains, revocation and withdrawal, quorum tallies, and a resolver that answers "does a root I trust confer scope S on key K?" from local verified state. |
| **Admission gates** | Write doors that refuse on governance grounds. A refusal is typed and names the missing conferral. |
| **Verifiable attestation store** | One signed envelope shape for every object, canonicalised with RFC 8785 (JCS), content-hashed, append-only with tombstones. |
| **Consent and erasure** | Consent is a projection over the signed edge graph, not a flag on a row. Erasure cascades. Each community has its own data-encryption keys, rotated with no exposure window when a member is removed. |

Built on these: the signed reasoning-trace log, a hash-chained audit log
(RFC 6962 Merkle), the memory graph, telemetry, secrets at rest, encrypted and
replicated blob storage, fountain-coded content, and the lens schemas.

Optional parts are Cargo features (`postgres`, `sqlite`, `pyo3`, `cirisgraph`,
`cirisaudit`, `telemetry`, `secrets`, `server`, `tls`, and others).
[docs/FEATURE_MATRIX.md](docs/FEATURE_MATRIX.md) lists them and how CI covers
each combination. The Python wheel ships the feature set listed under
`[tool.maturin]` in `pyproject.toml`.

## When not to use it

- **You want a general-purpose database.** Use PostgreSQL. Persist refuses
  writes on governance grounds, and that cannot be configured away.
- **You want to swap the policy engine.** With OPA or Cedar you can. Here you use
  these gates or you fork.
- **You need CBOR/COSE on the wire.** Not supported. For RATS/EAT or a
  COSE-native profile, look at [Veraison](https://github.com/veraison).
- **You want a store that trusts what an upstream service admitted.** Persist
  does not, by design.
- **You need horizontal sharding.** Persist is a library, not a service.

## Standards it builds on

- **Canonicalisation:** RFC 8785 (JCS).
- **Audit log:** RFC 6962 Merkle trees, from
  [CIRISVerify](https://github.com/CIRISAI/CIRISVerify). Persist implements no
  Merkle, preimage or signature logic of its own.
- **Delegation chains:** the idea behind UCAN, Biscuit, ZCAP-LD and macaroons.
- **Authorisation walk:** the idea behind Zanzibar, SpiceDB and OpenFGA.
- **Erasure coding:** RFC 6330.
- **Post-quantum signatures:** FIPS 204 (ML-DSA-65), paired with Ed25519.
- **Verifiable append-only state:** the ground immudb, Trillian, Rekor and IETF
  SCITT stand on.

No single project is a direct peer. Roughly, persist covers the union of
**immudb** (verifiable append-only state), **SCITT** (a transparency service
whose registration policy decides what may be logged) and **SpiceDB** (schema,
relationship graph, checks and store in one system).

## What is different

1. **The registration policy is a named, versioned, hash-pinned corpus.** The
   governing vocabulary (consent grammar, replication policy, namespace
   manifest) is pinned by hash, and a refusal names the rule that refused. A
   peer can learn *why* a row was refused.
2. **Each conferral declares where it is enforced, and the build checks it.** An
   authority-conferring claim declares whether it is enforced at registration
   or resolved at use. The build fails if a claim declared "resolved at use" is
   consumed by a plain membership test.
3. **Consent is a projection over the edge graph**, not a column.
4. **Commons operations use a reverse quorum:** one of N may protect, m of n are
   needed to undo, and the protective side is capped, never floored.
5. **Backend parity is enforced.** SQLite and PostgreSQL run the same test
   bodies through the real write path.

## The trade-offs

Putting vocabulary, logic, enforcement and storage in one process buys
coherence and costs flexibility:

- **You cannot swap the policy engine.**
- **The vocabulary version is the crate version.** A governance change is a code
  release, which is why the major version number is high. The CHANGELOG records
  what each major changed.
- **Downstream cannot run a different rule set**, so every tightening is a
  coordinated adoption across consumers.
- **A gate is only as good as its witnesses.** Every gate has tests, and the
  load-bearing ones are mutation-tested, but a gate can still pass over a case
  nobody thought to test.

## Validation and review

**Independent conformance.**
[CIRISConformance](https://github.com/CIRISAI) is a separate suite that drives
the real built wheel, never a mock. Its findings have become fixes here, for
example an admission bypass where a raw emit carrying only the constitutional
marker skipped the single-owner gate. That is the kind of hole an in-repo suite
misses: a gate that passes its author's fixtures.

**In this repository.** Several thousand tests across the feature matrix, each
run on both backends; property tests; mutation testing of the load-bearing gates
([docs/MUTATION_TESTING.md](docs/MUTATION_TESTING.md)); source gates that read
the code itself ([docs/FROM_DISK_GATES.md](docs/FROM_DISK_GATES.md)); and a
benchmark [trend dashboard](https://cirisai.github.io/CIRISPersist/dev/bench/)
updated on every commit to main. Benchmark figures are kept on the dashboard,
not in this file.

**External review: none of this crate yet.** Two external reviews of the CIRIS
stack exist and neither examines CIRISPersist. The public one, at
[towards-alignment.com](https://towards-alignment.com/cards/field-agendas/ciris/),
is an alignment assessment, not a security audit, and covers Accord,
CIRISAgent, Verify, Lens and Proxy. The other is not public and does not cover
this crate either.

Treat every security property described here as a claim backed by our own
tests, one independent conformance suite and a published
[threat model](docs/THREAT_MODEL.md), **not as audited**. An adversarial reader
is worth more to us than a pull request.

## Using it

### Rust

Add the crate from its git tag with the backend features you need. This snippet
is compiled in CI as [`examples/readme.rs`](examples/readme.rs):

```rust
use ciris_persist::signing::{LocalSigner, LocalSignerConfig};
use ciris_persist::Engine;
use std::sync::Arc;

async fn open_node() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Arc::new(LocalSigner::from_config(&LocalSignerConfig {
        key_id: "my-node".to_owned(),
        key_path: "/run/keys/ed25519.seed".into(),
        pqc_key_id: None,
        pqc_key_path: None,
    })?);

    // Migrations run as part of construction; the Engine is ready to use.
    let engine = Engine::with_signer(signer, "sqlite:///./node.db").await?;
    let _ = engine;
    Ok(())
}
```

### Python

The wheel is an abi3 build for Python 3.10 and later. It is built by CI from
each release tag (`maturin build`); it is not published to PyPI.

```python
import ciris_persist as cp

engine = cp.Engine(dsn="sqlite://./agent.db", signing_key_id="agent-ed25519")
engine.register_consumer("my-adapter", ["cirisgraph"])
summary = engine.receive_and_persist(request_body_bytes)
```

The backend is chosen by the DSN scheme (`postgres://…` or `sqlite://…`).
[docs/COHABITATION.md](docs/COHABITATION.md) explains how several components
share one `Engine` in a process.

## Building and testing

```bash
cargo build --features sqlite                 # SQLite only
cargo build --features postgres,sqlite        # both backends
cargo nextest run --features sqlite           # SQLite suite, no database needed
```

The PostgreSQL suite needs a database to itself: some tests assert on global
row counts and one drops a schema. `scripts/pg_test_db.sh` creates a fresh
single-use database, runs the command, drops the database and passes the exit
code through:

```bash
scripts/pg_test_db.sh -- cargo nextest run --features postgres,sqlite
scripts/pg_test_db.sh --check     # show which suite is on which database
```

Within a run, each test process gets its own database cloned from an
already-migrated template (`CREATE DATABASE … TEMPLATE`), so isolation costs
less than replaying migrations.

The test cluster is disposable, so it can run without crash safety, which makes
the suite much faster. `scripts/pg_tune_test_cluster.sh` turns off `fsync`,
`synchronous_commit`, `full_page_writes` and JIT, and can put `PGDATA` on tmpfs.
It refuses to run until a marker file is placed in the container, and prints the
command to place it:

```bash
scripts/pg_tune_test_cluster.sh                  # tune the test cluster
scripts/pg_tune_test_cluster.sh --recreate-tmpfs # PGDATA in RAM (destroys the cluster's data)
scripts/pg_tune_test_cluster.sh --reset          # back to stock settings
```

`scripts/certify.sh full` runs every leg CI runs, locally, and its exit code is
the verdict; `certify.sh quick` is a fast pre-push check.
[docs/TOOLING.md](docs/TOOLING.md) describes the local and CI tools, and
[docs/RELEASE.md](docs/RELEASE.md) the release procedure.

Parallel worktrees each grow a large `target/`. `scripts/reap_worktree_targets.sh`
(dry run by default, `--apply` to act) removes `target/` from linked worktrees
that are merged, clean, unlocked, idle and cold for an hour.

## Documentation

| document | contents |
|---|---|
| [MISSION.md](MISSION.md) | What persist is for, and the rules every change is held to |
| [FSD/CIRIS_PERSIST.md](FSD/CIRIS_PERSIST.md) | Functional specification; the other files in [FSD/](FSD) specify individual surfaces |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat model: the `AV-*` attack vectors and their mitigations |
| [docs/PUBLIC_SCHEMA_CONTRACT.md](docs/PUBLIC_SCHEMA_CONTRACT.md) | The stable schema contract for readers of the database |
| [docs/FEDERATION_DIRECTORY.md](docs/FEDERATION_DIRECTORY.md) | The federation directory: keys, attestations, trust anchors |
| [docs/COHABITATION.md](docs/COHABITATION.md) | Sharing one `Engine` between components in a process |
| [docs/INTEGRATION_LENS.md](docs/INTEGRATION_LENS.md) | Integrating CIRISLens with persist |
| [WIRE_VOCABULARY_KINDS.md](WIRE_VOCABULARY_KINDS.md) | The wire vocabulary's kinds and what each means |
| [docs/V61_TASK_PLAN.md](docs/V61_TASK_PLAN.md) | The plan for the next release |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

For cryptographic primitives, hardware attestation and post-quantum posture,
[CIRISVerify](https://github.com/CIRISAI/CIRISVerify) is the authority. Persist
uses it and pins it, and does not restate its claims.

## Where it sits

CIRIS is the reference deployment, not the definition. In it, Verify owns the
cryptographic primitives, Edge owns transport, the agent does the reasoning, and
adjudication belongs to a quorum of human authorities. Persist holds the state
those decisions are made from and enforces what may enter it. **The substrate
observes; it does not adjudicate.**

## License

AGPL-3.0-or-later. The persistence path is meant to be auditable line by line,
and the license forbids closed-source forks, so that audit stays possible for
every deployment.
