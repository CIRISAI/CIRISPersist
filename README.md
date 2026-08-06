# CIRISPersist

A Rust crate that decides **which claims about identity, authority, and consent
are allowed to become state** — and stores them so the decision can be
re-derived later by anyone holding the same rows.

Not a database with a policy layer bolted on. The admission gates *are* the API:
`put_attestation` refuses, and the refusal is typed and names the thing that was
missing. Postgres, SQLite, or in-memory — the same behaviour on all three, as an
enforced invariant. Embeddable as a Rust library or a Python wheel.

> **Version, pins, and history:** see [CHANGELOG.md](CHANGELOG.md) and
> `Cargo.toml`. This file deliberately hard-codes **no** version numbers — the
> previous README claimed `v8.5.0` for twenty-two majors because nothing checked
> it, and a fact nothing checks is a fact that rots.

## The idea

Everything upstream of a substrate produces **claims**: an agent's reasoning, a
witness's assurance, a peer's replicated row, an operator's admin action. Most
systems store claims and sort out authority somewhere else, later, in a service
that may or may not be consulted.

CIRISPersist inverts that. A claim reaches storage only by passing the gate that
governs it, and the gate answers by **re-deriving authority from rows this node
already holds and verified** — never from a flag, a token, or a boolean the
caller passed in. There is no "trusted caller" path, because in a federation
there is no trusted memory.

Concretely, that means questions like *may this key assert an age-assurance rung
about a third party?* or *may this key file a record about someone else?* are
answered by walking a signed delegation graph to a root **this node** trusts, at
the moment of the write, every time.

## What you can use it for

Four areas, adoptable independently:

| area | what it gives you |
|---|---|
| **federation directory & conferral graph** | hybrid (Ed25519 + ML-DSA-65) key records, `delegates_to` chains, revocation and withdrawal folds, quorum tallies, and a resolver that answers "does a root I trust confer scope S on key K?" from local verified state |
| **admission gates** | write chokepoints that refuse on governance grounds, with typed refusals that name the missing conferral rather than returning a bare boolean |
| **verifiable attestation store** | one signed envelope shape for every object, canonicalised per RFC 8785 (JCS), content-hashed, append-only with tombstone semantics, across three backends at enforced parity |
| **consent & erasure lifecycle** | consent modelled as a projection over the edge graph rather than a flag on a row; cascading erasure; per-community data-encryption keys with zero-window rotation on member removal |

Plus the substrates built on top: signed reasoning-trace log, hash-chained audit
log (RFC 6962 Merkle), memory graph, telemetry, secrets-at-rest,
fountain-coded content, and the lens schemas.

## Who this is not for

Be direct about it — most projects should use something else:

- **You want a general-purpose database.** Use Postgres. This one refuses writes
  on governance grounds and that is not a bug you can configure away.
- **You want to swap the policy engine.** OPA and Cedar users can. Here you get
  these gates or you fork — see *The bill*, below.
- **You need CBOR/COSE on the wire.** Not supported. If you are building to
  RATS/EAT or a COSE-native profile, look at
  [Veraison](https://github.com/veraison) first.
- **You want a store that trusts what an upstream admitted.** The entire value
  here is that it does not.
- **You need horizontal sharding.** This is a library, not a service.

## Standing on other people's standards

Most of this surface is a competent implementation of work done elsewhere, and
saying so is the point:

- **Canonicalisation** is RFC 8785 (JCS), not a bespoke scheme.
- **The audit log** is RFC 6962 Merkle, consumed from
  [CIRISVerify](https://github.com/CIRISAI/CIRISVerify) rather than re-rolled.
  Persist never implements Merkle, preimage, or signature logic itself.
- **Delegation chains** are the idea behind UCAN, Biscuit, ZCAP-LD, and
  macaroons.
- **The authorization walk** is the idea behind Zanzibar / SpiceDB / OpenFGA.
- **Erasure coding** is RFC 6330's.
- **Post-quantum signatures** are FIPS 204 (ML-DSA-65), hybridised with Ed25519.
- **Verifiable append-only state** is the ground immudb, Trillian, Rekor, and
  IETF SCITT already stand on.

There is no single peer project. The closest honest description is that
CIRISPersist occupies roughly the union of **immudb** (verifiable append-only
state), **SCITT** (a transparency service whose *registration policy* decides
what may be logged), and **SpiceDB** (schema, relationship graph, checks, and
store fused into one system).

## What is actually different

Held to a short list on purpose:

1. **Registration policy as a named, versioned, hash-pinned corpus.** SCITT has
   registration policies, but they are per-operator and opaque — a peer cannot
   learn *why* a row was refused. Here the governing vocabulary is pinned by
   hash (consent grammar, replication policy, the namespace manifest) and the
   refusal names the branch.
2. **Conferral modes as a declared contract the build checks.** Each
   authority-conferring claim declares *where* it is enforced — at registration,
   or resolved at use. A gate then fails the build when a claim declaring
   "resolved at use" is consumed by a plain membership test. Writing down where
   a rule is enforced is common; failing the build when nothing enforces it
   there is not.
3. **Consent as a projection over the edge graph**, not a column.
4. **Reverse quorum for commons operations** — one-of-N to protect, m-of-n to
   undo, with the protective side capped and never floored.
5. **Backend parity as an enforced invariant, not an aspiration.** Memory,
   SQLite, and Postgres run the same witness bodies through the real write path.
   Memory tolerates what the SQL backends reject, which is exactly why it gets
   its own leg.

## The bill

Fusing vocabulary, logic, enforcement, and storage into one process buys
coherence and costs flexibility. The costs are real:

- **You cannot swap the policy engine.**
- **Vocabulary version is crate version.** A governance change is a code
  release. That is why the major number is high — the taxonomy ships honestly
  rather than drifting silently — but a reader is entitled to read a high major
  count as churn, so: it is the former, and the CHANGELOG is the evidence.
- **Downstream cannot run a different rule set**, so every tightening is a
  coordinated adoption across consumers.
- **The gates are only as good as their witnesses.** This repo's own history is
  the argument for that caution: multiple gates have shipped green over holes
  they could not see, and were caught by an issue rather than by the build.

## Validation and review status

**Independent conformance.** [CIRISConformance](https://github.com/CIRISAI) is a
separate suite that drives the **real built wheel — never a mock** — and it has
filed findings that became fixes here. Two concrete ones:

- `test_551` found an admission bypass: the single-owner gate keyed on persist's
  *internal* dimension, so a raw emit carrying only the constitutional marker
  (`delegation_purpose: "owner_binding"`, no `dimension`) went **ungated** and a
  second distinct owner was admitted.
- `#11 round 2` found the repository-statistics cache was a process global, so a
  fresh engine was served a prior engine's row.

Both are the class an in-repo suite is worst at catching: a gate that passes its
author's fixtures because the author tested the path they were thinking about.

**In-repo.** Several thousand tests across a feature matrix, every leg run
against all three backends; property tests; mutation testing on load-bearing
gates; and a benchmark
[trend dashboard](https://cirisai.github.io/CIRISPersist/dev/bench/) published
per commit. Benchmark numbers are deliberately **not** copied into this file —
that is how the old one came to quote a throughput figure against a
seven-major-old dependency.

**External review — the headline is that there has been none of this crate.**

Two external reviews of the CIRIS stack exist. **Neither examines
CIRISPersist.**

- The public one is a field assessment at
  [towards-alignment.com](https://towards-alignment.com/cards/field-agendas/ciris/),
  relating the stack to seven AI-safety cruxes. It is an **alignment
  assessment, not a security audit**, and the components it names are Accord,
  CIRISAgent, Verify, Lens, and Proxy.
- The second is not public, and also does not cover this crate.

So: treat every security property described above as a claim backed by our own
tests, one independent conformance suite, and a published threat model — **not
as audited**. The substrate that enforces the stack's admission rules is the
part of the stack no outside reviewer has yet read.

That is the gap to close, and an adversarial reader is worth more to us than a
pull request.

The public assessment also makes, from outside, the argument this codebase keeps
re-learning from inside:

> "Green attestation does not imply correction uptake; a signed agent record
> does not imply the real agent."

## Quick start

Rust — this snippet is compiled by CI as
[`examples/readme.rs`](examples/readme.rs), so it cannot silently rot:

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

Python:

```python
import ciris_persist as cp

engine = cp.Engine(dsn="sqlite://./agent.db", signing_key_id="agent-ed25519")
engine.register_consumer("my-adapter", ["cirisgraph"])
summary = engine.receive_and_persist(request_body_bytes)
```

## Running the tests

The Postgres suite needs a database to itself. Several tests assert on **global**
row counts, and one does `DROP SCHEMA cirislens CASCADE`, so a second suite
sharing the database reds tests that have nothing to do with either change.
Measured, two concurrent copies of the same suite over six iterations: one shared
database → 6/6 iterations red; separate fresh databases → 0/6.

It is *not* the migration advisory lock, which is the common guess. PostgreSQL
builds the advisory-lock tag from `MyDatabaseId` plus the key, so advisory locks
are per-database — two suites on two databases cannot contend on one no matter
what key they use.

```bash
# fresh single-use database, dropped afterwards, exit code propagated exactly
scripts/pg_test_db.sh -- cargo nextest run --features postgres,sqlite

scripts/pg_test_db.sh --check     # who is on which database right now
```

Within a run, each test **process** gets its own database cloned from an
already-migrated template. Per-test isolation *alone* is a 2.6× regression,
because every test then replays the full migration set into an empty database;
`CREATE DATABASE … TEMPLATE` is what makes isolation cheaper than sharing rather
than more expensive. Anyone adopting half of that change gets a slower suite and
concludes the approach failed.

Parallel worktrees each grow a large `target/`. To reclaim the finished ones:

```bash
scripts/reap_worktree_targets.sh            # dry run — prints verdict + reason
scripts/reap_worktree_targets.sh --apply
```

It removes `target/`, and only `target/`, and only from a linked worktree that is
unlocked, merged into `origin/main`, clean (untracked counts as dirty), has no
process living in it, and whose `target/` has been cold for an hour. Any one of
those failing skips it.

## Docs

| Doc | What |
|---|---|
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threat model — the `AV-*` attack vectors and their shipped mitigations |
| [FSD/CIRIS_PERSIST.md](FSD/CIRIS_PERSIST.md) | Full functional spec |
| [docs/PUBLIC_SCHEMA_CONTRACT.md](docs/PUBLIC_SCHEMA_CONTRACT.md) | Stable schema contract |
| [docs/COHABITATION.md](docs/COHABITATION.md) | In-process cohabitation model |
| [docs/FEDERATION_DIRECTORY.md](docs/FEDERATION_DIRECTORY.md) | Directory surface |
| [MISSION.md](MISSION.md) | Mission alignment |
| [CHANGELOG.md](CHANGELOG.md) | Per-release history — and the record of what each major actually changed |

For cryptographic primitives, hardware attestation, and post-quantum posture,
[CIRISVerify](https://github.com/CIRISAI/CIRISVerify) is the authority; persist
consumes it and pins it, and does not restate its claims here.

## Where it sits

CIRIS is the reference deployment, not the definition. Within it: Verify owns
cryptographic primitives, Edge owns transport, the agent does the reasoning, and
adjudication belongs to a quorum of human authorities. Persist holds the state
those decisions are made from and enforces what may enter it — **the substrate
observes; it does not adjudicate.**

## License

AGPL-3.0-or-later. The persistence path is auditable line-by-line by design:
closed-source forks are forbidden, which makes the audit story structurally
enforceable rather than socially expected.
