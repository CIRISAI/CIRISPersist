# MISSION — `ciris-persist`

> Mission Driven Development (MDD): the FSD names what we build; this
> document names *why*, against the CIRIS Accord's objective ethical
> framework. Every component, every test, every PR cites against this
> file. See `~/CIRISAgent/FSD/MISSION_DRIVEN_DEVELOPMENT.md` for the
> methodology.

## 1. Meta-Goal alignment — M-1

The CIRIS Accord (v1.2-Beta, 2025-04-16) names **Meta-Goal M-1**:

> *Promote sustainable adaptive coherence — the living conditions under
> which diverse sentient beings may pursue their own flourishing in
> justice and wonder.*

`ciris-persist` is the substrate on which M-1 becomes durable. The
agent reasons; the lens scores; **persistence is what makes either of
those evidence rather than ephemera.** A signed trace that nobody stores
correctly proves nothing. A score recomputed on a corpus that drifts
silently proves nothing. A federation that can't replicate evidence
between peers proves nothing.

The crate's job is to **carry the cryptographic and behavioral evidence
on which the Federated Ratchet (Accord Book IX Ch. 3-4) operates** —
durably, verifiably, auditable by any peer, on every platform a CIRIS
deployment reaches.

## 2. Mission alignment per component

The FSD §3.1 names six modules. Each must answer **why does this serve
M-1?** before any code lands.

### `schema/` (WHAT)

**Mission:** carry the wire-format contract verbatim. The trace's shape
is the agent's testimony; ambiguity in the parser is a way for a Sybil
or a buggy pipeline to claim something the agent didn't say.

**Constraint:** zero `serde_json::Value` in hot paths. Every event variant
has a concrete struct with a discriminant. Schema-version is a hard gate,
not a hint. *(MDD parity with the agent's "no Dict[str, Any]" rule.)*

**Anti-pattern that violates mission:** "I'll just deserialize to a
JSON value and pull fields lazily." That defeats the
`schema-version-gate` from FSD §3.4 and lets malformed payloads pass
verify because the parser was too forgiving.

### `verify/` (WHAT × HOW)

**Mission:** signature verification is the cryptographic floor of the
Coherent Intersection Hypothesis. Every persisted row must have been
provably produced by the claimed agent at the claimed moment, OR be
explicitly marked unverified. There is no third state.

**Constraint:** `verify_strict` semantics — reject weak keys, malleable
signatures, schema-version mismatch, audit-anchor inconsistency. Every
rejection emits a structured error; never silently coerce.

**Anti-pattern that violates mission:** "store first, verify later."
Verify-before-persist is the contract (FSD §3.3 step 2). Persisting
unverified bytes corrupts the corpus N_eff measurement (PoB §2.4)
operates on.

### `store/` (HOW × WHO)

**Mission:** the same persistence trait surface, regardless of whether
the substrate is Postgres on a datacenter, SQLite on an iPhone, or redb
on a 4GB-RAM solar-LoRa node. The Federated Ratchet only reaches
"diverse sentient beings ... in justice and wonder" if the substrate
reaches the people who need it. That includes the people without
datacenter fiber.

**Constraint:** trait `Backend` shape sealed in Phase 1, covers Phases
2 and 3. No backend-specific public API leaks. Idempotency on
`(trace_id, thought_id, event_type, attempt_index)` is a contract, not
an implementation detail.

**Anti-pattern that violates mission:** "Postgres-only Phase 1, we'll
worry about SQLite later." Phase-1 trait choices that lock SQLite or
no_std out of Phase 2 betray the platform reach commitment in
`PLATFORM_ARCHITECTURE.md` §1, which itself is grounded in PoB §2.5's
L-01 cracking.

### `scrub/` (WHAT × HOW)

**Mission:** privacy at trace level. The Accord (Book II §IV) and the
GDPR/HIPAA compliance posture in CIRISLens require that PII never
crosses the persistence boundary at trace levels where it isn't
warranted.

**Constraint:** Phase 1 delegates to the existing `cirislens-core`
scrubber (no behavior change — FSD §3.3 step 3). Future scrubbers are
trait impls; the interface is the choke point through which all
content-bearing payloads pass.

### `server/` (HOW × WHO)

**Mission:** the network edge. Verification is meaningless if the wire
edge is exploitable. Memory-safe parsing of untrusted bytes is the
recurring CVE class for federation services; Rust's static guarantees
are the answer.

**Constraint:** axum + tower; bounded queue; backpressure via 429,
never via dropping bytes silently. Every error response is a defined
type, not an opportunistic string.

### `ffi/` (WHO)

**Mission:** every CIRIS deployment target reaches the same Rust core.
The agent's iOS bundled-Python persistence is a debt against M-1
because every divergence between iOS and server reasoning is a place
the Federated Ratchet can be silently broken — different bug surfaces,
different invariants, different PII boundaries. One core; many shells.

**Constraint:** PyO3 (Python), swift-bridge (iOS), uniffi (Android,
Phase 2.5+), cbindgen (C ABI base). Each FFI shell is a thin
translation layer; business logic lives in Layer 3 (Public Rust API),
never duplicated in shell code.

## 3. Anti-patterns that fail MDD review

Any PR exhibiting these is rejected on mission grounds, not style:

1. **`serde_json::Value` in a `*_hot_path*`.** Untyped data structures
   in production. Use a concrete `enum ReasoningEvent` variant.
2. **A new schema struct with `_v2` / `_NewVersion` suffix.** Search
   `grep -r 'pub struct.*<the type>'` first; the schema already exists.
   Versioning is via `schema_version` field + migrators, not parallel
   types.
3. **A bypass branch like `if self.is_admin { skip_verify(); }`** —
   single-rule architecture. There is no auth shortcut around
   signature verification; admin keys verify by the same path.
4. **`.unwrap()` / `.expect()` in non-test code paths.** Typed errors
   via `thiserror`. Every fallible operation has a defined failure
   mode.
5. **`unsafe` blocks without an audit comment naming the invariant
   maintained.** Every `unsafe` block is paired with a doc comment
   explaining what makes it safe and why a safe alternative is
   inadequate.
6. **A new feature flag for a "temporary" workaround.** Every feature
   flag in `Cargo.toml` is documented in `FSD/CIRIS_PERSIST.md` with a
   phase ownership and a removal condition (or "permanent — defines
   target build").
7. **A test that asserts only "no error returned."** Tests must
   verify **mission-aligned outcomes** — the right data persisted, the
   right signature rejected, the right backpressure applied. Functional
   absence-of-panic is necessary but never sufficient.
8. **Stripping content text from payloads in a `scrub::*` impl in a
   way that loses the thing the scrubber was supposed to preserve.**
   Privacy-preserving redaction maintains analytical signal; "delete
   the whole field" is only correct when the field has no
   privacy-safe form. Test for this; the trace level (`generic`,
   `detailed`, `full_traces`) is the gate, not the scrubber's
   convenience.
9. **A migration that drops a column without a versioned data
   migration that preserves the values being lost.** The corpus N_eff
   measurement (PoB §2.4) depends on every field being present in
   queryable form across the lifetime of the trace.
10. **A platform target dropped from CI because it's "the painful
    one."** Every target in `PLATFORM_ARCHITECTURE.md` §1 has an
    operational reason. iOS / Android / no_std / Pi are the painful
    ones precisely because they're the M-1 reach commitments.

## 4. Test categories — every test answers a mission question

Per MDD §"Testing Standards" + the agent's CLAUDE.md "verify
mission-alignment, not just functional correctness":

| Category | Mission question | Examples |
|---|---|---|
| **Schema parity** | Does the parser preserve the agent's testimony byte-for-byte? | recorded-batch JSON → struct round-trips byte-exact for canonical bytes |
| **Verify rejection** | Does verify reject what should be rejected? | mutated-byte tests, weak-key, schema-version mismatch, audit-chain break |
| **Idempotency** | Can the agent's retry not corrupt the corpus? | duplicate batch insert is a no-op on the conflict key |
| **Backend parity** | Does the same trace land identically on Postgres and SQLite? | per-trait-method conformance suite, run against every backend |
| **Canonicalization parity** | Does Rust canonicalize byte-exact with the agent's Python signer? | corpus of recorded `python json.dumps` outputs vs Rust impl |
| **Backpressure** | Does the queue exert correct pressure under load? | full-queue → 429 with Retry-After; never silent drop |
| **Power-cycle resilience** | Does the journal survive `kill -9` mid-batch? | injection test in CI |
| **Platform parity** | Does the iOS build agree with the Linux build on the same input? | XCTest against the same recorded batches |
| **Mission rejection** | Does the system refuse mission-violating requests? | unverified bytes never persist; PII at GENERIC level never stored |

A PR adding a new code path **adds a test in at least one of the
above categories or it is not done.** Test absence is mission drift.

## 5. Continuous mission validation

Borrowed from CIRISAgent's grace tooling:

- **Schema drift audit.** A CI job greps the source for `serde_json::Value`,
  `HashMap<String, ?>` in non-`payload` positions, `unwrap()` outside
  `#[cfg(test)]`. Drift over zero is a soft block (review reminder),
  drift up by 1 is a hard block (PR cannot merge).
- **Mission justification in commit messages.** Every commit body has
  one line of the form `Mission: <short M-1 alignment>`. Squash-merging
  is fine; the squash body must keep at least one of the source
  commits' mission lines.
- **Quarterly review.** The `FSD/CIRIS_PERSIST.md` + `MISSION.md` pair
  is reviewed every quarter against the deployed reality. Drift is
  treated as a project-level signal, not as a documentation chore.
- **Anti-Goodhart on test counts.** Test count is not a metric. Test
  *coverage by mission category* (§4 above) is. Counts that go up
  without category coverage going up are rejected as drift.

## 6. License-locked mission preservation

`ciris-persist` is **AGPL-3.0-or-later** (Cargo.toml:5). The license is
the structural commitment that the substrate stays open in the same way
the canon stays open: anyone reasoning about whether a CIRIS-derived
deployment preserves M-1 alignment can see and audit every line of the
persistence path. Closed-source forks are forbidden by the license,
which makes the federation primitive's audit story
*structurally enforceable*, not merely socially expected.

This is a mission decision, not a licensing one. The Accord (Book IX
Ch. 9 — NEW-04) acknowledges that no detector is complete; the only
counterweight is **legibility under audit**. Closed source breaks
legibility. AGPL is the lock-in.

## 7. Failure modes — when the mission is at risk

Borrowed from MDD §"Failure Modes":

| Symptom | Mission risk | Mitigation |
|---|---|---|
| Phase 1 ships with a Postgres-only Backend trait | Locks SQLite + iOS + no_std out of Phase 2 | Trait shape sealed Phase 1, includes Phase 2/3 method signatures stubbed (`unimplemented!()`) |
| Schema version handled "loosely" | Sybil corpus drift undetectable | `SUPPORTED_VERSIONS` constant + structured 422 reject |
| `serde_json::Value` creeps into hot path | Untyped bug surface; MDD parity broken | CI grep block on its appearance outside payload-blob slots |
| Canonicalization implementation doesn't match agent's signer | Every signature fails verification → corpus is empty → PoB §2.4 measurement collapses | Parity-test corpus in CI; byte-exact compare gates merge |
| iOS path drifts from Linux path | Cross-platform agent reasoning becomes incoherent → Federated Ratchet broken | Same trait surface, same backend parity tests run on both |
| Closed-source fork emerges | Audit legibility breaks | AGPL-3.0 enforcement; license-deny in `cargo deny` config |

## 8. Closing note

The FSD specifies the work; the platform sketch specifies the reach;
this document names **why any of it matters.** The CIRIS Accord is the
canon; M-1 is the meta-goal; every PR against this repo demonstrates
its alignment or it does not merge. The mission is not external
constraint — it is the architectural foundation that *makes the
technical decisions tractable*. A persistence layer with no mission
justification has no principled answer to "should this be SQLite or
Postgres? should this be no_std-clean? should iOS link bundled
SQLite?". With the mission, every answer follows from a single
question: **does this bring more peers' evidence into the federation
that M-1 needs to operate?**

Yes / no. The rest is engineering.
