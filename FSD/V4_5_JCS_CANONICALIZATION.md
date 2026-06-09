# FSD: CIRISPersist — JCS (RFC 8785) canonicalization flip — the CEG 1.0 §0.9 conformance milestone

**Status:** Draft — for the four-impl + Verify review before any code. This is a **federation signing-contract change**; it cannot land on persist's say-so. NOT accepted.
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.8
**Created:** 2026-06-09
**Repo:** `~/CIRISPersist`
**Target cut:** v4.5.0 (the canonicalizer flip) — gates `attestation_promote` and persist's CEG 1.0 / agent-3.0 readiness.
**Risk:** **Breaking, federation-wide, bidirectionally coupled.** persist both *produces* signatures (attestations, keys, outbound replication) and *verifies* producer signatures (agent trace ingest). The signing bytes change for non-ASCII envelopes. persist MUST flip in **lockstep** with the agent's 3.0 RFC-8785 flip (and lens/registry), or each side fails to verify the other.
**Normative anchor:** CEG 0.15 **§0.9** ("A CEG-Conforming Producer MUST produce signing bytes via JCS [RFC 8785] over the envelope object; a CEG-Conforming Consumer MUST recompute via the same JCS rule"). The §0.9 mandate is *global* — Python-compat canonicalization is non-conformant everywhere it feeds a CEG signature.
**Driving context:** CIRISVerify is agent-3.0 / ceg-1.0 ready (shipped `ciris_verify_core::jcs`, v4.11.0). persist is the next link in the chain. CIRISAgent#840 (CEG-native agent, 3.0) is the lockstep counterpart. Blocks CIRISPersist#171 phase 2 (`attestation_promote` — OQ-4 requires JCS).

---

## 0. TL;DR for reviewers

persist canonicalizes every CEG signing payload with **`PythonJsonDumpsCanonicalizer`** — sorted-key `json.dumps`, which the code itself documents as *"not RFC 8785 JCS"* and whose flip is *"gated on the agent flip\[ping] to JCS."* CEG §0.9 mandates **JCS**. This FSD flips persist's CEG signing/verifying canonicalizer **Python-compat → JCS** (`Rfc8785Canonicalizer`, already implemented in-tree; or `ciris_verify_core::jcs`, pinned v4.11.0). The flip is the §0.9 conformance milestone and the precondition for `attestation_promote`.

**The one hard fact that shapes everything:** persist *verifies* agent trace signatures (`ingest.rs`) and *produces* its own (attestations/keys/replication). So this is not a unilateral persist change — it is a **coordinated, simultaneous flip** with the agent (3.0) and the other CEG-RC1 impls. The **ASCII-identity dividend** softens it: Python-compat and JCS produce **byte-identical** output for ASCII-only payloads; they diverge only on **non-BMP unicode** (the §3.2.2.2 surrogate-pair / escaping rule) and **number formatting** (RFC 8785 §3.2.2.3 ECMAScript). So the *corpus that breaks* is exactly the non-ASCII / exotic-number subset.

---

## 1. Why this exists — the mission case

### 1.1 The gap
`src/verify/canonical.rs` is explicit: the production canonicalizer is `PythonJsonDumpsCanonicalizer`, and *"unless the agent flips to JCS, the lens must produce \[Python-compat]"* — the canonicalizer choice is deliberately **slaved to the agent**. CEG §0.9 makes JCS mandatory for every CEG-conforming producer and consumer. So **persist is not §0.9-conformant**, and cannot be until it flips — which it cannot safely do until the agent flips (it verifies the agent's signatures). Verify shipping `jcs` (4.11.0) + declaring ceg-1.0-readiness is the signal that the chain is flipping; persist is next.

### 1.2 Alignment against MISSION.md
- **§1.1 / §1.5** — one canonicalization rule across every tier and impl is the integrity floor; a federation cannot measure a corpus it cannot consistently verify.
- **§1.4 apophatic bound** — JCS is a *fixed, externally-specified* rule (RFC 8785), not a persist invention; adopting it removes a persist-local quirk, it does not add a knob.
- **§1.6 fail-honest** — a canonicalizer mismatch is a *silent* whole-signature failure (the worst class, same as the nonce/wrap encodings #63/#64). Pinning JCS closes a silent-divergence surface.
- **§1.7** — persist records/verifies what the chain signs; it must use the chain's canonicalization, not its own.

---

## 2. Scope — the flip surface

Every site where persist computes canonical bytes that feed a **CEG signature or content-hash crossing the federation boundary**:

| Site | Direction | Today | Risk |
|---|---|---|---|
| `ingest.rs` (trace verify) | **verify** agent signatures | Python-compat | **Lockstep** — must match what the agent 3.0 signs |
| `engine.rs` (attestation / key / withdraws / blob-signing `original_content_hash`) | **produce** | Python-compat | Peers verifying persist-produced rows must use the same |
| `queue.rs` + `federation/replication/mod.rs` (outbound replication envelopes) | **produce** | Python-compat | Replication peers must match |
| FFI `canonicalize_envelope` (pyo3) | **producer-facing** | Python-compat | Python callers sign over this — flipping changes their bytes |
| `types.rs` `compute_persist_row_hash` / `original_content_hash` | internal + boundary | Python-compat | `original_content_hash` is boundary (signed); `persist_row_hash` is internal-only (may stay) |

**In scope:** flip the boundary-crossing signing/verifying sites to JCS. **Out of scope (named):** the purely-internal `persist_row_hash` integrity hash MAY stay Python-compat (it never crosses the federation boundary) — decided in OQ-2.

`Rfc8785Canonicalizer` (in-tree, `serde_json_canonicalizer` 0.3) is a working impl; `ciris_verify_core::jcs::canonicalize` (v4.11.0) is the cross-impl-blessed one. **OQ-1: one or the other** — prefer the Verify module so persist and Verify share the exact bytes (no second JCS impl to keep in lockstep).

## 3. The migration strategy — the load-bearing decision

The corpus already holds Python-signed rows/traces; the agent already emits Python-signed traces. A hard cut breaks verification of everything signed before the flip (for non-ASCII payloads). Three candidate strategies (**OQ-3, the central open question**):

- **(A) Lockstep hard cut.** persist + agent + lens + registry flip at one coordinated version boundary (agent 3.0 / persist 4.5 / ceg 1.0). Simplest contract; requires the federation to cut together and accepts that pre-cut non-ASCII rows verify only under the legacy rule (a dated `valid_from`/version gate selects the canonicalizer).
- **(B) Dual-verify transition.** persist verifies under JCS, falling back to Python-compat on failure (and vice-versa), for a bounded window; produces JCS only. Tolerates mixed-version peers; doubles verify cost in the window; needs a sunset.
- **(C) Version-tagged envelopes.** Every envelope carries a `canon: jcs|python` tag; verifier picks the canonicalizer per-row. Most robust, but a wire-format addition (touches §4 — heavier CEG change).

The **ASCII-identity dividend** makes (A) far less scary than it sounds: every ASCII-only envelope (the overwhelming majority of dimensions, keys, scores) is byte-identical, so a hard cut only "breaks" the non-ASCII / exotic-number tail. OQ-3 picks the strategy; my lean is **(A)** with a `crypto_kind`/version gate, given the chain is cutting to ceg-1.0 together.

## 4. `attestation_promote` rides on this (CIRISPersist#171 phase 2)
Once the signing canonicalizer is JCS, `attestation_promote` is unblocked and trivial: load the `local` row → `jcs::canonicalize(attestation_envelope)` → `Engine::sign_hybrid` → write the scrub envelope + flip `tier=federation` (Registry must #1 byte-identity now holds, because native rows are *also* JCS). promote lands in the same v4.5 cut or immediately after.

## 5. Backend / parity
The canonicalizer is backend-agnostic (it runs above the store). Both backends already call the same `canonicalize_value` sites; the flip is a single canonicalizer swap, parity-preserving. The existing `ascii_only_python_matches_jcs` parity test extends into a conformance vector set (composes with CIRISConformance#9's RFC 8785 vectors).

## 6. Threat / conformance
- **AV-63 (canonicalizer-mismatch silent failure)** — a producer and consumer disagreeing on the canonicalizer yields a silent whole-signature failure (forged-rejection or, worse, a mismatch read as tampering). Closed by pinning JCS chain-wide + the shared `ciris_verify_core::jcs` impl + the conformance vector set. Same hazard class as #63/#64.
- **Downgrade guard** — under any transition strategy, the flip MUST NOT let an attacker force the weaker/legacy canonicalizer to bypass a check; the version gate is signed-bytes-bound, not caller-selectable.

## 7. Open questions — gate acceptance
- **OQ-1 — which JCS impl.** `ciris_verify_core::jcs` (shared with Verify, single source of truth) vs the in-tree `Rfc8785Canonicalizer`. Lean: the Verify module.
- **OQ-2 — `persist_row_hash` scope.** Flip it too, or leave the internal integrity hash Python-compat (it never crosses the boundary)? Lean: leave internal, flip only boundary-crossing sites.
- **OQ-3 — migration strategy** (A hard-cut / B dual-verify / C version-tag). The federation-coordination question. Lean: (A), ASCII-identity makes it tractable.
- **OQ-4 — lockstep timing.** Is the agent's 3.0 JCS flip live now? persist's ingest-verify MUST flip simultaneously — confirm the cut boundary with CIRISAgent / lens / registry.
- **OQ-5 — legacy-row verification.** Pre-cut non-ASCII rows: re-sign, dual-verify-on-read, or version-gate-by-`valid_from`?

## 8. Who needs to nod / shake
This is the signing contract — the **whole chain** must agree, not just persist's usual consumers:
- **CIRISAgent (#840, 3.0)** — the lockstep counterpart. Confirm the 3.0 JCS flip + the cut boundary (OQ-4). persist verifies what the agent signs; they flip together or not at all. **Hard veto.**
- **CIRISVerify** — owns the shared `jcs` impl; confirm persist should consume `ciris_verify_core::jcs` (OQ-1) and the conformance vectors (CIRISConformance#9).
- **CIRISRegistry (CEG authority)** — §0.9 conformance + the migration strategy's CEG-conformance (esp. if OQ-3 picks (C) version-tag, which touches §4).
- **CIRISLensCore** — also verifies/produces CEG signatures; flips in the same lockstep. Confirm.
- **CIRISConformance#9** — the cross-impl RFC 8785 vector set that proves byte-identity across all four impls.

**Minimum to accept:** Agent confirms the 3.0 flip + boundary (OQ-4) and the migration strategy (OQ-3) is agreed chain-wide; Verify blesses the shared impl (OQ-1). Then persist flips, `attestation_promote` follows.
