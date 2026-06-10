# FSD: CIRISPersist — JCS (RFC 8785) canonicalization flip — the CEG 1.0 §0.9 conformance milestone

**Status:** **ACTIVATED — persist v4.15.0 (2026-06-09).** The machinery shipped in v4.6.0 (gate + JcsCanonicalizer + signed-epoch version gate, produce held at `V1Python`); **v4.15.0 flips `produce_canon_version() → V2Jcs` and lands the `"3.0.0"` verify arm**, in lockstep with the agent's 2.9.6 hard-JCS cutover. **Coordination resolved:** the agent's cutover (`9c3546dc8`) initially kept `trace_schema_version = "2.7.9"`, which would have defeated the signed-epoch gate (`major ≥ 3 ⇒ JCS`) and failed every non-ASCII trace; surfaced as **CIRISAgent#871**, the agent **bumped the stamp to `"3.0.0"`** (`2a228b4a4`, before merge) — field layout byte-identical to 2.7.9, only the canonicalizer changed. Substrate triple: agent 2.9.6 JCS + persist 4.15 + ciris-verify 5.0.0. NodeCore-consensus / edge-wire / internal-`persist_row_hash` stay on their own tracks (see CHANGELOG 4.15.0 "out of scope").

_Original acceptance (v4.6.0, 2026-06-09):_ **ACCEPTED (CIRISAgent ✅, conditional — folded).** Ships as persist v4.6.0, which lands FIRST; the agent validates byte-identity, then bumps pins at the 2.9.6 substrate triple. **Two conditions from the agent review, both folded:** (1) the "ASCII-identity dividend" framing was *wrong* — the agent signs `ensure_ascii=True`, so Python-compat ⊥ JCS on **all** non-ASCII (agent measured 2/6 byte-identical, §0); (2) OQ-5's signed-epoch **version gate is MANDATORY and part of this cut**, not a follow-up.
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.8
**Created:** 2026-06-09
**Repo:** `~/CIRISPersist`
**Target cut:** **v4.6.0** (the canonicalizer flip + the signed-epoch version gate) — gates `attestation_promote` and persist's CEG 1.0 / agent-3.0 readiness. (v4.5.0 shipped only `attestation_query`; the production canonicalizer is still Python-compat.)
**Risk:** **Breaking, federation-wide, bidirectionally coupled.** persist both *produces* signatures (attestations, keys, outbound replication) and *verifies* producer signatures (agent trace ingest). The signing bytes change for non-ASCII envelopes. persist MUST flip in **lockstep** with the agent's 3.0 RFC-8785 flip (and lens/registry), or each side fails to verify the other.
**Normative anchor:** CEG 0.15 **§0.9** ("A CEG-Conforming Producer MUST produce signing bytes via JCS [RFC 8785] over the envelope object; a CEG-Conforming Consumer MUST recompute via the same JCS rule"). The §0.9 mandate is *global* — Python-compat canonicalization is non-conformant everywhere it feeds a CEG signature.
**Driving context:** CIRISVerify is agent-3.0 / ceg-1.0 ready (shipped `ciris_verify_core::jcs`, v4.11.0). persist is the next link in the chain. CIRISAgent#840 (CEG-native agent, 3.0) is the lockstep counterpart. Blocks CIRISPersist#171 phase 2 (`attestation_promote` — OQ-4 requires JCS).

---

## 0. TL;DR for reviewers

persist canonicalizes every CEG signing payload with **`PythonJsonDumpsCanonicalizer`** — sorted-key `json.dumps`, which the code itself documents as *"not RFC 8785 JCS"* and whose flip is *"gated on the agent flip\[ping] to JCS."* CEG §0.9 mandates **JCS**. This FSD flips persist's CEG signing/verifying canonicalizer **Python-compat → JCS** (`Rfc8785Canonicalizer`, already implemented in-tree; or `ciris_verify_core::jcs`, pinned v4.11.0). The flip is the §0.9 conformance milestone and the precondition for `attestation_promote`.

**The one hard fact that shapes everything:** persist *verifies* agent trace signatures (`ingest.rs`) and *produces* its own (attestations/keys/replication). So this is not a unilateral persist change — it is a **coordinated, simultaneous flip** with the agent (3.0) and the other CEG-RC1 impls.

**Parity reality (corrected by the CIRISAgent #174 measurement — the draft's "ASCII-identity dividend" was wrong).** The agent signs with `json.dumps(sort_keys=True, separators=(",",":"))` and **no `ensure_ascii` argument** → Python's default **`ensure_ascii=True`**, which `\uXXXX`-escapes every non-ASCII codepoint. persist's `PythonJsonDumpsCanonicalizer` escapes identically, so it matches the agent today *in every language*. **JCS (RFC 8785 §3.2.2.2) emits raw UTF-8** for non-ASCII. Therefore Python-compat ⊥ JCS on **every non-ASCII character** — *not* merely the non-BMP tail. The agent measured **2/6 byte-identical** over realistic 9-field traces: ✅ pure-ASCII GENERIC/DETAILED en; ❌ every non-English `thought_content`/`rationale` (am/zh/ar) **and** any English trace carrying the `⚠️` attestation-disclosure emoji (fires at GENERIC). So the breaking corpus is the **majority** of a 29-language reasoner's stream, not an edge case.

**What that does to the cut:** the **go-forward** path (new traces signed under JCS) is clean and language-independent — both sides flip together at 2.9.6, so agent-JCS ≡ persist-JCS in any locale. The **backward** path (verifying pre-cut Python-signed rows after the flip) breaks for all that non-ASCII corpus → a **mandatory, signed-epoch-bound version gate** (OQ-5) selects the legacy canonicalizer for pre-cut rows. The pure-ASCII identity still buys one thing: ASCII traffic (most keys/scores/hashes/ISO timestamps) needs no gate either way.

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

**RESOLVED (agent + persist): (A) hard cut + a MANDATORY signed-epoch version gate.** The chain cuts to ceg-1.0 together (agent 3.0 / persist 4.6 / verify 4.11), so go-forward is (A). But because the breaking corpus is the *majority* (not a tail — §0), (A) is **not** naked: pre-cut rows MUST verify under the legacy canonicalizer, selected by a **signed-epoch-bound** discriminator (attacker-uncontrollable per the §6 downgrade guard), bounded by the agent's trace-retention window, after which the legacy path sunsets. (B) bounded dual-verify stays the known-shape fallback — persist already runs a 2-field→9-field *try-both* accept window at ingest, so the dual-canonicalizer machinery is familiar. (C) version-tag-in-envelope is rejected (it touches §4 wire format).

**The version-gate mechanism (persist proposes; agent validates at the 2.9.6 pin-bump).** persist selects Python-compat vs JCS per row using a discriminator that is *inside the signed bytes* (so it cannot be downgraded): the row's signed schema/epoch. Concretely — gate on the signed `schema_version` / `crypto_kind` the producer stamps at the flip (agent 3.0 bumps it), with a pinned boundary; pre-boundary → Python-compat, at/after → JCS. The exact field + boundary value is pinned with the agent during the Conformance#9 byte-identity validation before they bump pins.

## 4. `attestation_promote` rides on this (CIRISPersist#171 phase 2)
Once the signing canonicalizer is JCS, `attestation_promote` is unblocked and trivial: load the `local` row → `jcs::canonicalize(attestation_envelope)` → `Engine::sign_hybrid` → write the scrub envelope + flip `tier=federation` (Registry must #1 byte-identity now holds, because native rows are *also* JCS). promote lands in the same v4.5 cut or immediately after.

## 5. Backend / parity
The canonicalizer is backend-agnostic (it runs above the store). Both backends already call the same `canonicalize_value` sites; the flip is a single canonicalizer swap, parity-preserving. The existing `ascii_only_python_matches_jcs` parity test extends into a conformance vector set (composes with CIRISConformance#9's RFC 8785 vectors).

## 6. Threat / conformance
- **AV-63 (canonicalizer-mismatch silent failure)** — a producer and consumer disagreeing on the canonicalizer yields a silent whole-signature failure (forged-rejection or, worse, a mismatch read as tampering). Closed by pinning JCS chain-wide + the shared `ciris_verify_core::jcs` impl + the conformance vector set. Same hazard class as #63/#64.
- **Downgrade guard** — under any transition strategy, the flip MUST NOT let an attacker force the weaker/legacy canonicalizer to bypass a check; the version gate is signed-bytes-bound, not caller-selectable.

## 7. Open questions — resolved by the CIRISAgent #174 review
- **OQ-1 — which JCS impl. ✅ `ciris_verify_core::jcs`** (single blessed impl shared Rust-side). Agent ask folded: **CIRISVerify must also expose that same impl as a Python binding** so the agent's producer side canonicalizes byte-identically (the agent has no JCS lib today). One impl across Rust + the Python producer, or we reintroduce the divergence this FSD closes. → upstream ask on CIRISVerify.
- **OQ-2 — `persist_row_hash`. ✅ leave Python-compat.** Internal-only, never crosses the boundary; flipping it would break existing rows' integrity recompute. Flip ONLY boundary-crossing sites. Agent agrees (it never touches `persist_row_hash`).
- **OQ-3 — migration strategy. ✅ (A) hard cut + MANDATORY signed-epoch version gate** (§3). Not (A)-naked — the breaking corpus is the majority, so the legacy path is required, bounded by retention then sunset.
- **OQ-4 — lockstep timing. ✅ NOT live yet; cut boundary = the 2.9.6 substrate triple** (agent 3.0 JCS + persist 4.6 + verify 4.11 + edge + lens). **persist 4.6 ships FIRST**; the agent validates byte-identity via Conformance#9, then bumps pins. Agent hard-veto satisfied.
- **OQ-5 — legacy rows. ✅ REQUIRED, version-gate-by-signed-epoch** (this cut, not a follow-up). Re-signing is unavailable (the agent doesn't retain pre-cut canonical state); the canonicalizer is selected by the row's signed epoch (attacker-uncontrollable), bounded by trace retention, then the legacy path sunsets.

## 8. Reviewers — status
This is the signing contract — the **whole chain** agrees, not just persist's usual consumers:
- **CIRISAgent (#840, 3.0)** — **✅ NOD (conditional, both conditions folded):** the lockstep go-forward cut is safe in every language; conditions = (1) fix the false ASCII-identity premise (done, §0 + `canonical.rs`), (2) the version gate is part of this cut (done, §3/OQ-5). Confirmed the 2.9.6 boundary + persist-4.6-first + OQ-1 shared impl. Offered the multilingual + `⚠️`-disclosure vectors to Conformance#9.
- **CIRISVerify** — owns the shared `jcs` impl; persist consumes `ciris_verify_core::jcs` (OQ-1). **Open ask:** expose the same impl as a Python binding for the agent producer.
- **CIRISRegistry (CEG authority)** — §0.9 conformance. (C) version-tag rejected, so no §4 wire change.
- **CIRISLensCore** — also verifies/produces CEG signatures; flips in the same 2.9.6 lockstep.
- **CIRISConformance#9** — the cross-impl RFC 8785 vector set (+ the agent's multilingual / `⚠️` vectors) that proves byte-identity before the agent bumps pins.

**Accepted.** persist builds 4.6 (the flip + the signed-epoch version gate), ships first, and the chain validates via Conformance#9 before the 2.9.6 pin-bump. `attestation_promote` follows on the JCS foundation.
