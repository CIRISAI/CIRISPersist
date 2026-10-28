# FSD: CIRISPersist — JCS (RFC 8785) canonicalization — the CEG 1.0 §0.9 conformance surface

**Status:** Implemented. Persist produces every CEG signing payload with JCS and verifies each row under the canonicalizer its signed epoch selects. Code: `src/verify/canonical.rs` (`JcsCanonicalizer`, `PythonJsonDumpsCanonicalizer`, `CanonVersion`, `canonicalizer_for`, `produce_canon_version`, `ceg_produce_canonicalize`) and `src/verify/ed25519.rs` (`canon_version_for_trace_schema`). Tracks CIRISPersist#171 / #176; the agent's counterpart is CIRISAgent#840 / #871.
**Normative anchor:** CEG **§0.9** ("A CEG-Conforming Producer MUST produce signing bytes via JCS [RFC 8785] over the envelope object; a CEG-Conforming Consumer MUST recompute via the same JCS rule"). The mandate is *global*: Python-compat canonicalization is non-conformant everywhere it feeds a CEG signature.
**Risk:** federation-wide and bidirectional. Persist both *produces* signatures (attestations, keys, outbound replication) and *verifies* producer signatures (agent trace ingest), so its canonicalizer must agree with every peer's.

---

## 0. Summary

Persist has two canonicalizers:

- **`JcsCanonicalizer`** — RFC 8785, delegating to `ciris_verify_core::jcs::canonicalize`, so persist, CIRISVerify and the agent share one implementation.
- **`PythonJsonDumpsCanonicalizer`** — byte-exact with the agent's legacy `json.dumps(sort_keys=True, separators=(",", ":"))`, used only to verify rows signed under the legacy rule.

**Produce:** `produce_canon_version()` is the `const fn` `CanonVersion::V2Jcs`. Every persist-produced CEG signing payload (attestations, holding claims, withdraws, key registration, blob `original_content_hash`, FFI `canonicalize_envelope`) goes through `ceg_produce_canonicalize`, so that one constant is the whole produce side. It is a release-time constant, not a runtime toggle.

**Verify:** per row, by a discriminator inside the signed bytes. For agent traces, `canon_version_for_trace_schema` maps the signed `trace_schema_version`: major ≥ 3 (`"3.0.0"`) → JCS; anything earlier (`2.7.x`) → Python-compat. The selector is signed, so an attacker cannot downgrade a row to the legacy rule.

**Why the gate is mandatory.** The agent's legacy signer passes no `ensure_ascii` argument, so Python's default `ensure_ascii=True` `\uXXXX`-escapes every non-ASCII codepoint; JCS (RFC 8785 §3.2.2.2) emits raw UTF-8. The two forms agree on pure-ASCII payloads and **diverge on every non-ASCII character** — not merely the non-BMP tail. In a multilingual reasoning stream that is most traces: every non-English `thought_content` / `rationale`, and English traces carrying the `⚠️` attestation-disclosure emoji. Without the per-row gate, every such legacy row would fail verification.

Persist's own produce envelopes are structured ASCII (key ids, SHA-256 hex, ISO timestamps, base64), where the two forms are byte-identical, so producing JCS does not break a peer that still verifies Python-compat.

---

## 1. Why this exists

### 1.1 The rule
CEG §0.9 makes JCS mandatory for every CEG-conforming producer and consumer. Persist sits in the middle of the chain — it verifies what the agent signs and signs what peers verify — so its canonicalizer follows the chain: JCS for the current epoch, the legacy rule only for rows signed before it.

### 1.2 Alignment against MISSION.md
- **§1.1 / §1.5** — one canonicalization rule across every tier and implementation is the integrity floor; a federation cannot measure a corpus it cannot consistently verify.
- **§1.4 apophatic bound** — JCS is a *fixed, externally specified* rule (RFC 8785), not a persist invention.
- **§1.6 fail-honest** — a canonicalizer mismatch is a *silent* whole-signature failure. A shared JCS implementation closes that surface.
- **§1.7** — persist records and verifies what the chain signs; it uses the chain's canonicalization, not its own.

---

## 2. Scope — where canonical bytes feed a signature

| Site | Direction | Canonicalizer |
|---|---|---|
| `ingest.rs` (trace verify) | **verify** agent signatures | per row, by `trace_schema_version` (§0) |
| `engine.rs` (attestation / key / withdraws / blob-signing `original_content_hash`) | **produce** | JCS |
| `queue.rs` + `federation/replication/` (outbound replication envelopes) | **produce** | JCS |
| FFI `canonicalize_envelope` (PyO3) | **producer-facing** — Python callers sign over these bytes | JCS |
| `compute_persist_row_hash` | internal integrity hash, never crosses the federation boundary | Python-compat (unchanged, so existing rows' integrity recompute keeps working) |

## 3. Migration strategy

A hard cut with a **mandatory signed-epoch version gate**: the chain moves to JCS together for new rows, and rows signed before the boundary verify under the legacy canonicalizer, selected by the row's own signed epoch (§0). Re-signing legacy rows is not available — the agent does not retain their pre-cut canonical state.

**Rejected alternatives:**
- **Dual-verify with fallback** (try JCS, then Python-compat, for a window) — doubles verify cost and lets the weaker rule be reached by failure rather than by a signed fact.
- **A `canon: jcs|python` tag in the envelope** — a wire-format addition (CEG §4).

**Limit:** the legacy verify path has no sunset in code; it remains for as long as legacy-epoch rows are held.

## 4. Federation crossing on the JCS foundation
Because native and promoted rows both sign `JCS(envelope)`, a row that crosses into the federation tier is byte-identical to one born there (CC 5.3.2.4.2). The crossing verbs are specified in `FSD/PROMOTION_PRESERVES_THE_ACTOR_SIGNATURE.md`.

## 5. Backend / parity
The canonicalizer runs above the store and is backend-agnostic; both backends call the same sites. The parity tests pin the Python-compat form against recorded `json.dumps` outputs and assert it disagrees with the RFC 8785 reference (the test-only `Rfc8785Canonicalizer`) on non-ASCII; the cross-implementation vector set is CIRISConformance#9.

## 6. Threat / conformance
- **Canonicalizer-mismatch silent failure** — a producer and consumer disagreeing on the canonicalizer yields a silent whole-signature failure (a valid row rejected, or a mismatch read as tampering). Closed by the shared `ciris_verify_core::jcs` implementation and the conformance vector set.
- **Downgrade guard** — the legacy canonicalizer is selected only by a signed discriminator, never by the caller and never by a verification failure.

## 7. Decisions
- **Which JCS implementation:** `ciris_verify_core::jcs`, the single implementation shared Rust-side. The agent's Python producer must canonicalize byte-identically; CIRISVerify exposing the same implementation as a Python binding is the way to guarantee that (a CIRISVerify concern).
- **`persist_row_hash`:** stays Python-compat (internal only).
- **Migration:** hard cut + signed-epoch version gate (§3).
- **Legacy rows:** verified under the legacy rule, selected by signed epoch (§0).

## 8. Parties
The canonicalizer is a chain-wide signing contract:
- **CIRISAgent** — signs traces under JCS from `trace_schema_version` `"3.0.0"` (CIRISAgent#871).
- **CIRISVerify** — owns the shared `jcs` implementation.
- **CIRISRegistry** — CEG authority for §0.9.
- **CIRISLensCore** — also verifies and produces CEG signatures under the same rule.
- **CIRISConformance#9** — the cross-implementation RFC 8785 vector set, including multilingual and `⚠️` vectors.
