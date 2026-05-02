# TRACE_WIRE_FORMAT.md — moved upstream

The authoritative wire-format spec lives in **CIRISAgent** at:

- **Path**: `CIRISAgent/FSD/TRACE_WIRE_FORMAT.md`
- **Pinned commit**: `cc41f315f` (release/2.7.9 HEAD; will be byte-identical at the `v2.7.9-stable` git tag once `release/2.7.9` merges to `main`)
- **Permalink**: https://github.com/CIRISAI/CIRISAgent/blob/cc41f315f/FSD/TRACE_WIRE_FORMAT.md

## Why this is a pointer, not a copy

Persist's pre-v0.3.0 `context/TRACE_WIRE_FORMAT.md` was a vendored copy. The spec lived in two places, and one side could drift from the other — exactly the failure shape that produced the v0.1.18 → v0.1.20 float-canonicalization drift class:

- The agent's spec said one thing about float formatting.
- Persist's vendored copy didn't capture every nuance.
- Production verify broke universally.

v0.3.0 (per cc41f315f hand-off note from CIRISAgent PR #714) replaces the vendored copy with this single-line pointer. The agent's FSD is the source of truth; persist tracks via the pinned commit reference. Same shape lens already adopted in `dab6df6`.

## What persist tracks against the spec

- `SUPPORTED_VERSIONS = ["2.7.0", "2.7.9"]` — `src/schema/version.rs`
- Canonical-shape dispatch by `trace_schema_version` (deterministic, NOT iterative) — `src/verify/ed25519.rs::verify_trace`
- Per-shape canonical reconstruction:
  - `canonical_payload_value(trace)` — 2.7.0, 4-field per-component
  - `canonical_payload_value_v279(trace)` — 2.7.9, 5-field per-component (with denormalized `agent_id_hash`)
  - `canonical_payload_value_legacy(trace)` — 2-field, opt-in via `"2.7.legacy"` sentinel
- Cross-shape field injection defense (§3.1): at "2.7.0", canonical reconstruction ignores per-component `agent_id_hash` even if present on the wire — only envelope value is authoritative

## When this pointer updates

When `release/2.7.9` merges to `main` and the `v2.7.9-stable` tag lands, this file's pinned commit reference moves from `cc41f315f` to whatever the tag resolves to (will be byte-identical content per CIRISAgent's hand-off note).

When the agent introduces a future schema version (`2.8.0`, `2.7.10`, etc.):
1. Agent ships the new FSD content + tag at `vX.Y.Z-stable`
2. Persist bumps `SUPPORTED_VERSIONS` + adds the dispatch arm + canonical reconstruction function + tests
3. This pointer's commit reference updates to the new tag
4. CHANGELOG entry documents the bump

The pointer-update cadence is paired with persist version bumps so consumers tracking persist's wheel pin always have a coherent (spec, persist code) pair.
