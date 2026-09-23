# FSD — the drive query, and the chunk adopt reaches Python

**Cut:** v46.4.0 (CIRISPersist#891, CIRISPersist#821), carrying the cycle-time work (#879, #880, #881).
**Normative anchors:** CC 5.2 (self/family audience), CC 2.6.1.3 (the envelope bound), CC 5.3.3.1 (sealed chunk DAG), CEG §8.1.13.3 (the cohort_scope read gate).
**Consumers:** CIRISEdge `FSD/CONTENT_TRANSFER.md` §6.7 / §6.8 (PR CIRISAI/CIRISEdge#654), CIRISServer#615 §3 (`GET /v1/drive`).

## 1. What was actually missing

Two asks, and in both cases the substrate was nearer than the issue assumed. Stating the correction first, because it is most of the cut:

**#891 — the door exists; the axis does not.** Edge asked for (a) a `cohort_scope` axis on `AttestationFilter` and (b) "a cursor-paged filtered read over the attestation plane." (b) has shipped since v4.0: **`list_attestations(filter, cursor, limit, scope)`** pages `federation_attestations` newest-first by `(asserted_at DESC, attestation_id DESC)`, composes the whole filter, and carries the §4.3 caller-visibility gate — on the Rust trait and on PyO3 (`list_attestations(filter_json, cursor_json, limit, caller_occurrence_key_id)`). Edge was walking `list_attestations_since` instead, which is a *different plane*: the replication cursor, ascending by `COALESCE(admitted_at, promoted_at, asserted_at)`, returning `ServedAttestation`, and composing **no** visibility gate.

So the cut is one axis, not a door.

**#821 — the scoped chunk DAG shipped in #832/#838; its receiving half is unreachable.** `put_blob_chunk_scoped` → `seal_stream_scoped` → `read_stream_chunk_as` / `read_blob_range_as` are all on PyO3. `Engine::adopt_sealed_chunk` — the chunk twin of `adopt_sealed_blob`, the door a sibling device needs to take a chunk it was sent — has **no PyO3 binding**. A drive can seal a video and cannot adopt one.

## 2. The two cursors — stated once, because picking the wrong one is silent

| door | order | gap-free on this node | gate | returns |
|---|---|---|---|---|
| `list_attestations` | `(asserted_at DESC, attestation_id DESC)` | **no** — a row signed earlier and admitted later sorts below a page already read | §4.3 caller-visibility + local-tier | `AttestationListPage` |
| `list_attestations_since` | `COALESCE(admitted_at, …) ASC` | **yes** — the node-local monotone instant | **none** (replication) | `ServedAttestation` |

A **drive listing** is a display: the user's files, newest first, by the file's own instant — `list_attestations`. A **catch-up** is a cursor: everything this node has learned since, in the order it learned it — `list_attestations_since`. The first is not a replacement for the second and the second must not be dressed as a reader door, which is why the axis goes on the filter and `list_attestations_since` keeps its signature.

## 3. Surface

| symbol | change |
|---|---|
| `AttestationFilter::cohort_scope: Option<String>` | NEW — exact match on the row's `cohort_scope` column (V056, indexed `WHERE cohort_scope != 'federation'`). `None` = today's behaviour |
| `AttestationFilter::cohort_target_id: Option<String>` | NEW — exact match on the row's `cohort_target_id` (the community / family / owner the row names). A `self` row names its owner; a `federation` row names nobody |
| `Engine::adopt_sealed_chunk_json` (PyO3) | NEW — the chunk twin of `adopt_sealed_blob_json`; same `BlobProvenance` payload plus `stream_id`, `seq`, `epoch`, `plaintext_size`, and the same `would_hold` + §4.3 gates the Engine door already applies |

Both filter fields are optional on a `#[non_exhaustive]`, `Serialize`/`Deserialize` struct — so they reach PyO3 through the existing `filter_json` with no signature change, and old consumers keep compiling and deserializing (C.4 rule 2).

No wire change, no migration, no vocabulary change. MINOR.

## 4. Invariants

- **I142** (sqlite, postgres — `list_attestations`; all three through
  `list_scores` as `i142_mem`, because the memory backend has no relational
  CEG read substrate and its twin of the axis would otherwise have no
  witness) — **the drive query.** Seed rows across `(cohort_scope, cohort_target_id)`: two `self` rows the caller owns, one `family` row of the caller's family, one `community` row of a room the caller is in, one `community` row of a room it is not, one `federation` row. Then:
  - `cohort_scope: "self"` returns exactly the two self rows; combined with `dimension_prefixes: ["file:"]` it returns the drive listing and nothing else;
  - `cohort_target_id: <family key>` returns exactly that family's row;
  - the two axes AND with each other and with the nine existing axes (window, tier, attester) rather than overwriting them;
  - a filter naming a room the caller is **not** in returns nothing even though the row is on disk — the §4.3 gate, not the filter, is what refuses;
  - the page is resumable: `limit: 1` twice with the returned cursor yields the second row and no repeat.
  - Mutants: drop the `cohort_scope` predicate (self query returns everything); drop `cohort_target_id` (the other room's row appears); OR the two instead of ANDing (a federation row appears in the self query); apply the axis before the scope gate (the not-a-member room's row appears).
- **I143** (from disk + sqlite/postgres two-node) — **the chunk adopt reaches Python.** From disk: `adopt_sealed_chunk_json` is present in `ffi/pyo3.rs` and classified in the taxonomy. Two-node: A appends a sealed chunk at `self` and seals the stream; B — the owner's other node — adopts the chunk through the Engine door with the author's provenance and `read_stream_chunk_as` opens it. Mutant: the binding drops the provenance's author (the adopt admits a chunk the caller is not party to).

## 4.1 Mutation table (2026-09-23)

| Mutant | Verdict |
|---|---|
| M1 sqlite drops the cohort_scope predicate | KILLED by sqlite::i142_mem sqlite::i142  |
| M2 postgres drops the cohort_scope predicate | KILLED by postgres::i142 postgres::i142_mem (under scripts/pg_test_db.sh — without a DSN the leg passes vacuously in 0.00s) |
| M4 memory twin ignores the axis | KILLED by memory::i142_mem  |
| M5 the chunk binding is unreachable | KILLED by i143  |

The postgres row is the lesson: run under `scripts/pg_test_db.sh` or the leg
returns early, prints `ok` in 0.00 s, and reports a mutant as surviving when
it was never exercised.

## 5. Not in scope

- `list_attestations_since` gaining a filter. It is the replication door; a filtered, ungated read is the shape §2 exists to keep apart.
- A gap-free *listing* cursor (an `admitted_at`-ordered filtered read). If a consumer needs catch-up semantics over a filtered set rather than a display order, that is a third door and wants its own issue — say so and it gets one.
- #890 (the bulk owned-nodes read) — independent, tracked.
