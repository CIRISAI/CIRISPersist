# FSD — the drive query, and the chunk adopt from Python

**Tracking:** CIRISPersist#891 (the drive query), CIRISPersist#821 (the chunk adopt).
**Normative anchors:** CC 5.2 (self/family audience), CC 2.6.1.3 (the envelope bound), CC 5.3.3.1 (sealed chunk DAG), CEG §8.1.13.3 (the cohort_scope read gate).
**Consumers:** CIRISEdge `FSD/CONTENT_TRANSFER.md` §6.7 / §6.8, CIRISServer#615 §3 (`GET /v1/drive`).

## 1. What this covers

A drive needs two things from persist: a filtered, paged listing of the caller's own rows, and a way for a sibling device to take a sealed chunk it was sent.

**The drive query (#891).** `list_attestations(filter, cursor, limit, scope)` pages `federation_attestations` newest-first by `(asserted_at DESC, attestation_id DESC)`, composes the whole filter, and carries the §4.3 caller-visibility gate. It is on the Rust trait and on PyO3 (`list_attestations(filter_json, cursor_json, limit, caller_occurrence_key_id)`). The filter carries a `cohort_scope` axis and a `cohort_target_id` axis, so a drive asks for "my `self` rows" directly. `list_attestations_since` is a different plane — the replication cursor — and is not the drive door (§2).

**The chunk adopt (#821).** The scoped chunk DAG is on PyO3: `put_blob_chunk_scoped` → `seal_stream_scoped` → `read_stream_chunk_as` / `read_blob_range_as`. `Engine::adopt_sealed_chunk` is the chunk twin of `adopt_sealed_blob` — the door a sibling device uses to take a chunk it was sent. It is reachable from Python as `adopt_sealed_chunk_json`.

## 2. The two cursors

Picking the wrong one fails silently, so the difference is stated here.

| door | order | gap-free on this node | gate | returns |
|---|---|---|---|---|
| `list_attestations` | `(asserted_at DESC, attestation_id DESC)` | **no** — a row signed earlier and admitted later sorts below a page already read | §4.3 caller-visibility + local-tier | `AttestationListPage` |
| `list_attestations_since` | `COALESCE(admitted_at, promoted_at, asserted_at) ASC` | **yes** — the node-local monotone instant | **none** (replication) | `ServedAttestation` |

A **drive listing** is a display: the user's files, newest first, by the file's own instant — `list_attestations`. A **catch-up** is a cursor: everything this node has learned since, in the order it learned it — `list_attestations_since`. Neither replaces the other. The replication cursor is not a reader door, which is why the cohort axes live on the filter and `list_attestations_since` takes no filter.

## 3. Surface

| symbol | meaning |
|---|---|
| `AttestationFilter::cohort_scope: Option<String>` | exact match on the row's `cohort_scope` column (V056, indexed `WHERE cohort_scope != 'federation'`). `None` = no constraint |
| `AttestationFilter::cohort_target_id: Option<String>` | exact match on the row's `cohort_target_id` (the community / family / owner the row names). A `self` row names its owner; a `federation` row names nobody |
| `Engine::adopt_sealed_chunk_json` (PyO3) | the chunk twin of `adopt_sealed_blob_json`; same `BlobProvenance` payload plus `stream_id`, `seq`, `epoch`, `plaintext_size`, and the same `would_hold` + §4.3 gates the Engine door applies |

Both filter fields are optional on a `#[non_exhaustive]`, `Serialize`/`Deserialize` struct, so they reach PyO3 through the existing `filter_json`, and consumers that omit them deserialize unchanged (C.4 rule 2).

No wire, migration or vocabulary change is involved.

## 4. Invariants

- **I142** (sqlite, postgres — `list_attestations`, and the same axis on the scores plane through `list_scores`) — **the drive query.** Seed rows across `(cohort_scope, cohort_target_id)`: two `self` rows the caller owns, one `family` row of the caller's family, one `community` row of a room the caller is in, one `community` row of a room it is not, one `federation` row. Then:
  - `cohort_scope: "self"` returns exactly the two self rows; combined with `dimension_prefixes: ["file:"]` it returns the drive listing and nothing else;
  - `cohort_target_id: <family key>` returns exactly that family's row;
  - the two axes AND with each other and with the existing axes (window, tier, attester) rather than overwriting them;
  - a filter naming a room the caller is **not** in returns nothing even though the row is on disk — the §4.3 gate, not the filter, is what refuses;
  - the page is resumable: `limit: 1` twice with the returned cursor yields the second row and no repeat.
  - Witnesses: `i142_the_drive_query`, `i142_scores_the_axis_on_the_scores_plane` (`src/ceg/list/drive_query_invariants.rs`).
  - Mutants: drop the `cohort_scope` predicate (self query returns everything); drop `cohort_target_id` (the other room's row appears); OR the two instead of ANDing (a federation row appears in the self query); apply the axis before the scope gate (the not-a-member room's row appears).
- **I143** (from disk + sqlite/postgres two-node) — **the chunk adopt reaches Python.** From disk: `adopt_sealed_chunk_json` is present in `ffi/pyo3.rs` and classified in the taxonomy. Two-node: A appends a sealed chunk at `self` and seals the stream; B — the owner's other node — adopts the chunk through the Engine door with the author's provenance and `read_stream_chunk_as` opens it. Witness: `i143_the_chunk_adopt_reaches_python`. Mutant: the binding drops the provenance's author (the adopt admits a chunk the caller is not party to).

## 4.1 Mutation table

| Mutant | Verdict |
|---|---|
| M1 sqlite drops the cohort_scope predicate | KILLED by sqlite `i142` |
| M2 postgres drops the cohort_scope predicate | KILLED by postgres `i142` (under `scripts/pg_test_db.sh`) |
| M5 the chunk binding is unreachable | KILLED by `i143` |

The postgres leg must run under `scripts/pg_test_db.sh`. Without a DSN it returns early, prints `ok` in 0.00 s, and reports a mutant as surviving when it was never exercised.

## 5. Not in scope

- A filter on `list_attestations_since`. It is the replication door; a filtered, ungated read is the shape §2 keeps apart.
- A gap-free *listing* cursor (an `admitted_at`-ordered filtered read). Catch-up semantics over a filtered set would be a third door with its own issue.
- The bulk owned-nodes read — tracked separately (#890).
