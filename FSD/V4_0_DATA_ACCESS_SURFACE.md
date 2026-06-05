# FSD: CIRISPersist v4.0 — Data Access Surface

**Status:** Proposed (FSD lockdown — implementation gated on user approval)
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.7
**Created:** 2026-06-05
**Repo:** `~/CIRISPersist`
**Risk:** Cut release. Hard break — every consumer (CIRISLens, CIRISLensCore, sovereign-mode agent, CIRISBridge, CIRISNodeCore, sister repos) must update to the v4.0 API. No deprecation window, no aliases. Eric notifies the sisters and federation on cut; downstream PRs land against v4.0.
**Upstream issues:** CIRISPersist#159 (`get_repository_statistics`), CIRISPersist#135 (attestation listing by target), CIRISPersist#150 (cohort_scope read-side honesty), CIRISLens#mock-routing-removal, CIRISEdge#48-A (consumer-side cohort_scope check).
**Replaces / supersedes:** the v3.x ad-hoc surface of `list_*`, `aggregate_*`, scattered `Backend::fetch_*` methods, and the proposal in #159 to ship sqlite NotImplemented.

---

## 0. TL;DR for reviewers

v4.0 reorganizes the persist read surface around four primitives — **CallerScope**, **Filter**, **Aggregate**, **Cache** — and reorganizes the module tree under topic-named CEG namespaces. Every read primitive becomes scope-aware; every aggregate becomes cache-aware; both backends implement everything in the same cut. The cut also ships the `federation_communities` substrate (V060) so the lens-trace community flow — agent + bootstrap servers form a community, lens-capable peers receive traces via `service_announcement` discovery (NodeCore SCHEMA §4.23) and edge `ServiceRequest` delivery — has end-to-end substrate support, not just a label. The driving consumer is CIRISLens' `get_repository_statistics` (#159), but the surface lands as a substrate-wide capability that any federation consumer — lens, bridge, node-core, sovereign-mode agent — uses identically. Edge backs persist as a second, independent enforcement layer for cohort_scope (CEG 0.10 §10.1.4 structural invisibility); persist refuses if edge fails open, edge refuses if persist fails open — defense in depth.

---

## 1. Why this exists — the mission case

### 1.1 The driving observation

The v3.x read surface (`src/read/`) grew per-consumer: `list_trace_summaries` for lens dashboards, `aggregate_scoring_factors` for Coherence Ratchet, `corpus_shape` for `scripts/corpus_shape.py`, `list_federation_keys` for federation observability. Each landed honestly — typed filter struct + cursor + page result. But three structural problems compounded as the surface grew:

1. **Scope is implicit.** Every primitive returns everything the backing tables contain. CEG 0.10 §10.1.4 (structural-invisibility for `cohort_scope: self|family` content) is enforced *upstream* at CIRISEdge#48-A — a consumer-side check that filters at egress. The substrate has no first-class scope concept; if a consumer forgets to apply the cohort gate, persist returns the wrong rows. **A single substrate-side gate is missing.**
2. **Aggregates are one-shot.** Every `aggregate_*` recomputes from the raw rows on every call. A Coherence Ratchet dashboard refreshing every 30s re-runs the same windowed scan against `trace_events`. v3.x has no cache primitive — a consumer either bolts on its own (lens does, via FastAPI middleware) or eats the cost.
3. **Filtering is non-composable.** `TraceFilter`, `LlmCallFilter`, `AttestationFilter` are parallel structs with overlapping fields (`agent_id_hash`, `deployment_domain`, time windows). No shared filter primitive; no way to layer cohort_scope on top.

The #159 ask (`get_repository_statistics(filter, scope)`) makes all three structural problems visible in one call. Filter + scope + aggregate + cache — and the result feeds a UI that's repaint-sensitive. Fixing #159 in isolation papers over the structural shape. **Fixing the structural shape lets every future read primitive — and there will be more, the federation is young — slot in.**

### 1.2 Alignment against MISSION.md

This is not feature-add; it's substrate-shape work. Each pillar:

- **Mission (§1.1 — Justice + Integrity)** — A federation peer running on a Raspberry Pi or iPhone needs to query its own repository's statistics under the same scope discipline as a datacenter peer. The DAS is one shape across every deployment tier (§1.5 parity); the cache substrate makes "this peer cannot afford to re-aggregate on every dashboard repaint" not be the same as "this peer is degraded."
- **Mission (§1.2 — N_eff measurement)** — Statistics and aggregates ARE the corpus measurement. `pass_rate`, `override_rate`, `fragile_trace_rate` are the numerators of ρ. If the aggregate substrate silently coerces (cache returns stale data without saying so; sample_count is elided when small; scope leaks suppressed content into an Unauthenticated caller) the measurement is corrupted at the load-bearing layer.
- **Apophatic bound (§1.4 — not a columnar engine)** — The DAS is a *fixed*, named, query-shaped surface. Covering indexes (V042 lineage; V060 v4.0 cut adds scope predicates + `federation_communities`). It deliberately is not an OLAP layer — no ad-hoc SQL, no caller-composed projections, no JSONPath. Consumers pick a primitive; the substrate runs the named query.
- **Relational fabric, not Cartesian gate (§1.7)** — `CallerScope::Authenticated { admission }` is *recorded admission*, not *adjudicated admission*. Identity, family memberships, and community memberships are resolved from `federation_identity_occurrences` / `federation_families` / `federation_communities` — what the chain has admitted — and the substrate applies them. The substrate doesn't decide who is "really" a peer, who is "really" in a family, or who is "really" in a community; it applies the policy the federation chain expresses.
- **Fail-honest (§1.6)** — The cache substrate reports `cache_hit: bool` and `evaluated_at: i64` on every aggregate result. A stale read is *labelled stale*, not silently served. `sample_count` is on every aggregate — small-N is *labelled small*, never hidden. AV-43 k-anonymity is the consumer's policy; the substrate gives the consumer the count to enforce it.
- **Parity (§1.5)** — Both backends implement every v4.0 primitive in the cut. SQLite uses correlated subqueries where Postgres uses a CTE. The shape of the answer is identical; the wall-clock differs. **No NotImplemented for sqlite.** This explicitly invalidates the v3-era proposal in #159's first draft to ship sqlite NotImplemented.

### 1.3 Why a 4.0 (not a 3.15)

Six structural changes land together:

1. **Module reorganization** — `src/read/` modules rehome under topic-named `src/ceg/` namespaces. Public paths change.
2. **CallerScope** added to every CEG-protected read trait method. Trait signatures change.
3. **Cache primitive** lands as a first-class substrate concept (`src/cache/`). New module.
4. **Filter trait** replaces per-surface `*Filter` structs. Filter struct shapes change (back-compat-incompatible for callers building filters by struct-literal).
5. **PyO3 method signatures** gain a `scope: str` parameter at every CEG-protected entry point. Python callers update at the call site.
6. **The `prelude` reshapes** — re-exports follow the new module tree.

Each of these alone is a soft break the team has absorbed in a minor before. **All six together is a 4.0** — and the per-issue feedback (`feedback_clean_break_renames`, `feedback_rename_consistency`, `feedback_no_pg_only_no_deferral`) lines up: one cut, no aliases, internal+external renamed together, both backends implement everything. Eric explicitly directed "hard cut, just roll 4.0 and I will notify the sisters and federation to move."

---

## 2. Scope

### 2.1 In scope for v4.0 (the cut)

| Surface | Concrete deliverable |
|---|---|
| **Module reorg** | `src/read/{trace,task,llm,scoring,scrub,corpus,federation,types}.rs` → topic-named `src/ceg/{cohort_scope,identity,family,community,structural_invisibility,streaming,aggregates,list,types}/*.rs`; CEG version provenance lives in each module's header doc. `src/read/mod.rs` is removed in v4.0 |
| **CallerScope primitive** | `src/scope/caller.rs` — `CallerScope::{Unauthenticated, Authenticated { admission: CallerAdmission }}` enum. Two variants; the federation cohorts (self / family / community) are NOT enum variants — they are *admission resolutions* on the `Authenticated` caller's occurrence key |
| **CallerAdmission** | `{ occurrence_key_id, identity_key_id, family_key_ids, community_key_ids }` — substrate-built by resolving the caller's occurrence key through `federation_identity_occurrences` (V059) + `federation_families` (V059) + `federation_communities` (V060 this cut). Never caller-asserted |
| **`federation_communities` substrate (V060)** | Analogous to `federation_families` (V059) but with §8.1.13.3 NO-suppression semantics. New table + `put_community` / `lookup_community` / `list_communities_for_member` trait methods on `FederationDirectory` |
| **SQL helper** | `cohort_scope_sql_predicate(backend, table_alias, emitter_key_col, scope_col, &CallerScope) -> (String, Vec<Param>)` — emits the WHERE-fragment + JOIN clauses for identity / family / community admission. Postgres uses `EXISTS` against `federation_identity_occurrences` / `federation_families` / `federation_communities`; sqlite uses the same shape with json_each / json_extract |
| **Filter trait** | `trait Filter` — composable over time windows, agent ids, deployment domains, cohort scope; concrete `RepositoryFilter`, `TraceFilter`, `LlmCallFilter`, `AttestationFilter` implement it |
| **Aggregate trait** | `trait Aggregate` — every aggregate result carries `sample_count: i64`, `evaluated_at_unix_ms: i64`, `cache_hit: bool` |
| **Cache primitive** | `src/cache/` — generic, TTL-bounded, key-derived-from-(method, filter, scope), backend-agnostic, in-process. Hit-rate observable; eviction is explicit; staleness is reported. SizeBound + TTL bound; LRU eviction. No external cache (no Redis); no distributed cache (this is library-local) |
| **`ReadEngine` v2 trait** | Every method takes `&CallerScope`; every aggregate goes through cache helper |
| **`get_repository_statistics`** | The #159 primitive — `RepositoryStatistics { period, totals, scores, conscience, actions, fragility, by_domain }` — both backends, scope-gated, cache-aware |
| **`list_attestations_for`** | #135 + part of #150 — `(target_key_id, scope) → page` — substrate-side scope honesty |
| **PyO3 v2 surface** | `Engine.get_repository_statistics(filter, scope)`, `Engine.list_attestations_for(target, scope)`, `Engine.cache_stats() → CacheStats` |
| **Migration V060** | (a) `federation_communities` table — the §8.1.13.3 community substrate; (b) scope-aware covering indexes on `trace_events.cohort_scope`, `federation_attestations.cohort_scope` + emitter_key joins to `federation_identity_occurrences` / `federation_families` / `federation_communities` |
| **THREAT_MODEL.md** | New AV-44 (scope-escalation via caller assertion) — mitigation: admission set built by substrate from `federation_keys`, never caller-asserted |

### 2.2 Out of scope for v4.0 (named, not deferred)

- **No distributed cache** — local-process LRU only. A federation peer wanting cross-node statistics builds it from per-node DAS calls. (Federation is the trust boundary; persist does not aggregate across peers.)
- **No ad-hoc SQL** — DAS is the *fixed query set* per §1.4 apophatic bound. The substrate refuses to be a columnar engine.
- **No caller-composed projections** — every primitive returns its named shape; no `SELECT only these fields`. Consumers receive the full named struct and pick the fields they want at their layer.
- ~~**No write-path scope.**~~ **Reversed (CIRISPersist#160 review, comment 4):** v4.0 now closes the write-side too. The earlier "v4.0 is read-surface only" posture left AV-45 (write-side cohort_scope downgrade) as an open forge surface, which structurally collapses §9's defense-in-depth claim on the write side — edge's Layer 2 can only catch what Layer 1 missed, and with no Layer 1 on writes a downgraded `cohort_scope: federation` row is admissible to every Unauthenticated reader under the §4.3 predicate. Closing AV-44 by construction while leaving AV-45 open is asymmetric in a way the cut posture explicitly rejects.

  The fold is small (reviewer's split (a)): extend `DimensionAdmissionPolicy` (`src/federation/admission.rs`) with one cohort_scope predicate using the same `CallerAdmission` primitive `CallerScope::Authenticated` already carries. See §4.6 for shape. v4.0 lands as: AV-44 closed (read-side, §4.3), **AV-45 closed (write-side, §4.6)**, joint defense-in-depth complete on both sides.
- **No third CallerScope variant.** `CallerScope` expresses *who is asking* (two variants: Unauthenticated, Authenticated). The CEG cohort vocabulary `{self, family, community, affiliations, species, biosphere, federation}` lives on *rows*, not on callers. A sovereign-mode agent is an `Authenticated` caller whose `CallerAdmission.identity_key_id` is its own identity and whose family/community sets reflect what the federation chain has admitted.

- **No peer-capability table added by v4.0.** Peer capabilities are already first-class as the `service_announcement` Contribution subject_kind (NodeCore SCHEMA §4.23). Capability advertisement is a *routing* primitive (used by NodeCore + CIRISEdge to discover who to send what to); persist's CallerScope is a *visibility* primitive (admission to read what's already stored). The two are deliberately separate — capabilities don't appear in persist's read predicate.

### 2.3 Backend parity — both ship in the cut

Per MISSION.md §6 anti-pattern #4. Both backends implement every primitive in this FSD by v4.0 tag. Performance characteristics may differ:

- **Postgres** — single CTE for `get_repository_statistics`; covering index lookups on V060; ~5–15ms p50 for 7-day window on a 1M-trace tenant.
- **SQLite** — correlated subqueries or a sequence of small queries combined in Rust; covering indexes shape the same; ~30–80ms p50 for the same window on the same tenant.

Performance asymmetry is *characterized*, not labelled as a defect. A Raspberry Pi peer running SQLite gets honest 30–80ms statistics; that is a first-class deployment tier. The DAS spec includes a perf table in `docs/PUBLIC_SCHEMA_CONTRACT.md` (updated this cut).

---

## 3. Module reorganization — CEG topic namespaces

### 3.1 The principle

The CEG (Coherence Epistemic Graph) is the federation's living protocol; persist tracks it through topic-named modules under `src/ceg/`. Each module's header documents the CEG version that introduced the construct (e.g. "CEG 0.4 cohort_scope wire format; admission-gate semantics added 0.10 §10.1.4"). Topic axis ages better than version axis as the CEG accumulates — version provenance lives in module docs and `git log`, not in directory names.

```
src/
  ceg/
    mod.rs                       # façade — re-exports CallerScope, Filter, Aggregate, ReadEngine
    cohort_scope/                # CEG 0.4 wire-format + 0.10 admission semantics
      mod.rs
      classification.rs          # suppresses_holds_bytes, closed-set validation
      predicate.rs               # the §4.3 SQL predicate
    identity/                    # CEG 0.7 §5.6.8.8 identity_occurrence reads
      mod.rs
      occurrence.rs
    family/                      # CEG 0.7 §5.6.8.9 family reads
      mod.rs
    community/                   # CEG 0.10 §8.1.13.3 community reads (V060)
      mod.rs
    structural_invisibility/     # CEG 0.10 §10.1.4 — the read-side gate
      mod.rs
    streaming/                   # CEG 0.10 streaming attestation reads
      mod.rs
    aggregates/
      repository.rs              # get_repository_statistics
      llm.rs                     # aggregate_llm_costs
      scoring.rs                 # aggregate_scoring_factors
      scrub.rs                   # aggregate_scrub_stats
      corpus.rs                  # corpus_shape
    list/
      traces.rs                  # list_trace_summaries + get_trace_summary + get_trace_detail
      tasks.rs                   # list_tasks
      llm.rs                     # list_llm_calls
      federation.rs              # list_federation_keys + list_attestations + list_attestations_for + list_revocations
    types/
      filter.rs                  # Filter trait + shared filter primitives
      aggregate.rs               # Aggregate trait + sample_count discipline
      cursor.rs                  # TraceCursor + other cursor types
      window.rs                  # TimeWindow
  scope/
    caller.rs                    # CallerScope enum
    admission.rs                 # CallerAdmission + build_caller_admission
    sql.rs                       # cohort_scope_sql_predicate
  cache/
    mod.rs                       # public substrate cache surface
    lru.rs                       # bounded LRU implementation
    key.rs                       # cache key derivation (filter + scope + method → digest)
    stats.rs                     # CacheStats observability
```

### 3.2 Façade and prelude

`src/ceg/mod.rs` re-exports the namespace contents through a flat surface. `crate::prelude` exposes `CallerScope`, `Filter`, `Aggregate`, `ReadEngine`, `RepositoryStatistics`, and the cursor / window types directly.

The topic subpath is documentation of subject area; the flat re-export is what consumers use. CEG version provenance lives in each module's header doc — `git log` answers "when did this land?"

### 3.3 What moves where

| v3.x location | v4.0 location |
|---|---|
| `src/read/trace.rs::TraceSummary, TraceDetail, …` | `src/ceg/list/traces.rs` |
| `src/read/trace.rs::DivergenceRow, TemporalDriftRow, OverrideRateRow, HashChainGap` | `src/ceg/aggregates/scoring.rs` |
| `src/read/llm.rs` | `src/ceg/list/llm.rs` + `src/ceg/aggregates/llm.rs` |
| `src/read/scoring.rs` | `src/ceg/aggregates/scoring.rs` |
| `src/read/scrub.rs` | `src/ceg/aggregates/scrub.rs` |
| `src/read/corpus.rs` | `src/ceg/aggregates/corpus.rs` |
| `src/read/federation.rs` | `src/ceg/list/federation.rs` |
| `src/read/task.rs` | `src/ceg/list/tasks.rs` |
| `src/read/types.rs::TimeWindow, TraceCursor, TraceFilter, DeviationMetric` | `src/ceg/types/{window,cursor,filter}.rs` |

`src/read/mod.rs` is **removed** in v4.0. Consumers re-import from `ciris_persist::ceg::*` or `ciris_persist::prelude::*`. The `src/federation/` module is **not** moved — federation directory primitives (`federation_keys`, `federation_identity_occurrences`, `federation_families`, `federation_communities`) stay there; the `src/ceg/` namespace is the *read-surface* reorganization. `src/ceg/community/`, `src/ceg/family/`, `src/ceg/identity/` *consume* the federation substrate via trait methods, they don't replace it.

---

## 4. CallerScope — the scope substrate

### 4.1 Shape

```rust
// src/scope/caller.rs

#[derive(Clone, Debug)]
pub enum CallerScope {
    /// Unauthenticated reader. Admits rows tagged cohort_scope ∈
    /// {community, affiliations, species, biosphere, federation} —
    /// the non-suppressed tiers per §8.1.13.3. Refuses self + family
    /// (cohort_scope::suppresses_holds_bytes returns true for those).
    Unauthenticated,

    /// Authenticated caller. Admission is *substrate-built* from
    /// the caller's occurrence key — never caller-asserted (§4.2,
    /// THREAT_MODEL AV-44). Self/family/community are NOT
    /// enum variants; they are admission *resolutions* on the
    /// caller's identity.
    Authenticated {
        admission: CallerAdmission,
    },
}
```

```rust
// src/scope/admission.rs

#[derive(Clone, Debug)]
pub struct CallerAdmission {
    /// The caller's occurrence key — the literal signing key they
    /// presented at the boundary. The only field the caller has any
    /// agency over; everything else below is substrate-resolved.
    pub occurrence_key_id: KeyId,

    /// The caller's IDENTITY — resolved via
    /// federation_identity_occurrences (V059 §5.6.8.8).
    /// "Lookup occurrence_key_id → identity_key_id."
    /// Singleton fallback: when the occurrence key is not bound
    /// (i.e. not yet declared as an occurrence of any identity),
    /// the caller IS its own identity (occurrence == identity).
    pub identity_key_id: KeyId,

    /// Every family the caller's IDENTITY is a member of —
    /// resolved via list_families_for_member(identity_key_id)
    /// against federation_families (V059 §5.6.8.9).
    /// Members are IDENTITY keys, NOT occurrence keys.
    pub family_key_ids: BTreeSet<KeyId>,

    /// Every community the caller's IDENTITY is a member of —
    /// resolved via list_communities_for_member(identity_key_id)
    /// against federation_communities (V060 this cut).
    /// Same identity-keys-as-members shape as families.
    pub community_key_ids: BTreeSet<KeyId>,
}

/// Build the admission set for a caller from their occurrence key.
/// Substrate-side helper — the SOLE way to construct a
/// `CallerAdmission`. The struct's constructor is crate-private.
pub async fn build_caller_admission(
    engine: &Engine,
    occurrence_key_id: &KeyId,
) -> Result<CallerAdmission, AdmissionError> { ... }
```

### 4.2 Why this is a recording boundary, not a Cartesian gate

Per MISSION.md §1.7 — substrate doesn't arbitrate whether the self the chain describes is "real." Identity, family membership, and community membership are *what the federation chain has admitted*; the substrate reads these from `federation_identity_occurrences` / `federation_families` / `federation_communities` and applies the closure as a SQL predicate.

The substrate's job:

- **Resolve** the caller's admission deterministically from the chain (identity-occurrence lookup → family membership lookup → community membership lookup).
- **Apply** the resulting predicate to read primitives.
- **Refuse** caller-asserted admission — `CallerAdmission` has no public constructor; only `build_caller_admission(engine, occurrence_key_id)` produces one. The struct fields are `pub` for read-only access by the SQL helper, but construction is crate-private.

The PyO3 boundary takes the *occurrence key id* (a string) and nothing else admission-related. The substrate resolves identity + families + communities itself. AV-44 in THREAT_MODEL.md: a Python caller cannot forge `Authenticated { admission: { everything } }` by constructing the struct — there is no public constructor.

### 4.3 The SQL predicate

```rust
// src/scope/sql.rs

/// Emit the SQL fragment + params enforcing read-side cohort_scope
/// admission for the given caller scope. The fragment AND-composes
/// into the caller's WHERE. Returns the fragment + bind params,
/// matching backend dialect (`->>` for PG / `json_extract` for SQLite).
pub fn cohort_scope_sql_predicate(
    backend: BackendKind,
    table_alias: &str,
    emitter_key_col: &str,    // e.g. "scrub_key_id" or "author_key_id"
    scope_col: &str,          // e.g. "cohort_scope" (TEXT) or a JSON path
    scope: &CallerScope,
) -> (String, Vec<ScopeParam>);
```

Conceptual shape, both backends:

**Unauthenticated** — `<scope_col> IN ('community','affiliations','species','biosphere','federation')`

**Authenticated { admission }** — admits a row when ANY of:

```sql
-- broadly-visible tiers — any authenticated caller passes
<scope_col> IN ('community','affiliations','species','biosphere','federation')

-- self — caller's identity == emitter's identity
OR (<scope_col> = 'self' AND EXISTS (
  SELECT 1
    FROM federation_identity_occurrences io_e
   WHERE io_e.occurrence_key_id = <emitter_key_col>
     AND io_e.identity_key_id   = $caller_identity_key_id
))

-- family — caller's identity ∈ same family as emitter's identity
OR (<scope_col> = 'family' AND EXISTS (
  SELECT 1
    FROM federation_families f
    JOIN federation_identity_occurrences io_e
      ON io_e.occurrence_key_id = <emitter_key_col>
   WHERE f.family_key_id = ANY($caller_family_key_ids)
     AND f.members @> jsonb_build_array(
           jsonb_build_object('key_id', io_e.identity_key_id)
         )                          -- PG; sqlite uses json_each
))

-- community — symmetric to family against federation_communities
OR (<scope_col> = 'community' AND EXISTS (
  SELECT 1
    FROM federation_communities c
    JOIN federation_identity_occurrences io_e
      ON io_e.occurrence_key_id = <emitter_key_col>
   WHERE c.community_key_id = ANY($caller_community_key_ids)
     AND c.members @> jsonb_build_array(
           jsonb_build_object('key_id', io_e.identity_key_id)
         )
))
```

The community branch is the lens-trace path: a lens-capable peer's identity sits in the agent's community; lens-cohort rows the agent stored land at the peer when the peer reads — without persist needing to know "lens" as a routing concept. Routing happened upstream (NodeCore `service_announcement` discovery + Edge `ServiceRequest`); persist applies the visibility predicate the cohort label expresses.

### 4.4 The singleton-identity fallback

A peer whose occurrence key has not yet been bound as an `IdentityOccurrence` (a fresh sovereign deployment, an embedded device whose first transmission predates any binding) is its own identity: `identity_key_id = occurrence_key_id`, `family_key_ids = {}`, `community_key_ids = {}`. They see broadly-visible tiers + their own `self`-cohort rows (because emitter and caller occurrence keys both resolve to the same identity — themselves).

This is the sovereign-mode posture in concrete form: no occurrence binding, no families, no communities → just self-cohort visibility on their own emissions. No special enum variant needed.

### 4.5 Performance posture (Path A vs Path B)

The §4.3 predicate is JOIN-heavy. Two implementation choices:

- **Path A (v4.0 default)** — query-time joins against `federation_identity_occurrences` / `federation_families` / `federation_communities`. Indexable on `(occurrence_key_id)` + `(identity_key_id)` + `(family_key_id)` + `(community_key_id)`. Correct, honest, slower on big tenants.
- **Path B (v4.1+ perf cleanup)** — precomputed materialized projection: per-row `admitted_identity_key_id` denormalized at insert (substrate maintains alongside the row). Query-time becomes `WHERE admitted_identity_key_id = $caller_identity OR scope IN (...)`. Fast read; complicates writes; requires backfill at landing.

v4.0 ships Path A. Path B is named-not-deferred per `feedback_no_pg_only_no_deferral` — tracked issue at v4.0 tag.

### 4.6 Write-path admission — AV-45 closure (v4.0)

The same `CallerAdmission` primitive `CallerScope::Authenticated` carries on the read side admits a one-predicate extension on the write side. At write time, the writer's claimed cohort_scope must be consistent with what their admission permits emitting:

```rust
// src/federation/admission.rs — DimensionAdmissionPolicy extension

impl DimensionAdmissionPolicy {
    /// AV-45 closure — writer's claimed cohort_scope must be permitted
    /// by their admission. Called from put_attestation, the trace
    /// ingest pipeline (verify-before-persist gate, MISSION §4), and
    /// every other write path that stores rows carrying a cohort_scope.
    ///
    /// Returns Err(ScopeRefused(...)) when the write attempts to
    /// downgrade — e.g. claims cohort_scope: federation on content
    /// the writer's admission can only emit at cohort_scope: self.
    pub fn check_write_cohort_scope(
        writer_admission: &CallerAdmission,
        emitter_key_id: &KeyId,
        claimed_cohort_scope: &str,
    ) -> Result<(), ScopeRefusalReason> {
        match claimed_cohort_scope {
            // Self — writer's identity must own the emitter occurrence.
            "self" => {
                let emitter_identity = lookup_identity_for_occurrence(emitter_key_id)?;
                if emitter_identity != writer_admission.identity_key_id {
                    return Err(ScopeRefusalReason::WrongIdentity);
                }
                Ok(())
            }

            // Family — writer's identity must share a family with the emitter's.
            "family" => {
                let emitter_identity = lookup_identity_for_occurrence(emitter_key_id)?;
                let shared = writer_admission.family_key_ids.iter().any(|fid| {
                    family_contains(fid, &emitter_identity)
                });
                if !shared {
                    return Err(ScopeRefusalReason::NoFamilyMembership);
                }
                Ok(())
            }

            // Community — symmetric.
            "community" => { /* identical shape against community_key_ids */ }

            // Broader tiers — no further check; non-suppressed per §8.1.13.3.
            // ANY authenticated writer may emit at these tiers; the chain
            // counter-signs at the federation layer (CIRISVerify hybrid sigs).
            "affiliations" | "species" | "biosphere" | "federation" => Ok(()),

            other => Err(ScopeRefusalReason::InvalidCohortScope(other.to_string())),
        }
    }
}
```

**Where it lands at write time:**

| Write path | Gate location |
|---|---|
| `Engine::receive_and_persist` (trace ingest) | After verify, before scrub — the writer's admission is built from `scrub_key_id` (the Ed25519-verified signer of the envelope); the trace's emitted `cohort_scope` is checked against the writer's admission |
| `put_attestation` | Same pattern — `attesting_key_id` is the writer identity |
| `put_identity_occurrence` / `put_family` / `put_community` | Self-admission writes — writer is the authority for the row's subject; no cohort_scope downgrade concept applies |
| `put_revocation` / `put_takedown_notice` | Author's admission must permit emission at the revocation's cohort_scope (mirrors the source content's scope) |
| Internal substrate writes (chain anchors, migrations) | No admission needed — substrate is its own authority for these |

**Why the closure is light:**

- The substrate already has the writer identity at write time (the verified envelope signer); no new auth surface.
- The `CallerAdmission` resolution path is the same as read-side; one builder, used in both directions.
- The cohort_scope vocabulary is closed; the dispatch is a 7-arm match.
- AV-45 closes by the same construction discipline as AV-44 — typed admission, substrate-built, predicate at the boundary.

**Defense in depth (§9) on the write side:** Layer 1 is `check_write_cohort_scope` at substrate; Layer 2 is edge's pre-ingest verification that the wire-format envelope's claimed cohort_scope matches the routing the writer used. Joint `cohort_scope_write_double_miss_total` mirrors the read-side alert.

### 4.7 Performance headroom — Path A vs Path B

**Estimated perf headroom Path B leaves on the table** (so the v4.1 deferral is calibrated, not vague):

| Backend | Path A (v4.0 ships) | Path B (v4.1+ deferred) |
|---|---|---|
| Postgres | 5–15 ms p50 (1M-trace 7d window) | sub-millisecond p50 (covering-index single fetch) |
| SQLite | 30–80 ms p50 (same corpus) | 5–10 ms p50 (denormalized projection, single scan) |

The lens dashboard refresh budget (15s) makes Path A non-blocking at v4.0 for current corpora. Path B's value scales with corpus size: at 10M+ traces, Path A's CTE-join becomes the dominant repaint cost; v4.1 timing is gated on when that crossover hits in production.

---

## 5. Filter — the filtering substrate

### 5.1 The trait

```rust
// src/ceg/types/filter.rs

/// Filter primitives — composable shapes substrate read primitives
/// accept. Each primitive defines its own concrete filter (e.g.
/// RepositoryFilter, TraceFilter); the trait exists to unify
/// time-window + scope + agent-id-hash shape across them.
pub trait Filter {
    fn window(&self) -> &TimeWindow;
    fn agent_id_hashes(&self) -> &[String];
    fn deployment_domains(&self) -> &[String];
    fn cohort_scope_in(&self) -> &[String];

    /// Cache-key digest — used by the cache substrate to derive
    /// `CacheKey`. The default implementation hashes
    /// `(TypeId, window, agent_id_hashes, deployment_domains,
    /// cohort_scope_in)`.
    ///
    /// **The default impl is correct ONLY when an implementer's
    /// discriminating state is fully captured by the five fields
    /// above.** Filters with additional fields that change query
    /// results — `task_classes`, `fragility_only`, `model_substring`,
    /// any future discriminator — MUST override this method to fold
    /// those fields into the hash. The parity suite enforces this
    /// (`parity_cache_key_disjoint_per_filter_field` in §14)
    /// — every concrete `Filter` impl is constructed with every
    /// discriminating-field variant and the resulting digests must
    /// be pairwise-distinct. A new impl that adds a discriminator
    /// without overriding fails the parity test.
    fn cache_key_digest(&self) -> [u8; 32] { ... }
}
```

Concrete filter structs (one per primitive) implement `Filter`. The trait does not let consumers compose arbitrary filters — it lets the substrate write *one* cache helper and *one* scope helper that work across every primitive.

### 5.2 RepositoryFilter (driver for #159)

```rust
pub struct RepositoryFilter {
    pub window: TimeWindow,
    pub agent_id_hashes: Vec<String>,        // empty = all agents
    pub deployment_domains: Vec<String>,     // empty = all domains
    pub cohort_scope_in: Vec<String>,        // empty = scope-default
    pub task_classes: Vec<TaskClass>,        // empty = all classes — discriminator
    pub fragility_only: bool,                // CEG 0.5+ fragility filter — discriminator
}

impl Filter for RepositoryFilter {
    fn window(&self) -> &TimeWindow { &self.window }
    fn agent_id_hashes(&self) -> &[String] { &self.agent_id_hashes }
    fn deployment_domains(&self) -> &[String] { &self.deployment_domains }
    fn cohort_scope_in(&self) -> &[String] { &self.cohort_scope_in }

    /// MUST override — task_classes + fragility_only are
    /// discriminators not captured by the default impl.
    fn cache_key_digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"RepositoryFilter:v4.0");
        // base fields
        h.update(&self.window.to_canonical_bytes());
        for a in &self.agent_id_hashes { h.update(a.as_bytes()); h.update(b"\0"); }
        for d in &self.deployment_domains { h.update(d.as_bytes()); h.update(b"\0"); }
        for s in &self.cohort_scope_in { h.update(s.as_bytes()); h.update(b"\0"); }
        // discriminators
        for c in &self.task_classes { h.update(c.as_str().as_bytes()); h.update(b"\0"); }
        h.update(&[self.fragility_only as u8]);
        *h.finalize().as_bytes()
    }
}
```

---

## 6. Aggregate — the statistics substrate

### 6.1 The trait

```rust
// src/ceg/types/aggregate.rs

/// Every aggregate result carries these invariants. The substrate
/// fails honest (§1.6): small-N is labelled, staleness is labelled.
pub trait Aggregate {
    /// **Top-level sample count.** Number of rows in the scope-filtered
    /// windowed set — the "denominator" of the question the aggregate
    /// answers. For `RepositoryStatistics` over a 7-day window, this is
    /// the count of distinct traces visible to the caller's scope after
    /// the §4.3 predicate is applied.
    ///
    /// This is NOT necessarily the count contributing to every nested
    /// sub-aggregate. See §6.3 — nested aggregates carry their own
    /// `sample_count` for the sub-population that contributed to *that*
    /// statistic. A 1M-trace window where 800K rows have non-null
    /// plausibility scores produces `top_level.sample_count = 1M` and
    /// `top_level.scores.plausibility.sample_count = 800K`.
    ///
    /// AV-43 k-anonymity: every aggregate (top-level and nested) exposes
    /// this so the consumer applies its threshold at the level matching
    /// the question. Never elided. Zero is honest.
    fn sample_count(&self) -> i64;

    /// Unix milliseconds when the aggregate was computed against the
    /// backend. With cache_hit=true, this is the cached evaluation
    /// time, NOT the current time.
    fn evaluated_at_unix_ms(&self) -> i64;

    /// True iff this result came from the cache. False = fresh DB read.
    /// Caller decides whether staleness matters; substrate reports it.
    fn cache_hit(&self) -> bool;
}
```

### 6.2 RepositoryStatistics (#159 shape, MISSION-aligned)

```rust
pub struct RepositoryStatistics {
    pub period: TimeWindow,
    pub totals: Totals,
    pub scores: ScoreAggregates,
    pub conscience: ConscienceAggregates,
    pub actions: ActionAggregates,
    pub fragility: FragilityAggregates,
    pub by_domain: Vec<DomainBreakdown>,

    /// Per Aggregate trait — load-bearing for AV-43 and cache observability.
    pub sample_count: i64,
    pub evaluated_at_unix_ms: i64,
    pub cache_hit: bool,
}

pub struct Totals { pub traces: i64, pub agents: i64, pub domains: i64 }

pub struct ScoreAggregates {
    pub plausibility: ScoreDistribution,
    pub alignment: ScoreDistribution,
}

pub struct ScoreDistribution {
    pub mean: f64,
    pub std: f64,
    pub p50: f64,
    pub p95: f64,
    pub sample_count: i64,  // always present, never elided
}

pub struct ConscienceAggregates {
    pub pass_rate: f64,
    pub override_rate: f64,
    pub by_check: BTreeMap<String, ConsciencePerCheck>,
    pub sample_count: i64,
}

pub struct ActionAggregates {
    /// HDMA action histogram — SPEAK/TOOL/MEMORIZE/RECALL/DEFER/REJECT/PONDER/OBSERVE
    pub distribution: BTreeMap<String, f64>,
    pub success_rate: f64,
    pub sample_count: i64,
}

pub struct FragilityAggregates {
    pub fragile_trace_rate: f64,
    /// CEG 0.5+ phase enum histogram
    pub phase_distribution: BTreeMap<String, f64>,
    pub sample_count: i64,
}

pub struct DomainBreakdown {
    pub domain: String,
    pub traces: i64,
    pub avg_plausibility: f64,
    pub avg_alignment: f64,
    pub sample_count: i64,
}
```

### 6.3 `sample_count` — top-level vs nested contract

Every `sample_count` answers a different question. Consumers applying AV-43 k-anonymity must apply the threshold at the level matching the question they're answering. The contract is **explicit**, not implicit:

| Field | Meaning | Excludes |
|---|---|---|
| `RepositoryStatistics.sample_count` | Rows in the scope-filtered windowed set (the "1M traces this window contains, after scope") | Suppressed-cohort rows the caller cannot see |
| `Totals.traces` | Same as above when filter has no further discrimination | — |
| `Totals.agents` / `Totals.domains` | Distinct counts (never sample sizes) | — (not sample counts) |
| `ScoreDistribution.sample_count` | Rows contributing to *this* distribution — i.e. rows in the windowed set whose corresponding score field is non-NULL and schema-valid | NULL plausibility/alignment, schema-version-mismatch rows that were window-counted but score-skipped |
| `ConscienceAggregates.sample_count` | Rows with a conscience check recorded (non-NULL `conscience_passed` AND non-empty `conscience_checks` array) | Rows where conscience was skipped (e.g. early-bail in DMA) |
| `ConsciencePerCheck.sample_count` (inside `by_check`) | Rows where THIS check ran (more granular than envelope-level) | Rows where this specific check was disabled |
| `ActionAggregates.sample_count` | Rows that emitted an action (non-NULL `action_kind`) | Rows that aborted before action emission |
| `FragilityAggregates.sample_count` | Rows with a fragility classification (CEG 0.5+ field present) | Pre-CEG-0.5 rows, rows where classification was skipped |
| `DomainBreakdown.sample_count` | Rows attributed to this specific domain within the windowed set | Rows in other domains, NULL-domain rows |

**Consequence:** for a window with 1M total traces, 800K with scoring data, 600K with conscience records, 950K with actions, a k=10 policy applied at top-level admits the whole result; applied at `conscience.by_check["bias"].sample_count = 3` it would mask that specific sub-check. Consumers are responsible for picking the right level; the substrate exposes both so they can.

Test: `sample_count_top_level_vs_nested_documented` constructs a corpus with intentional NULL distribution across scoring / conscience / action / fragility fields and asserts each nested `sample_count` equals the non-NULL contributing-row count for that sub-aggregate, while top-level equals the windowed set size.

---

## 7. Cache — the substrate caching primitive

### 7.1 Why a substrate cache (not bolted on)

Eric's directive: *"yeah we need a cache and the full cache mechanics, caching should be a generic persist capability."* Three reasons it's substrate-level, not per-consumer:

1. **One eviction policy** — a federation peer running lens + sovereign-agent + bridge in one cohabiting process has one cache, one memory budget, one eviction LRU.
2. **One observability** — `cache_stats()` answers "what's hot in this peer's read path right now" across every consumer.
3. **One staleness contract** — every cached aggregate reports `cache_hit: true` + `evaluated_at_unix_ms`. A consumer can't accidentally serve stale data as fresh; the substrate refuses to lie.

### 7.2 Shape

```rust
// src/cache/mod.rs

pub struct Cache {
    inner: Mutex<LruCache<CacheKey, Arc<CacheEntry>>>,
    config: CacheConfig,
    stats: AtomicCacheStats,
}

pub struct CacheConfig {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub ttl: Duration,              // default: 30s for aggregates
    pub invalidation_bucket: Duration,  // default: 1h — see §7.3
}

/// Deployment-tier default — derived at compile time from target_os.
/// Mobile (iOS / Android) gets ~8 MiB resident cache so OS persistence
/// budget isn't blown. Edge (small ARM, RaspberryPi-class) gets ~32 MiB.
/// Server (x86_64 Linux / macOS) gets ~64 MiB. The DeploymentTier surface
/// can be overridden at construction by operators with tighter budgets.
impl Default for CacheConfig {
    fn default() -> Self {
        Self::default_for_tier(DeploymentTier::compile_time_default())
    }
}

impl CacheConfig {
    pub fn default_for_tier(tier: DeploymentTier) -> Self {
        match tier {
            DeploymentTier::Mobile => Self {
                max_entries: 256,
                max_bytes: 8 * 1024 * 1024,
                ttl: Duration::from_secs(30),
                invalidation_bucket: Duration::from_secs(3600),
            },
            DeploymentTier::Edge => Self {
                max_entries: 512,
                max_bytes: 32 * 1024 * 1024,
                ttl: Duration::from_secs(30),
                invalidation_bucket: Duration::from_secs(3600),
            },
            DeploymentTier::Server => Self {
                max_entries: 1024,
                max_bytes: 64 * 1024 * 1024,
                ttl: Duration::from_secs(30),
                invalidation_bucket: Duration::from_secs(3600),
            },
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum DeploymentTier { Mobile, Edge, Server }

impl DeploymentTier {
    /// Compile-time default. Override at Engine construction when a
    /// runtime tier indicator (e.g. operator policy) overrides target_os.
    pub const fn compile_time_default() -> Self {
        if cfg!(any(target_os = "ios", target_os = "android")) {
            Self::Mobile
        } else if cfg!(any(target_arch = "arm", target_arch = "aarch64"))
            && cfg!(target_os = "linux") {
            // Best-effort heuristic for Pi-class edge; operator override
            // is still the source of truth.
            Self::Edge
        } else {
            Self::Server
        }
    }
}

pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions_lru: u64,
    pub evictions_ttl: u64,
    pub invalidations_write: u64,    // §7.3 bucket invalidation
    pub bytes_resident: u64,
    pub entries_resident: u64,
}

/// CacheKey is derived from (method_id, filter.cache_key_digest(),
/// scope_digest, time_bucket). Two callers with identical (method,
/// filter, scope, bucket) share a cache entry. Two callers with
/// different scope NEVER share (admission resolution differs). Two
/// queries spanning different time_buckets get separate entries so
/// bucket-scoped write invalidation is precise (§7.3).
pub struct CacheKey { ... }
```

### 7.3 Discipline

- **In-process, library-local.** No Redis, no IPC. A cohab process shares one cache; separate processes don't share.
- **LRU + TTL.** Whichever hits first. TTL is per-primitive (aggregates: 30s; list primitives: not cached — pagination is page-local, caching adds correctness risk for stale cursors).
- **Scope-disjoint.** The cache key includes the scope digest. An Unauthenticated caller and an Authenticated caller (and two Authenticated callers with different admission resolutions) for the same filter on the same window get separate cache entries — admission set differs → answer differs.
- **Cache miss path is the only path to backend.** The DAS primitive checks cache → on miss, runs the SQL → stores result → returns. The path is uniform; per-primitive code is the SQL + result shape, not the caching dance.
- **Eviction observable.** `cache_stats()` returns the struct above; cohabitation `Engine.cache_stats()` exposes it through PyO3.
- **No write-through.** Cache is read-only side-effect of read primitives. Writes invalidate by **window-overlap bucket set**: every cached aggregate's key carries the *set* of buckets its `[window.start, window.end]` overlaps (not just the bucket of `window.end`). When a write lands at timestamp `t`, the cache evicts every entry whose bucket-set contains `bucket_of(t)`.
  - **Correctness motivation (CIRISPersist#160 comment 2).** An earlier draft keyed only on `bucket_of(window.end)`. That was unsound for the case where `window` straddles a bucket boundary: window `[t-7d, t]` lives in bucket B (where `bucket_of(t) = B`), but a write at `t-1.5h` falls into bucket B-1 — yet that write IS inside the window and DOES change the aggregate's answer. v4.0 keys on the full overlap set so any write inside the window invalidates the entry.
  - **Reverse index.** The cache maintains `bucket → set<CacheKey>` so write-invalidation is O(1) per bucket: on write at `t`, look up `bucket_of(t)`, evict every entry in that bucket's set.
  - **Trade-off.** Bigger windows touch more buckets and pay more invalidations per write. For repository-statistics over 7-day windows at 1h buckets, each entry occupies 168 buckets and a single write evicts ≤1 entry per affected window-key. Net: write-invalidation is bounded by `O(distinct_active_cache_keys)`, not by window size.
  - **Bucket granularity is a substrate setting**, not a per-call concern. Smaller bucket = tighter invalidation timing but more buckets per window-key; larger bucket = fewer buckets per window-key but coarser invalidation. Default 1h matches the Coherence Ratchet / lens dashboard refresh cadences.
  - Cross-process invalidation is out of scope — TTL closes that loop. A cohab process writes and reads in one Cache instance; separate processes have separate caches and TTL bounds staleness.

### 7.4 Fail-honest with the cache

The cache **never silently extends staleness**. If TTL fires and the backend is unreachable, the cache entry is dropped and the next caller gets a real backend error — *not* a stale read with no warning. This matches MISSION.md §1.6 — a partial result is labelled, never coerced.

### 7.5 Admission cache — bounded resolution overhead (CIRISPersist#160 comment 3)

`build_caller_admission(engine, occurrence_key_id)` issues ~3 backend reads per invocation (identity_occurrence lookup + family fan-out + community fan-out). For consumer hot paths — e.g. lens-core's `ScoresOracle::for_agent_window` in a relay handler — those reads dominate the resolution cost ahead of the substrate aggregate cache.

v4.0 ships **both** mitigations (belt-and-suspenders):

```rust
// src/cache/admission.rs

pub struct AdmissionCache {
    inner: Mutex<LruCache<OccurrenceKeyId, Arc<CallerAdmission>>>,
    ttl: Duration,                   // default: 5 minutes
    stats: AtomicAdmissionStats,
}

pub struct AdmissionStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions_ttl: u64,
    pub invalidations_chain_write: u64,
    pub entries_resident: u64,
}
```

**Substrate-side (default-on):** internal admission cache keyed on `occurrence_key_id`, 5-minute TTL. Federation chain admits identities / families / communities through consensus protocols — second-scale staleness is acceptable because the chain's own write cadence is much slower. The 5-minute default trades admission-cache correctness for a worst-case 5min latency on a fresh family/community membership admission, well below the dashboard / relay timing budgets.

**Chain-write invalidation:**
- `put_identity_occurrence(io)` → invalidate `io.occurrence_key_id`.
- `put_family(f)` / `put_community(c)` → invalidate every cached admission whose `identity_key_id ∈ f.members ∪ c.members`. The reverse index `identity_key_id → set<OccurrenceKeyId>` makes this O(|members|).

**Consumer-side (documented pattern):** consumers with a logical session (lens FastAPI request, sovereign-agent run, etc.) SHOULD build `CallerAdmission` once at the session boundary and pass it through `ReadEngine` calls within the session. The substrate cache + consumer reuse compound — no correctness risk, lower steady-state cost.

`Engine.admission_cache_stats()` exposes the internal cache surface for observability. Operators with tighter chain-staleness requirements override the TTL at construction.

**Fail-honest discipline:** identical to §7.4 — a cache miss + backend unreachable returns a real error, never a stale admission.

---

## 8. The new ReadEngine trait shape

### 8.1 Scope as a load-bearing argument

Every CEG-protected method on the public `ReadEngine` trait takes `&CallerScope`. The enum stays two-variant (Unauthenticated / Authenticated) — no `Internal` variant — because the variant invariant ("a `CallerScope` represents a real external caller's scope") is more valuable than the syntactic convenience.

Internal scope-bypassed reads (integrity checks, write-path-internal lookups, the cache substrate's own backend reads) plumb through **per-primitive `*_internal` siblings** marked `pub(crate)`, NOT a third enum variant:

```rust
// src/ceg/aggregates/repository.rs
pub(crate) async fn get_repository_statistics_internal(
    backend: &dyn Backend,
    filter: &RepositoryFilter,
) -> Result<RepositoryStatistics, Error> { ... }
```

The public trait method `get_repository_statistics(filter, scope)` builds the scope predicate, calls `_internal`, and returns. Internal callers (the cache's miss-path, the integrity test scaffold) call `_internal` directly. The trait-method-takes-scope invariant is uniform; the bypass is by *call site*, not by *enum variant*.

```rust
pub trait ReadEngine: Send + Sync {
    // ── Aggregates ──────────────────────────────────────────────

    fn get_repository_statistics(
        &self,
        filter: RepositoryFilter,
        scope: CallerScope,
    ) -> impl Future<Output = Result<RepositoryStatistics, Error>> + Send;

    fn aggregate_scoring_factors(
        &self,
        agent_id_hash: &str,
        window: TimeWindow,
        baseline_window: Option<TimeWindow>,
        scope: CallerScope,
    ) -> impl Future<Output = Result<ScoringFactorAggregate, Error>> + Send;

    fn aggregate_llm_costs(
        &self,
        filter: LlmCallFilter,
        scope: CallerScope,
    ) -> impl Future<Output = Result<LlmCostAggregate, Error>> + Send;

    fn aggregate_scrub_stats(
        &self,
        window: TimeWindow,
        scope: CallerScope,
    ) -> impl Future<Output = Result<ScrubAggregate, Error>> + Send;

    fn corpus_shape(
        &self,
        filter: CorpusShapeFilter,
        scope: CallerScope,
    ) -> impl Future<Output = Result<CorpusShape, Error>> + Send;

    // ── List primitives — scope-aware, no cache ─────────────────

    fn list_trace_summaries(
        &self,
        filter: TraceFilter,
        cursor: Option<TraceCursor>,
        limit: i64,
        scope: CallerScope,
    ) -> impl Future<Output = Result<TraceListPage, Error>> + Send;

    fn get_trace_summary(
        &self,
        trace_id: &str,
        scope: CallerScope,
    ) -> impl Future<Output = Result<Option<TraceSummary>, Error>> + Send;

    fn get_trace_detail(
        &self,
        trace_id: &str,
        scope: CallerScope,
    ) -> impl Future<Output = Result<Option<TraceDetail>, Error>> + Send;

    fn list_tasks(
        &self,
        filter: TaskFilter,
        cursor: Option<TaskCursor>,
        limit: i64,
        scope: CallerScope,
    ) -> impl Future<Output = Result<TaskListPage, Error>> + Send;

    fn list_llm_calls(
        &self,
        filter: LlmCallFilter,
        cursor: Option<LlmCallCursor>,
        limit: i64,
        scope: CallerScope,
    ) -> impl Future<Output = Result<LlmCallListPage, Error>> + Send;

    fn list_federation_keys(
        &self,
        filter: FederationKeyFilter,
        cursor: Option<FederationKeyCursor>,
        limit: i64,
        scope: CallerScope,
    ) -> impl Future<Output = Result<FederationKeyListPage, Error>> + Send;

    fn list_attestations(
        &self,
        filter: AttestationFilter,
        cursor: Option<AttestationCursor>,
        limit: i64,
        scope: CallerScope,
    ) -> impl Future<Output = Result<AttestationListPage, Error>> + Send;

    /// #135 + part of #150 — list every attestation whose subject
    /// is `target`, scoped by caller. The scope predicate applies
    /// to the attestation's `cohort_scope`, NOT the target's.
    fn list_attestations_for(
        &self,
        target: &KeyId,
        cursor: Option<AttestationCursor>,
        limit: i64,
        scope: CallerScope,
    ) -> impl Future<Output = Result<AttestationListPage, Error>> + Send;

    fn list_revocations(
        &self,
        filter: RevocationFilter,
        cursor: Option<RevocationCursor>,
        limit: i64,
        scope: CallerScope,
    ) -> impl Future<Output = Result<RevocationListPage, Error>> + Send;

    // ── Coherence Ratchet inputs ────────────────────────────────

    fn cross_agent_divergence(
        &self,
        deployment_domain: &str,
        window: TimeWindow,
        metric: DeviationMetric,
        scope: CallerScope,
    ) -> impl Future<Output = Result<Vec<DivergenceRow>, Error>> + Send;

    fn temporal_drift(
        &self,
        agent_id_hash: &str,
        baseline: TimeWindow,
        comparison: TimeWindow,
        scope: CallerScope,
    ) -> impl Future<Output = Result<Vec<TemporalDriftRow>, Error>> + Send;

    fn hash_chain_gaps(
        &self,
        agent_id_hash: &str,
        window: TimeWindow,
        scope: CallerScope,
    ) -> impl Future<Output = Result<Vec<HashChainGap>, Error>> + Send;

    fn conscience_override_rates(
        &self,
        deployment_domain: &str,
        window: TimeWindow,
        scope: CallerScope,
    ) -> impl Future<Output = Result<Vec<OverrideRateRow>, Error>> + Send;

    // ── Granular counters ───────────────────────────────────────

    fn count_traces(&self, filter: TraceFilter, scope: CallerScope)
        -> impl Future<Output = Result<i64, Error>> + Send;

    fn count_overrides(&self, filter: TraceFilter, scope: CallerScope)
        -> impl Future<Output = Result<i64, Error>> + Send;

    fn count_identity_changes(&self, filter: TraceFilter, scope: CallerScope)
        -> impl Future<Output = Result<i64, Error>> + Send;

    fn aggregate_audit_chain(&self, filter: TraceFilter, scope: CallerScope)
        -> impl Future<Output = Result<AuditChainAggregate, Error>> + Send;
}
```

### 8.2 The `Error` enum sheds `NotImplemented`, gains structured `ScopeRefused`

`Error::NotImplemented` was the v3.x escape hatch for sqlite-incomplete primitives. v4.0 ships both backends in the cut; the variant goes away. Backend-shape differences (Postgres CTE vs sqlite correlated subquery) are implementation details, not error states.

`ScopeRefused` carries a structured reason — `&'static str` was insufficient because consumers (lens UI, audit dashboards, automated policy enforcement) need to distinguish *why* the scope refused: wrong identity vs no family membership vs no community membership vs boundary auth failure are different conditions with different consumer remediations.

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("invalid cursor: {0}")]
    InvalidCursor(String),

    #[error("backend: {0}")]
    Backend(String),

    #[error("scope refused: {0}")]
    ScopeRefused(#[from] ScopeRefusalReason),  // new in v4.0
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeRefusalReason {
    /// Caller's identity ≠ emitter's identity for a `cohort_scope: self` row.
    #[error("caller identity does not match emitter identity for self-scoped row")]
    WrongIdentity,

    /// Caller's identity is not a member of any family containing the
    /// emitter's identity, for a `cohort_scope: family` row.
    #[error("caller's identity is not a member of any family containing the emitter's identity")]
    NoFamilyMembership,

    /// Caller's identity is not a member of any community containing the
    /// emitter's identity, for a `cohort_scope: community` row.
    #[error("caller's identity is not a member of any community containing the emitter's identity")]
    NoCommunityMembership,

    /// Caller's `occurrence_key_id` could not be resolved through any
    /// substrate primitive — neither bound as an occurrence nor present
    /// as an identity in any family/community. Boundary auth held that
    /// the key is real; substrate can't admit any cohort beyond the
    /// non-suppressed tiers. Treated as Unauthenticated visibility plus
    /// the singleton-identity fallback (§4.4).
    #[error("occurrence_key_id could not be resolved to an admission")]
    BoundaryAuthFailed,

    /// Unauthenticated caller attempted to read self/family-scoped
    /// content. The §8.1.13.3 structural-invisibility rule applies
    /// even at the SQL layer.
    #[error("unauthenticated caller cannot read structurally-invisible cohort scopes")]
    UnauthenticatedSuppressedCohort,
}
```

The `kind()` mapping drops `read_not_implemented` and adds `read_scope_refused`. AV-15 stable-token discipline: `read_scope_refused` is the single token crossing PyO3 / HTTP boundaries; the `ScopeRefusalReason` variant tag is a separate closed-set `&'static str` available via `reason.kind()` for callers that need machine-distinguishable detail. The inner `Display` form goes to tracing only.

---

## 9. Defense in depth — edge backs persist

### 9.1 The two-layer enforcement

Eric: *"defensive in depth with edge backing us up."*

```
┌─────────────────────────────────────────────────────────────┐
│ CIRISLens / CIRISBridge / sovereign agent  (consumer)       │
│                                                              │
│  ┌──────────────────────────────────────────────┐           │
│  │ CIRISEdge#48-A — consumer-side cohort_scope  │ ← layer 2 │
│  │ check on rows received from persist.          │           │
│  │ Refuses suppressed content if persist failed  │           │
│  │ open. Telemetry counter: edge_refused_scope.  │           │
│  └──────────────────────────────────────────────┘           │
│                       │                                      │
│                       ▼                                      │
│  ┌──────────────────────────────────────────────┐           │
│  │ CIRISPersist v4.0 DAS                         │ ← layer 1 │
│  │ Substrate cohort_scope predicate. Refuses    │           │
│  │ suppressed content at SQL level. Telemetry:   │           │
│  │ persist_refused_scope.                        │           │
│  └──────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

**Layer 1 — substrate gate.** The `cohort_scope_sql_predicate` AND-composed into the WHERE. Suppressed rows never leave Postgres / sqlite. This is the primary enforcement.

**Layer 2 — edge gate (CIRISEdge#48-A).** Consumer-side filter applies the same logic. If layer 1 leaks (a bug, a misconfigured caller, an incomplete predicate on a new column), layer 2 catches. If layer 2 fails open, layer 1 caught at substrate.

### 9.2 Why both, not one

If we only had substrate: a bug in `cohort_scope_sql_predicate` (e.g. a missed table, an inverted predicate) leaks suppressed content to every caller. No second check; no observable miss.

If we only had edge: a substrate-side query returning unsanitized rows hits the wire (network or PyO3 boundary). The edge check filters egress, but the rows already exist in a process buffer where a sibling consumer in the same cohab process could observe them.

Both: the substrate refuses at SQL; the edge refuses at egress. A miss on either layer is caught by the other; a miss on *both* is the alert condition. Both layers emit telemetry; the joint alert is `cohort_scope_double_miss`.

### 9.3 The observable joint contract

```
# Read-side (AV-44 closure, §4.3)
persist_refused_scope_total{scope, reason}             # layer 1 refusal
edge_refused_scope_total{scope, reason}                # layer 2 refusal
cohort_scope_double_miss_total{scope}                  # alert — both layers passed something they shouldn't have

# Write-side (AV-45 closure, §4.6) — symmetric
persist_refused_write_scope_total{scope, reason}       # layer 1 — substrate refused a downgraded cohort_scope
edge_refused_write_scope_total{scope, reason}          # layer 2 — edge refused at pre-ingest verification
cohort_scope_write_double_miss_total{scope}            # alert — both layers passed a downgraded label
```

Layer 2 firing while layer 1 passed is **not** a bug in layer 2 — it's a bug in layer 1, and layer 2 caught it. The two `_double_miss` counters are the only alerts that require immediate response.

### 9.4 Symmetric closure of AV-44 + AV-45

The cut now closes both forge surfaces by the same construction discipline:

| Surface | Read side (AV-44) | Write side (AV-45) |
|---|---|---|
| What's forged | Admission claim ("I have access to identity X / family F / community C") | cohort_scope label ("this content is federation-visible") |
| Layer 1 (substrate) | `cohort_scope_sql_predicate` in §4.3 — the WHERE clause refuses to surface suppressed rows to admission the caller doesn't actually hold | `DimensionAdmissionPolicy::check_write_cohort_scope` in §4.6 — refuses writes whose claimed cohort_scope exceeds the writer's admission |
| Layer 2 (edge) | CIRISEdge#48-A — consumer-side cohort_scope re-check at egress | Edge pre-ingest verification — writer's claimed scope matches the routing they used |
| Closed by construction | `CallerAdmission` private constructor + substrate-only builder | Writer admission resolved from the verified envelope signer; no caller-asserted scope label trusted |

With both sides closed, defense in depth is uniform. v4.0 doesn't leave one half of the asymmetry open.

---

## 10. Backend implementations — parity discipline

### 10.1 Postgres

- `get_repository_statistics` — single CTE: `WITH window_traces AS (SELECT * FROM cirislens.trace_events WHERE ts BETWEEN ... AND <§4.3 scope predicate>), totals AS (...), scores AS (...), ...`. The scope predicate joins through `federation_identity_occurrences` (and conditionally `federation_families` / `federation_communities`) inside the windowed CTE so subsequent aggregate CTEs scan the already-scope-filtered set. One round-trip; Rust struct decodes the single result row.
- Covering indexes — V060 adds `(ts, deployment_domain, cohort_scope) INCLUDE (trace_id, agent_id_hash, plausibility, alignment, scrub_key_id)` on `trace_events`. The scrub_key_id INCLUDE is what makes the §4.3 EXISTS-join indexable without a heap fetch on the inner JOIN.
- `list_attestations_for` — uses the existing `(subject_key_id, cohort_scope, asserted_at)` index on `federation_attestations`; V060 adds the corresponding `(scrub_key_id, cohort_scope)` index for the EXISTS-join inner.

### 10.2 SQLite

- `get_repository_statistics` — two-step: (1) materialize the windowed `trace_events` rows matching filter+scope into a temp table (the scope predicate runs as correlated `EXISTS` against the V059/V060 substrate tables — sqlite handles this efficiently when the inner tables have the right indexes); (2) emit per-aggregate queries against the temp table.
- Covering indexes — V060 adds the same shape; sqlite query planner uses `(ts, cohort_scope, scrub_key_id)` ordering.
- `list_attestations_for` — same index, sqlite syntax.
- **No NotImplemented.** Wall-clock differs; correctness identical.

### 10.3 Substrate methods landing in this cut

`federation_communities` substrate (V060) requires four new trait methods on `FederationDirectory` (symmetric with V059 family methods at `src/federation/mod.rs:344-380`):

```rust
async fn put_community(&self, community: SignedCommunity) -> Result<(), Error>;
async fn lookup_community(&self, community_key_id: &str) -> Result<Option<Community>, Error>;
async fn list_communities_for_member(&self, member_identity_key_id: &str) -> Result<Vec<Community>, Error>;
```

Both backends implement these in Commit D (§15) alongside the rest of the v4.0 break. The shape mirrors family ones one-for-one; the difference is the `cohort_scope::suppresses_holds_bytes` classification (false for community, true for family) — read paths apply the predicate accordingly.

### 10.4 Parity conformance suite

`tests/ceg/parity.rs` runs every v4.0 primitive against both backends with identical input and asserts byte-equal output (modulo `evaluated_at_unix_ms` which differs per run). The suite is per-primitive × per-scope × per-backend = `N_primitives × 3 × 2` matrix; new primitives add a row.

---

## 11. PyO3 surface

### 11.1 Engine methods

```python
class Engine:
    # Aggregates
    def get_repository_statistics(
        self,
        filter: RepositoryFilter,
        caller_occurrence_key_id: str | None = None,    # None → Unauthenticated; Some → Authenticated w/ substrate-resolved admission
    ) -> RepositoryStatistics: ...

    def aggregate_scoring_factors(
        self,
        agent_id_hash: str,
        window: TimeWindow,
        baseline_window: TimeWindow | None,
        caller_occurrence_key_id: str | None = None,
    ) -> ScoringFactorAggregate: ...

    # … (same shape for every aggregate)

    # Lists — same shape
    def list_attestations_for(
        self,
        target_key_id: str,
        cursor: str | None,
        limit: int,
        caller_occurrence_key_id: str | None = None,
    ) -> AttestationListPage: ...

    # Cache observability
    def cache_stats(self) -> CacheStats: ...
```

### 11.2 The caller-occurrence-key-id contract

Python passes a *caller occurrence key id* — `None` means `Unauthenticated`, `Some(key)` means `Authenticated` with substrate-resolved admission. Rust calls `build_caller_admission(engine, occurrence_key_id)` which:

1. Resolves `occurrence_key_id → identity_key_id` via `lookup_identity_for_occurrence` (V059 §5.6.8.8). Singleton-identity fallback (§4.4) when no binding exists.
2. Resolves `identity_key_id → family_key_ids` via `list_families_for_member` (V059 §5.6.8.9).
3. Resolves `identity_key_id → community_key_ids` via `list_communities_for_member` (V060 this cut).

**Python NEVER passes admission fields.** No scope-string parameter; the variant is determined by whether the occurrence key is present. The AV-44 forge surface is closed by construction — there's no admission field a caller can lie about, and no string label to mislabel.

### 11.3 Filter and result struct binding

`RepositoryFilter`, `RepositoryStatistics`, `Totals`, `ScoreAggregates`, `ScoreDistribution`, `ConscienceAggregates`, `ActionAggregates`, `FragilityAggregates`, `DomainBreakdown`, `TimeWindow`, `CacheStats` — all exposed as `@pyclass` types with field accessors. JSON-friendly via `__json__` (returns a `dict`); not `__dict__` because we want explicit serialization control.

---

## 12. Migration V060

V057 is already taken (peer_metadata_cohort_scope_index, v3.9.x); V058–V059 are the v3.11/v3.12 cuts. V060 is the next free number and lands as the v4.0 DAS migration. Two concerns in one numbered cut, mirroring the V059 dual-substrate pattern:

```sql
-- migrations/postgres/lens/V060__v4_0_communities_and_das_indexes.sql

-- ── Part A: federation_communities substrate (§8.1.13.3) ───────────
-- Symmetric to V059's federation_families shape. members JSONB carries
-- IDENTITY keys (not occurrence keys), matching the §5.6.8.9 worked
-- example. policy_blob carries the cohort_scope membership label
-- consumed at CIRISEdge#48-A (V057 already indexed the analogous shape
-- on federation_peer_metadata).

CREATE TABLE cirislens.federation_communities (
    community_key_id      TEXT PRIMARY KEY,
    community_name        TEXT NOT NULL,
    members               JSONB NOT NULL,
    founded_at            TIMESTAMPTZ NOT NULL,
    consensus_protocol    TEXT NOT NULL,
    policy_blob           JSONB,
    persist_row_hash      TEXT NOT NULL,
    CONSTRAINT federation_communities_consensus_protocol_form
        CHECK (consensus_protocol ~ '^(founder_only|unanimous|majority|quorum:[0-9]+/[0-9]+|weighted:.+|custom:.+)$')
);

-- Membership fan-out index for list_communities_for_member.
CREATE INDEX idx_federation_communities_members_gin
    ON cirislens.federation_communities USING GIN (members);

-- ── Part B: DAS covering indexes ───────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_trace_events_v060_repository_stats
ON cirislens.trace_events (ts, deployment_domain, cohort_scope)
INCLUDE (trace_id, agent_id_hash, plausibility_score, alignment_score,
         conscience_passed, action_kind, action_succeeded,
         fragility_phase, scrub_key_id);

CREATE INDEX IF NOT EXISTS idx_federation_attestations_v060_by_target
ON cirislens.federation_attestations (subject_key_id, cohort_scope, asserted_at DESC)
INCLUDE (attestation_id, asserter_key_id, attestation_kind, scrub_key_id);

CREATE INDEX IF NOT EXISTS idx_federation_attestations_v060_emitter_scope
ON cirislens.federation_attestations (scrub_key_id, cohort_scope);
-- Indexes the inner side of the §4.3 scope-predicate EXISTS join.
```

```sql
-- migrations/sqlite/lens/V060__v4_0_communities_and_das_indexes.sql

-- Part A
CREATE TABLE federation_communities (
    community_key_id      TEXT PRIMARY KEY,
    community_name        TEXT NOT NULL,
    members               TEXT NOT NULL,   -- JSON-shaped
    founded_at            TEXT NOT NULL,   -- RFC-3339
    consensus_protocol    TEXT NOT NULL,
    policy_blob           TEXT,            -- JSON-shaped or NULL
    persist_row_hash      TEXT NOT NULL,
    CHECK (consensus_protocol GLOB 'founder_only'
        OR consensus_protocol GLOB 'unanimous'
        OR consensus_protocol GLOB 'majority'
        OR consensus_protocol GLOB 'quorum:*/*'
        OR consensus_protocol GLOB 'weighted:?*'
        OR consensus_protocol GLOB 'custom:?*')
);

-- Part B (sqlite: no INCLUDE — index columns directly)
CREATE INDEX IF NOT EXISTS idx_trace_events_v060_repository_stats
ON trace_events (ts, deployment_domain, cohort_scope, trace_id);

CREATE INDEX IF NOT EXISTS idx_federation_attestations_v060_by_target
ON federation_attestations (subject_key_id, cohort_scope, asserted_at DESC, attestation_id);

CREATE INDEX IF NOT EXISTS idx_federation_attestations_v060_emitter_scope
ON federation_attestations (scrub_key_id, cohort_scope);
```

Both files land in the same release. The community-membership fan-out is `members @> jsonb_build_array(...)` on PG and `json_each(members)` on sqlite — the substrate hides the dialect difference behind `list_communities_for_member`.

---

## 13. Threat model — AV-44 (new)

Added to `docs/THREAT_MODEL.md`:

**AV-44 — scope escalation via caller-asserted admission.**

*Attack:* A malicious caller constructs a `CallerScope::Authenticated { admission: CallerAdmission { identity_key_id: <victim's identity>, family_key_ids: <every family>, community_key_ids: <every community> } }` and passes it to the substrate, escalating to "see all suppressed content."

*Mitigation:* `CallerAdmission` has no public constructor. The substrate-side builder `build_caller_admission(engine, occurrence_key_id)` is the **only** way to obtain one; the builder resolves identity / families / communities deterministically from `federation_identity_occurrences` / `federation_families` / `federation_communities`. The PyO3 surface accepts an `occurrence_key_id` string only; the substrate resolves the rest.

A caller presenting an `occurrence_key_id` they don't actually control is a separate authentication concern — the boundary (PyO3 caller, HTTP middleware, edge auth) is responsible for proving the caller holds the corresponding private key (Ed25519 signature challenge over a server-issued nonce, or an existing authenticated channel). Persist trusts the boundary on key ownership; persist enforces visibility based on what the chain has admitted about that key.

*Defense in depth:* The edge layer (CIRISEdge#48-A) re-checks `cohort_scope` on every row returned; a forged admission leaked through layer 1 is caught at layer 2. Joint `cohort_scope_double_miss_total` is the alert condition.

*Test:* `tests/scope/forged_admission.rs` — constructs every plausible forge attempt (struct literal, `mem::transmute`, Deserialize bypass) and asserts the API rejects at the type-system level (private constructor) or at the builder boundary (only `build_caller_admission` yields one).

---

## 14. Test discipline

Per MISSION.md §5 — every test answers a mission question. v4.0 adds:

| Category | Test |
|---|---|
| **Scope refusal** | `unauthenticated_sees_no_self_or_family` — Unauthenticated caller against a corpus with `cohort_scope: self/family` rows returns zero of them; community/affiliations/species/biosphere/federation rows are returned per §8.1.13.3. |
| **Scope refusal** | `authenticated_self_requires_same_identity` — Authenticated caller with `identity_key_id = I1` sees `cohort_scope: self` rows emitted by occurrence keys resolving to I1; sees zero `self` rows from occurrence keys resolving to I2. |
| **Scope refusal** | `authenticated_family_requires_membership` — Authenticated caller in family F1 (not F2) sees `cohort_scope: family` rows emitted by identities in F1; not from identities exclusively in F2. |
| **Scope refusal** | `authenticated_community_requires_membership` — symmetric test against `federation_communities`. |
| **Scope refusal** | `forged_admission_refused_at_compile_time` — `CallerAdmission` literal construction outside the crate fails to compile (private constructor); deserialization paths are blocked by serde-skip on the struct. |
| **Scope refusal** | `singleton_identity_fallback` — caller whose `occurrence_key_id` has no `identity_occurrence` row sees their own emissions as `self`-cohort (identity == occurrence). |
| **Backend parity** | `parity_get_repository_statistics_all_scope_variants` — Unauthenticated + Authenticated(I1 in F1, C1) on Postgres+SQLite returns identical struct (modulo `evaluated_at_unix_ms`). |
| **Backend parity** | `parity_list_attestations_for_scope_variants` — same. |
| **Backend parity** | `parity_federation_communities_substrate` — V060 put/lookup/list_for_member behave identically on PG + SQLite. |
| **Cache contract** | `cache_hit_reports_true` — second call within TTL returns `cache_hit: true` with the original `evaluated_at_unix_ms`. |
| **Cache contract** | `cache_miss_after_ttl` — third call after TTL returns `cache_hit: false`. |
| **Cache contract** | `scope_disjoint_cache` — same filter, Unauthenticated vs Authenticated vs different Authenticated identities never share a cache entry. |
| **Cache contract** | `cache_does_not_serve_stale_on_backend_failure` — TTL expiry + backend down → fresh error, never stale read. |
| **Aggregate honesty** | `sample_count_zero_is_reported` — empty window returns `sample_count: 0`, not an error. |
| **Aggregate honesty** | `small_n_not_hidden` — `sample_count: 3` is reported faithfully; k-anonymity policy is consumer's. |
| **Defense in depth** | `edge_catches_substrate_leak` — simulated substrate predicate bug; edge layer refuses the leaked row; `cohort_scope_double_miss_total` fires. |
| **Lens flow end-to-end** | `community_cohort_admits_lens_capable_peer` — agent stores trace as `cohort_scope: community` with the lens peer's community; lens peer reads with their own occurrence key, admission resolves to the community, row is returned. (Does not exercise the routing layer — that's NodeCore/Edge.) |

---

## 15. Cut sequence — logical commits inside one tagged release

Per §16.4 the v4.0 cut is **one big break** — there are no separately landing PRs ahead of v4.0.0. The cut lands as a single tagged release on `main`. The substeps below are reviewable *commits within that cut*, ordered for review legibility (each commit could in principle be reverted to the prior state and still build / test green):

1. **Commit A — module reorganization** (no behavior change): move `src/read/*` → `src/ceg/*` under the topic-named namespaces; update internal call sites. Façade re-exports preserve current public API at this commit. Tests pass unchanged.
2. **Commit B — CallerScope + admission + SQL helper** (additive): `src/scope/` lands with `CallerScope`, `CallerAdmission`, `build_caller_admission`, `cohort_scope_sql_predicate`. New types; not yet wired into trait methods. Unit tests for the predicate per scope × per backend.
3. **Commit C — Cache primitive** (additive): `src/cache/` lands; `CacheConfig::default_for_tier`; admission cache (§7.5); `Engine.cache_stats()` exposed. No aggregates use it yet.
4. **Commit D — `federation_communities` substrate**: V060 migration Part A; `put_community` / `lookup_community` / `list_communities_for_member` on `FederationDirectory`; both backend implementations; parity tests.
5. **Commit E — `ReadEngine` v2 trait** (the read-side break): adds `scope` to every read method, drops `Error::NotImplemented`, adds `Error::ScopeRefused(ScopeRefusalReason)`; both backends implement every primitive; PyO3 surface updates.
6. **Commit F — write-path admission (AV-45 closure)**: extends `DimensionAdmissionPolicy` with `check_write_cohort_scope` (§4.6); wired into `Engine::receive_and_persist`, `put_attestation`, `put_revocation`, `put_takedown_notice`. Tests: write-side forge attempts refused (downgrade attempt → `ScopeRefusalReason`). Closes AV-45 candidate; joint `cohort_scope_write_double_miss_total` observable.
7. **Commit G — `get_repository_statistics`**: the #159 primitive, both backends, scope-gated, cache-aware. V060 migration Part B (DAS covering indexes).
8. **Commit H — `list_attestations_for`**: #135 + part of #150.
9. **Commit I — docs**: MISSION.md cross-references, PUBLIC_SCHEMA_CONTRACT.md update, THREAT_MODEL.md AV-44 + AV-45 (both closed in v4.0), this FSD marked Accepted.

The whole sequence lands in one PR against `main`, tagged v4.0.0. The commit-axis review is for legibility (reviewer can walk commit-by-commit); the break is at Commit E (read-side trait) + Commit F (write-side admission extension). Eric notifies sisters and federation when the tag publishes.

### 15.5 Consumer migration order (CIRISPersist#160 comment 1 ask)

The v4.0 tag triggers a documented consumer-update cascade. Sister repos that consume persist's read or write surface coordinate against this sequence:

| Step | Repo | Bump | Notes |
|---|---|---|---|
| 0 | CIRISPersist | tag `v4.0.0` | Wheel + crate publish |
| 1 | CIRISLensCore | `v0.5.0` | Cohabitation pin v3.14.3 → v4.0; adopt `ceg::*` import paths; `ScoresOracle::{for_trace, for_agent_window, detector_history}` gain `scope` parameter; error-mapping in `src/scoring/result.rs` extends with `ScopeRefused { reason: ScopeRefusalReason }`. PyO3 surface unchanged at v0.5.0 (lens-core's read-API endpoints land at v0.6.0 with CIRISLensCore#15). Internal-only aggregate callers migrate to `*_internal` siblings per §8.1. |
| 2 | CIRISEdge | follow-up release | Consumer-side §48-A read check + write-side pre-ingest verification (§9.3). The joint `_double_miss` counters land here. |
| 3 | CIRISLensCore | `v0.6.0` | Node UX read endpoints with `caller_occurrence_key_id` PyO3 contract (CIRISLensCore#15 close). |
| 4 | CIRISBridge / CIRISNodeCore | bumps as needed | Bridge consumes lens-core, not persist directly. NodeCore's persist consumption (audit chain + federation directory) is internal; no `scope`-aware reads in NodeCore's hot path. |
| 5 | CIRISConformance | matrix bump | Records the v4.0 + v0.5 + v0.6 cohabitation pin sets as the new baseline. |

**Where calibration_bundles lands post-reorg** (per lens-core's specific ask): the `derived/` substrate is NOT part of the `ceg/` read-surface reorganization. `src/derived/{mod,types}.rs` and `DerivedSchema::{put_calibration_bundle, get_current_calibration_bundle, get_calibration_bundle_by_version}` keep their current paths. The `ceg/` namespace is for read primitives that take a `CallerScope`; the derived-schema substrate is consumer-facing write+read surface for calibration artifacts and stays where it is. Lens-core's `derived::{CalibrationBundle, CohortCentroid, ProjectionMetadata, Standardization}` imports do not change in v4.0.

---

## 16. Open questions for sign-off

These are the points where I want explicit user confirmation before the v4.0 cut PR lands:

**Locked (Eric, 2026-06-05):**

1. **CEG namespace granularity** — topic-only (`src/ceg/cohort_scope/`, `src/ceg/identity/`, `src/ceg/community/`, `src/ceg/structural_invisibility/`, `src/ceg/streaming/`); CEG version provenance documented in each module's header doc.
2. **Cache TTL default** — 30s for aggregates, per-primitive override available.
3. **CallerScope shape** — two variants, `Unauthenticated` and `Authenticated { admission: CallerAdmission }`. `CallerAdmission` resolves the caller's `occurrence_key_id` through `federation_identity_occurrences` (identity) + `federation_families` (V059) + `federation_communities` (V060 this cut). Self / family / community are admission resolutions, not enum variants. Sovereign-mode is the singleton-identity fallback (§4.4).
4. **One big cut break** — the v4.0 cut lands as a single PR against `main`; §15 substeps are commits within that PR, ordered for review legibility (Commit A is the module reorg, Commit E is the read-side break, Commit F is the write-side break). No separately-landing PRs.
5. **Rollout** — tag v4.0.0 → wheel artifacts publish → Eric notifies sisters/federation → consumer PRs land per §15.5. No staging cut.
6. **No scope-string at PyO3 boundary.** Removed entirely. The PyO3 surface takes `caller_occurrence_key_id: Optional[str]`; `None` → Unauthenticated, `Some(key)` → Authenticated with substrate-resolved admission. No admission fields cross the boundary; no string label a caller can lie about; AV-44 forge surface closed by construction.
7. **`federation_communities` ships in v4.0 (Option 1).** V060 migration + symmetric `put_community` / `lookup_community` / `list_communities_for_member` substrate methods. Closes the gap that would otherwise leave the lens-trace community flow theoretical until v4.1.
8. **Peer capabilities** — NOT added by v4.0. Already first-class as the `service_announcement` Contribution subject_kind (NodeCore SCHEMA §4.23). Capabilities are routing, not scoping; persist doesn't need to model them at the read predicate.
9. **Write-side scope folds into v4.0 (CIRISPersist#160 comment 4).** AV-44 + AV-45 close together. `DimensionAdmissionPolicy::check_write_cohort_scope` (§4.6) enforced at every write path carrying a cohort_scope label. Symmetric defense in depth (§9.4) on both sides.
10. **Admission cache (CIRISPersist#160 comment 3).** Substrate-side default-on with 5-min TTL + chain-write invalidation; consumers SHOULD also reuse `CallerAdmission` across logical sessions. Belt-and-suspenders bounding of resolution overhead.
11. **Cache window-overlap correctness (CIRISPersist#160 comment 2).** Cache keys carry the full set of buckets `[window.start, window.end]` overlaps, not just `bucket_of(window.end)`. A write inside any cached entry's window invalidates that entry regardless of which bucket the write timestamp falls in.
12. **Consumer migration order (CIRISPersist#160 comment 1).** §15.5 names the v4.0 → lens-core v0.5 → edge → lens-core v0.6 → bridge/node-core sequence. `src/derived/` is NOT moved by the reorg; calibration_bundles paths stay at `derived::*`.

---

## 17. Out-of-scope-but-tracked

Per `feedback_no_pg_only_no_deferral` — anything named here gets a tracked issue, not a "deferred" label:

- **v4.1 — Path B perf cleanup.** Precomputed `admitted_identity_key_id` denormalization on hot tables, eliminating the query-time identity-occurrence join. Tracked: opened on v4.0 tag.
- **v4.x — Cross-process / cross-node cache coordination.** Out of scope (federation is the trust boundary; persist is local). Issue not opened; documented here as "deliberately not pursued."
- **v4.x — Ad-hoc query surface.** Refused per §1.4 apophatic bound. Not tracked; this is a "no" with a reason.

(Earlier draft listed "v4.1 sovereign-mode scope semantics" — removed: sovereign-mode is the singleton-identity fallback in §4.4, no enum work needed. Earlier draft also flagged a "capability advertisement primitive" gap — also removed: peer capabilities are first-class as `service_announcement` Contributions per NodeCore SCHEMA §4.23, and they're a routing concern, not a substrate visibility concern. Earlier draft deferred "v4.1 write-path scope (AV-45 candidate)" — also removed per CIRISPersist#160 comment 4: write-side admission folds into v4.0 (Commit F, §4.6), closing AV-44 + AV-45 together as a single cohesive cut.)

---

## 18. Cross-references

- **`MISSION.md` §1.5** — backend parity (load-bearing for §2.3 of this FSD)
- **`MISSION.md` §1.6** — fail-honest (load-bearing for §6.1 + §7.4)
- **`MISSION.md` §1.7** — relational fabric (load-bearing for §4.2)
- **`MISSION.md` §6 anti-pattern #4** — no PG-only / no deferred (the discipline that invalidates the #159 first draft)
- **`MISSION.md` §6 anti-pattern #10** — storing trust ≠ conferring trust (load-bearing for §4.2)
- **CEG 0.10 §10.1.4** — structural invisibility (load-bearing for §4.3)
- **CEG 0.10 §8.1.13.3** — community non-suppression (load-bearing for `federation_communities` shipping in v4.0 without suppression bits)
- **NodeCore SCHEMA §4.23** — `service_announcement` Contribution subject_kind — the routing-side counterpart to persist's visibility-side scoping (validates that capability advertisement is upstream of substrate, not part of v4.0)
- **`docs/THREAT_MODEL.md`** — AV-43 (k-anonymity), new AV-44 (scope escalation)
- **`docs/PUBLIC_SCHEMA_CONTRACT.md`** — v4.0 update names the DAS perf table
- **CIRISPersist#159** — the driving #159 issue; this FSD supersedes its sqlite-NotImplemented proposal
- **CIRISPersist#135** — `list_attestations_for` ask (closed by Commit G)
- **CIRISPersist#150** — read-side cohort_scope honesty (partial close by §4.3 + Commit E)
- **CIRISPersist#160** — external Opus 4.7 FSD review (this revision addresses all 7 concerns + 3 nits; close on v4.0 tag)
- **CIRISEdge#48-A** — consumer-side cohort_scope check (the §9 layer-2 partner)
- **`FSD/CIRIS_PERSIST.md`** — the base substrate FSD
- **`FSD/V0_5_0_FEDERATION_READ_PRIMITIVES.md`** — v0.5 read-primitive precedent
- **`feedback_clean_break_renames`** — discipline applied to §1.3
- **`feedback_rename_consistency`** — discipline applied to §2.1 PyO3 + Filter renames in one cut
- **`feedback_no_pg_only_no_deferral`** — discipline applied to §2.3 + §17
