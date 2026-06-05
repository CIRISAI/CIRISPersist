//! `get_repository_statistics` (#159) — the corpus-wide aggregate
//! primitive (FSD §6.2).
//!
//! The driving consumer is CIRISLens' `/repository/statistics` endpoint;
//! the primitive lands as a substrate-wide capability. One call computes
//! the full FSD shape — totals + DMA score distributions + conscience
//! pass/override rates + action histogram + fragility breakdown +
//! per-domain rollup — in a single round-trip (Postgres CTE, §10.1) or a
//! two-step materialize-then-aggregate pass (SQLite, §10.2), gated by the
//! §4.3 cohort_scope predicate and routed through the §7 substrate cache.
//!
//! # Where the scores live (load-bearing)
//!
//! Scores are NOT physical columns on `trace_events`. Per the V042
//! functional-index lineage they live in the per-event-type `payload`
//! JSON: `csdma_plausibility_score` / `dsdma_domain_alignment` under
//! `event_type = 'DMA_RESULTS'`; `conscience_passed` /
//! `action_was_overridden` / the per-check `*_passed` flags under
//! `'CONSCIENCE_RESULT'`; `action_executed` / `success` under
//! `'ACTION_RESULT'`; `idma_fragility_flag` / `idma_phase` under
//! `'IDMA_RESULT'`. A "trace" is therefore a `GROUP BY trace_id` rollup
//! across many event rows — the same shape the existing
//! `list_trace_summaries` / `corpus_shape` aggregates already use
//! (`TRACE_SUMMARY_SELECT` in the backends). This primitive reuses that
//! exact per-trace extraction, then aggregates a second time over the
//! per-trace rows. The `cohort_scope` / `cohort_target_id` columns ARE
//! physical per-event columns (V060 / D2), so the §4.3 scope predicate
//! AND-composes at the event-row level inside the windowed CTE.
//!
//! # `sample_count` contract (FSD §6.3)
//!
//! Every aggregate carries its own `sample_count`. Top-level
//! [`RepositoryStatistics::sample_count`] is the scope-filtered windowed
//! *trace* count (the denominator). Each nested sub-aggregate's
//! `sample_count` is the count of traces that contributed to *that*
//! statistic — i.e. traces whose relevant score field is non-NULL.
//! Never elided; zero is honest (AV-43).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ceg::list::tasks::TaskClass;
use crate::ceg::types::filter::canonical_window_bytes;
use crate::ceg::types::{Aggregate, Filter, TimeWindow};

/// Stable cache method-id for `get_repository_statistics` (FSD §7.2).
pub const REPOSITORY_STATISTICS_METHOD_ID: &str = "get_repository_statistics:v4.0";

/// The process-local substrate cache for repository statistics (FSD
/// §7.1 — "one cache per cohab process").
///
/// A cohabiting peer process running lens + sovereign-agent + bridge
/// shares this single LRU+TTL cache, one memory budget, one eviction
/// policy, one `cache_stats()` observability surface. Constructed lazily
/// with the compile-time deployment-tier defaults
/// ([`crate::cache::CacheConfig::default`]); the [`crate::cache::Cache`]
/// is internally `Mutex`-guarded so concurrent reads share it safely.
static REPOSITORY_STATS_CACHE: std::sync::OnceLock<crate::cache::Cache<RepositoryStatistics>> =
    std::sync::OnceLock::new();

/// Accessor for the process-local repository-statistics cache (§7.1).
/// Both backends route their `get_repository_statistics` through this so
/// the cache key, the scope-disjoint discipline, and the staleness
/// contract are uniform across Postgres + SQLite.
pub fn repository_stats_cache() -> &'static crate::cache::Cache<RepositoryStatistics> {
    REPOSITORY_STATS_CACHE.get_or_init(crate::cache::Cache::new)
}

/// Build the [`crate::cache::CacheKey`] for a `(filter, scope)` pair
/// (FSD §7.2 / §7.3). Folds the filter's `cache_key_digest` + the
/// scope digest + the window-overlap bucket set. Two callers with a
/// different scope digest never share an entry (scope-disjoint, §7.3).
pub fn repository_stats_cache_key(
    filter: &RepositoryFilter,
    scope: &crate::scope::CallerScope,
) -> crate::cache::CacheKey {
    let scope_digest = scope_digest_for(scope);
    crate::cache::CacheKey::new(
        REPOSITORY_STATISTICS_METHOD_ID,
        &filter.cache_key_digest(),
        &scope_digest,
        filter.window.since.timestamp_millis(),
        filter.window.until.timestamp_millis(),
        repository_stats_cache().config().invalidation_bucket,
    )
}

/// Derive the 32-byte scope digest from a [`crate::scope::CallerScope`]
/// (§7.3 scope-disjoint). Unauthenticated → the canonical
/// unauthenticated digest; Authenticated → folds the resolved
/// identity + family + community admission sets.
fn scope_digest_for(scope: &crate::scope::CallerScope) -> [u8; 32] {
    match scope {
        crate::scope::CallerScope::Unauthenticated => {
            crate::cache::key::scope_digest(false, "", &[], &[])
        }
        crate::scope::CallerScope::Authenticated { admission } => {
            let fams: Vec<String> = admission.family_key_ids.iter().cloned().collect();
            let coms: Vec<String> = admission.community_key_ids.iter().cloned().collect();
            crate::cache::key::scope_digest(true, &admission.identity_key_id, &fams, &coms)
        }
    }
}

/// Approximate the resident byte size of a [`RepositoryStatistics`] for
/// the cache's `max_bytes` accounting (§7.2). A coarse estimate — the
/// fixed scalar fields plus the variable map / vec entries — is enough
/// for LRU budgeting; exactness is not load-bearing.
pub fn estimate_size(stats: &RepositoryStatistics) -> usize {
    let base = std::mem::size_of::<RepositoryStatistics>();
    let conscience = stats.conscience.by_check.len() * 64;
    let actions = stats.actions.distribution.len() * 48;
    let fragility = stats.fragility.phase_distribution.len() * 48;
    let domains = stats
        .by_domain
        .iter()
        .map(|d| 64 + d.domain.len())
        .sum::<usize>();
    base + conscience + actions + fragility + domains
}

/// Filter for [`crate::ceg::ReadEngine::get_repository_statistics`]
/// (FSD §5.2).
///
/// `window` is required (statistics are inherently windowed). The list
/// fields compose AND-style; an empty list means "no restriction on this
/// dimension". `task_classes` and `fragility_only` are **discriminators**
/// — they change the answer but are not part of the [`Filter`] base
/// shape, so [`RepositoryFilter`] overrides
/// [`Filter::cache_key_digest`] to fold them in (FSD §5.1; the parity
/// suite enforces this).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryFilter {
    /// Window on `ts`. Required.
    pub window: TimeWindow,
    /// Filter by `agent_id_hash`. Empty = all agents.
    #[serde(default)]
    pub agent_id_hashes: Vec<String>,
    /// Filter by `deployment_domain`. Empty = all domains.
    #[serde(default)]
    pub deployment_domains: Vec<String>,
    /// Restrict to these `cohort_scope` tiers. Empty = scope-default
    /// (the §4.3 predicate's admitted set for the caller).
    #[serde(default)]
    pub cohort_scope_in: Vec<String>,
    /// Restrict to these task classes (`task_id` prefix match).
    /// Empty = all classes. **Discriminator** (FSD §5.1).
    #[serde(default)]
    pub task_classes: Vec<TaskClass>,
    /// CEG 0.5+ fragility filter — restrict to fragile traces only.
    /// **Discriminator** (FSD §5.1).
    #[serde(default)]
    pub fragility_only: bool,
}

impl Filter for RepositoryFilter {
    fn window(&self) -> &TimeWindow {
        &self.window
    }
    fn agent_id_hashes(&self) -> &[String] {
        &self.agent_id_hashes
    }
    fn deployment_domains(&self) -> &[String] {
        &self.deployment_domains
    }
    fn cohort_scope_in(&self) -> &[String] {
        &self.cohort_scope_in
    }

    /// MUST override (FSD §5.1) — `task_classes` + `fragility_only` are
    /// result-changing discriminators the default impl does not capture.
    fn cache_key_digest(&self) -> [u8; 32] {
        let mut h = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut h, b"RepositoryFilter:v4.0\0");
        sha2::Digest::update(&mut h, canonical_window_bytes(&self.window));
        for a in &self.agent_id_hashes {
            sha2::Digest::update(&mut h, a.as_bytes());
            sha2::Digest::update(&mut h, b"\0");
        }
        sha2::Digest::update(&mut h, b"|d\0");
        for d in &self.deployment_domains {
            sha2::Digest::update(&mut h, d.as_bytes());
            sha2::Digest::update(&mut h, b"\0");
        }
        sha2::Digest::update(&mut h, b"|s\0");
        for s in &self.cohort_scope_in {
            sha2::Digest::update(&mut h, s.as_bytes());
            sha2::Digest::update(&mut h, b"\0");
        }
        // discriminators
        sha2::Digest::update(&mut h, b"|tc\0");
        for c in &self.task_classes {
            sha2::Digest::update(&mut h, c.as_wire_str().as_bytes());
            sha2::Digest::update(&mut h, b"\0");
        }
        sha2::Digest::update(&mut h, b"|fr\0");
        sha2::Digest::update(&mut h, [self.fragility_only as u8]);
        sha2::Digest::finalize(h).into()
    }
}

/// Corpus-wide repository statistics (FSD §6.2, #159).
///
/// The single-round-trip aggregate that drives `/repository/statistics`.
/// Every sub-aggregate carries its own `sample_count` (FSD §6.3); the
/// top-level `sample_count` is the scope-filtered windowed trace count.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepositoryStatistics {
    /// The window the rollup covers.
    pub period: TimeWindow,
    /// Trace / agent / domain totals.
    pub totals: Totals,
    /// DMA score distributions.
    pub scores: ScoreAggregates,
    /// Conscience pass / override rates + per-check breakdown.
    pub conscience: ConscienceAggregates,
    /// HDMA action histogram + success rate.
    pub actions: ActionAggregates,
    /// Fragility rate + phase histogram.
    pub fragility: FragilityAggregates,
    /// Per-deployment-domain breakdown.
    pub by_domain: Vec<DomainBreakdown>,

    /// Top-level sample count — scope-filtered windowed trace count
    /// (FSD §6.1 / §6.3). Never elided; zero is honest (AV-43).
    pub sample_count: i64,
    /// Unix-ms the aggregate was computed against the backend (the
    /// *cached* time when `cache_hit`).
    pub evaluated_at_unix_ms: i64,
    /// `true` iff served from the substrate cache (§7).
    pub cache_hit: bool,
}

impl Aggregate for RepositoryStatistics {
    fn sample_count(&self) -> i64 {
        self.sample_count
    }
    fn evaluated_at_unix_ms(&self) -> i64 {
        self.evaluated_at_unix_ms
    }
    fn cache_hit(&self) -> bool {
        self.cache_hit
    }
}

/// Trace / agent / domain totals (FSD §6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    /// Distinct traces in the scope-filtered window.
    pub traces: i64,
    /// Distinct `agent_id_hash` count over the window.
    pub agents: i64,
    /// Distinct `deployment_domain` count over the window.
    pub domains: i64,
}

/// DMA score distributions (FSD §6.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoreAggregates {
    /// CSDMA plausibility distribution (`csdma_plausibility_score`).
    pub plausibility: ScoreDistribution,
    /// DSDMA domain-alignment distribution (`dsdma_domain_alignment`).
    pub alignment: ScoreDistribution,
}

/// A single score's distribution (FSD §6.2). `sample_count` is always
/// present — the count of traces whose per-trace score was non-NULL.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoreDistribution {
    /// Arithmetic mean over contributing traces.
    pub mean: f64,
    /// Sample standard deviation.
    pub std: f64,
    /// Median (50th percentile).
    pub p50: f64,
    /// 95th percentile.
    pub p95: f64,
    /// Traces contributing to this distribution (non-NULL score).
    pub sample_count: i64,
}

/// Conscience pass / override rates + per-check breakdown (FSD §6.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConscienceAggregates {
    /// Fraction of contributing traces whose conscience passed.
    pub pass_rate: f64,
    /// Fraction whose action was overridden.
    pub override_rate: f64,
    /// Per-check pass rate. Keys are the canonical sub-check names
    /// (`entropy` / `coherence` / `optimization_veto` /
    /// `epistemic_humility`).
    pub by_check: BTreeMap<String, ConsciencePerCheck>,
    /// Traces with a conscience record (non-NULL `conscience_passed`).
    pub sample_count: i64,
}

/// One conscience sub-check's pass rate (FSD §6.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsciencePerCheck {
    /// Fraction of contributing traces this check passed.
    pub pass_rate: f64,
    /// Traces where this specific check ran (non-NULL flag).
    pub sample_count: i64,
}

/// HDMA action histogram + success rate (FSD §6.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionAggregates {
    /// Action name → fraction of action-emitting traces. Keys are the
    /// raw `action_executed` strings the writer emitted (lowercased).
    pub distribution: BTreeMap<String, f64>,
    /// `action_success == true` rate over action-emitting traces.
    pub success_rate: f64,
    /// Traces that emitted an action (non-NULL `selected_action`).
    pub sample_count: i64,
}

/// Fragility rate + phase histogram (FSD §6.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FragilityAggregates {
    /// Fraction of classified traces flagged fragile.
    pub fragile_trace_rate: f64,
    /// `idma_phase` value → fraction of classified traces.
    pub phase_distribution: BTreeMap<String, f64>,
    /// Traces with a fragility classification (non-NULL flag/phase).
    pub sample_count: i64,
}

/// Per-deployment-domain breakdown (FSD §6.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainBreakdown {
    /// The `deployment_domain` value.
    pub domain: String,
    /// Traces attributed to this domain in the window.
    pub traces: i64,
    /// Mean plausibility over this domain's traces with a score.
    pub avg_plausibility: f64,
    /// Mean alignment over this domain's traces with a score.
    pub avg_alignment: f64,
    /// Traces in this domain contributing to the averages.
    pub sample_count: i64,
}

/// The per-trace rolled-up row both backends materialize before the
/// second aggregation pass. One row per `trace_id`; the score / flag
/// fields are the per-trace `payload`-extraction rollups (Postgres
/// `FILTER` / SQLite `CASE`). `Option` everywhere a trace may not have
/// emitted the corresponding event so the §6.3 `sample_count` excludes
/// NULLs honestly.
///
/// Shared so the Postgres single-CTE result rows and the SQLite
/// two-step temp rows both decode into one shape, and the Rust-side
/// fold ([`fold_statistics`]) produces a byte-identical struct for the
/// parity suite (FSD §10.4).
#[derive(Debug, Clone, Default)]
pub struct PerTraceRow {
    /// `deployment_domain` (NULL-domain traces fold into `""`).
    pub deployment_domain: Option<String>,
    /// `agent_id_hash` — for the distinct-agent total.
    pub agent_id_hash: Option<String>,
    /// Per-trace mean CSDMA plausibility (NULL if no DMA_RESULTS).
    pub plausibility: Option<f64>,
    /// Per-trace mean DSDMA alignment (NULL if no DMA_RESULTS).
    pub alignment: Option<f64>,
    /// Per-trace conscience pass (NULL if no CONSCIENCE_RESULT).
    pub conscience_passed: Option<bool>,
    /// Per-trace action-overridden flag.
    pub action_was_overridden: Option<bool>,
    /// Per-check pass flags (NULL if that check did not run).
    pub entropy_passed: Option<bool>,
    /// See [`Self::entropy_passed`].
    pub coherence_passed: Option<bool>,
    /// See [`Self::entropy_passed`].
    pub optimization_veto_passed: Option<bool>,
    /// See [`Self::entropy_passed`].
    pub epistemic_humility_passed: Option<bool>,
    /// Selected action string (NULL if no ACTION_RESULT).
    pub selected_action: Option<String>,
    /// Action success flag.
    pub action_success: Option<bool>,
    /// Fragility flag (NULL if no IDMA_RESULT).
    pub fragility_flag: Option<bool>,
    /// Fragility phase string.
    pub fragility_phase: Option<String>,
}

/// Fold a set of per-trace rows into the [`RepositoryStatistics`] shape.
///
/// Backend-agnostic: both Postgres and SQLite materialize the same
/// [`PerTraceRow`] set (already scope-filtered + windowed) and call this
/// to produce a byte-identical struct modulo `evaluated_at_unix_ms`
/// (FSD §10.4 parity). The caller supplies `period` + the cache/eval
/// fields.
pub fn fold_statistics(
    period: TimeWindow,
    rows: &[PerTraceRow],
    evaluated_at_unix_ms: i64,
    cache_hit: bool,
) -> RepositoryStatistics {
    let total = rows.len() as i64;

    // Totals — distinct agents + domains.
    let mut agents = std::collections::BTreeSet::new();
    let mut domains = std::collections::BTreeSet::new();
    for r in rows {
        if let Some(a) = &r.agent_id_hash {
            agents.insert(a.clone());
        }
        if let Some(d) = &r.deployment_domain {
            domains.insert(d.clone());
        }
    }
    let totals = Totals {
        traces: total,
        agents: agents.len() as i64,
        domains: domains.len() as i64,
    };

    // Score distributions.
    let plausibility = score_distribution(rows.iter().filter_map(|r| r.plausibility));
    let alignment = score_distribution(rows.iter().filter_map(|r| r.alignment));
    let scores = ScoreAggregates {
        plausibility,
        alignment,
    };

    // Conscience.
    let conscience = {
        let with_record: Vec<&PerTraceRow> = rows
            .iter()
            .filter(|r| r.conscience_passed.is_some())
            .collect();
        let n = with_record.len() as i64;
        let passes = with_record
            .iter()
            .filter(|r| r.conscience_passed == Some(true))
            .count() as i64;
        let overrides = with_record
            .iter()
            .filter(|r| r.action_was_overridden == Some(true))
            .count() as i64;
        let mut by_check = BTreeMap::new();
        for (name, sel) in [
            ("entropy", per_check_sel(0)),
            ("coherence", per_check_sel(1)),
            ("optimization_veto", per_check_sel(2)),
            ("epistemic_humility", per_check_sel(3)),
        ] {
            let ran: Vec<bool> = rows.iter().filter_map(sel).collect();
            let cn = ran.len() as i64;
            let cp = ran.iter().filter(|p| **p).count() as i64;
            by_check.insert(
                name.to_string(),
                ConsciencePerCheck {
                    pass_rate: rate(cp, cn),
                    sample_count: cn,
                },
            );
        }
        ConscienceAggregates {
            pass_rate: rate(passes, n),
            override_rate: rate(overrides, n),
            by_check,
            sample_count: n,
        }
    };

    // Actions.
    let actions = {
        let with_action: Vec<&PerTraceRow> = rows
            .iter()
            .filter(|r| r.selected_action.is_some())
            .collect();
        let n = with_action.len() as i64;
        let mut counts: BTreeMap<String, i64> = BTreeMap::new();
        for r in &with_action {
            if let Some(a) = &r.selected_action {
                *counts.entry(a.to_ascii_lowercase()).or_insert(0) += 1;
            }
        }
        let distribution = counts
            .into_iter()
            .map(|(k, c)| (k, rate(c, n)))
            .collect::<BTreeMap<_, _>>();
        let successes = with_action
            .iter()
            .filter(|r| r.action_success == Some(true))
            .count() as i64;
        ActionAggregates {
            distribution,
            success_rate: rate(successes, n),
            sample_count: n,
        }
    };

    // Fragility.
    let fragility = {
        let classified: Vec<&PerTraceRow> = rows
            .iter()
            .filter(|r| r.fragility_flag.is_some() || r.fragility_phase.is_some())
            .collect();
        let n = classified.len() as i64;
        let fragile = classified
            .iter()
            .filter(|r| r.fragility_flag == Some(true))
            .count() as i64;
        let mut phase_counts: BTreeMap<String, i64> = BTreeMap::new();
        for r in &classified {
            if let Some(p) = &r.fragility_phase {
                *phase_counts.entry(p.to_ascii_lowercase()).or_insert(0) += 1;
            }
        }
        let phase_distribution = phase_counts
            .into_iter()
            .map(|(k, c)| (k, rate(c, n)))
            .collect::<BTreeMap<_, _>>();
        FragilityAggregates {
            fragile_trace_rate: rate(fragile, n),
            phase_distribution,
            sample_count: n,
        }
    };

    // Per-domain breakdown — ordered by domain for deterministic parity.
    let by_domain = {
        let mut grouped: BTreeMap<String, Vec<&PerTraceRow>> = BTreeMap::new();
        for r in rows {
            if let Some(d) = &r.deployment_domain {
                grouped.entry(d.clone()).or_default().push(r);
            }
        }
        grouped
            .into_iter()
            .map(|(domain, drows)| {
                let plaus: Vec<f64> = drows.iter().filter_map(|r| r.plausibility).collect();
                let align: Vec<f64> = drows.iter().filter_map(|r| r.alignment).collect();
                // sample_count = traces with at least one of the two scores.
                let contributing = drows
                    .iter()
                    .filter(|r| r.plausibility.is_some() || r.alignment.is_some())
                    .count() as i64;
                DomainBreakdown {
                    domain,
                    traces: drows.len() as i64,
                    avg_plausibility: mean(&plaus),
                    avg_alignment: mean(&align),
                    sample_count: contributing,
                }
            })
            .collect()
    };

    RepositoryStatistics {
        period,
        totals,
        scores,
        conscience,
        actions,
        fragility,
        by_domain,
        sample_count: total,
        evaluated_at_unix_ms,
        cache_hit,
    }
}

/// Selector for one of the four per-check flags, indexed 0..=3 in the
/// `CONSCIENCE_CHECKS` order.
fn per_check_sel(idx: usize) -> fn(&PerTraceRow) -> Option<bool> {
    match idx {
        0 => |r: &PerTraceRow| r.entropy_passed,
        1 => |r: &PerTraceRow| r.coherence_passed,
        2 => |r: &PerTraceRow| r.optimization_veto_passed,
        _ => |r: &PerTraceRow| r.epistemic_humility_passed,
    }
}

/// `numer / denom` as f64; `0.0` when `denom == 0` (honest zero, never
/// NaN — FSD §6.3 "zero is honest").
fn rate(numer: i64, denom: i64) -> f64 {
    if denom == 0 {
        0.0
    } else {
        numer as f64 / denom as f64
    }
}

/// Arithmetic mean; `0.0` for an empty slice.
fn mean(v: &[f64]) -> f64 {
    if v.is_empty() {
        0.0
    } else {
        v.iter().sum::<f64>() / v.len() as f64
    }
}

/// Build a [`ScoreDistribution`] from an iterator of per-trace scores.
/// Percentiles use the nearest-rank method on the sorted contributing
/// set; std is the population standard deviation. Empty input yields the
/// all-zero distribution with `sample_count: 0` (FSD §6.3).
fn score_distribution<I: Iterator<Item = f64>>(it: I) -> ScoreDistribution {
    let mut xs: Vec<f64> = it.filter(|x| x.is_finite()).collect();
    let n = xs.len() as i64;
    if xs.is_empty() {
        return ScoreDistribution {
            mean: 0.0,
            std: 0.0,
            p50: 0.0,
            p95: 0.0,
            sample_count: 0,
        };
    }
    let m = mean(&xs);
    let var = xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / xs.len() as f64;
    let std = var.sqrt();
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    ScoreDistribution {
        mean: m,
        std,
        p50: percentile(&xs, 50.0),
        p95: percentile(&xs, 95.0),
        sample_count: n,
    }
}

/// Nearest-rank percentile on a sorted, non-empty slice.
fn percentile(sorted: &[f64], pct: f64) -> f64 {
    debug_assert!(!sorted.is_empty());
    let rank = (pct / 100.0 * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn window() -> TimeWindow {
        TimeWindow::new(
            Utc.timestamp_opt(0, 0).unwrap(),
            Utc.timestamp_opt(7 * 86_400, 0).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn empty_window_is_zero_not_error() {
        let stats = fold_statistics(window(), &[], 123, false);
        assert_eq!(stats.sample_count, 0);
        assert_eq!(stats.totals.traces, 0);
        assert_eq!(stats.totals.agents, 0);
        assert_eq!(stats.scores.plausibility.sample_count, 0);
        assert_eq!(stats.scores.plausibility.mean, 0.0);
        assert_eq!(stats.conscience.sample_count, 0);
        assert_eq!(stats.actions.sample_count, 0);
        assert_eq!(stats.fragility.sample_count, 0);
        assert!(stats.by_domain.is_empty());
        assert!(!stats.cache_hit);
        assert_eq!(stats.evaluated_at_unix_ms, 123);
    }

    #[test]
    fn small_n_reported_faithfully_and_nested_excludes_nulls() {
        // 3 traces total; 2 with plausibility, 1 with conscience, all
        // distinct domains/agents — §6.3 top-vs-nested.
        let rows = vec![
            PerTraceRow {
                deployment_domain: Some("d1".into()),
                agent_id_hash: Some("a1".into()),
                plausibility: Some(0.8),
                alignment: Some(0.5),
                conscience_passed: Some(true),
                entropy_passed: Some(true),
                selected_action: Some("SPEAK".into()),
                action_success: Some(true),
                fragility_flag: Some(false),
                fragility_phase: Some("flexibility".into()),
                ..Default::default()
            },
            PerTraceRow {
                deployment_domain: Some("d1".into()),
                agent_id_hash: Some("a2".into()),
                plausibility: Some(0.6),
                ..Default::default()
            },
            PerTraceRow {
                deployment_domain: Some("d2".into()),
                agent_id_hash: Some("a1".into()),
                ..Default::default()
            },
        ];
        let s = fold_statistics(window(), &rows, 7, false);
        assert_eq!(s.sample_count, 3, "top-level = windowed trace count");
        assert_eq!(s.totals.agents, 2);
        assert_eq!(s.totals.domains, 2);
        // plausibility contributed by 2 of 3.
        assert_eq!(s.scores.plausibility.sample_count, 2);
        assert!((s.scores.plausibility.mean - 0.7).abs() < 1e-9);
        // alignment contributed by 1 of 3.
        assert_eq!(s.scores.alignment.sample_count, 1);
        // conscience recorded on 1 of 3.
        assert_eq!(s.conscience.sample_count, 1);
        assert_eq!(s.conscience.pass_rate, 1.0);
        // entropy check ran on exactly 1.
        assert_eq!(s.conscience.by_check["entropy"].sample_count, 1);
        // coherence never ran.
        assert_eq!(s.conscience.by_check["coherence"].sample_count, 0);
        assert_eq!(s.conscience.by_check["coherence"].pass_rate, 0.0);
        // action on 1.
        assert_eq!(s.actions.sample_count, 1);
        assert_eq!(s.actions.distribution["speak"], 1.0);
        assert_eq!(s.actions.success_rate, 1.0);
        // fragility classified on 1.
        assert_eq!(s.fragility.sample_count, 1);
        assert_eq!(s.fragility.fragile_trace_rate, 0.0);
        assert_eq!(s.fragility.phase_distribution["flexibility"], 1.0);
        // by_domain: d1 has 2 traces (1 contributing), d2 has 1 (0).
        assert_eq!(s.by_domain.len(), 2);
        let d1 = s.by_domain.iter().find(|d| d.domain == "d1").unwrap();
        assert_eq!(d1.traces, 2);
        assert_eq!(d1.sample_count, 2);
        let d2 = s.by_domain.iter().find(|d| d.domain == "d2").unwrap();
        assert_eq!(d2.traces, 1);
        assert_eq!(d2.sample_count, 0);
    }

    #[test]
    fn percentile_nearest_rank() {
        let xs: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        assert_eq!(percentile(&xs, 50.0), 50.0);
        assert_eq!(percentile(&xs, 95.0), 95.0);
    }

    #[test]
    fn filter_digest_folds_discriminators() {
        let base = RepositoryFilter {
            window: window(),
            agent_id_hashes: vec![],
            deployment_domains: vec![],
            cohort_scope_in: vec![],
            task_classes: vec![],
            fragility_only: false,
        };
        let with_tc = RepositoryFilter {
            task_classes: vec![TaskClass::QaEval],
            ..base.clone()
        };
        let with_frag = RepositoryFilter {
            fragility_only: true,
            ..base.clone()
        };
        // Discriminators change the digest (FSD §5.1 parity).
        assert_ne!(base.cache_key_digest(), with_tc.cache_key_digest());
        assert_ne!(base.cache_key_digest(), with_frag.cache_key_digest());
        assert_ne!(with_tc.cache_key_digest(), with_frag.cache_key_digest());
        // Stable for identical filters.
        assert_eq!(base.cache_key_digest(), base.clone().cache_key_digest());
    }
}
