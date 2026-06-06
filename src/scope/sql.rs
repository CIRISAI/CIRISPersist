//! [`cohort_scope_sql_predicate`] — the §4.3 read-side admission gate
//! as a SQL WHERE-fragment + bind params, for both backends.
//!
//! # The model (FSD §4.3 — target-membership)
//!
//! `cohort_scope` is the CEG visibility/routing axis; its value is
//! **formed upstream** by the producer's trust/distribution policy and
//! the substrate only **records** it (MISSION §1.7). A scoped row carries
//! both its `cohort_scope` AND the scope **target** it was routed to
//! (`family_id` / `community_id`, or — for `self` — the owner identity the
//! substrate resolved from the verified signer at write). The read-gate is
//! **pure set-membership**: a reader sees the row iff the reader belongs to
//! the *specific target cohort the row names*.
//!
//! This is deliberately NOT "emitter and reader share a cohort" — that
//! formulation leaks (an agent in communities A+B routing a row to B only
//! would expose it to an A-only co-member). Target-membership eliminates
//! the leak and eliminates the emitter→identity join entirely: the
//! predicate compares the row's `cohort_target_id` against the reader's
//! already-resolved [`CallerAdmission`](super::admission::CallerAdmission)
//! sets. No subquery, no join.
//!
//! The fragment AND-composes into the caller's existing WHERE and is
//! always parenthesized. Bind params are returned positionally in
//! [`ScopeParam`] order; Postgres placeholders are emitted starting at
//! `$1` (Commit E rebinds them when composing into a larger statement),
//! SQLite uses `?`.
//!
//! # Scope-tier coverage (v4.0)
//!
//! Precise target-membership is gated on the cohorts that have a
//! membership substrate: `self` (identity_occurrences V059), `family`
//! (federation_families V059), `community` (federation_communities V060).
//! The broad belonging-tiers `affiliations` / `species` / `biosphere` /
//! `federation` carry no per-row target and have no membership table, so
//! they are admitted as broad tiers (any authenticated reader;
//! `federation` also to the unauthenticated).

use super::caller::CallerScope;

/// Which SQL dialect to emit (FSD §4.3). There is no existing crate-wide
/// backend-kind enum — the backends are distinguished structurally via
/// [`crate::engine::BackendDispatch`] match arms — so this minimal
/// two-variant enum drives the predicate emitter. The backend
/// implementations map their `BackendDispatch` arm to a `BackendKind`
/// when calling this helper.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BackendKind {
    /// Postgres dialect (`$n` placeholders, `= ANY($n)` array membership).
    Postgres,
    /// SQLite dialect (`?` placeholders, `IN (?,?,…)` membership).
    Sqlite,
}

/// A single positional bind parameter produced by
/// [`cohort_scope_sql_predicate`]. The caller binds these, in order,
/// against the fragment's placeholders.
///
/// There is no existing crate-wide dynamic-SQL param enum (the backends
/// bind statically-typed `&[&(dyn ToSql)]` / `params![]` at each call
/// site), so this minimal carrier bridges. The backend impl maps each
/// variant to its native bind type at the call site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeParam {
    /// A single key id (the reader's resolved identity, or one expanded
    /// family/community key on SQLite).
    Key(String),
    /// A list of key ids — the reader's family or community admission
    /// set. Postgres binds this as one array param (`= ANY($n)`); SQLite
    /// expands it into one `?` per element (`IN (?,?,…)`) and the emitter
    /// pushes one [`ScopeParam::Key`] each instead of a `KeyList`.
    KeyList(Vec<String>),
}

/// The broad belonging-tiers, admitted with no per-row target. `self`,
/// `family`, `community` are membership-gated and NOT in this set.
const BROAD_TIERS: &[&str] = &["affiliations", "species", "biosphere", "federation"];

/// SQL string-literal list of the broad tiers, e.g.
/// `'affiliations','species','biosphere','federation'`.
fn broad_tiers_sql() -> String {
    BROAD_TIERS
        .iter()
        .map(|t| format!("'{t}'"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Emit the SQL fragment + params enforcing read-side cohort_scope
/// admission for the given caller scope (FSD §4.3). The fragment
/// AND-composes into the caller's WHERE.
///
/// - `scope_col` — the row's `cohort_scope` column reference (caller
///   qualifies, e.g. `"t.cohort_scope"`).
/// - `target_col` — the row's `cohort_target_id` column reference (the
///   `family_id`/`community_id`/owner-identity the row was scoped to).
///
/// Postgres placeholders start at `$1`; Commit E rebinds them when
/// composing into a larger statement.
pub fn cohort_scope_sql_predicate(
    backend: BackendKind,
    scope_col: &str,
    target_col: &str,
    scope: &CallerScope,
) -> (String, Vec<ScopeParam>) {
    let broad = broad_tiers_sql();

    match scope {
        // Unauthenticated — only the broad belonging-tiers. No target,
        // no membership, no params. Self/family/community are
        // membership-gated and an unauthenticated reader proves nothing.
        CallerScope::Unauthenticated => (format!("({scope_col} IN ({broad}))"), Vec::new()),

        // Authenticated — broad tiers OR target-membership on
        // self/family/community. Placeholders assigned left-to-right in
        // the order params is built.
        CallerScope::Authenticated { admission } => {
            let mut params: Vec<ScopeParam> = Vec::new();
            let mut next = 1usize;

            // self — the row's target IS an owner identity; reader sees it
            // iff that identity is the reader's own.
            let id_ph = placeholder(backend, &mut next);
            params.push(ScopeParam::Key(admission.identity_key_id.clone()));
            let self_branch = format!("({scope_col} = 'self' AND {target_col} = {id_ph})");

            // family — target ∈ the reader's admitted families.
            let family_branch = target_membership_branch(
                backend,
                scope_col,
                target_col,
                "family",
                &admission.family_key_ids,
                &mut next,
                &mut params,
            );

            // community — target ∈ the reader's admitted communities.
            let community_branch = target_membership_branch(
                backend,
                scope_col,
                target_col,
                "community",
                &admission.community_key_ids,
                &mut next,
                &mut params,
            );

            let frag = format!(
                "({scope_col} IN ({broad}) \
                 OR {self_branch} \
                 OR {family_branch} \
                 OR {community_branch})"
            );
            (frag, params)
        }
    }
}

/// Emit a `$n` (Postgres) or `?` (SQLite) placeholder, advancing the
/// Postgres counter.
fn placeholder(backend: BackendKind, next: &mut usize) -> String {
    match backend {
        BackendKind::Postgres => {
            let s = format!("${next}");
            *next += 1;
            s
        }
        BackendKind::Sqlite => "?".to_string(),
    }
}

/// Build a `family`/`community` target-membership branch: admit a
/// `cohort_scope: <label>` row iff its `target_col` is one of the
/// reader's admitted cohort keys. Pure set-membership — no join.
///
/// Empty admission set (the §4.4 singleton fallback, or a reader in no
/// families/communities) → constant-false `(scope_col = '<label>' AND
/// 1=0)`: the reader is in no such cohort, so no row at that label is
/// admitted. No params in that case.
fn target_membership_branch(
    backend: BackendKind,
    scope_col: &str,
    target_col: &str,
    label: &str,
    admission_keys: &std::collections::BTreeSet<String>,
    next: &mut usize,
    params: &mut Vec<ScopeParam>,
) -> String {
    if admission_keys.is_empty() {
        return format!("({scope_col} = '{label}' AND 1=0)");
    }

    let membership = match backend {
        BackendKind::Postgres => {
            let ph = placeholder(backend, next); // single array param
            params.push(ScopeParam::KeyList(
                admission_keys.iter().cloned().collect(),
            ));
            format!("{target_col} = ANY({ph})")
        }
        BackendKind::Sqlite => {
            let mut phs = Vec::with_capacity(admission_keys.len());
            for k in admission_keys {
                phs.push(placeholder(backend, next));
                params.push(ScopeParam::Key(k.clone()));
            }
            format!("{target_col} IN ({})", phs.join(","))
        }
    };

    format!("({scope_col} = '{label}' AND {membership})")
}

#[cfg(test)]
mod tests {
    use super::super::admission::CallerAdmission;
    use super::*;

    fn unauth() -> CallerScope {
        CallerScope::Unauthenticated
    }

    /// Authenticated caller, singleton-identity fallback (§4.4): no
    /// families, no communities.
    fn auth_singleton() -> CallerScope {
        CallerScope::Authenticated {
            admission: CallerAdmission::for_test("occ-1", "occ-1", [], []),
        }
    }

    /// Authenticated caller with identity id-1, in families F1+F2 and
    /// community C1.
    fn auth_full() -> CallerScope {
        CallerScope::Authenticated {
            admission: CallerAdmission::for_test(
                "occ-1",
                "id-1",
                ["F1".to_string(), "F2".to_string()],
                ["C1".to_string()],
            ),
        }
    }

    #[test]
    fn unauthenticated_admits_only_broad_tiers_both_backends() {
        for backend in [BackendKind::Postgres, BackendKind::Sqlite] {
            let (frag, params) = cohort_scope_sql_predicate(
                backend,
                "t.cohort_scope",
                "t.cohort_target_id",
                &unauth(),
            );
            assert_eq!(
                frag,
                "(t.cohort_scope IN ('affiliations','species','biosphere','federation'))"
            );
            assert!(params.is_empty(), "unauth emits no params");
            // membership-gated cohorts never admitted for the unauthenticated
            assert!(!frag.contains("'self'"));
            assert!(!frag.contains("'family'"));
            assert!(!frag.contains("'community'"));
        }
    }

    #[test]
    fn authenticated_singleton_postgres_self_target_eq_identity() {
        let (frag, params) = cohort_scope_sql_predicate(
            BackendKind::Postgres,
            "t.cohort_scope",
            "t.cohort_target_id",
            &auth_singleton(),
        );
        // broad tiers (no community — it's membership-gated now)
        assert!(
            frag.contains("t.cohort_scope IN ('affiliations','species','biosphere','federation')")
        );
        // self: target == reader identity ($1). No join, no subquery.
        assert!(frag.contains("(t.cohort_scope = 'self' AND t.cohort_target_id = $1)"));
        assert!(
            !frag.contains("EXISTS"),
            "target-membership uses no subquery"
        );
        assert!(!frag.contains("occurrence_key_id"), "no emitter join");
        // family + community constant-false (no admission sets)
        assert!(frag.contains("(t.cohort_scope = 'family' AND 1=0)"));
        assert!(frag.contains("(t.cohort_scope = 'community' AND 1=0)"));
        // only the identity param
        assert_eq!(params, vec![ScopeParam::Key("occ-1".to_string())]);
    }

    #[test]
    fn authenticated_singleton_sqlite_uses_question_placeholder() {
        let (frag, params) = cohort_scope_sql_predicate(
            BackendKind::Sqlite,
            "t.cohort_scope",
            "t.cohort_target_id",
            &auth_singleton(),
        );
        assert!(frag.contains("(t.cohort_scope = 'self' AND t.cohort_target_id = ?)"));
        assert!(!frag.contains("$1"), "sqlite never emits $n");
        assert!(frag.contains("(t.cohort_scope = 'family' AND 1=0)"));
        assert_eq!(params, vec![ScopeParam::Key("occ-1".to_string())]);
    }

    #[test]
    fn authenticated_full_postgres_target_any_arrays() {
        let (frag, params) = cohort_scope_sql_predicate(
            BackendKind::Postgres,
            "t.cohort_scope",
            "t.cohort_target_id",
            &auth_full(),
        );
        // self: target == $1 (identity)
        assert!(frag.contains("(t.cohort_scope = 'self' AND t.cohort_target_id = $1)"));
        // family: target ∈ reader families via ANY($2)
        assert!(frag.contains("(t.cohort_scope = 'family' AND t.cohort_target_id = ANY($2))"));
        // community: target ∈ reader communities via ANY($3)
        assert!(frag.contains("(t.cohort_scope = 'community' AND t.cohort_target_id = ANY($3))"));
        assert!(!frag.contains("EXISTS"));
        assert!(!frag.contains("federation_families"), "no roster join");
        // params: identity, family-set, community-set (BTreeSet sorts F1<F2)
        assert_eq!(
            params,
            vec![
                ScopeParam::Key("id-1".to_string()),
                ScopeParam::KeyList(vec!["F1".to_string(), "F2".to_string()]),
                ScopeParam::KeyList(vec!["C1".to_string()]),
            ]
        );
    }

    #[test]
    fn authenticated_full_sqlite_expands_in_lists() {
        let (frag, params) = cohort_scope_sql_predicate(
            BackendKind::Sqlite,
            "t.cohort_scope",
            "t.cohort_target_id",
            &auth_full(),
        );
        // family has 2 keys -> IN (?,?); community 1 -> IN (?)
        assert!(frag.contains("(t.cohort_scope = 'family' AND t.cohort_target_id IN (?,?))"));
        assert!(frag.contains("(t.cohort_scope = 'community' AND t.cohort_target_id IN (?))"));
        // params expanded: identity, F1, F2, C1 (BTreeSet-sorted)
        assert_eq!(
            params,
            vec![
                ScopeParam::Key("id-1".to_string()),
                ScopeParam::Key("F1".to_string()),
                ScopeParam::Key("F2".to_string()),
                ScopeParam::Key("C1".to_string()),
            ]
        );
    }

    /// The leak the target-membership model fixes: a reader sharing
    /// community C1 with an emitter must NOT see a row the emitter scoped
    /// to a DIFFERENT community C2. With target-membership the predicate
    /// only admits `community` rows whose target ∈ {C1}, so a C2-targeted
    /// row is never matched — structurally, not by emitter comparison.
    #[test]
    fn community_row_targeted_elsewhere_is_not_admitted() {
        let (frag, _) = cohort_scope_sql_predicate(
            BackendKind::Postgres,
            "t.cohort_scope",
            "t.cohort_target_id",
            &auth_full(), // admitted community = {C1}
        );
        // The only community admission is target ∈ ANY($3) where $3 = [C1].
        // A row with cohort_target_id = 'C2' fails that membership — there
        // is no emitter-shared-cohort path that could admit it.
        assert!(frag.contains("(t.cohort_scope = 'community' AND t.cohort_target_id = ANY($3))"));
        assert!(
            !frag.contains("members"),
            "no roster containment path exists"
        );
    }

    #[test]
    fn fragment_is_parenthesized_for_and_composition() {
        for scope in [unauth(), auth_singleton(), auth_full()] {
            for backend in [BackendKind::Postgres, BackendKind::Sqlite] {
                let (frag, _) = cohort_scope_sql_predicate(
                    backend,
                    "t.cohort_scope",
                    "t.cohort_target_id",
                    &scope,
                );
                assert!(frag.starts_with('('), "must be parenthesized: {frag}");
                assert!(frag.ends_with(')'), "must be parenthesized: {frag}");
            }
        }
    }
}
