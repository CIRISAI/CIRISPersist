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
    cohort_scope_sql_predicate_with_dimension(backend, scope_col, target_col, None, scope)
}

/// v46.3.1 (PR #889 review, round three) — **the local-tier gate**, the SQL
/// twin of [`CallerScope::admits_local_tier`]: `tier <> 'local' OR
/// attester = caller occurrence` (unauthenticated: `tier <> 'local'`).
/// `FSD/V4_4_SHARED_ATTESTATION_SURFACE.md` §3 — a local-tier row is
/// producer-only authority and visible to its producing occurrence alone;
/// the `self` arm's collective widening never reaches it. Composed by every
/// door over `federation_attestations` that takes a `CallerScope` (pinned
/// from disk). `tier` is `NOT NULL DEFAULT 'federation'` (V066).
pub fn local_tier_sql_predicate(
    backend: BackendKind,
    tier_col: &str,
    attester_col: &str,
    scope: &CallerScope,
) -> (String, Vec<ScopeParam>) {
    match scope {
        CallerScope::Unauthenticated => (format!("({tier_col} <> 'local')"), Vec::new()),
        CallerScope::Authenticated { admission } => {
            let mut next = 1usize;
            let ph = placeholder(backend, &mut next);
            (
                format!("({tier_col} <> 'local' OR {attester_col} = {ph})"),
                vec![ScopeParam::Key(admission.occurrence_key_id.clone())],
            )
        }
    }
}

/// v46.3.1 (PR #889 review) — [`cohort_scope_sql_predicate`] for a table
/// that carries a `dimension` column (the attestation doors): the `self`
/// branch additionally keeps a SENSITIVE `config:*` leaf (CC 3.4.5.1,
/// [`CONFIG_SENSITIVE_LEAVES`](crate::federation::admission::CONFIG_SENSITIVE_LEAVES))
/// node-local — admitted only when the row's target IS the caller's
/// occurrence key — rendered with `substr`/`length` so the SQL matches
/// `scope_covers` byte-for-byte (no `LIKE`, whose case rule differs by
/// backend). Tables without a dimension column pass `None` and carry no
/// config rows.
pub fn cohort_scope_sql_predicate_with_dimension(
    backend: BackendKind,
    scope_col: &str,
    target_col: &str,
    dimension_col: Option<&str>,
    scope: &CallerScope,
) -> (String, Vec<ScopeParam>) {
    cohort_scope_sql_predicate_full(backend, scope_col, target_col, None, dimension_col, scope)
}

/// v46.5.0 (CIRISPersist#893, `FSD/TARGETED_COHORT_READ.md` §3) — the full
/// form: `cohort_target_col` is the ROW's room (the V150 generated column),
/// which the `family` / `community` arms bind against while `self` keeps
/// `target_col`. A caller that passes `None` gets the pre-#893 behaviour for
/// the targeted arms, which is "refuse everything" — so a door that forgets
/// the column fails CLOSED and is caught by I144 rather than leaking.
pub fn cohort_scope_sql_predicate_full(
    backend: BackendKind,
    scope_col: &str,
    target_col: &str,
    cohort_target_col: Option<&str>,
    dimension_col: Option<&str>,
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

            // self — target ∈ the reader's self-collective (v46.3.1, #888:
            // the occurrence, its identity, its principals and their
            // occurrences / owned nodes — resolved the way the hold path
            // resolves the caller, so a claimed node reads its own rows).
            let mut self_branch = target_membership_branch(
                backend,
                scope_col,
                target_col,
                "self",
                &admission.self_key_ids,
                &mut next,
                &mut params,
            );
            if let Some(dim) = dimension_col {
                // node-only for the sensitive leaves: target = caller's
                // occurrence, OR the dimension is not a sensitive leaf.
                let occ_ph = placeholder(backend, &mut next);
                params.push(ScopeParam::Key(admission.occurrence_key_id.clone()));
                let sensitive = crate::federation::admission::CONFIG_SENSITIVE_LEAVES
                    .iter()
                    .map(|leaf| {
                        let n = leaf.len() + 1;
                        format!(
                            "{dim} = '{leaf}' OR (substr({dim}, 1, {n}) = '{leaf}:' AND length({dim}) > {n})"
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" OR ");
                // A row with NO dimension is not a sensitive leaf: `NOT (NULL)`
                // is NULL in SQL and would exclude it for every reader but
                // the writer (PR #889 review, round two) — the Rust twin's
                // `None` is spelled `IS NULL` here.
                self_branch = format!(
                    "({self_branch} AND ({target_col} = {occ_ph} OR {dim} IS NULL OR NOT ({sensitive})))"
                );
            }

            // family — target ∈ the reader's admitted families.
            // The targeted arms key on the ROW's room. `None` means "the
            // target column already IS the room", which is the TRACE plane:
            // `trace_events.cohort_target_id` (V060) is the room, and those
            // arms have always been correct there. Only the ATTESTATION plane
            // needed a second column, because AV-84 pins its `attested_key_id`
            // to the producer (#893). Falling back to `target_col` therefore
            // preserves trace exactly and leaves a door that forgets the
            // column with the pre-#893 behaviour — which refuses, never leaks.
            let room_col = cohort_target_col.unwrap_or(target_col);
            let family_branch = target_membership_branch(
                backend,
                scope_col,
                room_col,
                "family",
                &admission.family_key_ids,
                &mut next,
                &mut params,
            );

            // community — target ∈ the reader's admitted communities.
            let community_branch = target_membership_branch(
                backend,
                scope_col,
                room_col,
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
        assert!(frag.contains("(t.cohort_scope = 'self' AND t.cohort_target_id = ANY($1))"));
        assert!(
            !frag.contains("EXISTS"),
            "target-membership uses no subquery"
        );
        assert!(!frag.contains("occurrence_key_id"), "no emitter join");
        // family + community constant-false (no admission sets)
        assert!(frag.contains("(t.cohort_scope = 'family' AND 1=0)"));
        assert!(frag.contains("(t.cohort_scope = 'community' AND 1=0)"));
        // only the identity param
        assert_eq!(params, vec![ScopeParam::KeyList(vec!["occ-1".to_string()])]);
    }

    #[test]
    fn authenticated_singleton_sqlite_uses_question_placeholder() {
        let (frag, params) = cohort_scope_sql_predicate(
            BackendKind::Sqlite,
            "t.cohort_scope",
            "t.cohort_target_id",
            &auth_singleton(),
        );
        assert!(frag.contains("(t.cohort_scope = 'self' AND t.cohort_target_id IN (?))"));
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
        // self: target ∈ {id-1, occ-1} via ANY($1) (v46.3.1)
        assert!(frag.contains("(t.cohort_scope = 'self' AND t.cohort_target_id = ANY($1))"));
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
                ScopeParam::KeyList(vec!["id-1".to_string(), "occ-1".to_string()]),
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
        // params expanded: id-1, occ-1 (the self set), F1, F2, C1 (BTreeSet-sorted)
        assert_eq!(
            params,
            vec![
                ScopeParam::Key("id-1".to_string()),
                ScopeParam::Key("occ-1".to_string()),
                ScopeParam::Key("F1".to_string()),
                ScopeParam::Key("F2".to_string()),
                ScopeParam::Key("C1".to_string()),
            ]
        );
    }

    #[test]
    fn with_dimension_keeps_sensitive_leaves_node_only_both_backends() {
        for (backend, expect_occ, expect_dim) in [
            (
                BackendKind::Postgres,
                "= $2",
                "substr(t.dimension, 1, 17) = 'config:admission:'",
            ),
            (
                BackendKind::Sqlite,
                "= ?",
                "substr(t.dimension, 1, 17) = 'config:admission:'",
            ),
        ] {
            let (frag, params) = cohort_scope_sql_predicate_with_dimension(
                backend,
                "t.cohort_scope",
                "t.cohort_target_id",
                Some("t.dimension"),
                &auth_singleton(),
            );
            assert!(frag.contains(expect_dim), "{frag}");
            assert!(frag.contains("t.dimension = 'config:transport'"), "{frag}");
            assert!(
                frag.contains(&format!(
                    "t.cohort_target_id {expect_occ} OR t.dimension IS NULL OR NOT ("
                )),
                "{frag}"
            );
            assert!(
                !frag.contains("LIKE"),
                "no LIKE — its case rule differs by backend: {frag}"
            );
            assert!(
                frag.contains("OR t.dimension IS NULL OR NOT ("),
                "a NULL dimension is not sensitive (SQL three-valued logic): {frag}"
            );
            // the occurrence key is bound once more, AFTER the self set
            assert_eq!(
                params.last(),
                Some(&ScopeParam::Key("occ-1".to_string())),
                "{params:?}"
            );
            // without a dimension column: the plain shape, no extra param
            let (plain, pparams) = cohort_scope_sql_predicate(
                backend,
                "t.cohort_scope",
                "t.cohort_target_id",
                &auth_singleton(),
            );
            assert!(!plain.contains("substr("), "{plain}");
            assert_eq!(pparams.len() + 1, params.len());
        }
    }

    #[test]
    fn local_tier_rows_are_their_producers_alone() {
        let (frag, params) = local_tier_sql_predicate(
            BackendKind::Postgres,
            "tier",
            "attesting_key_id",
            &auth_singleton(),
        );
        assert_eq!(frag, "(tier <> 'local' OR attesting_key_id = $1)");
        assert_eq!(params, vec![ScopeParam::Key("occ-1".to_string())]);
        let (frag, params) = local_tier_sql_predicate(
            BackendKind::Sqlite,
            "tier",
            "attesting_key_id",
            &auth_full(),
        );
        assert_eq!(frag, "(tier <> 'local' OR attesting_key_id = ?)");
        assert_eq!(
            params,
            vec![ScopeParam::Key("occ-1".to_string())],
            "the OCCURRENCE, never the identity"
        );
        let (frag, params) = local_tier_sql_predicate(
            BackendKind::Sqlite,
            "tier",
            "attesting_key_id",
            &CallerScope::Unauthenticated,
        );
        assert_eq!(frag, "(tier <> 'local')");
        assert!(params.is_empty());
    }

    /// From disk (PR #889 review): every scope-gated door over
    /// `federation_attestations` — the only tables that carry `config:*`
    /// rows — composes the dimension-aware form. A door that passes the
    /// attested key as target without the dimension column would leak the
    /// sensitive leaves to the collective again.
    #[test]
    fn every_attestation_door_composes_the_dimension_aware_predicate() {
        for file in ["src/store/sqlite.rs", "src/store/postgres.rs"] {
            let src =
                std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/").to_owned() + file)
                    .unwrap();
            let lines: Vec<&str> = src.lines().collect();
            let mut doors = 0;
            for (i, l) in lines.iter().enumerate() {
                if l.trim() == "\"attested_key_id\"," || l.trim() == "\"fa.attested_key_id\"," {
                    let window = lines[i.saturating_sub(4)..i].join("\n");
                    if window.contains("scope_predicate_") {
                        doors += 1;
                        assert!(
                            window.contains("_with_dimension("),
                            "{file}:{}: an attestation door composes the scope predicate without its dimension column",
                            i + 1
                        );
                        let after = lines[i..(i + 16).min(lines.len())].join("\n");
                        assert!(
                            after.contains("local_tier_predicate_"),
                            "{file}:{}: an attestation door composes the scope predicate without the local-tier gate (V4.4 §3)",
                            i + 1
                        );
                    }
                }
            }
            assert!(
                doors >= 3,
                "{file}: expected the attestation doors, found {doors}"
            );
        }
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
