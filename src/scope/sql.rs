//! [`cohort_scope_sql_predicate`] — the §4.3 read-side admission gate
//! as a SQL WHERE-fragment + bind params, for both backends.
//!
//! The fragment AND-composes into the caller's existing WHERE. It is
//! always parenthesized so AND-composition is sound regardless of the
//! caller's surrounding clause. Bind params are returned positionally
//! in [`ScopeParam`] order; the caller binds them after its own params
//! (Postgres `$n` placeholders are emitted relative to a caller-supplied
//! base offset, see [`cohort_scope_sql_predicate`]'s `first_param_index`
//! — Commit B emits a self-contained fragment starting at `$1`; Commit E
//! threads the real offset when it composes the fragment into a larger
//! statement).
//!
//! # Backend dialect (mirrors the existing V059 family reads)
//!
//! | Construct            | Postgres                              | SQLite                                            |
//! |----------------------|---------------------------------------|---------------------------------------------------|
//! | scope label fetch    | `<scope_col>` (TEXT column)           | `<scope_col>` (TEXT column)                        |
//! | table qualification  | `cirislens.federation_*`              | `federation_*` (unqualified)                      |
//! | members containment  | `members @> '[{"key_id":..}]'`        | `EXISTS(SELECT 1 FROM json_each(members) WHERE json_extract(value,'$.key_id')=?)` |
//! | list membership      | `f.family_key_id = ANY($n)`           | `f.family_key_id IN (?,?,…)`                       |
//! | placeholder          | `$n`                                  | `?`                                               |
//!
//! `scope_col` is documented in §4.3 as "`cohort_scope` (TEXT) or a
//! JSON path". Both backends store `cohort_scope` as a TEXT column on
//! `trace_events` / `federation_attestations` (V057 indexed it as
//! such), so this helper treats `scope_col` as a column reference and
//! does NOT JSON-extract it. A caller passing a JSON-path scope_col is
//! out of contract for v4.0.

use super::caller::CallerScope;

/// Which SQL dialect to emit (FSD §4.3). There is no existing crate-wide
/// backend-kind enum — the backends are distinguished structurally via
/// [`crate::engine::BackendDispatch`] match arms — so Commit B defines
/// this minimal two-variant enum for the predicate emitter. Commit E /
/// the backend implementations map their `BackendDispatch` arm to a
/// `BackendKind` when calling this helper.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BackendKind {
    /// Postgres dialect (`$n` placeholders, `@>`, `= ANY`, schema-qualified
    /// `cirislens.federation_*` tables).
    Postgres,
    /// SQLite dialect (`?` placeholders, `json_each` / `json_extract`,
    /// unqualified `federation_*` tables).
    Sqlite,
}

/// A single positional bind parameter produced by
/// [`cohort_scope_sql_predicate`]. The caller binds these, in order,
/// against the fragment's placeholders.
///
/// There is no existing crate-wide dynamic-SQL param enum (the backends
/// bind statically-typed `&[&(dyn ToSql)]` / `params![]` at each call
/// site), so Commit B defines this minimal carrier. Commit E maps each
/// variant to the backend's native bind type at the call site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeParam {
    /// A single key id — the caller's resolved identity key
    /// (`$caller_identity_key_id`).
    Key(String),
    /// A list of key ids — the caller's family or community admission
    /// set. Postgres binds this as a single array param (`= ANY($n)`);
    /// SQLite expands it into one `?` per element (`IN (?,?,…)`), and
    /// the helper emits exactly `keys.len()` `ScopeParam::Key` entries
    /// in that case instead of a single `KeyList` (see emitter).
    KeyList(Vec<String>),
}

/// The non-suppressed cohort tiers any caller (authenticated or not)
/// may read, per §8.1.13.3. `self` and `family` are suppressed;
/// `community` is non-suppressed for the *broad* admit but ALSO has a
/// membership-gated branch on the authenticated side (a community row
/// is broadly visible per §8.1.13.3's NO-suppression semantics — the
/// extra EXISTS branch in §4.3 is the membership *narrowing* path used
/// when a consumer wants member-only community visibility).
const BROAD_TIERS: &[&str] = &[
    "community",
    "affiliations",
    "species",
    "biosphere",
    "federation",
];

/// SQL string literal list of the broad tiers, e.g.
/// `'community','affiliations','species','biosphere','federation'`.
fn broad_tiers_sql() -> String {
    BROAD_TIERS
        .iter()
        .map(|t| format!("'{t}'"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Fully-qualified table name for the dialect.
fn table(backend: BackendKind, name: &str) -> String {
    match backend {
        BackendKind::Postgres => format!("cirislens.{name}"),
        BackendKind::Sqlite => name.to_string(),
    }
}

/// Emit the SQL fragment + params enforcing read-side cohort_scope
/// admission for the given caller scope (FSD §4.3). The fragment
/// AND-composes into the caller's WHERE. Returns the fragment + bind
/// params, matching backend dialect.
///
/// - `table_alias` — alias of the row table in the caller's query
///   (e.g. `"t"` for `trace_events t`). Used to qualify `emitter_key_col`
///   / `scope_col`.
/// - `emitter_key_col` — the column holding the row's emitter occurrence
///   key (e.g. `"scrub_key_id"` or `"author_key_id"`).
/// - `scope_col` — the TEXT column holding the row's `cohort_scope`.
///
/// Postgres placeholders are emitted starting at `$1`; Commit E rebinds
/// them when composing into a larger statement.
pub fn cohort_scope_sql_predicate(
    backend: BackendKind,
    table_alias: &str,
    emitter_key_col: &str,
    scope_col: &str,
    scope: &CallerScope,
) -> (String, Vec<ScopeParam>) {
    let scope_ref = format!("{table_alias}.{scope_col}");
    let emitter_ref = format!("{table_alias}.{emitter_key_col}");
    let broad = broad_tiers_sql();

    match scope {
        // Unauthenticated — only the non-suppressed tiers. No params.
        CallerScope::Unauthenticated => {
            let frag = format!("({scope_ref} IN ({broad}))");
            (frag, Vec::new())
        }

        // Authenticated — broad tiers OR self/family/community by
        // admission resolution. Placeholders are assigned left-to-right
        // in the order the params Vec is built.
        CallerScope::Authenticated { admission } => {
            let mut params: Vec<ScopeParam> = Vec::new();
            // PG placeholder counter; unused for SQLite (always `?`).
            let mut next = 1usize;

            // self — caller's identity == emitter's identity.
            let identity_ph = placeholder(backend, &mut next);
            params.push(ScopeParam::Key(admission.identity_key_id.clone()));
            let io = table(backend, "federation_identity_occurrences");
            let self_branch = format!(
                "({scope_ref} = 'self' AND EXISTS (\
                   SELECT 1 FROM {io} io_e \
                   WHERE io_e.occurrence_key_id = {emitter_ref} \
                     AND io_e.identity_key_id = {identity_ph}))"
            );

            // family — caller's identity ∈ same family as emitter's
            // identity. Membership test against the family roster joins
            // the emitter occurrence → emitter identity, then checks the
            // emitter identity is in a family the caller is admitted to.
            let family_branch = membership_branch(
                backend,
                &scope_ref,
                &emitter_ref,
                "family",
                "federation_families",
                "family_key_id",
                &admission.family_key_ids,
                &mut next,
                &mut params,
            );

            // community — symmetric against federation_communities.
            let community_branch = membership_branch(
                backend,
                &scope_ref,
                &emitter_ref,
                "community",
                "federation_communities",
                "community_key_id",
                &admission.community_key_ids,
                &mut next,
                &mut params,
            );

            let frag = format!(
                "({scope_ref} IN ({broad}) \
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

/// Build a family/community EXISTS membership branch for the §4.3
/// predicate. The branch admits a `cohort_scope: <label>` row when the
/// emitter's identity is in the roster of a `<table>` row whose own key
/// is in the caller's admission set.
///
/// When the caller's admission set is empty (no families / no
/// communities — e.g. the §4.4 singleton fallback), the branch is a
/// constant-false `(... AND 1=0)`: the caller is in no such cohort, so
/// no row at that label is admitted. No params are emitted in that case.
#[allow(clippy::too_many_arguments)]
fn membership_branch(
    backend: BackendKind,
    scope_ref: &str,
    emitter_ref: &str,
    label: &str,
    cohort_table: &str,
    cohort_key_col: &str,
    admission_keys: &std::collections::BTreeSet<String>,
    next: &mut usize,
    params: &mut Vec<ScopeParam>,
) -> String {
    if admission_keys.is_empty() {
        // Caller is in no cohort of this kind — admit nothing at this
        // label. Constant-false, no params.
        return format!("({scope_ref} = '{label}' AND 1=0)");
    }

    let cohort = table(backend, cohort_table);
    let io = table(backend, "federation_identity_occurrences");

    // Caller-admission membership test: `c.<key_col> IN/ANY (caller set)`.
    let admit_membership = match backend {
        BackendKind::Postgres => {
            let ph = placeholder(backend, next); // single array param
            params.push(ScopeParam::KeyList(
                admission_keys.iter().cloned().collect(),
            ));
            format!("c.{cohort_key_col} = ANY({ph})")
        }
        BackendKind::Sqlite => {
            // One `?` per key; emit one ScopeParam::Key each.
            let mut phs = Vec::with_capacity(admission_keys.len());
            for k in admission_keys {
                phs.push(placeholder(backend, next));
                params.push(ScopeParam::Key(k.clone()));
            }
            format!("c.{cohort_key_col} IN ({})", phs.join(","))
        }
    };

    // Roster-containment test: emitter's identity ∈ c.members.
    let roster_contains = match backend {
        BackendKind::Postgres => {
            // members @> jsonb_build_array(jsonb_build_object('key_id', io_e.identity_key_id))
            "c.members @> jsonb_build_array(\
               jsonb_build_object('key_id', io_e.identity_key_id))"
                .to_string()
        }
        BackendKind::Sqlite => "EXISTS (SELECT 1 FROM json_each(c.members) \
               WHERE json_extract(value, '$.key_id') = io_e.identity_key_id)"
            .to_string(),
    };

    format!(
        "({scope_ref} = '{label}' AND EXISTS (\
           SELECT 1 FROM {cohort} c \
           JOIN {io} io_e ON io_e.occurrence_key_id = {emitter_ref} \
           WHERE {admit_membership} \
             AND {roster_contains}))"
    )
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

    /// Authenticated caller in family F1 + F2 and community C1.
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
            let (frag, params) =
                cohort_scope_sql_predicate(backend, "t", "scrub_key_id", "cohort_scope", &unauth());
            assert_eq!(
                frag,
                "(t.cohort_scope IN ('community','affiliations','species','biosphere','federation'))"
            );
            assert!(params.is_empty(), "unauth emits no params");
            // never admits self / family
            assert!(!frag.contains("'self'"));
            assert!(!frag.contains("'family'"));
        }
    }

    #[test]
    fn authenticated_singleton_postgres_self_only_no_cohorts() {
        let (frag, params) = cohort_scope_sql_predicate(
            BackendKind::Postgres,
            "t",
            "scrub_key_id",
            "cohort_scope",
            &auth_singleton(),
        );
        // broad tiers present
        assert!(frag.contains(
            "t.cohort_scope IN ('community','affiliations','species','biosphere','federation')"
        ));
        // self branch with $1 = identity, joining identity_occurrences
        assert!(frag.contains("t.cohort_scope = 'self' AND EXISTS ("));
        assert!(frag.contains("FROM cirislens.federation_identity_occurrences io_e"));
        assert!(frag.contains("io_e.occurrence_key_id = t.scrub_key_id"));
        assert!(frag.contains("io_e.identity_key_id = $1"));
        // family + community are constant-false (no admission sets)
        assert!(frag.contains("(t.cohort_scope = 'family' AND 1=0)"));
        assert!(frag.contains("(t.cohort_scope = 'community' AND 1=0)"));
        // only the identity param
        assert_eq!(params, vec![ScopeParam::Key("occ-1".to_string())]);
    }

    #[test]
    fn authenticated_singleton_sqlite_uses_question_placeholders() {
        let (frag, params) = cohort_scope_sql_predicate(
            BackendKind::Sqlite,
            "t",
            "scrub_key_id",
            "cohort_scope",
            &auth_singleton(),
        );
        assert!(frag.contains("FROM federation_identity_occurrences io_e"));
        assert!(frag.contains("io_e.identity_key_id = ?"));
        assert!(!frag.contains("$1"), "sqlite never emits $n");
        assert!(frag.contains("(t.cohort_scope = 'family' AND 1=0)"));
        assert_eq!(params, vec![ScopeParam::Key("occ-1".to_string())]);
    }

    #[test]
    fn authenticated_full_postgres_family_community_any_arrays() {
        let (frag, params) = cohort_scope_sql_predicate(
            BackendKind::Postgres,
            "t",
            "author_key_id",
            "cohort_scope",
            &auth_full(),
        );
        // self branch -> $1
        assert!(frag.contains("io_e.identity_key_id = $1"));
        // family branch: ANY($2) against federation_families, roster @>
        assert!(frag.contains("FROM cirislens.federation_families c"));
        assert!(frag.contains("c.family_key_id = ANY($2)"));
        assert!(frag.contains("c.members @> jsonb_build_array("));
        assert!(frag.contains("io_e.occurrence_key_id = t.author_key_id"));
        // community branch: ANY($3) against federation_communities
        assert!(frag.contains("FROM cirislens.federation_communities c"));
        assert!(frag.contains("c.community_key_id = ANY($3)"));
        // params, in order: identity, family-set, community-set.
        // BTreeSet sorts F1<F2.
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
            "t",
            "author_key_id",
            "cohort_scope",
            &auth_full(),
        );
        assert!(frag.contains("FROM federation_families c"));
        // family has 2 keys -> IN (?,?)
        assert!(frag.contains("c.family_key_id IN (?,?)"));
        // community has 1 key -> IN (?)
        assert!(frag.contains("c.community_key_id IN (?)"));
        assert!(frag.contains(
            "EXISTS (SELECT 1 FROM json_each(c.members) \
               WHERE json_extract(value, '$.key_id') = io_e.identity_key_id)"
        ));
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

    #[test]
    fn fragment_is_parenthesized_for_and_composition() {
        for scope in [unauth(), auth_singleton(), auth_full()] {
            for backend in [BackendKind::Postgres, BackendKind::Sqlite] {
                let (frag, _) = cohort_scope_sql_predicate(
                    backend,
                    "t",
                    "scrub_key_id",
                    "cohort_scope",
                    &scope,
                );
                assert!(
                    frag.starts_with('('),
                    "fragment must be parenthesized: {frag}"
                );
                assert!(
                    frag.ends_with(')'),
                    "fragment must be parenthesized: {frag}"
                );
            }
        }
    }
}
