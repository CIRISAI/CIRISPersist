//! Scope-predicate bind glue (FSD §8, Commit E).
//!
//! [`cohort_scope_sql_predicate`](crate::scope::cohort_scope_sql_predicate)
//! emits its placeholders starting at `$1` (Postgres) or bare `?`
//! (SQLite). A read method composes that fragment into a larger statement
//! whose own filter/cursor params already occupy the leading placeholder
//! slots, so the fragment must be *rebased* onto the next free slot. This
//! module owns that rebasing for both backends so each call site stays a
//! one-liner and the offset arithmetic lives in exactly one place.
//!
//! # Placeholder rebasing
//!
//! - **Postgres** — the predicate emits `$1`, `$2`, … (one `$n` per
//!   [`ScopeParam`], a `KeyList` being a single array param). With an
//!   `offset` of N already-bound params, `$k` becomes `$(k + N)`.
//! - **SQLite** — the predicate emits bare `?` (one per `ScopeParam`,
//!   `KeyList`s already expanded to individual `Key`s by the emitter).
//!   The surrounding statements use *numbered* `?N` placeholders, so each
//!   bare `?` is rewritten to `?(N + k)` left-to-right to avoid mixing
//!   anonymous and numbered placeholders in one rusqlite statement.
//!
//! The two `*_for_*` functions return the rebased fragment plus the
//! params already converted to the backend's native bind type, ready to
//! append to the call site's param vector.

use crate::scope::{BackendKind, CallerScope, ScopeParam};

/// Rebase a Postgres scope fragment and box its params.
///
/// `bound_so_far` is the number of params already pushed onto the call
/// site's `Vec<Box<dyn ToSql …>>` (i.e. the count of leading `$1..$n`
/// already consumed). Returns the fragment with every `$k` rewritten to
/// `$(k + bound_so_far)`, plus the boxed params in bind order. A `KeyList`
/// is bound as a single `Vec<String>` (Postgres `= ANY($n)` array).
#[cfg(feature = "postgres")]
pub(crate) fn scope_predicate_pg(
    scope: &CallerScope,
    scope_col: &str,
    target_col: &str,
    bound_so_far: usize,
) -> (
    String,
    Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>>,
) {
    let (frag, params) = crate::scope::cohort_scope_sql_predicate(
        BackendKind::Postgres,
        scope_col,
        target_col,
        scope,
    );
    let frag = rebase_pg_placeholders(&frag, bound_so_far);
    let boxed: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = params
        .into_iter()
        .map(|p| match p {
            ScopeParam::Key(k) => {
                Box::new(k) as Box<dyn tokio_postgres::types::ToSql + Sync + Send>
            }
            ScopeParam::KeyList(ks) => {
                Box::new(ks) as Box<dyn tokio_postgres::types::ToSql + Sync + Send>
            }
        })
        .collect();
    (frag, boxed)
}

/// Rebase a SQLite scope fragment and lower its params to [`SqlValue`].
///
/// `bound_so_far` is the count of leading numbered placeholders already
/// in use. Each bare `?` the predicate emitted is rewritten left-to-right
/// to `?(bound_so_far + k)`. The emitter has already expanded any
/// `KeyList` into individual `Key`s, so every param is a single text
/// value.
#[cfg(feature = "sqlite")]
pub(crate) fn scope_predicate_sqlite(
    scope: &CallerScope,
    scope_col: &str,
    target_col: &str,
    bound_so_far: usize,
) -> (String, Vec<rusqlite::types::Value>) {
    let (frag, params) =
        crate::scope::cohort_scope_sql_predicate(BackendKind::Sqlite, scope_col, target_col, scope);
    let frag = rebase_sqlite_placeholders(&frag, bound_so_far);
    let values: Vec<rusqlite::types::Value> = params
        .into_iter()
        .map(|p| match p {
            ScopeParam::Key(k) => rusqlite::types::Value::Text(k),
            // KeyList is never produced for SQLite (the emitter expands
            // it), but lower defensively to keep the match total.
            ScopeParam::KeyList(ks) => rusqlite::types::Value::Text(ks.join(",")),
        })
        .collect();
    (frag, values)
}

/// Rewrite every `$k` in `frag` to `$(k + offset)`. Scans for `$`
/// followed by ASCII digits; non-placeholder `$` (there are none in the
/// predicate output) are left untouched.
#[cfg(feature = "postgres")]
fn rebase_pg_placeholders(frag: &str, offset: usize) -> String {
    if offset == 0 {
        return frag.to_string();
    }
    let bytes = frag.as_bytes();
    let mut out = String::with_capacity(frag.len() + 4);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            let n: usize = frag[i + 1..j].parse().expect("digits parse");
            out.push('$');
            out.push_str(&(n + offset).to_string());
            i = j;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Rewrite each bare `?` in `frag` to `?(offset + k)` left-to-right
/// (k = 1, 2, …). The predicate never emits numbered `?N`, so every `?`
/// is anonymous and gets a fresh number.
#[cfg(feature = "sqlite")]
fn rebase_sqlite_placeholders(frag: &str, offset: usize) -> String {
    let mut out = String::with_capacity(frag.len() + 8);
    let mut k = 0usize;
    for ch in frag.chars() {
        if ch == '?' {
            k += 1;
            out.push('?');
            out.push_str(&(offset + k).to_string());
        } else {
            out.push(ch);
        }
    }
    out
}

/// AND-compose a scope fragment into an existing `where_sql` that is
/// either empty or begins with `WHERE `. The fragment is always
/// parenthesized by the predicate emitter, so a bare `AND` join is safe.
///
/// SQLite-only: the Postgres backend composes scope fragments inline at
/// its call sites, so this helper has no Postgres caller. Gating it on
/// `sqlite` keeps the `pyo3`-without-sqlite build (the maturin
/// `test-panic` / abi3 wheel step) free of a dead-code `-D warnings` break.
#[cfg(feature = "sqlite")]
pub(crate) fn and_compose(where_sql: &str, scope_frag: &str) -> String {
    if where_sql.is_empty() {
        format!("WHERE {scope_frag}")
    } else {
        format!("{where_sql} AND {scope_frag}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::admission::CallerAdmission;

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

    #[cfg(feature = "postgres")]
    #[test]
    #[serial_test::serial(postgres)]
    fn pg_rebases_offset_onto_every_placeholder() {
        // 3 filter params already bound → scope params start at $4.
        let (frag, params) =
            scope_predicate_pg(&auth_full(), "t.cohort_scope", "t.cohort_target_id", 3);
        assert!(
            frag.contains("t.cohort_target_id = $4"),
            "self → $4: {frag}"
        );
        assert!(frag.contains("= ANY($5)"), "family array → $5: {frag}");
        assert!(frag.contains("= ANY($6)"), "community array → $6: {frag}");
        assert!(!frag.contains("$1"), "no original $1 remains: {frag}");
        assert_eq!(params.len(), 3, "identity + family-list + community-list");
    }

    #[cfg(feature = "postgres")]
    #[test]
    #[serial_test::serial(postgres)]
    fn pg_zero_offset_is_identity() {
        let (frag, _) = scope_predicate_pg(
            &CallerScope::Unauthenticated,
            "t.cohort_scope",
            "t.cohort_target_id",
            0,
        );
        assert_eq!(
            frag,
            "(t.cohort_scope IN ('affiliations','species','biosphere','federation'))"
        );
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_numbers_each_bare_question_mark() {
        // 2 filter params bound → scope params start at ?3.
        let (frag, values) =
            scope_predicate_sqlite(&auth_full(), "t.cohort_scope", "t.cohort_target_id", 2);
        // self → ?3 ; family F1,F2 → ?4,?5 ; community C1 → ?6
        assert!(frag.contains("t.cohort_target_id = ?3"), "{frag}");
        assert!(frag.contains("IN (?4,?5)"), "{frag}");
        assert!(frag.contains("IN (?6)"), "{frag}");
        assert!(!frag.contains("(?)"), "no bare ? left: {frag}");
        assert_eq!(values.len(), 4, "identity + F1 + F2 + C1");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_unauthenticated_no_params() {
        let (frag, values) = scope_predicate_sqlite(
            &CallerScope::Unauthenticated,
            "t.cohort_scope",
            "t.cohort_target_id",
            0,
        );
        assert!(values.is_empty());
        assert!(!frag.contains('?'));
    }
}
