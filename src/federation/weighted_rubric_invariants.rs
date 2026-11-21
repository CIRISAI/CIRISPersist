//! v62.0.0 (SD-fix3; Constitution 2026-11-21: "I find no
//! half-not-more-than-half threshold anywhere in Parts 3 or 4. A count is the
//! strict majority or a threshold the record states. Remove it.") — **I5304:
//! no rubric is built in**, at the boundary n = 2 and n = 4, sqlite and pg.
//!
//! Through the community count `admission::community_quorum_cosigned_at`
//! (the gate under `group_act_at`, `appointment_stands_at` and the
//! affiliation owner-binding door), over a counted row whose voices land one
//! at a time through the statement door:
//!
//! - an UNDECLARED `weighted:uniform_half` admits at NO voice count. Before
//!   SD-fix3 it admitted at ⌈n/2⌉: 1 of 2 and 2 of 4;
//! - `majority` admits at the strict majority, 2 of 2 and 3 of 4, through the
//!   shared `admission::strict_majority`;
//! - a rubric the RECORD states under the same name (`policy.rubrics`,
//!   default weight 1, threshold n/2) admits at its stated threshold: the
//!   name is no longer special, and the record's own number rules.

use crate::federation::edition2::fixture_switch as e2;
use crate::federation::edition2::voices_invariants::{add_voice, counted_row, found_community};
use crate::federation::types::identity_type;
use crate::federation::FederationDirectory;

/// After each member's voice (in roster order), is the counted row met?
async fn met_after_each_voice(
    d: &dyn FederationDirectory,
    tag: &str,
    n: usize,
    protocol: &str,
    policy: Option<serde_json::Value>,
) -> Vec<bool> {
    let seeds: Vec<String> = (0..n).map(|i| format!("sd3-{tag}-{i}")).collect();
    let refs: Vec<&str> = seeds.iter().map(String::as_str).collect();
    for s in &refs {
        e2::put_key(d, s, &[identity_type::USER]).await;
    }
    let c = found_community(d, &format!("sd3-{tag}-g"), &refs, protocol, policy).await;
    let row = counted_row(d, refs[0]).await;
    let at = row.asserted_at;
    let mut out = Vec::with_capacity(n);
    for (i, s) in refs.iter().enumerate() {
        if i > 0 {
            add_voice(d, &row, s)
                .await
                .expect("I5304: a member's voice");
        }
        out.push(
            crate::federation::admission::community_quorum_cosigned_at(d, &c, &row, at)
                .await
                .expect("I5304: the community count"),
        );
    }
    out
}

pub(crate) async fn i5304_no_rubric_is_built_in(d: &dyn FederationDirectory) {
    for n in [2usize, 4] {
        assert_eq!(
            met_after_each_voice(d, &format!("undeclared-{n}"), n, "weighted:uniform_half", None)
                .await,
            vec![false; n],
            "I5304 n={n}: an undeclared weighted:uniform_half is no rule (it admitted at {} of {n})",
            n.div_ceil(2)
        );
        let majority: Vec<bool> = (1..=n).map(|k| k > n / 2).collect();
        assert_eq!(
            met_after_each_voice(d, &format!("majority-{n}"), n, "majority", None).await,
            majority,
            "I5304 n={n}: majority admits at the strict majority"
        );
        let stated = serde_json::json!({
            "rubrics": {"uniform_half": {"default_weight": 1, "threshold": n / 2}}
        });
        let at_stated: Vec<bool> = (1..=n).map(|k| k >= n / 2).collect();
        assert_eq!(
            met_after_each_voice(
                d,
                &format!("stated-{n}"),
                n,
                "weighted:uniform_half",
                Some(stated)
            )
            .await,
            at_stated,
            "I5304 n={n}: a rubric the record states counts by its stated threshold"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i5304_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i5304_no_rubric_is_built_in(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i5304_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i5304_no_rubric_is_built_in(&b)).await;
}
