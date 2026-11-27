//! v62.0.0 (D4.rev2; CC 3.4.7; the lead's ruling 4: "hold when the
//! conferral could still arrive; refuse only on what the row settles") —
//! **I6611–I6612: a root-conferred family's duty, held or refused.**
//!
//! The `TrustedRoot` arm of `admission::check_reserved_prefix_admission`
//! (`age_assurance:*`, `capacity_assurance:*`, `detection:*`). Every leg goes
//! through the real statement door, with the row stated as its producer
//! states it (`fixture_switch::with_head_resolved`), and reads the one
//! verdict.
//!
//! - **I6611** — a person's `age_assurance:*` row on a node with NO identity
//!   yet. The bundle is in force, so the row names it. The node can read no
//!   root it trusts until its identity is set, so the conferral could still
//!   be read: the row is HELD `reserved_family_unseated` (kept, concluding
//!   nothing), never refused.
//! - **I6612** — an owned NODE's `age_assurance:*` row (its head is its
//!   owner binding). `assure:age` is a person's or an institution's, and a
//!   node key can never be granted it (`scopes_are_infra_only`). The held
//!   node record settles it: REFUSED, and nothing is kept.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::r2_test_support::confer_from_owner;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::fold::reason::gc1::RESERVED_FAMILY_UNSEATED;
    use crate::federation::edition2::names::RowId;
    use crate::federation::edition2::verdict::{row_state, RowState};
    use crate::federation::types::identity_type as it;
    use crate::federation::{Error, FederationDirectory};

    const AGE: &str = "age_assurance:provider:adult:v1";

    /// `by`'s age row about `about`, stated as `d`'s producer states it: its
    /// row id and its statement.
    async fn age_row(d: &dyn FederationDirectory, by: &str, about: &str) -> (RowId, Vec<u8>) {
        use crate::federation::tier_ingest::test_support as ts;
        let id = uuid::Uuid::new_v4().to_string();
        let mut a = ts::bare_attestation(&id, by, about, &serde_json::json!({ "id": id }));
        a.attestation_type = AGE.to_owned();
        a.asserted_at = chrono::Utc::now() - chrono::Duration::minutes(5);
        a.scrub_timestamp = a.asserted_at;
        ts::seal_row_in_place(by, &mut a);
        let st = e2::carried_statement(&a).expect("an edition-2 row carries its statement");
        let headed = e2::with_head_resolved(d, &st, None)
            .await
            .expect("the head read");
        (
            RowId::of_statement(&headed).expect("a row statement"),
            headed,
        )
    }

    async fn state(d: &dyn FederationDirectory, id: &RowId) -> RowState {
        row_state(d, id).await.expect("the verdict read")
    }

    /// I6611 — no node identity: the conferral could still be read, so HELD.
    pub(crate) async fn i6611_no_node_identity_holds(d: &dyn FederationDirectory, tag: &str) {
        let (assessor, person) = (format!("i6611-a-{tag}"), format!("i6611-p-{tag}"));
        crate::federation::edition2::fixture_genesis::install_ceremony_v2(
            d,
            crate::federation::edition2::fixture_genesis::bundle_v2_wide(),
        )
        .await
        .expect("I6611: the bundle in force");
        assert!(
            d.node_key_id().is_none(),
            "I6611: this directory has no node identity"
        );
        let _ = e2::put_key(d, &assessor, &[it::USER]).await;
        let _ = e2::put_key(d, &person, &[it::USER]).await;
        let (id, st) = age_row(d, &assessor, &person).await;
        e2::put_statement(d, &st)
            .await
            .unwrap_or_else(|e| panic!("I6611: kept, not refused: {e}"));
        let s = state(d, &id).await;
        assert_eq!(
            s.held().map(|h| h.reason.as_str()),
            Some(RESERVED_FAMILY_UNSEATED),
            "I6611: with no node identity, the row is held, concluding nothing: {s:?}"
        );
    }

    /// I6612 — an owned node signs an assurance row: refused, nothing kept.
    pub(crate) async fn i6612_a_node_key_is_refused_assurance(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (owner, node, person) = (
            format!("i6612-o-{tag}"),
            format!("i6612-n-{tag}"),
            format!("i6612-p-{tag}"),
        );
        let _ = e2::put_key(d, &node, &[it::NODE]).await;
        let _ = e2::put_key(d, &person, &[it::USER]).await;
        confer_from_owner(d, &owner, &node, &[]).await;
        let (id, st) = age_row(d, &node, &person).await;
        let e = e2::put_statement(d, &st)
            .await
            .expect_err("I6612: a node's assurance row is refused");
        assert!(
            matches!(e, Error::ReservedPrefixEmitterMismatch { .. }),
            "I6612: refused by the assurance duty, not another gate: {e:?}"
        );
        assert_eq!(
            state(d, &id).await,
            RowState::Absent,
            "I6612: nothing is kept"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    macro_rules! on_every_backend {
        ($name:ident, $body:path) => {
            mod $name {
                use super::*;

                #[cfg(feature = "sqlite")]
                #[tokio::test(flavor = "multi_thread")]
                async fn sqlite() {
                    use crate::store::Backend as _;
                    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b, &tag("s")).await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test(flavor = "multi_thread")]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        eprintln!("D4 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
                        return;
                    };
                    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b, &tag("p")).await;
                    eprintln!("{}: RAN", stringify!($name));
                }
            }
        };
    }

    on_every_backend!(i6611, bodies::i6611_no_node_identity_holds);
    on_every_backend!(i6612, bodies::i6612_a_node_key_is_refused_assurance);
}
