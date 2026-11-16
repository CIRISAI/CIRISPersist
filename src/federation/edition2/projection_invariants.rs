//! v62.0.0 (slice J0) — the edition-2 read models and the cross-form
//! refusal, on sqlite and postgres.
//!
//! - **I2000 (projection equals reading).** After a record, a renewal after
//!   its end, and a self-revocation bounded by `revoked_after`,
//!   `lookup_public_key(iref)` is the edition-2 projection: the composite's
//!   two halves, `valid_from` the earliest record, `valid_until` the greatest
//!   end, `edition = 2`, `record_row_id` / `kid`; and [`HeldKeys::liveness`]
//!   reads the same span and the same revocation.
//! - **I2001 (the edition, read two ways).** `key_edition` reads the column on
//!   the backends; the provided reading (`edition_of_key_record` over
//!   `lookup_public_key`) answers the same for an edition-2 projection and an
//!   earlier-form key.
//! - **I2002 (the signer FK holds).** An edition-2 row inserts with both
//!   signer FKs present (sqlite: `foreign_keys` is on and lists both); a copy
//!   of it naming a stranger as its signer fails the FK.
//! - **I2003 (cross-form refusal).** An earlier-form row (the mapped row with
//!   its statement removed) whose signer is the edition-2 key is refused
//!   `earlier_form_signer_is_edition2` at every choke point, called directly:
//!   `tier_ingest::verify_row_hybrid_signature`,
//!   `register::verify_key_registration`, `register::verify_proof_of_possession`
//!   (→ `verify_record_signed_by`), `key_plane::verify_plane_row`,
//!   `group_plane::verify_plane_row`, `self_roster::verify_proposal_row`,
//!   `cosign::verify_row`, `occurrence_revocation_carrier::verify_carrier_row`,
//!   `admission::verify_consent_record_transit_ingest`,
//!   `admission::verify_caller_signed_local_row`. The same rows under an
//!   earlier-form key id are never refused by that name, and the mapped row
//!   (carrying its statement) passes the guard.
//! - **I2004 (revocation readers).** The self-revocation is seen by
//!   `revocations_for` / `revocations_for_subject`, by the key-statement fold
//!   (`resolve_key_statement_standing`), by the lineage witness gate
//!   (`witness_standing_at`), and the subject read (`wire_refs_for_subject`)
//!   still answers.
//! - **I2005 (revocation authority).** A stranger's `key:revocation` is held
//!   and projects nothing; an owner's projects nothing under [`SelfOnly`] and
//!   projects (with the owner's key row, its FK target) only under a
//!   [`RevokerStanding`] that admits it.
//! - **I2006 (one fold).** The projected row corrupted (`valid_until` in the
//!   past, `identity_type` and the Ed25519 half replaced): the key's next
//!   edition-2 row is admitted exactly as before.
//! - **I2007 (idempotence, re-derivation).** Re-putting a record or a
//!   revocation leaves the projected rows byte-identical; a renewal
//!   re-projects (`valid_until`, `mutated_at`).
//! - **I2007b.** A key id held by an earlier-form row is never overwritten
//!   by a projection: `Conflict`, and the row is unchanged.
//! - **I2009 (the read models are not earlier-form rows).** On a fresh
//!   open of the same store, the key-plane rehome mints no `key:record:v1` /
//!   revocation row for a projection and its report counts none, and the
//!   key and revocation projection-rebuild gates find no divergence.
//! - **I2008 (the serve listing).** `edition2_statements_since` serves every
//!   held statement once, as received, in admission order, paging by its
//!   cursor; positions strictly increase.

use std::sync::Arc;

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::sign_row_statement;

use super::door_invariants::fixture::*;
use super::ingest::{held_keys_for_kid, put_statement, StatementOutcome, INGEST_TIER};
use super::liveness::{Liveness, RevokerStanding};
use super::projection::{
    edition_of_key_record, project_key, project_key_with, EDITION_ONE, EDITION_TWO,
};
use crate::federation::types::Attestation;
use crate::federation::{malformed_row, Error, FederationDirectory};

fn at(ms: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms).unwrap()
}

/// An authored score row of `k` at `at_ms` (Verify's vector family).
fn score_row(k: &ciris_crypto::composite::CompositeSigningKey, at_ms: u64) -> Vec<u8> {
    let payload = map(vec![
        ("asserted_at", Value::Uint(at_ms)),
        ("author", Value::Text(iref(k))),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        (
            "dimension",
            Value::Text("evidence:safety_battery:capture:a:b:v1".into()),
        ),
    ]);
    sign_row_statement(
        k,
        &iref(k),
        &iref(k),
        "scores",
        "evidence:.suite:.kind:.cell:.prefix",
        &payload,
        vec![],
    )
    .unwrap()
}

/// The raw store, for what the directory does not expose: the whole
/// projected row as text, a corruption, an FK probe.
pub(crate) enum Raw<'a> {
    #[cfg(feature = "sqlite")]
    Sqlite(&'a crate::store::sqlite::SqliteBackend),
    #[cfg(feature = "postgres")]
    Pg(&'a crate::store::postgres::PostgresBackend),
}

impl Raw<'_> {
    async fn exec(&self, sql: &str) -> Result<(), String> {
        match self {
            #[cfg(feature = "sqlite")]
            Raw::Sqlite(b) => b
                .conn_handle()
                .lock()
                .execute_batch(sql)
                .map_err(|e| e.to_string()),
            #[cfg(feature = "postgres")]
            Raw::Pg(b) => b
                .checkout()
                .await
                .unwrap()
                .batch_execute(sql)
                .await
                .map_err(|e| format!("{e:?}")),
        }
    }

    /// Every row of `table` matching `pred`, each as one text, sorted.
    async fn rows(&self, table: &str, pred: &str) -> Vec<String> {
        match self {
            #[cfg(feature = "sqlite")]
            Raw::Sqlite(b) => {
                let c = b.conn_handle();
                let c = c.lock();
                let mut st = c
                    .prepare(&format!("SELECT * FROM {table} WHERE {pred}"))
                    .unwrap();
                let n = st.column_count();
                let mut out: Vec<String> = st
                    .query_map([], |r| {
                        Ok((0..n)
                            .map(|i| format!("{:?}", r.get_ref(i).unwrap()))
                            .collect::<Vec<_>>()
                            .join("|"))
                    })
                    .unwrap()
                    .map(Result::unwrap)
                    .collect();
                out.sort();
                out
            }
            #[cfg(feature = "postgres")]
            Raw::Pg(b) => {
                let c = b.checkout().await.unwrap();
                let mut out: Vec<String> = c
                    .query(
                        &format!(
                            "SELECT row_to_json(t)::text FROM cirislens.{table} t WHERE {pred}"
                        ),
                        &[],
                    )
                    .await
                    .unwrap()
                    .iter()
                    .map(|r| r.get::<_, String>(0))
                    .collect();
                out.sort();
                out
            }
        }
    }

    /// Copy a stored attestation under a new id, naming `signer` as its
    /// attester and scrubber: the FK probe (generated columns left out).
    async fn copy_row_as_signer(&self, id: &str, signer: &str) -> Result<(), String> {
        let cols: Vec<String> = match self {
            #[cfg(feature = "sqlite")]
            Raw::Sqlite(b) => {
                let c = b.conn_handle();
                let c = c.lock();
                let mut st = c
                    .prepare(
                        "SELECT name FROM pragma_table_xinfo('federation_attestations') \
                         WHERE hidden = 0 ORDER BY cid",
                    )
                    .unwrap();
                st.query_map([], |r| r.get::<_, String>(0))
                    .unwrap()
                    .map(Result::unwrap)
                    .collect()
            }
            #[cfg(feature = "postgres")]
            Raw::Pg(b) => b
                .checkout()
                .await
                .unwrap()
                .query(
                    "SELECT column_name::text FROM information_schema.columns WHERE \
                     table_schema = 'cirislens' AND table_name = 'federation_attestations' \
                     AND is_generated = 'NEVER' ORDER BY ordinal_position",
                    &[],
                )
                .await
                .unwrap()
                .iter()
                .map(|r| r.get::<_, String>(0))
                .collect(),
        };
        let values: Vec<String> = cols
            .iter()
            .map(|c| match c.as_str() {
                "attestation_id" | "persist_row_hash" => sq("j0-stranger"),
                "attesting_key_id" | "scrub_key_id" => sq(signer),
                other => other.to_owned(),
            })
            .collect();
        let q = self.q();
        self.exec(&format!(
            "INSERT INTO {q}federation_attestations ({}) SELECT {} FROM \
             {q}federation_attestations WHERE attestation_id = {}",
            cols.join(", "),
            values.join(", "),
            sq(id)
        ))
        .await
    }

    fn q(&self) -> &'static str {
        match self {
            #[cfg(feature = "sqlite")]
            Raw::Sqlite(_) => "",
            #[cfg(feature = "postgres")]
            Raw::Pg(_) => "cirislens.",
        }
    }
}

fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// A standing that admits one owner over one subject.
struct Owner {
    owner: String,
    subject: String,
}

impl RevokerStanding for Owner {
    fn may_revoke(&self, revoker: &str, subject: &str) -> bool {
        revoker == self.owner && subject == self.subject
    }
}

pub(crate) async fn body(d: &dyn FederationDirectory, raw: &Raw<'_>) {
    let q = raw.q();
    let k = key(70);
    let ik = iref(&k);
    let kk = kid(&k);

    // ── I2000 / I2007: a record, its re-put, a renewal after its end ──
    let rec1 = key_record(&k, &["node", "witness"], 1_000, Some(5_000));
    let out = put_statement(d, &rec1, None, INGEST_TIER).await.unwrap();
    assert!(matches!(out, StatementOutcome::KeyPlane { new: true, .. }));
    let first = d
        .lookup_public_key(&ik)
        .await
        .unwrap()
        .expect("I2000: projected");
    assert_eq!(first.valid_from, at(1_000), "I2000: valid_from");
    assert_eq!(first.valid_until, Some(at(5_000)), "I2000: valid_until");
    assert_eq!(first.identity_type, "node,witness", "I2000: identity set");
    assert_eq!(first.identity_ref, ik);
    assert_eq!(first.scrub_key_id, ik, "I2000: the record's own signer");
    let pk = k.public_key().as_bytes();
    {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        assert_eq!(
            first.pubkey_ed25519_base64,
            b64.encode(&pk[pk.len() - 32..])
        );
        assert_eq!(
            first.pubkey_ml_dsa_65_base64.as_deref(),
            Some(b64.encode(&pk[..pk.len() - 32]).as_str()),
            "I2000: the ML-DSA-65 half, 1952 bytes"
        );
    }
    assert_eq!(
        first.pqc_completed_at,
        Some(at(1_000)),
        "I2000: the composite is complete at signing"
    );
    assert!(
        !d.list_hybrid_pending_keys(1_000)
            .await
            .unwrap()
            .iter()
            .any(|r| r.id == ik),
        "I2000: the PQC sweep never offers a projection"
    );
    let ev = first.attestation_evidence.clone().expect("I2000: evidence");
    assert_eq!(ev["chain"], serde_json::json!([]), "I2000: evidence shape");
    let row_before = raw
        .rows("federation_keys", &format!("key_id = {}", sq(&ik)))
        .await;
    assert_eq!(row_before.len(), 1);
    // I2007: a re-put leaves it byte-identical.
    let again = put_statement(d, &rec1, None, INGEST_TIER).await.unwrap();
    assert!(matches!(
        again,
        StatementOutcome::KeyPlane { new: false, .. }
    ));
    assert_eq!(
        raw.rows("federation_keys", &format!("key_id = {}", sq(&ik)))
            .await,
        row_before,
        "I2007: re-put record, byte-identical projection"
    );
    // I2001: the edition, read two ways.
    assert_eq!(
        d.key_edition(&ik).await.unwrap(),
        Some(EDITION_TWO),
        "I2001 column"
    );
    assert_eq!(edition_of_key_record(&first), EDITION_TWO, "I2001 provided");
    // The renewal after the end re-projects (I2007), and reads as liveness does.
    let rec2 = key_record(&k, &["node", "witness"], 8_000, Some(12_000));
    put_statement(d, &rec2, None, INGEST_TIER).await.unwrap();
    let renewed = d.lookup_public_key(&ik).await.unwrap().unwrap();
    assert_eq!(renewed.valid_from, at(1_000), "I2000: the earliest record");
    assert_eq!(
        renewed.valid_until,
        Some(at(12_000)),
        "I2000: the greatest end"
    );
    assert_ne!(
        raw.rows("federation_keys", &format!("key_id = {}", sq(&ik)))
            .await,
        row_before,
        "I2007: a renewal re-projects"
    );
    let held = held_keys_for_kid(d, &kk).await.unwrap();
    assert!(
        matches!(held.liveness(&kk, 12_000), Liveness::Live(_)),
        "I2000"
    );
    assert!(
        matches!(held.liveness(&kk, 12_001), Liveness::NotCovered),
        "I2000"
    );
    assert!(
        matches!(held.liveness(&kk, 6_000), Liveness::NotCovered),
        "I2000 gap"
    );

    // ── I2002: the FK holds ──
    let st = score_row(&k, 9_000);
    let StatementOutcome::Row { row_id, .. } = put_statement(d, &st, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| panic!("I2002: an edition-2 row inserts under the FK: {e:?}"))
    else {
        panic!("I2002: a row");
    };
    let mapped: Attestation = d.get_attestation(&row_id.hex()).await.unwrap().unwrap();
    let stranger = iref(&key(79));
    let fk = raw
        .copy_row_as_signer(&row_id.hex(), &stranger)
        .await
        .expect_err("I2002: a stranger's row fails the FK");
    assert!(
        fk.to_lowercase().contains("foreign key"),
        "I2002: refused by the FK, not another rule: {fk}"
    );

    // ── I2003: the cross-form refusal at every choke point ──
    let mut json_row = mapped.clone();
    json_row
        .attestation_envelope
        .as_object_mut()
        .unwrap()
        .remove(super::ingest::STATEMENT_MEMBER);
    cross_form(d, &json_row, &first, true).await;
    // The same rows under an earlier-form key id: never refused by that name.
    let mut other = json_row.clone();
    other.attesting_key_id = "j0-json-key-fp".into();
    other.scrub_key_id = "j0-json-key-fp".into();
    let mut other_rec = first.clone();
    other_rec.key_id = "j0-json-key-fp".into();
    other_rec.scrub_key_id = "j0-json-key-fp".into();
    other_rec
        .registration_envelope
        .as_object_mut()
        .unwrap()
        .remove(super::ingest::STATEMENT_MEMBER);
    cross_form(d, &other, &other_rec, false).await;
    // The mapped row (it carries its statement) passes the guard.
    super::projection::refuse_edition2_row_signer(d, "attestation", &mapped)
        .await
        .expect("I2003: a carried row is not an earlier-form verification");
    crate::federation::tier_ingest::verify_row_hybrid_signature(d, &mapped)
        .await
        .expect("I2003: the carried arm verifies the edition-2 row");

    // ── I2006: one fold ──
    let corrupt = format!(
        "UPDATE {q}federation_keys SET valid_until = {past}, identity_type = 'user', \
         pubkey_ed25519_base64 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' WHERE key_id = {k}",
        past = if q.is_empty() {
            "'1970-01-01T00:00:01+00:00'".to_owned()
        } else {
            "'1970-01-01T00:00:01Z'".to_owned()
        },
        k = sq(&ik),
    );
    raw.exec(&corrupt).await.unwrap();
    let st2 = score_row(&k, 10_000);
    put_statement(d, &st2, None, INGEST_TIER)
        .await
        .unwrap_or_else(|e| {
            panic!("I2006: edition-2 admission reads HeldKeys, not the projection: {e:?}")
        });
    let st2_row = d
        .get_attestation(
            &super::door::admit_row(
                &st2,
                &held_keys_for_kid(d, &kk).await.unwrap(),
                None,
                Default::default(),
            )
            .unwrap()
            .row_id
            .hex(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        super::ingest::carried_identity_type(d, &st2_row)
            .await
            .unwrap()
            .as_deref(),
        Some("node,witness"),
        "I2006: tier 2 reads the record, not the corrupted column"
    );
    // The next projection re-derives the row from the held plane.
    project_key(d, &kk).await.unwrap();
    assert_eq!(
        d.lookup_public_key(&ik).await.unwrap().unwrap().valid_until,
        Some(at(12_000)),
        "I2006: re-derived"
    );

    // ── I2004 / I2007: a self-revocation, bounded ──
    let key_row = raw
        .rows("federation_keys", &format!("key_id = {}", sq(&ik)))
        .await;
    let rev = revocation(&k, &k, 11_000, Some(11_000));
    put_statement(d, &rev, None, INGEST_TIER).await.unwrap();
    let revs = d.revocations_for(&ik).await.unwrap();
    assert_eq!(revs.len(), 1, "I2004: revocations_for sees it");
    assert_eq!(
        revs[0].effective_at,
        at(11_000),
        "I2004: effective_at = revoked_after"
    );
    assert_eq!(revs[0].revoked_after, Some(at(11_000)));
    assert_eq!(revs[0].revoking_key_id, ik);
    let digest = crate::federation::key_digest::Sha256Ed25519Raw::from_pubkey_base64(
        &d.lookup_public_key(&ik)
            .await
            .unwrap()
            .unwrap()
            .pubkey_ed25519_base64,
    )
    .unwrap()
    .to_hex();
    assert_eq!(
        d.revocations_for_subject(&digest).await.unwrap().len(),
        1,
        "I2004: by subject digest"
    );
    let held = held_keys_for_kid(d, &kk).await.unwrap();
    assert!(matches!(held.liveness(&kk, 10_999), Liveness::Live(_)));
    assert!(
        matches!(held.liveness(&kk, 11_000), Liveness::Revoked),
        "I2000 revoked"
    );
    use crate::federation::register::{resolve_key_statement_standing, KeyStatementStanding};
    let far = at(1_000_000);
    assert_eq!(
        resolve_key_statement_standing(d, &ik, at(10_500), far)
            .await
            .unwrap()
            .standing,
        KeyStatementStanding::Stands,
        "I2004: the key-statement fold, before the bound"
    );
    assert_eq!(
        resolve_key_statement_standing(d, &ik, at(11_500), far)
            .await
            .unwrap()
            .standing,
        KeyStatementStanding::SuspectAfterBound,
        "I2004: the key-statement fold, after the bound"
    );
    use crate::federation::lineage_witness::{witness_standing_at, WitnessStanding};
    assert!(
        matches!(
            witness_standing_at(d, &ik, at(10_500)).await.unwrap(),
            WitnessStanding::Counts { .. }
        ),
        "I2004: the witness gate, before the bound"
    );
    assert!(
        matches!(
            witness_standing_at(d, &ik, at(11_500)).await.unwrap(),
            WitnessStanding::NotValidAt
        ),
        "I2004: the witness gate refuses the revoked key"
    );
    crate::federation::wire_index::wire_refs_for_subject(d, &ik)
        .await
        .expect("I2004: the subject read answers over a projected revocation");
    // I2007: the key row is untouched by its revocation; a re-put changes nothing.
    assert_eq!(
        raw.rows("federation_keys", &format!("key_id = {}", sq(&ik)))
            .await,
        key_row,
        "I2007: the revocation is its own read model"
    );
    let rev_rows = raw
        .rows(
            "federation_revocations",
            &format!("revoked_key_id = {}", sq(&ik)),
        )
        .await;
    let again = put_statement(d, &rev, None, INGEST_TIER).await.unwrap();
    assert!(matches!(
        again,
        StatementOutcome::KeyPlane { new: false, .. }
    ));
    assert_eq!(
        raw.rows(
            "federation_revocations",
            &format!("revoked_key_id = {}", sq(&ik))
        )
        .await,
        rev_rows,
        "I2007: re-put revocation, byte-identical"
    );

    // ── I2005: revocation authority ──
    let subj = key(71);
    let owner = key(72);
    let stranger_k = key(73);
    for kk in [&subj, &owner, &stranger_k] {
        put_statement(d, &key_record(kk, &["user"], 0, None), None, INGEST_TIER)
            .await
            .unwrap();
    }
    let by_stranger = revocation(&stranger_k, &subj, 2_000, None);
    put_statement(d, &by_stranger, None, INGEST_TIER)
        .await
        .unwrap();
    assert!(
        d.revocations_for(&iref(&subj)).await.unwrap().is_empty(),
        "I2005: a stranger's revocation projects nothing"
    );
    let by_owner = revocation(&owner, &subj, 3_000, None);
    put_statement(d, &by_owner, None, INGEST_TIER)
        .await
        .unwrap();
    assert!(
        d.revocations_for(&iref(&subj)).await.unwrap().is_empty(),
        "I2005: an owner's revocation projects nothing without standing"
    );
    let standing: Arc<dyn RevokerStanding> = Arc::new(Owner {
        owner: iref(&owner),
        subject: iref(&subj),
    });
    let set = project_key_with(d, &kid(&subj), standing).await.unwrap();
    assert_eq!(set.revocations.len(), 1, "I2005: only the owner's");
    let revs = d.revocations_for(&iref(&subj)).await.unwrap();
    assert_eq!(revs.len(), 1, "I2005: projected with standing");
    assert_eq!(
        revs[0].revoking_key_id,
        iref(&owner),
        "I2005: the owner's, not the stranger's"
    );

    // I2001: an earlier-form key answers 1 both ways (a stored JSON key).
    let json = crate::federation::tier_ingest::test_support::replicated_key_record(
        "j0-json-key",
        "agent",
        "j0-json-key",
        "j0-json-key",
        "j0",
    );
    d.put_public_key(crate::federation::SignedKeyRecord {
        record: json.clone(),
    })
    .await
    .unwrap();
    assert_eq!(
        d.key_edition(&json.key_id).await.unwrap(),
        Some(EDITION_ONE),
        "I2001 column, earlier form"
    );
    let held_json = d.lookup_public_key(&json.key_id).await.unwrap().unwrap();
    assert_eq!(
        edition_of_key_record(&held_json),
        EDITION_ONE,
        "I2001 provided, earlier form"
    );
    assert_eq!(
        d.key_edition("j0-not-held").await.unwrap(),
        None,
        "I2001: none held"
    );

    // ── I2007b: an earlier-form row is never overwritten ──
    let squat = key(74);
    let json_squat = crate::federation::tier_ingest::test_support::replicated_key_record(
        "j0-squat", "agent", "j0-squat", "j0-squat", "j0",
    );
    let squat_id = iref(&squat);
    raw.exec(&format!(
        "INSERT INTO {q}federation_keys (key_id, pubkey_ed25519_base64, algorithm, identity_type, \
         identity_ref, valid_from, registration_envelope, original_content_hash, \
         scrub_signature_classical, scrub_key_id, scrub_timestamp, persist_row_hash, \
         admitted_at) VALUES ({id}, {pk}, 'hybrid', 'agent', {id}, {t}, '{{}}', {h}, 'x', {id}, \
         {t}, 'x', {t})",
        id = sq(&squat_id),
        pk = sq(&json_squat.pubkey_ed25519_base64),
        t = sq("2026-01-01T00:00:00+00:00"),
        h = if q.is_empty() {
            "X'00'"
        } else {
            "'\\x00'::bytea"
        },
    ))
    .await
    .unwrap();
    let squat_row = raw
        .rows("federation_keys", &format!("key_id = {}", sq(&squat_id)))
        .await;
    let e = put_statement(
        d,
        &key_record(&squat, &["user"], 0, None),
        None,
        INGEST_TIER,
    )
    .await
    .expect_err("I2007b: refused");
    assert!(
        matches!(e, Error::Conflict(_)),
        "I2007b: Conflict, got {e:?}"
    );
    assert_eq!(
        raw.rows("federation_keys", &format!("key_id = {}", sq(&squat_id)))
            .await,
        squat_row,
        "I2007b: the earlier-form row is unchanged"
    );
    raw.exec(&format!(
        "DELETE FROM {q}federation_keys WHERE key_id = {}",
        sq(&squat_id)
    ))
    .await
    .unwrap();

    // ── I2008: the serve listing ──
    let mut served = Vec::new();
    let mut cursor = None;
    loop {
        let page = d
            .edition2_statements_since(cursor.as_ref(), 3)
            .await
            .unwrap();
        assert!(page.len() <= 3, "I2008: the limit");
        let Some(last) = page.last() else { break };
        cursor = Some(last.cursor);
        served.extend(page);
    }
    let positions: Vec<_> = served.iter().map(|s| s.cursor).collect();
    assert!(
        positions.windows(2).all(|w| w[0] < w[1]),
        "I2008: strictly increasing cursor"
    );
    assert!(
        positions
            .windows(2)
            .all(|w| w[0].admitted_us < w[1].admitted_us),
        "I2008: a serialised writer hands out strictly increasing positions"
    );
    let bytes: Vec<Vec<u8>> = served.iter().map(|s| s.bytes.clone()).collect();
    for st in [&rec1, &rec2, &st, &st2, &rev, &by_stranger, &by_owner] {
        assert_eq!(
            bytes.iter().filter(|b| b == &st).count(),
            1,
            "I2008: each held statement served once, as received"
        );
    }
    assert_eq!(
        d.edition2_statements_since(cursor.as_ref(), 3)
            .await
            .unwrap(),
        vec![],
        "I2008: nothing after the last"
    );
}

/// I2009 on a fresh open of the store `body` filled: the rehome and the two
/// rebuild gates leave the read models alone.
pub(crate) async fn read_models_are_not_earlier_form_rows(
    report: crate::federation::key_plane::KeyPlaneRehomeReport,
    keys: crate::federation::silo_projection::ProjectionRebuild,
    revocations: crate::federation::silo_projection::ProjectionRebuild,
    raw: &Raw<'_>,
) {
    assert_eq!(
        report.keys_without_row, 0,
        "I2009: no projection counted: {report:?}"
    );
    assert_eq!(report.revocations_without_row, 0, "I2009: {report:?}");
    assert_eq!(keys.divergence(), None, "I2009: the key rebuild gate");
    assert_eq!(
        revocations.divergence(),
        None,
        "I2009: the revocation rebuild gate"
    );
    assert_eq!(
        raw.rows("federation_keys", "edition = 2 AND attestation_id IS NULL")
            .await
            .len(),
        4,
        "I2009: every projection is still rowless"
    );
    assert!(
        raw.rows(
            "federation_keys",
            "edition = 2 AND attestation_id IS NOT NULL"
        )
        .await
        .is_empty(),
        "I2009: no key:record:v1 row minted for a projection"
    );
    assert!(
        raw.rows(
            "federation_revocations",
            "attestation_id IS NOT NULL AND revoked_key_id LIKE 'urn:%'"
        )
        .await
        .is_empty(),
        "I2009: no revocation row minted for a projection"
    );
}

/// I2003 at each choke point: `refused` says whether the signer is edition 2.
async fn cross_form(
    d: &dyn FederationDirectory,
    row: &Attestation,
    record: &crate::federation::KeyRecord,
    refused: bool,
) {
    use crate::federation::{
        admission, cosign, group_plane, key_plane, occurrence_revocation_carrier, register,
        self_roster, tier_ingest,
    };
    let token = malformed_row::EARLIER_FORM_SIGNER_IS_EDITION2;
    // Each site refuses under its own plane, so a site whose guard is gone
    // is seen even where a later site would refuse by the same reason.
    let check = |site: &str, plane: &str, r: Result<(), Error>| {
        let got = r.err().map(|e| match e {
            Error::MalformedRow { plane, reason, .. } => format!("{plane}:{reason}"),
            other => format!("{}: {other}", other.kind()),
        });
        if refused {
            assert_eq!(
                got.as_deref(),
                Some(format!("{plane}:{token}").as_str()),
                "I2003 at {site}"
            );
        } else {
            assert!(
                !got.as_deref().is_some_and(|g| g.ends_with(token)),
                "I2003 control at {site}: {got:?}"
            );
        }
    };
    let b = |r: Result<bool, Error>| r.map(|_| ());
    check(
        "tier_ingest::verify_row_hybrid_signature",
        "attestation",
        tier_ingest::verify_row_hybrid_signature(d, row).await,
    );
    check(
        "register::verify_key_registration",
        "key_registration",
        register::verify_key_registration(d, record)
            .await
            .map(|_| ()),
    );
    check(
        "register::verify_proof_of_possession",
        "key_record",
        register::verify_proof_of_possession(record),
    );
    check(
        "key_plane::verify_plane_row",
        "key_plane",
        b(key_plane::verify_plane_row(d, row).await),
    );
    check(
        "group_plane::verify_plane_row",
        "group_plane",
        b(group_plane::verify_plane_row(d, row).await),
    );
    check(
        "self_roster::verify_proposal_row",
        "self_roster",
        b(self_roster::verify_proposal_row(d, row).await),
    );
    check(
        "cosign::verify_row",
        "cosign",
        b(cosign::verify_row(d, row).await),
    );
    check(
        "occurrence_revocation_carrier::verify_carrier_row",
        "occurrence_revocation_carrier",
        b(occurrence_revocation_carrier::verify_carrier_row(d, row).await),
    );
    // A subject-side withdrawal transiting the local tier.
    let mut transit = row.clone();
    transit.tier = crate::federation::types::attestation_tier::LOCAL.to_owned();
    transit.attestation_type = crate::federation::types::attestation_type::WITHDRAWS.to_owned();
    transit.subject_key_ids = vec![row.attesting_key_id.clone()];
    check(
        "admission::verify_consent_record_transit_ingest",
        "consent_record",
        admission::verify_consent_record_transit_ingest(d, &transit).await,
    );
    let input: crate::federation::types::LocalAttestationInput =
        serde_json::from_value(serde_json::json!({
            "attesting_key_id": row.attesting_key_id,
            "attestation_type": "scores",
            "attestation_envelope": row.attestation_envelope,
            "scrub_signature_classical": "AA==",
        }))
        .unwrap();
    check(
        "admission::verify_caller_signed_local_row",
        "local_attestation",
        admission::verify_caller_signed_local_row(
            d,
            admission::LocalTierDisposition::Durable,
            &input,
        )
        .await
        .map(|_| ()),
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2000_to_i2009_sqlite() {
    use crate::store::Backend as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j0.db").to_string_lossy().into_owned();
    let b = crate::store::sqlite::SqliteBackend::open(path.clone())
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    {
        // I2002: the signer FKs are enforced on this connection.
        let c = b.conn_handle();
        let c = c.lock();
        let on: i64 = c
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(on, 1, "I2002: foreign_keys is on");
        let fks: Vec<(String, String)> = c
            .prepare(
                "SELECT \"from\", \"table\" FROM pragma_foreign_key_list('federation_attestations')",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for col in ["attesting_key_id", "scrub_key_id"] {
            assert!(
                fks.contains(&(col.to_owned(), "federation_keys".to_owned())),
                "I2002: {col} → federation_keys: {fks:?}"
            );
        }
    }
    Box::pin(body(&b, &Raw::Sqlite(&b))).await;
    drop(b);
    // I2009: a fresh open of the same file.
    let b = crate::store::sqlite::SqliteBackend::open(path)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    use crate::federation::attestation_admit::AttestationStore as _;
    use crate::federation::silo_projection::SiloProjection;
    let report = b.rehome_key_plane_at_open().await.unwrap();
    let keys = b
        .projection_rebuild(SiloProjection::FederationKeys)
        .await
        .unwrap();
    let revs = b
        .projection_rebuild(SiloProjection::FederationRevocations)
        .await
        .unwrap();
    read_models_are_not_earlier_form_rows(report, keys, revs, &Raw::Sqlite(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2000_to_i2009_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b, &Raw::Pg(&b))).await;
    // I2009: a fresh open of the same database.
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    use crate::federation::attestation_admit::AttestationStore as _;
    use crate::federation::silo_projection::SiloProjection;
    let report = b.rehome_key_plane_at_open().await.unwrap();
    let keys = b
        .projection_rebuild(SiloProjection::FederationKeys)
        .await
        .unwrap();
    let revs = b
        .projection_rebuild(SiloProjection::FederationRevocations)
        .await
        .unwrap();
    read_models_are_not_earlier_form_rows(report, keys, revs, &Raw::Pg(&b)).await;
}
