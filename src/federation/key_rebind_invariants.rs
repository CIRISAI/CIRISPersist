//! CIRISPersist#864 — witnesses for `FSD/KEY_RECORD_REBIND.md` §5. One body
//! per invariant over `&dyn FederationDirectory`, run by memory, sqlite and
//! postgres so the three cannot diverge; the multi-engine leg on sqlite.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::register::{
        self, KeyRefusalReason, ReplicatedKeyOutcome, ReplicatedKeyPlan,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{AGENT, NODE, USER};
    use crate::federation::{admission, Error, FederationDirectory, KeyRecord, SignedKeyRecord};

    /// The canonical's July shape: a self-signed record whose envelope is
    /// exactly `{"key_id": …}` — pubkeys correct, subject unbound.
    pub fn legacy_record(key_id: &str, identity_type: &str) -> KeyRecord {
        let (ed_pk, mldsa_pk) = ts::hybrid_pubkeys(key_id);
        let envelope = serde_json::json!({ "key_id": key_id });
        let (och, classical, pqc) = ts::sign_envelope(key_id, &envelope);
        let ts_: chrono::DateTime<chrono::Utc> = "2026-05-01T00:00:00Z".parse().unwrap();
        KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: ts_,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: ts_,
            pqc_completed_at: Some(ts_),
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// The same holder's bound record: same pubkeys, same claim, the #659
    /// subject bound into the envelope, self-signed.
    pub fn bound_record(key_id: &str, identity_type: &str, nonce: &str) -> KeyRecord {
        ts::replicated_key_record(key_id, identity_type, key_id, key_id, nonce)
    }

    fn signed(r: KeyRecord) -> SignedKeyRecord {
        SignedKeyRecord { record: r }
    }

    /// **I99 — the plan classifies a rebind, and refuses everything that is
    /// not one.**
    pub async fn i99_plan_classifies_the_rebind(d: &dyn FederationDirectory, s: &str) {
        let k = format!("i99-k-{s}");
        d.put_public_key(signed(legacy_record(&k, USER)))
            .await
            .expect("I99: the legacy row seeds through the raw door (as the canonical's did)");
        assert!(
            admission::verify_envelope_binds_subject(
                &d.lookup_public_key(&k).await.unwrap().unwrap()
            )
            .is_err(),
            "I99 precondition: the stored row is unbound"
        );

        // The rebind.
        let plan = register::plan_replicated_key_apply(d, &bound_record(&k, USER, "n1"))
            .await
            .unwrap();
        assert!(matches!(plan, ReplicatedKeyPlan::Rebind), "I99: unbound self-signed row + bound self-signed same-pubkey record → Rebind, got {plan:?}");

        // A differing pubkey half is a different identity.
        let mut swap = bound_record(&k, USER, "n2");
        swap.pubkey_ml_dsa_65_base64 = ts::hybrid_pubkeys("i99-other").1;
        assert!(
            matches!(
                register::plan_replicated_key_apply(d, &swap).await.unwrap(),
                ReplicatedKeyPlan::Refused {
                    reason: KeyRefusalReason::PubkeySwap
                }
            ),
            "I99: pubkey swap"
        );

        // A changed claim member is not a rebind: identity_type, valid_from, roles.
        let changed_type = bound_record(&k, AGENT, "n3");
        assert!(
            matches!(
                register::plan_replicated_key_apply(d, &changed_type)
                    .await
                    .unwrap(),
                ReplicatedKeyPlan::Refused {
                    reason: KeyRefusalReason::RebindChangesRecord
                }
            ),
            "I99: identity_type"
        );
        let mut later = bound_record(&k, USER, "n4");
        later.valid_from += chrono::Duration::days(1);
        assert!(
            matches!(
                register::plan_replicated_key_apply(d, &later)
                    .await
                    .unwrap(),
                ReplicatedKeyPlan::Refused {
                    reason: KeyRefusalReason::RebindChangesRecord
                }
            ),
            "I99: valid_from"
        );

        // A bad signature is not possession.
        let mut forged = bound_record(&k, USER, "n5");
        forged.scrub_signature_classical = forged.scrub_signature_classical.chars().rev().collect();
        assert!(
            matches!(
                register::plan_replicated_key_apply(d, &forged)
                    .await
                    .unwrap(),
                ReplicatedKeyPlan::Refused {
                    reason: KeyRefusalReason::UnverifiableSignature
                }
            ),
            "I99: signature"
        );

        // Bound → bound differing stays first-seen-wins.
        let k2 = format!("i99-bound-{s}");
        d.put_public_key(signed(bound_record(&k2, USER, "b1")))
            .await
            .unwrap();
        assert!(
            matches!(
                register::plan_replicated_key_apply(d, &bound_record(&k2, USER, "b2"))
                    .await
                    .unwrap(),
                ReplicatedKeyPlan::Refused {
                    reason: KeyRefusalReason::ConflictingVersion
                }
            ),
            "I99: a bound record is never rebound"
        );

        // An anchor-scrubbed unbound row is never rebound by its holder.
        let (k3, anchor) = (format!("i99-anch-{s}"), format!("i99-anchor-{s}"));
        ts::register_identity_key(d, &anchor, NODE).await;
        let mut anchored = legacy_record(&k3, NODE);
        let (och, c, p) = ts::sign_envelope(&anchor, &anchored.registration_envelope);
        anchored.original_content_hash = och;
        anchored.scrub_signature_classical = c;
        anchored.scrub_signature_pqc = p;
        anchored.scrub_key_id = anchor.clone();
        d.put_public_key(signed(anchored))
            .await
            .expect("I99: an anchor-scrubbed unbound row seeds");
        assert!(
            matches!(
                register::plan_replicated_key_apply(d, &bound_record(&k3, NODE, "a1"))
                    .await
                    .unwrap(),
                ReplicatedKeyPlan::Refused {
                    reason: KeyRefusalReason::Downgrade
                }
            ),
            "I99: anchor-scrubbed → Downgrade, not Rebind"
        );
    }

    /// **I100 — the store step: bound, unchanged where it must be, re-served,
    /// history kept, idempotent.**
    pub async fn i100_store_rebinds_and_reserves(d: &dyn FederationDirectory, s: &str) {
        let k = format!("i100-k-{s}");
        let legacy = legacy_record(&k, USER);
        d.put_public_key(signed(legacy.clone())).await.unwrap();
        let before = d.lookup_public_key(&k).await.unwrap().unwrap();
        // A cursor that has already passed the row.
        let served = d.list_signed_key_records_since(None, 10_000).await.unwrap();
        let cursor = served
            .iter()
            .find(|r| r.record.key_id == k)
            .map(|r| r.resume_pair())
            .expect("I100: the legacy row is served");
        assert!(
            d.list_signed_key_records_since(Some(cursor.clone()), 10_000)
                .await
                .unwrap()
                .iter()
                .all(|r| r.record.key_id != k),
            "I100 precondition: past the cursor, the row is not served"
        );

        let out = d
            .apply_replicated_key_record(signed(bound_record(&k, USER, "r1")))
            .await
            .unwrap();
        assert!(
            matches!(out, ReplicatedKeyOutcome::Rebound),
            "I100: {out:?}"
        );
        let after = d.lookup_public_key(&k).await.unwrap().unwrap();
        admission::verify_envelope_binds_subject(&after).expect("I100: the row is bound now");
        register::verify_key_registration(d, &after)
            .await
            .expect("I100: and verifies as a registration");
        assert_eq!(after.pubkey_ed25519_base64, before.pubkey_ed25519_base64);
        assert_eq!(
            after.pubkey_ml_dsa_65_base64,
            before.pubkey_ml_dsa_65_base64
        );
        assert_eq!(
            after.valid_from, before.valid_from,
            "I100: valid_from is history, untouched"
        );
        assert_eq!(after.identity_type, before.identity_type);
        assert_ne!(
            after.persist_row_hash, before.persist_row_hash,
            "I100: the hash follows the bytes"
        );
        assert!(
            d.list_signed_key_records_since(Some(cursor), 10_000)
                .await
                .unwrap()
                .iter()
                .any(|r| r.record.key_id == k),
            "I100: the rebound row is re-served past the old cursor"
        );
        let history = d.list_key_registration_history(&k).await.unwrap();
        assert_eq!(history.len(), 1, "I100: one replaced registration");
        assert_eq!(
            history[0].original_content_hash, before.original_content_hash,
            "I100: the history row is the OLD claim"
        );
        assert_eq!(history[0].replaced_by_hash, after.persist_row_hash);
        // Idempotent.
        assert!(
            matches!(
                d.apply_replicated_key_record(signed(bound_record(&k, USER, "r1")))
                    .await
                    .unwrap(),
                ReplicatedKeyOutcome::Unchanged
            ),
            "I100: a second apply is Unchanged"
        );
        assert_eq!(
            d.list_key_registration_history(&k).await.unwrap().len(),
            1,
            "I100: no second history row"
        );
        // The store step itself, called PAST the plan, re-asserts what it can:
        // a swapped pubkey and a changed claim are `Conflict`, the row untouched.
        let mut swapped = bound_record(&k, USER, "r2");
        // (The fixture seeds from the FIRST 32 bytes of a key id; a suffix on
        // a long id changes nothing, so the other identity is a prefix.)
        swapped.pubkey_ed25519_base64 = ts::hybrid_pubkeys(&format!("other-{k}")).0;
        let r = d.store_rebound_key_record(signed(swapped)).await;
        assert!(
            matches!(r, Err(Error::Conflict(_))),
            "I100: the store step refuses a pubkey swap on its own: {r:?}"
        );
        assert!(
            matches!(
                d.store_rebound_key_record(signed(bound_record(&k, NODE, "r3")))
                    .await,
                Err(Error::Conflict(_))
            ),
            "I100: the store step refuses a changed claim on its own"
        );
        assert_eq!(
            d.lookup_public_key(&k)
                .await
                .unwrap()
                .unwrap()
                .persist_row_hash,
            after.persist_row_hash,
            "I100: refused store calls leave the row"
        );
        assert_eq!(
            d.list_key_registration_history(&k).await.unwrap().len(),
            1,
            "I100: and write no history"
        );
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i99() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i99_plan_classifies_the_rebind(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i100() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i100_store_rebinds_and_reserves(&b, &super::suffix()).await
                }
            }
        };
    }
    runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });
    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "postgres")]
    runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    /// **I101 — three engines: the holder rebinds on A; B (holding the legacy
    /// row) heals from the plane; C (never held it) refused the legacy record
    /// and admits the bound one; both then admit the key's attestation.**
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i101_the_identity_round_completes_after_the_rebind() {
        use super::bodies::{bound_record, legacy_record};
        use crate::federation::register::{KeyRefusalReason, RebindOutcome, ReplicatedKeyOutcome};
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type::USER;
        use crate::federation::{FederationDirectory, SignedAttestation, SignedKeyRecord};
        let run = super::run::suffix();
        let mk = |alias: String| async move {
            let e =
                crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), "sqlite::memory:")
                    .await
                    .unwrap();
            e.register_self_federation_key(
                crate::federation::types::identity_type::NODE,
                &alias,
                None,
                serde_json::json!({}),
                vec![],
            )
            .await
            .unwrap();
            e
        };
        let (a, b, c) = (
            mk(format!("i101-a-{run}")).await,
            mk(format!("i101-b-{run}")).await,
            mk(format!("i101-c-{run}")).await,
        );
        let (sa, sb, sc) = (
            a.sqlite_backend().unwrap().clone(),
            b.sqlite_backend().unwrap().clone(),
            c.sqlite_backend().unwrap().clone(),
        );
        let user = format!("i101-user-{run}");
        for s in [&sa, &sb] {
            s.put_public_key(SignedKeyRecord {
                record: legacy_record(&user, USER),
            })
            .await
            .expect("I101: A and B hold the legacy row");
        }
        // C, a fresh peer, REFUSES the legacy record the plane serves: this is
        // the blocker, reproduced through persist's own gate.
        let legacy_served = sa
            .list_signed_key_records_since(None, 10_000)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.record.key_id == user)
            .unwrap()
            .record;
        // The insert arm runs `verify_key_registration` fail-closed BEFORE any
        // write and propagates its error (v21.0.0 #502 E2 shape, unchanged
        // here): the refusal is the #659 subject-binding error, by name.
        let refused = sc
            .apply_replicated_key_record(SignedKeyRecord {
                record: legacy_served,
            })
            .await;
        assert!(matches!(&refused, Err(crate::federation::Error::SignatureInvalid(m)) if m.contains("does not bind")), "I101 precondition: a fresh peer refuses the unbound record at the insert gate: {refused:?}");

        // The local door refuses what is not a rebind by NAME, before the plan
        // could mutate anything: a record scrubbed by someone else, a key A
        // does not hold.
        let mut not_self = bound_record(&user, USER, "heal");
        not_self.scrub_key_id = format!("i101-other-{run}");
        assert!(
            matches!(
                a.rebind_key_record(SignedKeyRecord { record: not_self })
                    .await
                    .unwrap(),
                RebindOutcome::Refused {
                    reason: KeyRefusalReason::NotSelfSigned
                }
            ),
            "I101: not self-signed"
        );
        let absent = format!("i101-absent-{run}");
        assert!(
            matches!(
                a.rebind_key_record(SignedKeyRecord {
                    record: bound_record(&absent, USER, "x")
                })
                .await
                .unwrap(),
                RebindOutcome::Refused {
                    reason: KeyRefusalReason::RecordAbsent
                }
            ),
            "I101: no row to rebind"
        );
        assert!(
            sa.lookup_public_key(&absent).await.unwrap().is_none(),
            "I101: the door inserts nothing"
        );

        // The holder rebinds on A.
        let out = a
            .rebind_key_record(SignedKeyRecord {
                record: bound_record(&user, USER, "heal"),
            })
            .await
            .unwrap();
        assert!(matches!(out, RebindOutcome::Rebound), "I101: {out:?}");
        let healed = sa
            .list_signed_key_records_since(None, 10_000)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.record.key_id == user)
            .unwrap()
            .record;
        crate::federation::admission::verify_envelope_binds_subject(&healed)
            .expect("I101: the plane serves the bound record");

        // B heals from the plane; C inserts it.
        assert!(
            matches!(
                sb.apply_replicated_key_record(SignedKeyRecord {
                    record: healed.clone()
                })
                .await
                .unwrap(),
                ReplicatedKeyOutcome::Rebound
            ),
            "I101: B rebinds from the plane"
        );
        assert!(
            matches!(
                sc.apply_replicated_key_record(SignedKeyRecord { record: healed })
                    .await
                    .unwrap(),
                ReplicatedKeyOutcome::Inserted
            ),
            "I101: C inserts the bound record"
        );

        // And the key's attestation is admitted everywhere — the identity round completes.
        // (B and C first learn A's own node record from the plane, as they would;
        // an owner-binding names the node it binds.)
        let node_a = a.local_derived_key_id().await.unwrap();
        let node_a_row = sa.lookup_public_key(&node_a).await.unwrap().unwrap();
        for (name, s) in [("B", &sb), ("C", &sc)] {
            let out = s
                .apply_replicated_key_record(SignedKeyRecord {
                    record: node_a_row.clone(),
                })
                .await
                .unwrap();
            assert!(
                matches!(out, ReplicatedKeyOutcome::Inserted),
                "I101: {name} inserts A's node record: {out:?}"
            );
        }
        let ob = ts::owner_binding_attestation(&format!("i101-ob-{run}"), &user, &node_a);
        for (name, s) in [("A", &sa), ("B", &sb), ("C", &sc)] {
            s.apply_replicated_attestation(SignedAttestation {
                attestation: ob.clone(),
            })
            .await
            .unwrap_or_else(|e| {
                panic!("I101: {name} admits the user's owner-binding after the rebind: {e}")
            });
        }
    }

    /// **I102 — the self door: an engine heals its own unbound record.**
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i102_rebind_self_heals_an_empty_envelope_record() {
        use crate::federation::register::{KeyRefusalReason, RebindOutcome};
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::{FederationDirectory, KeyRecord, SignedKeyRecord};
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let run = super::run::suffix();
        let alias = format!("i102-{run}");
        let local = ts::local_signer(&alias);
        let engine = crate::Engine::with_signer_pre_genesis(local.clone(), "sqlite::memory:")
            .await
            .unwrap();
        let s = engine.sqlite_backend().unwrap().clone();
        let me = engine.local_derived_key_id().await.unwrap();
        // The 529 shape: this engine's own key, registered with an EMPTY envelope,
        // self-signed with its real keys.
        let envelope = serde_json::json!({});
        let canonical = crate::verify::canonical::ceg_produce_canonicalize(&envelope).unwrap();
        let sig = local.sign_hybrid(&canonical).await.unwrap();
        let now = chrono::Utc::now();
        s.put_public_key(SignedKeyRecord {
            record: KeyRecord {
                key_id: me.clone(),
                pubkey_ed25519_base64: local.public_key_b64(),
                pubkey_ml_dsa_65_base64: local.pqc_public_key_b64().await.unwrap(),
                algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
                identity_type: crate::federation::types::identity_type::AGENT.to_owned(),
                identity_ref: me.clone(),
                valid_from: now,
                valid_until: None,
                registration_envelope: envelope,
                original_content_hash: {
                    use sha2::Digest as _;
                    hex::encode(sha2::Sha256::digest(&canonical))
                },
                scrub_signature_classical: B64.encode(&sig.classical.signature),
                scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
                scrub_key_id: me.clone(),
                scrub_timestamp: now,
                pqc_completed_at: Some(now),
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .expect("I102: the empty-envelope row seeds");
        assert!(crate::federation::admission::verify_envelope_binds_subject(
            &s.lookup_public_key(&me).await.unwrap().unwrap()
        )
        .is_err());

        let out = engine
            .rebind_self_federation_key(crate::federation::types::identity_type::AGENT)
            .await
            .unwrap();
        assert!(matches!(out, RebindOutcome::Rebound), "I102: {out:?}");
        let row = s.lookup_public_key(&me).await.unwrap().unwrap();
        crate::federation::admission::verify_envelope_binds_subject(&row).expect("I102: bound");
        crate::federation::register::verify_key_registration(s.as_ref(), &row)
            .await
            .expect("I102: verifies");
        assert!(
            matches!(
                engine
                    .rebind_self_federation_key(crate::federation::types::identity_type::AGENT)
                    .await
                    .unwrap(),
                RebindOutcome::Unchanged
            ),
            "I102: idempotent"
        );
        // A different identity_type is not a rebind.
        assert!(
            matches!(
                engine
                    .rebind_self_federation_key(crate::federation::types::identity_type::NODE)
                    .await
                    .unwrap(),
                RebindOutcome::Refused {
                    reason: KeyRefusalReason::RebindChangesRecord
                }
            ),
            "I102: the claim does not move"
        );
    }

    /// **I103 — from disk: one rule, and every mirror delegates.**
    #[test]
    fn i103_one_rule_every_door() {
        const REG: &str = include_str!("register.rs");
        const SQLITE: &str = include_str!("../store/sqlite.rs");
        const PG: &str = include_str!("../store/postgres.rs");
        const MEM: &str = include_str!("../store/memory.rs");
        const PYO3: &str = include_str!("../ffi/pyo3.rs");
        const ENGINE: &str = include_str!("../engine.rs");
        assert_eq!(
            REG.matches("ReplicatedKeyPlan::Rebind =>").count()
                + REG.matches("Ok(ReplicatedKeyPlan::Rebind)").count(),
            1,
            "I103: the plan produces Rebind in exactly one place"
        );
        for (name, text) in [
            ("sqlite.rs", SQLITE),
            ("postgres.rs", PG),
            ("memory.rs", MEM),
        ] {
            let body = text
                .split("fn store_rebound_key_record(")
                .nth(1)
                .unwrap_or_else(|| panic!("I103: {name} has the store step"));
            let body = &body[..body.find("\n    }\n").expect("end")];
            assert!(
                !body.contains("verify_envelope_binds_subject("),
                "I103: {name}'s store step re-decides the rule"
            );
            assert!(
                text.contains("ReplicatedKeyPlan::Rebind =>"),
                "I103: {name}'s apply dispatches the arm"
            );
        }
        for f in ["rebind_key_record", "rebind_self_federation_key"] {
            let d = PYO3
                .split(&format!("    fn {f}("))
                .nth(1)
                .unwrap_or_else(|| panic!("I103: PyO3 mirror {f}"));
            let body = &d[..d.find("\n    }\n").expect("end")];
            assert!(
                body.contains(&format!(".{f}(")),
                "I103: the PyO3 mirror `{f}` delegates to the Engine"
            );
        }
        assert!(
            ENGINE.contains("pub async fn rebind_key_record(")
                && ENGINE.contains("pub async fn rebind_self_federation_key("),
            "I103: both Engine doors exist"
        );
    }
}
