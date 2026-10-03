//! v53.0.0 (CC 4.2.6 / CC 3.2 T6) — **the accord's roster change**, the
//! door's third shape. I450e–I450h.
//!
//! - **I450e** the local door: a version adding a holder is admitted under a
//!   strict majority of the STANDING roster, covering one authorized, closed
//!   decision binding exactly that change, signed by the added holder, naming
//!   a re-scrubbed charter that commits the new holder's recovery key. Each
//!   leg missing refuses by name; the admitted version moves the head, clears
//!   the decision's lag, and its roster is the fold's.
//! - **I450f** replicated: a peer judges the same predicate — it refuses the
//!   version while it holds no decision, and admits it once the decision is
//!   held.
//! - **I450g** a removal: the charter must drop the removed holder (a charter
//!   still committing them is a stray at the version), then it is admitted.
//! - **I450j** a seat goes only to an `accord_holder` key record (both the
//!   roster change and the recovery door).
//! - **I450i** from disk: the genesis bundle check runs the same coverage
//!   rule and propagates its refusal.
//! - **I450h** the standing roster is the HELD head's: cosigns from the holder
//!   being added do not count toward the majority.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::accord_roster::{
        seat_change_digest, SeatAdd, SeatChange, ROSTER_CHANGE_KIND,
    };
    use crate::federation::canonical_community::accord_family_key_id;
    use crate::federation::canonical_community_invariants::bodies::stand_up;
    use crate::federation::operational::test_support as ops;
    use crate::federation::roster_head::{fold_disagreement, roster_lag, LineageRecord};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::trust_root::{
        test_accord_recovery_commitments, test_pre_rotation_commitment, INFRA_ATTEST_SCOPE,
        INFRA_SERVE_SCOPE, TRUST_CHARTER_DIMENSION,
    };
    use crate::federation::types::{attestation_type, identity_type, Family, FamilyMember};
    use crate::federation::{Error, FederationDirectory, SignedFamily};
    use ciris_verify_core::accord_live_quorum::{AccordAction, AccordDecision, AccordProposal};

    pub(crate) async fn held(d: &dyn FederationDirectory) -> Family {
        d.lookup_family(accord_family_key_id())
            .await
            .unwrap()
            .expect("the accord is held")
    }

    async fn held_charter(d: &dyn FederationDirectory) -> String {
        held(d).await.charter_digest
    }

    fn ids(f: &Family) -> Vec<String> {
        f.members.iter().map(|m| m.key_id.clone()).collect()
    }

    /// A charter of the accord committing a recovery key for `roster`,
    /// scrubbed by the held holders. Returns its digest.
    pub(crate) async fn rescrub(
        d: &dyn FederationDirectory,
        roster: &[String],
        tag: &str,
    ) -> String {
        let accord = accord_family_key_id();
        let signers = ids(&held(d).await);
        let id = format!("ar-charter-{tag}-{}", uuid::Uuid::new_v4().simple());
        let env = serde_json::json!({
            "references_attestation_id": id,
            "dimension": TRUST_CHARTER_DIMENSION,
            "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            "pre_rotation_commitment": test_pre_rotation_commitment(&[
                "accord-succ-a".to_owned(),
                "accord-succ-b".to_owned(),
            ])
            .unwrap(),
            "recovery_commitments": test_accord_recovery_commitments(roster),
        });
        let cosigners: Vec<&str> = signers[1..].iter().map(String::as_str).collect();
        let c = ops::co_signed_trust_attestation(
            &id,
            &signers[0],
            accord,
            attestation_type::DELEGATES_TO,
            env,
            &cosigners,
        );
        let digest = ops::charter_digest_of(&c);
        d.put_attestation(crate::federation::SignedAttestation { attestation: c })
            .await
            .expect("the re-scrubbed charter is admitted (shape only)");
        digest
    }

    /// Record an accord `roster_change` decision for `change` on the held head.
    pub(crate) async fn decide(
        d: &dyn FederationDirectory,
        change: &SeatChange,
        closes: chrono::DateTime<chrono::Utc>,
        authorized: bool,
        nonce: &str,
    ) -> String {
        let accord = accord_family_key_id();
        let head = held(d).await;
        d.issue_accord_nonce(accord, nonce).await.unwrap();
        let proposal = AccordProposal {
            family_key_id: accord.to_owned(),
            action: AccordAction::RosterChange,
            nonce: nonce.to_owned(),
            window_until: closes.to_rfc3339(),
            prior_family_digest: head.persist_row_hash.clone(),
            payload_sha256: seat_change_digest(accord, change).unwrap(),
        };
        d.put_accord_proposal(proposal.clone(), None).await.unwrap();
        d.put_accord_decision(AccordDecision {
            proposal: proposal.clone(),
            live_set: vec![],
            yes: 2,
            no: 0,
            abstain: 0,
            authorized,
        })
        .await
        .unwrap();
        proposal.digest()
    }

    /// The version applying `change` to the held head, naming `charter`,
    /// covering `decision`, cosigned by `yes`, its record signed by `author`.
    pub(crate) async fn version(
        d: &dyn FederationDirectory,
        change: &SeatChange,
        decision: &str,
        charter: &str,
        yes: &[&str],
        author: &str,
    ) -> SignedFamily {
        let accord = accord_family_key_id();
        let head = held(d).await;
        let mut next = head.clone();
        next.members.retain(|m| !change.remove.contains(&m.key_id));
        for a in &change.add {
            next.members.push(FamilyMember {
                key_id: a.key_id.clone(),
                joined_at: head.founded_at,
                role: a.role.clone(),
            });
        }
        next.prev_head_digest = head.persist_row_hash.clone();
        next.charter_digest = charter.to_owned();
        next.persist_row_hash = String::new();
        let mut c = serde_json::to_value(change).unwrap();
        c["decision"] = serde_json::json!(decision);
        let env = serde_json::json!({
            "kind": ROSTER_CHANGE_KIND,
            "family_key_id": accord,
            "prior_persist_row_hash": head.persist_row_hash,
            "next_persist_row_hash": crate::federation::types::compute_persist_row_hash(&next).unwrap(),
            "changes": [c],
        });
        let bytes = ciris_verify_core::accord_genesis::accord_family_signing_bytes(&env).unwrap();
        let mut signed = ts::sign_family(author, next);
        signed.supersede_proof = Some(crate::federation::types::GroupSupersedeProof {
            prior_persist_row_hash: head.persist_row_hash,
            change_envelope: env,
            quorum_signatures: yes.iter().map(|k| ts::threshold_sign(k, &bytes)).collect(),
        });
        signed
    }

    pub(crate) async fn apply(d: &dyn FederationDirectory, v: SignedFamily) -> Result<u32, Error> {
        crate::federation::group_amendment::supersede_family_signed(d, v, None).await
    }

    fn refused(r: Result<u32, Error>, token: &str, what: &str) {
        match r {
            Err(Error::CharterInvalid { detail }) if detail.contains(token) => {}
            other => panic!("{what}: expected {token:?}, got {other:?}"),
        }
    }

    fn adding(key: &str, role: Option<String>) -> SeatChange {
        SeatChange {
            remove: vec![],
            add: vec![SeatAdd {
                key_id: key.to_owned(),
                role,
            }],
        }
    }

    /// A key an accord holder can hold: an `accord_holder` record (CC 4.2.6).
    pub(crate) async fn newcomer(d: &dyn FederationDirectory, tag: &str) -> String {
        let k = format!("ar-new-{tag}");
        ops::register_accord_holder_as(d, &ops::Identity::new(&k), identity_type::ACCORD_HOLDER)
            .await
            .expect("an accord_holder key");
        k
    }

    /// **I450j** — a seat goes only to an `accord_holder` key: the roster
    /// change refuses a newcomer whose record lacks it, by name.
    pub async fn i450j_a_seat_needs_an_accord_holder_key(d: &dyn FederationDirectory, tag: &str) {
        stand_up(d).await;
        let before = held(d).await;
        let holders = ids(&before);
        let plain = format!("ar-plain-{tag}");
        ts::register_hybrid_key_as(d, &plain, &plain, identity_type::NODE).await;
        let change = adding(&plain, before.members[0].role.clone());
        let mut grown = holders.clone();
        grown.push(plain.clone());
        let charter = rescrub(d, &grown, tag).await;
        let decision = decide(
            d,
            &change,
            chrono::Utc::now() - chrono::Duration::hours(1),
            true,
            &format!("ar-j-{tag}"),
        )
        .await;
        refused(
            apply(
                d,
                version(
                    d,
                    &change,
                    &decision,
                    &charter,
                    &[&holders[0], &holders[1]],
                    &plain,
                )
                .await,
            )
            .await,
            "accord_roster_change_not_a_holder_key",
            "I450j: a node key takes no accord seat",
        );
        assert_eq!(held(d).await, before, "I450j: nothing written");
    }

    /// **I450e** — the local door, each leg and the admitted version.
    pub async fn i450e_a_roster_change_is_admitted_whole(d: &dyn FederationDirectory, tag: &str) {
        stand_up(d).await;
        let before = held(d).await;
        let holders = ids(&before);
        let role = before.members[0].role.clone();
        let new = newcomer(d, tag).await;
        let change = adding(&new, role);
        let mut grown = holders.clone();
        grown.push(new.clone());
        let charter = rescrub(d, &grown, tag).await;
        // A held charter that commits only the standing roster.
        let old_charter = rescrub(d, &holders, tag).await;
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let h = |i: usize| holders[i].as_str();

        // No decision covers it.
        let e = apply(
            d,
            version(d, &change, &"ab".repeat(32), &charter, &[h(0), h(1)], &new).await,
        )
        .await;
        refused(e, "accord_roster_change_uncovered", "I450e: no decision");
        // An unauthorized decision, an open window, a decision for another change.
        let refusedd = decide(d, &change, past, false, &format!("ar-r-{tag}")).await;
        refused(
            apply(
                d,
                version(d, &change, &refusedd, &charter, &[h(0), h(1)], &new).await,
            )
            .await,
            "accord_roster_change_uncovered",
            "I450e: unauthorized",
        );
        let open = decide(
            d,
            &change,
            chrono::Utc::now() + chrono::Duration::hours(1),
            true,
            &format!("ar-o-{tag}"),
        )
        .await;
        refused(
            apply(
                d,
                version(d, &change, &open, &charter, &[h(0), h(1)], &new).await,
            )
            .await,
            "accord_roster_change_uncovered",
            "I450e: window open (the removed holder's lame duck runs to its close)",
        );
        let other = decide(
            d,
            &adding("ar-someone-else", None),
            past,
            true,
            &format!("ar-x-{tag}"),
        )
        .await;
        refused(
            apply(
                d,
                version(d, &change, &other, &charter, &[h(0), h(1)], &new).await,
            )
            .await,
            "accord_roster_change_uncovered",
            "I450e: a decision binding another change",
        );
        let decision = decide(d, &change, past, true, &format!("ar-ok-{tag}")).await;
        // One yes of three is short of the standing majority.
        refused(
            apply(
                d,
                version(d, &change, &decision, &charter, &[h(0)], &new).await,
            )
            .await,
            "accord_roster_change_short",
            "I450e: one of three",
        );
        // The added holder did not sign the record.
        let mut unconsented = version(d, &change, &decision, &charter, &[h(0), h(1)], h(0)).await;
        unconsented
            .cosignatures
            .retain(|c| c.authority_key_id != new);
        refused(
            apply(d, unconsented).await,
            "accord_roster_change_unconsented",
            "I450e: unconsented",
        );
        // The charter it names does not commit the new holder.
        refused(
            apply(
                d,
                version(d, &change, &decision, &old_charter, &[h(0), h(1)], &new).await,
            )
            .await,
            "accord_recovery_commitment_missing",
            "I450e: the charter misses the added holder",
        );
        assert_eq!(held(d).await, before, "I450e: nothing written");
        assert!(
            roster_lag(d, accord_family_key_id(), chrono::Utc::now())
                .await
                .unwrap()
                .is_some_and(|l| l.uncovered_decisions.contains(&decision)),
            "I450e: the authorized decision lags the head"
        );
        apply(
            d,
            version(d, &change, &decision, &charter, &[h(0), h(1)], &new).await,
        )
        .await
        .unwrap_or_else(|e| panic!("I450e: the covering roster change: {e}"));
        let after = held(d).await;
        assert!(ids(&after).contains(&new), "I450e: seated");
        assert_eq!(
            after.prev_head_digest, before.persist_row_hash,
            "I450e: chained"
        );
        assert_eq!(
            after.charter_digest, charter,
            "I450e: the re-scrub is in force"
        );
        assert!(
            roster_lag(d, accord_family_key_id(), chrono::Utc::now())
                .await
                .unwrap()
                .is_none(),
            "I450e: the head moved: no decision lags"
        );
        assert!(
            fold_disagreement(d, LineageRecord::Family(&after), None, chrono::Utc::now())
                .await
                .unwrap()
                .is_empty(),
            "I450e: the roster is the fold's"
        );
    }

    /// **I450f** — a peer judges the same predicate.
    pub async fn i450f_a_peer_judges_the_same(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let mut v = None;
        let mut decision_rows = None;
        for d in [a, b] {
            stand_up(d).await;
        }
        let before = held(a).await;
        let holders = ids(&before);
        let new = newcomer(a, tag).await;
        newcomer(b, tag).await;
        let mut grown = holders.clone();
        grown.push(new.clone());
        let change = adding(&new, before.members[0].role.clone());
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        for (i, d) in [a, b].into_iter().enumerate() {
            if i == 1 {
                // The charter row reaches b as any attestation does.
                let named = held_charter(a).await;
                let row = a
                    .list_attestations_for(accord_family_key_id())
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|r| r.persist_row_hash == named)
                    .expect("a holds the charter it named");
                d.put_attestation(crate::federation::SignedAttestation { attestation: row })
                    .await
                    .expect("I450f: the charter replicates");
                continue;
            }
            let charter = rescrub(d, &grown, "f").await;
            if i == 0 {
                let decision = decide(d, &change, past, true, &format!("ar-f-{tag}")).await;
                let signed = version(
                    d,
                    &change,
                    &decision,
                    &charter,
                    &[holders[0].as_str(), holders[1].as_str()],
                    &new,
                )
                .await;
                apply(d, signed.clone()).await.expect("I450f: a admits");
                v = Some(signed);
                decision_rows = Some(decision);
            }
        }
        let v = v.unwrap();
        // b holds no decision yet: refused by name (retryable).
        let e = b
            .put_family(v.clone())
            .await
            .expect_err("I450f: no decision on b");
        assert!(
            matches!(&e, Error::CharterInvalid { detail } if detail.contains("accord_roster_change_uncovered")),
            "I450f: {e:?}"
        );
        // The decision reaches b (the accord evidence carriage); b admits.
        let decided = decide(b, &change, past, true, &format!("ar-f-{tag}")).await;
        assert_eq!(Some(decided), decision_rows, "I450f: the same decision");
        b.put_family(v)
            .await
            .expect("I450f: b admits the replicated version");
        assert_eq!(
            held(a).await.persist_row_hash,
            held(b).await.persist_row_hash,
            "I450f: both hold the same head"
        );
    }

    /// **I450g** — a removal re-scrubs the charter without the removed holder.
    pub async fn i450g_a_removal_drops_the_commitment(d: &dyn FederationDirectory, tag: &str) {
        stand_up(d).await;
        let before = held(d).await;
        let holders = ids(&before);
        let gone = holders[2].clone();
        let change = SeatChange {
            remove: vec![gone.clone()],
            add: vec![],
        };
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let decision = decide(d, &change, past, true, &format!("ar-g-{tag}")).await;
        let stale = rescrub(d, &holders, tag).await;
        refused(
            apply(
                d,
                version(
                    d,
                    &change,
                    &decision,
                    &stale,
                    &[&holders[0], &holders[1]],
                    &holders[0],
                )
                .await,
            )
            .await,
            "accord_recovery_commitment_stray",
            "I450g: a charter still committing the removed holder",
        );
        let kept = rescrub(d, &holders[..2], tag).await;
        apply(
            d,
            version(
                d,
                &change,
                &decision,
                &kept,
                &[&holders[0], &holders[1]],
                &holders[0],
            )
            .await,
        )
        .await
        .unwrap_or_else(|e| panic!("I450g: the removal: {e}"));
        assert!(!ids(&held(d).await).contains(&gone), "I450g: removed");
    }

    /// **I450h** — the majority is of the HELD head's roster: the added
    /// holder's own cosign does not count toward it.
    pub async fn i450h_the_standing_roster_is_the_held_heads(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        stand_up(d).await;
        let before = held(d).await;
        let holders = ids(&before);
        let role = before.members[0].role.clone();
        let n1 = newcomer(d, &format!("{tag}1")).await;
        let n2 = newcomer(d, &format!("{tag}2")).await;
        let change = SeatChange {
            remove: vec![],
            add: vec![
                SeatAdd {
                    key_id: n1.clone(),
                    role: role.clone(),
                },
                SeatAdd {
                    key_id: n2.clone(),
                    role,
                },
            ],
        };
        let mut grown = holders.clone();
        grown.extend([n1.clone(), n2.clone()]);
        let charter = rescrub(d, &grown, tag).await;
        let decision = decide(
            d,
            &change,
            chrono::Utc::now() - chrono::Duration::hours(1),
            true,
            &format!("ar-h-{tag}"),
        )
        .await;
        // One standing yes and both newcomers' are 3 of the OFFERED 5 but 1 of
        // the standing 3.
        refused(
            apply(
                d,
                version(
                    d,
                    &change,
                    &decision,
                    &charter,
                    &[&holders[0], &n1, &n2],
                    &n1,
                )
                .await,
            )
            .await,
            "accord_roster_change_short",
            "I450h: the newcomers' yes counts for nothing",
        );
        apply(
            d,
            version(
                d,
                &change,
                &decision,
                &charter,
                &[&holders[0], &holders[1]],
                &n1,
            )
            .await,
        )
        .await
        .unwrap_or_else(|e| panic!("I450h: two of the standing three: {e}"));
    }
}

#[cfg(test)]
mod pure {
    /// **I450i** — from disk, comments stripped: the genesis bundle check runs
    /// the same coverage rule as the version door and PROPAGATES its refusal.
    /// A bundle whose charter misses a holder cannot be built here without also
    /// breaking the record-equality leg that runs first, so the leg is pinned by
    /// its code; `charter_commitments_cover` itself is witnessed by I432, I433,
    /// I450e and I450g through the door.
    #[test]
    fn i450i_genesis_runs_the_coverage_rule() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/federation/genesis/ceremony_verify.rs");
        let code: String = std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        let start = code
            .find("fn check_family_record(")
            .expect("check_family_record");
        let body = &code[start..];
        let body = &body[..body.find("\n}\n").unwrap_or(body.len())];
        let flat: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flat.contains("accord_roster::charter_commitments_cover(")
                && flat.contains(".map_err(|(token, detail)| format!(\"{token}: {detail}\"))?;"),
            "I450i: the genesis check propagates the coverage refusal"
        );
    }
}

#[cfg(test)]
mod run {
    use super::bodies;

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..10].to_owned()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::{bodies, suffix};
                #[tokio::test]
                async fn i450e() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i450e_a_roster_change_is_admitted_whole(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i450f() {
                    let Some(a) = $fresh.await else { return };
                    let Some(b) = $fresh.await else { return };
                    bodies::i450f_a_peer_judges_the_same(&a, &b, &suffix()).await
                }
                #[tokio::test]
                async fn i450g() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i450g_a_removal_drops_the_commitment(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i450j() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i450j_a_seat_needs_an_accord_holder_key(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i450h() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i450h_the_standing_roster_is_the_held_heads(&b, &suffix()).await
                }
            }
        };
    }
    runners!(memory, async { Some(crate::store::MemoryBackend::new()) });
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
}
