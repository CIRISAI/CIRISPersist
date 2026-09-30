//! v52.0.0 (CIRISPersist#672) — **a re-offer of a held record settles before
//! verification, and nothing else does.** Witnesses for
//! [`replication_policy::settle_if_held`](super::replication_policy::settle_if_held).
//!
//! - **I230** (memory, sqlite, postgres) — every seeded kind (Key,
//!   Attestation, Revocation, LocationProof, Family, Community), re-offered as
//!   the bytes this node serves, answers "already held" through its door and
//!   counts on `already_held_count`.
//! - **I231** — a differing body under a held id is not settled (the door
//!   refuses it on its merits), and a held-but-purged row whose index entry
//!   survives is not settled (it is admitted again).
//! - **I233** — a three-node cycle A→B→C→A carried through the doors: the row
//!   returns to its origin as "already held"; every hop serves the same hash.
//! - **I234** — 1 000 re-offers of a held attestation from one peer all
//!   settle; none spends the per-peer quota (600 per window), so none is
//!   rate-limited.
//! - **I235** (from disk, comments stripped) — every replicated kind's door in
//!   every backend runs the settle as its first statement (the attestation
//!   door: before the per-peer quota), naming its own kind, or the kind is on
//!   [`SETTLE_EXEMPT`](super::replication_policy::SETTLE_EXEMPT).

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::replication_policy::{already_held_count, EnvelopeKind};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::{AttestationOutcome, FederationDirectory, SignedAttestation};

    pub(crate) fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..10].to_owned()
    }

    fn now_micros() -> chrono::DateTime<chrono::Utc> {
        use chrono::Timelike as _;
        let t = chrono::Utc::now();
        t.with_nanosecond(t.nanosecond() / 1_000 * 1_000).unwrap()
    }

    /// A sealed, federation-tier `scores` attestation by `author`.
    pub(crate) fn sealed_attestation(
        author: &str,
        dimension: &str,
    ) -> crate::federation::Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_micros();
        let mut row = crate::federation::Attestation {
            attestation_id: id.clone(),
            attesting_key_id: author.to_owned(),
            attested_key_id: author.to_owned(),
            attestation_type: crate::federation::types::attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "id": id, "dimension": dimension, "score": 1.0, "confidence": 0.9,
            }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: author.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        ts::seal_row_in_place(author, &mut row);
        row
    }

    /// The bytes this node SERVES for the attestation `id` (what a peer
    /// fetches), and their wire hash.
    pub(crate) async fn served_attestation(
        dir: &dyn FederationDirectory,
        id: &str,
    ) -> (String, crate::federation::Attestation) {
        let (_, hash, _) = crate::federation::wire_index::all_kind_hash_keys(dir)
            .await
            .unwrap()
            .into_iter()
            .find(|(k, _, rk)| *k == "Attestation" && rk.contains(id))
            .expect("the attestation is indexed");
        let bytes = dir
            .lookup_signed_record_by_content_hash("Attestation", &hash)
            .await
            .unwrap()
            .expect("the served ref resolves");
        (hash, serde_json::from_slice(&bytes).unwrap())
    }

    // ── I230 ────────────────────────────────────────────────────────────
    pub(crate) async fn i230_every_seeded_kind_settles(dir: &dyn FederationDirectory, tag: &str) {
        let author = format!("i230-author-{tag}");
        let member = format!("i230-member-{tag}");
        let fam = format!("i230-fam-{tag}");
        let comm = format!("i230-comm-{tag}");
        let victim = format!("i230-victim-{tag}");
        ts::register_hybrid_key(dir, &author).await;
        ts::register_identity_key(dir, &member, crate::federation::types::identity_type::USER)
            .await;
        ts::register_hybrid_key(dir, &fam).await;
        ts::register_hybrid_key(dir, &comm).await;
        ts::register_hybrid_key(dir, &victim).await;
        let now = now_micros();

        let att = sealed_attestation(&author, "trust:i230:v1");
        let att_id = att.attestation_id.clone();
        dir.put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap_or_else(|e| panic!("[{tag}] I230 seed attestation: {e}"));
        let cell = h3o::LatLng::new(37.0, -122.0)
            .unwrap()
            .to_cell(h3o::Resolution::Seven)
            .to_string();
        dir.put_location_proof(ts::sign_location_proof(
            &author,
            crate::federation::types::LocationProof {
                subject_key_id: author.clone(),
                cell_id: cell,
                cell_resolution: 7,
                asserted_at: now,
                valid_until: None,
                attestation_evidence: None,
                withdrawn_at: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I230 seed location proof: {e}"));
        dir.put_family(ts::sign_family(
            &author,
            crate::federation::types::Family {
                family_key_id: fam.clone(),
                family_name: format!("i230-family-{tag}"),
                members: vec![crate::federation::types::FamilyMember {
                    key_id: member.clone(),
                    joined_at: now,
                    role: Some("founder".to_owned()),
                }],
                founded_at: now,
                consensus_protocol: "founder_only".to_owned(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I230 seed family: {e}"));
        dir.put_community(ts::sign_community(
            &author,
            crate::federation::types::Community {
                community_key_id: comm.clone(),
                community_name: format!("i230-community-{tag}"),
                members: vec![crate::federation::types::CommunityMember {
                    key_id: member.clone(),
                    joined_at: now,
                    role: Some("founder".to_owned()),
                }],
                founded_at: now,
                consensus_protocol: "founder_only".to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I230 seed community: {e}"));
        let rev_id = uuid::Uuid::new_v4().to_string();
        let revocation = ts::seal_revocation(crate::federation::Revocation {
            revocation_id: rev_id.clone(),
            revoked_key_id: Some(victim.clone()),
            revoked_key_sha256_ed25519_raw: ts::subject_digest_of(&victim),
            revoking_key_id: victim.clone(),
            reason: Some("i230 self-revocation".to_owned()),
            revoked_at: now,
            effective_at: now,
            revocation_envelope: serde_json::json!({ "revokes": victim }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: victim.clone(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            observed_region: crate::federation::verify_coord::region::US.to_owned(),
            revoked_after: None,
            persist_row_hash: String::new(),
        });
        dir.put_revocation(crate::federation::SignedRevocation { revocation })
            .await
            .unwrap_or_else(|e| panic!("[{tag}] I230 seed revocation: {e}"));

        let mine: Vec<(String, String)> = crate::federation::wire_index::all_kind_hash_keys(dir)
            .await
            .unwrap()
            .into_iter()
            .filter(|(_, _, rk)| {
                [&author, &member, &fam, &comm, &victim, &att_id, &rev_id]
                    .iter()
                    .any(|id| rk.contains(id.as_str()))
            })
            .map(|(k, h, _)| (k.to_owned(), h))
            .collect();
        for kind in [
            "Key",
            "Attestation",
            "Revocation",
            "LocationProof",
            "Family",
            "Community",
        ] {
            assert!(
                mine.iter().any(|(k, _)| k == kind),
                "[{tag}] I230: no {kind} ref seeded; got {mine:?}"
            );
        }

        for (kind, hash) in &mine {
            let bytes = dir
                .lookup_signed_record_by_content_hash(kind, hash)
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("[{tag}] I230: {kind}/{hash} does not resolve"));
            let ek = EnvelopeKind::ALL
                .into_iter()
                .find(|k| k.as_str() == kind)
                .expect("an indexed kind is an EnvelopeKind");
            let before = already_held_count(ek);
            match kind.as_str() {
                "Key" => assert_eq!(
                    dir.apply_replicated_key_record(serde_json::from_slice(&bytes).unwrap())
                        .await
                        .unwrap(),
                    crate::federation::register::ReplicatedKeyOutcome::Unchanged,
                    "[{tag}] I230 Key"
                ),
                "Attestation" => assert_eq!(
                    dir.put_attestation(SignedAttestation {
                        attestation: serde_json::from_slice(&bytes).unwrap(),
                    })
                    .await
                    .unwrap(),
                    AttestationOutcome::AlreadyHeld,
                    "[{tag}] I230 Attestation"
                ),
                "Revocation" => dir
                    .put_revocation(serde_json::from_slice(&bytes).unwrap())
                    .await
                    .unwrap_or_else(|e| panic!("[{tag}] I230 Revocation re-offer: {e}")),
                "LocationProof" => dir
                    .put_location_proof(serde_json::from_slice(&bytes).unwrap())
                    .await
                    .unwrap_or_else(|e| panic!("[{tag}] I230 LocationProof re-offer: {e}")),
                "Family" => dir
                    .put_family(serde_json::from_slice(&bytes).unwrap())
                    .await
                    .unwrap_or_else(|e| panic!("[{tag}] I230 Family re-offer: {e}")),
                "Community" => assert_eq!(
                    dir.apply_replicated_community(serde_json::from_slice(&bytes).unwrap())
                        .await
                        .unwrap(),
                    crate::federation::ReplicatedCommunityOutcome::Unchanged,
                    "[{tag}] I230 Community"
                ),
                other => panic!("[{tag}] I230: unexpected kind {other}"),
            }
            assert!(
                already_held_count(ek) > before,
                "[{tag}] I230: the {kind} re-offer answered held but did not SETTLE — it went \
                 through the full apply (#672)"
            );
        }
    }

    // ── I231 ────────────────────────────────────────────────────────────
    pub(crate) async fn i231_only_a_resolved_identical_row_settles(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        let author = format!("i231-author-{tag}");
        ts::register_hybrid_key(dir, &author).await;

        // (a) A differing body under a held id: refused on its merits.
        let att = sealed_attestation(&author, "trust:i231:v1");
        let id = att.attestation_id.clone();
        dir.put_attestation(SignedAttestation {
            attestation: att.clone(),
        })
        .await
        .unwrap();
        let mut impostor = att.clone();
        impostor.attestation_envelope["dimension"] = serde_json::json!("trust:i231-other:v1");
        ts::seal_row_in_place(&author, &mut impostor);
        let r = dir
            .put_attestation(SignedAttestation {
                attestation: impostor,
            })
            .await;
        assert!(
            r.is_err(),
            "[{tag}] I231(a): a different body under a held id must be refused on its merits, \
             never settled as held: {r:?}"
        );

        // (b) Held, then purged: the index entry survives the purge (the
        // rebuild is the repair), the row does not. Not settled — admitted.
        let (hash, served) = served_attestation(dir, &id).await;
        assert!(
            dir.purge_attestation_v31(&id).await.unwrap(),
            "[{tag}] I231(b): the purge removed the row"
        );
        assert!(
            dir.lookup_signed_record_by_content_hash("Attestation", &hash)
                .await
                .unwrap()
                .is_none(),
            "[{tag}] I231(b): the stale entry resolves to nothing"
        );
        assert_eq!(
            dir.put_attestation(SignedAttestation {
                attestation: served
            })
            .await
            .unwrap(),
            AttestationOutcome::Inserted,
            "[{tag}] I231(b): a purged row re-offered is admitted again, never settled as held"
        );
    }

    // ── I233 ────────────────────────────────────────────────────────────
    pub(crate) async fn i233_a_cycle_returns_held(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        c: &dyn FederationDirectory,
        tag: &str,
    ) {
        let author = format!("i233-author-{tag}");
        for n in [a, b, c] {
            ts::register_hybrid_key(n, &author).await;
        }
        let att = sealed_attestation(&author, "trust:i233:v1");
        let id = att.attestation_id.clone();
        assert_eq!(
            a.put_attestation(SignedAttestation { attestation: att })
                .await
                .unwrap(),
            AttestationOutcome::Inserted
        );
        let (h_a, from_a) = served_attestation(a, &id).await;
        assert_eq!(
            b.put_attestation(SignedAttestation {
                attestation: from_a
            })
            .await
            .unwrap(),
            AttestationOutcome::Inserted,
            "[{tag}] I233: A→B admits"
        );
        let (h_b, from_b) = served_attestation(b, &id).await;
        assert_eq!(
            c.put_attestation(SignedAttestation {
                attestation: from_b
            })
            .await
            .unwrap(),
            AttestationOutcome::Inserted,
            "[{tag}] I233: B→C admits"
        );
        let (h_c, from_c) = served_attestation(c, &id).await;
        assert_eq!(
            (&h_a, &h_b),
            (&h_c, &h_c),
            "[{tag}] I233: one hash on every hop"
        );
        let before = already_held_count(EnvelopeKind::Attestation);
        assert_eq!(
            a.put_attestation(SignedAttestation {
                attestation: from_c.clone(),
            })
            .await
            .unwrap(),
            AttestationOutcome::AlreadyHeld,
            "[{tag}] I233: C→A closes the cycle as held"
        );
        assert_eq!(
            b.put_attestation(SignedAttestation {
                attestation: from_c
            })
            .await
            .unwrap(),
            AttestationOutcome::AlreadyHeld,
            "[{tag}] I233: and so does the next lap"
        );
        assert!(already_held_count(EnvelopeKind::Attestation) >= before + 2);
    }

    // ── I234 ────────────────────────────────────────────────────────────
    pub(crate) async fn i234_held_reoffers_spend_no_quota(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        let author = format!("i234-author-{tag}");
        ts::register_hybrid_key(dir, &author).await;
        let att = sealed_attestation(&author, "trust:i234:v1");
        let id = att.attestation_id.clone();
        dir.put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap();
        let (_, served) = served_attestation(dir, &id).await;
        let n = 1_000u32;
        assert!(
            n > crate::federation::replication::admission::PER_PEER_ATTESTATION_WRITES_PER_WINDOW,
            "the flood must exceed the window's quota or this cannot fail"
        );
        let before = already_held_count(EnvelopeKind::Attestation);
        for i in 0..n {
            let r = dir
                .put_attestation(SignedAttestation {
                    attestation: served.clone(),
                })
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "[{tag}] I234: held re-offer {i} was charged against the sender's \
                         quota (or verified) instead of settling: {e}"
                    )
                });
            assert_eq!(r, AttestationOutcome::AlreadyHeld);
        }
        assert!(already_held_count(EnvelopeKind::Attestation) >= before + u64::from(n));
    }
}

#[cfg(test)]
mod from_disk {
    use crate::federation::replication_policy::{EnvelopeKind, SETTLE_EXEMPT};

    /// Each replicated kind → the door every backend implements for it.
    const DOORS: &[(EnvelopeKind, &str)] = &[
        (EnvelopeKind::Key, "apply_replicated_key_record"),
        (EnvelopeKind::Attestation, "put_attestation_with_origin"),
        (EnvelopeKind::Revocation, "put_revocation"),
        (EnvelopeKind::IdentityOccurrence, "put_identity_occurrence"),
        (EnvelopeKind::Family, "put_family"),
        (EnvelopeKind::Community, "put_community_at_door"),
        (
            EnvelopeKind::IdentityOccurrenceRevocation,
            "put_identity_occurrence_revocation",
        ),
        (
            EnvelopeKind::FamilyMembershipRevocation,
            "put_family_membership_revocation",
        ),
        (
            EnvelopeKind::CommunityMembershipRevocation,
            "put_community_membership_revocation",
        ),
        (EnvelopeKind::LocationProof, "put_location_proof"),
        (EnvelopeKind::Organization, "put_organization"),
        (EnvelopeKind::OrgMembership, "put_org_membership"),
        (EnvelopeKind::PartnerRecord, "put_partner_record"),
        (
            EnvelopeKind::TransportDestination,
            "put_signed_transport_destination",
        ),
        (
            EnvelopeKind::CommunityMembershipWidening,
            "put_community_membership_widening",
        ),
        (
            EnvelopeKind::FamilyMembershipWidening,
            "put_family_membership_widening",
        ),
        (
            EnvelopeKind::CommunityMembershipListing,
            "put_community_membership_listing",
        ),
    ];

    /// The body of `async fn NAME(` in `src`, comments and blank lines
    /// stripped, one statement-ish line per entry.
    fn body_lines(src: &str, name: &str) -> Vec<String> {
        let sig = format!("async fn {name}(");
        let starts: Vec<usize> = src
            .lines()
            .enumerate()
            .filter(|(_, l)| {
                let t = l.trim_start();
                (t.starts_with("async fn ") || t.starts_with("pub(crate) async fn "))
                    && t.contains(&sig)
                    && l.starts_with("    ")
                    && !l.starts_with("     ")
            })
            .map(|(i, _)| i)
            .collect();
        assert_eq!(starts.len(), 1, "exactly one `{name}` impl per backend");
        let lines: Vec<&str> = src.lines().collect();
        let mut i = starts[0];
        while !lines[i].trim_end().ends_with('{') {
            i += 1;
        }
        let mut out = Vec::new();
        for l in &lines[i + 1..] {
            if *l == "    }" {
                break;
            }
            let code = match l.find("//") {
                Some(c) => &l[..c],
                None => l,
            };
            let t = code.trim();
            if !t.is_empty() {
                out.push(t.to_owned());
            }
        }
        out
    }

    // ── I235 ────────────────────────────────────────────────────────────
    #[test]
    fn i235_every_replicated_door_settles_first() {
        for k in EnvelopeKind::ALL {
            let doors = DOORS.iter().filter(|(d, _)| *d == k).count();
            let exempt = SETTLE_EXEMPT.iter().filter(|(e, _)| *e == k).count();
            assert_eq!(
                doors + exempt,
                1,
                "I235: {k:?} must have exactly one settling door or one written exemption"
            );
        }
        for (_, reason) in SETTLE_EXEMPT {
            assert!(reason.len() > 40, "I235: an exemption carries its reason");
        }
        let root = env!("CARGO_MANIFEST_DIR");
        for backend in ["memory", "sqlite", "postgres"] {
            let src = std::fs::read_to_string(format!("{root}/src/store/{backend}.rs")).unwrap();
            for (kind, door) in DOORS {
                let body = body_lines(&src, door);
                let settle = format!(
                    "crate::federation::replication_policy::EnvelopeKind::{}",
                    kind.as_str()
                );
                let joined = body.join(" ");
                let at = joined
                    .find("replication_policy::settle_if_held(")
                    .unwrap_or_else(|| panic!("I235: {backend}::{door} never settles"));
                let stmt = &joined[at..joined[at..].find('}').map_or(joined.len(), |e| at + e)];
                assert!(
                    stmt.contains(&settle),
                    "I235: {backend}::{door} settles under the wrong kind: {stmt}"
                );
                if *kind == EnvelopeKind::Attestation {
                    let quota = joined
                        .find("peer_write_quota")
                        .unwrap_or_else(|| panic!("I235: {backend}::{door} has no quota"));
                    assert!(
                        at < quota,
                        "I235: {backend}::{door} settles AFTER the per-peer quota"
                    );
                } else {
                    assert!(
                        body[0].starts_with(
                            "if crate::federation::replication_policy::settle_if_held("
                        ),
                        "I235: {backend}::{door}'s first statement must be the settle, got `{}`",
                        body[0]
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod run {
    use super::bodies;

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::bodies;
                #[tokio::test]
                async fn i230() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i230_every_seeded_kind_settles(&b, &bodies::suffix()).await
                }
                #[tokio::test]
                async fn i231() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i231_only_a_resolved_identical_row_settles(&b, &bodies::suffix()).await
                }
                #[tokio::test]
                async fn i233() {
                    let (Some(a), Some(b), Some(c)) = ($fresh.await, $fresh.await, $fresh.await)
                    else {
                        return;
                    };
                    bodies::i233_a_cycle_returns_held(&a, &b, &c, &bodies::suffix()).await
                }
                #[tokio::test]
                async fn i234() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i234_held_reoffers_spend_no_quota(&b, &bodies::suffix()).await
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
}
