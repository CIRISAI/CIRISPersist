//! v60.0.0 (CIRISPersist#1036 items 1-5, #1049, #1062; CC 2.4.1.1,
//! 2.4.1.2.1, 3.2, 3.3.9 at rc9) — **an organisation is an affiliation.**
//!
//! The three operational planes (`organization`, `org_membership`,
//! `partner_record`) retired onto the rows every community already uses, and
//! a licence under an affiliation became the affiliation's act. Every
//! witness here runs on sqlite and postgres (S5 retires the memory backend).
//!
//! - **I1210** — the licence payload's pure gate: the `partner_record` field
//!   set parses, its four set-semantics arrays are sorted AND unique (a
//!   repeat is `federation_set_semantics_unsorted`, which v59 let through),
//!   and its envelope carries no payment-processor identifier.
//! - **I1211** — the payload's `revision` anti-rollback, judged against the
//!   AUTHORITY's own held licences only: a lower revision is
//!   `federation_partner_record_rollback`, an equal one admits, and a
//!   stranger's testimony neither counts nor is counted.
//! - **I1212** — the ±5 min skew bound, ported: a licence dated past it is
//!   refused at the attestation door.
//! - **I1213** — the three retired wire kinds are refused
//!   `federation_envelope_kind_retired` and their tables are gone (V205).
//! - **I1214** — item 1: under a quorum protocol a licence is a COSIGNED row;
//!   one member's signature is testimony, a stranger's cosignature counts for
//!   nothing.
//! - **I1215** — item 1: the `license` chain roots at an edge the quorum
//!   cosigned and that names the affiliation; a lone member's appointment
//!   resolves to nothing (`authority_acts_by_quorum`); onward hops need
//!   `sub_delegation`; a root edge is retracted only by a cosigned
//!   `withdraws` (rule 0), and its retraction stops future issuance without
//!   reclassifying a licence already issued (item 2).
//! - **I1216** — item 3: a licence has no public default; the charter's
//!   `licence_audiences` is the authority's declared choice per class.
//! - **I1217** — item 3: a re-emission to named readers carries the same
//!   licence at the same scope, naming its readers.
//! - **I1218** — item 5: a subject's `withdraws` against `licensure:*` /
//!   `revocation:*` is refused; the contest path is
//!   `reconsideration:{grounds}`, filed by the licensee, ruled by the
//!   authority's set.
//! - **I1219** — #1062: an owner-binding that names an affiliation is
//!   cosigned under its protocol; `affiliation_of_binding` reads it.
//! - **I1220** — #1049: a consent row's `grant` chain is judged at its signed
//!   instant, with W in front.
//! - **I1221** — #1049: a `key_grant` row's sealer chain likewise (sqlite /
//!   postgres nodes; see `grant_scope_invariants::key_grant_arms`).
//! - **I1222** (pure) — the JCS order of a set is UTF-16, not byte order.

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub mod bodies {
    use crate::federation::admission::{
        licence_audience_reason as aud, owner_binding_affiliation_reason as obr,
        LicensureChainBreak, DELEGATION_SCOPE_LICENSE, LICENCE_AUDIENCE_REFUSED,
        LICENCE_RE_EMITS_MEMBER, OWNER_BINDING_AFFILIATION_REFUSED,
    };
    use crate::federation::licensure::{status_set_for, LicensureStatus};
    use crate::federation::licensure_chain_invariants::bodies::{
        base, edge, keys, licence, must_put, must_refuse_as, officer, put,
    };
    use crate::federation::room_roster_authority_invariants::bodies::make_group;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, consensus_protocol, identity_type, ScrubSig};
    use crate::federation::{Attestation, Error, FederationDirectory};
    use chrono::{Duration, Utc};
    use std::collections::BTreeSet;

    /// The `partner_record` field set as a licence payload.
    pub(crate) fn payload(
        license_id: &str,
        license_type: &str,
        revision: u64,
        caps: &[&str],
    ) -> serde_json::Value {
        serde_json::json!({
            "license_id": license_id,
            "license_type": license_type,
            "capabilities_granted": caps,
            "capabilities_denied": [],
            "max_autonomy_tier": "A2",
            "requires_supervisor": false,
            "geographic_restrictions": ["CA", "US"],
            "allowed_identity_templates": [],
            "deployment_limit": 10,
            "offline_grace_hours": 24,
            "revision": revision,
            "issued_at": "2026-10-01T00:00:00.000Z",
            "expires_at": "2027-10-01T00:00:00.000Z",
        })
    }

    /// The class the test affiliations declare public.
    pub(crate) const PUBLIC_CLASS: &str = "professional_full";

    /// `row` carrying a licence payload of [`PUBLIC_CLASS`] (its own id as
    /// the `license_id`), so an affiliation that declares the class public
    /// admits it at `federation`.
    pub(crate) fn classed(row: Attestation) -> Attestation {
        let id = row.attestation_id.clone();
        with(row, "partner_record", payload(&id, PUBLIC_CLASS, 1, &[]))
    }

    /// `row` with `member` set to `value`, re-sealed by its emitter.
    pub(crate) fn with(
        mut row: Attestation,
        member: &str,
        value: serde_json::Value,
    ) -> Attestation {
        row.attestation_envelope[member] = value;
        ts::reseal(&mut row);
        row
    }

    /// `row` placed at `scope` naming `subjects`, re-sealed.
    pub(crate) fn placed(mut row: Attestation, scope: &str, subjects: &[&str]) -> Attestation {
        row.cohort_scope = scope.to_owned();
        row.subject_key_ids = subjects.iter().map(|s| (*s).to_owned()).collect();
        ts::reseal(&mut row);
        row
    }

    /// `row` cosigned by each of `cosigners` over its (final) envelope bytes:
    /// the `additional_scrubs[]` carrier (CC 2.4 cosigned rows).
    pub(crate) fn cosigned(mut row: Attestation, cosigners: &[&str]) -> Attestation {
        for c in cosigners {
            let (_, classical, pqc) = ts::sign_envelope(c, &row.attestation_envelope);
            row.additional_scrubs.push(ScrubSig {
                scrub_key_id: (*c).to_owned(),
                scrub_signature_classical: classical,
                scrub_signature_pqc: pqc,
                cosigned_at: None,
            });
        }
        row.persist_row_hash = String::new();
        row
    }

    fn kind_of(r: Result<Attestation, Error>, what: &str) -> String {
        match r {
            Ok(a) => panic!("{what}: must be refused, admitted {}", a.attestation_id),
            Err(e) => e.kind().to_owned(),
        }
    }

    async fn not_stored(d: &dyn FederationDirectory, row: &Attestation, what: &str) {
        assert!(
            d.get_attestation(&row.attestation_id)
                .await
                .expect("read")
                .is_none(),
            "{what}: a refused row is not stored"
        );
    }

    /// An affiliation (`cohort_scope: affiliations`) under `protocol`, with
    /// `config` as its charter (`affiliation_config`).
    pub(crate) async fn affiliation(
        d: &dyn FederationDirectory,
        tag: &str,
        protocol: &str,
        names: &[&str],
        founders: usize,
        config: Option<serde_json::Value>,
    ) -> (String, Vec<String>) {
        let mut blob = serde_json::json!({ "cohort_scope": "affiliations" });
        // Unless the witness supplies its own charter, it declares
        // [`PUBLIC_CLASS`] public (item 3: no default, so it must say so).
        blob["affiliation_config"] = config.unwrap_or_else(
            || serde_json::json!({ "licence_audiences": { PUBLIC_CLASS: "federation" } }),
        );
        make_group(d, tag, protocol, names, founders, Some(blob), None).await
    }

    /// **I1210** — the payload's pure gate.
    pub async fn i1210_licence_payload_pure_gate(d: &dyn FederationDirectory, tag: &str) {
        let (board, holder) = keys(d, tag).await;
        let at = base() - Duration::minutes(5);
        let lic = |p: serde_json::Value| {
            with(
                licence(&board, &holder, &board, "issued", None, at),
                "partner_record",
                p,
            )
        };
        // Control: a well-formed payload admits and reads back typed.
        let ok = must_put(
            d,
            &lic(payload(
                "lic-1",
                "professional_full",
                1,
                &["a.read", "b.write"],
            )),
            &format!("[{tag}] I1210 control"),
        )
        .await;
        let typed = crate::federation::operational::partner_record_of(&ok)
            .expect("parses")
            .expect("carries the payload");
        assert_eq!(
            typed.revision, 1,
            "[{tag}] I1210: the typed payload reads back"
        );
        // A repeat in a set: refused. Kills: the non-decreasing check (v59).
        let dup = lic(payload(
            "lic-2",
            "professional_full",
            1,
            &["a.read", "a.read"],
        ));
        assert_eq!(
            kind_of(put(d, &dup).await, "I1210 repeat"),
            "federation_set_semantics_unsorted",
            "[{tag}] I1210: a repeated set member"
        );
        not_stored(d, &dup, "I1210 repeat").await;
        // Out of order: refused. Kills: dropping the order arm.
        let unsorted = lic(payload(
            "lic-3",
            "professional_full",
            1,
            &["b.write", "a.read"],
        ));
        assert_eq!(
            kind_of(put(d, &unsorted).await, "I1210 unsorted"),
            "federation_set_semantics_unsorted",
            "[{tag}] I1210: an unsorted set"
        );
        // Every set is checked, not only capabilities_granted.
        let mut geo = payload("lic-4", "professional_full", 1, &[]);
        geo["geographic_restrictions"] = serde_json::json!(["US", "CA"]);
        assert_eq!(
            kind_of(put(d, &lic(geo)).await, "I1210 geo"),
            "federation_set_semantics_unsorted",
            "[{tag}] I1210: geographic_restrictions is a set"
        );
        // A processor id anywhere in the envelope: refused.
        let stripe = with(
            lic(payload("lic-5", "professional_full", 1, &[])),
            "billing_note",
            serde_json::json!("cus_9ab12"),
        );
        assert_eq!(
            kind_of(put(d, &stripe).await, "I1210 stripe"),
            "federation_payment_processor_identifier",
            "[{tag}] I1210: a payment-processor identifier"
        );
        // A payload that is not the field set: malformed.
        let malformed = lic(serde_json::json!({ "license_id": "lic-6" }));
        let e = put(d, &malformed).await.expect_err("I1210 malformed");
        assert!(
            matches!(&e, Error::MalformedRow { reason, .. } if *reason == "envelope_member_invalid"),
            "[{tag}] I1210: a payload missing its fields is malformed: {e:?}"
        );
        // Without the payload a licence is untouched by this gate, even with
        // a processor-shaped string (the scan is the payload's port).
        must_put(
            d,
            &with(
                licence(&board, &holder, &board, "probation", None, at),
                "note",
                serde_json::json!("in_review"),
            ),
            &format!("[{tag}] I1210: a licence without the payload is not scanned"),
        )
        .await;
    }

    /// **I1211** — the `revision` anti-rollback.
    pub async fn i1211_revision_never_goes_backwards(d: &dyn FederationDirectory, tag: &str) {
        let (board, holder) = keys(d, tag).await;
        let stranger = format!("{tag}-stranger");
        crate::federation::admission::steward_liveness_test_support::register(
            d,
            &stranger,
            &[identity_type::USER],
        )
        .await;
        let now = base();
        let lic = |by: &str, rev: u64, status: &str, mins: i64| {
            with(
                licence(
                    by,
                    &holder,
                    &board,
                    status,
                    None,
                    now - Duration::minutes(mins),
                ),
                "partner_record",
                payload("lic-r", "professional_full", rev, &[]),
            )
        };
        must_put(d, &lic(&board, 2, "issued", 30), "I1211 revision 2").await;
        // Lower: refused. Kills: dropping the comparison.
        let back = lic(&board, 1, "issued", 20);
        let e = put(d, &back).await.expect_err("I1211 rollback");
        assert!(
            matches!(
                &e,
                Error::PartnerRecordRollback {
                    submitted: 1,
                    existing: 2,
                    ..
                }
            ),
            "[{tag}] I1211: a lower revision is a rollback: {e:?}"
        );
        not_stored(d, &back, "I1211 rollback").await;
        // Equal: admits (a re-emission carries the revision it re-emits).
        // Kills: `<` → `<=` (the v59 strict rule).
        must_put(d, &lic(&board, 2, "restricted", 15), "I1211 equal revision").await;
        // Testimony is not counted: a stranger's revision 99 does not freeze
        // the board's licence. Kills: counting rows that are not the
        // authority's.
        must_put(
            d,
            &lic(&stranger, 99, "revoked", 10),
            "I1211 testimony at 99",
        )
        .await;
        must_put(
            d,
            &lic(&board, 3, "issued", 5),
            "I1211 the board's revision 3",
        )
        .await;
        // Testimony is not judged: a stranger's revision 1 admits.
        must_put(d, &lic(&stranger, 1, "issued", 4), "I1211 testimony at 1").await;
        // Another licence_id is its own counter.
        must_put(
            d,
            &with(
                licence(
                    &board,
                    &holder,
                    &board,
                    "issued",
                    None,
                    now - Duration::minutes(3),
                ),
                "partner_record",
                payload("lic-other", "professional_full", 1, &[]),
            ),
            "I1211 another licence",
        )
        .await;
    }

    /// **I1212** — the skew bound, ported.
    pub async fn i1212_licence_skew_bound(d: &dyn FederationDirectory, tag: &str) {
        let (board, holder) = keys(d, tag).await;
        let ahead = with(
            licence(
                &board,
                &holder,
                &board,
                "issued",
                None,
                base() + Duration::minutes(6),
            ),
            "partner_record",
            payload("lic-s", "professional_full", 1, &[]),
        );
        let e = put(d, &ahead).await.expect_err("I1212 future-dated");
        assert!(
            format!("{e}").contains("skew"),
            "[{tag}] I1212: refused by the skew bound: {e}"
        );
        must_put(
            d,
            &with(
                licence(
                    &board,
                    &holder,
                    &board,
                    "issued",
                    None,
                    base() + Duration::minutes(4),
                ),
                "partner_record",
                payload("lic-s", "professional_full", 1, &[]),
            ),
            "I1212 inside the tolerance",
        )
        .await;
    }

    /// **I1213** — the retired wire kinds.
    pub async fn i1213_operational_kinds_are_retired(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::replication_policy::{retired_detail, EnvelopeKind, RETIRED_FRAMED};
        let hash = "cd".repeat(32);
        for kind in [
            EnvelopeKind::Organization,
            EnvelopeKind::OrgMembership,
            EnvelopeKind::PartnerRecord,
        ] {
            assert!(
                RETIRED_FRAMED.contains(&kind),
                "[{tag}] I1213: {kind:?} retired"
            );
            match d
                .insert_known_wire_hash(kind.as_str(), &hash, Some("a-peer"), Utc::now())
                .await
            {
                Err(e @ Error::EnvelopeKindRetired { .. }) => assert!(
                    e.to_string().starts_with(&format!(
                        "federation_envelope_kind_retired: {}",
                        retired_detail(kind)
                    )),
                    "[{tag}] I1213: {e}"
                ),
                other => panic!("[{tag}] I1213: {kind:?} advertisement taken in: {other:?}"),
            }
        }
        // The kinds keep their hashed positions (appended, never renumbered).
        assert_eq!(EnvelopeKind::ALL[10], EnvelopeKind::Organization);
        assert_eq!(EnvelopeKind::ALL[11], EnvelopeKind::OrgMembership);
        assert_eq!(EnvelopeKind::ALL[12], EnvelopeKind::PartnerRecord);
    }

    /// **I1214** — a licence under a quorum is a cosigned row.
    pub async fn i1214_quorum_licence_is_cosigned(d: &dyn FederationDirectory, tag: &str) {
        let (aff, k) = affiliation(
            d,
            &format!("{tag}-mj"),
            consensus_protocol::MAJORITY,
            &["a", "b", "c"],
            1,
            None,
        )
        .await;
        let holder = format!("{tag}-holder");
        let stranger = format!("{tag}-stranger");
        for key in [&holder, &stranger] {
            crate::federation::admission::steward_liveness_test_support::register(
                d,
                key,
                &[identity_type::USER],
            )
            .await;
        }
        let now = base();
        let lic = |status: &str, mins: i64| {
            classed(licence(
                &k[0],
                &holder,
                &aff,
                status,
                None,
                now - Duration::minutes(mins),
            ))
        };
        // One member's signature: testimony, admitted, outside the fold.
        // Kills: a lone member standing for a quorum protocol.
        let lone = must_put(d, &lic("revoked", 30), "I1214 one member").await;
        assert!(
            !crate::federation::admission::row_was_issued_under_authority(d, &lone, &aff)
                .await
                .unwrap(),
            "[{tag}] I1214: one member of a majority affiliation is not its authority"
        );
        // A stranger's cosignature counts for nothing. Kills: counting
        // scrubs outside the roster.
        let with_stranger = must_put(
            d,
            &cosigned(lic("suspended", 25), &[&stranger]),
            "I1214 cosigned by a non-member",
        )
        .await;
        assert!(
            !crate::federation::admission::row_was_issued_under_authority(d, &with_stranger, &aff)
                .await
                .unwrap(),
            "[{tag}] I1214: a non-member's cosignature does not make a quorum"
        );
        // Two of three cosign: the affiliation's licence. Kills: dropping the
        // cosigned-row arm (item 1).
        let quorum = must_put(
            d,
            &cosigned(lic("issued", 20), &[&k[1]]),
            "I1214 two of three",
        )
        .await;
        assert!(
            crate::federation::admission::row_was_issued_under_authority(d, &quorum, &aff)
                .await
                .unwrap(),
            "[{tag}] I1214: a quorum-cosigned licence is the affiliation's"
        );
        assert_eq!(
            status_set_for(d, &holder, &aff, Utc::now()).await.unwrap(),
            BTreeSet::from([LicensureStatus::Issued]),
            "[{tag}] I1214: the lone `revoked` binds nobody; the quorum's `issued` stands"
        );
        let listed: BTreeSet<String> = crate::federation::admission::licences_issued_under(d, &aff)
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.attestation_id)
            .collect();
        assert_eq!(
            listed,
            BTreeSet::from([quorum.attestation_id.clone()]),
            "[{tag}] I1214: the list-by-authority holds the cosigned licence only"
        );
        assert!(
            !crate::federation::admission::emitter_resolves_to_authority(d, &k[0], &aff)
                .await
                .unwrap(),
            "[{tag}] I1214: no single member resolves to a quorum authority"
        );
    }

    /// **I1215** — the `license` chain roots at the quorum.
    #[allow(clippy::too_many_lines)]
    pub async fn i1215_chain_roots_at_the_quorum(d: &dyn FederationDirectory, tag: &str) {
        let (aff, k) = affiliation(
            d,
            &format!("{tag}-mj"),
            consensus_protocol::MAJORITY,
            &["a", "b", "c"],
            1,
            None,
        )
        .await;
        let holder = format!("{tag}-holder");
        crate::federation::admission::steward_liveness_test_support::register(
            d,
            &holder,
            &[identity_type::USER],
        )
        .await;
        let now = base();
        let names = serde_json::json!(aff);
        let appoint = |to: &str, sub: bool, naming: bool, hours: i64| {
            let mut extra = vec![("sub_delegation", serde_json::json!(sub))];
            if naming {
                extra.push(("community_id", names.clone()));
            }
            edge(
                &k[0],
                to,
                &[DELEGATION_SCOPE_LICENSE],
                now - Duration::hours(hours),
                &extra,
            )
        };
        // (1) A lone member's appointment: nothing.
        let o1 = officer(d, tag, "o1").await;
        let lone = must_put(d, &appoint(&o1, false, true, 6), "I1215 lone appointment").await;
        must_refuse_as(
            d,
            &classed(licence(
                &o1,
                &holder,
                &aff,
                "issued",
                Some(&lone.attestation_id),
                now - Duration::hours(1),
            )),
            LicensureChainBreak::AuthorityActsByQuorum,
            &format!("[{tag}] I1215(1): a lone member's officer"),
        )
        .await;
        // (2) A quorum-cosigned appointment naming the affiliation: the root.
        // Kills: dropping the quorum root walk.
        let o2 = officer(d, tag, "o2").await;
        let root = must_put(
            d,
            &cosigned(appoint(&o2, false, true, 6), &[&k[1]]),
            "I1215 quorum appointment",
        )
        .await;
        let early = must_put(
            d,
            &classed(licence(
                &o2,
                &holder,
                &aff,
                "issued",
                Some(&root.attestation_id),
                now - Duration::hours(2),
            )),
            &format!("[{tag}] I1215(2): the quorum's officer issues"),
        )
        .await;
        assert!(
            crate::federation::admission::emitter_resolves_to_authority(d, &o2, &aff)
                .await
                .unwrap(),
            "[{tag}] I1215(2): the quorum's officer resolves to the authority"
        );
        // (3) Cosigned but naming no community: not a root. Kills: dropping
        // the community check on the root edge.
        let o3 = officer(d, tag, "o3").await;
        let unnamed = must_put(
            d,
            &cosigned(appoint(&o3, false, false, 6), &[&k[1]]),
            "I1215 cosigned, unnamed",
        )
        .await;
        must_refuse_as(
            d,
            &classed(licence(
                &o3,
                &holder,
                &aff,
                "issued",
                Some(&unnamed.attestation_id),
                now - Duration::hours(1),
            )),
            LicensureChainBreak::AuthorityActsByQuorum,
            &format!("[{tag}] I1215(3): a root edge names the affiliation"),
        )
        .await;
        // (4) Onward: only through a root that granted sub_delegation.
        // Kills: walking on from every root.
        let o4 = officer(d, tag, "o4").await;
        let o5 = officer(d, tag, "o5").await;
        let o6 = officer(d, tag, "o6").await;
        let onward_from_leaf = must_put(
            d,
            &edge(
                &o2,
                &o4,
                &[DELEGATION_SCOPE_LICENSE],
                now - Duration::hours(5),
                &[],
            ),
            "I1215 o2 appoints onward without the right",
        )
        .await;
        must_refuse_as(
            d,
            &classed(licence(
                &o4,
                &holder,
                &aff,
                "issued",
                Some(&onward_from_leaf.attestation_id),
                now - Duration::hours(1),
            )),
            LicensureChainBreak::AuthorityActsByQuorum,
            &format!("[{tag}] I1215(4): no sub_delegation on the root"),
        )
        .await;
        let deputising = must_put(
            d,
            &cosigned(appoint(&o5, true, true, 6), &[&k[2]]),
            "I1215 quorum appointment with sub_delegation",
        )
        .await;
        let _ = deputising;
        let onward = must_put(
            d,
            &edge(
                &o5,
                &o6,
                &[DELEGATION_SCOPE_LICENSE],
                now - Duration::hours(5),
                &[],
            ),
            "I1215 o5 appoints onward",
        )
        .await;
        must_put(
            d,
            &classed(licence(
                &o6,
                &holder,
                &aff,
                "probation",
                Some(&onward.attestation_id),
                now - Duration::hours(1),
            )),
            &format!("[{tag}] I1215(4): two hops from the quorum, under sub_delegation"),
        )
        .await;
        // (5) A lone member's withdraws does not retract a cosigned root
        // (rule 0). Kills: honouring any retraction of the root. (Its own
        // root: the cosigned retraction below would otherwise be the same
        // `(references, type, attester)` triple, which §6.1 dedups.)
        let o7 = officer(d, tag, "o7").await;
        let root_b = must_put(
            d,
            &cosigned(appoint(&o7, false, true, 6), &[&k[1]]),
            "I1215 a second quorum appointment",
        )
        .await;
        let mut w_lone = edge(&k[0], &o7, &[], now - Duration::minutes(50), &[]);
        w_lone.attestation_type = attestation_type::WITHDRAWS.to_owned();
        let w_lone = with(
            w_lone,
            "references_attestation_id",
            serde_json::json!(root_b.attestation_id),
        );
        must_put(d, &w_lone, "I1215 a lone member withdraws the root").await;
        must_put(
            d,
            &classed(licence(
                &o7,
                &holder,
                &aff,
                "restricted",
                Some(&root_b.attestation_id),
                now - Duration::minutes(40),
            )),
            &format!("[{tag}] I1215(5): a lone retraction does not undo a quorum's act"),
        )
        .await;
        // (6) A cosigned withdraws retracts it: a later licence is refused,
        // the earlier ones stay the affiliation's (item 2). Kills: ignoring
        // a cosigned retraction; reclassifying history.
        let mut w_q = edge(&k[0], &o2, &[], now - Duration::minutes(30), &[]);
        w_q.attestation_type = attestation_type::WITHDRAWS.to_owned();
        let w_q = with(
            w_q,
            "references_attestation_id",
            serde_json::json!(root.attestation_id),
        );
        must_put(
            d,
            &cosigned(w_q, &[&k[1]]),
            "I1215 the quorum withdraws the root",
        )
        .await;
        must_refuse_as(
            d,
            &classed(licence(
                &o2,
                &holder,
                &aff,
                "issued",
                Some(&root.attestation_id),
                now - Duration::minutes(10),
            )),
            LicensureChainBreak::AuthorityActsByQuorum,
            &format!("[{tag}] I1215(6): an officer whose quorum appointment was withdrawn"),
        )
        .await;
        assert!(
            crate::federation::admission::row_was_issued_under_authority(d, &early, &aff)
                .await
                .unwrap(),
            "[{tag}] I1215(6): a licence issued before the withdrawal stays the affiliation's"
        );
    }

    /// **I1216** — no public default; the charter declares per class.
    pub async fn i1216_licence_has_no_public_default(d: &dyn FederationDirectory, tag: &str) {
        let (aff, k) = affiliation(
            d,
            &format!("{tag}-fo"),
            consensus_protocol::FOUNDER_ONLY,
            &["a", "b"],
            1,
            Some(serde_json::json!({
                "licence_audiences": {
                    "professional_full": "federation",
                    "community_plus": "self",
                }
            })),
        )
        .await;
        let holder = format!("{tag}-holder");
        crate::federation::admission::steward_liveness_test_support::register(
            d,
            &holder,
            &[identity_type::USER],
        )
        .await;
        let at = base() - Duration::minutes(5);
        let lic = |class: Option<&str>, scope: &str, id: &str| {
            let row = licence(&k[0], &holder, &aff, "issued", None, at);
            let row = match class {
                Some(c) => with(row, "partner_record", payload(id, c, 1, &[])),
                None => row,
            };
            placed(row, scope, &[])
        };
        let refused = |r: Result<Attestation, Error>, reason: &str, what: &str| match r {
            Err(Error::InvalidArgument(m)) => assert!(
                m.starts_with(&format!("{LICENCE_AUDIENCE_REFUSED}: {reason}:")),
                "[{tag}] {what}: {m}"
            ),
            other => panic!(
                "[{tag}] {what}: expected {LICENCE_AUDIENCE_REFUSED}: {reason}, got {other:?}"
            ),
        };
        // Declared public: admits at federation.
        must_put(
            d,
            &lic(Some("professional_full"), "federation", "l1"),
            "I1216 declared public",
        )
        .await;
        // Declared `self`: the declared choice only. Kills: dropping the
        // declared-scope equality.
        refused(
            put(d, &lic(Some("community_plus"), "federation", "l2")).await,
            aud::SCOPE_NOT_THE_DECLARED_CHOICE,
            "I1216 a self class at federation",
        );
        must_put(
            d,
            &lic(Some("community_plus"), "self", "l3"),
            "I1216 a self class at self",
        )
        .await;
        // Undeclared: any scope but a commons one. Kills: a public default.
        refused(
            put(d, &lic(Some("internal_badge"), "federation", "l4")).await,
            aud::CLASS_NOT_DECLARED_PUBLIC,
            "I1216 an undeclared class at federation",
        );
        refused(
            put(d, &lic(Some("internal_badge"), "species", "l5")).await,
            aud::CLASS_NOT_DECLARED_PUBLIC,
            "I1216 an undeclared class at species (commons)",
        );
        must_put(
            d,
            &lic(Some("internal_badge"), "self", "l6"),
            "I1216 undeclared at self",
        )
        .await;
        // No payload, no class: no public default either.
        refused(
            put(d, &lic(None, "federation", "l7")).await,
            aud::CLASS_NOT_DECLARED_PUBLIC,
            "I1216 a licence with no class at federation",
        );
        // Control: a key authority has no charter; the producer chooses.
        let (board, h2) = keys(d, &format!("{tag}-key")).await;
        must_put(
            d,
            &with(
                licence(&board, &h2, &board, "issued", None, at),
                "partner_record",
                payload("l8", "internal_badge", 1, &[]),
            ),
            "I1216 a key authority at federation",
        )
        .await;
    }

    /// **I1217** — re-emission to named readers.
    pub async fn i1217_re_emission_to_named_readers(d: &dyn FederationDirectory, tag: &str) {
        let (aff, k) = affiliation(
            d,
            &format!("{tag}-fo"),
            consensus_protocol::FOUNDER_ONLY,
            &["a", "b"],
            1,
            Some(serde_json::json!({ "licence_audiences": { "community_plus": "self" } })),
        )
        .await;
        let holder = format!("{tag}-holder");
        let reader = format!("{tag}-reader");
        for key in [&holder, &reader] {
            crate::federation::admission::steward_liveness_test_support::register(
                d,
                key,
                &[identity_type::USER],
            )
            .await;
        }
        let at = base() - Duration::minutes(10);
        let original = must_put(
            d,
            &placed(
                with(
                    licence(&k[0], &holder, &aff, "issued", None, at),
                    "partner_record",
                    payload("lic-re", "community_plus", 4, &[]),
                ),
                "self",
                &[],
            ),
            "I1217 the original licence",
        )
        .await;
        let re = |rev: u64, scope: &str, subjects: &[&str], target: &str| {
            let row = with(
                licence(
                    &k[0],
                    &holder,
                    &aff,
                    "issued",
                    None,
                    at + Duration::minutes(2),
                ),
                "partner_record",
                payload("lic-re", "community_plus", rev, &[]),
            );
            let row = with(row, LICENCE_RE_EMITS_MEMBER, serde_json::json!(target));
            placed(row, scope, subjects)
        };
        let refused = |r: Result<Attestation, Error>, reason: &str, what: &str| match r {
            Err(Error::InvalidArgument(m)) => assert!(
                m.starts_with(&format!("{LICENCE_AUDIENCE_REFUSED}: {reason}:")),
                "[{tag}] {what}: {m}"
            ),
            other => panic!("[{tag}] {what}: expected {reason}, got {other:?}"),
        };
        // The re-emission: same licence, same scope, the reader named.
        must_put(
            d,
            &re(4, "self", &[&holder, &reader], &original.attestation_id),
            "I1217 re-emitted to a named reader",
        )
        .await;
        // Naming no reader. Kills: dropping the reader check.
        refused(
            put(d, &re(4, "self", &[&holder], &original.attestation_id)).await,
            aud::RE_EMISSION_NAMES_NO_READER,
            "I1217 a re-emission naming only the licensee",
        );
        // A different licence. Kills: dropping the payload comparison.
        refused(
            put(
                d,
                &re(5, "self", &[&holder, &reader], &original.attestation_id),
            )
            .await,
            aud::RE_EMISSION_DIVERGES,
            "I1217 a re-emission carrying another revision",
        );
        // Re-emitting what is not held.
        refused(
            put(d, &re(4, "self", &[&holder, &reader], "no-such-licence")).await,
            aud::RE_EMISSION_TARGET_UNKNOWN,
            "I1217 a re-emission of nothing",
        );
        // At the wrong scope: never carried at a scope the class does not
        // declare. Kills: exempting re-emissions from the scope rule.
        refused(
            put(
                d,
                &re(
                    4,
                    "federation",
                    &[&holder, &reader],
                    &original.attestation_id,
                ),
            )
            .await,
            aud::SCOPE_NOT_THE_DECLARED_CHOICE,
            "I1217 a re-emission widened to federation",
        );
    }

    /// **I1218** — the contest path.
    #[allow(clippy::too_many_lines)]
    pub async fn i1218_licence_contest_path(d: &dyn FederationDirectory, tag: &str) {
        let (board, holder) = keys(d, tag).await;
        let stranger = format!("{tag}-stranger");
        crate::federation::admission::steward_liveness_test_support::register(
            d,
            &stranger,
            &[identity_type::USER],
        )
        .await;
        let at = base() - Duration::minutes(30);
        let named = |row: Attestation| placed(row, "federation", &[&holder]);
        let lic = must_put(
            d,
            &named(licence(&board, &holder, &board, "suspended", None, at)),
            "I1218 the licence",
        )
        .await;
        let adverse = must_put(
            d,
            &named(with(
                with(
                    with(
                        licence(&board, &holder, &board, "issued", None, at),
                        "dimension",
                        serde_json::json!("revocation:agent:misconduct:v1"),
                    ),
                    "score",
                    serde_json::json!(-1.0),
                ),
                "status",
                serde_json::Value::Null,
            )),
            "I1218 a revocation row about the holder",
        )
        .await;
        let benign = must_put(
            d,
            &named(with(
                licence(&board, &holder, &board, "issued", None, at),
                "dimension",
                serde_json::json!("endorsement:skill:v1"),
            )),
            "I1218 a benign row about the holder",
        )
        .await;
        let withdraw = |by: &str, target: &str, mins: i64| {
            let mut w = edge(by, &holder, &[], base() - Duration::minutes(mins), &[]);
            w.attestation_type = attestation_type::WITHDRAWS.to_owned();
            with(w, "references_attestation_id", serde_json::json!(target))
        };
        // The subject may not withdraw a licence or a revocation about
        // itself. Kills: the carve-out missing `licensure:` / `revocation:`.
        for (target, what) in [(&lic, "licensure"), (&adverse, "revocation")] {
            let e = put(d, &withdraw(&holder, &target.attestation_id, 20))
                .await
                .expect_err("subject withdraws an adverse row");
            assert_eq!(
                e.kind(),
                "federation_withdraws_not_admitted",
                "[{tag}] I1218: a subject's withdraws against {what}"
            );
        }
        // Control: the subject may withdraw a benign row about itself (rule 2).
        must_put(
            d,
            &withdraw(&holder, &benign.attestation_id, 19),
            "I1218 benign withdraws",
        )
        .await;
        // The contest: reconsideration, filed by the licensee.
        let recon = |by: &str, extra: serde_json::Value, mins: i64| {
            let mut row = licence(by, by, by, "issued", None, base() - Duration::minutes(mins));
            row.attestation_envelope = serde_json::json!({
                "id": row.attestation_id,
                "dimension": "reconsideration:new_evidence:v1",
                "score": 1.0, "confidence": 1.0,
                "references_attestation_id": lic.attestation_id,
            });
            for (key, v) in extra.as_object().unwrap() {
                row.attestation_envelope[key] = v.clone();
            }
            ts::reseal(&mut row);
            row
        };
        must_put(
            d,
            &recon(&holder, serde_json::json!({}), 15),
            "I1218 the licensee files",
        )
        .await;
        let e = put(d, &recon(&stranger, serde_json::json!({}), 14))
            .await
            .expect_err("a stranger files");
        assert_eq!(
            e.kind(),
            "federation_delegated_scope_unauthorized",
            "[{tag}] I1218: a stranger has no standing on a licence"
        );
        // The ruling is the authority's. Kills: dropping the authority set
        // from the duty-holders.
        must_put(
            d,
            &recon(&board, serde_json::json!({ "outcome": "reversed" }), 10),
            "I1218 the authority rules",
        )
        .await;
        let e = put(
            d,
            &recon(&holder, serde_json::json!({ "outcome": "reversed" }), 9),
        )
        .await
        .expect_err("the licensee rules");
        assert_eq!(
            e.kind(),
            "federation_delegated_scope_unauthorized",
            "[{tag}] I1218: the licensee files but does not rule"
        );
        // The producer still withdraws its own licence (rule 1).
        must_put(
            d,
            &withdraw(&board, &lic.attestation_id, 5),
            "I1218 the board withdraws",
        )
        .await;
    }

    /// **I1219** — #1062: the organisation on the bond.
    pub async fn i1219_owner_binding_names_the_affiliation(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::types::{delegation_scope as ds, owner_binding};
        let (aff, k) = affiliation(
            d,
            &format!("{tag}-mj"),
            consensus_protocol::MAJORITY,
            &["a", "b", "c"],
            1,
            None,
        )
        .await;
        let (plain, pk) = make_group(
            d,
            &format!("{tag}-pl"),
            consensus_protocol::MAJORITY,
            &["p", "q"],
            1,
            None,
            None,
        )
        .await;
        let binding = |steward: &str, node: &str, community: Option<&str>| {
            let mut env = serde_json::json!({
                "kind": "delegates_to",
                "dimension": owner_binding::DIMENSION,
                "delegation_purpose": owner_binding::PURPOSE,
                "scope": [ds::INFRA_SERVE],
            });
            if let Some(c) = community {
                env["community_id"] = serde_json::json!(c);
            }
            let mut row = crate::federation::admission::steward_liveness_test_support::signed_row(
                steward,
                node,
                attestation_type::DELEGATES_TO,
                env,
            );
            row.asserted_at = base() - Duration::minutes(5);
            row.scrub_timestamp = row.asserted_at;
            ts::reseal(&mut row);
            row
        };
        let node = |n: &str| format!("{tag}-{n}");
        for n in ["n1", "n2", "n3", "n4", "n5"] {
            ts::register_hybrid_key_as(d, &node(n), &node(n), identity_type::NODE).await;
        }
        let refused = |r: Result<Attestation, Error>, reason: &str, what: &str| match r {
            Err(Error::InvalidArgument(m)) => assert!(
                m.starts_with(&format!("{OWNER_BINDING_AFFILIATION_REFUSED}: {reason}:")),
                "[{tag}] {what}: {m}"
            ),
            other => panic!("[{tag}] {what}: expected {reason}, got {other:?}"),
        };
        // Signed by one member only. Kills: dropping the cosign check.
        refused(
            put(d, &binding(&k[0], &node("n1"), Some(&aff))).await,
            obr::NOT_COSIGNED_UNDER_PROTOCOL,
            "I1219 an organisation's binding signed by one member",
        );
        // Cosigned under the protocol: admitted, and the fold names it.
        must_put(
            d,
            &cosigned(binding(&k[0], &node("n2"), Some(&aff)), &[&k[1]]),
            "I1219 an organisation's binding cosigned 2 of 3",
        )
        .await;
        assert_eq!(
            crate::federation::admission::affiliation_of_binding(d, &node("n2"))
                .await
                .unwrap(),
            Some(aff.clone()),
            "[{tag}] I1219: the affiliation answers alongside the steward"
        );
        // A personal steward's binding: unchanged, no affiliation.
        must_put(
            d,
            &binding(&k[2], &node("n3"), None),
            "I1219 a personal binding",
        )
        .await;
        assert_eq!(
            crate::federation::admission::affiliation_of_binding(d, &node("n3"))
                .await
                .unwrap(),
            None,
            "[{tag}] I1219: a personal binding names no affiliation"
        );
        // A plain community is not an organisation. Kills: dropping the
        // affiliation check.
        refused(
            put(
                d,
                &cosigned(binding(&pk[0], &node("n4"), Some(&plain)), &[&pk[1]]),
            )
            .await,
            obr::NOT_AN_AFFILIATION,
            "I1219 a binding naming a plain community",
        );
        refused(
            put(d, &binding(&k[0], &node("n5"), Some("no-such-org"))).await,
            obr::AFFILIATION_NOT_HELD,
            "I1219 a binding naming an unknown community",
        );
    }

    /// **I1220** — #1049: the consent `grant` chain at the signed instant.
    pub async fn i1220_consent_chain_judged_at_issuance(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::grant_scope_invariants::bodies::{row, withdraw};
        use crate::federation::types::identity_type::{AGENT, USER};
        let k = |n: &str| format!("i1220-{n}-{tag}");
        let (alice, m) = (k("alice"), k("m"));
        ts::register_identity_key(d, &alice, USER).await;
        ts::register_identity_key(d, &m, AGENT).await;
        let now = Utc::now();
        let chain = crate::federation::grant_scope_invariants::bodies::put_grant_with_term(
            d,
            &alice,
            &m,
            now - Duration::days(5),
            now - Duration::days(5),
            now + Duration::days(30),
        )
        .await;
        let grant = |id: &str, at: chrono::DateTime<Utc>| {
            row(
                id,
                &m,
                &m,
                &m,
                attestation_type::SCORES,
                serde_json::json!({
                    "dimension": crate::federation::consent_peer_set::DIMENSION,
                    "payload": {
                        "grants": "replication",
                        "attestation_prefixes": ["i1220-fixture:"],
                        crate::federation::consent_by_humans::FOR_KEY_ID: alice,
                    },
                }),
                vec!["i1220-peer".to_owned()],
                crate::federation::admission::truncate_to_substrate_resolution(at),
            )
        };
        let put_row = |r: Attestation| async move {
            d.put_attestation(crate::federation::SignedAttestation { attestation: r })
                .await
                .map(|_| ())
        };
        // Beyond W, the chain still live at receipt: admits.
        put_row(grant(&k("g1"), now - Duration::days(4)))
            .await
            .unwrap_or_else(|e| panic!("[{tag}] I1220: an old grant whose chain stands: {e}"));
        withdraw(d, &alice, &alice, &m, &chain).await;
        // Inside W, signed while the chain was live: admits (judged at the
        // signed instant). Kills: judging the chain at receipt.
        put_row(grant(&k("g2"), now - Duration::hours(1)))
            .await
            .unwrap_or_else(|e| panic!("[{tag}] I1220: a grant signed inside W: {e}"));
        // Beyond W, the chain withdrawn since: asserted_at_stale. Kills:
        // dropping the W gate.
        let e = put_row(grant(&k("g3"), now - Duration::days(4)))
            .await
            .expect_err("a backdated grant from a withdrawn delegate");
        assert!(
            matches!(
                &e,
                Error::AssertedAtStale {
                    plane: "consent",
                    ..
                }
            ),
            "[{tag}] I1220: asserted_at_stale on the consent plane: {e:?}"
        );
        // After the withdrawal, a fresh grant is refused as before.
        let e = put_row(grant(&k("g4"), Utc::now() + Duration::seconds(1)))
            .await
            .expect_err("fresh after withdrawal");
        assert!(
            matches!(&e, Error::InvalidArgument(m)
                if m.starts_with(crate::federation::admission::CONSENT_FOR_KEY_NOT_DELEGATED)),
            "[{tag}] I1220: a grant signed after the withdrawal: {e}"
        );
    }
}

/// **I1222** — the JCS order of a set (pure).
#[cfg(test)]
mod jcs_order {
    use crate::federation::operational::{check_partner_record_sets, PartnerRecord};

    fn rec(caps: &[&str]) -> PartnerRecord {
        serde_json::from_value(serde_json::json!({
            "license_id": "l", "license_type": "t",
            "capabilities_granted": caps, "capabilities_denied": [],
            "max_autonomy_tier": "A0", "requires_supervisor": false,
            "geographic_restrictions": [], "allowed_identity_templates": [],
            "deployment_limit": 1, "offline_grace_hours": 1, "revision": 1,
            "issued_at": "2026-10-01T00:00:00Z", "expires_at": "2027-10-01T00:00:00Z",
        }))
        .unwrap()
    }

    #[test]
    fn i1222_set_order_is_utf16_and_unique() {
        // U+FF5E (BMP, high) and U+1F600 (astral): byte order puts the astral
        // one last, UTF-16 order (its surrogate D83D) puts it first.
        let astral = "\u{1F600}";
        let high_bmp = "\u{FF5E}";
        assert!(check_partner_record_sets(&rec(&[astral, high_bmp])).is_ok());
        assert!(check_partner_record_sets(&rec(&[high_bmp, astral])).is_err());
        assert!(check_partner_record_sets(&rec(&["a", "a"])).is_err());
        assert!(check_partner_record_sets(&rec(&["a", "b"])).is_ok());
        let mut r = rec(&["b", "a", "b", high_bmp, astral]);
        r.canonicalize_sets();
        assert_eq!(r.capabilities_granted, vec!["a", "b", astral, high_bmp]);
        assert!(check_partner_record_sets(&r).is_ok());
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    /// sqlite and postgres only (S5 retires the memory backend).
    macro_rules! on_both_backends {
        ($body:ident, $sqlite:ident, $postgres:ident, $prefix:literal) => {
            #[cfg(feature = "sqlite")]
            #[tokio::test(flavor = "multi_thread")]
            async fn $sqlite() {
                use crate::store::Backend as _;
                let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                    .await
                    .unwrap();
                b.run_migrations().await.unwrap();
                super::bodies::$body(&b, &format!("{}-{}", $prefix, suffix())).await;
            }

            #[cfg(feature = "postgres")]
            #[tokio::test(flavor = "multi_thread")]
            async fn $postgres() {
                use crate::store::Backend as _;
                let Some(dsn) = crate::test_pg::empty_dsn() else {
                    return;
                };
                let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                    .await
                    .unwrap();
                b.run_migrations().await.unwrap();
                super::bodies::$body(&b, &format!("{}-{}", $prefix, suffix())).await;
            }
        };
    }

    on_both_backends!(
        i1210_licence_payload_pure_gate,
        i1210_sqlite,
        i1210_postgres,
        "i1210"
    );
    on_both_backends!(
        i1211_revision_never_goes_backwards,
        i1211_sqlite,
        i1211_postgres,
        "i1211"
    );
    on_both_backends!(
        i1212_licence_skew_bound,
        i1212_sqlite,
        i1212_postgres,
        "i1212"
    );
    on_both_backends!(
        i1213_operational_kinds_are_retired,
        i1213_sqlite,
        i1213_postgres,
        "i1213"
    );
    on_both_backends!(
        i1214_quorum_licence_is_cosigned,
        i1214_sqlite,
        i1214_postgres,
        "i1214"
    );
    on_both_backends!(
        i1215_chain_roots_at_the_quorum,
        i1215_sqlite,
        i1215_postgres,
        "i1215"
    );
    on_both_backends!(
        i1216_licence_has_no_public_default,
        i1216_sqlite,
        i1216_postgres,
        "i1216"
    );
    on_both_backends!(
        i1217_re_emission_to_named_readers,
        i1217_sqlite,
        i1217_postgres,
        "i1217"
    );
    on_both_backends!(
        i1218_licence_contest_path,
        i1218_sqlite,
        i1218_postgres,
        "i1218"
    );
    on_both_backends!(
        i1219_owner_binding_names_the_affiliation,
        i1219_sqlite,
        i1219_postgres,
        "i1219"
    );
    on_both_backends!(
        i1220_consent_chain_judged_at_issuance,
        i1220_sqlite,
        i1220_postgres,
        "i1220"
    );

    /// **I1213b** — V205 dropped the three tables (sqlite).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1213b_v205_dropped_the_tables_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        for t in [
            "federation_organizations",
            "federation_org_memberships",
            "federation_partner_records",
            "federation_attestations",
        ] {
            let name = t.to_owned();
            let n: i64 = b
                .read(move |c| {
                    c.query_row(
                        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                        [name],
                        |r| r.get(0),
                    )
                })
                .await
                .unwrap();
            assert_eq!(
                n,
                i64::from(t == "federation_attestations"),
                "I1213b: {t} after V205"
            );
        }
    }

    /// **I1213b** — V205 dropped the three tables (postgres).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1213b_v205_dropped_the_tables_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let client = b.pool().get().await.unwrap();
        for t in [
            "federation_organizations",
            "federation_org_memberships",
            "federation_partner_records",
            "federation_attestations",
        ] {
            let n: i64 = client
                .query_one(
                    "SELECT count(*) FROM information_schema.tables \
                     WHERE table_schema = 'cirislens' AND table_name = $1",
                    &[&t],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(
                n,
                i64::from(t == "federation_attestations"),
                "I1213b: {t} after V205"
            );
        }
    }
}
