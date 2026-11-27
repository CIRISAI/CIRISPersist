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
//! - **I1223** — the promotion chokepoint re-runs the payload gate.
//! - **I1225** (pure) — W is a closed window at its boundary.

/// The backend-agnostic witness bodies; `run` instantiates them per backend.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub mod bodies {
    use crate::federation::admission::{
        licence_audience_reason as aud, owner_binding_affiliation_reason as obr,
        LicensureChainBreak, DELEGATION_SCOPE_LICENSE, LICENCE_AUDIENCE_REFUSED,
        LICENCE_RE_EMITS_MEMBER, OWNER_BINDING_AFFILIATION_REFUSED,
    };
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::licensure::{status_set_for, LicensureStatus};
    use crate::federation::licensure_chain_invariants::bodies::key_id;
    use crate::federation::licensure_chain_invariants::bodies::{
        base, edge, held_reason, keys, licence, must_put, must_refuse_as, officer, put,
        refusal_message,
    };
    use crate::federation::room_roster_authority_invariants::bodies::make_group;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, consensus_protocol, identity_type};
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
        // A JSON `null` drops the member: an optional member is absent, never
        // `null` (CC 2.6.1.1.1, `envelope_member_null`).
        if value.is_null() {
            if let Some(members) = row.attestation_envelope.as_object_mut() {
                members.remove(member);
            }
        } else {
            row.attestation_envelope[member] = value;
        }
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

    /// `row` cosigned by each of `cosigners`. v62.0.0 (CC 2.4.1.3,
    /// CLM-licence-authority-quorum): a cosignature is one more edition-2
    /// voice over the row's payload and row id, offered after the row by
    /// `licensure_chain_invariants::bodies::put` (`note_cosigners`); a
    /// counted row short of its protocol is held `Pending`.
    pub(crate) fn cosigned(row: Attestation, cosigners: &[&str]) -> Attestation {
        crate::federation::licensure_chain_invariants::bodies::note_cosigners(&row, cosigners);
        row
    }

    /// v62.0.0 (LF-fix1; CC 2.7.3) — **the gate's token behind a [`put`]
    /// result that must not conclude**: a refusal's `kind`, or, for a row the
    /// door HELD on a fold condition, the fold's reason token spelled as that
    /// kind (`federation_<reason>`: each reason token is the gate's former
    /// refusal kind without the prefix, `fold::reason`). Panics when the row
    /// was admitted. `put` reports a held row only after reading that no row
    /// is stored under its id.
    fn refused_or_held(r: Result<Attestation, Error>, what: &str) -> String {
        match held_reason(&r) {
            Some((reason, _detail)) => format!("federation_{reason}"),
            None => kind_of(r, what),
        }
    }

    /// v62.0.0 (LF-fix1) — is the revocation `revocation_id` held on the
    /// revocation plane under the subject key digest `subject_digest`?
    async fn revocation_held(
        d: &dyn FederationDirectory,
        subject_digest: &str,
        revocation_id: &str,
    ) -> bool {
        d.revocations_for_subject(subject_digest)
            .await
            .unwrap()
            .iter()
            .any(|r| r.revocation_id == revocation_id)
    }

    fn kind_of(r: Result<Attestation, Error>, what: &str) -> String {
        match r {
            Ok(a) => panic!("{what}: must be refused, admitted {}", a.attestation_id),
            Err(e) => e.kind().to_owned(),
        }
    }

    /// v62.0.0 (E2-fix3) — `r` is the `revision` rollback of `submitted`
    /// below `existing`: refused typed (the earlier form), or HELD
    /// `partner_record_rollback` with that refusal's text (edition 2; the held
    /// revision is another row, CC 2.7.3).
    fn rollback(r: &Result<Attestation, Error>, submitted: u64, existing: u64) -> bool {
        if let Err(Error::PartnerRecordRollback {
            submitted: s,
            existing: e,
            ..
        }) = r
        {
            return *s == submitted && *e == existing;
        }
        held_reason(r).is_some_and(|(reason, detail)| {
            reason == crate::federation::edition2::fold::reason::gc1::PARTNER_RECORD_ROLLBACK
                && detail.ends_with(&format!(
                    "submitted revision {submitted} is below existing {existing}"
                ))
        })
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

    /// **I1223** — the promotion chokepoint re-runs the payload gate: a
    /// licence whose payload repeats a set member does not cross to the
    /// federation tier, and the well-formed one does. Kills: dropping
    /// `check_licence_payload` from `check_promotion_admission` (no mutant
    /// deletes a call; this is the reachability witness).
    pub async fn i1223_promotion_re_runs_the_payload_gate(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::admission::check_promotion_admission;
        let (board, holder) = keys(d, tag).await;
        let at = base() - Duration::minutes(5);
        let lic = |id: &str, caps: &[&str]| {
            with(
                licence(&board, &holder, &board, "issued", None, at),
                "partner_record",
                payload(id, "professional_full", 1, caps),
            )
        };
        let dup = lic("lic-p1", &["a.read", "a.read"]);
        assert_eq!(
            kind_of(
                check_promotion_admission(d, &dup, None)
                    .await
                    .map(|()| dup.clone()),
                "I1223 repeat"
            ),
            "federation_set_semantics_unsorted",
            "[{tag}] I1223: a repeated set member does not cross"
        );
        let ok = lic("lic-p2", &["a.read", "b.write"]);
        if let Err(e) = check_promotion_admission(d, &ok, None).await {
            panic!(
                "[{tag}] I1223 control: a well-formed licence crosses, got {} ({e})",
                e.kind()
            );
        }
    }

    /// **I1211** — the `revision` anti-rollback.
    pub async fn i1211_revision_never_goes_backwards(d: &dyn FederationDirectory, tag: &str) {
        let (board, holder) = keys(d, tag).await;
        let stranger = format!("{tag}-stranger");
        crate::federation::licensure_chain_invariants::bodies::reg(
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
        // v62.0.0 (E2-fix3; CC 2.7.3, wave GC1) — the held revision is
        // ANOTHER row, so an edition-2 rollback is HELD
        // `partner_record_rollback` with the refusal's text; the earlier form
        // refuses it typed.
        let back = lic(&board, 1, "issued", 20);
        let r = put(d, &back).await;
        assert!(
            rollback(&r, 1, 2),
            "[{tag}] I1211: a lower revision is a rollback: {r:?}"
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
        // A rollback names the HIGHEST held revision (3 over 2, 2), not the
        // first one read. Kills: the running-maximum test inverted.
        let r = put(d, &lic(&board, 1, "issued", 0)).await;
        assert!(
            rollback(&r, 1, 3),
            "[{tag}] I1211: the rollback names the highest held revision: {r:?}"
        );
        // Another authority whose id the board's is a prefix of: the prefix
        // read reaches its rows, and the board's own testimony there at
        // revision 50 is not the board's counter. Kills: the
        // foreign-authority skip weakened (the board's row under
        // `licensure:{board}2` would count as the board's own).
        let board2 = format!("{board}2");
        crate::federation::licensure_chain_invariants::bodies::reg(
            d,
            &board2,
            &[identity_type::USER],
        )
        .await;
        must_put(
            d,
            &with(
                licence(
                    &board,
                    &holder,
                    &board2,
                    "issued",
                    None,
                    now - Duration::minutes(2),
                ),
                "partner_record",
                payload("lic-r", "professional_full", 50, &[]),
            ),
            "I1211 the board's testimony under another authority at 50",
        )
        .await;
        must_put(
            d,
            &lic(&board, 4, "issued", 1),
            "I1211 the board's revision 4 under its own authority",
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

    /// **I2630** (v62.0.0, E2-fix6; CC 2.7.4, CC 3.2 T6) — **a counted act is
    /// counted over the roster version its `refs.head` NAMES, found by that
    /// version's ROW ID.** A typed community version carries its record's
    /// content hash, never the roster statement's row id, so the door must
    /// map the named statement to its record before it can find the version.
    /// Under `majority` over three members: one member's licence HOLDS (1 of
    /// 3), and a second member's voice SETTLES it (2 of 3 is a majority).
    /// Kills: comparing the version's `persist_row_hash` with the head's row
    /// id (no head ever matches, every act stays short); counting a lone
    /// voice as a majority.
    pub async fn i2630_a_majority_counts_at_its_named_head(d: &dyn FederationDirectory, tag: &str) {
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
        crate::federation::licensure_chain_invariants::bodies::reg(
            d,
            &holder,
            &[identity_type::USER],
        )
        .await;
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
        // 1 of 3: held (`Pending`), no typed row.
        match crate::federation::licensure_chain_invariants::bodies::offer(d, &lic("suspended", 20))
            .await
        {
            Ok((held, Some(StatementOutcome::Pending { .. }))) => assert!(
                d.get_attestation(&held.attestation_id)
                    .await
                    .unwrap()
                    .is_none(),
                "[{tag}] I2630: one member of three is short of a majority: no typed row"
            ),
            other => panic!("[{tag}] I2630: one member of three must wait, got {other:?}"),
        }
        // 2 of 3: settles, and it is the affiliation's licence.
        let settled = must_put(
            d,
            &cosigned(lic("issued", 10), &[&k[1]]),
            &format!("[{tag}] I2630: two members of three"),
        )
        .await;
        assert!(
            crate::federation::admission::row_was_issued_under_authority(
                d,
                &settled,
                &key_id(&aff)
            )
            .await
            .unwrap(),
            "[{tag}] I2630: the majority-cosigned licence is the affiliation's"
        );
        // A head that names a held row which is NOT a roster version (here the
        // settled licence itself) counts nothing: even all three members'
        // voices leave the act WAITING, with no typed row. Kills: reading any
        // held statement under the head as the roster; mapping a non-roster
        // head to a refusal or to a version.
        use crate::federation::edition2::fixture_switch as e2;
        let mut shape = lic("revoked", 5);
        shape.attestation_envelope["refs"] =
            serde_json::json!({ "head": [2, [-16, settled.attestation_id.clone()]] });
        let counted = e2::counted_row_of(&shape, &e2::seed_of(&shape.attesting_key_id));
        let mut out = e2::put_signed(d, &counted)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] I2630: a non-roster head waits, refused: {e}"));
        for v in e2::voices_of(&counted, &[k[1].as_str(), k[2].as_str()]) {
            out = e2::put_statement(d, &v)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] I2630: a voice over it, refused: {e}"));
        }
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "[{tag}] I2630: a head naming a non-roster row waits, got {out:?}"
        );
        assert!(
            d.get_attestation(&counted.attestation_id)
                .await
                .unwrap()
                .is_none(),
            "[{tag}] I2630: a non-roster head lands no typed row"
        );
        // A head naming roster VERSION 2 whose version 1 is not held here (a
        // v1' of this group that never landed) is absence: the act WAITS,
        // all three voices notwithstanding. Kills: refusing (or erroring) on
        // a lineage this node has not received yet.
        let roster = |name: &str| {
            crate::federation::tier_ingest::test_support::sign_community(
                &k[0],
                crate::federation::Community {
                    prev_head_digest: String::new(),
                    charter_digest: String::new(),
                    community_key_id: aff.clone(),
                    community_name: name.into(),
                    members: k
                        .iter()
                        .enumerate()
                        .map(|(i, m)| crate::federation::CommunityMember {
                            key_id: m.clone(),
                            joined_at: base() - Duration::days(1),
                            role: (i == 0).then(|| "founder".to_owned()),
                        })
                        .collect(),
                    founded_at: base() - Duration::days(1),
                    consensus_protocol: consensus_protocol::MAJORITY.into(),
                    policy_blob: Some(serde_json::json!({
                        "cohort_scope": "affiliations",
                        "affiliation_config": { "licence_audiences": { PUBLIC_CLASS: "federation" } },
                    })),
                    persist_row_hash: String::new(),
                },
            )
        };
        let at_ms = e2::ms(base());
        let v1_unheld = e2::community_voices(&roster("never landed"), 1, None, at_ms);
        let v1_id = crate::federation::edition2::names::RowId::of_statement(&v1_unheld[0])
            .expect("a roster statement has a row id");
        let v2 = e2::community_voices(&roster("version two"), 2, Some(&v1_id), at_ms);
        let v2_id = crate::federation::edition2::names::RowId::of_statement(&v2[0])
            .expect("a roster statement has a row id");
        // v2 itself waits on its unheld predecessor; its statements are kept.
        let _ = e2::put_voices(d, &v2).await;
        let mut shape = lic("probation", 3);
        shape.attestation_envelope["refs"] = serde_json::json!({ "head": [2, [-16, v2_id.hex()]] });
        let counted = e2::counted_row_of(&shape, &e2::seed_of(&shape.attesting_key_id));
        let mut out = e2::put_signed(d, &counted).await.unwrap_or_else(|e| {
            panic!("[{tag}] I2630: a head whose version 1 is not held waits, refused: {e}")
        });
        for v in e2::voices_of(&counted, &[k[1].as_str(), k[2].as_str()]) {
            out = e2::put_statement(d, &v)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] I2630: a voice over it, refused: {e}"));
        }
        assert!(
            matches!(out, StatementOutcome::Pending { .. }),
            "[{tag}] I2630: a head whose version 1 is not held waits, got {out:?}"
        );
        assert!(
            d.get_attestation(&counted.attestation_id)
                .await
                .unwrap()
                .is_none(),
            "[{tag}] I2630: a head whose version 1 is not held lands no typed row"
        );
    }

    /// **I6930 (LINEAGE-L6b (c); CC 2.4.1.1, Kernel 11-24) — a founder
    /// issues at the head its licence names.** A `founder_only` affiliation
    /// founded by a; two widenings naming v1 make two tips: x (a member) at
    /// T1, y (a FOUNDER) at T2. y's licence naming T2 is the affiliation's
    /// own act (`Authority`); the same licence naming T1, where y holds no
    /// founder seat, is not. Red on the founders folded at the signed
    /// instant (y, a founder by then, issued at T1 too).
    pub async fn i6930_a_founder_issues_at_the_head_it_names(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::admission::{
            licensure_issuance_at, resolve_licensure_authority, LicensureIssuance,
        };
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::room_roster_authority_invariants::bodies::{consent, head_of};
        use crate::federation::types::CommunityMembershipWidening;
        let (aff, k) = affiliation(
            d,
            &format!("{tag}-fo"),
            consensus_protocol::FOUNDER_ONLY,
            &["a", "b"],
            1,
            None,
        )
        .await;
        let [x, y, holder] = ["x", "y", "holder"].map(|n| format!("{tag}-{n}"));
        for n in [&x, &y, &holder] {
            crate::federation::licensure_chain_invariants::bodies::reg(
                d,
                n,
                &[identity_type::USER],
            )
            .await;
        }
        let v1 = head_of(d, &aff).await.expect("I6930: the founding version");
        let widening = |m: &str, role: Option<&str>| CommunityMembershipWidening {
            community_key_id: aff.clone(),
            member_key_id: m.to_owned(),
            joined_at: base() - Duration::minutes(3),
            effective_at: base() - Duration::minutes(3),
            role: role.map(str::to_owned),
            persist_row_hash: String::new(),
        };
        let mut tips = Vec::new();
        for (m, role) in [(&x, None), (&y, Some("founder"))] {
            let w = widening(m, role);
            consent(d, &k[0], &w).await;
            let voices = e2::community_widening_voices(
                &ts::sign_community_membership_widening(&k[0], w),
                Some(&v1),
            );
            let id = e2::row_id_of(&voices[0]);
            let r = e2::put_voices(d, &voices).await;
            assert!(
                matches!(r, Ok(StatementOutcome::Row { .. })),
                "[{tag}] I6930 premise: the widening of {m} lands: {r:?}"
            );
            tips.push(id);
        }
        let (t1, t2) = (tips[0], tips[1]);
        let authority = resolve_licensure_authority(d, &key_id(&aff))
            .await
            .expect("I6930: the authority");
        let issued_at = |head: &crate::federation::edition2::names::RowId| {
            let mut shape = licence(
                &y,
                &holder,
                &aff,
                "issued",
                None,
                base() - Duration::minutes(1),
            );
            shape.attestation_envelope["refs"] =
                serde_json::json!({ "head": [2, [-16, head.hex()]] });
            e2::row_of(&shape, &e2::seed_of(&shape.attesting_key_id))
        };
        let at_t2 = issued_at(&t2);
        assert!(
            matches!(
                licensure_issuance_at(d, &authority, &at_t2, base())
                    .await
                    .unwrap(),
                LicensureIssuance::Authority
            ),
            "[{tag}] I6930: naming T2, y holds the founder seat: the affiliation's act"
        );
        let at_t1 = issued_at(&t1);
        assert!(
            !matches!(
                licensure_issuance_at(d, &authority, &at_t1, base())
                    .await
                    .unwrap(),
                LicensureIssuance::Authority
            ),
            "[{tag}] I6930: naming T1, y holds no founder seat there"
        );
    }

    /// **I6931 (LINEAGE-L6b (d); CC 4.4.3.12, Kernel 11-24) — the deciding
    /// seats are read at the head the change names.** A `founder_only`
    /// affiliation founded by a, with member b; tips T1 (x, a member) and T2
    /// (y, a FOUNDER), both naming v1. A removal of b voiced by a alone
    /// naming T1 meets ONE deciding seat there (a): the one-seat floor asks a
    /// countersign from outside the seat, and there is none: it does not
    /// land. The same removal naming T2 meets two seats (a, y): no floor; it
    /// lands. Red on the roster folded at the instant (a and y both
    /// founders: no floor for the T1 removal either).
    pub async fn i6931_deciding_seats_are_read_at_the_named_head(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::room_roster_authority_invariants::bodies::{consent, head_of};
        use crate::federation::types::{
            CommunityMembershipRevocation, CommunityMembershipWidening, RevocationLeaf,
        };
        let (aff, k) = affiliation(
            d,
            &format!("{tag}-ds"),
            consensus_protocol::FOUNDER_ONLY,
            &["a", "b"],
            1,
            None,
        )
        .await;
        let [x, y] = ["x", "y"].map(|n| format!("{tag}-{n}"));
        for n in [&x, &y] {
            crate::federation::licensure_chain_invariants::bodies::reg(
                d,
                n,
                &[identity_type::USER],
            )
            .await;
        }
        let v1 = head_of(d, &aff).await.expect("I6931: the founding version");
        let mut tips = Vec::new();
        for (m, role) in [(&x, None), (&y, Some("founder"))] {
            let w = CommunityMembershipWidening {
                community_key_id: aff.clone(),
                member_key_id: m.clone(),
                joined_at: base() - Duration::minutes(3),
                effective_at: base() - Duration::minutes(3),
                role: role.map(str::to_owned),
                persist_row_hash: String::new(),
            };
            consent(d, &k[0], &w).await;
            let voices = e2::community_widening_voices(
                &ts::sign_community_membership_widening(&k[0], w),
                Some(&v1),
            );
            let id = e2::row_id_of(&voices[0]);
            let r = e2::put_voices(d, &voices).await;
            assert!(
                matches!(r, Ok(StatementOutcome::Row { .. })),
                "[{tag}] I6931 premise: the widening of {m} lands: {r:?}"
            );
            tips.push(id);
        }
        let removal = |head: &crate::federation::edition2::names::RowId, mins: i64| {
            let at = base() - Duration::minutes(mins);
            e2::community_revocation_voices(
                &ts::sign_community_membership_revocation(
                    &k[0],
                    CommunityMembershipRevocation {
                        community_key_id: aff.clone(),
                        removed_identity_key_id: k[1].clone(),
                        removed_at: at,
                        effective_at: at,
                        reason: None,
                        witness_set: vec![],
                        persist_row_hash: String::new(),
                        leaf: RevocationLeaf::Removal,
                    },
                ),
                Some(head),
            )
        };
        let r = e2::put_voices(d, &removal(&tips[0], 2)).await;
        assert!(
            !matches!(r, Ok(StatementOutcome::Row { .. })),
            "[{tag}] I6931: at T1 a is the one deciding seat: no outside countersign, no \
             removal: {r:?}"
        );
        let r = e2::put_voices(d, &removal(&tips[1], 1)).await;
        assert!(
            matches!(r, Ok(StatementOutcome::Row { .. })),
            "[{tag}] I6931: at T2 a and y are two seats: no floor, the removal lands: {r:?}"
        );
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
            crate::federation::licensure_chain_invariants::bodies::reg(
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
        // v62.0.0 (CC rc20 2.4 / 2.6.1.9, CIRISPersist#1274) — one member's
        // signature is SHORT of the quorum: no longer testimony, it waits (a
        // typed retryable refusal; nothing is stored). Until v62 this leg
        // asserted the row was admitted as testimony. CC 2.4: "a row short of
        // its protocol by signatures alone is not refused; it waits".
        // Kills: a lone member standing for a quorum protocol.
        // v62.0.0 (CC 2.4.1.3): a counted licence short of its protocol is
        // HELD (`Pending`): its voices are kept, no typed row lands.
        let short = |row: &Attestation| {
            let row = row.clone();
            async move {
                match crate::federation::licensure_chain_invariants::bodies::offer(d, &row).await {
                    Ok((held, Some(StatementOutcome::Pending { .. }))) => {
                        assert!(
                            d.get_attestation(&held.attestation_id)
                                .await
                                .unwrap()
                                .is_none(),
                            "[{tag}] I1880: a held row writes no typed row"
                        );
                        1usize
                    }
                    other => panic!("[{tag}] I1880: short of the quorum must wait, got {other:?}"),
                }
            }
        };
        let lone = lic("revoked", 30);
        assert_eq!(
            short(&lone).await,
            1,
            "[{tag}] I1880: one member's signature"
        );
        assert!(
            d.get_attestation(&lone.attestation_id)
                .await
                .unwrap()
                .is_none(),
            "[{tag}] I1880: nothing stored"
        );
        // A stranger's cosignature counts for nothing. Kills: counting
        // scrubs outside the roster.
        // v62.0.0: the stranger's voice is not counted (a non-member of the
        // roster at the named head); held or refused, no typed row lands.
        let stray = cosigned(lic("suspended", 25), &[&stranger]);
        let stray_id =
            match crate::federation::licensure_chain_invariants::bodies::offer(d, &stray).await {
                Ok((offered, _)) => offered.attestation_id,
                Err(_) => stray.attestation_id.clone(),
            };
        assert!(
            d.get_attestation(&stray_id).await.unwrap().is_none(),
            "[{tag}] I1880: a non-member's cosignature does not make a quorum"
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
            crate::federation::admission::row_was_issued_under_authority(d, &quorum, &key_id(&aff))
                .await
                .unwrap(),
            "[{tag}] I1214: a quorum-cosigned licence is the affiliation's"
        );
        assert_eq!(
            status_set_for(d, &key_id(&holder), &key_id(&aff), Utc::now())
                .await
                .unwrap(),
            BTreeSet::from([LicensureStatus::Issued]),
            "[{tag}] I1214: the lone `revoked` binds nobody; the quorum's `issued` stands"
        );
        let listed: BTreeSet<String> =
            crate::federation::admission::licences_issued_under(d, &key_id(&aff))
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
            !crate::federation::admission::emitter_resolves_to_authority(
                d,
                &key_id(&k[0]),
                &key_id(&aff)
            )
            .await
            .unwrap(),
            "[{tag}] I1214: no single member resolves to a quorum authority"
        );
        // I1880 — a `founder_only` authority is unchanged: a non-founder
        // member's row naming no delegation is still testimony, admitted.
        let (fo, fk) = affiliation(
            d,
            &format!("{tag}-fo"),
            consensus_protocol::FOUNDER_ONLY,
            &["a", "b", "c"],
            1,
            None,
        )
        .await;
        let testimony = must_put(
            d,
            &classed(licence(
                &fk[1],
                &holder,
                &fo,
                "issued",
                None,
                now - Duration::minutes(10),
            )),
            "I1880 founder_only testimony",
        )
        .await;
        assert!(
            !crate::federation::admission::row_was_issued_under_authority(
                d,
                &testimony,
                &key_id(&fo)
            )
            .await
            .unwrap(),
            "[{tag}] I1880: under founder_only a non-founder's row stays testimony"
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
        crate::federation::licensure_chain_invariants::bodies::reg(
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
        // v62.0.0 (CC 4.4.3.12, V1b): an officer appointment naming the
        // affiliation is a COUNTED `self:delegates_to` over the roster head it
        // names (`offer` restates it); it lands at the affiliation's protocol,
        // and the SEAT stands only with the officer's own
        // `membership:acceptance` naming it (`seat`).
        let seat = |officer: String, appointment: Attestation| {
            let aff = aff.clone();
            async move {
                let mut answered = appointment.clone();
                answered.cohort_scope = "community".to_owned();
                answered.attestation_envelope["community_key_id"] = serde_json::json!(aff.clone());
                let acceptance =
                    crate::federation::membership_acceptance::test_support::acceptance_row(
                        &officer,
                        &answered,
                        now - Duration::hours(5),
                    );
                crate::federation::edition2::fixture_switch::put_signed(d, &acceptance)
                    .await
                    .expect("the officer accepts the seat");
            }
        };
        // (1) A lone member's appointment: held (Pending), it roots nothing.
        let o1 = officer(d, tag, "o1").await;
        let lone = match crate::federation::licensure_chain_invariants::bodies::offer(
            d,
            &appoint(&o1, false, true, 6),
        )
        .await
        {
            Ok((held, Some(StatementOutcome::Pending { .. }))) => held,
            other => panic!("[{tag}] I1215(1): a lone member's appointment is held, got {other:?}"),
        };
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
        seat(o2.clone(), root.clone()).await;
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
            crate::federation::admission::emitter_resolves_to_authority(
                d,
                &key_id(&o2),
                &key_id(&aff)
            )
            .await
            .unwrap(),
            "[{tag}] I1215(2): the quorum's officer resolves to the authority"
        );
        // (3) Cosigned but naming no community: not a root. Kills: dropping
        // the community check on the root edge.
        let o3 = officer(d, tag, "o3").await;
        // v62.0.0: an edge naming no affiliation is an authored edge (no
        // second-signer role), so it goes alone.
        let unnamed = must_put(d, &appoint(&o3, false, false, 6), "I1215 unnamed").await;
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
        seat(o5.clone(), deputising.clone()).await;
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
        // The key-at-now reading agrees: o6 resolves to the affiliation
        // through the quorum's deputising root; o4 (under a root without
        // sub_delegation) does not. Kills: the onward reach not reported.
        use crate::federation::admission::emitter_resolves_to_authority as resolves;
        assert!(
            resolves(d, &key_id(&o6), &key_id(&aff))
                .await
                .expect("resolves"),
            "[{tag}] I1215(4): o6 resolves through the quorum's onward chain"
        );
        assert!(
            !resolves(d, &key_id(&o4), &key_id(&aff))
                .await
                .expect("resolves"),
            "[{tag}] I1215(4): o4 does not"
        );
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
        seat(o7.clone(), root_b.clone()).await;
        let mut w_lone = edge(&k[0], &o7, &[], now - Duration::minutes(50), &[]);
        w_lone.attestation_type = attestation_type::WITHDRAWS.to_owned();
        let w_lone = with(
            w_lone,
            "references_attestation_id",
            serde_json::json!(root_b.attestation_id),
        );
        // v62.0.0: held or refused, a lone retraction lands nothing.
        let _ = crate::federation::licensure_chain_invariants::bodies::offer(d, &w_lone).await;
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
        // v62.0.0: the quorum's retraction names the affiliation, so it is
        // counted at its protocol like the appointment.
        let w_q = with(w_q, "community_id", names.clone());
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
            crate::federation::admission::row_was_issued_under_authority(d, &early, &key_id(&aff))
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
        crate::federation::licensure_chain_invariants::bodies::reg(
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
        // v62.0.0 (E2-fix3; CC 2.7.3) — an arm that reads another row (the
        // charter) HOLDS the licence with the gate's message; one on the
        // row's own bytes refuses it. Either way the gate's message is read.
        let refused =
            |r: Result<Attestation, Error>, reason: &str, what: &str| match refusal_message(&r) {
                Some(m) => assert!(
                    m.starts_with(&format!("{LICENCE_AUDIENCE_REFUSED}: {reason}:")),
                    "[{tag}] {what}: {m}"
                ),
                None => panic!(
                    "[{tag}] {what}: expected {LICENCE_AUDIENCE_REFUSED}: {reason}, got {r:?}"
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
            crate::federation::licensure_chain_invariants::bodies::reg(
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
        // v62.0.0 (E2-fix3; CC 2.7.3) — an arm that reads another row (the
        // original a re-emission names) HOLDS the licence with the gate's
        // message; one on the row's own bytes refuses it.
        let refused =
            |r: Result<Attestation, Error>, reason: &str, what: &str| match refusal_message(&r) {
                Some(m) => assert!(
                    m.starts_with(&format!("{LICENCE_AUDIENCE_REFUSED}: {reason}:")),
                    "[{tag}] {what}: {m}"
                ),
                None => panic!("[{tag}] {what}: expected {reason}, got {r:?}"),
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
        // Re-emitting a held licence about ANOTHER subject, or under ANOTHER
        // authority: each alone is not this licence. Kills: the authority OR
        // subject test weakened to AND.
        let about_reader = must_put(
            d,
            &placed(
                with(
                    licence(&k[0], &reader, &aff, "issued", None, at),
                    "partner_record",
                    payload("lic-reader", "community_plus", 1, &[]),
                ),
                "self",
                &[],
            ),
            "I1217 a licence about the reader",
        )
        .await;
        refused(
            put(
                d,
                &re(4, "self", &[&holder, &reader], &about_reader.attestation_id),
            )
            .await,
            aud::RE_EMISSION_TARGET_UNKNOWN,
            "I1217 a re-emission of a licence about another subject",
        );
        let under_key = must_put(
            d,
            &with(
                licence(&k[1], &holder, &k[1], "issued", None, at),
                "partner_record",
                payload("lic-key", "community_plus", 1, &[]),
            ),
            "I1217 a licence under another (key) authority",
        )
        .await;
        refused(
            put(
                d,
                &re(4, "self", &[&holder, &reader], &under_key.attestation_id),
            )
            .await,
            aud::RE_EMISSION_TARGET_UNKNOWN,
            "I1217 a re-emission of a licence under another authority",
        );
        // Another status, same payload. Kills: the status OR payload test
        // weakened to AND.
        let suspended = placed(
            with(
                with(
                    licence(
                        &k[0],
                        &holder,
                        &aff,
                        "suspended",
                        None,
                        at + Duration::minutes(2),
                    ),
                    "partner_record",
                    payload("lic-re", "community_plus", 4, &[]),
                ),
                LICENCE_RE_EMITS_MEMBER,
                serde_json::json!(original.attestation_id),
            ),
            "self",
            &[&holder, &reader],
        );
        refused(
            put(d, &suspended).await,
            aud::RE_EMISSION_DIVERGES,
            "I1217 a re-emission carrying another status",
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
        crate::federation::licensure_chain_invariants::bodies::reg(
            d,
            &stranger,
            &[identity_type::USER],
        )
        .await;
        let at = base() - Duration::minutes(30);
        let named = |row: Attestation| placed(row, "federation", &[&holder]);
        // v62.0.0 (LF-fix1; CIRISPersist#596 item 1) — the board's adverse
        // row below is a `revocation:{entity_type}:{reason}` about a KEYED
        // subject: the typed revocation plane, whose door asks the revoker's
        // `slash` conferral from a root THIS node trusts
        // (`check_revocation_authority`). So the runner gives the backend a
        // node identity, the node holds a ROOTED trust root (W1b), and the
        // root confers `slash` on the board with the board's own voice
        // (`put_conferral`). Postcondition: the conferral reaches the root
        // through this node, so a fixture that confers nothing fails here.
        {
            use crate::federation::admission::DELEGATION_SCOPE_SLASH;
            use crate::federation::edition2::fixture_switch as e2;
            let node = d.node_key_id().unwrap_or_else(|| {
                panic!("[{tag}] I1218: the runner gives the backend a node identity")
            });
            let r = e2::rooted_trust_root(
                d,
                &crate::federation::edition2::fixture_genesis::HOLDER_SEEDS,
                "quorum:2/3",
            )
            .await;
            crate::federation::edition2::fixture_trust_root::put_conferral(
                d,
                &r,
                &board,
                &[DELEGATION_SCOPE_SLASH],
            )
            .await
            .unwrap_or_else(|e| panic!("[{tag}] I1218: the root confers slash on the board: {e}"));
            let rooted = crate::federation::trust_root::capability_roots_to_trusted_root(
                d,
                &node,
                &e2::kid(&board),
                DELEGATION_SCOPE_SLASH,
                crate::host::clock::now(),
            )
            .await
            .expect("capability_roots_to_trusted_root");
            assert!(
                rooted.as_ref().is_some_and(|g| g.root_key_id == r.lineage),
                "[{tag}] I1218 precondition: the board's slash roots at {} through this node: \
                 {rooted:?}",
                r.lineage
            );
        }
        let lic = must_put(
            d,
            &named(licence(&board, &holder, &board, "suspended", None, at)),
            "I1218 the licence",
        )
        .await;
        // v62.0.0 (E2-fix3) — a `revocation:{entity_type}:{reason}` payload
        // carries its `revoked_at` and `effective_at` (both required, CC
        // rc21; `edition2::payloads`).
        let revoked = crate::federation::licensure_chain_invariants::bodies::rfc3339(at);
        // v62.0.0 (LF-fix1) — a revocation about a keyed subject is the typed
        // revocation plane's (`edition2::typed`): it lands as the
        // [`Revocation`](crate::federation::Revocation) it states, held under
        // the subject's key digest, and its statement; no row of the
        // attestation plane carries its id. So the witness reads the door's
        // outcome and the plane, not `get_attestation`.
        let (adverse, adverse_out) = crate::federation::licensure_chain_invariants::bodies::offer(
            d,
            &named(with(
                with(
                    with(
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
                    ),
                    "revoked_at",
                    revoked.clone(),
                ),
                "effective_at",
                revoked,
            )),
        )
        .await
        .unwrap_or_else(|e| panic!("[{tag}] I1218 a revocation row about the holder: {e}"));
        if !matches!(adverse_out, Some(StatementOutcome::Row { .. })) {
            let why = match &adverse_out {
                Some(StatementOutcome::Pending { row_id, .. }) => {
                    crate::federation::edition2::fold::why_held(d, row_id)
                        .await
                        .unwrap()
                        .map(|h| format!("{}: {}", h.reason, h.detail))
                }
                _ => None,
            };
            panic!(
                "[{tag}] I1218: the board's revocation must conclude (its slash is conferred): \
                 {adverse_out:?}, held {why:?}"
            );
        }
        let holder_digest = {
            let rec = d
                .lookup_public_key(&key_id(&holder))
                .await
                .unwrap()
                .expect("the holder's key is held");
            crate::federation::key_digest::Sha256Ed25519Raw::from_pubkey_base64(
                &rec.pubkey_ed25519_base64,
            )
            .expect("the holder's Ed25519 half")
            .to_hex()
        };
        assert!(
            revocation_held(d, &holder_digest, &adverse.attestation_id).await,
            "[{tag}] I1218: the revocation is held on its plane, under the holder's key"
        );
        let benign = must_put(
            d,
            &named(with(
                licence(&board, &holder, &board, "issued", None, at),
                "dimension",
                // v62 (LF-fix1): a REGISTERED family outside the adverse
                // classes (`need:{domain}:{kind}`); `endorsement:` resolves
                // to no registered family and the edition-2 door refuses it.
                serde_json::json!("need:identity:handle:v1"),
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
        // v62.0.0 (LF-fix1; wave GC1, CC 2.7.3) — the verdict over a HELD
        // target reads that other row, so the door HOLDS a withdraws its
        // issuer has no standing for (`withdraws_not_admitted`) instead of
        // refusing it: `refused_or_held` reads the gate's token either way,
        // and `put` reports that no row was stored.
        let e = refused_or_held(
            put(d, &withdraw(&holder, &lic.attestation_id, 20)).await,
            "I1218 the subject withdraws its licence",
        );
        assert_eq!(
            e, "federation_withdraws_not_admitted",
            "[{tag}] I1218: a subject's withdraws against licensure"
        );
        assert!(
            d.get_attestation(&lic.attestation_id)
                .await
                .unwrap()
                .is_some(),
            "[{tag}] I1218: the licence stands"
        );
        // The revocation: its subject's withdraws concludes nothing, and the
        // revocation stands (CC 2.4.1.1: an entity revocation is withdrawn by
        // nobody). The typed plane holds no attestation row under the
        // statement's id; v62.0.0 (LF-fix2, P5) the withdraws gate reads the
        // statement store under it. v62.0.0 (KR-fix20; the count always wins)
        // — the target is held and never withdrawn, so the door REFUSES the
        // withdraws by name (`withdraws_never_retracts`) and keeps nothing: no
        // fold record, no statement, nothing in the held set (it was held
        // `withdraws_not_admitted` for ever before).
        {
            use crate::federation::edition2::fold;
            // The held set as a full re-fold leaves it, before the offer.
            fold::refold_all(d)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] I1218: refold_all: {e:?}"));
            let held_before = fold::held_rows(d, None, fold::MAX_HELD_PAGE).await.unwrap();
            let w = withdraw(&holder, &adverse.attestation_id, 20);
            let refusal = crate::federation::licensure_chain_invariants::bodies::offer(d, &w)
                .await
                .expect_err("I1218: a subject's withdraws of the revocation is refused");
            assert!(
                matches!(
                    &refusal,
                    Error::MalformedRow { reason, .. }
                        if *reason == crate::federation::malformed_row::WITHDRAWS_NEVER_RETRACTS
                ),
                "[{tag}] I1218: refused withdraws_never_retracts: {refusal:?}"
            );
            fold::refold_all(d)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] I1218: refold_all: {e:?}"));
            let held_after = fold::held_rows(d, None, fold::MAX_HELD_PAGE).await.unwrap();
            assert_eq!(
                held_after.iter().map(|h| h.row_id).collect::<Vec<_>>(),
                held_before.iter().map(|h| h.row_id).collect::<Vec<_>>(),
                "[{tag}] I1218: nothing of the refused withdraws is held"
            );
        }
        assert!(
            revocation_held(d, &holder_digest, &adverse.attestation_id).await,
            "[{tag}] I1218: the revocation stands after its subject's withdraws"
        );
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
        let e = refused_or_held(
            put(d, &recon(&stranger, serde_json::json!({}), 14)).await,
            "I1218 a stranger files",
        );
        assert_eq!(
            e, "federation_delegated_scope_unauthorized",
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
        let e = refused_or_held(
            put(
                d,
                &recon(&holder, serde_json::json!({ "outcome": "reversed" }), 9),
            )
            .await,
            "I1218 the licensee rules",
        );
        assert_eq!(
            e, "federation_delegated_scope_unauthorized",
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
            // v62.0.0 (BIND-1; CC rc22 rule `owner-binding`) — the
            // organisation on the bond is the one `on_behalf_of` names; the
            // placement (`community_id`) is only where the row is held, and
            // the producer signs no `kind`.
            let mut env = serde_json::json!({
                "dimension": owner_binding::DIMENSION,
                "delegation_purpose": owner_binding::PURPOSE,
                "scope": [ds::INFRA_SERVE],
            });
            if let Some(c) = community {
                env[crate::federation::admission::ON_BEHALF_OF_FIELD] = serde_json::json!(c);
            }
            let mut row = crate::federation::admission::steward_liveness_test_support::signed_row(
                &crate::federation::edition2::fixture_switch::seed_of(steward),
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
        // v62.0.0 (E2-fix3; CC 2.7.3) — held with the gate's message when
        // the arm reads another row (the affiliation), refused otherwise.
        let refused =
            |r: Result<Attestation, Error>, reason: &str, what: &str| match refusal_message(&r) {
                Some(m) => assert!(
                    m.starts_with(&format!("{OWNER_BINDING_AFFILIATION_REFUSED}: {reason}:")),
                    "[{tag}] {what}: {m}"
                ),
                None => panic!("[{tag}] {what}: expected {reason}, got {r:?}"),
            };
        // v62.0.0 (CC ruling (a), V1b): an owner binding naming an affiliation
        // is COUNTED: the owner's statement, the bound key's, and the members'
        // voices at the affiliation's protocol over the `refs.head` it names.
        // Short of that it is HELD (`Pending`, no typed row).
        let held = |r: Result<Attestation, Error>, what: &str| match r {
            Err(Error::InvalidArgument(m))
                if m.starts_with(
                    crate::federation::licensure_chain_invariants::bodies::PENDING,
                ) => {}
            other => panic!("[{tag}] {what}: expected a held (Pending) binding, got {other:?}"),
        };
        // Signed by one member only (plus the bound key): held. Kills:
        // dropping the cosign check.
        held(
            put(d, &binding(&k[0], &node("n1"), Some(&aff))).await,
            "I1219 an organisation's binding signed by one member",
        );
        assert_eq!(
            crate::federation::admission::affiliation_of_binding(d, &key_id(&node("n1")))
                .await
                .unwrap(),
            None,
            "[{tag}] I1219: a held binding names no affiliation on the bond"
        );
        // Cosigned under the protocol: admitted, and the fold names it.
        must_put(
            d,
            &cosigned(binding(&k[0], &node("n2"), Some(&aff)), &[&k[1]]),
            "I1219 an organisation's binding cosigned 2 of 3",
        )
        .await;
        assert_eq!(
            crate::federation::admission::affiliation_of_binding(d, &key_id(&node("n2")))
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
            crate::federation::admission::affiliation_of_binding(d, &key_id(&node("n3")))
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
            // v62.0.0 (BIND-1) — the edition-2 gate's appended token.
            obr::OWNER_BINDING_NOT_AN_AFFILIATION,
            "I1219 a binding naming a plain community",
        );
        // An affiliation this node does not hold yet: the binding WAITS
        // (edition 2 holds it Pending; no longer `affiliation_not_held`).
        held(
            put(d, &binding(&k[0], &node("n5"), Some("no-such-org"))).await,
            "I1219 a binding naming an unknown community",
        );
        // Signed beyond W, cosigned by a quorum that still holds at receipt:
        // admitted (W binds only a signer set that has lost standing). Kills:
        // the W gate refusing every stale binding, or refusing a still-valid
        // one.
        ts::register_hybrid_key_as(d, &node("n6"), &node("n6"), identity_type::NODE).await;
        let mut stale = binding(&k[0], &node("n6"), Some(&aff));
        stale.asserted_at = base() - Duration::days(4);
        stale.scrub_timestamp = stale.asserted_at;
        ts::reseal(&mut stale);
        let stale_row = must_put(
            d,
            &cosigned(stale, &[&k[1]]),
            "I1219 a binding signed four days ago, its quorum still standing",
        )
        .await;
        // A retraction of the binding ends it only when its GRANTER signs it.
        // Kills: the retraction match inverted. v62.0.0: a withdraws names
        // its target (`refs.target`); a target-less "bare" withdraws is
        // refused by Verify's reader, so the retraction names the binding.
        let bare = |by: &str| {
            crate::federation::edition2::fixture_switch::composer_of(
                attestation_type::WITHDRAWS,
                &stale_row,
                by,
            )
        };
        let on_bond = || async {
            crate::federation::admission::affiliation_of_binding(d, &key_id(&node("n6")))
                .await
                .unwrap()
        };
        assert_eq!(
            on_bond().await,
            Some(aff.clone()),
            "[{tag}] I1219: n6 on the bond"
        );
        // Another key's withdraws: held or refused, it does not end the binding.
        let _ = crate::federation::licensure_chain_invariants::bodies::offer(d, &bare(&k[2])).await;
        assert_eq!(
            on_bond().await,
            Some(aff.clone()),
            "[{tag}] I1219: another key's bare retraction does not end the binding"
        );
        let retraction = must_put(d, &bare(&k[0]), "I1219 the granter's bare retraction").await;
        // The STORED instant (postgres keeps microseconds).
        let w_at = d
            .get_attestation(&retraction.attestation_id)
            .await
            .unwrap()
            .expect("stored")
            .asserted_at;
        // In force up to, not at, the retraction's instant (half-open).
        // Kills: the end bound read inclusively.
        let in_force = |t| async move {
            crate::federation::admission::owner_bindings_in_force_at(d, &key_id(&node("n6")), t)
                .await
                .unwrap()
                .len()
        };
        assert_eq!(
            in_force(w_at - Duration::milliseconds(1)).await,
            1,
            "[{tag}] I1219: in force just before its granter's retraction"
        );
        assert_eq!(
            in_force(w_at).await,
            0,
            "[{tag}] I1219: not in force at the retraction's instant"
        );
        assert_eq!(
            on_bond().await,
            None,
            "[{tag}] I1219: the granter's bare retraction ends it"
        );
        // A general delegation onto a node naming a community is not an
        // owner-binding: the fold does not read it. Kills: the owner-binding
        // filter weakened from AND to OR.
        let mut general = crate::federation::admission::steward_liveness_test_support::signed_row(
            &crate::federation::edition2::fixture_switch::seed_of(&pk[0]),
            &node("n3"),
            attestation_type::DELEGATES_TO,
            // v62.0.0 (BIND-1) — naming the community the way an owner
            // binding names its organisation (`on_behalf_of`).
            serde_json::json!({ "scope": [ds::INFRA_SERVE], "on_behalf_of": plain }),
        );
        general.asserted_at = base() - Duration::minutes(4);
        general.scrub_timestamp = general.asserted_at;
        ts::reseal(&mut general);
        must_put(d, &general, "I1219 a general delegation naming a community").await;
        assert_eq!(
            crate::federation::admission::affiliation_of_binding(d, &key_id(&node("n3")))
                .await
                .unwrap(),
            None,
            "[{tag}] I1219: a general delegation names no affiliation on the bond"
        );
        // Two bindings in force by the same steward, naming two
        // affiliations: the fold names the smaller id, whichever was read
        // first (the larger one is the older row). Kills: the minimum
        // inverted or dropped.
        let (aff2, k2) = affiliation(
            d,
            &format!("{tag}-zz"),
            consensus_protocol::MAJORITY,
            &["a", "b", "c"],
            1,
            None,
        )
        .await;
        assert!(aff < aff2, "the witness needs aff < aff2");
        let mut older = binding(&k[0], &node("n2"), Some(&aff2));
        older.asserted_at = base() - Duration::minutes(6);
        older.scrub_timestamp = older.asserted_at;
        ts::reseal(&mut older);
        must_put(
            d,
            &cosigned(older, &[&k2[0], &k2[1]]),
            "I1219 the steward's older binding naming the second affiliation",
        )
        .await;
        assert_eq!(
            crate::federation::admission::affiliation_of_binding(d, &key_id(&node("n2")))
                .await
                .unwrap(),
            Some(aff.clone()),
            "[{tag}] I1219: two affiliations on the bond, the smaller id is named"
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
            crate::federation::edition2::fixture_switch::put_signed(d, &r)
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
        // The refusal says which defect it is. Kills: the repeat / order
        // wording swapped.
        let says = |v: &[&str]| check_partner_record_sets(&rec(v)).unwrap_err().to_string();
        assert!(says(&["a", "a"]).contains("repeats"), "a repeat is named");
        assert!(
            says(&["b", "a"]).contains("is out of order after"),
            "an inversion is named"
        );
    }

    /// **I1225** (pure) — W's boundary: a row signed exactly W ago is inside
    /// the window; one a nanosecond older is outside. Kills: the bound read
    /// inclusively.
    #[test]
    fn i1225_w_is_a_closed_window() {
        use crate::federation::self_roster::{
            outside_past_freshness_window, PAST_FRESHNESS_W_SECS,
        };
        let now = chrono::Utc::now();
        let w = chrono::Duration::seconds(PAST_FRESHNESS_W_SECS);
        assert!(
            !outside_past_freshness_window(now - w, now),
            "exactly W ago"
        );
        assert!(
            outside_past_freshness_window(now - w - chrono::Duration::nanoseconds(1), now),
            "a nanosecond older"
        );
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
        i1223_promotion_re_runs_the_payload_gate,
        i1223_sqlite,
        i1223_postgres,
        "i1223"
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
        i2630_a_majority_counts_at_its_named_head,
        i2630_sqlite,
        i2630_postgres,
        "i2630"
    );
    on_both_backends!(
        i6930_a_founder_issues_at_the_head_it_names,
        i6930_sqlite,
        i6930_postgres,
        "i6930"
    );
    on_both_backends!(
        i6931_deciding_seats_are_read_at_the_named_head,
        i6931_sqlite,
        i6931_postgres,
        "i6931"
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
    // v62.0.0 (LF-fix1) — I1218's revocation leg reads this node's own trust
    // root (`check_revocation_authority`), so its runners give the backend a
    // node identity: a `node` key E0 minted, live as an edition-2
    // `key:record`. Same body on both backends.
    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1218_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let tag = format!("i1218-{}", suffix());
        let node = crate::federation::edition2::fixture_switch::put_key(
            &b,
            &format!("node-{tag}"),
            &[crate::federation::types::identity_type::NODE],
        )
        .await;
        b.set_node_key_id(node);
        super::bodies::i1218_licence_contest_path(&b, &tag).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1218_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let tag = format!("i1218-{}", suffix());
        let node = crate::federation::edition2::fixture_switch::put_key(
            &b,
            &format!("node-{tag}"),
            &[crate::federation::types::identity_type::NODE],
        )
        .await;
        b.set_node_key_id(node);
        super::bodies::i1218_licence_contest_path(&b, &tag).await;
    }
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
        let client = b.checkout().await.unwrap();
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
