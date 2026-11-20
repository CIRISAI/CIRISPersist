//! v53.0.0 (CC 3.2 T6, rc7 `36432c6`) — **roster rows and the head.**
//! I450–I459.
//!
//! The conferring quorum covers a roster row with a new version; the substrate
//! never synthesises one and enforces three consequences:
//!
//! - **I450** (i) a version of a conferring family that does not reflect an
//!   effective revocation is refused `lineage_version_disagrees_with_roster_fold`
//!   naming the key; the version that drops the seat is admitted.
//! - **I451** (i) the same for a widening, and for a widening that re-roles a
//!   seat: the version must carry the seat AND its role.
//! - **I452** (i) only a witnessed lineage is judged: a family whose head names
//!   no charter takes a version the planes disagree with.
//! - **I453** the one comparison on the community arm: a revocation of a room
//!   names exactly its key until a record reflects it, and only while it is
//!   after the floor (the held head's instant) and effective at the instant.
//! - **I454** (ii) a row older than one `witness_cadence_secs` that no version
//!   covers lags the head (`lineage_head_lags_roster`, served on the witness
//!   view with its keys and instant); a younger row does not; the covering
//!   version clears it.
//! - **I455** (ii) with witnessed mode on a witness's cosign of the lagging held
//!   head is refused `lineage_head_lags_roster`; with it off the cosign is
//!   stored and the lag is still reported.
//! - **I456** (iii) the removal takes effect at its `effective_at`, before any
//!   version covers it: the fold drops the seat while the head still lists it.
//! - **I457** the accord's version needs signatures from a strict majority of
//!   its STANDING roster — two of five is short where `quorum:2/3` reads two,
//!   three is enough, and one key's two signatures count once.
//! - **I458** from disk: every version door runs consequence (i), the cosign
//!   door runs (ii), and the accord head door counts the standing majority.
//! - **I459** (ii) an authorized accord `roster_change` decision anchored on the
//!   held accord head, with its window closed, lags the head; one anchored on
//!   another head, an unauthorized one, or one whose window is open does not.
//!
//! v62.0.0 (JSON cut, wave 3, E5) — **I457 and I459 are deleted** (lead's
//! ruling 1: the accord's head is the genesis bundle in force; its standing
//! majority and roster-change decisions are bundle/2): covered by C2's I2333 (a
//! later bundle counts a strict majority) and C1's I2315 / I2316.
//!
//! v62.0.0 (JSON cut, E13) — **I450–I456 and I450b–d run on edition 2.** Every
//! roster version is a `group:roster` row of version v+1 naming the held head
//! by `refs.head` (T1.api §6), voiced by members of the prior roster; every
//! revocation and widening is a counted `membership:{stage}` row naming the
//! roster version it is counted over; a widening is preceded by the member's
//! proposal and acceptance (T1.api §3). Keys are E0 identity-refs
//! (`e2::put_key`), and every row a node signs is dated now-relative. The
//! conferring family is founded by its holders' voices (the earlier fixture
//! wrote it below the door through `put_family_local`); its charter is a
//! counted `trust:charter:v1` row voiced by every holder. I450b–d moved from
//! the earlier-form canonical room to an edition-2 trust-root-grade
//! (`infrastructure`) room (`rooted_infrastructure_room_e2`): the floor they
//! witness (the held head's instant) is the community arm's.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use ciris_crypto::composite::CompositeSigningKey;

    use crate::federation::canonical_community::root_witness_view;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::group::{GroupRecord, MembershipRecord};
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::lineage_witness::{
        LineageCosignOutcome, LineageCosignRefusal, LineageHeadCosign,
    };
    use crate::federation::membership_acceptance::test_support::{acceptance_row, proposal_row};
    use crate::federation::roster_head::{
        fold_disagreement, roster_lag, LineageRecord, LINEAGE_HEAD_LAGS_ROSTER,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::trust_root::{
        INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE, TRUST_CHARTER_DIMENSION,
    };
    use crate::federation::types::{
        attestation_type, cohort_scope, identity_type, Community, CommunityMember,
        CommunityMembershipRevocation, Family, FamilyMember, FamilyMembershipRevocation,
        FamilyMembershipWidening,
    };
    use crate::federation::{Error, FederationDirectory};

    const PROTOCOL: &str = "quorum:2/3";

    fn hours(h: i64) -> chrono::Duration {
        chrono::Duration::hours(h)
    }

    /// `t` at the millisecond the edition-2 payload carries.
    fn at_ms(t: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(t.timestamp_millis())
            .expect("an instant")
    }

    /// One composite key per signer (a seed or an identity-ref E0 minted).
    fn keys_of(signers: &[&str]) -> Vec<CompositeSigningKey> {
        signers.iter().map(|s| e2::signing_key(s)).collect()
    }

    /// `put_voices`, asserting the typed row landed.
    pub(crate) fn landed(out: Result<StatementOutcome, Error>, what: &str) {
        match out {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("{what}: expected the row to land, got {other:?}"),
        }
    }

    /// Three registered holders (`user`); returns their identity-refs.
    async fn holders(d: &dyn FederationDirectory, tag: &str) -> Vec<String> {
        let mut keys = Vec::new();
        for i in 0..3 {
            keys.push(e2::put_key(d, &format!("rh{i}-{tag}"), &[identity_type::USER]).await);
        }
        keys
    }

    /// A family founded by every holder's `group:roster` voice (version 1),
    /// naming `charter` (empty: none). Returns its identity-ref.
    async fn found(
        d: &dyn FederationDirectory,
        seed: &str,
        keys: &[String],
        charter: &str,
    ) -> String {
        let fam = e2::put_key(d, seed, &[identity_type::USER]).await;
        let founded_at = at_ms(chrono::Utc::now() - hours(24));
        let family = Family {
            prev_head_digest: String::new(),
            charter_digest: charter.to_owned(),
            family_key_id: fam.clone(),
            family_name: fam.clone(),
            members: keys
                .iter()
                .map(|k| FamilyMember {
                    key_id: k.clone(),
                    joined_at: founded_at,
                    role: Some("founder".to_owned()),
                })
                .collect(),
            founded_at,
            consensus_protocol: PROTOCOL.to_owned(),
            consensus_protocol_entrenched: true,
            dissolved_at: None,
            persist_row_hash: String::new(),
        };
        let signers: Vec<&str> = keys.iter().map(String::as_str).collect();
        let k = keys_of(&signers);
        let refs: Vec<&CompositeSigningKey> = k.iter().collect();
        landed(
            e2::put_voices(
                d,
                &e2::roster_voices(
                    &GroupRecord::Family(family),
                    1,
                    None,
                    e2::ms(founded_at),
                    &refs,
                ),
            )
            .await,
            &format!("the founding of {seed}"),
        );
        fam
    }

    /// A conferring family: its founding head names a charter (`digest`).
    async fn conferring(d: &dyn FederationDirectory, tag: &str, keys: &[String]) -> String {
        found(d, &format!("rf-{tag}"), keys, &"ab".repeat(32)).await
    }

    async fn head(d: &dyn FederationDirectory, fam: &str) -> Family {
        d.lookup_family(fam).await.unwrap().expect("family held")
    }

    /// The held head of `group` (its version's row id and number).
    async fn held(
        d: &dyn FederationDirectory,
        group: &str,
    ) -> (crate::federation::edition2::names::RowId, u64) {
        e2::held_head(d, group)
            .await
            .unwrap_or_else(|| panic!("{group}: a held edition-2 head"))
    }

    /// **The next version of a group** (T1.api §6): `record` at the held
    /// head's version + 1 naming it by `refs.head`, one voice per signer,
    /// asserted now. `Row` when it landed, `Pending` when short; an `Err` is
    /// the door's refusal (nothing written).
    pub(crate) async fn next_version(
        d: &dyn FederationDirectory,
        record: GroupRecord,
        signers: &[&str],
    ) -> Result<StatementOutcome, Error> {
        let _group = match &record {
            GroupRecord::Family(f) => f.family_key_id.clone(),
            GroupRecord::Community(c) => c.community_key_id.clone(),
        };
        let k = keys_of(signers);
        let refs: Vec<&CompositeSigningKey> = k.iter().collect();
        next_version_by(d, record, &refs).await
    }

    /// [`next_version`] voiced by `keys` (W1-fix4: a trust-root room's
    /// founders are the genesis bundle's holders, `fixture_genesis` keys).
    pub(crate) async fn next_version_by(
        d: &dyn FederationDirectory,
        record: GroupRecord,
        keys: &[&CompositeSigningKey],
    ) -> Result<StatementOutcome, Error> {
        let group = match &record {
            GroupRecord::Family(f) => f.family_key_id.clone(),
            GroupRecord::Community(c) => c.community_key_id.clone(),
        };
        let (h, v) = held(d, &group).await;
        e2::put_voices(
            d,
            &e2::roster_voices(&record, v + 1, Some(&h), e2::ms(chrono::Utc::now()), keys),
        )
        .await
    }

    /// A version of `fam` with `members`, naming the held head, voiced by
    /// two of the three holders (the head's `quorum:2/3`).
    async fn version(
        d: &dyn FederationDirectory,
        fam: &str,
        members: Vec<FamilyMember>,
        signers: &[&str],
    ) -> Result<StatementOutcome, Error> {
        let mut next = head(d, fam).await;
        next.members = members;
        next.prev_head_digest = String::new();
        next.persist_row_hash = String::new();
        next_version(d, GroupRecord::Family(next), signers).await
    }

    /// `who` leaves `fam` on their own voice, effective `at` (a self-removal
    /// needs no one else's: `roster_event_standing`).
    async fn leave(
        d: &dyn FederationDirectory,
        fam: &str,
        who: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) {
        let (h, _) = held(d, fam).await;
        let at = at_ms(at);
        let r = MembershipRecord::FamilyRemoval(FamilyMembershipRevocation {
            family_key_id: fam.to_owned(),
            removed_identity_key_id: who.to_owned(),
            removed_at: at,
            effective_at: at,
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        });
        let k = keys_of(&[who]);
        let refs: Vec<&CompositeSigningKey> = k.iter().collect();
        landed(
            e2::put_voices(d, &e2::membership_voices(&r, Some(&h), &refs)).await,
            &format!("{who} leaves {fam}"),
        );
    }

    /// `member` widened into `fam` with `role`, voiced by `signers`, after
    /// the member's own consent (the proposal by `signers[0]` and the
    /// member's acceptance, edition-2 rows: T1.api §3).
    async fn widen(
        d: &dyn FederationDirectory,
        fam: &str,
        member: &str,
        role: Option<&str>,
        at: chrono::DateTime<chrono::Utc>,
        signers: &[&str],
    ) {
        let at = at_ms(at);
        let p = proposal_row(signers[0], cohort_scope::FAMILY, fam, member, role, at);
        e2::put_signed(d, &p)
            .await
            .unwrap_or_else(|e| panic!("the proposal of {member}: {e}"));
        e2::put_signed(d, &acceptance_row(member, &p, at))
            .await
            .unwrap_or_else(|e| panic!("{member}'s acceptance: {e}"));
        let (h, _) = held(d, fam).await;
        let w = MembershipRecord::FamilyWidening(FamilyMembershipWidening {
            family_key_id: fam.to_owned(),
            member_key_id: member.to_owned(),
            joined_at: at,
            effective_at: at,
            role: role.map(str::to_owned),
            persist_row_hash: String::new(),
        });
        let k = keys_of(signers);
        let refs: Vec<&CompositeSigningKey> = k.iter().collect();
        landed(
            e2::put_voices(d, &e2::membership_voices(&w, Some(&h), &refs)).await,
            &format!("{member} widened into {fam}"),
        );
    }

    fn without(held: &Family, key: &str) -> Vec<FamilyMember> {
        held.members
            .iter()
            .filter(|m| m.key_id != key)
            .cloned()
            .collect()
    }

    fn with(held: &Family, key: &str, role: Option<&str>) -> Vec<FamilyMember> {
        let mut out = without(held, key);
        out.push(FamilyMember {
            key_id: key.to_owned(),
            joined_at: held.founded_at,
            role: role.map(str::to_owned),
        });
        out
    }

    fn disagrees(e: &Error, key: &str) -> bool {
        matches!(e, Error::LineageVersionDisagreesWithFold { keys, .. } if keys == &[key.to_owned()])
            && e.kind() == crate::federation::roster_head::LINEAGE_VERSION_DISAGREES_WITH_FOLD
    }

    /// The two holders who voice every version (the head's `quorum:2/3`).
    fn two(keys: &[String]) -> [&str; 2] {
        [keys[0].as_str(), keys[1].as_str()]
    }

    /// **I450** — (i) an effective revocation the version does not reflect.
    pub async fn i450_a_version_reflects_a_revocation(d: &dyn FederationDirectory, tag: &str) {
        let keys = holders(d, tag).await;
        let fam = conferring(d, tag, &keys).await;
        leave(d, &fam, &keys[2], chrono::Utc::now() - hours(1)).await;
        let held = head(d, &fam).await;
        let e = version(d, &fam, held.members.clone(), &two(&keys))
            .await
            .expect_err("a version still listing the leaver is refused");
        assert!(disagrees(&e, &keys[2]), "{tag} I450: {e:?}");
        assert_eq!(head(d, &fam).await, held, "{tag} I450: nothing written");
        landed(
            version(d, &fam, without(&held, &keys[2]), &two(&keys)).await,
            &format!("{tag} I450: the version dropping the seat"),
        );
    }

    /// **I451** — (i) a widening, and a re-role, the version does not reflect.
    pub async fn i451_a_version_reflects_a_widening(d: &dyn FederationDirectory, tag: &str) {
        let keys = holders(d, tag).await;
        let fam = conferring(d, tag, &keys).await;
        let joiner = e2::put_key(d, &format!("rj-{tag}"), &[identity_type::USER]).await;
        widen(
            d,
            &fam,
            &joiner,
            Some("member"),
            chrono::Utc::now() - hours(1),
            &two(&keys),
        )
        .await;
        let held = head(d, &fam).await;
        let e = version(d, &fam, held.members.clone(), &two(&keys))
            .await
            .expect_err("a version without the widened seat is refused");
        assert!(disagrees(&e, &joiner), "{tag} I451 seat: {e:?}");
        let e = version(d, &fam, with(&held, &joiner, Some("founder")), &two(&keys))
            .await
            .expect_err("the seat with another role is refused");
        assert!(disagrees(&e, &joiner), "{tag} I451 role: {e:?}");
        landed(
            version(d, &fam, with(&held, &joiner, Some("member")), &two(&keys)).await,
            &format!("{tag} I451: the covering version"),
        );
    }

    /// **I452** — (i) judges only a witnessed lineage.
    pub async fn i452_only_a_witnessed_lineage_is_judged(d: &dyn FederationDirectory, tag: &str) {
        let keys = holders(d, tag).await;
        let fam = found(d, &format!("rn-{tag}"), &keys, "").await;
        leave(d, &fam, &keys[2], chrono::Utc::now() - hours(1)).await;
        let held = head(d, &fam).await;
        assert!(
            !LineageRecord::Family(&held).is_witnessed(),
            "{tag} I452: a head naming no charter is no lineage"
        );
        landed(
            version(d, &fam, held.members.clone(), &two(&keys)).await,
            &format!("{tag} I452: not judged"),
        );
        assert!(
            roster_lag(d, &fam, chrono::Utc::now())
                .await
                .unwrap()
                .is_none(),
            "{tag} I452: and never lags"
        );
    }

    /// **I453** — the one comparison on the community arm.
    pub async fn i453_the_community_arm(d: &dyn FederationDirectory, tag: &str) {
        let mut keys = Vec::new();
        for i in 0..3 {
            keys.push(e2::put_key(d, &format!("rc{i}-{tag}"), &[identity_type::USER]).await);
        }
        let id = e2::put_key(d, &format!("rr-{tag}"), &[identity_type::USER]).await;
        let founded_at = at_ms(chrono::Utc::now() - hours(3));
        let row = Community {
            community_key_id: id.clone(),
            community_name: id.clone(),
            members: keys
                .iter()
                .map(|k| CommunityMember {
                    key_id: k.clone(),
                    joined_at: founded_at,
                    role: Some("founder".to_owned()),
                })
                .collect(),
            founded_at,
            consensus_protocol: PROTOCOL.to_owned(),
            policy_blob: None,
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            persist_row_hash: String::new(),
        };
        let signers: Vec<&str> = keys.iter().map(String::as_str).collect();
        let k = keys_of(&signers);
        let refs: Vec<&CompositeSigningKey> = k.iter().collect();
        landed(
            e2::put_voices(
                d,
                &e2::roster_voices(
                    &GroupRecord::Community(row),
                    1,
                    None,
                    e2::ms(founded_at),
                    &refs,
                ),
            )
            .await,
            &format!("{tag} I453: the room"),
        );
        let at = at_ms(chrono::Utc::now() - hours(1));
        let (h, _) = held(d, &id).await;
        let leave = MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
            community_key_id: id.clone(),
            removed_identity_key_id: keys[2].clone(),
            removed_at: at,
            effective_at: at,
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        });
        let k2 = keys_of(&[keys[2].as_str()]);
        let r2: Vec<&CompositeSigningKey> = k2.iter().collect();
        landed(
            e2::put_voices(d, &e2::membership_voices(&leave, Some(&h), &r2)).await,
            &format!("{tag} I453: the leave"),
        );
        let held = d.lookup_community(&id).await.unwrap().unwrap();
        let now = chrono::Utc::now();
        assert_eq!(
            fold_disagreement(d, LineageRecord::Community(&held), None, now)
                .await
                .unwrap(),
            vec![keys[2].clone()],
            "{tag} I453: the record still lists the leaver"
        );
        let mut reflected = held.clone();
        reflected.members.retain(|m| m.key_id != keys[2]);
        assert!(
            fold_disagreement(d, LineageRecord::Community(&reflected), None, now)
                .await
                .unwrap()
                .is_empty(),
            "{tag} I453: a record reflecting the row"
        );
        assert!(
            fold_disagreement(d, LineageRecord::Community(&held), None, at - hours(1))
                .await
                .unwrap()
                .is_empty(),
            "{tag} I453: before the row took effect"
        );
        assert!(
            fold_disagreement(d, LineageRecord::Community(&held), Some(at), now)
                .await
                .unwrap()
                .is_empty(),
            "{tag} I453: a row at or before the floor is the held head's, not this one's"
        );
    }

    /// **A charter of `fam`** carrying `extra`: a counted `trust:charter:v1`
    /// row `delegates_to(holder → fam)` (no `author`: the holders' act), its
    /// first voice by `keys[0]` and one more voice per other holder (the
    /// earlier co-scrubs). Returns its row id, the digest a version names.
    async fn put_charter(
        d: &dyn FederationDirectory,
        fam: &str,
        keys: &[String],
        extra: serde_json::Value,
    ) -> String {
        // v62.0.0 (E13 fix1) — the successor keys are named from the family's
        // SEED: `fam` is an identity-ref, and a test signer never seeds from a
        // kid (`e2::seed_of`).
        let seed = e2::seed_of(fam);
        let commitment = crate::federation::trust_root::test_pre_rotation_commitment(&[
            format!("{seed}-succ-a"),
            format!("{seed}-succ-b"),
        ])
        .unwrap();
        let mut env = serde_json::json!({
            "dimension": TRUST_CHARTER_DIMENSION,
            "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            "pre_rotation_commitment": commitment,
        });
        if let (Some(e), Some(x)) = (env.as_object_mut(), extra.as_object()) {
            for (k, v) in x {
                e.insert(k.clone(), v.clone());
            }
        }
        let mut a = ts::bare_attestation(&uuid::Uuid::new_v4().to_string(), &keys[0], fam, &env);
        a.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        let row = e2::counted_row_of(&a, &keys[0]);
        e2::put_signed(d, &row)
            .await
            .unwrap_or_else(|e| panic!("the charter of {fam}: {e}"));
        let others: Vec<&str> = keys[1..].iter().map(String::as_str).collect();
        for v in e2::voices_of(&row, &others) {
            e2::put_statement(d, &v)
                .await
                .unwrap_or_else(|e| panic!("a holder's voice on the charter of {fam}: {e}"));
        }
        let id = e2::rid(&row);
        assert!(
            d.get_attestation(&id).await.unwrap().is_some(),
            "the charter of {fam} landed at its row id"
        );
        id
    }

    /// A family chartered with `extra` (a cadence, a quorum) and versioned to
    /// name it: the charter in force.
    async fn chartered(
        d: &dyn FederationDirectory,
        tag: &str,
        keys: &[String],
        extra: serde_json::Value,
    ) -> String {
        let fam = found(d, &format!("rk-{tag}"), keys, "").await;
        let digest = put_charter(d, &fam, keys, extra).await;
        let mut next = head(d, &fam).await;
        next.charter_digest = digest;
        next.prev_head_digest = String::new();
        next.persist_row_hash = String::new();
        let signers: Vec<&str> = keys.iter().map(String::as_str).collect();
        landed(
            next_version(d, GroupRecord::Family(next), &signers).await,
            &format!("{tag}: the version naming the charter"),
        );
        fam
    }

    /// **I454** — (ii) an uncovered row older than one cadence lags the head.
    pub async fn i454_an_uncovered_row_lags_the_head(d: &dyn FederationDirectory, tag: &str) {
        let keys = holders(d, tag).await;
        let fam = chartered(
            d,
            tag,
            &keys,
            serde_json::json!({ "witness_cadence_secs": 3600 }),
        )
        .await;
        let now = chrono::Utc::now();
        assert!(
            roster_lag(d, &fam, now).await.unwrap().is_none(),
            "{tag} I454: a covered head does not lag"
        );
        // A row younger than one cadence does not lag yet.
        leave(d, &fam, &keys[2], now - chrono::Duration::minutes(10)).await;
        assert!(
            roster_lag(d, &fam, now).await.unwrap().is_none(),
            "{tag} I454: younger than the cadence"
        );
        // One cadence after THIS node admitted it, it does.
        let admitted = chrono::Utc::now();
        assert!(
            roster_lag(d, &fam, admitted + chrono::Duration::minutes(59))
                .await
                .unwrap()
                .is_none(),
            "{tag} I454: the cadence runs from admission, not the row's instant"
        );
        let later = admitted + hours(1) + chrono::Duration::minutes(1);
        let lag = roster_lag(d, &fam, later)
            .await
            .unwrap()
            .expect("an hour on, the uncovered leave lags");
        assert_eq!(lag.token, LINEAGE_HEAD_LAGS_ROSTER, "{tag} I454");
        assert_eq!(lag.uncovered_keys, vec![keys[2].clone()], "{tag} I454");
        assert_eq!(lag.cadence_secs, 3600, "{tag} I454");
        assert_eq!(
            lag.head_digest,
            head(d, &fam).await.persist_row_hash,
            "{tag} I454: the head that lags"
        );
        assert!(
            lag.since >= now && lag.since <= admitted,
            "{tag} I454: since this node admitted the row: {lag:?}"
        );
        let view = root_witness_view(d, &fam, later).await.unwrap().unwrap();
        assert_eq!(
            view.roster_lag.as_ref(),
            Some(&lag),
            "{tag} I454: served on the witness view"
        );
        let held = head(d, &fam).await;
        landed(
            version(d, &fam, without(&held, &keys[2]), &two(&keys)).await,
            &format!("{tag} I454: the covering version"),
        );
        assert!(
            roster_lag(d, &fam, later).await.unwrap().is_none(),
            "{tag} I454: the covering version clears the lag"
        );
    }

    /// A witness's cosign of `fam`'s head: `witness` is its identity-ref, and
    /// the signature is the witness SEED's hybrid pair (the material E0's
    /// composite key for that seed carries).
    fn cosign(
        fam: &Family,
        witness: &str,
        witness_seed: &str,
        signed_at: chrono::DateTime<chrono::Utc>,
    ) -> LineageHeadCosign {
        let mut c = LineageHeadCosign {
            lineage_key_id: fam.family_key_id.clone(),
            head_digest_sha256_hex: fam.persist_row_hash.clone(),
            head_asserted_at: fam.founded_at.to_rfc3339(),
            prior_head_digest_sha256_hex: None,
            signed_at: signed_at.to_rfc3339(),
            witness_key_id: witness.to_owned(),
            signature_classical: String::new(),
            signature_pqc: None,
        };
        let bytes = crate::verify::canonical::ceg_produce_canonicalize(&c.signing_envelope())
            .expect("cosign envelope canonicalizes");
        let sig = ts::threshold_sign(witness_seed, &bytes);
        c.signature_classical = sig.ed25519_signature_base64;
        c.signature_pqc = sig.mldsa65_signature_base64;
        c
    }

    /// **I455** — (ii) witnesses do not cosign a lagging head; with witnessed
    /// mode off the lag is only reported.
    pub async fn i455_a_lagging_head_is_not_cosigned(d: &dyn FederationDirectory, tag: &str) {
        let witness_seed = format!("rw-{tag}");
        let witness = e2::put_key(d, &witness_seed, &[identity_type::WITNESS]).await;
        for (mode, extra) in [
            ("on", serde_json::json!({ "witness_quorum": 2 })),
            ("off", serde_json::json!({})),
        ] {
            let tag = format!("{tag}{mode}");
            let keys = holders(d, &tag).await;
            let fam = chartered(d, &tag, &keys, extra).await;
            // No cadence declared: an uncovered row lags from its instant.
            leave(d, &fam, &keys[2], chrono::Utc::now() - hours(1)).await;
            let held = head(d, &fam).await;
            let lag = roster_lag(d, &fam, chrono::Utc::now()).await.unwrap();
            assert!(lag.is_some(), "{tag} I455: lags in either mode");
            let out = d
                .put_lineage_head_cosign(cosign(&held, &witness, &witness_seed, chrono::Utc::now()))
                .await
                .unwrap();
            match mode {
                "on" => {
                    // v62.0.0 (wave GC3; CC 2.7, rc21 item 15) — kept, and
                    // not counted toward the head's quorum.
                    assert_eq!(
                        out,
                        LineageCosignOutcome::KeptNotCounted {
                            reason: LineageCosignRefusal::HeadLagsRoster
                        },
                        "{tag} I455: a cosign on a lagging head is kept, not counted"
                    );
                    let view = root_witness_view(d, &fam, chrono::Utc::now())
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(
                        view.latest_cosign_at, None,
                        "{tag} I455: the kept cosign counts for nothing"
                    );
                    assert_eq!(
                        LineageCosignRefusal::HeadLagsRoster.as_str(),
                        LINEAGE_HEAD_LAGS_ROSTER,
                        "{tag} I455: the token CC names"
                    );
                    // The covering version is cosignable.
                    landed(
                        version(d, &fam, without(&held, &keys[2]), &two(&keys)).await,
                        &format!("{tag} I455: the covering version"),
                    );
                    let covered = head(d, &fam).await;
                    let out = d
                        .put_lineage_head_cosign(cosign(
                            &covered,
                            &witness,
                            &witness_seed,
                            chrono::Utc::now(),
                        ))
                        .await
                        .unwrap();
                    assert_eq!(
                        out,
                        LineageCosignOutcome::Inserted,
                        "{tag} I455: the covering head"
                    );
                }
                _ => {
                    assert_eq!(
                        out,
                        LineageCosignOutcome::Inserted,
                        "{tag} I455: witnessed mode off changes nothing but the report"
                    );
                    let view = root_witness_view(d, &fam, chrono::Utc::now())
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(view.roster_lag.is_some(), "{tag} I455: reported");
                }
            }
        }
    }

    /// **I456** — (iii) the removal takes effect before any version covers it.
    pub async fn i456_the_removal_does_not_wait(d: &dyn FederationDirectory, tag: &str) {
        let keys = holders(d, tag).await;
        let fam = conferring(d, tag, &keys).await;
        let before = head(d, &fam).await;
        leave(d, &fam, &keys[2], chrono::Utc::now() - hours(1)).await;
        let active: Vec<String> = d
            .active_family_members(&fam)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        assert!(
            !active.contains(&keys[2]),
            "{tag} I456: the fold dropped the seat: {active:?}"
        );
        let held = head(d, &fam).await;
        assert_eq!(held, before, "{tag} I456: no version was synthesised");
        assert!(
            held.members.iter().any(|m| m.key_id == keys[2]),
            "{tag} I456: the head still lists it"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod backdated {
    use ciris_crypto::composite::CompositeSigningKey;

    use super::bodies::{landed, next_version_by};
    use crate::federation::canonical_community as cc;
    use crate::federation::canonical_community_invariants::bodies::{
        rooted_infrastructure_room_e2, SetNodeKey,
    };
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::group::{GroupRecord, MembershipRecord};
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::roster_head::roster_lag;
    use crate::federation::types::{
        identity_type, Community, CommunityMember, CommunityMembershipRevocation,
    };
    use crate::federation::{Error, FederationDirectory};

    const NODE_SEED: &str = "bd-serve-node";
    const ROOM_SEED: &str = "bd-infra-room";
    const TAG: &str = "bd";

    /// Two founders `rooted_infrastructure_room_e2` seats, who voice every
    /// version and the revocation (the room's `quorum:2/3`). W1-fix4 (after
    /// C5-fix1): a trust-root room's founders are the genesis bundle's holders
    /// (holder seeds 1 and 2, their placed keys).
    fn founder_keys() -> [CompositeSigningKey; 2] {
        use crate::federation::edition2::fixture_genesis as fg;
        [
            fg::test_key(fg::HOLDER_SEEDS[0]),
            fg::test_key(fg::HOLDER_SEEDS[1]),
        ]
    }

    fn with_member(held: &Community, key: &str, role: &str) -> Community {
        let mut c = without(held, key);
        c.members.push(CommunityMember {
            key_id: key.to_owned(),
            joined_at: held.founded_at,
            role: Some(role.to_owned()),
        });
        c
    }

    fn without(held: &Community, key: &str) -> Community {
        let mut c = held.clone();
        c.members.retain(|m| m.key_id != key);
        c.prev_head_digest = String::new();
        c.persist_row_hash = String::new();
        c
    }

    async fn room_version(
        d: &dyn FederationDirectory,
        record: Community,
    ) -> Result<StatementOutcome, Error> {
        let [k0, k1] = founder_keys();
        next_version_by(d, GroupRecord::Community(record), &[&k0, &k1]).await
    }

    /// An edition-2 trust-root-grade (`infrastructure`) room with a serve
    /// node widened in on the plane and covered by v2, then a revocation of
    /// the node by two founders' voices, signed with an instant BEFORE v2 and
    /// admitted after it. Returns the room, the node and the revocation's
    /// instant.
    async fn backdated_revocation<B>(b: &B) -> (String, String, chrono::DateTime<chrono::Utc>)
    where
        B: FederationDirectory + SetNodeKey + Sync,
    {
        let node = e2::put_key(b, NODE_SEED, &[identity_type::NODE]).await;
        let room = rooted_infrastructure_room_e2(b, ROOM_SEED, &[NODE_SEED], TAG).await;
        let d: &dyn FederationDirectory = b;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let backdated = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            chrono::Utc::now().timestamp_millis(),
        )
        .expect("an instant");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let held = d.lookup_community(&room).await.unwrap().expect("the room");
        landed(
            room_version(d, with_member(&held, &node, "member")).await,
            "v2 covers the join",
        );
        let v2 = cc::lookup_signed_community(d, &room)
            .await
            .unwrap()
            .unwrap();
        assert!(cc::head_instant(&v2) > backdated, "the row predates v2");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let (head, _) = e2::held_head(d, &room).await.expect("v2 is the held head");
        let r = MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
            community_key_id: room.clone(),
            removed_identity_key_id: node.clone(),
            removed_at: backdated,
            effective_at: backdated,
            reason: None,
            witness_set: vec![],
            persist_row_hash: String::new(),
        });
        let keys = founder_keys();
        let refs: Vec<&CompositeSigningKey> = keys.iter().collect();
        landed(
            e2::put_voices(d, &e2::membership_voices(&r, Some(&head), &refs)).await,
            "a revocation of the node dated before v2, admitted after it",
        );
        (room, node, backdated)
    }

    /// **I450b** — (ii) a backdated revocation does not escape the lag: the
    /// held head is judged against the fold now, over the rows this node
    /// admitted after it, whatever instant they were signed with.
    pub async fn i450b_a_backdated_row_lags<B>(b: &B)
    where
        B: FederationDirectory + SetNodeKey + Sync,
    {
        let (room, node, _) = backdated_revocation(b).await;
        let lag = roster_lag(b, &room, chrono::Utc::now())
            .await
            .unwrap()
            .expect("the backdated revocation lags the head");
        assert_eq!(lag.uncovered_keys, vec![node], "I450b");
    }

    /// **I450c** — (i), which way it goes: a version that leaves the backdated
    /// revocation uncovered DISAGREES with the fold at its own instant and is
    /// refused; the version that drops the node is admitted and clears the lag.
    pub async fn i450c_a_version_must_cover_a_backdated_row<B>(b: &B)
    where
        B: FederationDirectory + SetNodeKey + Sync,
    {
        let (room, node, _) = backdated_revocation(b).await;
        let d: &dyn FederationDirectory = b;
        let held = d.lookup_community(&room).await.unwrap().unwrap();
        let e = room_version(d, with_member(&held, &node, "member"))
            .await
            .expect_err("a v3 still listing the revoked node is refused");
        assert!(
            matches!(&e, Error::LineageVersionDisagreesWithFold { keys, .. }
                if keys == std::slice::from_ref(&node)),
            "I450c: {e:?}"
        );
        landed(
            room_version(d, without(&held, &node)).await,
            "v3 drops the node",
        );
        assert!(
            roster_lag(d, &room, chrono::Utc::now())
                .await
                .unwrap()
                .is_none(),
            "I450c: covered"
        );
    }

    /// **I450d** — (ii) the cadence and `since` are timed from THIS node's
    /// admission, never from the row's signer-chosen instant: the lag names
    /// the admission instant, after the backdated one.
    pub async fn i450d_the_lag_is_timed_from_admission<B>(b: &B)
    where
        B: FederationDirectory + SetNodeKey + Sync,
    {
        let (room, _, backdated) = backdated_revocation(b).await;
        let lag = roster_lag(b, &room, chrono::Utc::now())
            .await
            .unwrap()
            .expect("lags");
        let v2 = cc::lookup_signed_community(b, &room)
            .await
            .unwrap()
            .unwrap();
        assert!(
            lag.since > backdated && lag.since > cc::head_instant(&v2),
            "I450d: since is when this node admitted the row: {lag:?}"
        );
    }
}

#[cfg(test)]
mod pure {
    fn code_of(file: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
        std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The body of `fn name` in `code` (to the next item at the same indent).
    fn body<'a>(code: &'a str, name: &str) -> &'a str {
        let start = code
            .find(name)
            .unwrap_or_else(|| panic!("{name} not found"));
        let rest = &code[start..];
        let end = rest[1..]
            .find("\nfn ")
            .or_else(|| rest[1..].find("\npub(crate) async fn "))
            .or_else(|| rest[1..].find("\nasync fn "))
            .or_else(|| rest[1..].find("\npub async fn "))
            .map_or(rest.len(), |i| i + 1);
        &rest[..end]
    }

    /// **I458** — from disk, comments stripped: every version door runs
    /// consequence (i) before its write, the cosign door runs (ii), and the
    /// accord head door counts the standing majority.
    #[test]
    fn i458_every_door_runs_its_consequence() {
        let ga = code_of("src/federation/group_amendment.rs");
        for door in [
            "pub(crate) async fn route_occupied_family",
            "pub(crate) async fn supersede_family_signed",
            "pub(crate) async fn supersede_community_signed",
        ] {
            let b = body(&ga, door);
            let check = b
                .find("roster_head::check_version_covers_fold(")
                .unwrap_or_else(|| panic!("I458: {door} runs consequence (i)"));
            let write = b
                .find("supersede_group_row(")
                .unwrap_or_else(|| panic!("I458: {door} writes"));
            assert!(check < write, "I458: {door} judges BEFORE it writes");
        }
        let cc = code_of("src/federation/canonical_community.rs");
        let b = body(&cc, "pub(crate) async fn apply_trust_root_chain_counted");
        let check = b
            .find("roster_head::check_version_covers_fold_since(")
            .expect("I458: the trust-root chain apply runs consequence (i)");
        assert!(
            check < b.find("supersede_group_row(").expect("writes"),
            "I458: the chain apply judges before it writes"
        );
        let lw = code_of("src/federation/lineage_witness.rs");
        let b = body(&lw, "pub async fn admit_lineage_head_cosign");
        // v62.0.0 (wave GC3; rc21 item 15) — the door keeps a lagging head's
        // cosign uncounted, through the predicate the witnessed-head fold
        // shares.
        assert!(
            b.contains("head_lags_roster_at(")
                && b.contains("LineageCosignRefusal::HeadLagsRoster"),
            "I458: the cosign door keeps a lagging head's cosign uncounted"
        );
        let h = body(&lw, "pub async fn head_lags_roster_at");
        assert!(
            h.contains("roster_head::roster_lag("),
            "I458: the shared predicate reads the roster lag"
        );
        // The door RETURNS the count's verdict (its tail expression), so a
        // call whose result is dropped does not pass. While the accord is three
        // holders `quorum:2/3` IS the standing majority, so no behaviour can tell
        // the leg apart; I457 witnesses the count itself.
        let ti = code_of("src/federation/tier_ingest.rs");
        let b = body(&ti, "async fn is_accord_head_version");
        let flat: String = b.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            flat.contains(
                "accord_standing_majority_signed(directory, &offered.family_key_id, proof).await }"
            ),
            "I458: the accord head door returns the standing-majority count"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    use super::bodies;

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::{bodies, suffix};
                #[tokio::test]
                async fn i450() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i450_a_version_reflects_a_revocation(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i451() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i451_a_version_reflects_a_widening(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i452() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i452_only_a_witnessed_lineage_is_judged(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i453() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i453_the_community_arm(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i454() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i454_an_uncovered_row_lags_the_head(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i455() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i455_a_lagging_head_is_not_cosigned(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i456() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i456_the_removal_does_not_wait(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i450b() {
                    let Some(b) = $fresh.await else { return };
                    super::super::backdated::i450b_a_backdated_row_lags(&b).await
                }
                #[tokio::test]
                async fn i450c() {
                    let Some(b) = $fresh.await else { return };
                    super::super::backdated::i450c_a_version_must_cover_a_backdated_row(&b).await
                }
                #[tokio::test]
                async fn i450d() {
                    let Some(b) = $fresh.await else { return };
                    super::super::backdated::i450d_the_lag_is_timed_from_admission(&b).await
                }
            }
        };
    }
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
