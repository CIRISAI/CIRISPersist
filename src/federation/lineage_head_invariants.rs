//! v53.0.0 (CC 3.2 T6, operator ruling B-1 on CIRISConstitution#136) —
//! **the head moves with the record.** I440–I449.
//!
//! The lineage head is the family or community record at a version. Its
//! signed `prev_head_digest` names the version it succeeds and its
//! `charter_digest` names the charter in force at that version. A charter row
//! no version names is not in force, so a charter re-scrub takes effect only
//! through a new version, and the head moves with it.
//!
//! - **I440** both members are signed, persisted and served: the row hash
//!   covers them, and every backend returns what was written.
//! - **I441** a supersede whose `prev_head_digest` is not the held head (empty,
//!   or another digest) is refused `lineage_prev_head_mismatch`, on the family
//!   and the community arm; the one naming the held head is admitted.
//! - **I442** a quorate charter of a family whose head names no charter
//!   confers nothing; a version naming it makes the root valid, and that
//!   version's `prev_head_digest` is the head it replaced.
//! - **I443** a charter re-scrub with no new version confers nothing: the
//!   named charter withdrawn and a fresh quorate one admitted leaves the root
//!   chartered by nothing until a version names the fresh one.
//! - **I444** the charter members (attach window) are the named charter's,
//!   never another charter row's, and follow the head when it moves.
//! - **I445** the attach head moves with the version: an acceptance edge naming
//!   the replaced head is stale at the author's door; the new head attaches.
//! - **I446** the accord family's genesis version names the bundle's charter,
//!   and on a seeded node that is the stored `genesis-charter` row; the
//!   reserved accord id admits exactly one door record — a version of the
//!   held accord that moves only its head, whose quorum signed WHICH version.
//! - **I447** a community's charter is its conferring family's in force.
//! - **I448** from disk: every backend's `supersede_group_row` runs the prev
//!   check on both arms.
//! - **I449** a key root (no lineage record) keeps its self-charter.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::canonical_community::{
        charter_in_force, charter_members_for, HeadCharter,
    };
    use crate::federation::operational::test_support as ops;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::trust_root::{
        trust_root_valid, INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE, TRUST_CHARTER_DIMENSION,
    };
    use crate::federation::types::{attestation_type, identity_type};
    use crate::federation::{Error, FederationDirectory};

    const PROTOCOL: &str = "quorum:2/3";

    /// Three registered holders and a registered user.
    async fn people(d: &dyn FederationDirectory, tag: &str) -> (Vec<String>, String) {
        let holders: Vec<String> = (0..3).map(|i| format!("lh{i}-{tag}")).collect();
        for h in &holders {
            ops::register_typed_key(d, h, identity_type::NODE)
                .await
                .unwrap_or_else(|e| panic!("{tag}: register {h}: {e}"));
        }
        let user = format!("lu-{tag}");
        ops::register_typed_key(d, &user, identity_type::USER)
            .await
            .unwrap_or_else(|e| panic!("{tag}: register {user}: {e}"));
        (holders, user)
    }

    /// Three registered USER keys: a community's founders (a node key is no
    /// founder of an ordinary room).
    async fn users(d: &dyn FederationDirectory, tag: &str) -> Vec<String> {
        let keys: Vec<String> = (0..3).map(|i| format!("lm{i}-{tag}")).collect();
        for k in &keys {
            ops::register_typed_key(d, k, identity_type::USER)
                .await
                .unwrap_or_else(|e| panic!("{tag}: register {k}: {e}"));
        }
        keys
    }

    /// A charter of `family` scrubbed by every holder, carrying `extra`
    /// members (an attach window, say).
    fn charter(
        family: &str,
        id: &str,
        holders: &[String],
        extra: serde_json::Value,
    ) -> crate::federation::Attestation {
        let commitment = crate::federation::trust_root::pre_rotation_commitment(&[
            format!("{family}-succ-a"),
            format!("{family}-succ-b"),
        ])
        .unwrap();
        let mut env = serde_json::json!({
            "references_attestation_id": id,
            "dimension": TRUST_CHARTER_DIMENSION,
            "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
            "pre_rotation_commitment": commitment,
        });
        if let (Some(e), Some(x)) = (env.as_object_mut(), extra.as_object()) {
            for (k, v) in x {
                e.insert(k.clone(), v.clone());
            }
        }
        let cosigners: Vec<&str> = holders[1..].iter().map(String::as_str).collect();
        ops::co_signed_trust_attestation(
            id,
            &holders[0],
            family,
            attestation_type::DELEGATES_TO,
            env,
            &cosigners,
        )
    }

    async fn put(d: &dyn FederationDirectory, a: crate::federation::Attestation) {
        d.put_attestation(crate::federation::SignedAttestation { attestation: a })
            .await
            .expect("charter admitted");
    }

    async fn head(d: &dyn FederationDirectory, family: &str) -> crate::federation::Family {
        d.lookup_family(family).await.unwrap().expect("family held")
    }

    fn is_prev_mismatch(e: &Error) -> bool {
        matches!(e, Error::Conflict(m) if m.contains("lineage_prev_head_mismatch"))
    }

    /// **I440** — the two members are signed, persisted and served.
    pub async fn i440_members_are_signed_and_persisted(d: &dyn FederationDirectory, tag: &str) {
        let (holders, _) = people(d, tag).await;
        let fam = format!("lf-{tag}");
        let digest = "ab".repeat(32);
        ops::seed_test_family_naming(d, &fam, &holders, PROTOCOL, &digest)
            .await
            .unwrap();
        let held = head(d, &fam).await;
        assert_eq!(
            held.charter_digest, digest,
            "{tag} I440: charter_digest stored"
        );
        assert_eq!(
            held.prev_head_digest, "",
            "{tag} I440: a founding version names none"
        );
        let mut other = held.clone();
        other.charter_digest = "cd".repeat(32);
        assert_ne!(
            crate::federation::types::compute_persist_row_hash(&held).unwrap(),
            crate::federation::types::compute_persist_row_hash(&other).unwrap(),
            "{tag} I440: the row hash covers charter_digest"
        );
        other.charter_digest = digest.clone();
        other.prev_head_digest = "ef".repeat(32);
        assert_ne!(
            crate::federation::types::compute_persist_row_hash(&held).unwrap(),
            crate::federation::types::compute_persist_row_hash(&other).unwrap(),
            "{tag} I440: the row hash covers prev_head_digest"
        );
        assert!(
            held.signing_envelope().get("charter_digest").is_some(),
            "{tag} I440: charter_digest is signed"
        );
        // A version carrying both round-trips through the supersede door.
        let mut next = held.clone();
        next.prev_head_digest = held.persist_row_hash.clone();
        next.charter_digest = "12".repeat(32);
        next.persist_row_hash = String::new();
        d.supersede_family(ts::sign_family(&holders[0], next), None)
            .await
            .unwrap_or_else(|e| panic!("{tag} I440: supersede naming the held head: {e}"));
        let now = head(d, &fam).await;
        assert_eq!(now.prev_head_digest, held.persist_row_hash, "{tag} I440");
        assert_eq!(now.charter_digest, "12".repeat(32), "{tag} I440");
        let served = d
            .list_signed_families_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.family.family.family_key_id == fam)
            .expect("served")
            .family
            .family;
        assert_eq!(
            (served.prev_head_digest, served.charter_digest),
            (held.persist_row_hash.clone(), "12".repeat(32)),
            "{tag} I440: the served version carries both"
        );
    }

    /// **I441** — a version must name the head it succeeds.
    pub async fn i441_prev_must_name_the_held_head(d: &dyn FederationDirectory, tag: &str) {
        let (holders, _) = people(d, tag).await;
        let fam = format!("lf-{tag}");
        ops::seed_test_family(d, &fam, &holders, PROTOCOL)
            .await
            .unwrap();
        let held = head(d, &fam).await;
        for (why, prev) in [("empty", String::new()), ("another head", "cd".repeat(32))] {
            let mut next = held.clone();
            next.prev_head_digest = prev;
            next.family_name = format!("renamed-{why}");
            next.persist_row_hash = String::new();
            let e = d
                .supersede_family(ts::sign_family(&holders[0], next), None)
                .await
                .expect_err("a version naming another predecessor is refused");
            assert!(is_prev_mismatch(&e), "{tag} I441 family ({why}): {e:?}");
            assert_eq!(
                head(d, &fam).await,
                held,
                "{tag} I441: nothing written ({why})"
            );
        }
        let mut next = held.clone();
        next.prev_head_digest = held.persist_row_hash.clone();
        next.family_name = "renamed".to_owned();
        next.persist_row_hash = String::new();
        let v = d
            .supersede_family(ts::sign_family(&holders[0], next), None)
            .await
            .unwrap_or_else(|e| panic!("{tag} I441: the held head admits: {e}"));
        assert_eq!(v, 2, "{tag} I441");

        // The community arm.
        let holders = users(d, tag).await;
        let id = format!("lc-{tag}");
        let founded_at = chrono::Utc::now();
        let row = crate::federation::types::Community {
            community_key_id: id.clone(),
            community_name: id.clone(),
            members: holders
                .iter()
                .map(|k| crate::federation::types::CommunityMember {
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
        d.put_community(ts::sign_community(&holders[0], row.clone()))
            .await
            .unwrap_or_else(|e| panic!("{tag} I441: community founded: {e}"));
        let held = d.lookup_community(&id).await.unwrap().unwrap();
        let mut next = held.clone();
        next.community_name = "renamed".to_owned();
        next.persist_row_hash = String::new();
        let e = d
            .supersede_community(ts::sign_community(&holders[0], next.clone()), None)
            .await
            .expect_err("a community version naming no predecessor is refused");
        assert!(is_prev_mismatch(&e), "{tag} I441 community: {e:?}");
        next.prev_head_digest = held.persist_row_hash.clone();
        d.supersede_community(ts::sign_community(&holders[0], next), None)
            .await
            .unwrap_or_else(|e| panic!("{tag} I441: community naming the held head: {e}"));
    }

    /// **I442** — a charter no version names confers nothing.
    pub async fn i442_an_unnamed_charter_confers_nothing(d: &dyn FederationDirectory, tag: &str) {
        let (holders, user) = people(d, tag).await;
        let fam = format!("lf-{tag}");
        ops::seed_test_family(d, &fam, &holders, PROTOCOL)
            .await
            .unwrap();
        let c = charter(
            &fam,
            &format!("{fam}-charter"),
            &holders,
            serde_json::json!({}),
        );
        let digest = ops::charter_digest_of(&c);
        put(d, c).await;
        ops::emit_trust_edge(d, &user, &fam, None).await.unwrap();
        let before = trust_root_valid(d, &user, &fam).await.unwrap();
        assert!(
            !before.valid && !before.root_self_declares,
            "{tag} I442: a quorate charter the head does not name is no charter: {before:?}"
        );
        let old = head(d, &fam).await;
        ops::version_family_naming_charter(d, &fam, &digest, &holders)
            .await
            .unwrap_or_else(|e| panic!("{tag} I442: version naming the charter: {e}"));
        let new = head(d, &fam).await;
        assert_eq!(
            new.prev_head_digest, old.persist_row_hash,
            "{tag} I442: the chain"
        );
        assert_ne!(
            new.persist_row_hash, old.persist_row_hash,
            "{tag} I442: the head moved"
        );
        let after = trust_root_valid(d, &user, &fam).await.unwrap();
        assert!(
            after.root_self_declares && after.charter_quorum.is_some_and(|q| q.met()),
            "{tag} I442: the named charter stands: {after:?}"
        );
    }

    /// **I443** — a re-scrub with no new version confers nothing.
    pub async fn i443_a_rescrub_needs_a_version(d: &dyn FederationDirectory, tag: &str) {
        let (holders, user) = people(d, tag).await;
        let fam = format!("lf-{tag}");
        ops::seed_chartered_family_root(d, &fam, &holders, &user)
            .await
            .unwrap();
        let first = trust_root_valid(d, &user, &fam).await.unwrap();
        assert!(
            first.root_self_declares,
            "{tag} I443: chartered at founding: {first:?}"
        );
        // The named charter withdrawn by its author; a fresh one admitted.
        ops::withdraw_attestation(d, &holders[0], &fam, &format!("{fam}-charter"))
            .await
            .unwrap();
        let fresh = charter(
            &fam,
            &format!("{fam}-rescrub"),
            &holders,
            serde_json::json!({}),
        );
        let digest = ops::charter_digest_of(&fresh);
        put(d, fresh).await;
        let unnamed = trust_root_valid(d, &user, &fam).await.unwrap();
        assert!(
            !unnamed.root_self_declares,
            "{tag} I443: the re-scrub alone charters nothing: {unnamed:?}"
        );
        ops::version_family_naming_charter(d, &fam, &digest, &holders)
            .await
            .unwrap_or_else(|e| panic!("{tag} I443: the re-scrub's version: {e}"));
        let named = trust_root_valid(d, &user, &fam).await.unwrap();
        assert!(named.root_self_declares, "{tag} I443: versioned: {named:?}");
    }

    /// **I444** — the charter members are the named charter's.
    pub async fn i444_members_follow_the_head(d: &dyn FederationDirectory, tag: &str) {
        let (holders, _) = people(d, tag).await;
        let fam = format!("lf-{tag}");
        let first = charter(
            &fam,
            &format!("{fam}-c1"),
            &holders,
            serde_json::json!({ "attach_window_secs": 111 }),
        );
        let first_digest = ops::charter_digest_of(&first);
        ops::seed_test_family_naming(d, &fam, &holders, PROTOCOL, &first_digest)
            .await
            .unwrap();
        // A second charter admitted FIRST in listing order would have been
        // `find`'s pick: admit it before the named one.
        let second = charter(
            &fam,
            &format!("{fam}-c0"),
            &holders,
            serde_json::json!({ "attach_window_secs": 777 }),
        );
        let second_digest = ops::charter_digest_of(&second);
        put(d, second).await;
        put(d, first).await;
        let m = charter_members_for(d, &fam).await.unwrap().unwrap();
        assert_eq!(
            m.attach_window_secs,
            Some(111),
            "{tag} I444: the named charter's"
        );
        ops::version_family_naming_charter(d, &fam, &second_digest, &holders)
            .await
            .unwrap();
        let m = charter_members_for(d, &fam).await.unwrap().unwrap();
        assert_eq!(
            m.attach_window_secs,
            Some(777),
            "{tag} I444: follows the head"
        );
    }

    /// **I445** — the attach head moves with the version.
    pub async fn i445_attach_on_the_replaced_head_is_stale(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::canonical_community::{
            attach_head_for, check_attach_freshness, AttachDoor,
        };
        let (holders, user) = people(d, tag).await;
        let fam = format!("lf-{tag}");
        ops::seed_chartered_family_root(d, &fam, &holders, &user)
            .await
            .unwrap();
        let now = chrono::Utc::now();
        let old = attach_head_for(d, &fam, now)
            .await
            .unwrap()
            .expect("a held head");
        let fresh = charter(&fam, &format!("{fam}-v2"), &holders, serde_json::json!({}));
        let digest = ops::charter_digest_of(&fresh);
        put(d, fresh).await;
        ops::version_family_naming_charter(d, &fam, &digest, &holders)
            .await
            .unwrap();
        let new = attach_head_for(d, &fam, now)
            .await
            .unwrap()
            .expect("a held head");
        assert_ne!(old, new, "{tag} I445: the head moved");
        assert_eq!(new, head(d, &fam).await.persist_row_hash, "{tag} I445");
        let edge = |h: &str| {
            serde_json::json!({
                "dimension": crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
                "scope": [INFRA_SERVE_SCOPE],
                crate::federation::envelope::paths::ATTACHED_HEAD_DIGEST: h,
            })
        };
        let consumer = format!("lc2-{tag}");
        let stale = check_attach_freshness(
            d,
            AttachDoor::Author,
            None,
            &consumer,
            attestation_type::DELEGATES_TO,
            &fam,
            &edge(&old),
            now,
        )
        .await
        .expect_err("the replaced head is stale");
        assert!(
            matches!(stale, Error::TrustRootHeadStale { .. }),
            "{tag} I445: {stale:?}"
        );
        check_attach_freshness(
            d,
            AttachDoor::Author,
            None,
            &consumer,
            attestation_type::DELEGATES_TO,
            &fam,
            &edge(&new),
            now,
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I445: the new head attaches: {e}"));
    }

    /// **I446 (door)** — the reserved accord id re-versions only its head,
    /// only under its own quorum, and only the version the quorum bound.
    pub async fn i446_the_accord_moves_only_its_head(d: &dyn FederationDirectory, tag: &str) {
        use crate::federation::canonical_community::NEXT_PERSIST_ROW_HASH;
        ops::register_genesis_accord_roster(d).await.unwrap();
        crate::federation::genesis::seed_accord_family(d)
            .await
            .unwrap();
        let accord = crate::federation::canonical_community::accord_family_key_id();
        let held = head(d, accord).await;
        let ids: Vec<String> = held.members.iter().map(|m| m.key_id.clone()).collect();
        let signers: Vec<&str> = ids.iter().map(String::as_str).collect();
        let _ = &ids;
        let attempt = |next: crate::federation::Family, bind: Option<String>| {
            // Signed by the seats the offered roster keeps: a quorum of the
            // held roster either way, so only the head door can refuse it.
            let signers: Vec<&str> = signers
                .iter()
                .copied()
                .filter(|k| next.members.iter().any(|m| m.key_id == *k))
                .collect();
            async move {
                // The envelope describes the offered roster, so a roster
                // change reaches the head door rather than the envelope match.
                let roster: Vec<String> = next.members.iter().map(|m| m.key_id.clone()).collect();
                let mut env = d
                    .build_membership_change_envelope(
                        crate::federation::cohort::Cohort::Family,
                        accord,
                        &roster,
                        true,
                        Some(&next.consensus_protocol),
                    )
                    .await
                    .unwrap();
                if let Some(h) = bind {
                    env[NEXT_PERSIST_ROW_HASH] = serde_json::Value::String(h);
                }
                let bytes = ciris_verify_core::jcs::canonicalize(&env).unwrap();
                let sigs = signers
                    .iter()
                    .map(|k| ts::threshold_sign(k, &bytes))
                    .collect();
                d.supersede_family_with_quorum(ts::sign_family(signers[0], next), env, sigs)
                    .await
            }
        };
        let hash = |f: &crate::federation::Family| {
            crate::federation::types::compute_persist_row_hash(f).unwrap()
        };
        let mut next = held.clone();
        next.prev_head_digest = held.persist_row_hash.clone();
        next.charter_digest = "5e".repeat(32);
        next.persist_row_hash = String::new();
        let reserved = |e: &Error| matches!(e, Error::ConstitutionalFamilyReserved { .. });
        // Unbound: the quorum signed "the same roster", not this version.
        let e = attempt(next.clone(), None).await.expect_err("unbound");
        assert!(reserved(&e), "{tag} I446: an unbound envelope: {e:?}");
        // Bound to another version.
        let e = attempt(next.clone(), Some("ab".repeat(32)))
            .await
            .expect_err("bound elsewhere");
        assert!(reserved(&e), "{tag} I446: bound to another version: {e:?}");
        // A roster change is not a head move, however bound.
        let mut grown = next.clone();
        grown.members[2].role = Some("member".to_owned());
        let bound = hash(&grown);
        let e = attempt(grown, Some(bound)).await.expect_err("roster");
        assert!(
            reserved(&e),
            "{tag} I446: a roster change through the head door: {e:?}"
        );
        assert_eq!(head(d, accord).await, held, "{tag} I446: nothing moved");
        // The head-only version the quorum bound.
        let bound = hash(&next);
        attempt(next, Some(bound))
            .await
            .unwrap_or_else(|e| panic!("{tag} I446: the bound head-only version: {e}"));
        let moved = head(d, accord).await;
        assert_eq!(moved.charter_digest, "5e".repeat(32), "{tag} I446");
        assert_eq!(moved.prev_head_digest, held.persist_row_hash, "{tag} I446");
    }

    /// **I447** — a community's charter is its conferring family's.
    pub async fn i447_a_community_reads_its_family_head(d: &dyn FederationDirectory, tag: &str) {
        let (holders, _) = people(d, tag).await;
        let accord = crate::federation::canonical_community::accord_family_key_id();
        let digest = "9a".repeat(32);
        ops::seed_test_family_naming(d, accord, &holders, PROTOCOL, &digest)
            .await
            .unwrap();
        let members = users(d, tag).await;
        let id = format!("lc-{tag}");
        let founded_at = chrono::Utc::now();
        let row = crate::federation::types::Community {
            community_key_id: id.clone(),
            community_name: id.clone(),
            members: members
                .iter()
                .map(|k| crate::federation::types::CommunityMember {
                    key_id: k.clone(),
                    joined_at: founded_at,
                    role: Some("founder".to_owned()),
                })
                .collect(),
            founded_at,
            consensus_protocol: PROTOCOL.to_owned(),
            policy_blob: None,
            prev_head_digest: String::new(),
            // What the community version records does not decide: its legs
            // are the family's.
            charter_digest: "77".repeat(32),
            persist_row_hash: String::new(),
        };
        d.put_community(ts::sign_community(&members[0], row))
            .await
            .unwrap();
        assert_eq!(
            charter_in_force(d, &id).await.unwrap(),
            (accord.to_owned(), HeadCharter::Named(digest)),
            "{tag} I447"
        );
    }

    /// **I449** — a key root keeps its self-charter.
    pub async fn i449_a_key_root_keeps_its_self_charter(d: &dyn FederationDirectory, tag: &str) {
        let root = format!("lk-{tag}");
        ops::register_typed_key(d, &root, identity_type::NODE)
            .await
            .unwrap();
        assert_eq!(
            charter_in_force(d, &root).await.unwrap(),
            (root.clone(), HeadCharter::KeyRoot),
            "{tag} I449"
        );
        let self_charter = ops::co_signed_trust_attestation(
            &format!("{root}-charter"),
            &root,
            &root,
            attestation_type::DELEGATES_TO,
            serde_json::json!({
                "references_attestation_id": format!("{root}-charter"),
                "dimension": TRUST_CHARTER_DIMENSION,
                "scope": [INFRA_ATTEST_SCOPE, INFRA_SERVE_SCOPE],
                "attach_window_secs": 4242,
                "pre_rotation_commitment": crate::federation::trust_root::pre_rotation_commitment(
                    &[format!("{root}-succ")]
                ).unwrap(),
            }),
            &[],
        );
        put(d, self_charter).await;
        let m = charter_members_for(d, &root).await.unwrap().unwrap();
        assert_eq!(m.attach_window_secs, Some(4242), "{tag} I449");
    }
}

#[cfg(test)]
mod pure {
    /// **I448** — from disk: every backend's `supersede_group_row` runs the
    /// prev check on BOTH arms (family, community). Comments stripped, so a
    /// commented-out call cannot pass.
    #[test]
    fn i448_every_backend_runs_the_prev_check_on_both_arms() {
        for file in [
            "src/store/memory.rs",
            "src/store/sqlite.rs",
            "src/store/postgres.rs",
        ] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
            let text = std::fs::read_to_string(&path).unwrap();
            let start = text
                .find("async fn supersede_group_row(")
                .unwrap_or_else(|| panic!("{file}: supersede_group_row"));
            let body = &text[start..];
            let end = body[1..]
                .find("\n    async fn ")
                .map_or(body.len(), |i| i + 1);
            let code: String = body[..end]
                .lines()
                .map(|l| l.split("//").next().unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\n");
            let calls = code.matches("check_prev_head_names_held(").count();
            assert_eq!(
                calls, 2,
                "{file}: the prev check on the family AND community arm"
            );
            for field in ["new_fam.prev_head_digest", "new_comm.prev_head_digest"] {
                assert!(code.contains(field), "{file}: judges {field}");
            }
        }
    }

    /// **I446 (pure)** — the genesis version of the accord family names the
    /// bundle's charter of the family.
    #[test]
    fn i446_the_genesis_version_names_the_bundle_charter() {
        let fam = crate::federation::genesis::accord_family_genesis_record();
        let charter = crate::federation::genesis::canonical_genesis_bundle()
            .attestations
            .iter()
            .find(|s| s.attestation.attestation_id == "genesis-charter")
            .expect("the shipped bundle carries genesis-charter");
        assert_eq!(
            fam.charter_digest,
            crate::federation::canonical_community::stored_row_hash(&charter.attestation).unwrap(),
            "I446: the accord family's genesis version names genesis-charter"
        );
        assert!(!fam.charter_digest.is_empty(), "I446");
        assert_eq!(
            fam.prev_head_digest, "",
            "I446: the genesis version names no predecessor"
        );
    }
}

#[cfg(test)]
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
                async fn i440() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i440_members_are_signed_and_persisted(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i441() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i441_prev_must_name_the_held_head(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i442() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i442_an_unnamed_charter_confers_nothing(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i443() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i443_a_rescrub_needs_a_version(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i444() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i444_members_follow_the_head(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i445() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i445_attach_on_the_replaced_head_is_stale(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i446() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i446_the_accord_moves_only_its_head(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i447() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i447_a_community_reads_its_family_head(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i449() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i449_a_key_root_keeps_its_self_charter(&b, &suffix()).await
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
