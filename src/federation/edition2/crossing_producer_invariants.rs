//! v62.0.0 (v62 P8) — **I3520–I3532: every re-signing path states edition 2,
//! and a SECOND node admits what it states.** sqlite and postgres; two
//! engines, delivered through the planes (`edition2_statements_served_to`
//! → `put_edition2_statement`) where the audience lets the second node be
//! served, and by the statement's bytes where it does not.
//!
//! - **I3520** — `enter_mesh` over an edition-2 local row crosses IN PLACE
//!   on its own statement (`TierPromotionCustody::Statement`): the same row
//!   id, the same statement bytes, the same signature column, no co-scrub;
//!   nothing is re-signed and nothing is JCS-signed. A second crossing is
//!   `AlreadyInMesh`.
//! - **I3521** — the crossing moves the row's statements to the node's next
//!   serve position: a reader whose cursor passed them while they were local
//!   (withheld) reads them after the crossing.
//! - **I3522** — `widen_audience` over an edition-2 row RESTATES it at the
//!   wider audience (`crossing::restate_at_audience` → `sign_row` →
//!   `put_statement`): a new row id, the prior's family and claim instant,
//!   A's own kid; node B is served it and admits it under the same row id,
//!   attested by A, while the `self` prior is never served to B. The same
//!   widening again is `AlreadyWidened`; a `strip` naming the claim's
//!   instant is refused before anything is admitted.
//! - **I3524** — with the earlier-form doors shut, an earlier-form local row
//!   (unsigned, from the local door) is RESTATED by its actor (a new row, an
//!   edition-2 statement; the local row stays local and unsigned); widened,
//!   it reaches B.
//! - **I3532** — the occurrence producer (`publish_self_occurrence`, which
//!   signed a `LocalSelfSigner` JCS envelope) states an edition-2
//!   `identity:occurrence` bind (O1's): the self pair lands on A on its one
//!   statement; B admits the same bytes and lists the occurrence. Under
//!   another identity with no author signer, the author's voice comes back
//!   DRAFTED (the node never authors it), and nothing lands.
//! - **I3538** — `self_at_login` with every pen in hand: the app binds under
//!   the user (the user authors, the device voices), the AGENT under its
//!   own identity (the user, its owner, authors; the agent voices), the
//!   owner binding is stated first; nothing is left to sign.
//! - **I3541** — `Engine::sign_draft` signs a drafted statement with the
//!   engine's composite key and a second node admits it; `sign_hybrid` is
//!   `EarlierFormShut` once the doors are shut.
//! - **I3542** — `state_community_founding` is `Pending` while a listed
//!   member has not voiced the founding roster, and lands on that member's
//!   voice (drafted, signed by its engine). **I3543** —
//!   `rekey_community_member_revoke_voices` is `None` while the removal is
//!   short of the community's protocol, `Some(epoch)` once counted, and the
//!   removal lands once. **I3544** — the family founding twin.
//!
//! Mutations: drop the re-stamp in `enter_mesh` (sqlite / postgres), and
//! I3521 reds; route an edition-2 row through `custody_for`, and I3520 reds
//! on `custody_for`'s refusal; restate the widening at the prior's scope,
//! and I3522 reds on `AudienceNotWider`.

pub(crate) mod bodies {
    use super::super::producer_invariants::bodies::{deliver, node};
    use crate::federation::crossing::{self, Audience, CrossingBasis};
    use crate::federation::edition2::emit::{carried_statement, family_of_statement};
    use crate::federation::edition2::ingest::{kid_of_identity_ref, statement_kid};
    use crate::federation::types::{
        attestation_tier, attestation_type, cohort_scope, identity_type, LocalAttestationInput,
    };
    use crate::federation::{EmitAttestationInput, Error, MeshCrossingOutcome};
    use crate::Engine;

    fn envelope() -> crate::federation::envelope::EnvelopeCore {
        crate::federation::envelope::EnvelopeCore::from_value(serde_json::json!({
            "dimension": "observation:reachability:v1",
            "score": 0.5,
        }))
        .expect("an envelope")
    }

    async fn held(e: &Engine, id: &str) -> crate::federation::Attestation {
        e.federation_directory()
            .get_attestation(id)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("row {id} is held"))
    }

    /// A local edition-2 row: stated by A's composite key and put at the
    /// local tier through the statement door.
    async fn local_statement_row(a: &Engine) -> crate::federation::Attestation {
        let dir = a.federation_directory();
        let signer = a
            .composite_signer("p8 witness")
            .expect("a composite signer");
        let input = EmitAttestationInput::with_envelope(
            attestation_type::SCORES,
            envelope(),
            cohort_scope::SELF,
        );
        let produced = crate::federation::attestation_emit::produce_row(&*dir, signer, input, None)
            .await
            .expect("the row is produced");
        crate::federation::edition2::ingest::put_statement_with_origin(
            &*dir,
            &produced.statement,
            None,
            attestation_tier::LOCAL,
            crate::federation::replication::admission::WriteOrigin::Authored,
        )
        .await
        .expect("the local put");
        let rid = crate::federation::edition2::names::RowId::of_statement(&produced.statement)
            .expect("a row statement");
        held(a, &rid.hex()).await
    }

    /// I3520 / I3521 / I3522.
    pub(crate) async fn i3520_an_edition2_local_row_crosses_and_widens(
        a_dsn: &str,
        b_dsn: &str,
        tag: &str,
    ) {
        let a = node(a_dsn, &format!("{tag}-3520-a")).await;
        let b = node(b_dsn, &format!("{tag}-3520-b")).await;
        let a_id = a
            .register_self_federation_key(identity_type::NODE, None, None)
            .await
            .expect("I3520: A registers");
        let mut cursor = None;
        deliver(&a, &b, &mut cursor).await;

        let local = local_statement_row(&a).await;
        assert_eq!(local.tier, attestation_tier::LOCAL, "I3520: a local row");
        let st0 = carried_statement(&local).expect("I3520: an edition-2 local row");
        // I3521 — the raw position the store has handed out so far.
        let before = a
            .federation_directory()
            .edition2_statements_since(None, 1000)
            .await
            .unwrap();
        let last = before.last().map(|s| s.cursor).expect("I3521: held");
        assert!(
            before.iter().any(|s| s.bytes == st0),
            "I3521: the local statement is held"
        );

        let ci = crossing::describe(
            &local,
            Audience::of_row(&local).expect("audience"),
            CrossingBasis::ProducerAuthority,
        )
        .expect("I3520: describable");
        match a.enter_mesh(&local.attestation_id, &ci, None).await {
            Ok(MeshCrossingOutcome::Crossed(c)) => {
                assert_eq!(c.attestation_id, local.attestation_id, "I3520: in place");
                assert_eq!(c.audience, Audience::SelfOnly, "I3520: its own audience");
            }
            other => panic!("I3520: the edition-2 row crosses: {other:?}"),
        }
        let crossed = held(&a, &local.attestation_id).await;
        assert_eq!(crossed.tier, attestation_tier::FEDERATION, "I3520");
        assert_eq!(
            carried_statement(&crossed).as_deref(),
            Some(st0.as_slice()),
            "I3520: the same statement bytes"
        );
        assert_eq!(
            crossed.scrub_signature_classical, local.scrub_signature_classical,
            "I3520: nothing was re-signed"
        );
        assert!(
            crossed.additional_scrubs.is_empty(),
            "I3520: no co-scrub (nothing JCS-signed)"
        );
        assert_eq!(
            crossed.original_content_hash, local.original_content_hash,
            "I3520: the envelope is the mapping's, untouched"
        );
        assert!(
            matches!(
                a.enter_mesh(&local.attestation_id, &ci, None).await,
                Ok(MeshCrossingOutcome::AlreadyInMesh { .. })
            ),
            "I3520: idempotent"
        );

        // I3521 — served again after the position a reader had passed.
        let after = a
            .federation_directory()
            .edition2_statements_since(Some(&last), 1000)
            .await
            .unwrap();
        assert!(
            after.iter().any(|s| s.bytes == st0),
            "I3521: the crossed row's statement is past the old cursor"
        );

        // I3522 — widened by restatement.
        let ci_w = crossing::describe(
            &crossed,
            Audience::Federation,
            CrossingBasis::ProducerAuthority,
        )
        .expect("I3522: describable");
        let refused = a
            .widen_audience(
                &crossed.attestation_id,
                &ci_w,
                None,
                &["/asserted_at".to_owned()],
            )
            .await;
        assert!(
            matches!(refused, Err(Error::WideningMalformed { .. })),
            "I3522: the claim's instant is never stripped: {refused:?}"
        );
        let widened = match a
            .widen_audience(&crossed.attestation_id, &ci_w, None, &[])
            .await
        {
            Ok(MeshCrossingOutcome::Crossed(w)) => w,
            other => panic!("I3522: the restatement is admitted: {other:?}"),
        };
        assert_ne!(
            widened.attestation_id, crossed.attestation_id,
            "I3522: a row of its own"
        );
        assert_eq!(widened.audience, Audience::Federation, "I3522");
        let w = held(&a, &widened.attestation_id).await;
        let stw = carried_statement(&w).expect("I3522: an edition-2 statement");
        assert_eq!(
            family_of_statement(&stw),
            family_of_statement(&st0),
            "I3522: the prior's family"
        );
        assert_eq!(
            statement_kid(&stw),
            kid_of_identity_ref(&a_id),
            "I3522: signed by A's own key"
        );
        assert_eq!(w.cohort_scope, cohort_scope::FEDERATION, "I3522");
        assert_eq!(
            w.asserted_at, crossed.asserted_at,
            "I3522: the claim's instant"
        );
        assert!(w.additional_scrubs.is_empty(), "I3522: nothing JCS-signed");
        assert!(
            matches!(
                a.widen_audience(&crossed.attestation_id, &ci_w, None, &[])
                    .await,
                Ok(MeshCrossingOutcome::AlreadyWidened { .. })
            ),
            "I3522: idempotent per audience"
        );
        assert_eq!(
            held(&a, &crossed.attestation_id).await.cohort_scope,
            cohort_scope::SELF,
            "I3522: the prior is untouched"
        );

        let delivered = deliver(&a, &b, &mut cursor).await;
        assert!(delivered.contains(&stw), "I3522: A serves the restatement");
        assert!(
            !delivered.contains(&st0),
            "I3522: the self prior is never served to B"
        );
        let at_b = b
            .federation_directory()
            .get_attestation(&widened.attestation_id)
            .await
            .unwrap()
            .expect("I3522: B admits the restatement under the same row id");
        assert_eq!(at_b.attesting_key_id, a_id, "I3522: attested by A");
        assert_eq!(at_b.cohort_scope, cohort_scope::FEDERATION, "I3522");
    }

    /// I3524.
    pub(crate) async fn i3524_an_earlier_form_local_row_is_restated(
        a_dsn: &str,
        b_dsn: &str,
        tag: &str,
    ) {
        let a = node(a_dsn, &format!("{tag}-3524-a")).await;
        let b = node(b_dsn, &format!("{tag}-3524-b")).await;
        let a_id = a
            .register_self_federation_key(identity_type::NODE, None, None)
            .await
            .expect("I3524: A registers");
        let mut cursor = None;
        deliver(&a, &b, &mut cursor).await;
        let local_id = a
            .federation_directory()
            .attestation_upsert_local(LocalAttestationInput {
                attestation_id: None,
                attesting_key_id: a_id.clone(),
                attested_key_id: None,
                attestation_type: attestation_type::SCORES.to_owned(),
                weight: None,
                expires_at: None,
                attestation_envelope: envelope(),
                subject_key_ids: Vec::new(),
                cohort_scope: cohort_scope::SELF.to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            })
            .await
            .expect("I3524: the local door writes an unsigned row");
        let local = held(&a, &local_id).await;
        assert!(
            carried_statement(&local).is_none(),
            "I3524: an earlier-form row"
        );
        let ci = crossing::describe(
            &local,
            Audience::of_row(&local).expect("audience"),
            CrossingBasis::ProducerAuthority,
        )
        .expect("I3524: describable");

        let (stated, widened) =
            crate::federation::edition2::door::with_earlier_form_doors_shut(async {
                let stated = match a.enter_mesh(&local_id, &ci, None).await {
                    Ok(MeshCrossingOutcome::Crossed(c)) => c,
                    other => panic!("I3524: the row is restated: {other:?}"),
                };
                let s = held(&a, &stated.attestation_id).await;
                let ci_w =
                    crossing::describe(&s, Audience::Federation, CrossingBasis::ProducerAuthority)
                        .expect("I3524: describable");
                let widened = match a
                    .widen_audience(&stated.attestation_id, &ci_w, None, &[])
                    .await
                {
                    Ok(MeshCrossingOutcome::Crossed(w)) => w,
                    other => panic!("I3524: the restatement widens: {other:?}"),
                };
                (stated, widened)
            })
            .await;
        assert_ne!(stated.attestation_id, local_id, "I3524: a new row");
        let s = held(&a, &stated.attestation_id).await;
        let st = carried_statement(&s).expect("I3524: an edition-2 statement");
        assert_eq!(
            statement_kid(&st),
            kid_of_identity_ref(&a_id),
            "I3524: stated by A's own key"
        );
        assert_eq!(s.tier, attestation_tier::FEDERATION, "I3524");
        let still = held(&a, &local_id).await;
        assert_eq!(
            still.tier,
            attestation_tier::LOCAL,
            "I3524: the local row stays"
        );
        assert!(
            still.scrub_signature_classical.is_empty(),
            "I3524: the local row is never JCS-signed"
        );

        deliver(&a, &b, &mut cursor).await;
        let at_b = b
            .federation_directory()
            .get_attestation(&widened.attestation_id)
            .await
            .unwrap()
            .expect("I3524: B admits the widened restatement");
        assert_eq!(at_b.attesting_key_id, a_id, "I3524: attested by A");
    }

    /// I3532.
    pub(crate) async fn i3532_the_occurrence_producer_states_a_bind(
        a_dsn: &str,
        b_dsn: &str,
        tag: &str,
    ) {
        let a = node(a_dsn, &format!("{tag}-3532-a")).await;
        let b = node(b_dsn, &format!("{tag}-3532-b")).await;
        let a_id = a
            .register_self_federation_key(identity_type::NODE, None, None)
            .await
            .expect("I3532: A registers");
        let mut cursor = None;
        deliver(&a, &b, &mut cursor).await;

        let out = a
            .publish_self_occurrence(&a_id, "server", None, None)
            .await
            .expect("I3532: A states its own occurrence");
        assert!(
            out.landed,
            "I3532: the self pair lands on its one statement"
        );
        assert!(
            out.author_draft.is_none() && out.own_draft.is_none(),
            "I3532: nothing left to sign"
        );
        let st = out.own_voice.expect("I3532: the node's own voice");
        assert!(
            crate::federation::edition2::liveness::statement_parts(&st)
                .and_then(|(_, p)| p.get_text("refs").and_then(|r| r.get_text("head")).cloned())
                .is_some(),
            "I3532: the bind names its identity's self-roster head (CC rc21 refs.head)"
        );
        assert_eq!(
            family_of_statement(&st),
            Some(("identity:occurrence".to_owned(), "scores".to_owned())),
            "I3532: O1's bind"
        );
        assert_eq!(
            statement_kid(&st),
            kid_of_identity_ref(&a_id),
            "I3532: signed by A's own key"
        );
        let on_a = a
            .federation_directory()
            .list_identity_occurrences_for(&a_id)
            .await
            .unwrap();
        assert!(
            on_a.iter().any(|o| o.occurrence_key_id == a_id),
            "I3532: the self pair lands on A: {on_a:?}"
        );
        b.put_edition2_statement(&st, None)
            .await
            .expect("I3532: B admits the same statement");
        let on_b = b
            .federation_directory()
            .list_identity_occurrences_for(&a_id)
            .await
            .unwrap();
        assert!(
            on_b.iter().any(|o| o.occurrence_key_id == a_id),
            "I3532: the bind lands on B: {on_b:?}"
        );

        // Under another identity (a user that owns the node) with no author
        // signer: the node states its own voice, the author's is a draft.
        let (_u, u_id) = {
            let u = node(b_dsn, &format!("{tag}-3532-u")).await;
            let id = u
                .register_self_federation_key(identity_type::USER, None, None)
                .await
                .expect("I3532: the user registers");
            let mut c = None;
            deliver(&u, &a, &mut c).await;
            (u, id)
        };
        let out = a.publish_self_occurrence(&u_id, "server", None, None).await;
        match out {
            Ok(o) => {
                assert!(!o.landed, "I3532: nothing lands without the author");
                assert!(o.author_voice.is_none(), "I3532: the node never authors it");
                assert!(
                    o.author_draft.is_some(),
                    "I3532: the owner's pen gets a draft"
                );
            }
            // O1's identity-set exclusion may refuse a node key under a
            // person at the node's own voice: also never node-authored.
            Err(e) => assert!(
                e.to_string().contains("occurrence_binds_machine_to_person"),
                "I3532: {e}"
            ),
        }
    }

    /// I3538.
    pub(crate) async fn i3538_self_at_login_states_o1_binds(a_dsn: &str, tag: &str) {
        use super::super::producer_invariants::bodies::signer;
        use crate::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
        let alias = |who: &str| format!("{tag}-3538-{who}");
        let a = node(a_dsn, &alias("user")).await;
        let u_id = a
            .register_self_federation_key(identity_type::USER, None, None)
            .await
            .expect("I3538: the user registers");
        // The app's and the agent's keys, registered on the same store.
        let mut keys = Vec::new();
        for (who, ty) in [
            ("app", identity_type::USER),
            ("agent", identity_type::AGENT),
        ] {
            let e = node(a_dsn, &alias(who)).await;
            let id = e
                .register_self_federation_key(ty, None, None)
                .await
                .unwrap_or_else(|e| panic!("I3538: the {who} key registers: {e}"));
            keys.push((id, signer(&alias(who), &alias(who))));
        }
        let (agent_id, agent_signer) = keys.pop().expect("agent");
        let (app_id, app_signer) = keys.pop().expect("app");
        let kem = || {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            let (_xp, x_pub, _mp, ml_pub) =
                crate::federation::identity_aggregate::mint_content_kem_keypair()
                    .expect("mint content-kem");
            crate::federation::EncryptionPubkeys {
                x25519_base64: B64.encode(x_pub),
                ml_kem_768_base64: B64.encode(ml_pub),
            }
        };
        let out = a
            .self_at_login(SelfAtLoginInput {
                identity_key_id: u_id.clone(),
                identity_signer: Some(signer(&alias("user"), &alias("user"))),
                app: SelfAtLoginOccurrence {
                    occurrence_key_id: app_id.clone(),
                    device_class: crate::federation::device_class::PHONE.to_owned(),
                    encryption_pubkeys: Some(kem()),
                    occurrence_signer: Some(app_signer),
                    ..SelfAtLoginOccurrence::default()
                },
                agent: SelfAtLoginOccurrence {
                    occurrence_key_id: agent_id.clone(),
                    device_class: crate::federation::device_class::AGENT.to_owned(),
                    encryption_pubkeys: Some(kem()),
                    occurrence_signer: Some(agent_signer),
                    ..SelfAtLoginOccurrence::default()
                },
                bilateral_pair_id: uuid::Uuid::new_v4().to_string(),
                delegation_scope: None,
            })
            .await
            .expect("I3538: self_at_login");
        assert!(out.bind_drafts.is_empty(), "I3538: every voice was in hand");
        assert_eq!(
            out.agent_identity_key_id, agent_id,
            "I3538: the agent's own identity"
        );
        for k in [&app_id, &agent_id] {
            assert!(
                out.occurrences_published.contains(k),
                "I3538: {k} is published: {:?}",
                out.occurrences_published
            );
        }
        let dir = a.federation_directory();
        let under_user = dir.list_identity_occurrences_for(&u_id).await.unwrap();
        assert!(
            under_user.iter().any(|o| o.occurrence_key_id == app_id)
                && under_user.iter().all(|o| o.occurrence_key_id != agent_id),
            "I3538: the app binds under the user, the agent never does: {under_user:?}"
        );
        let under_agent = dir.list_identity_occurrences_for(&agent_id).await.unwrap();
        assert!(
            under_agent.iter().any(|o| o.occurrence_key_id == agent_id),
            "I3538: the agent binds under its own identity: {under_agent:?}"
        );
        assert_eq!(
            crate::federation::admission::agent_owner_of(
                &*dir,
                &agent_id,
                u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap()
            )
            .await
            .unwrap()
            .as_deref(),
            Some(u_id.as_str()),
            "I3538: the owner binding was stated"
        );
    }

    /// I3541.
    pub(crate) async fn i3541_a_drafted_statement_signed_by_the_engine(
        a_dsn: &str,
        b_dsn: &str,
        tag: &str,
    ) {
        use ciris_verify_core::cde::Value;
        let a = node(a_dsn, &format!("{tag}-3541-a")).await;
        let b = node(b_dsn, &format!("{tag}-3541-b")).await;
        let a_id = a
            .register_self_federation_key(identity_type::NODE, None, None)
            .await
            .expect("I3541: A registers");
        let mut cursor = None;
        deliver(&a, &b, &mut cursor).await;
        let kid = kid_of_identity_ref(&a_id).expect("an identity-ref");
        let at = u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap();
        let payload = crate::federation::edition2::emit::sorted_map(vec![
            (Value::Text("asserted_at".into()), Value::Uint(at)),
            (
                Value::Text("cohort_scope".into()),
                Value::Text(cohort_scope::FEDERATION.into()),
            ),
            (
                Value::Text("dimension".into()),
                Value::Text("observation:reachability:v1".into()),
            ),
            (Value::Text("score".into()), Value::Uint(500_000)),
        ]);
        let draft = crate::federation::edition2::emit::draft_row(
            &kid,
            &a_id,
            &a_id,
            "scores",
            "observation:reachability",
            &payload,
        )
        .expect("I3541: drafted");
        let st = a
            .sign_draft(&draft)
            .await
            .expect("I3541: the engine signs it");
        assert_eq!(statement_kid(&st), Some(kid), "I3541: A's own key");
        b.put_edition2_statement(&st, None)
            .await
            .expect("I3541: B admits the signed draft");
        // The earlier form, behind the switch.
        let refused = crate::federation::edition2::door::with_earlier_form_doors_shut(
            a.sign_hybrid(b"earlier"),
        )
        .await;
        assert!(
            matches!(refused, Err(crate::engine::SignError::EarlierFormShut)),
            "I3541: {refused:?}"
        );
    }

    /// A member's voice over `a`'s held voice of `row_id`: the same payload,
    /// drafted for `member` and signed by its engine.
    async fn second_voice(
        a: &Engine,
        member: &Engine,
        member_id: &str,
        row_id: &crate::federation::edition2::names::RowId,
    ) -> Vec<u8> {
        let held = a
            .federation_directory()
            .edition2_voices(row_id)
            .await
            .unwrap()
            .into_iter()
            .next()
            .expect("a held voice");
        let (protected, payload) =
            crate::federation::edition2::liveness::statement_parts(&held).expect("decodes");
        let (family, row_type) = family_of_statement(&held).expect("a row");
        // CWT claims (header 15), `sub` (2).
        let sub = protected
            .get_int(15)
            .and_then(|c| c.get_int(2))
            .and_then(ciris_verify_core::cde::Value::as_text)
            .expect("sub")
            .to_owned();
        let kid = kid_of_identity_ref(member_id).expect("an identity-ref");
        let draft = crate::federation::edition2::emit::draft_row(
            &kid, member_id, &sub, &row_type, &family, &payload,
        )
        .expect("drafted");
        member.sign_draft(&draft).await.expect("signed")
    }

    async fn rekey(
        e: &Engine,
        community: &str,
        minter: &str,
        removed: &str,
        at: chrono::DateTime<chrono::Utc>,
        voices: &[Vec<u8>],
    ) -> Option<u64> {
        use crate::federation::at_rest_cascade::orchestrate::rekey_community_member_revoke_voices as r;
        #[cfg(feature = "sqlite")]
        if let Some(b) = e.sqlite_backend() {
            return r(b.as_ref(), community, minter, removed, at, voices)
                .await
                .expect("I3543: the rekey");
        }
        #[cfg(feature = "postgres")]
        if let Some(b) = e.postgres_backend() {
            return r(b.as_ref(), community, minter, removed, at, voices)
                .await
                .expect("I3543: the rekey");
        }
        panic!("no backend")
    }

    /// I3542 / I3543 / I3544.
    pub(crate) async fn i3542_founding_and_rekey(dsn: &str, tag: &str) {
        use crate::federation::edition2::group::{removal_draft, MembershipRecord};
        use crate::federation::edition2::ingest::StatementOutcome as O;
        use crate::federation::types::{
            Community, CommunityMember, CommunityMembershipRevocation, Family, FamilyMember,
        };
        let party = |who: &'static str| {
            let alias = format!("{tag}-3542-{who}");
            async move {
                let e = node(dsn, &alias).await;
                let id = e
                    .register_self_federation_key(identity_type::USER, None, None)
                    .await
                    .unwrap_or_else(|e| panic!("{who} registers: {e}"));
                (e, id)
            }
        };
        let (a, a_id) = party("a").await;
        let (x, x_id) = party("x").await;
        let (_g, g_id) = party("g").await;
        let (_f, f_id) = party("f").await;
        let now = crate::host::clock::now();

        // I3542 — a community founding is Pending until the listed member
        // voices it, then lands.
        let community = Community {
            community_key_id: g_id.clone(),
            community_name: "p8 room".into(),
            members: [(&a_id, Some("founder")), (&x_id, None)]
                .iter()
                .map(|(k, role)| CommunityMember {
                    key_id: (*k).clone(),
                    joined_at: now,
                    role: role.map(str::to_owned),
                })
                .collect(),
            founded_at: now,
            consensus_protocol: "majority".into(),
            policy_blob: None,
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            persist_row_hash: String::new(),
        };
        let rid = match a.state_community_founding(community).await {
            Ok(O::Pending { row_id, .. }) => row_id,
            other => panic!("I3542: short of the listed members: {other:?}"),
        };
        let dir = a.federation_directory();
        assert!(
            dir.lookup_community(&g_id).await.unwrap().is_none(),
            "I3542: not yet"
        );
        let head = match x
            .put_edition2_statement(&second_voice(&a, &x, &x_id, &rid).await, None)
            .await
        {
            Ok(O::Row { row_id, .. }) => row_id,
            other => panic!("I3542: the member's voice lands it: {other:?}"),
        };
        assert_eq!(head, rid, "I3542: one row, two voices");
        assert!(
            dir.lookup_community(&g_id).await.unwrap().is_some(),
            "I3542: landed"
        );

        // I3543 — the rekey: None while the removal is Pending, Some once
        // counted (majority of two = both).
        let at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now.timestamp_millis())
            .expect("ms");
        let removal = MembershipRecord::CommunityRemoval(CommunityMembershipRevocation {
            community_key_id: g_id.clone(),
            removed_identity_key_id: x_id.clone(),
            removed_at: at,
            effective_at: at,
            reason: None,
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
        });
        let voice = |e: &'static str| {
            let (eng, id) = if e == "a" { (&a, &a_id) } else { (&x, &x_id) };
            let draft = removal_draft(&removal, &head, id).expect("I3543: drafted");
            async move { eng.sign_draft(&draft).await.expect("I3543: signed") }
        };
        let va = voice("a").await;
        assert_eq!(
            rekey(&a, &g_id, &a_id, &x_id, at, &[va]).await,
            None,
            "I3543: short of the protocol, no epoch bump"
        );
        let vx = voice("x").await;
        assert!(
            rekey(&a, &g_id, &a_id, &x_id, at, &[vx]).await.is_some(),
            "I3543: counted, the epoch is bumped"
        );
        assert_eq!(
            dir.list_community_membership_revocations_for(&g_id)
                .await
                .unwrap()
                .len(),
            1,
            "I3543: the removal landed once"
        );

        // I3544 — the family twin of I3542.
        let family = Family {
            family_key_id: f_id.clone(),
            family_name: "p8 family".into(),
            members: [&a_id, &x_id]
                .iter()
                .map(|k| FamilyMember {
                    key_id: (*k).clone(),
                    joined_at: now,
                    role: None,
                })
                .collect(),
            founded_at: now,
            consensus_protocol: "majority".into(),
            consensus_protocol_entrenched: false,
            dissolved_at: None,
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            persist_row_hash: String::new(),
        };
        let rid = match a.state_family_founding(family).await {
            Ok(O::Pending { row_id, .. }) => row_id,
            other => panic!("I3544: short of the listed members: {other:?}"),
        };
        assert!(
            dir.lookup_family(&f_id).await.unwrap().is_none(),
            "I3544: not yet"
        );
        assert!(
            matches!(
                x.put_edition2_statement(&second_voice(&a, &x, &x_id, &rid).await, None)
                    .await,
                Ok(O::Row { .. })
            ),
            "I3544: the member's voice lands it"
        );
        assert!(
            dir.lookup_family(&f_id).await.unwrap().is_some(),
            "I3544: landed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::bodies as b;

    fn tag() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    fn sqlite_dsn(d: &tempfile::TempDir, name: &str) -> String {
        format!(
            "sqlite:///{}",
            d.path().join(format!("{name}.db")).display()
        )
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3520_sqlite() {
        let d = tempfile::tempdir().unwrap();
        Box::pin(b::i3520_an_edition2_local_row_crosses_and_widens(
            &sqlite_dsn(&d, "a"),
            &sqlite_dsn(&d, "b"),
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3520_postgres() {
        let (Some(a), Some(bb)) = (
            crate::test_pg::isolated_dsn(),
            crate::test_pg::isolated_dsn(),
        ) else {
            eprintln!("i3520 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        Box::pin(b::i3520_an_edition2_local_row_crosses_and_widens(
            &a,
            &bb,
            &tag(),
        ))
        .await;
        eprintln!("i3520 postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3524_sqlite() {
        let d = tempfile::tempdir().unwrap();
        Box::pin(b::i3524_an_earlier_form_local_row_is_restated(
            &sqlite_dsn(&d, "a"),
            &sqlite_dsn(&d, "b"),
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3524_postgres() {
        let (Some(a), Some(bb)) = (
            crate::test_pg::isolated_dsn(),
            crate::test_pg::isolated_dsn(),
        ) else {
            eprintln!("i3524 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        Box::pin(b::i3524_an_earlier_form_local_row_is_restated(
            &a,
            &bb,
            &tag(),
        ))
        .await;
        eprintln!("i3524 postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3532_sqlite() {
        let d = tempfile::tempdir().unwrap();
        Box::pin(b::i3532_the_occurrence_producer_states_a_bind(
            &sqlite_dsn(&d, "a"),
            &sqlite_dsn(&d, "b"),
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3532_postgres() {
        let (Some(a), Some(bb)) = (
            crate::test_pg::isolated_dsn(),
            crate::test_pg::isolated_dsn(),
        ) else {
            eprintln!("i3532 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        Box::pin(b::i3532_the_occurrence_producer_states_a_bind(
            &a,
            &bb,
            &tag(),
        ))
        .await;
        eprintln!("i3532 postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3538_sqlite() {
        let d = tempfile::tempdir().unwrap();
        Box::pin(b::i3538_self_at_login_states_o1_binds(
            &sqlite_dsn(&d, "a"),
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3538_postgres() {
        let Some(a) = crate::test_pg::isolated_dsn() else {
            eprintln!("i3538 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        Box::pin(b::i3538_self_at_login_states_o1_binds(&a, &tag())).await;
        eprintln!("i3538 postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3541_sqlite() {
        let d = tempfile::tempdir().unwrap();
        Box::pin(b::i3541_a_drafted_statement_signed_by_the_engine(
            &sqlite_dsn(&d, "a"),
            &sqlite_dsn(&d, "b"),
            &tag(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3541_postgres() {
        let (Some(a), Some(bb)) = (
            crate::test_pg::isolated_dsn(),
            crate::test_pg::isolated_dsn(),
        ) else {
            eprintln!("i3541 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        Box::pin(b::i3541_a_drafted_statement_signed_by_the_engine(
            &a,
            &bb,
            &tag(),
        ))
        .await;
        eprintln!("i3541 postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3542_sqlite() {
        let d = tempfile::tempdir().unwrap();
        Box::pin(b::i3542_founding_and_rekey(&sqlite_dsn(&d, "a"), &tag())).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i3542_postgres() {
        let Some(a) = crate::test_pg::isolated_dsn() else {
            eprintln!("i3542 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        Box::pin(b::i3542_founding_and_rekey(&a, &tag())).await;
        eprintln!("i3542 postgres: RAN");
    }
}
