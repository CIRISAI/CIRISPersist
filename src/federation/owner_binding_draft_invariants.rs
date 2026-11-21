//! v62.0.0 (KR-fix11; CC 3.2 "the first binding", CC 2.6.1.9, CC 3.1.3.2) —
//! **I4285–I4286: a canonical seat's owner binding, produced with the
//! owner's key outside the Engine.**
//!
//! - **I4285** the operator's own person key (not held by the Engine) signs
//!   the drafted owner binding (`Engine::owner_binding_draft`); the tool's
//!   self-check passes; submitted, it WAITS for the node's own voice; the
//!   node finds it (`held_rows_for`, role `bound_node`), voices it, and it is
//!   seated: `owner_of` names the operator and the binding is announced at
//!   federation scope (`serve_seat_owner_announced`), carrying
//!   `infra:attest`.
//! - **I4286** the draft and the software producer state ONE row: at the
//!   same instant, the drafted payload is byte-for-byte the payload
//!   `Engine::steward_bind`'s producer states.
//!
//! sqlite and postgres, through the Engine's own verbs.

use crate::federation::edition2::fixture_switch as e2;
use crate::federation::edition2::second_signer_voice::VoiceOutcome;
use crate::federation::self_at_login::{
    check_owner_binding_statement, owner_binding_delegates_to_envelope,
    owner_binding_draft_envelope,
};
use crate::federation::types::{attestation_type, cohort_scope, delegation_scope as ds};
use crate::federation::FederationDirectory;

fn scopes() -> Vec<String> {
    [
        ds::INFRA_SERVE,
        ds::INFRA_NETWORK_PRESENCE,
        ds::INFRA_ATTEST,
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

fn now_ms() -> u64 {
    u64::try_from(crate::host::clock::now().timestamp_millis()).expect("after 1970")
}

/// **I4285.**
pub(crate) async fn i4285_an_owner_binding_signed_outside_the_engine(e: &crate::Engine) {
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let (owner_seed, node_seed) = ("o-i4285", "n-i4285");
    let owner = e2::put_key(d, owner_seed, &["user"]).await;
    let node = e2::put_key(d, node_seed, &["node"]).await;
    assert_eq!(
        e.owner_of(&node).await.expect("I4285: owner_of"),
        None,
        "I4285: unowned before the binding"
    );

    // The owner's half: drafted by the Engine, signed OUTSIDE it.
    let draft = e
        .owner_binding_draft(
            &node,
            &scopes(),
            &owner,
            &hex::encode(e2::kid_digest(owner_seed)),
            now_ms(),
        )
        .await
        .expect("I4285: Engine::owner_binding_draft");
    let statement = draft.assemble(
        e2::signing_key(owner_seed)
            .sign(&draft.sig_structure)
            .expect("I4285: the owner signs outside the Engine"),
    );
    check_owner_binding_statement(
        &statement,
        &owner,
        &node,
        &[ds::INFRA_ATTEST, ds::INFRA_SERVE],
    )
    .expect("I4285: the tool's self-check passes");
    // The self-check catches what a tool would get wrong.
    check_owner_binding_statement(&statement, &node, &node, &[])
        .expect_err("I4285: the self-check names a wrong owner");
    check_owner_binding_statement(&statement, &owner, &owner, &[])
        .expect_err("I4285: the self-check names a wrong node");
    check_owner_binding_statement(&statement, &owner, &node, &["infra:detect"])
        .expect_err("I4285: the self-check names a missing scope");

    let o = e
        .submit_voice(&statement)
        .await
        .expect("I4285: the owner's half is kept");
    assert!(
        matches!(o, VoiceOutcome::Waiting { .. }),
        "I4285: it waits for the node's own voice: {o:?}"
    );
    assert_eq!(
        e.owner_of(&node).await.expect("I4285: owner_of"),
        None,
        "I4285: one voice binds nothing (CC 3.2: the node's own key cosigns)"
    );
    assert!(
        !e.serve_seat_owner_announced(&node)
            .await
            .expect("I4285: reads"),
        "I4285: not announced before the node's voice"
    );

    // The node's half: it finds the row and voices it.
    let rows = e
        .held_rows_for(Some(node.as_str()), Some("bound_node"), None, 10)
        .await
        .expect("I4285: Engine::held_rows_for");
    assert_eq!(rows.len(), 1, "I4285: the node finds its binding: {rows:?}");
    let d2 = e
        .voice_draft(&rows[0].row_id, &node)
        .await
        .expect("I4285: Engine::voice_draft");
    let voice = d2.assemble(
        e2::signing_key(node_seed)
            .sign(&d2.sig_structure)
            .expect("I4285: the node signs"),
    );
    let o = e
        .submit_voice(&voice)
        .await
        .expect("I4285: the node's voice");
    assert!(o.is_seated(), "I4285: both voices seat it: {o:?}");

    assert_eq!(
        e.owner_of(&node).await.expect("I4285: owner_of").as_deref(),
        Some(owner.as_str()),
        "I4285: the operator owns the node"
    );
    assert!(
        e.serve_seat_owner_announced(&node)
            .await
            .expect("I4285: reads"),
        "I4285: announced at federation scope"
    );
    let row = d
        .get_attestation(&rows[0].row_id)
        .await
        .expect("I4285: reads")
        .expect("I4285: the binding landed");
    assert_eq!(row.cohort_scope, cohort_scope::FEDERATION, "I4285: placed");
    assert_eq!(row.attesting_key_id, owner, "I4285: the owner's row");
    assert_eq!(row.attested_key_id, node, "I4285: about the node");
    let carried: Vec<&str> = row
        .attestation_envelope
        .get("scope")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|t| t.as_str()).collect())
        .unwrap_or_default();
    assert!(
        carried.contains(&ds::INFRA_ATTEST) && carried.contains(&ds::INFRA_SERVE),
        "I4285: it carries infra:attest and infra:serve: {carried:?}"
    );
}

/// **I4286.**
pub(crate) async fn i4286_the_draft_states_the_software_producers_row(e: &crate::Engine) {
    use crate::federation::tier_ingest::test_support as ts;
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let (owner_seed, node_seed) = ("o-i4286", "n-i4286");
    let owner = e2::put_key(d, owner_seed, &["user"]).await;
    let node = e2::put_key(d, node_seed, &["node"]).await;
    // The software producer's row, as `Engine::steward_bind` builds it
    // (`grant_delegation_in`): not put, only produced.
    let mut input = crate::federation::EmitAttestationInput::with_envelope(
        attestation_type::DELEGATES_TO,
        crate::federation::envelope::EnvelopeCore::from_value(owner_binding_delegates_to_envelope(
            &node,
            &scopes(),
        ))
        .expect("I4286: the envelope"),
        cohort_scope::FEDERATION,
    );
    input.attested_key_id = Some(node.clone());
    let produced = crate::federation::attestation_emit::produce_row(
        d,
        &ts::local_signer(owner_seed),
        input,
        None,
    )
    .await
    .expect("I4286: the software producer states the binding");
    assert_eq!(
        produced.iss, owner,
        "I4286 premise: the software signer is the same owner key"
    );
    let draft = e
        .owner_binding_draft(
            &node,
            &scopes(),
            &owner,
            &hex::encode(e2::kid_digest(owner_seed)),
            produced.asserted_at_ms,
        )
        .await
        .expect("I4286: the draft");
    // The bytes the software producer actually SIGNED (the payload inside
    // its statement), never a re-encoding of its decoded value: an encoder
    // difference cannot hide.
    let signed_payload = crate::federation::edition2::door::raw_payload(&produced.statement)
        .expect("I4286: the produced statement carries its payload");
    assert_eq!(
        draft.payload, signed_payload,
        "I4286: one row, byte for byte, whichever producer states it"
    );
    assert_eq!(
        signed_payload,
        ciris_verify_core::cde::encode(&produced.payload),
        "I4286: and the producer's reported payload is what it signed"
    );
    assert_eq!(produced.sub, node, "I4286: about the node");
    let _ = owner_binding_draft_envelope(&node, &[])
        .expect_err("I4286: an owner binding with no scope is not drafted");
    let _ = owner_binding_draft_envelope(&node, &["agent:act".to_owned()])
        .expect_err("I4286: a scope outside infra:* is not drafted");
}

/// Deliver `from`'s edition-2 plane to `to` the way a peer pulls it: the
/// filtered serve listing for `requester`, each statement through `to`'s one
/// entry. A statement `from` does not serve to `requester` never arrives.
async fn deliver(from: &dyn FederationDirectory, to: &dyn FederationDirectory, requester: &str) {
    use crate::federation::edition2::ingest::{put_statement, INGEST_TIER};
    let mut cursor = None;
    loop {
        let page = crate::federation::edition2::serve::statements_served_to(
            from,
            cursor.as_ref(),
            256,
            Some(requester),
        )
        .await
        .expect("the serve listing");
        let Some(next) = page.next else { break };
        cursor = Some(next);
        for st in page.statements {
            let _ = put_statement(to, &st.bytes, None, INGEST_TIER).await;
        }
    }
}

/// How many voices of row `id` `from` serves `requester`.
async fn served_of(
    from: &dyn FederationDirectory,
    requester: &str,
    id: &crate::federation::edition2::names::RowId,
) -> usize {
    use crate::federation::edition2::names::RowId;
    let (mut n, mut cursor) = (0, None);
    loop {
        let page = crate::federation::edition2::serve::statements_served_to(
            from,
            cursor.as_ref(),
            256,
            Some(requester),
        )
        .await
        .expect("the serve listing");
        n += page
            .statements
            .iter()
            .filter(|st| RowId::of_statement(&st.bytes) == Some(*id))
            .count();
        let Some(next) = page.next else { break };
        cursor = Some(next);
    }
    n
}

/// **I4289** (KR-fix12). The self-check catches a bad signing step and a
/// non-person owner BY NAME, before anything is submitted.
/// - signed by the WRONG key (another key signs the owner's draft):
///   `owner_binding_signature_invalid`, pure form and Engine form;
/// - a TRUNCATED signature: `owner_binding_signature_invalid`;
/// - the owner's half drafted for and signed by a NODE key:
///   `owner_binding_owner_not_a_person`;
/// - a good statement passes both forms.
///
/// Nothing faulty is submitted: the store holds no voice of those rows.
pub(crate) async fn i4289_the_self_check_verifies_the_signature(e: &crate::Engine) {
    use crate::federation::edition2::names::RowId;
    use crate::federation::self_at_login::verify_owner_binding_statement;
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let (owner_seed, other_seed, node_seed, node_owner_seed) =
        ("o-i4289", "x-i4289", "n-i4289", "m-i4289");
    let owner = e2::put_key(d, owner_seed, &["user"]).await;
    e2::put_key(d, other_seed, &["user"]).await;
    let node = e2::put_key(d, node_seed, &["node"]).await;
    let machine = e2::put_key(d, node_owner_seed, &["node"]).await;
    let owner_key = e2::signing_key(owner_seed);
    let required = [ds::INFRA_ATTEST, ds::INFRA_SERVE];
    let draft = e
        .owner_binding_draft(
            &node,
            &scopes(),
            &owner,
            &hex::encode(e2::kid_digest(owner_seed)),
            now_ms(),
        )
        .await
        .expect("I4289: the draft");
    let fault_of = |st: Vec<u8>| {
        let node = node.clone();
        async move {
            let pure = verify_owner_binding_statement(
                &st,
                e2::signing_key(owner_seed).public_key(),
                "user",
                &node,
                &required,
            )
            .err()
            .map(|f| f.token());
            let held = e
                .check_owner_binding(&st, &node, &required)
                .await
                .expect("I4289: Engine::check_owner_binding")
                .map(|f| f.token());
            (pure, held)
        }
    };
    let none_held = |id: RowId| async move {
        assert!(
            d.edition2_voices(&id)
                .await
                .expect("I4289: reads")
                .is_empty(),
            "I4289: a statement the self-check refused was never submitted"
        );
    };

    // Good.
    let good = draft.assemble(
        owner_key
            .sign(&draft.sig_structure)
            .expect("I4289: the owner signs"),
    );
    assert_eq!(
        fault_of(good.clone()).await,
        (None, None),
        "I4289: a good statement passes"
    );

    // The wrong key signed the owner's draft.
    let wrong = draft.assemble(
        e2::signing_key(other_seed)
            .sign(&draft.sig_structure)
            .expect("I4289: another key signs"),
    );
    let bad = Some("owner_binding_signature_invalid");
    assert_eq!(
        fault_of(wrong.clone()).await,
        (bad, bad),
        "I4289: signed by the wrong key"
    );

    // A truncated signature.
    let mut sig = owner_key
        .sign(&draft.sig_structure)
        .expect("I4289: the owner signs");
    sig.truncate(sig.len() - 7);
    let cut = draft.assemble(sig);
    assert_eq!(
        fault_of(cut).await,
        (bad, bad),
        "I4289: a truncated signature"
    );
    // (Same row id as the good statement, which was not submitted either.)
    none_held(RowId::of_statement(&wrong).expect("I4289: a row id")).await;

    // The owner's half drafted for, and signed by, a NODE key.
    let by_node = e
        .owner_binding_draft(
            &node,
            &scopes(),
            &machine,
            &hex::encode(e2::kid_digest(node_owner_seed)),
            now_ms(),
        )
        .await
        .expect("I4289: a draft naming a node as owner");
    let st = by_node.assemble(
        e2::signing_key(node_owner_seed)
            .sign(&by_node.sig_structure)
            .expect("I4289: the node key signs"),
    );
    assert_eq!(
        verify_owner_binding_statement(
            &st,
            e2::signing_key(node_owner_seed).public_key(),
            "node",
            &node,
            &required,
        )
        .err()
        .map(|f| f.token()),
        Some("owner_binding_owner_not_a_person"),
        "I4289: pure form: a node key owns nothing"
    );
    assert_eq!(
        e.check_owner_binding(&st, &node, &required)
            .await
            .expect("I4289: Engine::check_owner_binding")
            .map(|f| f.token()),
        Some("owner_binding_owner_not_a_person"),
        "I4289: Engine form: the held record is not a person's"
    );
    none_held(RowId::of_statement(&st).expect("I4289: a row id")).await;

    // `submit_owner_binding` runs the same check first: each faulty
    // statement is refused by its fault's name and nothing is kept.
    for (what, bytes, token) in [
        ("the wrong key", &wrong, "owner_binding_signature_invalid"),
        (
            "a node-signed owner half",
            &st,
            "owner_binding_owner_not_a_person",
        ),
    ] {
        let err = e
            .submit_owner_binding(bytes)
            .await
            .expect_err("I4289: submit_owner_binding refuses a faulty owner binding");
        assert!(
            err.to_string().contains(token),
            "I4289: {what}: refused by name {token}: {err}"
        );
        none_held(RowId::of_statement(bytes).expect("I4289: a row id")).await;
    }
    // The good one is taken (the node is not this Engine's key: it waits).
    let o = e
        .submit_owner_binding(&good)
        .await
        .expect("I4289: the good owner binding is kept");
    assert!(
        matches!(o, VoiceOutcome::Waiting { .. }),
        "I4289: kept, waiting for the node's voice: {o:?}"
    );
}

/// **I4291** (KR-fix14). The DOOR refuses an owner's half signed by a key
/// that is not a person's, by the self-check's own token
/// (`owner_binding_owner_not_a_person`), at the authored door
/// (`Engine::submit_voice`) and at the wire door (a peer's copy,
/// `replicated_statement_door`): nothing is kept, no owner results. A
/// person's half through the wire door is kept, waiting for the node.
pub(crate) async fn i4291_the_door_refuses_a_non_person_owner(e: &crate::Engine) {
    use crate::federation::admission::OWNER_BINDING_OWNER_NOT_A_PERSON;
    use crate::federation::edition2::ingest::ReplicatedStatementOutcome;
    use crate::federation::edition2::names::RowId;
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let (owner_seed, machine_seed, node_seed) = ("o-i4291", "m-i4291", "n-i4291");
    let owner = e2::put_key(d, owner_seed, &["user"]).await;
    let machine = e2::put_key(d, machine_seed, &["node"]).await;
    let node = e2::put_key(d, node_seed, &["node"]).await;
    let half = |signer: String, seed: &'static str| {
        let node = node.clone();
        async move {
            let draft = e
                .owner_binding_draft(
                    &node,
                    &scopes(),
                    &signer,
                    &hex::encode(e2::kid_digest(seed)),
                    now_ms(),
                )
                .await
                .expect("I4291: the draft");
            draft.assemble(
                e2::signing_key(seed)
                    .sign(&draft.sig_structure)
                    .expect("I4291: signed"),
            )
        }
    };
    let by_node = half(machine.clone(), machine_seed).await;
    let id = RowId::of_statement(&by_node).expect("I4291: a row id");

    // The authored door.
    let err = e
        .submit_voice(&by_node)
        .await
        .expect_err("I4291: the door refuses a node-signed owner binding");
    assert!(
        err.to_string().contains(OWNER_BINDING_OWNER_NOT_A_PERSON),
        "I4291: refused by name at the authored door: {err}"
    );
    // The wire door: the same row from a peer.
    match d.replicated_statement_door(&by_node, &id.0).await {
        Err(err) => assert!(
            err.to_string().contains(OWNER_BINDING_OWNER_NOT_A_PERSON),
            "I4291: refused by name at the wire door: {err}"
        ),
        Ok(ReplicatedStatementOutcome::Admitted(o)) => {
            panic!("I4291: the wire door admitted a node-signed owner binding: {o:?}")
        }
        Ok(_) => {}
    }
    assert!(
        d.edition2_voices(&id)
            .await
            .expect("I4291: reads")
            .is_empty(),
        "I4291: nothing of it is kept by either door"
    );
    assert_eq!(
        e.owner_of(&node).await.expect("I4291: owner_of"),
        None,
        "I4291: and the node has no owner"
    );

    // Control: a PERSON's half through the wire door is kept, waiting.
    let by_person = half(owner.clone(), owner_seed).await;
    let pid = RowId::of_statement(&by_person).expect("I4291: a row id");
    let out = d
        .replicated_statement_door(&by_person, &pid.0)
        .await
        .expect("I4291: a person's half is taken by the wire door");
    assert!(
        matches!(out, ReplicatedStatementOutcome::Admitted(_)),
        "I4291: admitted (kept, waiting for the node): {out:?}"
    );
    assert_eq!(
        d.edition2_voices(&pid).await.expect("I4291: reads").len(),
        1,
        "I4291: the person's half is held"
    );
}

/// **I4292** (KR-fix14). The ONE generic signature self-check, on drafts of
/// other families (no shape rule of its own): a grant from the root and an
/// owner binding. Signed by the key the draft names: passes. Signed by
/// another key: `statement_signature_invalid`. Checked against a key the
/// draft does not name: `statement_signer_kid_mismatch`. A cut signature:
/// `statement_signature_invalid`. Bytes that are no statement:
/// `statement_not_a_row_statement`.
pub(crate) async fn i4292_the_generic_signature_self_check(e: &crate::Engine) {
    use crate::federation::edition2::fixture_genesis as fg;
    use crate::federation::edition2::self_check::{verify_statement_signature, SignerKey};
    let dir = e.federation_directory();
    let d: &dyn FederationDirectory = dir.as_dyn_directory();
    let c = fg::bundle_v2();
    let (owner_seed, other_seed) = ("o-i4292", "x-i4292");
    let owner = e2::put_key(d, owner_seed, &["user"]).await;
    e2::put_key(d, other_seed, &["user"]).await;
    let node = e2::put_key(d, "n-i4292", &["node"]).await;
    // A grant from the root, drafted for holder 1.
    let grant = e
        .statement_draft(
            attestation_type::DELEGATES_TO,
            &serde_json::json!({
                "dimension": crate::federation::trust_root::TRUST_CONFERS_DIMENSION,
                "scope": [ds::INFRA_ATTEST],
                "head": hex::encode(c.object_id),
            }),
            c.holder_identity_ref(0),
            &hex::encode(fg::kid_of(fg::HOLDER_SEEDS[0])),
            &node,
            c.asserted_at_ms + 120_000,
            None,
        )
        .await
        .expect("I4292: a grant draft");
    let binding = e
        .owner_binding_draft(
            &node,
            &scopes(),
            &owner,
            &hex::encode(e2::kid_digest(owner_seed)),
            now_ms(),
        )
        .await
        .expect("I4292: an owner binding draft");
    let token = |st: &[u8], key: &ciris_crypto::composite::CompositePublicKey| {
        verify_statement_signature(st, SignerKey::PublicKey(key))
            .err()
            .map(|f| f.token())
    };
    for (what, draft, right, wrong) in [
        (
            "a grant from the root",
            &grant,
            c.holder_key(0),
            c.holder_key(1),
        ),
        (
            "an owner binding",
            &binding,
            e2::signing_key(owner_seed),
            e2::signing_key(other_seed),
        ),
    ] {
        let good = draft.assemble(right.sign(&draft.sig_structure).expect("I4292: signs"));
        assert_eq!(
            token(&good, right.public_key()),
            None,
            "I4292: {what}: the right key's signature passes"
        );
        let by_wrong = draft.assemble(wrong.sign(&draft.sig_structure).expect("I4292: signs"));
        assert_eq!(
            token(&by_wrong, right.public_key()),
            Some("statement_signature_invalid"),
            "I4292: {what}: another key signed it"
        );
        assert_eq!(
            token(&good, wrong.public_key()),
            Some("statement_signer_kid_mismatch"),
            "I4292: {what}: checked against a key the draft does not name"
        );
        let mut sig = right.sign(&draft.sig_structure).expect("I4292: signs");
        sig.truncate(sig.len() - 5);
        assert_eq!(
            token(&draft.assemble(sig), right.public_key()),
            Some("statement_signature_invalid"),
            "I4292: {what}: a cut signature"
        );
    }
    assert_eq!(
        token(b"not a statement", c.holder_key(0).public_key()),
        Some("statement_not_a_row_statement"),
        "I4292: bytes that are no statement"
    );
}

/// **I4287** (KR-fix12). The ceremony's two hosts. Host A assembles the
/// owner's half (the owner's key is outside both Engines) and submits it:
/// waiting. A does NOT serve a row still held for its second signer, so the
/// node's host B gets the owner's half as BYTES (the tool carries the
/// statement) and takes it with `Engine::submit_owner_binding`: B's Engine
/// key IS the node, so the node's own voice follows and the binding is
/// seated on B. A then pulls B's feed as the owner; both hosts read the same
/// owner, row, scopes (with `infra:attest`) and the federation announcement.
pub(crate) async fn i4287_two_hosts(
    a: &crate::Engine,
    b: &crate::Engine,
    b_signer: &crate::signing::LocalSigner,
) {
    use crate::federation::edition2::names::RowId;
    let (dir_a, dir_b) = (a.federation_directory(), b.federation_directory());
    let (da, db): (&dyn FederationDirectory, &dyn FederationDirectory) =
        (dir_a.as_dyn_directory(), dir_b.as_dyn_directory());
    // B's own key is the node.
    let node = e2::put_key_for_signer(db, b_signer, &["node"]).await;
    assert_eq!(
        b.local_derived_key_id().await.expect("I4287: B's key"),
        node,
        "I4287 premise: host B's Engine key is the node"
    );
    // The owner is known to A; its key is in neither Engine.
    let owner_seed = "o-i4287";
    let owner = e2::put_key(da, owner_seed, &["user"]).await;
    // Key records cross (served to anyone): A learns the node, B the owner.
    deliver(db, da, &owner).await;
    deliver(da, db, &node).await;

    // ── Host A: draft, sign outside, self-check, submit ──────────────────
    let draft = a
        .owner_binding_draft(
            &node,
            &scopes(),
            &owner,
            &hex::encode(e2::kid_digest(owner_seed)),
            now_ms(),
        )
        .await
        .expect("I4287: A drafts the owner's half");
    let statement = draft.assemble(
        e2::signing_key(owner_seed)
            .sign(&draft.sig_structure)
            .expect("I4287: the owner signs outside both Engines"),
    );
    check_owner_binding_statement(&statement, &owner, &node, &[ds::INFRA_ATTEST])
        .expect("I4287: the tool's self-check");
    let id = RowId::of_statement(&statement).expect("I4287: a row id");
    let o = a
        .submit_owner_binding(&statement)
        .await
        .expect("I4287: A keeps the owner's half");
    assert!(
        matches!(o, VoiceOutcome::Waiting { .. }),
        "I4287: on a host that is not the node, it waits: {o:?}"
    );
    assert!(
        a.node_owner_binding(&node)
            .await
            .expect("I4287: A reads")
            .is_none(),
        "I4287: no owner on A before the node's voice"
    );
    // The feed does not carry a row held for its second signer: the node's
    // host gets the owner's half as bytes.
    assert_eq!(
        served_of(da, &node, &id).await,
        0,
        "I4287: a binding still waiting for the node is not served by the feed"
    );

    // ── Host B (the node): takes the bytes; its own voice follows ────────
    let o = b
        .submit_owner_binding(&statement)
        .await
        .expect("I4287: B takes the owner's half and voices it");
    assert!(o.is_seated(), "I4287: owner + node seat it on B: {o:?}");

    // ── Host A pulls back, as the owner ──────────────────────────────────
    deliver(db, da, &owner).await;
    for (host, e) in [("B", b), ("A", a)] {
        let read = e
            .node_owner_binding(&node)
            .await
            .expect("I4287: reads")
            .unwrap_or_else(|| panic!("I4287: host {host} reads no owner"));
        assert_eq!(read.owner, owner, "I4287: host {host}: the owner");
        assert_eq!(
            read.row_id.as_deref(),
            Some(id.hex().as_str()),
            "I4287: host {host}: the authorising row"
        );
        assert!(
            read.scopes.iter().any(|t| t == ds::INFRA_ATTEST)
                && read.scopes.iter().any(|t| t == ds::INFRA_SERVE),
            "I4287: host {host}: its scopes carry infra:attest: {:?}",
            read.scopes
        );
        assert_eq!(
            read.cohort_scope.as_deref(),
            Some(cohort_scope::FEDERATION),
            "I4287: host {host}: placed at federation"
        );
        assert!(
            read.announced_at_federation,
            "I4287: host {host}: announced at federation scope"
        );
    }
}

/// **I4288** (KR-fix12). The node is THIS Engine's key, on the draft path,
/// and the order of the two voices.
/// - The node cannot voice FIRST: before the owner's half is held there is
///   no statement of the row to voice (`voice_held_row` and `voice_draft`
///   refuse, naming the row).
/// - `submit_voice` keeps the owner's half and adds nothing: waiting. The
///   node's host then voices it itself (`voice_held_row`): seated.
/// - `submit_owner_binding` does both in one act (on a second Engine).
pub(crate) async fn i4288_the_node_is_this_engine(
    c: &crate::Engine,
    c_signer: &crate::signing::LocalSigner,
    b: &crate::Engine,
    b_signer: &crate::signing::LocalSigner,
) {
    use crate::federation::edition2::names::RowId;
    for (tag, e, signer, one_act) in [("C", c, c_signer, false), ("B", b, b_signer, true)] {
        let dir = e.federation_directory();
        let d: &dyn FederationDirectory = dir.as_dyn_directory();
        let node = e2::put_key_for_signer(d, signer, &["node"]).await;
        let owner_seed = if one_act { "o-i4288-b" } else { "o-i4288-c" };
        let owner = e2::put_key(d, owner_seed, &["user"]).await;
        let draft = e
            .owner_binding_draft(
                &node,
                &scopes(),
                &owner,
                &hex::encode(e2::kid_digest(owner_seed)),
                now_ms(),
            )
            .await
            .expect("I4288: the draft");
        let statement = draft.assemble(
            e2::signing_key(owner_seed)
                .sign(&draft.sig_structure)
                .expect("I4288: the owner signs outside the Engine"),
        );
        let id = RowId::of_statement(&statement).expect("I4288: a row id");
        // The node cannot voice first.
        let err = e
            .voice_held_row(&id.hex(), None)
            .await
            .expect_err("I4288: nothing of the row is held yet");
        assert!(
            err.to_string().contains(&id.hex()),
            "I4288: host {tag}: the refusal names the row: {err}"
        );
        e.voice_draft(&id.hex(), &node)
            .await
            .expect_err("I4288: no statement to draft a voice from");
        let seated = if one_act {
            e.submit_owner_binding(&statement)
                .await
                .expect("I4288: the node's host takes its owner binding")
        } else {
            let o = e
                .submit_voice(&statement)
                .await
                .expect("I4288: submit_voice keeps the owner's half");
            assert!(
                matches!(o, VoiceOutcome::Waiting { .. }),
                "I4288: submit_voice adds no voice of its own: {o:?}"
            );
            e.voice_held_row(&id.hex(), None)
                .await
                .expect("I4288: the node's host voices it itself")
        };
        assert!(seated.is_seated(), "I4288: host {tag}: seated: {seated:?}");
        let read = e
            .node_owner_binding(&node)
            .await
            .expect("I4288: reads")
            .unwrap_or_else(|| panic!("I4288: host {tag} reads no owner"));
        assert!(
            read.owner == owner
                && read.row_id.as_deref() == Some(id.hex().as_str())
                && read.announced_at_federation,
            "I4288: host {tag}: {read:?}"
        );
    }
    // A statement that is not an owner binding is not taken by the verb.
    b.submit_owner_binding(b"not a statement")
        .await
        .expect_err("I4288: submit_owner_binding takes an owner binding only");
}

#[cfg(feature = "sqlite")]
async fn sqlite_engine(seed: &str) -> crate::Engine {
    crate::Engine::with_signer(
        crate::federation::tier_ingest::test_support::local_signer(seed),
        "sqlite::memory:",
    )
    .await
    .expect("a sqlite Engine")
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i4285_sqlite() {
    Box::pin(i4285_an_owner_binding_signed_outside_the_engine(
        &sqlite_engine("i4285-engine").await,
    ))
    .await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i4286_sqlite() {
    Box::pin(i4286_the_draft_states_the_software_producers_row(
        &sqlite_engine("i4286-engine").await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
async fn pg_engine(seed: &str) -> Option<crate::Engine> {
    let dsn = crate::test_pg::isolated_dsn()?;
    Some(
        crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer(seed),
            &dsn,
        )
        .await
        .expect("a postgres Engine"),
    )
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4285_postgres() {
    let Some(e) = pg_engine("i4285-engine").await else {
        return;
    };
    Box::pin(i4285_an_owner_binding_signed_outside_the_engine(&e)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4286_postgres() {
    let Some(e) = pg_engine("i4286-engine").await else {
        return;
    };
    Box::pin(i4286_the_draft_states_the_software_producers_row(&e)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i4289_sqlite() {
    Box::pin(i4289_the_self_check_verifies_the_signature(
        &sqlite_engine("i4289-engine").await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4289_postgres() {
    let Some(e) = pg_engine("i4289-engine").await else {
        return;
    };
    Box::pin(i4289_the_self_check_verifies_the_signature(&e)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i4291_sqlite() {
    Box::pin(i4291_the_door_refuses_a_non_person_owner(
        &sqlite_engine("i4291-engine").await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4291_postgres() {
    let Some(e) = pg_engine("i4291-engine").await else {
        return;
    };
    Box::pin(i4291_the_door_refuses_a_non_person_owner(&e)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i4292_sqlite() {
    Box::pin(i4292_the_generic_signature_self_check(
        &sqlite_engine("i4292-engine").await,
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4292_postgres() {
    let Some(e) = pg_engine("i4292-engine").await else {
        return;
    };
    Box::pin(i4292_the_generic_signature_self_check(&e)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i4287_sqlite() {
    let b_signer = crate::federation::tier_ingest::test_support::local_signer("i4287-node");
    let b = crate::Engine::with_signer(b_signer.clone(), "sqlite::memory:")
        .await
        .expect("host B");
    Box::pin(i4287_two_hosts(
        &sqlite_engine("i4287-host-a").await,
        &b,
        &b_signer,
    ))
    .await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i4288_sqlite() {
    use crate::federation::tier_ingest::test_support::local_signer;
    let (cs, bs) = (local_signer("i4288-node-c"), local_signer("i4288-node-b"));
    let c = crate::Engine::with_signer(cs.clone(), "sqlite::memory:")
        .await
        .expect("host C");
    let b = crate::Engine::with_signer(bs.clone(), "sqlite::memory:")
        .await
        .expect("host B");
    Box::pin(i4288_the_node_is_this_engine(&c, &cs, &b, &bs)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4287_postgres() {
    let b_signer = crate::federation::tier_ingest::test_support::local_signer("i4287-node");
    let (Some(dsn_b), Some(a)) = (
        crate::test_pg::isolated_dsn(),
        pg_engine("i4287-host-a").await,
    ) else {
        return;
    };
    let b = crate::Engine::with_signer(b_signer.clone(), &dsn_b)
        .await
        .expect("host B");
    Box::pin(i4287_two_hosts(&a, &b, &b_signer)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4288_postgres() {
    use crate::federation::tier_ingest::test_support::local_signer;
    let (cs, bs) = (local_signer("i4288-node-c"), local_signer("i4288-node-b"));
    let (Some(dsn_c), Some(dsn_b)) = (
        crate::test_pg::isolated_dsn(),
        crate::test_pg::isolated_dsn(),
    ) else {
        return;
    };
    let c = crate::Engine::with_signer(cs.clone(), &dsn_c)
        .await
        .expect("host C");
    let b = crate::Engine::with_signer(bs.clone(), &dsn_b)
        .await
        .expect("host B");
    Box::pin(i4288_the_node_is_this_engine(&c, &cs, &b, &bs)).await;
}
