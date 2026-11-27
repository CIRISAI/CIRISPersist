//! **I3020–I3026, I3030, I3032–I3034, I3044** (wave O1; CC 3.3.6, CC 3.3.6.4, CC 3.1.3, the rc21
//! rule): the edition-2 `identity:occurrence` bind and the key-of-issuer
//! check's occurrence arm, on sqlite and postgres.
//!
//! - I3020: a user's second device, bound by the user and its own key,
//!   signs as the user and is admitted (the occurrence arm answers `Yes`).
//! - I3021: once its occurrence is revoked, the same device signing as the
//!   user is refused `kid_not_of_iss`.
//! - I3022: an author statement with no statement of the occurrence key's
//!   own is refused (retryable, naming the occurrence key) and binds
//!   nothing.
//! - I3023: an agent's occurrence binds the agent's own identity and is
//!   AUTHORED by the agent's owner (its `ownership:…:agent:…` binding
//!   held): the owner's statement plus the agent occurrence key's own is
//!   admitted to the occurrence table.
//! - I3032: the agent identity authoring its own occurrence is HELD,
//!   concluding nothing, reason `agent_occurrence_not_owner_authored`
//!   (v62.0.0 wave GC7, CC 2.7.3: the owner is another row's word).
//! - I3033: an agent with no owner binding: its bind is HELD, concluding
//!   nothing, reason `agent_occurrence_unowned`; nothing is bound; once the
//!   owner binding is held the row re-folds and no longer holds.
//! - I3034: an edition-2 bind appears in the signed occurrence listing,
//!   which serves its statements (`ceg_statement`, `ceg_statements`) and no
//!   earlier-form signature.
//! - I3024: `valid_until` not after `asserted_at` is refused
//!   `valid_until_not_after_asserted_at`.
//! - I3025 (pure): the occurrence window is half-open, and a revocation
//!   after an assertion ends it until a later assertion.
//! - I3026 (pure; VA-cc-cut): the door's family model, `VendoredFamilyModel`
//!   (CIRISVerify 23.3.3, CC b016df4), names the occurrence key's role
//!   (`occurrence`, member `occurrence_key_id`) on `identity:occurrence`.
//! - I3030: no occurrence binds a machine to a person (CC 3.3.6, rc21): an
//!   agent key under a user identity (as `agent` or as `laptop`), and
//!   `device_class: agent` under a user identity, are refused
//!   `occurrence_mixes_person_and_machine`; and an agent key is never a key
//!   of its owner's identity (`kid_not_of_iss`).
//! - I3044: the trusted-LOCAL occurrence door keeps the same exclusion: an
//!   agent key under a user, a user key under an agent identity, and
//!   `device_class: agent` under a user are refused
//!   `occurrence_mixes_person_and_machine`; a user's device under the user is
//!   stored.
//! - I2438 (PIN-fix9b; the Constitution's ruling of 2026-11-21, CC 2.4.1) — a
//!   `supersedes` of an occurrence is a REPLACEMENT OCCURRENCE through the
//!   bind's own gates: one that binds a machine class under a person is
//!   refused `occurrence_mixes_person_and_machine`, as the same bind stated
//!   as an ordinary row is; one with no statement of the occurrence key's own
//!   binds nothing (proof of possession); a conforming one (both voices)
//!   lands, and the pair's row is now the replacement's (the replaced bind
//!   retired). PIN-fix9b.rev2 (CC 4.5.5, CC 3.1.3, as Constitution ruled
//!   2026-11-22): an OLDER replacement of the same pair lands as history and
//!   the stored row is unchanged (newest wins); a supersedes naming ANOTHER
//!   pair is refused `supersedes_not_a_replacement`, for either voice, and
//!   binds nothing.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::{FamilyModel as _, RoleParty, VendoredFamilyModel};
use ciris_verify_core::edition2::sign_row_statement;

use super::door_invariants::fixture::{iref, key, key_record, kid, map};
use super::ingest::{held_keys_for, put_statement, StatementOutcome, INGEST_TIER};
use super::liveness::KeyOf;
use super::occurrence::{
    occurrence_live_at, OCCURRENCE_FAMILY, OCCURRENCE_KEY_MEMBER, OCCURRENCE_KEY_ROLE,
};
use crate::federation::types::IdentityOccurrenceRevocation;
use crate::federation::{malformed_row, Error, FederationDirectory};

fn reason(e: &Error) -> String {
    match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    }
}

fn at(ms: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(i64::try_from(ms).unwrap()).unwrap()
}

/// One statement over an `identity:occurrence` payload: `signer` signs as
/// `iss`; the row's `sub` is the occurrence key, its `author` the identity,
/// its `refs.head` the identity's current roster head (CC 3.3.6.4).
#[allow(clippy::too_many_arguments)]
async fn bind(
    d: &dyn FederationDirectory,
    signer: &CompositeSigningKey,
    iss: &str,
    identity: &str,
    occurrence: &str,
    device_class: &str,
    asserted_at: u64,
    valid_until: Option<u64>,
) -> Vec<u8> {
    bind_authored(
        d,
        signer,
        iss,
        identity,
        identity,
        occurrence,
        device_class,
        asserted_at,
        valid_until,
    )
    .await
}

/// [`bind`] with an `author` other than the identity (an agent's owner).
#[allow(clippy::too_many_arguments)]
async fn bind_authored(
    d: &dyn FederationDirectory,
    signer: &CompositeSigningKey,
    iss: &str,
    author: &str,
    identity: &str,
    occurrence: &str,
    device_class: &str,
    asserted_at: u64,
    valid_until: Option<u64>,
) -> Vec<u8> {
    let head = super::occurrence::current_roster_head(d, identity)
        .await
        .unwrap()
        .expect("the identity's key record is held");
    let mut m = vec![
        ("asserted_at", Value::Uint(asserted_at)),
        ("author", Value::Text(author.to_owned())),
        ("identity_key_id", Value::Text(identity.to_owned())),
        ("occurrence_key_id", Value::Text(occurrence.to_owned())),
        ("device_class", Value::Text(device_class.to_owned())),
        (
            "refs",
            map(vec![(
                "head",
                ciris_verify_core::edition2::row_ref(&head.0),
            )]),
        ),
    ];
    if let Some(u) = valid_until {
        m.push(("valid_until", Value::Uint(u)));
    }
    sign_row_statement(
        signer,
        iss,
        occurrence,
        "scores",
        OCCURRENCE_FAMILY,
        &map(m),
        vec![],
    )
    .unwrap()
}

/// An authored score row (the I1909 vector family) `signer` signs as `iss`.
fn row_as(signer: &CompositeSigningKey, iss: &str, asserted_at: u64) -> Vec<u8> {
    let payload = map(vec![
        ("asserted_at", Value::Uint(asserted_at)),
        ("author", Value::Text(iss.to_owned())),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        ("dimension", Value::Text("coherence_standing:cab:v1".into())),
    ]);
    sign_row_statement(
        signer,
        iss,
        iss,
        "scores",
        "coherence_standing:.cohort",
        &payload,
        vec![],
    )
    .unwrap()
}

async fn put(d: &dyn FederationDirectory, st: &[u8]) -> Result<StatementOutcome, Error> {
    Box::pin(put_statement(d, st, None, INGEST_TIER)).await
}

async fn bound(d: &dyn FederationDirectory, identity: &str, occurrence: &str) -> Option<String> {
    d.list_identity_occurrences_for(identity)
        .await
        .unwrap()
        .into_iter()
        .find(|o| o.occurrence_key_id == occurrence)
        .map(|o| o.device_class)
}

/// The owner binding `delegates_to(owner → agent)` of the family
/// `ownership:{relation}:{target_kind}:{version}` at
/// `ownership:responsible_party:agent:v1`: the owner's statement and the
/// agent's own (its `bound_node` second voice), admitted by the door and
/// held as edition-2 statements (what `admission::agent_owner_of` reads).
async fn put_agent_owner_binding(
    d: &dyn FederationDirectory,
    owner: &CompositeSigningKey,
    agent: &CompositeSigningKey,
    asserted_at: u64,
) {
    let family = ciris_verify_core::namespace_match::family_id(
        "ownership:{relation}:{target_kind}:{version}",
    );
    let payload = map(vec![
        ("asserted_at", Value::Uint(asserted_at)),
        ("author", Value::Text(iref(owner))),
        (
            "dimension",
            Value::Text("ownership:responsible_party:agent:v1".into()),
        ),
    ]);
    let mut last = None;
    for (signer, iss) in [(owner, iref(owner)), (agent, iref(agent))] {
        let st = sign_row_statement(
            signer,
            &iss,
            &iref(agent),
            "delegates_to",
            &family,
            &payload,
            vec![],
        )
        .unwrap();
        // v62.0.0 (VD-step1c, F9) — through the statement door: the binding
        // must CONCLUDE (`agent_owner_of` counts a concluded binding only).
        last = Some(
            put(d, &st)
                .await
                .unwrap_or_else(|e| panic!("owner binding voice of {iss}: {e}")),
        );
    }
    assert!(
        matches!(last, Some(StatementOutcome::Row { .. })),
        "the owner binding concludes: {last:?}"
    );
}

pub(crate) async fn body(d: &dyn FederationDirectory) {
    let user = key(70);
    let device = key(71);
    let lone = key(72);
    let agent = key(73);
    let ended = key(74);
    let agent_key = key(75);
    for k in [&user, &device, &lone, &ended] {
        put(d, &key_record(k, &["user"], 0, None)).await.unwrap();
    }
    // An agent identity and its occurrence key; an agent key states an end
    // (CC 2.4.1.1): 1 000 ms to 30 days later.
    for k in [&agent, &agent_key] {
        put(
            d,
            &key_record(k, &["agent"], 1_000, Some(1_000 + 2_592_000_000)),
        )
        .await
        .unwrap();
    }
    let u = iref(&user);

    // I3020: the device's own statement, then the user's, bind it.
    let own = bind(
        d,
        &device,
        &iref(&device),
        &u,
        &iref(&device),
        "phone",
        10_000,
        None,
    )
    .await;
    let StatementOutcome::Voice { row_id, new: true } = put(d, &own).await.unwrap() else {
        panic!("I3020: the occurrence key's own statement is held as a voice");
    };
    assert_eq!(
        bound(d, &u, &iref(&device)).await,
        None,
        "I3020: one voice binds nothing"
    );
    let by_user = bind(d, &user, &u, &u, &iref(&device), "phone", 10_000, None).await;
    assert_eq!(
        put(d, &by_user).await.unwrap(),
        StatementOutcome::Row { row_id, new: true },
        "I3020: the author's statement lands the bind"
    );
    assert_eq!(
        bound(d, &u, &iref(&device)).await.as_deref(),
        Some("phone"),
        "I3020: the bind is in the occurrence table"
    );
    // The device signs as the user: a key of the user's, and admitted.
    let signed = row_as(&device, &u, 20_000);
    let keys = held_keys_for(d, &signed).await.unwrap();
    assert_eq!(
        keys.key_of(&kid(&device), &kid(&user)),
        KeyOf::Yes,
        "I3020: the occurrence arm"
    );
    let out = put(d, &signed).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Row { .. })),
        "I3020: the second device signing as the user is admitted: {out:?}"
    );

    // I3021: revoked at 30 000 ms, its later statement as the user is not
    // of the user's.
    d.put_identity_occurrence_revocation_edition2(
        IdentityOccurrenceRevocation {
            identity_key_id: u.clone(),
            occurrence_key_id: iref(&device),
            revoked_at: at(30_000),
            effective_at: at(30_000),
            reason: None,
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
        },
        crate::federation::DoorToken::new(),
    )
    .await
    .unwrap();
    let after = row_as(&device, &u, 40_000);
    let keys = held_keys_for(d, &after).await.unwrap();
    assert_eq!(
        keys.key_of(&kid(&device), &kid(&user)),
        KeyOf::No,
        "I3021: a revoked occurrence is not a key of its identity"
    );
    let e = put(d, &after).await.unwrap_err();
    assert_eq!(reason(&e), malformed_row::KID_NOT_OF_ISS, "I3021: {e}");

    // I3022: the user's statement alone, the occurrence key silent.
    let alone = bind(d, &user, &u, &u, &iref(&lone), "laptop", 11_000, None).await;
    let e = put(d, &alone).await.unwrap_err();
    assert_eq!(
        e.kind(),
        "federation_attester_key_unknown",
        "I3022: retryable, waiting on the occurrence key's own statement: {e}"
    );
    assert!(e.to_string().contains(&iref(&lone)), "I3022 names it: {e}");
    assert_eq!(
        bound(d, &u, &iref(&lone)).await,
        None,
        "I3022: nothing bound"
    );

    // I3023: an agent's occurrence binds the AGENT's identity, authored by
    // the agent's OWNER (its owner binding held), plus the agent occurrence
    // key's own statement.
    let ai = iref(&agent);
    let ak = iref(&agent_key);
    // I3033 (first, before any owner binding): an unowned agent's bind is
    // HELD (v62.0.0 wave GC7): kept, concluding nothing, with the reason.
    let unowned = bind_authored(d, &agent_key, &ak, &u, &ai, &ak, "agent", 11_500, None).await;
    let out = put(d, &unowned).await;
    let Ok(StatementOutcome::Pending {
        row_id: unowned_row,
        ..
    }) = out
    else {
        panic!("I3033: the unowned agent's bind is held: {out:?}");
    };
    assert_eq!(
        super::fold::why_held(d, &unowned_row)
            .await
            .unwrap()
            .map(|h| h.reason),
        Some(super::fold::reason::AGENT_OCCURRENCE_UNOWNED.to_owned()),
        "I3033: held, reason agent_occurrence_unowned"
    );
    assert_eq!(bound(d, &ai, &ak).await, None, "I3033: nothing bound");
    put_agent_owner_binding(d, &user, &agent, 5_000).await;
    // The fixture stores the binding's voices directly (no door tail), so
    // the re-fold its arrival would run is run here.
    super::fold::refold_rows(d, std::iter::once(unowned_row).collect())
        .await
        .unwrap();
    assert_eq!(
        super::fold::why_held(d, &unowned_row).await.unwrap(),
        None,
        "I3033: the owner binding held, the row no longer holds"
    );
    let agent_own = bind_authored(d, &agent_key, &ak, &u, &ai, &ak, "agent", 12_000, None).await;
    assert!(
        matches!(put(d, &agent_own).await, Ok(StatementOutcome::Voice { .. })),
        "I3023: the agent key's own statement is held"
    );
    let by_owner = bind_authored(d, &user, &u, &u, &ai, &ak, "agent", 12_000, None).await;
    assert!(
        matches!(put(d, &by_owner).await, Ok(StatementOutcome::Row { .. })),
        "I3023: the owner's statement lands the agent bind"
    );
    assert_eq!(
        bound(d, &ai, &ak).await.as_deref(),
        Some("agent"),
        "I3023: the agent bind is in the occurrence table"
    );
    // I3032: the agent identity authoring its own occurrence is HELD,
    // concluding nothing, whichever voice arrives (v62.0.0 wave GC7).
    for (signer, iss) in [(&agent, ai.as_str()), (&agent_key, ak.as_str())] {
        let st = bind_authored(d, signer, iss, &ai, &ai, &ak, "agent", 13_000, None).await;
        let out = put(d, &st).await;
        let Ok(StatementOutcome::Pending { row_id, .. }) = out else {
            panic!("I3032 ({iss}): held: {out:?}");
        };
        assert_eq!(
            super::fold::why_held(d, &row_id)
                .await
                .unwrap()
                .map(|h| h.reason),
            Some(super::fold::reason::AGENT_OCCURRENCE_NOT_OWNER_AUTHORED.to_owned()),
            "I3032 ({iss}): reason agent_occurrence_not_owner_authored"
        );
    }

    // I3034: edition-2 binds appear in the signed listing, carrying their
    // statements (`ceg_statement`, the author's) instead of a signature.
    for (identity, occ, author_st) in [(&u, iref(&device), &by_user), (&ai, ak.clone(), &by_owner)]
    {
        let listed = d
            .list_signed_identity_occurrences_for(identity)
            .await
            .unwrap();
        let o = listed
            .iter()
            .find(|o| o.identity_occurrence.occurrence_key_id == occ)
            .unwrap_or_else(|| panic!("I3034: {occ} is in the signed listing of {identity}"));
        assert_eq!(
            o.signed_envelope
                .get(super::ingest::STATEMENT_MEMBER)
                .and_then(serde_json::Value::as_str),
            Some(hex::encode(author_st).as_str()),
            "I3034: the listing serves the author's statement"
        );
        assert!(
            o.signed_envelope
                .get("ceg_statements")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|a| a.len() >= 2),
            "I3034: and every voice"
        );
        assert!(
            o.signature.mldsa65_signature_base64.is_none()
                && o.signature.ed25519_signature_base64.is_empty(),
            "I3034: no earlier-form signature"
        );
    }

    // I3030: no occurrence binds a machine to a person (CC 3.3.6, rc21).
    // (a) an agent key under the user, `device_class` agent;
    // (b) the same key under the user as a `laptop`;
    // (c) a user-typed key under the user with `device_class` agent.
    let lone_ref = iref(&lone);
    for (what, signer, occ, class) in [
        ("I3030 (a)", &agent_key, ak.as_str(), "agent"),
        ("I3030 (b)", &agent_key, ak.as_str(), "laptop"),
        ("I3030 (c)", &lone, lone_ref.as_str(), "agent"),
    ] {
        let st = bind(d, signer, occ, &u, occ, class, 14_000, None).await;
        let e = put(d, &st).await.unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::OCCURRENCE_MIXES_PERSON_AND_MACHINE,
            "{what}: {e}"
        );
        assert_eq!(bound(d, &u, occ).await, None, "{what}: nothing bound");
    }
    // I3044: the trusted-LOCAL door keeps the same exclusion. (a) an agent
    // key under the user; (b) a user key under the agent identity; (c)
    // `device_class` agent under the user with a user-typed key; and the
    // control, (d) a user's device under the user, is stored.
    let local = |identity: &str, occurrence: &str, class: &str| {
        crate::federation::types::IdentityOccurrence {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: occurrence.to_owned(),
            device_class: class.to_owned(),
            hardware_attestation: None,
            asserted_at: at(2_000),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        }
    };
    for (what, identity, occurrence, class) in [
        ("I3044 (a)", u.as_str(), ak.as_str(), "agent"),
        ("I3044 (b)", ai.as_str(), lone_ref.as_str(), "laptop"),
        ("I3044 (c)", u.as_str(), lone_ref.as_str(), "agent"),
    ] {
        let e = d
            .test_seam_put_identity_occurrence(local(identity, occurrence, class))
            .await
            .unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::OCCURRENCE_MIXES_PERSON_AND_MACHINE,
            "{what}: {e}"
        );
        assert_eq!(
            bound(d, identity, occurrence).await,
            None,
            "{what}: nothing stored"
        );
    }
    d.test_seam_put_identity_occurrence(local(&u, &lone_ref, "laptop"))
        .await
        .expect("I3044 (d): a user's device under the user is stored");

    // (d) an agent key never signs as its owner's identity (no door binds
    // it under the user, I3030 (a) and I3044 (a)).
    let as_owner = row_as(&agent_key, &u, 20_000);
    let keys = held_keys_for(d, &as_owner).await.unwrap();
    assert_eq!(
        keys.key_of(&kid(&agent_key), &kid(&user)),
        KeyOf::No,
        "I3030 (d): an agent key is never a key of a person"
    );
    let e = put(d, &as_owner).await.unwrap_err();
    assert_eq!(reason(&e), malformed_row::KID_NOT_OF_ISS, "I3030 (d): {e}");

    // I3024: an end not after the assertion, equal or earlier.
    for until in [13_000, 12_999] {
        let st = bind(
            d,
            &ended,
            &iref(&ended),
            &u,
            &iref(&ended),
            "laptop",
            13_000,
            Some(until),
        )
        .await;
        let e = put(d, &st).await.unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::VALID_UNTIL_NOT_AFTER_ASSERTED_AT,
            "I3024 ({until}): {e}"
        );
    }
    assert_eq!(
        bound(d, &u, &iref(&ended)).await,
        None,
        "I3024: nothing bound"
    );
}

#[test]
fn i3025_the_occurrence_window_is_half_open() {
    let asserted = [(1_000, Some(2_000))];
    assert!(occurrence_live_at(&asserted, &[], 1_000), "I3025: from");
    assert!(occurrence_live_at(&asserted, &[], 1_999), "I3025: inside");
    assert!(
        !occurrence_live_at(&asserted, &[], 2_000),
        "I3025: not at valid_until"
    );
    assert!(
        !occurrence_live_at(&asserted, &[], 999),
        "I3025: not before"
    );
    let open = [(1_000, None)];
    assert!(
        occurrence_live_at(&open, &[], u64::MAX),
        "I3025: indefinite"
    );
    // A revocation in effect after the assertion ends it ...
    assert!(
        occurrence_live_at(&open, &[5_000], 4_999),
        "I3025: before it"
    );
    assert!(
        !occurrence_live_at(&open, &[5_000], 5_000),
        "I3025: revoked"
    );
    // ... until a later assertion re-establishes it; an older one is void.
    let again = [(1_000, None), (6_000, None)];
    assert!(
        occurrence_live_at(&again, &[5_000], 6_000),
        "I3025: re-established"
    );
    assert!(
        occurrence_live_at(&[(6_000, None)], &[5_000], 7_000),
        "I3025: older revocation"
    );
}

/// v62.0.0 (VA-cc-cut; CIRISVerify 23.3.3, CC v1.0-rc21 b016df4) — I3026
/// re-anchored: the door reads `VendoredFamilyModel` directly, and CC's own
/// cell names the occurrence key's role (`occurrence`, member
/// `occurrence_key_id`) on `identity:occurrence`, authored. (Green only on
/// 23.3.3's model: at e6fd7c6 the cell named no second signer, which the
/// deleted `PersistCells` overlay supplied.)
#[test]
fn i3026_the_vendored_model_names_the_occurrence_key_role() {
    let rule = VendoredFamilyModel
        .rule(OCCURRENCE_FAMILY)
        .expect("I3026: registered");
    assert!(rule.authored, "I3026: authored");
    assert!(
        rule.roles.iter().any(|(r, p)| r == OCCURRENCE_KEY_ROLE
            && *p == RoleParty::Member(OCCURRENCE_KEY_MEMBER.to_owned())),
        "I3026: the occurrence key's own voice is CC's cell"
    );
}

/// A `supersedes` of the held bind `target`: [`bind`]'s payload, naming
/// `target` by `refs.target` beside the identity's current roster head.
#[allow(clippy::too_many_arguments)]
async fn supersede(
    d: &dyn FederationDirectory,
    signer: &CompositeSigningKey,
    iss: &str,
    identity: &str,
    occurrence: &str,
    device_class: &str,
    asserted_at: u64,
    target: &super::names::RowId,
) -> Vec<u8> {
    let head = super::occurrence::current_roster_head(d, identity)
        .await
        .unwrap()
        .expect("the identity's roster head is held");
    let m = vec![
        ("asserted_at", Value::Uint(asserted_at)),
        ("author", Value::Text(identity.to_owned())),
        ("identity_key_id", Value::Text(identity.to_owned())),
        ("occurrence_key_id", Value::Text(occurrence.to_owned())),
        ("device_class", Value::Text(device_class.to_owned())),
        (
            "refs",
            map(vec![
                ("head", ciris_verify_core::edition2::row_ref(&head.0)),
                ("target", ciris_verify_core::edition2::row_ref(&target.0)),
            ]),
        ),
    ];
    sign_row_statement(
        signer,
        iss,
        occurrence,
        "supersedes",
        OCCURRENCE_FAMILY,
        &map(m),
        vec![],
    )
    .unwrap()
}

/// I2438: a replacement occurrence takes the bind's gates.
pub(crate) async fn replacement_body(d: &dyn FederationDirectory) {
    let (user, device) = (key(80), key(81));
    for k in [&user, &device] {
        put(d, &key_record(k, &["user"], 0, None)).await.unwrap();
    }
    let (u, dv) = (iref(&user), iref(&device));
    // The bind it replaces: the device's own statement, then the user's.
    put(
        d,
        &bind(d, &device, &dv, &u, &dv, "phone", 10_000, None).await,
    )
    .await
    .unwrap();
    let by_user = bind(d, &user, &u, &u, &dv, "phone", 10_000, None).await;
    let Ok(StatementOutcome::Row { row_id: target, .. }) = put(d, &by_user).await else {
        panic!("I2438: the bind it replaces lands");
    };
    assert_eq!(bound(d, &u, &dv).await.as_deref(), Some("phone"));
    // A machine class under the person: the bind's refusal, for either.
    let plain = put(d, &bind(d, &user, &u, &u, &dv, "agent", 11_000, None).await)
        .await
        .unwrap_err();
    assert_eq!(
        reason(&plain),
        malformed_row::OCCURRENCE_MIXES_PERSON_AND_MACHINE,
        "I2438 the ordinary bind: {plain}"
    );
    let mixed = put(
        d,
        &supersede(d, &user, &u, &u, &dv, "agent", 11_000, &target).await,
    )
    .await
    .unwrap_err();
    assert_eq!(
        reason(&mixed),
        reason(&plain),
        "I2438 the replacement's refusal is the bind's: {mixed}"
    );
    assert_eq!(
        bound(d, &u, &dv).await.as_deref(),
        Some("phone"),
        "I2438 a refused replacement retires nothing"
    );
    // Possession: the author's statement alone binds nothing.
    let alone = put(
        d,
        &supersede(d, &user, &u, &u, &dv, "laptop", 12_000, &target).await,
    )
    .await;
    assert!(
        alone.is_err(),
        "I2438 a replacement with no statement of the occurrence key's own: {alone:?}"
    );
    assert_eq!(bound(d, &u, &dv).await.as_deref(), Some("phone"));
    // A conforming replacement: both voices; the pair's row is replaced.
    let own = supersede(d, &device, &dv, &u, &dv, "laptop", 13_000, &target).await;
    let by_user = supersede(d, &user, &u, &u, &dv, "laptop", 13_000, &target).await;
    let first = put(d, &own).await;
    assert!(
        matches!(first, Ok(StatementOutcome::Voice { .. })),
        "I2438 the occurrence key's own statement is held: {first:?}"
    );
    let out = put(d, &by_user).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Row { .. })),
        "I2438 the conforming replacement lands: {out:?}"
    );
    assert_eq!(
        bound(d, &u, &dv).await.as_deref(),
        Some("laptop"),
        "I2438 the pair's row is the replacement's: the replaced bind is retired"
    );
    // PIN-fix9b.rev2 — an OLDER replacement of the same pair lands as
    // history; the stored row is unchanged (newest wins).
    let own = supersede(d, &device, &dv, &u, &dv, "phone", 11_500, &target).await;
    let by_user = supersede(d, &user, &u, &u, &dv, "phone", 11_500, &target).await;
    put(d, &own)
        .await
        .expect("I2438 the older replacement's own voice");
    let out = put(d, &by_user).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Row { .. })),
        "I2438 an older replacement of the same pair lands as history: {out:?}"
    );
    assert_eq!(
        bound(d, &u, &dv).await.as_deref(),
        Some("laptop"),
        "I2438 the newer row stays: newest wins"
    );
    // PIN-fix9b.rev2 (CC 4.5.5, CC 3.1.3) — a supersedes naming ANOTHER pair
    // (a new device "replacing" the old) is refused by name, for either
    // voice; replacing a device is the self-roster door.
    let other = key(82);
    put(d, &key_record(&other, &["user"], 0, None))
        .await
        .unwrap();
    let ov = iref(&other);
    for (signer, iss, what) in [
        (&other, ov.clone(), "its own voice"),
        (&user, u.clone(), "the author's"),
    ] {
        let e = put(
            d,
            &supersede(d, signer, &iss, &u, &ov, "laptop", 14_000, &target).await,
        )
        .await
        .unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::SUPERSEDES_NOT_A_REPLACEMENT,
            "I2438 another pair, {what}: {e}"
        );
    }
    assert_eq!(
        bound(d, &u, &ov).await,
        None,
        "I2438 nothing bound for the other key"
    );
    assert_eq!(
        bound(d, &u, &dv).await.as_deref(),
        Some("laptop"),
        "I2438 and the target's pair is untouched"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2438_a_replacement_occurrence_takes_the_binds_gates_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(replacement_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2438_a_replacement_occurrence_takes_the_binds_gates_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(replacement_body(&b)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3020_to_i3024_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3020_to_i3024_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

// ─────────────────────────────────────────────────────────────────────────
//  I3910 (wave GC7; CC 2.7.3) — the agent-owner fold, either arrival order
// ─────────────────────────────────────────────────────────────────────────

/// The owner binding of [`put_agent_owner_binding`], with the door's tail
/// re-fold run for each voice (`fold::refold_touched` over what the voice
/// touches), so the dependency index, not the test, wakes the held bind.
async fn put_agent_owner_binding_refolding(
    d: &dyn FederationDirectory,
    owner: &CompositeSigningKey,
    agent: &CompositeSigningKey,
    asserted_at: u64,
) {
    let family = ciris_verify_core::namespace_match::family_id(
        "ownership:{relation}:{target_kind}:{version}",
    );
    let payload = map(vec![
        ("asserted_at", Value::Uint(asserted_at)),
        ("author", Value::Text(iref(owner))),
        (
            "dimension",
            Value::Text("ownership:responsible_party:agent:v1".into()),
        ),
    ]);
    let mut last = None;
    for (signer, iss) in [(owner, iref(owner)), (agent, iref(agent))] {
        let st = sign_row_statement(
            signer,
            &iss,
            &iref(agent),
            "delegates_to",
            &family,
            &payload,
            vec![],
        )
        .unwrap();
        // v62.0.0 (VD-step1c, F9) — through the statement door, whose tail
        // runs the re-fold (`fold::after_statement`): the binding must
        // CONCLUDE, and the dependency index, not the test, wakes the bind.
        last = Some(
            put(d, &st)
                .await
                .unwrap_or_else(|e| panic!("I3910: owner binding voice of {iss}: {e}")),
        );
    }
    assert!(
        matches!(last, Some(StatementOutcome::Row { .. })),
        "I3910: the owner binding concludes: {last:?}"
    );
}

/// One store, one arrival order: the agent's occurrence key's own statement
/// (the bind's first voice) and the owner binding, `bind_first` deciding
/// which lands first; then the owner's statement. Returns what the store
/// answers at the end: the held reason of the bind's row (none) and the
/// occurrence table's device class.
async fn i3910_one_order(
    d: &dyn FederationDirectory,
    bind_first: bool,
) -> (Option<String>, Option<String>) {
    let user = key(90);
    let agent = key(91);
    let agent_key = key(92);
    put(d, &key_record(&user, &["user"], 0, None))
        .await
        .unwrap();
    for k in [&agent, &agent_key] {
        put(
            d,
            &key_record(k, &["agent"], 1_000, Some(1_000 + 2_592_000_000)),
        )
        .await
        .unwrap();
    }
    let (u, ai, ak) = (iref(&user), iref(&agent), iref(&agent_key));
    let own = bind_authored(d, &agent_key, &ak, &u, &ai, &ak, "agent", 12_000, None).await;
    let row_id = if bind_first {
        let out = put(d, &own).await;
        let Ok(StatementOutcome::Pending { row_id, .. }) = out else {
            panic!("I3910: with no owner binding held, the bind is held: {out:?}");
        };
        assert_eq!(
            super::fold::why_held(d, &row_id)
                .await
                .unwrap()
                .map(|h| h.reason),
            Some(super::fold::reason::AGENT_OCCURRENCE_UNOWNED.to_owned()),
            "I3910: held, concluding nothing, reason agent_occurrence_unowned"
        );
        assert_eq!(bound(d, &ai, &ak).await, None, "I3910: nothing bound");
        put_agent_owner_binding_refolding(d, &user, &agent, 5_000).await;
        row_id
    } else {
        put_agent_owner_binding_refolding(d, &user, &agent, 5_000).await;
        let out = put(d, &own).await;
        let Ok(StatementOutcome::Voice { row_id, .. }) = out else {
            panic!("I3910: with the owner binding held, the key's own voice is kept: {out:?}");
        };
        row_id
    };
    let held_after_binding = super::fold::why_held(d, &row_id)
        .await
        .unwrap()
        .map(|h| h.reason);
    let by_owner = bind_authored(d, &user, &u, &u, &ai, &ak, "agent", 12_000, None).await;
    let out = put(d, &by_owner).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Row { row_id: r, .. }) if r == row_id),
        "I3910 (bind_first={bind_first}): the owner's statement lands the bind: {out:?}"
    );
    (held_after_binding, bound(d, &ai, &ak).await)
}

/// I3910 (wave GC7; CC 2.7.3): an agent occurrence bind whose owner binding
/// is not held is HELD (reason `agent_occurrence_unowned`), never refused;
/// the owner binding's arrival re-folds it through the dependency index; and
/// the answer is the same whichever arrived first: no hold, and the bind in
/// the occurrence table once the owner's statement lands.
async fn i3910_body(first: &dyn FederationDirectory, second: &dyn FederationDirectory) {
    let a = i3910_one_order(first, true).await;
    let b = i3910_one_order(second, false).await;
    assert_eq!(
        a.0, None,
        "I3910: the owner binding's arrival releases the hold"
    );
    assert_eq!(a, b, "I3910: the same answer for either arrival order");
    assert_eq!(a.1.as_deref(), Some("agent"), "I3910: the bind landed");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3910_agent_owner_fold_order_sqlite() {
    use crate::store::Backend as _;
    let open = || async {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    };
    let (x, y) = (open().await, open().await);
    Box::pin(i3910_body(&x, &y)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3910_agent_owner_fold_order_postgres() {
    use crate::store::Backend as _;
    let mut stores = Vec::new();
    for _ in 0..2 {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        stores.push(b);
    }
    Box::pin(i3910_body(&stores[0], &stores[1])).await;
}

/// v62.0.0 (KR-fix43b; Constitution's correction of CC 2.4.1.1) — **I4352
/// (agent) and I4353**: an AGENT key's owner ends the owner binding two ways,
/// and neither ends the agent key.
///
/// - **I4352** — the owner's `key:revocation` of the agent key, under its
///   binding, is ADMITTED (kept, concluded): from its instant the agent is
///   unowned (`agent_owner_of`), before it still owned; the agent key stays
///   LIVE (no key's revocation but its own ends its liveness). A STRANGER's
///   `key:revocation` of the same key is HELD `key_revocation_no_standing`
///   and changes nothing.
/// - **I4353** — the owner's `withdraws` of the agent's owner binding (the
///   agent-unbind witness): from its instant the agent is unowned.
async fn owner_ends_the_agent_binding_body(d: &dyn FederationDirectory) {
    use super::door_invariants::fixture::revocation;
    use crate::federation::admission::agent_owner_of;
    let (owner, stranger) = (key(80), key(81));
    for k in [&owner, &stranger] {
        put(d, &key_record(k, &["user"], 0, None)).await.unwrap();
    }
    let (agent_r, agent_w) = (key(82), key(83));
    for k in [&agent_r, &agent_w] {
        put(
            d,
            &key_record(k, &["agent"], 1_000, Some(1_000 + 2_592_000_000)),
        )
        .await
        .unwrap();
    }

    // ── I4352: the owner revokes the agent key under the binding.
    put_agent_owner_binding(d, &owner, &agent_r, 5_000).await;
    let ar = iref(&agent_r);
    assert_eq!(
        agent_owner_of(d, &ar, 15_000).await.unwrap(),
        Some(iref(&owner)),
        "I4352 precondition: owned"
    );
    let by_stranger = revocation(&stranger, &agent_r, 18_000, None);
    let out = put(d, &by_stranger).await;
    let Ok(StatementOutcome::Pending { row_id, .. }) = out else {
        panic!("I4352: a stranger's key:revocation is kept and held: {out:?}");
    };
    assert_eq!(
        super::fold::why_held(d, &row_id)
            .await
            .unwrap()
            .map(|h| h.reason),
        Some(super::fold::reason::KEY_REVOCATION_NO_STANDING.to_owned()),
        "I4352: held key_revocation_no_standing"
    );
    assert_eq!(
        agent_owner_of(d, &ar, 19_000).await.unwrap(),
        Some(iref(&owner)),
        "I4352: a stranger's revocation ends nothing"
    );
    let by_owner = revocation(&owner, &agent_r, 20_000, None);
    let out = put(d, &by_owner).await;
    assert!(
        matches!(out, Ok(StatementOutcome::KeyPlane { .. })),
        "I4352: the owner's key:revocation under its binding is admitted: {out:?}"
    );
    assert_eq!(
        agent_owner_of(d, &ar, 19_999).await.unwrap(),
        Some(iref(&owner)),
        "I4352: before its instant the agent is still owned"
    );
    assert_eq!(
        agent_owner_of(d, &ar, 25_000).await.unwrap(),
        None,
        "I4352: from its instant the agent is unowned"
    );
    let held = super::ingest::held_keys_for_kid(d, &kid(&agent_r))
        .await
        .unwrap();
    assert!(
        matches!(
            held.liveness(&kid(&agent_r), 25_000),
            super::liveness::Liveness::Live(_)
        ),
        "I4352: the agent key stays LIVE: only its own revocation ends it"
    );

    // ── I4353: the owner withdraws the agent's owner binding.
    let binding = put_agent_owner_binding_returning(d, &owner, &agent_w, 5_000).await;
    let aw = iref(&agent_w);
    assert_eq!(
        agent_owner_of(d, &aw, 15_000).await.unwrap(),
        Some(iref(&owner)),
        "I4353 precondition: owned"
    );
    let family = ciris_verify_core::namespace_match::family_id(
        "ownership:{relation}:{target_kind}:{version}",
    );
    let withdraws = sign_row_statement(
        &owner,
        &iref(&owner),
        &aw,
        crate::federation::types::attestation_type::WITHDRAWS,
        &family,
        &map(vec![
            ("asserted_at", Value::Uint(30_000)),
            ("author", Value::Text(iref(&owner))),
            ("refs", super::emit::refs_target(&binding.0)),
        ]),
        vec![],
    )
    .unwrap();
    let out = put(d, &withdraws).await;
    assert!(
        matches!(out, Ok(StatementOutcome::Row { .. })),
        "I4353: the owner's withdraws of the agent binding lands: {out:?}"
    );
    assert_eq!(
        agent_owner_of(d, &aw, 35_000).await.unwrap(),
        None,
        "I4353: from its instant the agent is unowned"
    );
}

/// [`put_agent_owner_binding`], returning the binding's row id.
async fn put_agent_owner_binding_returning(
    d: &dyn FederationDirectory,
    owner: &CompositeSigningKey,
    agent: &CompositeSigningKey,
    asserted_at: u64,
) -> super::names::RowId {
    let family = ciris_verify_core::namespace_match::family_id(
        "ownership:{relation}:{target_kind}:{version}",
    );
    let payload = map(vec![
        ("asserted_at", Value::Uint(asserted_at)),
        ("author", Value::Text(iref(owner))),
        (
            "dimension",
            Value::Text("ownership:responsible_party:agent:v1".into()),
        ),
    ]);
    let mut id = None;
    for (signer, iss) in [(owner, iref(owner)), (agent, iref(agent))] {
        let st = sign_row_statement(
            signer,
            &iss,
            &iref(agent),
            "delegates_to",
            &family,
            &payload,
            vec![],
        )
        .unwrap();
        id = super::names::RowId::of_statement(&st);
        put(d, &st)
            .await
            .unwrap_or_else(|e| panic!("owner binding voice of {iss}: {e}"));
    }
    id.expect("the binding's row id")
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i4352_i4353_the_owner_ends_the_agent_binding_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(owner_ends_the_agent_binding_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4352_i4353_the_owner_ends_the_agent_binding_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(owner_ends_the_agent_binding_body(&b)).await;
}
