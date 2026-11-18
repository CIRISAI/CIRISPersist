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
//! - I3032: the agent identity authoring its own occurrence is refused
//!   `agent_occurrence_not_owner_authored`.
//! - I3033: an agent with no owner binding: its bind is refused
//!   `agent_occurrence_unowned`, and nothing is bound.
//! - I3034: an edition-2 bind appears in the signed occurrence listing,
//!   which serves its statements (`ceg_statement`, `ceg_statements`) and no
//!   earlier-form signature.
//! - I3024: `valid_until` not after `asserted_at` is refused
//!   `valid_until_not_after_asserted_at`.
//! - I3025 (pure): the occurrence window is half-open, and a revocation
//!   after an assertion ends it until a later assertion.
//! - I3026 (pure): the door's family model adds the occurrence key's role to
//!   `identity:occurrence` and to no other family.
//! - I3030: no occurrence binds a machine to a person (CC 3.3.6, rc21): an
//!   agent key under a user identity (as `agent` or as `laptop`), and
//!   `device_class: agent` under a user identity, are refused
//!   `occurrence_binds_machine_to_person`; and an agent key is never a key
//!   of its owner's identity (`kid_not_of_iss`).
//! - I3044: the trusted-LOCAL occurrence door keeps the same exclusion: an
//!   agent key under a user, a user key under an agent identity, and
//!   `device_class: agent` under a user are refused
//!   `occurrence_binds_machine_to_person`; a user's device under the user is
//!   stored.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::{FamilyModel as _, RoleParty, VendoredFamilyModel};
use ciris_verify_core::edition2::sign_row_statement;

use super::door_invariants::fixture::{iref, key, key_record, kid, map};
use super::ingest::{held_keys_for, put_statement, StatementOutcome, INGEST_TIER};
use super::liveness::KeyOf;
use super::occurrence::{
    occurrence_live_at, WithOccurrenceRole, OCCURRENCE_FAMILY, OCCURRENCE_KEY_ROLE,
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
        (
            "dimension",
            Value::Text("evidence:safety_battery:capture:a:b:v1".into()),
        ),
    ]);
    sign_row_statement(
        signer,
        iss,
        iss,
        "scores",
        "evidence:.suite:.kind:.cell:.prefix",
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
        let keys = held_keys_for(d, &st).await.unwrap();
        let admitted = super::door::admit_row(
            &st,
            &keys,
            None,
            ciris_verify_core::edition2::family::SelectContext::default(),
        )
        .unwrap_or_else(|e| panic!("owner binding voice of {iss}: {e}"));
        d.put_edition2_statement(&admitted).await.unwrap();
    }
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
    d.put_identity_occurrence_revocation_local(IdentityOccurrenceRevocation {
        identity_key_id: u.clone(),
        occurrence_key_id: iref(&device),
        revoked_at: at(30_000),
        effective_at: at(30_000),
        reason: None,
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
    })
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
    // refused, at its first voice, and nothing is held.
    let unowned = bind_authored(d, &agent_key, &ak, &u, &ai, &ak, "agent", 11_500, None).await;
    let e = put(d, &unowned).await.unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::AGENT_OCCURRENCE_UNOWNED,
        "I3033: {e}"
    );
    assert_eq!(bound(d, &ai, &ak).await, None, "I3033: nothing bound");
    put_agent_owner_binding(d, &user, &agent, 5_000).await;
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
    // I3032: the agent identity authoring its own occurrence is refused,
    // whichever voice arrives.
    for (signer, iss) in [(&agent, ai.as_str()), (&agent_key, ak.as_str())] {
        let st = bind_authored(d, signer, iss, &ai, &ai, &ak, "agent", 13_000, None).await;
        let e = put(d, &st).await.unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::AGENT_OCCURRENCE_NOT_OWNER_AUTHORED,
            "I3032 ({iss}): {e}"
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
            malformed_row::OCCURRENCE_BINDS_MACHINE_TO_PERSON,
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
            .put_identity_occurrence_local(local(identity, occurrence, class))
            .await
            .unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::OCCURRENCE_BINDS_MACHINE_TO_PERSON,
            "{what}: {e}"
        );
        assert_eq!(
            bound(d, identity, occurrence).await,
            None,
            "{what}: nothing stored"
        );
    }
    d.put_identity_occurrence_local(local(&u, &lone_ref, "laptop"))
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

#[test]
fn i3026_the_door_model_adds_the_occurrence_key_role_to_its_family_only() {
    let model = WithOccurrenceRole(&VendoredFamilyModel);
    let rule = model.rule(OCCURRENCE_FAMILY).expect("I3026: registered");
    assert!(rule.authored, "I3026: authored");
    assert!(
        rule.roles
            .iter()
            .any(|(r, p)| r == OCCURRENCE_KEY_ROLE && *p == RoleParty::Sub),
        "I3026: the occurrence key's own voice"
    );
    for other in ["key:revocation", "identity_amendment", "self:delegates_to"] {
        let r = model.rule(other);
        assert!(r.is_some(), "I3026: {other} registered");
        assert_eq!(
            r,
            VendoredFamilyModel.rule(other),
            "I3026: {other} unchanged"
        );
    }
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
