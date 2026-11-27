//! v62.0.0 (wave O1) — **the shared fixture for `identity:occurrence`
//! binds** (re-exported from [`super::fixture_switch`] as `e2::…`). One
//! builder for every agent's witnesses, so they sign binds one way.
//!
//! Keys are E0's seeds ([`super::fixture_switch::signing_key`],
//! [`super::fixture_switch::kid`]): a seed text, or an identity-ref the
//! fixtures derived. A bind is two (or more) statements over one payload
//! (`edition2::occurrence`):
//! 1. the occurrence key's own statement (`iss` = `sub` = the occurrence);
//! 2. the author's statement (`iss` = `author`): the identity itself, or,
//!    for an agent identity, its OWNER (whose owner binding must be held:
//!    [`put_agent_owner_binding`]).
//!
//! [`occurrence_bind_voices`] returns them in that order, the order the door
//! takes them; [`put_bind`] offers them through `ingest::put_statement`.

use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::sign_row_statement;

use super::fixture_switch::{kid, signing_key};
use super::ingest::{put_statement, StatementOutcome, INGEST_TIER};
use super::occurrence::OCCURRENCE_FAMILY;
use crate::federation::{Error, FederationDirectory};

fn det_map(mut m: Vec<(&str, Value)>) -> Value {
    m.sort_by_key(|(k, _)| cde::encode(&Value::Text((*k).to_owned())));
    Value::Map(
        m.into_iter()
            .map(|(k, v)| (Value::Text(k.to_owned()), v))
            .collect(),
    )
}

/// What a bind states, beyond its keys.
#[derive(Clone, Debug)]
pub struct BindOptions {
    /// `asserted_at`, POSIX ms.
    pub asserted_at_ms: u64,
    /// `valid_until`, POSIX ms; `None` is indefinite.
    pub valid_until_ms: Option<u64>,
    /// Further payload members (`transport_destination`,
    /// `encryption_pubkeys`, the X-Wing keys, ...), as CBOR.
    pub extra: Vec<(&'static str, Value)>,
    /// v7 — the roster row the bind names, `refs.head` (required, CC
    /// 3.3.6.4). `None`: [`put_bind`] states the identity's current head
    /// (`occurrence::current_roster_head`); [`occurrence_bind_voices`]
    /// states none (the door refuses it).
    pub head: Option<super::names::RowId>,
    /// v7 — the other tips the bind merges, `refs.further_heads` (CC rc21).
    /// [`put_bind`] states the current ones when `head` is `None`.
    pub further_heads: Vec<super::names::RowId>,
}

impl Default for BindOptions {
    fn default() -> Self {
        BindOptions {
            asserted_at_ms: super::fixture_switch::ms(crate::host::clock::now()),
            valid_until_ms: None,
            extra: Vec::new(),
            head: None,
            further_heads: Vec::new(),
        }
    }
}

/// **The voices of one bind**: `occurrence`'s own statement, then
/// `author`'s, over the payload binding `occurrence` (a seed or kid) to
/// `identity` (a seed or kid) at `device_class`. `author` is the identity
/// for a person's occurrence and the owner for an agent's.
///
/// # Panics
/// A signing failure.
#[must_use]
pub fn occurrence_bind_voices(
    author: &str,
    identity: &str,
    occurrence: &str,
    device_class: &str,
    opts: &BindOptions,
) -> Vec<Vec<u8>> {
    let (author_ref, occ_ref) = (kid(author), kid(occurrence));
    let payload = bind_payload(author, identity, occurrence, device_class, opts);
    let sign = |seed: &str, iss: &str| sign_voice(seed, iss, &occ_ref, &payload);
    let own = sign(occurrence, &occ_ref);
    if author_ref == occ_ref {
        // The self pair: one statement is both voices.
        return vec![own];
    }
    vec![own, sign(author, &author_ref)]
}

/// `seed`'s statement as `iss` over a bind `payload` whose `sub` is `occ_ref`.
fn sign_voice(seed: &str, iss: &str, occ_ref: &str, payload: &Value) -> Vec<u8> {
    sign_row_statement(
        &signing_key(seed),
        iss,
        occ_ref,
        "scores",
        OCCURRENCE_FAMILY,
        payload,
        vec![],
    )
    .expect("fixture_occurrence: sign a bind voice")
}

/// The payload of [`occurrence_bind_voices`]'s bind.
fn bind_payload(
    author: &str,
    identity: &str,
    occurrence: &str,
    device_class: &str,
    opts: &BindOptions,
) -> Value {
    let (author_ref, identity_ref, occ_ref) = (kid(author), kid(identity), kid(occurrence));
    let mut m = vec![
        ("asserted_at", Value::Uint(opts.asserted_at_ms)),
        ("author", Value::Text(author_ref)),
        ("identity_key_id", Value::Text(identity_ref)),
        ("occurrence_key_id", Value::Text(occ_ref)),
        ("device_class", Value::Text(device_class.to_owned())),
    ];
    if let Some(u) = opts.valid_until_ms {
        m.push(("valid_until", Value::Uint(u)));
    }
    for (k, v) in &opts.extra {
        m.push((*k, v.clone()));
    }
    if let Some(h) = &opts.head {
        let mut refs = vec![("head", ciris_verify_core::edition2::row_ref(&h.0))];
        if !opts.further_heads.is_empty() {
            // v62.0.0 (E2-fix10) — a `row-ref-set`: sorted by encoding, no
            // duplicate (CC 2.6.1.2; `payloads::check_refs`).
            let mut set: Vec<Value> = opts
                .further_heads
                .iter()
                .map(|f| ciris_verify_core::edition2::row_ref(&f.0))
                .collect();
            set.sort_by_key(ciris_verify_core::cde::encode);
            set.dedup();
            refs.push(("further_heads", Value::Array(set)));
        }
        m.push(("refs", det_map(refs)));
    }
    det_map(m)
}

/// **Put a bind**: each of [`occurrence_bind_voices`] through the one entry,
/// in order; the last outcome (`Row` when the bind landed).
///
/// # Errors
/// The door's refusal of any voice.
pub async fn put_bind<D: FederationDirectory + ?Sized>(
    dir: &D,
    author: &str,
    identity: &str,
    occurrence: &str,
    device_class: &str,
    opts: &BindOptions,
) -> Result<StatementOutcome, Error> {
    let mut opts = opts.clone();
    if opts.head.is_none() {
        if let Some((h, further)) =
            super::occurrence::current_roster_heads(dir, &kid(identity)).await?
        {
            opts.head = Some(h);
            opts.further_heads = further;
        }
    }
    let mut last = None;
    for v in occurrence_bind_voices(author, identity, occurrence, device_class, &opts) {
        last = Some(Box::pin(put_statement(dir, &v, None, INGEST_TIER)).await?);
    }
    last.ok_or_else(|| Error::InvalidArgument("fixture_occurrence: no voice".into()))
}

/// **An agent's owner binding**, held as edition-2 statements:
/// `delegates_to(owner → agent)` at `ownership:responsible_party:agent:v1`
/// (family `ownership:{relation}:{target_kind}:{version}`), the owner's
/// statement and the agent's own (`bound_node`), each put through the
/// statement door (VD-step1c: before, they were stored
/// directly and never concluded; [`crate::federation::admission::agent_owner_of`]
/// now counts only a concluded binding).
///
/// # Panics
/// The door refuses a voice, or the binding does not conclude.
pub async fn put_agent_owner_binding<D: FederationDirectory + ?Sized>(
    dir: &D,
    owner: &str,
    agent: &str,
    asserted_at_ms: u64,
) {
    put_agent_owner_binding_placed(
        dir,
        owner,
        agent,
        asserted_at_ms,
        crate::federation::types::cohort_scope::SELF,
        None,
    )
    .await;
}

/// v62.0.0 (BIND-2; CC rc22 rule `owner-binding`, Constitution's ruling (b):
/// "the first binding is written at whatever scope its owner first places
/// the key at") — **[`put_agent_owner_binding`] PLACED**: the agent's owner
/// binding at `cohort_scope`, naming `group` as its placement member where
/// the scope is a group's (`community_id` for `community` / `affiliations`,
/// `family_id` for `family`). The placement says who may hold the row; it
/// counts nobody (`on_behalf_of` does that, and this helper states none). An
/// agent's binding carries no `scope`. Returns the binding's row id (the
/// owner's statement's).
///
/// # Panics
/// A group scope with no `group`, or a `group` at a scope that names none;
/// the door refuses a voice; the binding does not conclude.
pub async fn put_agent_owner_binding_placed<D: FederationDirectory + ?Sized>(
    dir: &D,
    owner: &str,
    agent: &str,
    asserted_at_ms: u64,
    cohort_scope: &str,
    group: Option<&str>,
) -> super::names::RowId {
    use crate::federation::types::cohort_scope as cs;
    let member = match cohort_scope {
        cs::COMMUNITY | cs::AFFILIATIONS => Some("community_id"),
        cs::FAMILY => Some("family_id"),
        _ => None,
    };
    assert_eq!(
        member.is_some(),
        group.is_some(),
        "fixture_occurrence: an agent binding at {cohort_scope:?} names a group exactly when \
         the scope is a group's (got {group:?})"
    );
    let family = ciris_verify_core::namespace_match::family_id(
        "ownership:{relation}:{target_kind}:{version}",
    );
    let agent_ref = kid(agent);
    let mut members = vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        ("author", Value::Text(kid(owner))),
        (
            "dimension",
            Value::Text("ownership:responsible_party:agent:v1".into()),
        ),
        // v62.0.0 (BIND-1) — as the producer states it
        // (`occurrence::agent_owner_binding_payload`).
        (
            "delegation_purpose",
            Value::Text(crate::federation::types::owner_binding::PURPOSE.into()),
        ),
        ("cohort_scope", Value::Text(cohort_scope.to_owned())),
    ];
    if let (Some(m), Some(g)) = (member, group) {
        members.push((m, Value::Text(g.to_owned())));
    }
    let payload = det_map(members);
    let mut binding = None;
    let mut last = None;
    for seed in [owner, agent] {
        let st = sign_row_statement(
            &signing_key(seed),
            &kid(seed),
            &agent_ref,
            "delegates_to",
            &family,
            &payload,
            vec![],
        )
        .expect("fixture_occurrence: sign an owner binding voice");
        if binding.is_none() {
            binding = super::names::RowId::of_statement(&st);
        }
        last = Some(
            Box::pin(put_statement(dir, &st, None, INGEST_TIER))
                .await
                .unwrap_or_else(|e| {
                    panic!("fixture_occurrence: owner binding voice of {seed}: {e}")
                }),
        );
    }
    // v62.0.0 (VD-step1c, F9) — the binding must CONCLUDE: `agent_owner_of`
    // counts a concluded binding only, never kept voices.
    assert!(
        matches!(last, Some(StatementOutcome::Row { .. })),
        "fixture_occurrence: the owner binding {owner} -> {agent} did not conclude: {last:?}"
    );
    binding.expect("fixture_occurrence: the owner's statement has a row id")
}

/// v62.0.0 (WD-fix11; the lead's ruling) — **an occurrence seeded through
/// the signed door**, for a fixture that wrote the retired trusted-local row
/// (`test_seam_put_identity_occurrence`, now `cfg(test)` only, so it is never
/// in a `test-anchor` build). `occ`'s keys are seeds or identity-refs
/// ([`kid`]). The bind is stated as a host's would be: the occurrence key's
/// own statement, then the author's (the identity, or an agent's owner,
/// [`super::occurrence::bind_author`]) signed AS the author by EVERY key on
/// the author's roster now, so the self-roster gate's quorum is met at any
/// roster size (CC 3.3.6.4, the quorum path). It names the identity's
/// current head. The self pair (author = identity = occurrence) is its one
/// statement. Nothing is written but what the door admits.
///
/// # Errors
/// The door's refusal of any statement; `InvalidArgument` for a member that
/// does not decode, or when the bind did not land.
pub async fn put_occurrence_signed<D: FederationDirectory + ?Sized>(
    dir: &D,
    occ: crate::federation::types::IdentityOccurrence,
) -> Result<(), Error> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let bad = |what: &str| Error::InvalidArgument(format!("fixture_occurrence: {what}"));
    let ms = |t: chrono::DateTime<chrono::Utc>| u64::try_from(t.timestamp_millis()).unwrap_or(0);
    let identity = kid(&occ.identity_key_id);
    let occurrence = kid(&occ.occurrence_key_id);
    let asserted_at_ms = ms(occ.asserted_at);
    let author = super::occurrence::bind_author(dir, &identity, asserted_at_ms).await?;
    let b64 = |s: &str| {
        B64.decode(s)
            .map(Value::Bytes)
            .map_err(|e| bad(&format!("not base64: {e}")))
    };
    let mut extra = Vec::new();
    if let Some(h) = &occ.hardware_attestation {
        extra.push(("hardware_attestation", b64(h)?));
    }
    if let Some(e) = &occ.encryption_pubkeys {
        extra.push((
            "encryption_pubkeys",
            det_map(vec![
                ("ml_kem_768", b64(&e.ml_kem_768_base64)?),
                ("x25519", b64(&e.x25519_base64)?),
            ]),
        ));
    }
    if let Some(t) = &occ.transport_binding {
        // The bind's `transport_destination` (CC 3.3.6.2): the destination
        // hash is DERIVED from the keys and name, as the door re-derives it
        // (the row's stated hash is not carried).
        let raw = |s: &str| B64.decode(s).map_err(|e| bad(&format!("not base64: {e}")));
        let (x, ed) = (
            raw(&t.reticulum_x25519_pubkey_base64)?,
            raw(&t.reticulum_ed25519_pubkey_base64)?,
        );
        let dest = ciris_verify_core::transport_binding::compute_destination_hash(
            &t.app_name,
            &t.aspects,
            &x,
            &ed,
        )
        .ok_or_else(|| bad("the transport destination hash does not derive"))?;
        extra.push((
            "transport_destination",
            det_map(vec![
                ("reticulum_x25519_pubkey", Value::Bytes(x)),
                ("reticulum_ed25519_pubkey", Value::Bytes(ed)),
                ("app_name", Value::Text(t.app_name.clone())),
                (
                    "aspects",
                    Value::Array(t.aspects.iter().map(|a| Value::Text(a.clone())).collect()),
                ),
                ("destination_hash", Value::Bytes(dest.to_vec())),
            ]),
        ));
    }
    let (head, further_heads) =
        match super::occurrence::current_roster_heads(dir, &identity).await? {
            Some((h, f)) => (Some(h), f),
            None => (None, Vec::new()),
        };
    let opts = BindOptions {
        asserted_at_ms,
        valid_until_ms: occ.valid_until.map(ms),
        extra,
        head,
        further_heads,
    };
    let voices = occurrence_bind_voices(&author, &identity, &occurrence, &occ.device_class, &opts);
    let mut landed = false;
    // The occurrence key's own statement (the self pair: its one statement).
    let own = voices
        .first()
        .ok_or_else(|| bad("a bind with no statement"))?;
    landed |= matches!(
        Box::pin(put_statement(dir, own, None, INGEST_TIER)).await?,
        StatementOutcome::Row { .. }
    );
    if !landed && voices.len() > 1 {
        // The author's statement by each of the author's roster keys, as the
        // author, over the same payload: the strict majority at any size.
        let mut signers: Vec<String> = crate::federation::self_roster::roster_now(dir, &author)
            .await?
            .into_iter()
            .collect();
        if !signers.contains(&author) {
            signers.insert(0, author.clone());
        }
        let payload = bind_payload(&author, &identity, &occurrence, &occ.device_class, &opts);
        for s in signers {
            let st = sign_voice(&s, &author, &occurrence, &payload);
            if matches!(
                Box::pin(put_statement(dir, &st, None, INGEST_TIER)).await?,
                StatementOutcome::Row { .. }
            ) {
                landed = true;
                break;
            }
        }
    }
    if landed {
        Ok(())
    } else {
        Err(bad(&format!(
            "the bind of {occurrence} under {identity} (author {author}) did not land"
        )))
    }
}

/// v62.0.0 (BIND-3-fx; Constitution's ruling on the login placement: a
/// person's device is announced only by its owner's CHOICE, a second row at
/// `federation`) — **the owner ANNOUNCES `node`**: the node owner binding
/// `delegates_to(owner → node)` placed at `cohort_scope: federation`, as the
/// producer states it (`self_at_login::owner_binding_delegates_to_envelope`'s
/// members: the node dimension, purpose `owner_binding`, the scope set
/// `[infra:serve, infra:network_presence]`), the owner's statement then the
/// node's own (`bound_node`), each through the statement door. A fixture
/// whose node must be announced (a relay hop, a serve seat, an allegiance
/// fact a stranger reads) states it with this step, explicitly: no producer
/// announces a device on its own. Both keys must be held, live at
/// `asserted_at_ms`. Returns the binding's row id.
///
/// # Panics
/// The door refuses a voice, or the binding does not conclude.
pub async fn announce_node_owner<D: FederationDirectory + ?Sized>(
    dir: &D,
    owner: &ciris_crypto::composite::CompositeSigningKey,
    node: &ciris_crypto::composite::CompositeSigningKey,
    asserted_at_ms: u64,
) -> super::names::RowId {
    use crate::federation::types::{cohort_scope, delegation_scope as ds, owner_binding};
    use ciris_verify_core::edition2::{identity_ref, thumbprint};
    let iref_of = |k: &ciris_crypto::composite::CompositeSigningKey| {
        identity_ref(&thumbprint(k.public_key()))
    };
    let (owner_ref, node_ref) = (iref_of(owner), iref_of(node));
    let family = ciris_verify_core::namespace_match::family_id(
        "ownership:{relation}:{target_kind}:{version}",
    );
    let scope = crate::federation::self_at_login::scope_set(&[
        ds::INFRA_SERVE.to_owned(),
        ds::INFRA_NETWORK_PRESENCE.to_owned(),
    ]);
    let payload = det_map(vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        ("author", Value::Text(owner_ref.clone())),
        ("dimension", Value::Text(owner_binding::DIMENSION.into())),
        (
            "delegation_purpose",
            Value::Text(owner_binding::PURPOSE.into()),
        ),
        (
            "scope",
            Value::Array(scope.into_iter().map(Value::Text).collect()),
        ),
        ("cohort_scope", Value::Text(cohort_scope::FEDERATION.into())),
    ]);
    let mut binding = None;
    let mut last = None;
    for (key, iss) in [(owner, &owner_ref), (node, &node_ref)] {
        let st = sign_row_statement(
            key,
            iss,
            &node_ref,
            "delegates_to",
            &family,
            &payload,
            vec![],
        )
        .expect("fixture_occurrence: sign an announcing owner binding voice");
        if binding.is_none() {
            binding = super::names::RowId::of_statement(&st);
        }
        last = Some(
            Box::pin(put_statement(dir, &st, None, INGEST_TIER))
                .await
                .unwrap_or_else(|e| {
                    panic!("fixture_occurrence: announcing owner binding voice of {iss}: {e}")
                }),
        );
    }
    assert!(
        matches!(last, Some(StatementOutcome::Row { .. })),
        "fixture_occurrence: the announcing owner binding {owner_ref} -> {node_ref} did not \
         conclude: {last:?}"
    );
    binding.expect("fixture_occurrence: the owner's statement has a row id")
}

/// v62.0.0 (BIND-3-fx) — [`announce_node_owner`] by fixture seeds
/// ([`signing_key`]).
///
/// # Panics
/// As [`announce_node_owner`].
pub async fn announce_node_owner_seeds<D: FederationDirectory + ?Sized>(
    dir: &D,
    owner_seed: &str,
    node_seed: &str,
    asserted_at_ms: u64,
) -> super::names::RowId {
    announce_node_owner(
        dir,
        &signing_key(owner_seed),
        &signing_key(node_seed),
        asserted_at_ms,
    )
    .await
}
