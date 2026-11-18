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
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::sign_row_statement;

use super::fixture_switch::{kid, signing_key};
use super::ingest::{held_keys_for, put_statement, StatementOutcome, INGEST_TIER};
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
}

impl Default for BindOptions {
    fn default() -> Self {
        BindOptions {
            asserted_at_ms: super::fixture_switch::ms(crate::host::clock::now()),
            valid_until_ms: None,
            extra: Vec::new(),
            head: None,
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
    let (author_ref, identity_ref, occ_ref) = (kid(author), kid(identity), kid(occurrence));
    let mut m = vec![
        ("asserted_at", Value::Uint(opts.asserted_at_ms)),
        ("author", Value::Text(author_ref.clone())),
        ("identity_key_id", Value::Text(identity_ref)),
        ("occurrence_key_id", Value::Text(occ_ref.clone())),
        ("device_class", Value::Text(device_class.to_owned())),
    ];
    if let Some(u) = opts.valid_until_ms {
        m.push(("valid_until", Value::Uint(u)));
    }
    for (k, v) in &opts.extra {
        m.push((*k, v.clone()));
    }
    if let Some(h) = &opts.head {
        m.push((
            "refs",
            det_map(vec![("head", ciris_verify_core::edition2::row_ref(&h.0))]),
        ));
    }
    let payload = det_map(m);
    let sign = |seed: &str, iss: &str| {
        sign_row_statement(
            &signing_key(seed),
            iss,
            &occ_ref,
            "scores",
            OCCURRENCE_FAMILY,
            &payload,
            vec![],
        )
        .expect("fixture_occurrence: sign a bind voice")
    };
    let own = sign(occurrence, &occ_ref);
    if author_ref == occ_ref {
        // The self pair: one statement is both voices.
        return vec![own];
    }
    vec![own, sign(author, &author_ref)]
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
        opts.head = super::occurrence::current_roster_head(dir, &kid(identity)).await?;
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
/// statement and the agent's own (`bound_node`), each admitted by the door
/// and stored ([`crate::federation::admission::agent_owner_of`] reads them).
///
/// # Panics
/// The door refuses a voice; the store refuses it.
pub async fn put_agent_owner_binding<D: FederationDirectory + ?Sized>(
    dir: &D,
    owner: &str,
    agent: &str,
    asserted_at_ms: u64,
) {
    let family = ciris_verify_core::namespace_match::family_id(
        "ownership:{relation}:{target_kind}:{version}",
    );
    let agent_ref = kid(agent);
    let payload = det_map(vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        ("author", Value::Text(kid(owner))),
        (
            "dimension",
            Value::Text("ownership:responsible_party:agent:v1".into()),
        ),
    ]);
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
        let keys = held_keys_for(dir, &st)
            .await
            .unwrap_or_else(|e| panic!("fixture_occurrence: keys for {seed}: {e}"));
        let admitted = super::door::admit_row(&st, &keys, None, SelectContext::default())
            .unwrap_or_else(|e| panic!("fixture_occurrence: owner binding voice of {seed}: {e}"));
        dir.put_edition2_statement(&admitted)
            .await
            .unwrap_or_else(|e| panic!("fixture_occurrence: store {seed}'s voice: {e}"));
    }
}
