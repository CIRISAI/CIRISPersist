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

/// v62.0.0 (HEAD-fix1) — one voice (`seed`'s: the owner's or the agent's)
/// of the agent owner binding [`put_agent_owner_binding`] puts.
///
/// # Panics
/// The statement does not sign.
#[must_use]
pub fn agent_owner_binding_voice(
    owner: &str,
    agent: &str,
    asserted_at_ms: u64,
    seed: &str,
) -> Vec<u8> {
    let family = ciris_verify_core::namespace_match::family_id(
        "ownership:{relation}:{target_kind}:{version}",
    );
    let payload = det_map(vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        ("author", Value::Text(kid(owner))),
        (
            "dimension",
            Value::Text("ownership:responsible_party:agent:v1".into()),
        ),
    ]);
    sign_row_statement(
        &signing_key(seed),
        &kid(seed),
        &kid(agent),
        "delegates_to",
        &family,
        &payload,
        vec![],
    )
    .expect("fixture_occurrence: sign an owner binding voice")
}

/// v62.0.0 (HEAD-fix1; CC 2.4.1.1) — the ROW ID of that binding (the head an
/// act of the agent under it names), computed without a directory: the row
/// id is the payload's and the header's, the same for both voices.
///
/// # Panics
/// Not a row statement.
#[must_use]
pub fn agent_owner_binding_row_id(
    owner: &str,
    agent: &str,
    asserted_at_ms: u64,
) -> super::names::RowId {
    super::names::RowId::of_statement(&agent_owner_binding_voice(
        owner,
        agent,
        asserted_at_ms,
        owner,
    ))
    .expect("fixture_occurrence: an owner binding is a row statement")
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
    let mut last = None;
    for seed in [owner, agent] {
        let st = agent_owner_binding_voice(owner, agent, asserted_at_ms, seed);
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
}
