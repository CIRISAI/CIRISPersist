//! v62.0.0 (RL-fix2; Constitution's ruling on the node code, Eric
//! 2026-11-20: "no directory services, but you can add a peer with a
//! nodecode; it includes the transport hint") — **first contact between
//! rootless nodes, persist's part.**
//!
//! The code layout is Verify's and is not parsed here: a host decodes the
//! code and hands persist the decoded fields. The code commits to the node's
//! KEY by its kid. It carries no pin and no transit commitment: the node's
//! own signed route row authenticates its transit pair through the pre-seal
//! route request (CC 5.3.3.10 E1 steps 5–9; CC 3.3.6.2; CC 5.3.4 "Before the
//! first sealed link"; CC 5.4.6). "Rooted standing is not required to seal …
//! two peers who hold each other's signed bindings seal and root each other
//! with no canonical in the path" (CC 3.3.6, part_3 l.1887).
//!
//! The path, as a host walks it:
//!
//! 1. **Dial hint** ([`record_dial_hints`]): from the decoded code, a LOCAL,
//!    UNSIGNED record per node kid — the node's 64-byte Reticulum transport
//!    identity (X25519 ‖ Ed25519) and an ORDERED list of opaque `(tag,
//!    body)` hints, 1:1 with Verify's edition-2 FedCode `Endpoint` (most
//!    preferred first; possibly empty), optionally the identity kid the
//!    code named and its kind. It is never a transit pair and never served
//!    to another node; it lives in its own table, so no route, binding or
//!    transit read can confuse it with a signed row.
//! 2. **Pre-seal answer** ([`admit_pre_seal_answer`]): the node's own
//!    `key:record` and its own `identity:occurrence` bind carrying
//!    `transport_destination` and `transit_xwing_pubkey`, admitted only if
//!    the key record's thumbprint is the dialled kid and the node signed and
//!    is the subject of both. Any mismatch is a named refusal with NOTHING
//!    stored (E1 step 7: "a row signed by or about another key is refused
//!    and never stored"). Then `transit_kex_pair_for` answers from the
//!    edition-2 bind arm.
//! 3. **After the seal** ([`admit_contact_owner_rows`]): for a `user` code,
//!    the owner's key record and owner binding, admitted only if the owner's
//!    thumbprint is the code's identity kid and the binding binds the node.
//!    A `node` code has no owner check.

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::{identity_ref, Digest32};
use serde::{Deserialize, Serialize};

use super::ingest::{
    apply_replicated_statement, kid_of_identity_ref, statement_kid, ReplicatedStatementOutcome,
};
use super::liveness::{recorded_kid, statement_parts, HeldKeys};
use super::names::RowId;
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The plane this module's refusals name.
pub const PLANE: &str = "contact";

/// The owner-binding family a bound key's binding is filed under.
const OWNERSHIP_FAMILY: &str = "ownership:{relation}:{target_kind}:{version}";

/// The most hints one node's endpoint carries (Verify's edition-2 FedCode:
/// 4 hints per node).
pub const MAX_DIAL_HINTS: usize = 4;
/// The most bytes of the code's whole payload (Verify's FedCode cap): one
/// node's hint bodies together never exceed it.
pub const MAX_DIAL_HINT_PAYLOAD_BYTES: usize = 1024;
/// The most bytes one hint body carries (inside the payload cap).
pub const MAX_DIAL_HINT_BODY_BYTES: usize = 255;
/// A Reticulum transport public identity: X25519 (32) ‖ Ed25519 (32).
pub const TRANSPORT_IDENTITY_LEN: usize = 64;

/// One transport hint, OPAQUE to persist and 1:1 with Verify's FedCode
/// `Hint` (`Tcp` / `Udp` / `Auto` / `RNode` / `Http` / `Unknown { tag, body
/// }`): its wire tag and its body bytes, in the code's order. The dialler
/// interprets the tag and skips one it does not know; an unknown hint
/// round-trips unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DialHint {
    /// The hint's wire tag (Verify pins the vocabulary).
    pub tag: u16,
    /// The hint's body, as the code carries it.
    pub body: Vec<u8>,
}

/// What the code said the contact is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactKind {
    /// A person's code: `identity` is the person, and the node is theirs.
    User,
    /// A node's own code: no owner is named, and none is checked.
    Node,
}

/// **The local dial hint of one node** (never signed, never served).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DialHints {
    /// The node's identity-ref (its kid, as the code commits to it).
    pub node: String,
    /// The node's Reticulum transport identity, X25519 ‖ Ed25519 (64 bytes).
    pub transport_identity: Vec<u8>,
    /// The hints, in the code's order, most preferred first. May be empty.
    pub hints: Vec<DialHint>,
    /// The identity-ref the code named, if any.
    pub identity: Option<String>,
    /// What the code said the contact is, if it said.
    pub kind: Option<ContactKind>,
    /// When this record was written (POSIX ms, this node's clock).
    pub recorded_at_ms: i64,
}

/// What the pre-seal door admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreSealAdmission {
    /// The node's key record at the replicated door.
    pub key_record: ReplicatedStatementOutcome,
    /// The node's bind at the replicated door.
    pub route: ReplicatedStatementOutcome,
    /// Does `transit_kex_pair_for(node)` answer now (the dialler can seal)?
    pub transit_ready: bool,
}

/// What the post-seal owner door admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactOwner {
    /// The outcomes, the owner's key record first, then each binding voice.
    pub outcomes: Vec<ReplicatedStatementOutcome>,
    /// Does the node's one live owner resolve to the code's identity now?
    /// (`false` while the binding is held, e.g. short of the node's voice.)
    pub owner_resolved: bool,
}

fn refuse(reason: &'static str, detail: impl Into<String>) -> Error {
    Error::malformed_row(PLANE, reason, detail)
}

fn kid_of(what: &str, s: &str) -> Result<Digest32, Error> {
    kid_of_identity_ref(s).ok_or_else(|| {
        Error::InvalidArgument(format!("contact: `{what}` is not an identity-ref: {s:?}"))
    })
}

/// The statement's header family, CWT `iss` and `sub`.
fn header(statement: &[u8]) -> Option<(String, Option<String>, Option<String>, Value)> {
    let (protected, payload) = statement_parts(statement)?;
    let family = protected.get_int(-70002)?.as_text()?.to_owned();
    let claims = protected.get_int(15);
    let text = |label: i64| {
        claims
            .and_then(|c| c.get_int(label))
            .and_then(Value::as_text)
            .map(str::to_owned)
    };
    Some((family, text(1), text(2), payload))
}

fn payload_text(payload: &Value, member: &str) -> Option<String> {
    payload
        .get_text(member)
        .and_then(Value::as_text)
        .map(str::to_owned)
}

/// The Ed25519 half of a held key's federation key, if held.
async fn federation_ed25519_of<F>(dir: &F, key: &str) -> Result<Option<Vec<u8>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use base64::Engine as _;
    Ok(dir.lookup_public_key(key).await?.and_then(|k| {
        base64::engine::general_purpose::STANDARD
            .decode(k.pubkey_ed25519_base64)
            .ok()
    }))
}

/// **Record a node's dial hint** from a decoded code. Re-recording the same
/// node replaces its list. Refused (nothing written):
///
/// - [`malformed_row::DIAL_HINT_OUT_OF_BOUNDS`] — a transport
///   identity not [`TRANSPORT_IDENTITY_LEN`] bytes, more than
///   [`MAX_DIAL_HINTS`] hints, a body over [`MAX_DIAL_HINT_BODY_BYTES`], or
///   bodies past [`MAX_DIAL_HINT_PAYLOAD_BYTES`] with the identity;
/// - [`malformed_row::FEDCODE_TRANSPORT_IS_FEDERATION_KEY`] (Verify's own
///   token, so a host sees one name whichever layer caught it) — the
///   transport identity's Ed25519 half is the node's or its owner's
///   federation key's Ed25519 half, where this node holds that key (CC 2.6.8
///   constraint 1: a transport key is never a federation key). The owner is
///   the code's identity, and the node's live owner if one resolves.
///
/// `recorded_at_ms` is overwritten with this node's clock.
///
/// # Errors
/// The refusals above; `node` or `identity` not an identity-ref; the store.
pub async fn record_dial_hints<F>(dir: &F, mut hints: DialHints) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    kid_of("node", &hints.node)?;
    if let Some(i) = &hints.identity {
        kid_of("identity", i)?;
    }
    let body_total: usize = hints.hints.iter().map(|h| h.body.len()).sum();
    if hints.transport_identity.len() != TRANSPORT_IDENTITY_LEN
        || hints.hints.len() > MAX_DIAL_HINTS
        || hints
            .hints
            .iter()
            .any(|h| h.body.len() > MAX_DIAL_HINT_BODY_BYTES)
        || body_total + TRANSPORT_IDENTITY_LEN > MAX_DIAL_HINT_PAYLOAD_BYTES
    {
        return Err(refuse(
            malformed_row::DIAL_HINT_OUT_OF_BOUNDS,
            format!(
                "a dial hint record carries a {TRANSPORT_IDENTITY_LEN}-byte transport identity \
                 and at most {MAX_DIAL_HINTS} hints of at most {MAX_DIAL_HINT_BODY_BYTES} bytes, \
                 within the code's {MAX_DIAL_HINT_PAYLOAD_BYTES}-byte payload"
            ),
        ));
    }
    let transport_ed25519 = &hints.transport_identity[32..];
    let mut federation_keys = vec![hints.node.clone()];
    federation_keys.extend(hints.identity.clone());
    match crate::federation::admission::owner_of_unmarked(dir, &hints.node).await {
        Ok(Some(o)) => federation_keys.push(o),
        Ok(None) | Err(Error::AmbiguousNodeOwner { .. }) => {}
        Err(e) => return Err(e),
    }
    for k in &federation_keys {
        if federation_ed25519_of(dir, k)
            .await?
            .is_some_and(|ed| ed.as_slice() == transport_ed25519)
        {
            return Err(refuse(
                malformed_row::FEDCODE_TRANSPORT_IS_FEDERATION_KEY,
                format!(
                    "the transport identity's Ed25519 half is {k}'s federation key; a transport \
                     key is never a federation key (CC 2.6.8)"
                ),
            ));
        }
    }
    hints.recorded_at_ms = crate::host::clock::now().timestamp_millis();
    dir.put_dial_hints(&hints).await
}

/// **The dial hint this node holds for `node`**, if any.
///
/// # Errors
/// The store.
pub async fn dial_hints_for<F>(dir: &F, node: &str) -> Result<Option<DialHints>, Error>
where
    F: FederationDirectory + ?Sized,
{
    dir.dial_hints_for(node).await
}

/// **Every dial hint this node holds**, by node: "who can I dial" on a node
/// with no directory service.
///
/// # Errors
/// The store.
pub async fn list_dial_hints<F>(dir: &F) -> Result<Vec<DialHints>, Error>
where
    F: FederationDirectory + ?Sized,
{
    dir.list_dial_hints().await
}

/// **Remove a contact's dial hint** (a removed contact keeps none). `false`
/// when none was held.
///
/// # Errors
/// The store.
pub async fn remove_dial_hints<F>(dir: &F, node: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    dir.remove_dial_hints(node).await
}

/// The pure checks of the pre-seal answer (E1 steps 5–7): every one runs
/// before anything is stored.
fn check_pre_seal_rows(n: &Digest32, key_record: &[u8], route: &[u8]) -> Result<(), Error> {
    let n_ref = identity_ref(n);
    // (i) the key record is the dialled key's, in its own voice.
    let record_ok = header(key_record)
        .is_some_and(|(f, ..)| f == ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY)
        && recorded_kid(key_record).as_ref() == Some(n)
        && statement_kid(key_record).as_ref() == Some(n);
    if !record_ok {
        return Err(refuse(
            malformed_row::CODE_NODE_KEY_MISMATCH,
            format!(
                "the key record answered for {n_ref} is not that key's own record (the code \
                 commits to the node's key by its kid)"
            ),
        ));
    }
    // (ii) the route is the node's own bind of itself: signed by N, about N.
    let Some((family, _iss, sub, payload)) = header(route) else {
        return Err(refuse(
            malformed_row::CODE_ROUTE_SIGNER_MISMATCH,
            "the route answered is not an edition-2 row statement",
        ));
    };
    let own = family == super::occurrence::OCCURRENCE_FAMILY
        && statement_kid(route).as_ref() == Some(n)
        && sub.as_deref() == Some(n_ref.as_str())
        && payload_text(&payload, "occurrence_key_id").as_deref() == Some(n_ref.as_str())
        && payload_text(&payload, "identity_key_id").as_deref() == Some(n_ref.as_str())
        && payload_text(&payload, "author").as_deref() == Some(n_ref.as_str());
    if !own {
        return Err(refuse(
            malformed_row::CODE_ROUTE_SIGNER_MISMATCH,
            format!(
                "the route answered for {n_ref} is not that node's own `identity:occurrence` \
                 bind of itself, signed by it (E1 step 7: a row signed by or about another key \
                 is refused and never stored)"
            ),
        ));
    }
    // (iii) it carries a route and a transit key.
    let carries = payload.get_text("transport_destination").is_some()
        && payload
            .get_text(crate::federation::self_at_login::TRANSIT_XWING_PUBKEY_MEMBER)
            .and_then(Value::as_bytes)
            .is_some();
    if !carries {
        return Err(refuse(
            malformed_row::CODE_ROUTE_CARRIES_NO_TRANSIT_KEY,
            format!("the bind answered for {n_ref} carries no route or no transit key"),
        ));
    }
    Ok(())
}

async fn offer<F>(dir: &F, st: &[u8]) -> Result<ReplicatedStatementOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let id = RowId::of_statement(st).ok_or_else(|| {
        refuse(
            malformed_row::CODE_ROUTE_SIGNER_MISMATCH,
            "a contact row is not a row statement",
        )
    })?;
    Box::pin(apply_replicated_statement(dir, st, &id.0)).await
}

/// **The checked admission of a pre-seal answer** (CC 5.3.3.10 E1 steps
/// 5–9), for the node `dialled` (its identity-ref, from the dial hint):
///
/// - (i) `key_record` records the dialled key and is signed by it, else
///   [`malformed_row::CODE_NODE_KEY_MISMATCH`];
/// - (ii) `route` is the node's own `identity:occurrence` bind of itself
///   (signer, subject, identity and author all the node), else
///   [`malformed_row::CODE_ROUTE_SIGNER_MISMATCH`];
/// - (iii) it carries `transport_destination` and `transit_xwing_pubkey`,
///   else [`malformed_row::CODE_ROUTE_CARRIES_NO_TRANSIT_KEY`] (the in-row
///   key separation is the bind door's own rule, `occurrence_xwing_*`);
/// - (iv) both signatures verify, under the answered key record alone, by
///   the door's own verifier (`door::admit_row`), before either is stored.
///
/// On any refusal NOTHING is stored. Then the key record goes through the
/// replicated door (the key plane: own voice), then the bind (the occurrence
/// plane: a self pair needs no owner, so it concludes with no owner row
/// held), and `transit_ready` says whether `transit_kex_pair_for` answers.
///
/// # Errors
/// The refusals above; the doors' own refusals; `dialled` not an
/// identity-ref; directory failures.
pub async fn admit_pre_seal_answer<F>(
    dir: &F,
    dialled: &str,
    key_record: &[u8],
    route: &[u8],
) -> Result<PreSealAdmission, Error>
where
    F: FederationDirectory + ?Sized,
{
    let n = kid_of("dialled", dialled)?;
    check_pre_seal_rows(&n, key_record, route)?;
    // (iv) verify both against the answered record, as the statement door
    // does (held keys, the record offered as its own source), storing
    // nothing yet.
    let mut keys = HeldKeys::new();
    keys.insert_record(key_record.to_vec());
    for st in [key_record, route] {
        let ctx = super::typed::family_context(dir, st).await?;
        super::door::admit_row(st, &keys, None, ctx)?;
    }
    let key_out = offer(dir, key_record).await?;
    let route_out = offer(dir, route).await?;
    let transit_ready =
        crate::federation::self_at_login::transit_kex_pair_for(dir, &identity_ref(&n))
            .await?
            .is_some();
    Ok(PreSealAdmission {
        key_record: key_out,
        route: route_out,
        transit_ready,
    })
}

/// The pure checks of the post-seal owner rows.
fn check_owner_rows(
    node: &Digest32,
    identity: &Digest32,
    owner_key_record: &[u8],
    binding: &[Vec<u8>],
) -> Result<(), Error> {
    let (node_ref, id_ref) = (identity_ref(node), identity_ref(identity));
    let record_ok = recorded_kid(owner_key_record).as_ref() == Some(identity)
        && statement_kid(owner_key_record).as_ref() == Some(identity);
    if !record_ok {
        return Err(refuse(
            malformed_row::CODE_OWNER_MISMATCH,
            format!("the owner's key record is not {id_ref}'s own (the code's identity kid)"),
        ));
    }
    let mut by_owner = false;
    for st in binding {
        let Some((family, _iss, sub, payload)) = header(st) else {
            return Err(refuse(
                malformed_row::CODE_OWNER_BINDING_NOT_FOR_NODE,
                "an owner binding voice is not an edition-2 row statement",
            ));
        };
        let signer = statement_kid(st);
        // A person's owner binding is `self:delegates_to`; one at the
        // `ownership:responsible_party:node:v1` dimension names the bound
        // key as `sub` under the `ownership:{..}` family.
        let ownership = ciris_verify_core::namespace_match::family_id(OWNERSHIP_FAMILY);
        let ok = (family == super::emit::DELEGATES_TO_FAMILY
            || family == OWNERSHIP_FAMILY
            || family == ownership)
            && sub.as_deref() == Some(node_ref.as_str())
            && payload_text(&payload, "author").as_deref() == Some(id_ref.as_str())
            && (signer.as_ref() == Some(identity) || signer.as_ref() == Some(node));
        if !ok {
            return Err(refuse(
                malformed_row::CODE_OWNER_BINDING_NOT_FOR_NODE,
                format!("an owner binding voice does not bind {node_ref} to {id_ref}"),
            ));
        }
        by_owner |= signer.as_ref() == Some(identity);
    }
    if !by_owner {
        return Err(refuse(
            malformed_row::CODE_OWNER_BINDING_NOT_FOR_NODE,
            format!("no owner binding voice is {id_ref}'s own"),
        ));
    }
    Ok(())
}

/// **The post-seal owner check** for a `user` code: the contact's owner key
/// record and owner binding, after the seal. The owner's key record must be
/// the code's `identity` kid's own ([`malformed_row::CODE_OWNER_MISMATCH`]),
/// and every binding voice must bind `node` to that identity, at least one
/// in the identity's own voice
/// ([`malformed_row::CODE_OWNER_BINDING_NOT_FOR_NODE`]). On a refusal
/// nothing of the owner rows is stored, and the node's two public rows
/// confer nothing. Then each row goes through the replicated door (a voice
/// that waits on another is re-offered after it), and `owner_resolved` says
/// whether the node's one live owner is now the code's identity.
///
/// # Errors
/// The refusals above; the doors' refusals of a row that never lands;
/// `node` or `identity` not an identity-ref; directory failures.
pub async fn admit_contact_owner_rows<F>(
    dir: &F,
    node: &str,
    identity: &str,
    owner_key_record: &[u8],
    binding: &[Vec<u8>],
) -> Result<ContactOwner, Error>
where
    F: FederationDirectory + ?Sized,
{
    let n = kid_of("node", node)?;
    let i = kid_of("identity", identity)?;
    check_owner_rows(&n, &i, owner_key_record, binding)?;
    let mut outcomes = vec![offer(dir, owner_key_record).await?];
    let mut pending: Vec<&Vec<u8>> = binding.iter().collect();
    while !pending.is_empty() {
        let before = pending.len();
        let mut waiting = Vec::new();
        let mut last = None;
        for st in pending {
            match offer(dir, st).await {
                Ok(o) => outcomes.push(o),
                Err(e) if e.is_wait() => {
                    last = Some(e);
                    waiting.push(st);
                }
                Err(e) => return Err(e),
            }
        }
        if waiting.len() == before {
            return Err(last.expect("a waiting voice carries its wait"));
        }
        pending = waiting;
    }
    let owner_resolved = crate::federation::admission::owner_of_unmarked(dir, node)
        .await
        .ok()
        .flatten()
        .as_deref()
        == Some(identity);
    Ok(ContactOwner {
        outcomes,
        owner_resolved,
    })
}

/// sqlite: replace `hints.node`'s record.
///
/// # Errors
/// sqlite errors; a record that does not serialize.
#[cfg(feature = "sqlite")]
pub fn put_sqlite(conn: &mut rusqlite::Connection, hints: &DialHints) -> Result<(), Error> {
    let body =
        serde_json::to_string(hints).map_err(|e| Error::Backend(format!("ceg_dial_hints: {e}")))?;
    conn.execute(
        "INSERT INTO ceg_dial_hints (node, body, recorded_at_ms) VALUES (?1, ?2, ?3) \
         ON CONFLICT (node) DO UPDATE SET body = excluded.body, \
         recorded_at_ms = excluded.recorded_at_ms",
        rusqlite::params![hints.node, body, hints.recorded_at_ms],
    )
    .map(|_| ())
    .map_err(|e| Error::Backend(format!("ceg_dial_hints: {e}")))
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn parse(body: &str) -> Result<DialHints, Error> {
    serde_json::from_str(body).map_err(|e| Error::Backend(format!("ceg_dial_hints: {e}")))
}

/// sqlite: one node's record.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn get_sqlite(conn: &rusqlite::Connection, node: &str) -> Result<Option<DialHints>, Error> {
    use rusqlite::OptionalExtension as _;
    let body: Option<String> = conn
        .query_row(
            "SELECT body FROM ceg_dial_hints WHERE node = ?1",
            rusqlite::params![node],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| Error::Backend(format!("ceg_dial_hints: {e}")))?;
    body.as_deref().map(parse).transpose()
}

/// sqlite: every record, by node.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn list_sqlite(conn: &rusqlite::Connection) -> Result<Vec<DialHints>, Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_dial_hints: {e}"));
    let mut st = conn
        .prepare("SELECT body FROM ceg_dial_hints ORDER BY node")
        .map_err(be)?;
    let bodies = st
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(be)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(be)?;
    bodies.iter().map(|b| parse(b)).collect()
}

/// sqlite: remove one node's record.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn remove_sqlite(conn: &mut rusqlite::Connection, node: &str) -> Result<bool, Error> {
    conn.execute(
        "DELETE FROM ceg_dial_hints WHERE node = ?1",
        rusqlite::params![node],
    )
    .map(|n| n > 0)
    .map_err(|e| Error::Backend(format!("ceg_dial_hints: {e}")))
}

/// postgres: replace `hints.node`'s record.
///
/// # Errors
/// postgres errors; a record that does not serialize.
#[cfg(feature = "postgres")]
pub async fn put_postgres<C>(client: &C, hints: &DialHints) -> Result<(), Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let body =
        serde_json::to_string(hints).map_err(|e| Error::Backend(format!("ceg_dial_hints: {e}")))?;
    client
        .execute(
            "INSERT INTO cirislens.ceg_dial_hints (node, body, recorded_at_ms) \
             VALUES ($1, $2, $3) ON CONFLICT (node) DO UPDATE SET body = EXCLUDED.body, \
             recorded_at_ms = EXCLUDED.recorded_at_ms",
            &[&hints.node, &body, &hints.recorded_at_ms],
        )
        .await
        .map(|_| ())
        .map_err(|e| Error::Backend(format!("ceg_dial_hints: {e}")))
}

/// postgres: one node's record.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn get_postgres<C>(client: &C, node: &str) -> Result<Option<DialHints>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let row = client
        .query_opt(
            "SELECT body FROM cirislens.ceg_dial_hints WHERE node = $1",
            &[&node],
        )
        .await
        .map_err(|e| Error::Backend(format!("ceg_dial_hints: {e}")))?;
    row.map(|r| parse(&r.get::<_, String>(0))).transpose()
}

/// postgres: every record, by node.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn list_postgres<C>(client: &C) -> Result<Vec<DialHints>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let rows = client
        .query(
            "SELECT body FROM cirislens.ceg_dial_hints ORDER BY node",
            &[],
        )
        .await
        .map_err(|e| Error::Backend(format!("ceg_dial_hints: {e}")))?;
    rows.iter().map(|r| parse(&r.get::<_, String>(0))).collect()
}

/// postgres: remove one node's record.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn remove_postgres<C>(client: &C, node: &str) -> Result<bool, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    client
        .execute(
            "DELETE FROM cirislens.ceg_dial_hints WHERE node = $1",
            &[&node],
        )
        .await
        .map(|n| n > 0)
        .map_err(|e| Error::Backend(format!("ceg_dial_hints: {e}")))
}
