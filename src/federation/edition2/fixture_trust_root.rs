//! v62.0.0 — **a node ROOTED under the genesis bundle**, stood up through the
//! doors a node uses (CC 3.2 T3–T6).
//!
//! THE ROOT IS THE BUNDLE'S LINEAGE (CC 3.2 T5, "The root is the bundle's
//! lineage"): it is named by the bundle's `family_key_id`, its charter is the
//! bundle's `charter` member, its conferring roster is the bundle's
//! `holders`. "There is no other kind of root. A key that signs a charter
//! about itself is no root." So this fixture founds no root community and
//! signs no charter row (LEAD-root1; the earlier W1b form did both, under a
//! key whose id was also the community's):
//!
//! 1. the genesis bundle in force (`fixture_genesis::install_v2` when none is
//!    held);
//! 2. THIS node's `trust:accepts:v1` edge to the lineage, attached on the
//!    bundle in force (`attached_head_digest`, CC 3.2 T4a);
//! 3. on request ([`put_conferral`]), a grant from the root: a
//!    `trust:confers:v1` row COUNTED over the holders of the bundle in force,
//!    naming that bundle in `refs.head`, and the grantee's acceptance.
//!
//! Every statement goes through the statement door. **Idempotent per
//! directory**: every instant derives from the bundle in force.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::{row_ref, sign_row_statement, Digest32};
use ciris_verify_core::namespace_match;

use super::fixture_genesis;
use super::fixture_switch as e2;
use super::genesis::genesis_in_force;
use super::group_fixtures::row_id_of;
use super::names::RowId;
use crate::federation::{Error, FederationDirectory};

/// What [`rooted_trust_root`] stood up.
#[derive(Clone, Debug)]
pub struct RootedTrustRoot {
    /// The root: the LINEAGE of the bundle in force, by its `family_key_id`
    /// (a name, never a key or a group).
    pub lineage: String,
    /// The object id of the bundle in force the node attached on.
    pub head: Digest32,
    /// The identity-refs of the holders asked for, in the order given.
    pub founders: Vec<String>,
    /// Their holder seeds, same order ([`Self::founder_key`]).
    pub founder_seeds: Vec<u8>,
    /// The protocol asked for (kept for callers that state it).
    pub protocol: String,
    /// THIS node's `trust:accepts:v1` edge to the lineage.
    pub acceptance: RowId,
}

impl RootedTrustRoot {
    /// Holder `i`'s signing key (its bundle-placed holder key).
    #[must_use]
    pub fn founder_key(&self, i: usize) -> CompositeSigningKey {
        fixture_genesis::test_key(self.founder_seeds[i])
    }
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

/// A payload map in deterministic key order.
fn map(members: Vec<(&str, Value)>) -> Value {
    let mut m: Vec<(Value, Value)> = members.into_iter().map(|(k, v)| (text(k), v)).collect();
    m.sort_by_key(|(k, _)| cde::encode(k));
    Value::Map(m)
}

fn refused(step: &str, detail: impl std::fmt::Display) -> Error {
    Error::InvalidArgument(format!("fixture_trust_root: {step}: {detail}"))
}

/// A `delegates_to` statement at a `trust:{job}:{version}` dimension.
fn trust_edge(
    key: &CompositeSigningKey,
    iss: &str,
    sub: &str,
    members: Vec<(&str, Value)>,
) -> Result<Vec<u8>, Error> {
    sign_row_statement(
        key,
        iss,
        sub,
        crate::federation::types::attestation_type::DELEGATES_TO,
        &namespace_match::family_id("trust:{job}:{version}"),
        &map(members),
        vec![],
    )
    .map_err(|e| refused("sign a trust edge", e))
}

/// One voice of the COUNTED root grant of `scope` to `grantee` over the
/// bundle `head` (CC 3.2 T5: counted over the holders of the bundle in force;
/// no `author`; `sub` = the grantee; `refs.head` = the bundle's object id).
///
/// # Panics
/// A signing failure (a fixture).
#[must_use]
pub fn grant_voice(
    key: &CompositeSigningKey,
    iss: &str,
    grantee: &str,
    scope: &[&str],
    head: &Digest32,
    asserted_at_ms: u64,
) -> Vec<u8> {
    let payload = map(vec![
        ("asserted_at", Value::Uint(asserted_at_ms)),
        (
            "dimension",
            text(crate::federation::trust_root::TRUST_CONFERS_DIMENSION),
        ),
        ("refs", map(vec![("head", row_ref(head))])),
        (
            "scope",
            Value::Array(scope.iter().map(|s| text(s)).collect()),
        ),
    ]);
    sign_row_statement(
        key,
        iss,
        grantee,
        crate::federation::types::attestation_type::DELEGATES_TO,
        &namespace_match::family_id("trust:{job}:{version}"),
        &payload,
        vec![],
    )
    .expect("fixture_trust_root: sign a grant voice")
}

/// [`rooted_trust_root`], returning the first refusal.
///
/// # Errors
/// A founder that is not a holder of the bundle in force, no node key, or any
/// door's refusal.
pub async fn try_rooted_trust_root<D>(
    dir: &D,
    founders: &[u8],
    protocol: &str,
) -> Result<RootedTrustRoot, Error>
where
    D: FederationDirectory + ?Sized,
{
    // 1. The genesis bundle in force.
    if !genesis_in_force(dir).await?.is_held() {
        // The production-scope charter: the root can then grant what the
        // production root grants.
        fixture_genesis::install_ceremony_v2(dir, fixture_genesis::bundle_v2_wide()).await?;
    }
    let in_force = genesis_in_force(dir).await?;
    let mut founder_refs = Vec::with_capacity(founders.len());
    for s in founders {
        let iref = fixture_genesis::identity_ref_of(*s);
        if !in_force
            .holders()
            .iter()
            .any(|h| h.identity_ref == iref && h.kid == fixture_genesis::kid_of(*s))
        {
            return Err(refused(
                "founders",
                format!("holder seed {s} is not a holder of the bundle in force at its key"),
            ));
        }
        founder_refs.push(iref);
    }
    let lineage = in_force
        .family_key_id()
        .ok_or_else(|| refused("genesis", "no bundle in force"))?
        .to_owned();
    let head = in_force
        .tips()
        .first()
        .ok_or_else(|| refused("genesis", "no bundle in force"))?
        .object_id;
    let Some(node) = dir.node_key_id() else {
        return Err(refused(
            "node",
            "the directory has no node key: set it first (set_node_key_id(e2::put_key(..)))",
        ));
    };
    // The node signs THIS node's acceptance edge, so its edition-2 key must
    // be live first.
    ensure_live_key(dir, &node, &["node"]).await?;

    // 2. THIS node's acceptance of the lineage, attached on the bundle in
    // force. (The node's own edge: CC 3.2 T3 reads it for that node while its
    // owner has signed none.)
    let acceptance =
        bundle_acceptance_statement(dir, &e2::signing_key(&node), &node, &hex::encode(head))
            .await?;
    e2::put_statement(dir, &acceptance).await?;
    require_concluded(dir, "acceptance", &row_id_of(&acceptance)).await?;

    Ok(RootedTrustRoot {
        lineage,
        head,
        founders: founder_refs,
        founder_seeds: founders.to_vec(),
        protocol: protocol.to_owned(),
        acceptance: row_id_of(&acceptance),
    })
}

/// v62.0.0 (R2-accept; CC 2.6, `hash-digest`) — `bytes` as a hash digest,
/// `[-16, bstr .size 32]`: the form the Constitution's `trust-accepts` rule
/// states `attached_head_digest` in (`payloads::HASH_DIGEST_MEMBERS`).
fn hash_digest(bytes: Vec<u8>) -> Value {
    Value::Array(vec![Value::Nint(15), Value::Bytes(bytes)])
}

/// `iss`'s `trust:accepts:v1` edge to `root` signed by `key`, naming the head
/// `head_hex`. v62.0.0 (R2-accept; the Constitution's `trust-accepts` rule):
/// no `scope` (the edge carries none), the bundle as a hash digest.
fn acceptance_statement_by(
    key: &CompositeSigningKey,
    iss: &str,
    root: &str,
    head_hex: &str,
    at: u64,
) -> Result<Vec<u8>, Error> {
    let head_bytes = hex::decode(head_hex).map_err(|e| refused("acceptance", e))?;
    trust_edge(
        key,
        iss,
        root,
        vec![
            ("author", text(iss)),
            ("asserted_at", Value::Uint(at)),
            (
                "dimension",
                text(crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION),
            ),
            (
                crate::federation::envelope::paths::ATTACHED_HEAD_DIGEST,
                hash_digest(head_bytes),
            ),
        ],
    )
}

/// v62.0.0 (KB-fix1; CC 3.2 at rc22 `87abd2d`) — `iss`'s `trust:accepts:v1`
/// edge to the BUNDLE root: it names the lineage by the `family_key_id` of
/// the bundle in force and, for audit, the bundle it attaches on by object id
/// (`head_hex`), signed by `key`, stated one minute after the bundle's newest
/// tip or one second into `iss`'s own key window, whichever is later. Returns
/// the statement (not put).
///
/// # Errors
/// No bundle in force; a signing failure.
pub async fn bundle_acceptance_statement<D>(
    dir: &D,
    key: &CompositeSigningKey,
    iss: &str,
    head_hex: &str,
) -> Result<Vec<u8>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let in_force = genesis_in_force(dir).await?;
    let root = in_force
        .family_key_id()
        .ok_or_else(|| refused("acceptance", "no bundle in force"))?
        .to_owned();
    let mut at = conferral_instant(dir).await? - 30_000;
    if let Some(rec) = dir.lookup_public_key(iss).await? {
        at = at.max(e2::ms(rec.valid_from).saturating_add(1_000));
    }
    acceptance_statement_by(key, iss, &root, head_hex, at)
}

/// v62.0.0 (RL-fix15) — `iss`'s `trust:accepts:v1` edge to `root` (a bundle
/// lineage's `family_key_id`, literal), signed by `key`, stated at `at`,
/// naming `head_hex` (a bundle object id), or none: a NEW edge naming none
/// is refused `trust_root_head_unnamed` (R2-accept; the fixture states it so
/// the refusal can be witnessed). No `scope`; the bundle as a hash digest.
/// Not put.
///
/// # Errors
/// A `head_hex` that is not hex; a signing failure.
pub fn root_acceptance_statement(
    key: &CompositeSigningKey,
    iss: &str,
    root: &str,
    head_hex: Option<&str>,
    at: u64,
) -> Result<Vec<u8>, Error> {
    let mut members = vec![
        ("author", text(iss)),
        ("asserted_at", Value::Uint(at)),
        (
            "dimension",
            text(crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION),
        ),
    ];
    if let Some(h) = head_hex {
        let head = hex::decode(h).map_err(|e| refused("acceptance", e))?;
        members.push((
            crate::federation::envelope::paths::ATTACHED_HEAD_DIGEST,
            hash_digest(head),
        ));
    }
    trust_edge(key, iss, root, members)
}

/// **Another party accepts the root**: `iss`'s `trust:accepts:v1` edge to the
/// lineage, signed by `key`, attached on the bundle in force (idempotent).
/// Returns the edge's row id.
///
/// # Errors
/// No bundle in force, or the door's refusal.
pub async fn put_acceptance<D>(
    dir: &D,
    r: &RootedTrustRoot,
    key: &CompositeSigningKey,
    iss: &str,
) -> Result<RowId, Error>
where
    D: FederationDirectory + ?Sized,
{
    let st = bundle_acceptance_statement(dir, key, iss, &hex::encode(r.head)).await?;
    e2::put_statement(dir, &st).await?;
    require_concluded(dir, "acceptance", &row_id_of(&st)).await?;
    Ok(row_id_of(&st))
}

/// W1-fix2 — `key` (a kid E0 minted, or a seed) holds a live edition-2
/// `key:record` now; else its record is put (`e2::put_key`, `types`).
async fn ensure_live_key<D>(dir: &D, key: &str, types: &[&str]) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    let Some(kid) = super::ingest::kid_of_identity_ref(&e2::kid(key)) else {
        return Err(refused("key", format!("{key} names no key")));
    };
    let now = u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap_or(0);
    let held = super::ingest::held_keys_for_kid(dir, &kid).await?;
    if !matches!(held.liveness(&kid, now), super::liveness::Liveness::Live(_)) {
        e2::put_key(dir, key, types).await;
    }
    Ok(())
}

/// W1-fix2 — **a fixture row must CONCLUDE** (its typed row is held in
/// `federation_attestations`). A row the fold holds is an `Err` naming the
/// fold's reason and the refusal its gate would have raised, so a red says
/// WHY instead of failing later at a standing read.
async fn require_concluded<D>(dir: &D, step: &str, row_id: &RowId) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    if dir.get_attestation(&row_id.hex()).await?.is_some() {
        return Ok(());
    }
    Err(refused(
        step,
        match super::fold::why_held(dir, row_id).await? {
            Some(h) => format!(
                "row {} concludes nothing: held `{}` ({})",
                row_id.hex(),
                h.reason,
                h.detail
            ),
            None => format!("row {} is neither concluded nor held", row_id.hex()),
        },
    ))
}

/// The instant [`put_conferral`] states a grant at: the bundle in force's
/// newest tip + 90 s (after the root's own rows; idempotent per directory).
async fn conferral_instant<D>(dir: &D) -> Result<u64, Error>
where
    D: FederationDirectory + ?Sized,
{
    Ok(genesis_in_force(dir)
        .await?
        .tips()
        .iter()
        .map(|t| t.asserted_at)
        .max()
        .ok_or_else(|| refused("conferral", "no bundle in force"))?
        + 90_000)
}

/// **The root confers `scope` on `subject_seed`'s key**: the grant COUNTED
/// over holders 0 and 1 of the bundle in force ([`grant_voice`]), then the
/// grantee's own acceptance through the real producer
/// (`membership_acceptance::reply_input`). The subject's key is registered
/// first (`user`) when it is not held. Idempotent. Returns the grant's row
/// id.
///
/// # Errors
/// Either voice's refusal, or the acceptance's.
pub async fn put_conferral(
    dir: &dyn FederationDirectory,
    r: &RootedTrustRoot,
    subject_seed: &str,
    scope: &[&str],
) -> Result<RowId, Error> {
    put_conferral_accepted_by(dir, r, subject_seed, scope, subject_seed).await
}

/// [`put_conferral`] where `acceptor_seed` gives the consent (a machine
/// grantee's OWNER accepts for it).
///
/// # Errors
/// As [`put_conferral`].
pub async fn put_conferral_accepted_by(
    dir: &dyn FederationDirectory,
    r: &RootedTrustRoot,
    subject_seed: &str,
    scope: &[&str],
    acceptor_seed: &str,
) -> Result<RowId, Error> {
    let subject = e2::kid(subject_seed);
    if dir.lookup_public_key(&subject).await?.is_none() {
        e2::put_key(dir, subject_seed, &["user"]).await;
    }
    let at = conferral_instant(dir).await?;
    let c = fixture_genesis::bundle_v2();
    let v0 = grant_voice(
        &c.holder_key(0),
        c.holder_identity_ref(0),
        &subject,
        scope,
        &r.head,
        at,
    );
    let id = row_id_of(&v0);
    let v1 = grant_voice(
        &c.holder_key(1),
        c.holder_identity_ref(1),
        &subject,
        scope,
        &r.head,
        at,
    );
    e2::put_statement(dir, &v0).await?;
    e2::put_statement(dir, &v1).await?;
    require_concluded(dir, "conferral", &id).await?;
    let grant = dir
        .get_attestation(&id.hex())
        .await?
        .ok_or_else(|| refused("conferral", "the grant is not held"))?;
    let already = crate::federation::admission::root_grants_for(
        dir,
        &subject,
        crate::host::clock::now() + chrono::Duration::seconds(1),
    )
    .await?
    .into_iter()
    .any(|g| g.row_id == grant.attestation_id && g.accepted);
    if !already {
        let signer = crate::federation::tier_ingest::test_support::local_signer(acceptor_seed);
        crate::federation::attestation_emit::emit_with_local_signer(
            dir,
            &signer,
            crate::federation::membership_acceptance::reply_input(&grant, true),
        )
        .await?;
    }
    Ok(id)
}

/// **Stand a node up ROOTED under the genesis bundle** (module doc).
///
/// `founders`: holder seeds of the bundle in force (`bundle_v2()`: 1, 2, 3).
/// Precondition: `dir.node_key_id()` is a kid E0 minted in this process.
///
/// # Panics
/// Any refusal ([`try_rooted_trust_root`]).
pub async fn rooted_trust_root<D>(dir: &D, founders: &[u8], protocol: &str) -> RootedTrustRoot
where
    D: FederationDirectory + ?Sized,
{
    try_rooted_trust_root(dir, founders, protocol)
        .await
        .unwrap_or_else(|e| panic!("fixture_trust_root: {e}"))
}
