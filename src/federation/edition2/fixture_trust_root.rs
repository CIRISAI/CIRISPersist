//! v62.0.0 (wave W1b) — **a ROOTED edition-2 trust root**, stood up through
//! the doors a node uses (CC 3.2 T2/T3, CC 4.4.3.34):
//!
//! 1. the genesis bundle in force (`fixture_genesis::install_v2` when none is
//!    held);
//! 2. the root's key: an identity-ref (`e2::kid(ROOT_SEED)`);
//! 3. an `infrastructure` community at that identity-ref, founded by holders
//!    of the bundle in force through T1's `group:roster` voices (the birth is
//!    counted over the bundle's holders, `edition2::trust_root_group`);
//! 4. the root's `trust:charter:v1` self-edge `delegates_to(root → root)`,
//!    scope `infra:serve` + `infra:attest`, with a pre-rotation commitment
//!    over a successor key's material;
//! 5. THIS node's `trust:accepts:v1` edge `delegates_to(node → root)`, naming
//!    the root's held head (CC 3.2 T4a).
//!
//! Every statement goes through `ingest::put_statement`. See `W1.api.md`.
//!
//! **Idempotent per directory** (for the same founders and protocol, while
//! the bundle in force is the same): every statement is stated at an instant
//! derived from the bundle in force, so a second call re-puts identical
//! bytes and returns identical ids. Two directories standing the root up
//! independently hold byte-identical statements too.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::recovery::recovery_commitment;
use ciris_verify_core::edition2::sign_row_statement;
use ciris_verify_core::namespace_match;

use super::fixture_genesis;
use super::fixture_switch as e2;
use super::genesis::genesis_in_force;
use super::group::GroupRecord;
use super::group_fixtures::{put_voices, roster_voices, row_id_of};
use super::ingest::StatementOutcome;
use super::names::RowId;
use crate::federation::types::{Community, CommunityMember};
use crate::federation::{Error, FederationDirectory};

/// The root's E0 seed: the root's identity-ref is `e2::kid(ROOT_SEED)`.
pub const ROOT_SEED: &str = "w1-rooted-trust-root";

/// The seed of the successor key the root's charter commits to.
pub const ROOT_SUCCESSOR_SEED: &str = "w1-rooted-trust-root-successor";

/// What [`rooted_trust_root`] stood up.
#[derive(Clone, Debug)]
pub struct RootedTrustRoot {
    /// The root's identity-ref (the community_key_id, `e2::kid(ROOT_SEED)`).
    pub root: String,
    /// The founders' identity-refs, in the order given.
    pub founders: Vec<String>,
    /// The founders' holder seeds, same order ([`Self::founder_key`]).
    pub founder_seeds: Vec<u8>,
    /// The `consensus_protocol` the root was founded at.
    pub protocol: String,
    /// The founding `group:roster` version's row id.
    pub birth: RowId,
    /// The root's `trust:charter:v1` self-edge.
    pub charter: RowId,
    /// THIS node's `trust:accepts:v1` edge to the root.
    pub acceptance: RowId,
}

impl RootedTrustRoot {
    /// Founder `i`'s signing key (its bundle-placed holder key).
    #[must_use]
    pub fn founder_key(&self, i: usize) -> CompositeSigningKey {
        fixture_genesis::test_key(self.founder_seeds[i])
    }
}

fn instant(ms: u64) -> chrono::DateTime<chrono::Utc> {
    i64::try_from(ms)
        .ok()
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .expect("fixture_trust_root: an instant")
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

/// The root's `trust:confers:v1` grant `delegates_to(root → subject)` with
/// `scope`, stated at `asserted_at_ms`, signed by the root's key. Verify's
/// rule for the `confers` leaf asks the subject for a second voice
/// (`delegate: sub`): add it with `e2::voice_of(&st, subject_seed)`.
///
/// # Panics
/// A signing failure (a fixture).
#[must_use]
pub fn confers_statement(
    r: &RootedTrustRoot,
    subject: &str,
    scope: &[&str],
    asserted_at_ms: u64,
) -> Vec<u8> {
    trust_edge(
        &e2::signing_key(ROOT_SEED),
        &r.root,
        subject,
        vec![
            ("author", text(&r.root)),
            ("asserted_at", Value::Uint(asserted_at_ms)),
            (
                "dimension",
                text(crate::federation::trust_root::TRUST_CONFERS_DIMENSION),
            ),
            (
                "scope",
                Value::Array(scope.iter().map(|s| text(s)).collect()),
            ),
        ],
    )
    .expect("fixture_trust_root: sign a conferral")
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
        fixture_genesis::install_v2(dir).await?;
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
    let Some(node) = dir.node_key_id() else {
        return Err(refused(
            "node",
            "the directory has no node key: set it first (set_node_key_id(e2::put_key(..)))",
        ));
    };

    // 2. The root's key.
    let root = e2::put_key(dir, ROOT_SEED, &["user"]).await;

    // 3. The founding. IDEMPOTENT per directory: every instant derives from
    // the bundle in force (one minute after its newest tip), so a second call
    // with the same founders and protocol re-puts byte-identical statements,
    // each a no-op (`Row`/`Voice { new: false }`), and returns the same ids.
    let at = in_force
        .tips()
        .iter()
        .map(|t| t.asserted_at)
        .max()
        .ok_or_else(|| refused("genesis", "no bundle in force"))?
        + 60_000;
    let founded_at = instant(at - 30_000);
    let community = Community {
        community_key_id: root.clone(),
        community_name: "w1b rooted trust root".into(),
        members: founder_refs
            .iter()
            .map(|f| CommunityMember {
                key_id: f.clone(),
                joined_at: founded_at,
                role: Some(crate::federation::admission::MEMBER_ROLE_FOUNDER.to_owned()),
            })
            .collect(),
        founded_at,
        consensus_protocol: protocol.to_owned(),
        policy_blob: Some(serde_json::json!({
            "cohort_subkind": crate::federation::canonical_community::COHORT_SUBKIND_INFRASTRUCTURE,
            "cohort_subkind_payload": {
                "infrastructure_constraint": {
                    "admission_quorum_basis":
                        crate::federation::canonical_community::ADMISSION_QUORUM_BASIS_FOUNDERS,
                },
            },
            "consensus_protocol_entrenched": true,
        })),
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        persist_row_hash: String::new(),
    };
    let keys: Vec<CompositeSigningKey> = founders
        .iter()
        .map(|s| fixture_genesis::test_key(*s))
        .collect();
    let key_refs: Vec<&CompositeSigningKey> = keys.iter().collect();
    let voices = roster_voices(&GroupRecord::Community(community), 1, None, at, &key_refs);
    let birth = row_id_of(&voices[0]);
    let charter = charter_statement(&root, at)?;

    // A second call: the root this directory already holds is RETURNED, never
    // re-founded. A root held at ROOT_SEED that another call founded with
    // other founders or another protocol is refused (it would fork).
    if let Some(held) = dir.lookup_community(&root).await? {
        if dir.edition2_voices(&birth).await?.is_empty() {
            return Err(refused(
                "founding",
                "a root founded with other founders or another protocol is already held at \
                 ROOT_SEED",
            ));
        }
        let acceptance = acceptance_statement(&node, &root, &held.persist_row_hash, at)?;
        if dir
            .get_attestation(&row_id_of(&charter).hex())
            .await?
            .is_some()
            && dir
                .get_attestation(&row_id_of(&acceptance).hex())
                .await?
                .is_some()
        {
            return Ok(RootedTrustRoot {
                root,
                founders: founder_refs,
                founder_seeds: founders.to_vec(),
                protocol: protocol.to_owned(),
                birth,
                charter: row_id_of(&charter),
                acceptance: row_id_of(&acceptance),
            });
        }
    }
    match put_voices(dir, &voices).await? {
        StatementOutcome::Row { .. } => {}
        other => return Err(refused("founding", format!("did not land: {other:?}"))),
    }

    // 4. The root's charter self-edge.
    // v62.0.0 (E10, round 3; CC 2.7.3: a held row concludes nothing) — the
    // root is ROOTED only if the charter and the acceptance CONCLUDE
    // (`own_chain_to` reads concluded rows). A put that is held is a fixture
    // that stands up no root: refuse it, naming the fold's reason, rather
    // than return a root every reader then finds not rooted.
    let out = e2::put_statement(dir, &charter).await?;
    require_concluded(dir, "charter", &out).await?;

    // 5. THIS node's acceptance edge, naming the held head.
    let head = dir
        .lookup_community(&root)
        .await?
        .ok_or_else(|| refused("acceptance", "the root is not held"))?
        .persist_row_hash;
    let acceptance = acceptance_statement(&node, &root, &head, at)?;
    let out = e2::put_statement(dir, &acceptance).await?;
    require_concluded(dir, "acceptance", &out).await?;

    Ok(RootedTrustRoot {
        root,
        founders: founder_refs,
        founder_seeds: founders.to_vec(),
        protocol: protocol.to_owned(),
        birth,
        charter: row_id_of(&charter),
        acceptance: row_id_of(&acceptance),
    })
}

/// A put that landed as a row (or a further voice of one); a `Pending` one
/// is refused with the fold's recorded reason (`fold_state`).
async fn require_concluded<D>(dir: &D, step: &str, out: &StatementOutcome) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    match out {
        StatementOutcome::Row { .. } | StatementOutcome::Voice { .. } => Ok(()),
        StatementOutcome::Pending { row_id, .. } => {
            let held = dir.fold_state(row_id).await?.and_then(|s| s.held);
            Err(refused(
                step,
                format!("held, not concluded: {held:?} (CC 2.7.3)"),
            ))
        }
        StatementOutcome::KeyPlane { .. } => Err(refused(step, "landed on the key plane")),
    }
}

/// The root's `trust:charter:v1` self-edge at `at`.
fn charter_statement(root: &str, at: u64) -> Result<Vec<u8>, Error> {
    let successor = e2::signing_key(ROOT_SUCCESSOR_SEED);
    let commitment = recovery_commitment(&[successor.public_key().clone()]);
    trust_edge(
        &e2::signing_key(ROOT_SEED),
        root,
        root,
        vec![
            ("author", text(root)),
            ("asserted_at", Value::Uint(at)),
            (
                "dimension",
                text(crate::federation::trust_root::TRUST_CHARTER_DIMENSION),
            ),
            (
                "scope",
                Value::Array(vec![
                    text(crate::federation::trust_root::INFRA_SERVE_SCOPE),
                    text(crate::federation::trust_root::INFRA_ATTEST_SCOPE),
                ]),
            ),
            (
                crate::federation::trust_root::CHARTER_PRE_ROTATION_FIELD,
                Value::Bytes(commitment.to_vec()),
            ),
        ],
    )
}

/// `node`'s `trust:accepts:v1` edge to `root`, naming the head `head_hex`.
fn acceptance_statement(node: &str, root: &str, head_hex: &str, at: u64) -> Result<Vec<u8>, Error> {
    acceptance_statement_by(&e2::signing_key(node), node, root, head_hex, at)
}

/// `iss`'s `trust:accepts:v1` edge to `root` signed by `key`, naming the head
/// `head_hex`.
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
                "scope",
                Value::Array(vec![text(crate::federation::trust_root::INFRA_SERVE_SCOPE)]),
            ),
            (
                crate::federation::envelope::paths::ATTACHED_HEAD_DIGEST,
                Value::Bytes(head_bytes),
            ),
        ],
    )
}

/// **Another party accepts the root**: `iss`'s `trust:accepts:v1` edge to
/// `r.root`, signed by `key` (e.g. a bundle seat's
/// `fixture_genesis::test_key(seed)` signing as its identity-ref), naming the
/// held head, stated at the bundle's newest tip + 60 s (idempotent). Returns
/// the edge's row id.
///
/// # Errors
/// The root not held, or the door's refusal.
pub async fn put_acceptance<D>(
    dir: &D,
    r: &RootedTrustRoot,
    key: &CompositeSigningKey,
    iss: &str,
) -> Result<RowId, Error>
where
    D: FederationDirectory + ?Sized,
{
    let head = dir
        .lookup_community(&r.root)
        .await?
        .ok_or_else(|| refused("acceptance", "the root is not held"))?
        .persist_row_hash;
    let at = conferral_instant(dir).await? - 30_000;
    let st = acceptance_statement_by(key, iss, &r.root, &head, at)?;
    e2::put_statement(dir, &st).await?;
    Ok(row_id_of(&st))
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

/// **The root confers `scope` on `subject_seed`'s key** (a room's key, or any
/// key E0 minted): the root's `trust:confers:v1` grant
/// ([`confers_statement`]) and then the subject's own second voice, which
/// Verify's `confers` rule requires (`delegate: sub`, CC 2.6.1.9). The
/// subject's key is registered first (`user`). Idempotent. Returns the
/// grant's row id.
///
/// # Errors
/// Either voice's refusal.
pub async fn put_conferral<D>(
    dir: &D,
    r: &RootedTrustRoot,
    subject_seed: &str,
    scope: &[&str],
) -> Result<RowId, Error>
where
    D: FederationDirectory + ?Sized,
{
    let subject = e2::put_key(dir, subject_seed, &["user"]).await;
    let at = conferral_instant(dir).await?;
    let grant = confers_statement(r, &subject, scope, at);
    e2::put_statement(dir, &grant).await?;
    e2::put_statement(dir, &e2::voice_of(&grant, subject_seed)).await?;
    Ok(row_id_of(&grant))
}

/// **Stand up a ROOTED edition-2 trust root** (module doc; `W1.api.md`).
///
/// `founders`: holder seeds of the bundle in force (`bundle_v2()`: 1, 2, 3).
/// `protocol`: `quorum:M/N` with `founders.len() >= M + 1`.
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
