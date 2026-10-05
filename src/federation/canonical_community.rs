//! v50.0.0 (CIRISPersist#926, operator ruling (b) 2026-09-27; FSD
//! `SECOND_DEVICE.md` §9) — **the `ciris-canonical` community row: born as a
//! post-genesis Contribution, admitted under the accord's own quorum, served
//! beside the bundle.**
//!
//! CC 4.4's recommended default pin is `pinned_trust = {community_key_id:
//! ciris-canonical, family: humanity-accord}`, bootstrapped from the CC 5.3.4
//! GenesisBundle route and resolved live via `resolve_community`. Before this
//! cut no `community` row existed for that id anywhere (`canonical_seed.json`
//! carries zero), so a consumer following the CC pinned a name that resolved
//! to nothing.
//!
//! The ruling chose (b): the row is NOT inside the GenesisBundle (its bytes and
//! [`verify_bundle_quorum`](super::genesis::bundle::verify_bundle_quorum) are
//! untouched and stay the only ROOT authority). It is an ordinary `community`
//! row that the door admits only when:
//!
//! 1. **the shape is CC 3.2's trust-root grade** — `cohort_subkind:
//!    infrastructure`, `cohort_subkind_payload.infrastructure_constraint.
//!    admission_quorum_basis: "founders"`, a `quorum:M/N` protocol, and
//!    `consensus_protocol_entrenched: true` (carried in `policy_blob`, beside
//!    `cohort_subkind` — the [`Community`] record has no entrenchment column);
//! 2. **every founder is an accord-conferred steward key held by a human**
//!    (CC 3.2 T2; #925's rule — `user` in `identity_type`, `node` not);
//! 3. **the row's own scrub set reaches the HUMANITY_ACCORD family's quorum**
//!    — the authority signature plus [`SignedCommunity::cosignatures`], all
//!    over [`Community::signing_envelope`], counted by the SAME m-of-n body
//!    that charters a family root
//!    ([`family_quorum_holders_over_envelope`](super::trust_root::family_quorum_holders_over_envelope)),
//!    against THIS node's own stored accord family and its own directory pins.
//!
//! The id `ciris-canonical` is reserved to this door: any row at that id runs
//! all three checks, so the shipped default cannot be squatted by a
//! first-come self-signed row. Any other row that DECLARES the
//! `infrastructure_constraint` payload is held to the same grade — the payload
//! is a claim of trust-root standing, and a claim is checked, never read.
//!
//! # Birth by the accord, amendment by the founders (#926 review ruling)
//!
//! The accord holders' 2-of-3 is the BIRTH of the row (and, on the ceremony
//! plane, the conferral of each founder). After birth the row changes only by
//! its FOUNDERS' quorum — its own entrenched `quorum:M/N` over the `founder`
//! seats — on every door: the local `supersede_community_with_quorum`, the
//! replicated `put_community` of an amended version (whose `supersede_proof`
//! the receiver verifies against its OWN prior founder roster), and the roster
//! planes ([`check_trust_root_roster_change`]). No door re-demands the accord
//! count for an amendment, and no door lets an amendment change the grade, the
//! basis, the subkind or the entrenched protocol. Every founder on every
//! version is still accord-conferred, human and not node-bearing.
//!
//! # A row is its CHAIN (#926 re-check)
//!
//! A trust-root row travels with its [`SignedCommunity::lineage`]: the
//! accord-born version, then every founders' amendment, in order. Standing is
//! the chain, never the latest proof: a node holding nothing walks it from the
//! birth ([`verify_chain`]); a node holding an older version walks from what it
//! holds ([`verify_founders_link`] per link). A founders' amendment never moves
//! founder SEATS (those move only on the roster planes, under the founders'
//! quorum), and the change envelope the founders sign binds every member's
//! role, so a genuine proof cannot be replayed over a body that demotes one.
//!
//! # A stored row is re-judged on every read
//!
//! A row at a trust-root id is honoured (resolved, served, trusted, taken as
//! the community arm of a root) only while it is ROOTED ([`stored_standing`]):
//! conformant in shape, its chain verifying from an accord birth (the birth's
//! accord quorum re-derived now — a holder revocation that drops the family's
//! count below quorum un-roots it until a re-birth), and every active founder
//! eligible. There is no proof-only arm. A row that never passed this door — a
//! pre-v50 squat at the reserved id — is `NotRooted`: it resolves to nothing, is
//! served as `null` with the reason, and the accord's birth chain REPLACES it.

use super::types::{
    consensus_protocol as cp, identity_type, Community, KeyRecord, ScrubSig, SignedCommunity,
    SignedKeyRecord,
};
use super::{Error, FederationDirectory};
use serde::{Deserialize, Serialize};

/// The shipped default trust-root community id (CC 3.2 worked example; CC 4.4
/// `pinned_trust.community_key_id`). Reserved to the trust-root door.
pub const CIRIS_CANONICAL_COMMUNITY_KEY_ID: &str = "ciris-canonical";

/// `cohort_subkind` value for a governed trust-root collective (CC 3.2).
pub const COHORT_SUBKIND_INFRASTRUCTURE: &str = "infrastructure";

/// The only admissible `infrastructure_constraint.admission_quorum_basis`
/// (CC 3.2: a REQUIRED literal).
pub const ADMISSION_QUORUM_BASIS_FOUNDERS: &str = "founders";

/// The `infrastructure_constraint` payload a row declares, if any
/// (`policy_blob.cohort_subkind_payload.infrastructure_constraint`).
#[must_use]
pub fn infrastructure_constraint(community: &Community) -> Option<&serde_json::Value> {
    community
        .policy_blob
        .as_ref()?
        .get("cohort_subkind_payload")?
        .get("infrastructure_constraint")
}

/// Is this row held to the trust-root grade? The reserved id always is; any
/// other row is when it declares the `infrastructure_constraint` payload.
#[must_use]
pub fn is_trust_root_grade(community: &Community) -> bool {
    community.community_key_id == CIRIS_CANONICAL_COMMUNITY_KEY_ID
        || infrastructure_constraint(community).is_some()
}

fn policy_str<'a>(community: &'a Community, field: &str) -> Option<&'a str> {
    community.policy_blob.as_ref()?.get(field)?.as_str()
}

/// The row's declared entrenchment (`policy_blob.consensus_protocol_entrenched`).
#[must_use]
pub fn declares_entrenched(community: &Community) -> bool {
    community
        .policy_blob
        .as_ref()
        .and_then(|b| b.get("consensus_protocol_entrenched"))
        == Some(&serde_json::Value::Bool(true))
}

/// The founder key ids, in record order.
#[must_use]
pub fn founders(community: &Community) -> Vec<&str> {
    community
        .members
        .iter()
        .filter(|m| m.role.as_deref() == Some(super::admission::MEMBER_ROLE_FOUNDER))
        .map(|m| m.key_id.as_str())
        .collect()
}

fn violation(community_key_id: &str, rule: &'static str, detail: impl std::fmt::Display) -> Error {
    Error::CommunityConsensusProtocolViolation {
        community_key_id: community_key_id.to_owned(),
        rule,
        detail: format!("{detail} (CC 3.2 trust-root grade; CIRISPersist#926)"),
    }
}

/// CC 3.2 conformance for a trust-root-grade row — pure, over the record.
///
/// # Errors
///
/// [`Error::CommunityConsensusProtocolViolation`]
/// for the first clause that fails.
pub fn check_trust_root_shape(community: &Community) -> Result<(), Error> {
    let id = community.community_key_id.as_str();
    if policy_str(community, "cohort_subkind") != Some(COHORT_SUBKIND_INFRASTRUCTURE) {
        return Err(violation(
            id,
            super::admission::INFRA_RULE_SUBKIND_NOT_INFRASTRUCTURE,
            "a trust-root community must declare cohort_subkind: infrastructure",
        ));
    }
    let basis = infrastructure_constraint(community)
        .and_then(|c| c.get("admission_quorum_basis"))
        .and_then(|v| v.as_str());
    if basis != Some(ADMISSION_QUORUM_BASIS_FOUNDERS) {
        return Err(violation(
            id,
            super::admission::INFRA_RULE_BASIS_NOT_FOUNDERS,
            format!(
                "infrastructure_constraint.admission_quorum_basis must be \
                 {ADMISSION_QUORUM_BASIS_FOUNDERS:?}, got {basis:?}"
            ),
        ));
    }
    let quorum_form = community
        .consensus_protocol
        .strip_prefix(cp::QUORUM_PREFIX)
        .and_then(|_| super::genesis::bundle::parse_quorum(&community.consensus_protocol))
        .is_some_and(|(m, n)| m >= 1 && m <= n);
    if !quorum_form {
        return Err(violation(
            id,
            super::admission::INFRA_RULE_PROTOCOL_NOT_QUORUM,
            format!(
                "consensus_protocol must be a quorum:M/N kind (founder_only / unanimous / \
                 majority are non-conformant for infrastructure), got {:?}",
                community.consensus_protocol
            ),
        ));
    }
    if !declares_entrenched(community) {
        return Err(violation(
            id,
            super::admission::INFRA_RULE_NOT_ENTRENCHED,
            "consensus_protocol_entrenched must be true — the admission door cannot be \
             lowered after founding",
        ));
    }
    if founders(community).is_empty() {
        return Err(violation(
            id,
            super::admission::INFRA_RULE_NO_FOUNDER,
            "a trust-root community names no founder",
        ));
    }
    Ok(())
}

/// CIRISPersist#972 — the arm a founder of an infrastructure
/// community counts under at an instant. ONE predicate, read by the door
/// ([`check_founder_eligible`]) and by the chain / liveness folds
/// ([`Memo::founder_counts`]): two copies of "who is a founder" is how a row
/// is admitted and then counts nobody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FounderArm {
    /// A CURRENT seat of the conferring accord family (its revocation-folded
    /// roster at the instant). Human-held by the holder triple (CC 4.2.3): no
    /// `user` type and no `steward` conferral are asked. Leaving the accord
    /// roster ends it (CC 3.2 T7).
    Holder,
    /// A `user` key that still has to show an accord-conferred `steward`
    /// (CC 3.2 T2) — the rule for every founder who is not an accord holder.
    Steward,
    /// Node-bearing (#925, "infrastructure does not vote"), or neither a
    /// seated holder nor a `user` key.
    Neither,
}

/// Is `key_id` a seat of the conferring accord family at `at`? Asked of this
/// node's stored family and its roster planes
/// ([`authorized_family_roster_at`](super::authorized_family_roster_at), the
/// fold the accord quorum itself is counted over) — never of the key's own
/// `identity_type`, which is the key's word.
async fn accord_holder_seated_at<F>(
    directory: &F,
    key_id: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(family) =
        super::trust_root::resolve_family_root(directory, accord_family_key_id()).await?
    else {
        return Ok(false);
    };
    match super::authorized_family_roster_at(directory, &family, at).await {
        Ok(seats) => Ok(seats.iter().any(|m| m.key_id == key_id)),
        Err(Error::Unsupported { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

/// [`FounderArm`] of `record` at `at`, plus the earliest occurrence-interval
/// edge after `at` where the node-bearing answer may change
/// ([`node_bearing_at_with_next`](super::node_bearing_at_with_next)). The
/// holder arm changes at the accord family's roster events
/// ([`family_event_instants`]), which the caller bounds.
async fn founder_arm_at<F>(
    directory: &F,
    record: &KeyRecord,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<(FounderArm, Option<chrono::DateTime<chrono::Utc>>), Error>
where
    F: FederationDirectory + ?Sized,
{
    let (node_bearing, next_edge) =
        super::node_bearing_at_with_next(directory, &record.key_id, at).await?;
    let arm = if node_bearing {
        FounderArm::Neither
    } else if accord_holder_seated_at(directory, &record.key_id, at).await? {
        FounderArm::Holder
    } else if identity_type::set_contains(&record.identity_type, identity_type::USER) {
        FounderArm::Steward
    } else {
        FounderArm::Neither
    };
    Ok((arm, next_edge))
}

/// One founder is eligible ([`founder_arm_at`]): a key record here, not
/// node-bearing (#925), and EITHER a current seat of the conferring accord
/// family (#972 — nothing more is asked of a seated holder) OR a `user` key
/// with an accord-conferred `steward` whose conferral has not been withdrawn
/// (CC 3.2 T2). The conferral is judged against the COMPILED accord holder roster
/// (`accord_holder_roster_key_ids`, the ceremony plane every key-plane
/// conferral uses); the row's own quorum is judged against the family's
/// revocation-folded roster ([`accord_quorum_over_community`]).
///
/// # Errors
///
/// [`Error::CommunityConsensusProtocolViolation`] for an unknown or node-bearing
/// founder; [`Error::RoleNotAccordConferred`] for a human founder the accord
/// did not confer (or whose conferral was withdrawn).
pub async fn check_founder_eligible<F>(
    directory: &F,
    community_key_id: &str,
    founder: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(record) = directory.lookup_public_key(founder).await? else {
        return Err(violation(
            community_key_id,
            super::admission::INFRA_RULE_FOUNDER_NOT_CONFERRED,
            format!("founder {founder:?} has no key record on this node"),
        ));
    };
    let arm = founder_arm_at(directory, &record, now).await?.0;
    if arm == FounderArm::Holder {
        return Ok(());
    }
    if arm == FounderArm::Neither {
        return Err(violation(
            community_key_id,
            super::admission::INFRA_RULE_NODE_BEARING_FOUNDER,
            format!(
                "founder {founder:?} is not a human key (identity_type {:?}, and not a current \
                 seat of the accord family): a node-bearing key MUST NOT be a founder of an \
                 infrastructure community (CIRISPersist#925)",
                record.identity_type
            ),
        ));
    }
    if !super::admission::has_accord_conferred_role_over_roster(
        directory,
        founder,
        identity_type::STEWARD,
        &super::admission::accord_holder_roster_key_ids(),
    )
    .await?
    {
        return Err(Error::RoleNotAccordConferred {
            role: identity_type::STEWARD.to_owned(),
            key_id: founder.to_owned(),
            scrub_key_id: record.scrub_key_id.clone(),
            reason: format!(
                "a founder of trust-root community {community_key_id:?} must be an \
                 accord-conferred steward key (CC 3.2 T2)"
            ),
        });
    }
    Ok(())
}

/// Every founder the record names is eligible at `now` ([`check_founder_eligible`]).
///
/// # Errors
///
/// The first founder's refusal.
pub async fn check_founders_eligible<F>(
    directory: &F,
    community: &Community,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    for founder in founders(community) {
        check_founder_eligible(directory, &community.community_key_id, founder, now).await?;
    }
    Ok(())
}

/// The row's scrub set: the authority signature first, then each co-signature,
/// all over the SAME [`Community::signing_envelope`].
#[must_use]
pub fn community_scrubs(signed: &SignedCommunity) -> Vec<ScrubSig> {
    std::iter::once(ScrubSig {
        scrub_key_id: signed.authority_key_id.clone(),
        scrub_signature_classical: signed.scrub_signature_classical.clone(),
        scrub_signature_pqc: signed.scrub_signature_pqc.clone(),
        cosigned_at: None,
    })
    .chain(signed.cosignatures.iter().map(|c| ScrubSig {
        scrub_key_id: c.authority_key_id.clone(),
        scrub_signature_classical: c.scrub_signature_classical.clone(),
        scrub_signature_pqc: c.scrub_signature_pqc.clone(),
        cosigned_at: None,
    }))
    .collect()
}

/// The accord family a trust-root community is born under.
#[must_use]
pub fn accord_family_key_id() -> &'static str {
    ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID
}

/// How many distinct seated HUMANITY_ACCORD holders verifiably signed this
/// row, against the threshold this node's OWN accord family demands (its
/// revocation-folded roster, floored at a strict majority).
///
/// # Errors
///
/// [`Error::RosterAuthorityUnauthorized`] (`roster_consensus_insufficient`)
/// when this node holds no accord family to count against.
pub async fn accord_quorum_over_community<F>(
    directory: &F,
    signed: &SignedCommunity,
) -> Result<super::trust_root::CharterQuorum, Error>
where
    F: FederationDirectory + ?Sized,
{
    accord_quorum_at(directory, signed, &mut Memo::at(chrono::Utc::now())).await
}

/// [`accord_quorum_over_community`] with the family roster folded at
/// `memo.now`. The fold applies each holder widening and revocation whose
/// `effective_at` is at or before that instant, so the earliest such instant
/// AFTER it bounds how long the count holds (`Memo::bound`).
async fn accord_quorum_at<F>(
    directory: &F,
    signed: &SignedCommunity,
    memo: &mut Memo,
) -> Result<super::trust_root::CharterQuorum, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(family) =
        super::trust_root::resolve_family_root(directory, accord_family_key_id()).await?
    else {
        return Err(insufficient(signed));
    };
    for t in family_event_instants(directory, &family.family_key_id).await? {
        memo.bound(t);
    }
    let (quorum, _) = super::trust_root::family_quorum_holders_over_envelope_at(
        directory,
        &signed.community.signing_envelope(),
        &community_scrubs(signed),
        &family,
        memo.now,
    )
    .await?;
    Ok(quorum)
}

/// Every holder widening and revocation instant of the family's roster plane
/// (the events the family fold applies by `effective_at`).
async fn family_event_instants<F>(
    directory: &F,
    family_key_id: &str,
) -> Result<Vec<chrono::DateTime<chrono::Utc>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut out = Vec::new();
    match directory
        .list_family_membership_widenings_for(family_key_id)
        .await
    {
        Ok(ws) => out.extend(ws.into_iter().map(|w| w.effective_at)),
        Err(Error::Unsupported { .. }) => {}
        Err(e) => return Err(e),
    }
    match directory
        .list_family_membership_revocations_for(family_key_id)
        .await
    {
        Ok(rs) => out.extend(rs.into_iter().map(|r| r.effective_at)),
        Err(Error::Unsupported { .. }) => {}
        Err(e) => return Err(e),
    }
    Ok(out)
}

fn insufficient(signed: &SignedCommunity) -> Error {
    Error::RosterAuthorityUnauthorized {
        group_key_id: signed.community.community_key_id.clone(),
        offered_authority_key_id: signed.authority_key_id.clone(),
        rule: super::ROSTER_CONSENSUS_INSUFFICIENT,
    }
}

fn row_hash(c: &Community) -> Result<String, Error> {
    super::types::compute_persist_row_hash(c)
}

/// A version as it sits in a chain: its own `lineage` emptied.
fn stripped(signed: &SignedCommunity) -> SignedCommunity {
    SignedCommunity {
        lineage: Vec::new(),
        ..signed.clone()
    }
}

/// The row's CHAIN, oldest first: its `lineage` (the accord-born version, then
/// each founders' amendment) followed by the row itself — every entry with an
/// empty `lineage` of its own.
#[must_use]
pub fn chain_of(signed: &SignedCommunity) -> Vec<SignedCommunity> {
    signed
        .lineage
        .iter()
        .map(stripped)
        .chain(std::iter::once(stripped(signed)))
        .collect()
}

/// The most versions a chain may carry (#926 re-check): the birth plus 1023
/// amendments. Refused at the door, before any signature is checked.
pub const MAX_LINEAGE_LEN: usize = 1024;

/// The most bytes a chain's `lineage` may serialize to, refused as
/// [`Error::EnvelopeTooLarge`] at the door before any signature is checked.
/// Sized so the LENGTH cap binds first (~15–20 KB per version). Past the
/// length cap the chain restarts by compaction: the founders resign or the
/// accord withdraws conferrals, the row stalls, and an accord re-birth begins
/// a new chain.
pub const MAX_LINEAGE_BYTES: usize = 32 * 1024 * 1024;

/// How far in the future a link's signed `amended_at` may sit: the ONE
/// substrate future-skew bound roster rows use.
const AMENDED_AT_SKEW_SECS: i64 = super::community_dek::COMMUNITY_REVOCATION_MAX_FUTURE_SKEW_SECS;

/// The envelope field that binds a founders' proof to exactly ONE next body
/// (#926 re-check, MEDIUM-B): the next version's content hash.
pub const NEXT_PERSIST_ROW_HASH: &str = "next_persist_row_hash";

/// The envelope field carrying the link's signed instant: the founders'
/// statement of when they amended, which decides whether a founder whose
/// conferral was later withdrawn (a key rotation) still counts for THIS link.
pub const AMENDED_AT: &str = "amended_at";

/// Bind a founders' change envelope to the ONE version it authorizes (#926
/// re-check): every member's role as `next` records it (so a founder added or
/// removed by the amendment is named), `next`'s content hash, and the link's
/// instant. The founders sign the envelope AFTER this. Callers building an
/// amendment of a trust-root community run it on the envelope
/// [`build_membership_change_envelope`](super::FederationDirectory::build_membership_change_envelope)
/// returns.
///
/// # Errors
///
/// A `next` whose content hash cannot be computed.
pub fn bind_next_version(
    change_envelope: &mut serde_json::Value,
    next: &Community,
    amended_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error> {
    let roles: std::collections::BTreeMap<&str, Option<&str>> = next
        .members
        .iter()
        .map(|m| (m.key_id.as_str(), m.role.as_deref()))
        .collect();
    if let Some(members) = change_envelope
        .get_mut("members")
        .and_then(|v| v.as_array_mut())
    {
        for m in members.iter_mut() {
            let key = m
                .get("key_id")
                .and_then(|k| k.as_str())
                .unwrap_or_default()
                .to_owned();
            let role = roles
                .get(key.as_str())
                .copied()
                .flatten()
                .unwrap_or("member");
            m["role"] = serde_json::Value::String(role.to_owned());
        }
    }
    change_envelope[NEXT_PERSIST_ROW_HASH] = serde_json::Value::String(row_hash(next)?);
    change_envelope[AMENDED_AT] = serde_json::Value::String(
        super::admission::truncate_to_substrate_resolution(amended_at).to_rfc3339(),
    );
    Ok(())
}

/// The founder roles the founders' signed change envelope names.
fn envelope_founders(change_envelope: &serde_json::Value) -> std::collections::BTreeSet<String> {
    change_envelope
        .get("members")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter(|m| {
                    m.get("role").and_then(|r| r.as_str())
                        == Some(super::admission::MEMBER_ROLE_FOUNDER)
                })
                .filter_map(|m| m.get("key_id").and_then(|k| k.as_str()).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Per-call memo of the expensive founder questions (the conferral co-scrub
/// verification), so one read or one door judges each key once.
///
/// It also carries the verdict's `now` (#926 round 9): nothing under a
/// verdict reads the wall clock. Every comparison against `now` registers the
/// input's instant with [`Memo::bound`], and `valid_until` ends up as the
/// EARLIEST such instant strictly after `now`: the moment the same inputs may
/// give a different verdict. The standing cache serves an entry only before
/// it.
struct Memo {
    now: chrono::DateTime<chrono::Utc>,
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
    records: std::collections::HashMap<String, Option<KeyRecord>>,
    conferred: std::collections::HashMap<String, bool>,
    /// The accord family's roster event instants (#972): the holder arm of
    /// [`FounderArm`] changes at them. Read once per verdict.
    accord_events: Option<Vec<chrono::DateTime<chrono::Utc>>>,
    /// Per community: every self-signed resignation instant of each key,
    /// ascending (a re-seated founder may resign again; the earliest alone
    /// would mask the later one behind the re-seat floor).
    resignations: std::collections::HashMap<
        String,
        std::collections::HashMap<String, Vec<chrono::DateTime<chrono::Utc>>>,
    >,
}

impl Memo {
    fn at(now: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            now,
            valid_until: None,
            records: std::collections::HashMap::new(),
            conferred: std::collections::HashMap::new(),
            accord_events: None,
            resignations: std::collections::HashMap::new(),
        }
    }

    /// An input compared against `now` changes its answer at `t`: a verdict
    /// judged at `now` holds only until the earliest such `t` after it.
    fn bound(&mut self, t: chrono::DateTime<chrono::Utc>) {
        if t > self.now {
            self.valid_until = Some(self.valid_until.map_or(t, |v| v.min(t)));
        }
    }

    async fn record<F>(&mut self, directory: &F, key_id: &str) -> Result<Option<KeyRecord>, Error>
    where
        F: FederationDirectory + ?Sized,
    {
        if let Some(r) = self.records.get(key_id) {
            return Ok(r.clone());
        }
        let r = directory.lookup_public_key(key_id).await?;
        self.records.insert(key_id.to_owned(), r.clone());
        Ok(r)
    }

    /// The key claims `steward` and its scrub set reaches the accord m-of-n —
    /// the conferral, without the withdrawal fold.
    async fn conferred<F>(&mut self, directory: &F, key_id: &str) -> Result<bool, Error>
    where
        F: FederationDirectory + ?Sized,
    {
        if let Some(c) = self.conferred.get(key_id) {
            return Ok(*c);
        }
        let c = match self.record(directory, key_id).await? {
            Some(rec) => {
                super::admission::record_is_accord_conferred(
                    directory,
                    &rec,
                    identity_type::STEWARD,
                    &super::admission::accord_holder_roster_key_ids(),
                )
                .await?
            }
            None => false,
        };
        self.conferred.insert(key_id.to_owned(), c);
        Ok(c)
    }

    /// Every resignation instant of `key_id` from `community_key_id` (its own
    /// plane revocation, signed by that founder alone). Read once per
    /// community per call.
    async fn resignations_of<F>(
        &mut self,
        directory: &F,
        community_key_id: &str,
        key_id: &str,
    ) -> Result<Vec<chrono::DateTime<chrono::Utc>>, Error>
    where
        F: FederationDirectory + ?Sized,
    {
        if !self.resignations.contains_key(community_key_id) {
            let mut map = std::collections::HashMap::new();
            match directory.community_roster_signers(community_key_id).await {
                Ok(signers) => {
                    for r in signers.revocation_signers {
                        if r.authority_key_id.as_deref() == Some(r.member_key_id.as_str())
                            && r.cosigner_key_ids.is_empty()
                        {
                            map.entry(r.member_key_id)
                                .or_insert_with(Vec::new)
                                .push(r.effective_at);
                        }
                    }
                }
                // No stored community yet (a birth being judged) or a directory
                // that cannot answer: no resignations to fold.
                Err(Error::Unsupported { .. } | Error::InvalidArgument(_)) => {}
                Err(e) => return Err(e),
            }
            self.resignations.insert(community_key_id.to_owned(), map);
        }
        Ok(self.resignations[community_key_id]
            .get(key_id)
            .cloned()
            .unwrap_or_default())
    }

    /// Whether `key_id` resigned from `community_key_id` at an instant in
    /// `(after, until]`.
    async fn resigned_within<F>(
        &mut self,
        directory: &F,
        community_key_id: &str,
        key_id: &str,
        after: chrono::DateTime<chrono::Utc>,
        until: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, Error>
    where
        F: FederationDirectory + ?Sized,
    {
        Ok(self
            .resignations_of(directory, community_key_id, key_id)
            .await?
            .iter()
            .any(|r| *r > after && *r <= until))
    }

    /// When the withdrawal of `key_id`'s steward conferral took effect — a
    /// NODE-INDEPENDENT instant: the signed `window_until` of the accord
    /// proposal the withdrawal re-tallied (#926 re-check, MEDIUM-W). A
    /// withdrawal whose proposal this node does not hold has no instant to
    /// judge history against, so it un-counts the key at every instant
    /// (fail-secure).
    async fn withdrawal_instant<F>(
        &mut self,
        directory: &F,
        w: &super::admission::RoleWithdrawal,
    ) -> Result<chrono::DateTime<chrono::Utc>, Error>
    where
        F: FederationDirectory + ?Sized,
    {
        let stored = match directory
            .get_accord_proposal(&w.authority_decision_digest)
            .await
        {
            Ok(p) => p,
            Err(Error::Unsupported { .. }) => None,
            Err(e) => return Err(e),
        };
        Ok(stored
            .and_then(|p| chrono::DateTime::parse_from_rfc3339(&p.proposal.window_until).ok())
            .map(|t| t.with_timezone(&chrono::Utc))
            .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC))
    }

    /// Does `key_id` count as a founder of `community_key_id` at `at` (`None`
    /// = the verdict's `now`)? By the ONE founder predicate
    /// ([`founder_arm_at`], #972): a seated accord holder at that instant, not
    /// resigned by its own signature — or a human key at that instant (#925's
    /// [`is_node_bearing_key_at`](super::is_node_bearing_key_at)),
    /// accord-conferred as a steward, not resigned by its own signature, and
    /// not withdrawn — or, for a link instant, withdrawn only AFTER it (a
    /// rotation does not un-count the historical signatures of the key it
    /// retired). A withdrawal whose successor is the key itself is a rotate-in
    /// and never un-counts.
    ///
    /// **The counting rule (#926 round 9 ruling).** A resignation applies when
    /// its `effective_at` is in `(seated_since, at]`: `seated_since` is the
    /// instant of the version that (re-)seated the key (the birth, or the link
    /// whose prior did not name it a founder). The same rule judges a link
    /// (`at` = its `amended_at`, `seated_since` over the chain up to its prior)
    /// and the head (`at` = now). Every resignation is kept; a later version
    /// MAY still record a resigned founder, who then counts as nothing until
    /// the record amends them out or re-seats them.
    ///
    /// Judged at `now` (`at` = `None`), the node-bearing interval edges and the
    /// resignation instants after `now` bound the verdict ([`Memo::bound`]).
    async fn founder_counts<F>(
        &mut self,
        directory: &F,
        community_key_id: &str,
        key_id: &str,
        at: Option<chrono::DateTime<chrono::Utc>>,
        seated_since: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, Error>
    where
        F: FederationDirectory + ?Sized,
    {
        let Some(rec) = self.record(directory, key_id).await? else {
            return Ok(false);
        };
        let when = at.unwrap_or(self.now);
        let (arm, next_edge) = founder_arm_at(directory, &rec, when).await?;
        if at.is_none() {
            if let Some(t) = next_edge {
                self.bound(t);
            }
            // #972 — a holder joining or leaving the accord roster changes
            // the arm, so those instants bound the verdict too.
            if self.accord_events.is_none() {
                self.accord_events =
                    Some(family_event_instants(directory, accord_family_key_id()).await?);
            }
            for t in self.accord_events.clone().unwrap_or_default() {
                self.bound(t);
            }
            for r in self
                .resignations_of(directory, community_key_id, key_id)
                .await?
            {
                self.bound(r);
            }
        }
        match arm {
            FounderArm::Neither => return Ok(false),
            FounderArm::Steward if !self.conferred(directory, key_id).await? => return Ok(false),
            FounderArm::Holder | FounderArm::Steward => {}
        }
        if self
            .resigned_within(directory, community_key_id, key_id, seated_since, when)
            .await?
        {
            return Ok(false);
        }
        // The `steward` role withdrawal is the steward arm's alone: a seated
        // holder was never conferred `steward`, and leaves by leaving the
        // accord roster.
        if arm == FounderArm::Holder {
            return Ok(true);
        }
        Ok(
            match directory
                .lookup_role_withdrawal(identity_type::STEWARD, key_id)
                .await?
            {
                None => true,
                Some(w) if w.superseded_by.as_deref() == Some(key_id) => true,
                Some(w) => {
                    let instant = self.withdrawal_instant(directory, &w).await?;
                    at.is_some_and(|t| t < instant)
                }
            },
        )
    }
}

/// **One link of the chain** (CIRISPersist#926 re-checks): `next` is a
/// founders' amendment of `prior`, verified from `prior` alone — never from
/// what this node happens to store — so a node holding nothing, or an older
/// version, can walk it:
///
/// - `next` carries a `supersede_proof` naming `prior`'s content hash;
/// - the immutables hold (grade, basis, subkind, entrenched protocol). The
///   founder SET may change — founder seats move ONLY through the record,
///   never on the roster planes;
/// - the change envelope describes `next` (id, protocol, member set), BINDS
///   every founder role `next` names, and binds `next`'s content hash, so one
///   proof admits exactly one body;
/// - its signed `amended_at` is not before the previous link's, and not in the
///   future;
/// - its verified signers — `prior`'s RECORDED founders that count at
///   `amended_at` (human, accord-conferred, not withdrawn before it, and no
///   resignation in `(seated_since, amended_at]`, `seated_since` taken over
///   `chain`, the counting rule of #926 round 9), each hybrid-verified against
///   this node's pinned pubkeys (founder key records are never deleted) — meet
///   `prior`'s protocol over its founder seats;
/// - `next`'s authority is one of those counted founders, and its signature
///   over `next` verifies.
///
/// `chain` is the chain up to and including `prior` (its last entry), oldest
/// first: the link reads `prior` and each founder's `seated_since` from it.
/// Returns the link's instant.
///
/// # Errors
///
/// [`Error::CommunityConsensusProtocolViolation`] for a structural clause;
/// [`Error::RosterAuthorityUnauthorized`] (`roster_consensus_insufficient`)
/// short of the founders' quorum; [`Error::InvalidArgument`] for an empty
/// `chain`.
pub async fn verify_founders_link<F>(
    directory: &F,
    chain: &[SignedCommunity],
    next: &SignedCommunity,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<chrono::DateTime<chrono::Utc>, Error>
where
    F: FederationDirectory + ?Sized,
{
    verify_founders_link_memo(directory, chain, next, &mut Memo::at(now)).await
}

async fn verify_founders_link_memo<F>(
    directory: &F,
    chain: &[SignedCommunity],
    next: &SignedCommunity,
    memo: &mut Memo,
) -> Result<chrono::DateTime<chrono::Utc>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use ciris_verify_core::threshold::ThresholdMember;
    let Some(prior_signed) = chain.last() else {
        return Err(Error::InvalidArgument(
            "a founders' link needs the chain up to its prior version".into(),
        ));
    };
    let prior = &prior_signed.community;
    let prior_instant = link_instant(prior_signed);
    let id = next.community.community_key_id.as_str();
    let Some(proof) = next.supersede_proof.as_ref() else {
        return Err(needs_founders_quorum(id));
    };
    if proof.prior_persist_row_hash != row_hash(prior)? {
        return Err(violation(
            id,
            super::admission::TRUST_ROOT_RULE_CHAIN,
            "the founders' proof does not name the version it follows",
        ));
    }
    check_amendment_immutables(prior, &next.community)?;
    let members: std::collections::BTreeSet<&str> = next
        .community
        .members
        .iter()
        .map(|m| m.key_id.as_str())
        .collect();
    super::assert_change_envelope_matches(
        id,
        &members,
        &next.community.consensus_protocol,
        &proof.change_envelope,
    )?;
    let next_founders: std::collections::BTreeSet<String> = founders(&next.community)
        .into_iter()
        .map(str::to_owned)
        .collect();
    if envelope_founders(&proof.change_envelope) != next_founders {
        return Err(violation(
            id,
            super::admission::TRUST_ROOT_RULE_CHAIN,
            "the founders' change envelope does not bind the founder roles the version names",
        ));
    }
    if proof
        .change_envelope
        .get(NEXT_PERSIST_ROW_HASH)
        .and_then(|v| v.as_str())
        != Some(row_hash(&next.community)?.as_str())
    {
        return Err(violation(
            id,
            super::admission::TRUST_ROOT_RULE_CHAIN,
            "the founders' change envelope does not bind the version's content (one proof, one body)",
        ));
    }
    let amended_at = proof
        .change_envelope
        .get(AMENDED_AT)
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
        .ok_or_else(|| {
            violation(
                id,
                super::admission::TRUST_ROOT_RULE_CHAIN,
                "the founders' change envelope carries no amended_at",
            )
        })?;
    let floor = prior_instant.unwrap_or(prior.founded_at);
    // The future bound compares against `now`: a link refused as too far
    // ahead is admissible from `amended_at - skew` on.
    let skew = chrono::Duration::seconds(AMENDED_AT_SKEW_SECS);
    memo.bound(amended_at - skew);
    if amended_at < floor || amended_at > memo.now + skew {
        return Err(violation(
            id,
            super::admission::TRUST_ROOT_RULE_CHAIN,
            format!(
                "the link's amended_at {amended_at} is before the version it follows ({floor}) \
                 or in the future"
            ),
        ));
    }
    let prior_founders = founders(prior);
    // The counting rule (#926 round 9 ruling): a prior founder counts on this
    // link iff no resignation of theirs falls in (seated_since, amended_at].
    // A version MAY still record a resigned founder; they count as nothing
    // here, so the link needs the others' quorum, and the row reads Stalled
    // until the record amends them out or re-seats them.
    let bytes =
        ciris_verify_core::accord_genesis::accord_family_signing_bytes(&proof.change_envelope)
            .map_err(|e| Error::InvalidArgument(format!("founders' change envelope: {e}")))?;
    let mut signers = std::collections::BTreeSet::new();
    for sig in &proof.quorum_signatures {
        if !prior_founders.contains(&sig.member_id.as_str())
            || signers.contains(&sig.member_id)
            || !memo
                .founder_counts(
                    directory,
                    id,
                    &sig.member_id,
                    Some(amended_at),
                    seated_since(chain, &sig.member_id),
                )
                .await?
        {
            continue;
        }
        let Some(rec) = memo.record(directory, &sig.member_id).await? else {
            continue;
        };
        let member = ThresholdMember {
            member_id: rec.key_id,
            ed25519_public_key_base64: rec.pubkey_ed25519_base64,
            mldsa65_public_key_base64: rec.pubkey_ml_dsa_65_base64,
            role: None,
        };
        if ciris_verify_core::threshold::verify_threshold_signatures(
            &bytes,
            std::slice::from_ref(&member),
            std::slice::from_ref(sig),
            1,
        )
        .is_ok()
        {
            signers.insert(sig.member_id.clone());
        }
    }
    // The seats: prior's recorded members, minus every founder that does not
    // count at the link's instant — resigned, node-bearing (#925), withdrawn or
    // never conferred — so an ineligible seat never inflates the denominator.
    let mut seats: Vec<super::consensus::Seat> = Vec::with_capacity(prior.members.len());
    for m in &prior.members {
        let is_founder = m.role.as_deref() == Some(super::admission::MEMBER_ROLE_FOUNDER);
        if is_founder
            && !memo
                .founder_counts(
                    directory,
                    id,
                    &m.key_id,
                    Some(amended_at),
                    seated_since(chain, &m.key_id),
                )
                .await?
        {
            continue;
        }
        seats.push(super::consensus::Seat {
            key_id: m.key_id.clone(),
            role: m.role.clone(),
            node_bearing: super::is_node_bearing_key_at(directory, &m.key_id, amended_at).await?,
        });
    }
    let verdict = super::consensus::evaluate(&super::consensus::Ballot {
        protocol: &prior.consensus_protocol,
        subkind: Some(COHORT_SUBKIND_INFRASTRUCTURE),
        policy_blob: prior.policy_blob.as_ref(),
        roster: &seats,
        signers: &signers,
        direction: super::consensus::Direction::Add,
    });
    if !verdict.admits() {
        return Err(Error::RosterAuthorityUnauthorized {
            group_key_id: id.to_owned(),
            offered_authority_key_id: next.authority_key_id.clone(),
            rule: super::ROSTER_CONSENSUS_INSUFFICIENT,
        });
    }
    if !signers.contains(&next.authority_key_id) {
        return Err(violation(
            id,
            super::admission::TRUST_ROOT_RULE_CHAIN,
            format!(
                "the version's authority {:?} is not one of the founders its proof counted",
                next.authority_key_id
            ),
        ));
    }
    super::verify_community_admission(directory, next).await?;
    Ok(amended_at)
}

/// The instant of the version that most recently SEATED `founder` in `chain`
/// (the birth's `founded_at`, or the `amended_at` of the link whose prior did
/// not name it a founder).
fn seated_since(chain: &[SignedCommunity], founder: &str) -> chrono::DateTime<chrono::Utc> {
    let is_f = |v: &SignedCommunity| founders(&v.community).contains(&founder);
    let mut since = chain
        .first()
        .map_or(chrono::DateTime::<chrono::Utc>::MIN_UTC, |b| {
            b.community.founded_at
        });
    for w in chain.windows(2) {
        if is_f(&w[1]) && !is_f(&w[0]) {
            since = link_instant(&w[1]).unwrap_or(since);
        }
    }
    since
}

/// The instant a stored head speaks at: its link's `amended_at`, or the
/// birth's `founded_at`.
pub(crate) fn head_instant(head: &SignedCommunity) -> chrono::DateTime<chrono::Utc> {
    link_instant(head).unwrap_or(head.community.founded_at)
}

fn link_instant(v: &SignedCommunity) -> Option<chrono::DateTime<chrono::Utc>> {
    v.supersede_proof
        .as_ref()?
        .change_envelope
        .get(AMENDED_AT)?
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
}

/// Walk `chain` from `chain[start]`, TRUSTING `chain[..=start]` (the birth,
/// or the version this node already holds with the chain it holds it by):
/// every later version must be a verified founders' link of the one before
/// it. Each link reads its founders' `seated_since` from the chain before it.
async fn verify_links_from<F>(
    directory: &F,
    chain: &[SignedCommunity],
    start: usize,
    memo: &mut Memo,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    for i in start..chain.len().saturating_sub(1) {
        verify_founders_link_memo(directory, &chain[..=i], &chain[i + 1], memo).await?;
    }
    Ok(())
}

/// The chain a node walks from a version it HOLDS: the held version's own
/// chain (what this node verified), then the offered versions after the held
/// one. The offered lineage before the held version is never read, so an
/// offered prefix cannot move a founder's `seated_since`. Returns the walk and
/// the held version's index in it.
fn walk_from_held(
    held: &SignedCommunity,
    offered: &[SignedCommunity],
    pos: usize,
) -> (Vec<SignedCommunity>, usize) {
    let mut walk = chain_of(held);
    let at = walk.len() - 1;
    walk.extend(offered[pos + 1..].iter().cloned());
    (walk, at)
}

/// **The whole chain** (CIRISPersist#926 re-check, HIGH-A): `chain[0]` is an
/// accord BIRTH — no proof, conformant, its own scrub set reaching the accord
/// family's quorum (re-derived now, so a holder revocation that drops the
/// family's count below quorum un-roots it until a re-birth), every founder
/// counting at the birth — and every later version is a verified founders'
/// link. All versions name the same id.
///
/// # Errors
///
/// The refusal of the first clause that fails.
pub async fn verify_chain<F>(
    directory: &F,
    chain: &[SignedCommunity],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    verify_chain_memo(directory, chain, &mut Memo::at(now)).await
}

async fn verify_chain_memo<F>(
    directory: &F,
    chain: &[SignedCommunity],
    memo: &mut Memo,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(birth) = chain.first() else {
        return Err(Error::InvalidArgument("an empty trust-root chain".into()));
    };
    let id = birth.community.community_key_id.as_str();
    if chain.iter().any(|v| v.community.community_key_id != id) {
        return Err(violation(
            id,
            super::admission::TRUST_ROOT_RULE_CHAIN,
            "a chain names more than one community",
        ));
    }
    if birth.supersede_proof.is_some() {
        return Err(violation(
            id,
            super::admission::TRUST_ROOT_RULE_CHAIN,
            "the chain does not start at an accord birth (its first version carries a proof)",
        ));
    }
    check_trust_root_shape(&birth.community)?;
    for f in founders(&birth.community) {
        if !memo
            .founder_counts(
                directory,
                id,
                f,
                Some(birth.community.founded_at),
                birth.community.founded_at,
            )
            .await?
        {
            return Err(violation(
                id,
                super::admission::INFRA_RULE_FOUNDER_NOT_CONFERRED,
                format!("the birth's founder {f:?} was not an eligible founder at the birth"),
            ));
        }
    }
    if !accord_quorum_at(directory, birth, memo).await?.met() {
        return Err(insufficient(birth));
    }
    verify_links_from(directory, chain, 0, memo).await
}

/// Is `e` a verdict about the row (it does not verify), as opposed to a
/// failure of this node (which must propagate)?
///
fn is_row_verdict(e: &Error) -> bool {
    matches!(
        e,
        Error::InvalidArgument(_)
            | Error::RosterAuthorityUnauthorized { .. }
            | Error::RoleNotAccordConferred { .. }
            | Error::FederationTierUnverified { .. }
            | Error::CommunityConsensusProtocolViolation { .. }
    )
}

/// What this node holds at a trust-root id.
#[derive(Debug, Clone)]
pub enum StoredStanding {
    /// No row.
    Absent,
    /// A row whose chain verifies from an accord birth and whose every
    /// RECORDED founder counts now: resolved, served and trusted.
    Rooted(Box<SignedCommunity>),
    /// A row whose chain STILL verifies from an accord birth but one of whose
    /// recorded founders no longer counts (a withdrawn or rotated conferral).
    /// Not resolved, served or trusted — but it is still the version the
    /// founders amend from: a founders' amendment that retires the founder
    /// roots it again.
    Stalled {
        /// The held row.
        held: Box<SignedCommunity>,
        /// Why, by name (served beside `community: null`).
        reason: String,
    },
    /// A row at the id that never passed (or no longer passes) this door —
    /// never resolved, served or trusted, and replaceable by an accord birth.
    NotRooted {
        /// Why, by name (served beside `community: null`).
        reason: String,
    },
}

impl StoredStanding {
    /// The version a founders' amendment may extend: a rooted row, or a
    /// stalled one whose chain still verifies.
    fn held(&self) -> Option<&SignedCommunity> {
        match self {
            Self::Rooted(h) | Self::Stalled { held: h, .. } => Some(h),
            Self::Absent | Self::NotRooted { .. } => None,
        }
    }
}

/// A per-directory cache of [`stored_standing`] (#926 re-check, MEDIUM-C),
/// held by each real backend and reached through
/// [`FederationDirectory::trust_root_standing_cache`](super::FederationDirectory::trust_root_standing_cache).
///
/// Keyed on a digest of EVERY input the verdict reads, as stored — the signed
/// row with its lineage, the accord family's record and raw roster plane, the
/// key record, steward withdrawal (with its proposal's signed `window_until`)
/// and node-bearing intervals of every holder and every key the chain names,
/// and the community's resignation instants — so any change to them (a holder
/// revocation, a founder key rotation or withdrawal, a resignation, an
/// amendment) is a different key. The key holds no value evaluated against
/// the clock. Instead each entry carries the instant it was judged at and
/// `valid_until`, the earliest time-dependent boundary after it
/// ([`Memo::bound`]), and is served only between the two (#926 round 9).
/// Never process-global: two directories never share one.
#[derive(Debug, Default)]
pub struct StandingCache {
    entries: std::sync::Mutex<std::collections::HashMap<String, CachedStanding>>,
    computations: std::sync::atomic::AtomicU64,
    /// v51.0.0 (CIRISPersist#939) — the last LIVENESS this directory observed
    /// per community, keyed by id (not by input key), so a live ↔ stalled
    /// transition is declared once even though the transition changes the
    /// cache key. One bool per id, cleared at [`STANDING_CACHE_CAP`] like
    /// `entries` (PR #943 review: bounded). A report of the transition, never
    /// an input to a verdict.
    last: std::sync::Mutex<std::collections::HashMap<String, bool>>,
}

/// One cached verdict and the span of instants it holds for.
#[derive(Debug, Clone)]
struct CachedStanding {
    standing: StoredStanding,
    judged_at: chrono::DateTime<chrono::Utc>,
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
}

impl CachedStanding {
    /// The verdict judged at `judged_at` still holds at `now`: no input the
    /// verdict compares against the clock changes its answer in
    /// `[judged_at, now]`.
    fn holds_at(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.judged_at <= now && self.valid_until.is_none_or(|v| now < v)
    }
}

impl StandingCache {
    /// How many times a standing was COMPUTED (signatures verified) rather
    /// than served from the cache.
    #[must_use]
    pub fn computations(&self) -> u64 {
        self.computations.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The most entries a [`StandingCache`] keeps before it starts over.
const STANDING_CACHE_CAP: usize = 256;

async fn standing_cache_key<F>(directory: &F, signed: &SignedCommunity) -> Result<String, Error>
where
    F: FederationDirectory + ?Sized,
{
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let mut feed = |label: &str, v: &serde_json::Value| {
        h.update(label.as_bytes());
        h.update(b"\x00");
        h.update(serde_json::to_vec(v).unwrap_or_default());
        h.update(b"\x00");
    };
    feed("row", &serde_json::to_value(signed).unwrap_or_default());
    // v51.0.0 (#938) — every cosign held for the lineage (a stored input the
    // witnessed-head fold reads; propagates its failure like every read here).
    let cosigns = match directory
        .list_lineage_head_cosigns_for(&signed.community.community_key_id)
        .await
    {
        Ok(c) => Some(c),
        Err(Error::Unsupported { .. }) => None,
        Err(e) => return Err(e),
    };
    feed(
        "lineage_cosigns",
        &serde_json::to_value(&cosigns).unwrap_or_default(),
    );
    // PR #943 review — the charter members the witnessed-head fold reads
    // (`witness_quorum`; with the window and cadence for completeness): a
    // quorum-authorized charter that raises the quorum must change the key.
    let charter = charter_members_for(directory, &signed.community.community_key_id).await?;
    feed(
        "charter_members",
        &serde_json::json!(charter.map(|c| (
            c.attach_window_secs,
            c.witness_cadence_secs,
            c.witness_quorum
        ))),
    );
    let family_id = accord_family_key_id();
    // PR #921 review (Codex, F1) — every read here PROPAGATES its failure. A
    // key built over a failed read keyed exactly like a genuinely empty
    // plane, so a Rooted verdict cached over an empty plane was served while
    // the revocation state could not be read. No key → no lookup → the error
    // reaches the caller and nothing is cached. `Unsupported` (the directory
    // cannot answer, a structural fact) keys as its own marker, never equal to
    // any answer.
    let family = directory.lookup_family(family_id).await?;
    feed("family", &serde_json::to_value(&family).unwrap_or_default());
    // The family's roster plane AS STORED (every widening and revocation, and
    // their signers), not the roster folded at the clock: the fold's answer
    // at the verdict's instant is bounded by `valid_until` instead.
    let widenings = answered(
        directory
            .list_family_membership_widenings_for(family_id)
            .await,
    )?;
    let revocations = answered(
        directory
            .list_family_membership_revocations_for(family_id)
            .await,
    )?;
    // `family_roster_signers` names an unknown family `InvalidArgument`; with
    // no family read above there is nothing to ask it.
    let signers = match &family {
        Some(_) => answered(directory.family_roster_signers(family_id).await)?,
        None => None,
    };
    feed(
        "family_plane",
        &serde_json::json!({
            "w": serde_json::to_value(&widenings).unwrap_or_default(),
            "r": serde_json::to_value(&revocations).unwrap_or_default(),
            "s": serde_json::to_value(&signers).unwrap_or_default(),
        }),
    );
    let mut keys: std::collections::BTreeSet<String> =
        super::admission::accord_holder_roster_key_ids()
            .into_iter()
            .collect();
    if let Some(f) = &family {
        keys.extend(f.members.iter().map(|m| m.key_id.clone()));
    }
    keys.extend(widenings.iter().flatten().map(|w| w.member().key_id));
    for v in chain_of(signed) {
        keys.extend(v.community.members.iter().map(|m| m.key_id.clone()));
        keys.insert(v.authority_key_id.clone());
        keys.extend(v.cosignatures.iter().map(|c| c.authority_key_id.clone()));
        if let Some(p) = &v.supersede_proof {
            keys.extend(p.quorum_signatures.iter().map(|s| s.member_id.clone()));
        }
    }
    for k in &keys {
        let rec = directory
            .lookup_public_key(k)
            .await?
            .map(|r| r.persist_row_hash);
        let w = directory
            .lookup_role_withdrawal(identity_type::STEWARD, k)
            .await?;
        // The withdrawal's instant is its proposal's signed `window_until`,
        // or MIN while this node holds no proposal (`Memo::withdrawal_instant`):
        // the proposal landing is a changed input (#926 round 9, 2c).
        let window = match &w {
            Some(w) => match directory
                .get_accord_proposal(&w.authority_decision_digest)
                .await
            {
                Ok(Some(p)) => serde_json::json!(p.proposal.window_until),
                Ok(None) | Err(Error::Unsupported { .. }) => serde_json::json!("no-proposal"),
                Err(e) => return Err(e),
            },
            None => serde_json::Value::Null,
        };
        // #925's node-bearing inputs (own set, agreed occurrence bindings of a
        // `node` identity) as stored intervals: a founder later bound as an
        // occurrence of a node is a different key; the interval's value at the
        // verdict's instant is bounded by `valid_until`.
        let (own_node, node_intervals) = super::node_bearing_of(directory, k).await?;
        feed(
            "key",
            &serde_json::json!({
                "k": k,
                "rec": rec,
                "w": serde_json::to_value(&w).unwrap_or_default(),
                "window_until": window,
                "node": own_node,
                "node_intervals": format!("{node_intervals:?}"),
            }),
        );
    }
    // Every self-signed resignation instant (`Memo::resignations_of` reads
    // these), past or future: a re-seated founder's SECOND resignation leaves
    // the folded roster unchanged, so only the instants themselves key it.
    let mut resignations: Vec<(String, String)> = match directory
        .community_roster_signers(&signed.community.community_key_id)
        .await
    {
        Ok(signers) => signers
            .revocation_signers
            .into_iter()
            .filter(|r| {
                r.authority_key_id.as_deref() == Some(r.member_key_id.as_str())
                    && r.cosigner_key_ids.is_empty()
            })
            .map(|r| (r.member_key_id, r.effective_at.to_rfc3339()))
            .collect(),
        Err(Error::Unsupported { .. } | Error::InvalidArgument(_)) => Vec::new(),
        Err(e) => return Err(e),
    };
    resignations.sort();
    feed("resignations", &serde_json::json!(resignations));
    Ok(hex::encode(h.finalize()))
}

/// A cache-key read's answer: `Some` for a real answer, `None` when the
/// directory cannot answer (`Unsupported`, keyed as `null` — never equal to an
/// answer, the empty plane included). Every other error propagates: a failed
/// read is not an answer (PR #921 review, F1).
fn answered<T>(read: Result<T, Error>) -> Result<Option<T>, Error> {
    match read {
        Ok(v) => Ok(Some(v)),
        Err(Error::Unsupported { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// [`stored_standing_at`] at the wall clock: the one clock read, taken by the
/// caller's door.
///
/// # Errors
///
/// Directory read failures.
pub async fn stored_standing<F>(
    directory: &F,
    community_key_id: &str,
) -> Result<StoredStanding, Error>
where
    F: FederationDirectory + ?Sized,
{
    stored_standing_at(directory, community_key_id, chrono::Utc::now()).await
}

/// Re-judge the row stored at `community_key_id` AT `now` (see the module
/// doc). Called by every read side and by the doors before deciding what an
/// offered row extends. ROOTED ⇔ the stored row conforms, its CHAIN (stored
/// `lineage` plus the row) verifies from an accord birth ([`verify_chain`],
/// every link's proof re-verified — there is no proof-only arm), and EVERY
/// recorded founder counts at `now`. Nothing under it reads the wall clock.
/// Served from this directory's [`StandingCache`] while every input is
/// unchanged and `now` is before the entry's `valid_until`.
///
/// # Errors
///
/// Directory read failures.
pub async fn stored_standing_at<F>(
    directory: &F,
    community_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<StoredStanding, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(bare) = directory.lookup_community(community_key_id).await? else {
        return Ok(StoredStanding::Absent);
    };
    let not = |reason: String| Ok(StoredStanding::NotRooted { reason });
    if !is_trust_root_grade(&bare) {
        return not("not a trust-root community".into());
    }
    let Some(signed) = lookup_signed_community(directory, community_key_id).await? else {
        return not("the stored row carries no authority signature".into());
    };
    let cache = directory.trust_root_standing_cache();
    let key = match cache {
        Some(_) => Some(standing_cache_key(directory, &signed).await?),
        None => None,
    };
    if let (Some(c), Some(k)) = (cache, key.as_ref()) {
        if let Some(hit) = c.entries.lock().expect("standing cache").get(k) {
            if hit.holds_at(now) {
                return Ok(hit.standing.clone());
            }
        }
    }
    let (standing, valid_until) = compute_standing(directory, signed.clone(), now).await?;
    // v51.0.0 (CIRISPersist#939, CC 3.2 T7) — stalled is DECLARED at the
    // transition: live → stalled emits `community_liveness_stalled`, the
    // reverse `…_restored`. Liveness is the ACTIVE founder count against
    // M + 1 (PR #943 review), for any chain that still holds (Rooted or
    // Stalled). Every fold reproduces the verdict from rows; the hard case is
    // a report of the transition, never an input.
    if let Some(c) = cache {
        let live_now = match &standing {
            StoredStanding::Rooted(_) | StoredStanding::Stalled { .. } => {
                Some(is_live(directory, &signed, now).await?)
            }
            _ => None,
        };
        if let Some(live_now) = live_now {
            let prev = {
                let mut last = c.last.lock().expect("standing cache");
                if last.len() >= STANDING_CACHE_CAP && !last.contains_key(community_key_id) {
                    last.clear();
                }
                last.insert(community_key_id.to_owned(), live_now)
            };
            if let Some(prev) = prev {
                emit_liveness_transition(
                    directory,
                    community_key_id,
                    prev,
                    live_now,
                    &standing,
                    now,
                )
                .await?;
            }
        }
    }
    if let (Some(c), Some(k)) = (cache, key) {
        c.computations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut entries = c.entries.lock().expect("standing cache");
        if entries.len() >= STANDING_CACHE_CAP {
            entries.clear();
        }
        entries.insert(
            k,
            CachedStanding {
                standing: standing.clone(),
                judged_at: now,
                valid_until,
            },
        );
    }
    Ok(standing)
}

/// v51.0.0 (CIRISPersist#939) — emit the liveness hard case at a Rooted ↔
/// Stalled transition (idempotent per (community, transition instant)).
async fn emit_liveness_transition<F>(
    directory: &F,
    community_key_id: &str,
    prev_live: bool,
    live: bool,
    next: &StoredStanding,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let kind = match (prev_live, live) {
        (true, false) => super::hard_case::kind::COMMUNITY_LIVENESS_STALLED,
        (false, true) => super::hard_case::kind::COMMUNITY_LIVENESS_RESTORED,
        _ => return Ok(()),
    };
    let reason = match next {
        StoredStanding::Stalled { reason, .. } if !live => reason.clone(),
        _ if live => "the active founders reach M + 1 again".to_owned(),
        _ => "the active founders fell to M or fewer".to_owned(),
    };
    let event = super::hard_case::HardCaseEvent {
        event_id: format!("{kind}:{community_key_id}:{}", now.timestamp()),
        kind: kind.to_owned(),
        target_key_id: Some(community_key_id.to_owned()),
        subject_key_id: Some(community_key_id.to_owned()),
        detail: serde_json::json!({ "reason": reason, "at": now.to_rfc3339() }),
        emitted_at: now,
    };
    match directory.record_hard_case(event).await {
        Ok(()) => Ok(()),
        Err(Error::Backend(m)) if m.contains("not implemented") => Ok(()),
        Err(e) => Err(e),
    }
}

/// v51.0.0 (CIRISPersist#939, CC 3.2 T7; PR #943 review) — the ACTIVE founder
/// count of a trust-root row and its `M`: the recorded founders that count now
/// (not resigned since seated, not withdrawn, not node-bearing, accord-
/// conferred — the same `founder_counts` the standing fold reads). Live at
/// `active >= M + 1`; stalled at `active <= M` (valid, non-admitting).
pub async fn founder_liveness<F>(
    directory: &F,
    signed: &SignedCommunity,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(usize, usize), Error>
where
    F: FederationDirectory + ?Sized,
{
    let m = super::admission::infrastructure_quorum(&signed.community.consensus_protocol)
        .map(|(m, _)| m as usize)
        .unwrap_or(usize::MAX);
    let chain = chain_of(signed);
    let mut memo = Memo::at(now);
    let mut active = 0;
    for f in founders(&signed.community) {
        if memo
            .founder_counts(
                directory,
                &signed.community.community_key_id,
                f,
                None,
                seated_since(&chain, f),
            )
            .await?
        {
            active += 1;
        }
    }
    Ok((active, m))
}

/// Live at `active >= M + 1` (see [`founder_liveness`]).
pub async fn is_live<F>(
    directory: &F,
    signed: &SignedCommunity,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let (active, m) = founder_liveness(directory, signed, now).await?;
    Ok(active >= m.saturating_add(1))
}

/// The verdict at `now`, and the earliest instant after `now` at which the
/// same inputs may give a different one (`None`: none do).
async fn compute_standing<F>(
    directory: &F,
    signed: SignedCommunity,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(StoredStanding, Option<chrono::DateTime<chrono::Utc>>), Error>
where
    F: FederationDirectory + ?Sized,
{
    if let Err(e) = check_trust_root_shape(&signed.community) {
        return Ok((
            StoredStanding::NotRooted {
                reason: format!("non-conformant: {e}"),
            },
            None,
        ));
    }
    let mut memo = Memo::at(now);
    let chain = chain_of(&signed);
    match verify_chain_memo(directory, &chain, &mut memo).await {
        Ok(()) => {}
        Err(e) if is_row_verdict(&e) => {
            return Ok((
                StoredStanding::NotRooted {
                    reason: format!(
                        "not accord-born: its chain does not verify from an accord birth ({e})"
                    ),
                },
                memo.valid_until,
            ))
        }
        Err(e) => return Err(e),
    }
    // v51.0.0 (CIRISPersist#938, CC 3.2 T6) — the current head is the latest
    // WITNESSED version of the chain this node holds; an unwitnessed tail is
    // held, not adopted; two witnessed heads freeze the lineage at their last
    // common ancestor. A lineage never witnessed is judged as before
    // (`ever_witnessed` — the upgrade cannot un-root every node at once).
    let witness = witnessed_head(directory, &chain, now).await?;
    let signed = match witness.judged {
        Some(i) if i + 1 < chain.len() => {
            let mut judged = chain[i].clone();
            judged.lineage = chain[..i].to_vec();
            judged
        }
        _ => signed,
    };
    let chain = chain_of(&signed);
    for f in founders(&signed.community) {
        if !memo
            .founder_counts(
                directory,
                &signed.community.community_key_id,
                f,
                None,
                seated_since(&chain, f),
            )
            .await?
        {
            let reason = format!(
                "founder {f:?} is not eligible now (human, accord-conferred, not withdrawn, not \
                 resigned since seated); a founders' amendment that retires it roots the row again"
            );
            return Ok((
                StoredStanding::Stalled {
                    held: Box::new(signed),
                    reason,
                },
                memo.valid_until,
            ));
        }
    }
    Ok((StoredStanding::Rooted(Box::new(signed)), memo.valid_until))
}

/// v51.0.0 (CIRISPersist#938) — what the witness plane says about a chain this
/// node holds (FSD `TRUST_ROOT_RC6.md` §3.2–§3.3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct WitnessedHead {
    /// The chain index the standing is judged at: the latest witnessed
    /// version, or the fork point under equivocation. `None` when the lineage
    /// has never been witnessed (judged at its head, as before rc6).
    pub judged: Option<usize>,
    /// Versions past the judged one this node holds but does not adopt.
    pub unwitnessed_tail: usize,
    /// A competing witnessed head, when the lineage is frozen.
    pub equivocation: Option<Equivocation>,
    /// The latest cosign instant this node holds for the lineage, if any.
    pub latest_cosign_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Two witnessed heads for one lineage (T6): the evidence object.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Equivocation {
    /// This node's witnessed head.
    pub held_head_digest: String,
    /// The competing witnessed head the witness plane names.
    pub competing_head_digest: String,
    /// The last common ancestor both descend from — the frozen head.
    pub fork_digest: String,
    /// The witnesses of each.
    pub held_witnesses: Vec<String>,
    /// The witnesses of the competing head.
    pub competing_witnesses: Vec<String>,
}

/// v51.0.0 (CIRISPersist#937/#938) — the charter members of a root
/// (`trust:charter:v1`, the self-loop `delegates_to` the root signed with an
/// `infra:` scope): `attach_window_secs`, `witness_cadence_secs`,
/// `witness_quorum`. `None` when the root has no charter row here.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CharterMembers {
    /// [`super::envelope::paths::ATTACH_WINDOW_SECS`].
    pub attach_window_secs: Option<u64>,
    /// [`super::envelope::paths::WITNESS_CADENCE_SECS`].
    pub witness_cadence_secs: Option<u64>,
    /// [`super::envelope::paths::WITNESS_QUORUM`].
    pub witness_quorum: Option<u32>,
}

/// v53.0.0 (CC 3.2 T6, operator ruling B-1 on CIRISConstitution#136) —
/// **which charter rows a root's lineage head puts in force.** The head is the
/// family record at a version and names the charter in force at that version
/// (`charter_digest`); a charter row no version names is not in force, so a
/// charter re-scrub takes effect only through a new version, and the head
/// moves with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadCharter {
    /// The root holds no lineage record here (a key root): there is no head to
    /// name a charter, so every live charter-shaped row stands, as before.
    KeyRoot,
    /// The head names this charter (`persist_row_hash` of the
    /// `trust:charter:v1` row).
    Named(String),
    /// The head names no charter: none is in force.
    Unnamed,
}

impl HeadCharter {
    /// Read a head's `charter_digest`.
    #[must_use]
    pub fn of(charter_digest: &str) -> Self {
        if charter_digest.is_empty() {
            Self::Unnamed
        } else {
            Self::Named(charter_digest.to_owned())
        }
    }

    /// Does this head put `charter` in force?
    #[must_use]
    pub fn admits(&self, charter: &super::Attestation) -> bool {
        match self {
            Self::KeyRoot => true,
            Self::Named(digest) => charter.persist_row_hash == *digest,
            Self::Unnamed => false,
        }
    }
}

/// v53.0.0 (CC 3.2 T6) — **the digest a version names a charter by, computed
/// before the row is stored**: the `persist_row_hash` every backend assigns
/// the row, which is taken over the envelope in its at-rest canonical form
/// (`canonical_at_rest::canonicalize_in_place`, run at every put door before
/// the hash). A producer minting a version together with its charter (a
/// genesis, a ceremony) names the charter by this.
///
/// # Errors
///
/// An envelope the at-rest canonicalizer refuses, or a row that does not hash.
pub fn stored_row_hash(charter: &super::Attestation) -> Result<String, Error> {
    let mut row = charter.clone();
    super::canonical_at_rest::canonicalize_in_place(&mut row.attestation_envelope)?;
    row.persist_row_hash = String::new();
    super::types::compute_persist_row_hash(&row)
}

/// v53.0.0 (CC 3.2 T6) — **the ONE answer to "which charter is in force for
/// `root`"**: the lineage whose head decides, and what that head names.
///
/// - a family root: its own head;
/// - a community: its conferring family's head — a community's legs are the
///   family's (CC 4.4: `{community_key_id: ciris-canonical, family:
///   humanity-accord}`), and every trust-root community is accord-rooted;
/// - anything else: a key root ([`HeadCharter::KeyRoot`]), whose charter is
///   its own self-loop.
///
/// Returns the key id the charter rows name (`attested_key_id`) with the
/// verdict. Every reader of a root's charter — the trust-root charter leg,
/// the charter members (attach window, witness cadence and quorum) — routes
/// through here, so they cannot disagree about which charter stands.
///
/// # Errors
///
/// Directory read failures.
pub async fn charter_in_force<F>(
    directory: &F,
    root_key_id: &str,
) -> Result<(String, HeadCharter), Error>
where
    F: FederationDirectory + ?Sized,
{
    if let Some(fam) = directory.lookup_family(root_key_id).await? {
        return Ok((root_key_id.to_owned(), HeadCharter::of(&fam.charter_digest)));
    }
    if directory.lookup_community(root_key_id).await?.is_some() {
        let family = accord_family_key_id();
        let head = match directory.lookup_family(family).await? {
            Some(fam) => HeadCharter::of(&fam.charter_digest),
            None => HeadCharter::Unnamed,
        };
        return Ok((family.to_owned(), head));
    }
    Ok((root_key_id.to_owned(), HeadCharter::KeyRoot))
}

/// v53.1.2 (CIRISPersist#984 row 5) — **the live charter row of `family`
/// that `digest` names**: a held `delegates_to` toward the family carrying
/// the charter reading, whose direction reading stands and which no
/// entitled retraction has retired. `None` for an empty digest, a digest no
/// row carries, a row that is not a charter, or one withdrawn. The ONE
/// predicate every reader of a named charter runs — the accord version
/// door, the recovery commitment in force, the genesis roster install — so
/// a withdrawn or unlabelled row is a charter to none of them.
///
/// # Errors
///
/// Directory read failures.
pub async fn live_charter_row<F>(
    directory: &F,
    family: &str,
    digest: &str,
) -> Result<Option<super::Attestation>, Error>
where
    F: FederationDirectory + ?Sized,
{
    if digest.is_empty() {
        return Ok(None);
    }
    let is_charter = |a: &super::Attestation| {
        a.attestation_type == super::types::attestation_type::DELEGATES_TO
            && a.attested_key_id == family
            && super::trust_root::job_dimension_admits(
                &a.attestation_envelope,
                super::trust_root::TRUST_CHARTER_DIMENSION,
            )
    };
    let rows = directory.list_attestations_for(family).await?;
    let refs: Vec<&super::Attestation> = rows.iter().collect();
    let retired = super::precedence::retired_ids(&refs);
    let denied =
        super::trust_root::direction_denied_ids(directory, rows.iter().filter(|a| is_charter(a)))
            .await?;
    Ok(rows.into_iter().find(|a| {
        a.persist_row_hash == digest
            && is_charter(a)
            && !denied.contains(&a.attestation_id)
            && !retired.contains(&a.attestation_id)
    }))
}

/// Read a root's charter members from the charter in force
/// ([`charter_in_force`]).
pub async fn charter_members_for<F>(
    directory: &F,
    root_key_id: &str,
) -> Result<Option<CharterMembers>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::envelope::paths;
    let is_charter = |a: &super::Attestation| {
        a.attestation_type == super::types::attestation_type::DELEGATES_TO
            && super::trust_root::job_dimension_admits(
                &a.attestation_envelope,
                super::trust_root::TRUST_CHARTER_DIMENSION,
            )
    };
    // The charter names its lineage as its ATTESTED key (a key root charters
    // itself; the accord's holders charter their family).
    let in_force = |owner: String, head: HeadCharter| async move {
        let mut rows = directory.list_attestations_for(&owner).await?;
        // #973 (CC 3.2 T4a) — an unlabelled row is a charter only where its
        // direction reading stands (held, or a pinned-bundle row).
        let denied = super::trust_root::direction_denied_ids(
            directory,
            rows.iter().filter(|a| is_charter(a)),
        )
        .await?;
        rows.retain(|a| is_charter(a) && !denied.contains(&a.attestation_id) && head.admits(a));
        Ok::<_, Error>(rows)
    };
    let (owner, head) = charter_in_force(directory, root_key_id).await?;
    let key_root = head == HeadCharter::KeyRoot;
    let mut rows = in_force(owner, head).await?;
    // A key root with no charter of its own reads the accord's, as before.
    if rows.is_empty() && key_root && root_key_id != accord_family_key_id() {
        let (owner, head) = charter_in_force(directory, accord_family_key_id()).await?;
        rows = in_force(owner, head).await?;
    }
    let charter = rows.first();
    Ok(charter.map(|a| {
        let e = &a.attestation_envelope;
        CharterMembers {
            attach_window_secs: e.get(paths::ATTACH_WINDOW_SECS).and_then(|v| v.as_u64()),
            witness_cadence_secs: e.get(paths::WITNESS_CADENCE_SECS).and_then(|v| v.as_u64()),
            witness_quorum: e
                .get(paths::WITNESS_QUORUM)
                .and_then(|v| v.as_u64())
                .map(|q| q.min(u32::MAX as u64) as u32),
        }
    }))
}

/// The witness quorum a lineage's charter declares; `0` when the charter is
/// silent or declares zero — witnessed mode off (#973, CC 3.2 T6).
async fn witness_quorum_for<F>(directory: &F, community: &Community) -> Result<u32, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(super::lineage_witness::declared_witness_quorum(
        charter_members_for(directory, &community.community_key_id)
            .await?
            .and_then(|c| c.witness_quorum),
    ))
}

/// The witnessed-head computation over the chain this node holds and every
/// cosign held for the lineage. Emits `hard_case:lineage_equivocation` (once
/// per pair, idempotent by event id) when two witnessed heads are found.
async fn witnessed_head<F>(
    directory: &F,
    chain: &[SignedCommunity],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<WitnessedHead, Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::lineage_witness::{effective_cosigns, principals_of, witnessed, witnesses_of};
    let Some(head) = chain.last() else {
        return Ok(WitnessedHead {
            judged: None,
            unwitnessed_tail: 0,
            equivocation: None,
            latest_cosign_at: None,
        });
    };
    let id = head.community.community_key_id.as_str();
    let cosigns = match directory.list_lineage_head_cosigns_for(id).await {
        Ok(c) => c,
        Err(Error::Unsupported { .. }) => Vec::new(),
        Err(e) => return Err(e),
    };
    let known: Vec<(String, chrono::DateTime<chrono::Utc>)> = chain
        .iter()
        .map(|v| Ok((row_hash(&v.community)?, head_instant(v))))
        .collect::<Result<_, Error>>()?;
    let digests: Vec<String> = known.iter().map(|(d, _)| d.clone()).collect();
    // PR #943 review: only cosigns that COUNT (the witness key valid at its
    // instant; a deferred cosign re-checked against the version it names).
    let effective = effective_cosigns(directory, &cosigns, &known).await?;
    let latest_cosign_at = effective.iter().map(|c| c.signed_at).max();
    let founders_all: Vec<String> = chain
        .iter()
        .flat_map(|v| founders(&v.community).into_iter().map(str::to_owned))
        .collect();
    let founder_principals = principals_of(directory, &founders_all).await?;
    let quorum = witness_quorum_for(directory, &head.community).await?;
    // #973 (CC 3.2 T6) — witnessed mode OFF: the head is current on the
    // founders' quorum and its descent, exactly as before rc6. Cosigns held
    // are evidence and judge nothing: no witnessed prefix, no equivocation.
    if !super::lineage_witness::witnessed_mode_on(quorum) {
        return Ok(WitnessedHead {
            judged: None,
            unwitnessed_tail: 0,
            equivocation: None,
            latest_cosign_at,
        });
    }
    // Witnessed mode engages only once some version of this chain has actually
    // reached the QUORUM (PR #943 review: one cosign under a quorum of two
    // must not roll a multi-version lineage back to its birth). Until then the
    // lineage is judged as before rc6.
    let Some(mut judged) = (0..chain.len())
        .rev()
        .find(|&i| witnessed(&effective, &digests[i], &founder_principals, quorum))
    else {
        return Ok(WitnessedHead {
            judged: None,
            unwitnessed_tail: 0,
            equivocation: None,
            latest_cosign_at,
        });
    };
    // Equivocation: a WITNESSED head not in this chain whose ancestry, walked
    // back through the priors the witness plane names, reaches this chain at
    // or before the judged version (PR #943 review: walk the whole competing
    // ancestry, not only the immediate prior — H1→H2′→H3′ against H1→H2→H3
    // forks at H1).
    let priors: std::collections::BTreeMap<&str, Vec<&str>> = {
        let mut m: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
        for c in &effective {
            if let Some(p) = c.prior.as_deref() {
                m.entry(c.head_digest.as_str()).or_default().push(p);
            }
        }
        m
    };
    let fork_point = |start: &str| -> Option<usize> {
        let mut frontier = vec![start];
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        let mut best: Option<usize> = None;
        while let Some(d) = frontier.pop() {
            if !seen.insert(d) || seen.len() > effective.len() + 1 {
                continue;
            }
            for p in priors.get(d).into_iter().flatten() {
                match digests.iter().position(|x| x == p) {
                    Some(i) => best = Some(best.map_or(i, |b: usize| b.min(i))),
                    None => frontier.push(p),
                }
            }
        }
        best
    };
    let mut equivocation = None;
    let mut competing: Vec<&str> = effective
        .iter()
        .filter(|c| !digests.contains(&c.head_digest))
        .map(|c| c.head_digest.as_str())
        .collect();
    competing.sort_unstable();
    competing.dedup();
    for d in competing {
        if !witnessed(&effective, d, &founder_principals, quorum) {
            continue;
        }
        let Some(fork_i) = fork_point(d) else {
            continue;
        };
        if fork_i < judged {
            let e = Equivocation {
                held_head_digest: digests[judged].clone(),
                competing_head_digest: d.to_owned(),
                fork_digest: digests[fork_i].clone(),
                held_witnesses: witnesses_of(&effective, &digests[judged], &founder_principals),
                competing_witnesses: witnesses_of(&effective, d, &founder_principals),
            };
            emit_lineage_equivocation(directory, id, &e, now).await?;
            judged = fork_i;
            equivocation = Some(e);
        }
    }
    Ok(WitnessedHead {
        judged: Some(judged),
        unwitnessed_tail: chain.len() - 1 - judged,
        equivocation,
        latest_cosign_at,
    })
}

/// `hard_case:lineage_equivocation:{lineage}` under the substrate emitter
/// rule; idempotent per (lineage, pair) by event id.
async fn emit_lineage_equivocation<F>(
    directory: &F,
    lineage_key_id: &str,
    e: &Equivocation,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let (a, b) = if e.held_head_digest <= e.competing_head_digest {
        (&e.held_head_digest, &e.competing_head_digest)
    } else {
        (&e.competing_head_digest, &e.held_head_digest)
    };
    let event = super::hard_case::HardCaseEvent {
        event_id: format!(
            "lineage_equivocation:{lineage_key_id}:{}:{}",
            &a[..16],
            &b[..16]
        ),
        kind: super::hard_case::kind::LINEAGE_EQUIVOCATION.to_owned(),
        target_key_id: Some(lineage_key_id.to_owned()),
        subject_key_id: Some(lineage_key_id.to_owned()),
        detail: serde_json::to_value(e).unwrap_or_default(),
        emitted_at: now,
    };
    match directory.record_hard_case(event).await {
        Ok(()) => Ok(()),
        // a backend with no hard-case plane (the fault double's inner, a bare
        // memory in a unit) still judges; the evidence is the cosign rows
        Err(Error::Backend(m)) if m.contains("not implemented") => Ok(()),
        Err(e) => Err(e),
    }
}

/// #973 — which door an acceptance edge is arriving through at
/// [`check_attach_freshness`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachDoor {
    /// This node authored the edge in-process: its own attach, judged in full.
    Author,
    /// The edge arrived from elsewhere (a peer, a sync, an import): another
    /// node's attach, already admitted at its own door.
    Replicated,
}

impl AttachDoor {
    /// The door a stored write's origin names.
    #[must_use]
    pub fn of(origin: &super::replication::admission::WriteOrigin) -> Self {
        match origin {
            super::replication::admission::WriteOrigin::Authored => Self::Author,
            super::replication::admission::WriteOrigin::Wire
            | super::replication::admission::WriteOrigin::Sync { .. } => Self::Replicated,
        }
    }
}

/// **T4a — the acceptance edge is gated on freshness** (CIRISPersist#937, CC
/// 3.2 T4a rc6; FSD `TRUST_ROOT_RC6.md` §2.2). For a `delegates_to` carrying
/// `trust:accepts:v1` whose `attested_key_id` is a root this node holds a
/// LINEAGE for (a trust-root community, or a family): the edge must name the
/// head it attaches under (`attached_head_digest`); that head must be the one
/// this node holds, WITNESSED (the charter's quorum of independent witnesses),
/// and no older than the charter's `attach_window_secs` measured against the
/// head's signer-stamped instant under the CC 2.6.7 skew rule. A charter with
/// no window admits only an edge naming the head (the T5 anchor). Refusals are
/// `Error::TrustRootHeadStale`. A root with no lineage here (a KEY root) is
/// not this gate's business; nothing on the ATTACHED side reads this.
///
/// #973 (CC 3.2 T4a, rc6 5cceadb) — **only a NEW edge is gated.** "An edge
/// admitted before a substrate enforced this rule carries no
/// `attached_head_digest` and stays valid … on every later put, replication
/// or restore of that same edge; it is read as naming the head the node held
/// when it was admitted. Only a new edge is gated: a new edge that names no
/// head is refused in every mode, witnessed mode off included, where the head
/// it must name is the anchored one." NEW is structural: `attestation_id`
/// names no row this node holds with the same attester, root and signed
/// envelope. A held edge re-offered unchanged passes without re-running
/// freshness; anything else under a held id is judged as new. A new headless
/// edge is refused `Error::TrustRootHeadUnnamed`.
///
/// #973 (CC 3.2 T4a: "a write-side gate … the gate runs on the edge's first
/// admission only … once the edge is written, T4 governs without exception")
/// — **a peer does not re-judge another node's attach.** The head and
/// freshness comparison belongs to the ATTACHING node's own write
/// ([`AttachDoor::Author`]). At [`AttachDoor::Replicated`] the edge was
/// already admitted where it was written: this node's head may be ahead of or
/// behind the one it names, and its witness view is its own, so only the
/// SHAPE rule runs there (a new labelled edge names a head).
#[allow(clippy::too_many_arguments)]
pub async fn check_attach_freshness<F>(
    directory: &F,
    door: AttachDoor,
    attestation_id: Option<&str>,
    attesting_key_id: &str,
    attestation_type_str: &str,
    attested_key_id: &str,
    envelope: &serde_json::Value,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::envelope::paths;
    if attestation_type_str != super::types::attestation_type::DELEGATES_TO
        || !super::trust_root::job_dimension_admits(
            envelope,
            super::trust_root::TRUST_ACCEPTS_DIMENSION,
        )
    {
        return Ok(());
    }
    // #973 (CC 3.2 T4a, "bundle only") — "a new row with no `trust:{job}`
    // label gives no acceptance and is no charter". Outside the pinned bundle
    // an unlabelled row is therefore not an acceptance edge and there is
    // nothing to gate: it is stored as a delegation and the readers never
    // count it (`trust_root::direction_denied_ids`). A pinned-bundle row
    // keeps the reading its direction gives it, gate included.
    if super::trust_root::names_no_trust_job(envelope)
        && !attestation_id
            .is_some_and(|id| super::genesis::is_pinned_bundle_statement(id, envelope))
    {
        return Ok(());
    }
    let root = attested_key_id;
    let refuse = |detail: String| {
        Err(Error::TrustRootHeadStale {
            root_key_id: root.to_owned(),
            detail,
        })
    };
    // The lineage head the attach is judged against is the WITNESSED head the
    // fold serves (PR #943 review): with a witnessed H1 and an unwitnessed H2
    // held, a consumer attaches under H1 — comparing with the raw stored H2
    // made every witness-lag interval un-attachable.
    let Some(view) = root_witness_view(directory, root, now).await? else {
        return Ok(());
    };
    // T4a: "the gate runs on the edge's first admission only".
    if edge_already_admitted(directory, attestation_id, attesting_key_id, root, envelope).await? {
        return Ok(());
    }
    let charter = charter_members_for(directory, root)
        .await?
        .unwrap_or_default();
    let presented = envelope
        .get(paths::ATTACHED_HEAD_DIGEST)
        .and_then(|v| v.as_str());
    // A new edge that NAMES itself `trust:accepts:v1` names the head it
    // attaches on, in every mode. A row with no job label reaches this gate
    // by direction inference only, and the same inference covers a family's
    // charter and the baked genesis plane (the unlabeled `genesis-charter`),
    // which are not acceptance edges and carry no head: for those the
    // pre-#973 reading is kept exactly — armed by the charter's window.
    let labeled = super::admission::envelope_dimension(envelope)
        == Some(super::trust_root::TRUST_ACCEPTS_DIMENSION);
    let off = !super::lineage_witness::witnessed_mode_on(view.quorum);
    // Another node's attach: the shape rule only. Which head it named, and
    // whether that head was fresh and witnessed, was its own door's question.
    if door == AttachDoor::Replicated && (presented.is_some() || !labeled) {
        return Ok(());
    }
    let Some(presented) = presented else {
        if labeled {
            return Err(Error::TrustRootHeadUnnamed {
                root_key_id: root.to_owned(),
                detail: format!(
                    "a new acceptance edge must name the lineage head it attaches on (`{}`): the \
                     witnessed head, or the anchored head this node holds while witnessed mode is \
                     off (CC 3.2 T4a)",
                    paths::ATTACHED_HEAD_DIGEST
                ),
            });
        }
        if charter.attach_window_secs.is_none() {
            return Ok(());
        }
        return if off {
            refuse(format!(
                "the lineage of {root} is in witnessed mode off: attaching requires an \
                 out-of-band anchor naming the head (`{}`), never a cosignature (CC 3.2 T6)",
                paths::ATTACHED_HEAD_DIGEST
            ))
        } else {
            refuse(format!(
                "the root's charter declares an attach window of {}s: attaching requires the \
                 witnessed lineage head (`{}`) inside it — never attach on a stale or absent one",
                charter.attach_window_secs.unwrap_or_default(),
                paths::ATTACHED_HEAD_DIGEST
            ))
        };
    };
    // #973 (CC 3.2 T6, witnessed mode off) — no head is fresh by cosignature,
    // so none is attachable by cosignature: an attach is by an out-of-band
    // anchor to the head this node holds (T5), and the window does not apply.
    if off {
        return match view.held_head.as_ref() {
            Some((held, _)) if presented == held => Ok(()),
            _ => refuse(format!(
                "the presented head {presented} is not the head this node holds for {root}: in \
                 witnessed mode off an attach names the current head as its anchor"
            )),
        };
    }
    let Some((head_digest, head_at)) = view.witnessed_head.clone() else {
        return refuse(format!(
            "the lineage of {root} is not witnessed ({} independent witness cosign(s) required, \
             founders excluded): never attach on an unwitnessed head (CC 3.2 T6)",
            view.quorum
        ));
    };
    if presented != head_digest {
        return refuse(format!(
            "the presented head {presented} is not the witnessed head this node serves for \
             {root} ({head_digest}): fetch the current witnessed head, never attach on a stale one"
        ));
    }
    match charter.attach_window_secs {
        None => Ok(()), // no window: the named head IS the T5 anchor
        Some(window) => {
            // PR #943 review: checked conversion and date arithmetic — a
            // window beyond what an instant can express is no bound at all.
            let latest_ok = i64::try_from(window)
                .ok()
                .and_then(chrono::Duration::try_seconds)
                .and_then(|w| head_at.checked_add_signed(w))
                .and_then(|t| t.checked_add_signed(super::operational::CLOCK_SKEW_TOLERANCE));
            match latest_ok {
                Some(latest_ok) if now > latest_ok => refuse(format!(
                    "the head {head_digest} was asserted at {} — older than the root's attach \
                     window of {window}s (measured against the signer-stamped instant, ±skew): \
                     fetch a fresher witnessed head or refuse to attach",
                    head_at.to_rfc3339()
                )),
                _ => Ok(()),
            }
        }
    }
}

/// T4a's "first admission only", decided structurally: this node already holds
/// a row under `attestation_id` with the same attester, the same root and the
/// same signed envelope. A directory that cannot answer the lookup, or a held
/// row that differs in any of the three, is "new".
async fn edge_already_admitted<F>(
    directory: &F,
    attestation_id: Option<&str>,
    attesting_key_id: &str,
    root: &str,
    envelope: &serde_json::Value,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(id) = attestation_id else {
        return Ok(false);
    };
    let held = match directory.get_attestation(id).await {
        Ok(Some(h)) => h,
        Ok(None) | Err(Error::Unsupported { .. }) => return Ok(false),
        Err(e) => return Err(e),
    };
    if held.attesting_key_id != attesting_key_id || held.attested_key_id != root {
        return Ok(false);
    }
    let canonical = |v: &serde_json::Value| -> Result<serde_json::Value, Error> {
        let mut v = v.clone();
        super::canonical_at_rest::canonicalize_in_place(&mut v)?;
        Ok(v)
    };
    Ok(canonical(&held.attestation_envelope)? == canonical(envelope)?)
}

/// The witness plane's view of a ROOT this node holds a lineage for — a
/// trust-root community (its chain) or a conferring family (its record) —
/// in the one shape the attach gate and the trust surfaces read (PR #943
/// review: families are lineages too).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RootWitnessView {
    /// The served head when witnessed: digest and signer-stamped instant.
    pub witnessed_head: Option<(String, chrono::DateTime<chrono::Utc>)>,
    /// The head this node holds for the lineage, witnessed or not: the anchor
    /// an attach names while witnessed mode is off (#973).
    pub held_head: Option<(String, chrono::DateTime<chrono::Utc>)>,
    /// The charter's quorum; `0` = witnessed mode off (a silent charter, or
    /// one declaring zero — no default is substituted).
    pub quorum: u32,
    /// The community fold's detail (`None` for a family root).
    pub community: Option<WitnessedHead>,
    /// The latest instant a counting cosign was signed.
    pub latest_cosign_at: Option<chrono::DateTime<chrono::Utc>>,
    /// v53.0.0 (CC 3.2 T6, consequence (ii)) — the held head lags its roster:
    /// a roster row older than one `witness_cadence_secs` that no version
    /// covers (`lineage_head_lags_roster`). Reported whatever the witness
    /// quorum; with witnessed mode on, witnesses do not cosign it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roster_lag: Option<super::roster_head::RosterLag>,
}

/// See [`RootWitnessView`]. `None` when this node holds no lineage for `root`.
pub async fn root_witness_view<F>(
    directory: &F,
    root: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<RootWitnessView>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::lineage_witness::{effective_cosigns, principals_of, witnessed};
    let quorum = super::lineage_witness::declared_witness_quorum(
        charter_members_for(directory, root)
            .await?
            .and_then(|c| c.witness_quorum),
    );
    if let Some(signed) = lookup_signed_community(directory, root).await? {
        let chain = chain_of(&signed);
        let held_head = match chain.last() {
            Some(h) => Some((row_hash(&h.community)?, head_instant(h))),
            None => None,
        };
        let w = witnessed_head(directory, &chain, now).await?;
        let witnessed_head = match w.judged {
            Some(i) => Some((row_hash(&chain[i].community)?, head_instant(&chain[i]))),
            None => None,
        };
        let latest = w.latest_cosign_at;
        let roster_lag = super::roster_head::roster_lag(directory, root, now).await?;
        return Ok(Some(RootWitnessView {
            witnessed_head,
            held_head,
            quorum,
            community: Some(w),
            latest_cosign_at: latest,
            roster_lag,
        }));
    }
    let Some(fam) = directory.lookup_family(root).await? else {
        return Ok(None);
    };
    let cosigns = match directory.list_lineage_head_cosigns_for(root).await {
        Ok(c) => c,
        Err(Error::Unsupported { .. }) => Vec::new(),
        Err(e) => return Err(e),
    };
    let known = vec![(fam.persist_row_hash.clone(), fam.founded_at)];
    let effective = effective_cosigns(directory, &cosigns, &known).await?;
    let members: Vec<String> = fam.members.iter().map(|m| m.key_id.clone()).collect();
    let founder_principals = principals_of(directory, &members).await?;
    let witnessed_head = witnessed(
        &effective,
        &fam.persist_row_hash,
        &founder_principals,
        quorum,
    )
    .then(|| (fam.persist_row_hash.clone(), fam.founded_at));
    Ok(Some(RootWitnessView {
        witnessed_head,
        held_head: Some((fam.persist_row_hash.clone(), fam.founded_at)),
        quorum,
        community: None,
        latest_cosign_at: effective.iter().map(|c| c.signed_at).max(),
        roster_lag: super::roster_head::roster_lag(directory, root, now).await?,
    }))
}

/// #973 (CC 3.2 T4a) — **the head a NEW acceptance edge must name** for
/// `root`, as this node sees it now: the witnessed head while witnessed mode
/// is on (`None` while the held head is not yet witnessed — nothing is
/// attachable), the held head as the out-of-band anchor while it is off.
/// `None` also when this node holds no lineage for `root` (a key root: the
/// gate does not apply and no head is named). A host building an acceptance
/// edge writes the returned digest as `attached_head_digest`.
pub async fn attach_head_for<F>(
    directory: &F,
    root: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(view) = root_witness_view(directory, root, now).await? else {
        return Ok(None);
    };
    let head = if super::lineage_witness::witnessed_mode_on(view.quorum) {
        view.witnessed_head
    } else {
        view.held_head
    };
    Ok(head.map(|(digest, _)| digest))
}

/// #973 (CC 3.2 T3 / T4a) — **the signed envelope of a NEW acceptance edge**
/// toward `root`, as a host emits it: the job label, the scope the node
/// accepts the root for, and the head it attaches on.
///
/// ```json
/// { "dimension": "trust:accepts:v1",
///   "scope": ["infra:attest", "infra:serve"],
///   "attached_head_digest": "<64 hex>" }
/// ```
///
/// `attached_head_digest` is [`attach_head_for`]'s answer and is omitted for a
/// key root (no lineage held: the attach gate does not apply). The host adds
/// its own `references_attestation_id` if it uses one and emits the row as a
/// `delegates_to` with `attested_key_id = root`. Since #973 a `delegates_to`
/// toward a root WITHOUT the label gives no acceptance, and a labelled one
/// without the head is refused `trust_root_head_unnamed`.
///
/// # Errors
///
/// A directory read failure. `Ok` with no head while a witnessed lineage has
/// no witnessed head yet: the edge is then refused at the write door, which is
/// the honest answer (nothing is attachable).
pub async fn acceptance_edge_envelope<F>(
    directory: &F,
    root: &str,
    scope: &[&str],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<serde_json::Value, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut envelope = serde_json::json!({
        "dimension": super::trust_root::TRUST_ACCEPTS_DIMENSION,
        "scope": scope,
    });
    if let Some(head) = attach_head_for(directory, root, now).await? {
        envelope[super::envelope::paths::ATTACHED_HEAD_DIGEST] = serde_json::Value::String(head);
    }
    Ok(envelope)
}

/// v51.0.0 (CIRISPersist#938) — the witness plane's view of a held trust-root
/// lineage, for the trust surfaces (`resolve_community`, the bundle response):
/// the judged index, the unwitnessed tail, any equivocation, and `silent_since`
/// — the latest cosign older than the charter's cadence (a liveness signal,
/// never a validity leg).
pub async fn lineage_witness_view<F>(
    directory: &F,
    community_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<WitnessedHead>, Error>
where
    F: FederationDirectory + ?Sized,
{
    // PR #943 review — ONE path: the community arm of [`root_witness_view`],
    // the same fold the attach gate and the bundle surface read.
    Ok(root_witness_view(directory, community_key_id, now)
        .await?
        .and_then(|v| v.community))
}

/// `Some(accord family id)` when `community_key_id` is a ROOTED trust-root
/// community — the community arm of
/// [`trust_root_valid`](super::trust_root::trust_root_valid).
///
/// # Errors
///
/// Directory read failures.
pub async fn rooted_community_family<F>(
    directory: &F,
    community_key_id: &str,
) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    // v51.0.0 (CC 3.2 T7; PR #943 review): a STALLED root is valid but
    // non-admitting — T4 holds, nothing detaches. Its chain still verifies
    // from an accord birth; liveness gates new admissions, never validity.
    Ok(match stored_standing(directory, community_key_id).await {
        Ok(StoredStanding::Rooted(_) | StoredStanding::Stalled { .. }) => {
            Some(accord_family_key_id().to_owned())
        }
        Ok(_) | Err(Error::Unsupported { .. }) => None,
        Err(e) => return Err(e),
    })
}

/// Is the row stored at this id a rooted trust-root community?
///
/// # Errors
///
/// Directory read failures.
pub async fn is_rooted<F>(directory: &F, community_key_id: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(rooted_community_family(directory, community_key_id)
        .await?
        .is_some())
}

/// The immutables of an amendment (CC 3.2): the offered version is still
/// trust-root grade and conformant, and its entrenched protocol is the
/// prior's. The founder set is NOT frozen: founder seats move through the
/// record (a founders' amendment whose envelope binds the new roles), and only
/// there.
fn check_amendment_immutables(prior: &Community, new: &Community) -> Result<(), Error> {
    let id = new.community_key_id.as_str();
    if !is_trust_root_grade(new) {
        return Err(violation(
            id,
            super::admission::INFRA_RULE_GRADE_CHANGED,
            "an amendment cannot drop a trust-root community's infrastructure_constraint",
        ));
    }
    check_trust_root_shape(new)?;
    if new.consensus_protocol != prior.consensus_protocol {
        return Err(violation(
            id,
            super::admission::INFRA_RULE_GRADE_CHANGED,
            format!(
                "consensus_protocol is entrenched: {:?} cannot become {:?}",
                prior.consensus_protocol, new.consensus_protocol
            ),
        ));
    }
    Ok(())
}

fn needs_founders_quorum(id: &str) -> Error {
    violation(
        id,
        super::admission::TRUST_ROOT_RULE_CHAIN,
        "after its accord birth a trust-root community changes only by its founders' quorum \
         (a supersede_proof over the founder seats)",
    )
}

fn check_lineage_caps(signed: &SignedCommunity) -> Result<(), Error> {
    if signed.lineage.len() >= MAX_LINEAGE_LEN {
        return Err(violation(
            &signed.community.community_key_id,
            super::admission::TRUST_ROOT_RULE_LINEAGE_CAP,
            format!(
                "a chain of {} versions exceeds the cap of {MAX_LINEAGE_LEN}",
                signed.lineage.len() + 1
            ),
        ));
    }
    let bytes = serde_json::to_vec(&signed.lineage)
        .map_err(|e| Error::Backend(format!("lineage serialize: {e}")))?
        .len();
    if bytes > MAX_LINEAGE_BYTES {
        return Err(Error::EnvelopeTooLarge {
            bytes,
            cap: MAX_LINEAGE_BYTES,
        });
    }
    Ok(())
}

/// **The trust-root door** — run by every backend's `put_community` after
/// the authority scrub (and every co-signature) verified and before any write.
/// `Ok(false)`: not a trust-root-grade row. `Ok(true)`: an authorized
/// infrastructure community — the caller skips the non-infrastructure
/// steward-binding precondition (a serve node is a member of the trust root
/// without a steward, CC 3.2).
///
/// The offered row travels with its CHAIN ([`SignedCommunity::lineage`]),
/// capped at [`MAX_LINEAGE_LEN`] versions and [`MAX_LINEAGE_BYTES`] before any
/// signature is checked:
/// - nothing rooted at the id (absent, or a row that never passed this door):
///   the WHOLE chain must verify from an accord birth ([`verify_chain`]) — so a
///   fresh node admits an amended row, and never the latest version on its own
///   proof;
/// - a rooted row with identical content: the #758 no-op;
/// - a rooted row and a different version: the offered chain must EXTEND the
///   held version (it appears in the chain), and every link after it must
///   verify ([`verify_founders_link`]) — so a node that missed a version walks
///   from what it holds. The accord count is not re-demanded.
///
/// Either way the offered version's founders must all count now.
///
/// # Errors
///
/// The shape and founder refusals; [`Error::RosterAuthorityUnauthorized`]
/// (`roster_consensus_insufficient`) for a birth short of the accord quorum or
/// a link short of the founders'; [`Error::CommunityConsensusProtocolViolation`]
/// for a structural clause or a chain that does not extend the held version;
/// [`Error::EnvelopeTooLarge`] for a chain over the byte cap.
pub async fn check_trust_root_community_admission<F>(
    directory: &F,
    signed: &SignedCommunity,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let community = &signed.community;
    if !is_trust_root_grade(community) {
        return Ok(false);
    }
    check_lineage_caps(signed)?;
    check_trust_root_shape(community)?;
    let chain = chain_of(signed);
    // v51.0.0 (CIRISPersist#939, CC 3.2 T7) — the liveness margin at FOUNDING
    // is a property of the BIRTH version (the protocol is entrenched, N is the
    // founder count): judged on chain[0], so an amendment that tries to move
    // the protocol is still refused as the entrenchment violation it is.
    check_founding_margin(&chain[0].community)?;
    // The door's one clock read; everything below judges at it.
    let now = chrono::Utc::now();
    check_founders_eligible(directory, community, now).await?;
    let mut memo = Memo::at(now);
    let standing = stored_standing_at(directory, &community.community_key_id, now).await?;
    if let Some(held) = standing.held() {
        match extends(held, &chain)? {
            Extends::Same => return Ok(true),
            Extends::From(pos) => {
                let (walk, at) = walk_from_held(held, &chain, pos);
                verify_links_from(directory, &walk, at, &mut memo).await?;
            }
            Extends::No if is_rebirth_over_stalled(&standing, &chain) => {
                verify_chain_memo(directory, &chain, &mut memo).await?
            }
            Extends::No => return Err(does_not_extend(&community.community_key_id)),
        }
    } else {
        verify_chain_memo(directory, &chain, &mut memo).await?;
    }
    Ok(true)
}

/// v51.0.0 (CIRISPersist#939, CC 3.2 T7 rc6) — a trust-root-grade row is live
/// only at M + 1 active founders; founded at N ≤ M it is stalled from birth
/// (every remaining founder a veto). `liveness_margin_at_founding`.
fn check_founding_margin(birth: &Community) -> Result<(), Error> {
    let Some((m, _n)) = super::admission::infrastructure_quorum(&birth.consensus_protocol) else {
        return Ok(()); // the protocol gate names this refusal
    };
    let founders_n = founders(birth).len();
    if founders_n < m as usize + 1 {
        return Err(violation(
            &birth.community_key_id,
            super::admission::INFRA_RULE_LIVENESS_MARGIN_AT_FOUNDING,
            format!(
                "consensus_protocol {:?} over {founders_n} founder(s): a trust-root-grade community \
                 is live only at M + 1 = {} active founders (CC 3.2 T7 rc6, CIRISPersist#939); \
                 founded at N ≤ M it is stalled from birth",
                birth.consensus_protocol,
                m + 1
            ),
        ));
    }
    Ok(())
}

/// The recovery ruling (#926 re-check): an accord RE-BIRTH replaces a
/// STALLED row — one whose recorded founders can no longer reach their
/// quorum (withdrawn or rotated conferrals, resignations) — when the offered
/// chain starts at a birth founded LATER than the held chain's. It never
/// replaces a ROOTED row: the accord's lever over live founders is withdrawing
/// their conferrals, which stalls the row first. (The chain itself is still
/// verified in full — the birth's accord quorum included.)
fn is_rebirth_over_stalled(standing: &StoredStanding, chain: &[SignedCommunity]) -> bool {
    let StoredStanding::Stalled { held, .. } = standing else {
        return false;
    };
    let held_birth = held
        .lineage
        .first()
        .map_or(held.community.founded_at, |b| b.community.founded_at);
    chain
        .first()
        .is_some_and(|b| b.supersede_proof.is_none() && b.community.founded_at > held_birth)
}

/// The trust-root door as each community door runs it (CIRISPersist#931 /
/// #926): the same predicate on the LOCAL door (`put_community`) and the
/// REPLICATED entry (`apply_replicated_community`). The one difference is the
/// ruled legacy allowance: on the replicated entry, a record at ANOTHER id
/// that declares `infrastructure_constraint` but does not verify is kept as
/// data (`Ok(false)`: not an authorized infrastructure room — it reads
/// `NotRooted`, is never served as a trust root and never a `trust:accepts`
/// subject). The reserved `ciris-canonical` id has no such allowance on
/// either door: nothing but a chain from an accord birth lands there.
///
/// # Errors
///
/// Every refusal of [`check_trust_root_community_admission`] on the local
/// door and for the reserved id; directory failures on both.
pub async fn check_trust_root_at_door<F>(
    directory: &F,
    signed: &SignedCommunity,
    replicated: bool,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    match check_trust_root_community_admission(directory, signed).await {
        Err(e)
            if replicated
                && signed.community.community_key_id != CIRIS_CANONICAL_COMMUNITY_KEY_ID
                && is_row_verdict(&e) =>
        {
            Ok(false)
        }
        other => other,
    }
}

/// How an offered chain relates to the version this node holds.
enum Extends {
    /// Nothing new: the offered chain IS the held chain, or its head has the
    /// held content (#758's no-op; a stale or equivocating copy of the held
    /// content never replaces it).
    Same,
    /// The offered chain extends the held version, which sits at this index.
    From(usize),
    /// Neither.
    No,
}

/// One version of a chain, as a node-independent identity: its content hash,
/// its authority and its founders' proof (`None` for a birth). The same
/// content reached by two different links (a re-seat back to an earlier
/// roster, or equivocation) is two different versions.
fn same_version(a: &SignedCommunity, b: &SignedCommunity) -> Result<bool, Error> {
    Ok(row_hash(&a.community)? == row_hash(&b.community)?
        && a.authority_key_id == b.authority_key_id
        && serde_json::to_value(&a.supersede_proof).ok()
            == serde_json::to_value(&b.supersede_proof).ok())
}

/// Does `chain` extend `held` (#926 round 10)? The held version is located by
/// POSITION, not by content: its index is `held.lineage.len()`, and the
/// offered chain up to and including that index must be the held chain,
/// version for version (`same_version`). Content alone repeats: a re-seat
/// back to the birth roster reproduces the birth's content, so a
/// first-occurrence match replayed old links after the held head, and a
/// last-occurrence match skipped the links that re-seated a founder.
fn extends(held: &SignedCommunity, chain: &[SignedCommunity]) -> Result<Extends, Error> {
    let held_chain = chain_of(held);
    let at = held_chain.len() - 1;
    let mut prefix_matches = chain.len() > at;
    if prefix_matches {
        for (h, o) in held_chain.iter().zip(chain) {
            if !same_version(h, o)? {
                prefix_matches = false;
                break;
            }
        }
    }
    if prefix_matches {
        return Ok(if chain.len() - 1 == at {
            Extends::Same
        } else {
            Extends::From(at)
        });
    }
    let offered_head = chain.last().map(|v| row_hash(&v.community)).transpose()?;
    if offered_head.as_deref() == Some(row_hash(&held.community)?.as_str()) {
        return Ok(Extends::Same);
    }
    Ok(Extends::No)
}

fn does_not_extend(id: &str) -> Error {
    violation(
        id,
        super::admission::TRUST_ROOT_RULE_CHAIN,
        "the offered chain does not extend the version this node holds (a re-birth or a fork \
         of a rooted trust root is refused)",
    )
}

/// The replicated occupied-id route for a trust-root row (called by
/// `route_occupied_community` after [`check_trust_root_community_admission`]
/// admitted it). The offered chain is applied VERSION BY VERSION from the
/// point this node's state allows, so every stored version is one a proof
/// names exactly and the version history stays whole:
/// - rooted held version in the chain: each later link, in order;
/// - a non-rooted row at the id (a squat): the whole chain from the birth,
///   the birth recorded as `accord_birth_replaces_unrooted`;
/// - nothing stored: `Ok(false)` — the caller inserts the offered row with its
///   lineage.
///
/// Every applied version is re-verified here (defence in depth; the door
/// judged the whole chain first).
///
/// # Errors
///
/// The chain refusals, and backend write failures.
pub async fn apply_trust_root_chain<F>(
    directory: &F,
    offered: &SignedCommunity,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(apply_trust_root_chain_counted(directory, offered)
        .await?
        .is_some())
}

/// The authorization label of an accord birth stored over an un-rooted row
/// (a squat) — its value is the replaced row's hash.
pub(crate) const BIRTH_REPLACES_UNROOTED: &str = "accord_birth_replaces_unrooted";
/// The authorization label of an accord re-birth stored over a stalled
/// chain — its value is the replaced row's hash.
pub(crate) const REBIRTH_REPLACES_STALLED: &str = "accord_rebirth_replaces_stalled";

/// [`apply_trust_root_chain`] reporting what it WROTE (PR #921 review, F3):
/// `None` — nothing stored, the caller inserts; `Some(0)` — the chain this
/// node holds is the offered one, nothing written; `Some(n)` — `n` versions
/// written. The replicated door's typed outcome is derived from this, not
/// from a read taken before the write.
pub(crate) async fn apply_trust_root_chain_counted<F>(
    directory: &F,
    offered: &SignedCommunity,
) -> Result<Option<usize>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut chain = chain_of(offered);
    let id = offered.community.community_key_id.as_str();
    let now = chrono::Utc::now();
    let mut memo = Memo::at(now);
    let standing = stored_standing_at(directory, id, now).await?;
    let (start, replaces) = match (&standing, standing.held()) {
        (StoredStanding::Absent, _) => return Ok(None),
        (_, Some(held)) => {
            let held_hash = row_hash(&held.community)?;
            match extends(held, &chain)? {
                Extends::Same => return Ok(Some(0)),
                Extends::From(pos) => {
                    // Walk, and store, from the chain this node holds.
                    let (walk, at) = walk_from_held(held, &chain, pos);
                    verify_links_from(directory, &walk, at, &mut memo).await?;
                    chain = walk;
                    (at + 1, None)
                }
                Extends::No if is_rebirth_over_stalled(&standing, &chain) => {
                    verify_chain_memo(directory, &chain, &mut memo).await?;
                    (0, Some((REBIRTH_REPLACES_STALLED, held_hash)))
                }
                Extends::No => return Err(does_not_extend(id)),
            }
        }
        (_, None) => {
            verify_chain_memo(directory, &chain, &mut memo).await?;
            let stored = directory
                .lookup_community(id)
                .await?
                .map(|c| c.persist_row_hash)
                .unwrap_or_default();
            (0, Some((BIRTH_REPLACES_UNROOTED, stored)))
        }
    };
    // v53.0.0 (CC 3.2 T6, consequence (i)) — the version this apply makes the
    // head must reflect the roster rows effective after its predecessor in the
    // chain and up to its own instant (CC 3.2 T8 (iii): a resignation never
    // reaches behind a link's instant — the predecessor answered for those).
    // A birth or a re-birth (it replaces a squat or a stalled chain) is a
    // first version and is not judged against the replaced lineage's rows.
    if replaces.is_none() && start < chain.len() {
        if let [.., before, head] = chain.as_slice() {
            super::roster_head::check_version_covers_fold_since(
                directory,
                super::roster_head::LineageRecord::Community(&head.community),
                Some(head_instant(before)),
                head_instant(head),
            )
            .await?;
        }
    }
    let mut written = 0;
    for i in start..chain.len() {
        let mut version = chain[i].clone();
        version.lineage = chain[..i].to_vec();
        let authorization = match (&version.supersede_proof, &replaces) {
            (None, Some((label, prior))) => serde_json::json!({ *label: prior }),
            (Some(p), _) => serde_json::json!({
                "change_envelope": p.change_envelope,
                "quorum_signatures": p.quorum_signatures,
            }),
            (None, None) => return Err(does_not_extend(id)),
        };
        let snapshot = serde_json::to_value(&version)
            .map_err(|e| Error::Backend(format!("trust-root chain snapshot serialize: {e}")))?;
        directory
            .supersede_group_row(
                super::cohort::Cohort::Community,
                snapshot,
                Some(authorization),
            )
            .await?;
        written += 1;
    }
    Ok(Some(written))
}

/// Whether the local quorum-gated supersede of `community_key_id` is judged by
/// the founders' link alone: the stored row is trust-root grade and its chain
/// holds (`Rooted` or `Stalled`). Anything else — no row, an ordinary room, a
/// `NotRooted` squat — keeps the generic folded-roster quorum.
///
/// # Errors
///
/// Directory read failures.
pub async fn founders_link_is_the_quorum<F>(
    directory: &F,
    community_key_id: &str,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(stored) = directory.lookup_community(community_key_id).await? else {
        return Ok(false);
    };
    if !is_trust_root_grade(&stored) {
        return Ok(false);
    }
    Ok(stored_standing(directory, community_key_id)
        .await?
        .held()
        .is_some())
}

/// The local supersede door's half (`supersede_community_signed`): for a
/// ROOTED trust-root row, the new version must be a verified founders' link of
/// the held one ([`verify_founders_link`]) whose founders all count now, and it
/// is returned carrying its CHAIN (the held version's lineage plus the held
/// version) so the stored row stays walkable. Nothing becomes trust-root grade
/// by supersede: a birth goes through `put_community` under the accord's
/// quorum.
///
/// # Errors
///
/// The link and founder refusals; [`Error::CommunityConsensusProtocolViolation`]
/// for a promotion into the grade.
pub async fn prepare_trust_root_supersede<F>(
    directory: &F,
    mut new: SignedCommunity,
    generic_quorum_skipped: bool,
) -> Result<SignedCommunity, Error>
where
    F: FederationDirectory + ?Sized,
{
    let id = new.community.community_key_id.clone();
    let now = chrono::Utc::now();
    let standing = stored_standing_at(directory, &id, now).await?;
    match standing.held() {
        Some(held) => {
            // v51.0.0 (CIRISPersist#938, T6 §3) — restore discipline: the
            // witness plane knows a head this node does not hold (a cosign
            // whose prior is OUR head) — a founder writing over it would fork
            // silently; fetch the witnessed head first.
            check_not_behind_witness_plane(directory, held).await?;
            verify_founders_link(directory, &chain_of(held), &new, now).await?;
            check_founders_eligible(directory, &new.community, now).await?;
            new.lineage = chain_of(held);
            check_lineage_caps(&new)?;
            Ok(new)
        }
        // The caller skipped the generic quorum because the chain held when
        // it looked; it no longer does. Nothing judged this version's quorum,
        // so it is refused rather than written (review TOCTOU).
        None if generic_quorum_skipped => Err(violation(
            &id,
            super::admission::TRUST_ROOT_RULE_CHAIN,
            "the trust root's chain stopped holding during the supersede; the founders' link \
             that stood in for the quorum no longer applies — retry",
        )),
        None if is_trust_root_grade(&new.community) => Err(violation(
            &id,
            super::admission::INFRA_RULE_GRADE_CHANGED,
            "a supersede cannot promote a community to trust-root grade — the accord's quorum \
             founds a trust root (put_community)",
        )),
        _ => Ok(new),
    }
}

/// v51.0.0 (CIRISPersist#938) — `lineage_head_behind_witness`: this node holds
/// a cosign for a head digest it does not hold, whose `prior` is a version it
/// holds — the witness plane is ahead of this node (a restore, a lag). A
/// founder extending from here would write a detectable non-descendant; the
/// door refuses until the witnessed head is fetched.
async fn check_not_behind_witness_plane<F>(
    directory: &F,
    held: &SignedCommunity,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let id = held.community.community_key_id.as_str();
    let cosigns = match directory.list_lineage_head_cosigns_for(id).await {
        Ok(c) => c,
        Err(Error::Unsupported { .. }) => return Ok(()),
        Err(e) => return Err(e),
    };
    // PR #943 review (I193b) — two chains: `held` is the judged (witnessed)
    // prefix the next amendment follows; the node may also STORE an
    // unwitnessed tail beyond it. A cosign shows the node is behind when it
    // names a head the node does not STORE whose prior is a stored version at
    // or after the judged one — never for cosigns on the node's own tail.
    let judged_len = chain_of(held).len();
    let stored = lookup_signed_community(directory, id).await?;
    let chain = chain_of(stored.as_ref().unwrap_or(held));
    let digests: Vec<String> = chain
        .iter()
        .map(|v| row_hash(&v.community))
        .collect::<Result<_, _>>()?;
    let anchors = &digests[judged_len.saturating_sub(1).min(digests.len())..];
    let head_digest = digests.last().cloned().unwrap_or_default();
    if let Some(c) = cosigns.iter().find(|c| {
        !digests.contains(&c.head_digest_sha256_hex)
            && c.prior_head_digest_sha256_hex
                .as_deref()
                .is_some_and(|p| anchors.iter().any(|a| a == p))
    }) {
        return Err(violation(
            id,
            super::admission::TRUST_ROOT_RULE_BEHIND_WITNESS,
            format!(
                "the witness plane holds a cosign by {} for head {} whose prior {} is a \
                 version this node holds (its head is {}): this node is behind the witnessed \
                 lineage (a restore or a lag) — fetch the witnessed head before extending \
                 (CC 3.2 T6 rc6, restore discipline)",
                c.witness_key_id,
                c.head_digest_sha256_hex,
                c.prior_head_digest_sha256_hex
                    .as_deref()
                    .unwrap_or_default(),
                head_digest
            ),
        ));
    }
    Ok(())
}

/// **The roster-plane guard** (CIRISPersist#926 re-check, HIGH-3 ruling), run
/// by [`check_community_roster_authority`](super::check_community_roster_authority)
/// — both room roster doors on every backend — for a trust-root community.
///
/// Founder seats of a trust-root community move ONLY through the record: a
/// founders' amendment whose envelope binds the new roles, walkable by a fresh
/// node from the chain alone. So the planes refuse ANY founder-seat change —
/// seating a founder, re-roling a recorded or folded founder, revoking one —
/// whoever signs it, the full founders' quorum included. A founder exits by a
/// founders' amendment, or by the accord withdrawing the conferral (which
/// already un-counts the key). The planes admit and remove MEMBERS only.
///
/// One exception, the consent floor (#926 re-check): a founder's OWN
/// revocation, signed by that founder alone, is admitted as a RESIGNATION. It
/// does not move the record: from its `effective_at` the founder stops
/// counting (and stops being a seat) in every link and in the row's standing,
/// so the row stalls until the other founders amend the seat out — or, if the
/// resignations make the quorum unreachable, until an accord re-birth. The
/// trade, stated: one founder can stall the root. Consent over availability.
///
/// # Errors
///
/// [`Error::CommunityConsensusProtocolViolation`] for any other founder-seat
/// change.
pub async fn check_trust_root_roster_change<F>(
    directory: &F,
    community: &Community,
    signers: &std::collections::BTreeSet<String>,
    incoming: &super::types::CommunityMember,
    is_revocation: bool,
    effective_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let founder = super::admission::MEMBER_ROLE_FOUNDER;
    let recorded = founders(community).contains(&incoming.key_id.as_str());
    let folded = super::effective_roster(directory, community)
        .await?
        .iter()
        .any(|m| m.key_id == incoming.key_id && m.role.as_deref() == Some(founder));
    let seats_founder = !is_revocation && incoming.role.as_deref() == Some(founder);
    let resignation = is_revocation
        && (recorded || folded)
        && signers.len() == 1
        && signers.contains(&incoming.key_id);
    if resignation {
        // Review MEDIUM-R (a): a resignation dated at or before the stored
        // head's instant would un-count a link the founder co-signed and
        // un-root the row on every node — the head's own link judges
        // resignations up to and INCLUDING its `amended_at`, so equality is
        // refused too. A founder resigns strictly after the head, never over
        // it.
        if let Some(head) = lookup_signed_community(directory, &community.community_key_id).await? {
            let instant = head_instant(&head);
            if effective_at <= instant {
                return Err(violation(
                    &community.community_key_id,
                    super::admission::TRUST_ROOT_RULE_RESIGNATION_BACKDATED,
                    format!(
                        "{:?}'s resignation is dated {effective_at}, not strictly after the \
                         head's instant {instant}: a resignation cannot reach back over a link",
                        incoming.key_id
                    ),
                ));
            }
        }
        return Ok(());
    }
    // v51.0.0 (CIRISPersist#939, CC 3.2 T7; PR #943 review) — a stalled root
    // is NON-ADMITTING: nothing new is conferred on it until the conferring
    // body restores the margin. A member leaving is not an admission.
    if !is_revocation && !(recorded || folded || seats_founder) {
        if let Some(head) = lookup_signed_community(directory, &community.community_key_id).await? {
            if !is_live(directory, &head, effective_at).await? {
                return Err(violation(
                    &community.community_key_id,
                    super::admission::TRUST_ROOT_RULE_STALLED_NON_ADMITTING,
                    format!(
                        "the trust root is stalled (active founders at or below M): valid but \
                         non-admitting (CC 3.2 T7) — {:?} is not admitted until the margin is \
                         restored",
                        incoming.key_id
                    ),
                ));
            }
        }
    }
    if recorded || folded || seats_founder {
        return Err(violation(
            &community.community_key_id,
            super::admission::TRUST_ROOT_RULE_FOUNDER_SEAT_ON_PLANE,
            format!(
                "founder seats of a trust-root community move only through the record (a \
                 founders' amendment); the roster planes admit and remove members only \
                 ({:?} {})",
                incoming.key_id,
                if is_revocation { "revoked" } else { "widened" }
            ),
        ));
    }
    Ok(())
}

/// CC 4.4.3.2.4 `resolve_community` — the live view a consumer pins: the
/// community's founders and members after the roster fold (widenings and
/// revocations applied), its subkind, protocol and entrenchment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedCommunity {
    /// The community id.
    pub community_key_id: String,
    /// The founders — the admission quorum basis. For a trust-root community,
    /// the RECORD's founders (every one of which counts now, or the row is not
    /// rooted and resolves to nothing).
    pub founders: Vec<String>,
    /// Every other active member key id (serve, store, replicate; no vote).
    pub members: Vec<String>,
    /// `policy_blob.cohort_subkind`, if declared.
    pub cohort_subkind: Option<String>,
    /// The community's `consensus_protocol`.
    pub consensus_protocol: String,
    /// `policy_blob.consensus_protocol_entrenched`.
    pub consensus_protocol_entrenched: bool,
    /// v51.0.0 (CIRISPersist#939, CC 3.2 T7) — for a trust-root community:
    /// live at ≥ M + 1 active founders; `false` = stalled (valid, non-admitting).
    /// `true` for an ordinary room.
    #[serde(default)]
    pub live: bool,
    /// v51.0.0 (CIRISPersist#938, T6) — the served head is a WITNESSED version
    /// (`false` for a lineage the witness plane has never cosigned, which is
    /// judged as before rc6, and for an ordinary room).
    #[serde(default)]
    pub witnessed: bool,
    /// v51.0.0 (#938) — versions this node holds past the witnessed head, held
    /// and not adopted.
    #[serde(default)]
    pub unwitnessed_tail: usize,
    /// v51.0.0 (#938) — the lineage is frozen at the last common ancestor of
    /// two witnessed heads; the evidence object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equivocation: Option<Equivocation>,
    /// v51.0.0 (#938 §3.2) — the latest cosign instant when it is older than
    /// the charter's `witness_cadence_secs`: SILENT, a liveness signal, never a
    /// validity leg.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_silent_since: Option<chrono::DateTime<chrono::Utc>>,
}

/// Resolve `community_key_id` from THIS node's state. `None` when no row is
/// stored — and, for a trust-root id, when the stored row is not rooted
/// ([`stored_standing`]): a squat resolves to nothing.
///
/// # Errors
///
/// Directory read failures.
pub async fn resolve_community<F>(
    directory: &F,
    community_key_id: &str,
) -> Result<Option<ResolvedCommunity>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(community) = directory.lookup_community(community_key_id).await? else {
        return Ok(None);
    };
    let trust_root = is_trust_root_grade(&community);
    let now = chrono::Utc::now();
    let mut rooted_head: Option<Community> = None;
    let mut live_now: Option<bool> = None;
    if trust_root {
        match stored_standing_at(directory, community_key_id, now).await? {
            StoredStanding::Rooted(signed) | StoredStanding::Stalled { held: signed, .. } => {
                live_now = Some(is_live(directory, &signed, now).await?);
                rooted_head = Some(signed.community.clone());
            }
            _ => return Ok(None),
        }
    }
    // v51.0.0 (#938) — a trust root resolves to its WITNESSED head (the
    // judged version), which may be an ancestor of the stored row.
    let community = rooted_head.unwrap_or(community);
    let witness = if trust_root {
        lineage_witness_view(directory, community_key_id, now).await?
    } else {
        None
    };
    let roster = super::effective_roster(directory, &community).await?;
    let recorded: Vec<String> = founders(&community)
        .into_iter()
        .map(str::to_owned)
        .collect();
    // A trust root's founders are the RECORD's (seats move only through it),
    // and `Rooted` already established that each one counts now — a
    // resignation older than the version that (re-)seated the key does not
    // apply (LOW-1). Reading them off the plane roster instead would re-apply
    // that old resignation against the member's original `joined_at`, so the
    // standing and the resolved founder set would disagree.
    let mut founders_out = if trust_root {
        recorded.clone()
    } else {
        Vec::new()
    };
    let mut members = Vec::new();
    for m in roster {
        if trust_root {
            if !recorded.contains(&m.key_id) {
                members.push(m.key_id);
            }
        } else if m.role.as_deref() == Some(super::admission::MEMBER_ROLE_FOUNDER) {
            founders_out.push(m.key_id);
        } else {
            members.push(m.key_id);
        }
    }
    Ok(Some(ResolvedCommunity {
        community_key_id: community.community_key_id.clone(),
        founders: founders_out,
        members,
        cohort_subkind: policy_str(&community, "cohort_subkind").map(str::to_owned),
        consensus_protocol: community.consensus_protocol.clone(),
        consensus_protocol_entrenched: declares_entrenched(&community),
        live: live_now.unwrap_or(true),
        witnessed: witness.as_ref().is_some_and(|w| w.judged.is_some()),
        unwitnessed_tail: witness.as_ref().map_or(0, |w| w.unwitnessed_tail),
        equivocation: witness.as_ref().and_then(|w| w.equivocation.clone()),
        witness_silent_since: match &witness {
            Some(w) => {
                let cadence = charter_members_for(directory, community_key_id)
                    .await?
                    .and_then(|c| c.witness_cadence_secs);
                // PR #943 review: checked conversion and arithmetic.
                let horizon = cadence
                    .and_then(|c| i64::try_from(c).ok())
                    .and_then(chrono::Duration::try_seconds);
                match (w.latest_cosign_at, horizon) {
                    (Some(at), Some(h)) if at.checked_add_signed(h).is_some_and(|t| now > t) => {
                        Some(at)
                    }
                    _ => None,
                }
            }
            None => None,
        },
    }))
}

/// This node's signed copy of one community row (authority signature,
/// co-signatures and supersede proof included): the backend's point read,
/// falling back to the signed since-plane on a directory that cannot answer it.
///
/// # Errors
///
/// Directory read failures.
pub async fn lookup_signed_community<F>(
    directory: &F,
    community_key_id: &str,
) -> Result<Option<SignedCommunity>, Error>
where
    F: FederationDirectory + ?Sized,
{
    match directory.lookup_signed_community(community_key_id).await {
        Err(Error::Unsupported { .. }) => {}
        other => return other,
    }
    const PAGE: u32 = 256;
    let mut cursor = None;
    loop {
        let page = directory
            .list_signed_communities_since(cursor.clone(), PAGE)
            .await?;
        if let Some(hit) = page
            .iter()
            .find(|s| s.community.community.community_key_id == community_key_id)
        {
            return Ok(Some(hit.community.clone()));
        }
        match page.last() {
            Some(last) if page.len() == PAGE as usize => cursor = Some(last.resume_pair()),
            _ => return Ok(None),
        }
    }
}

/// CC 5.3.4 — the body `GET /v1/trust-root/bundle` (alias `/v1/steward-key`)
/// serves: the GenesisBundle, byte-for-byte as carried, with the
/// `ciris-canonical` community row BESIDE it — never inside it — and the key
/// records the row names, so a consumer resolves `pinned_trust =
/// {community_key_id: ciris-canonical, family: humanity-accord}` from one
/// fetch ([`pin_trust_from_bundle_response`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRootBundleResponse {
    /// The GenesisBundle, unchanged.
    pub bundle: super::genesis::bundle::GenesisBundle,
    /// Hex SHA-256 [`authorization_digest`](super::genesis::bundle::authorization_digest)
    /// of the bundle — what its holder authorizations sign.
    pub authorization_digest: String,
    /// The accord family the bundle roots (`bundle.family_key_id`).
    pub charter_root_key_id: String,
    /// The signed ROOTED `ciris-canonical` row, or `None` when this node holds
    /// none (or holds one that is not rooted — see `community_withheld`).
    pub community: Option<SignedCommunity>,
    /// Why `community` is `None` although a row is stored at the id (a squat,
    /// a non-conformant row). `None` when a row is served or none is stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community_withheld: Option<String>,
    /// The key records of every member the row names (founders first), as
    /// this node stores them — what a consumer's door needs to admit the row.
    #[serde(default)]
    pub community_member_records: Vec<SignedKeyRecord>,
    /// The accord quorum evidence (proposal + participations) behind every
    /// steward withdrawal of a key the chain names (#926 re-check, MEDIUM-W):
    /// a consumer re-tallies it through the ordinary evidence door and so
    /// judges historical links against the SAME, signed withdrawal instant
    /// every other node uses — never its own sync time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steward_withdrawal_evidence: Vec<super::accord_carriage::AccordQuorumEvidence>,
}

/// Build the CC 5.3.4 response from this node's own state.
///
/// # Errors
///
/// Directory read failures; a bundle whose digest cannot be computed.
pub async fn trust_root_bundle_response<F>(
    directory: &F,
    bundle: &super::genesis::bundle::GenesisBundle,
) -> Result<TrustRootBundleResponse, Error>
where
    F: FederationDirectory + ?Sized,
{
    let digest = super::genesis::bundle::authorization_digest(bundle)?;
    let (community, community_withheld) =
        match stored_standing(directory, CIRIS_CANONICAL_COMMUNITY_KEY_ID).await? {
            StoredStanding::Rooted(signed) => (Some(*signed), None),
            StoredStanding::Absent => (None, None),
            StoredStanding::Stalled { reason, .. } | StoredStanding::NotRooted { reason } => {
                (None, Some(reason))
            }
        };
    let mut community_member_records = Vec::new();
    let mut steward_withdrawal_evidence = Vec::new();
    if let Some(signed) = &community {
        // Every key the CHAIN names — each version's members, authority and
        // proof signers, founders first — so a fresh consumer can verify every
        // historical link (founder key records are never deleted, so a key a
        // later version retired is still served).
        let mut ordered: Vec<String> = founders(&signed.community)
            .into_iter()
            .map(str::to_owned)
            .collect();
        for v in chain_of(signed) {
            let mut named: Vec<String> = v
                .community
                .members
                .iter()
                .map(|m| m.key_id.clone())
                .collect();
            named.push(v.authority_key_id.clone());
            named.extend(v.cosignatures.iter().map(|c| c.authority_key_id.clone()));
            if let Some(p) = &v.supersede_proof {
                named.extend(p.quorum_signatures.iter().map(|s| s.member_id.clone()));
            }
            for k in named {
                if !ordered.contains(&k) {
                    ordered.push(k);
                }
            }
        }
        let mut digests = std::collections::BTreeSet::new();
        for key_id in &ordered {
            if let Some(record) = directory.lookup_public_key(key_id).await? {
                community_member_records.push(SignedKeyRecord { record });
            }
            if let Some(w) = directory
                .lookup_role_withdrawal(identity_type::STEWARD, key_id)
                .await?
            {
                digests.insert(w.authority_decision_digest);
            }
        }
        // O(withdrawals) point reads — never a scan of accord history on an
        // unauthenticated GET (review LOW-3).
        let mut proposals = Vec::with_capacity(digests.len());
        for digest in &digests {
            if let Some(stored) = directory.get_accord_proposal(digest).await? {
                let at = stored.created_at;
                proposals.push((stored, at));
            }
        }
        if !proposals.is_empty() {
            steward_withdrawal_evidence = super::accord_carriage::assemble_evidence_page(
                directory.as_dyn_directory(),
                proposals,
            )
            .await?;
        }
    }
    Ok(TrustRootBundleResponse {
        bundle: bundle.clone(),
        authorization_digest: hex::encode(digest),
        charter_root_key_id: bundle.family_key_id.clone(),
        community,
        community_withheld,
        community_member_records,
        steward_withdrawal_evidence,
    })
}

/// What a consumer pinned from one [`TrustRootBundleResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedTrust {
    /// `pinned_trust.family` — the accord family whose quorum verified.
    pub family: String,
    /// How many distinct holders' bundle authorizations verified here.
    pub bundle_holders_verified: usize,
    /// The community as resolved on the consumer after admission.
    pub community: ResolvedCommunity,
}

/// The consumer half of CC 4.4 / 5.3.4: from ONE response, (1) verify the
/// bundle's holder quorum against THIS node's own roster (a short quorum is
/// refused — the #809 assertion, gated), (2) admit the key records the row
/// names through the ordinary key door, (3) admit the community row through
/// the ordinary community door, which re-runs the accord quorum
/// ([`check_trust_root_community_admission`]) against this node's own pins,
/// and (4) resolve it. Nothing in the response is trusted for being in the
/// response.
///
/// **Why the key records go in before the community.** The community door
/// judges each founder from THIS node's key records, so they must exist first.
/// Each record passes the key door on its own terms (a founder's accord
/// co-scrub is re-verified against this node's pins; a serve node's record is
/// a self-registration any caller may submit), so a response whose community
/// is then refused leaves behind only records this node would have admitted
/// from anyone — never a community, and never a conferral the accord did not
/// sign.
///
/// # Errors
///
/// [`Error::GenesisBundleInvalid`] for a bundle whose quorum does not verify;
/// [`Error::InvalidArgument`] when no `ciris-canonical` row travels beside it;
/// every refusal of the key and community doors.
pub async fn pin_trust_from_bundle_response<F>(
    directory: &F,
    response: &TrustRootBundleResponse,
) -> Result<PinnedTrust, Error>
where
    F: FederationDirectory + ?Sized,
{
    let proof = super::genesis::bundle::verify_bundle_quorum(directory, &response.bundle).await?;
    let bundle_holders_verified = proof.distinct_holders();
    let Some(signed) = response.community.clone() else {
        return Err(Error::InvalidArgument(format!(
            "trust-root response carries no {CIRIS_CANONICAL_COMMUNITY_KEY_ID:?} community row \
             beside the bundle — nothing to pin (CIRISPersist#926){}",
            response
                .community_withheld
                .as_deref()
                .map(|r| format!("; the server withheld it: {r}"))
                .unwrap_or_default()
        )));
    };
    if signed.community.community_key_id != CIRIS_CANONICAL_COMMUNITY_KEY_ID {
        return Err(Error::InvalidArgument(format!(
            "trust-root response carries community {:?}, not {CIRIS_CANONICAL_COMMUNITY_KEY_ID:?}",
            signed.community.community_key_id
        )));
    }
    for record in &response.community_member_records {
        if directory
            .lookup_public_key(&record.record.key_id)
            .await?
            .is_none()
        {
            directory.put_public_key(record.clone()).await?;
        }
    }
    admit_response_withdrawals(directory, response).await?;
    let id = signed.community.community_key_id.clone();
    directory.put_community(signed).await?;
    let community = resolve_community(directory, &id)
        .await?
        .ok_or_else(|| Error::Backend(format!("community {id:?} admitted but not rooted")))?;
    Ok(PinnedTrust {
        family: response.bundle.family_key_id.clone(),
        bundle_holders_verified,
        community,
    })
}

/// Admit the steward-withdrawal evidence a [`TrustRootBundleResponse`]
/// carries, through the ORDINARY accord evidence door (re-tallied against
/// THIS node's own accord roster), then re-derive this node's own steward
/// withdrawals for every key the response names. Evidence that does not
/// re-tally is refused by that door, not trusted for being in the response.
///
/// # Errors
///
/// The evidence door's refusals; directory failures.
// FOLD(#926-rotation): persist has no steward SUPERSEDE door today — a
// founder's retirement is a plain withdraw, so this projects plain withdrawals
// only. If a steward supersede door is ever added, project its
// (old → successor) pairs over the chain-named keys here too.
pub async fn admit_response_withdrawals<F>(
    directory: &F,
    response: &TrustRootBundleResponse,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    for evidence in &response.steward_withdrawal_evidence {
        directory.apply_replicated_accord_evidence(evidence).await?;
    }
    if response.steward_withdrawal_evidence.is_empty() {
        return Ok(());
    }
    let roster = super::admission::accord_holder_roster_key_ids();
    for r in &response.community_member_records {
        super::accord_carriage::project_role_withdrawal_for_key(
            directory.as_dyn_directory(),
            identity_type::STEWARD,
            &r.record.key_id,
            &roster,
        )
        .await?;
    }
    Ok(())
}
