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
//! the bundle quorum are untouched and stay the only ROOT authority; v62.0.0:
//! the bundle is the ingested `ceg-genesis-bundle/2`). It is an ordinary `community`
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

use super::edition2::fold::{self, Dep};
use super::types::{
    consensus_protocol as cp, identity_type, Community, KeyRecord, ScrubSig, SignedCommunity,
};
use super::{Error, FederationDirectory};
use serde::{Deserialize, Serialize};

/// v62.0.0 (wave GC8; CC 2.7.3) — declare what a trust-root fold reads
/// beyond the row: the founder's (or cosigner's) own key plane and the rows
/// about it (conferrals, occurrences, a genesis bundle placing it: a
/// bundle's re-fold touches its holders' keys, G0 v3 §2), and the accord
/// family's roster. No `family:` key (G0 v4 cost rule). A no-op outside a
/// fold attempt.
fn reads_founder(founder: &str) {
    fold::reads(Dep::key(founder));
    fold::reads(Dep::key(accord_family_key_id()));
}

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
        .and_then(|_| parse_quorum(&community.consensus_protocol))
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
    // v62.0.0 (wave W1) — the accord is the genesis bundle in force: a
    // holder of it is a seat of the accord (`edition2::trust_root_group`).
    if super::edition2::trust_root_group::is_bundle_holder(directory, key_id).await? {
        return Ok(true);
    }
    let Some(family) =
        super::trust_root::resolve_family_root(directory, accord_family_key_id()).await?
    else {
        return Ok(false);
    };
    match super::authorized_family_roster_at(directory, &family, at).await {
        Ok(seats) => Ok(seats.iter().any(|m| m.key_id == key_id)),
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
/// (`accord_holder_roster`, the ceremony plane every key-plane
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
    // v62.0.0 (wave GC8; CC 2.7.3) — a founder is a MEMBER the record
    // names, not the signer: every leg below reads other rows (the founder's
    // key record, its occurrences, the accord's roster and conferrals, the
    // genesis bundle). Each unmet leg is a fold condition: the row is held
    // with the leg's token and re-folds when one of those rows lands or is
    // withdrawn. Outside a fold attempt each is the refusal it was.
    reads_founder(founder);
    // v62.0.0 (wave W1) — a holder of the genesis bundle in force is a seated
    // holder (#972: nothing more is asked of one), read before its key
    // record: the bundle placed its key.
    if super::edition2::trust_root_group::is_bundle_holder(directory, founder).await? {
        return Ok(());
    }
    let Some(record) = directory.lookup_public_key(founder).await? else {
        return Err(fold::hold(
            fold::reason::gc8::FOUNDER_NOT_CONFERRED,
            violation(
                community_key_id,
                super::admission::INFRA_RULE_FOUNDER_NOT_CONFERRED,
                format!("founder {founder:?} has no key record on this node"),
            ),
        ));
    };
    let arm = founder_arm_at(directory, &record, now).await?.0;
    if arm == FounderArm::Holder {
        return Ok(());
    }
    if arm == FounderArm::Neither {
        return Err(fold::hold(
            fold::reason::gc8::NODE_BEARING_FOUNDER,
            violation(
                community_key_id,
                super::admission::INFRA_RULE_NODE_BEARING_FOUNDER,
                format!(
                    "founder {founder:?} is not a human key (identity_type {:?}, and not a \
                     current seat of the accord family): a node-bearing key MUST NOT be a \
                     founder of an infrastructure community (CIRISPersist#925)",
                    record.identity_type
                ),
            ),
        ));
    }
    if !super::admission::has_accord_conferred_role_over_roster(
        directory,
        founder,
        identity_type::STEWARD,
        &super::admission::accord_holder_roster(directory).await?,
    )
    .await?
    {
        return Err(fold::hold(
            fold::reason::gc8::ROLE_NOT_ACCORD_CONFERRED,
            Error::RoleNotAccordConferred {
                role: identity_type::STEWARD.to_owned(),
                key_id: founder.to_owned(),
                scrub_key_id: record.scrub_key_id.clone(),
                reason: format!(
                    "a founder of trust-root community {community_key_id:?} must be an \
                     accord-conferred steward key (CC 3.2 T2)"
                ),
            },
        ));
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
    accord_quorum_at(directory, signed, &mut Memo::at(crate::host::clock::now())).await
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
    // v62.0.0 (wave W1; CC 3.2 citing CC 2.7.5, CC 2.6.1.11) — an edition-2 birth: its
    // voices are the held `group:roster` statements of the version (and the
    // vouched ones at its door), counted against a strict majority of the
    // holders of the genesis bundle in force.
    if let Some(signers) =
        super::edition2::trust_root_group::version_signers(directory, &signed.community).await?
    {
        return super::edition2::trust_root_group::bundle_quorum_over(directory, &signers).await;
    }
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
        Err(e) => return Err(e),
    }
    match directory
        .list_family_membership_revocations_for(family_key_id)
        .await
    {
        Ok(rs) => out.extend(rs.into_iter().map(|r| r.effective_at)),
        Err(e) => return Err(e),
    }
    Ok(out)
}

fn insufficient(signed: &SignedCommunity) -> Error {
    // v62.0.0 (wave W1) — at an edition-2 door the voices so far are short:
    // the voice is kept and the version waits for the next one (a no-op
    // outside a vouch).
    super::edition2::group::note_short();
    Error::RosterAuthorityUnauthorized {
        group_key_id: signed.community.community_key_id.clone(),
        offered_authority_key_id: signed.authority_key_id.clone(),
        rule: super::ROSTER_CONSENSUS_INSUFFICIENT,
        // The accord's charter quorum counts holders, not this record's
        // ballot.
        shortfall: None,
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
    // CC 2.6.2: the signed instant is `.sssZ` (v61 S3).
    change_envelope[AMENDED_AT] =
        serde_json::Value::String(super::admission::render_signed_instant(amended_at));
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
                    &super::admission::accord_holder_roster(directory).await?,
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
                // No stored community yet (a birth being judged): no
                // resignations to fold. v62.0.0 (PX-fix3) — a directory that
                // cannot answer (`Unsupported`) propagates (I2190).
                Err(Error::InvalidArgument(_)) => {}
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
        let stored = directory
            .get_accord_proposal(&w.authority_decision_digest)
            .await?;
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
        let when = at.unwrap_or(self.now);
        // v62.0.0 (wave W1) — a holder of the genesis bundle in force is the
        // holder arm, whatever this node's key-record read model holds.
        let (arm, next_edge) =
            if super::edition2::trust_root_group::is_bundle_holder(directory, key_id).await? {
                (FounderArm::Holder, None)
            } else {
                let Some(rec) = self.record(directory, key_id).await? else {
                    return Ok(false);
                };
                founder_arm_at(directory, &rec, when).await?
            };
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
    // v62.0.0 (BH-fix1; RULINGS "composite signatures only") — the earlier
    // form counted `proof.quorum_signatures`, each a separate Ed25519 +
    // ML-DSA-65 pair verified against the founder's component halves. That
    // verify is DELETED: a link's signers are its edition-2 voices only.
    let mut signers = std::collections::BTreeSet::new();
    // v62.0.0 (wave W1) — an edition-2 version carries no quorum signatures:
    // its voices are the held `group:roster` statements of the version (and
    // the vouched ones at its door), each verified at the edition-2 door.
    // A voice counts when it is a prior founder that counts at the link's
    // instant.
    let edition2_voices =
        super::edition2::trust_root_group::version_signers(directory, &next.community).await?;
    if let Some(voices) = &edition2_voices {
        for v in voices {
            if !prior_founders.contains(&v.as_str())
                || signers.contains(v)
                || !memo
                    .founder_counts(directory, id, v, Some(amended_at), seated_since(chain, v))
                    .await?
            {
                continue;
            }
            signers.insert(v.clone());
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
        subject: None,
        // The trust root's chain keeps the per-key count (CIRISPersist#1198).
        persons: super::key_person::PersonsAt::each_key(),
        high_water: None,
    });
    if !verdict.admits() {
        // v62.0.0 (wave W1) — short at an edition-2 door: the voice waits.
        super::edition2::group::note_short();
        return Err(Error::RosterAuthorityUnauthorized {
            group_key_id: id.to_owned(),
            offered_authority_key_id: next.authority_key_id.clone(),
            rule: super::ROSTER_CONSENSUS_INSUFFICIENT,
            shortfall: verdict.shortfall().cloned(),
        });
    }
    // v62.0.0 (wave W1) — an edition-2 version has no single authority: its
    // signature columns name its first voice in key order, which may be a
    // voice that is not counted (a seat the version adds). The count above
    // is its whole authorization.
    if edition2_voices.is_none() && !signers.contains(&next.authority_key_id) {
        return Err(violation(
            id,
            super::admission::TRUST_ROOT_RULE_CHAIN,
            format!(
                "the version's authority {:?} is not one of the founders its proof counted",
                next.authority_key_id
            ),
        ));
    }
    // v62.0.0 (wave W1) — an edition-2 version's authority is one of its
    // voices, verified at the edition-2 door (above: it is a counted
    // signer); its signature columns hold the composite markers, which the
    // earlier verifier reads only under the door's vouch. A re-judge outside
    // the door reads the voices instead.
    if edition2_voices.is_none() {
        super::verify_community_admission(directory, next).await?;
    }
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
        // v62.0.0 (wave GC8) — the birth founder's eligibility reads other
        // rows (as `check_founder_eligible`): a fold condition.
        reads_founder(f);
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
            return Err(fold::hold(
                fold::reason::gc8::FOUNDER_NOT_CONFERRED,
                violation(
                    id,
                    super::admission::INFRA_RULE_FOUNDER_NOT_CONFERRED,
                    format!("the birth's founder {f:?} was not an eligible founder at the birth"),
                ),
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
            | Error::MalformedRow { .. }
            | Error::RosterAuthorityUnauthorized { .. }
            | Error::RoleNotAccordConferred { .. }
            | Error::FederationTierUnverified { .. }
            // v54.1.0 (#1042) — was `FederationTierUnverified` before the
            // ordering gap got its own variant; still a verdict on the row.
            | Error::AttesterKeyUnknown { .. }
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
    // v62.0.0 (wave W1) — the edition-2 inputs: the holders of the genesis
    // bundle in force (the holder arm and the birth's count) and the held
    // `group:roster` voices of the community (a version's signers).
    let bundle_holders = super::edition2::trust_root_group::bundle_holder_refs(directory).await?;
    feed("bundle_holders", &serde_json::json!(bundle_holders));
    let roster_voices: Vec<String> = super::edition2::trust_root_group::roster_statements(
        directory,
        &signed.community.community_key_id,
    )
    .await?
    .iter()
    .map(hex::encode)
    .collect();
    feed("edition2_roster_voices", &serde_json::json!(roster_voices));
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
        super::admission::accord_holder_roster(directory)
            .await?
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
                Ok(None) => serde_json::json!("no-proposal"),
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
        Err(Error::InvalidArgument(_)) => Vec::new(),
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
    super::optional_capability::unsupported_is_none(read, "canonical_community::answered")
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
    stored_standing_at(directory, community_key_id, crate::host::clock::now()).await
}

/// v62.0.0 (wave W1b; CC 3.2 T3, CC 4.4.3.34, CC 2.6.1.12) — **the READ
/// verdict** at a trust-root id, at `now`:
///
/// - an **edition-2 trust root** (its stored version has edition-2
///   `group:roster` voices, [`super::edition2::trust_root_group::version_signers`]):
///   the chain verdict ([`chain_standing_at`]) AND this node's own T3 chain,
///   the node being its own seed ([`super::trust_root::own_chain_to`]): a live
///   `trust:accepts:v1` edge from the node (or its owner) to the root, and
///   the root's live `trust:charter:v1` self-edge carrying a well-formed
///   pre-rotation commitment. A chain that holds without them is
///   `NotRooted`, by name;
/// - an **earlier-form** chain: read only while the earlier-form doors are
///   open ([`super::edition2::door::earlier_form_doors_shut`]); shut, it is
///   `NotRooted` ("nothing carries", CC 2.6.1.12).
///
/// The doors (admission, chain apply, supersede) read the chain verdict
/// alone: what a version extends is a property of the chain, not of whether
/// this node accepts the root.
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
    let node = directory.node_key_id();
    stored_standing_for(directory, node.as_deref(), community_key_id, now).await
}

/// v62.0.0 (PR-fix1; CC 3.2 T3, T8) — [`stored_standing_at`] judged FOR the
/// reader node `reader` (its owner's acceptance edges, CC 3.2 T3) rather than
/// for this directory's node key: the one body both read, so a peer verdict
/// for a named reader and this node's own read never disagree. `reader =
/// None`: nothing is accepted.
///
/// # Errors
///
/// Directory read failures.
pub async fn stored_standing_for<F>(
    directory: &F,
    reader: Option<&str>,
    community_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<StoredStanding, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(reader_standing(directory, reader, community_key_id, now)
        .await?
        .0)
}

/// [`stored_standing_for`], with the T3 legs it read (`None` where it read
/// none: no row, a chain that does not hold, or an earlier-form chain) so a
/// caller can name why a `NotRooted` is not rooted.
///
/// # Errors
///
/// Directory read failures.
pub(crate) async fn reader_standing<F>(
    directory: &F,
    reader: Option<&str>,
    community_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(StoredStanding, Option<super::trust_root::ChainLegs>), Error>
where
    F: FederationDirectory + ?Sized,
{
    let chain = chain_standing_at(directory, community_key_id, now).await?;
    let held = match &chain {
        StoredStanding::Rooted(h) | StoredStanding::Stalled { held: h, .. } => h.clone(),
        StoredStanding::Absent | StoredStanding::NotRooted { .. } => return Ok((chain, None)),
    };
    let edition2 = super::edition2::trust_root_group::version_signers(directory, &held.community)
        .await?
        .is_some();
    if !edition2 {
        if super::edition2::door::earlier_form_doors_shut() {
            return Ok((
                StoredStanding::NotRooted {
                    reason: "an earlier-form trust-root chain: the earlier form is shut at this \
                             node's doors (CC 2.6.1.12)"
                        .into(),
                },
                None,
            ));
        }
        return Ok((chain, None));
    }
    let legs = super::trust_root::chain_legs_of(directory, reader, community_key_id, now).await?;
    let own = legs.own_chain();
    if !own.accepted {
        return Ok((
            StoredStanding::NotRooted {
                reason: "this node holds no live trust:accepts:v1 edge to the root (CC 3.2 T3: \
                         the evaluating node's own chain)"
                    .into(),
            },
            Some(legs),
        ));
    }
    if !own.chartered {
        return Ok((
            StoredStanding::NotRooted {
                reason: "the root holds no live trust:charter:v1 self-edge carrying a \
                         pre-rotation commitment (CC 3.2 T3)"
                    .into(),
            },
            Some(legs),
        ));
    }
    Ok((chain, Some(legs)))
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
pub async fn chain_standing_at<F>(
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
        emitter_key_id: String::new(),
    };
    match super::hard_case::record_observation(directory, event).await {
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
    let mut memo = Memo::at(now);
    let (active, m, _) = active_founders(directory, signed, &mut memo).await?;
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
    // v62.0.0 (wave GC8; G0 v3 §4) — a READ: the chain's verdict becomes
    // "not rooted", so the gates' fold marks are discarded (their reads kept).
    match fold::unmarked(verify_chain_memo(directory, &chain, &mut memo)).await {
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
    // v62.0.0 (TR-fix1; CC rc21 3.2 T7 l.1232, T8 l.1257) — Stalled is the
    // MARGIN, never "a recorded founder stopped counting": live while the
    // active founder set holds at least M + 1 (M the absolute first number
    // of `quorum:M/N`), stalled at M or fewer. Rooted and Stalled are both
    // valid; Stalled is non-admitting only for the founders' count (T7).
    let (active, m, not_counting) = active_founders(directory, &signed, &mut memo).await?;
    if active >= m.saturating_add(1) {
        return Ok((StoredStanding::Rooted(Box::new(signed)), memo.valid_until));
    }
    let reason = format!(
        "{active} active founder(s) at {:?}: live needs M + 1 = {} (CC 3.2 T7); not counting \
         now: {not_counting:?}. Valid but non-admitting: the recovery widening restores it",
        signed.community.consensus_protocol,
        m.saturating_add(1)
    );
    Ok((
        StoredStanding::Stalled {
            held: Box::new(signed),
            reason,
        },
        memo.valid_until,
    ))
}

/// v62.0.0 (TR-fix1; CC rc21 3.2 T7) — **the active founder set**, the ONE
/// count behind [`compute_standing`] and [`founder_liveness`]: `(active, M,
/// the recorded founders that do not count)`. A founder counts at the memo's
/// instant per `Memo::founder_counts` (seated, not resigned or withdrawn
/// since, its key not past `revoked_after`, not node-bearing, accord-
/// conferred). `M` is `quorum:M/N`'s absolute first number; a protocol that
/// does not parse reads `usize::MAX` (never live).
async fn active_founders<F>(
    directory: &F,
    signed: &SignedCommunity,
    memo: &mut Memo,
) -> Result<(usize, usize, Vec<String>), Error>
where
    F: FederationDirectory + ?Sized,
{
    let m = super::admission::infrastructure_quorum(&signed.community.consensus_protocol)
        .map(|(m, _)| m as usize)
        .unwrap_or(usize::MAX);
    let chain = chain_of(signed);
    let mut active = 0;
    let mut not_counting = Vec::new();
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
        } else {
            not_counting.push(f.to_owned());
        }
    }
    Ok((active, m, not_counting))
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
    Ok(live_charter_rows(directory, family)
        .await?
        .into_iter()
        .find(|a| a.persist_row_hash == digest))
}

/// v53.1.2 (CIRISPersist#984 rows 5 and 18) — **every live charter row of
/// `family`**: the predicate [`live_charter_row`] picks from, and the set
/// [`charter_members_for`] reads the head's charter out of. One filter —
/// charter-labelled `delegates_to` toward the family, direction standing,
/// not retired — so a withdrawn charter is a charter to no reader.
///
/// # Errors
///
/// Directory read failures.
pub async fn live_charter_rows<F>(
    directory: &F,
    family: &str,
) -> Result<Vec<super::Attestation>, Error>
where
    F: FederationDirectory + ?Sized,
{
    live_or_held_charter_rows(directory, family, true).await
}

/// v62.0.0 (slice E2a; CC 4.2.6; Verify's `accord_recovery_refusals_v2`
/// `charter_missing`) — **is a charter row carrying `digest` HELD here at
/// all**, live or withdrawn? A charter the lineage adopts and this node does
/// not hold is a gap, and the commitment walk fails closed across it
/// (`accord_recovery_lineage_incomplete`). A held, withdrawn charter names
/// nothing (#984 row 5).
///
/// # Errors
///
/// Directory read failures.
pub async fn charter_row_held<F>(directory: &F, family: &str, digest: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(!digest.is_empty()
        && live_or_held_charter_rows(directory, family, false)
            .await?
            .iter()
            .any(|a| a.persist_row_hash == digest))
}

async fn live_or_held_charter_rows<F>(
    directory: &F,
    family: &str,
    live_only: bool,
) -> Result<Vec<super::Attestation>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let is_charter = |a: &super::Attestation| {
        a.attestation_type == super::types::attestation_type::DELEGATES_TO
            && a.attested_key_id == family
            && super::trust_root::job_dimension_admits(
                &a.attestation_envelope,
                super::trust_root::TRUST_CHARTER_DIMENSION,
            )
    };
    // v53.1.7 — the charter-shaped rows and their composers, never every
    // trust edge naming the family.
    let mut charters = Vec::new();
    let mut pages =
        super::attestation_query::AttestationQuery::to(family, super::attestation_query::FOLD_PAGE)
            .types(&[super::types::attestation_type::DELEGATES_TO])
            .excluding_dimensions(&super::trust_root::jobs_other_than(
                super::trust_root::TRUST_CHARTER_DIMENSION,
            ))
            .pages();
    while let Some(page) = pages.next(directory).await? {
        charters.extend(page);
    }
    if !live_only {
        return Ok(charters.into_iter().filter(|a| is_charter(a)).collect());
    }
    let rows =
        super::trust_root::with_slice_composers(directory, charters, Some(family), None).await?;
    let refs: Vec<&super::Attestation> = rows.iter().collect();
    let retired = super::precedence::retired_ids(&refs);
    let denied =
        super::trust_root::direction_denied_ids(directory, rows.iter().filter(|a| is_charter(a)))
            .await?;
    Ok(rows
        .into_iter()
        .filter(|a| {
            is_charter(a)
                && !denied.contains(&a.attestation_id)
                && !retired.contains(&a.attestation_id)
        })
        .collect())
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
    // The charter names its lineage as its ATTESTED key (a key root charters
    // itself; the accord's holders charter their family). v53.1.2 (#984 row
    // 18) — the LIVE rows (direction standing, not retired: the one filter
    // `live_charter_rows` is), then those the head admits.
    let in_force = |owner: String, head: HeadCharter| async move {
        let mut rows = live_charter_rows(directory, &owner).await?;
        rows.retain(|a| head.admits(a));
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
    let cosigns = directory.list_lineage_head_cosigns_for(id).await?;
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
        emitter_key_id: String::new(),
    };
    match super::hard_case::record_observation(directory, event).await {
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
    // v62.0.0 (C5-fix1): the pinned bundle is deleted, so no row is exempt.
    if super::trust_root::names_no_trust_job(envelope) {
        return Ok(());
    }
    let root = attested_key_id;
    // v62.0.0 (wave GC8; CC 2.7.3) — freshness reads the root's lineage
    // (its held head, its witness cosigns, its charter's window), which are
    // other rows: an edge that is not fresh against them is HELD with
    // `trust_root_head_stale` and re-folds when the root's rows change. The
    // edge naming no head at all (`TrustRootHeadUnnamed`) is the row's own
    // bytes and stays a refusal.
    fold::reads(Dep::key(root));
    let refuse = |detail: String| {
        Err(fold::hold(
            fold::reason::gc8::TRUST_ROOT_HEAD_STALE,
            Error::TrustRootHeadStale {
                root_key_id: root.to_owned(),
                detail,
            },
        ))
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
        Ok(None) => return Ok(false),
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
    let cosigns = directory.list_lineage_head_cosigns_for(root).await?;
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

/// `Some(accord family id)` when `community_key_id` is a ROOTED earlier-form
/// trust-root community; `Some(community_key_id)` itself for a ROOTED
/// edition-2 trust root (W1b: it is its own root) — the community arm of
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
    rooted_community_family_at(directory, community_key_id, crate::host::clock::now()).await
}

/// v62.0.0 (TR-fix1; CC 3.2 T8) — [`rooted_community_family`] judged at the
/// caller's signer-stamped instant `now` (the standing verdict reads no
/// clock).
///
/// # Errors
///
/// Directory read failures.
pub async fn rooted_community_family_at<F>(
    directory: &F,
    community_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    // v62.0.0 (wave W1b; CC 3.2 T3) — an EDITION-2 trust root is its own
    // root: its legs (the user's acceptance edge, its own charter self-edge)
    // are read at its own id, never at the accord family's name. Its CHAIN
    // verdict decides the arm; the user's edge leg is the caller's to read
    // (`trust_root_valid` asks it for ITS user, not for this node).
    if let Some(held) = directory.lookup_community(community_key_id).await? {
        if super::edition2::trust_root_group::version_signers(directory, &held)
            .await?
            .is_some()
        {
            return Ok(
                match chain_standing_at(directory, community_key_id, now).await? {
                    StoredStanding::Rooted(_) | StoredStanding::Stalled { .. } => {
                        Some(community_key_id.to_owned())
                    }
                    StoredStanding::Absent | StoredStanding::NotRooted { .. } => None,
                },
            );
        }
    }
    // v51.0.0 (CC 3.2 T7; PR #943 review): a STALLED root is valid but
    // non-admitting — T4 holds, nothing detaches. Its chain still verifies
    // from an accord birth; liveness gates new admissions, never validity.
    // v62.0.0 (wave W1b) — an earlier-form chain is read through
    // `stored_standing`, so only while the earlier-form doors are open.
    Ok(match stored_standing(directory, community_key_id).await {
        Ok(StoredStanding::Rooted(_) | StoredStanding::Stalled { .. }) => {
            Some(accord_family_key_id().to_owned())
        }
        Ok(_) => None,
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
    // v62.0.0 (wave GC8; CC 2.7.3) — the two arms above read the new
    // version's own bytes and stay refusals. This one compares with the
    // PRIOR version (the held head, when the walk starts from it): a fold
    // condition, held with `grade_changed`.
    if new.consensus_protocol != prior.consensus_protocol {
        return Err(fold::hold(
            fold::reason::gc8::GRADE_CHANGED,
            violation(
                id,
                super::admission::INFRA_RULE_GRADE_CHANGED,
                format!(
                    "consensus_protocol is entrenched: {:?} cannot become {:?}",
                    prior.consensus_protocol, new.consensus_protocol
                ),
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
    let now = crate::host::clock::now();
    // v62.0.0 (wave GC8) — the held chain at this id is an input of the fold
    // below (extends / re-birth over stalled).
    fold::reads(Dep::key(&community.community_key_id));
    check_founders_eligible(directory, community, now).await?;
    let mut memo = Memo::at(now);
    let standing = chain_standing_at(directory, &community.community_key_id, now).await?;
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
            Extends::No => {
                return Err(fold::hold(
                    fold::reason::gc8::TRUST_ROOT_CHAIN,
                    does_not_extend(&community.community_key_id),
                ))
            }
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
    // v62.0.0 (wave GC8; G0 v3 §4) — on the replicated door a non-canonical
    // row's verdict is swallowed into "kept, not rooted": its fold marks must
    // not hold the row, so they are discarded there (reads kept).
    let swallows =
        replicated && signed.community.community_key_id != CIRIS_CANONICAL_COMMUNITY_KEY_ID;
    let verdict = if swallows {
        fold::unmarked(check_trust_root_community_admission(directory, signed)).await
    } else {
        check_trust_root_community_admission(directory, signed).await
    };
    match verdict {
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

/// v62.0.0 (wave GC8; CC 3.2 T6, rc21 ruling 16) — a chain that does not
/// extend the held version is a competing TIP: it waits (held, concluding
/// nothing, reason `trust_root_chain`), and a reader that holds the witnessed
/// head holds it void for itself. "No lineage is settled by which version a
/// node saw first." Every caller wraps this in `fold::hold`.
fn does_not_extend(id: &str) -> Error {
    violation(
        id,
        super::admission::TRUST_ROOT_RULE_CHAIN,
        "the offered chain does not extend the version this node holds: it is a competing tip \
         and waits (held, concluding nothing); a reader holding the witnessed head holds it \
         void (CC 3.2 T6)",
    )
}

/// The replicated occupied-id route for a trust-root row (called by
/// `group_amendment::apply_occupied_community` after [`check_trust_root_community_admission`]
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
    fold::reads(Dep::key(id));
    let now = crate::host::clock::now();
    let mut memo = Memo::at(now);
    let standing = chain_standing_at(directory, id, now).await?;
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
                // v62.0.0 (wave GC8; CC 2.7.8) — a chain that does not extend
                // the held version is a fold condition, never a refusal.
                Extends::No => {
                    return Err(fold::hold(
                        fold::reason::gc8::TRUST_ROOT_CHAIN,
                        does_not_extend(id),
                    ))
                }
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
        // v62.0.0 (kernel pass 2, K1, I2811) — the supersede door holds a
        // version that does not name the held head as a tip rather than
        // refusing it. A chain hop held as a tip (a concurrent write moved
        // the head) did not extend the chain: it stops here, as the stale
        // refusal stopped it before (`lost_race` reads the Conflict).
        let head_now = directory
            .lookup_community(id)
            .await?
            .map(|c| c.persist_row_hash);
        if head_now.as_deref() != Some(row_hash(&version.community)?.as_str()) {
            // v62.0.0 (wave GC8; rc21 ruling 16) — a version held as a tip
            // waits: the row is held (`trust_root_chain`), never refused, and
            // re-folds when the head moves.
            return Err(fold::hold(
                fold::reason::gc8::TRUST_ROOT_CHAIN,
                Error::Conflict(format!(
                    "trust-root chain {id}: version {} was held as a tip beside the head, not \
                 applied over it (the head moved); retryable",
                    i + 1
                )),
            ));
        }
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
    Ok(
        chain_standing_at(directory, community_key_id, crate::host::clock::now())
            .await?
            .held()
            .is_some(),
    )
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
    fold::reads(Dep::key(&id));
    let now = crate::host::clock::now();
    let standing = chain_standing_at(directory, &id, now).await?;
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
        // v62.0.0 (wave GC8) — reads that no chain is held at the id: a fold
        // condition (a birth landing later changes it).
        None if is_trust_root_grade(&new.community) => Err(fold::hold(
            fold::reason::gc8::GRADE_CHANGED,
            violation(
                &id,
                super::admission::INFRA_RULE_GRADE_CHANGED,
                "a supersede cannot promote a community to trust-root grade — the accord's \
                 quorum founds a trust root (put_community)",
            ),
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
    // v62.0.0 (wave GC8) — the witness plane's cosigns are other rows.
    fold::reads(Dep::key(id));
    let cosigns = directory.list_lineage_head_cosigns_for(id).await?;
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
        return Err(fold::hold(
            fold::reason::gc8::LINEAGE_HEAD_BEHIND_WITNESS,
            violation(
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
    // v62.0.0 (wave GC8; CC 2.7.3) — the held head, its roster fold and its
    // liveness are other rows: each leg that reads them is a fold
    // condition. Seating a founder on a plane is the incoming row's own
    // bytes (its role) and stays a refusal, ahead of the fold.
    fold::reads(Dep::key(&community.community_key_id));
    fold::reads(Dep::key(&incoming.key_id));
    if !is_revocation && incoming.role.as_deref() == Some(founder) {
        return Err(violation(
            &community.community_key_id,
            super::admission::TRUST_ROOT_RULE_FOUNDER_SEAT_ON_PLANE,
            format!(
                "founder seats of a trust-root community move only through the record (a \
                 founders' amendment); the roster planes admit and remove members only \
                 ({:?} widened as a founder)",
                incoming.key_id
            ),
        ));
    }
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
                return Err(fold::hold(
                    fold::reason::gc8::RESIGNATION_BACKDATED,
                    violation(
                        &community.community_key_id,
                        super::admission::TRUST_ROOT_RULE_RESIGNATION_BACKDATED,
                        format!(
                            "{:?}'s resignation is dated {effective_at}, not strictly after the \
                             head's instant {instant}: a resignation cannot reach back over a \
                             link",
                            incoming.key_id
                        ),
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
                return Err(fold::hold(
                    fold::reason::gc8::LIVENESS_STALLED_NON_ADMITTING,
                    violation(
                        &community.community_key_id,
                        super::admission::TRUST_ROOT_RULE_STALLED_NON_ADMITTING,
                        format!(
                            "the trust root is stalled (active founders at or below M): valid \
                             but non-admitting (CC 3.2 T7) — {:?} is not admitted until the \
                             margin is restored",
                            incoming.key_id
                        ),
                    ),
                ));
            }
        }
    }
    // `seats_founder` was refused above (the row's own bytes); what is left
    // is a founder seat the HELD record or fold names: a fold condition.
    if recorded || folded || seats_founder {
        return Err(fold::hold(
            fold::reason::gc8::FOUNDER_SEAT_ON_PLANE,
            violation(
                &community.community_key_id,
                super::admission::TRUST_ROOT_RULE_FOUNDER_SEAT_ON_PLANE,
                format!(
                    "founder seats of a trust-root community move only through the record (a \
                     founders' amendment); the roster planes admit and remove members only \
                     ({:?} {})",
                    incoming.key_id,
                    if is_revocation { "revoked" } else { "widened" }
                ),
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
    let now = crate::host::clock::now();
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
    // v62.0.0 (PX-fix3) — the fallback below pages for the same record.
    if let Some(found) = super::optional_capability::unsupported_is_none(
        directory.lookup_signed_community(community_key_id).await,
        "canonical_community::lookup_signed_community",
    )? {
        return Ok(found);
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

/// Parse `quorum:M/N` → `(M, N)`: the one parser for the wire form (a
/// family's, a community's and a trust root's `consensus_protocol`).
/// v62.0.0 (C5-fix1): moved here from the deleted `genesis::bundle`.
pub(crate) fn parse_quorum(s: &str) -> Option<(usize, usize)> {
    let rest = s.strip_prefix("quorum:")?;
    let (m, n) = rest.split_once('/')?;
    Some((m.parse().ok()?, n.parse().ok()?))
}

// v62.0.0 (C5-fix1; ceremony gap 1): the bundle/1 trust-root response
// (`TrustRootBundleResponse`, `trust_root_bundle_response`) and its consumer
// (`pin_trust_from_bundle_response`, `PinnedTrust`,
// `admit_response_withdrawals`) are deleted with the baked genesis. The
// trust-root route serves the edition-2 body
// (`server::edition2::trust_root_statements`); a node imports a genesis at
// `edition2::genesis::put_genesis_bundle`.

/// v62.0.0 (wave T2) — the trust root's ROOTED head, or why there is none
/// (a refusal pair, `(reason, detail)`), for the edition-2 voice count
/// ([`trust_root_counts_voices`]). v62.0.0 (BH-fix1): the earlier
/// cosigned-envelope count (`trust_root_cosigners_over`, separate Ed25519 +
/// ML-DSA-65 pairs) is deleted.
///
/// # Errors
/// Directory reads.
pub(crate) async fn trust_root_head<F>(
    directory: &F,
    community_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Result<Box<SignedCommunity>, (&'static str, String)>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::steward_purge::unauthorised_reason as why;
    // v62.0.0 (wave GC8; CC 2.7.3) — the root's standing is other rows: an
    // answer that is not `Rooted` is a fold condition, noted on the running
    // attempt with its token (the caller still answers its refusal pair; at
    // an edition-2 door the row is held and re-folds when the root's rows
    // change). Outside an attempt nothing is marked.
    fold::reads(Dep::key(community_key_id));
    let out = match stored_standing_at(directory, community_key_id, now).await? {
        // v62.0.0 (TR-fix1; CC rc21 3.2 T7 l.1240) — a STALLED root is valid,
        // and "non-admitting means exactly" no roster widening or removal by
        // the founders' count and no ceremony-plane conferral by this roster.
        // A purge is neither, so a stalled root's founders still authorise it
        // ("Everything else is unchanged").
        StoredStanding::Rooted(head) | StoredStanding::Stalled { held: head, .. } => Ok(head),
        StoredStanding::NotRooted { reason } => Err((
            why::ROOT_NOT_ROOTED,
            format!("the row at {community_key_id:?} is not rooted ({reason})"),
        )),
        StoredStanding::Absent => Err((
            why::ROOT_NOT_HELD,
            format!(
                "no community row at {community_key_id:?}: the claimant is not a trust root this \
                 node holds"
            ),
        )),
    };
    if let Err((why_token, _)) = &out {
        note_fold_reason(why_token);
    }
    Ok(out)
}

/// v62.0.0 (wave GC8) — mark the running fold attempt with the fold reason a
/// trust-root count's refusal token names (`steward_purge::unauthorised_reason`).
/// Only the tokens that read OTHER rows are fold conditions; a token about
/// the notice's own bytes (no cosignature, a duplicate, a signature that does
/// not verify, a malformed notice) marks nothing and stays a refusal.
fn note_fold_reason(why_token: &str) {
    use super::steward_purge::unauthorised_reason as why;
    let r = match why_token {
        t if t == why::ROOT_NOT_HELD => fold::reason::gc8::ROOT_NOT_HELD,
        t if t == why::ROOT_NOT_ROOTED => fold::reason::gc8::ROOT_NOT_ROOTED,
        t if t == why::STALLED => fold::reason::gc8::STALLED,
        t if t == why::NOT_A_SEAT => fold::reason::gc8::NOT_A_SEAT,
        t if t == why::COSIGNER_KEY_NOT_HELD => fold::reason::gc8::COSIGNER_KEY_NOT_HELD,
        t if t == why::QUORUM_NOT_MET => fold::reason::COUNT_SHORT,
        t if t == why::PROTOCOL_UNEVALUABLE => fold::reason::gc8::PROTOCOL_UNEVALUABLE,
        _ => return,
    };
    fold::note(r);
}

/// v62.0.0 (wave T2) — the trust root's own `consensus_protocol` over
/// `signers` (seats already checked): the ONE count both purge
/// authorisations run.
///
/// # Errors
/// Directory reads.
async fn count_over_trust_root<F>(
    directory: &F,
    head: &SignedCommunity,
    signers: std::collections::BTreeSet<String>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Result<std::collections::BTreeSet<String>, (&'static str, String)>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::steward_purge::unauthorised_reason as why;
    let mut seats: Vec<super::consensus::Seat> = Vec::with_capacity(head.community.members.len());
    fold::reads(Dep::key(&head.community.community_key_id));
    for m in &head.community.members {
        fold::reads(Dep::key(&m.key_id));
        seats.push(super::consensus::Seat {
            key_id: m.key_id.clone(),
            role: m.role.clone(),
            node_bearing: super::is_node_bearing_key_at(directory, &m.key_id, now).await?,
        });
    }
    let verdict = super::consensus::evaluate(&super::consensus::Ballot {
        protocol: &head.community.consensus_protocol,
        subkind: super::community_subkind(&head.community),
        policy_blob: head.community.policy_blob.as_ref(),
        roster: &seats,
        signers: &signers,
        direction: super::consensus::Direction::Add,
        subject: None,
        // The trust root's chain keeps the per-key count (CIRISPersist#1198).
        persons: super::key_person::PersonsAt::each_key(),
        high_water: None,
    });
    // v62.0.0 (wave GC8) — a count short of the held head's protocol, or one
    // the held roster cannot evaluate, is a fold condition.
    match &verdict {
        super::consensus::Verdict::Admit => {}
        super::consensus::Verdict::Insufficient { .. } => note_fold_reason(why::QUORUM_NOT_MET),
        super::consensus::Verdict::Unevaluable { .. } => {
            note_fold_reason(why::PROTOCOL_UNEVALUABLE);
        }
    }
    match verdict {
        super::consensus::Verdict::Admit => Ok(Ok(signers)),
        super::consensus::Verdict::Insufficient { detail, .. } => Ok(Err((
            why::QUORUM_NOT_MET,
            format!(
                "the trust root's consensus_protocol {:?} is not met: {detail}",
                head.community.consensus_protocol
            ),
        ))),
        super::consensus::Verdict::Unevaluable { reason } => Ok(Err((
            why::PROTOCOL_UNEVALUABLE,
            format!(
                "the trust root's consensus_protocol {:?} cannot be evaluated: {reason}",
                head.community.consensus_protocol
            ),
        ))),
    }
}

/// v62.0.0 (wave T2) — **the trust root's count over an edition-2 notice's
/// voices**: `voices` are the issuers of the notice's held statements, each
/// verified by the edition-2 door (`cosign::edition2_voices` re-admits
/// them), so no signature is checked here. The root must be rooted, every
/// voice a seat of its head (a non-seat is a refusal, not a discount, as
/// for a cosignature), and the head's protocol met
/// ([`count_over_trust_root`], the same count).
///
/// # Errors
/// `Ok(Err((reason, detail)))` names why the voices do not authorise:
/// `reason` is a [`unauthorised_reason`](super::steward_purge::unauthorised_reason)
/// token; `Err` is a directory read failure.
pub async fn trust_root_counts_voices<F>(
    directory: &F,
    community_key_id: &str,
    voices: &std::collections::BTreeSet<String>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Result<std::collections::BTreeSet<String>, (&'static str, String)>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let head = match trust_root_head(directory, community_key_id, now).await? {
        Ok(head) => head,
        Err(refusal) => return Ok(Err(refusal)),
    };
    counts_voices_over_head(directory, &head, voices, now).await
}

/// v62.0.0 (wave T2) — [`trust_root_counts_voices`] past the standing read:
/// every voice a seat of `head`, then the head's own protocol
/// ([`count_over_trust_root`]). Separate so a witness can hand it a head
/// directly.
///
/// # Errors
/// As [`trust_root_counts_voices`].
pub(crate) async fn counts_voices_over_head<F>(
    directory: &F,
    head: &SignedCommunity,
    voices: &std::collections::BTreeSet<String>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Result<std::collections::BTreeSet<String>, (&'static str, String)>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::steward_purge::unauthorised_reason as why;
    let community_key_id = head.community.community_key_id.as_str();
    if voices.is_empty() {
        return Ok(Err((
            why::NO_COSIGNATURE,
            "no statement of the notice is held".to_owned(),
        )));
    }
    for v in voices {
        if !head.community.members.iter().any(|m| m.key_id == *v) {
            note_fold_reason(why::NOT_A_SEAT);
            return Ok(Err((
                why::NOT_A_SEAT,
                format!("voice {v:?} holds no seat on the trust root {community_key_id:?}"),
            )));
        }
    }
    count_over_trust_root(directory, head, voices.clone(), now).await
}

/// v53.1.7 — I547's oracle: [`live_charter_rows`] as v53.1.6 shipped it,
/// VERBATIM (the family's whole about-slice), `super::` spelled from the crate
/// root.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod v53_1_6_reference {
    use super::*;

    pub(crate) async fn live_charter_rows_reference<F>(
        directory: &F,
        family: &str,
    ) -> Result<Vec<crate::federation::Attestation>, Error>
    where
        F: FederationDirectory + ?Sized,
    {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        let is_charter = |a: &crate::federation::Attestation| {
            a.attestation_type == crate::federation::types::attestation_type::DELEGATES_TO
                && a.attested_key_id == family
                && crate::federation::trust_root::job_dimension_admits(
                    &a.attestation_envelope,
                    crate::federation::trust_root::TRUST_CHARTER_DIMENSION,
                )
        };
        let rows = directory.all_attestations_for(family).await?;
        let refs: Vec<&crate::federation::Attestation> = rows.iter().collect();
        let retired = crate::federation::precedence::retired_ids(&refs);
        let denied = crate::federation::trust_root::direction_denied_ids(
            directory,
            rows.iter().filter(|a| is_charter(a)),
        )
        .await?;
        Ok(rows
            .into_iter()
            .filter(|a| {
                is_charter(a)
                    && !denied.contains(&a.attestation_id)
                    && !retired.contains(&a.attestation_id)
            })
            .collect())
    }
}
