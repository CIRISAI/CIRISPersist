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

/// #925 (CC 3.2 rc5, "infrastructure does not vote") plus CC 3.2 T2 — a
/// founder of a trust-root community is a HUMAN key at `at`: `user` in its own
/// `identity_type` set, and NOT node-bearing by #925's one predicate
/// ([`is_node_bearing_key_at`](super::is_node_bearing_key_at) — its own set,
/// or an agreed occurrence of a `node` identity at `at`).
async fn founder_is_human_at<F>(
    directory: &F,
    record: &KeyRecord,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(
        identity_type::set_contains(&record.identity_type, identity_type::USER)
            && !super::is_node_bearing_key_at(directory, &record.key_id, at).await?,
    )
}

/// One founder is eligible: a key record here, human (#925), and an
/// accord-conferred `steward` whose conferral has not been withdrawn (CC 3.2
/// T2). The conferral is judged against the COMPILED accord holder roster
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
    if !founder_is_human_at(directory, &record, chrono::Utc::now()).await? {
        return Err(violation(
            community_key_id,
            super::admission::INFRA_RULE_NODE_BEARING_FOUNDER,
            format!(
                "founder {founder:?} is not a human key (identity_type {:?}): a node-bearing key \
                 MUST NOT be a founder of an infrastructure community (CIRISPersist#925)",
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

/// Every founder the record names is eligible ([`check_founder_eligible`]).
///
/// # Errors
///
/// The first founder's refusal.
pub async fn check_founders_eligible<F>(directory: &F, community: &Community) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    for founder in founders(community) {
        check_founder_eligible(directory, &community.community_key_id, founder).await?;
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
    let Some(family) =
        super::trust_root::resolve_family_root(directory, accord_family_key_id()).await?
    else {
        return Err(insufficient(signed));
    };
    let (quorum, _) = super::trust_root::family_quorum_holders_over_envelope(
        directory,
        &signed.community.signing_envelope(),
        &community_scrubs(signed),
        &family,
    )
    .await?;
    Ok(quorum)
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
#[derive(Default)]
struct Memo {
    records: std::collections::HashMap<String, Option<KeyRecord>>,
    conferred: std::collections::HashMap<String, bool>,
    /// Per community: every self-signed resignation instant of each key,
    /// ascending (a re-seated founder may resign again; the earliest alone
    /// would mask the later one behind the re-seat floor).
    resignations: std::collections::HashMap<
        String,
        std::collections::HashMap<String, Vec<chrono::DateTime<chrono::Utc>>>,
    >,
}

impl Memo {
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

    /// Whether `key_id` resigned from `community_key_id` (its own plane
    /// revocation, signed by that founder alone) at an instant in
    /// `(after, until]` — `after` inclusive when `inclusive`. Read once per
    /// community per call.
    async fn resigned_within<F>(
        &mut self,
        directory: &F,
        community_key_id: &str,
        key_id: &str,
        after: Option<chrono::DateTime<chrono::Utc>>,
        inclusive: bool,
        until: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, Error>
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
            .is_some_and(|all| {
                all.iter().any(|r| {
                    *r <= until && after.is_none_or(|a| if inclusive { *r >= a } else { *r > a })
                })
            }))
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
    /// = now)? A human key at that instant (#925's
    /// [`is_node_bearing_key_at`](super::is_node_bearing_key_at)),
    /// accord-conferred as a steward, not resigned by its own signature, and
    /// not withdrawn — or, for a link instant, withdrawn only AFTER it (a
    /// rotation does not un-count the historical signatures of the key it
    /// retired). A withdrawal whose successor is the key itself is a rotate-in
    /// and never un-counts.
    ///
    /// A resignation applies only when its `effective_at` is LATER than
    /// `resignation_floor` and at or before `at`. The floor is the instant of
    /// the version being judged: for a link, the PRIOR version's instant, so a
    /// resignation never invalidates a link that follows a version predating it
    /// (review MEDIUM-R (b)); for the head's founders, the instant of the
    /// version that (re-)seated the key, so a resignation older than a re-seat
    /// is cleared — the re-seat is the founders' quorum speaking later (LOW-1).
    async fn founder_counts<F>(
        &mut self,
        directory: &F,
        community_key_id: &str,
        key_id: &str,
        at: Option<chrono::DateTime<chrono::Utc>>,
        resignation_floor: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<bool, Error>
    where
        F: FederationDirectory + ?Sized,
    {
        let Some(rec) = self.record(directory, key_id).await? else {
            return Ok(false);
        };
        let when = at.unwrap_or_else(chrono::Utc::now);
        if !founder_is_human_at(directory, &rec, when).await?
            || !self.conferred(directory, key_id).await?
        {
            return Ok(false);
        }
        if self
            .resigned_within(
                directory,
                community_key_id,
                key_id,
                resignation_floor,
                false,
                when,
            )
            .await?
        {
            return Ok(false);
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
///   `amended_at` (human, accord-conferred, not withdrawn before it), each
///   hybrid-verified against this node's pinned pubkeys (founder key records
///   are never deleted) — meet `prior`'s protocol over its founder seats;
/// - `next`'s authority is one of those counted founders, and its signature
///   over `next` verifies.
///
/// Returns the link's instant.
///
/// # Errors
///
/// [`Error::CommunityConsensusProtocolViolation`] for a structural clause;
/// [`Error::RosterAuthorityUnauthorized`] (`roster_consensus_insufficient`)
/// short of the founders' quorum.
pub async fn verify_founders_link<F>(
    directory: &F,
    prior: &Community,
    prior_instant: Option<chrono::DateTime<chrono::Utc>>,
    next: &SignedCommunity,
) -> Result<chrono::DateTime<chrono::Utc>, Error>
where
    F: FederationDirectory + ?Sized,
{
    verify_founders_link_memo(directory, prior, prior_instant, next, &mut Memo::default()).await
}

async fn verify_founders_link_memo<F>(
    directory: &F,
    prior: &Community,
    prior_instant: Option<chrono::DateTime<chrono::Utc>>,
    next: &SignedCommunity,
    memo: &mut Memo,
) -> Result<chrono::DateTime<chrono::Utc>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use ciris_verify_core::threshold::ThresholdMember;
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
    if amended_at < floor
        || amended_at > chrono::Utc::now() + chrono::Duration::seconds(AMENDED_AT_SKEW_SECS)
    {
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
    // Review R2: a resignation does not LAPSE. A link that still records a
    // founder carried from the prior version, whose resignation falls at or
    // after the prior's instant and at or before this link's, is refused: the
    // other founders must amend the seat out, so no later version records a
    // resigned founder and the prior-instant floor stays sound. A founder the
    // link newly seats is a re-seat — the founders' quorum speaking later —
    // and clears an older resignation (LOW-1).
    for f in founders(&next.community) {
        if prior_founders.contains(&f)
            && memo
                .resigned_within(directory, id, f, Some(floor), true, amended_at)
                .await?
        {
            return Err(violation(
                id,
                super::admission::TRUST_ROOT_RULE_RESIGNATION_CARRIED_FORWARD,
                format!(
                    "the version still records {f:?} as a founder after their resignation; the \
                     founders must amend the seat out"
                ),
            ));
        }
    }
    let bytes =
        ciris_verify_core::accord_genesis::accord_family_signing_bytes(&proof.change_envelope)
            .map_err(|e| Error::InvalidArgument(format!("founders' change envelope: {e}")))?;
    let mut signers = std::collections::BTreeSet::new();
    for sig in &proof.quorum_signatures {
        if !prior_founders.contains(&sig.member_id.as_str())
            || signers.contains(&sig.member_id)
            || !memo
                .founder_counts(directory, id, &sig.member_id, Some(amended_at), Some(floor))
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
                .founder_counts(directory, id, &m.key_id, Some(amended_at), Some(floor))
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
fn head_instant(head: &SignedCommunity) -> chrono::DateTime<chrono::Utc> {
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

/// Walk `chain` from `chain[0]`, TRUSTING `chain[0]` (the version this node
/// already holds and has judged rooted): every later version must be a
/// verified founders' link of the one before it.
async fn verify_links_from<F>(
    directory: &F,
    chain: &[SignedCommunity],
    memo: &mut Memo,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut instant = chain.first().and_then(link_instant);
    for w in chain.windows(2) {
        instant = Some(
            verify_founders_link_memo(directory, &w[0].community, instant, &w[1], memo).await?,
        );
    }
    Ok(())
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
pub async fn verify_chain<F>(directory: &F, chain: &[SignedCommunity]) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    verify_chain_memo(directory, chain, &mut Memo::default()).await
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
                Some(birth.community.founded_at),
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
    if !accord_quorum_over_community(directory, birth).await?.met() {
        return Err(insufficient(birth));
    }
    verify_links_from(directory, chain, memo).await
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
/// Keyed on a digest of EVERY input the verdict reads — the stored signed row
/// with its lineage, the accord family's record and active roster, the key
/// record and steward withdrawal of every holder and every founder or signer
/// the chain names, and the community's folded roster — so any change to them
/// (a holder revocation, a founder key rotation or withdrawal, a plane change,
/// an amendment) is a different key. Never process-global: two directories
/// never share one.
#[derive(Debug, Default)]
pub struct StandingCache {
    entries: std::sync::Mutex<std::collections::HashMap<String, StoredStanding>>,
    computations: std::sync::atomic::AtomicU64,
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
    let family_id = accord_family_key_id();
    feed(
        "family",
        &serde_json::to_value(directory.lookup_family(family_id).await.ok().flatten())
            .unwrap_or_default(),
    );
    let roster: Vec<String> = match directory.active_family_members(family_id).await {
        Ok(m) => m.into_iter().map(|m| m.key_id).collect(),
        Err(_) => Vec::new(),
    };
    feed("roster", &serde_json::json!(roster));
    let mut keys: std::collections::BTreeSet<String> =
        super::admission::accord_holder_roster_key_ids()
            .into_iter()
            .collect();
    keys.extend(roster);
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
        // #925's node-bearing inputs (own set, agreed occurrence bindings of a
        // `node` identity): a founder later bound as an occurrence of a node
        // is a different key, never a stale Rooted verdict.
        let (own_node, node_intervals) = super::node_bearing_of(directory, k).await?;
        feed(
            "key",
            &serde_json::json!({
                "k": k,
                "rec": rec,
                "w": serde_json::to_value(&w).unwrap_or_default(),
                "node": own_node,
                "node_intervals": format!("{node_intervals:?}"),
            }),
        );
    }
    let folded: Vec<(String, Option<String>)> =
        super::effective_roster(directory, &signed.community)
            .await?
            .into_iter()
            .map(|m| (m.key_id, m.role))
            .collect();
    feed("folded", &serde_json::json!(folded));
    // Every self-signed resignation instant (`Memo::resigned_within` reads
    // these). The fold alone is not enough: a re-seated founder's SECOND
    // resignation leaves the folded roster unchanged — the first one already
    // folded them out — so a key without it served a stale Rooted verdict.
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

/// Re-judge the row stored at `community_key_id` (see the module doc). Called
/// by every read side and by the doors before deciding what an offered row
/// extends. ROOTED ⇔ the stored row conforms, its CHAIN (stored `lineage` plus
/// the row) verifies from an accord birth ([`verify_chain`], every link's proof
/// re-verified — there is no proof-only arm), and EVERY recorded founder
/// counts now. Served from this directory's [`StandingCache`] while every
/// input is unchanged.
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
            return Ok(hit.clone());
        }
    }
    let standing = compute_standing(directory, signed).await?;
    if let (Some(c), Some(k)) = (cache, key) {
        c.computations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut entries = c.entries.lock().expect("standing cache");
        if entries.len() >= STANDING_CACHE_CAP {
            entries.clear();
        }
        entries.insert(k, standing.clone());
    }
    Ok(standing)
}

async fn compute_standing<F>(
    directory: &F,
    signed: SignedCommunity,
) -> Result<StoredStanding, Error>
where
    F: FederationDirectory + ?Sized,
{
    let not = |reason: String| Ok(StoredStanding::NotRooted { reason });
    if let Err(e) = check_trust_root_shape(&signed.community) {
        return not(format!("non-conformant: {e}"));
    }
    let mut memo = Memo::default();
    match verify_chain_memo(directory, &chain_of(&signed), &mut memo).await {
        Ok(()) => {}
        Err(e) if is_row_verdict(&e) => {
            return not(format!(
                "not accord-born: its chain does not verify from an accord birth ({e})"
            ))
        }
        Err(e) => return Err(e),
    }
    let chain = chain_of(&signed);
    for f in founders(&signed.community) {
        if !memo
            .founder_counts(
                directory,
                &signed.community.community_key_id,
                f,
                None,
                Some(seated_since(&chain, f)),
            )
            .await?
        {
            let reason = format!(
                "founder {f:?} is not eligible now (human, accord-conferred, not withdrawn); a \
                 founders' amendment that retires it roots the row again"
            );
            return Ok(StoredStanding::Stalled {
                held: Box::new(signed),
                reason,
            });
        }
    }
    Ok(StoredStanding::Rooted(Box::new(signed)))
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
    Ok(match stored_standing(directory, community_key_id).await {
        Ok(StoredStanding::Rooted(_)) => Some(accord_family_key_id().to_owned()),
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
    check_founders_eligible(directory, community).await?;
    let chain = chain_of(signed);
    let mut memo = Memo::default();
    let standing = stored_standing(directory, &community.community_key_id).await?;
    if let Some(held) = standing.held() {
        let held_hash = row_hash(&held.community)?;
        if row_hash(community)? == held_hash {
            return Ok(true);
        }
        match extends_at(&chain, &held_hash)? {
            Some(pos) => verify_links_from(directory, &chain[pos..], &mut memo).await?,
            None if is_rebirth_over_stalled(&standing, &chain) => {
                verify_chain_memo(directory, &chain, &mut memo).await?
            }
            None => return Err(does_not_extend(&community.community_key_id)),
        }
    } else {
        verify_chain_memo(directory, &chain, &mut memo).await?;
    }
    Ok(true)
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

fn extends_at(chain: &[SignedCommunity], held_hash: &str) -> Result<Option<usize>, Error> {
    for (i, v) in chain.iter().enumerate() {
        if row_hash(&v.community)? == held_hash {
            return Ok(Some(i));
        }
    }
    Ok(None)
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
    let chain = chain_of(offered);
    let id = offered.community.community_key_id.as_str();
    let mut memo = Memo::default();
    let standing = stored_standing(directory, id).await?;
    let (start, replaces) = match (&standing, standing.held()) {
        (StoredStanding::Absent, _) => return Ok(false),
        (_, Some(held)) => {
            let held_hash = row_hash(&held.community)?;
            if row_hash(&offered.community)? == held_hash {
                return Ok(true);
            }
            match extends_at(&chain, &held_hash)? {
                Some(pos) => {
                    verify_links_from(directory, &chain[pos..], &mut memo).await?;
                    (pos + 1, None)
                }
                None if is_rebirth_over_stalled(&standing, &chain) => {
                    verify_chain_memo(directory, &chain, &mut memo).await?;
                    (0, Some(("accord_rebirth_replaces_stalled", held_hash)))
                }
                None => return Err(does_not_extend(id)),
            }
        }
        (_, None) => {
            verify_chain_memo(directory, &chain, &mut memo).await?;
            let stored = directory
                .lookup_community(id)
                .await?
                .map(|c| c.persist_row_hash)
                .unwrap_or_default();
            (0, Some(("accord_birth_replaces_unrooted", stored)))
        }
    };
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
    }
    Ok(true)
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
    let standing = stored_standing(directory, &id).await?;
    match standing.held() {
        Some(held) => {
            verify_founders_link(directory, &held.community, link_instant(held), &new).await?;
            check_founders_eligible(directory, &new.community).await?;
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
    if trust_root
        && !matches!(
            stored_standing(directory, community_key_id).await?,
            StoredStanding::Rooted(_)
        )
    {
        return Ok(None);
    }
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
