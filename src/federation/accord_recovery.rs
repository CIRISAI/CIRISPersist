//! v53.0.0 (CC 4.2.6, rc7 `fe459cf`/`5e89627`) — **an accord holder's
//! recovery.**
//!
//! Every holder carries a pre-committed recovery key, committed in the
//! accord's charter (`recovery_commitments`, a [`recovery_commitment`] over
//! the key's material). "A holder who has lost signing-key material, and only
//! that holder, rotates by a `supersedes` signed under the recovery key; the
//! rotation is a roster change by that holder about themselves and needs no
//! quorum."
//!
//! The rotation is a new version of the accord's family record (CC 3.2 T6: a
//! roster-affecting row produces a new version) that differs from the held
//! head in exactly one seat — the old signing key swapped for the new — and in
//! its head fields (`prev_head_digest` = the held head). It enters through the
//! accord's one door ([`verify_family_admission`](super::tier_ingest::verify_family_admission)),
//! as the second shape that door admits beside a quorum-proven head version:
//!
//! - its `supersede_proof.change_envelope` is the **recovery statement**
//!   ([`RECOVERY_STATEMENT_KIND`]): the family, the held head it replaces, the
//!   offered version's content hash, the old and new holder keys, the recovery
//!   key, and the commitment to the new key's own next recovery key;
//! - its one `quorum_signatures` entry is the recovery key's hybrid signature
//!   over that statement's JCS bytes, verified against the recovery key's
//!   STORED record;
//! - the commitment recomputed from that stored record must equal the old
//!   holder's commitment in force ([`recovery_commitment_in_force`]) — so a
//!   record registered under the committed id with other keys is refused;
//! - the record itself is signed by the NEW key (possession of the key that
//!   takes the seat).
//!
//! The statement is recorded as the superseded version's authorization, so the
//! version chain is the ledger: a recovery key that already rotated a seat is
//! spent (`accord_recovery_key_spent`), and a recovered holder's next recovery
//! commitment is the one its recovery statement named.

use super::canonical_community::{charter_in_force, HeadCharter};
use super::cohort::Cohort;
use super::edition2::fold::reason as held_reason;
use super::trust_root::{recovery_commitment, CommittedKey};
use super::types::{Family, FamilyMember, SignedFamily};
use super::{Error, FederationDirectory};

/// The `kind` of a recovery statement.
pub const RECOVERY_STATEMENT_KIND: &str = "ciris.accord_recovery.v1";

/// v62.0.0 (CC rc20 4.2.6, CIRISPersist#1274; Verify `RecoveryReusesSigningKey`)
/// — the recovery names the holder's CURRENT signing key as the new one.
pub const ACCORD_RECOVERY_REUSES_SIGNING_KEY: &str = "accord_recovery_reuses_signing_key";
/// v62.0.0 (CC rc20 4.2.6; Verify `RecoveryKeyAsSigningKey`) — the recovery
/// seats a recovery key as the new signing key, by id or by public key
/// material (this recovery's key, or one the lineage already spent).
pub const ACCORD_RECOVERY_KEY_AS_SIGNING_KEY: &str = "accord_recovery_key_as_signing_key";
/// v62.0.0 (CC rc20 4.2.6; Verify `LineageIncomplete`) — the lineage names a
/// predecessor this node does not hold.
pub const ACCORD_RECOVERY_LINEAGE_INCOMPLETE: &str = "accord_recovery_lineage_incomplete";

fn refuse<T>(token: &str, detail: impl std::fmt::Display) -> Result<T, Error> {
    Err(Error::CharterInvalid {
        detail: format!("{token}: {detail}"),
    })
}

/// v62.0.0 (wave GC3; CC 2.7.3) — [`refuse`] for a check that read OTHER
/// rows (the held accord, its seats, its recovery lineage, a key record):
/// inside a fold attempt the recovery is HELD with `token` as its reason
/// (a [`fold::reason`](super::edition2::fold::reason) token, the same text
/// the refusal leads with), and re-folds when the rows it read change.
/// Outside an attempt it is exactly [`refuse`].
fn hold_on<T>(token: &'static str, detail: impl std::fmt::Display) -> Result<T, Error> {
    Err(super::edition2::fold::hold(
        token,
        Error::CharterInvalid {
            detail: format!("{token}: {detail}"),
        },
    ))
}

fn well_formed_commitment(h: &str) -> bool {
    h.len() == 64
        && h.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// What a host asks for: which seat, to which key, under which recovery key,
/// and the commitment to the new key's own recovery key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccordRecoveryRequest {
    /// The accord family (`humanity-accord`).
    pub family_key_id: String,
    /// The seat's lost signing key.
    pub old_holder_key_id: String,
    /// The new signing key (registered before the rotation).
    pub new_holder_key_id: String,
    /// The old holder's pre-committed recovery key (registered).
    pub recovery_key_id: String,
    /// The commitment ([`recovery_commitment`]) to the new key's recovery key.
    pub next_recovery_commitment: String,
    /// The new seat's `joined_at`, stamped once by the caller.
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

/// The bytes the two keys sign, and the version they produce.
#[derive(Debug, Clone, PartialEq)]
pub struct AccordRecoveryDraft {
    /// The offered version of the family record.
    pub next: Family,
    /// The recovery statement (the supersede proof's change envelope).
    pub statement: serde_json::Value,
    /// JCS of the statement: the recovery key signs these.
    pub statement_bytes: Vec<u8>,
    /// JCS of the offered record's signing envelope: the NEW key signs these.
    pub record_bytes: Vec<u8>,
}

/// **Draft a recovery** against the accord this node holds.
///
/// # Errors
///
/// No held accord; the old key holds no seat; the new key already does.
pub async fn draft_accord_recovery<F>(
    directory: &F,
    req: &AccordRecoveryRequest,
) -> Result<AccordRecoveryDraft, Error>
where
    F: FederationDirectory + ?Sized,
{
    let held = directory
        .lookup_family(&req.family_key_id)
        .await?
        .ok_or_else(|| Error::InvalidArgument(format!("no family {}", req.family_key_id)))?;
    let Some(seat) = held
        .members
        .iter()
        .find(|m| m.key_id == req.old_holder_key_id)
    else {
        return refuse(
            "accord_recovery_not_a_holder",
            format!(
                "{} holds no seat in {}",
                req.old_holder_key_id, req.family_key_id
            ),
        );
    };
    if held
        .members
        .iter()
        .any(|m| m.key_id == req.new_holder_key_id)
    {
        return refuse(
            "accord_recovery_seat_taken",
            format!("{} already holds a seat", req.new_holder_key_id),
        );
    }
    let role = seat.role.clone();
    let mut next = held.clone();
    next.persist_row_hash = String::new();
    next.prev_head_digest = held.persist_row_hash.clone();
    for m in &mut next.members {
        if m.key_id == req.old_holder_key_id {
            *m = FamilyMember {
                key_id: req.new_holder_key_id.clone(),
                joined_at: req.joined_at,
                role: role.clone(),
            };
        }
    }
    let statement = serde_json::json!({
        "kind": RECOVERY_STATEMENT_KIND,
        "family_key_id": req.family_key_id,
        "prior_persist_row_hash": held.persist_row_hash,
        "next_persist_row_hash": super::types::compute_persist_row_hash(&next)?,
        "old_holder_key_id": req.old_holder_key_id,
        "new_holder_key_id": req.new_holder_key_id,
        "recovery_key_id": req.recovery_key_id,
        "next_recovery_commitment": req.next_recovery_commitment,
    });
    let jcs = |v: &serde_json::Value| {
        crate::verify::canonical::ceg_produce_canonicalize(v)
            .map_err(|e| Error::InvalidArgument(format!("recovery canonicalize: {e}")))
    };
    Ok(AccordRecoveryDraft {
        statement_bytes: jcs(&statement)?,
        record_bytes: jcs(&next.signing_envelope())?,
        next,
        statement,
    })
}

/// **Rotate a holder's seat under their recovery key** (CC 4.2.6): the draft,
/// the recovery key's signature over `statement_bytes` and the new key's over
/// `record_bytes`, each `(Ed25519, ML-DSA-65 over bytes ‖ ed_sig)` base64.
/// No quorum. Returns the new version number.
///
/// # Errors
///
/// [`Error::CharterInvalid`] naming the refusal (`accord_recovery_*`), or the
/// write door's own refusals.
pub async fn recover_accord_holder<F>(
    directory: &F,
    draft: AccordRecoveryDraft,
    recovery_signature: (String, String),
    new_holder_signature: (String, String),
) -> Result<u32, Error>
where
    F: FederationDirectory + ?Sized,
{
    let held = directory
        .lookup_family(&draft.next.family_key_id)
        .await?
        .ok_or_else(|| Error::InvalidArgument(format!("no family {}", draft.next.family_key_id)))?;
    let signed = recovery_version(
        &held.persist_row_hash,
        &draft,
        recovery_signature,
        new_holder_signature,
    );
    // Judged here with its reason, then admitted by the accord's one door.
    // Codex on #978: `Ok(None)` means "not the accord family" — a recovery
    // is an ACCORD version and nothing else may reach the signed supersede.
    if verify_accord_recovery(directory, &signed).await?.is_none() {
        return Err(Error::CharterInvalid {
            detail: format!(
                "accord_recovery_not_an_accord_family: {} is not the accord family; a \
                 recovery version exists only for the accord",
                signed.family.family_key_id
            ),
        });
    }
    let authorization = serde_json::json!({
        "change_envelope": draft.statement.clone(),
        "quorum_signatures": signed
            .supersede_proof
            .as_ref()
            .map(|p| p.quorum_signatures.clone())
            .unwrap_or_default(),
    });
    super::group_amendment::supersede_family_signed(directory, signed, Some(authorization)).await
}

/// **The signed recovery version** a draft and its two signatures form: the
/// record signed by the new key, the supersede proof carrying the statement
/// and the recovery key's signature, naming `held_head` as its prior. What
/// [`recover_accord_holder`] submits and what a peer receives.
#[must_use]
pub fn recovery_version(
    held_head: &str,
    draft: &AccordRecoveryDraft,
    recovery_signature: (String, String),
    new_holder_signature: (String, String),
) -> SignedFamily {
    let field = |k: &str| {
        draft
            .statement
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned()
    };
    SignedFamily {
        family: draft.next.clone(),
        authority_key_id: field("new_holder_key_id"),
        scrub_signature_classical: new_holder_signature.0,
        scrub_signature_pqc: Some(new_holder_signature.1),
        supersede_proof: Some(super::types::GroupSupersedeProof {
            prior_persist_row_hash: held_head.to_owned(),
            change_envelope: draft.statement.clone(),
            quorum_signatures: vec![ciris_verify_core::threshold::ThresholdSignature {
                member_id: field("recovery_key_id"),
                ed25519_signature_base64: recovery_signature.0,
                mldsa65_signature_base64: Some(recovery_signature.1),
            }],
        }),
        cosignatures: Vec::new(),
    }
}

/// The charter a stored version row named: the versions table snapshots the
/// superseded `Family` (bare, or the signed wrapper around it).
fn version_charter_digest(snapshot: &serde_json::Value) -> &str {
    snapshot
        .get("family")
        .unwrap_or(snapshot)
        .get("charter_digest")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
}

/// The recovery statements this accord's version chain records, oldest
/// first — every one, or (v53.1.2, CIRISPersist#984 row 3) only those made
/// UNDER `under_charter`: a statement is the authorization of the version it
/// superseded, and that version's `charter_digest` is the charter in force
/// when the recovery was made. A new charter is a fresh commitments table;
/// a recovery made under an older one carries no exception into it.
pub(crate) async fn recorded_statements<F>(
    directory: &F,
    family_key_id: &str,
    under_charter: Option<&str>,
) -> Result<Vec<serde_json::Value>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(directory
        .list_group_versions(Cohort::Family, family_key_id)
        .await?
        .into_iter()
        .filter(|v| under_charter.is_none_or(|c| version_charter_digest(&v.snapshot) == c))
        .filter_map(|v| v.authorization)
        .filter_map(|a| a.get("change_envelope").cloned())
        .filter(|e| e.get("kind").and_then(|k| k.as_str()) == Some(RECOVERY_STATEMENT_KIND))
        .collect())
}

/// v62.0.0 (CC rc20 4.2.6, CIRISPersist#1274) — the accord's roster lineage
/// as this node holds it, **oldest first, walked by `prev_head_digest` links
/// from the head, never by instant**: each version with the change envelope
/// that admitted it (`None` for the genesis version). A version is read from
/// its history row (`federation_group_versions`, whose `change_authorization`
/// is the change that SUPERSEDED that snapshot) and the head from the live
/// row.
///
/// # Errors
///
/// `accord_recovery_lineage_incomplete` when a link names a version this node
/// does not hold (or the chain loops): it fails closed and never falls back
/// to an earlier row across the gap (CC 4.2.6; Verify `LineageIncomplete`).
/// Directory read failures.
pub(crate) async fn accord_lineage<F>(
    directory: &F,
    family_key_id: &str,
) -> Result<Vec<(Family, Option<serde_json::Value>)>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(head) = directory.lookup_family(family_key_id).await? else {
        return Ok(Vec::new());
    };
    let mut by_hash: std::collections::HashMap<String, (Family, Option<serde_json::Value>)> =
        std::collections::HashMap::new();
    for v in directory
        .list_group_versions(Cohort::Family, family_key_id)
        .await?
    {
        if v.is_current {
            continue;
        }
        let bare = v.snapshot.get("family").unwrap_or(&v.snapshot).clone();
        let Ok(fam) = serde_json::from_value::<Family>(bare) else {
            continue;
        };
        let env = v
            .authorization
            .and_then(|a| a.get("change_envelope").cloned());
        by_hash.insert(fam.persist_row_hash.clone(), (fam, env));
    }
    // Walk back from the head; each step's envelope admitted the step AFTER it.
    let mut chain: Vec<(Family, Option<serde_json::Value>)> = vec![(head, None)];
    loop {
        let prev = chain
            .last()
            .map(|(f, _)| f.prev_head_digest.clone())
            .unwrap_or_default();
        if prev.is_empty() {
            break;
        }
        let Some((fam, env)) = by_hash.remove(&prev) else {
            return refuse(
                ACCORD_RECOVERY_LINEAGE_INCOMPLETE,
                format!(
                    "the accord lineage names {prev} as a predecessor this node does not hold \
                     (CC 4.2.6: the walk follows the links and never steps across a gap)"
                ),
            );
        };
        if let Some(last) = chain.last_mut() {
            last.1 = env;
        }
        chain.push((fam, None));
    }
    chain.reverse();
    Ok(chain)
}

/// v62.0.0 (CC rc20 4.2.6) — every commitment the lineage names, per key id,
/// in link order; every commitment a recovery in it spent; and every recovery
/// statement it records (oldest first).
#[derive(Debug, Default)]
pub(crate) struct CommitmentWalk {
    named: std::collections::BTreeMap<String, Vec<String>>,
    spent: std::collections::BTreeSet<String>,
    /// The lineage's recovery statements, oldest first.
    pub(crate) statements: Vec<serde_json::Value>,
}

impl CommitmentWalk {
    /// The latest commitment named for `key_id` that no recovery has spent.
    /// CC 4.2.6: "A spent commitment never returns: a row that names it again
    /// is read as naming none for that holder."
    pub(crate) fn in_force(&self, key_id: &str) -> Option<String> {
        self.named
            .get(key_id)?
            .iter()
            .rev()
            .find(|c| !self.spent.contains(*c))
            .cloned()
    }

    /// Did a recovery in the lineage spend `commitment`?
    pub(crate) fn is_spent(&self, commitment: &str) -> bool {
        self.spent.contains(commitment)
    }
}

/// v62.0.0 (CC rc20 4.2.6, CIRISPersist#1274; Verify 23.1.0
/// `accord_live_quorum::recovery_commitment_in_force_with_charters`) — **walk
/// the accord's lineage in link order** ([`accord_lineage`]), recording each
/// commitment a row names and each one a recovery spends. A recovery version
/// spends the commitment then in force for its old key and names its
/// `next_recovery_commitment` for the new key. A charter version (the genesis
/// version, or one naming a `charter_digest` other than its predecessor's)
/// names every entry of that charter's `recovery_commitments`; a charter that
/// is not a LIVE row here names nothing (#984 row 5: a withdrawn charter
/// commits nothing).
///
/// # Errors
///
/// As [`accord_lineage`]; directory read failures.
pub(crate) async fn walk_commitments<F>(
    directory: &F,
    family_key_id: &str,
) -> Result<CommitmentWalk, Error>
where
    F: FederationDirectory + ?Sized,
{
    let lineage = accord_lineage(directory, family_key_id).await?;
    let charters: std::collections::HashMap<String, serde_json::Value> =
        super::canonical_community::live_charter_rows(directory, family_key_id)
            .await?
            .into_iter()
            .map(|a| {
                let c = a
                    .attestation_envelope
                    .get(super::envelope::paths::RECOVERY_COMMITMENTS)
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                (a.persist_row_hash, c)
            })
            .collect();
    let mut walk = CommitmentWalk::default();
    for (index, (fam, admitted_by)) in lineage.iter().enumerate() {
        if let Some(st) = admitted_by
            .as_ref()
            .filter(|e| e.get("kind").and_then(|k| k.as_str()) == Some(RECOVERY_STATEMENT_KIND))
        {
            let field = |k: &str| st.get(k).and_then(|v| v.as_str()).unwrap_or_default();
            if let Some(c) = walk.in_force(field("old_holder_key_id")) {
                walk.spent.insert(c);
            }
            let next = field("next_recovery_commitment");
            if !next.is_empty() {
                walk.named
                    .entry(field("new_holder_key_id").to_owned())
                    .or_default()
                    .push(next.to_owned());
            }
            walk.statements.push(st.clone());
        }
        let adopts = index == 0 || fam.charter_digest != lineage[index - 1].0.charter_digest;
        if adopts && !fam.charter_digest.is_empty() {
            if let Some(entries) = charters
                .get(&fam.charter_digest)
                .and_then(|c| c.as_object())
            {
                for (key_id, c) in entries {
                    if let Some(c) = c.as_str() {
                        walk.named
                            .entry(key_id.clone())
                            .or_default()
                            .push(c.to_owned());
                    }
                }
            }
        }
    }
    Ok(walk)
}

/// **The recovery commitment in force for `holder`** (CC rc20 4.2.6): "The
/// commitment **in force** for a holder is the one named by the latest row of
/// the accord's lineage that names one for that holder: a recovery version or
/// a charter version." Latest follows the `prev_head_digest` links, never
/// instants ([`walk_commitments`]), and a spent commitment named again names
/// none. `None` when the holder holds no seat at the head, or no row names an
/// unspent commitment for them.
///
/// Persist keeps one stricter precondition from v53.1.2 (#984 rows 3 and 5):
/// the head must name a charter that is a LIVE row here, else `None` (no
/// version the accord door admits can name another, so this only bites when
/// the head's charter was withdrawn after the head named it).
///
/// v62.0.0 replaced the v53.1.2 reading ("the latest recovery under the
/// charter in force, else that charter's entry"), which read recoveries in
/// version-number order and could return a commitment a recovery had spent.
///
/// # Errors
///
/// `accord_recovery_lineage_incomplete`; directory read failures.
pub async fn recovery_commitment_in_force<F>(
    directory: &F,
    family_key_id: &str,
    holder: &str,
) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let (charter_key, head) = charter_in_force(directory, family_key_id).await?;
    let HeadCharter::Named(digest) = &head else {
        return Ok(None);
    };
    if super::canonical_community::live_charter_row(directory, &charter_key, digest)
        .await?
        .is_none()
    {
        // v62.0.0 (slice E2a) — a head charter this node does not hold at all
        // is a gap in the lineage: fail closed, never read as "no charter"
        // (Verify's `charter_missing`). A held, withdrawn one names nothing.
        if !super::canonical_community::charter_row_held(directory, &charter_key, digest).await? {
            return refuse(
                ACCORD_RECOVERY_LINEAGE_INCOMPLETE,
                format!(
                    "the accord's head names charter {digest}, which this node does not hold \
                     (CC 4.2.6: a charter row the walk needs and is not given fails closed)"
                ),
            );
        }
        return Ok(None);
    }
    let Some(fam) = directory.lookup_family(family_key_id).await? else {
        return Ok(None);
    };
    if !fam.members.iter().any(|m| m.key_id == holder) {
        return Ok(None);
    }
    Ok(walk_commitments(directory, family_key_id)
        .await?
        .in_force(holder))
}

/// **Is `signed` a valid recovery version of the held accord?** `Ok(None)`
/// when it is not shaped as one (no recovery statement); `Ok(Some(new
/// holder))` when it is and every check holds; `Err` naming the first check
/// that fails.
///
/// # Errors
///
/// [`Error::CharterInvalid`] with an `accord_recovery_*` token; directory read
/// failures.
pub async fn verify_accord_recovery<F>(
    directory: &F,
    signed: &SignedFamily,
) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    // CC 4.2.6 is the accord's rule; no other family rotates a seat this way.
    if signed.family.family_key_id
        != ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID
    {
        return Ok(None);
    }
    let Some(proof) = signed.supersede_proof.as_ref() else {
        return Ok(None);
    };
    let st = &proof.change_envelope;
    if st.get("kind").and_then(|k| k.as_str()) != Some(RECOVERY_STATEMENT_KIND) {
        return Ok(None);
    }
    let field = |k: &str| st.get(k).and_then(|v| v.as_str()).unwrap_or_default();
    let offered = &signed.family;
    let (old, new, recovery_key_id, next_commitment) = (
        field("old_holder_key_id"),
        field("new_holder_key_id"),
        field("recovery_key_id"),
        field("next_recovery_commitment"),
    );
    // v62.0.0 (wave GC3; CC 2.7.3) — every check below that reads the held
    // accord, its lineage or a key record is a FOLD condition: declared here,
    // and held (`hold_on`) rather than refused. The checks on the statement's
    // own bytes stay refusals.
    {
        use super::edition2::fold::{reads, Dep};
        reads(Dep::key(&offered.family_key_id));
        for k in [old, new, recovery_key_id] {
            if !k.is_empty() {
                reads(Dep::key(k));
            }
        }
    }
    // The statement's own bytes: it names this family and the offered
    // version's content hash.
    if field("family_key_id") != offered.family_key_id
        || field("next_persist_row_hash") != super::types::compute_persist_row_hash(offered)?
    {
        return refuse(
            "accord_recovery_statement_unbound",
            "the statement must name this family, the held head it replaces and the offered \
             version's content hash, and the version must name the held head",
        );
    }
    let Some(held) = directory.lookup_family(&offered.family_key_id).await? else {
        return hold_on(
            held_reason::ACCORD_RECOVERY_NO_HELD_ACCORD,
            &offered.family_key_id,
        );
    };
    // The statement and the version name the held head (another row).
    if field("prior_persist_row_hash") != held.persist_row_hash
        || proof.prior_persist_row_hash != held.persist_row_hash
        || offered.prev_head_digest != held.persist_row_hash
    {
        return hold_on(
            held_reason::ACCORD_RECOVERY_STATEMENT_UNBOUND,
            "the statement must name this family, the held head it replaces and the offered \
             version's content hash, and the version must name the held head",
        );
    }
    // Exactly one seat moves, old -> new; nothing else but the head.
    let mut expected = held.clone();
    expected.persist_row_hash = String::new();
    expected.prev_head_digest = held.persist_row_hash.clone();
    let Some(seat) = expected.members.iter_mut().find(|m| m.key_id == old) else {
        return hold_on(
            held_reason::ACCORD_RECOVERY_NOT_A_HOLDER,
            format!("{old} holds no seat"),
        );
    };
    // v62.0.0 (CC rc20 4.2.6) — "A recovery that names as the new signing key
    // either the holder's current signing key or the recovery key itself
    // concludes nothing." Each has its own token (until v62 the first read as
    // `accord_recovery_seat_taken`, a side effect of the old key's own seat).
    if new == old {
        return refuse(
            ACCORD_RECOVERY_REUSES_SIGNING_KEY,
            format!("the recovery names {old}, the holder's current signing key (CC 4.2.6)"),
        );
    }
    if new == recovery_key_id {
        return refuse(
            ACCORD_RECOVERY_KEY_AS_SIGNING_KEY,
            format!("the recovery seats its own recovery key {recovery_key_id} (CC 4.2.6)"),
        );
    }
    if new.is_empty() {
        return refuse(
            "accord_recovery_seat_taken",
            format!("{new} already holds a seat"),
        );
    }
    if held.members.iter().any(|m| m.key_id == new) {
        return hold_on(
            held_reason::ACCORD_RECOVERY_SEAT_TAKEN,
            format!("{new} already holds a seat"),
        );
    }
    // v53.0.0 (CC 4.2.6) — the key taking the seat is an accord holder's key.
    if !super::accord_roster::is_accord_holder_key(directory, new).await? {
        return hold_on(
            held_reason::ACCORD_RECOVERY_NOT_A_HOLDER_KEY,
            format!("{new} is not an accord_holder key record (CC 4.2.6)"),
        );
    }
    let joined_at = offered
        .members
        .iter()
        .find(|m| m.key_id == new)
        .map(|m| m.joined_at)
        .unwrap_or(seat.joined_at);
    *seat = FamilyMember {
        key_id: new.to_owned(),
        joined_at,
        role: seat.role.clone(),
    };
    let mut bare = offered.clone();
    bare.persist_row_hash = String::new();
    if bare != expected {
        return hold_on(
            held_reason::ACCORD_RECOVERY_CHANGES_MORE_THAN_ITS_SEAT,
            "a recovery swaps the holder's own seat and changes nothing else (CC 4.2.6)",
        );
    }
    // The record is signed by the key that takes the seat.
    if signed.authority_key_id != new {
        return refuse(
            "accord_recovery_record_not_signed_by_new_key",
            format!(
                "the version is signed by {}, not {new}",
                signed.authority_key_id
            ),
        );
    }
    if !well_formed_commitment(next_commitment) {
        return refuse(
            "accord_recovery_next_commitment_malformed",
            "the new key's recovery commitment is not 64 lowercase hex",
        );
    }
    // The recovery key: its STORED material reproduces the old holder's
    // commitment in force, it has not rotated a seat before, and it signed.
    let Some(in_force) = recovery_commitment_in_force(directory, &held.family_key_id, old).await?
    else {
        return hold_on(
            held_reason::ACCORD_RECOVERY_COMMITMENT_MISSING,
            format!("no recovery commitment is in force for {old}"),
        );
    };
    let Some(record) = directory.lookup_public_key(recovery_key_id).await? else {
        return hold_on(
            held_reason::ACCORD_RECOVERY_KEY_UNREGISTERED,
            format!("recovery key {recovery_key_id} is not registered"),
        );
    };
    let presented = CommittedKey::from_record(&record)
        .and_then(|k| recovery_commitment(&k))
        .map_err(|e| {
            super::edition2::fold::hold(
                held_reason::ACCORD_RECOVERY_KEY_MISMATCH,
                Error::CharterInvalid {
                    detail: format!("accord_recovery_key_mismatch: {e}"),
                },
            )
        })?;
    // v62.0.0 (CC rc20 4.2.6) — the lineage, walked in link order.
    let walk = walk_commitments(directory, &held.family_key_id).await?;
    // v62.0.0 (slice E2a; Verify's accord_recovery_refusals_v2
    // `spent_commitment_relisted`) — a spent recovery key is named spent
    // BEFORE its material is compared with the commitment in force: a spent
    // commitment a later charter re-lists names none (CC 4.2.6), so the
    // mismatch below would hide the more specific refusal.
    // Over the WHOLE lineage: a recovery key that rotated a seat is spent
    // under every charter since (#984 row 3 bounds the exception, not this),
    // by id or by the commitment its material reproduces.
    let spent_by_id = walk
        .statements
        .iter()
        .any(|s| s.get("recovery_key_id").and_then(|v| v.as_str()) == Some(recovery_key_id));
    if spent_by_id || walk.is_spent(&presented) {
        return hold_on(
            held_reason::ACCORD_RECOVERY_KEY_SPENT,
            format!("{recovery_key_id} already rotated a seat"),
        );
    }
    if presented != in_force {
        return hold_on(
            held_reason::ACCORD_RECOVERY_KEY_MISMATCH,
            format!(
                "the stored keys of {recovery_key_id} do not reproduce {old}'s recovery \
                 commitment (an id that matches with other keys is not the committed key)"
            ),
        );
    }
    // "The next commitment MUST differ from the one the recovery spends", and
    // "a spent commitment never returns": neither the one in force nor one a
    // recovery already spent.
    if next_commitment == in_force || walk.is_spent(next_commitment) {
        return hold_on(
            held_reason::ACCORD_RECOVERY_NEXT_COMMITMENT_NOT_FRESH,
            "the new key's recovery commitment repeats the one it spends or one already spent",
        );
    }
    // v62.0.0 (CC rc20 4.2.6) — "A recovery key is spent by the recovery it
    // signs and never becomes a seat's signing key, under any id; the test is
    // the public key material, not the id." The new key's material is neither
    // this recovery key's nor any recovery key the lineage spent.
    let Some(new_record) = directory.lookup_public_key(new).await? else {
        return hold_on(
            held_reason::ACCORD_RECOVERY_NOT_A_HOLDER_KEY,
            format!("{new} is not registered"),
        );
    };
    let mut recovery_keys = vec![record.clone()];
    for st in &walk.statements {
        if let Some(id) = st.get("recovery_key_id").and_then(|v| v.as_str()) {
            if let Some(r) = directory.lookup_public_key(id).await? {
                recovery_keys.push(r);
            }
        }
    }
    let same_material = |a: &super::KeyRecord, b: &super::KeyRecord| {
        a.pubkey_ed25519_base64 == b.pubkey_ed25519_base64
            || (a.pubkey_ml_dsa_65_base64.is_some()
                && a.pubkey_ml_dsa_65_base64 == b.pubkey_ml_dsa_65_base64)
    };
    if let Some(r) = recovery_keys.iter().find(|r| same_material(&new_record, r)) {
        return hold_on(
            held_reason::ACCORD_RECOVERY_KEY_AS_SIGNING_KEY,
            format!(
                "{new} carries the public key material of recovery key {} (CC 4.2.6: a \
                 recovery key never becomes a seat's signing key, under any id)",
                r.key_id
            ),
        );
    }
    let [sig] = proof.quorum_signatures.as_slice() else {
        return refuse(
            "accord_recovery_signature",
            "a recovery carries exactly one signature: the recovery key's",
        );
    };
    if sig.member_id != recovery_key_id {
        return refuse(
            "accord_recovery_signature",
            format!("signed by {}, not the recovery key", sig.member_id),
        );
    }
    let bytes = crate::verify::canonical::ceg_produce_canonicalize(st)
        .map_err(|e| Error::InvalidArgument(format!("recovery canonicalize: {e}")))?;
    crate::verify::hybrid::verify_hybrid(
        &bytes,
        &sig.ed25519_signature_base64,
        sig.mldsa65_signature_base64.as_deref(),
        &record.pubkey_ed25519_base64,
        record.pubkey_ml_dsa_65_base64.as_deref(),
        crate::verify::hybrid::HybridPolicy::Strict,
        None,
    )
    .map_err(|e| Error::CharterInvalid {
        detail: format!("accord_recovery_signature: {e}"),
    })?;
    Ok(Some(new.to_owned()))
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod codex_978 {
    use super::*;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::genesis::accord_family_genesis_record_for;
    use crate::federation::types::identity_type;

    /// **I504 — a non-accord family cannot take the recovery door** (Codex on
    /// #978): `verify_accord_recovery` answers `None` for any family that is
    /// not the accord, and the door refuses by name instead of reaching the
    /// already-verified supersede. The family is unchanged.
    async fn non_accord_family_is_refused(d: &dyn FederationDirectory, tag: &str) {
        let fid = format!("i504-family-{tag}");
        // v62.0.0: the founders are live by their edition-2 `key:record`s and
        // named by kid.
        let (a, b) = (format!("i504-a-{tag}"), format!("i504-b-{tag}"));
        for k in [&a, &b] {
            let _ = e2::put_key(d, k, &[identity_type::USER]).await;
        }
        let (a, b) = (e2::kid(&a), e2::kid(&b));
        let family =
            accord_family_genesis_record_for(&fid, "quorum:2/2", [a.as_str(), b.as_str()], "");
        d.put_family_local(family).await.unwrap();
        let held = d.lookup_family(&fid).await.unwrap().unwrap();
        // A hand-built draft (every field is public): the family renamed,
        // chained on the held head, "signed" by nobody in particular.
        let mut next = held.clone();
        next.family_name = "hijacked".to_owned();
        next.persist_row_hash = String::new();
        next.prev_head_digest = held.persist_row_hash.clone();
        let draft = AccordRecoveryDraft {
            next,
            statement: serde_json::json!({ "kind": "i504" }),
            statement_bytes: b"i504".to_vec(),
            record_bytes: b"i504".to_vec(),
        };
        let err = recover_accord_holder(
            d,
            draft,
            ("c2ln".to_owned(), "c2ln".to_owned()),
            ("c2ln".to_owned(), "c2ln".to_owned()),
        )
        .await
        .expect_err("I504: refused");
        assert!(
            err.to_string()
                .contains("accord_recovery_not_an_accord_family"),
            "{tag} I504: {err}"
        );
        let after = d.lookup_family(&fid).await.unwrap().unwrap();
        assert_eq!(
            after.persist_row_hash, held.persist_row_hash,
            "{tag} I504: unchanged"
        );
        assert_eq!(after.family_name, held.family_name, "{tag} I504: unchanged");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i504_sqlite() {
        use crate::store::Backend as _;
        let d = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        non_accord_family_is_refused(&d, "sqlite").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i504_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let d = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        non_accord_family_is_refused(&d, &uuid::Uuid::new_v4().simple().to_string()).await;
    }
}
