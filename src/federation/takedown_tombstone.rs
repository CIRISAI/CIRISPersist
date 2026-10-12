//! v55.0.0 (CIRISPersist#1007; CC 4.5.3 step 2, CC 4.5.5, CC 2.3, CC 3.1.3.3
//! rule 4) — **the duty-holder takedown, on the CC 2.3 tombstone.**
//!
//! A takedown used to be a set of `withdraws` rows: the moderation path
//! withdrew every holder's `holds_bytes` claim and, for an immediate-removal
//! basis, ran `evict_actor` on each holder. Two things were wrong with that.
//! A `withdraws` of another device's holding claim is not the holder's act
//! (CC 3.1.3.3 rule 4: "nobody withdraws another device's report, and a
//! takedown is the CC 2.3 tombstone path"), so the fold ignored those rows and
//! the door could only admit them inert. And `evict_actor(holder)` deleted
//! every blob the holder held, not the one taken down.
//!
//! Now a takedown is ONE tombstone on the bytes plane, written in the same
//! table and row shape as the steward purge's (CC 4.5.3 step 2, confirmed by
//! the Constitution session: one tombstone row shape across both bases, one
//! row per record keyed by its digest). What differs is the admission and the
//! reach:
//!
//! - **Admission (CC 4.5.5).** The notice is a signed `takedown_notice`
//!   Contribution ([`TakedownNotice`]). The door verifies its signature, then
//!   asks THIS node's own state whether the signer holds the `takedown` duty
//!   over the content: a signed subject of the content, a named moderator of
//!   its community, or a delegate a steward-bound one reaches through a live
//!   `takedown`-scoped chain ([`verify_takedown_authority`]). Never a verdict
//!   the caller hands in.
//! - **Reach: the bytes plane only.** A takedown tombstones ONE record,
//!   `blob:{content_sha256}`. A replicated takedown naming anything else is
//!   refused ([`token::NOT_BYTES_PLANE`]); a claim row is never a takedown's
//!   to retract.
//! - **Per basis** ([`basis_disposition`]). An immediate-removal basis (CC
//!   4.5.3: `tvec_terrorist`, `ncmec_csam`, `gifct_cip`,
//!   `perceptual_hash_csam`, `court_order`) settles at once: the Engine
//!   destroys the bytes on receipt, and the node records
//!   `hard_case:fast_path_takedown` (CC 4.5.3 step 4). The fast path waives
//!   the CC 4.5.1 quorum and the counter notice, never the duty-holder gate. A counter-notice basis (`dmca_512`,
//!   `dsa_article_16`, `osa_illegal_content`, `community_standards`)
//!   withholds the bytes at once and settles after its counter-notice window,
//!   when `purge_finalize` hard-deletes them. The age-gate basis
//!   (`avmsd_age_inappropriate`) is not a removal: it writes no tombstone,
//!   and the receiver's display gate filters (CEG §8.1.10).
//!
//! The tombstone replicates as a [`PurgeBundle`](super::steward_purge::PurgeBundle)
//! like a purge's; the receiver re-verifies the signature and re-asks CC 4.5.5
//! against ITS OWN state ([`apply_replicated_takedown`]).
//!
//! A holder's own claim is still the holder's: the Engine retracts THIS node's
//! holding claim for the taken-down bytes (the holder re-acknowledging `none`,
//! CC 4.5.3 step 2), and the withdraws door refuses every non-holder's
//! `withdraws` of a holding claim (`custody_ack_withdraws_not_the_holder`).

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use super::steward_purge::{
    self as sp, origin, PurgeExecution, PurgePlane, PurgeTombstone, STEWARD_PURGE_BASIS,
};
use super::{Error, FederationDirectory};

/// The closed set of refusal tokens this door raises, each the
/// [`Error::kind`] of an [`Error::PurgeRefused`] (the one tombstone plane's
/// error). Persist-local.
pub mod token {
    /// The notice is malformed, its signature does not verify, its basis is
    /// outside the closed set, it is outside its window, or its signer holds
    /// no `takedown` duty over the content on this node (CC 4.5.5). Body:
    /// `{notice_id?, reason}`.
    pub const UNAUTHORISED: &str = "takedown_unauthorised";
    /// A replicated takedown names a record other than the notice's own
    /// content on the bytes plane: a takedown reaches the bytes plane only
    /// (CC 4.5.3 step 2), and a duty-holder tombstone against a claim row is
    /// refused. Body: `{notice_id, record_ids}`.
    pub const NOT_BYTES_PLANE: &str = "takedown_not_bytes_plane";

    /// RETRYABLE — this node holds no row that binds the content, so it
    /// cannot tell whose content it is (the content's community and its
    /// signed subjects are read from the binding rows, never from the
    /// notice). An ordering gap: re-offer once the binding row has
    /// replicated here. Body: `{content_sha256, retryable: true}`.
    pub const CONTENT_UNBOUND: &str = "takedown_content_unbound";
    /// Every token. (Taken-down bytes re-offered at a write door are
    /// `BlobError::Purged`, the read doors' own answer, for a takedown and a
    /// purge alike: one tombstone plane, one refusal.)
    pub const ALL: &[&str] = &[UNAUTHORISED, NOT_BYTES_PLANE, CONTENT_UNBOUND];
}

/// The `subject_kind` of a takedown notice Contribution (CC 3.3.2).
pub const TAKEDOWN_NOTICE_SUBJECT_KIND: &str = "takedown_notice";

/// CC 4.5.3's immediate-removal bases, by wire string: no counter notice, and
/// a reachable holder MUST destroy the bytes on receipt.
pub const IMMEDIATE_REMOVAL_BASES: &[&str] = &[
    "tvec_terrorist",
    "ncmec_csam",
    "gifct_cip",
    "perceptual_hash_csam",
    "court_order",
];

/// The expeditious-with-counter-notice bases and their counter-notice
/// windows in days (the cirisnode `LegalBasis::counter_notice_window_days`
/// defaults, CEG 0.3 §5.6.8.4).
pub const COUNTER_NOTICE_BASES: &[(&str, i64)] = &[
    ("dmca_512", 10),
    ("dsa_article_16", 14),
    ("osa_illegal_content", 14),
    ("community_standards", 30),
];

/// The age-gate basis: an age-assurance gate, not a removal.
pub const AGE_GATE_BASIS: &str = "avmsd_age_inappropriate";

/// What a takedown basis does to the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TakedownDisposition {
    /// Tombstone, and destroy the bytes on receipt (CC 4.5.3).
    DestroyOnReceipt,
    /// Tombstone (the bytes are withheld at once), and hard-delete them after
    /// the counter-notice window.
    WithholdThenDelete {
        /// The window, in days.
        window_days: i64,
    },
    /// No tombstone: the receiver's display gate filters (CEG §8.1.10).
    AgeGate,
}

/// The disposition of a `legal_basis` wire string, or `None` for a string
/// outside the closed set. `steward_purge` is not a takedown basis: it is
/// the trust root's cosigned purge (`steward_purge::purge_rows`).
#[must_use]
pub fn basis_disposition(legal_basis: &str) -> Option<TakedownDisposition> {
    if IMMEDIATE_REMOVAL_BASES.contains(&legal_basis) {
        return Some(TakedownDisposition::DestroyOnReceipt);
    }
    if legal_basis == AGE_GATE_BASIS {
        return Some(TakedownDisposition::AgeGate);
    }
    COUNTER_NOTICE_BASES
        .iter()
        .find(|(b, _)| *b == legal_basis)
        .map(|(_, d)| TakedownDisposition::WithholdThenDelete { window_days: *d })
}

/// When a recorded tombstone settles, by its header's `legal_basis`: a
/// steward purge after `W` = 72 h, an immediate-removal takedown at once, a
/// counter-notice takedown after its window. A basis outside both sets
/// settles as a purge does (never earlier). `purge_finalize` hard-deletes
/// only at or after this instant.
#[must_use]
pub fn settles_at(execution: &PurgeExecution) -> chrono::DateTime<chrono::Utc> {
    let purge = execution.executed_at + chrono::Duration::seconds(sp::PURGE_SETTLE_DWELL_SECS);
    if execution.legal_basis == STEWARD_PURGE_BASIS {
        return purge;
    }
    match basis_disposition(&execution.legal_basis) {
        Some(TakedownDisposition::DestroyOnReceipt) => execution.executed_at,
        Some(TakedownDisposition::WithholdThenDelete { window_days }) => {
            execution.executed_at + chrono::Duration::days(window_days)
        }
        Some(TakedownDisposition::AgeGate) | None => purge,
    }
}

/// A signed `takedown_notice` Contribution, as the cirisnode door verified and
/// stored it: the `ContributionEnvelope` serialized to JSON, signature
/// included. The door re-verifies it; nothing in it is trusted unverified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakedownNotice {
    /// The envelope.
    pub envelope: serde_json::Value,
}

/// A takedown notice's verified terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakedownTerms {
    /// `hex(sha256(JCS(envelope)))`, signature included — the notice id the
    /// tombstone cites.
    pub notice_id: String,
    /// The envelope's JCS text: the header's `notice_jcs`.
    pub notice_jcs: String,
    /// The verified signer (`author_id`).
    pub signer: String,
    /// The payload's `claimant_key_id`.
    pub claimant_key_id: String,
    /// The content, lowercase hex.
    pub content_sha256: String,
    /// The `legal_basis` wire string.
    pub legal_basis: String,
    /// Its disposition.
    pub disposition: TakedownDisposition,
    /// The notice's own instant.
    pub asserted_at: chrono::DateTime<chrono::Utc>,
    /// When it stops authorising.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl TakedownTerms {
    /// The one record a takedown tombstones.
    #[must_use]
    pub fn record_id(&self) -> String {
        format!("{}:{}", PurgePlane::Blob.as_str(), self.content_sha256)
    }
}

fn refused(token: &'static str, body: serde_json::Value) -> Error {
    Error::PurgeRefused { token, body }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Is `envelope` a takedown notice Contribution (rather than a steward purge
/// notice)? A shape question only; [`takedown_terms`] verifies it.
#[must_use]
pub fn is_takedown_notice_envelope(envelope: &serde_json::Value) -> bool {
    envelope
        .pointer("/subject/subject")
        .and_then(serde_json::Value::as_str)
        == Some(TAKEDOWN_NOTICE_SUBJECT_KIND)
        && envelope.get("author_id").is_some()
}

/// Parse and VERIFY a takedown notice: its shape, the closed-set basis, and
/// the signature over the envelope (the cirisnode track's own rule: the
/// `author_id` IS the Ed25519 pubkey, the envelope minus its signature is the
/// signed body, `Ed25519Fallback`, exactly as `put_contribution` verifies it).
/// Every failure is [`token::UNAUTHORISED`].
///
/// # Errors
///
/// [`token::UNAUTHORISED`] naming the member or the failed check.
pub fn takedown_terms(notice: &TakedownNotice) -> Result<TakedownTerms, Error> {
    let env = &notice.envelope;
    let jcs = ciris_verify_core::jcs::canonicalize(env).map_err(|e| {
        refused(
            token::UNAUTHORISED,
            serde_json::json!({"reason": format!("the notice does not canonicalize: {e}")}),
        )
    })?;
    let notice_id = hex::encode(sha2::Sha256::digest(&jcs));
    let notice_jcs = String::from_utf8(jcs)
        .map_err(|e| Error::Backend(format!("notice JCS is not UTF-8: {e}")))?;
    let unauth = |reason: String| {
        refused(
            token::UNAUTHORISED,
            serde_json::json!({"notice_id": notice_id, "reason": reason}),
        )
    };
    if !is_takedown_notice_envelope(env) {
        return Err(unauth(format!(
            "not a `{TAKEDOWN_NOTICE_SUBJECT_KIND}` Contribution"
        )));
    }
    let s = |v: Option<&serde_json::Value>, k: &str| -> Result<String, Error> {
        match v.and_then(serde_json::Value::as_str) {
            Some(x) if !x.trim().is_empty() => Ok(x.to_owned()),
            _ => Err(unauth(format!("the notice carries no non-empty `{k}`"))),
        }
    };
    let signer = s(env.get("author_id"), "author_id")?;
    let ed25519 = s(env.pointer("/signature/ed25519"), "signature.ed25519")?;
    let ml_dsa = env
        .pointer("/signature/ml_dsa_65")
        .and_then(serde_json::Value::as_str);
    let canonical = crate::verify::canonical::canonicalize_envelope_for_signing(env)
        .map_err(|e| unauth(format!("the notice does not canonicalize for signing: {e}")))?;
    crate::verify::hybrid::verify_hybrid(
        &canonical,
        &ed25519,
        ml_dsa,
        &signer,
        // The cirisnode track has no per-contributor ML-DSA-65 key; the same
        // pinned policy as `cirisnode::verify::verify_envelope_signed`.
        None,
        crate::verify::hybrid::HybridPolicy::Ed25519Fallback,
        None,
    )
    .map_err(|e| unauth(format!("the notice's signature does not verify: {e}")))?;
    let payload = env
        .get("payload")
        .ok_or_else(|| unauth("the notice carries no payload".to_owned()))?;
    let content_sha256 = s(payload.get("content_sha256"), "content_sha256")?;
    if !is_hex64(&content_sha256) {
        return Err(unauth("content_sha256 is not 64 lowercase hex".to_owned()));
    }
    let claimant_key_id = s(payload.get("claimant_key_id"), "claimant_key_id")?;
    let legal_basis = s(payload.get("legal_basis"), "legal_basis")?;
    let disposition = basis_disposition(&legal_basis).ok_or_else(|| {
        unauth(format!(
            "legal_basis {legal_basis:?} is not a takedown basis (the closed set of CC 3.3.2; \
             `{STEWARD_PURGE_BASIS}` is the trust root's cosigned purge)"
        ))
    })?;
    let instant = |k: &str| -> Result<chrono::DateTime<chrono::Utc>, Error> {
        let raw = s(payload.get(k), k)?;
        chrono::DateTime::parse_from_rfc3339(&raw)
            .map(|t| t.with_timezone(&chrono::Utc))
            .map_err(|e| unauth(format!("`{k}` is not RFC 3339: {e}")))
    };
    let asserted_at = instant("asserted_at")?;
    let expires_at = instant("expires_at")?;
    if expires_at <= asserted_at {
        return Err(unauth("expires_at must be after asserted_at".to_owned()));
    }
    Ok(TakedownTerms {
        notice_id,
        notice_jcs,
        signer,
        claimant_key_id,
        content_sha256,
        legal_basis,
        disposition,
        asserted_at,
        expires_at,
    })
}

/// **CC 4.5.5, asked of THIS node's state at `now`.** The notice is inside
/// its window, and [`takedown_authority`] admits its verified signer over
/// the content as this node holds it. The same decision `put_contribution`
/// runs on the notice, re-asked at execution: standing that lapsed since the
/// notice was filed authorises nothing.
///
/// # Errors
///
/// [`token::UNAUTHORISED`], [`token::CONTENT_UNBOUND`]; directory reads.
pub async fn verify_takedown_authority(
    directory: &dyn FederationDirectory,
    terms: &TakedownTerms,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error> {
    let unauth = |reason: String| {
        refused(
            token::UNAUTHORISED,
            serde_json::json!({"notice_id": terms.notice_id, "reason": reason}),
        )
    };
    if terms.asserted_at > now + super::admission::DEFAULT_MAX_TOUCH_SKEW {
        return Err(unauth(format!(
            "the notice is asserted at {}, in the future",
            terms.asserted_at.to_rfc3339()
        )));
    }
    if terms.expires_at <= now {
        return Err(unauth(format!(
            "the notice expired at {}",
            terms.expires_at.to_rfc3339()
        )));
    }
    takedown_authority(
        directory,
        &terms.signer,
        &terms.content_sha256,
        &terms.legal_basis,
    )
    .await
    .map_err(|e| match e {
        Error::PurgeRefused { token, mut body } => {
            body["notice_id"] = serde_json::json!(terms.notice_id);
            Error::PurgeRefused { token, body }
        }
        other => other,
    })
}

/// The communities `content_sha256` is bound into ON THIS NODE: every held
/// row that binds the content (its `evidence_refs` name the digest), at
/// `community` scope, names its community. `None` when no binding row is
/// held — whose content it is cannot be told here. Never read from a notice.
///
/// Codex r2 on #1065 — only LIVE bindings confer authority: a row expired at
/// the read instant, or retired by a `withdraws` / `recants` (the bytes-plane
/// fold, `blob_tombstone::retiring_composer`, with every entitlement
/// re-derived now), names no subject and no community. A former subject or a
/// former room's moderator never authorizes through a retired row. Each live
/// row's subjects are its `subject_key_ids` AND its non-empty
/// `attested_key_id` (the purge subject helper's reading), and its room is
/// the `community_id` of a `community` or `affiliations` row.
///
/// # Errors
///
/// Directory reads.
pub async fn content_binding(
    directory: &dyn FederationDirectory,
    content_sha256: &str,
) -> Result<Option<ContentBinding>, Error> {
    if !is_hex64(content_sha256) {
        return Ok(None);
    }
    let rows = directory
        .attestations_binding_content(content_sha256)
        .await?;
    if rows.is_empty() {
        return Ok(None);
    }
    let mut out = ContentBinding::default();
    let now = chrono::Utc::now();
    for row in rows {
        if row.expires_at.is_some_and(|e| e <= now)
            || super::blob_tombstone::retiring_composer(directory, &row)
                .await?
                .is_some()
        {
            continue;
        }
        out.subjects.extend(row.subject_key_ids.iter().cloned());
        if !row.attested_key_id.is_empty() {
            out.subjects.insert(row.attested_key_id.clone());
        }
        if matches!(
            row.cohort_scope.as_str(),
            super::types::cohort_scope::COMMUNITY | super::types::cohort_scope::AFFILIATIONS
        ) {
            if let Some(c) = row
                .attestation_envelope
                .get("community_id")
                .and_then(serde_json::Value::as_str)
                .filter(|c| !c.is_empty())
            {
                out.communities.insert(c.to_owned());
            }
        }
    }
    Ok(Some(out))
}

/// What this node's held binding rows say about a content digest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentBinding {
    /// The SIGNED subjects of the binding rows (CC 4.5.5 `subject_of`).
    pub subjects: std::collections::BTreeSet<String>,
    /// The communities the content is bound into.
    pub communities: std::collections::BTreeSet<String>,
}

/// **THE takedown authority decision** (CC 4.5.5), in one place: the
/// `put_contribution` gate on a `takedown_notice` and the tombstone door both
/// call it. The signer must hold the `takedown` duty over the content as
/// THIS node holds it: a signed subject of a row binding the content, a
/// named moderator of a community the content is bound into, or a delegate a
/// steward-bound duty-holder reaches over a live `takedown`-scoped chain. The
/// content's community is the held binding's, never a community the notice
/// names. No binding row held is [`token::CONTENT_UNBOUND`] (retryable).
///
/// `legal_basis` is not consulted: every basis needs a duty-holder (operator
/// ruling, v55 slice C). Were CC to admit an immediate-removal basis from any
/// claimant, that is a one-line change here.
///
/// # Errors
///
/// [`token::UNAUTHORISED`], [`token::CONTENT_UNBOUND`]; directory reads.
pub async fn takedown_authority(
    directory: &dyn FederationDirectory,
    signer: &str,
    content_sha256: &str,
    _legal_basis: &str,
) -> Result<(), Error> {
    let Some(binding) = content_binding(directory, content_sha256).await? else {
        return Err(refused(
            token::CONTENT_UNBOUND,
            serde_json::json!({
                "content_sha256": content_sha256,
                "retryable": true,
                "reason": "no row binding the content is held here, so whose content it is \
                           cannot be told; re-offer once it has replicated",
            }),
        ));
    };
    let duty = super::admission::DELEGATION_SCOPE_TAKEDOWN;
    let mut holders: std::collections::HashSet<String> = binding.subjects.iter().cloned().collect();
    for community in &binding.communities {
        holders.extend(super::admission::community_duty_roots(directory, community, duty).await?);
    }
    match super::admission::check_moderation_admission(
        directory,
        signer,
        &holders,
        duty,
        TAKEDOWN_NOTICE_SUBJECT_KIND,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(Error::DelegatedScopeUnauthorized { .. }) => Err(refused(
            token::UNAUTHORISED,
            serde_json::json!({
                "signer": signer,
                "content_sha256": content_sha256,
                "communities": binding.communities,
                "reason": "the signer holds neither the takedown duty over the content as itself \
                           nor a live takedown-scoped delegates_to chain from a steward-bound \
                           duty-holder, under the content's own binding here (CC 4.5.5)",
            }),
        )),
        Err(e) => Err(e),
    }
}

/// What a takedown did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakedownReport {
    /// The notice id the tombstone cites.
    pub notice_id: String,
    /// The content taken down, lowercase hex.
    pub content_sha256: String,
    /// The notice's `legal_basis`.
    pub legal_basis: String,
    /// What the basis does to the bytes.
    pub disposition: TakedownDisposition,
    /// The verified signer.
    pub signer: String,
    /// `true` when THIS call wrote the tombstone; `false` when it was already
    /// held, or for the age-gate basis (which writes none).
    pub tombstoned: bool,
    /// When `purge_finalize` may hard-delete the bytes (`None`: no tombstone).
    pub settles_at: Option<chrono::DateTime<chrono::Utc>>,
    /// This node's own holding claims the Engine retracted (the holder
    /// re-acknowledging `none`). The federation door retracts nothing.
    #[serde(default)]
    pub claims_retracted: u64,
    /// `true` when the Engine destroyed the bytes on receipt (an
    /// immediate-removal basis).
    #[serde(default)]
    pub bytes_destroyed: bool,
}

/// **The takedown door**, at the purge clock: verify the notice
/// ([`takedown_terms`]), re-ask CC 4.5.5 ([`verify_takedown_authority`]), and
/// record the header and its one bytes-plane tombstone in ONE transaction
/// (the steward purge's `purge_put_execution`; idempotent on the notice id).
/// The age-gate basis records nothing. Deletes nothing: the Engine destroys an
/// immediate-removal basis's bytes on receipt through `purge_finalize`, which
/// a counter-notice basis reaches after its window.
///
/// # Errors
///
/// [`token::UNAUTHORISED`]; directory reads and writes.
pub async fn takedown_tombstone(
    directory: &dyn FederationDirectory,
    notice: &TakedownNotice,
    executed_by: &str,
) -> Result<TakedownReport, Error> {
    let now = sp::purge_clock();
    let terms = takedown_terms(notice)?;
    verify_takedown_authority(directory, &terms, now).await?;
    record(directory, &terms, executed_by, origin::LOCAL, now).await
}

/// **Apply a replicated takedown** (a [`PurgeBundle`](super::steward_purge::PurgeBundle)
/// whose notice is a takedown Contribution). The receiver trusts nothing the
/// sender says: it verifies the signature, re-asks CC 4.5.5 against its OWN
/// state, and requires the bundle to name exactly the notice's own content on
/// the bytes plane ([`token::NOT_BYTES_PLANE`]). An age-gate notice carries no
/// tombstone to apply and is refused as unauthorised.
///
/// # Errors
///
/// [`token::UNAUTHORISED`], [`token::NOT_BYTES_PLANE`]; directory writes.
pub async fn apply_replicated_takedown(
    directory: &dyn FederationDirectory,
    notice: &TakedownNotice,
    record_ids: &[String],
    receiver_key_id: &str,
) -> Result<TakedownReport, Error> {
    let now = sp::purge_clock();
    let terms = takedown_terms(notice)?;
    if terms.disposition == TakedownDisposition::AgeGate {
        return Err(refused(
            token::UNAUTHORISED,
            serde_json::json!({
                "notice_id": terms.notice_id,
                "reason": "an age-gate notice writes no tombstone, so there is none to apply",
            }),
        ));
    }
    if record_ids != [terms.record_id()].as_slice() {
        return Err(refused(
            token::NOT_BYTES_PLANE,
            serde_json::json!({
                "notice_id": terms.notice_id,
                "record_ids": record_ids,
                "reason": "a takedown tombstones exactly its own content on the bytes plane",
            }),
        ));
    }
    verify_takedown_authority(directory, &terms, now).await?;
    record(directory, &terms, receiver_key_id, origin::REPLICATED, now).await
}

async fn record(
    directory: &dyn FederationDirectory,
    terms: &TakedownTerms,
    executed_by: &str,
    from: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<TakedownReport, Error> {
    let mut report = TakedownReport {
        notice_id: terms.notice_id.clone(),
        content_sha256: terms.content_sha256.clone(),
        legal_basis: terms.legal_basis.clone(),
        disposition: terms.disposition,
        signer: terms.signer.clone(),
        tombstoned: false,
        settles_at: None,
        claims_retracted: 0,
        bytes_destroyed: false,
    };
    if terms.disposition == TakedownDisposition::AgeGate {
        return Ok(report);
    }
    let record_id = terms.record_id();
    let put = directory
        .purge_put_execution(
            &PurgeExecution {
                notice_id: terms.notice_id.clone(),
                selection_digest: sp::selection_digest(&[record_id.as_str()]),
                claimant_key_id: terms.claimant_key_id.clone(),
                legal_basis: terms.legal_basis.clone(),
                record_count: 1,
                notice_jcs: terms.notice_jcs.clone(),
                // A duty-holder notice carries one signature, inside the
                // envelope; there is no cosignature set.
                cosignatures_json: "[]".to_owned(),
                executed_by: executed_by.to_owned(),
                origin: from.to_owned(),
                executed_at: now,
                admitted_at: now,
                finalized_at: None,
            },
            &[PurgeTombstone {
                notice_id: terms.notice_id.clone(),
                ordinal: 0,
                plane: PurgePlane::Blob,
                record_ref: terms.content_sha256.clone(),
                derived_from: None,
            }],
        )
        .await?;
    report.tombstoned = put.tombstones_inserted.first().copied().unwrap_or(false);
    // The header that is held (a re-run keeps the first execution's instant).
    if let Some(e) = directory.purge_execution(&terms.notice_id).await? {
        report.settles_at = Some(settles_at(&e));
    }
    // CC 4.5.3 step 4 — every fast-path takedown enters the audit trail for
    // downstream review (`hard_case:fast_path_takedown`, idempotent on the
    // notice).
    if terms.disposition == TakedownDisposition::DestroyOnReceipt {
        directory
            .record_hard_case(super::hard_case::HardCaseEvent {
                event_id: format!(
                    "{}:{}",
                    super::hard_case::kind::FAST_PATH_TAKEDOWN,
                    terms.notice_id
                ),
                kind: super::hard_case::kind::FAST_PATH_TAKEDOWN.to_owned(),
                target_key_id: Some(terms.notice_id.clone()),
                subject_key_id: None,
                detail: serde_json::json!({
                    "content_sha256": terms.content_sha256,
                    "legal_basis": terms.legal_basis,
                    "signer": terms.signer,
                    "origin": from,
                }),
                emitted_at: now,
            })
            .await?;
    }
    Ok(report)
}
