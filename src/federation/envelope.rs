//! v20.0.0 (CIRISPersist#495, wall 2) — the TYPED attestation-envelope
//! core: the universal envelope keys as a struct whose serde field names
//! ARE the projection paths.
//!
//! Before this cut the envelope was an opaque `serde_json::Value` on both
//! sides of every boundary: the server hand-built keys with `json!{}`,
//! persist hand-read them with `json_extract('$.x')` / `->>'x'`, and
//! nothing bound writer to reader — a rename of
//! `references_attestation_id` would have made the withdraws/supersedes
//! `NOT EXISTS` check never match, silently leaving **a withdrawn
//! attestation active**. Now:
//!
//! - [`EnvelopeCore`] carries the universal keys TYPED; dimension-specific
//!   payload rides `#[serde(flatten)] extra` — openness is preserved
//!   (covered by the vocabulary hash), the universal keys are not.
//! - [`paths`] is the ONE set of key constants; every SQL projection
//!   interpolates them, every Rust accessor reads through them, and the
//!   `envelope_core_paths_bind_serde_names` witness asserts each constant
//!   round-trips through serde — so a struct-field rename that isn't
//!   mirrored in the constant (or vice versa) fails the build's tests.
//! - The emit/local INPUT types now carry `EnvelopeCore` (the v20 flip):
//!   producers CONSTRUCT envelopes, they do not spell keys. Stored rows
//!   keep `serde_json::Value` — storage is byte-faithful; signatures ride
//!   JCS (order-independent), so the typed re-serialization is invisible
//!   to every verifier.

use serde::{Deserialize, Serialize};

/// The ONE set of universal envelope key constants. SQL interpolates
/// these; accessors read through them; the witness binds them to
/// [`EnvelopeCore`]'s serde names.
pub mod paths {
    /// The CEG Information-Type parameter (see the trace:* validator).
    pub const DIMENSION: &str = "dimension";
    /// The composer target: which attestation a `withdraws` / `supersedes`
    /// / `recants` / `delegates_to` row references.
    pub const REFERENCES_ATTESTATION_ID: &str = "references_attestation_id";
    /// Delegation scope: bare string OR array of tokens (both wire shapes
    /// are established — see `trust_root::scope_contains`).
    pub const SCOPE: &str = "scope";
    /// Charter pre-rotation commitment (v19.0.0 #488, the KERI lesson).
    pub const PRE_ROTATION_COMMITMENT: &str = "pre_rotation_commitment";
    /// Charter recovery: the predecessor root being rotated.
    pub const RECOVERS: &str = "recovers";
    /// Charter recovery: the pre-committed successor key set.
    pub const SUCCESSOR_KEYS: &str = "successor_keys";
    /// Withdraws composer: the producer's stated reason.
    pub const WITHDRAWAL_REASON: &str = "withdrawal_reason";
    /// v21.9.0 (CIRISPersist#519 item 2 field-hoist) — the CI
    /// recipient-RECEIVE axis: how a consented payload is delivered
    /// (edge-owned processor `reachability.rs`; persist types it). Hoisted
    /// from `extra` to a typed `EnvelopeCore` field, byte-invariant.
    pub const DELIVERY_MODE: &str = "delivery_mode";
    /// v21.9.0 (CIRISPersist#519 item 2 field-hoist) — the CI
    /// temporal-lifecycle erasure window: the deadline by which a
    /// consented payload must be deleted (persist-owned lifecycle
    /// processor — the breach signal). Hoisted from `extra`, byte-invariant.
    pub const DELETION_WINDOW: &str = "deletion_window";
    /// v31.0.0 (CIRISPersist#598) — **the SIGNED assertion instant.** The
    /// `federation_attestations.asserted_at` COLUMN is stored verbatim from
    /// the caller on all three backends and is not covered by any signature
    /// (`original_content_hash` covers `attestation_envelope` and nothing
    /// else). The consent fold orders on that column, so a replay of a
    /// subject's own still-valid grant with a bumped column flipped a
    /// revocation back to Granted. This key is the column's signed twin:
    /// [`crate::federation::admission::check_consent_state_instant_binding`]
    /// refuses a `consent:state:*` row whose column and envelope disagree.
    pub const ASSERTED_AT: &str = "asserted_at";
    /// v31.0.0 (CIRISPersist#598) — the SIGNED expiry instant, the twin of
    /// `federation_attestations.expires_at`. Same unsigned row column, same
    /// treatment: the consent fold drops a row whose `expires_at` has passed,
    /// so an unsigned column is an unsigned mute button.
    pub const EXPIRES_AT: &str = "expires_at";
    /// v31.0.0 (CIRISPersist#643) — **the TYPED-COLUMN MIRROR.** One object,
    /// not five sibling keys: the five `federation_attestations` columns that
    /// decide what a row MEANS and no signature covered
    /// ([`super::RowMirror`] — `attestation_type`, `attested_key_id`,
    /// `subject_key_ids`, `cohort_scope`, `weight`).
    ///
    /// `original_content_hash` covers `attestation_envelope` and nothing else,
    /// so before this key a relay could flip `withdraws` → `scores` (the
    /// retraction becomes an ordinary claim and the thing it retracted stays
    /// live — note the TARGET, `references_attestation_id`, was already
    /// signed) or append a canonical binding hash to `subject_key_ids` (which
    /// grants that key rule-2 revocation standing at
    /// [`crate::federation::admission::withdraws_admission_rule_for`]), and
    /// the row still verified.
    ///
    /// Stamped by
    /// [`crate::federation::attestation_emit::stamp_and_canonicalize`] BEFORE
    /// the bytes are signed; enforced at every `put_attestation` by
    /// [`crate::federation::admission::check_row_column_binding`].
    pub const ROW: &str = "row";
}

/// v31.0.0 (CIRISPersist#643) — the member names INSIDE [`paths::ROW`]. One
/// object with a CLOSED member set (see [`RowMirror`]'s
/// `deny_unknown_fields`), so "the mirror" is one vocabulary entry rather than
/// five top-level keys accreted over five releases.
pub mod row_paths {
    /// The row's IDENTITY. Binding it makes a replay of a still-valid signed
    /// envelope under a fresh `attestation_id` structurally impossible: same
    /// bytes ⇒ same id ⇒ the PK dedup absorbs it as an idempotent no-op.
    pub const ATTESTATION_ID: &str = "attestation_id";
    /// WHO made the claim. Emergently bound already (the ingest verifier
    /// resolves this key's registered pubkeys and the producer's signature
    /// verifies under no other), but bound EXPLICITLY here so the property
    /// holds on the local tier too, where signature verification is deferred.
    pub const ATTESTING_KEY_ID: &str = "attesting_key_id";
    /// The VERB — `scores` / `withdraws` / `supersedes` / `recants` /
    /// `delegates_to`.
    pub const ATTESTATION_TYPE: &str = "attestation_type";
    /// Who the claim is ABOUT.
    pub const ATTESTED_KEY_ID: &str = "attested_key_id";
    /// §4.2.6 subjects — the field that GRANTS revocation authority.
    pub const SUBJECT_KEY_IDS: &str = "subject_key_ids";
    /// Who may SEE it.
    pub const COHORT_SCOPE: &str = "cohort_scope";
    /// How much it COUNTS.
    pub const WEIGHT: &str = "weight";
}

/// v31.0.0 (CIRISPersist#643) — the signed twin of the five typed
/// `federation_attestations` columns the envelope never covered. Rides the
/// envelope under [`paths::ROW`] as ONE object.
///
/// # Why an object and not five sibling keys
///
/// Five top-level keys would be five independent vocabulary additions, each
/// individually optional-looking, and a producer that stamped four of five
/// would look conformant. One object is one presence check: the mirror is
/// there in full or the row is refused.
///
/// # Closed member set
///
/// `deny_unknown_fields` — an unexpected member inside `row` is a refusal, not
/// a shrug. The mirror is not an extension point: anything that wants to ride
/// the envelope rides the envelope's own `extra`, where the vocabulary hash
/// covers it. A SIXTH column joining the mirror is a deliberate re-pin of
/// [`ENVELOPE_VOCABULARY_SHA256`], exactly as this one was.
///
/// # `subject_key_ids` is ORDER-SENSITIVE
///
/// The mirror carries the list AS A LIST and
/// [`crate::federation::admission::check_row_column_binding`] compares it
/// element-by-element. Every *semantic* consumer is a membership test
/// (`iter().any`, `HashSet::contains`, `for subj in …` — the rule-2/3/4 arms,
/// the V106 subject projection, the trace self-emission polarity check), so
/// nothing reads position. But
/// [`crate::federation::types::compute_persist_row_hash`] and
/// [`crate::federation::wire_index::content_hash_of`] both serialize the field
/// as an ORDERED JSON array, so a set-wise comparison here would let a relay
/// permute the list, change the row's content hash and its wire-index address,
/// and still satisfy the binding — a divergence traded one plane over rather
/// than closed. Order round-trips verbatim on all three backends (sqlite
/// `TEXT` JSON array, postgres JSONB array, memory `Vec`), so the strict
/// comparison is exactly reproducible and is never a false refusal.
/// # What is deliberately NOT in the mirror
///
/// Binding a field that the receiving node RE-DERIVES from its own verified
/// state would be worse than leaving it unbound — it would make a peer's
/// signed opinion about our placement decisions into something we have to
/// honour. So:
///
/// - `tier`, `promoted_at` — this node's own placement of the row. Re-gated at
///   every door ([`check_local_tier_eligibility`], [`check_promotion_admission`]).
/// - `withdraws_admission_rule` — audit metadata RE-DERIVED at admission by
///   [`resolve_withdraws_admission_rule`]; a signed claim to a rule would be a
///   producer asserting its own authority.
/// - `persist_row_hash` — locally computed, over the row including this
///   envelope; binding it would be circular.
/// - `original_content_hash`, `scrub_signature_*` — the signature and its
///   digest cannot live inside the bytes they cover.
/// - `scrub_key_id`, `scrub_timestamp`, `pqc_completed_at` — signature
///   metadata, legitimately REWRITTEN when a promoting node re-scrubs the row.
///   No authority gate reads them (the ingest verifier resolves
///   `attesting_key_id`); `additional_scrubs` are each verified individually
///   over the same preimage (#556), which is a stronger property than binding.
/// - `asserted_at`, `expires_at` — bound, but as TOP-LEVEL envelope keys by
///   CIRISPersist#598 in this same break window, not inside `row`. They are
///   assertion-native (the validity interval of a claim, which any CEG reader
///   expects at the envelope root) rather than persist projections, and
///   [`check_consent_state_instant_binding`] reads them there.
///
/// [`check_local_tier_eligibility`]: crate::federation::admission::check_local_tier_eligibility
/// [`check_promotion_admission`]: crate::federation::admission::check_promotion_admission
/// [`resolve_withdraws_admission_rule`]: crate::federation::admission::resolve_withdraws_admission_rule
/// [`check_consent_state_instant_binding`]: crate::federation::admission::check_consent_state_instant_binding
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowMirror {
    /// [`row_paths::ATTESTATION_ID`].
    pub attestation_id: String,
    /// [`row_paths::ATTESTING_KEY_ID`].
    pub attesting_key_id: String,
    /// [`row_paths::ATTESTATION_TYPE`].
    pub attestation_type: String,
    /// [`row_paths::ATTESTED_KEY_ID`].
    pub attested_key_id: String,
    /// [`row_paths::SUBJECT_KEY_IDS`] — order-sensitive (see the type doc).
    #[serde(default)]
    pub subject_key_ids: Vec<String>,
    /// [`row_paths::COHORT_SCOPE`].
    pub cohort_scope: String,
    /// [`row_paths::WEIGHT`] — absent ⇔ the row column is `None`. Held as a
    /// [`serde_json::Number`] rather than an `f64` so [`EnvelopeCore`] keeps
    /// its `Eq` (and so a non-finite weight, which JSON cannot represent at
    /// all, is refused at the stamp instead of silently becoming `null`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<serde_json::Number>,
}

/// A delegation `scope` in either established wire shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScopeSet {
    /// The bare-string form (`"scope": "consent_revocation"`).
    One(String),
    /// The token-set form (`"scope": ["infra:serve", …]`).
    Many(Vec<String>),
}

impl ScopeSet {
    /// Does the set contain `token` (exact match, either shape)?
    #[must_use]
    pub fn contains(&self, token: &str) -> bool {
        match self {
            ScopeSet::One(s) => s == token,
            ScopeSet::Many(v) => v.iter().any(|s| s == token),
        }
    }
}

/// v20.0.0 (#495) — the typed universal envelope. Every field is optional
/// (envelopes carry the keys their kind needs); everything else rides
/// `extra` untouched, byte-order-free (signatures are over JCS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EnvelopeCore {
    /// [`paths::DIMENSION`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dimension: Option<String>,
    /// [`paths::REFERENCES_ATTESTATION_ID`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub references_attestation_id: Option<String>,
    /// [`paths::SCOPE`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeSet>,
    /// [`paths::PRE_ROTATION_COMMITMENT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_rotation_commitment: Option<String>,
    /// [`paths::RECOVERS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovers: Option<String>,
    /// [`paths::SUCCESSOR_KEYS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_keys: Option<Vec<String>>,
    /// [`paths::WITHDRAWAL_REASON`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawal_reason: Option<String>,
    /// [`paths::DELIVERY_MODE`] — v21.9.0 (#519 field-hoist). Typed here
    /// (was untyped `extra`); the PROCESSOR is edge's
    /// (`reachability.rs#ReachabilityTracker`). Byte-invariant: `None` ⇒ no
    /// key, `Some` ⇒ same `delivery_mode` key/value ⇒ identical JCS bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_mode: Option<String>,
    /// [`paths::DELETION_WINDOW`] — v21.9.0 (#519 field-hoist). Typed here
    /// (was untyped `extra`) with a persist-owned lifecycle processor (the
    /// breach signal — see [`super::deletion_window`]). Byte-invariant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_window: Option<String>,
    /// [`paths::ASSERTED_AT`] — v31.0.0 (#598). RFC-3339. The signed twin
    /// of the `asserted_at` ROW COLUMN the consent fold orders on. Stamped
    /// by [`crate::federation::attestation_emit::stamp_and_canonicalize`]
    /// BEFORE the bytes are signed, and read back out by
    /// [`crate::federation::attestation_emit::assemble`] — the emit path no
    /// longer samples a second clock after signing, so the two can never
    /// disagree at the mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asserted_at: Option<String>,
    /// [`paths::EXPIRES_AT`] — v31.0.0 (#598). RFC-3339. The signed twin of
    /// the `expires_at` ROW COLUMN. `None` ⇔ the row column is `None`; the
    /// binding gate refuses any other pairing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// [`paths::ROW`] — v31.0.0 (#643). The signed twin of the five typed
    /// columns (see [`RowMirror`]). `None` on an envelope that has not been
    /// through
    /// [`crate::federation::attestation_emit::stamp_and_canonicalize`];
    /// `put_attestation` REFUSES such a row on every backend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row: Option<RowMirror>,
    /// Every dimension-specific key, untyped and preserved. Covered by
    /// the envelope vocabulary hash, not by the compiler.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl RowMirror {
    /// v31.0.0 (CIRISPersist#643) — **the ONE definition of "the mirror this
    /// row implies"**, shared by the stamp side
    /// ([`crate::federation::attestation_emit::stamp_and_canonicalize`] builds
    /// the same shape from the emit input) and the check side
    /// ([`crate::federation::admission::check_row_column_binding`] compares
    /// against this). Two definitions of the projection would be two
    /// definitions of the binding, and this substrate has a recorded defect
    /// class for exactly that.
    ///
    /// Fails only on a non-finite `weight`, which JSON cannot represent at all
    /// — refused rather than silently serialized as `null`.
    pub fn of(row: &super::Attestation) -> Result<Self, super::Error> {
        Ok(Self {
            attestation_id: row.attestation_id.clone(),
            attesting_key_id: row.attesting_key_id.clone(),
            attestation_type: row.attestation_type.clone(),
            attested_key_id: row.attested_key_id.clone(),
            subject_key_ids: row.subject_key_ids.clone(),
            cohort_scope: row.cohort_scope.clone(),
            weight: match row.weight {
                None => None,
                Some(w) => Some(serde_json::Number::from_f64(w).ok_or_else(|| {
                    super::Error::InvalidArgument(format!(
                        "attestation {}: `weight` {w} is not finite and cannot be bound into the \
                         signed envelope (CIRISPersist#643)",
                        row.attestation_id
                    ))
                })?),
            },
        })
    }

    /// v31.0.0 (CIRISPersist#649) — **stamp [`Self::of`] into an envelope
    /// VALUE**: the ONE placement of the one projection, for every write path
    /// that owns the bytes it is about to sign.
    ///
    /// [`crate::federation::attestation_emit::stamp_and_canonicalize`] cannot
    /// use this (at the mint there is no row yet — it builds the mirror from
    /// the emit input and the id it is minting). Every OTHER producing path
    /// has a row in hand: the local-tier write, and the two placement-touching
    /// re-signs (promotion and the #530 repair re-scope). Those go through
    /// here rather than each spelling `envelope[paths::ROW] =
    /// to_value(RowMirror::of(row))`, because a copied projection is a second
    /// definition of the binding and this substrate has a recorded defect
    /// class for exactly that.
    ///
    /// Refuses a non-object envelope rather than silently replacing it — an
    /// envelope is always an object (see [`EnvelopeCore::from_value`]), and
    /// `serde_json`'s `IndexMut` would otherwise *overwrite* a scalar with an
    /// object and lose the producer's bytes.
    pub fn stamp_into(
        envelope: &mut serde_json::Value,
        row: &super::Attestation,
    ) -> Result<(), super::Error> {
        let mirror = Self::of(row)?;
        mirror.insert_into(envelope, &row.attestation_id)
    }

    /// The ONE write of [`paths::ROW`] — every stamping entry point funnels
    /// here so there is one placement as well as one projection.
    fn insert_into(
        &self,
        envelope: &mut serde_json::Value,
        attestation_id: &str,
    ) -> Result<(), super::Error> {
        let obj = envelope.as_object_mut().ok_or_else(|| {
            super::Error::InvalidArgument(format!(
                "attestation {attestation_id}: attestation_envelope must be a JSON object to \
                 carry the signed `{}` mirror (CIRISPersist#649)",
                paths::ROW,
            ))
        })?;
        obj.insert(
            paths::ROW.to_owned(),
            serde_json::to_value(self).map_err(|e| {
                super::Error::Backend(format!("RowMirror serialize: {e} (CIRISPersist#649)"))
            })?,
        );
        Ok(())
    }

    /// v31.0.0 (CIRISPersist#649) — **the envelope a PLACEMENT-TOUCHING write
    /// must sign AND store.**
    ///
    /// `base` is the envelope whose bytes will actually be served — the row's
    /// own for an ordinary promotion, the TRANSFORMED clone for a #510
    /// restriction pipeline. `row` is the row as it stands; `cohort_scope` is
    /// the placement it is about to land at. The returned envelope carries the
    /// mirror of the row **as it will be stored**, so the bytes signed over it
    /// and the columns written beside it are one statement.
    ///
    /// This exists because promotion RE-SIGNS a row and CHANGES `cohort_scope`
    /// — one of the seven columns #643 bound — so re-signing the pre-promotion
    /// envelope produced a row asserting its old scope while its column said
    /// otherwise, and every peer's `put_attestation` refused it. Promotion is
    /// the local→federation path, so that broke the thing promotion is for.
    /// The same shape as CIRISPersist#598 (`assemble` sampling `Utc::now()`
    /// after signing) and #643's blob-eviction sweeper: **a write path that
    /// constructs signed bytes and then mutates the row.**
    pub fn restamp_for_scope(
        base: &serde_json::Value,
        row: &super::Attestation,
        cohort_scope: &str,
    ) -> Result<serde_json::Value, super::Error> {
        let mut as_stored = row.clone();
        as_stored.cohort_scope = cohort_scope.to_owned();
        let mut envelope = base.clone();
        Self::stamp_into(&mut envelope, &as_stored)?;
        Ok(envelope)
    }

    /// v31.0.0 (CIRISPersist#649) — **the local-tier write STAMPS.** Called by
    /// all three backends' `write_local_attestation` on the assembled row,
    /// before `persist_row_hash`.
    ///
    /// # The decision, and why
    ///
    /// The choice was "stamp at write" vs "stay unstamped until sealed".
    /// **Stamp**, on the emit path's own rule: *the party that MINTS the bytes
    /// stamps; the party that RECEIVES them checks.* At this door persist mints
    /// the bytes — it assigns `attestation_id` (a `Uuid::new_v4()` unless the
    /// producer supplied a deterministic one), defaults `attested_key_id` to the
    /// attester, and stamps `tier`/`cohort_scope`. Four of the seven bound
    /// columns are therefore persist's own values, and a producer literally
    /// cannot bind them in advance.
    ///
    /// Three consequences settle it:
    ///
    /// 1. **`put_attestation`'s binding gate is TIER-BLIND** (#643, deliberately
    ///    — a tier-scoped binding is skippable by writing `tier = "local"`). So
    ///    an unstamped local row is a row this substrate's OWN put door refuses:
    ///    two local-write doors, one of which mints rows the other rejects. That
    ///    is the "door beside the door" class, minted fresh.
    /// 2. **The promote door now asks the same question**
    ///    ([`crate::federation::admission::check_promotion_admission`]). Leaving
    ///    the stamp to promotion means the FIRST time a local row's meaning is
    ///    bound is the moment it is republished — so nothing at rest at the local
    ///    tier is self-describing, and the substrate's own copy is the one plane
    ///    where a rewritten `attestation_type` leaves no trace.
    /// 3. **It is free and lossless here.** A durable local row carries the
    ///    deferred empty-sentinel scrub envelope (`scrub_signature_classical =
    ///    ""`), so there is no signature to invalidate: this is the last moment
    ///    the bytes are persist's to write. Promotion's re-stamp then becomes a
    ///    one-column narrowing (`cohort_scope`) of an already-correct mirror
    ///    rather than a first stamp.
    ///
    /// # The transit exclusion (`caller_signed`)
    ///
    /// A **subject-side revocation transiting** the local tier
    /// ([`crate::federation::types::LocalAttestationInput::into_transit_revocation_row`])
    /// is NOT persist's to stamp: the caller hybrid-signed
    /// `JCS(attestation_envelope)` and
    /// [`crate::federation::admission::verify_local_transit_revocation`] has
    /// already verified that signature and derived `original_content_hash` from
    /// those exact bytes. Stamping afterwards would rewrite the signed bytes and
    /// leave a stored hash and signature covering an envelope that no longer
    /// exists — **this very defect, one door over**. For that shape persist is
    /// the receiver, so the mirror is the producer's to bind and persist's to
    /// check; it is checked where the signature is (`put_attestation`, and the
    /// promote door the SLA watcher drives it through), not silently written
    /// here.
    pub fn stamp_local_row(
        row: &mut super::Attestation,
        caller_signed: bool,
    ) -> Result<(), super::Error> {
        if caller_signed {
            return Ok(());
        }
        let mirror = Self::of(row)?;
        let attestation_id = row.attestation_id.clone();
        mirror.insert_into(&mut row.attestation_envelope, &attestation_id)
    }
}

impl EnvelopeCore {
    /// Parse from a JSON value. Refuses non-objects (an envelope is
    /// always an object); every unknown key lands in `extra` losslessly.
    pub fn from_value(v: serde_json::Value) -> Result<Self, super::Error> {
        if !v.is_object() {
            return Err(super::Error::InvalidArgument(
                "attestation envelope must be a JSON object".into(),
            ));
        }
        serde_json::from_value(v)
            .map_err(|e| super::Error::InvalidArgument(format!("envelope parse: {e}")))
    }

    /// Serialize to the storage/wire `Value` (the stored row keeps
    /// `Value`; signatures ride JCS so field order is immaterial).
    #[must_use]
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("EnvelopeCore serializes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE binding witness: every [`paths`] constant round-trips through
    /// [`EnvelopeCore`]'s serde — a struct-field rename not mirrored in
    /// the constant (or vice versa) fails HERE, at build-test time, not
    /// as a silent NULL in a projection.
    #[test]
    fn envelope_core_paths_bind_serde_names() {
        let core = EnvelopeCore {
            dimension: Some("d:v1".into()),
            references_attestation_id: Some("ref-1".into()),
            scope: Some(ScopeSet::Many(vec!["infra:serve".into()])),
            pre_rotation_commitment: Some("ab".repeat(32)),
            recovers: Some("old-root".into()),
            successor_keys: Some(vec!["k1".into()]),
            withdrawal_reason: Some("test".into()),
            delivery_mode: Some("mandatory".into()),
            deletion_window: Some("2027-01-01T00:00:00Z".into()),
            asserted_at: Some("2026-08-12T00:00:00.000000+00:00".into()),
            expires_at: Some("2027-01-01T00:00:00.000000+00:00".into()),
            row: Some(RowMirror {
                attestation_id: "att-1".into(),
                attesting_key_id: "k-auth".into(),
                attestation_type: "scores".into(),
                attested_key_id: "k-att".into(),
                subject_key_ids: vec!["k-subj".into()],
                cohort_scope: "federation".into(),
                weight: serde_json::Number::from_f64(1.0),
            }),
            extra: serde_json::Map::new(),
        };
        let v = core.to_value();
        for (path, expect_present) in [
            (paths::DIMENSION, true),
            (paths::REFERENCES_ATTESTATION_ID, true),
            (paths::SCOPE, true),
            (paths::PRE_ROTATION_COMMITMENT, true),
            (paths::RECOVERS, true),
            (paths::SUCCESSOR_KEYS, true),
            (paths::WITHDRAWAL_REASON, true),
            (paths::DELIVERY_MODE, true),
            (paths::DELETION_WINDOW, true),
            (paths::ASSERTED_AT, true),
            (paths::EXPIRES_AT, true),
            (paths::ROW, true),
        ] {
            assert_eq!(
                v.get(path).is_some(),
                expect_present,
                "paths::{path} does not bind an EnvelopeCore serde field"
            );
        }
        // v31.0.0 (CIRISPersist#643) — the same binding one level down: every
        // `row_paths` constant must name a real [`RowMirror`] serde field, or
        // the gate would compare a member the wire never carries.
        let row_v = v.get(paths::ROW).expect("row mirror serialized");
        for path in [
            row_paths::ATTESTATION_ID,
            row_paths::ATTESTING_KEY_ID,
            row_paths::ATTESTATION_TYPE,
            row_paths::ATTESTED_KEY_ID,
            row_paths::SUBJECT_KEY_IDS,
            row_paths::COHORT_SCOPE,
            row_paths::WEIGHT,
        ] {
            assert!(
                row_v.get(path).is_some(),
                "row_paths::{path} does not bind a RowMirror serde field"
            );
        }
        // The member set is CLOSED: an unknown member is refused, not ignored.
        let mut junk = row_v.clone();
        junk.as_object_mut()
            .unwrap()
            .insert("smuggled".into(), serde_json::json!(1));
        let mut env_junk = v.clone();
        env_junk[paths::ROW] = junk;
        assert!(
            EnvelopeCore::from_value(env_junk).is_err(),
            "an unknown member inside `row` must be REFUSED (the mirror is a closed vocabulary)"
        );
        // Round-trip losslessness incl. extras.
        let mut with_extra = core.clone();
        with_extra
            .extra
            .insert("score".into(), serde_json::json!(0.9));
        let rt = EnvelopeCore::from_value(with_extra.to_value()).unwrap();
        assert_eq!(rt, with_extra, "lossless round-trip incl. extras");
    }

    /// v21.9.0 (CIRISPersist#519 field-hoist) — THE byte-invariance witness:
    /// hoisting `delivery_mode` / `deletion_window` from untyped `extra` to
    /// typed fields must NOT change the canonical bytes, so a signature
    /// computed before the hoist still verifies after. A raw JSON envelope
    /// carrying these keys must canonicalize IDENTICALLY to the same envelope
    /// round-tripped through the (now-typed) `EnvelopeCore` — proving the two
    /// fields land under the same wire keys with the same values. If serde
    /// renamed them, or the flatten interaction reordered/renamed anything,
    /// this fails.
    #[test]
    fn hoisted_fields_are_canonicalization_byte_invariant() {
        use crate::verify::canonical::ceg_produce_canonicalize;
        // A raw envelope as a producer would emit it (keys in extra, pre-hoist
        // shape) — including an unrelated payload key to exercise flatten.
        let raw = serde_json::json!({
            "dimension": "trace:complete:v1",
            "delivery_mode": "mandatory",
            "deletion_window": "2027-01-01T00:00:00Z",
            "trace_id": "t-1",
            "score": 0.9,
        });
        let via_typed = EnvelopeCore::from_value(raw.clone()).unwrap().to_value();
        // The typed fields captured the two keys (not left in extra)...
        let parsed = EnvelopeCore::from_value(raw.clone()).unwrap();
        assert_eq!(parsed.delivery_mode.as_deref(), Some("mandatory"));
        assert_eq!(
            parsed.deletion_window.as_deref(),
            Some("2027-01-01T00:00:00Z")
        );
        assert!(!parsed.extra.contains_key("delivery_mode"));
        assert!(!parsed.extra.contains_key("deletion_window"));
        // ...and the canonical bytes are byte-identical raw vs round-tripped.
        assert_eq!(
            ceg_produce_canonicalize(&raw).unwrap(),
            ceg_produce_canonicalize(&via_typed).unwrap(),
            "the field-hoist changed the canonical bytes — existing signatures would break"
        );
    }

    /// Both established scope wire shapes parse and match.
    #[test]
    fn scope_set_both_wire_shapes() {
        let one: EnvelopeCore =
            serde_json::from_value(serde_json::json!({"scope": "manifest:foo"})).unwrap();
        assert!(one.scope.unwrap().contains("manifest:foo"));
        let many: EnvelopeCore =
            serde_json::from_value(serde_json::json!({"scope": ["a", "b"]})).unwrap();
        assert!(many.scope.as_ref().unwrap().contains("b"));
        assert!(!many.scope.unwrap().contains("c"));
    }
}

/// v20.0.0 (#495) — the envelope-vocabulary manifest: the universal path
/// constants + the consent-state dimension prefixes, as one canonical
/// JSON document. Mirrors `WIRE_VOCABULARY_HASH` / the trace-summary
/// contract: CIRISServer serves the hash on `/v1/health`, consumers
/// assert it, and a vocabulary change on either side fails loudly on
/// both.
pub fn envelope_vocabulary_json() -> serde_json::Value {
    use crate::federation::consent::consent_dimension as cd;
    serde_json::json!({
        "contract": "attestation_envelope_vocabulary",
        "version": 1,
        "universal_paths": [
            paths::DIMENSION,
            paths::REFERENCES_ATTESTATION_ID,
            paths::SCOPE,
            paths::PRE_ROTATION_COMMITMENT,
            paths::RECOVERS,
            paths::SUCCESSOR_KEYS,
            paths::WITHDRAWAL_REASON,
            // v31.0.0 (CIRISPersist#598) — the two signed instants. Added to
            // the vocabulary DELIBERATELY (this re-pins
            // `ENVELOPE_VOCABULARY_SHA256` and every consumer asserting it):
            // an ordering key that decides consent must be part of the
            // vocabulary both sides agree on, not a row column one side can
            // choose.
            paths::ASSERTED_AT,
            paths::EXPIRES_AT,
            // v31.0.0 (CIRISPersist#643) — the typed-column mirror. Added
            // DELIBERATELY (re-pinning `ENVELOPE_VOCABULARY_SHA256` a second
            // time in this cut): the VERB of an attestation, and the field
            // that grants revocation authority over it, must be part of the
            // vocabulary both sides agree on rather than unsigned columns a
            // relay can rewrite.
            paths::ROW,
        ],
        // v31.0.0 (CIRISPersist#643) — the CLOSED member set of `row`. Served
        // alongside the universal paths so a consumer can validate the mirror
        // it must now stamp, and so adding a sixth column is a visible
        // vocabulary change rather than a quiet one.
        "row_members": [
            row_paths::ATTESTATION_ID,
            row_paths::ATTESTING_KEY_ID,
            row_paths::ATTESTATION_TYPE,
            row_paths::ATTESTED_KEY_ID,
            row_paths::SUBJECT_KEY_IDS,
            row_paths::COHORT_SCOPE,
            row_paths::WEIGHT,
        ],
        "consent_dimension_prefixes": [
            cd::STATE_GRANTED_PREFIX,
            cd::STATE_REVOKED_PREFIX,
            cd::STATE_EXPIRED_PREFIX,
        ],
    })
}

/// sha256 (lowercase hex) over JCS of [`envelope_vocabulary_json`].
pub fn envelope_vocabulary_sha256() -> String {
    use sha2::Digest as _;
    let canonical = crate::verify::canonical::ceg_produce_canonicalize(&envelope_vocabulary_json())
        .expect("envelope vocabulary canonicalizes");
    hex::encode(sha2::Sha256::digest(&canonical))
}

/// The PINNED envelope-vocabulary hash (see
/// `envelope_vocabulary_hash_is_pinned` — computed == pinned is a gating
/// witness; changing the vocabulary without a deliberate re-pin fails CI).
/// v31.0.0 (CIRISPersist#598) — RE-PINNED. `asserted_at` and `expires_at`
/// joined `universal_paths`: the instant that decides which consent claim
/// wins is now part of the vocabulary both sides agree on. Consumers
/// asserting the old hash BREAK, deliberately and loudly (operator decision
/// on #598 — no grandfathering).
/// v31.0.0 (CIRISPersist#643) — RE-PINNED AGAIN, same window, same decision.
/// `row` joined `universal_paths` and its closed member set joined the
/// document as `row_members`: the VERB of an attestation, and the field that
/// grants revocation authority over it, are now signed material.
pub const ENVELOPE_VOCABULARY_SHA256: &str =
    "0a6f72817eb39d4205ea024ce4a0056112a0614d5a023b8c2c7c88dcfb7264f5";

#[cfg(test)]
mod vocab_tests {
    use super::*;

    /// The pin gate (the loud-drift discipline, third instance).
    #[test]
    fn envelope_vocabulary_hash_is_pinned() {
        assert_eq!(
            envelope_vocabulary_sha256(),
            ENVELOPE_VOCABULARY_SHA256,
            "envelope vocabulary changed: re-pin ENVELOPE_VOCABULARY_SHA256 \
             deliberately (and notify /v1/health + consumer-test holders)"
        );
    }
}
