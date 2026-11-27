//! The partner_record field set as the typed licence payload, and the two
//! operational-data admission checks that outlived their planes
//! (v60.0.0, CIRISPersist#1036 item 4; CC 3.3.9 rc9, CIRISConstitution#161).
//!
//! # What retired, and what this module still is
//!
//! Until v60.0.0 this module held three operational subject_kinds —
//! `organization`, `org_membership`, `partner_record` — each with its own
//! typed table (V071/V072), its own write door, its own merge dispatcher and
//! its own replication wire kind. CC 3.3.9 (steward ruling 2026-10-08) moved
//! all three onto affiliation rows:
//!
//! | retired | is now |
//! |---|---|
//! | `organization` | a community record at `cohort_scope: affiliations` (CC 4.4.3.2.8); `org_id` is its `community_key_id`, `parent_org_id` is `hierarchy` nesting, `org_type` is `affiliation_archetype` + `membership_basis` |
//! | `org_membership` | a `membership:{stage}` seat plus a `delegates_to` edge in the hierarchy whose `scope` set names what the member may do |
//! | `partner_record` | a `licensure:{community_key_id}:v1` row carrying [`PARTNER_RECORD_MEMBER`] — the field set below, typed |
//!
//! V205 dropped the three tables and the three replication kinds joined
//! [`RETIRED_FRAMED`](super::replication_policy::RETIRED_FRAMED). No Portal
//! data existed to migrate.
//!
//! What remains here is what CC says to PORT onto the licence row:
//!
//! - **the skew bound** ([`check_skew_bound`], ±5 min). Every attestation row
//!   already meets it at the attestation door
//!   (`admission::check_instant_binding`, `DEFAULT_MAX_TOUCH_SKEW`), so a
//!   licence row inherits it with no code of its own; the function stays for
//!   the typed planes that call it directly.
//! - **the payment-processor rejection**
//!   ([`reject_payment_processor_identifiers`]), over the whole signed
//!   envelope of a row that carries the licence payload.
//! - **the field set as the typed payload** ([`PartnerRecord`]), with its four
//!   set-semantics arrays sorted AND unique ([`check_partner_record_sets`]).
//! - **the `revision` anti-rollback** per `license_id`, judged at the licensure
//!   door against the authority's own held licences
//!   (`admission::check_partner_record_revision`).
//!
//! The licence's AUTHORITY is no longer an M-of-N steward roster: a licence
//! under an affiliation is the affiliation's act, cosigned under its own
//! `consensus_protocol` (CC 2.4.1.2.1, CIRISConstitution#162), judged by the
//! one licensure chain function (`admission::licensure_issuance_at`).

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::Error;

/// CC 2.6.7 clock-skew tolerance (±5 minutes). A row whose signed
/// `asserted_at` is more than this far in the future is refused: the
/// last-writer front-running bound.
pub const CLOCK_SKEW_TOLERANCE: Duration = Duration::minutes(5);

/// Reject an envelope whose `asserted_at` is more than
/// [`CLOCK_SKEW_TOLERANCE`] (±5 min) in the future relative to `now`.
/// Without it a forward-skewed clock future-dates `asserted_at` and wins
/// every later-instant comparison indefinitely.
///
/// # Errors
/// [`Error::ClockSkewViolation`] when `asserted_at > now + tolerance`.
pub fn check_skew_bound(asserted_at: DateTime<Utc>, now: DateTime<Utc>) -> Result<(), Error> {
    if asserted_at > now + CLOCK_SKEW_TOLERANCE {
        return Err(Error::ClockSkewViolation {
            asserted_at: asserted_at.to_rfc3339(),
            now: now.to_rfc3339(),
        });
    }
    Ok(())
}

/// Stripe / payment-processor identifier prefixes that an operational
/// envelope MUST NOT carry (CC 3.3.9, fail-secure). Defense-in-depth behind
/// the Registry's emit-side minimization. These are the canonical Stripe
/// object-id prefixes (customer / subscription / charge / payment-intent /
/// card / invoice / payment-method / setup-intent / price / product / bank
/// account / source / token).
pub const PAYMENT_PROCESSOR_PREFIXES: &[&str] = &[
    "cus_", "sub_", "ch_", "pi_", "card_", "in_", "pm_", "seti_", "price_", "prod_", "ba_", "src_",
    "tok_", "re_", "py_", "txn_", "ii_",
];

/// Recursively scan a JSON value for any string that begins with a
/// recognizable payment-processor identifier prefix
/// ([`PAYMENT_PROCESSOR_PREFIXES`]) — anywhere, including open-vocabulary
/// fields, object keys, and array elements (CC 3.3.9).
///
/// # Errors
/// [`Error::PaymentProcessorIdentifier`] on the first offending token,
/// naming the matched prefix.
pub fn reject_payment_processor_identifiers(value: &Value) -> Result<(), Error> {
    fn matches_prefix(s: &str) -> Option<&'static str> {
        PAYMENT_PROCESSOR_PREFIXES
            .iter()
            .copied()
            .find(|p| s.starts_with(p) && s.len() > p.len())
    }
    match value {
        Value::String(s) => {
            if let Some(prefix) = matches_prefix(s) {
                return Err(Error::PaymentProcessorIdentifier {
                    matched_prefix: prefix,
                });
            }
        }
        Value::Array(arr) => {
            for v in arr {
                reject_payment_processor_identifiers(v)?;
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                // Keys are open-vocab too — a forged key like `cus_x` is
                // just as much a leak vector as a value.
                if let Some(prefix) = matches_prefix(k) {
                    return Err(Error::PaymentProcessorIdentifier {
                        matched_prefix: prefix,
                    });
                }
                reject_payment_processor_identifiers(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}

// ── The typed licence payload (CC 3.3.9: "the partner_record field set as
//    the typed licence payload") ──────────────────────────────────────────

/// The envelope member of a `licensure:{authority_id}` row that carries the
/// typed licence payload ([`PartnerRecord`]). Persist's spelling: CC 3.3.9
/// ports "the `partner_record` field set as the typed licence payload" and
/// names no member, so the member keeps the field set's name.
pub const PARTNER_RECORD_MEMBER: &str = "partner_record";

/// The `partner_record` field set, typed: the licence payload a
/// `licensure:{community_key_id}:v1` row carries (CC 3.3.9).
///
/// Three members of the retired record are NOT here, because the licence row
/// already says them in its own signed bytes: `org_id` is the authority
/// segment of the dimension, `partner_id` is the row's `attested_key_id`, and
/// `status` is the licensure row's own `status` member (the closed CC 3.1.1
/// vocabulary the status fold reads; `active` is `issued`). `asserted_at` is
/// the row's. Unknown members are carried, not refused (CC 2.1.1 forward
/// compatibility): the signature covers them either way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartnerRecord {
    /// The licence's stable business id: the `revision` counter is per
    /// `license_id`.
    pub license_id: String,
    /// `community` | `community_plus` | `professional_*` | `professional_full`.
    pub license_type: String,
    /// SET-SEMANTICS: sorted and unique.
    pub capabilities_granted: Vec<String>,
    /// SET-SEMANTICS: sorted and unique.
    pub capabilities_denied: Vec<String>,
    /// `A0`..`A4`.
    pub max_autonomy_tier: String,
    /// Whether deployment requires a supervisor.
    pub requires_supervisor: bool,
    /// ISO country codes. SET-SEMANTICS: sorted and unique.
    pub geographic_restrictions: Vec<String>,
    /// SET-SEMANTICS: sorted and unique.
    pub allowed_identity_templates: Vec<String>,
    /// Max concurrent deployments.
    pub deployment_limit: u32,
    /// Offline grace window, hours.
    pub offline_grace_hours: u32,
    /// MONOTONIC per `license_id`: admission refuses a decrease against the
    /// authority's own held licences (the F-AV-ROLLBACK discipline).
    pub revision: u64,
    /// CC 2.6.2 instant.
    pub issued_at: DateTime<Utc>,
    /// CC 2.6.2 instant.
    pub expires_at: DateTime<Utc>,
}

/// The set-semantics array members of [`PartnerRecord`] (CC 3.3.9, CC
/// 2.6.1.1.1 rule 1). Each MUST be sorted by JCS string form and carry no
/// repeat, so the M members who cosign a licence sign byte-identical bytes
/// and a set has one spelling.
pub const PARTNER_RECORD_SET_FIELDS: &[&str] = &[
    "allowed_identity_templates",
    "capabilities_denied",
    "capabilities_granted",
    "geographic_restrictions",
];

impl PartnerRecord {
    /// The four set-semantics arrays, in [`PARTNER_RECORD_SET_FIELDS`] order.
    #[must_use]
    pub fn sets(&self) -> [(&'static str, &[String]); 4] {
        [
            (
                PARTNER_RECORD_SET_FIELDS[0],
                &self.allowed_identity_templates,
            ),
            (PARTNER_RECORD_SET_FIELDS[1], &self.capabilities_denied),
            (PARTNER_RECORD_SET_FIELDS[2], &self.capabilities_granted),
            (PARTNER_RECORD_SET_FIELDS[3], &self.geographic_restrictions),
        ]
    }

    /// The producer's half of the set rule: sort each set by JCS string form
    /// and drop repeats. A producer calls this before signing; the door
    /// ([`check_partner_record_sets`]) refuses what it would have changed.
    pub fn canonicalize_sets(&mut self) {
        for v in [
            &mut self.allowed_identity_templates,
            &mut self.capabilities_denied,
            &mut self.capabilities_granted,
            &mut self.geographic_restrictions,
        ] {
            v.sort_by(|a, b| jcs_string_order(a, b));
            v.dedup();
        }
    }
}

/// CC 2.6.1.1.1 rule 1: strings order by their UTF-16 code units, the order
/// JCS (RFC 8785 §3.2.3) sorts members by. It differs from Rust's byte order
/// only above U+FFFF against U+E000..=U+FFFF.
pub(crate) fn jcs_string_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// v60.0.0 (CIRISPersist#1036 item 4; S6v carried flag) — **a set is sorted
/// AND unique.** Each [`PARTNER_RECORD_SET_FIELDS`] array must be strictly
/// increasing under JCS string order: an out-of-order pair is unsorted, and
/// an equal adjacent pair is a duplicate the set's one spelling does not
/// carry. Before v60 the check (verify-core's `check_set_semantics_sorted`)
/// was non-decreasing, so `["a", "a"]` passed.
///
/// # Errors
/// [`Error::SetSemanticsUnsorted`] (`federation_set_semantics_unsorted`)
/// naming the array and the offending pair.
pub fn check_partner_record_sets(rec: &PartnerRecord) -> Result<(), Error> {
    for (field, values) in rec.sets() {
        for pair in values.windows(2) {
            let ord = jcs_string_order(&pair[0], &pair[1]);
            if ord != std::cmp::Ordering::Less {
                let why = if ord == std::cmp::Ordering::Equal {
                    "repeats"
                } else {
                    "is out of order after"
                };
                return Err(Error::SetSemanticsUnsorted(format!(
                    "{PARTNER_RECORD_MEMBER}.{field}: {:?} {why} {:?} — a set-semantics array is \
                     sorted by JCS string form and carries no repeat (CC 2.6.1.1.1 rule 1, CC \
                     3.3.9)",
                    pair[1], pair[0]
                )));
            }
        }
    }
    Ok(())
}

/// The typed licence payload a row carries, if it carries one: a `scores`
/// row on a `licensure:` dimension with a [`PARTNER_RECORD_MEMBER`] member.
/// `Ok(None)` for every other row.
///
/// # Errors
/// [`Error::MalformedRow`] (`envelope_member_invalid`) when the member is
/// present and does not parse as [`PartnerRecord`].
pub fn partner_record_of(row: &super::Attestation) -> Result<Option<PartnerRecord>, Error> {
    if row.attestation_type != super::types::attestation_type::SCORES {
        return Ok(None);
    }
    let Some(dimension) = super::admission::envelope_dimension(&row.attestation_envelope) else {
        return Ok(None);
    };
    if !dimension.starts_with(super::licensure::LICENSURE_DIMENSION_PREFIX) {
        return Ok(None);
    }
    let Some(member) = row.attestation_envelope.get(PARTNER_RECORD_MEMBER) else {
        return Ok(None);
    };
    serde_json::from_value::<PartnerRecord>(member.clone())
        .map(Some)
        .map_err(|e| {
            Error::malformed_row(
                "attestation",
                super::malformed_row::ENVELOPE_MEMBER_INVALID,
                format!(
                    "{}: {PARTNER_RECORD_MEMBER} on {dimension:?} is not the typed licence \
                     payload (CC 3.3.9): {e}",
                    row.attestation_id
                ),
            )
        })
}

/// v60.0.0 (CIRISPersist#1036 item 4) — **the licence payload's pure
/// admission checks**: the payload parses ([`partner_record_of`]), its sets
/// are sorted and unique ([`check_partner_record_sets`]), and the row's whole
/// signed envelope carries no payment-processor identifier
/// ([`reject_payment_processor_identifiers`]). A no-op for a row without the
/// payload. Pure: the attestation door runs it in its pure tier, every
/// backend alike. The `revision` anti-rollback reads held state and runs at
/// the licensure door (`admission::check_partner_record_revision`).
///
/// # Errors
/// [`Error::MalformedRow`], [`Error::SetSemanticsUnsorted`],
/// [`Error::PaymentProcessorIdentifier`].
pub fn check_licence_payload(row: &super::Attestation) -> Result<(), Error> {
    let Some(rec) = partner_record_of(row)? else {
        return Ok(());
    };
    check_partner_record_sets(&rec)?;
    reject_payment_processor_identifiers(&row.attestation_envelope)
}

/// Test-support builders shared by the backend test modules (hybrid-signing
/// identities, accord co-scrubbed records, trust-root and conferral
/// fixtures). Crate-internal, test-only.
///
/// `#[allow(dead_code)]`: the builders are consumed by the `sqlite` /
/// `postgres` backend test modules; under a backend-less test build those
/// modules don't compile, so the builders are legitimately unused there.
// v18.3.0 (CIRISPersist#484) — gated `#[cfg(any(test, feature =
// "test-anchor"))]` so DOWNSTREAM test builds can mint a genuinely
// accord-co-scrubbed record and test the `has_accord_conferred_role` ALLOW
// path. `test-anchor` is persist's "test-only, NEVER in a published wheel"
// fence (see Cargo.toml), so the signing helpers stay out of release builds.
#[cfg(any(test, feature = "test-anchor"))]
#[allow(dead_code)]
pub mod test_support {

    use base64::Engine as _;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer, MlDsa65Signer, PqcSigner};
    use serde_json::json;

    fn b64() -> base64::engine::general_purpose::GeneralPurpose {
        base64::engine::general_purpose::STANDARD
    }

    /// A signing identity: a key_id plus its hybrid keypair.
    pub struct Identity {
        /// The identity's `key_id`.
        pub key_id: String,
        ed: Ed25519Signer,
        mldsa: MlDsa65Signer,
    }

    impl Identity {
        /// v21.0.0 (#502 E9 test-isolation fix) — a DETERMINISTIC hybrid
        /// identity seeded from `id` (the same `[0x11;32]`-overlay seed
        /// `tier_ingest::test_support` uses), NOT a random keypair.
        ///
        /// The old random constructor meant a fixed key_id like `"s1"` had
        /// DIFFERENT pubkeys on every construction — harmless while rosters
        /// were passed in-memory per test, but once E9 resolves the roster
        /// from the shared directory, two serial tests reusing `"s1"` on one
        /// pg DB got mismatched pubkeys-vs-signatures (roster from run A,
        /// signatures from run B → 0 valid). Deterministic seeding makes
        /// `"s1"` stable across tests/runs AND byte-identical to
        /// `hybrid_pubkeys("s1")`, so registration is idempotent and the
        /// resolved roster always verifies the signatures.
        pub fn new(id: &str) -> Self {
            let mut seed = [0x11u8; 32];
            for (i, b) in id.bytes().take(32).enumerate() {
                seed[i] = b;
            }
            Self {
                key_id: id.to_string(),
                ed: Ed25519Signer::from_seed(&seed).expect("ed seed"),
                mldsa: MlDsa65Signer::from_seed(&seed).expect("mldsa seed"),
            }
        }

        /// CIRISPersist#973 — an identity whose hybrid pair comes from GIVEN
        /// seeds rather than from its label: a test-anchor holder
        /// (`test-accord-holder-{i}`), whose keys are the block's, signs the
        /// dry-run ceremony as itself.
        ///
        /// # Errors
        ///
        /// A seed the signer rejects.
        pub fn from_seeds(
            key_id: &str,
            ed_seed: &[u8; 32],
            mldsa_seed: &[u8; 32],
        ) -> Result<Self, crate::federation::Error> {
            let bad = |what: &str, e: String| {
                crate::federation::Error::InvalidArgument(format!(
                    "Identity::from_seeds: {what}: {e}"
                ))
            };
            Ok(Self {
                key_id: key_id.to_owned(),
                ed: Ed25519Signer::from_seed(ed_seed).map_err(|e| bad("ed25519", e.to_string()))?,
                mldsa: MlDsa65Signer::from_seed(mldsa_seed)
                    .map_err(|e| bad("ml-dsa-65", e.to_string()))?,
            })
        }

        /// CIRISPersist#973 — the hybrid scrub of `envelope` (through the CEG
        /// produce canonicalizer) by this identity: `(original_content_hash,
        /// classical, pqc)`, the shape every federation-tier row carries.
        pub fn sign_envelope(
            &self,
            envelope: &serde_json::Value,
        ) -> (String, String, Option<String>) {
            crate::federation::tier_ingest::test_support::sign_envelope_with(
                &self.ed,
                &self.mldsa,
                envelope,
            )
        }

        /// v21.0.0 (#502 E9) — this identity as a REGISTERED `steward`
        /// `KeyRecord` (identity_type = steward, carrying this identity's
        /// pubkeys) so `resolve_steward_roster` finds it in the directory.
        /// The E9 model: stewards are registered steward keys, not a
        /// caller-passed roster.
        pub fn steward_key_record(&self) -> crate::federation::types::KeyRecord {
            let m = self.member();
            // v62.0.0 (E0) — under the switch, the steward's edition-2 key
            // record (its read model) when this identity is the deterministic
            // key its id seeds; an identity from other seeds keeps the earlier
            // form (no seed names it).
            if crate::federation::edition2::fixture_switch::emit_edition2()
                && m.ed25519_public_key_base64
                    == crate::federation::tier_ingest::test_support::hybrid_pubkeys(&self.key_id).0
            {
                return crate::federation::edition2::fixture_switch::key_row_for_earlier(
                    &self.key_id,
                    crate::federation::types::identity_type::STEWARD,
                    None,
                    None,
                );
            }
            crate::federation::types::KeyRecord {
                key_id: self.key_id.clone(),
                pubkey_ed25519_base64: m.ed25519_public_key_base64,
                pubkey_ml_dsa_65_base64: m.mldsa65_public_key_base64,
                algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
                identity_type: crate::federation::types::identity_type::STEWARD.to_owned(),
                identity_ref: self.key_id.clone(),
                // Fixed timestamp — deterministic content so the same key_id
                // registers idempotently across serial tests on a shared DB.
                valid_from: "2020-01-01T00:00:00Z".parse().unwrap(),
                valid_until: None,
                registration_envelope: json!({ "key_id": self.key_id }),
                original_content_hash: {
                    use sha2::Digest as _;
                    let env = json!({ "key_id": self.key_id });
                    let canonical =
                        crate::verify::canonical::ceg_produce_canonicalize(&env).unwrap();
                    hex::encode(sha2::Sha256::digest(&canonical))
                },
                scrub_signature_classical: "AA".to_owned(),
                scrub_signature_pqc: None,
                scrub_key_id: self.key_id.clone(),
                scrub_timestamp: "2020-01-01T00:00:00Z".parse().unwrap(),
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                // v47.3.0 (#901, FSD §3.6) — every synthetic identity is hardware-attested.
                attestation_evidence: Some(crate::federation::hardware_attestation::test_support::fresh_accord_holder_evidence()),
                consent_role: None,
                additional_scrubs: Vec::new(),
            }
        }

        /// This identity as a plain (non-founder) directory member.
        pub fn member(&self) -> ciris_verify_core::threshold::ThresholdMember {
            ciris_verify_core::threshold::ThresholdMember {
                member_id: self.key_id.clone(),
                ed25519_public_key_base64: b64().encode(self.ed.public_key().unwrap()),
                mldsa65_public_key_base64: Some(b64().encode(self.mldsa.public_key().unwrap())),
                role: None,
            }
        }

        /// This identity as a `Founder`-role roster member (partner_record
        /// quorum counts only Founders).
        pub fn founder_member(&self) -> ciris_verify_core::threshold::ThresholdMember {
            let mut m = self.member();
            m.role = Some(ciris_verify_core::threshold::Role::Founder);
            m
        }

        /// Hybrid-sign `bytes` → (ed_sig_b64, mldsa_sig_b64) bound payload.
        pub fn sign_bytes(&self, bytes: &[u8]) -> (String, String) {
            let ed_sig = self.ed.sign(bytes).unwrap();
            let mut bound = bytes.to_vec();
            bound.extend_from_slice(&ed_sig);
            let pqc_sig = self.mldsa.sign(&bound).unwrap();
            (b64().encode(&ed_sig), b64().encode(&pqc_sig))
        }

        /// A threshold signature over `bytes` for the partner quorum.
        pub fn threshold_sig(
            &self,
            bytes: &[u8],
        ) -> crate::federation::types::RetiredMemberPairSignature {
            let (ed, mldsa) = self.sign_bytes(bytes);
            crate::federation::types::RetiredMemberPairSignature {
                member_id: self.key_id.clone(),
                ed25519_signature_base64: ed,
                mldsa65_signature_base64: Some(mldsa),
            }
        }
    }

    /// v13.2.0 (CIRISPersist#383) — build a **multi-scrub canonical**
    /// `KeyRecord` for `key_id` carrying `identity_type`, scrubbed by each of
    /// `scrubbers` over the SAME canonical `registration_envelope` (JCS via
    /// `ceg_produce_canonicalize` — the IDENTICAL bytes
    /// [`check_canonical_role_admission`](crate::federation::admission::check_canonical_role_admission)
    /// verifies). Scrub #1 fills the base `scrub_key_id`/`scrub_signature_*`
    /// fields; scrubs #2..N ride `additional_scrubs`. Each scrub is a REAL
    /// hybrid signature by the scrubber's keypair, so the strict-majority add gate
    /// (`verify_quorum_policy`) counts it. Pass the accord-holder `Identity`s as
    /// `scrubbers` (2 distinct: a strict majority of a three-holder fixture). `envelope` lets a test embed
    /// e.g. a `transport_hints` array (the bootstrap-dial-set surface).
    ///
    /// # v31.0.0 (CIRISPersist#659) — BREAKING: the subject is now BOUND
    ///
    /// The helper stamps the subject's `key_id`, `identity_type` and BOTH
    /// pubkeys into
    /// `envelope` before canonicalizing and signing it, through the one shared
    /// [`crate::federation::admission::bind_subject_into_envelope`] — the same
    /// projection the co-scrub gate checks with, so a record this helper builds
    /// is conformant by construction and a caller cannot write the binding
    /// wrong. Every other field of `envelope` survives untouched.
    ///
    /// Two changes, both deliberate:
    ///
    /// - a **preimage change** for any caller whose envelope did not already
    ///   carry every [`crate::federation::admission::subject_binding`] member
    ///   (the in-repo `{"key_id": k}` fixtures did not) — the signed bytes now
    ///   differ, so records must be re-minted, not re-used;
    /// - a **signature change**: the subject's pubkeys are explicit parameters.
    ///   #659's second half is precisely that the accord signs for the
    ///   subject's KEYS and not merely its name, and a helper that hardcoded
    ///   ONE placeholder pubkey for every record could not express two records
    ///   whose keys differ — i.e. could not express the attack, and so could
    ///   not witness the fix.
    ///
    /// Mechanical update for downstream mesh simulations: insert
    /// `PLACEHOLDER_SUBJECT_ED25519_BASE64, None,` after `identity_type` to
    /// keep exactly the pre-#659 columns. A caller that used to OVERWRITE
    /// `record.pubkey_ed25519_base64` after the call must pass the key here
    /// instead — post-hoc mutation now (correctly) breaks the binding.
    pub fn signed_canonical_record(
        key_id: &str,
        identity_type: &str,
        pubkey_ed25519_base64: &str,
        pubkey_ml_dsa_65_base64: Option<&str>,
        envelope: serde_json::Value,
        scrubbers: &[&Identity],
    ) -> crate::federation::types::KeyRecord {
        use crate::federation::types::ScrubSig;
        use sha2::{Digest, Sha256};
        // v62.0.0 (E0) — under the switch, the subject's edition-2 key record
        // (its read model) when the pubkeys are the deterministic ones its id
        // seeds. The scrubbers' conferral is not carried: canonical standing
        // is the genesis bundle's `serve_nodes` (RULINGS ruling C). Foreign
        // pubkeys keep the earlier form (no seed signs for them).
        if crate::federation::edition2::fixture_switch::emit_edition2()
            && pubkey_ed25519_base64
                == crate::federation::tier_ingest::test_support::hybrid_pubkeys(key_id).0
        {
            return crate::federation::edition2::fixture_switch::key_row_for_earlier(
                key_id,
                identity_type,
                None,
                None,
            );
        }
        // #659 — bind the subject BEFORE the bytes are formed: the accord
        // family must sign a preimage that names the key it confers on.
        let mut envelope = envelope;
        crate::federation::admission::bind_subject_into_envelope(
            &mut envelope,
            key_id,
            identity_type,
            pubkey_ed25519_base64,
            pubkey_ml_dsa_65_base64,
            None,
        )
        .expect("bind the #659 subject into the registration envelope");
        let bytes = crate::verify::canonical::ceg_produce_canonicalize(&envelope)
            .expect("canonicalize envelope");
        let now = crate::host::clock::now();
        let scrub_sigs: Vec<ScrubSig> = scrubbers
            .iter()
            .map(|s| {
                let (ed, pqc) = s.sign_bytes(&bytes);
                ScrubSig {
                    cosigned_at: None,
                    scrub_key_id: s.key_id.clone(),
                    scrub_signature_classical: ed,
                    scrub_signature_pqc: Some(pqc),
                }
            })
            .collect();
        assert!(!scrub_sigs.is_empty(), "at least one scrubber required");
        let first = scrub_sigs[0].clone();
        crate::federation::types::KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: pubkey_ed25519_base64.to_owned(),
            pubkey_ml_dsa_65_base64: pubkey_ml_dsa_65_base64.map(str::to_owned),
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(Sha256::digest(&bytes)),
            scrub_signature_classical: first.scrub_signature_classical,
            scrub_signature_pqc: first.scrub_signature_pqc,
            scrub_key_id: first.scrub_key_id,
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            // v47.3.0 (#901, FSD §3.6) — every synthetic identity is hardware-attested.
            attestation_evidence: Some(
                crate::federation::hardware_attestation::test_support::fresh_accord_holder_evidence(
                ),
            ),
            consent_role: None,
            additional_scrubs: scrub_sigs[1..].to_vec(),
        }
    }

    /// v18.3.0 (CIRISPersist#484) — a co-scrubbed record that carries
    /// `roles`, so a consumer can test the `has_accord_conferred_role` **ALLOW**
    /// path (not just the deny path).
    ///
    /// Identical to [`signed_canonical_record`] but stamps `roles` onto the
    /// row. The co-scrub is over `JCS(registration_envelope)` (the roles
    /// column is not part of the signed bytes — matching the production
    /// admission model: role CLAIM is the column, role CONFERRAL is the
    /// re-verified co-scrub against the accord roster). Pass 2 distinct
    /// accord-holder `Identity`s (a strict majority of a three-holder fixture) as `scrubbers`, register
    /// them with [`register_accord_holder`], then read back with
    /// [`crate::federation::admission::has_accord_conferred_role_over_roster`] over
    /// their key_ids.
    ///
    /// v31.0.0 (CIRISPersist#659) — takes the subject's pubkeys for the same
    /// reason [`signed_canonical_record`] does, and in the same position; see
    /// that helper's BREAKING note.
    pub fn signed_canonical_record_with_roles(
        key_id: &str,
        identity_type: &str,
        pubkey_ed25519_base64: &str,
        pubkey_ml_dsa_65_base64: Option<&str>,
        roles: Vec<String>,
        envelope: serde_json::Value,
        scrubbers: &[&Identity],
    ) -> crate::federation::types::KeyRecord {
        let mut rec = signed_canonical_record(
            key_id,
            identity_type,
            pubkey_ed25519_base64,
            pubkey_ml_dsa_65_base64,
            envelope,
            scrubbers,
        );
        // v62.0.0 (E0) — an edition-2 record carries no capability roles.
        if crate::federation::edition2::fixture_switch::emit_edition2()
            && crate::federation::edition2::projection::edition_of_key_record(&rec)
                == crate::federation::edition2::projection::EDITION_TWO
        {
            return rec;
        }
        rec.capability_roles = roles;
        rec
    }

    /// v31.0.0 (CIRISPersist#659) — the subject Ed25519 pubkey
    /// [`signed_canonical_record`] hardcoded for EVERY record it minted before
    /// the subject binding landed (32 bytes of `0x07`, base64).
    ///
    /// Exported so a downstream mesh simulation's update is a two-token
    /// insertion that preserves its records' columns byte-for-byte. It is a
    /// PLACEHOLDER, not a key: no private half exists, so a record carrying it
    /// can never sign anything, and two records carrying it are the SAME
    /// identity as far as the #659 binding is concerned. A simulation that
    /// needs distinct canonicals must now pass distinct keys — which is the
    /// point of binding the pubkeys at all, and the reason this could not stay
    /// a hidden constant.
    pub const PLACEHOLDER_SUBJECT_ED25519_BASE64: &str =
        "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";

    /// v18.3.0 (CIRISPersist#484) — register `holder`'s PINNED hybrid
    /// pubkeys as a directory row so the accord roster resolves to keys the
    /// co-scrub can be verified against. `node` identity_type (not
    /// `accord_holder`) so it skips the hardware-signer gate — the roster
    /// resolution in `verify_accord_family_coscrub` only needs the pubkeys,
    /// not the HW attestation. The exported analogue of admission's
    /// previously-private `register_founder`.
    ///
    /// v22.0.0 (CIRISPersist#543) — **fully deterministic**: `valid_from` /
    /// `scrub_timestamp` are the same FIXED instant `Identity::steward_key_record`
    /// pins, not `Utc::now()`. Combined with `Identity::new`'s deterministic
    /// seeding (#502 E9) and the timestamp-free `registration_envelope`, a given
    /// `holder` now produces a BYTE-IDENTICAL record on every call — so
    /// re-registering the same holder against a shared postgres test DB is a
    /// true no-op instead of a differing-content write under a fixed `key_id`.
    /// That matters as of [`register_genesis_accord_roster`], which registers
    /// the FIXED genesis ids (`A1`/`B1`/`C1`) rather than per-test unique ones,
    /// and is called once per conferred key.
    pub async fn register_accord_holder(
        directory: &dyn crate::federation::FederationDirectory,
        holder: &Identity,
    ) -> Result<(), crate::federation::Error> {
        register_accord_holder_as(
            directory,
            holder,
            crate::federation::types::identity_type::NODE,
        )
        .await
    }

    /// [`register_accord_holder`] with the record's own `identity_type` set
    /// chosen by the caller. The historical fixture types its holders `node`;
    /// the baked production holders are typed `accord_holder`
    /// (`genesis/accord_holder_seed.json`), which is the shape #972's
    /// holder-as-founder witnesses need.
    pub async fn register_accord_holder_as(
        directory: &dyn crate::federation::FederationDirectory,
        holder: &Identity,
        own_identity_type: &str,
    ) -> Result<(), crate::federation::Error> {
        use sha2::{Digest, Sha256};
        let m = holder.member();
        let registration_envelope = json!({ "key_id": holder.key_id });
        // The pinned instant — see the determinism note above. Well in the past,
        // so the row is live for every gate that reads `valid_from`.
        let pinned: chrono::DateTime<chrono::Utc> = "2020-01-01T00:00:00Z"
            .parse()
            .expect("pinned holder timestamp is valid RFC-3339");
        // v21.14.0 (CIRISPersist#534) — self-scrub the holder registration for
        // real: canonicalize the envelope, hash it to a VALID-HEX
        // `original_content_hash`, and sign those exact bytes with the holder's
        // own hybrid key. The pre-#534 placeholders (`original_content_hash =
        // "test-anchor"`, `scrub_signature_classical = "AA"`) are NON-HEX /
        // NON-BASE64 and the SQLite backend hex/base64-decodes both columns on
        // `put_public_key` — so the holder never landed on sqlite (blocker 1),
        // which then starved roster resolution to 0 valid co-scrubs (blocker 2).
        // The (since retired) memory backend tolerated the placeholders, which
        // is why this crate's own helper test only ever ran on memory (the #518 "tested on one
        // backend, used on the other" shape). A real self-scrub round-trips on
        // every backend.
        let bytes = crate::verify::canonical::ceg_produce_canonicalize(&registration_envelope)
            .expect("canonicalize holder registration envelope");
        let (ed, pqc) = holder.sign_bytes(&bytes);
        let rec = crate::federation::types::KeyRecord {
            key_id: holder.key_id.clone(),
            pubkey_ed25519_base64: m.ed25519_public_key_base64,
            pubkey_ml_dsa_65_base64: m.mldsa65_public_key_base64,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: own_identity_type.to_owned(),
            identity_ref: holder.key_id.clone(),
            valid_from: pinned,
            valid_until: None,
            registration_envelope,
            original_content_hash: hex::encode(Sha256::digest(&bytes)),
            scrub_signature_classical: ed,
            scrub_signature_pqc: Some(pqc),
            scrub_key_id: holder.key_id.clone(),
            scrub_timestamp: pinned,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            // v47.3.0 (#901, FSD §3.6) — every synthetic identity is hardware-attested.
            attestation_evidence: Some(
                crate::federation::hardware_attestation::test_support::fresh_accord_holder_evidence(
                ),
            ),
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        // persist_row_hash is (re)computed by the backend on write (parity
        // with admission's private `register_founder`, which left it empty).
        directory
            .put_public_key(crate::federation::types::SignedKeyRecord { record: rec })
            .await
    }

    /// v21.14.0 (CIRISPersist#534) — the ONE backend-agnostic conferral
    /// primitive: stand up a fresh three-holder accord family (strict majority: two), register its pinned
    /// pubkeys, and write a `key_id` canonical record whose `roles` are
    /// genuinely co-scrubbed by two distinct holders — so
    /// [`crate::federation::admission::has_accord_conferred_role_over_roster`] (over
    /// the returned roster) reads the conferred roles TRUE on any backend
    /// (sqlite / postgres / memory).
    ///
    /// This is the honest path the `InfraAttestRoleNotAccordConferred` gate
    /// demands — it does the real m-of-n dance, it does NOT bypass conferral.
    /// Consumers building an in-process round test (agent-shaped → canonical-
    /// shaped, real engines/bridges, no docker) call this instead of
    /// reassembling an accord family by hand (which every consumer got subtly
    /// wrong — CIRISPersist#534). Returns the holder roster (their `key_id`s)
    /// to pass to `has_accord_conferred_role_over_roster` / admission.
    ///
    /// The `family_tag` scopes the generated holder ids so repeated calls (and
    /// a shared postgres test DB) do not collide.
    ///
    /// # `infra:attest` vs `infra:serve` — the FIPS-custody caveat (CIRISPersist#536)
    ///
    /// This helper confers via the roster-co-scrub core, which is exactly what
    /// `infra:attest` needs. **`infra:serve` is stricter**: its admission runs
    /// the m-of-n with `require_fips_custody = true` (CIRISPersist#513), and the
    /// roster resolves from
    /// [`accord_holder_roster`](crate::federation::admission::accord_holder_roster) —
    /// the GENESIS holders — **never from the holders this helper mints**. So a
    /// software-signed `infra:serve` conferral only verifies under test-anchor
    /// **Mode A** (`CIRIS_TESTING_MODE=true` + `CIRIS_TEST_TRUST_ROOT*`
    /// publishing the genesis holders' pubkeys). Without that, the co-scrub is
    /// checked against genesis pubkeys the minted holders do not hold and the
    /// failure surfaces as an opaque `insufficient distinct valid signatures:
    /// 0 < threshold 2`. If you are standing up a TRUST ROOT (the `infra:serve`
    /// SCOPE in a `delegates_to` charter, a different plane from the key ROLE),
    /// use [`rooted_trust_root`](crate::federation::edition2::fixture_trust_root::rooted_trust_root)
    /// instead — it needs none of this (v62.0.0 R2-fixture: the root is the
    /// bundle's lineage).
    pub async fn confer_roles(
        directory: &dyn crate::federation::FederationDirectory,
        key_id: &str,
        roles: &[&str],
        family_tag: &str,
    ) -> Result<Vec<String>, crate::federation::Error> {
        let holders = [
            Identity::new(&format!("{family_tag}-h0")),
            Identity::new(&format!("{family_tag}-h1")),
            Identity::new(&format!("{family_tag}-h2")),
        ];
        for h in &holders {
            register_accord_holder(directory, h).await.map_err(|e| {
                crate::federation::Error::Backend(format!("#548 step holder-reg {}: {e}", h.key_id))
            })?;
        }
        let roster: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();
        let record = signed_canonical_record_with_roles(
            key_id,
            crate::federation::types::identity_type::NODE,
            PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            roles.iter().map(|r| (*r).to_owned()).collect(),
            json!({ "key_id": key_id, "conferred_by": family_tag }),
            &[&holders[0], &holders[1]],
        );
        directory
            .put_public_key(crate::federation::types::SignedKeyRecord { record })
            .await?;
        Ok(roster)
    }

    /// The accord holders of the INGESTED genesis, as test identities named
    /// by their identity-refs (v62.0.0, C5-fix1; ceremony gap 1).
    ///
    /// Until v62.0 this registered TEST key material under the baked A1/B1/C1
    /// `key_id`s (or the test-anchor block's `test-accord-holder-{i}`), so an
    /// earlier-form (JSON) co-scrub by them met the write-side role gates. The
    /// baked roster is deleted: the roster is the holders of the
    /// `ceg-genesis-bundle/2` in force
    /// ([`accord_holder_roster`](crate::federation::admission::accord_holder_roster)),
    /// edition-2 composite keys whose private halves no `Identity` holds. So
    /// this registers NOTHING, returns the empty list on a directory with no
    /// genesis, and an earlier-form co-scrub by the identities it returns never
    /// verifies (`earlier_form_signer_is_edition2`). Every caller asserts
    /// earlier-form conferral behaviour.
    // TODO(json-cut C5): delete with its callers at the E flip (edition-2
    // conferral fixtures: `edition2::fixture_genesis`).
    pub async fn register_genesis_accord_roster(
        directory: &dyn crate::federation::FederationDirectory,
    ) -> Result<Vec<Identity>, crate::federation::Error> {
        Ok(
            crate::federation::admission::accord_holder_roster(directory)
                .await?
                .iter()
                .map(|identity_ref| Identity::new(identity_ref.as_str()))
                .collect(),
        )
    }

    /// v22.0.0 (CIRISPersist#543) — turn a self-scrubbed fixture `KeyRecord`
    /// into an accord-**CONFERRED** one: replace the placeholder scrub columns
    /// with REAL hybrid signatures by each of `scrubbers` over
    /// `JCS(registration_envelope)` — the identical bytes
    /// `verify_accord_family_coscrub` re-canonicalizes and verifies. Scrub #1
    /// fills the base `scrub_key_id`/`scrub_signature_*` fields, #2..N ride
    /// `additional_scrubs`, and `original_content_hash` is recomputed over the
    /// same bytes.
    ///
    /// Everything else on the record is preserved — notably its `key_id`,
    /// `identity_type` and (deterministic) pubkeys — so a fixture keeps
    /// testing what it always tested and only the CONFERRAL changes: the key
    /// stops asserting its own privileged type and starts being granted it.
    /// Pass 2 distinct [`register_genesis_accord_roster`] holders for a
    /// strict-majority admit (two of a three-holder fixture).
    pub fn accord_conferred(
        mut record: crate::federation::types::KeyRecord,
        scrubbers: &[&Identity],
    ) -> crate::federation::types::KeyRecord {
        use crate::federation::types::ScrubSig;
        use sha2::{Digest, Sha256};
        assert!(!scrubbers.is_empty(), "at least one scrubber required");
        // v62.0.0 (E0) — under the switch an edition-2 record is returned as
        // it is: a conferral is the genesis bundle's (RULINGS ruling C), never
        // co-scrubs on a key record.
        if crate::federation::edition2::fixture_switch::emit_edition2()
            && crate::federation::edition2::projection::edition_of_key_record(&record)
                == crate::federation::edition2::projection::EDITION_TWO
        {
            return record;
        }
        // v31.0.0 (CIRISPersist#659) — the SECOND producer of co-scrubbed
        // records, and therefore the second place the subject has to be bound.
        // It runs through the same `bind_subject_into_envelope` the gate checks
        // with, off the record's OWN key_id, identity_type and pubkeys, so a
        // fixture cannot hand the accord family a preimage that names somebody
        // else — nor, since 13.1.0, one that names a DIFFERENT STANDING for the
        // same key, which is the conferral this helper exists to simulate.
        crate::federation::admission::bind_subject_into_envelope(
            &mut record.registration_envelope,
            &record.key_id,
            &record.identity_type,
            &record.pubkey_ed25519_base64,
            record.pubkey_ml_dsa_65_base64.as_deref(),
            None,
        )
        .expect("bind the #659 subject into the registration envelope");
        let bytes =
            crate::verify::canonical::ceg_produce_canonicalize(&record.registration_envelope)
                .expect("canonicalize registration_envelope");
        let scrubs: Vec<ScrubSig> = scrubbers
            .iter()
            .map(|s| {
                let (ed, pqc) = s.sign_bytes(&bytes);
                ScrubSig {
                    cosigned_at: None,
                    scrub_key_id: s.key_id.clone(),
                    scrub_signature_classical: ed,
                    scrub_signature_pqc: Some(pqc),
                }
            })
            .collect();
        record.original_content_hash = hex::encode(Sha256::digest(&bytes));
        record.scrub_key_id = scrubs[0].scrub_key_id.clone();
        record.scrub_signature_classical = scrubs[0].scrub_signature_classical.clone();
        record.scrub_signature_pqc = scrubs[0].scrub_signature_pqc.clone();
        record.additional_scrubs = scrubs[1..].to_vec();
        record
    }

    /// v22.0.0 (CIRISPersist#543) — the one-call fixture path for "this key
    /// legitimately holds a privileged `identity_type`": stand up the genesis
    /// accord roster ([`register_genesis_accord_roster`]), co-scrub `record`
    /// to the family m-of-n ([`accord_conferred`]), and write it.
    ///
    /// Use wherever a fixture previously SELF-ASSERTED a member of
    /// `identity_type::AUTHORITY_CONFERRING_IDENTITY_TYPES` whose
    /// `ConferralMode` is `AccordCoScrubbed` (`trusted_publisher` /
    /// `lenscore_detector`) — types that assert about a THIRD PARTY and so are
    /// refused fail-closed at every `federation_keys` write chokepoint when
    /// self-declared (`Error::RoleNotAccordConferred`).
    pub async fn put_accord_conferred_key(
        directory: &dyn crate::federation::FederationDirectory,
        record: crate::federation::types::KeyRecord,
    ) -> Result<(), crate::federation::Error> {
        let holders = register_genesis_accord_roster(directory).await?;
        assert!(
            holders.len() >= 2,
            "the genesis accord roster must have at least 2 holders to reach a strict-majority quorum"
        );
        let record = accord_conferred(record, &[&holders[0], &holders[1]]);
        directory
            .put_public_key(crate::federation::types::SignedKeyRecord { record })
            .await
    }

    /// v21.15.0 (CIRISPersist#536) — register `key_id` with a chosen
    /// `identity_type` and its deterministic hybrid pubkeys (the pair
    /// [`crate::federation::tier_ingest::test_support::sign_envelope`] signs
    /// with), so a federation-tier row this identity attests hybrid-verifies at
    /// the ingest gate on every backend. The placeholder scrub columns are
    /// valid-hex / valid-base64 (unlike the pre-#534 `test-anchor`), so the
    /// KeyRecord itself round-trips through sqlite/postgres column decoding.
    pub async fn register_typed_key(
        directory: &dyn crate::federation::FederationDirectory,
        key_id: &str,
        identity_type: &str,
    ) -> Result<(), crate::federation::Error> {
        // v62.0.0 (E0) — under the switch, an edition-2 `key:record`
        // (`fixture_switch::put_key`): the key's id is `kid(key_id)`. The
        // hardware evidence is not carried (see E0.md).
        if crate::federation::edition2::fixture_switch::emit_edition2() {
            use crate::federation::edition2::fixture_switch as e2;
            e2::put_key(directory, key_id, &e2::identity_types_of(identity_type)).await;
            return Ok(());
        }
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(key_id);
        let now = crate::host::clock::now();
        // An `accord_holder` registration hits the #513 hardware-attestation
        // gate on every backend: the established mock Android-StrongBox
        // evidence with a FRESH nonce passes shape + freshness (≤24h).
        // v47.3.0 (CIRISPersist#901, FSD §3.6) — EVERY synthetic identity
        // carries it: a valid root is defined by its holders' attested
        // hardware, and any key this helper registers may be seated as a
        // charter holder or stand as a Key-kind root. A fixture that wants an
        // unattested key says so through `register_typed_key_with_evidence`.
        let attestation_evidence = Some(strongbox_evidence(now));
        let rec = crate::federation::types::KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: json!({ "id": key_id }),
            original_content_hash: "deadbeef".to_owned(),
            scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        directory
            .put_public_key(crate::federation::types::SignedKeyRecord { record: rec })
            .await
    }

    /// v47.3.0 (CIRISPersist#901) — [`register_typed_key`] with the
    /// evidence CHOSEN by the caller (`None` = a software-class record), through
    /// the LOCAL door (`put_public_key`: structure + freshness at admission).
    pub async fn register_typed_key_with_evidence(
        directory: &dyn crate::federation::FederationDirectory,
        key_id: &str,
        identity_type: &str,
        attestation_evidence: Option<serde_json::Value>,
    ) -> Result<(), crate::federation::Error> {
        let rec = typed_key_record(key_id, identity_type, attestation_evidence);
        directory
            .put_public_key(crate::federation::types::SignedKeyRecord { record: rec })
            .await
    }

    /// v47.3.0 (#901) — the same record arriving BY REPLICATION
    /// (`apply_replicated_key_record`: structure only — its nonce was fresh
    /// where it registered).
    pub async fn apply_replicated_typed_key_with_evidence(
        directory: &dyn crate::federation::FederationDirectory,
        key_id: &str,
        identity_type: &str,
        attestation_evidence: Option<serde_json::Value>,
    ) -> Result<crate::federation::register::ReplicatedKeyOutcome, crate::federation::Error> {
        // The replicated door verifies the registration envelope binds its
        // subject (#659) and the hybrid signature over it; the evidence rides
        // OUTSIDE the envelope, as it does on a real record.
        let mut rec = crate::federation::tier_ingest::test_support::replicated_key_record(
            key_id,
            identity_type,
            key_id,
            key_id,
            "v1",
        );
        rec.attestation_evidence = attestation_evidence;
        directory
            .apply_replicated_key_record(crate::federation::types::SignedKeyRecord { record: rec })
            .await
    }

    /// The `KeyRecord` [`register_typed_key`] builds, with the evidence
    /// supplied rather than derived from the role.
    fn typed_key_record(
        key_id: &str,
        identity_type: &str,
        attestation_evidence: Option<serde_json::Value>,
    ) -> crate::federation::types::KeyRecord {
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(key_id);
        let now = crate::host::clock::now();
        crate::federation::types::KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: json!({ "id": key_id }),
            original_content_hash: "deadbeef".to_owned(),
            scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    // v62.0.0 (R2-fixture; CC 3.2 T5, "the root is the bundle's lineage") —
    // `seed_chartered_family_root` and
    // `seed_chartered_family_root_with_scrubs` DELETED (no caller): a chartered FAMILY
    // root signed by a holder is the earlier form; the root is the bundle
    // (`edition2::fixture_trust_root`).

    /// The established mock Android-StrongBox `attestation_evidence` value the
    /// #513 hardware-attestation gate accepts in test builds (shape + a fresh
    /// `nonce_captured_at`; the cert chain is not cryptographically walked
    /// here). Mirrors the sqlite backend's own `android_strongbox_evidence_value`
    /// test fixture — the ONE shape that lets an `accord_holder` register
    /// without real hardware.
    pub(crate) fn strongbox_evidence(
        captured_at: chrono::DateTime<chrono::Utc>,
    ) -> serde_json::Value {
        json!({
            "platform_attestation": {
                "Android": {
                    "key_attestation_chain": [
                        vec![0x30u8, 0x82, 0x01, 0x00],
                        vec![0x30u8, 0x82, 0x02, 0x00],
                    ],
                    "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                    "strongbox_backed": true,
                }
            },
            "nonce_captured_at": captured_at.to_rfc3339(),
        })
    }

    /// v21.15.0 (CIRISPersist#536) — a federation-tier [`Attestation`] REALLY
    /// signed by `attester`'s deterministic hybrid key (via `sign_envelope`),
    /// so it passes the federation-tier ingest hybrid-verify on sqlite/postgres
    /// (not just on a backend that skips it). The graph-shaped counterpart to
    /// [`signed_canonical_record`] (which builds a `KeyRecord`); the trust-root
    /// legs are `delegates_to` / `scores` rows, not key records.
    pub(crate) fn signed_trust_attestation(
        id: &str,
        attester: &str,
        attested: &str,
        attestation_type: &str,
        envelope: serde_json::Value,
    ) -> crate::federation::Attestation {
        // Signed by the attester's OWN deterministic key (the synthetic case).
        signed_trust_attestation_signed_by(
            id,
            attester,
            attested,
            attestation_type,
            envelope,
            attester,
        )
    }

    /// v21.16.0 (CIRISPersist#536 follow-up) — like [`signed_trust_attestation`]
    /// but signs with `signing_key_id`'s key while stamping `attester` as the
    /// `attesting_key_id` / `scrub_key_id`. Models a REAL engine-backed user
    /// whose registered pubkey is `hybrid_pubkeys(signing_key_id)`, NOT the
    /// deterministic `hybrid_pubkeys(attester)` — so its OWN signer produces an
    /// edge that hybrid-verifies while `sign_envelope(attester)` would not.
    fn signed_trust_attestation_signed_by(
        id: &str,
        attester: &str,
        attested: &str,
        attestation_type: &str,
        envelope: serde_json::Value,
        signing_key_id: &str,
    ) -> crate::federation::Attestation {
        let (och, sc, sp) =
            crate::federation::tier_ingest::test_support::sign_envelope(signing_key_id, &envelope);
        let now = crate::host::clock::now();
        crate::federation::tier_ingest::test_support::seal_row(
            signing_key_id,
            crate::federation::Attestation {
                attestation_id: id.to_owned(),
                attesting_key_id: attester.to_owned(),
                attested_key_id: attested.to_owned(),
                attestation_type: attestation_type.to_owned(),
                weight: Some(1.0),
                asserted_at: now,
                expires_at: None,
                attestation_envelope: envelope,
                original_content_hash: och,
                scrub_signature_classical: sc,
                scrub_signature_pqc: sp,
                scrub_key_id: attester.to_owned(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: Vec::new(),
                withdraws_admission_rule: None,
                cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
                tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            },
        )
    }

    // v62.0.0 (R2-fixture; CC 3.2 T5, "the root is the bundle's lineage") —
    // `grant_scope` DELETED: a conferral signed
    // by ONE root key is the keyed root; a root grant is counted over the bundle's
    // holders (`fixture_trust_root::put_conferral`).

    /// **CIRISPersist#548 — a conferral the capability walk must see, and the
    /// asking node's own trust chain it must still require in full.**
    ///
    /// The earlier body pinned the baked-seed shape: an accord co-scrub
    /// inside a key record's `registration_envelope` (the
    /// `ConferralPlane::AccordCoScrub` read). v62.0.0 (E9, I3345): that
    /// plane has no edition-2 form. A `key:record` carries no co-scrub and no
    /// roles (CC 3.4.7.1), the walk reads the plane only while the
    /// earlier-form doors are open (CC 2.6.1.12), and a canonical's serve
    /// standing is the genesis bundle's `serve_nodes` (ruling C; C1's
    /// witnesses). The AccordCoScrub assertion is DELETED with it.
    ///
    /// What #548 protects stands, on the delegation plane:
    /// - the conferral (`trust:confers:v1` from the root, with the delegate's
    ///   second voice) yields a candidate, and the node's own chain (its
    ///   acceptance, the root's charter with recovery) is still required in
    ///   full: the walk returns the ROOT, plane `Delegation`;
    /// - the drill is a SIGNAL, not a gate: none minted, `Red`, still valid,
    ///   and the walk still confers;
    /// - candidacy is EARNED (run before the lever, so each negative is
    ///   load-bearing against a walk that would otherwise succeed): a grant
    ///   signed by one holder alone confers nothing; a grant of a DIFFERENT
    ///   scope confers nothing here;
    /// - THE LEVER: withdraw the node's ONE acceptance edge and trust
    ///   collapses, with the conferral still fully valid.
    ///
    /// PRECONDITION: the runner sets the node key.
    /// DEPENDS ON W1: `trust_root_valid`'s edition-2 arm (W1b update 5: legs
    /// at the root, the founders' hardware leg) and the ruling that an id
    /// holding a trust-root community never takes the key arm.
    pub async fn exercise_ceremony_plane_capability_walk(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::edition2::fixture_genesis::HOLDER_SEEDS;
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::trust_root::{
            capability_roots_to_trusted_root, trust_root_valid, ConferralPlane, DrillFreshness,
            INFRA_SERVE_SCOPE,
        };

        let node = e2_node(directory, tag);
        let r = e2::rooted_trust_root(directory, &HOLDER_SEEDS, "quorum:2/3").await;
        let canonical_seed = format!("{tag}-canonical");
        crate::federation::edition2::fixture_trust_root::put_conferral(
            directory,
            &r,
            &canonical_seed,
            &[INFRA_SERVE_SCOPE],
        )
        .await?;
        let canonical = e2::kid(&canonical_seed);

        // THE #548 ASSERTION — the walk sees the conferral, through the
        // node's own chain.
        let grant = capability_roots_to_trusted_root(
            directory,
            &node,
            &canonical,
            INFRA_SERVE_SCOPE,
            crate::host::clock::now(),
        )
        .await?
        .unwrap_or_else(|| {
            panic!(
                "({tag}) #548: a conferral of {INFRA_SERVE_SCOPE} from a root the node \
                         accepted, plus the node's own live chain, must satisfy the walk"
            )
        });
        assert_eq!(
            grant.root_key_id, r.lineage,
            "({tag}) #548: the root that conferred is the one named"
        );
        assert_eq!(
            grant.conferral_plane,
            ConferralPlane::Delegation,
            "({tag}) #548: the plane is named, not fused into the grant id"
        );

        // THE DRILL IS A SIGNAL, NOT A GATE (v23.0.0, CIRISPersist#551 item 4).
        let undrilled =
            trust_root_valid(directory, &node, &r.lineage, crate::host::clock::now()).await?;
        assert!(
            undrilled.valid,
            "({tag}) #551 item 4: an UNDRILLED root must still serve: {undrilled:?}"
        );
        assert_eq!(
            undrilled.drill_freshness,
            DrillFreshness::Red,
            "({tag}) #551 item 4: …and the signal says so — Red: {undrilled:?}"
        );
        assert_eq!(
            undrilled.last_drill_at, None,
            "({tag}) #551 item 4: never drilled is carried by last_drill_at: {undrilled:?}"
        );

        // NEGATIVES — candidacy is EARNED.
        // (a) one holder's grant is not the root's: a seated holder signs a
        // conferral onto a fresh subject (with the subject's voice).
        let weak_seed = format!("{tag}-one-holder");
        let weak = e2::put_key(directory, &weak_seed, &["user"]).await;
        let holder_grant = e2_trust_edge_by_key(
            &r.founder_key(0),
            &r.founders[0],
            &weak,
            &[INFRA_SERVE_SCOPE],
        );
        e2::put_statement(directory, &holder_grant).await?;
        e2::put_statement(directory, &e2::voice_of(&holder_grant, &weak_seed)).await?;
        assert!(
            capability_roots_to_trusted_root(
                directory,
                &node,
                &weak,
                INFRA_SERVE_SCOPE,
                crate::host::clock::now()
            )
            .await?
            .is_none(),
            "({tag}) #548: ONE holder is not the threshold root — no candidate"
        );
        // (b) …and a root conferring a DIFFERENT scope confers nothing here.
        let other_seed = format!("{tag}-other-scope");
        crate::federation::edition2::fixture_trust_root::put_conferral(
            directory,
            &r,
            &other_seed,
            &["infra:store"],
        )
        .await?;
        assert!(
            capability_roots_to_trusted_root(
                directory,
                &node,
                &e2::kid(&other_seed),
                INFRA_SERVE_SCOPE,
                crate::host::clock::now()
            )
            .await?
            .is_none(),
            "({tag}) #548: a conferral confers the scopes it NAMES, nothing more"
        );

        // THE LEVER — withdraw the node's one acceptance edge; trust must
        // collapse, emergent, with the conferral still fully valid.
        withdraw_e2(directory, &node, &r.lineage, &r.acceptance).await?;
        let after = capability_roots_to_trusted_root(
            directory,
            &node,
            &canonical,
            INFRA_SERVE_SCOPE,
            crate::host::clock::now(),
        )
        .await?;
        assert!(
            after.is_none(),
            "({tag}) #548: withdrawing the node's ONE acceptance edge must collapse trust — \
             the un-trust lever is the property the corrected ask exists to protect: {after:?}"
        );
        Ok(())
    }

    // v62.0.0 (R2-fixture; CC 3.2 T5, "the root is the bundle's lineage") —
    // `establish_trust_root` /
    // `establish_trust_root_side` (the earlier-form KEYED root: a self-charter, a
    // heartbeat, one signer's conferral) DELETED. A test that needs a valid root
    // stands up `fixture_trust_root::rooted_trust_root` (the bundle's lineage, this
    // node's acceptance) and `put_conferral` (the counted grant). Adopter: CIRISServer
    // `tests/trace_round_e2e.rs:320`.

    // v62.0.0 (R2-fixture; CC 3.2 T5, "the root is the bundle's lineage") —
    // `exercise_trust_root` DELETED:
    // its body (a rooted bundle root is valid; a counted conferral roots the
    // subject's scope to it) is `exercise_ceremony_plane_capability_walk`, on every
    // backend.

    // ── v62.0.0 (E9) — edition-2 trust roots beyond W1's fixed one ─────────
    //
    // W1b's `fixture_trust_root::rooted_trust_root` stands up ONE root per
    // directory (`ROOT_SEED`), founded by every holder of the bundle in force
    // and accepted by THIS node. The witnesses below also need roots the node
    // has NOT accepted, roots founded short of the count, a second root to
    // let lapse, and a charter whose row id is known before it lands. These
    // helpers build them through the same doors and in the same shapes
    // (`fixture_trust_root.rs` read-checked): an `infrastructure` community
    // at the root key's identity-ref, voiced through T1's `group:roster`
    // door; the root key's `trust:charter:v1` self-edge; `trust:accepts:v1`
    // edges naming the held head; `trust:confers:v1` grants with the
    // delegate's second voice; and the granter's `withdraws`. Every seed is
    // an E0 seed (or a kid E0 minted in this process).

    /// The instant now, POSIX ms.
    pub fn e2_now_ms() -> u64 {
        crate::federation::edition2::fixture_switch::ms(crate::host::clock::now())
    }

    /// A CDE payload map in deterministic key order (the shape
    /// `fixture_trust_root` signs).
    fn e2_payload(
        members: Vec<(&str, ciris_verify_core::cde::Value)>,
    ) -> ciris_verify_core::cde::Value {
        use ciris_verify_core::cde::{self, Value};
        let mut m: Vec<(Value, Value)> = members
            .into_iter()
            .map(|(k, v)| (Value::Text(k.to_owned()), v))
            .collect();
        m.sort_by_key(|(k, _)| cde::encode(k));
        Value::Map(m)
    }

    fn e2_text(s: &str) -> ciris_verify_core::cde::Value {
        ciris_verify_core::cde::Value::Text(s.to_owned())
    }

    /// A `delegates_to` statement at the `trust:{job}:{version}` family,
    /// signed by `signer_seed`'s key and naming `iss` (normally the signer's
    /// own identity-ref; another one is the forged-edge shape).
    pub fn e2_trust_edge(
        signer_seed: &str,
        iss: &str,
        sub: &str,
        members: Vec<(&str, ciris_verify_core::cde::Value)>,
    ) -> Vec<u8> {
        use crate::federation::edition2::fixture_switch as e2;
        ciris_verify_core::edition2::sign_row_statement(
            &e2::signing_key(signer_seed),
            iss,
            sub,
            crate::federation::types::attestation_type::DELEGATES_TO,
            &ciris_verify_core::namespace_match::family_id(
                crate::federation::edition2::typed::TRUST_PREFIX,
            ),
            &e2_payload(members),
            vec![],
        )
        .expect("operational: sign a trust edge")
    }

    /// Install the genesis bundle in force when none is held (W1b's step 1).
    pub async fn ensure_e2_genesis(
        directory: &dyn crate::federation::FederationDirectory,
    ) -> Result<(), crate::federation::Error> {
        if !crate::federation::edition2::genesis::genesis_in_force(directory)
            .await?
            .is_held()
        {
            crate::federation::edition2::fixture_genesis::install_v2(directory).await?;
        }
        Ok(())
    }

    // v62.0.0 (R2-fixture; CC 3.2 T5, "the root is the bundle's lineage") —
    // the KEYED-root helpers (`E2Root`,
    // `e2_root_community`, `found_e2_root`, `e2_charter_statement`,
    // `stand_up_e2_root(_at)`, `confer_e2`, `establish_e2_trust_root`,
    // `seed_chartered_e2_root`) DELETED: a root community at a key with its own charter
    // self-edge and single-signer conferrals is no root. The root is
    // `fixture_trust_root::rooted_trust_root`; its grant is `put_conferral`.

    /// v62.0.0 (R2-fixture; the Constitution's `trust-accepts` rule) —
    /// `granter`'s `trust:accepts:v1` edge to the lineage `lineage` (`sub`, the
    /// bundle's `family_key_id`), attached on the bundle `bundle_hex` (object id,
    /// stated as a hash digest), stated at `asserted_at_ms`, ending at
    /// `valid_until_ms` when given. No `scope`, no `refs`. `granter` is a seed or
    /// a kid E0 minted (the node's). Pure: a bundle this node does not hold is
    /// the stale-head shape.
    pub fn e2_acceptance_statement(
        granter: &str,
        lineage: &str,
        bundle_hex: &str,
        asserted_at_ms: u64,
        valid_until_ms: Option<u64>,
    ) -> Vec<u8> {
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION;
        use ciris_verify_core::cde::Value;
        let iss = e2::kid(granter);
        let bundle = hex::decode(bundle_hex).expect("operational: a bundle id is hex");
        let mut members = vec![
            ("author", e2_text(&iss)),
            ("asserted_at", Value::Uint(asserted_at_ms)),
            ("dimension", e2_text(TRUST_ACCEPTS_DIMENSION)),
            (
                crate::federation::envelope::paths::ATTACHED_HEAD_DIGEST,
                Value::Array(vec![Value::Nint(15), Value::Bytes(bundle)]),
            ),
        ];
        if let Some(until) = valid_until_ms {
            members.push(("valid_until", Value::Uint(until)));
        }
        e2_trust_edge(granter, &iss, lineage, members)
    }

    /// v62.0.0 (R2-fixture) — [`e2_acceptance_statement`] of the lineage of the
    /// bundle in force, attached on its newest tip, put through the door. Its
    /// row id.
    ///
    /// # Errors
    /// No bundle in force; the door's refusal.
    pub async fn accept_lineage_e2_at(
        directory: &dyn crate::federation::FederationDirectory,
        granter: &str,
        asserted_at_ms: u64,
        valid_until_ms: Option<u64>,
    ) -> Result<crate::federation::edition2::names::RowId, crate::federation::Error> {
        let in_force = crate::federation::edition2::genesis::genesis_in_force(directory).await?;
        let none = || crate::federation::Error::Backend("operational: no bundle in force".into());
        let lineage = in_force.family_key_id().ok_or_else(none)?.to_owned();
        let tip = in_force
            .tips()
            .iter()
            .max_by_key(|t| t.asserted_at)
            .ok_or_else(none)?
            .object_id;
        let st = e2_acceptance_statement(
            granter,
            &lineage,
            &hex::encode(tip),
            asserted_at_ms,
            valid_until_ms,
        );
        crate::federation::edition2::fixture_switch::put_statement(directory, &st).await?;
        Ok(crate::federation::edition2::fixture_switch::row_id_of(&st))
    }

    /// [`accept_lineage_e2_at`] now, with no end.
    ///
    /// # Errors
    /// As [`accept_lineage_e2_at`].
    pub async fn accept_lineage_e2(
        directory: &dyn crate::federation::FederationDirectory,
        granter: &str,
    ) -> Result<crate::federation::edition2::names::RowId, crate::federation::Error> {
        accept_lineage_e2_at(directory, granter, e2_now_ms(), None).await
    }

    /// `granter`'s `withdraws` of its own held trust edge `edge` to `sub`
    /// (T2's `trust_withdraws_statement`): the CEG un-trust act.
    pub async fn withdraw_e2(
        directory: &dyn crate::federation::FederationDirectory,
        granter: &str,
        sub: &str,
        edge: &crate::federation::edition2::names::RowId,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::edition2::fixture_switch as e2;
        e2::put_statement(
            directory,
            &e2::trust_withdraws_statement(granter, sub, edge, e2_now_ms()),
        )
        .await
        .map(|_| ())
    }

    /// THIS directory's node key (the asking party, CC 4.4.3.34: the node is
    /// its own seed). The runner sets it first:
    /// `backend.set_node_key_id(e2::put_key(&backend, "<seed>", &["node"]).await)`.
    ///
    /// # Panics
    /// No node key.
    pub fn e2_node(directory: &dyn crate::federation::FederationDirectory, tag: &str) -> String {
        directory.node_key_id().unwrap_or_else(|| {
            panic!(
                "({tag}) the runner sets the node key first: \
                 set_node_key_id(e2::put_key(&backend, \"<seed>\", &[\"node\"]).await)"
            )
        })
    }

    /// v24.0.0 (CIRISPersist#556) — a federation-tier attestation really signed
    /// by `attester` AND co-signed by each of `cosigners` over the **same**
    /// canonical envelope bytes.
    ///
    /// Scrub #1 fills the base `scrub_key_id`/`scrub_signature_*` fields; scrubs
    /// #2..N ride `additional_scrubs`. Every co-signer must be registered with
    /// its deterministic `sign_envelope` pubkeys ([`register_typed_key`]), since
    /// both federation-tier ingest and the family-quorum count resolve each
    /// scrub key from the DIRECTORY.
    pub(crate) fn co_signed_trust_attestation(
        id: &str,
        attester: &str,
        attested: &str,
        attestation_type: &str,
        envelope: serde_json::Value,
        cosigners: &[&str],
    ) -> crate::federation::Attestation {
        let mut row =
            signed_trust_attestation(id, attester, attested, attestation_type, envelope.clone());
        // v62.0.0 (E0) — under the switch the co-signers are further
        // statements over the row (`fixture_switch::voices_of(&row,
        // cosigners)`), put after it; never co-scrubs.
        if crate::federation::edition2::fixture_switch::emit_edition2() {
            return row;
        }
        // v31.0.0 (CIRISPersist#643) — the co-signers sign the SEALED envelope,
        // i.e. the one `signed_trust_attestation` just stamped the typed-column
        // mirror into. Every scrub is over the SAME preimage (#556), and the
        // mirror is part of that preimage now.
        let envelope = row.attestation_envelope.clone();
        row.additional_scrubs = cosigners
            .iter()
            .map(|k| co_scrub(&envelope, k, &ScrubSigner::Deterministic(k)))
            .collect();
        row
    }

    /// v47.3.0 (CIRISPersist#901) — who signs a co-scrub: the deterministic
    /// test pair for a label (the default — the label is normally the scrub's
    /// own key id), or the signers `MockYubicoCa::attest_member` derived for
    /// a member from its Ed25519 seed (so the scrub verifies against the
    /// pubkeys that member's custody chain names).
    pub enum ScrubSigner<'a> {
        /// The deterministic test pair for this label.
        Deterministic(&'a str),
        /// The mock YubiKey member attested from this Ed25519 seed.
        MockMember([u8; 32]),
        /// No scrub at all: a SEATED holder who did not sign this charter
        /// (quorum may still be met by the others; this seat is then not a
        /// holder OF THIS CHARTER — the v47.3.0 leg must not judge it).
        Absent,
    }

    /// One co-scrub over the sealed envelope, `scrub_key_id = key_id`, signed
    /// by `signer`.
    fn co_scrub(
        envelope: &serde_json::Value,
        key_id: &str,
        signer: &ScrubSigner<'_>,
    ) -> crate::federation::types::ScrubSig {
        use crate::federation::tier_ingest::test_support as ts;
        let (_, classical, pqc) = match signer {
            ScrubSigner::Deterministic(label) => ts::sign_envelope(label, envelope),
            ScrubSigner::MockMember(seed) => {
                let (ed, mldsa) = ts::mock_member_signers(seed);
                ts::sign_envelope_with(&ed, &mldsa, envelope)
            }
            ScrubSigner::Absent => unreachable!("an absent scrub is filtered before signing"),
        };
        crate::federation::types::ScrubSig {
            cosigned_at: None,
            scrub_key_id: key_id.to_owned(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// v24.0.0 (CIRISPersist#557) — seed a KEYLESS constitutional family with
    /// `holders` seated as founders under `consensus_protocol`, on any backend.
    ///
    /// Written through `put_family_local` because a family has no key and
    /// therefore cannot sign its own declaration — the same door the deleted
    /// baked accord-family seed used for `humanity-accord`. The holders must already be registered.
    pub async fn seed_test_family(
        directory: &dyn crate::federation::FederationDirectory,
        family_key_id: &str,
        holders: &[String],
        consensus_protocol: &str,
    ) -> Result<(), crate::federation::Error> {
        seed_test_family_naming(directory, family_key_id, holders, consensus_protocol, "").await
    }

    /// v53.0.0 (CC 3.2 T6) — [`seed_test_family`] whose founding version
    /// names `charter_digest` as the charter in force (the head names its
    /// charter; one no version names is not in force).
    pub async fn seed_test_family_naming(
        directory: &dyn crate::federation::FederationDirectory,
        family_key_id: &str,
        holders: &[String],
        consensus_protocol: &str,
        charter_digest: &str,
    ) -> Result<(), crate::federation::Error> {
        let founded_at: chrono::DateTime<chrono::Utc> = "2020-01-01T00:00:00Z"
            .parse()
            .expect("pinned family founding instant is valid RFC-3339");
        let mut family = crate::federation::types::Family {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            family_key_id: family_key_id.to_owned(),
            family_name: family_key_id.to_owned(),
            members: holders
                .iter()
                .map(|k| crate::federation::types::FamilyMember {
                    key_id: k.clone(),
                    joined_at: founded_at,
                    role: Some("founder".to_owned()),
                })
                .collect(),
            founded_at,
            consensus_protocol: consensus_protocol.to_owned(),
            consensus_protocol_entrenched: true,
            dissolved_at: None,
            persist_row_hash: String::new(),
        };
        family.charter_digest = charter_digest.to_owned();
        directory.put_family_local(family).await
    }

    /// v53.0.0 (CC 3.2 T6) — the digest a version names a charter by: the
    /// row hash the store computes for it. Fixtures compute it before the row
    /// is written (the founding version must name it, and a family must exist
    /// before its charter is admitted); [`assert_charter_digest_held`] checks
    /// the store agreed.
    pub fn charter_digest_of(charter: &crate::federation::Attestation) -> String {
        crate::federation::canonical_community::stored_row_hash(charter)
            .expect("a charter row always hashes")
    }

    /// The stored row of `attestation_id` carries `digest` — the fixture's
    /// precomputed digest is the one the store holds.
    pub async fn assert_charter_digest_held(
        directory: &dyn crate::federation::FederationDirectory,
        attested_key_id: &str,
        attestation_id: &str,
        digest: &str,
    ) {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        let held = directory
            .all_attestations_for(attested_key_id)
            .await
            .expect("list charters")
            .into_iter()
            .find(|a| a.attestation_id == attestation_id)
            .expect("the charter was stored");
        assert_eq!(
            held.persist_row_hash, digest,
            "the store's row hash of {attestation_id} is the digest the version names"
        );
    }

    /// v53.0.0 (CC 3.2 T6) — **admit a family's charter and the version that
    /// puts it in force**: the charter row, then a new version of the family
    /// it names (`attested_key_id`) whose `charter_digest` is the stored row's
    /// hash, authorized by `signers`. The shape every re-scrub takes now.
    pub async fn charter_family_and_version(
        directory: &dyn crate::federation::FederationDirectory,
        charter: crate::federation::Attestation,
        signers: &[&str],
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::attestation_query::test_support::AllAttestations as _;
        let family = charter.attested_key_id.clone();
        let id = charter.attestation_id.clone();
        directory
            .put_attestation(crate::federation::SignedAttestation {
                attestation: charter,
            })
            .await?;
        let held = directory
            .all_attestations_for(&family)
            .await?
            .into_iter()
            .find(|a| a.attestation_id == id)
            .ok_or_else(|| crate::federation::Error::Backend(format!("charter {id} not stored")))?;
        let signers: Vec<String> = signers.iter().map(|s| (*s).to_owned()).collect();
        version_family_naming_charter(directory, &family, &held.persist_row_hash, &signers)
            .await
            .map(|_| ())
    }

    /// v53.0.0 (CC 3.2 T6) — **a new version of `family_key_id` naming
    /// `charter_digest`**: same roster, protocol and entrenchment, the held
    /// head as `prev_head_digest`, authored by `signers[0]` and authorized by
    /// every signer's threshold signature over the change envelope — the
    /// shape a charter re-scrub takes now that the charter in force is the
    /// one the head names.
    pub async fn version_family_naming_charter(
        directory: &dyn crate::federation::FederationDirectory,
        family_key_id: &str,
        charter_digest: &str,
        signers: &[String],
    ) -> Result<u32, crate::federation::Error> {
        use crate::federation::tier_ingest::test_support as ts;
        let held = directory
            .lookup_family(family_key_id)
            .await?
            .ok_or_else(|| {
                crate::federation::Error::InvalidArgument(format!("no family {family_key_id}"))
            })?;
        let mut next = held.clone();
        next.prev_head_digest = held.persist_row_hash.clone();
        next.charter_digest = charter_digest.to_owned();
        next.persist_row_hash = String::new();
        let ids: Vec<String> = held.members.iter().map(|m| m.key_id.clone()).collect();
        let mut env = directory
            .build_membership_change_envelope(
                crate::federation::cohort::Cohort::Family,
                family_key_id,
                &ids,
                held.consensus_protocol_entrenched,
                Some(&held.consensus_protocol),
            )
            .await?;
        // The quorum signs WHICH version (the accord's door requires it).
        env[crate::federation::canonical_community::NEXT_PERSIST_ROW_HASH] =
            serde_json::Value::String(crate::federation::types::compute_persist_row_hash(&next)?);
        let bytes = ciris_verify_core::jcs::canonicalize(&env)
            .map_err(|e| crate::federation::Error::Backend(format!("jcs: {e}")))?;
        let sigs = signers
            .iter()
            .map(|k| ts::threshold_sign(k, &bytes))
            .collect();
        directory
            .supersede_family_with_quorum(ts::sign_family(&signers[0], next), env, sigs)
            .await
    }

    // LEAD-root1 (CC 3.2 T5) — `exercise_family_trust_root` DELETED: it witnessed the root COMMUNITY (a threshold root founded as an infrastructure community, chartered by a self-edge). The root is the bundle's lineage; its threshold is the bundle's count (genesis_invariants; root_grant_invariants I4200–I4214).

    /// A `trust:confers:v1` grant `delegates_to(iss → subject)` signed by
    /// `key` as `iss` (a bundle holder's placed key, which no E0 seed names).
    pub fn e2_trust_edge_by_key(
        key: &ciris_crypto::composite::CompositeSigningKey,
        iss: &str,
        subject: &str,
        scope: &[&str],
    ) -> Vec<u8> {
        use ciris_verify_core::cde::Value;
        ciris_verify_core::edition2::sign_row_statement(
            key,
            iss,
            subject,
            crate::federation::types::attestation_type::DELEGATES_TO,
            &ciris_verify_core::namespace_match::family_id(
                crate::federation::edition2::typed::TRUST_PREFIX,
            ),
            &e2_payload(vec![
                ("author", e2_text(iss)),
                ("asserted_at", Value::Uint(e2_now_ms())),
                (
                    "dimension",
                    e2_text(crate::federation::trust_root::TRUST_CONFERS_DIMENSION),
                ),
                (
                    "scope",
                    Value::Array(scope.iter().map(|s| e2_text(s)).collect()),
                ),
            ]),
            vec![],
        )
        .expect("operational: sign a holder's grant")
    }

    // v62.0.0 (R2-fixture; CC 3.2 T5, "the root is the bundle's lineage") —
    // `exercise_trust_root_real_user`
    // DELETED (lead's ruling): it witnessed a KEYED root. On the bundle path its two
    // properties are I2400 (before the node's edge the root is not valid) and
    // I2416/I2464 (the node, or its owner, signs its own acceptance and reads
    // rooted). GAP: a forged acceptance in the node's name (`kid_not_of_iss`) has no
    // acceptance-specific witness; the door's key-of-issuer check is witnessed
    // generically (`edition2::door`, `key_chain_invariants`).

    // v62.0.0 (R2-fixture; CC 3.2 T5, "the root is the bundle's lineage") —
    // `emit_trust_edge` (an earlier-form
    // JSON acceptance to a KEYED root) DELETED; I549 states the bundle acceptance
    // (`fixture_trust_root::bundle_acceptance_statement`).

    /// v24.1.0 (CIRISPersist#561) — tombstone `attestation_id` with a
    /// `withdraws` composer authored by `attester` (the CEG un-trust act).
    pub(crate) async fn withdraw_attestation(
        directory: &dyn crate::federation::FederationDirectory,
        attester: &str,
        subject: &str,
        attestation_id: &str,
    ) -> Result<(), crate::federation::Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let row = signed_trust_attestation(
            &id,
            attester,
            subject,
            crate::federation::types::attestation_type::WITHDRAWS,
            json!({
                "id": id,
                "references_attestation_id": attestation_id,
            }),
        );
        directory
            .put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await
            .map(|_| ())
    }

    /// v62.0.0 (E9) — put `seed`'s key as a NODE that self-offers
    /// `infra:transport` (the identity set `{infra:transport, node}`: CC 3.4.7
    /// "stand as written"; `claims_role` reads the set, P4's G9 opt-in).
    /// The self-claim conjuncts (B) and (C) of the transit gate, and NOTHING
    /// else: this alone must buy a peer nothing. Its kid.
    async fn put_transport_node(
        directory: &dyn crate::federation::FederationDirectory,
        seed: &str,
    ) -> String {
        crate::federation::edition2::fixture_switch::put_key(
            directory,
            seed,
            &[
                crate::federation::types::delegation_scope::INFRA_TRANSPORT,
                "node",
            ],
        )
        .await
    }

    /// **CIRISPersist#561 — transport-hop eligibility, end to end, on any
    /// backend.**
    ///
    /// The scenario is CIRISEdge#430's: a selecting node, a candidate relay,
    /// and a shared trust root neither of them owns. Each witness pins one
    /// clause of the rule.
    ///
    /// v62.0.0 (E9, I3342) — re-pointed at edition 2: the asking side is THIS
    /// node (its key is the runner's), the shared root is W1b's rooted
    /// threshold root, each side's trust is its own `trust:accepts:v1` edge,
    /// an un-trust is the granter's `withdraws`, and an edge's end is its
    /// `valid_until`.
    ///
    /// | # | witness | what it pins |
    /// |---|---|---|
    /// | a | unregistered user ⇒ `false` | fail-closed on the ASKING side, not just the peer's |
    /// | b | self-claimed `infra:transport`, no shared root ⇒ `false` | the AV-75 property: registering the string buys nothing |
    /// | c | all four legs ⇒ `true`, `via_root` names the root, the TTL is the earliest bound walked (the peer key's own end: a node key ends, CC 2.4.1.1) | the gate, and its authoritative cache bound |
    /// | h | a latched halt on the shared root changes nothing | a halt is an agent pause (CC 4.2.1.1) |
    /// | g | the `_over_roster` arm agrees with the default arm | the ceremony-parity entry point |
    /// | c2 | the TTL min-folds from BOTH sides | the earliest bound wins whichever side carries it |
    /// | e | a hostile peer's 50 acceptance edges change neither the verdict NOR the candidate set | the anti-inflation property |
    /// | d | each leg removed individually ⇒ `false` | every conjunct is load-bearing |
    /// | f | withdraw the node's edge ⇒ `false` on the very next call | the event-driven invalidation contract's substrate half |
    /// | e2 | an edge whose `valid_until` has passed is no edge | stale grants die of age |
    ///
    /// PRECONDITION: the runner sets the node key.
    /// DEPENDS ON W1: `trust_root_valid`'s edition-2 arm (W1b update 5: legs
    /// at the root, the founders' hardware leg) and the ruling that an id
    /// holding a trust-root community never takes the key arm.
    pub async fn exercise_transit_eligibility(
        directory: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::edition2::fixture_genesis::{identity_ref_of, HOLDER_SEEDS};
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::trust_root::{
            resolve_transit_eligibility, resolve_transit_eligibility_over_roster,
        };

        let node = e2_node(directory, tag);
        let peer_seed = format!("{tag}-peer");

        // ── (a) RED — an unregistered USER cannot be eligible for anything.
        // The peer does not exist yet either; what is pinned is that the walk
        // DENIES rather than erroring out of the caller's hands.
        let unknown = resolve_transit_eligibility(
            directory,
            &format!("{tag}-ghost-user"),
            &e2::kid(&peer_seed),
        )
        .await?;
        assert!(
            !unknown.eligible && unknown.via_root.is_none() && unknown.valid_until.is_none(),
            "({tag}) (a) an unresolvable walk DENIES — a transport gate never fails open: \
             {unknown:?}"
        );

        let peer = put_transport_node(directory, &peer_seed).await;

        // ── (b) THE AV-75 PROPERTY. The peer is a `node` offering
        // `infra:transport` — conjuncts (A)(B)(C) all hold — and there is no
        // shared root. Eligibility must be false, or the gate is a
        // self-declaration.
        let self_claimed = resolve_transit_eligibility(directory, &node, &peer).await?;
        assert!(
            !self_claimed.eligible,
            "({tag}) (b) self-claimed infra:transport with NO shared root buys NOTHING \
             (AV-75): {self_claimed:?}"
        );

        // The shared root: founded by the bundle's holders, chartered, and
        // accepted by THIS node (the fixture), plus the peer's own edge.
        let r = e2::rooted_trust_root(directory, &HOLDER_SEEDS, "quorum:2/3").await;
        let peer_edge = accept_lineage_e2(directory, &peer_seed).await?;

        // ── (c) GREEN — all four legs.
        let ok = resolve_transit_eligibility(directory, &node, &peer).await?;
        assert!(
            ok.eligible,
            "({tag}) (c) node + infra:transport + a shared valid root ⇒ eligible: {ok:?}"
        );
        assert_eq!(
            ok.via_root.as_deref(),
            Some(r.lineage.as_str()),
            "({tag}) (c) via_root NAMES the shared root — the caller's cache key"
        );
        let peer_end = directory
            .lookup_public_key(&peer)
            .await?
            .and_then(|k| k.valid_until);
        assert!(
            peer_end.is_some(),
            "({tag}) (c) a node key ends by its own record (CC 2.4.1.1)"
        );
        assert_eq!(
            ok.valid_until, peer_end,
            "({tag}) (c) no edge or charter walked is time-bounded, so the TTL is the peer \
             key's own end — the earliest bound walked, NOT a fabricated value: {ok:?}"
        );

        // ── (h) v58.0.0 (CIRISPersist#1094; CC 4.2.1.1) — a latched halt on the
        // shared root changes NOTHING here. Transit is a data door; a halt is
        // an agent pause.
        let halt_id = format!("{tag}-halt");
        directory
            .set_active_halt(&r.lineage, &halt_id, None)
            .await?;
        let under_halt = resolve_transit_eligibility(directory, &node, &peer).await?;
        assert_eq!(
            under_halt, ok,
            "({tag}) (h) a latched constitutional halt on the shared root leaves transit \
             eligibility UNCHANGED — a relay that closed here would be the breaker \
             CC 4.2.1.1 names"
        );
        directory.clear_active_halt(&r.lineage, &halt_id).await?;

        // ── (g) the `_over_roster` arm. Driven with the bundle's holders, and
        // it must agree with the default arm exactly.
        let holders: Vec<String> = HOLDER_SEEDS.iter().map(|s| identity_ref_of(*s)).collect();
        let over =
            resolve_transit_eligibility_over_roster(directory, &node, &peer, &holders).await?;
        assert_eq!(
            over, ok,
            "({tag}) (g) the _over_roster arm returns the SAME verdict — none of the four \
             conjuncts reads the ceremony plane, and the entry point must not invent one"
        );

        // ── (c2) TTL MIN-FOLD, from BOTH sides.
        //
        // Both edges must be finite for this to say anything: with one side
        // unbounded, min and max agree and a fold written the wrong way round
        // passes. So the unbounded edges are withdrawn first, and the earliest
        // bound is then moved from one side to the other. Both bounds sit well
        // inside the peer key's own end, so neither is masked by it.
        let near = crate::host::clock::now() + chrono::Duration::hours(2);
        let far = crate::host::clock::now() + chrono::Duration::hours(9);
        let ms = e2::ms;
        withdraw_e2(directory, &peer_seed, &r.lineage, &peer_edge).await?;
        withdraw_e2(directory, &node, &r.lineage, &r.acceptance).await?;
        let peer_far =
            accept_lineage_e2_at(directory, &peer_seed, e2_now_ms(), Some(ms(far))).await?;
        let user_near = accept_lineage_e2_at(directory, &node, e2_now_ms(), Some(ms(near))).await?;

        // OUR side is the earlier one.
        let bounded = resolve_transit_eligibility(directory, &node, &peer).await?;
        assert!(bounded.eligible, "({tag}) (c2) still eligible: {bounded:?}");
        let ttl = bounded
            .valid_until
            .unwrap_or_else(|| panic!("({tag}) (c2) a bounded edge MUST produce a bounded TTL"));
        assert!(
            (ttl - near).num_seconds().abs() <= 1,
            "({tag}) (c2) the EARLIEST bound wins: expected ~{near}, got {ttl}. The peer's \
             own edge ends at {far} and must not be what the caller caches to."
        );

        // THEIR side is the earlier one — same rule, other direction.
        withdraw_e2(directory, &peer_seed, &r.lineage, &peer_far).await?;
        withdraw_e2(directory, &node, &r.lineage, &user_near).await?;
        accept_lineage_e2_at(directory, &peer_seed, e2_now_ms(), Some(ms(near))).await?;
        let user_far = accept_lineage_e2_at(directory, &node, e2_now_ms(), Some(ms(far))).await?;
        let flipped = resolve_transit_eligibility(directory, &node, &peer).await?;
        let flipped_ttl = flipped
            .valid_until
            .unwrap_or_else(|| panic!("({tag}) (c2) the flipped case is bounded too"));
        assert!(
            (flipped_ttl - near).num_seconds().abs() <= 1,
            "({tag}) (c2) the earliest bound wins whichever SIDE carries it: expected \
             ~{near} (the peer's), got {flipped_ttl}"
        );

        // ── (e) ANTI-INFLATION. A hostile peer authors fifty `trust:accepts`
        // edges to fifty roots we have never heard of, and neither the verdict
        // nor the WORK may grow.
        //
        // 1. The work is read from the REAL walk's own count of candidate
        //    roots evaluated, never re-derived in the test.
        // 2. The probe peer is INELIGIBLE, so the candidate loop runs to
        //    exhaustion (the DoS shape is a candidate that never matches).
        // 3. The flood is authored by the peer being MEASURED.
        let flooded_seed = format!("{tag}-flooded");
        let flooded = put_transport_node(directory, &flooded_seed).await;
        let (before_verdict, walked_before) =
            crate::federation::trust_root::resolve_transit_eligibility_counting_roots(
                directory, &node, &flooded,
            )
            .await?;
        assert!(
            !before_verdict.eligible,
            "({tag}) (e) the probe peer shares no root, so the loop EXHAUSTS the candidate \
             set rather than short-circuiting: {before_verdict:?}"
        );
        assert_eq!(
            walked_before, 1,
            "({tag}) (e) the node trusts exactly one root, so exactly one candidate is walked"
        );
        for i in 0..50 {
            let bogus = e2::put_key(directory, &format!("{tag}-bogus{i}"), &["user"]).await;
            // v62.0.0 (R2-fixture) — a hostile peer's edge to a key it chose:
            // the shape the candidate bound exists against (no lineage, no
            // bundle named).
            e2::put_statement(
                directory,
                &e2::trust_accepts_statement(
                    &flooded_seed,
                    &bogus,
                    &[],
                    None,
                    crate::federation::types::cohort_scope::FEDERATION,
                    e2_now_ms(),
                ),
            )
            .await?;
        }
        let (after_verdict, walked_after) =
            crate::federation::trust_root::resolve_transit_eligibility_counting_roots(
                directory, &node, &flooded,
            )
            .await?;
        assert_eq!(
            walked_after, walked_before,
            "({tag}) (e) 50 peer-authored edges did not add ONE unit of work (still \
             {walked_before}, not 51). The candidate set is bounded by the ASKING node's \
             own records."
        );
        assert!(
            !after_verdict.eligible,
            "({tag}) (e) …and fifty self-authored roots still buy the peer nothing: \
             {after_verdict:?}"
        );
        let after_flood = resolve_transit_eligibility(directory, &node, &peer).await?;
        assert_eq!(
            after_flood.via_root.as_deref(),
            Some(r.lineage.as_str()),
            "({tag}) (e) the real peer still roots through OUR root, not one of theirs"
        );

        // ── (d) EVERY CONJUNCT IS LOAD-BEARING.
        //
        // (d/A) a peer that is not in the directory at all.
        let absent =
            resolve_transit_eligibility(directory, &node, &e2::kid(&format!("{tag}-ghost")))
                .await?;
        assert!(
            !absent.eligible,
            "({tag}) (d/A) directory presence is required: {absent:?}"
        );

        // (d/B) a peer that is NOT a node — same trust root, same transport
        // offer, wrong identity set.
        let agent_seed = format!("{tag}-agent");
        let agent = e2::put_key(
            directory,
            &agent_seed,
            &[
                "agent",
                crate::federation::types::delegation_scope::INFRA_TRANSPORT,
            ],
        )
        .await;
        accept_lineage_e2(directory, &agent_seed).await?;
        let not_a_node = resolve_transit_eligibility(directory, &node, &agent).await?;
        assert!(
            !not_a_node.eligible,
            "({tag}) (d/B) a non-`node` identity is not a hop, however it is rooted: \
             {not_a_node:?}"
        );

        // (d/C) a NODE, validly sharing our root, that never offered transport.
        let quiet_seed = format!("{tag}-quiet");
        let quiet = e2::put_key(directory, &quiet_seed, &["node"]).await;
        accept_lineage_e2(directory, &quiet_seed).await?;
        let no_offer = resolve_transit_eligibility(directory, &node, &quiet).await?;
        assert!(
            !no_offer.eligible,
            "({tag}) (d/C) a node that does not offer infra:transport is not a hop: \
             {no_offer:?}"
        );

        // (d/D) a peer with NO trust root of its own.
        let solo = put_transport_node(directory, &format!("{tag}-solo")).await;
        let solo_ineligible = resolve_transit_eligibility(directory, &node, &solo).await?;
        assert!(
            !solo_ineligible.eligible,
            "({tag}) (d/D) a rooted-to-nothing peer shares no root with us: \
             {solo_ineligible:?}"
        );

        // ── (f) WITHDRAWAL — the invalidation contract's substrate half.
        // Withdraw the node's ONE live edge and the very next resolution reads
        // false: the `withdraws` IS the mechanism.
        withdraw_e2(directory, &node, &r.lineage, &user_far).await?;
        let after_withdrawal = resolve_transit_eligibility(directory, &node, &peer).await?;
        assert!(
            !after_withdrawal.eligible,
            "({tag}) (f) withdrawing our own trust edge un-elects the peer on the NEXT \
             call: {after_withdrawal:?}"
        );
        assert!(
            after_withdrawal.via_root.is_none() && after_withdrawal.valid_until.is_none(),
            "({tag}) (f) a denied verdict carries no root and no TTL: {after_withdrawal:?}"
        );

        // ── (e2) EXPIRY IS HONORED without any withdrawal: an edge whose
        // `valid_until` has PASSED is as dead to the walk as a withdrawn one
        // (#488 delta 3). The edge's window is in the past but well-formed
        // (`valid_until` after `asserted_at`, K1). v62.0.0 (R2-fixture): one
        // root, the bundle's lineage; the node's only edge to it (after (f)) is
        // this expired one, and the peer's own edge (ending `near`) is live.
        let now = crate::host::clock::now();
        accept_lineage_e2_at(
            directory,
            &node,
            ms(now - chrono::Duration::minutes(10)),
            Some(ms(now - chrono::Duration::minutes(5))),
        )
        .await?;
        let expired = resolve_transit_eligibility(directory, &node, &peer).await?;
        assert!(
            !expired.eligible,
            "({tag}) (e2) an EXPIRED shared-root edge is not a shared root — stale grants \
             die of age, no withdrawal required: {expired:?}"
        );
        Ok(())
    }

    // LEAD-root1 (CC 3.2 T5) — `exercise_foreign_retraction_cannot_sever_charter` DELETED: no row is a charter. A foreign withdrawal of a root grant or of an acceptance is root_grant_invariants I4219 / peer_rooting I2223.

    // v62.0.0 (R2-fixture; CC 3.2 T5, "the root is the bundle's lineage") —
    // `exercise_transit_eligibility_family_root` DELETED (lead's ruling): there is one
    // kind of root, so "a threshold root satisfies (D) too" is
    // `exercise_transit_eligibility` itself (its shared root IS the bundle's
    // threshold); a later bundle needing no re-acceptance is I2402.

    /// CIRISPersist#785 — **the known set and the holdings set are
    /// never the same set**, on every backend.
    ///
    /// This is the witness for the one property the whole plane exists to
    /// protect. `want = remote ∖ holdings`; if a known-but-not-held hash
    /// reaches `holdings`, the node concludes it already has everything it has
    /// merely HEARD OF, stops fetching, and its corpus freezes — with no error
    /// on either side. `lookup_signed_record_by_content_hash` cannot report it
    /// either: it returns `Ok(None)` on an unresolvable entry BY DESIGN, as a
    /// self-healing posture toward index drift. So "we would notice" is not
    /// available, and this assertion is what stands in its place.
    ///
    /// The guarantee is deliberately ONE-DIRECTIONAL: a known-only hash never
    /// reaches the holdings read. The reverse — a held hash never appearing in
    /// the known set — is NOT promised, because the re-sweep re-advertises
    /// what we hold and maintaining it would mean consulting holdings on every
    /// advertisement. An earlier draft asserted disjointness and passed only
    /// because it never persisted a body matching the hash it inserted; the
    /// overlap case is now exercised directly.
    pub async fn exercise_known_hashes_never_reach_holdings_785(
        dir: &dyn crate::federation::FederationDirectory,
        label: &str,
    ) {
        let t0 = crate::host::clock::now();
        // v59.0.0 — on the Attestation kind: a framed `Key` advertisement is
        // refused at this door (the sealed-transport floor, I1150).
        // A hash this node has HEARD OF and does not hold. A REAL sha256 —
        // the insert door refuses anything that is not canonical lowercase
        // 64-hex, and it refused this fixture's earlier hand-built form,
        // which is the gate doing its job on its own witness. Derived from
        // the label because the postgres leg runs against a SHARED live
        // database: every assertion below names THIS run's hash rather than
        // counting the set.
        let known_only = crate::federation::wire_index::content_hash_of_bytes(
            format!("known{label}").as_bytes(),
        );
        dir.insert_known_wire_hash("Attestation", &known_only, Some("peer-1"), t0)
            .await
            .unwrap_or_else(|e| panic!("({label}) insert_known_wire_hash: {e}"));

        // Direction 1: the known hash must NOT appear in the holdings read.
        let holdings = dir
            .list_wire_hashes_since("Attestation", None, u32::MAX)
            .await
            .unwrap_or_else(|e| panic!("({label}) list_wire_hashes_since: {e}"));
        assert!(
            !holdings.contains(&known_only),
            "({label}) #785: a KNOWN-but-not-held hash reached the holdings read. \
             `want = remote ∖ holdings` would now exclude it, so this node stops \
             fetching a record it does not have — silently, and permanently until \
             something else rebuilds the index"
        );

        // Direction 2: the known set must not have absorbed the holdings set
        // either. Checked because an implementation that aliased both to one
        // table would pass direction 1 whenever the holdings set was empty,
        // which is exactly the state a fresh node is in.
        let known = dir
            .list_known_wire_hashes_since("Attestation", None, u32::MAX)
            .await
            .unwrap_or_else(|e| panic!("({label}) list_known_wire_hashes_since: {e}"));
        let mine = known
            .iter()
            .find(|r| r.content_hash == known_only)
            .unwrap_or_else(|| panic!("({label}) the inserted hash is not in the known set"));
        assert_eq!(
            mine.advertised_by.as_deref(),
            Some("peer-1"),
            "({label}) the advertising peer is the local-only holder map"
        );

        // The guarantee is ONE-DIRECTIONAL, and the earlier draft of this
        // witness over-claimed it as disjointness (caught in review on
        // PR #786). What is guaranteed and enforced: a KNOWN-only hash never
        // appears in the holdings read — asserted above, and the only
        // direction that can break convergence.
        //
        // The reverse is NOT guaranteed, and could not be maintained cheaply
        // if it were promised. A peer keeps advertising hashes we already
        // hold — that is what a wrapping re-sweep DOES — so `insert_known_
        // wire_hash` re-records them on every wrap. Removing a known entry
        // when its body arrives would not achieve disjointness either; the
        // next wrap puts it straight back. Genuine disjointness would require
        // consulting the holdings index on every advertisement, coupling the
        // two sets on the WRITE path — the exact coupling this design exists
        // to avoid, bought to prevent a harmless overlap.
        //
        // Harmless because `want = remote ∖ holdings` reads holdings, not
        // this set: a hash present in BOTH is one we hold, holdings says so,
        // and `want` correctly excludes it. The set's own question is "what
        // exists in the federation", and something we hold does still exist.
        //
        // So the assertion below is the real invariant, exercised through the
        // transition that actually produces overlap.
        let holdings_before = holdings.len();

        // Take a hash this node genuinely HOLDS — if the backend has one —
        // and record it as advertised, which is exactly what the next wrap
        // does. This is the case the earlier witness never reached: it only
        // ever inserted a hash nothing held, so its intersection was empty by
        // construction rather than by enforcement.
        if let Some(held) = holdings.first().cloned() {
            dir.insert_known_wire_hash("Attestation", &held, Some("peer-1"), t0)
                .await
                .unwrap_or_else(|e| panic!("({label}) insert held-and-known: {e}"));

            let holdings_after = dir
                .list_wire_hashes_since("Attestation", None, u32::MAX)
                .await
                .unwrap_or_else(|e| panic!("({label}) list_wire_hashes_since: {e}"));
            assert_eq!(
                holdings_after.len(),
                holdings_before,
                "({label}) #785: recording an advertisement CHANGED the holdings \
                 read. The known set must be invisible to that read whatever it \
                 contains — writing through one door and having the other door's \
                 answer move is the union this plane exists to prevent"
            );
            assert!(
                holdings_after.contains(&held),
                "({label}) #785: the held hash vanished from holdings"
            );
            assert!(
                dir.known_wire_hash_contains("Attestation", &held)
                    .await
                    .unwrap_or_else(|e| panic!("({label}) contains: {e}")),
                "({label}) #785: a hash that is BOTH held and advertised belongs \
                 in the known set — it exists in the federation, which is the \
                 question this set answers"
            );
        }

        // `contains` answers the KNOWN question only.
        assert!(
            dir.known_wire_hash_contains("Attestation", &known_only)
                .await
                .unwrap_or_else(|e| panic!("({label}) known_wire_hash_contains: {e}")),
            "({label}) the hash just inserted must be known"
        );
        assert!(
            !dir.known_wire_hash_contains("Family", &known_only)
                .await
                .unwrap_or_else(|e| panic!("({label}) known_wire_hash_contains: {e}")),
            "({label}) the set is keyed by (kind, hash) — a hash known for one \
             kind must not answer for another"
        );
    }

    /// CIRISPersist#785 — the known-hash surface is REACHABLE THROUGH THE
    /// PUBLIC DOUBLE, un-faulted, and still faultable on demand.
    ///
    /// `FaultInjectingDirectory` is `pub` because CIRISServer/Edge/Agent
    /// fixtures use it, and its contract is that *"every un-faulted call keeps
    /// real behaviour"*. That held only for the trait's REQUIRED methods: the
    /// generator emitted delegations for `;`-terminated signatures alone, so a
    /// method added with a DEFAULT BODY silently inherited the default and
    /// answered `Unsupported` even when nothing was faulted. The compiler
    /// cannot catch that — a default always compiles — so the double diverged
    /// from a bare backend with nothing failing.
    ///
    /// #785 is FOR edge, and edge wraps backends in this double, so a surface
    /// that is unreachable through it is not shipped
    /// (`shipped means host-reachable`). Found by review on PR #786.
    pub async fn exercise_known_hashes_reachable_through_the_double_785(
        inner: std::sync::Arc<dyn crate::federation::FederationDirectory>,
        label: &str,
    ) {
        use crate::federation::directory_double::FaultInjectingDirectory;
        // The trait itself, so the delegations are callable on the concrete
        // double — which is also how a downstream fixture reaches them.
        use crate::federation::FederationDirectory as _;

        let hash = crate::federation::wire_index::content_hash_of_bytes(
            format!("double{label}").as_bytes(),
        );
        let now = crate::host::clock::now();

        // UN-faulted: every call must reach the inner backend.
        let dbl = FaultInjectingDirectory::new(std::sync::Arc::clone(&inner));
        dbl.insert_known_wire_hash("LocationProof", &hash, Some("peer-1"), now)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "({label}) #785: insert_known_wire_hash through an UN-FAULTED \
                     double failed with {e}. The double must be transparent when \
                     nothing is declared — a defaulted trait method that is not \
                     delegated answers `Unsupported` here while a bare backend \
                     answers correctly"
                )
            });
        assert!(
            dbl.known_wire_hash_contains("LocationProof", &hash)
                .await
                .unwrap_or_else(|e| panic!("({label}) contains through double: {e}")),
            "({label}) #785: the hash inserted through the double is not visible \
             through it"
        );
        let rows = dbl
            .list_known_wire_hashes_since("LocationProof", None, u32::MAX)
            .await
            .unwrap_or_else(|e| panic!("({label}) list through double: {e}"));
        assert!(
            rows.iter().any(|r| r.content_hash == hash),
            "({label}) #785: paging through the double does not return what was \
             written through it"
        );
        dbl.evict_known_wire_hashes(now - chrono::Duration::hours(1), u64::MAX)
            .await
            .unwrap_or_else(|e| panic!("({label}) evict through double: {e}"));

        // …and the fault still fires when it IS declared, so the delegation did
        // not simply bypass the wrapper.
        let faulted = FaultInjectingDirectory::new(inner).unsupported("insert_known_wire_hash");
        assert!(
            faulted
                .insert_known_wire_hash("LocationProof", &hash, None, now)
                .await
                .is_err(),
            "({label}) #785: a DECLARED fault on a delegated method must still \
             fire — a delegation that forgot the fault check would make the \
             double untestable in the other direction"
        );
    }

    /// CIRISPersist#785 — the ageing column moves FORWARDS ONLY, and the
    /// insert door refuses a non-canonical hash.
    ///
    /// Both found in review on PR #786, and both are the same shape: a write
    /// that succeeds while quietly making the set mean something other than
    /// what it says.
    ///
    /// **Monotonic.** Execution order is not observation order. A caller that
    /// stamps `now` and hands the write to a delayed task can apply an OLDER
    /// sighting after a newer one; an unconditional upsert drags
    /// `last_advertised_at` backwards, and the next sweep evicts a hash that
    /// was in fact recently advertised — invisibly, until edge's re-sweep
    /// wraps back around to it.
    ///
    /// **Canonical.** An empty hash stores fine and answers `contains`, but
    /// every first page asks `content_hash > ''`, so it can never be
    /// enumerated: a row whose existence depends on which door you ask. And a
    /// case variant becomes a SECOND entry for one digest with its own ageing
    /// clock, so re-advertisement bumps one while the other quietly ages out.
    pub async fn exercise_known_hash_monotonic_and_canonical_785(
        dir: &dyn crate::federation::FederationDirectory,
        label: &str,
    ) {
        let hash =
            crate::federation::wire_index::content_hash_of_bytes(format!("mono{label}").as_bytes());

        // Chosen so the two instants render at DIFFERENT fractional widths:
        // `…:00.100Z` (earlier) and `…:00.100001Z` (later). Under chrono's
        // variable-width `to_rfc3339()` a TEXT comparison puts the LATER one
        // first — '0' < 'Z' at the fourth fractional character — so a sqlite
        // backend storing this column as TEXT would treat the newer sighting
        // as older, silently keep the stale value, and let eviction delete
        // rows it should keep.
        //
        // An earlier draft of this witness used `Utc::now()` for both, which
        // renders both at the same width and cannot see the defect at all
        // (found in review on PR #786).
        let base = chrono::DateTime::parse_from_rfc3339("2027-03-04T05:06:00Z")
            .expect("literal is valid RFC-3339")
            .with_timezone(&chrono::Utc);
        let older = base + chrono::Duration::milliseconds(100);
        let newer = base + chrono::Duration::microseconds(100_001);
        assert!(older < newer, "fixture instants are ordered");

        dir.insert_known_wire_hash("LocationProof", &hash, Some("peer-new"), newer)
            .await
            .unwrap_or_else(|e| panic!("({label}) insert newer: {e}"));
        // The delayed write, carrying the OLDER observation.
        dir.insert_known_wire_hash("LocationProof", &hash, Some("peer-old"), older)
            .await
            .unwrap_or_else(|e| panic!("({label}) insert older: {e}"));

        let row = dir
            .list_known_wire_hashes_since("LocationProof", None, u32::MAX)
            .await
            .unwrap_or_else(|e| panic!("({label}) list: {e}"))
            .into_iter()
            .find(|r| r.content_hash == hash)
            .unwrap_or_else(|| panic!("({label}) entry vanished"));
        // Asserted as "did not go backwards", NOT as byte-equality with
        // `newer`. Postgres TIMESTAMPTZ is MICROSECOND precision while chrono
        // carries nanoseconds, so the value round-trips truncated
        // (…611926112Z stored as …611926Z) — an equality assertion passes on
        // memory and sqlite and fails on postgres for a reason that has
        // nothing to do with the property under test. The property is the
        // ORDERING, and it survives truncation.
        assert!(
            row.last_advertised_at > older,
            "({label}) #785: a LATE-ARRIVING OLDER sighting moved \
             `last_advertised_at` backwards. The next sweep would then evict a \
             hash that was recently advertised, and the loss is invisible until \
             the re-sweep wraps"
        );
        assert!(
            (newer - row.last_advertised_at) < chrono::Duration::milliseconds(1),
            "({label}) #785: the stored instant is not the newer sighting \
             (stored {stored}, newer {newer}) — anything beyond storage \
             truncation means the monotonic guard kept the wrong value",
            stored = row.last_advertised_at
        );
        assert_eq!(
            row.advertised_by.as_deref(),
            Some("peer-new"),
            "({label}) the advertiser must follow the same monotonic rule as the \
             timestamp it is recorded with, or the holder map names a peer from \
             an older sighting than the one the clock reports"
        );

        // The TEXT-ordering hazard again, on the EVICTION predicate: a cutoff
        // between the two must delete neither, since both are newer than a
        // cutoff below them. Spelled with the same awkward widths so a
        // regression in the cutoff's serialization is caught here too.
        let below_both = base - chrono::Duration::seconds(1);
        dir.evict_known_wire_hashes(below_both, u64::MAX)
            .await
            .unwrap_or_else(|e| panic!("({label}) evict below both: {e}"));
        assert!(
            dir.known_wire_hash_contains("LocationProof", &hash)
                .await
                .unwrap_or_else(|e| panic!("({label}) contains: {e}")),
            "({label}) #785: a cutoff BELOW every entry evicted one anyway — the \
             range predicate is not comparing chronologically"
        );

        // Non-canonical hashes are REFUSED at the door, not normalised.
        for bad in ["", "ABC", &hash.to_uppercase(), &hash[..63]] {
            let Err(why) = dir
                .insert_known_wire_hash("LocationProof", bad, None, newer)
                .await
            else {
                panic!(
                    "({label}) #785: {bad:?} was accepted as a content hash. An \
                     empty value stores but can never be paged, and a case \
                     variant splits one digest into two entries with separate \
                     ageing clocks"
                );
            };
            // The KIND matters as much as the refusal. This is caller input,
            // not a substrate failure, and consumers split the two to decide
            // what to RETRY — filed as `federation_backend`, a permanently
            // invalid advertisement would be retried forever, because no
            // number of attempts makes an empty hash canonical.
            assert_eq!(
                why.kind(),
                "federation_invalid_argument",
                "({label}) #785: refusing {bad:?} must be an INPUT refusal, not \
                 a backend failure — got {why}"
            );
        }
    }

    /// CIRISPersist#785 — `last_advertised_at` MOVES on
    /// re-advertisement, and eviction is measured against the caller's cutoff.
    ///
    /// The first half is #776's lesson made executable. That prune aged on
    /// `asserted_at` — a value the writer freezes — so the cutoff never
    /// advanced, the prune never fired, and both consumers independently
    /// refused to call it rather than reporting a fault. A known-hash set built
    /// the obvious way (`INSERT OR IGNORE`, first-seen wins) has the identical
    /// defect, and this is what fails when someone writes it that way.
    ///
    /// The second half pins the asymmetry between the floor and the bound: an
    /// over-bound set is VISIBLE and reported; evicting below the floor is
    /// invisible until edge's re-sweep wraps back around, which on a large
    /// corpus is hours. So the floor wins and the overage is reported.
    pub async fn exercise_known_hash_ageing_and_eviction_785(
        dir: &dyn crate::federation::FederationDirectory,
        label: &str,
    ) {
        let old = crate::host::clock::now() - chrono::Duration::hours(4);
        let fresh = crate::host::clock::now();
        // Per-run canonical hashes: the postgres leg shares a live table with
        // every other run, so each assertion below is about THIS run's two
        // entries, and the insert door requires real 64-hex.
        let stale_hash = crate::federation::wire_index::content_hash_of_bytes(
            format!("stale{label}").as_bytes(),
        );
        let live_hash =
            crate::federation::wire_index::content_hash_of_bytes(format!("live{label}").as_bytes());

        // Advertised long ago, and never again.
        dir.insert_known_wire_hash("LocationProof", &stale_hash, Some("peer-1"), old)
            .await
            .unwrap_or_else(|e| panic!("({label}) insert stale: {e}"));
        // Advertised long ago, then RE-advertised by the wrapping re-sweep.
        dir.insert_known_wire_hash("LocationProof", &live_hash, Some("peer-1"), old)
            .await
            .unwrap_or_else(|e| panic!("({label}) insert live: {e}"));
        dir.insert_known_wire_hash("LocationProof", &live_hash, Some("peer-2"), fresh)
            .await
            .unwrap_or_else(|e| panic!("({label}) re-advertise live: {e}"));

        let rows = dir
            .list_known_wire_hashes_since("LocationProof", None, u32::MAX)
            .await
            .unwrap_or_else(|e| panic!("({label}) list: {e}"));
        let live = rows
            .iter()
            .find(|r| r.content_hash == live_hash)
            .unwrap_or_else(|| panic!("({label}) re-advertised hash vanished"));
        assert!(
            live.last_advertised_at > old,
            "({label}) #785/#776: re-advertising did not move `last_advertised_at`. \
             Built this way the eviction floor is measured against a value that \
             cannot move, so the sweep either never fires or evicts live \
             entries — the #776 shape exactly"
        );
        assert_eq!(
            live.advertised_by.as_deref(),
            Some("peer-2"),
            "({label}) the most recent advertiser is the one recorded"
        );

        // Cutoff between the two: the stale entry goes, the live one stays.
        // Persist compares timestamps and never derives this instant — edge
        // owns the wrap period that produced it.
        let cutoff = crate::host::clock::now() - chrono::Duration::hours(1);
        let report = dir
            .evict_known_wire_hashes(cutoff, u64::MAX)
            .await
            .unwrap_or_else(|e| panic!("({label}) evict: {e}"));
        assert!(
            report.evicted >= 1,
            "({label}) the entry not advertised since the cutoff must be evicted"
        );
        assert!(
            dir.known_wire_hash_contains("LocationProof", &live_hash)
                .await
                .unwrap_or_else(|e| panic!("({label}) contains: {e}")),
            "({label}) a hash re-advertised AFTER the cutoff must survive — \
             evicting it is the invisible failure, recoverable only when edge's \
             re-sweep wraps back around"
        );
        assert!(
            !dir.known_wire_hash_contains("LocationProof", &stale_hash)
                .await
                .unwrap_or_else(|e| panic!("({label}) contains: {e}")),
            "({label}) the stale hash must be gone"
        );

        // The floor WINS over the bound: with a bound of 0 and everything
        // younger than the cutoff, nothing further is evicted and the overage
        // is REPORTED rather than silently resolved.
        let report = dir
            .evict_known_wire_hashes(cutoff, 0)
            .await
            .unwrap_or_else(|e| panic!("({label}) evict under bound: {e}"));
        assert!(
            report.over_bound_by >= 1,
            "({label}) #785: the set is over its bound and every entry is younger \
             than the floor — that must be REPORTED via over_bound_by, because an \
             over-bound set is visible and actionable while evicting below the \
             floor is not"
        );
        assert!(
            dir.known_wire_hash_contains("LocationProof", &live_hash)
                .await
                .unwrap_or_else(|e| panic!("({label}) contains: {e}")),
            "({label}) a bound of 0 must NOT evict below the caller's floor"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;

    fn t(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    // ── skew bound ──────────────────────────────────────────────────

    #[test]
    fn skew_bound_accepts_within_tolerance() {
        let now = t(0);
        // exactly at the edge (now + 5min) is accepted (> is the reject).
        assert!(check_skew_bound(now + Duration::minutes(5), now).is_ok());
        assert!(check_skew_bound(now - Duration::hours(1), now).is_ok());
    }

    #[test]
    fn skew_bound_rejects_future_dated() {
        let now = t(0);
        let err = check_skew_bound(now + Duration::minutes(6), now).unwrap_err();
        assert_eq!(err.kind(), "federation_clock_skew_violation");
    }

    // ── payment-processor reject ────────────────────────────────────

    #[test]
    fn payment_processor_ids_rejected_anywhere() {
        // top-level value
        assert!(reject_payment_processor_identifiers(&json!({
            "billing_ref": "cus_ABC123"
        }))
        .is_err());
        // nested in an open-vocab object
        assert!(reject_payment_processor_identifiers(&json!({
            "metadata": {"note": "sub_9xKpQ"}
        }))
        .is_err());
        // inside an array
        assert!(reject_payment_processor_identifiers(&json!({
            "refs": ["ok", "ch_1ABC"]
        }))
        .is_err());
        // as an object KEY
        assert!(reject_payment_processor_identifiers(&json!({
            "pi_3xyz": "value"
        }))
        .is_err());
    }

    #[test]
    fn clean_envelope_passes_payment_check() {
        assert!(reject_payment_processor_identifiers(&json!({
            "org_id": "org-x",
            "name": "Acme",
            "capabilities_granted": ["billing.read", "identity.read"],
        }))
        .is_ok());
        // bare prefix with no suffix is not a real id (e.g. the word
        // "card_" alone) — len > prefix.len() guards this.
        assert!(reject_payment_processor_identifiers(&json!({"x": "cus_"})).is_ok());
    }
}
