//! Hardware-attestation admission policy for `accord_holder` rows
//! (CIRISPersist#102 Ask 8, v2.5.0).
//!
//! # Mission alignment (FSD-002 §7.3 + FEDERATION_ANNOUNCEMENT §4.5.2)
//!
//! HUMANITY_ACCORD keys (`identity_type = 'accord_holder'`) MUST live
//! on hardware substrate. CIRISVerify v3.0.1's
//! `docs/HARDWARE_ATTESTATION.md` explicitly does NOT publish a single
//! `hardware_attested: bool` — per the auth ≠ trust separation,
//! Verify exposes evidence; the consumer (persist) authors the
//! policy. Persist's
//! [`HardwareAttestationPolicy`] is that policy.
//!
//! Persist's verdict for an `accord_holder` row depends on WHICH custody
//! story the evidence tells — see [`AttestationEvidence`]'s three arms.
//!
//! For [`AttestationEvidence::Hardware`] (attested against a fresh
//! per-request nonce) =
//!
//! 1. `attestation_evidence` is present, non-null, deserializes as
//!    `(PlatformAttestation, nonce_captured_at)`.
//! 2. The `hardware_type` derivable from the variant is in
//!    [`HardwareAttestationPolicy::accepted_hardware_types`].
//! 3. The variant carries its required fields (Android key-attestation
//!    chain + Play Integrity + StrongBox flag; iOS Secure Enclave +
//!    App Attest + DeviceCheck; TPM TPMS_ATTEST + EK cert + AK pubkey +
//!    PCR values + manufacturer + discrete-vs-firmware flag).
//! 4. The captured nonce is fresh (`now - nonce_captured_at ≤
//!    max_nonce_age`).
//!
//! For [`AttestationEvidence::GenerationCustody`] (v23.1.0,
//! CIRISPersist#554 — the device attests at key GENERATION, so there is no
//! nonce and nothing to age) the verdict is the contract identity, the
//! holder identity binding, the tier allowlist, and the sha256 certificate
//! commitments — enumerated in full, together with what it deliberately
//! defers and why, on `HardwareAttestationPolicy::check_generation_custody`.
//!
//! **At THIS call site persist does not walk a device-attestation chain**
//! (cert-chain to the Google root for Android, EK-cert validation for TPM,
//! JWT-verify of Play Integrity, App Attest assertion against Apple's
//! roots). The structural check here ensures the evidence *shape* is right
//! and the nonce is fresh, and persist's storage of the evidence preserves
//! the audit trail. What is available to change that, and what genuinely
//! is not, is the matrix below.
//!
//! Note the deliberate asymmetry with the **PIV custody** walk: that one is
//! not deferred anywhere. It runs in this crate, against the pinned Yubico
//! root, on the canonical-role gate — see
//! `HardwareAttestationPolicy::check_generation_custody`, which corrects a
//! note that used to point at another repo.
//!
//! # CIRISVerify v12.1.0 capability matrix — what is adoptable, what is not
//!
//! Recorded here (CIRISPersist#568) so a reader deciding whether a gap is
//! real does not need a round trip to another repo. Verify posted this
//! against the v12.1.0 release; persist pins v12.1.0.
//!
//! | Capability | Status | Entry point |
//! |---|---|---|
//! | YubiKey PIV custody | shipped, hardware-validated | `verify_accord_custody_attestation` / `verify_yubikey_piv_attestation` |
//! | Android Key Attestation | shipped **v10.8.0** | `device_attestation::verify_android_key_attestation{,_with_store}` |
//! | Apple App Attest | shipped **v11.0.0** | `device_attestation::verify_apple_app_attest{,_with_store}` |
//! | **TPM EK** | **STILL DEFERRED** | — the last open leg of **CIRISVerify#199** |
//! | Pinned vendor roots | verify now bakes them | `trust_anchor_store::baked` — Yubico, Google ×2, Apple |
//! | Constrained anchor store | shipped v10.9.0–v10.11.0 | `TrustAnchorStore::resolve(purpose, environment)` |
//! | Presenter binding (build) | shipped v10.7.0 | `verify_build_attestation_bundle` (CIRISPersist#567) |
//!
//! So the old note here — *"CIRISVerify#32 Ask 5's local-chain-validation
//! surface, which Verify v3.0.1 has NOT shipped"* — was stale twice over:
//! **CIRISVerify#32 is CLOSED** (the live tracker is **CIRISVerify#199**),
//! and two of its three legs have shipped. Persist's deferral stands, but
//! it is now a *choice* rather than an absence, and only the TPM EK leg is
//! genuinely unavailable — blocked upstream on vendor-root-**set**
//! management, which is a different problem from pinning one root.
//!
//! # The measurement/gate inversion this module must not make
//!
//! Verify's device-attestation validators are deliberately **measurements
//! and over-claim refuters, not gates**: absence of an attestation is not a
//! failure, and a `Software` security level is a valid measurement. As of
//! v12.1.0 the types say so themselves —
//! `AndroidSecurityLevel` and `AppAttestEnvironment` implement
//! `ciris_verify_core::classification::Classification` returning
//! `Gating::Measurement`, so `may_gate()` is **false** for both. Persist
//! encodes that rule once, in
//! [`super::admission::classification_standing`], and pins those two
//! verdicts to `NoStanding` in a test. Adopting the Android or Apple leg
//! here therefore widens the *evidence*, never the *requirement* — the
//! `SoftwareOnly` floor below stays the one structural line.
//!
//! # `strongbox_backed` is a SELF-REPORT, and it is now falsifiable
//!
//! Persist's structural check requires the Android variant to carry
//! `strongbox_backed`, and `platform_to_hardware_type` reads it to pick
//! `AndroidStrongbox` vs `AndroidKeystore`. That flag is the peer's own
//! claim and is **not authoritative** — shape-only, which is why the
//! deferral above is correct rather than merely convenient. It is no longer
//! *uncheckable*, though: verify's `AndroidAttestationVerdict::refutes(claimed_class)`
//! fires iff a peer claims stronger custody than the chain measures. A
//! future adopter wires refutation (a peer caught over-claiming), never
//! promotion (a self-reported flag becoming trusted).
//!
//! # Why the `SoftwareOnly` floor is the ONE thing Verify draws
//!
//! Per `HardwareSigner::hardware_type()` semantics +
//! `HardwareType::supports_professional_license()`:
//! `SoftwareOnly.supports_professional_license() == false`. This is
//! Verify's one structural floor: software-only keys are not
//! hardware-attested, period. Everything finer (which HSMs are
//! production-grade, which require firmware vs discrete TPM, etc.) is
//! the consumer's call. [`HardwareAttestationPolicy::default()`]'s
//! accepted set drops `SoftwareOnly` and accepts the other 12 variants;
//! deployments tighten further (e.g. AWS HSM-only) by overriding.

use std::collections::HashSet;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ciris_keyring::{HardwareType, PlatformAttestation};
use serde::{Deserialize, Serialize};

use super::Error;

/// v2.5.0 (CIRISPersist#102 Ask 8) — default max age of the captured
/// nonce. 24 hours.
///
/// Defeats replay of an old attestation against a new key-binding
/// event. The 24h figure is the FSD-002 §7.3 reference value;
/// deployments tune via [`HardwareAttestationPolicy::max_nonce_age`].
pub const DEFAULT_MAX_NONCE_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// v2.5.0 (CIRISPersist#102 Ask 8) — the configurable hardware-
/// attestation policy applied at `put_public_key` admission time for
/// `identity_type = 'accord_holder'` rows.
///
/// # `pub` fields rationale
///
/// Sovereign deployments extend / tighten by mutating the struct
/// directly (e.g. `policy.accepted_hardware_types.insert(MyVariant)`).
/// No private fields — the policy IS the configuration surface.
///
/// # Default (FSD-002 §7.3)
///
/// - `accepted_hardware_types`: all 12 non-`SoftwareOnly` variants.
///   The one structural floor Verify draws is
///   `SoftwareOnly.supports_professional_license() == false`; that
///   floor is operationally absorbed here.
/// - `max_nonce_age`: [`DEFAULT_MAX_NONCE_AGE`] (24h).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareAttestationPolicy {
    /// Hardware variants persist accepts for accord-holder identity.
    /// Default: every variant EXCEPT
    /// [`HardwareType::SoftwareOnly`].
    pub accepted_hardware_types: HashSet<HardwareType>,
    /// Maximum age of the attestation's captured nonce. Stale
    /// attestations are rejected; this defeats replay of an old
    /// attestation against a new key-binding event. Default:
    /// [`DEFAULT_MAX_NONCE_AGE`].
    ///
    /// Applies to [`AttestationEvidence::Hardware`] ONLY — see
    /// [`Self::accepted_custody_tiers`] for why an
    /// attestation-at-generation has no nonce to age.
    pub max_nonce_age: Duration,
    /// v23.1.0 (CIRISPersist#554) — the custody tiers accepted on the
    /// [`AttestationEvidence::GenerationCustody`] arm. Default:
    /// `{"portable_2fa"}` (the HUMANITY_ACCORD holder custody a YubiKey
    /// PIV slot-9c ceremony produces).
    ///
    /// `custody_tier` is a holder SELF-CLAIM, so it is allowlisted rather
    /// than echoed — the same shape as [`Self::accepted_hardware_types`],
    /// and the same reason: a consumer that gates on tier must never
    /// inherit an unbounded unverified string. Deployments tighten or
    /// widen by mutating the set.
    pub accepted_custody_tiers: HashSet<String>,
}

impl Default for HardwareAttestationPolicy {
    fn default() -> Self {
        // All 13 variants minus SoftwareOnly. Listed explicitly so
        // adding a future variant in ciris-keyring lights up a
        // compile error here (good — forces a policy decision).
        let accepted = [
            HardwareType::AndroidKeystore,
            HardwareType::AndroidStrongbox,
            HardwareType::IosSecureEnclave,
            HardwareType::MacOsSecureEnclave,
            HardwareType::TpmDiscrete,
            HardwareType::TpmFirmware,
            HardwareType::IntelSgx,
            HardwareType::AwsCloudHsm,
            HardwareType::AzureHsm,
            HardwareType::GcpCloudHsm,
            HardwareType::YubiHsm,
            // CIRISPersist#268 (v9.11.0) — external secure element /
            // FIPS YubiKey PIV token. The canonical HUMANITY_ACCORD holder
            // custody (`portable_2fa`); without it real YubiKey-backed
            // accord holders cannot be admitted and genesis entrenchment 409s.
            HardwareType::ExternalSecureElement,
        ];
        Self {
            accepted_hardware_types: accepted.into_iter().collect(),
            max_nonce_age: DEFAULT_MAX_NONCE_AGE,
            // v23.1.0 (CIRISPersist#554) — the tier the real ceremony
            // asserts. Sourced from verify's const so persist and the
            // producer cannot drift on the spelling.
            accepted_custody_tiers: [
                ciris_verify_core::accord_custody_attestation::CUSTODY_TIER_PORTABLE_2FA.to_owned(),
            ]
            .into_iter()
            .collect(),
        }
    }
}

/// v2.5.0 (CIRISPersist#102 Ask 8) — the on-row serialized shape of
/// `attestation_evidence`. Stored as JSONB on Postgres,
/// TEXT-as-JSON on SQLite.
///
/// # Cross-language compat
///
/// The Python side (PyEngine FFI) JSON-encodes the same shape:
/// `{"platform_attestation": <PlatformAttestation JSON>,
///   "nonce_captured_at": "<RFC3339>"}`. PlatformAttestation's serde
/// shape is whatever ciris-keyring emits; persist treats the body as
/// opaque-via-derive.
/// v22.0.1 (CIRISPersist#545) — **the evidence is an ENUM so the honest
/// software-test custody marker is representable by construction.** v22.0.0
/// had two parts disagreeing about one shape: the test-anchor genesis
/// synthesizer emits `{"tier":"SoftwareOnly_TEST","test_anchor":true}` —
/// "honest about what it is, never a fabricated hardware claim" — while this
/// type required a non-optional `platform_attestation`, so the marker failed
/// SERDE before any tier logic could honour it and persist refused its own
/// synthesized accord holders. CIRISServer caught it on adoption and,
/// correctly, refused to work around it by fabricating hardware evidence in
/// a fixture (which would have quietly certified the hardware path — the
/// AV-77 class).
///
/// Untagged: a hardware body deserializes as [`Self::Hardware`]; a signed
/// custody CEG object as [`Self::GenerationCustody`]; the exact two-field
/// marker (and nothing else — `deny_unknown_fields`) as
/// [`Self::SoftwareOnlyTest`]. The marker's ADMISSIBILITY is decided in
/// [`HardwareAttestationPolicy::check`], never by parsing: it admits ONLY
/// under a live test anchor, and its production refusal is typed and loud —
/// "honest about what it is" is now a type, not a convention.
///
/// v23.1.0 (CIRISPersist#554) — **#545 one layer out.** #545 was: the type
/// could not represent the honest software-test marker, so persist refused its
/// own *synthesized* holders. #554 is the same failure with real hardware: the
/// type could not represent the custody evidence a real ceremony produces —
/// a **PIV attestation over a YubiKey slot-9c key**, which has no nonce
/// challenge because the device attests at key GENERATION, not per request —
/// so persist refused its own *production* holders. Both were invisible until
/// adoption because no fixture had ever fed persist evidence it had not
/// synthesized to satisfy itself.
///
/// The parse admits the SHAPE; [`HardwareAttestationPolicy::check`] decides
/// admissibility. That split is #545's whole point and is preserved here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttestationEvidence {
    /// Real platform custody evidence, attested against a fresh per-request
    /// nonce (TPM / Secure Enclave / Android Keystore).
    Hardware(Box<HardwareCustodyEvidence>),
    /// v23.1.0 (CIRISPersist#554) — custody attested at key GENERATION: the
    /// device signs the attestation when the key is created, so there is no
    /// nonce and nothing to age. YubiKey PIV slot-9c today; the same shape
    /// fits any device that attests at generation rather than per nonce.
    GenerationCustody(Box<GenerationCustodyAttestation>),
    /// The test-anchor genesis marker (CIRISVerify#202's
    /// `accord_custody_attestation` admits the same tier under the same
    /// condition). Never admissible without a live test anchor.
    SoftwareOnlyTest(SoftwareOnlyTestMarker),
}

/// The hardware arm's body — the pre-#545 `AttestationEvidence` shape,
/// byte-compatible on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCustodyEvidence {
    /// The platform attestation Verify produced via
    /// `HardwareSigner::attestation_with_nonce(challenge)`.
    pub platform_attestation: PlatformAttestation,
    /// When Verify captured the nonce challenge. Persist checks
    /// freshness against [`HardwareAttestationPolicy::max_nonce_age`].
    pub nonce_captured_at: DateTime<Utc>,
}

/// v23.1.0 (CIRISPersist#554) — the attestation-at-generation arm's body: the
/// signed CEG object a custody ceremony emits — CIRISVerify's
/// `accord_custody_attestation` (implemented and released; the custody
/// attestation + PIV chain verifier is CIRISVerify#91, produced by
/// `produce_accord_custody_attestation`). NOT #202 — that is the test-mode
/// single-key trust-root override, a different mechanism; citing it here
/// would send a reader chasing chain verification into the test-anchor
/// feature.
///
/// # Why no `deny_unknown_fields`
///
/// The ceremony format is CIRISVerify's, not persist's, and it may GROW —
/// pinning it closed here would make persist refuse a valid future artifact
/// for carrying a field it does not read. The binding is done the other way
/// round: every field persist actually gates on is REQUIRED and strictly
/// typed, so a body that omits or mistypes one fails the parse, while an
/// additive field rides through untouched. The `schema` id is pinned in
/// policy (a schema CHANGE is a contract change persist must adopt
/// consciously, not absorb silently).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationCustodyAttestation {
    /// Relay-envelope schema tag — [`ciris_verify_core::ceg_outbox::SCHEMA`].
    pub schema: String,
    /// The CEG object kind; must be
    /// [`ciris_verify_core::accord_custody_attestation::ACCORD_CUSTODY_ATTESTATION_KIND`].
    pub kind: String,
    /// The signing identity's federation `key_id`.
    pub key_id: String,
    /// RFC-3339 creation timestamp.
    pub created_at: String,
    /// The custody object.
    pub body: GenerationCustodyBody,
}

/// The custody object: the holder-signed envelope plus the hash-bound
/// attestation certificates.
///
/// The certificates ride here UNSIGNED and are bound to the holder's signature
/// only through the sha256 commitments inside
/// [`GenerationCustodyEnvelope`] — CIRISVerify#113's design, because a YubiKey's
/// single-part `CKM_EDDSA` input is bounded and a multi-KB inline cert chain
/// overran it. That indirection is exactly why persist recomputes the
/// commitments: without it the certs would be free-floating attacker-editable
/// bytes sitting next to a valid signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationCustodyBody {
    /// The envelope the holder hybrid-signed.
    pub signed_envelope: GenerationCustodyEnvelope,
    /// Ed25519 over the JCS bytes of `signed_envelope`, base64.
    pub ed25519_signature_base64: String,
    /// ML-DSA-65 over the bound preimage, base64. Optional on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mldsa65_signature_base64: Option<String>,
    /// The slot-9c attestation certificate DER, hex.
    pub yubikey_piv_attestation_9c_hex: String,
    /// Each chain certificate DER, hex, leaf-first (excluding the pinned root).
    pub yubikey_attestation_chain_hex: Vec<String>,
}

/// The holder-signed custody envelope. Every field here is inside the
/// signature; the sha256 fields are the commitments that bind
/// [`GenerationCustodyBody`]'s certificate hex to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationCustodyEnvelope {
    /// The asserted custody tier — a SELF-CLAIM, allowlisted in policy against
    /// [`HardwareAttestationPolicy::accepted_custody_tiers`].
    pub custody_tier: String,
    /// The holder this attestation is about; bound to the row's `key_id`.
    pub holder_key_id: String,
    /// The holder's Ed25519 public key, base64.
    pub ed25519_public_key_base64: String,
    /// Hex sha256 of the holder's ML-DSA-65 public key (committed, not inline
    /// — the 1952-byte key would overrun the hardware Ed25519 preimage).
    pub mldsa65_public_key_sha256: String,
    /// Hex sha256 of the slot-9c attestation certificate DER.
    pub yubikey_piv_attestation_9c_sha256: String,
    /// Hex sha256 of each chain certificate DER, leaf-first.
    pub yubikey_attestation_chain_sha256: Vec<String>,
    /// RFC-3339 instant the holder signed this envelope.
    pub signed_at: String,
}

/// Exactly `{"tier":"SoftwareOnly_TEST","test_anchor":true}` — the genesis
/// synthesizer's marker (`src/federation/genesis/mod.rs`). `deny_unknown_fields`
/// so no hardware-shaped body can fall through to this arm.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareOnlyTestMarker {
    /// The single legal value; any other string fails deserialization.
    pub tier: SoftwareOnlyTestTier,
    /// Must be literally `true` — checked in policy, not parsing, so the
    /// refusal is typed rather than "malformed".
    pub test_anchor: bool,
}

/// One variant, spelled exactly as the synthesizer emits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SoftwareOnlyTestTier {
    /// `"SoftwareOnly_TEST"`.
    #[serde(rename = "SoftwareOnly_TEST")]
    SoftwareOnlyTest,
}

impl HardwareAttestationPolicy {
    /// Apply the policy to an attestation_evidence JSON value (the
    /// shape stored in the `federation_keys.attestation_evidence`
    /// column).
    ///
    /// # Behavior
    ///
    /// - `evidence_value == null` or `missing` → typed
    ///   [`Error::AccordHolderRequiresAttestationEvidence`] with
    ///   `detail = "missing"` / `"null"`.
    /// - Malformed body → same error with `detail = "malformed: ..."`.
    /// - `hardware_type` not in `accepted_hardware_types` → typed
    ///   [`Error::HardwareTypeNotAccepted`].
    /// - Required variant fields missing → typed
    ///   [`Error::AttestationEvidenceIncomplete`].
    /// - Stale nonce → typed [`Error::AttestationEvidenceStale`].
    /// - OK → `Ok(())`.
    ///
    /// `now` is supplied as a parameter for testability; production
    /// callers pass `Utc::now()`.
    pub fn check(
        &self,
        key_id: &str,
        evidence_value: Option<&serde_json::Value>,
        now: DateTime<Utc>,
    ) -> Result<(), Error> {
        // 1. Presence + non-null.
        let value = match evidence_value {
            None => {
                return Err(Error::AccordHolderRequiresAttestationEvidence {
                    key_id: key_id.to_owned(),
                    detail: "missing".into(),
                });
            }
            Some(v) if v.is_null() => {
                return Err(Error::AccordHolderRequiresAttestationEvidence {
                    key_id: key_id.to_owned(),
                    detail: "null".into(),
                });
            }
            Some(v) => v,
        };

        // 2. Deserialize. Untagged: hardware body → Hardware, the exact
        // two-field marker → SoftwareOnlyTest, anything else → malformed.
        let evidence: AttestationEvidence = serde_json::from_value(value.clone()).map_err(|e| {
            Error::AccordHolderRequiresAttestationEvidence {
                key_id: key_id.to_owned(),
                detail: format!("malformed: {e}"),
            }
        })?;

        // 2b. The SoftwareOnly_TEST marker (CIRISPersist#545): admissible
        // ONLY under a live test anchor — the same condition under which the
        // genesis synthesizer that emits it exists at all. In production the
        // refusal is TYPED and names the tier, never "malformed": a peer
        // presenting the marker on a real mesh is making a claim this node
        // must refuse loudly, and a mis-shapen refusal reads as a parser bug
        // instead of a custody decision. Verify's accord_custody_attestation
        // (CIRISVerify#91) admits the same SoftwareOnly_TEST tier when its
        // test-anchor override (CIRISVerify#202) is live — the two issues are
        // different mechanisms and both cites matter.
        let evidence = match evidence {
            AttestationEvidence::SoftwareOnlyTest(marker) => {
                if !marker.test_anchor {
                    return Err(Error::AccordHolderRequiresAttestationEvidence {
                        key_id: key_id.to_owned(),
                        detail: "SoftwareOnly_TEST marker without test_anchor:true".into(),
                    });
                }
                if crate::federation::genesis::test_anchor_override_active() {
                    return Ok(());
                }
                return Err(Error::AccordHolderRequiresAttestationEvidence {
                    key_id: key_id.to_owned(),
                    detail: "SoftwareOnly_TEST custody marker refused: test anchor not live — \
                             production accord custody requires platform_attestation \
                             (CIRISPersist#545)"
                        .into(),
                });
            }
            // v23.1.0 (CIRISPersist#554) — the attestation-at-generation arm.
            AttestationEvidence::GenerationCustody(att) => {
                return self.check_generation_custody(key_id, &att);
            }
            AttestationEvidence::Hardware(hw) => *hw,
        };

        // 3. Variant → HardwareType.
        let hw_type = platform_to_hardware_type(&evidence.platform_attestation);

        // 4. Policy match.
        if !self.accepted_hardware_types.contains(&hw_type) {
            let mut accepted: Vec<String> = self
                .accepted_hardware_types
                .iter()
                .map(|t| format!("{t:?}"))
                .collect();
            accepted.sort();
            return Err(Error::HardwareTypeNotAccepted {
                got: format!("{hw_type:?}"),
                accepted,
            });
        }

        // 5. Variant structural check.
        let missing = required_field_gaps(&evidence.platform_attestation);
        if !missing.is_empty() {
            return Err(Error::AttestationEvidenceIncomplete {
                hardware_type: format!("{hw_type:?}"),
                missing_fields: missing,
            });
        }

        // 6. Freshness.
        let age = now
            .signed_duration_since(evidence.nonce_captured_at)
            .to_std()
            .unwrap_or(Duration::ZERO);
        if age > self.max_nonce_age {
            return Err(Error::AttestationEvidenceStale {
                captured_at: evidence.nonce_captured_at,
                max_age_secs: self.max_nonce_age.as_secs(),
            });
        }

        Ok(())
    }

    /// v23.1.0 (CIRISPersist#554) — the admissibility decision for
    /// [`AttestationEvidence::GenerationCustody`].
    ///
    /// # What this verifies
    ///
    /// 1. `schema` is the pinned CEG relay-envelope schema and `kind` is
    ///    exactly `accord_holder_custody_attestation` — the contract identity.
    /// 2. Identity binding: the signed envelope's `holder_key_id` equals the
    ///    row's `key_id`, and the object's own `key_id` agrees with it. A
    ///    holder cannot present another holder's custody attestation.
    /// 3. `custody_tier` is in [`Self::accepted_custody_tiers`] — the tier is a
    ///    self-claim, so it is allowlisted, never echoed.
    /// 4. [`HardwareType::ExternalSecureElement`] is in
    ///    [`Self::accepted_hardware_types`]. This arm asserts §9.4 external-
    ///    secure-element custody, so a deployment that has removed that class
    ///    must not get it admitted through a side door.
    /// 5. The **sha256 commitment bindings**: the certificate DERs ride
    ///    UNSIGNED in `body`, bound to the holder's signature only through the
    ///    sha256 fields inside the signed envelope. Persist recomputes every
    ///    one — leaf and each chain element, with matching lengths. Without
    ///    this the certs would be attacker-editable bytes next to a valid
    ///    signature.
    /// 6. The chain is non-empty and `signed_at` parses as RFC 3339.
    ///
    /// # What this does NOT verify, and why
    ///
    /// Not checked here: the holder's hybrid signature over the envelope, the
    /// X.509 path `9c → f9 → pinned Yubico root`, that the attested key IS the
    /// holder's federation Ed25519 key, and the FIPS / touch-policy floor.
    ///
    /// `ciris_verify_core::accord_custody_attestation::verify_accord_custody_attestation`
    /// (CIRISVerify#91 — implemented and released; the chain walk is
    /// `verify_yubikey_piv_attestation`, 9c → f9 → pinned Yubico root)
    /// does all four — but it requires two inputs this call site does not have:
    /// the holder's **directory-resolved** `ThresholdMember` pubkeys, and a
    /// **pinned Yubico attestation root**. Verify deliberately does not ship
    /// the latter ("verify provides the verification, not the trust root"), and
    /// [`Self::check`]'s signature is `(key_id, evidence, now)` — it holds
    /// neither. Verifying the signature against the pubkey carried *inside the
    /// same envelope* would be self-referential: it would prove the object is
    /// internally consistent, not that it belongs to the key being admitted.
    /// Fake depth is worse than declared depth, so persist does the bindings it
    /// can do honestly and says plainly what it defers.
    ///
    /// This is the SAME depth the [`AttestationEvidence::Hardware`] arm has
    /// always had (see the module header: persist does not do active chain
    /// validation *at this call site*).
    ///
    /// # Where the chain IS walked — corrected v25.1.0
    ///
    /// This note previously said the full walk "runs where the pinned root
    /// lives — CIRISServer's admission gate." **That was wrong, and wrong in
    /// the dangerous direction: it pointed a reader at another repo.** Server
    /// imports `verify_yubikey_piv_attestation`, but the walk against the
    /// *production* root runs **here, in persist**, roughly 4,300 lines below
    /// this comment:
    ///
    /// - [`super::admission::verify_member_fips_custody_against`] — ungated
    ///   `pub fn`, calling verify's `verify_accord_custody_attestation`.
    /// - Reached at runtime from `verify_accord_family_coscrub_with`, under
    ///   the canonical-role gate, against the pinned
    ///   [`super::admission::YUBICO_ATTESTATION_ROOT_1_DER`] — production
    ///   code, not a fixture. A caller-supplied root never reaches the
    ///   admission path.
    /// - The **baked production holders have actually been walked**:
    ///   `baked_accord_holders_fips_custody_verifies_513` runs the real A1 /
    ///   B1 / C1 genesis records against the real pinned root — holder
    ///   hybrid signature, `9c → f9 → root` link-by-link, attested key ==
    ///   holder's federation Ed25519, FIPS + touch=always — plus the inverse,
    ///   that mock members fail against the real root.
    ///
    /// Two further corrections: verify **does** ship the pinned root since
    /// v10.10.0 (`trust_anchor_store::baked`), so "verify deliberately ships
    /// neither" is stale — it ships the root and still requires
    /// caller-supplied directory pubkeys, which is correct because the
    /// directory is ours. And the runtime gate is **canonical-role only** by
    /// design (#513): ordinary node/agent admission does not walk the chain.
    ///
    /// The lesson is worth more than the correction. A deferral note that
    /// names another component as the place the check happens is a claim
    /// about a repo you are not compiling, and nothing fails when it stops
    /// being true. This one was stale in the direction that reads as "someone
    /// else has it covered" — the exact shape of #545/#554, where two layers
    /// each believed the other verified the artifact. **Persist's storage of
    /// the evidence preserves the audit trail regardless; the walk is what
    /// makes it mean something, and the walk is ours.**
    ///
    /// # No freshness check — deliberately
    ///
    /// There is no nonce to age. The device attests at key GENERATION, once,
    /// and the artifact is durable by design: a ceremony run in June is still
    /// the custody proof in December. Re-checking a generation-time timestamp
    /// against `max_nonce_age` at every boot would refuse the trust root for
    /// the crime of being old — a category error, and the reason the SQL
    /// backends grew a separate seeding door in the first place.
    fn check_generation_custody(
        &self,
        key_id: &str,
        att: &GenerationCustodyAttestation,
    ) -> Result<(), Error> {
        use ciris_verify_core::accord_custody_attestation::ACCORD_CUSTODY_ATTESTATION_KIND;
        use ciris_verify_core::ceg_outbox::SCHEMA as CEG_SCHEMA;

        // Every refusal below is TYPED and names the failing check. A custody
        // decision that reads as "malformed" teaches an operator nothing — the
        // #545 lesson, which is what let #554 hide for a whole ceremony.
        let refuse = |detail: String| Error::AccordHolderRequiresAttestationEvidence {
            key_id: key_id.to_owned(),
            detail,
        };

        // 1. Contract identity.
        if att.schema != CEG_SCHEMA {
            return Err(refuse(format!(
                "custody attestation schema {:?} is not the recognized {CEG_SCHEMA:?} — \
                 a schema change is a contract change persist must adopt consciously",
                att.schema
            )));
        }
        if att.kind != ACCORD_CUSTODY_ATTESTATION_KIND {
            return Err(refuse(format!(
                "custody attestation kind {:?} is not {ACCORD_CUSTODY_ATTESTATION_KIND:?}",
                att.kind
            )));
        }

        let env = &att.body.signed_envelope;

        // 2. Identity binding — the signed self-claim must be about THIS row.
        if env.holder_key_id != key_id {
            return Err(refuse(format!(
                "custody attestation holder_key_id {:?} does not match the row key_id \
                 {key_id:?} — a holder cannot present another holder's custody proof",
                env.holder_key_id
            )));
        }
        if att.key_id != env.holder_key_id {
            return Err(refuse(format!(
                "custody attestation object key_id {:?} disagrees with its signed \
                 holder_key_id {:?}",
                att.key_id, env.holder_key_id
            )));
        }

        // 3. Tier allowlist.
        if !self.accepted_custody_tiers.contains(&env.custody_tier) {
            let mut accepted: Vec<&str> = self
                .accepted_custody_tiers
                .iter()
                .map(String::as_str)
                .collect();
            accepted.sort_unstable();
            return Err(refuse(format!(
                "custody_tier {:?} is not accepted (accepted: {accepted:?})",
                env.custody_tier
            )));
        }

        // 4. The hardware class this arm asserts must itself be policy-accepted.
        if !self
            .accepted_hardware_types
            .contains(&HardwareType::ExternalSecureElement)
        {
            return Err(Error::HardwareTypeNotAccepted {
                got: format!("{:?}", HardwareType::ExternalSecureElement),
                accepted: {
                    let mut a: Vec<String> = self
                        .accepted_hardware_types
                        .iter()
                        .map(|t| format!("{t:?}"))
                        .collect();
                    a.sort();
                    a
                },
            });
        }

        // 5. Structural floor: an empty chain proves nothing.
        if att.body.yubikey_attestation_chain_hex.is_empty() {
            return Err(refuse(
                "custody attestation carries an EMPTY attestation chain — a leaf with \
                 no path above it is not custody evidence"
                    .into(),
            ));
        }
        if att.body.yubikey_attestation_chain_hex.len()
            != env.yubikey_attestation_chain_sha256.len()
        {
            return Err(refuse(format!(
                "yubikey_attestation_chain: {} evidence cert(s) but {} signed sha256 \
                 commitment(s) — the lists must correspond element for element",
                att.body.yubikey_attestation_chain_hex.len(),
                env.yubikey_attestation_chain_sha256.len()
            )));
        }

        // 6. The sha256 bindings — the cheap, honest integrity link between the
        // unsigned certificate bytes and the signed envelope.
        let der_9c = hex::decode(&att.body.yubikey_piv_attestation_9c_hex)
            .map_err(|e| refuse(format!("yubikey_piv_attestation_9c_hex is not hex: {e}")))?;
        if !sha256_hex(&der_9c).eq_ignore_ascii_case(&env.yubikey_piv_attestation_9c_sha256) {
            return Err(refuse(
                "yubikey_piv_attestation_9c: the certificate does not match its signed \
                 sha256 commitment — the evidence was altered after signing"
                    .into(),
            ));
        }
        for (i, (hex_der, commitment)) in att
            .body
            .yubikey_attestation_chain_hex
            .iter()
            .zip(env.yubikey_attestation_chain_sha256.iter())
            .enumerate()
        {
            let der = hex::decode(hex_der).map_err(|e| {
                refuse(format!(
                    "yubikey_attestation_chain_hex[{i}] is not hex: {e}"
                ))
            })?;
            if !sha256_hex(&der).eq_ignore_ascii_case(commitment) {
                return Err(refuse(format!(
                    "yubikey_attestation_chain[{i}]: the certificate does not match its \
                     signed sha256 commitment — the evidence was altered after signing"
                )));
            }
        }

        // 7. The generation instant must be a real instant (not aged — see the
        // "No freshness check" note above).
        DateTime::parse_from_rfc3339(&env.signed_at).map_err(|e| {
            refuse(format!(
                "custody attestation signed_at {:?} is not RFC 3339: {e}",
                env.signed_at
            ))
        })?;

        Ok(())
    }
}

/// Hex sha256 — the certificate commitment encoding (CIRISVerify#113).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Derive the [`HardwareType`] from a [`PlatformAttestation`] variant.
///
/// This mapping mirrors ciris-keyring's own variant-class semantics:
/// the variant proves the class, but the SAME variant can prove either
/// of two HardwareType values (StrongBox-on vs StrongBox-off; discrete
/// TPM vs firmware TPM). The function picks the *finer-grained* hardware
/// type when the variant's discriminator field is present.
pub(crate) fn platform_to_hardware_type(att: &PlatformAttestation) -> HardwareType {
    match att {
        PlatformAttestation::Android(a) => {
            if a.strongbox_backed {
                HardwareType::AndroidStrongbox
            } else {
                HardwareType::AndroidKeystore
            }
        }
        PlatformAttestation::Ios(_) => HardwareType::IosSecureEnclave,
        PlatformAttestation::Tpm(t) => {
            if t.discrete {
                HardwareType::TpmDiscrete
            } else {
                HardwareType::TpmFirmware
            }
        }
        PlatformAttestation::ExternalSecureElement(_) => HardwareType::ExternalSecureElement,
        PlatformAttestation::Software(_) => HardwareType::SoftwareOnly,
    }
}

/// Return the list of required-but-missing field names per variant.
/// Empty Vec = all required fields present.
///
/// Required-field vocabulary (stable for telemetry / tests):
///
/// - Android: `key_attestation_chain`, `play_integrity_token`,
///   `strongbox_backed` (strongbox_backed is always present as bool;
///   listed for symmetry but never reports missing).
/// - iOS: `secure_enclave`, `app_attest`, `device_check_token`.
/// - TPM: `quote`, `ek_cert`, `ak_public_key`, `manufacturer`,
///   `pcr_values`.
/// - Software: `software_only_not_accepted` (single token — the variant
///   itself is the policy violation; `HardwareTypeNotAccepted` fires
///   first, but the routine returns a single-token violation here for
///   defense in depth if a future policy admits Software).
pub(crate) fn required_field_gaps(att: &PlatformAttestation) -> Vec<String> {
    let mut gaps = Vec::new();
    match att {
        PlatformAttestation::Android(a) => {
            if a.key_attestation_chain.is_empty() {
                gaps.push("key_attestation_chain".into());
            }
            if a.play_integrity_token.is_none() {
                gaps.push("play_integrity_token".into());
            }
            // strongbox_backed is a bool — always present.
        }
        PlatformAttestation::Ios(i) => {
            if !i.secure_enclave {
                gaps.push("secure_enclave".into());
            }
            if i.app_attest.is_none() {
                gaps.push("app_attest".into());
            }
            if i.device_check_token.is_none() {
                gaps.push("device_check_token".into());
            }
        }
        PlatformAttestation::Tpm(t) => {
            if t.quote.is_none() {
                gaps.push("quote".into());
            }
            if t.ek_cert.is_none() {
                gaps.push("ek_cert".into());
            }
            if t.ak_public_key.is_none() {
                gaps.push("ak_public_key".into());
            }
            if t.manufacturer.is_empty() {
                gaps.push("manufacturer".into());
            }
            // pcr_values lives inside quote.pcr_values; surface it as a
            // top-level missing-field when the quote is present but the
            // PCR vec is None or empty.
            if let Some(q) = &t.quote {
                match &q.pcr_values {
                    None => gaps.push("pcr_values".into()),
                    Some(v) if v.is_empty() => gaps.push("pcr_values".into()),
                    _ => {}
                }
            }
        }
        PlatformAttestation::ExternalSecureElement(e) => {
            // §9.4 external secure element (YubiKey PIV / smartcard). The
            // load-bearing evidence is the leaf attestation cert (a YubiKey's
            // slot-9c attestation certificate) plus the chain above it up to
            // the pinned root. `hardware_class` names the §9.4 class.
            // `fips_certified` / `touch_always` are bools — always present.
            if e.hardware_class.is_empty() {
                gaps.push("hardware_class".into());
            }
            if e.attestation_cert_der.is_empty() {
                gaps.push("attestation_cert_der".into());
            }
            if e.attestation_chain_der.is_empty() {
                gaps.push("attestation_chain_der".into());
            }
        }
        PlatformAttestation::Software(_) => {
            gaps.push("software_only_not_accepted".into());
        }
    }
    gaps
}

/// v22.0.0 (CIRISPersist#543) — the ONE shared hardware-evidence fixture.
///
/// Test-only (`test` / `test-anchor`, the same gate the other `test_support`
/// modules use) so the signing/fixture helpers stay out of release builds.
///
/// Exists because closing the memory backend's missing `accord_holder`
/// hardware gate turned every `accord_holder` test fixture across the crate
/// into a rejected row. The fix is ONE helper every fixture calls, not the
/// same JSON blob pasted into each test module — a pasted blob is how the
/// backends drift apart in the first place.
#[cfg(any(test, feature = "test-anchor"))]
#[allow(dead_code)]
pub mod test_support {
    /// A structurally-complete, FRESH Android-Strongbox
    /// `attestation_evidence` value: the shape
    /// [`super::HardwareAttestationPolicy::check`] admits under the default
    /// policy. Fixtures that register an `accord_holder` attach this so the
    /// gate is SATISFIED rather than bypassed — the row proves the same
    /// custody claim on memory, sqlite and postgres alike.
    ///
    /// The nonce is captured at call time, so it is always inside
    /// `max_nonce_age`. Tests exercising the stale arm build their own value
    /// with a back-dated `nonce_captured_at`.
    pub fn fresh_accord_holder_evidence() -> serde_json::Value {
        serde_json::json!({
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
            "nonce_captured_at": chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Attach [`fresh_accord_holder_evidence`] to `row` iff it actually
    /// claims `accord_holder` (on either role surface — scalar set form or
    /// the `roles` vector, i.e. `KeyRecord::claims_role`). A no-op for every
    /// other row, so a fixture builder can call it unconditionally.
    pub fn attach_accord_holder_evidence(row: &mut crate::federation::types::KeyRecord) {
        if row.claims_role(crate::federation::types::identity_type::ACCORD_HOLDER) {
            row.attestation_evidence = Some(fresh_accord_holder_evidence());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_keyring::{
        AndroidAttestation, ExternalSecureElementAttestation, IosAttestation, SoftwareAttestation,
    };

    fn android_full() -> PlatformAttestation {
        PlatformAttestation::Android(AndroidAttestation {
            key_attestation_chain: vec![vec![0x30, 0x82], vec![0x30, 0x82]],
            play_integrity_token: Some("eyJhbGciOiJIUzI1NiJ9.fake.token".into()),
            strongbox_backed: true,
        })
    }

    fn ios_full() -> PlatformAttestation {
        PlatformAttestation::Ios(IosAttestation {
            secure_enclave: true,
            app_attest: Some(vec![0xab, 0xcd, 0xef]),
            device_check_token: Some(vec![0x12, 0x34, 0x56]),
        })
    }

    /// Build a TPM-variant PlatformAttestation by JSON round-trip.
    /// `TpmQuoteData` and `PcrValue` aren't re-exported by ciris-
    /// keyring's public surface — but the variant's serde shape is
    /// stable, so we construct via JSON and deserialize. The shape
    /// mirrors ciris-keyring/src/types.rs `TpmAttestation` /
    /// `TpmQuoteData` / `PcrValue` exactly.
    fn tpm_discrete_full() -> PlatformAttestation {
        let v = serde_json::json!({
            "Tpm": {
                "tpm_version": "2.0",
                "manufacturer": "Infineon",
                "discrete": true,
                "quote": {
                    "quoted": vec![0xffu8; 32],
                    "signature": vec![0xeeu8; 64],
                    "pcr_selection": [0x03],
                    "qualifying_data": vec![0u8; 32],
                    "pcr_values": [
                        { "index": 0, "digest": vec![0xabu8; 32] }
                    ],
                    "timestamp": 1_700_000_000u64,
                },
                "ek_cert": [0x30, 0x82, 0x01, 0x00],
                "ak_public_key": [0x04, 0x01, 0x02],
            }
        });
        serde_json::from_value(v).expect("tpm_discrete_full")
    }

    fn tpm_missing_pcr() -> PlatformAttestation {
        let v = serde_json::json!({
            "Tpm": {
                "tpm_version": "2.0",
                "manufacturer": "Infineon",
                "discrete": true,
                "quote": {
                    "quoted": vec![0xffu8; 32],
                    "signature": vec![0xeeu8; 64],
                    "pcr_selection": [0x03],
                    "qualifying_data": vec![0u8; 32],
                    "pcr_values": null,   // ← the gap
                    "timestamp": 1_700_000_000u64,
                },
                "ek_cert": [0x30, 0x82, 0x01, 0x00],
                "ak_public_key": [0x04, 0x01, 0x02],
            }
        });
        serde_json::from_value(v).expect("tpm_missing_pcr")
    }

    fn software_only() -> PlatformAttestation {
        PlatformAttestation::Software(SoftwareAttestation::default())
    }

    /// A fully-populated FIPS YubiKey PIV slot-9c attestation — the
    /// canonical HUMANITY_ACCORD holder custody (CIRISPersist#268).
    fn external_se_yubikey_full() -> PlatformAttestation {
        PlatformAttestation::ExternalSecureElement(ExternalSecureElementAttestation {
            hardware_class: "YubiKey_5_FIPS".into(),
            attestation_cert_der: vec![0x30, 0x82, 0x01, 0x00], // slot-9c leaf
            attestation_chain_der: vec![vec![0x30, 0x82, 0x02, 0x00]], // [f9, ..]
            firmware: Some("5.7.4".into()),
            serial: Some(12_345_678),
            fips_certified: true,
            touch_always: true,
        })
    }

    #[test]
    fn default_policy_drops_software_only() {
        let p = HardwareAttestationPolicy::default();
        assert!(!p
            .accepted_hardware_types
            .contains(&HardwareType::SoftwareOnly));
        // 12 of the 13 variants accepted.
        assert_eq!(p.accepted_hardware_types.len(), 12);
    }

    #[test]
    fn default_policy_max_nonce_age_24h() {
        let p = HardwareAttestationPolicy::default();
        assert_eq!(p.max_nonce_age, DEFAULT_MAX_NONCE_AGE);
        assert_eq!(p.max_nonce_age.as_secs(), 86_400);
    }

    #[test]
    fn platform_to_hardware_type_picks_finer_grain() {
        let android_strongbox = android_full();
        assert_eq!(
            platform_to_hardware_type(&android_strongbox),
            HardwareType::AndroidStrongbox
        );
        let mut android_no_sb = android_full();
        if let PlatformAttestation::Android(ref mut a) = android_no_sb {
            a.strongbox_backed = false;
        }
        assert_eq!(
            platform_to_hardware_type(&android_no_sb),
            HardwareType::AndroidKeystore
        );
        assert_eq!(
            platform_to_hardware_type(&tpm_discrete_full()),
            HardwareType::TpmDiscrete
        );
    }

    #[test]
    fn check_rejects_missing_evidence() {
        let p = HardwareAttestationPolicy::default();
        let err = p.check("k1", None, Utc::now()).unwrap_err();
        assert!(matches!(
            err,
            Error::AccordHolderRequiresAttestationEvidence { ref detail, .. } if detail == "missing"
        ));
        assert_eq!(
            err.kind(),
            "federation_accord_holder_requires_attestation_evidence"
        );
    }

    #[test]
    fn check_rejects_null_evidence() {
        let p = HardwareAttestationPolicy::default();
        let v = serde_json::Value::Null;
        let err = p.check("k1", Some(&v), Utc::now()).unwrap_err();
        assert!(matches!(
            err,
            Error::AccordHolderRequiresAttestationEvidence { ref detail, .. } if detail == "null"
        ));
    }

    /// #545 — the SoftwareOnly_TEST marker WITHOUT a live test anchor is a
    /// TYPED, loud refusal naming the tier — never "malformed". This is the
    /// security half of the #545 fix: making the marker representable must
    /// not make it admissible; a peer presenting it on a real mesh is making
    /// a custody claim this node refuses as a DECISION, not a parse error.
    #[serial_test::serial(test_anchor_env)]
    #[test]
    fn software_only_test_marker_refused_when_anchor_not_live_545() {
        // Ensure the anchor is genuinely dark for this process.
        std::env::remove_var("CIRIS_TEST_TRUST_ROOT");
        let p = HardwareAttestationPolicy::default();
        let v = serde_json::json!({"tier": "SoftwareOnly_TEST", "test_anchor": true});
        let err = p.check("mesh-peer", Some(&v), Utc::now()).unwrap_err();
        match err {
            Error::AccordHolderRequiresAttestationEvidence { ref detail, .. } => {
                assert!(
                    detail.contains("test anchor not live"),
                    "#545: the refusal must say WHY: {detail}"
                );
                assert!(
                    !detail.starts_with("malformed"),
                    "#545: a custody decision must not read as a parser bug: {detail}"
                );
            }
            other => panic!("#545: expected the typed evidence refusal, got {other:?}"),
        }
    }

    /// #545 — `test_anchor: false` on the marker is refused even if an anchor
    /// were live: the marker's own honesty bit must be set.
    #[test]
    fn software_only_test_marker_requires_test_anchor_true_545() {
        let p = HardwareAttestationPolicy::default();
        let v = serde_json::json!({"tier": "SoftwareOnly_TEST", "test_anchor": false});
        let err = p.check("k", Some(&v), Utc::now()).unwrap_err();
        assert!(
            format!("{err}").contains("test_anchor:true"),
            "#545: names the missing honesty bit: {err}"
        );
    }

    /// #545 — `deny_unknown_fields` keeps anything hardware-shaped (or
    /// padded) out of the marker arm: a marker with extra fields is
    /// MALFORMED, not a software-test claim.
    #[test]
    fn software_only_test_marker_with_extra_fields_is_malformed_545() {
        let p = HardwareAttestationPolicy::default();
        let v = serde_json::json!({
            "tier": "SoftwareOnly_TEST",
            "test_anchor": true,
            "platform_attestation": {"smuggled": true}
        });
        let err = p.check("k", Some(&v), Utc::now()).unwrap_err();
        assert!(
            format!("{err}").contains("malformed"),
            "#545: a padded marker must fail deserialization: {err}"
        );
    }

    #[test]
    fn check_rejects_software_only_variant() {
        let p = HardwareAttestationPolicy::default();
        let ev = AttestationEvidence::Hardware(Box::new(HardwareCustodyEvidence {
            platform_attestation: software_only(),
            nonce_captured_at: Utc::now(),
        }));
        let v = serde_json::to_value(&ev).unwrap();
        let err = p.check("k1", Some(&v), Utc::now()).unwrap_err();
        match err {
            Error::HardwareTypeNotAccepted { got, .. } => {
                assert_eq!(got, "SoftwareOnly");
            }
            other => panic!("expected HardwareTypeNotAccepted, got {other:?}"),
        }
    }

    #[test]
    fn check_reports_missing_pcr_values_for_tpm() {
        let p = HardwareAttestationPolicy::default();
        let ev = AttestationEvidence::Hardware(Box::new(HardwareCustodyEvidence {
            platform_attestation: tpm_missing_pcr(),
            nonce_captured_at: Utc::now(),
        }));
        let v = serde_json::to_value(&ev).unwrap();
        let err = p.check("k1", Some(&v), Utc::now()).unwrap_err();
        match err {
            Error::AttestationEvidenceIncomplete {
                hardware_type,
                missing_fields,
            } => {
                assert_eq!(hardware_type, "TpmDiscrete");
                assert!(missing_fields.iter().any(|f| f == "pcr_values"));
            }
            other => panic!("expected AttestationEvidenceIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn check_rejects_stale_nonce() {
        let p = HardwareAttestationPolicy::default();
        let captured = Utc::now() - chrono::Duration::hours(48);
        let ev = AttestationEvidence::Hardware(Box::new(HardwareCustodyEvidence {
            platform_attestation: android_full(),
            nonce_captured_at: captured,
        }));
        let v = serde_json::to_value(&ev).unwrap();
        let err = p.check("k1", Some(&v), Utc::now()).unwrap_err();
        match err {
            Error::AttestationEvidenceStale { max_age_secs, .. } => {
                assert_eq!(max_age_secs, 86_400);
            }
            other => panic!("expected AttestationEvidenceStale, got {other:?}"),
        }
    }

    #[test]
    fn check_accepts_full_android_strongbox() {
        let p = HardwareAttestationPolicy::default();
        let ev = AttestationEvidence::Hardware(Box::new(HardwareCustodyEvidence {
            platform_attestation: android_full(),
            nonce_captured_at: Utc::now(),
        }));
        let v = serde_json::to_value(&ev).unwrap();
        p.check("k1", Some(&v), Utc::now()).unwrap();
    }

    #[test]
    fn check_accepts_full_ios() {
        let p = HardwareAttestationPolicy::default();
        let ev = AttestationEvidence::Hardware(Box::new(HardwareCustodyEvidence {
            platform_attestation: ios_full(),
            nonce_captured_at: Utc::now(),
        }));
        let v = serde_json::to_value(&ev).unwrap();
        p.check("k1", Some(&v), Utc::now()).unwrap();
    }

    #[test]
    fn platform_to_hardware_type_maps_external_se() {
        assert_eq!(
            platform_to_hardware_type(&external_se_yubikey_full()),
            HardwareType::ExternalSecureElement
        );
    }

    #[test]
    fn default_policy_accepts_external_secure_element() {
        // CIRISPersist#268 — the FIPS YubiKey PIV admission path must be
        // open by default, else genesis entrenchment 409s.
        let p = HardwareAttestationPolicy::default();
        assert!(p
            .accepted_hardware_types
            .contains(&HardwareType::ExternalSecureElement));
    }

    #[test]
    fn check_accepts_full_yubikey_piv() {
        let p = HardwareAttestationPolicy::default();
        let ev = AttestationEvidence::Hardware(Box::new(HardwareCustodyEvidence {
            platform_attestation: external_se_yubikey_full(),
            nonce_captured_at: Utc::now(),
        }));
        let v = serde_json::to_value(&ev).unwrap();
        p.check("k1", Some(&v), Utc::now()).unwrap();
    }

    #[test]
    fn check_reports_missing_cert_and_chain_for_external_se() {
        let p = HardwareAttestationPolicy::default();
        let mut att = external_se_yubikey_full();
        if let PlatformAttestation::ExternalSecureElement(ref mut e) = att {
            e.attestation_cert_der.clear();
            e.attestation_chain_der.clear();
        }
        let ev = AttestationEvidence::Hardware(Box::new(HardwareCustodyEvidence {
            platform_attestation: att,
            nonce_captured_at: Utc::now(),
        }));
        let v = serde_json::to_value(&ev).unwrap();
        let err = p.check("k1", Some(&v), Utc::now()).unwrap_err();
        match err {
            Error::AttestationEvidenceIncomplete {
                hardware_type,
                missing_fields,
            } => {
                assert_eq!(hardware_type, "ExternalSecureElement");
                assert!(missing_fields.iter().any(|f| f == "attestation_cert_der"));
                assert!(missing_fields.iter().any(|f| f == "attestation_chain_der"));
            }
            other => panic!("expected AttestationEvidenceIncomplete, got {other:?}"),
        }
    }

    /// A minimal-but-valid generation-custody value, with cert hex whose
    /// sha256 commitments are computed (not pasted) so the bindings hold.
    fn generation_custody_value(holder: &str, tier: &str) -> serde_json::Value {
        let leaf = [0x30u8, 0x82, 0x01, 0x00];
        let chain = [0x30u8, 0x82, 0x02, 0x00];
        serde_json::json!({
            "schema": ciris_verify_core::ceg_outbox::SCHEMA,
            "kind": ciris_verify_core::accord_custody_attestation::ACCORD_CUSTODY_ATTESTATION_KIND,
            "key_id": holder,
            "created_at": "2026-06-23T03:16:34Z",
            "body": {
                "signed_envelope": {
                    "custody_tier": tier,
                    "holder_key_id": holder,
                    "ed25519_public_key_base64": "HMxA7KlgwUn5oWQlufB4aeFouTmFGsTILNphe0E3KlM=",
                    "mldsa65_public_key_sha256": sha256_hex(b"mldsa"),
                    "yubikey_piv_attestation_9c_sha256": sha256_hex(&leaf),
                    "yubikey_attestation_chain_sha256": [sha256_hex(&chain)],
                    "signed_at": "2026-06-23T03:16:34Z",
                },
                "ed25519_signature_base64": "AA==",
                "mldsa65_signature_base64": "AA==",
                "yubikey_piv_attestation_9c_hex": hex::encode(leaf),
                "yubikey_attestation_chain_hex": [hex::encode(chain)],
            }
        })
    }

    /// #554 — **untagged variant discrimination.** Adding a third arm to an
    /// untagged enum is exactly where one arm silently swallows another's
    /// payload. Pin that each shape still lands where it belongs: a hardware
    /// body is `Hardware`, a custody object is `GenerationCustody`, the marker
    /// is `SoftwareOnlyTest` — and none of them is reachable from the others.
    #[test]
    fn the_three_arms_do_not_capture_each_others_payloads_554() {
        let hw = serde_json::to_value(AttestationEvidence::Hardware(Box::new(
            HardwareCustodyEvidence {
                platform_attestation: android_full(),
                nonce_captured_at: Utc::now(),
            },
        )))
        .unwrap();
        let custody = generation_custody_value("A1", "portable_2fa");
        let marker = serde_json::json!({"tier": "SoftwareOnly_TEST", "test_anchor": true});

        assert!(matches!(
            serde_json::from_value::<AttestationEvidence>(hw).unwrap(),
            AttestationEvidence::Hardware(_)
        ));
        assert!(matches!(
            serde_json::from_value::<AttestationEvidence>(custody).unwrap(),
            AttestationEvidence::GenerationCustody(_)
        ));
        assert!(matches!(
            serde_json::from_value::<AttestationEvidence>(marker).unwrap(),
            AttestationEvidence::SoftwareOnlyTest(_)
        ));
    }

    /// #554 — a custody attestation is NOT aged. The device attests at key
    /// GENERATION, so the artifact is durable by design: a ceremony run years
    /// ago is still the custody proof today. Refusing the trust root for being
    /// old is the category error `max_nonce_age` must not commit here.
    #[test]
    fn generation_custody_is_not_subject_to_nonce_freshness_554() {
        let p = HardwareAttestationPolicy::default();
        let v = generation_custody_value("A1", "portable_2fa");
        // Ten years on — the Hardware arm would have refused this at 24h.
        let much_later = Utc::now() + chrono::Duration::days(3650);
        p.check("A1", Some(&v), much_later)
            .expect("#554: an attestation-at-generation has no nonce to age");
    }

    /// #554 — the tier allowlist is policy, so a deployment can tighten it and
    /// the previously-admitted tier is then refused BY NAME.
    #[test]
    fn tightening_accepted_custody_tiers_refuses_the_tier_by_name_554() {
        let mut p = HardwareAttestationPolicy::default();
        p.accepted_custody_tiers.clear();
        let v = generation_custody_value("A1", "portable_2fa");
        let err = p.check("A1", Some(&v), Utc::now()).unwrap_err();
        assert!(
            format!("{err}").contains("portable_2fa"),
            "#554: the refusal must name the tier: {err}"
        );
    }

    /// #554 — the §9.4 hardware class this arm asserts is itself policy-gated:
    /// dropping `ExternalSecureElement` must not leave a side door open.
    #[test]
    fn generation_custody_respects_accepted_hardware_types_554() {
        let mut p = HardwareAttestationPolicy::default();
        p.accepted_hardware_types
            .remove(&HardwareType::ExternalSecureElement);
        let v = generation_custody_value("A1", "portable_2fa");
        let err = p.check("A1", Some(&v), Utc::now()).unwrap_err();
        match err {
            Error::HardwareTypeNotAccepted { got, .. } => {
                assert_eq!(got, "ExternalSecureElement");
            }
            other => panic!("#554: expected HardwareTypeNotAccepted, got {other:?}"),
        }
    }

    /// #554 — an empty attestation chain is refused: a leaf with no path above
    /// it is not custody evidence, and the sha256 loop would otherwise pass
    /// vacuously.
    #[test]
    fn generation_custody_with_empty_chain_is_refused_554() {
        let p = HardwareAttestationPolicy::default();
        let mut v = generation_custody_value("A1", "portable_2fa");
        v["body"]["yubikey_attestation_chain_hex"] = serde_json::json!([]);
        v["body"]["signed_envelope"]["yubikey_attestation_chain_sha256"] = serde_json::json!([]);
        let err = p.check("A1", Some(&v), Utc::now()).unwrap_err();
        assert!(
            format!("{err}").contains("EMPTY attestation chain"),
            "#554: {err}"
        );
    }

    /// #554 — an unrecognized `schema` is a contract change, refused by name
    /// rather than absorbed silently.
    #[test]
    fn generation_custody_with_unknown_schema_is_refused_554() {
        let p = HardwareAttestationPolicy::default();
        let mut v = generation_custody_value("A1", "portable_2fa");
        v["schema"] = serde_json::json!("ciris.ceg.signed-object.v99");
        let err = p.check("A1", Some(&v), Utc::now()).unwrap_err();
        assert!(
            format!("{err}").contains("v99"),
            "#554: the refusal must name the schema it got: {err}"
        );
    }

    #[test]
    fn check_accepts_full_tpm_discrete() {
        let p = HardwareAttestationPolicy::default();
        let ev = AttestationEvidence::Hardware(Box::new(HardwareCustodyEvidence {
            platform_attestation: tpm_discrete_full(),
            nonce_captured_at: Utc::now(),
        }));
        let v = serde_json::to_value(&ev).unwrap();
        p.check("k1", Some(&v), Utc::now()).unwrap();
    }
}
