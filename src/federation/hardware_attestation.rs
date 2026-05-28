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
//! Persist's verdict for an `accord_holder` row =
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
//! Persist does NOT do active chain validation (cert-chain to
//! Google root for Android, EK cert validation for TPM, JWT-verify
//! Play Integrity, App Attest assertion against Apple's roots). That's
//! CIRISVerify#32 Ask 5's local-chain-validation surface, which
//! Verify v3.0.1 has NOT shipped — `play_integrity.rs` / `tpm_attest.rs` /
//! `app_attest.rs` are request/response types that route through the
//! registry today. Persist's structural check ensures the evidence
//! shape is right + the nonce is fresh; registry-side validation (or
//! Verify#32 Ask 5 when shipping) does the chain verification.
//! Persist's storage of the evidence preserves the audit trail.
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
//! accepted set drops `SoftwareOnly` and accepts the other 11 variants;
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
/// - `accepted_hardware_types`: all 11 non-`SoftwareOnly` variants.
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
    pub max_nonce_age: Duration,
}

impl Default for HardwareAttestationPolicy {
    fn default() -> Self {
        // All 12 variants minus SoftwareOnly. Listed explicitly so
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
        ];
        Self {
            accepted_hardware_types: accepted.into_iter().collect(),
            max_nonce_age: DEFAULT_MAX_NONCE_AGE,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    /// The platform attestation Verify produced via
    /// `HardwareSigner::attestation_with_nonce(challenge)`.
    pub platform_attestation: PlatformAttestation,
    /// When Verify captured the nonce challenge. Persist checks
    /// freshness against [`HardwareAttestationPolicy::max_nonce_age`].
    pub nonce_captured_at: DateTime<Utc>,
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

        // 2. Deserialize.
        let evidence: AttestationEvidence = serde_json::from_value(value.clone()).map_err(|e| {
            Error::AccordHolderRequiresAttestationEvidence {
                key_id: key_id.to_owned(),
                detail: format!("malformed: {e}"),
            }
        })?;

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
        PlatformAttestation::Software(_) => {
            gaps.push("software_only_not_accepted".into());
        }
    }
    gaps
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_keyring::{AndroidAttestation, IosAttestation, SoftwareAttestation};

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

    #[test]
    fn default_policy_drops_software_only() {
        let p = HardwareAttestationPolicy::default();
        assert!(!p
            .accepted_hardware_types
            .contains(&HardwareType::SoftwareOnly));
        // 11 of the 12 variants accepted.
        assert_eq!(p.accepted_hardware_types.len(), 11);
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

    #[test]
    fn check_rejects_software_only_variant() {
        let p = HardwareAttestationPolicy::default();
        let ev = AttestationEvidence {
            platform_attestation: software_only(),
            nonce_captured_at: Utc::now(),
        };
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
        let ev = AttestationEvidence {
            platform_attestation: tpm_missing_pcr(),
            nonce_captured_at: Utc::now(),
        };
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
        let ev = AttestationEvidence {
            platform_attestation: android_full(),
            nonce_captured_at: captured,
        };
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
        let ev = AttestationEvidence {
            platform_attestation: android_full(),
            nonce_captured_at: Utc::now(),
        };
        let v = serde_json::to_value(&ev).unwrap();
        p.check("k1", Some(&v), Utc::now()).unwrap();
    }

    #[test]
    fn check_accepts_full_ios() {
        let p = HardwareAttestationPolicy::default();
        let ev = AttestationEvidence {
            platform_attestation: ios_full(),
            nonce_captured_at: Utc::now(),
        };
        let v = serde_json::to_value(&ev).unwrap();
        p.check("k1", Some(&v), Utc::now()).unwrap();
    }

    #[test]
    fn check_accepts_full_tpm_discrete() {
        let p = HardwareAttestationPolicy::default();
        let ev = AttestationEvidence {
            platform_attestation: tpm_discrete_full(),
            nonce_captured_at: Utc::now(),
        };
        let v = serde_json::to_value(&ev).unwrap();
        p.check("k1", Some(&v), Utc::now()).unwrap();
    }
}
