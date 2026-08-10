//! Federation directory wire-format types.
//!
//! These shapes are the source of truth for both persist's backends
//! and CIRISRegistry's vendored
//! `rust-registry/src/federation/types.rs`. Field names + types must
//! match field-for-field between the two repos.
//!
//! # PQC strategy (v0.2.0): hot-path Ed25519, cold-path ML-DSA-65
//!
//! **Hybrid Ed25519 + ML-DSA-65 is the only signing scheme across
//! the federation.** Every row in the historical audit chain
//! converges to fully hybrid-signed. But the WRITE PATH accepts
//! Ed25519-only rows initially with the ML-DSA-65 signature
//! attached on the cold path — see `docs/FEDERATION_DIRECTORY.md`
//! §"Trust contract — eventual consistency as a federation
//! primitive" for the architectural rationale.
//!
//! Writer contract:
//!   1. Sign canonical_bytes with Ed25519 (synchronous, hot path).
//!   2. Write the row (PQC fields may be `None` at this step).
//!   3. **IMMEDIATELY** kick off ML-DSA-65 signing on the cold
//!      path — not delayed, not batched, just off the synchronous
//!      request path.
//!   4. Call `attach_pqc_signature` once the ML-DSA-65 sign
//!      completes. `pqc_completed_at` is timestamped.
//!
//! When quantum threat materializes, persist's runtime policy
//! flips (`require_pqc_on_write=true`); the kickoff step folds
//! into the synchronous path and PQC fields become required at
//! write time.
//!
//! Every key in the federation has TWO public-key components:
//!   - `pubkey_ed25519_base64` — 32 raw bytes, base64 standard, REQUIRED
//!   - `pubkey_ml_dsa_65_base64` — 1952 raw bytes, base64 standard,
//!     populated by `attach_pqc_signature` (`Option<String>`)
//!
//! Every signature in the federation has TWO components, bound:
//!   - `scrub_signature_classical` — `Ed25519.sign(canonical_bytes)`,
//!     REQUIRED
//!   - `scrub_signature_pqc` — `ML-DSA-65.sign(canonical_bytes ||
//!     classical_sig)`, populated by `attach_pqc_signature`
//!     (`Option<String>`)
//!
//! The bound signature pattern (PQC covers `data || classical`)
//! prevents stripping attacks where an attacker who breaks Ed25519
//! could otherwise replace the PQC signature with their own. This
//! matches CIRISVerify's `ManifestSignature` and `HybridSignature`
//! contracts (`ciris-verify-core/src/security/function_integrity.rs:149`,
//! `ciris-crypto/src/types.rs:156`).
//!
//! # Identity, algorithm, and attestation type strings
//!
//! Persist stores `identity_type` and `attestation_type` as TEXT
//! columns (not enums) so new values can be added by either side
//! without a schema break. `algorithm` is also TEXT but only
//! `"hybrid"` is accepted — the schema enforces it
//! (`CHECK (algorithm = 'hybrid')`), and persist's runtime rejects
//! writes with any other value. The column exists for forward compat
//! against future PQC schemes (ML-DSA-87, ML-DSA + ML-KEM, etc.) that
//! may emerge as the federation evolves.
//!
//! # Canonical hashing
//!
//! [`KeyRecord::persist_row_hash`] is computed server-side by persist
//! via `crate::verify::canonical::PythonJsonDumpsCanonicalizer` (sorted
//! keys, no whitespace, `ensure_ascii=True`) over the row's
//! user-visible fields. Consumers store the hex string verbatim and
//! string-compare on cache divergence checks. Same shape for
//! [`Attestation::persist_row_hash`] and
//! [`Revocation::persist_row_hash`].
//!
//! See `docs/FEDERATION_DIRECTORY.md` §"persist_row_hash —
//! server-computed for cache divergence" for the architectural
//! rationale.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Identity classification per persist's `identity_type` column.
///
/// **Vocabulary stability (v2.4.0, CIRISPersist#102 Ask 1).** The
/// column is free-form TEXT in the schema — consumers may extend.
/// Persist publishes these five values as the canonical vocabulary
/// per FSD-002 §7 (HUMANITY_ACCORD layer); see
/// `docs/FEDERATION_DIRECTORY.md` §"Schema sketch" for per-value
/// rationale.
pub mod identity_type {
    /// Agent trace-signing keys.
    pub const AGENT: &str = "agent";
    /// Primitive build-signing keys (ciris-persist, ciris-agent, etc.).
    pub const PRIMITIVE: &str = "primitive";
    /// Steward keys (registry, persist, lens, agent — the trust roots).
    pub const STEWARD: &str = "steward";
    /// Per-org partner keys for commercial onboarding.
    pub const PARTNER: &str = "partner";
    /// HUMANITY_ACCORD key material — the three hardware-attested
    /// human-held kill-switch keys per FSD-002 §7.2. Only rows with
    /// this identity_type may emit `accord:*` attestations
    /// (FSD-002 §4.1 / §7.1 — the federation's one constitutional
    /// asymmetry); the admission gate in [`super::admission`]
    /// enforces this at write time.
    pub const ACCORD_HOLDER: &str = "accord_holder";
    /// v3.0.0 (CIRISPersist#116, CEG 0.2 §5.3 / §7.2) — the running
    /// persist instance's self-reporting key. Only `federation_keys`
    /// rows with this identity_type may emit attestations on the
    /// substrate-self-report prefixes (`system:*`, `audit_chain:*`,
    /// `corpus_health:*`, `identity_continuity:*`,
    /// `federation_directory:*`). The admission gate in
    /// [`super::admission::default_reserved_prefix_rules`] enforces
    /// this.
    pub const SUBSTRATE_PERSIST: &str = "substrate_persist";
    /// v3.0.0 (CIRISPersist#116, CEG 0.2 §7.6 / §10.3) — registered
    /// transparency-log witnesses. Only `federation_keys` rows with
    /// this identity_type may emit `transparency_log:cosigned:*`
    /// attestations. The substrate-conformance migration path moves
    /// the 0.x interim per-region `registry_witnesses` table over to
    /// `federation_keys` rows with this identity_type, per CEG §10.3.
    pub const WITNESS: &str = "witness";
    /// v3.6.0 (CIRISPersist#134, CEG 0.3 §11.5.3) — Policy J
    /// trusted-publisher identity. Only `federation_keys` rows with
    /// this identity_type may emit publisher-curated content ratings
    /// (`content_rating:*` reserved-prefix attestations). The
    /// admission gate in
    /// [`super::admission::default_reserved_prefix_rules`] enforces
    /// this.
    pub const TRUSTED_PUBLISHER: &str = "trusted_publisher";
    /// v6.5.0 (CIRISPersist#183, CEG §7.0.1 / §8.1.12.7) — a human
    /// user identity. Per §7.0.1 `identity_type` is conceptually a
    /// **set** ("an identity can be both `{user}` and
    /// `{wise_authority}`"); persist stores it as the single free-form
    /// TEXT column above, so a multi-valued classification is encoded
    /// as a comma-joined set (see [`join_set`] / [`parse_set`] /
    /// [`set_contains`]). The "self at login" co-admission stamps each
    /// occurrence's identity key with at least `{user}`.
    pub const USER: &str = "user";
    /// v6.5.0 (CIRISPersist#183, CEG §7.0.1) — a Wise Authority identity.
    /// Carried alongside [`USER`] in the `identity_type` set when the
    /// human is also a WA (e.g. `"user,wise_authority"`).
    pub const WISE_AUTHORITY: &str = "wise_authority";

    /// v30.7.0 (CIRISPersist#625) — every value an `identity_type` may hold.
    ///
    /// CURATED: this module also holds `AUTHORITY_CONFERRING_IDENTITY_TYPES` and
    /// `CO_STEWARD_ROLES`, which are SETS OVER these members, not members. A
    /// mechanical glob would offer a human a list-of-lists.
    pub const ALL: &[&str] = &[
        AGENT,
        NODE,
        USER,
        STEWARD,
        PARTNER,
        CANONICAL,
        REGISTRY,
        WITNESS,
        PRIMITIVE,
        ACCORD_HOLDER,
        SUBSTRATE_PERSIST,
        TRUSTED_PUBLISHER,
        WISE_AUTHORITY,
        LENSCORE_DETECTOR,
        VERIFY,
    ];
    /// v8.9.0 (CIRISPersist#235, CC 3.4.7.1 / CC 1.13.5) — the
    /// fabric/infrastructure role. A CIRISServer (or any pure
    /// infrastructure node) self-registers its federation signing key
    /// with this `identity_type`. **A `node`-role key MUST NOT carry
    /// agency** (CC 1.13.5): a `delegates_to` whose recipient resolves
    /// to a `node`-only identity may carry ONLY [`super::delegation_scope`]
    /// `infra:*` scopes — the admission gate in
    /// [`super::admission::check_node_agency_admission`] rejects any
    /// `agency:*` (or legacy unprefixed agency kind) scope on such a
    /// delegation, making "infrastructure must not have agency"
    /// cryptographically enforced (CC 4.4.3.4.3). CIRISServer registers
    /// the literal `"node"` today (`compose.rs::build_self_key_record`);
    /// this publishes the canonical token so producer + verifier agree
    /// byte-for-byte.
    pub const NODE: &str = "node";
    /// v12.7.0 (CIRISPersist#366, CC 3.4.8) — the LensCore-detector role.
    /// Only `federation_keys` rows whose `identity_type` **set** contains
    /// this token may emit the detector-only reserved prefixes
    /// `detection:correlated_action:*` and `detection:distributive:access:*`
    /// (see [`super::admission::default_reserved_prefix_rules`]). Per
    /// CC 3.4.7.1 the gate is evaluated by **set membership** — a folded
    /// LensCore occurrence whose key holds `{agent, lenscore_detector}`
    /// satisfies the detector gate via `lenscore_detector ∈ set` while its
    /// cohabiting `agent` role neither grants nor blocks the detector right
    /// (CC 3.4.8 LensCore-fold worked example). Cross-attestations by
    /// non-detector peers MUST use the distinct `truth_grounding:detection:*`
    /// prefix (ungated here), so anything on `detection:*` is a primary
    /// detector emission and gate-able with no envelope field.
    pub const LENSCORE_DETECTOR: &str = "lenscore_detector";
    /// v12.7.0 (CIRISPersist#372, CC 3.4.7.1 set-membership) — a
    /// **canonical / founding bootstrap server**. This role marks a node
    /// as a member of the founding canonical set; it is **accord-CONFERRED,
    /// never self-claimed**.
    ///
    /// The load-bearing invariant (the whole point of the role): a
    /// `federation_keys` row may carry `canonical` in its `identity_type`
    /// **set** ([`set_contains`]) **IFF** the record is
    /// **anchor-scrub-signed** — `scrub_key_id != key_id` AND
    /// `scrub_key_id`'s Ed25519 pubkey ∈ the pinned HUMANITY_ACCORD anchor
    /// ([`ciris_verify_core::accord_genesis::accord_holder_bootstrap_anchor`],
    /// the SAME terminus [`super::super::rooting::root_binding`] and
    /// [`super::super::register::verify_key_registration`] /
    /// `adopt_scrub_upgrade` verify). A **self-signed** record
    /// (`scrub_key_id == key_id`) carrying `canonical`, or one scrubbed by a
    /// **non-anchor** key, is REFUSED at admission
    /// ([`super::super::Error::CanonicalRoleNotAccordConferred`], stable
    /// `kind()` token `canonical_role_not_accord_conferred`) — fail-closed.
    /// **Monotonic**: the role can only ever arrive on an anchor-scrubbed
    /// record; it can never be added by a later self-registration or by
    /// replication of a self-signed row (the gate composes with the
    /// `put_public_key` DO-NOTHING / `adopt_scrub_upgrade` paths). The ONLY
    /// way to become a canonical server is the Trust Root **add-canonical**
    /// op: an accord holder scrub-signs the node with the `canonical` role.
    /// The admission gate is
    /// [`super::super::admission::check_canonical_role_admission`].
    pub const CANONICAL: &str = "canonical";
    /// v17.0.0 (CIRISPersist#440, CC 3.4.9) — the **CIRISRegistry
    /// co-steward** of the co-stewarded `licensure:{authority_id}`
    /// dimension. CC 3.4.9 caps single-source licensure attestations at
    /// `confidence <= 0.5` until BOTH co-stewards have emitted; to apply
    /// the cap a consumer must resolve *which* co-steward an attesting
    /// key is **from the registered key record alone** (not an
    /// out-of-band consumer pin — the CIRISServer#159 workaround this
    /// member retires). Rides the [`set_contains`] set semantics
    /// (CC 3.4.7.1), so a key may hold e.g. `{node,registry}`.
    ///
    /// **Accord-CONFERRED, never self-claimed** (the co-steward relation
    /// is a trust statement about an institution, i.e. capability-
    /// granting): admitted at every `federation_keys` write chokepoint
    /// only when the record carries the accord family m-of-n co-scrub —
    /// the SAME ceremony as [`CANONICAL`] / `infra:attest`, via
    /// [`super::super::admission::check_co_steward_role_admission`].
    /// Withdrawal rides the V104 generic role tombstone.
    pub const REGISTRY: &str = "registry";
    /// v17.0.0 (CIRISPersist#440, CC 3.4.9) — the **CIRISVerify
    /// co-steward** of `licensure:{authority_id}`. Exact mirror of
    /// [`REGISTRY`]; see it for the conferral/withdrawal story.
    pub const VERIFY: &str = "verify";
    /// v17.0.0 (CIRISPersist#440) — the two CC 3.4.9 co-steward roles,
    /// in canonical order. Every member is accord-conferred.
    pub const CO_STEWARD_ROLES: [&str; 2] = [REGISTRY, VERIFY];

    /// v22.0.0 (CIRISPersist#543 finding 3) — **THE AUTHORITY-CONFERRING
    /// CLAIM SET**: every `identity_type` value that unlocks a decision
    /// somewhere in this codebase, and therefore MUST NOT be self-assertable
    /// at registration.
    ///
    /// # Why this list exists
    ///
    /// `register_federation_key` requires a self-signed hybrid
    /// proof-of-possession and nothing else — by design, because canonical
    /// servers exist to bootstrap strangers. That proves key CUSTODY, not
    /// identity and not authorization. So any privilege attached to an
    /// `identity_type` a peer writes into its own registration is a privilege
    /// the peer grants itself.
    ///
    /// Before #543 exactly four claims were gated — [`ACCORD_HOLDER`]
    /// (hardware attestation), [`CANONICAL`] (anchor-scrub), `infra:attest`
    /// and the [`CO_STEWARD_ROLES`] (accord co-scrub) — each noticed
    /// individually as its own incident. The audit found the rest of the
    /// privileged set still self-assertable: a Sybil could register as
    /// [`SUBSTRATE_PERSIST`], [`WITNESS`], [`TRUSTED_PUBLISHER`] or
    /// [`LENSCORE_DETECTOR`] and thereby emit under reserved dimension
    /// families reserved to exactly those types (`system:`, `audit_chain:`,
    /// `age_assurance:`, `capacity_assurance:`, `content_rating:`,
    /// `detection:*`, …) — i.e. assert system, age, capacity or detection
    /// authority **about a third party**.
    ///
    /// The rule is now closed-set rather than incident-driven: a claim is
    /// gated **iff** it appears here, and
    /// `admission::tests::authority_conferring_set_covers_every_reserved_prefix_rule`
    /// proves this list is a superset of every `identity_type` any
    /// reserved-prefix rule requires. Adding a rule that reserves a family to
    /// a new type without adding that type here fails the build.
    ///
    /// [`AGENT`] / [`USER`] / [`NODE`] / [`PRIMITIVE`] are deliberately absent:
    /// they are *descriptive* — they unlock no decision, so self-assertion
    /// costs nothing. [`STEWARD`], [`PARTNER`] and [`WISE_AUTHORITY`] ARE
    /// present: each is read as authority (steward-binding, partner licensure,
    /// WA adjudication) somewhere in the write path.
    pub const AUTHORITY_CONFERRING_IDENTITY_TYPES: [&str; 9] = [
        ACCORD_HOLDER,
        CANONICAL,
        SUBSTRATE_PERSIST,
        WITNESS,
        TRUSTED_PUBLISHER,
        LENSCORE_DETECTOR,
        STEWARD,
        PARTNER,
        WISE_AUTHORITY,
    ];

    /// v22.0.0 (CIRISPersist#543 finding 3) — HOW each member of
    /// [`AUTHORITY_CONFERRING_IDENTITY_TYPES`] is conferred. Naming the
    /// mechanism per claim is the point: the pre-#543 bug was not "we forgot a
    /// gate", it was "we assumed one ceremony fits every privilege". These
    /// privileges have genuinely different roots, and a gate that demands the
    /// wrong ceremony is as broken as no gate — it fails CLOSED on legitimate
    /// operators (a witness cannot produce an accord co-scrub, and at bootstrap
    /// there is no roster to produce one from).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ConferralMode {
        /// Hardware attestation ([`ACCORD_HOLDER`]) — the strongest root; the
        /// key must prove secure-element custody. Gated by
        /// `hardware_attestation_policy().check`.
        HardwareAttested,
        /// Pinned-anchor scrub ([`CANONICAL`]) — signed by a key in the pinned
        /// HUMANITY_ACCORD anchor set. Gated by
        /// `check_canonical_role_admission`.
        AnchorScrubbed,
        /// Accord family m-of-n co-scrub (`infra:attest`, the
        /// [`CO_STEWARD_ROLES`], and the substrate/detector types). Gated by
        /// `check_accord_role_admission_over_roster`.
        AccordCoScrubbed,
        /// Conferred by an EXISTING holder of the corresponding authority
        /// through a graph edge that persist already verifies elsewhere
        /// (steward-binding, partner licensure, WA adjudication). The
        /// registration-time claim is descriptive; the AUTHORITY is re-derived
        /// from persist's own verified state at each use, so a self-asserted
        /// claim buys nothing. **Not gated at registration by design** — see
        /// the note on `check_privileged_identity_type_admission`.
        DerivedFromVerifiedState,
        /// v22.0.0 (CIRISPersist#543 / AV-75) — conferred on the **delegation
        /// plane**: a trust root (or a canonical it granted) issues a
        /// `delegates_to(root → key, [scope])`, and the authority is resolved at
        /// USE by [`capability_roots_to_trusted_root`](crate::federation::trust_root)
        /// — the claim must root to a trust root *the asking node itself trusts*.
        ///
        /// This is the plane the portable trust root already uses for
        /// operational capability. A minted root is five objects: three accord
        /// holders, a `canonical` blessed by their 2-of-3 co-scrub, a
        /// self-referential charter `delegates_to(root → root, [infra:*])`, a
        /// grant `delegates_to(root → canonical, [infra:serve])`, and the user's
        /// own `delegates_to(user → root)` trust edge. Note the split: **root
        /// IDENTITY** is conferred by ceremony (co-scrub); **operational
        /// CAPABILITY** flows by delegation. Roles that are capabilities belong
        /// here, not on the ceremony.
        ///
        /// Why this and not `AccordCoScrubbed` for such roles: the co-scrub
        /// roster resolves to the accord holders, whose private halves live in
        /// hardware (the #268 ceremony). Demanding it for a routine operational
        /// role fails closed on every legitimate operator. Delegation is
        /// satisfiable by any root, which is what keeps the root **portable** —
        /// anyone with three hardware keys mints their own, and ours is merely
        /// the shipped default (CC 3.2: "a default-plus-re-root is a
        /// federation"). Ratification: CIRISConstitution#40.
        DelegatedFromTrustRoot,
    }

    /// The conferral mode for every authority-conferring claim. Exhaustive over
    /// [`AUTHORITY_CONFERRING_IDENTITY_TYPES`] (proven by
    /// `admission::tests::every_authority_claim_declares_a_conferral_mode`).
    pub fn conferral_mode(identity_type: &str) -> Option<ConferralMode> {
        Some(match identity_type {
            ACCORD_HOLDER => ConferralMode::HardwareAttested,
            CANONICAL => ConferralMode::AnchorScrubbed,

            // v22.0.0 (CIRISPersist#543 / AV-75) — CAPABILITIES, so they ride
            // the DELEGATION plane.
            //
            // Both assert about a THIRD PARTY — `trusted_publisher` signs
            // `content_rating:*` about others' content (and seeds
            // `lookup_trusted_publisher_chain`); `lenscore_detector` owns the
            // entire `detection:*` wildcard — so self-assertion IS the #543
            // attack and they must be conferred, not claimed.
            //
            // The gate was briefly `AccordCoScrubbed`. That was wrong: the
            // co-scrub roster resolves to the accord holders, whose private
            // halves live in the #268 hardware ceremony, so registering a
            // routine detector would have required 2-of-3 named humans with
            // hardware tokens. A gate that fails closed on every legitimate
            // operator is not a gate, it is an outage — and it would have made
            // the root LESS portable, since every minted root would owe the
            // ceremony for each operational role it wants to stand up.
            //
            // The portable trust root already shows the right split: root
            // IDENTITY (`canonical`) is conferred by the accord's 2-of-3
            // co-scrub, while operational CAPABILITY (`infra:serve`,
            // `infra:attest`, `infra:store`, `infra:transport`) flows by
            // `delegates_to` from the root. These two roles are capabilities.
            // They belong on the delegation plane, resolved at USE against a
            // root the asking node itself trusts.
            TRUSTED_PUBLISHER | LENSCORE_DETECTOR => ConferralMode::DelegatedFromTrustRoot,

            // SELF-DESCRIPTIVE. `substrate_persist` is a node's identity FOR
            // ITSELF — the families it unlocks (`system:`, `audit_chain:`,
            // `corpus_health:`, `identity_continuity:`, `federation_directory:`)
            // are the node's own operational telemetry about its own substrate,
            // and nothing consumes them as authority over a third party. A
            // Sybil calling itself "the substrate" gains standing over nobody:
            // its `system:` rows describe its own node, which it is free to
            // describe. Requiring an accord co-scrub here would also be
            // unsatisfiable by construction — a node registers this identity at
            // its OWN bootstrap, before any accord family exists to co-scrub it.
            // (If a `system:*` row ever becomes an input to a decision ABOUT
            // ANOTHER PARTY, this must move to AccordCoScrubbed.)
            SUBSTRATE_PERSIST => ConferralMode::DerivedFromVerifiedState,

            // Conferred by graph edges persist already verifies at each USE:
            // steward-binding, licensure quorum, WA adjudication, and the
            // witness-target walks. The registration claim is descriptive; the
            // authority is re-derived from persist's own verified state, so a
            // self-asserted claim buys nothing.
            // v30.2.0 (CIRISPersist#607) — WITNESS moved to
            // DelegatedFromTrustRoot. It was declared DerivedFromVerifiedState
            // on the reasoning that "the AUTHORITY is re-derived at each use,
            // so a self-asserted claim buys nothing". That holds for STEWARD /
            // PARTNER / WISE_AUTHORITY, each of which has a real graph edge to
            // walk (steward-binding, partner licensure, WA adjudication). It
            // was never true of WITNESS: there is no verified state that makes
            // a key a witness, so nothing was re-derived and the three doors it
            // opens — age_assurance:, capacity_assurance:,
            // transparency_log:cosigned: — were bare membership tests against a
            // string the holder wrote themselves.
            //
            // CC 3.4.11 calls a witness "a registered age-assurance provider".
            // Registered BY someone: that is conferral, and the delegation
            // plane is where conferral lives. The mode was mis-declared, not
            // merely unenforced.
            WITNESS => ConferralMode::DelegatedFromTrustRoot,
            STEWARD | PARTNER | WISE_AUTHORITY => ConferralMode::DerivedFromVerifiedState,
            _ => return None,
        })
    }

    /// v6.5.0 (CEG §7.0.1) — join an `identity_type` **set** into the
    /// single TEXT column representation: sorted, de-duplicated,
    /// comma-joined (no whitespace), so the stored string is canonical
    /// regardless of caller insertion order. Empty input yields an
    /// empty string.
    pub fn join_set<I, S>(types: I) -> String
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut v: Vec<String> = types
            .into_iter()
            .map(|s| s.as_ref().trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        v.sort();
        v.dedup();
        v.join(",")
    }

    /// v6.5.0 (CEG §7.0.1) — split a stored `identity_type` column back
    /// into its set members. A plain single value (`"agent"`) parses to
    /// a one-element set; a comma-joined value
    /// (`"user,wise_authority"`) to its members. Whitespace-trimmed,
    /// empties dropped.
    pub fn parse_set(stored: &str) -> Vec<&str> {
        stored
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// v6.5.0 (CEG §7.0.1) — does the stored `identity_type` set
    /// contain `member`? True for both the single-value case
    /// (`stored == member`) and the comma-joined-set case.
    pub fn set_contains(stored: &str, member: &str) -> bool {
        parse_set(stored).contains(&member)
    }
}

/// v15.0.0 (CIRISPersist#422) — accord-CONFERRED tokens that may appear in the
/// V020 [`KeyRecord::roles`] `Vec<String>`. Most `roles` entries are plain
/// persist-API authorization scopes (`cirislens_pipeline_writer`, …) that any
/// writer may self-assert; these are the ones that are **not** self-assertable
/// — they may only ever be conferred by an accord co-scrub, exactly like the
/// `canonical` [`identity_type`] role.
pub mod roles {
    /// The **build-manifest / CI-pipeline trust-root** role
    /// (CIRISPersist#422, CIRISVerify#185 — the "same ceremony, different CEG
    /// object" milestone). A key carrying `infra:attest` is an accord-blessed
    /// build-signing pipeline: blessed by the SAME m-of-n accord co-scrub as a
    /// canonical server, but carrying `infra:attest` where a canonical server
    /// carries `identity_type = canonical`.
    ///
    /// **Accord-conferred, never self-claimed** — monotonic and gated at every
    /// `federation_keys` write chokepoint by
    /// [`super::super::admission::check_infra_attest_role_admission`] (mirrors
    /// the `canonical` gate): the role is admitted ONLY on an anchor-scrubbed
    /// record whose scrub set meets the accord family m-of-n. A self-signed or
    /// sub-quorum record asserting `infra:attest` is refused fail-closed
    /// ([`super::super::Error::InfraAttestRoleNotAccordConferred`]). Resolver:
    /// [`super::super::admission::is_infra_attest`].
    pub const INFRA_ATTEST: &str = "infra:attest";
}

/// v12.7.0 (CIRISPersist#365, CC 3.4.7.2 `consent-counter`) — the
/// **Counter-RII `consent_role`** vocabulary: the role tokens carried on
/// [`KeyRecord::consent_role`] that gate Counter-RII probe detection
/// (RATCHET `FSD/COUNTER_RII_DETECTION.md`; Lean `ConsentGate.lean`, 8
/// theorems verified). CC 3.4.7.2 ratified three primitive-level
/// semantics that shape this field + edge's `ProbePatternObserver` gate.
///
/// Persist's role is **STORE + EXPOSE + OQ-1 overwrite**: it carries the
/// role on the wire, resolves it ([`super::consent::consent_role_of`]),
/// and gives it flat overwrite-on-revoke mutation semantics
/// ([`super::FederationDirectory::set_consent_role`]). The **detection**
/// itself (the OQ-2 / OQ-3 *signal* decisions) is applied by the
/// consumer (edge / RATCHET) reading this field — persist does NOT house
/// a Counter-RII detector.
///
/// **The column already shipped** — V020 (v1.3.0, the CIRISAgent#760 §RC
/// "consent role lock") added `federation_keys.consent_role TEXT NOT NULL
/// DEFAULT 'unregistered'` with exactly this six-token vocabulary (PG
/// CHECK-enforced; SQLite by application contract — the Rust-level
/// admission in `put_public_key`/`set_consent_role` keeps the backends
/// symmetric). CC 3.4.7.2's "non-breaking against the shipped flat
/// substrate" language is literal: OQ-1's flat overwrite-on-revoke IS the
/// natural UPDATE semantics of that column. v12.7.0 puts the field **on
/// the wire** ([`KeyRecord`]`::consent_role`, `None` ⇔ the stored
/// `'unregistered'` default) and exposes the resolver + mutation surface.
pub mod consent_role {
    /// The stored default — no Counter-RII consent role assigned. This is
    /// the V020 column default; on the wire it is represented as
    /// `KeyRecord.consent_role = None` (interconverted at the storage
    /// boundary, see [`wire_from_stored`] / [`stored_from_wire`]). An
    /// `unregistered` key is subject to Counter-RII detection normally
    /// (the `ConsentGate.lean` base default).
    pub const UNREGISTERED: &str = "unregistered";
    /// Base consent role mirroring [`super::TrustType::Temporary`] — the
    /// CIRISAgent ConsentService taxonomy rung. Detection applies.
    pub const TEMPORARY: &str = "temporary";
    /// Base consent role mirroring [`super::TrustType::Partnered`]
    /// (bilateral approval). Detection applies.
    pub const PARTNERED: &str = "partnered";
    /// Base consent role mirroring [`super::TrustType::Anonymous`].
    /// Detection applies.
    pub const ANONYMOUS: &str = "anonymous";
    /// OQ-3 strict post-window role (`ConsentGate.lean` `AuthorizedReview`).
    /// An `authorized_review` key is **signal-eligible immediately** at
    /// `t > window_end` — no grace period. **Consumer-applied**: persist
    /// carries the role; the consumer enforces the strict window.
    pub const AUTHORIZED_REVIEW: &str = "authorized_review";
    /// OQ-2 blanket-suppression role (`ConsentGate.lean` `Peer`). A node
    /// holding `peer` **escapes Counter-RII detection at any `trust_mode`**
    /// — a sovereign peer may probe other peers without raising the
    /// (advisory-only) `ratchet:flag:counter_rii:*` signal (CC 3.1.6: the
    /// flag can NEVER be sole evidence for `slashing:*`; the WA quorum is
    /// the load-bearing adjudication gate). **Consumer-applied**: persist
    /// carries the role; edge's `ProbePatternObserver` reads it and
    /// suppresses.
    pub const PEER: &str = "peer";

    /// The six ratified tokens (identical to the V020 PG CHECK set), in
    /// the V020 declaration order. Any other token is rejected at
    /// admission on BOTH backends (Rust-level; the PG CHECK is defense in
    /// depth).
    pub const RECOGNIZED: [&str; 6] = [
        UNREGISTERED,
        TEMPORARY,
        PARTNERED,
        ANONYMOUS,
        AUTHORIZED_REVIEW,
        PEER,
    ];

    /// Is `role` one of the six ratified V020/CC 3.4.7.2 tokens?
    pub fn is_recognized(role: &str) -> bool {
        RECOGNIZED.contains(&role)
    }

    /// Storage → wire: the stored `'unregistered'` default (and empty
    /// string, defensively) map to wire `None`; any other token is
    /// carried verbatim.
    pub fn wire_from_stored(stored: &str) -> Option<&str> {
        if stored.is_empty() || stored == UNREGISTERED {
            None
        } else {
            Some(stored)
        }
    }

    /// Wire → storage: wire `None` maps to the stored `'unregistered'`
    /// default (the V020 column is NOT NULL).
    pub fn stored_from_wire(wire: Option<&str>) -> &str {
        match wire {
            Some(role) => role,
            None => UNREGISTERED,
        }
    }

    /// Admission gate for a wire-shape consent_role: `None` and the six
    /// recognized tokens pass; anything else is
    /// [`Error::InvalidArgument`](crate::federation::Error::InvalidArgument).
    /// Applied in `put_public_key` + `set_consent_role` on EVERY backend
    /// so PG (schema CHECK) and SQLite (no CHECK — SQLite's V020 ALTER
    /// could not add one) behave identically.
    pub fn check_admissible(wire: Option<&str>) -> Result<(), crate::federation::Error> {
        match wire {
            None => Ok(()),
            Some(role) if is_recognized(role) => Ok(()),
            Some(role) => Err(crate::federation::Error::InvalidArgument(format!(
                "consent_role '{role}' is not a recognized CC 3.4.7.2 token \
                 (expected one of: {})",
                RECOGNIZED.join(", ")
            ))),
        }
    }
}

/// Algorithm strings matching persist's `algorithm` column.
///
/// **v0.2.0+ federation_keys writes MUST use [`HYBRID`].** Schema
/// enforces this with `CHECK (algorithm = 'hybrid')`. Other values
/// remain in this module only as forward-compat placeholders for
/// hypothetical future migration paths (e.g., upgrading legacy
/// agent trace-signing keys at v0.4.0+ if the agent fleet remains
/// Ed25519-only at that time — but the federation directory itself
/// is hybrid all the way down).
pub mod algorithm {
    /// Hybrid Ed25519 + ML-DSA-65. **The only valid value for
    /// federation_keys writes from v0.2.0 onward.** Bound signature
    /// protocol per CIRISVerify `HybridSignature`:
    /// `classical_sig = Ed25519.sign(canonical)`,
    /// `pqc_sig = ML-DSA-65.sign(canonical || classical_sig)`.
    /// Verification requires both signatures.
    pub const HYBRID: &str = "hybrid";
}

/// Attestation type vocabulary — the **one workhorse + four
/// structural** primitives per FSD-002 §2.
///
/// **v2.4.0 clean-break replacement (CIRISPersist#102 Ask 2).** The
/// pre-v2.4.0 vocabulary (`vouches_for` / `witnesses` / `referred` /
/// `delegated_to`) was speculative and never reached a downstream
/// consumer — persist was the only writer and the wire shape was
/// unfinalized. The 2.4.0 cut replaces the constants in lockstep
/// with the FSD-002 unified-primitive model; no migration is needed
/// (the column is free-form TEXT) and no deprecation aliases are
/// kept (per `feedback_clean_break_renames.md` — alias scaffolding
/// is rejected; rename + remove ship in the same cut, flagged in
/// CHANGELOG).
///
/// **Why `recants` is distinct from `withdraws`** (per FSD-002 v1.2
/// PRIOR_ART_SCAN Bucket 1): no prior wire format (PGP / SPKI /
/// W3C VC) typed *epistemic-error-admission* as a wire primitive.
/// `withdraws` is "I no longer stand behind this attestation"
/// (good-faith retraction; no claim that it was false at issuance);
/// `recants` is "this attestation was false at issuance — I admit
/// epistemic error". Persist keeps them distinct on the wire even
/// when consumer UIs collapse them.
pub mod attestation_type {
    /// The unified workhorse primitive per FSD-002 §2.1. Every claim
    /// about an entity — positive / negative, identity / capability /
    /// behavior / state / commitment — is a `scores` attestation on
    /// a named `dimension` with `score ∈ [-1, +1]` + `confidence ∈
    /// [0, 1]` + optional evidence refs in the envelope.
    pub const SCORES: &str = "scores";
    /// Structural primitive: "A authorizes B to sign on A's behalf
    /// within scope S" (FSD-002 §2.2.1). Bounded scope; default
    /// transitive depth = 2.
    pub const DELEGATES_TO: &str = "delegates_to";
    /// Structural primitive: "this row replaces a prior attestation
    /// by the same attester" (FSD-002 §2.2.2). Consumers walking
    /// history apply latest-wins per (attesting_key_id, dimension,
    /// attested_key_id).
    pub const SUPERSEDES: &str = "supersedes";
    /// Structural primitive: "I retract my prior attestation"
    /// (FSD-002 §2.2.3). Does NOT claim the original was false at
    /// issuance — good-faith withdrawal.
    pub const WITHDRAWS: &str = "withdraws";
    /// Structural primitive: "my prior attestation was false at
    /// issuance" (FSD-002 §2.2.4). Admits epistemic error.
    /// Wire-distinct from [`WITHDRAWS`] even when consumer UIs
    /// collapse the two — see module-level note.
    pub const RECANTS: &str = "recants";

    /// v30.7.0 (CIRISPersist#625) — the five structural attestation types.
    ///
    /// CC 1.7's "1+4 lockdown": one workhorse primitive (`scores`) plus four
    /// structural composers. This list is closed by constitutional rule, not by
    /// convention, so an addition here is a governance change.
    pub const ALL: &[&str] = &[SCORES, DELEGATES_TO, SUPERSEDES, WITHDRAWS, RECANTS];
}

/// v12.6.0 (CIRISPersist#363 / CIRISConstitution#23, CC 1.13.3.3 / CC 3.2) — the
/// substrate-normative discriminator for the **node owner-binding**: the
/// `delegates_to(user → node)` edge that names a node's single responsible
/// steward and thereby *defines* the node's `self` cohort boundary.
///
/// An owner-binding is a [`attestation_type::DELEGATES_TO`] carrying
/// [`DIMENSION`] as its envelope `dimension` (and, on the producer side,
/// [`PURPOSE`] as `delegation_purpose`, with `infra:*`-only `scope`). This is
/// what separates the **ownership** relation — which is **single-valued** (a
/// node has at most one owner, [`super::super::admission::owner_of`]) — from
/// the general (multi-parent) `delegates_to` grammar (act-on-behalf, hierarchy
/// per CC 4.5.13). CIRISServer's `auth::ownership` builds these; the two
/// constants MUST stay byte-identical to server's `DIMENSION_OWNER_BINDING` /
/// `OWNER_BINDING_PURPOSE` (the wire is the contract).
pub mod owner_binding {
    /// The versioned owner-binding `dimension` — the substrate keys the
    /// single-owner admission gate + [`super::super::admission::owner_of`] on
    /// this exact string. Versioned (`:v1`) per the dimension gate.
    pub const DIMENSION: &str = "ownership:responsible_party:node:v1";
    /// The owner-binding `delegation_purpose` (producer-side marker; the
    /// substrate gate keys on [`DIMENSION`], this documents the pair).
    pub const PURPOSE: &str = "responsible_for";
    /// v13.2.1 (CIRISPersist#378) — the **CC 2.4.1.2 canonical** owner-binding
    /// marker carried as `registration/attestation_envelope.delegation_purpose`.
    /// The substrate recognizes an owner-binding by EITHER this
    /// `delegation_purpose` value OR the internal [`DIMENSION`] (the
    /// `steward_bind` path sets the dimension; a raw `emit_attestation_self`
    /// `delegates_to` — the only expressible owner-binding path per CC 2.4.1.2,
    /// and what CIRISConformance probes — carries only this). Keying on the
    /// dimension ALONE let the raw-emit path bypass the single-owner gate.
    pub const CC_DELEGATION_PURPOSE: &str = "owner_binding";
}

/// v8.9.0 (CIRISPersist#236, CC 4.4.3.4.3 / CC 1.13.5) — the reserved
/// **two-prefix delegation scope split** that makes "infrastructure
/// must not have agency" wire-checkable.
///
/// CC 4.4.3.4.3 pins two reserved scope prefixes on a `delegates_to`
/// envelope's `scope` field:
///
/// - [`INFRA_PREFIX`] (`infra:*`) — **server-class** authority, the only
///   class a pure `node`-role delegate ([`super::types::identity_type::NODE`])
///   may carry. Canonical infra scopes: [`INFRA_NETWORK_PRESENCE`],
///   [`INFRA_HOLD_COMMUNITY_MEMBERSHIP`], [`INFRA_HOLD_FAMILY_MEMBERSHIP`],
///   [`INFRA_SERVE`], [`INFRA_STORE`],
///   [`INFRA_TRANSPORT`], [`INFRA_ATTEST`].
/// - [`AGENCY_PREFIX`] (`agency:*`) — **brain-only** authority, FORBIDDEN
///   for a `node`-role delegate (CC 1.13.5). Canonical agency scopes:
///   [`AGENCY_ACT_ON_BEHALF`], [`AGENCY_MESSAGE_IO`], [`AGENCY_REASON`],
///   [`AGENCY_DECIDE`].
///
/// The pre-CC-4.4.3.4.3 **legacy unprefixed** agency profile (the
/// `self_at_login` vocabulary — `act_on_behalf` / `message_io` /
/// `reason` / `decide` / `sub_delegation`) is ALSO agency and MUST be
/// rejected on a node key; [`is_legacy_agency_scope`] recognizes it.
/// Note `network_presence` is NOT a legacy-agency kind — it maps to
/// [`INFRA_NETWORK_PRESENCE`] (presence is an infra duty, not agency).
///
/// The CC 1.13.5 verifier is [`super::admission::scopes_are_infra_only`];
/// the CC 4.4.3.4.3 admission gate is
/// [`super::admission::check_node_agency_admission`].
pub mod delegation_scope {
    /// CC 4.4.3.4.3 — the server-class scope prefix. A `node`-role
    /// delegate may carry ONLY scopes under this prefix.
    pub const INFRA_PREFIX: &str = "infra:";
    /// CC 4.4.3.4.3 / CC 1.13.5 — the brain-only scope prefix. FORBIDDEN
    /// for a `node`-role delegate.
    pub const AGENCY_PREFIX: &str = "agency:";

    /// v30.2.0 (CIRISPersist#607) — `infra:attest_assurance` — issue
    /// **assurance attestations about third parties**: the `age_assurance:` and
    /// `capacity_assurance:` rungs, and `transparency_log:cosigned:`.
    ///
    /// The scope a `witness` must hold from a trust root before those doors
    /// open. It is deliberately NOT `infra:attest` — that scope already
    /// governs the build-manifest plane (#422), and reusing it would let an
    /// attest-scoped key silently gain the power to declare a third party's age
    /// band. One name, two authorities is the fusion class this repo keeps
    /// closing.
    pub const INFRA_ATTEST_ASSURANCE: &str = "infra:attest_assurance";

    /// v30.3.0 (CIRISPersist#607) — `infra:record_hard_case` — record a
    /// `hard_case:*` observation **about another party**.
    ///
    /// `hard_case:` is where CIRISServer's graded admin ladder writes every
    /// tombstone: the artifact whose entire job is to carry the authorizing
    /// `delegates_to` id and a mandatory reason for an action taken about
    /// someone else. A row on that family is about another party by
    /// construction, which is exactly the retirement condition
    /// `substrate_persist`'s own mode note states — *"if a `system:*` row ever
    /// becomes an input to a decision ABOUT ANOTHER PARTY, this must move"*.
    ///
    /// NOT required for a self-attested `hard_case:` row — the retirement
    /// condition is scoped to rows that are an input to a decision about ANOTHER
    /// PARTY, and tightening past it would leave a node unable to enter its own
    /// incident on this plane.
    ///
    /// Persist's own `hard_case:*` telemetry does not come through this door at
    /// all: the at-rest cascade, the community-DEK recipient exclusions and the
    /// consent-SLA watcher all write through
    /// `FederationDirectory::record_hard_case` into `hard_case_events`. Persist
    /// emits no `hard_case:` attestation. The traffic this scope governs is a
    /// host's — CIRISServer's graded admin ladder.
    pub const INFRA_RECORD_HARD_CASE: &str = "infra:record_hard_case";

    /// v30.3.0 (CIRISPersist#611) — `infra:publish_rating` — vouch on the
    /// `content_rating:*` plane as a `trusted_publisher`.
    ///
    /// The odd one out among these scopes: it governs a **READ** door, not a
    /// write door. CC 3.3.12 leaves `content_rating:` open vocabulary — the
    /// `{scheme}` field explicitly admits `operator:{operator_id}` rubrics — so
    /// persist deliberately carries no emitter rule on the write side
    /// (CIRISPersist#571 removed the CEG-sourced one as stricter than the
    /// Constitution). The whole discrimination therefore lives in
    /// `FederationDirectory::lookup_trusted_publisher_chain`, which surfaces
    /// only rows attested by `trusted_publisher` keys, and that filter was a
    /// membership test on a registration row the key wrote itself.
    ///
    /// A fourth name rather than reuse of `infra:attest`, `infra:attest_assurance`
    /// or `infra:record_hard_case`, for the reason every one of them gives: one
    /// name carrying two authorities is the fusion class this repo keeps closing.
    /// A key blessed to publish content ratings has not thereby been blessed to
    /// declare a third party's age band.
    pub const INFRA_PUBLISH_RATING: &str = "infra:publish_rating";

    /// v30.2.0 (CIRISPersist#607) — `infra:detect` — emit on the adversarial
    /// detection plane (`detection:*`) about other parties.
    ///
    /// The scope a `lenscore_detector` must hold. Its
    /// `DelegatedFromTrustRoot` mode always named
    /// [`capability_roots_to_trusted_root`](crate::federation::trust_root::capability_roots_to_trusted_root)
    /// as the resolver; nothing ever called it, so the whole `detection:*`
    /// wildcard was a membership test on a self-asserted string.
    pub const INFRA_DETECT: &str = "infra:detect";

    /// `infra:network_presence` — be reachable / present on the network
    /// as the node (the infra realization of presence; cf. the legacy
    /// unprefixed `network_presence`).
    pub const INFRA_NETWORK_PRESENCE: &str = "infra:network_presence";
    /// `infra:hold_community_membership` — occupy a member seat on
    /// **community** rosters under the delegator's standing (RC3 crystal
    /// vocabulary, CIRISPersist#487; CIRISServer `TRUST_ROOT_CAPABILITY_GATE`
    /// / CC 4.4.3.4.3). `hold_` names the persistent STANDING — not the join
    /// ceremony, not grant/manage authority (steward/moderator are judgment
    /// roles bestowed on the MEMBER, never node-holdable per CC 1.13.5).
    /// Owner-granted (the node's standing), NEVER charter-granted — see the
    /// two-granter split in `TRUST_ROOT_CAPABILITY_GATE`. Replaced the vague
    /// `infra:join_communities` (hard cut, no alias — pre-fleet).
    pub const INFRA_HOLD_COMMUNITY_MEMBERSHIP: &str = "infra:hold_community_membership";
    /// `infra:hold_family_membership` — occupy a member seat on **family**
    /// rosters under the delegator's standing (RC3, #487). The community /
    /// family split exists because they are distinct CEG objects
    /// (`put_community` / `put_family`) in different sensitivity classes: an
    /// owner can give a node community standing while keeping it out of the
    /// family. See [`INFRA_HOLD_COMMUNITY_MEMBERSHIP`].
    pub const INFRA_HOLD_FAMILY_MEMBERSHIP: &str = "infra:hold_family_membership";
    /// `infra:serve` — serve content / requests as infrastructure.
    pub const INFRA_SERVE: &str = "infra:serve";
    /// `infra:store` — persist / store data as infrastructure.
    pub const INFRA_STORE: &str = "infra:store";
    /// `infra:transport` — relay / transport traffic as infrastructure.
    pub const INFRA_TRANSPORT: &str = "infra:transport";
    /// `infra:attest` — emit infrastructure self-attestations.
    pub const INFRA_ATTEST: &str = "infra:attest";

    /// `agency:act_on_behalf` — take action attributable to a principal.
    pub const AGENCY_ACT_ON_BEHALF: &str = "agency:act_on_behalf";
    /// `agency:message_io` — send/receive messages as a principal.
    pub const AGENCY_MESSAGE_IO: &str = "agency:message_io";
    /// `agency:reason` — reason / deliberate as a principal.
    pub const AGENCY_REASON: &str = "agency:reason";
    /// `agency:decide` — make decisions as a principal.
    pub const AGENCY_DECIDE: &str = "agency:decide";

    // ── #249 Cut C ── §11.10 delegated-duty scope tokens ──────────────
    //
    // v9.3.0 (CIRISPersist#249, CEG §11.10 / §3.2.3 rule-(3);
    // CIRISRegistry#90) — the three moderation **duty** scope tokens a
    // `delegates_to` chain bears to confer a §11.10 moderation duty. These
    // are unprefixed duty tokens (NOT `infra:*` / `agency:*` — a
    // moderation duty is orthogonal to the CC 4.4.3.4.3 server/brain
    // split), and they are the producer-side names for the duties the
    // admission duty-walk matches: each ALIASES the canonical
    // [`crate::federation::admission`] duty-scope constant BY VALUE, so an
    // edge stamped with one of these is exactly what
    // [`crate::federation::admission::is_named_moderator`] /
    // [`crate::federation::admission::check_moderation_admission`] admit
    // (the walk's [`delegation_scope_grants`] containment check compares
    // against these same tokens). Same wire-shape acceptance as the other
    // scopes (bare string OR array-set).
    //
    // [`delegation_scope_grants`]: crate::federation::admission

    /// `moderate` — the §11.10 moderation duty. Aliases
    /// [`crate::federation::admission::DELEGATION_SCOPE_MODERATE`] by value
    /// (the token the duty walk matches). A `delegates_to` bearing this
    /// authorizes the delegate to file a `moderation:*` report on the
    /// delegator's behalf.
    pub const SCOPE_MODERATE: &str = crate::federation::admission::DELEGATION_SCOPE_MODERATE;
    /// `takedown` — the §11.10 takedown duty. Aliases
    /// [`crate::federation::admission::DELEGATION_SCOPE_TAKEDOWN`] by value.
    pub const SCOPE_TAKEDOWN: &str = crate::federation::admission::DELEGATION_SCOPE_TAKEDOWN;
    /// `review` — the §11.10 reconsideration/review duty. Aliases
    /// [`crate::federation::admission::DELEGATION_SCOPE_REVIEW`] by value.
    pub const SCOPE_REVIEW: &str = crate::federation::admission::DELEGATION_SCOPE_REVIEW;
    /// v25.1.0 (CIRISPersist#570 ask 2) — `slash`, the tier-3/4 REMOVAL duty
    /// (CC 6.1.2). Aliases
    /// [`crate::federation::admission::DELEGATION_SCOPE_SLASH`] by value.
    ///
    /// The other three producer aliases confer an authority to EMIT; this one
    /// confers the authority to take away — quarantine
    /// ([`crate::federation::quarantine`]) and time-bounded de-admission.
    /// Stamp it on a `delegates_to` exactly as the other three are stamped;
    /// the duty walk matches it under the same policy.
    pub const SCOPE_SLASH: &str = crate::federation::admission::DELEGATION_SCOPE_SLASH;

    /// v30.7.0 (CIRISPersist#625) — **every value a `scope` entry may hold, and
    /// nothing else.** For operator pickers: no free-form entry, so the list a
    /// human chooses from must come from here.
    ///
    /// CURATED, not globbed, and this module is exactly why. It holds THREE
    /// vocabularies:
    ///
    ///  1. the capability scopes below (`infra:*` + `agency:*`),
    ///  2. the moderation scopes re-exported from `admission` (`SCOPE_*`),
    ///  3. **two PREFIX constants that are not values at all** — `INFRA_PREFIX`
    ///     (`"infra:"`) and `AGENCY_PREFIX` (`"agency:"`).
    ///
    /// A client enumerating this module mechanically would offer a human
    /// **"infra:"** as a selectable scope. `LEGACY_AGENCY_KINDS` is likewise a
    /// set, not a member. Only this repo knows which is which, which is the
    /// whole reason the set is curated here rather than derived downstream.
    ///
    /// Kept honest by [`tests::every_delegation_scope_const_is_classified`]: a
    /// newly minted scope that is not placed in this list — or explicitly named
    /// as a non-member — fails the build. Four scopes were minted in v30.2.0 –
    /// v30.4.0 alone, so "remember to update the list" is not a plan.
    pub const ALL: &[&str] = &[
        // infra:* — what a node may do as infrastructure.
        INFRA_SERVE,
        INFRA_STORE,
        INFRA_TRANSPORT,
        INFRA_ATTEST,
        INFRA_NETWORK_PRESENCE,
        INFRA_HOLD_COMMUNITY_MEMBERSHIP,
        INFRA_HOLD_FAMILY_MEMBERSHIP,
        INFRA_ATTEST_ASSURANCE,
        INFRA_DETECT,
        INFRA_RECORD_HARD_CASE,
        INFRA_PUBLISH_RATING,
        // agency:* — what an agent may do on someone's behalf.
        AGENCY_ACT_ON_BEHALF,
        AGENCY_MESSAGE_IO,
        AGENCY_REASON,
        AGENCY_DECIDE,
        // moderation / admin ladder, re-exported from `admission`.
        SCOPE_MODERATE,
        SCOPE_TAKEDOWN,
        SCOPE_REVIEW,
        SCOPE_SLASH,
    ];

    /// v30.7.0 (CIRISPersist#625) — the `infra:*` axis: what a key may do as
    /// INFRASTRUCTURE.
    ///
    /// This is a real axis, not a naming convention. **CC 4.4.3.4.3 —
    /// "infrastructure must not have agency"** — is cryptographically enforced
    /// at the write gate: a `node`-only key's `delegates_to` may carry these and
    /// never [`AGENCY`]. A picker that mixed them would offer an operator a
    /// delegation the substrate will refuse.
    pub const INFRA: &[&str] = &[
        INFRA_SERVE,
        INFRA_STORE,
        INFRA_TRANSPORT,
        INFRA_ATTEST,
        INFRA_NETWORK_PRESENCE,
        INFRA_HOLD_COMMUNITY_MEMBERSHIP,
        INFRA_HOLD_FAMILY_MEMBERSHIP,
        INFRA_ATTEST_ASSURANCE,
        INFRA_DETECT,
        INFRA_RECORD_HARD_CASE,
        INFRA_PUBLISH_RATING,
    ];

    /// v30.7.0 (CIRISPersist#625) — the `agency:*` axis: what a key may do ON
    /// SOMEONE'S BEHALF. The other side of CC 4.4.3.4.3; see [`INFRA`].
    pub const AGENCY: &[&str] = &[
        AGENCY_ACT_ON_BEHALF,
        AGENCY_MESSAGE_IO,
        AGENCY_REASON,
        AGENCY_DECIDE,
    ];

    /// v30.7.0 (CIRISPersist#625) — the moderation / admin-ladder axis,
    /// re-exported from [`crate::federation::admission`]. Distinct from [`INFRA`]
    /// and [`AGENCY`]: these authorise action ABOUT ANOTHER PARTY rather than
    /// capability of the holder.
    pub const MODERATION: &[&str] = &[SCOPE_MODERATE, SCOPE_TAKEDOWN, SCOPE_REVIEW, SCOPE_SLASH];

    /// The constants in this module that are deliberately **NOT** members of
    /// [`ALL`], with the reason. Read by
    /// [`tests::every_delegation_scope_const_is_classified`] so that "not a
    /// member" is a recorded decision rather than an omission.
    pub const NON_MEMBERS: &[(&str, &str)] = &[
        ("INFRA_PREFIX", "a prefix (\"infra:\"), not a scope value"),
        ("AGENCY_PREFIX", "a prefix (\"agency:\"), not a scope value"),
        (
            "LEGACY_AGENCY_KINDS",
            "a set of legacy kinds, not a single value",
        ),
        ("ALL", "this list itself"),
        ("NON_MEMBERS", "this exclusion list itself"),
        ("INFRA", "an axis subset of ALL, not a single value"),
        ("AGENCY", "an axis subset of ALL, not a single value"),
        ("MODERATION", "an axis subset of ALL, not a single value"),
    ];

    /// CC 1.13.5 — the legacy **unprefixed** agency kinds (the pre-split
    /// `self_at_login` agency profile + `reason`/`decide`) that MUST also
    /// be rejected on a node key. `network_presence` is deliberately
    /// EXCLUDED (it is the infra presence duty, not agency). The
    /// `act_on_behalf` / `message_io` / `sub_delegation` entries alias the
    /// canonical [`crate::federation::self_at_login`] constants by value.
    pub const LEGACY_AGENCY_KINDS: [&str; 5] = [
        crate::federation::self_at_login::SCOPE_ACT_ON_BEHALF,
        crate::federation::self_at_login::SCOPE_MESSAGE_IO,
        "reason",
        "decide",
        crate::federation::self_at_login::SCOPE_SUB_DELEGATION,
    ];

    /// CC 1.13.5 — is `scope` one of the legacy unprefixed agency kinds
    /// ([`LEGACY_AGENCY_KINDS`])? Used by the node-agency gate so a
    /// pre-split delegation cannot smuggle agency onto a node key by
    /// dropping the `agency:` prefix.
    pub fn is_legacy_agency_scope(scope: &str) -> bool {
        LEGACY_AGENCY_KINDS.contains(&scope)
    }
}

/// v6.7.0 (CIRISPersist#146 Ask 5, CEG 1.0-RC5 §5.6.8.7) — the
/// `consent_record` ceremony shape over the consent primitive. A
/// `consent_record` rides the existing [`attestation_type::SCORES`]
/// primitive with a `subject_kind = "consent_record"` discriminator in
/// the envelope (NO new attestation_type — the 1+4 lockdown is
/// preserved); it simply carries a locked payload schema (`stance`,
/// `asserted_at`, …) instead of a free `dimension`. See
/// [`crate::federation::admission::check_consent_record_admission`].
pub mod consent_record {
    /// The envelope `subject_kind` discriminator that marks a `scores`
    /// row as a `consent_record` ceremony Contribution (§5.6.8.7).
    pub const SUBJECT_KIND: &str = "consent_record";

    /// The closed-set `stance` values (§5.6.8.7).
    pub mod stance {
        /// Subject affirms; processing may proceed within scope +
        /// valid_until. A `granted` *self*-consent (sole authority) MAY
        /// be local-tier (§10.1.5.2).
        pub const GRANTED: &str = "granted";
        /// Subject withdraws; producer must delete within the SLA
        /// window. Carries subject revocation authority → **NOT
        /// local-tier-eligible** (§10.1.3).
        pub const REVOKED: &str = "revoked";
        /// Substrate emission when `valid_until` passes without renewal.
        /// **Substrate-emitted only** — a producer/subject MUST NOT
        /// assert it (§5.6.8.7 rule 2).
        pub const EXPIRED: &str = "expired";

        /// True iff `s` is one of the three closed-set stance values.
        #[must_use]
        pub fn is_valid(s: &str) -> bool {
            matches!(s, GRANTED | REVOKED | EXPIRED)
        }
    }
}

/// `federation_keys` row.
///
/// Field order matters for serde default JSON serialization (field
/// declaration order is the JSON key order). CIRISRegistry's vendored
/// shape mirrors this declaration order; changes here require a
/// matching change there to preserve `persist_row_hash` parity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyRecord {
    /// Canonical key identifier (matches `signature_key_id` on the
    /// trace-verification wire).
    pub key_id: String,
    /// Ed25519 32-byte raw public key, base64 standard. 44 chars.
    /// Always required.
    pub pubkey_ed25519_base64: String,
    /// ML-DSA-65 1952-byte raw public key, base64 standard.
    /// ~2604 chars. `None` until the cold-path PQC sign completes
    /// via `attach_pqc_signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey_ml_dsa_65_base64: Option<String>,
    /// Algorithm string. **v0.2.0+ writes MUST be [`algorithm::HYBRID`].**
    pub algorithm: String,
    /// Identity classification ([`identity_type::AGENT`], etc.).
    pub identity_type: String,
    /// Logical identity reference (shape varies by `identity_type`).
    pub identity_ref: String,
    /// When the key became valid.
    pub valid_from: DateTime<Utc>,
    /// When the key expires (`None` = no expiry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    /// Canonical bytes of the registration envelope (verbatim).
    pub registration_envelope: serde_json::Value,
    /// SHA-256 of canonical(registration_envelope). Hex-encoded.
    pub original_content_hash: String,
    /// Classical Ed25519 signature: `Ed25519.sign(canonical_bytes)`.
    /// Base64-encoded (88 chars for 64-byte sig). Always required.
    pub scrub_signature_classical: String,
    /// PQC ML-DSA-65 signature: `ML-DSA-65.sign(canonical || classical_sig)`.
    /// Bound to the classical signature to prevent stripping attacks.
    /// Base64-encoded (~4412 chars for 3309-byte sig — FIPS 204 final,
    /// `c_tilde_bytes=48`; closes CIRISPersist#8). The pre-FIPS-204-final
    /// figure of 3293 bytes was the round-3 era size; live `ml-dsa = 0.1.0-rc.3`
    /// and CIRISVerify v1.8.5 both emit 3309. Empirically confirmed by
    /// CIRISBridge's lens-steward bootstrap producing 4412-char base64
    /// signatures via `dilithium-py.ML_DSA_65.sign`.
    /// `None` until the cold-path PQC sign completes via
    /// `attach_pqc_signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
    /// `key_id` of the row that signed THIS row. Bootstrap rows have
    /// `scrub_key_id == key_id` (self-signed); all others reference
    /// an existing `federation_keys` row.
    pub scrub_key_id: String,
    /// When the scrub-signature was issued.
    pub scrub_timestamp: DateTime<Utc>,
    /// When the cold-path PQC components were attached. `None` while
    /// the row is hybrid-pending (Ed25519-only); populated by
    /// `attach_pqc_signature` once ML-DSA-65 fills in. Telemetry +
    /// observability signal — auditable answer to "when did this row
    /// become hybrid-secure?"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_completed_at: Option<DateTime<Utc>>,
    /// **Server-computed.** Hex-encoded SHA-256 over the canonical
    /// bytes of this row (via persist's
    /// `PythonJsonDumpsCanonicalizer`). Consumers store + string-
    /// compare; they don't reproduce the canonicalizer. Closes the
    /// shortest-round-trip drift class of cache-divergence bugs.
    pub persist_row_hash: String,
    /// v1.3.0 (CIRISPersist#46) — Per-row **capability** role tags.
    /// Determines what the key is authorized to DO at the persist API
    /// boundary: `cirislens_pipeline_writer` gates
    /// `POST /api/v1/pipeline/ingest`; `cirislens_secrets_reader` /
    /// `_writer` / `_admin` gate the secrets routes. Empty default —
    /// pre-V020 rows + new rows that didn't declare roles deserialize to
    /// `vec![]`. The `#[serde(default)]` keeps the wire shape
    /// backward-compatible with v1.2.x writers that don't know the field.
    ///
    /// v23.0.0 (CIRISPersist#551 item 6) — renamed from `roles` because
    /// prose kept reading it as the thing reserved-prefix admission gates
    /// on. It is NOT: reserved dimension prefixes (`age_assurance:`,
    /// `system:`, `detection:`, …) gate on [`KeyRecord::identity_type`] via
    /// `required_identity_types`, and never on this field. #551 records the
    /// cost of that confusion — persist asserted in #543 that a Sybil could
    /// not mint reserved-prefix rows "without roles", which is false, and
    /// false in the direction that matters: `identity_type` is
    /// self-assertable, which is hole 3 of that very issue. Two names that
    /// read as synonyms for two different gates is how a correct
    /// implementation gets described wrongly by the people maintaining it.
    ///
    /// **The wire name is FROZEN at `roles`.** Every stored row and every
    /// signed `registration_envelope` carries `roles`; renaming the serde
    /// name would desync stored rows from the signatures over them — the
    /// #541 preserve-set≢verified-set class — silently invalidating every
    /// record in every deployment. The Rust name is free to be accurate;
    /// the wire name is load-bearing and stays.
    #[serde(default, rename = "roles")]
    pub capability_roles: Vec<String>,
    /// v2.5.0 (CIRISPersist#102 Ask 8) — Hardware-attestation evidence
    /// captured at key-binding time. REQUIRED for `identity_type =
    /// 'accord_holder'` rows (FSD-002 §7.3 + FEDERATION_ANNOUNCEMENT
    /// §4.5.2); the V048 schema CHECK + the
    /// [`HardwareAttestationPolicy`](super::HardwareAttestationPolicy)
    /// admission hook both enforce this.
    ///
    /// Shape is `{platform_attestation: <PlatformAttestation JSON>,
    /// nonce_captured_at: "<RFC3339>"}` — see
    /// [`super::hardware_attestation::AttestationEvidence`].
    ///
    /// `None` for non-accord-holder rows. Backward-compatible default
    /// — pre-V048 reads return `None` and the field is
    /// `skip_serializing_if = "Option::is_none"` so old `persist_row_hash`
    /// computations stay stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_evidence: Option<serde_json::Value>,
    /// v12.7.0 (CIRISPersist#365, CC 3.4.7.2 `consent-counter`) — the
    /// **Counter-RII `consent_role`**. A single role token (see the
    /// [`consent_role`] vocabulary module — `temporary` / `partnered` /
    /// `anonymous` / `authorized_review` / `peer`) that gates the
    /// Counter-RII probe detection a consumer (edge's
    /// `ProbePatternObserver`, RATCHET `FSD/COUNTER_RII_DETECTION.md`)
    /// applies. Per CC 3.4.7.2 this is a `federation_keys` **identity
    /// field** — a sibling to [`identity_type`] — **not** an envelope
    /// primitive. Backed by the V020 column (`TEXT NOT NULL DEFAULT
    /// 'unregistered'`, the CIRISAgent#760 §RC lock CC 3.4.7.2 ratifies);
    /// `None` here ⇔ the stored `'unregistered'` default (no assigned
    /// role — detection applies normally).
    ///
    /// **Mutable + overwrite-on-revoke (OQ-1).** Unlike the signed
    /// registration fields above, `consent_role` is an operational role
    /// marker that a governance/consent surface assigns and later
    /// overwrites (a subsequent revocation OVERWRITES the prior value —
    /// flat, bounded, non-recursive; NO chain embedded in the field).
    /// It is therefore **excluded from [`compute_persist_row_hash`]** (the
    /// signed-registration content hash) so a later
    /// [`FederationDirectory::set_consent_role`](super::FederationDirectory::set_consent_role)
    /// overwrite does NOT disturb the registration hash / CIRISRegistry
    /// vendored-shape parity, and `adopt_scrub_upgrade` deliberately does
    /// NOT touch it (an anchor-scrub upgrade must not clobber an assigned
    /// role). Backward-compatible default: pre-v12.7.0 rows + rows with no
    /// assigned role serialize without the field
    /// (`skip_serializing_if = "Option::is_none"`), so `persist_row_hash`
    /// stays byte-stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_role: Option<String>,
    /// v13.2.0 (CIRISPersist#383 / CIRISVerify#174) — the **2nd..Nth anchor
    /// scrub signatures** over the SAME canonical `registration_envelope`
    /// (scrub #1 is the base `scrub_key_id`/`scrub_signature_*` fields above).
    /// Empty for an ordinary / single-scrub record → serializes away entirely
    /// (`skip_serializing_if`), so the record stays **byte-identical** to the
    /// pre-#383 shape and cannot perturb `compute_persist_row_hash` (which
    /// excludes it — see there). The `canonical` role is conferred only on a
    /// record whose scrub set has **≥2 distinct anchor holders with valid
    /// signatures** (`check_canonical_role_admission`), the 2-of-3 add gate.
    /// `root_binding` still roots via **any one** scrub. Wire-identical to
    /// `ciris_verify_core::federation_self_record::KeyRecord::additional_scrubs`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_scrubs: Vec<ScrubSig>,
}

/// v13.2.0 (CIRISPersist#383 / CIRISVerify#174) — a single anchor-holder
/// scrub signature over a canonical `registration_envelope`, the shape of an
/// entry in [`KeyRecord::additional_scrubs`]. Every scrub on a record is over
/// the **same** canonical bytes; the scrub *set* lives OUTSIDE the signed
/// envelope, so a 1-scrub and a 2-scrub record of the same target canonicalize
/// identically. Wire-identical to `ciris_verify_core`'s `ScrubSig`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubSig {
    /// The anchor holder (A1/B1/C1) whose key produced this scrub. Must resolve
    /// to a registered `federation_keys` row; the scrub verifies against its
    /// pinned pubkeys over `JCS(registration_envelope)`.
    pub scrub_key_id: String,
    /// Base64 `Ed25519.sign(JCS(registration_envelope))`.
    pub scrub_signature_classical: String,
    /// Base64 `ML-DSA-65.sign(JCS(registration_envelope) ‖ ed25519_sig)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
}

/// A single **transport reachability hint** carried INSIDE a
/// [`KeyRecord`]'s signed `registration_envelope` (CIRISPersist#381).
///
/// Because the hint lives inside the envelope the accord holder scrubs, it
/// is **accord-attested by construction** — it is covered by the same
/// `original_content_hash` + scrub signature as the key, and cannot be
/// spoofed post-hoc. This is the *genesis / default* address; runtime
/// address churn is still handled by the mutable `TransportDestination`
/// overlay + the 1-of-N update-address op, which wins when present.
///
/// `kind` is an open vocabulary (`ip` | `reticulum` | `https` | …); the
/// `ip` hint is the internet-dialable TCP entry a cold node bootstraps
/// against, whereas a `reticulum` destination is a pubkey-derivable overlay
/// address (not itself a bootstrap target).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportHint {
    /// Open-vocabulary transport kind (`ip` | `reticulum` | `https` | …).
    pub kind: String,
    /// The address for that kind (e.g. `108.61.242.236:4242`).
    pub destination: String,
}

impl KeyRecord {
    /// The **transport reachability hints** embedded in this record's signed
    /// `registration_envelope` (CIRISPersist#381) — the accord-attested
    /// genesis/default dial addresses. Returns `[]` when the envelope carries
    /// no `transport_hints` (the field is OPTIONAL: ordinary node records and
    /// pre-#381 baked records simply omit it). A malformed `transport_hints`
    /// value is treated as absent (`[]`) rather than an error — this is a
    /// read-side convenience over opaque signed JSON, not an admission gate.
    ///
    /// This is a pure READ over the already-signed envelope; it does not
    /// mutate anything and cannot change the record's hash or signature.
    pub fn transport_hints(&self) -> Vec<TransportHint> {
        self.registration_envelope
            .get("transport_hints")
            .and_then(|v| serde_json::from_value::<Vec<TransportHint>>(v.clone()).ok())
            .unwrap_or_default()
    }

    /// v13.2.0 (CIRISPersist#383) — the **full ordered scrub set**: scrub #1
    /// reconstructed from the base `scrub_key_id`/`scrub_signature_*` fields,
    /// followed by every [`Self::additional_scrubs`] entry. Each is a signature
    /// over the SAME canonical `registration_envelope` bytes. This is the set
    /// `root_binding` roots (via any one) / `check_canonical_role_admission`
    /// confers `canonical` on (≥2 distinct anchor holders, sigs verified).
    /// Wire-identical to `ciris_verify_core`'s `KeyRecord::scrubs`.
    pub fn scrubs(&self) -> Vec<ScrubSig> {
        let mut out = Vec::with_capacity(1 + self.additional_scrubs.len());
        out.push(ScrubSig {
            scrub_key_id: self.scrub_key_id.clone(),
            scrub_signature_classical: self.scrub_signature_classical.clone(),
            scrub_signature_pqc: self.scrub_signature_pqc.clone(),
        });
        out.extend(self.additional_scrubs.iter().cloned());
        out
    }

    /// v13.2.0 (CIRISPersist#383) — count of **distinct** `scrub_key_id`s across
    /// the whole scrub set (a coarse pre-check; the admission gate additionally
    /// requires each counted scrub to be a pinned anchor holder with a VALID
    /// signature). Excludes nothing — a self-scrub (`scrub_key_id == key_id`)
    /// counts here but is rejected by the gate (self cannot confer `canonical`).
    pub fn distinct_scrub_count(&self) -> usize {
        let mut ids = std::collections::BTreeSet::new();
        ids.insert(self.scrub_key_id.as_str());
        for s in &self.additional_scrubs {
            ids.insert(s.scrub_key_id.as_str());
        }
        ids.len()
    }

    /// v17.0.0 (CIRISPersist#441, CC 3.4.7.1 / CC 4.5.8.1) — does this record
    /// claim `role` on EITHER role surface: the `identity_type` **set**
    /// ([`identity_type::set_contains`]) OR the V020 `roles` vector? This is
    /// the predicate every role admission gate evaluates, so the two surfaces
    /// can never disagree on which roles a key may self-assert: before #441
    /// the gates each read one surface, and `roles=["canonical"]` slipped the
    /// conferral gate the scalar path enforced (the CC 4.5.8.1 self-claim
    /// backdoor — held only by the accident that `roles` was decorative).
    pub fn claims_role(&self, role: &str) -> bool {
        identity_type::set_contains(&self.identity_type, role)
            || self.capability_roles.iter().any(|r| r == role)
    }

    /// True iff both PQC components have been attached. Consumers
    /// composing strict-hybrid trust policy refuse rows where this
    /// returns false.
    pub fn is_pqc_complete(&self) -> bool {
        self.pubkey_ml_dsa_65_base64.is_some()
            && self.scrub_signature_pqc.is_some()
            && self.pqc_completed_at.is_some()
    }

    /// True iff the row is in the cold-path PQC-signing window
    /// (Ed25519-only, ML-DSA-65 in flight). Consumers composing
    /// soft-hybrid + freshness policies use this with their own age
    /// threshold to decide whether the row is acceptably-pending vs
    /// concerning-stale.
    pub fn is_pqc_pending(&self) -> bool {
        !self.is_pqc_complete()
    }
}

/// `federation_attestations` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    /// UUID identifier for this attestation row.
    pub attestation_id: String,
    /// Key making the attestation (must exist in `federation_keys`).
    pub attesting_key_id: String,
    /// Key being attested (must exist in `federation_keys`).
    pub attested_key_id: String,
    /// Attestation type ([`attestation_type::SCORES`] /
    /// [`attestation_type::DELEGATES_TO`] / [`attestation_type::SUPERSEDES`]
    /// / [`attestation_type::WITHDRAWS`] / [`attestation_type::RECANTS`]).
    pub attestation_type: String,
    /// Optional weight signal carried by the attester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<f64>,
    /// When the attestation was made.
    pub asserted_at: DateTime<Utc>,
    /// When the attestation expires (`None` = no expiry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Canonical bytes of the attestation envelope.
    pub attestation_envelope: serde_json::Value,
    /// SHA-256 of canonical(attestation_envelope). Hex-encoded.
    pub original_content_hash: String,
    /// Classical Ed25519 sig over canonical bytes. Base64. Required.
    pub scrub_signature_classical: String,
    /// PQC ML-DSA-65 sig over (canonical || classical_sig). Base64.
    /// `None` while the row is hybrid-pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
    /// `key_id` that signed this row.
    pub scrub_key_id: String,
    /// When the scrub-signature was issued.
    pub scrub_timestamp: DateTime<Utc>,
    /// When the PQC components were attached. `None` while pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_completed_at: Option<DateTime<Utc>>,
    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
    /// v3.7.0 (CIRISPersist#146, CEG 0.6 §4.2). Optional list of
    /// consent-holder key_ids for this attestation. Each entry MAY be
    /// a `federation_keys.key_id` OR a canonical-hash identifier
    /// (CEG 0.6 §4.2.2). Default `[]` = status quo (producer-only
    /// authority). The substrate does NOT FK-enforce that entries
    /// resolve to `federation_keys` rows — canonical-hash subjects
    /// (Discord user-ids, external party identifiers) are valid
    /// entries per the CEG 0.6 design.
    ///
    /// The 4-rule broadened `withdraws` admission gate (CEG §3.2.3)
    /// reads this field at admission time; see
    /// [`Self::withdraws_admission_rule`] for the per-rule audit
    /// metadata recorded post-admission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_key_ids: Vec<String>,
    /// v3.7.0 (CIRISPersist#146, CEG 0.6 §3.2.3). Per-rule audit
    /// metadata: which admission rule admitted this withdraws.
    ///
    /// `Some(1)` — producer self-revocation (`issuer.key_id == T.attesting_key_id`).
    /// `Some(2)` — subject self-revocation (`issuer.key_id ∈ T.subject_key_ids`, CEG 0.6 NEW).
    /// `Some(3)` — `delegates_to` proxy chain with `consent_revocation` scope (CEG 0.6 NEW).
    /// `Some(4)` — `delegates_to` chain via any of 1-3.
    /// `Some(5)` — v21.8.0 (CIRISPersist#519, CC 3.2) — the **ownerless-lock
    ///             reclaim** exception: a third-party `withdraws` against a
    ///             LIVE owner-binding, admitted ONLY when the incumbent is
    ///             provably-abandoned (`fresh_as_of` floor stale) AND an m-of-n
    ///             reclaim quorum verifies. Ships INERT (refused until a
    ///             CIRISConstitution#43 policy is injected). See
    ///             [`crate::federation::ownership_reclaim`].
    /// `None`    — non-withdraws row, or pre-v3.8.0 withdraws written
    ///             before the admission gate landed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdraws_admission_rule: Option<u8>,
    /// v3.9.0 (CIRISPersist#150, CEG 0.4 §4.2.4). Producer-side
    /// visibility scope. Closed-set values: `self | family | community
    /// | affiliations | species | biosphere | federation`. Default
    /// `"federation"` (preserves pre-v3.9.0 semantic; producers
    /// writing new content explicitly tag self/family/etc.). Orthogonal
    /// to `subject_key_ids` (revocability authority) — see CEG §4.2.4.
    ///
    /// **v3.9.0 ships the schema + round-trip only.** Admission-gate
    /// enforcement, the §8.1.8.1 promotion ceremony, and read-time
    /// viewer-vs-scope filtering land in v3.10.0.
    #[serde(
        default = "default_cohort_scope",
        skip_serializing_if = "is_default_cohort_scope"
    )]
    pub cohort_scope: String,
    /// v4.4.0 (CIRISPersist#171, CEG §10.1.3/§10.1.5). Row tier:
    /// `"local"` (producer-only authority, signature deferred, visible
    /// ONLY to the producing occurrence) | `"federation"` (hybrid-signed,
    /// federation-visible). Default `"federation"` (preserves pre-v4.4.0
    /// rows). **Persist-internal row metadata — NOT part of the
    /// `attestation_envelope` JCS canonical signing bytes** (CEG
    /// §10.1.5.3 must #2): the signature covers `attestation_envelope`,
    /// not this struct, so a promoted row is byte-identical on the wire
    /// to a natively-federation one. `skip_serializing_if` default keeps
    /// federation-row JSON output stable across the v4.4 schema bump.
    #[serde(default = "default_tier", skip_serializing_if = "is_default_tier")]
    pub tier: String,
    /// v4.4.0 — wall-clock of the local→federation `attestation_promote`
    /// transition (the federation-emit moment). `None` for natively-
    /// federation rows and un-promoted local rows. Persist-internal; not
    /// in the canonical bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promoted_at: Option<DateTime<Utc>>,
    /// v24.0.0 (CIRISPersist#556) — the **2nd..Nth scrub signatures** over the
    /// SAME canonical `attestation_envelope` (scrub #1 is the base
    /// `scrub_key_id` / `scrub_signature_*` fields above). The attestation-plane
    /// twin of [`KeyRecord::additional_scrubs`]: same type, same "every scrub is
    /// over the same preimage" rule, same wire encoding.
    ///
    /// # What it makes provable
    ///
    /// One genesis ceremony used to produce two planes with two different
    /// outcomes: the serve-node KEY RECORD carried `scrub A1 +
    /// additional_scrubs [B1]` and proved 2-of-n, while the `genesis-charter`
    /// ATTESTATION that makes A1 a trust root carried one `scrub_key_id` and
    /// proved 1-of-n. The 2-of-3 that authorized it was real, checked at
    /// `verify_bundle`, and then unrecoverable — a peer receiving the charter by
    /// replication could only ever answer *"A1 asserted it"*. With this field a
    /// replicated row proves its own m-of-n, which is what the family trust root
    /// ([`trust_root_valid`](crate::federation::trust_root::trust_root_valid))
    /// re-derives at read time.
    ///
    /// # Byte-stability, and why the preserve set must equal the verified set
    ///
    /// Empty ⇒ wire-absent (`skip_serializing_if`), so an ordinary single-scrub
    /// row is byte-identical to its pre-v24 shape and its `persist_row_hash` and
    /// signature are untouched. A NON-empty set is covered by
    /// [`compute_persist_row_hash`] **and** re-verified at federation-tier
    /// ingest by
    /// [`verify_row_hybrid_signature`](crate::federation::verify_row_hybrid_signature)
    /// — deliberately, because a field that a writer may drop while the verifier
    /// never looks at it is exactly the #541 preserve-set≢verified-set class,
    /// and here dropping it would silently downgrade a quorum-chartered root to
    /// a single seat.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_scrubs: Vec<ScrubSig>,
}

impl Attestation {
    /// v24.0.0 (CIRISPersist#556) — the **full ordered scrub set**: scrub #1
    /// reconstructed from the base `scrub_key_id` / `scrub_signature_*` fields,
    /// followed by every [`Self::additional_scrubs`] entry. Each is a signature
    /// over the SAME canonical `attestation_envelope` bytes.
    ///
    /// The attestation-plane twin of [`KeyRecord::scrubs`] — one shape, so the
    /// quorum core that counts distinct valid holders never has to know which
    /// kind of row it was handed.
    #[must_use]
    pub fn scrubs(&self) -> Vec<ScrubSig> {
        let mut out = Vec::with_capacity(1 + self.additional_scrubs.len());
        out.push(ScrubSig {
            scrub_key_id: self.scrub_key_id.clone(),
            scrub_signature_classical: self.scrub_signature_classical.clone(),
            scrub_signature_pqc: self.scrub_signature_pqc.clone(),
        });
        out.extend(self.additional_scrubs.iter().cloned());
        out
    }

    /// v24.0.0 (CIRISPersist#556) — count of **distinct** `scrub_key_id`s
    /// across the whole scrub set. A coarse pre-check only: the family-charter
    /// quorum leg additionally requires each counted scrub to be a seated roster
    /// holder with a VALID hybrid signature. Twin of
    /// [`KeyRecord::distinct_scrub_count`].
    #[must_use]
    pub fn distinct_scrub_count(&self) -> usize {
        let mut ids = std::collections::BTreeSet::new();
        ids.insert(self.scrub_key_id.as_str());
        for s in &self.additional_scrubs {
            ids.insert(s.scrub_key_id.as_str());
        }
        ids.len()
    }
}

/// v4.4.0 (CIRISPersist#171) — attestation tier wire constants.
pub mod attestation_tier {
    /// Producer-only-authority, signature-deferred, self-visible-only.
    pub const LOCAL: &str = "local";
    /// Hybrid-signed, federation-visible (status quo + promotion target).
    pub const FEDERATION: &str = "federation";
}

/// Default tier for backward compat: pre-v4.4.0 rows are all federation.
fn default_tier() -> String {
    attestation_tier::FEDERATION.to_string()
}

/// True iff the tier equals the default (`federation`) — federation rows
/// omit the field from JSON so legacy canonical/round-trip output stays
/// stable across the v4.4 schema bump.
fn is_default_tier(tier: &str) -> bool {
    tier == attestation_tier::FEDERATION
}

/// v4.4.0 (CIRISPersist#171, CEG §10.1.3) — caller input for a local-tier
/// attestation write (`attestation_upsert_local` / `_insert_local`). The
/// producer-only-authority self-attestation envelope: the caller supplies
/// the semantic fields; persist fills the tier (`local`), the deferred
/// empty-sentinel scrub envelope, `asserted_at`, and the row id. The
/// signature is deferred to `attestation_promote` (no hybrid sig here).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAttestationInput {
    /// v18.0.0 (CIRISPersist#473) — OPTIONAL caller-supplied
    /// `attestation_id`. `None` (the default; pre-18.0 wire shape) mints a
    /// fresh UUIDv4 exactly as before. `Some` lets an idempotent producer —
    /// the envelope-native trace ingest — derive a DETERMINISTIC id (e.g.
    /// from `trace_id`) so a replayed batch re-mints the SAME id and the
    /// insert path's conflict-ignore makes the mint replay-safe instead of
    /// duplicating. Additive + serde-default: every existing caller/wire
    /// shape is untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_id: Option<String>,
    /// The producing occurrence's `federation_keys.key_id` (the
    /// `witness_relation: self` producer). Must exist in federation_keys.
    pub attesting_key_id: String,
    /// Primary attested key. Defaults to `attesting_key_id` (a
    /// self-attestation) when omitted. Must exist in federation_keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested_key_id: Option<String>,
    /// The §3 structural primitive (`scores` / `supersedes` / …).
    pub attestation_type: String,
    /// Optional weight signal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<f64>,
    /// Optional expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// The CEG attestation envelope. MUST carry a `"dimension"` string
    /// (the `(occurrence, dimension)` upsert key + the §7.5/§10.1.3
    /// local-tier gates read it).
    pub attestation_envelope: crate::federation::envelope::EnvelopeCore,
    /// §4.2.6 subjects this attestation names (producer-authority rows
    /// MAY name subjects; the local-tier gate refuses only a subject-side
    /// revocation, not subject-naming).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_key_ids: Vec<String>,
    /// Producer-side visibility scope. **Local-tier rows MUST be
    /// `self`** (private to the producing occurrence until promotion;
    /// the FSD §3 / CEG §10.1.5 tier read-gate is exactly the v4.0
    /// `self`-cohort gate). Defaults `self`; the write path rejects any
    /// other value at local tier. Promotion (v4.5) widens the scope.
    #[serde(default = "default_self_cohort_scope")]
    pub cohort_scope: String,
    /// v12.6.0 (CIRISPersist#171, §10.1.3 transit-not-rest) — the classical
    /// Ed25519 signature over `JCS(attestation_envelope)`. Populated ONLY
    /// for a **subject-side revocation transiting the local tier**: an
    /// ordinary producer-authority local row defers its signature (this
    /// stays `None` and the row is written with the empty-sentinel scrub
    /// envelope). When the write-path gate classifies the row as a
    /// [`crate::federation::admission::LocalTierDisposition::TransitRevocation`],
    /// this (and [`Self::scrub_signature_pqc`]) MUST be present and verify
    /// against the attester's registered pubkeys, or the write is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_classical: Option<String>,
    /// v12.6.0 — the ML-DSA-65 signature over the bound payload
    /// `JCS(attestation_envelope) ‖ ed25519_sig` (PQC-mandatory for a
    /// transit revocation; see [`Self::scrub_signature_classical`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
}

/// Default cohort_scope for a local-tier write — `self` (private to the
/// producing occurrence; CEG §10.1.5 tier read-gate).
fn default_self_cohort_scope() -> String {
    cohort_scope::SELF.to_string()
}

impl LocalAttestationInput {
    /// The envelope `dimension` (the local-tier key + gate axis).
    pub fn dimension(&self) -> Option<&str> {
        self.attestation_envelope.dimension.as_deref()
    }

    /// Build the `local`-tier [`Attestation`] row: caller fields + the
    /// deferred empty-sentinel scrub envelope (`scrub_signature_classical
    /// = ""` — admitted at local tier by the V066 CHECK; `scrub_key_id =
    /// attesting_key_id` so the FK holds; `original_content_hash = ""`,
    /// recomputed via JCS at promote). `persist_row_hash` is filled by the
    /// caller after construction (`compute_persist_row_hash`).
    pub fn into_local_row(self, attestation_id: String, asserted_at: DateTime<Utc>) -> Attestation {
        let attested_key_id = self
            .attested_key_id
            .unwrap_or_else(|| self.attesting_key_id.clone());
        Attestation {
            attestation_id,
            attesting_key_id: self.attesting_key_id.clone(),
            attested_key_id,
            attestation_type: self.attestation_type,
            weight: self.weight,
            asserted_at,
            expires_at: self.expires_at,
            attestation_envelope: self.attestation_envelope.to_value(),
            // Sentinel (empty) — local rows defer the scrub envelope.
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            // FK-valid sentinel: the producer's own key.
            scrub_key_id: self.attesting_key_id,
            scrub_timestamp: asserted_at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: self.subject_key_ids,
            withdraws_admission_rule: None,
            cohort_scope: self.cohort_scope,
            tier: attestation_tier::LOCAL.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// v12.6.0 (CIRISPersist#171, §10.1.3 transit-not-rest) — build the
    /// `local`-tier row for a **subject-side revocation transiting** the
    /// local write path. Unlike [`Self::into_local_row`] (deferred
    /// empty-sentinel scrub envelope), this carries the caller's REAL
    /// bound-hybrid signature + the persist-computed `original_content_hash`
    /// (hex `SHA-256(JCS(envelope))`, returned by the verify step) so the
    /// row is a fully-signed federation-classified revocation staged at
    /// `tier = local`, `promoted_at = None`. It is NOT a durable local row:
    /// the consent-SLA watcher drives it to promotion or overdue-flag.
    /// `persist_row_hash` is filled by the caller after construction.
    pub fn into_transit_revocation_row(
        self,
        attestation_id: String,
        asserted_at: DateTime<Utc>,
        original_content_hash: String,
        scrub_signature_classical: String,
        scrub_signature_pqc: Option<String>,
    ) -> Attestation {
        let attested_key_id = self
            .attested_key_id
            .unwrap_or_else(|| self.attesting_key_id.clone());
        Attestation {
            attestation_id,
            attesting_key_id: self.attesting_key_id.clone(),
            attested_key_id,
            attestation_type: self.attestation_type,
            weight: self.weight,
            asserted_at,
            expires_at: self.expires_at,
            attestation_envelope: self.attestation_envelope.to_value(),
            original_content_hash,
            scrub_signature_classical,
            scrub_signature_pqc,
            // Self-signed: the subject is the attester.
            scrub_key_id: self.attesting_key_id,
            scrub_timestamp: asserted_at,
            // PQC half is present + verified for a transit revocation.
            pqc_completed_at: Some(asserted_at),
            persist_row_hash: String::new(),
            subject_key_ids: self.subject_key_ids,
            withdraws_admission_rule: None,
            cohort_scope: self.cohort_scope,
            tier: attestation_tier::LOCAL.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }
}

/// v9.3.0 (CIRISPersist#248) — inputs to
/// [`crate::Engine::emit_attestation`], the high-level "produce ONE
/// signed federation-tier CEG attestation" primitive.
///
/// The helper canonicalizes [`Self::attestation_envelope`], SHA-256s the
/// canonical bytes (`original_content_hash`), hybrid-signs (Ed25519 +
/// ML-DSA-65 bound), and assembles the 20-field [`Attestation`] with
/// `attesting_key_id == scrub_key_id == <signer's DERIVED federation
/// key_id>` — derived internally (never a caller alias), which
/// structurally fixes CIRISPersist#247. Consumers stop hand-rolling the
/// ~50-line canonicalize→sign→assemble→`put_attestation` pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmitAttestationInput {
    /// The §3 structural primitive (`scores` / `delegates_to` /
    /// `withdraws` / …) — the row's `attestation_type`.
    pub attestation_type: String,
    /// Primary attested key. Defaults to the signer's derived key_id
    /// (a self-attestation) when `None`. Must exist in `federation_keys`
    /// when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested_key_id: Option<String>,
    /// The CEG attestation envelope (canonicalized via
    /// `ceg_produce_canonicalize`; never mutated).
    pub attestation_envelope: crate::federation::envelope::EnvelopeCore,
    /// §4.2.6 subjects this attestation names. May be empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_key_ids: Vec<String>,
    /// Producer-side visibility scope. Defaults `federation` for a
    /// federation-tier emit (see [`Self::with_envelope`]).
    #[serde(default = "default_cohort_scope")]
    pub cohort_scope: String,
    /// Optional expiry (`delegates_to` / `consent:*` lifecycles).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// v9.4.0 (CIRISPersist#252) — optional weight folded onto the
    /// assembled row's [`Attestation::weight`]. `None` (the default)
    /// preserves the pre-9.4.0 emit behavior (the row's `weight` stays
    /// `None`, which the replication trust model reads as `1.0`); a
    /// weighted `scores` producer sets `Some(w)` so the band survives the
    /// emit instead of collapsing to the `1.0` default
    /// (`trust_scoring`/`topology` fold `weight.unwrap_or(1.0)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<f64>,
}

impl EmitAttestationInput {
    /// Build a federation-scope input from a `type` + envelope, leaving
    /// `attested_key_id`/`subject_key_ids`/`expires_at` at their
    /// self-attestation defaults. `cohort_scope` defaults to
    /// `federation` (the tier of every [`crate::Engine::emit_attestation`]
    /// write).
    /// v21.11.0 (CIRISPersist#527) — `cohort_scope` is a REQUIRED argument, not
    /// a defaulted field. The write path must never fail-OPEN on the recipient
    /// axis: a producer that forgets the scope previously broadcast
    /// federation-wide (the widest exposure), inverting the fail-secure
    /// discipline the rest of the stack is built on (a missing/unresolved input
    /// resolves to LESS access — `self` — never a silent widening). Making it a
    /// required arg forces every producer to state the recipient axis at the
    /// call site — the same un-forgettable move as
    /// [`crate::Engine::attestation_promote`]`(id, cohort_scope)` at promotion
    /// (CIRISPersist#519/#527). This is DISTINCT from the read-path
    /// [`default_cohort_scope`] serde default (a pre-v3.9.0 stored row with no
    /// scope column still resolves to `federation`) — write vs read must not
    /// share one default. Pass one of the closed
    /// [`cohort_scope`](crate::federation::types::cohort_scope) values.
    pub fn with_envelope(
        attestation_type: impl Into<String>,
        attestation_envelope: crate::federation::envelope::EnvelopeCore,
        cohort_scope: impl Into<String>,
    ) -> Self {
        Self {
            attestation_type: attestation_type.into(),
            attested_key_id: None,
            attestation_envelope,
            subject_key_ids: Vec::new(),
            cohort_scope: cohort_scope.into(),
            expires_at: None,
            weight: None,
        }
    }

    /// v9.4.0 (CIRISPersist#252) — set the optional `weight` folded onto
    /// the assembled [`Attestation::weight`] (builder convenience for
    /// weighted `scores` producers). `None` keeps the default emit
    /// behavior.
    pub fn with_weight(mut self, weight: Option<f64>) -> Self {
        self.weight = weight;
        self
    }
}

/// v3.9.0 (CIRISPersist#150) — default cohort_scope for backward compat.
/// Pre-v3.9.0 attestations had no cohort_scope; reading them under the
/// new schema returns the column DEFAULT 'federation', so the Rust
/// default matches.
fn default_cohort_scope() -> String {
    "federation".to_string()
}

/// True iff the cohort_scope equals the default. Used by serde
/// `skip_serializing_if` so legacy rows' canonical bytes /
/// `persist_row_hash` stay stable across the v3.9.0 schema bump —
/// federation-scope rows omit the field entirely from JSON output.
fn is_default_cohort_scope(s: &String) -> bool {
    s == "federation"
}

/// v3.9.0 (CIRISPersist#150) — closed-set cohort_scope values per
/// CEG 0.4 §4.2.4. Producers MUST emit one of these or rely on the
/// substrate-side default of `federation`. `global` is intentionally
/// NOT a value — it's a §8.1.8 feed name aggregating
/// `{species, biosphere, federation}`, not a wire enum value.
pub mod cohort_scope {
    /// Locally-held content (locality dividend per
    /// FEDERATION_SCALING_MODEL §9.5). Never emits federation-tier
    /// holds_bytes; substrate-local-only.
    pub const SELF: &str = "self";
    /// Content shared with a partnered family/group (CEG §8.1.8).
    /// Visible to peers with `trust:partnered` or `trust:direct`.
    pub const FAMILY: &str = "family";
    /// Community-tier content per CEG §8.1.8. Visible to peers per
    /// the community's policy_blob cohort_scope (#127 #48-A).
    pub const COMMUNITY: &str = "community";
    /// Affiliations tier (CEG §8.1.8).
    pub const AFFILIATIONS: &str = "affiliations";
    /// Species tier (CEG §8.1.8 — broader-than-community human
    /// audience).
    pub const SPECIES: &str = "species";
    /// Biosphere tier (CEG §8.1.8 — including non-human stakeholders).
    pub const BIOSPHERE: &str = "biosphere";
    /// Federation-wide visibility (CEG §8.1.8). Status-quo
    /// pre-v3.9.0 semantic.
    pub const FEDERATION: &str = "federation";

    /// v30.7.0 (CIRISPersist#625) — every value a `cohort_scope` may hold, in
    /// widening order (self → biosphere), which is the order an operator picker
    /// should present.
    ///
    /// Distinct from [`super::device_class::ALL`], which is a different
    /// vocabulary in its own module. CIRISPersist#625 reported the two as mixed
    /// under one name; they are not, and were not.
    pub const ALL: &[&str] = &[
        SELF,
        FAMILY,
        COMMUNITY,
        AFFILIATIONS,
        SPECIES,
        BIOSPHERE,
        FEDERATION,
    ];

    /// True iff `s` is one of the closed-set values. Substrate
    /// admission-gate work in v3.10.0+ uses this for early rejection
    /// of malformed envelopes.
    pub fn is_valid(s: &str) -> bool {
        matches!(
            s,
            SELF | FAMILY | COMMUNITY | AFFILIATIONS | SPECIES | BIOSPHERE | FEDERATION
        )
    }

    /// v3.9.2 (CIRISPersist#153 Ask 5, CEG 0.7 §10.1.4) — the
    /// structural-invisibility classification.
    ///
    /// True iff content tagged with this `cohort_scope` is
    /// **structurally invisible** to the federation: the substrate
    /// MUST NOT emit a `holds_bytes:sha256:*` directory attestation
    /// for it, and MUST NOT propagate it beyond the self-collective /
    /// family scope via any directory or discovery surface. A
    /// non-member peer cannot issue a ContentFetch for it and cannot
    /// even discover the bytes exist — the `holds_bytes` row *is* the
    /// discovery surface, so not emitting it is the privacy primitive
    /// (the ciris.ai/cewp "the wire format can't carry them" claim).
    ///
    /// True for [`SELF`] and [`FAMILY`]. False for `community` /
    /// `affiliations` / `species` / `biosphere` / `federation`, which
    /// federate per status quo and emit `holds_bytes` normally — CEG
    /// 0.8 §8.1.13.3 is explicit that community content is NOT
    /// suppressed (communities can be large; per-member byte-level
    /// invisibility is infeasible, and the community privacy property
    /// is cohort-filtered visibility, not byte-level invisibility).
    ///
    /// This is the locality dividend of FEDERATION_SCALING_MODEL §9.5:
    /// self/family bytes never cost the federation a directory entry.
    pub fn suppresses_holds_bytes(s: &str) -> bool {
        matches!(s, SELF | FAMILY)
    }

    /// v4.12.0 (CIRISPersist#152 / #188, CEG 0.17 §8.1.13.3 / §10.1.4) —
    /// the at-rest crypto tier a `cohort_scope` resolves to. **Orthogonal
    /// to [`suppresses_holds_bytes`]**: self/family are encrypted AND
    /// suppressed; community/affiliations are encrypted but still emit
    /// `holds_bytes` (with cleartext provenance); Commons is plaintext.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CryptoTier {
        /// `self` / `family` — per-write fresh DEK wrapped to every active
        /// occurrence/member; structurally invisible (no `holds_bytes`).
        /// **Opt-in / default-off** (defense-in-depth over already-invisible
        /// bytes; the v1 migration posture). #152.
        InvisibleEncrypted,
        /// `community` / `affiliations` — a shared per-community DEK (the
        /// §10.5.3 epoch-DEK cascade with the roster as subscriber set),
        /// rotated on membership change; emits `holds_bytes:*` **with**
        /// cleartext provenance. **Mandatory** (the DEK is community
        /// content's sole confidentiality boundary). CEG 0.17 §8.1.13.3.
        CommunityDek,
        /// Commons (`species` / `biosphere` / `federation`), the
        /// `cohort_subkind: infrastructure` governance carve-out, and any
        /// **unrecognized** scope — plaintext, `holds_bytes` normally.
        Plaintext,
    }

    /// The §8.1.13.3 / §10.1.4 at-rest dispatch — **NEGATIVE-DEFAULT
    /// (#188)**: only `self`/`family` and `community`/`affiliations` are
    /// encrypted; *everything else, including unknown future scopes, falls
    /// through to plaintext*. A `community` whose `cohort_subkind` is
    /// `"infrastructure"` (e.g. `ciris-canonical` governance) is the
    /// plaintext-Commons carve-out — the trust root must be inspectable.
    pub fn crypto_tier(cohort_scope: &str, cohort_subkind: Option<&str>) -> CryptoTier {
        match cohort_scope {
            SELF | FAMILY => CryptoTier::InvisibleEncrypted,
            COMMUNITY | AFFILIATIONS if cohort_subkind != Some("infrastructure") => {
                CryptoTier::CommunityDek
            }
            // Negative default: Commons, infrastructure communities, and
            // any scope this build doesn't recognize → plaintext. New
            // tiers never silently encrypt-or-leak by falling through.
            _ => CryptoTier::Plaintext,
        }
    }

    #[cfg(test)]
    mod crypto_tier_tests {
        use super::*;

        #[test]
        fn self_family_are_invisible_encrypted() {
            assert_eq!(crypto_tier(SELF, None), CryptoTier::InvisibleEncrypted);
            assert_eq!(crypto_tier(FAMILY, None), CryptoTier::InvisibleEncrypted);
            // subkind is irrelevant for self/family.
            assert_eq!(
                crypto_tier(SELF, Some("infrastructure")),
                CryptoTier::InvisibleEncrypted
            );
        }

        #[test]
        fn community_affiliations_are_community_dek() {
            assert_eq!(crypto_tier(COMMUNITY, None), CryptoTier::CommunityDek);
            assert_eq!(crypto_tier(AFFILIATIONS, None), CryptoTier::CommunityDek);
            assert_eq!(
                crypto_tier(COMMUNITY, Some("geographic")),
                CryptoTier::CommunityDek
            );
        }

        #[test]
        fn infrastructure_community_is_plaintext_carveout() {
            assert_eq!(
                crypto_tier(COMMUNITY, Some("infrastructure")),
                CryptoTier::Plaintext
            );
            assert_eq!(
                crypto_tier(AFFILIATIONS, Some("infrastructure")),
                CryptoTier::Plaintext
            );
        }

        #[test]
        fn commons_and_unknown_are_plaintext_negative_default() {
            for s in [SPECIES, BIOSPHERE, FEDERATION] {
                assert_eq!(crypto_tier(s, None), CryptoTier::Plaintext);
            }
            // The #188 point: an unrecognized scope must NOT fall into an
            // encrypted arm — negative default.
            assert_eq!(crypto_tier("planet", None), CryptoTier::Plaintext);
            assert_eq!(crypto_tier("some_future_tier", None), CryptoTier::Plaintext);
        }
    }
}

impl Attestation {
    /// True iff PQC components have been attached.
    pub fn is_pqc_complete(&self) -> bool {
        self.scrub_signature_pqc.is_some() && self.pqc_completed_at.is_some()
    }
}

/// `federation_revocations` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Revocation {
    /// UUID identifier for this revocation row.
    pub revocation_id: String,
    /// Key being revoked.
    pub revoked_key_id: String,
    /// Key issuing the revocation.
    pub revoking_key_id: String,
    /// Free-form reason; consumers parse if they care.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When the revocation was issued.
    pub revoked_at: DateTime<Utc>,
    /// When the revocation takes effect (may be retroactive or future).
    pub effective_at: DateTime<Utc>,
    /// Canonical bytes of the revocation envelope.
    pub revocation_envelope: serde_json::Value,
    /// SHA-256 of canonical(revocation_envelope). Hex-encoded.
    pub original_content_hash: String,
    /// Classical Ed25519 sig over canonical bytes. Base64. Required.
    pub scrub_signature_classical: String,
    /// PQC ML-DSA-65 sig over (canonical || classical_sig). Base64.
    /// `None` while the row is hybrid-pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
    /// `key_id` that signed this row.
    pub scrub_key_id: String,
    /// When the scrub-signature was issued.
    pub scrub_timestamp: DateTime<Utc>,
    /// When the PQC components were attached. `None` while pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_completed_at: Option<DateTime<Utc>>,

    /// v3.11.0 (CIRISPersist#143, CIRISVerify FEDERATION_THREAT_MODEL
    /// §3.3.2 R1) — region that first observed this revocation
    /// (closed set: `us` / `eu` / `apac`, see
    /// [`crate::federation::verify_coord::region`]). Drives the Q1
    /// quorum-write tracking + R1 τ_propagate accounting.
    ///
    /// `#[serde(default, skip_serializing_if = …)]`: the default
    /// value [`crate::federation::verify_coord::region::US`] is
    /// skipped from canonical bytes so pre-v3.11 rows (which had no
    /// region field) and explicit `us` rows hash identically — the
    /// same backward-compat discipline v3.9.0 used for `cohort_scope`.
    #[serde(
        default = "default_observed_region",
        skip_serializing_if = "is_default_observed_region"
    )]
    pub observed_region: String,

    /// v25.1.0 (CIRISPersist#570 ask 4; CIRISServer `FSD/ADMIN_OPS_TAXONOMY.md`
    /// family 2b) — **the history bound.** The last instant this key's
    /// statements are still stood behind: a statement asserted at or before
    /// `revoked_after` survives the revocation; one asserted after it is
    /// suspect.
    ///
    /// `None` is today's meaning and stays the default: **all-or-nothing**.
    /// Nothing in the row scopes the history, so a consumer either keeps
    /// everything the key ever said or drops it, and the honest reading of an
    /// unbounded revocation is that the whole corpus is in doubt.
    ///
    /// # Why the bound has to exist
    ///
    /// A key is compromised on Tuesday. The only expressible response today
    /// destroys Monday too — every honest signature the key ever made, every
    /// row that depended on one. DigiNotar is the precedent: the long tail of
    /// a total revocation is measured in the things that were fine and died
    /// anyway. `revoked_after: Tuesday 09:00` says *from this instant*, and
    /// Monday survives.
    ///
    /// # It is SIGNED, not decorative
    ///
    /// The bound decides which of a key's history stands, so it is exactly the
    /// field an attacker wants to move. It is therefore **envelope-bound**:
    /// [`check_revocation_bound`](crate::federation::register::check_revocation_bound)
    /// refuses any row whose typed `revoked_after` is not mirrored, to the
    /// second, by a `revoked_after` in the signed `revocation_envelope` — the
    /// preserve-set-equals-verified-set discipline (#541), applied before the
    /// bound could ever be relied on. A revocation with a typed bound and no
    /// envelope bound is not a lenient revocation, it is a forged one.
    ///
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]`: a `None`
    /// bound is skipped from canonical bytes, so pre-v25.1 rows and explicit
    /// unbounded rows hash identically — the same backward-compat discipline
    /// [`Self::observed_region`] uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_after: Option<DateTime<Utc>>,

    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
}

fn default_observed_region() -> String {
    crate::federation::verify_coord::region::US.to_owned()
}

fn is_default_observed_region(s: &str) -> bool {
    s == crate::federation::verify_coord::region::US
}

impl Revocation {
    /// True iff PQC components have been attached.
    pub fn is_pqc_complete(&self) -> bool {
        self.scrub_signature_pqc.is_some() && self.pqc_completed_at.is_some()
    }

    /// v3.11.0 (CIRISPersist#143) — the **signed_timestamp** the Q1
    /// merge comparator reads (tier 2). Mapped from
    /// [`Revocation::scrub_timestamp`], the timestamp pinned into the
    /// signed scrub envelope.
    ///
    /// Exposed as a named accessor so the spec mapping
    /// (`signed_timestamp` in CIRISVerify FEDERATION_THREAT_MODEL
    /// §3.3.2) is verbatim in the substrate API, without storing the
    /// same value twice on the row.
    pub fn signed_timestamp(&self) -> DateTime<Utc> {
        self.scrub_timestamp
    }

    /// v3.11.0 (CIRISPersist#143) — the **canonical_bytes_hash** the
    /// Q1 merge comparator reads (tier 3, deterministic tie-break).
    /// Mapped from [`Revocation::original_content_hash`], the hex
    /// SHA-256 of the canonical revocation envelope.
    pub fn canonical_bytes_hash(&self) -> &str {
        &self.original_content_hash
    }

    /// v25.1.0 (CIRISPersist#570 ask 4) — **THE history comparator.** Does
    /// this revocation put a statement made at `statement_at` in doubt?
    ///
    /// The ONE predicate every history fold composes, so "does the bound
    /// cover this row?" can never mean two things in two places (rule #9).
    ///
    /// - **unbounded** ([`Self::revoked_after`] is `None`) — `true` for every
    ///   instant. All-or-nothing, which is what an unbounded revocation has
    ///   always meant; making that explicit is half the point of the field.
    /// - **bounded** — `true` iff `statement_at > revoked_after`. At-or-before
    ///   the bound survives. The boundary instant itself survives: a bound
    ///   says *after this*, and a compromise discovered at T does not
    ///   retroactively poison the signature made exactly at T.
    ///
    /// Independent of [`Self::effective_at`] on purpose. `effective_at` is
    /// about the KEY going forward (from when is it not admitted); this is
    /// about STATEMENTS looking back (which of what it already said stands).
    /// Fusing them is the axis-fusion class — one name, two questions.
    #[must_use]
    pub fn suspects_statement_at(&self, statement_at: DateTime<Utc>) -> bool {
        match self.revoked_after {
            None => true,
            Some(bound) => statement_at > bound,
        }
    }

    /// Is this revocation **history-bounded** — does it leave any of the key's
    /// past standing?
    #[must_use]
    pub fn is_history_bounded(&self) -> bool {
        self.revoked_after.is_some()
    }
}

// ─── CEG 0.7 (CIRISPersist#153 Asks 1-2, v3.12.0) ──────────────────
//
// §5.6.8.8 identity_occurrence + §5.6.8.9 family substrate types.
// "Participants that ARE me" (occurrences across my devices/agents)
// vs "trusted nodes that compose with me" (other people's identities,
// shared household devices). Wire-format-stable per Registry#47
// ratified-locked on 2026-05-31.

/// §5.6.8.8 `device_class` closed-set vocabulary.
///
/// Every `IdentityOccurrence` row carries a value from this set;
/// out-of-set producers are rejected at admission
/// ([`crate::federation::admission::check_device_class`]) and by the
/// V059 `CHECK` constraint.
pub mod device_class {
    /// Mobile device (iOS / Android / etc.); typically hardware-rooted.
    pub const PHONE: &str = "phone";
    /// Personal computing device (macOS / Linux / Windows).
    pub const LAPTOP: &str = "laptop";
    /// Always-on infrastructure node (home server, VPS, etc.).
    pub const SERVER: &str = "server";
    /// IoT / hardware peripheral / signing dongle.
    pub const EMBEDDED: &str = "embedded";
    /// An AI agent acting on the identity's behalf (composes with
    /// CIRISAgent#840 self-attestation pattern).
    pub const AGENT: &str = "agent";
    /// Background service / scheduled job / API integration acting
    /// on the identity's behalf.
    pub const SERVICE: &str = "service";

    /// True iff `s` is one of the six closed-set values.
    pub fn is_valid(s: &str) -> bool {
        matches!(s, PHONE | LAPTOP | SERVER | EMBEDDED | AGENT | SERVICE)
    }

    /// All six values in spec order.
    pub const ALL: [&str; 6] = [PHONE, LAPTOP, SERVER, EMBEDDED, AGENT, SERVICE];
}

/// v30.7.0 (CIRISPersist#625) — the **transmission principle** vocabulary: what
/// a recipient may DO with data, as distinct from who may see it
/// ([`cohort_scope`]).
///
/// The members were literals inside the consent-grammar JSON blob, which is
/// hash-pinned by `CONSENT_GRAMMAR_HASH`. They are named here and referenced
/// there, so the wire bytes are unchanged — the grammar-hash test proves it —
/// and an operator picker has a list to read.
pub mod transmission_principle {
    /// Keep a copy.
    pub const RETAIN: &str = "retain";
    /// Pass on to others in the permitted audience.
    pub const SHARE: &str = "share";
    /// Derive statistics or inferences.
    pub const ANALYZE: &str = "analyze";
    /// Use as training data.
    pub const TRAIN: &str = "train";
    /// Make publicly available.
    pub const PUBLISH: &str = "publish";

    /// Every transmission principle, in consent-grammar order. That order is
    /// load-bearing: it is the order serialized into the hash-pinned grammar.
    pub const ALL: &[&str] = &[RETAIN, SHARE, ANALYZE, TRAIN, PUBLISH];
}

/// v30.7.0 (CIRISPersist#625) — the **consent state** vocabulary.
///
/// The wire values are the `consent:state:*` dimension prefixes in
/// [`crate::federation::consent`]; `Unspecified` is a resolved outcome (the
/// subject was named but never declared a stance), not a value anyone emits, so
/// it is deliberately absent from [`ALL`].
pub mod consent_state {
    /// Latest stance is `granted` — processing may proceed in scope.
    pub const GRANTED: &str = "granted";
    /// Latest stance is `revoked` — the subject withdrew; the SLA clock runs.
    pub const REVOKED: &str = "revoked";
    /// Latest stance is `expired`, or a `valid_until` passed.
    pub const EXPIRED: &str = "expired";

    /// The three states a subject can DECLARE. `Unspecified` is not here: it is
    /// what the resolver returns when no stance exists, and offering it in a
    /// picker would invite an operator to "set" a state that means "unset".
    pub const ALL: &[&str] = &[GRANTED, REVOKED, EXPIRED];
}

/// §5.6.8.9 `consensus_protocol` canonical-kinds vocabulary.
///
/// OPEN vocab per the spec — operators MAY extend with their own
/// protocol names. The substrate's value-validation gate
/// ([`crate::federation::admission::check_consensus_protocol_form`])
/// verifies the string matches one of the canonical shapes; full
/// signature-counting against the protocol is the v3.13+ admission
/// gate (#153 Ask 3).
pub mod consensus_protocol {
    /// Original founders are the sole admission authority.
    pub const FOUNDER_ONLY: &str = "founder_only";
    /// Every current member must sign the admission.
    pub const UNANIMOUS: &str = "unanimous";
    /// > 50% of current members must sign.
    pub const MAJORITY: &str = "majority";
    /// Prefix for `quorum:{m}/{n}` shape (e.g., `quorum:2/3`).
    pub const QUORUM_PREFIX: &str = "quorum:";
    /// Prefix for `weighted:{rubric}` shape.
    pub const WEIGHTED_PREFIX: &str = "weighted:";
    /// Prefix for `custom:{family_specific_id}` shape.
    pub const CUSTOM_PREFIX: &str = "custom:";
    /// v24.3.0 (CIRISPersist#574) — prefix for the **objection** form,
    /// `reverse_quorum:{m}/{n}:{window_secs}` (e.g.
    /// `reverse_quorum:2/5:86400`).
    ///
    /// Every other member of this vocabulary is **approve-to-act**: it names
    /// who must sign BEFORE an action lands. This one is **act-unless-objected**
    /// — the action lands on arrival and `m` of `n` current members may object
    /// within `window_secs` to reverse it. That is the only shape that resolves
    /// speed against legitimacy in the commons, where consent gives no
    /// protection because everyone has already consented to look.
    ///
    /// Parsed and folded by [`crate::federation::reverse_quorum`]; the
    /// forward-threshold readers of this vocabulary
    /// ([`family_charter_threshold`](crate::federation::trust_root) and
    /// verify's membership-change gate) read it FAIL-SECURE as unanimity,
    /// because a reverse threshold is not a forward one and must never be
    /// mistaken for a smaller number.
    pub const REVERSE_QUORUM_PREFIX: &str = "reverse_quorum:";

    /// True iff `s` parses into one of the canonical-kinds shapes:
    /// the three bare forms (`founder_only`, `unanimous`, `majority`),
    /// one of the three prefixed forms with a non-empty tail
    /// (`quorum:{m}/{n}` where m, n parse as integers; `weighted:rubric`;
    /// `custom:id`), or the v24.3.0 objection form
    /// (`reverse_quorum:{m}/{n}:{window_secs}`). Returns false for empty
    /// strings, unprefixed names not in the bare set, and `quorum:` strings
    /// whose tail is not `{int}/{int}`.
    pub fn is_canonical_form(s: &str) -> bool {
        if matches!(s, FOUNDER_ONLY | UNANIMOUS | MAJORITY) {
            return true;
        }
        if s.starts_with(REVERSE_QUORUM_PREFIX) {
            // One parse door: the shape gate and the fold read the SAME
            // parser, so a string this function admits is a string
            // `reverse_quorum` can actually evaluate (rule #9 — one
            // predicate, one implementation).
            return crate::federation::reverse_quorum::ReverseQuorumPolicy::parse(s).is_some();
        }
        if let Some(tail) = s.strip_prefix(QUORUM_PREFIX) {
            // tail must be `{m}/{n}` with both as non-negative ints,
            // m <= n, n > 0 (a 0-of-0 quorum is meaningless).
            if let Some((m_s, n_s)) = tail.split_once('/') {
                if let (Ok(m), Ok(n)) = (m_s.parse::<u32>(), n_s.parse::<u32>()) {
                    return n > 0 && m <= n;
                }
            }
            return false;
        }
        if let Some(tail) = s.strip_prefix(WEIGHTED_PREFIX) {
            return !tail.is_empty();
        }
        if let Some(tail) = s.strip_prefix(CUSTOM_PREFIX) {
            return !tail.is_empty();
        }
        false
    }
}

/// `federation_identity_occurrences` row — the §5.6.8.8 wire-format
/// binding "this `occurrence_key_id` is also `identity_key_id`."
///
/// One identity may admit unbounded occurrences (the substrate
/// carries no hard cap; operator policy MAY impose limits). The
/// composite primary key `(identity_key_id, occurrence_key_id)`
/// makes the binding idempotent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityOccurrence {
    /// The root identity's `federation_keys.key_id`.
    pub identity_key_id: String,
    /// The participant's signing key — also a
    /// `federation_keys.key_id`.
    pub occurrence_key_id: String,
    /// Closed-set value per [`device_class`].
    pub device_class: String,
    /// Opaque base64 attestation blob (TPM / Secure Enclave /
    /// StrongBox / SGX / etc.). `None` for software-only occurrences.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware_attestation: Option<String>,
    /// When the binding was asserted (RFC-3339 canonical per §0.5).
    pub asserted_at: DateTime<Utc>,
    /// When the binding expires. `None` = indefinite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    /// v4.13.0 (CIRISPersist#192, CEG 0.18 §5.6.8.8) — the occurrence's
    /// **content-encryption** pubkeys (the `wrap_algorithm: v2` recipient
    /// inputs). `None` ⇒ this occurrence is **not** a wrap target and is
    /// fail-secure excluded from v2 grants (§10.1.4). Distinct from the
    /// signing keys (`federation_keys`) and the transport x25519. Present
    /// ⇒ both halves present (the field-set is meaningful only as a pair).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_pubkeys: Option<EncryptionPubkeys>,
    /// v14.0.0 (CIRISPersist#418, occurrence-KEX arc 2/4) — the occurrence's
    /// **transport binding** (RNS reticulum x25519, ed25519, destination_hash,
    /// app_name, aspects): the reticulum half of the SAME signed occurrence
    /// envelope that carries [`Self::encryption_pubkeys`]. Stored here so the
    /// occurrence is the single signed source of truth for the transport
    /// reticulum keys, dest_hash, and content-KEM (authoritative over the
    /// mutable `transport_destinations` overlay). `None` for a content-only
    /// occurrence (no C4 check applies then). `verify_transport_binding` checks
    /// the hybrid signature over the whole envelope and the §5.6.8.8.2 C4
    /// separation (transport-x25519 must not equal this content-KEM x25519).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_binding: Option<OccurrenceTransportBinding>,
    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
}

/// v14.0.0 (CIRISPersist#418) — persist's stored form of an occurrence's RNS
/// transport binding, mirroring `ciris_verify_core::transport_binding::TransportDestination`
/// (the shape the signed occurrence envelope carries + `verify_transport_binding`
/// checks). Kept as a persist type so the storage/wire surface doesn't leak the
/// verify-core type; [`OccurrenceTransportBinding::to_verify`] converts for the
/// verify call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OccurrenceTransportBinding {
    /// Transport identity's X25519 (encryption/KEX) pubkey — base64, 32 raw bytes.
    pub reticulum_x25519_pubkey_base64: String,
    /// Transport identity's Ed25519 (signing) pubkey — base64, 32 raw bytes.
    /// MUST differ from the occurrence's federation signing key (AV-17).
    pub reticulum_ed25519_pubkey_base64: String,
    /// RNS destination hash (truncated SHA-256), base64, 16 raw bytes; derives
    /// from the two pubkeys + `app_name` + `aspects` (§5.6.8.8.1).
    pub destination_hash_base64: String,
    /// RNS destination app name (e.g. `"ciris.federation"`).
    pub app_name: String,
    /// RNS aspects (ordered; part of the hash preimage).
    pub aspects: Vec<String>,
}

impl OccurrenceTransportBinding {
    /// The `transport_destinations.transport_kind` an occurrence-embedded
    /// binding projects to — this struct is RNS-specific by shape
    /// (`reticulum_*` pubkeys, RNS dest hash), so the kind is fixed.
    pub const TRANSPORT_KIND: &str = "reticulum";

    /// Convert to the verify-core `TransportDestination` for
    /// `verify_transport_binding`.
    pub fn to_verify(&self) -> ciris_verify_core::transport_binding::TransportDestination {
        ciris_verify_core::transport_binding::TransportDestination {
            reticulum_x25519_pubkey_base64: self.reticulum_x25519_pubkey_base64.clone(),
            reticulum_ed25519_pubkey_base64: self.reticulum_ed25519_pubkey_base64.clone(),
            destination_hash_base64: self.destination_hash_base64.clone(),
            app_name: self.app_name.clone(),
            aspects: self.aspects.clone(),
        }
    }

    /// v17.0.1 (CIRISPersist#446) — project this binding into the
    /// `transport_destinations` read model (the #336 last mile). The
    /// occurrence plane is the replication authority; the route table is a
    /// LOCAL MATERIALIZED VIEW of it, so the projected row:
    /// - inherits the occurrence's authenticated authority (the caller runs
    ///   it only inside an ACCEPTED occurrence write — after
    ///   `verify_signed_identity_occurrence`, or on the trusted-local path);
    /// - is a **local derived row** (the signed-column-free local put), so
    ///   `list_signed_transport_destinations_for` excludes it and the route
    ///   never double-replicates under two supersession clocks;
    /// - rides the occurrence's own last-signed-wins clock
    ///   (`asserted_at = occurrence.asserted_at`, `epoch = 0` — a LIVE
    ///   announced route at `epoch >= 1` always outranks the boot-time
    ///   projection, and a newer occurrence's projection supersedes an older
    ///   one, in lockstep with the occurrence UPSERT guard);
    /// - carries `Rooted` provenance from the authenticated CONTEXT (the
    ///   occurrence passed `signer_acts_for`), never from a wire field.
    ///
    /// v21.3.0 (CIRISPersist#512) — the projected row's `destination` is
    /// normalized to the column's ONE canonical encoding: **lowercase hex**
    /// of the raw RNS destination hash. Every other writer (the signed
    /// producer's `hex::encode`, the edge announce) and the #393 item-2
    /// gate's probe speak hex; this projection alone stored the envelope's
    /// base64 verbatim, so an occurrence-projected route could never match
    /// the gate's probe — same 16 bytes, two dialects, one column. The
    /// occurrence ENVELOPE keeps `destination_hash_base64` (its own
    /// `verify_transport_binding` gate wants base64 there); only the
    /// projected row normalizes. Malformed base64 is a fail-closed `Err` —
    /// never an empty/garbage `destination` row.
    pub fn project_route(
        &self,
        occurrence_key_id: &str,
        asserted_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<super::self_at_login::TransportDestination, super::Error> {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let destination_hash_raw = B64.decode(&self.destination_hash_base64).map_err(|e| {
            super::Error::InvalidArgument(format!(
                "project_route: transport_binding.destination_hash_base64 is not valid \
                 base64 ({e}) — refusing to project a route row with an \
                 unnormalizable destination"
            ))
        })?;
        Ok(super::self_at_login::TransportDestination {
            occurrence_key_id: occurrence_key_id.to_owned(),
            transport_kind: Self::TRANSPORT_KIND.to_owned(),
            destination: hex::encode(destination_hash_raw),
            asserted_at,
            last_seen_at: None,
            transport_ed25519_pubkey_base64: Some(self.reticulum_ed25519_pubkey_base64.clone()),
            transport_x25519_pubkey_base64: Some(self.reticulum_x25519_pubkey_base64.clone()),
            binding_provenance: super::self_at_login::BindingProvenance::Rooted,
            epoch: 0,
            retired_at: None,
        })
    }
}

/// v4.13.0 (CIRISPersist#192, CEG 0.18 §5.6.8.8) — the hybrid
/// content-encryption pubkey pair an [`IdentityOccurrence`] registers as
/// a wrap target. Both halves are required together: the §5.6.8.4
/// `wrap_algorithm: v2` (`x25519_mlkem768_aes256_gcm_hkdf_sha256`) needs
/// both. These are a **fresh content-KEM** keypair — never the signing
/// keys, never the Reticulum transport x25519.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionPubkeys {
    /// Classical KEM half — base64 x25519 public key (32 bytes raw).
    pub x25519_base64: String,
    /// PQC KEM half — base64 ML-KEM-768 public key (FIPS 203; 1184 bytes raw).
    pub ml_kem_768_base64: String,
}

/// v14.0.0 (CIRISPersist#418, occurrence-KEX arc 2/4) — a **signed**
/// identity-occurrence submission. Before this the type was just
/// `{ identity_occurrence }` and `put_identity_occurrence` admitted on
/// length/closed-set checks only, so the content-tier KEX pubkeys — the root
/// of content confidentiality — were admitted from replication peers with ZERO
/// proof they belong to the identity (silent content-MITM). Now the write MUST
/// carry a hybrid signature over the exact producer envelope, verified via
/// `ciris_verify_core::transport_binding::verify_transport_binding` at `put`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedIdentityOccurrence {
    /// Persist's typed projection of the occurrence (what gets stored). Its
    /// members are parsed FROM [`Self::signed_envelope`]; the signature is
    /// verified over `signed_envelope`, not over this projection, so the §0.9
    /// member-presence discipline is preserved (persist never re-canonicalizes).
    pub identity_occurrence: IdentityOccurrence,
    /// The claimed signer — a `federation_keys.key_id`. MUST be the identity's
    /// own registered key or an already-ACTIVE occurrence key of the same
    /// identity (`signer_acts_for`).
    pub attesting_key_id: String,
    /// The EXACT `identity_occurrence` envelope the producer signed (signature
    /// container stripped), as received — the bytes `verify_transport_binding`
    /// JCS-canonicalizes. Byte-exact by construction (never rebuilt from the
    /// typed projection).
    pub signed_envelope: serde_json::Value,
    /// The detached hybrid signature over `JCS(signed_envelope)` (Ed25519 over
    /// the bytes; ML-DSA-65 over `bytes ‖ ed25519_sig`).
    pub signature: ciris_verify_core::transport_binding::TransportBindingSignature,
}

/// One member of a [`Family`] — an IDENTITY key plus when they
/// joined plus an optional role tag.
///
/// Note: member entries are IDENTITY keys (NOT occurrence keys), per
/// the §5.6.8.9 worked example. Shared household devices have their
/// own identity_keys and join the family as members in their own
/// right rather than as occurrences of any single person.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FamilyMember {
    /// The member's `federation_keys.key_id` (identity key, not
    /// occurrence key).
    pub key_id: String,
    /// When the member joined (RFC-3339 canonical per §0.5).
    pub joined_at: DateTime<Utc>,
    /// `founder` / `member` / operator-defined. Open vocab.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// `federation_families` row — the §5.6.8.9 wire-format primitive
/// "a group of trusted nodes" for `cohort_scope: family` visibility
/// scoping.
///
/// Content scoped `cohort_scope: family` lands in substrate, is
/// wrapped under the family DEK by the v3.13+ at-rest cascade
/// (CIRISPersist#152), and is delivered to all current members via
/// `key_grant` per §5.6.8.4 — but never emits `holds_bytes:sha256:*`
/// to non-members (the structural-invisibility primitive shipped in
/// v3.9.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Family {
    /// The family's own `federation_keys.key_id`.
    pub family_key_id: String,
    /// Human-readable (e.g. `"Acme Household"`); non-unique.
    pub family_name: String,
    /// Roster of identity keys + join times + roles. Storage shape
    /// is `members JSONB` in postgres / `members TEXT (json)` in
    /// sqlite; consumers normalize via this typed projection.
    pub members: Vec<FamilyMember>,
    /// When the family was founded (RFC-3339 canonical per §0.5).
    pub founded_at: DateTime<Utc>,
    /// Per [`consensus_protocol::is_canonical_form`]. Open vocab;
    /// canonical kinds: `founder_only`, `unanimous`, `majority`,
    /// `quorum:m/n`, `weighted:rubric`, `custom:id`.
    pub consensus_protocol: String,
    /// Structural lock per §5.6.8.9: if `true`, the
    /// `consensus_protocol` field may NOT be amended via the
    /// protocol's own rules — replacement requires an out-of-band
    /// ceremony. HUMANITY_ACCORD per §9 is the canonical entrenched
    /// instance.
    #[serde(default)]
    pub consensus_protocol_entrenched: bool,
    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
}

impl Family {
    /// v21.0.0 (CIRISPersist#502 E4) — the canonical envelope an authority
    /// signs to admit this record: `Family`'s own JSON with `persist_row_hash`
    /// stripped (server-computed, never part of what's signed). `Family`
    /// carries no pre-existing envelope/canonical form of its own (unlike
    /// [`Attestation`]/[`Revocation`], which already had one) — this IS the
    /// synthesized canonical the [`SignedFamily`] admission gate
    /// (`verify_family_admission`) verifies over, and the SAME construction
    /// test fixtures sign through ([`super::tier_ingest::test_support`]).
    pub fn signing_envelope(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).expect("Family always serializes");
        if let Some(obj) = v.as_object_mut() {
            obj.remove("persist_row_hash");
        }
        v
    }
}

/// Wraps a [`Family`] payload for write submission.
///
/// v21.0.0 (CIRISPersist#502 E4) — `authority_key_id` +
/// `scrub_signature_classical` + `scrub_signature_pqc` are the closing half of
/// the keyless-declaration hole: before this, a `Family` admitted on
/// FK-existence alone (no proof ANYONE authored the declaration). Now
/// `put_family` hybrid-Strict-verifies `scrub_signature_{classical,pqc}` over
/// [`Family::signing_envelope`] against `authority_key_id`'s REGISTERED
/// pubkeys (`verify_family_admission`) before any write. Additive fields
/// (`#[serde(default)]`) — an old/unsigned payload decodes fine and then
/// fails closed at admission (empty signer/signature never verifies).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedFamily {
    /// The family record being submitted.
    pub family: Family,
    /// The claimed authority — a `federation_keys.key_id` whose REGISTERED
    /// pubkeys the scrub signature below must verify against.
    #[serde(default)]
    pub authority_key_id: String,
    /// Ed25519 signature (base64) over `JCS(Family::signing_envelope())`.
    #[serde(default)]
    pub scrub_signature_classical: String,
    /// ML-DSA-65 signature (base64) over the bound payload
    /// `canonical ‖ ed25519_sig`. `None` ⇒ hybrid-Strict verify rejects
    /// (PQC-mandatory, CC 5.3.2.4.3.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
}

/// One member of a [`Community`] — an IDENTITY key plus when they
/// joined plus an optional role tag. Structural mirror of
/// [`FamilyMember`] (V059 §5.6.8.9).
///
/// Note: member entries are IDENTITY keys (NOT occurrence keys), per
/// the §8.1.13.3 worked example — same shape as families.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommunityMember {
    /// The member's `federation_keys.key_id` (identity key, not
    /// occurrence key).
    pub key_id: String,
    /// When the member joined (RFC-3339 canonical per §0.5).
    pub joined_at: DateTime<Utc>,
    /// `founder` / `member` / operator-defined. Open vocab.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// `federation_communities` row — the CEG 0.8 §8.1.13.3 wire-format
/// primitive for `cohort_scope: community` visibility scoping. The
/// structural mirror of [`Family`] (V059 §5.6.8.9), with one
/// semantic difference: **community content is NOT structurally
/// invisible.**
///
/// [`cohort_scope::suppresses_holds_bytes`] returns `false` for
/// `community` (true for `self` / `family`). Community content
/// federates normally — it emits `holds_bytes:sha256:*` directory
/// attestations and propagates per status quo (communities can be
/// large; per-member byte-level invisibility is infeasible — the
/// community privacy property is cohort-filtered visibility, not
/// byte-level invisibility). This is the lens-trace path: a
/// lens-capable peer whose identity sits in the agent's community
/// receives community-cohort traces the agent stored, via the §4.3
/// read-side community predicate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Community {
    /// The community's own `federation_keys.key_id`.
    pub community_key_id: String,
    /// Human-readable (e.g. `"Acme Co-op"`); non-unique.
    pub community_name: String,
    /// Roster of identity keys + join times + roles. Storage shape
    /// is `members JSONB` in postgres / `members TEXT (json)` in
    /// sqlite; consumers normalize via this typed projection.
    pub members: Vec<CommunityMember>,
    /// When the community was founded (RFC-3339 canonical per §0.5).
    pub founded_at: DateTime<Utc>,
    /// Per [`consensus_protocol::is_canonical_form`]. Open vocab;
    /// canonical kinds: `founder_only`, `unanimous`, `majority`,
    /// `quorum:m/n`, `weighted:rubric`, `custom:id`.
    pub consensus_protocol: String,
    /// Opaque community policy blob (§8.1.13.3) — carries the
    /// `cohort_scope` membership label consumed at CIRISEdge#48-A.
    /// `None` when the community declares no policy. Stored as
    /// nullable JSONB (postgres) / JSON TEXT (sqlite).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_blob: Option<serde_json::Value>,
    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
}

impl Community {
    /// v21.0.0 (CIRISPersist#502 E4) — the canonical envelope an authority
    /// signs to admit this record. Same construction as
    /// [`Family::signing_envelope`] (`Community`'s own JSON,
    /// `persist_row_hash` stripped) — `Community` also carries no
    /// pre-existing envelope form, so this is a synthesized canonical.
    pub fn signing_envelope(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).expect("Community always serializes");
        if let Some(obj) = v.as_object_mut() {
            obj.remove("persist_row_hash");
        }
        v
    }
}

/// Wraps a [`Community`] payload for write submission.
///
/// v21.0.0 (CIRISPersist#502 E4) — structural mirror of [`SignedFamily`]'s
/// authority-signature fields; `put_community` hybrid-Strict-verifies
/// `scrub_signature_{classical,pqc}` over [`Community::signing_envelope`]
/// against `authority_key_id`'s REGISTERED pubkeys (`verify_community_admission`)
/// before any write. Additive (`#[serde(default)]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedCommunity {
    /// The community record being submitted.
    pub community: Community,
    /// The claimed authority — a `federation_keys.key_id` whose REGISTERED
    /// pubkeys the scrub signature below must verify against.
    #[serde(default)]
    pub authority_key_id: String,
    /// Ed25519 signature (base64) over `JCS(Community::signing_envelope())`.
    #[serde(default)]
    pub scrub_signature_classical: String,
    /// ML-DSA-65 signature (base64) over the bound payload
    /// `canonical ‖ ed25519_sig`. `None` ⇒ hybrid-Strict verify rejects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
}

// ─── v4.8.0 (CIRISPersist#161, CEG §11.7.1) — Option-A forward-secrecy
//     removal/revocation primitives. Append-only rows that SUPERSEDE a
//     V059/V060 admission binding: effective membership =
//     (admitted AND NOT revoked-with-effective_at<=now). The substrate's
//     "this binding/membership is currently revoked" expression that the
//     stop-wrapping rule (§11.7.1) and honest CallerAdmission depend on.

/// Revokes a single V059 `(identity_key_id, occurrence_key_id)` binding
/// (an occurrence leaving a self-collective). The admission row in
/// `federation_identity_occurrences` is left intact; the active-state
/// read excludes pairs with a matching revocation whose `effective_at`
/// has passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityOccurrenceRevocation {
    /// The root identity's `federation_keys.key_id`.
    pub identity_key_id: String,
    /// The occurrence being revoked — a `federation_keys.key_id`.
    pub occurrence_key_id: String,
    /// When the revocation ceremony issued it (RFC-3339 per §0.5).
    pub revoked_at: DateTime<Utc>,
    /// When the revocation takes effect (may be future-dated). The
    /// active-state filter is `effective_at <= now()`.
    pub effective_at: DateTime<Utc>,
    /// Optional operator/ceremony annotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Vouch set (`federation_keys.key_id`s). Single-vouch for self per
    /// §11.7.4 — the revoking occurrence OR the `identity_key_id`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_set: Vec<String>,
    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
}

impl IdentityOccurrenceRevocation {
    /// v16.0.0 (CIRISPersist#421) — **THE revocation-fold comparator**: does
    /// this revocation kill `occurrence` as of `now`? The single predicate
    /// every active/seal/admission fold composes (`resolve_encryption_keys`,
    /// `list_identity_occurrences_active`, `build_caller_admission`), so the
    /// re-establishment rule can never drift between them.
    ///
    /// True iff all three hold:
    /// - it names the occurrence (`occurrence_key_id` matches);
    /// - it is in effect (`effective_at <= now` — future-dated waits);
    /// - it is **not superseded by re-establishment**
    ///   (`effective_at >= occurrence.asserted_at`): a FRESH occurrence
    ///   asserted strictly after the revocation re-establishes under the same
    ///   key_id (compromise → revoke → re-key → publish → recovered), and a
    ///   replayed OLD revocation is a no-op. Without this clause a single
    ///   (even legitimate) self-revoke was terminal-forever.
    pub fn revokes(&self, occurrence: &IdentityOccurrence, now: DateTime<Utc>) -> bool {
        self.occurrence_key_id == occurrence.occurrence_key_id
            && self.effective_at <= now
            && self.effective_at >= occurrence.asserted_at
    }
}

/// A SIGNED [`IdentityOccurrenceRevocation`] — the revocation-plane mirror of
/// [`SignedIdentityOccurrence`] (v16.0.0, CIRISPersist#421; closes the
/// availability half #418 deferred).
///
/// An **unsigned, terminal** revocation on the wire is a permanent-DoS forgery:
/// any consented replication peer could fabricate `{identity: victim,
/// occurrence: victim}` and brick the victim's sealability forever
/// (`resolve_encryption_keys → None`, unrecoverable). This container carries the
/// same detached-signature discipline as the occurrence: the signature is over
/// `JCS(signed_envelope)` (the producer's EXACT revocation envelope — persist
/// never re-canonicalizes, §0.9), verified at
/// [`put_identity_occurrence_revocation`](crate::federation::FederationDirectory::put_identity_occurrence_revocation)
/// BEFORE any write, with the #418 `signer_acts_for` + divergent-typed-projection
/// rejection. Terminality is retired in the same cut:
/// [`resolve_encryption_keys`](crate::federation::FederationDirectory::resolve_encryption_keys)
/// lets a strictly-newer signed occurrence re-establish (publish → rotate →
/// revoke → re-establish, every transition authenticated and recoverable).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedIdentityOccurrenceRevocation {
    /// Persist's typed projection of the revocation (what gets stored). Its
    /// members are parsed FROM [`Self::signed_envelope`]; the signature is
    /// verified over `signed_envelope`, not over this projection, so the §0.9
    /// member-presence discipline is preserved.
    pub identity_occurrence_revocation: IdentityOccurrenceRevocation,
    /// The claimed signer — a `federation_keys.key_id`. MUST be the identity's
    /// own registered key or an already-ACTIVE occurrence of the same identity
    /// (`signer_acts_for` — the §11.7.4 single-vouch-for-self, enforced).
    pub attesting_key_id: String,
    /// The EXACT revocation envelope the producer signed (signature container
    /// stripped), as received — the bytes the gate JCS-canonicalizes.
    /// Byte-exact by construction (never rebuilt from the typed projection).
    pub signed_envelope: serde_json::Value,
    /// The detached hybrid signature over `JCS(signed_envelope)` (Ed25519 over
    /// the bytes; ML-DSA-65 over `bytes ‖ ed25519_sig`). Same container type as
    /// the occurrence — the producer is the same envelope-generic
    /// `produce_signed_identity_occurrence`.
    pub signature: ciris_verify_core::transport_binding::TransportBindingSignature,
}

/// Removes one identity from a V059 family roster. The family's
/// `members` roster is left intact; the active-membership read filters
/// against this table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyMembershipRevocation {
    /// The family's `federation_keys.key_id`.
    pub family_key_id: String,
    /// The removed member's identity `federation_keys.key_id`.
    pub removed_identity_key_id: String,
    /// When the removal ceremony issued it (RFC-3339 per §0.5).
    pub removed_at: DateTime<Utc>,
    /// When the removal takes effect. Active-state filter:
    /// `effective_at <= now()`.
    pub effective_at: DateTime<Utc>,
    /// Optional operator/ceremony annotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Vouch set — multi-vouch per the family's `consensus_protocol`
    /// (Registry-validated, CIRISRegistry#52 Ask 2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_set: Vec<String>,
    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
}

impl FamilyMembershipRevocation {
    /// v21.0.0 (CIRISPersist#502 E4) — the canonical envelope an authority
    /// signs to admit this removal: this record's own JSON with
    /// `persist_row_hash` stripped. Synthesized (no pre-existing envelope
    /// form) — see [`Family::signing_envelope`]. THE load-bearing gate:
    /// before this, a removal admitted on FK-existence alone, so any linked
    /// peer could forge `{family_key_id: victim-family, removed_identity_key_id:
    /// victim-member}` — a targeted de-family DoS.
    pub fn signing_envelope(&self) -> serde_json::Value {
        let mut v =
            serde_json::to_value(self).expect("FamilyMembershipRevocation always serializes");
        if let Some(obj) = v.as_object_mut() {
            obj.remove("persist_row_hash");
        }
        v
    }
}

/// Wraps a [`FamilyMembershipRevocation`] for write submission.
///
/// v21.0.0 (CIRISPersist#502 E4) — authority-signature fields, structural
/// mirror of [`SignedFamily`]'s. `put_family_membership_revocation`
/// hybrid-Strict-verifies `scrub_signature_{classical,pqc}` over
/// [`FamilyMembershipRevocation::signing_envelope`] against
/// `authority_key_id`'s REGISTERED pubkeys
/// (`verify_family_membership_revocation_admission`) before any write.
/// Additive (`#[serde(default)]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedFamilyMembershipRevocation {
    /// The revocation being submitted.
    pub family_membership_revocation: FamilyMembershipRevocation,
    /// The claimed authority — a `federation_keys.key_id` whose REGISTERED
    /// pubkeys the scrub signature below must verify against.
    #[serde(default)]
    pub authority_key_id: String,
    /// Ed25519 signature (base64) over
    /// `JCS(FamilyMembershipRevocation::signing_envelope())`.
    #[serde(default)]
    pub scrub_signature_classical: String,
    /// ML-DSA-65 signature (base64) over the bound payload
    /// `canonical ‖ ed25519_sig`. `None` ⇒ hybrid-Strict verify rejects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
}

/// Removes one identity from a V060 community roster. Structural mirror
/// of [`FamilyMembershipRevocation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityMembershipRevocation {
    /// The community's `federation_keys.key_id`.
    pub community_key_id: String,
    /// The removed member's identity `federation_keys.key_id`.
    pub removed_identity_key_id: String,
    /// When the removal ceremony issued it (RFC-3339 per §0.5).
    pub removed_at: DateTime<Utc>,
    /// When the removal takes effect. Active-state filter:
    /// `effective_at <= now()`.
    pub effective_at: DateTime<Utc>,
    /// Optional operator/ceremony annotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Vouch set — multi-vouch per the community's `consensus_protocol`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_set: Vec<String>,
    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
}

impl CommunityMembershipRevocation {
    /// v21.0.0 (CIRISPersist#502 E4) — the canonical envelope an authority
    /// signs to admit this removal. Synthesized, same construction as
    /// [`FamilyMembershipRevocation::signing_envelope`]. THE worst-case E4
    /// hole: a forged community-membership removal rotates the CC 4.4.3.2.2
    /// community DEK epoch on write — an unauthenticated forward-secrecy DoS
    /// (every future community write re-keys away from the real members too).
    pub fn signing_envelope(&self) -> serde_json::Value {
        let mut v =
            serde_json::to_value(self).expect("CommunityMembershipRevocation always serializes");
        if let Some(obj) = v.as_object_mut() {
            obj.remove("persist_row_hash");
        }
        v
    }
}

/// Wraps a [`CommunityMembershipRevocation`] for write submission.
///
/// v21.0.0 (CIRISPersist#502 E4) — authority-signature fields, structural
/// mirror of [`SignedFamilyMembershipRevocation`]'s.
/// `put_community_membership_revocation` hybrid-Strict-verifies
/// `scrub_signature_{classical,pqc}` over
/// [`CommunityMembershipRevocation::signing_envelope`] against
/// `authority_key_id`'s REGISTERED pubkeys
/// (`verify_community_membership_revocation_admission`) before any write —
/// BEFORE the CC 4.4.3.2.2 DEK epoch bump. Additive (`#[serde(default)]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCommunityMembershipRevocation {
    /// The revocation being submitted.
    pub community_membership_revocation: CommunityMembershipRevocation,
    /// The claimed authority — a `federation_keys.key_id` whose REGISTERED
    /// pubkeys the scrub signature below must verify against.
    #[serde(default)]
    pub authority_key_id: String,
    /// Ed25519 signature (base64) over
    /// `JCS(CommunityMembershipRevocation::signing_envelope())`.
    #[serde(default)]
    pub scrub_signature_classical: String,
    /// ML-DSA-65 signature (base64) over the bound payload
    /// `canonical ‖ ed25519_sig`. `None` ⇒ hybrid-Strict verify rejects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
}

/// v4.10.0 (CIRISPersist#154, CEG 0.8 §5.6.8.11 / §0.8.1) — a subject's
/// coarse geographic claim. The §0.8.1-normative privacy primitive:
/// `cell_resolution` is bounded to **≤ 7** ("rough-only") at admission
/// (see [`crate::federation::location::validate_location_cell`]) so the
/// substrate refuses an over-precise claim even if client UI gating
/// fails. Append-only; `withdrawn_at` marks a proof no longer in force.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocationProof {
    /// The subject's `federation_keys.key_id`.
    pub subject_key_id: String,
    /// H3 cell index, lowercase hex (§0.8). Canonical form + validity +
    /// resolution-redundancy are admission-gate enforced.
    pub cell_id: String,
    /// H3 resolution (0-15). The §0.8.1 gate rejects `> 7` at admission.
    pub cell_resolution: u8,
    /// When the proof was asserted (RFC-3339 per §0.5).
    pub asserted_at: DateTime<Utc>,
    /// When the proof expires. `None` = indefinite.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    /// Optional hardware attestation blob (TPM / Secure Enclave /
    /// StrongBox) backing the claim. `None` for software-only proofs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_evidence: Option<Vec<u8>>,
    /// `None` = currently in force; set = withdrawn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawn_at: Option<DateTime<Utc>>,
    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
}

impl LocationProof {
    /// v21.0.0 (CIRISPersist#502 E4) — the canonical envelope an authority
    /// signs to admit this claim. Synthesized (no pre-existing envelope
    /// form) — same construction as [`Family::signing_envelope`].
    pub fn signing_envelope(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).expect("LocationProof always serializes");
        if let Some(obj) = v.as_object_mut() {
            obj.remove("persist_row_hash");
        }
        v
    }
}

/// Wraps a [`LocationProof`] for write submission.
///
/// v21.0.0 (CIRISPersist#502 E4) — authority-signature fields, structural
/// mirror of [`SignedFamily`]'s. `put_location_proof` hybrid-Strict-verifies
/// `scrub_signature_{classical,pqc}` over [`LocationProof::signing_envelope`]
/// against `authority_key_id`'s REGISTERED pubkeys
/// (`verify_location_proof_admission`) before any write. Additive
/// (`#[serde(default)]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLocationProof {
    /// The location proof being submitted.
    pub location_proof: LocationProof,
    /// The claimed authority — a `federation_keys.key_id` whose REGISTERED
    /// pubkeys the scrub signature below must verify against. Typically the
    /// subject itself (`location_proof.subject_key_id`), but not enforced to
    /// be — E4 closes "no signature at all", not "which identity may assert
    /// a location for this subject" (a broader policy layer, out of scope).
    #[serde(default)]
    pub authority_key_id: String,
    /// Ed25519 signature (base64) over `JCS(LocationProof::signing_envelope())`.
    #[serde(default)]
    pub scrub_signature_classical: String,
    /// ML-DSA-65 signature (base64) over the bound payload
    /// `canonical ‖ ed25519_sig`. `None` ⇒ hybrid-Strict verify rejects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
}

/// One hybrid-pending federation row — minimum fields the sweep
/// needs to recompute the cold-path bound-signature input. Returned
/// by [`super::FederationDirectory::list_hybrid_pending_keys`] /
/// `_attestations` / `_revocations` (CIRISPersist#11, v0.3.2).
///
/// `id` is the row's primary key (`key_id` for `federation_keys`,
/// `attestation_id` / `revocation_id` for the others). `envelope` is
/// the JSONB column the original Ed25519 signature was computed over
/// — canonical bytes are recomputed via
/// `PythonJsonDumpsCanonicalizer::canonicalize_value` to feed the
/// bound-signature input. `classical_sig_b64` is the base64-encoded
/// Ed25519 signature that PQC will sign over alongside the canonical
/// bytes per the bound-signature contract.
#[derive(Debug, Clone, PartialEq)]
pub struct HybridPendingRow {
    /// Primary key of the hybrid-pending row.
    pub id: String,
    /// JSONB envelope the row's classical signature was computed over.
    pub envelope: serde_json::Value,
    /// Base64-encoded Ed25519 signature stored on the row.
    pub classical_sig_b64: String,
}

/// Wraps a [`KeyRecord`] payload that the caller has signed but
/// persist has not yet stored. Persist verifies the scrub-signature
/// on receipt before writing. The wrapper exists so write-path
/// signatures match read-path shapes (which include `persist_row_hash`
/// populated by persist) without forcing callers to compute that hash
/// themselves. On `put_public_key`, persist ignores the caller's
/// `persist_row_hash` field and computes its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedKeyRecord {
    /// The record being submitted. `persist_row_hash` is ignored on
    /// write — persist computes its own.
    pub record: KeyRecord,
}

/// Wraps an [`Attestation`] payload for write submission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedAttestation {
    /// The attestation being submitted.
    pub attestation: Attestation,
}

/// Wraps a [`Revocation`] payload for write submission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedRevocation {
    /// The revocation being submitted.
    pub revocation: Revocation,
}

// ─── Freshness floor (v21.6.0, CIRISPersist#519 item 2a-iii) ───────
//
// `namespace_supersets.json` § `freshness_floor`: a SIGNED temporal LOWER
// bound — "this object was demonstrably alive no earlier than T" — the
// dual of the existing upper bounds (`valid_until` / `expires_at` /
// `deletion_window`). See [`crate::federation::freshness`] for the merge
// semantics (monotonic max) and [`crate::federation::admission::verify_signed_touch_claim`]
// / [`crate::federation::admission::verify_touch_claim_admission`] for the
// admission gate. The existing gap this closes: persist already has
// `last_seen_at` (e.g. [`crate::federation::self_at_login::TransportDestination::last_seen_at`]),
// but that field is advisory liveness, not signed material — `fresh_as_of`
// is its SIGNED successor, not a duplicate.

/// Which signer attested a [`SignedTouchClaim`]'s `fresh_as_of` — the
/// closed set `namespace_supersets.json` § `freshness_floor.signer_forms`
/// names. Not merely descriptive: [`crate::federation::admission::verify_signed_touch_claim`]
/// enforces a DIFFERENT signer-target relationship per variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerForm {
    /// The touched target's own clock / dead-man's-switch: the attester IS
    /// the `target_key_id` (or a registered occurrence of it —
    /// `signer_acts_for`). "I am still here."
    SelfTouch,
    /// An independent witness's clock: the attester is REQUIRED to differ
    /// from the touched target (a witness cannot be the thing it
    /// witnesses). "I observed this target alive."
    WitnessTouch,
    /// Collusion-resistant: intended to require m-of-n independent
    /// co-signers (e.g. escalating a `self_touch` to a death finding on an
    /// `ownership:*` binding). **This cut's wire shape carries a single
    /// `attesting_key_id` + one [`ciris_verify_core::transport_binding::TransportBindingSignature`]**
    /// (mirroring [`super::self_at_login::SignedTransportDestination`]
    /// exactly), so admission currently verifies this identically to
    /// `WitnessTouch` (1-of-1, independent of the target) — real m-of-n
    /// tallying needs a multi-signer envelope shape and is a documented
    /// follow-up, not built here.
    NOfMCosigned,
}

impl SignerForm {
    /// Stable wire token (`"self_touch"` / `"witness_touch"` /
    /// `"n_of_m_cosigned"`) for the TEXT column and the signed envelope —
    /// same shape as [`crate::federation::self_at_login::BindingProvenance::as_str`].
    pub fn as_str(&self) -> &'static str {
        match self {
            SignerForm::SelfTouch => "self_touch",
            SignerForm::WitnessTouch => "witness_touch",
            SignerForm::NOfMCosigned => "n_of_m_cosigned",
        }
    }

    /// Parse from the stored/wire token. Unlike
    /// [`crate::federation::self_at_login::BindingProvenance::from_token`], there is no
    /// back-compat default here — `signer_form` is a brand-new REQUIRED
    /// field, so an unrecognized token is a hard read-time error (data
    /// corruption), not a silent fallback.
    pub fn from_token(s: &str) -> Option<Self> {
        match s {
            "self_touch" => Some(SignerForm::SelfTouch),
            "witness_touch" => Some(SignerForm::WitnessTouch),
            "n_of_m_cosigned" => Some(SignerForm::NOfMCosigned),
            _ => None,
        }
    }
}

/// A SIGNED touch-claim: the producer-side attestation that
/// `(target_key_id, target_kind)` was demonstrably alive no earlier than
/// `fresh_as_of` (`namespace_supersets.json` § `freshness_floor`).
/// **`now()` is not pure, so producing this value is an ATTESTATION, never
/// a transform opcode** — "reading emits a claim" is CEG-native here.
/// Persist stores + monotonic-max-merges these
/// ([`crate::federation::freshness`]); PRODUCING one (deciding which
/// `signer_form` to use, gathering witnesses/co-signers) is edge/agent's
/// job, documented for adoption, not built here.
///
/// Mirrors [`crate::federation::self_at_login::SignedTransportDestination`]'s hybrid-sig
/// shape exactly: `signed_envelope` is the EXACT bytes the producer
/// signed (as received — authority is the envelope, never the typed
/// projection, the #418 discipline), and `signature` is the same detached
/// hybrid container.
///
/// **`cohort_scope` is MANDATORY, not optional (§4 of the #519 item
/// 2a-iii brief):** touch-claims are cohort-scoped and consent-gated — an
/// unrestricted read-receipt trail is an access-pattern surveillance
/// surface, and for the `trace:*` family (already the one recipient-gated
/// family) it would leak exactly who is reading whose reasoning. Validated
/// at admission via [`crate::federation::admission::check_cohort_scope`].
/// A consumer of [`crate::federation::FederationDirectory::lookup_freshness_floor`]
/// MUST apply the same cohort/consent gating persist applies to any other
/// cohort-scoped read — this type does NOT expose a global read-receipt
/// trail on its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedTouchClaim {
    /// What's being kept alive — an `occurrence_key_id`, a canonical
    /// `key_id`, or any other object identifier the touch's consumer
    /// resolves via `target_kind`. NOT an FK (the freshness floor is
    /// deliberately generic across families — `ownership:*` / `trust:*` /
    /// `consent:*` / ...).
    pub target_key_id: String,
    /// The kind of thing `target_key_id` names (e.g. `"occurrence"`,
    /// `"canonical"`) — open vocab, resolved by the consumer.
    pub target_kind: String,
    /// The asserted LOWER bound: "alive no earlier than this instant."
    /// Merge is monotonic max ([`crate::federation::freshness`]) — this
    /// value only ever advances once stored.
    pub fresh_as_of: DateTime<Utc>,
    /// Which signer attested `fresh_as_of` — see [`SignerForm`].
    pub signer_form: SignerForm,
    /// The claimed signer — a `federation_keys.key_id`. The relationship
    /// this key must have to `target_key_id` depends on `signer_form` (see
    /// [`SignerForm`]'s variant docs); enforced by
    /// [`crate::federation::admission::verify_signed_touch_claim`].
    pub attesting_key_id: String,
    /// The EXACT envelope the producer signed (signature container
    /// stripped), as received. Byte-exact by construction (never rebuilt
    /// from the typed projection) — see [`Self::signing_envelope`] for the
    /// canonical CONSTRUCTION a producer (or this crate's test fixtures)
    /// builds before signing.
    pub signed_envelope: serde_json::Value,
    /// The detached hybrid signature over `JCS(signed_envelope)` (Ed25519
    /// over the bytes; ML-DSA-65 over `bytes ‖ ed25519_sig`) — the same
    /// container type [`crate::federation::self_at_login::SignedTransportDestination`] and the
    /// occurrence/revocation planes use.
    pub signature: ciris_verify_core::transport_binding::TransportBindingSignature,
    /// MANDATORY privacy row — see the struct-level docs. One of
    /// [`cohort_scope::SELF`] / [`cohort_scope::FAMILY`] /
    /// [`cohort_scope::COMMUNITY`] / [`cohort_scope::AFFILIATIONS`] /
    /// [`cohort_scope::SPECIES`] / [`cohort_scope::BIOSPHERE`] /
    /// [`cohort_scope::FEDERATION`] (validated at admission via
    /// [`crate::federation::admission::check_cohort_scope`]).
    pub cohort_scope: String,
}

impl SignedTouchClaim {
    /// The canonical envelope this claim's producer signs: `target_key_id`
    /// / `target_kind` / `fresh_as_of` (RFC-3339) / `signer_form` /
    /// `attesting_key_id` / `cohort_scope`. A producer (or this crate's
    /// `#[cfg(test)]` fixtures — see
    /// [`crate::federation::freshness::test_support`]) builds this,
    /// JCS-canonicalizes it, signs it, and puts the resulting value into
    /// [`Self::signed_envelope`] verbatim. Mirrors [`Family::signing_envelope`]:
    /// the admission gate never rebuilds the envelope from the typed
    /// fields, it only cross-checks equality (the §0.9 authority-is-the-
    /// envelope discipline).
    pub fn signing_envelope(&self) -> serde_json::Value {
        serde_json::json!({
            "target_key_id": self.target_key_id,
            "target_kind": self.target_kind,
            "fresh_as_of": self.fresh_as_of.to_rfc3339(),
            "signer_form": self.signer_form.as_str(),
            "attesting_key_id": self.attesting_key_id,
            "cohort_scope": self.cohort_scope,
        })
    }
}

// ─── Trust hierarchy (v1.3.0, CIRISPersist#46 + #47) ───────────────
//
// Persist absorbs NodeCore's `crate::trust` module surface at the
// M2 cut. See FSD TRUST_HIERARCHY.md §4.1 and the NodeCore
// `src/trust.rs` source (commit be82bd9) for the architectural
// rationale. Shapes mirror NodeCore exactly so NodeCore can
// replace its local placeholder trait definition with
// `pub use ciris_persist::federation::FederationDirectory` once
// this release ships.

/// Trust type axis. Mirrors CIRISAgent ConsentService taxonomy;
/// tracks CIRISAgent#760 §RC consent_role lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustType {
    /// Default. Most peer-to-peer agent-to-agent observations.
    Temporary,
    /// Bilateral approval (CIRISAgent#760 / LensCore ConsentService scope).
    Partnered,
    /// Anonymous trust grant.
    Anonymous,
}

impl TrustType {
    /// Wire-shaped string. Matches the federation_keys.trust_type
    /// CHECK constraint vocabulary.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Temporary => "temporary",
            Self::Partnered => "partnered",
            Self::Anonymous => "anonymous",
        }
    }

    /// Parse from the wire-shaped string. Returns `None` on
    /// vocabulary mismatch.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        Some(match s {
            "temporary" => Self::Temporary,
            "partnered" => Self::Partnered,
            "anonymous" => Self::Anonymous,
            _ => return None,
        })
    }
}

/// Trust relationship axis. New axis introduced by FSD
/// TRUST_HIERARCHY.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRelationship {
    /// Peer trust — `K_B` can act directly with the grantor.
    Direct,
    /// Vouching delegation — `K_B` can vouch for other keys within
    /// `trust_domains` only.
    Registry,
}

impl TrustRelationship {
    /// Wire-shaped string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Registry => "registry",
        }
    }

    /// Parse from the wire-shaped string.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        Some(match s {
            "direct" => Self::Direct,
            "registry" => Self::Registry,
            _ => return None,
        })
    }
}

/// A trust grant — what the grantor declared. The persist write
/// path materializes this into a row on `federation_keys` (UPSERT
/// on `key_id`, preserving the pubkey + signature envelope from the
/// prior `put_public_key`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGrant {
    /// Subject of the grant — the trusted key.
    pub key: String,
    /// Type axis.
    pub trust_type: TrustType,
    /// Relationship axis.
    pub trust_relationship: TrustRelationship,
    /// Domain scope. Required when `trust_relationship = Registry`;
    /// `None` for `Direct` grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domains: Option<Vec<String>>,
    /// Grantor key. Must differ from `key` per the
    /// `trusted_by != key` integrity rule (no self-trust).
    pub trusted_by: String,
    /// `None` = open-ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// A row from the directory — the grant + its `trusted_at`
/// timestamp. Returned by
/// [`super::FederationDirectory::lookup_trust`] and
/// [`super::FederationDirectory::list_trusted_keys`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustRow {
    /// Subject of the grant.
    pub key: String,
    /// Type axis.
    pub trust_type: TrustType,
    /// Relationship axis.
    pub trust_relationship: TrustRelationship,
    /// Domain scope (`Some` when relationship = Registry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domains: Option<Vec<String>>,
    /// Grantor key.
    pub trusted_by: String,
    /// When the grant was created.
    pub trusted_at: DateTime<Utc>,
    /// `None` = open-ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Filter for [`super::FederationDirectory::list_trusted_keys`].
/// All fields AND-composed; every field optional.
#[derive(Debug, Clone, Default)]
pub struct TrustFilter {
    /// Narrow by type axis.
    pub trust_type: Option<TrustType>,
    /// Narrow by relationship axis.
    pub trust_relationship: Option<TrustRelationship>,
    /// Narrow to registries vouching for `domain`. Only meaningful
    /// with `trust_relationship = Some(Registry)`.
    pub domain: Option<String>,
    /// If `false` (default), expired rows are filtered server-side
    /// via `WHERE expires_at IS NULL OR expires_at > NOW()`.
    pub include_expired: bool,
}

// ─── Peer metadata (v3.1.0, CIRISPersist#117) ──────────────────────
//
// The peer-mutation surface CIRISEdge v0.13.0 stubbed under UniFFI's
// `PEER_MUTATION_FOLLOWUP` constant lands here. Operator-local
// per-instance metadata (alias / trust / notes / policy / transport
// identity) — distinct from the federation-shared identity carried by
// `federation_keys` rows. See `migrations/postgres/lens/V051__*.sql`
// for the sibling-table architectural rationale.

/// Operator's trust class for a federation peer. Closed-set vocabulary
/// mirrored by the V051 `federation_peer_metadata.trust` CHECK
/// constraint via [`as_wire_str`](Self::as_wire_str) /
/// [`from_wire_str`](Self::from_wire_str) — same shape as
/// [`crate::store::VerificationSource`] (v2.0 CIRISPersist#91).
///
/// Default is [`Untrusted`](Self::Untrusted) — newly-added peers come
/// in unranked; the operator promotes via [`super::FederationDirectory
/// ::update_peer_trust`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    /// No trust claim yet. Default for newly-added peers.
    #[default]
    Untrusted,
    /// Operator has marked this peer as trusted.
    Trusted,
    /// Operator allows interaction under restrictions (e.g., read-
    /// only, throttled). Persist does not enforce the restrictions —
    /// that's a consumer-side composition.
    Restricted,
    /// Operator has blocked this peer. Persist still keeps the row
    /// (the block IS the operator-state we're persisting); consumers
    /// honor it.
    Blocked,
}

impl TrustClass {
    /// The TEXT-column wire form (`'untrusted'` / `'trusted'` /
    /// `'restricted'` / `'blocked'`). Matches the V051 CHECK-constraint
    /// value set.
    pub fn as_wire_str(self) -> &'static str {
        match self {
            TrustClass::Untrusted => "untrusted",
            TrustClass::Trusted => "trusted",
            TrustClass::Restricted => "restricted",
            TrustClass::Blocked => "blocked",
        }
    }

    /// Parse the TEXT-column wire form. `None` for any value outside
    /// the closed set — the caller surfaces it as a backend decode
    /// error (the DB CHECK constraint should make this unreachable on
    /// reads, but writes via [`update_peer_trust`](super::
    /// FederationDirectory::update_peer_trust) use the typed variant
    /// directly).
    pub fn from_wire_str(s: &str) -> Option<Self> {
        match s {
            "untrusted" => Some(TrustClass::Untrusted),
            "trusted" => Some(TrustClass::Trusted),
            "restricted" => Some(TrustClass::Restricted),
            "blocked" => Some(TrustClass::Blocked),
            _ => None,
        }
    }
}

/// Opaque consumer-defined policy blob for a peer. Persist round-trips
/// the JSON verbatim; the shape is owned by CIRISEdge's UniFFI
/// `PeerPolicy` type. Stored as JSONB on Postgres + TEXT-as-JSON on
/// SQLite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerPolicyBlob(pub serde_json::Value);

impl PeerPolicyBlob {
    /// Construct a blob from a `serde_json::Value`.
    pub fn new(value: serde_json::Value) -> Self {
        Self(value)
    }

    /// Borrow the underlying JSON value.
    pub fn as_value(&self) -> &serde_json::Value {
        &self.0
    }

    /// Consume into the underlying JSON value.
    pub fn into_value(self) -> serde_json::Value {
        self.0
    }
}

/// `federation_peer_metadata` row — read shape.
///
/// Returned by reads through the peer-metadata surface (future
/// methods; the v3.1.0 cut ships writes only, mirroring the v0.2.0
/// federation_keys/_attestations write-only initial cut). The row
/// carries `persist_row_hash` populated server-side via
/// [`compute_persist_row_hash`] over the rest of the row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerMetadataRow {
    /// FK to `federation_keys.key_id`.
    pub key_id: String,
    /// Operator-local display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Operator's trust class.
    pub trust: TrustClass,
    /// Operator-local notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Opaque policy blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_blob: Option<PeerPolicyBlob>,
    /// Opaque transport identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_identity: Option<String>,
    /// Soft-remove marker. `None` = live row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_at: Option<DateTime<Utc>>,
    /// First insertion time.
    pub inserted_at: DateTime<Utc>,
    /// Last mutation time (bumped on every `update_*` call).
    pub updated_at: DateTime<Utc>,
    /// Server-computed canonical-bytes hash.
    pub persist_row_hash: String,
}

/// `announced_peers` row — the seeder-bridge read shape (v17.8.0,
/// CIRISPersist#469).
///
/// A **non-canonical, untrusted discovery bookmark** for a peer learned from a
/// self-consistent (but not directory-rooted) LAN announce. NOT a
/// `federation_keys` identity: it lives in its own table precisely so it is
/// invisible to every admission / quorum / rooting / authority path by
/// construction. The server projects it to
/// `LocalPeerState { canonical: false, trust: "unknown", last_seen, … }` for
/// `GET /v1/federation/peers` (CIRISEdge#362).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnouncedPeer {
    /// The announced occurrence `key_id`. NOT an FK — the whole point is
    /// this key is not (yet) in the directory.
    pub key_id: String,
    /// Ed25519 pubkey from the announce, base64 standard.
    pub pubkey_ed25519_base64: String,
    /// ML-DSA-65 pubkey when the announce carried the PQC half.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey_ml_dsa_65_base64: Option<String>,
    /// The identity_type the announce CLAIMED (`node` / `steward` / …).
    /// Advisory display data only — unverified, never an authority input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_identity_type: Option<String>,
    /// First time this key_id was announced.
    pub first_seen_at: DateTime<Utc>,
    /// Most recent announce (refreshed by every `record_announced_peer`).
    pub last_seen_at: DateTime<Utc>,
    /// How many announces have been recorded (liveness signal).
    pub announce_count: i64,
}

/// Compute the canonical-bytes hash for a row used for
/// `persist_row_hash`. Persist calls this server-side on every write
/// path so consumers don't have to.
///
/// Uses [`crate::verify::canonical::PythonJsonDumpsCanonicalizer`] —
/// the same shape persist uses for trace canonical bytes — over the
/// row's serde-default JSON representation **excluding** the
/// `persist_row_hash` field itself (else the hash would depend on
/// itself).
///
/// Returns the hex-encoded SHA-256 string.
pub fn compute_persist_row_hash<T: Serialize>(row: &T) -> Result<String, super::Error> {
    use crate::verify::canonical::{Canonicalizer, PythonJsonDumpsCanonicalizer};
    use sha2::{Digest, Sha256};

    // Serialize → Value → drop `persist_row_hash` field if present →
    // canonicalize → hash. Dropping `persist_row_hash` keeps the hash
    // stable across populate/depopulate cycles (read response carries
    // the field; write submission may or may not).
    //
    // v12.7.0 (CIRISPersist#365, CC 3.4.7.2 OQ-1): also drop
    // `consent_role`. It is a MUTABLE, overwrite-on-revoke operational
    // role marker — NOT part of the signed registration content — so it
    // MUST NOT enter the registration hash. Excluding it keeps
    // `persist_row_hash` byte-identical to CIRISRegistry's vendored
    // shape (which does not carry the field) and lets `set_consent_role`
    // overwrite the role without invalidating the hash.
    let mut value = serde_json::to_value(row)
        .map_err(|e| super::Error::Backend(format!("serialize for hash: {e}")))?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("persist_row_hash");
        obj.remove("consent_role");
    }
    let bytes = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&value)
        .map_err(|e| super::Error::Backend(format!("canonicalize for hash: {e}")))?;
    let digest = Sha256::digest(&bytes);
    Ok(hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// v23.0.0 (CIRISPersist#551 item 6) — the Rust field is
    /// `capability_roles`; the WIRE name is still `roles`.
    ///
    /// This is the guard on the rename, not a restatement of it. The field
    /// rides inside `registration_envelope`s that were signed with the key
    /// spelled `roles` and inside rows whose `persist_row_hash` was computed
    /// over that spelling. Emitting `capability_roles` would desync every
    /// stored row from the signature over it — #541's
    /// preserve-set≢verified-set class, at the scale of every deployment.
    /// So: both directions are asserted (a v22 row still parses; a v23 row
    /// still emits the v22 bytes), and the row hash is asserted UNCHANGED,
    /// which is the property that actually protects the signatures.
    #[test]
    fn capability_roles_keeps_the_frozen_wire_name_551() {
        let json = serde_json::json!({
            "key_id": "k1",
            "pubkey_ed25519_base64": "AAAA",
            "algorithm": "hybrid",
            "identity_ref": "k1",
            "identity_type": "node",
            "valid_from": "2026-05-01T00:00:00Z",
            "registration_envelope": {"id": "k1"},
            "original_content_hash": "de",
            "scrub_signature_classical": "c2ln",
            "scrub_key_id": "k1",
            "scrub_timestamp": "2026-05-01T00:00:00Z",
            "persist_row_hash": "",
            "roles": ["cirislens_secrets_reader"],
        });
        // A pre-v23 row deserializes into the renamed field.
        let rec: KeyRecord = serde_json::from_value(json.clone()).expect("v22 wire parses");
        assert_eq!(rec.capability_roles, vec!["cirislens_secrets_reader"]);

        // …and re-serializes to the SAME key. `capability_roles` must not
        // appear on the wire anywhere.
        let out = serde_json::to_value(&rec).expect("serialize");
        assert_eq!(
            out.get("roles").and_then(|v| v.as_array()).map(Vec::len),
            Some(1),
            "the wire name `roles` is frozen: {out}"
        );
        assert!(
            out.get("capability_roles").is_none(),
            "the Rust name must never reach the wire: {out}"
        );

        // The signature-bearing property: the row hash is computed over the
        // frozen spelling, so it is unchanged by the rename.
        let hashed = compute_persist_row_hash(&rec).expect("row hash");
        let from_wire: serde_json::Value = serde_json::from_value(json).expect("value");
        assert_eq!(
            hashed,
            compute_persist_row_hash(&from_wire).expect("row hash of raw wire"),
            "persist_row_hash must be identical whether computed from the typed row or the \
             raw v22 wire bytes — this is what keeps stored rows bound to their signatures"
        );
    }

    /// v21.3.0 (CIRISPersist#512) — `project_route` normalizes the projected
    /// row's `destination` to the column's ONE canonical encoding (lowercase
    /// hex of the raw dest hash — the #393 item-2 gate's probe dialect),
    /// while the binding itself keeps base64. Malformed base64 is a
    /// fail-closed error, never an empty/garbage destination row.
    #[test]
    fn project_route_normalizes_destination_to_hex_512() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let raw = [0xA5u8; 16];
        let tb = OccurrenceTransportBinding {
            reticulum_x25519_pubkey_base64: B64.encode([0x01u8; 32]),
            reticulum_ed25519_pubkey_base64: B64.encode([0x02u8; 32]),
            destination_hash_base64: B64.encode(raw),
            app_name: "ciris.federation".into(),
            aspects: vec!["announce".into()],
        };
        let route = tb
            .project_route("occ-1", "2026-07-26T00:00:00Z".parse().unwrap())
            .expect("valid base64 must project");
        assert_eq!(
            route.destination,
            hex::encode(raw),
            "canonical hex, the gate's dialect"
        );
        // The binding's own envelope field stays base64 (its verify gate
        // wants base64 there) — only the projected row normalizes.
        assert_eq!(tb.destination_hash_base64, B64.encode(raw));
    }

    /// The fail-closed half: a binding whose `destination_hash_base64` is
    /// not valid base64 must refuse to project (an unnormalizable
    /// destination row would silently never match any probe).
    #[test]
    fn project_route_rejects_malformed_base64_512() {
        let tb = OccurrenceTransportBinding {
            reticulum_x25519_pubkey_base64: "AAAA".into(),
            reticulum_ed25519_pubkey_base64: "AAAA".into(),
            destination_hash_base64: "!!not-base64!!".into(),
            app_name: "ciris.federation".into(),
            aspects: vec![],
        };
        let err = tb
            .project_route("occ-1", "2026-07-26T00:00:00Z".parse().unwrap())
            .expect_err("malformed base64 must fail closed");
        assert!(
            err.to_string().contains("destination_hash_base64"),
            "error names the offending field: {err}"
        );
    }

    /// v13.1.0 (CIRISPersist#381) — `KeyRecord::transport_hints` reads the
    /// accord-attested hints from the signed envelope: present → typed list,
    /// absent → `[]`, malformed → `[]` (read-side convenience, not a gate).
    #[test]
    fn key_record_transport_hints_read_from_envelope() {
        let mut r = KeyRecord {
            key_id: "n1".into(),
            pubkey_ed25519_base64: "AAAA".into(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: algorithm::HYBRID.into(),
            identity_type: identity_type::NODE.into(),
            identity_ref: "n1".into(),
            valid_from: "2026-07-05T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({
                "key_id": "n1",
                "transport_hints": [
                    { "kind": "ip", "destination": "108.61.242.236:4242" },
                    { "kind": "reticulum", "destination": "deadbeef" }
                ]
            }),
            original_content_hash: "h".into(),
            scrub_signature_classical: "s".into(),
            scrub_signature_pqc: None,
            scrub_key_id: "A1".into(),
            scrub_timestamp: "2026-07-05T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        let hints = r.transport_hints();
        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].kind, "ip");
        assert_eq!(hints[0].destination, "108.61.242.236:4242");
        assert_eq!(hints[1].kind, "reticulum");

        // Absent → empty (optional field; ordinary/pre-#381 records).
        r.registration_envelope = serde_json::json!({ "key_id": "n1" });
        assert!(r.transport_hints().is_empty());

        // Malformed → empty (not an error on the read path).
        r.registration_envelope = serde_json::json!({ "transport_hints": "not-a-list" });
        assert!(r.transport_hints().is_empty());

        // v17.0.0 (#441) — `claims_role` evaluates BOTH role surfaces: the
        // identity_type set (scalar or comma-joined) and the roles vector.
        r.identity_type = "node".into();
        r.capability_roles = Vec::new();
        assert!(r.claims_role("node"));
        assert!(!r.claims_role("canonical"));
        r.identity_type = "canonical,node".into();
        assert!(r.claims_role("canonical"), "comma-set membership claims");
        r.identity_type = "node".into();
        r.capability_roles = vec!["agent".into(), "canonical".into()];
        assert!(r.claims_role("canonical"), "roles-vector membership claims");
        assert!(r.claims_role("agent"));
        assert!(!r.claims_role("registry"));
    }

    /// v13.2.0 (CIRISPersist#383) — the additive `additional_scrubs` field is
    /// **byte-invisible when empty**: it `skip_serializing_if = "Vec::is_empty"`
    /// so an ordinary / single-scrub record serializes WITHOUT the key and its
    /// `persist_row_hash` is byte-identical to the pre-#383 shape. A real 2-scrub
    /// set is included → its own distinct hash. Also exercises the
    /// `scrubs()` / `distinct_scrub_count()` helpers + ScrubSig serde round-trip.
    #[test]
    fn additional_scrubs_empty_is_hash_stable_nonempty_changes_hash() {
        let base = KeyRecord {
            key_id: "canon-1".into(),
            pubkey_ed25519_base64: "AAAA".into(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: algorithm::HYBRID.into(),
            identity_type: "canonical,node".into(),
            identity_ref: "canon-1".into(),
            valid_from: "2026-07-05T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({ "key_id": "canon-1" }),
            original_content_hash: "h".into(),
            scrub_signature_classical: "sig1".into(),
            scrub_signature_pqc: Some("pqc1".into()),
            scrub_key_id: "A1".into(),
            scrub_timestamp: "2026-07-05T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };

        // Empty set → the field serializes away entirely (byte-invisible).
        let json = serde_json::to_value(&base).unwrap();
        assert!(
            json.get("additional_scrubs").is_none(),
            "empty additional_scrubs must NOT appear on the wire"
        );

        // scrubs()/distinct_scrub_count() over the base (single-scrub) record.
        assert_eq!(base.scrubs().len(), 1);
        assert_eq!(base.distinct_scrub_count(), 1);

        // The hash of an empty-additional_scrubs record equals the hash of a
        // genuinely pre-#383 value — one whose JSON never carried the key.
        // `compute_persist_row_hash` is generic over Serialize, so we feed it a
        // `serde_json::Value` with the key removed; because skip_serializing_if
        // dropped it from the real record too, the two hashes match.
        let h_empty = compute_persist_row_hash(&base).unwrap();
        let mut pre383 = serde_json::to_value(&base).unwrap();
        assert!(
            pre383
                .as_object_mut()
                .unwrap()
                .remove("additional_scrubs")
                .is_none(),
            "the empty field was already absent from the serialized form"
        );
        assert_eq!(
            h_empty,
            compute_persist_row_hash(&pre383).unwrap(),
            "empty additional_scrubs → persist_row_hash byte-identical to pre-#383"
        );

        // A real 2-scrub record: scrub #2 rides additional_scrubs. The set is
        // now non-empty → included in the hash → a DISTINCT value.
        let mut two = base.clone();
        two.additional_scrubs = vec![ScrubSig {
            scrub_key_id: "B1".into(),
            scrub_signature_classical: "sig2".into(),
            scrub_signature_pqc: Some("pqc2".into()),
        }];
        let json2 = serde_json::to_value(&two).unwrap();
        assert!(
            json2.get("additional_scrubs").is_some(),
            "a non-empty scrub set MUST appear on the wire"
        );
        assert_eq!(two.scrubs().len(), 2, "scrub #1 + one additional");
        assert_eq!(two.distinct_scrub_count(), 2, "A1 + B1 distinct");
        assert_ne!(
            compute_persist_row_hash(&two).unwrap(),
            h_empty,
            "a real 2-scrub set must change the persist_row_hash"
        );

        // ScrubSig + additional_scrubs serde round-trip.
        let round: KeyRecord = serde_json::from_str(&serde_json::to_string(&two).unwrap()).unwrap();
        assert_eq!(round.additional_scrubs, two.additional_scrubs);
    }

    /// v12.7.0 (CIRISPersist#368) — the FFI wire contract for the
    /// witness-targets-subject age surface: `EmitAttestationInput` JSON
    /// (the exact `PyEngine::emit_attestation` / `emit_attestation_self`
    /// input) carries the optional `attested_key_id` naming the SUBJECT,
    /// and omitting it round-trips to `None` (the self-attestation
    /// default).
    #[test]
    fn emit_attestation_input_json_carries_attested_key_id_subject() {
        let with_subject: EmitAttestationInput = serde_json::from_str(
            r#"{
                "attestation_type": "age_assurance:government:adult:v1",
                "attested_key_id": "subject-key-1",
                "attestation_envelope": { "id": "wire-1" }
            }"#,
        )
        .expect("decode");
        assert_eq!(
            with_subject.attested_key_id.as_deref(),
            Some("subject-key-1")
        );
        assert_eq!(
            with_subject.attestation_type,
            "age_assurance:government:adult:v1"
        );
        // Round-trips (the field serializes back out when set).
        let json = serde_json::to_value(&with_subject).unwrap();
        assert_eq!(json["attested_key_id"], "subject-key-1");

        // Omitted ⇒ None ⇒ the emit path self-binds to the emitter (and the
        // `age_assurance:` admission gate then rejects the self-emission).
        let without: EmitAttestationInput = serde_json::from_str(
            r#"{
                "attestation_type": "age_assurance:provider:adult:v1",
                "attestation_envelope": { "id": "wire-2" }
            }"#,
        )
        .expect("decode");
        assert!(without.attested_key_id.is_none());
    }

    /// #249 Cut C — the producer-side moderate-scope tokens MUST equal the
    /// admission duty-walk's scope constants, or an emitted edge would not
    /// be admissible by `is_named_moderator` / `check_moderation_admission`.
    #[test]
    fn moderate_scope_tokens_match_the_admission_duty_walk() {
        assert_eq!(delegation_scope::SCOPE_MODERATE, "moderate");
        assert_eq!(delegation_scope::SCOPE_TAKEDOWN, "takedown");
        assert_eq!(delegation_scope::SCOPE_REVIEW, "review");
        // Aliased BY VALUE to the admission constants the walk matches.
        assert_eq!(
            delegation_scope::SCOPE_MODERATE,
            crate::federation::admission::DELEGATION_SCOPE_MODERATE
        );
        assert_eq!(
            delegation_scope::SCOPE_TAKEDOWN,
            crate::federation::admission::DELEGATION_SCOPE_TAKEDOWN
        );
        assert_eq!(
            delegation_scope::SCOPE_REVIEW,
            crate::federation::admission::DELEGATION_SCOPE_REVIEW
        );
        // #570 ask 2 — the removal duty joins the same alias discipline.
        assert_eq!(delegation_scope::SCOPE_SLASH, "slash");
        assert_eq!(
            delegation_scope::SCOPE_SLASH,
            crate::federation::admission::DELEGATION_SCOPE_SLASH
        );
        // …and is DISTINCT from all four emit duties — an authority to write
        // a note must never be readable as an authority to take something
        // away (the axis-fusion class: one name, two questions).
        for emit in [
            delegation_scope::SCOPE_MODERATE,
            delegation_scope::SCOPE_TAKEDOWN,
            delegation_scope::SCOPE_REVIEW,
            crate::federation::admission::DELEGATION_SCOPE_CONSENT_REVOCATION,
        ] {
            assert_ne!(delegation_scope::SCOPE_SLASH, emit);
        }
    }

    fn fixture_key_record() -> KeyRecord {
        KeyRecord {
            key_id: "persist-steward".into(),
            // Test fixture only — 32 zero bytes for Ed25519 placeholder.
            pubkey_ed25519_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            // Hybrid-complete fixture — both pubkeys + both sigs +
            // pqc_completed_at populated.
            pubkey_ml_dsa_65_base64: Some("AA".repeat(100)),
            algorithm: algorithm::HYBRID.into(),
            identity_type: identity_type::STEWARD.into(),
            identity_ref: "persist".into(),
            valid_from: DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
                .unwrap()
                .into(),
            valid_until: None,
            registration_envelope: serde_json::json!({"role": "persist-steward"}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJlX2NsYXNzaWNhbA==".into(),
            scrub_signature_pqc: Some("c2lnbmF0dXJlX3BxYw==".into()),
            scrub_key_id: "persist-steward".into(),
            scrub_timestamp: DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
                .unwrap()
                .into(),
            pqc_completed_at: Some(
                DateTime::parse_from_rfc3339("2026-05-01T00:00:01Z")
                    .unwrap()
                    .into(),
            ),
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// Hybrid-pending shape — Ed25519-only, PQC fields None. The
    /// soft-PQC write window per §"Trust contract" in
    /// FEDERATION_DIRECTORY.md.
    fn fixture_hybrid_pending() -> KeyRecord {
        KeyRecord {
            pubkey_ml_dsa_65_base64: None,
            scrub_signature_pqc: None,
            pqc_completed_at: None,
            ..fixture_key_record()
        }
    }

    #[test]
    fn pqc_complete_vs_pending() {
        assert!(fixture_key_record().is_pqc_complete());
        assert!(!fixture_key_record().is_pqc_pending());
        assert!(!fixture_hybrid_pending().is_pqc_complete());
        assert!(fixture_hybrid_pending().is_pqc_pending());
    }

    #[test]
    fn persist_row_hash_is_deterministic() {
        let row = fixture_key_record();
        let h1 = compute_persist_row_hash(&row).unwrap();
        let h2 = compute_persist_row_hash(&row).unwrap();
        assert_eq!(h1, h2, "hash must be deterministic across calls");
        assert_eq!(h1.len(), 64, "hex sha256 is 64 chars");
    }

    #[test]
    fn persist_row_hash_excludes_self() {
        // Two rows differing ONLY in their persist_row_hash field
        // should hash to the same value (the field excludes itself).
        let mut row1 = fixture_key_record();
        let mut row2 = fixture_key_record();
        row1.persist_row_hash = "before".into();
        row2.persist_row_hash = "after".into();
        assert_eq!(
            compute_persist_row_hash(&row1).unwrap(),
            compute_persist_row_hash(&row2).unwrap()
        );
    }

    #[test]
    fn persist_row_hash_changes_with_content() {
        let row1 = fixture_key_record();
        let mut row2 = fixture_key_record();
        row2.identity_ref = "different".into();
        assert_ne!(
            compute_persist_row_hash(&row1).unwrap(),
            compute_persist_row_hash(&row2).unwrap()
        );
    }

    #[test]
    fn key_record_serde_round_trip() {
        let row = fixture_key_record();
        let json = serde_json::to_string(&row).unwrap();
        let deser: KeyRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(row, deser);
    }

    /// v30.7.0 (CIRISPersist#625) — **the axis subsets PARTITION the union.**
    ///
    /// `ALL` and the three subsets serve different consumers and neither may
    /// re-derive the other: the validator needs the union, because `scope` is one
    /// wire field and any member is a legal value in it; a picker is always
    /// contextual, because the ACT determines the axis. Shipping only `ALL` makes
    /// every consumer partition it by prefix-matching and hardcoding the
    /// moderation four — and the next moderation scope is then missing from
    /// screens whose authors never knew a list existed. Shipping only the subsets
    /// makes the validator union them and drift the other way.
    ///
    /// So both are exported, and this asserts they cannot disagree: every member
    /// of `ALL` is in exactly one subset, and every subset member is in `ALL`.
    /// Without it, "the subsets partition the union" is a comment.
    #[test]
    fn delegation_scope_axes_partition_all() {
        use super::delegation_scope as ds;
        use std::collections::HashSet;

        let all: HashSet<&str> = ds::ALL.iter().copied().collect();
        assert_eq!(
            all.len(),
            ds::ALL.len(),
            "delegation_scope::ALL has duplicates"
        );

        let mut union: HashSet<&str> = HashSet::new();
        for (name, set) in [
            ("INFRA", ds::INFRA),
            ("AGENCY", ds::AGENCY),
            ("MODERATION", ds::MODERATION),
        ] {
            for v in set {
                assert!(
                    all.contains(v),
                    "{name} lists {v:?}, which is not in ALL — the union is not a union"
                );
                assert!(
                    union.insert(*v),
                    "{v:?} appears in more than one axis subset; the axes are meant to be disjoint \
                     (CC 4.4.3.4.3 makes infra/agency a real boundary, not a naming convention)"
                );
            }
        }

        let missing: Vec<&&str> = ds::ALL.iter().filter(|v| !union.contains(*v)).collect();
        assert!(
            missing.is_empty(),
            "scope(s) in ALL belong to no axis subset: {missing:?}. Every scope has an axis — add \
             it to INFRA, AGENCY or MODERATION, or say why a fourth axis exists."
        );

        // Non-vacuity: an empty or tiny set would satisfy everything above.
        assert!(ds::INFRA.len() >= 10 && ds::AGENCY.len() >= 4 && ds::MODERATION.len() >= 4);
    }

    /// v30.7.0 (CIRISPersist#625) — **every `delegation_scope` constant is either
    /// a member of `ALL` or a named non-member.**
    ///
    /// The picker requirement is no free-form entry, so `ALL` must be complete.
    /// Completeness by memory is not a plan: FOUR scopes were minted in
    /// v30.2.0–v30.4.0 alone (`infra:attest_assurance`, `infra:detect`,
    /// `infra:record_hard_case`, `infra:publish_rating`). A fifth that nobody
    /// adds to `ALL` is silently missing from every operator screen — a
    /// carried-but-unoffered gap, invisible from downstream.
    ///
    /// Non-members are NAMED with a reason rather than merely absent, so
    /// "not a scope value" is a recorded decision. The two prefixes are the
    /// live example: `INFRA_PREFIX` is `"infra:"`, and a mechanical glob would
    /// put it on a human's dropdown.
    #[test]
    fn every_delegation_scope_const_is_classified() {
        use super::delegation_scope as ds;
        let src = include_str!("types.rs");
        let module = src
            .split("pub mod delegation_scope {")
            .nth(1)
            .expect("delegation_scope module present")
            .split("\n}\n")
            .next()
            .expect("module body");

        let declared: Vec<String> = module
            .lines()
            .filter_map(|l| l.trim().strip_prefix("pub const "))
            .filter_map(|r| r.split(&[':', ' '][..]).next())
            .map(|n| n.to_owned())
            .collect();
        assert!(
            declared.len() >= 15,
            "parsed only {} consts from delegation_scope — the scan is broken, so this gate \
             proves nothing",
            declared.len()
        );

        let non_member: Vec<&str> = ds::NON_MEMBERS.iter().map(|(n, _)| *n).collect();
        let mut unclassified = Vec::new();
        for name in &declared {
            if non_member.contains(&name.as_str()) {
                continue;
            }
            // A member's VALUE must appear in ALL. Comparing values rather than
            // names keeps the re-exported `SCOPE_*` constants in scope.
            let value_in_all = match name.as_str() {
                "INFRA_SERVE" => ds::ALL.contains(&ds::INFRA_SERVE),
                "INFRA_STORE" => ds::ALL.contains(&ds::INFRA_STORE),
                "INFRA_TRANSPORT" => ds::ALL.contains(&ds::INFRA_TRANSPORT),
                "INFRA_ATTEST" => ds::ALL.contains(&ds::INFRA_ATTEST),
                "INFRA_NETWORK_PRESENCE" => ds::ALL.contains(&ds::INFRA_NETWORK_PRESENCE),
                "INFRA_HOLD_COMMUNITY_MEMBERSHIP" => {
                    ds::ALL.contains(&ds::INFRA_HOLD_COMMUNITY_MEMBERSHIP)
                }
                "INFRA_HOLD_FAMILY_MEMBERSHIP" => {
                    ds::ALL.contains(&ds::INFRA_HOLD_FAMILY_MEMBERSHIP)
                }
                "INFRA_ATTEST_ASSURANCE" => ds::ALL.contains(&ds::INFRA_ATTEST_ASSURANCE),
                "INFRA_DETECT" => ds::ALL.contains(&ds::INFRA_DETECT),
                "INFRA_RECORD_HARD_CASE" => ds::ALL.contains(&ds::INFRA_RECORD_HARD_CASE),
                "INFRA_PUBLISH_RATING" => ds::ALL.contains(&ds::INFRA_PUBLISH_RATING),
                "AGENCY_ACT_ON_BEHALF" => ds::ALL.contains(&ds::AGENCY_ACT_ON_BEHALF),
                "AGENCY_MESSAGE_IO" => ds::ALL.contains(&ds::AGENCY_MESSAGE_IO),
                "AGENCY_REASON" => ds::ALL.contains(&ds::AGENCY_REASON),
                "AGENCY_DECIDE" => ds::ALL.contains(&ds::AGENCY_DECIDE),
                "SCOPE_MODERATE" => ds::ALL.contains(&ds::SCOPE_MODERATE),
                "SCOPE_TAKEDOWN" => ds::ALL.contains(&ds::SCOPE_TAKEDOWN),
                "SCOPE_REVIEW" => ds::ALL.contains(&ds::SCOPE_REVIEW),
                "SCOPE_SLASH" => ds::ALL.contains(&ds::SCOPE_SLASH),
                _ => false,
            };
            if !value_in_all {
                unclassified.push(name.clone());
            }
        }

        assert!(
            unclassified.is_empty(),
            "delegation_scope constant(s) are in neither ALL nor NON_MEMBERS: {unclassified:?}.\n\
             A scope missing from ALL is silently absent from every operator picker \
             (CIRISPersist#625). Add it to ALL, or to NON_MEMBERS with the reason it is not a \
             selectable value (a prefix, a set, …), and extend this test's match arm."
        );

        // ALL itself must hold no duplicates and no prefixes.
        let mut seen = std::collections::HashSet::new();
        for v in ds::ALL {
            assert!(seen.insert(*v), "delegation_scope::ALL lists {v:?} twice");
            assert!(
                *v != ds::INFRA_PREFIX && *v != ds::AGENCY_PREFIX,
                "delegation_scope::ALL contains the bare prefix {v:?} — not a selectable value"
            );
        }
    }
}
