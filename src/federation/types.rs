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
///   [`INFRA_JOIN_COMMUNITIES`], [`INFRA_SERVE`], [`INFRA_STORE`],
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

    /// `infra:network_presence` — be reachable / present on the network
    /// as the node (the infra realization of presence; cf. the legacy
    /// unprefixed `network_presence`).
    pub const INFRA_NETWORK_PRESENCE: &str = "infra:network_presence";
    /// `infra:join_communities` — participate in federation membership.
    pub const INFRA_JOIN_COMMUNITIES: &str = "infra:join_communities";
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
    /// v1.3.0 (CIRISPersist#46) — Per-row role tags. Determines what
    /// the key is authorized to do at the persist API boundary:
    /// `cirislens_pipeline_writer` gates `POST /api/v1/pipeline/ingest`;
    /// `cirislens_secrets_reader` / `_writer` / `_admin` gate the
    /// secrets routes. Empty default — pre-V020 rows + new rows that
    /// didn't declare roles deserialize to `vec![]`. The `#[serde(default)]`
    /// keeps the wire shape backward-compatible with v1.2.x writers
    /// that don't know about the field yet.
    #[serde(default)]
    pub roles: Vec<String>,
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
}

impl KeyRecord {
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
    /// metadata: which of the 4 admission rules admitted this
    /// withdraws.
    ///
    /// `Some(1)` — producer self-revocation (`issuer.key_id == T.attesting_key_id`).
    /// `Some(2)` — subject self-revocation (`issuer.key_id ∈ T.subject_key_ids`, CEG 0.6 NEW).
    /// `Some(3)` — `delegates_to` proxy chain with `consent_revocation` scope (CEG 0.6 NEW).
    /// `Some(4)` — `delegates_to` chain via any of 1-3.
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
    pub attestation_envelope: serde_json::Value,
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
        self.attestation_envelope
            .get("dimension")
            .and_then(|v| v.as_str())
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
            attestation_envelope: self.attestation_envelope,
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
            attestation_envelope: self.attestation_envelope,
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
    pub attestation_envelope: serde_json::Value,
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
    pub fn with_envelope(
        attestation_type: impl Into<String>,
        attestation_envelope: serde_json::Value,
    ) -> Self {
        Self {
            attestation_type: attestation_type.into(),
            attested_key_id: None,
            attestation_envelope,
            subject_key_ids: Vec::new(),
            cohort_scope: cohort_scope::FEDERATION.to_string(),
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

    /// True iff `s` parses into one of the canonical-kinds shapes:
    /// the three bare forms (`founder_only`, `unanimous`, `majority`),
    /// or one of the three prefixed forms with a non-empty tail
    /// (`quorum:{m}/{n}` where m, n parse as integers; `weighted:rubric`;
    /// `custom:id`). Returns false for empty strings, unprefixed
    /// names not in the bare set, and `quorum:` strings whose tail
    /// is not `{int}/{int}`.
    pub fn is_canonical_form(s: &str) -> bool {
        if matches!(s, FOUNDER_ONLY | UNANIMOUS | MAJORITY) {
            return true;
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
    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
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

/// Wraps an [`IdentityOccurrence`] payload for write submission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedIdentityOccurrence {
    /// The identity-occurrence binding being submitted.
    pub identity_occurrence: IdentityOccurrence,
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

/// Wraps a [`Family`] payload for write submission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedFamily {
    /// The family record being submitted.
    pub family: Family,
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

/// Wraps a [`Community`] payload for write submission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedCommunity {
    /// The community record being submitted.
    pub community: Community,
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

/// Wraps an [`IdentityOccurrenceRevocation`] for write submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedIdentityOccurrenceRevocation {
    /// The revocation being submitted.
    pub identity_occurrence_revocation: IdentityOccurrenceRevocation,
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

/// Wraps a [`FamilyMembershipRevocation`] for write submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedFamilyMembershipRevocation {
    /// The revocation being submitted.
    pub family_membership_revocation: FamilyMembershipRevocation,
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

/// Wraps a [`CommunityMembershipRevocation`] for write submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCommunityMembershipRevocation {
    /// The revocation being submitted.
    pub community_membership_revocation: CommunityMembershipRevocation,
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

/// Wraps a [`LocationProof`] for write submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLocationProof {
    /// The location proof being submitted.
    pub location_proof: LocationProof,
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
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
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
}
