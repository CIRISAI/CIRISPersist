//! v31.0.0 (CIRISPersist#648) — **the pre-genesis state, named.**
//!
//! 31.0.0 is the binary that RUNS the ceremony that produces the trust root it
//! will later be baked with. It therefore has to boot without one. Before this
//! cut the only seedless constructor was `with_signer_no_genesis_seed`, fenced
//! behind the `test-genesis-seam` cargo feature and absent from every release
//! build, so "a node that has not yet had its genesis ceremony" was a state the
//! substrate could reach only in a test binary.
//!
//! Making that state reachable is the easy half. The dangerous half is the one
//! this module exists for:
//!
//! # A node with no trust root must not become a node that checks nothing
//!
//! Absence of a root is not absence of a rule. The failure mode is specific and
//! it has bitten this substrate before (CIRISPersist#632, the duty-holder
//! resolver): a gate re-derives an authority set, the set comes back EMPTY
//! because nothing was ever seeded, and the emptiness is read as *nothing to
//! check* rather than *nothing to check WITH*. A strict majority of an empty
//! roster is zero, and zero-of-zero is trivially met.
//!
//! So the pre-genesis state is not a relaxation. It is a state in which every
//! gate that resolves authority to the constitutional root returns
//! [`Error::NoConstitutionalRootYet`](crate::federation::Error::NoConstitutionalRootYet)
//! — a typed refusal naming the operation and the missing leg, never a silent
//! pass. [`require_constitutional_root`] is the single chokepoint those gates
//! call, and [`ROOT_REQUIRING_GATES`] is the enumeration a witness iterates, so
//! "which gates fail closed" is a list in the crate rather than a claim in a
//! commit message.
//!
//! # Persist reports; it does not decide who may run
//!
//! The operator's rule is per-MODE, not per-node: **node mode** (no agent —
//! "brainless") boots without a valid trust root and shows a warning banner;
//! **agent mode** must not, and that refusal is enforced in CIRISServer. Persist
//! owns neither mode and this cut deliberately introduces no `node_mode` /
//! `agent_mode` concept here. What persist owes the layer above is an accurate,
//! fail-closed answer to *"does this node hold a constitutional trust root, and
//! if not, which leg is missing"* — [`GenesisPosture`], reachable from
//! [`Engine::genesis_posture`](crate::Engine::genesis_posture) and folded into
//! the operator read surface as
//! [`NodeState::genesis`](crate::federation::node_state::NodeState::genesis),
//! with [`GenesisPosture::banner`] carrying the line a node-mode host renders.
//!
//! # Absent is not the same as divergent, and only one of them is survivable
//!
//! [`GenesisFault`] splits what a single `Err(String)` used to fuse:
//!
//! - [`GenesisFault::Absent`] — the constitutional rows are simply NOT THERE.
//!   That is a node before its ceremony. Boot proceeds; the gates refuse.
//! - [`GenesisFault::Divergent`] — a constitutional row IS there and is WRONG:
//!   a squatted holder `key_id` carrying a different pubkey, a family whose
//!   entrenched protocol or founder seats were mutated, a canonical that lost
//!   its role. That is tampering with an established root, and boot still
//!   REFUSES it. Trust roots co-exist — a new ceremony ADDS one — but nothing
//!   here may become a path to MUTATING one that already stands.
//! - [`GenesisFault::Unreadable`] — the backend could not be asked. Not
//!   entrenched, because a question that could not be answered is not a yes.

use super::super::{Error, FederationDirectory};
use serde::{Deserialize, Serialize};

/// v31.0.0 (CIRISPersist#648) — WHICH leg of the constitutional seed a fault is
/// about. Three legs, in the order [`seed_family_and_canonical`](super::seed_family_and_canonical)
/// establishes them, because a later leg cannot be judged before an earlier one
/// holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenesisLeg {
    /// The A1/B1/C1 accord-holder rooting-anchor `federation_keys` rows — the
    /// ROSTER every accord m-of-n is tallied against.
    Anchor,
    /// The keyless `humanity-accord` `federation_families` row — the
    /// THRESHOLD (`quorum:2/3`, entrenched) those tallies are measured by.
    Family,
    /// The baked 2-of-3 canonical serve node(s). Reported, but deliberately
    /// **not** required by [`require_constitutional_root`]: the ceremony
    /// installs the canonical THROUGH the accord-conferral gate, so demanding
    /// it as a precondition of that gate would make the ceremony unable to
    /// establish the very leg it is establishing.
    Canonical,
    /// v31.0.0 (CIRISPersist#648) — the baked DELEGATION PLANE: the
    /// `genesis-charter` / `genesis-grant:…` / `genesis-lifecycle`
    /// `federation_attestations` rows. The roster says WHO, the family says HOW
    /// MANY, the canonical says WHERE — and this leg is the only one that says
    /// WHAT THE ROOT ACTUALLY CONFERS.
    ///
    /// Reported for the same reason `Canonical` is, and excluded from
    /// [`require_constitutional_root`] for the same reason it is: the ceremony
    /// installs these rows THROUGH the conferral gates, so demanding them as a
    /// precondition of those gates would stop the ceremony establishing the
    /// very leg it exists to establish.
    Delegation,
}

impl GenesisLeg {
    /// The stable program token — identical to the serde token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anchor => "anchor",
            Self::Family => "family",
            Self::Canonical => "canonical",
            Self::Delegation => "delegation",
        }
    }

    /// Every leg, in establishment order — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::Anchor,
        Self::Family,
        Self::Canonical,
        Self::Delegation,
    ];
}

impl std::fmt::Display for GenesisLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// v31.0.0 (CIRISPersist#648) — a constitutional-seed fault, classified by
/// whether the node can survive it.
///
/// The classification IS the security content. `Absent` and `Divergent` were
/// one `Err(String)` before this cut, which is why the seed had to be
/// unconditional: with no way to tell "never seeded" from "seeded and then
/// tampered with", the only safe response to either was to refuse to boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisFault {
    /// **Not installed.** A node before its genesis ceremony. Boot proceeds;
    /// every gate in [`ROOT_REQUIRING_GATES`] refuses.
    Absent {
        /// Which leg is missing.
        leg: GenesisLeg,
        /// The specific finding, for an operator.
        detail: String,
    },
    /// **Installed and WRONG.** A pinned holder `key_id` present with a
    /// different pubkey (anchor squatting), a family whose entrenchment or
    /// founder seats were mutated, a canonical stripped of its role. Boot
    /// REFUSES: this is not a node awaiting a ceremony, it is a node whose
    /// established root has been altered underneath it.
    Divergent {
        /// Which leg diverged.
        leg: GenesisLeg,
        /// The specific finding, for an operator.
        detail: String,
    },
    /// **The backend could not be asked.** Reported honestly rather than
    /// guessed — an unanswered question is not a yes, so this is never
    /// [`GenesisPosture::Entrenched`].
    Unreadable {
        /// Which leg could not be read.
        leg: GenesisLeg,
        /// The underlying backend complaint.
        detail: String,
    },
}

impl GenesisFault {
    /// Which leg this fault is about.
    #[must_use]
    pub const fn leg(&self) -> GenesisLeg {
        match self {
            Self::Absent { leg, .. }
            | Self::Divergent { leg, .. }
            | Self::Unreadable { leg, .. } => *leg,
        }
    }

    /// The stable program token for the CLASS of fault.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Absent { .. } => "absent",
            Self::Divergent { .. } => "divergent",
            Self::Unreadable { .. } => "unreadable",
        }
    }

    /// **Must this fault stop the node from booting?**
    ///
    /// Only [`Self::Divergent`] does. That is the whole delta of #648: a node
    /// that never had a root boots and refuses; a node whose root was ALTERED
    /// still does not boot.
    #[must_use]
    pub const fn refuses_boot(&self) -> bool {
        matches!(self, Self::Divergent { .. })
    }

    /// The finding text.
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::Absent { detail, .. }
            | Self::Divergent { detail, .. }
            | Self::Unreadable { detail, .. } => detail,
        }
    }

    /// Build an [`Self::Absent`].
    pub(crate) fn absent(leg: GenesisLeg, detail: impl Into<String>) -> Self {
        Self::Absent {
            leg,
            detail: detail.into(),
        }
    }

    /// Build a [`Self::Divergent`].
    pub(crate) fn divergent(leg: GenesisLeg, detail: impl Into<String>) -> Self {
        Self::Divergent {
            leg,
            detail: detail.into(),
        }
    }

    /// Build an [`Self::Unreadable`].
    pub(crate) fn unreadable(leg: GenesisLeg, detail: impl Into<String>) -> Self {
        Self::Unreadable {
            leg,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for GenesisFault {
    /// Renders `<class>(<leg>): <detail>` — the `detail` half is byte-identical
    /// to the pre-#648 `Err(String)` these replaced, so an operator grepping old
    /// logs still finds the same sentence.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}({}): {}",
            self.as_str(),
            self.leg().as_str(),
            self.detail()
        )
    }
}

impl std::error::Error for GenesisFault {}

/// v31.0.0 (CIRISPersist#648) — **does this node hold a constitutional trust
/// root, and if not, which leg is missing?**
///
/// A gauge for the layer above (CIRISServer renders the node-mode banner from
/// [`Self::banner`] and gates agent mode on [`Self::entrenched`]), and a gate
/// only through [`require_constitutional_root`], which consults the seat legs
/// rather than this whole value — see [`GenesisLeg::Canonical`] for why those
/// differ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GenesisPosture {
    /// Anchor, family and canonical all installed and non-divergent. The
    /// pre-#648 steady state.
    ///
    /// # v31.1.0 (CIRISPersist#665 review) — what this asserts about the
    /// DELEGATION plane got STRONGER
    ///
    /// Consumers gate on [`Self::entrenched`] (CIRISServer gates agent mode on
    /// it, CIRISAI/CIRISServer#398), so it is worth being exact about what
    /// changed underneath them. **The direction of the gate is unchanged — this
    /// arm is still the only green one — but what a node must be for it to hold
    /// has narrowed.**
    ///
    /// Until this cut, a booted node reached `Entrenched` when each delegation
    /// row's `original_content_hash` matched the baked artifact's. That digest
    /// covers the ENVELOPE alone, and the ceremony's signature covers the
    /// envelope and nothing else — so the columns AROUND it were unchecked by
    /// anything on the boot path. A row whose `scrub_signature_classical`, PQC
    /// half, or `additional_scrubs` quorum set had been rewritten beneath
    /// persist read as current and the node reported `Entrenched` while holding
    /// a `genesis-charter` that
    /// [`family_quorum_over`](crate::federation::trust_root) could no longer
    /// count to threshold — the trust root silently below quorum, the banner
    /// green.
    ///
    /// `seed_delegation_plane` now compares the stored row to the baked
    /// artifact WHOLE and restores the compiled-in bytes when only the unsigned
    /// material around a byte-identical signed envelope has been altered. So
    /// `Entrenched` now additionally asserts: **every baked delegation row is
    /// byte-whole against the artifact this binary carries, co-signatures
    /// included.** Strictly more than it asserted before, and nothing that was
    /// green stops being green except a node that was already lying.
    Entrenched,
    /// **PRE-GENESIS** — a leg is simply not installed. The node runs, reports,
    /// and can host its own genesis ceremony; every root-requiring gate
    /// refuses.
    PreGenesis {
        /// The first leg that is missing.
        leg: GenesisLeg,
        /// The specific finding.
        detail: String,
    },
    /// **TAMPERED** — a constitutional row is present and wrong. Never produced
    /// by a booted Engine (boot refuses on this arm); reachable from
    /// [`genesis_posture`] against a directory an operator is inspecting.
    Divergent {
        /// The leg that diverged.
        leg: GenesisLeg,
        /// The specific finding.
        detail: String,
    },
    /// The backend could not answer. Not entrenched.
    Unreadable {
        /// The leg that could not be read.
        leg: GenesisLeg,
        /// The backend complaint.
        detail: String,
    },
}

impl From<GenesisFault> for GenesisPosture {
    fn from(f: GenesisFault) -> Self {
        match f {
            GenesisFault::Absent { leg, detail } => Self::PreGenesis { leg, detail },
            GenesisFault::Divergent { leg, detail } => Self::Divergent { leg, detail },
            GenesisFault::Unreadable { leg, detail } => Self::Unreadable { leg, detail },
        }
    }
}

impl GenesisPosture {
    /// The stable program token — identical to the serde `state` tag.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Entrenched => "entrenched",
            Self::PreGenesis { .. } => "pre_genesis",
            Self::Divergent { .. } => "divergent",
            Self::Unreadable { .. } => "unreadable",
        }
    }

    /// Is the constitutional seed fully installed and sound?
    ///
    /// **True on exactly one arm.** `Unreadable` is false for the same reason
    /// [`StateBand::Unknown`](crate::federation::node_state::StateBand::Unknown)
    /// is not green: most failure modes on this plane are silent, and "no bad
    /// news" rendered as good news is how an unrooted node looks healthy right
    /// up until it does not.
    #[must_use]
    pub const fn entrenched(&self) -> bool {
        matches!(self, Self::Entrenched)
    }

    /// Which leg, when there is a fault.
    #[must_use]
    pub const fn leg(&self) -> Option<GenesisLeg> {
        match self {
            Self::Entrenched => None,
            Self::PreGenesis { leg, .. }
            | Self::Divergent { leg, .. }
            | Self::Unreadable { leg, .. } => Some(*leg),
        }
    }

    /// **The node-mode warning banner**, or `None` when the root is entrenched.
    ///
    /// Persist supplies the sentence; the host decides whether to render it and
    /// whether the mode it is running may run at all. That split is deliberate:
    /// the agent-mode refusal is CIRISServer's and this crate has no notion of
    /// which mode it is in.
    #[must_use]
    pub fn banner(&self) -> Option<String> {
        match self {
            Self::Entrenched => None,
            Self::PreGenesis { leg, detail } => Some(format!(
                "PRE-GENESIS: this node holds no constitutional trust root \
                 ({leg} leg: {detail}). It can host a genesis ceremony; until one \
                 completes, every operation that resolves authority to the accord \
                 root is refused. Do not run an agent against this node."
            )),
            Self::Divergent { leg, detail } => Some(format!(
                "CONSTITUTIONAL DIVERGENCE: this node's {leg} leg is present and \
                 WRONG ({detail}). This is not a node awaiting a ceremony — an \
                 established root has been altered. Do not serve."
            )),
            Self::Unreadable { leg, detail } => Some(format!(
                "TRUST ROOT UNREADABLE: this node cannot determine whether it holds \
                 a constitutional trust root ({leg} leg: {detail}). Treated as \
                 unrooted — every root-requiring operation is refused."
            )),
        }
    }
}

/// v31.0.0 (CIRISPersist#648) — the SEAT legs: the roster and the threshold.
///
/// The reporting predicate. [`genesis_posture`] extends it with
/// [`GenesisLeg::Canonical`]; [`require_constitutional_root`] narrows it to
/// [`accord_roster_seated`] alone. All three walk the same legs in the same
/// order, differing only in how far they get to before answering.
pub async fn constitutional_seat<D>(dir: &D) -> Result<(), GenesisFault>
where
    D: FederationDirectory + ?Sized,
{
    accord_roster_seated(dir).await?;
    super::verify_family_seeded(dir).await
}

/// v31.0.0 (CIRISPersist#648) — **the leg a conferral gate actually rests on**:
/// the baked A1/B1/C1 accord-holder rows, live and non-divergent.
///
/// The REPORTING form, used by [`constitutional_seat`] and [`genesis_posture`].
/// The gate form is [`require_seated_accord_roster`], which asks the same
/// question of whichever roster the calling gate is tallying against — see
/// there for why the two differ.
pub async fn accord_roster_seated<D>(dir: &D) -> Result<(), GenesisFault>
where
    D: FederationDirectory + ?Sized,
{
    super::verify_anchor_seeded(dir).await
}

/// v31.0.0 (CIRISPersist#648) — **the read-time posture**, re-derived from the
/// directory on every call rather than remembered from boot.
///
/// Recomputed rather than cached because the transition this issue exists for
/// happens WHILE the process runs: an operator boots 31.0.0 pre-genesis, runs
/// the ceremony against it, and the node is rooted without a restart. A posture
/// captured at construction would report `pre_genesis` forever and the banner
/// would outlive the condition it warns about.
///
/// Mirrors [`seed_family_and_canonical`](super::seed_family_and_canonical)'s
/// leg order and its test-anchor skip, so the posture cannot disagree with what
/// the seeder actually attempted.
pub async fn genesis_posture<D>(dir: &D) -> GenesisPosture
where
    D: FederationDirectory + ?Sized,
{
    if let Err(f) = constitutional_seat(dir).await {
        return f.into();
    }
    // #449 — under a live test-anchor override the baked 2-of-3 canonical is
    // not seedable by construction (its A1/B1 scrubs cannot verify against the
    // swapped SW roster), so the seeder skips it and the posture must skip it
    // too. Dead code on a prod build.
    if super::test_anchor_override_active() {
        return GenesisPosture::Entrenched;
    }
    if let Err(f) = super::verify_canonical_seeded(dir).await {
        return f.into();
    }
    // v31.0.0 (CIRISPersist#648) — the FOURTH leg, and the one 31.0.0 actually
    // fails. The three legs above are ALL the key plane, which the stale baked
    // seed still installs cleanly; only the delegation plane is refused by the
    // #643 mirror and #598 instant gates. Without this check a 31.0.0 node
    // reports `entrenched`, renders no banner, and a server enables agent mode
    // — on a root whose conferral rows can never be installed. A posture that
    // cannot see the plane conferring everything is not reporting on a trust
    // root; it is reporting on a key list.
    match super::verify_delegation_plane_seeded(dir).await {
        Ok(()) => GenesisPosture::Entrenched,
        Err(f) => f.into(),
    }
}

/// v31.0.0 (CIRISPersist#648) — **the enumerated fail-closed set.**
///
/// Every gate that resolves authority to the constitutional root and therefore
/// calls [`require_constitutional_root`]. It is a `const` and not prose because
/// the anti-fail-open witness iterates it: a gate added to the substrate without
/// being added here is a gate nothing proves refuses, and a gate listed here
/// that stops calling the chokepoint fails the same witness.
///
/// The tokens are the `operation` field of
/// [`Error::NoConstitutionalRootYet`](crate::federation::Error::NoConstitutionalRootYet).
/// | token | gate | what it confers |
/// |---|---|---|
/// | `canonical_role_admission` | `check_canonical_role_admission[_over_roster]` | the `canonical` founding-server role |
/// | `infra_attest_role_admission` | `check_infra_attest_role_admission[_over_roster]` | `infra:attest`, the build-manifest signing authority |
/// | `accord_role_admission` | `check_accord_role_admission_over_roster` | the role-generic conferral behind co-steward roles and the accord-co-scrubbed privileged identity types |
/// | `canonical_withdraw_authority` | `verify_canonical_withdraw_authority` / `..._supersede_authority` | the destructive canonical ops |
/// | `family_charter_admission` | `check_family_charter_admission` | a `trust:charter:v1` naming a constitutional family as its subject |
pub const ROOT_REQUIRING_GATES: &[&str] = &[
    CANONICAL_ROLE_ADMISSION,
    INFRA_ATTEST_ROLE_ADMISSION,
    ACCORD_ROLE_ADMISSION,
    CANONICAL_WITHDRAW_AUTHORITY,
    FAMILY_CHARTER_ADMISSION,
];

/// `operation` token — see [`ROOT_REQUIRING_GATES`].
pub const CANONICAL_ROLE_ADMISSION: &str = "canonical_role_admission";
/// `operation` token — see [`ROOT_REQUIRING_GATES`].
pub const INFRA_ATTEST_ROLE_ADMISSION: &str = "infra_attest_role_admission";
/// `operation` token — see [`ROOT_REQUIRING_GATES`].
pub const ACCORD_ROLE_ADMISSION: &str = "accord_role_admission";
/// `operation` token — see [`ROOT_REQUIRING_GATES`].
pub const CANONICAL_WITHDRAW_AUTHORITY: &str = "canonical_withdraw_authority";
/// `operation` token — see [`ROOT_REQUIRING_GATES`].
pub const FAMILY_CHARTER_ADMISSION: &str = "family_charter_admission";

/// v31.0.0 (CIRISPersist#648) — **the anti-fail-open chokepoint.**
///
/// Called at the head of every gate in [`ROOT_REQUIRING_GATES`], AFTER that
/// gate's own fast path (a row claiming no gated role must still register on a
/// pre-genesis node — otherwise the node could not register the identity that
/// runs the ceremony). Returns
/// [`Error::NoConstitutionalRootYet`](crate::federation::Error::NoConstitutionalRootYet)
/// when **not one seat of the roster this gate would tally against resolves in
/// this node's directory**.
///
/// # Over the roster the GATE uses, not the baked one
///
/// The check takes `roster_key_ids` — the very slice the calling gate is about
/// to hand
/// [`verify_accord_family_coscrub_with`](crate::federation::admission) — rather
/// than consulting [`accord_roster_seated`]. A gate that adjudicates against an
/// injected roster and a precondition that adjudicates against the baked one
/// are two rules about one decision, and they disagree exactly where it
/// matters: the `_over_roster` forms exist so a harness can supply holders it
/// can sign as, and the baked-anchor check calls those "anchor squatting". A
/// precondition that refuses what the gate would have admitted is not a
/// stricter gate, it is a second gate.
///
/// # Why the threshold is "at least one", and where the rest lives
///
/// This is the anti-EMPTY-SET rule, stated. The empty roster is the one whose
/// absence can invert from refusal into permission — a strict majority of nothing
/// is zero, and zero-of-zero is trivially met. A PARTIAL roster is a different
/// question with a different owner: `m = max(n/2 + 1, floor)` over the resolved
/// seats, plus the #513 hardware floor of three distinct FIPS-custodied
/// co-scrubbers for a new canonical. Re-deriving quorum arithmetic here would
/// fork it.
///
/// # Why this exists when the arithmetic already refuses
///
/// It is belt AND braces, and the belt is the interesting one.
/// `verify_accord_family_coscrub_with` does currently refuse an empty roster —
/// `m` floors at 1 while `n` is 0, and `m > n` is checked. That refusal is
/// INCIDENTAL: it survives only as long as nobody changes the floor to
/// `min(..)` or adds a gate that forgets the check. #632 was exactly a
/// set-derived authority whose emptiness inverted, and the lesson taken there
/// was that the refusal has to be stated, not implied.
///
/// It also gives an operator the right sentence. "accord family m-of-n not met
/// (1-of-0)" reads like a quorum shortfall and sends someone hunting for a
/// missing signature; `no_constitutional_root_yet` names the ceremony.
pub async fn require_seated_accord_roster<D>(
    dir: &D,
    operation: &'static str,
    roster_key_ids: &[String],
) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    let refuse = |fault_kind: &'static str, detail: String| Error::NoConstitutionalRootYet {
        operation,
        leg: GenesisLeg::Anchor,
        fault_kind,
        detail,
    };
    if roster_key_ids.is_empty() {
        return Err(refuse(
            "absent",
            "the accord-holder roster is empty before any lookup — there is no authority set \
             for this decision to be tallied against"
                .to_owned(),
        ));
    }
    for kid in roster_key_ids {
        match dir.lookup_public_key(kid).await {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {}
            // Honestly unknown, never guessed. A backend that cannot answer is
            // not a backend that answered yes.
            Err(e) => {
                return Err(refuse(
                    "unreadable",
                    format!("resolving accord holder {kid}: {e}"),
                ))
            }
        }
    }
    Err(refuse(
        "absent",
        format!(
            "not one of the {} declared accord-holder seat(s) resolves in this node's \
             directory, so there is no roster to tally a quorum against",
            roster_key_ids.len()
        ),
    ))
}

/// [`require_seated_accord_roster`] over the PRODUCTION accord-holder roster —
/// the wrapper the non-`_over_roster` gates use, mirroring how
/// [`check_canonical_role_admission`](crate::federation::admission::check_canonical_role_admission)
/// wraps its own `_over_roster` core.
pub async fn require_constitutional_root<D>(dir: &D, operation: &'static str) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    require_seated_accord_roster(
        dir,
        operation,
        &crate::federation::admission::accord_holder_roster_key_ids(),
    )
    .await
}

/// v31.0.0 (CIRISPersist#648) — **the anti-fail-open witness, on every
/// backend.**
///
/// The most important assertion in this cut and the one most likely to be got
/// wrong, so it is a shared harness rather than a per-backend copy: memory,
/// sqlite and postgres run the SAME body against a directory with no accord
/// roster, and every gate in [`ROOT_REQUIRING_GATES`] must refuse with the
/// typed `federation_no_constitutional_root_yet`.
///
/// Why all three rather than one: *memory tolerates what postgres rejects* is a
/// named trap in this substrate (non-hex columns, absent FKs, TEXT ids), and it
/// has recurred often enough that a single-backend security witness is not
/// evidence. The specific hazard here is that a backend's `lookup_public_key`
/// could answer differently for an absent row and turn the chokepoint into a
/// no-op on one backend only.
///
/// The enumeration is checked for completeness at the end: every token in
/// [`ROOT_REQUIRING_GATES`] must be produced by some refusal below, and no
/// refusal may carry a token outside the list. A gate added to the constant
/// without a witness reds here; a listed gate that stops calling the chokepoint
/// reds here too.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) async fn exercise_seedless_gate_refusals(dir: &dyn FederationDirectory, tag: &str) {
    use crate::federation::admission;
    use crate::federation::types::{
        attestation_tier, attestation_type, cohort_scope, identity_type,
    };
    use std::collections::BTreeSet;

    // Precondition: the directory really has no roster. Handed a seeded backend
    // the whole witness would be vacuous, so say so rather than pass.
    assert!(
        accord_roster_seated(dir).await.is_err(),
        "[{tag}] the seedless witness needs a directory with NO accord roster"
    );

    let rogue = format!("rogue-{tag}");
    let claiming = |role: &str| {
        crate::federation::tier_ingest::test_support::replicated_key_record(
            &rogue, role, &rogue, &rogue, "n1",
        )
    };

    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    let mut record = |e: Error, what: &str| {
        assert_eq!(
            e.kind(),
            "federation_no_constitutional_root_yet",
            "[{tag}] {what} must refuse with the TYPED pre-genesis error, got {e:?}"
        );
        match e {
            Error::NoConstitutionalRootYet { operation, .. } => {
                seen.insert(operation);
            }
            other => panic!("[{tag}] {what}: {other:?}"),
        }
    };

    // 1. canonical_role_admission — the founding-server role.
    record(
        admission::check_canonical_role_admission(dir, &claiming(identity_type::CANONICAL))
            .await
            .expect_err("a `canonical` claim on a rootless node must REFUSE"),
        "check_canonical_role_admission",
    );

    // 2. infra_attest_role_admission — the build-manifest signing authority.
    record(
        admission::check_infra_attest_role_admission(
            dir,
            &claiming(crate::federation::types::roles::INFRA_ATTEST),
        )
        .await
        .expect_err("an `infra:attest` claim on a rootless node must REFUSE"),
        "check_infra_attest_role_admission",
    );

    // 3. accord_role_admission — the role-generic conferral gate.
    record(
        admission::check_co_steward_role_admission(dir, &claiming(identity_type::REGISTRY))
            .await
            .expect_err("a co-steward claim on a rootless node must REFUSE"),
        "check_co_steward_role_admission",
    );

    // 4. canonical_withdraw_authority — a DESTRUCTIVE constitutional op.
    record(
        admission::verify_canonical_withdraw_authority(dir, "some-canonical", "digest")
            .await
            .expect_err("a canonical withdraw on a rootless node must REFUSE"),
        "verify_canonical_withdraw_authority",
    );

    // 5. family_charter_admission — the #632 inversion in miniature. With no
    //    family row the quorum check used to be SKIPPED entirely, so an
    //    unauthorized charter for the constitutional family was admitted with
    //    no quorum and no pre-rotation commitment at all.
    let ts: chrono::DateTime<chrono::Utc> = "2026-05-01T00:00:00Z".parse().unwrap();
    let charter = crate::federation::Attestation {
        attestation_id: format!("rogue-charter-{tag}"),
        attesting_key_id: rogue.clone(),
        attested_key_id: "humanity-accord".to_owned(),
        attestation_type: attestation_type::DELEGATES_TO.to_owned(),
        weight: None,
        asserted_at: ts,
        expires_at: None,
        attestation_envelope: serde_json::json!({
            "id": format!("rogue-charter-{tag}"),
            "dimension": crate::federation::trust_root::TRUST_CHARTER_DIMENSION,
            "scope": ["infra:serve", "infra:attest"],
        }),
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: rogue.clone(),
        scrub_timestamp: ts,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_owned(),
        tier: attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    };
    record(
        crate::federation::trust_root::check_family_charter_admission(dir, &charter)
            .await
            .expect_err("an unquorumed constitutional charter must REFUSE, not be skipped"),
        "check_family_charter_admission",
    );

    // The enumeration IS the contract.
    let listed: BTreeSet<&str> = ROOT_REQUIRING_GATES.iter().copied().collect();
    let witnessed: BTreeSet<&str> = seen.iter().copied().collect();
    assert_eq!(
        listed, witnessed,
        "[{tag}] ROOT_REQUIRING_GATES must name exactly the gates this witness proves refuse"
    );

    // ── the read side: fail-closed BY VALUE, which is the other half of
    //    "never a silent pass". No root ⇒ no grant, not no-rule-to-apply.
    assert!(
        crate::federation::trust_root::capability_roots_to_trusted_root(
            dir,
            "some-user",
            "some-key",
            "infra:serve",
        )
        .await
        .expect("walk")
        .is_none(),
        "[{tag}] no root ⇒ NO capability, never an unconditional grant"
    );
    assert!(
        !admission::has_accord_conferred_role(dir, &rogue, identity_type::REGISTRY)
            .await
            .expect("read"),
        "[{tag}] no roster ⇒ the effective-role read is FALSE"
    );
    let verdict =
        crate::federation::trust_root::trust_root_valid(dir, "some-user", "humanity-accord")
            .await
            .expect("walk");
    assert!(
        !verdict.valid,
        "[{tag}] no charter ⇒ the constitutional root is NOT valid"
    );

    // ── and the constitutional family id cannot be claimed at the peer door,
    //    which is the hole that opening the seedless boot would otherwise have
    //    created: sole seat + `founder_only` ⇒ a 1-of-1 charter threshold.
    let squat = crate::federation::SignedFamily {
        family: crate::federation::types::Family {
            family_key_id: "humanity-accord".to_owned(),
            family_name: "MINE".to_owned(),
            members: vec![crate::federation::types::FamilyMember {
                key_id: rogue.clone(),
                joined_at: ts,
                role: Some("founder".to_owned()),
            }],
            founded_at: ts,
            consensus_protocol: "founder_only".to_owned(),
            consensus_protocol_entrenched: false,
            persist_row_hash: String::new(),
        },
        authority_key_id: rogue.clone(),
        scrub_signature_classical: "AA==".to_owned(),
        scrub_signature_pqc: None,
    };
    let err = dir
        .put_family(squat)
        .await
        .expect_err("the constitutional family id must not be claimable by a peer");
    assert_eq!(
        err.kind(),
        "federation_constitutional_family_reserved",
        "[{tag}] and the refusal names the reservation"
    );
    assert!(
        dir.lookup_family("humanity-accord")
            .await
            .expect("lookup")
            .is_none(),
        "[{tag}] a refused squat writes NOTHING"
    );
}
