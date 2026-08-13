//! v22.0.0 (CIRISPersist#541 follow-through) — the **substrate state-machine
//! property harness**: testing driven from INTENT (an op alphabet + invariants)
//! rather than from hand-written fixtures.
//!
//! # Why this module exists
//!
//! **1446 hand-written tests were green while CIRISPersist#541 was live.** That
//! is not a gap in test COUNT; it is a gap in test SHAPE. Every one of those
//! tests exercises ONE writer against a FRESH row, and #541 needed four things
//! in sequence before it could even be observed:
//!
//! 1. a signed write,
//! 2. a **different, unsigned** writer on the **same key**,
//! 3. a read back through the real `list_signed_*` / replication path,
//! 4. verification by the **real verifier**.
//!
//! Worse, hand fixtures reuse timestamps, and the monotonic write guard makes
//! an equal-clock write a trivial no-op — so on a hand fixture the bug could
//! not be *expressed*, let alone caught. And persist's only pre-existing
//! proptests ([`super::transform`], [`super::freshness`]) cover **pure
//! algebra**, while every real defect of the #519→#541 arc lived in
//! **stateful, multi-writer, cross-backend, crypto-round-trip sequences**.
//!
//! This harness closes that shape gap on the attestation plane — the plane that
//! carries `insert_local` / `put` / `promote` / `withdraw` / `supersede` /
//! `recant` and therefore has the richest write-order surface in the substrate.
//!
//! # The op alphabet
//!
//! An [`Op`] is a `{kind, family, attester, subject, tier, cohort_scope,
//! signature, clock, target}` tuple. [`OpKind`] is the closed alphabet:
//!
//! | Kind | Real surface driven |
//! |---|---|
//! | [`OpKind::InsertLocal`] | [`FederationDirectory::attestation_insert_local`] |
//! | [`OpKind::UpsertLocal`] | [`FederationDirectory::attestation_upsert_local`] |
//! | [`OpKind::Put`] | [`FederationDirectory::put_attestation`] at the op's `tier` |
//! | [`OpKind::Promote`] | `set_attestation_cohort_scope` + [`FederationDirectory::promote_attestation`] |
//! | [`OpKind::Withdraw`] | `put_attestation` of a `withdraws` referencing a prior row |
//! | [`OpKind::Supersede`] | `put_attestation` of a `supersedes` referencing a prior row |
//! | [`OpKind::Recant`] | `put_attestation` of a `recants` referencing a prior row |
//! | [`OpKind::UnsignedLocalWrite`] | an unsigned `attestation_upsert_local` **on the coordinates an earlier admitted row already occupies** — the #541 shape |
//! | [`OpKind::Deadmit`] | a `put_attestation` of the AV-77 peer de-admission row, which makes [`check_peer_deadmission`](super::admission::check_peer_deadmission) LIVE for the rest of the sequence |
//! | [`OpKind::ReadBack`] | `list_attestations_for` / `_by` + [`FederationDirectory::list_signed_records`], each row re-verified |
//!
//! [`OpKind::Deadmit`] exists because of a hole this harness had and did not
//! report. v22.0.0 fixed three backend-parity defects the differential oracle
//! should have screamed about — memory ran **no de-admission gate at all** (it
//! had no `self_key_id` field), memory ran **no SCORES envelope-schema
//! validation**, and postgres ran the de-admission gate with nothing proving
//! it. Entire gates were missing from one arm of the trio and the oracle stayed
//! silent, because **the op alphabet could not produce a row that reaches
//! them**. They were found by hand, by building an inventory table.
//!
//! That is the failure mode this module's own design notes name: *derive the
//! enumeration from the vocabulary, not from what the code parses.* A generator
//! that only emits families the backends already agree on will keep agreeing
//! with itself. Every gate added to a write path is therefore also a claim
//! about this alphabet — if no op can reach it, the trio is not being compared
//! on it.
//!
//! The clock **advances by default** ([`ClockStep::Advance`], weighted 9:1 over
//! [`ClockStep::Equal`]) — the #541 lesson, stated as a generator bias: an
//! equal-clock write is absorbed by the monotonic guard and proves nothing, so
//! equal-clock must be the deliberate rare case, never the accident.
//!
//! # The invariants
//!
//! | # | Invariant | Needs an oracle? |
//! |---|---|---|
//! | I1 | **The #541 invariant.** No sequence of local writes may render a signed row unverifiable by a remote peer: every federation-tier row read back must still pass the REAL [`verify_federation_tier_ingest`](super::verify_federation_tier_ingest) | no |
//! | I2 | **Zero-writes-on-refusal (AV-9).** A refused op leaves the corpus BYTE-identical | no |
//! | I3 | **Replay idempotence.** Re-applying an admitted op leaves the state exactly as one application did | no |
//! | I4 | **Monotone refusal.** A refused op, narrowed by an ADDITIONAL constraint, is still refused | no |
//! | I5 | **Parity.** memory ≡ sqlite on admitted-vs-refused, on storedness, and on resulting row state — asserted PER OP, so the FIRST divergence fails | differential |
//! | I6 | **Admitted implies stored.** A backend that answers `Ok` must be able to show you the row under the id you sent | no |
//!
//! # Provenance
//!
//! An invariant that fails at op N may have diverged at op M < N — a `Promote`
//! points at a row minted several ops earlier, and "target absent" is a symptom
//! of whatever failed to create it. So every id carries a [`Provenance`]
//! record (which op asked for it, that op's per-backend fate, whether the row
//! was actually readable), and every failure message prints it:
//!
//! ```text
//! PROVENANCE of 0f5cca98…: minted by op 2
//!   memory: op 2 (Put) = ADMITTED stored=true
//!   sqlite: op 2 (Put) = REFUSED(Some("federation_backend")) stored=false
//! ⇒ the divergence ORIGINATES at op 2, not at the op reported above.
//! ```
//!
//! [`Machine::minted`] is deliberately a mix of outcome and intent (it must
//! stay backend-independent or the two runs stop issuing the same sequence), so
//! membership in it proves nothing — the provenance map is what any message is
//! allowed to cite.
//!
//! I1 runs the **real verifier**, never a hand-rolled field comparison. That is
//! not a style preference: a field compare rebuilds the two-lists-that-disagree
//! problem *inside the test*, which is the exact defect class being tested for
//! (see the #541 commit message — "the verifier IS the list").
//!
//! I5 is a **differential oracle**: no expected-value table exists or is
//! wanted. This repo's parity invariant is "no backend is second-class", and
//! the #541 audit found memory silently accepting rows sqlite rejects. Any
//! divergence in admitted-vs-refused, or in the resulting row state, IS a bug —
//! the harness reports it without anyone having to have predicted it.
//!
//! # Budget
//!
//! The differential property runs **64 sequences × ≤8 ops × 2 backends**
//! (documented the way edge's `replication_wire_proptest.rs` documents its
//! own), and the meta-coverage property runs 192 generator draws with 24
//! executed. Every op does real ML-DSA-65 keygen + sign + verify and every
//! sequence pays a fresh `run_migrations`, so the case count is the wall-clock
//! knob: raise `PROPTEST_CASES` locally to hunt, leave it here so CI stays
//! sane.
//!
//! # Meta-coverage
//!
//! A generator that only ever produces refusals passes every invariant
//! *vacuously*. [`generator_reaches_interesting_states`] fails loudly if that
//! happens: it asserts every [`OpKind`] variant is emitted, both polarities
//! (admitted and refused) are reached, a floor fraction of sequences produce at
//! least one admitted **federation-tier signed** row, and the AV-77
//! de-admission gate actually **refused** a write.
//!
//! That last claim is a different kind of assertion from the first three, and
//! the reason is [`OpKind::Deadmit`]'s: EMITTING an op is not reaching a gate.
//! A `Deadmit` only exercises anything when it lands AND a later op writes as
//! the peer it named AND that write survives the gates ahead of tier 4b — a
//! conjunction the unbiased generator hit roughly once per 24 sequences.
//! Whenever a variant's whole point is a conjunction like that, the meta-
//! coverage claim has to be about the CONJUNCTION, not about the draw.
//!
//! # Known limits
//!
//! Stated here rather than only in the CHANGELOG and `docs/THREAT_MODEL.md`
//! (§3.16, AV-76/AV-78), because the person who needs them is reading this file
//! deciding whether a green run means anything about the change they just made.
//!
//! **1. A differential oracle is exactly as wide as its backend set.** Both
//! substrate bugs this harness found in v22 — `put_attestation` dropping the
//! caller's `tier`, and the §6.1 dedup short-circuit sitting ahead of the
//! crypto gate — were present IDENTICALLY in postgres, and the oracle found
//! NEITHER of them there. They were caught by READING postgres while porting
//! the sqlite fix. Three arms that share a defect agree perfectly. No
//! differential can report a bug all its arms have, and no amount of case
//! budget changes that — only reading, or a non-differential invariant (I1–I4,
//! I6), can.
//!
//! **2. A gate no op can reach is a gate the trio is not compared on.** See
//! [`OpKind::Deadmit`] above for the concrete miss. That gap is now CLOSED and
//! the closure was DEMONSTRATED, not asserted: temporarily deleting memory's
//! `check_peer_deadmission` call makes three tests here fail, and the
//! differential names the origin op —
//! `I5 (op 4 = Supersede…): ADMISSION DIVERGES — memory ADMITTED, sqlite
//! REFUSED … ⇒ the divergence ORIGINATES at op 2 (Deadmit)`. Before
//! [`OpKind::Deadmit`] existed the same deletion was invisible to every test
//! in this file.
//!
//! Reaching it required biasing the generator, not lowering a floor: the
//! conjunction (a sanction that LANDS, then a write from the peer it named,
//! both surviving the tiers ahead of the AV-77 gate) occurred in **7 of 240
//! sequences (2.9%)** on the unbiased generator (measured AFTER the
//! expiry-horizon fix of limit 7 — under the broken clock it was 0 of 240, and
//! no generator bias could have fixed that) — an expected count of 0.7 at
//! the meta-coverage budget, i.e. a coin flip. See
//! [`bias_deadmission_followups`]; the rate is now **18 of 240 (7.5%)** —
//! independently re-measured on the shipping generator. The op alphabet is the
//! harness's real coverage boundary, and it is much narrower than the write
//! path: notably, the alphabet reaches ONE write chokepoint family
//! (`put_attestation` + the two local paths + `promote_attestation`) on ONE
//! §3 plane (attestations). `federation_keys`, revocations, transport routes,
//! blobs, quorum state and the whole scores/trace projection plane have their
//! own gates and are NOT driven from here.
//!
//! **3. The SCORES envelope-schema gate is UNREACHABLE from this harness.**
//! Not "untested" — unreachable, and the distinction is the point. All three
//! backends default to [`NoOpSchemaResolver`](super::NoOpSchemaResolver), whose
//! `resolve` returns `Ok(None)`, so the validation body never executes. That is
//! why the differential could not see memory missing the whole
//! `if scores { resolve; validate }` block: with a no-op resolver, a backend
//! WITH the block and a backend WITHOUT it are observationally identical.
//! Closing it needs a schema-plane fixture — a
//! [`BlobBackedSchemaResolver`](super::BlobBackedSchemaResolver) plus a
//! byte-identical seeded schema blob installed on all three arms — which is a
//! different harness, not a bigger case count here. A resolver installed just
//! to make this section shorter would report coverage that does not exist.
//!
//! **4. Load, concurrency and DoS are out of scope.** Every sequence is
//! single-threaded against a fresh corpus, so nothing here says anything about
//! concurrent writers, lock contention, or the AV-76 amplification budget the
//! gate ORDER exists to protect. I5 compares WHICH gate refused
//! (`Error::kind`), which pins the ordering CONTRACT; it does not measure the
//! work a refusal costs. `benches/` owns that.
//!
//! **5. Spec gaps are recorded, not resolved.** Where the substrate's behaviour
//! is under-specified the harness pins what the code does and the question goes
//! upstream — it never invents an answer. Open: whether `witness_diversity`
//! *should* gate the band is a Constitution question, filed as
//! CIRISConstitution#46.
//!
//! **6. De-admission is exercised at FEDERATION tier only.**
//! [`check_peer_deadmission`](super::admission::check_peer_deadmission) does
//! not filter on `tier`, so a LOCAL-tier de-admission row is equally
//! enforceable — and, unlike a federation-tier one, it can be replaced by an
//! `attestation_upsert_local` on the same `(attesting_key_id, dimension)`
//! coordinates, which would lift the sanction without any `withdraws`. Only the
//! node itself writes its own local rows, so that is self-inflicted rather than
//! an attacker path; it is unexercised here all the same.
//!
//! **7. A fixed model clock against wall-clock gates has an EXPIRY HORIZON, and
//! it fails silently.** The model clock is pinned to 2026-01-01 because I3's
//! replay and I5's differential compare `expires_at` byte for byte, so it cannot
//! be `Utc::now()`. Substrate gates, however, evaluate liveness against
//! `Utc::now()`. While `row_for` stamped `expires_at = at + 30 days`, every row
//! this harness wrote was **already expired** at every such gate from 2026-01-31
//! onward — for roughly six months, with nothing failing, because no invariant
//! here depended on a row being LIVE. [`OpKind::Deadmit`] is what exposed it: a
//! sanction that landed and refused nothing.
//!
//! Measured blast radius over 240 sequences / 1099 ops, same seed, old expiry vs
//! new: **the ONLY outcomes that changed were the de-admission refusals
//! themselves** (unbiased 552→545 admitted, exactly the 7 the gate now refuses;
//! biased 582→556, exactly its 26). So the broken clock did not manufacture
//! false AGREEMENT — it made exactly one gate unreachable. Four other
//! wall-clock liveness folds over `delegates_to` edges
//! ([`is_steward_bound`](super::admission::is_steward_bound),
//! [`steward_bindings_of`](super::admission::steward_bindings_of),
//! [`steward_binding_chain`](super::admission::steward_binding_chain) and
//! `live_owner_binding_granters`) do read rows this harness writes, and changed
//! no outcome under this alphabet; that is a fact about the
//! alphabet, not a guarantee. `every_row_the_harness_writes_is_live_at_wall_clock`
//! now pins the horizon so the next drift fails loudly instead of quietly.
//!
//! **8. A substrate harness cannot see whether a HOST can reach a gate.** This
//! harness installs `self_key_id` directly on the concrete backend, which is
//! correct for testing the substrate contract — and it is exactly why AV-77
//! could be green here while being **unreachable in production**:
//! `set_self_key_id` existed only on the backend types, with no `Engine` method
//! and no PyO3 binding, so no host could turn the gate on. Every witness reached
//! PAST the Engine to configure the backend directly, so the whole matrix agreed
//! about a gate nobody could enable (v22.0.0, CIRISPersist#543; the fix is
//! `Engine::set_self_key_id` plus its FFI binding). This is the
//! "accepted but not projected" class again — v17.0.0 / CIRISPersist#444. A gate
//! is not shipped when its code path exists and passes; it is shipped when a
//! host can reach it, and **only a test that goes through the host surface can
//! say so**. Reachability-from-the-host is out of scope for every test in this
//! file, by construction.

/// Shared, backend-agnostic machine + invariant bodies. Compiled under `test`
/// and under the `test-anchor` feature (persist's test-only, never-in-a-
/// published-wheel fence) so a downstream conformance run can drive the same
/// state machine against its own [`FederationDirectory`] implementation — the
/// same posture as [`super::self_at_login::test_support`] and
/// [`super::bootstrap_admission::test_support`].
///
/// Deliberately free of any `proptest` dependency: `proptest` is a
/// dev-dependency, so the generators live in this module's `#[cfg(test)]`
/// sibling and only the *execution* half is shared.
#[cfg(any(test, feature = "test-anchor"))]
#[allow(dead_code)]
pub mod test_support {
    use std::collections::{BTreeMap, BTreeSet};

    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use chrono::{DateTime, Duration, Utc};

    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        attestation_tier, attestation_type, cohort_scope, LocalAttestationInput,
    };
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation};

    /// The cast the harness draws attesters/subjects from. Three principals is
    /// the minimum that can express "a DIFFERENT writer on the same key" (the
    /// #541 precondition) *and* a third-party attestation (the `capacity:*`
    /// anti-Goodhart ALLOW path) in one sequence.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Principal {
        /// First principal — the shrink target (proptest shrinks toward it).
        A,
        /// Second principal — the "different writer" of the #541 shape.
        B,
        /// Third principal — the independent third party.
        C,
    }

    impl Principal {
        /// Every principal, in shrink order.
        pub const ALL: [Principal; 3] = [Principal::A, Principal::B, Principal::C];

        /// This principal's UNTAGGED base name. Prefer [`Self::key_id_in`] —
        /// on a SHARED database (postgres) a constant cast id collides across
        /// sequences, which is why every id the machine writes is tagged.
        #[must_use]
        pub fn key_id(self) -> &'static str {
            match self {
                Principal::A => "sm-alice",
                Principal::B => "sm-bob",
                Principal::C => "sm-carol",
            }
        }

        /// This principal's `federation_keys.key_id` WITHIN a run.
        ///
        /// The per-run `tag` scopes the cast on a SHARED test database — the
        /// convention `src/store/postgres.rs`'s tests already use. Every
        /// backend in one differential shares the tag, so their rows stay
        /// byte-comparable; different sequences never collide. Without this the
        /// postgres arm would fight itself across cases on the one shared DB.
        #[must_use]
        pub fn key_id_in(self, tag: &str) -> String {
            format!("{}-{tag}", self.key_id())
        }
    }

    /// The cast member who is **THIS NODE** — the identity installed as the
    /// backend's `self_key_id`, which is what makes the AV-77 de-admission gate
    /// live (`check_peer_deadmission` is a no-op while the host has declared no
    /// identity).
    ///
    /// [`Principal::A`] rather than a fourth principal, for two reasons.
    /// Proptest shrinks toward `A`, so the minimal counterexample of any
    /// de-admission failure is also the one where the node is the author — the
    /// interesting case. And a node in a real mesh IS one of the writers: it
    /// attests, it is attested about, and it de-admits, all with the same key.
    /// A separate never-writing self principal would model a node that only
    /// judges, which is not the shape the substrate has to survive.
    pub const SELF_PRINCIPAL: Principal = Principal::A;

    /// The key id the harness installs as the node's OWN identity for run
    /// `tag` — see [`SELF_PRINCIPAL`] and [`run_sequence`].
    #[must_use]
    pub fn self_key_id_for(tag: &str) -> String {
        SELF_PRINCIPAL.key_id_in(tag)
    }

    /// A key id that is deliberately NEVER registered. Used by I4 as a
    /// strictly-narrowing transform: an unregistered attester fails the FK /
    /// pubkey-resolution precondition on every write path in the substrate, so
    /// "same op, unregistered attester" is monotonically more constrained.
    pub const UNREGISTERED_KEY_ID: &str = "sm-unregistered-never-put";

    /// The dimension families the alphabet ranges over. Chosen so the generator
    /// reaches BOTH polarities without the harness encoding any expected
    /// values: three families that admit on the happy path, three that a real
    /// gate refuses.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Family {
        /// Free, ungated dimension — the admit baseline.
        Identity,
        /// Free, ungated dimension — a second admit baseline so "same key" vs
        /// "different key" collisions are expressible.
        Reputation,
        /// `capacity:*` — CEG §7.5 / AV-62 anti-Goodhart: never local, never
        /// self-emitted. Admits only third-party at federation tier.
        Capacity,
        /// `trace:*` — the #473 Information-Type validator. Admits only with
        /// correct self-emission polarity (`attester ∈ subject_key_ids`) and a
        /// well-formed inline trace.
        Trace,
        /// `system:*` — reserved prefix, `substrate_persist` emitters only. The
        /// whole cast registers as `agent`, so this family always refuses; it
        /// is I4's narrowing target.
        Reserved,
        /// The #510 closed consent-transfer grammar, driven with a payload the
        /// grammar rejects — a clean always-refused probe for I2/I4.
        ConsentGrant,
    }

    impl Family {
        /// Every family, in shrink order.
        pub const ALL: [Family; 6] = [
            Family::Identity,
            Family::Reputation,
            Family::Capacity,
            Family::Trace,
            Family::Reserved,
            Family::ConsentGrant,
        ];

        /// The wire `dimension` string.
        #[must_use]
        pub fn dimension(self) -> &'static str {
            match self {
                Family::Identity => "identity:handle:v1",
                Family::Reputation => "reputation:helpfulness:v1",
                Family::Capacity => "capacity:core_identity:v1",
                Family::Trace => "trace:complete:v1",
                Family::Reserved => "system:machine:v1",
                Family::ConsentGrant => crate::federation::consent_grammar::GRANT_DIMENSION,
            }
        }
    }

    /// `cohort_scope` values the alphabet ranges over (a representative slice of
    /// the closed set, not all seven — the remaining four are the same
    /// admission class as `community`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Scope {
        /// The NARROWEST scope — I4's cohort-narrowing target.
        SelfScope,
        /// Partnered-family visibility.
        Family,
        /// Community visibility.
        Community,
        /// Federation-wide visibility.
        Federation,
    }

    impl Scope {
        /// Every scope, in shrink order.
        pub const ALL: [Scope; 4] = [
            Scope::SelfScope,
            Scope::Family,
            Scope::Community,
            Scope::Federation,
        ];

        /// The wire value.
        #[must_use]
        pub fn as_str(self) -> &'static str {
            match self {
                Scope::SelfScope => cohort_scope::SELF,
                Scope::Family => cohort_scope::FAMILY,
                Scope::Community => cohort_scope::COMMUNITY,
                Scope::Federation => cohort_scope::FEDERATION,
            }
        }
    }

    /// Row tier. Carried on the op (not implied by the kind) because
    /// `put_attestation` accepts BOTH — and a `tier = local` put is EXEMPT from
    /// the hybrid ingest gate (CC 5.3.2.2 deferred signature), which is a
    /// genuinely under-exercised state.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Tier {
        /// Producer-only authority, signature deferred, self-visible only.
        Local,
        /// Hybrid-signed, federation-visible.
        Federation,
    }

    impl Tier {
        /// Every tier, in shrink order.
        pub const ALL: [Tier; 2] = [Tier::Local, Tier::Federation];

        /// The wire value.
        #[must_use]
        pub fn as_str(self) -> &'static str {
            match self {
                Tier::Local => attestation_tier::LOCAL,
                Tier::Federation => attestation_tier::FEDERATION,
            }
        }
    }

    /// The §3 structural primitive an op writes. Ignored by
    /// [`OpKind::Withdraw`] / [`OpKind::Supersede`] / [`OpKind::Recant`], which
    /// carry their own by definition.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum AttType {
        /// The unified workhorse primitive.
        Scores,
        /// "A authorizes B to sign on A's behalf."
        DelegatesTo,
    }

    impl AttType {
        /// Every type, in shrink order.
        pub const ALL: [AttType; 2] = [AttType::Scores, AttType::DelegatesTo];

        /// The wire value.
        #[must_use]
        pub fn as_str(self) -> &'static str {
            match self {
                AttType::Scores => attestation_type::SCORES,
                AttType::DelegatesTo => attestation_type::DELEGATES_TO,
            }
        }
    }

    /// The signature state a signed-plane op carries. Local writes are unsigned
    /// by construction (the tier defers the signature), so this axis only bites
    /// on `Put` / `Withdraw` / `Supersede` / `Recant`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum SigState {
        /// A REAL hybrid signature over the REAL canonical envelope bytes.
        Valid,
        /// A real signature with one byte flipped — must never verify.
        Corrupt,
        /// No signature at all (the empty-sentinel shape a local row uses).
        Absent,
    }

    impl SigState {
        /// Every state, in shrink order.
        pub const ALL: [SigState; 3] = [SigState::Valid, SigState::Corrupt, SigState::Absent];
    }

    /// v24.0.0 (CIRISPersist#556) — how many CO-SIGNATURES a signed-plane row
    /// carries in `additional_scrubs`, and whether they are real.
    ///
    /// This axis exists because a field the harness never populates is a field
    /// the harness cannot guard. `additional_scrubs` is the evidence a family
    /// trust root's charter is quorum-signed; the moment it entered the row it
    /// entered the #541 blast radius — a writer that preserves the base scrub
    /// while dropping or mangling the co-signatures desyncs the row from its own
    /// signature. With this axis, I1 (the REAL ingest verifier, re-run on every
    /// federation row after every op) and the memory-vs-sqlite differential
    /// cover the new field forever, instead of covering only the shape it had
    /// on the day it was added.
    ///
    /// Local paths ignore it: a local-tier write defers its signature, so
    /// `LocalAttestationInput` carries no scrub set at all.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum CoSign {
        /// No co-signatures — the pre-v24 shape, and the shrink target.
        None,
        /// One REAL hybrid co-signature over the SAME canonical envelope, by a
        /// different registered principal.
        One,
        /// Two REAL co-signatures, by the other two principals — a row whose
        /// scrub set is a genuine 3-of-3.
        Two,
        /// One co-signature with a flipped byte. Must be REFUSED at
        /// federation-tier ingest exactly as a corrupt BASE signature is: a
        /// co-signature the verifier does not check is a co-signature a writer
        /// may forge.
        Corrupt,
    }

    impl CoSign {
        /// Every variant, in shrink order. Read by the meta-coverage assertion,
        /// so adding a variant without teaching the generator fails loudly
        /// instead of silently under-testing.
        pub const ALL: [CoSign; 4] = [CoSign::None, CoSign::One, CoSign::Two, CoSign::Corrupt];

        /// The extra principals that co-sign, given the row's base attester.
        fn co_signers(self, attester: Principal) -> Vec<Principal> {
            let others: Vec<Principal> = Principal::ALL
                .into_iter()
                .filter(|p| *p != attester)
                .collect();
            match self {
                CoSign::None => Vec::new(),
                CoSign::One | CoSign::Corrupt => others.into_iter().take(1).collect(),
                CoSign::Two => others,
            }
        }
    }

    /// How the model clock moves before an op. **Advancing is the default**
    /// (CIRISPersist#541): a monotonic write guard turns an equal-clock write
    /// into a no-op, so a harness that reuses timestamps cannot express the
    /// write it is trying to test.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum ClockStep {
        /// Move forward by N seconds (N ≥ 1).
        Advance(u32),
        /// The deliberate rare case: do not move. Exercises the guard itself.
        Equal,
    }

    /// The closed op alphabet.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum OpKind {
        /// Append a local-tier row (`attestation_insert_local`).
        InsertLocal,
        /// Replace the local-tier row at `(attester, dimension)`
        /// (`attestation_upsert_local`).
        UpsertLocal,
        /// Submit a row through `put_attestation` at the op's `tier`.
        Put,
        /// Promote a previously-minted row local→federation.
        Promote,
        /// A `withdraws` referencing a previously-minted row.
        Withdraw,
        /// A `supersedes` referencing a previously-minted row.
        Supersede,
        /// A `recants` referencing a previously-minted row.
        Recant,
        /// **The #541 shape.** An unsigned local write aimed at the
        /// `(attester, dimension)` coordinates an EARLIER ADMITTED row already
        /// occupies — a different writer, same key, later clock.
        UnsignedLocalWrite,
        /// **The AV-77 act.** A `put_attestation` of this node's own peer
        /// de-admission row: `scores` +
        /// [`PEER_DEADMISSION_DIMENSION`](crate::federation::admission::PEER_DEADMISSION_DIMENSION),
        /// authored by the node's OWN key, naming `op.subject` as the
        /// de-admitted peer. Once admitted,
        /// [`check_peer_deadmission`](crate::federation::admission::check_peer_deadmission)
        /// refuses every subsequent `put_attestation` authored by that peer for
        /// the rest of the sequence — so this is the one op whose effect is to
        /// change how EVERY later op is judged.
        ///
        /// The author is FORCED to the node's own identity
        /// ([`SELF_PRINCIPAL`]) rather than drawn, on the same reasoning
        /// [`OpKind::UnsignedLocalWrite`] forces `cohort_scope = self`: only the
        /// node may author an effective de-admission (the gate folds over
        /// `list_attestations_by(self_key_id)` and nothing else), so a drawn
        /// author would spend two draws in three on a row that is stored and
        /// INERT. That "a peer cannot de-admit on our behalf" property is worth
        /// more as a deterministic witness than as a 1-in-3 generator draw, and
        /// [`third_party_deadmission_of_a_peer_is_inert`] is that witness.
        Deadmit,
        /// Read the corpus back through the real replication surfaces and
        /// re-verify every federation row (I1, mid-sequence).
        ReadBack,
    }

    impl OpKind {
        /// Every kind, in shrink order. Used by the meta-coverage assertion —
        /// if a variant is added and the generator is not updated, coverage
        /// fails loudly rather than silently under-testing.
        pub const ALL: [OpKind; 10] = [
            OpKind::InsertLocal,
            OpKind::UpsertLocal,
            OpKind::Put,
            OpKind::Promote,
            OpKind::Withdraw,
            OpKind::Supersede,
            OpKind::Recant,
            OpKind::UnsignedLocalWrite,
            OpKind::Deadmit,
            OpKind::ReadBack,
        ];

        /// True for the kinds whose `dimension` and `cohort_scope` come from the
        /// op (so I4's narrowing transforms are meaningful). `Promote` takes its
        /// dimension from the target row, `Deadmit`'s dimension is fixed by the
        /// kind itself, and `ReadBack` writes nothing.
        #[must_use]
        pub fn dimension_is_caller_supplied(self) -> bool {
            !matches!(self, OpKind::Promote | OpKind::Deadmit | OpKind::ReadBack)
        }
    }

    /// One operation. Every field is `Copy` + `Debug` and every axis is a small
    /// closed enum or a bounded integer, so proptest's shrinker hands back a
    /// genuinely minimal failing sequence rather than a smaller pile of noise.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Op {
        /// Which surface to drive.
        pub kind: OpKind,
        /// The dimension family (⇒ the envelope `dimension`).
        pub family: Family,
        /// Who writes.
        pub attester: Principal,
        /// Who the row is about (`attested_key_id` + the single entry of
        /// `subject_key_ids`).
        pub subject: Principal,
        /// The row tier (meaningful for `Put`; local paths force `local`).
        pub tier: Tier,
        /// The producer-side visibility scope.
        pub cohort_scope: Scope,
        /// The signature state (meaningful for the signed-plane kinds).
        pub signature: SigState,
        /// v24.0.0 (CIRISPersist#556) — the `additional_scrubs` co-signature set
        /// (meaningful for the signed-plane kinds; local writes defer signatures
        /// and carry none). See [`CoSign`].
        pub cosign: CoSign,
        /// How the model clock moves before this op.
        pub clock: ClockStep,
        /// Selector into the model's minted-row / occupied-coordinate lists,
        /// taken modulo the list length. `0` is the shrink target.
        pub target: u8,
    }

    /// Where an attestation id came from, and what the backend did with it.
    ///
    /// The harness's own instrumentation defect this closes: an invariant that
    /// fails at op N referencing a row minted at op M used to report only op N.
    /// A late symptom must name its own root cause, so every id carries the op
    /// that asked for it and that op's per-backend fate.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Provenance {
        /// The op slot that asked the substrate for this id.
        pub minted_by_op: usize,
        /// That op's kind.
        pub kind: OpKind,
        /// Was the minting op ADMITTED on this backend?
        pub admitted: bool,
        /// Its refusal kind, if refused.
        pub error_kind: Option<&'static str>,
        /// Was the row READABLE afterwards? `stored: false` together with
        /// `admitted: true` is the substrate saying yes and showing you
        /// nothing — see I6.
        pub stored: bool,
    }

    impl Provenance {
        /// One line, for a panic message.
        #[must_use]
        pub fn describe(&self) -> String {
            format!(
                "op {} ({:?}) = {} stored={}",
                self.minted_by_op,
                self.kind,
                if self.admitted {
                    "ADMITTED".to_owned()
                } else {
                    format!("REFUSED({:?})", self.error_kind)
                },
                self.stored
            )
        }
    }

    /// What one applied op did. The differential compares these field for
    /// field across backends.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct OpOutcome {
        /// Did the substrate accept the write?
        pub admitted: bool,
        /// [`crate::federation::Error::kind`] of the refusal, if refused. The
        /// machine-readable discriminator consumers pattern-match on — never
        /// the human-readable message, whose wording legitimately differs per
        /// backend.
        pub error_kind: Option<&'static str>,
        /// The `attestation_id` the op targeted / minted, if any.
        pub row_id: Option<String>,
        /// Was [`Self::row_id`] READABLE from the substrate immediately after
        /// the op? Read back with `get_attestation` — never assumed from the id
        /// we sent, because "the backend said Ok" and "the backend stored it
        /// under that id" are two different claims (I6).
        pub stored: Option<bool>,
        /// The PRE-EXISTING row this op referenced, if any: `Promote`'s target,
        /// or a structural composer's `references_attestation_id`. Carried so a
        /// failure at this op can print the referenced row's PROVENANCE.
        pub referenced: Option<String>,
        /// How the `target` SELECTOR resolved on this backend — `minted` length,
        /// the index it landed on, and the mint history. Complements
        /// [`Provenance`]: that says what happened to a row, this says why this
        /// op aimed at that row at all. Populated where the distinction bites
        /// (an absent promote target).
        pub selector_note: Option<String>,
    }

    /// The full record of a sequence run against one backend.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Transcript {
        /// Per-op outcome, in order.
        pub outcomes: Vec<OpOutcome>,
        /// The NORMALIZED final corpus (see [`Machine::snapshot_normalized`]).
        pub final_state: String,
        /// The NORMALIZED corpus after EACH op. Compared per-op by
        /// [`assert_parity`] so the FIRST divergence is what fails — a
        /// differential that only compares the final state reports whichever
        /// consequence happened to survive to the end.
        pub states: Vec<String>,
        /// This backend's per-id [`Provenance`]. Read by failure messages so a
        /// symptom at op N can name the op that actually diverged.
        pub provenance: BTreeMap<String, Provenance>,
        /// How many federation-tier rows the sequence left behind that carry a
        /// real hybrid signature — the meta-coverage signal that the generator
        /// is reaching interesting states rather than refusing everything.
        pub signed_federation_rows: usize,
        /// How many writes the AV-77 de-admission gate actually REFUSED during
        /// the sequence. A meta-coverage signal like
        /// [`Self::signed_federation_rows`], and never a compared axis: an op
        /// alphabet that can EMIT a de-admission but never reaches the state
        /// where one BITES leaves the gate as unexercised as it was before the
        /// op existed.
        pub deadmissions_enforced: usize,
    }

    /// The model + driver. Holds ONLY what the substrate cannot be asked for
    /// (which ids were minted through a server-clocked path, which
    /// `(attester, dimension)` coordinates are occupied); every assertion reads
    /// its ground truth back out of the real directory.
    pub struct Machine<'a> {
        dir: &'a dyn FederationDirectory,
        /// Per-run scope for every id this machine writes. See
        /// [`Principal::key_id_in`].
        tag: String,
        /// The `target` selector's DOMAIN, in mint order.
        ///
        /// Deliberately a mix of outcome and intent, and the distinction is
        /// load-bearing: an id lands here when the substrate ADMITTED it, and
        /// ALSO — unconditionally — when the op belongs to a PINNED divergence
        /// class, so that the domain a later op selects from is identical on
        /// both backends even where their admission disagrees. Without that,
        /// the two runs would issue DIFFERENT ops from the same sequence and
        /// the differential would stop being a differential.
        ///
        /// Because it is a mix, membership here proves nothing on its own —
        /// [`Machine::provenance`] is what records each id's actual fate, and
        /// every failure message reports THAT, never bare membership.
        minted: Vec<String>,
        /// The subset of `minted` written through a LOCAL path, whose
        /// `asserted_at` / `scrub_timestamp` / `persist_row_hash` are minted
        /// from the server's wall clock and therefore cannot be compared across
        /// two independently-executed runs. See [`Self::snapshot_normalized`].
        server_clocked: BTreeSet<String>,
        /// Per-id PROVENANCE: which op asked for it, and what this backend
        /// actually did. The thing failure messages read.
        provenance: BTreeMap<String, Provenance>,
        /// `(attesting_key_id, dimension)` pairs an admitted row occupies — the
        /// coordinate domain [`OpKind::UnsignedLocalWrite`] aims at.
        occupied: Vec<(String, String)>,
        /// The structural-revocation TARGET each op slot resolved to, memoized
        /// by slot.
        ///
        /// Load-bearing for I3: a replay must re-submit the BYTE-IDENTICAL row,
        /// and resolving the target afresh would read a `minted` list that has
        /// grown since — so the "replay" would carry a different
        /// `references_attestation_id` under the same id. (The harness learned
        /// this the hard way, and the accidentally-different replay is how it
        /// found the duplicate-id divergence that
        /// `memory_admits_a_duplicate_attestation_id` now witnesses.)
        resolved_targets: BTreeMap<usize, String>,
        /// See [`Transcript::deadmissions_enforced`].
        deadmissions_enforced: usize,
    }

    impl<'a> Machine<'a> {
        /// A machine over `dir`. The caller must have registered the cast
        /// ([`register_cast`]) first.
        #[must_use]
        pub fn new(dir: &'a dyn FederationDirectory, tag: &str) -> Self {
            Self {
                dir,
                tag: tag.to_owned(),
                minted: Vec::new(),
                server_clocked: BTreeSet::new(),
                occupied: Vec::new(),
                provenance: BTreeMap::new(),
                resolved_targets: BTreeMap::new(),
                deadmissions_enforced: 0,
            }
        }

        /// The deterministic attestation id for op index `seq`. A UUIDv5 (not a
        /// bare label) so the id is a legal UUID on every backend, and
        /// deterministic so the two backends in the differential mint the SAME
        /// id for the same op — without which their rows could not be compared
        /// at all.
        #[must_use]
        pub fn id_for(tag: &str, seq: usize) -> String {
            uuid::Uuid::new_v5(
                &uuid::Uuid::NAMESPACE_OID,
                format!("ciris-persist/substrate_machine/{tag}/{seq}").as_bytes(),
            )
            .to_string()
        }

        /// `p`'s key id in THIS run.
        #[must_use]
        pub fn kid(&self, p: Principal) -> String {
            p.key_id_in(&self.tag)
        }

        /// Apply `op` at sequence slot `seq` and instant `at`.
        ///
        /// `seq` and `at` are caller-supplied, never derived internally, for
        /// one reason: I3 (replay idempotence) must re-apply the *identical*
        /// op — same id, same timestamps — and an internally-advanced clock
        /// would make every replay a different write.
        pub async fn apply(&mut self, op: &Op, seq: usize, at: DateTime<Utc>) -> OpOutcome {
            let mut outcome = self.apply_inner(op, seq, at).await;

            // READ BACK. "The backend returned Ok" and "the backend stored the
            // row under the id we sent" are two different claims, and this
            // harness has already caught the substrate making the first without
            // the second — sqlite's §6.1 short-circuit did exactly that before
            // AV-76's tier-4b move. So the id is never assumed; it is fetched.
            if let Some(id) = outcome.row_id.clone() {
                outcome.stored = Some(
                    self.dir
                        .get_attestation(&id)
                        .await
                        .expect("get_attestation")
                        .is_some(),
                );
            }
            outcome.referenced = self.resolved_targets.get(&seq).cloned();

            // Record provenance for the op that MINTED the id — first write
            // wins, so an I3 replay does not overwrite the original fate, and
            // I4's probe slots (which live above I4_SEQ_BASE) never enter the
            // map at all.
            if seq < I4_SEQ_BASE && op.kind != OpKind::Promote && op.kind != OpKind::ReadBack {
                if let Some(id) = outcome.row_id.clone() {
                    self.provenance.entry(id).or_insert(Provenance {
                        minted_by_op: seq,
                        kind: op.kind,
                        admitted: outcome.admitted,
                        error_kind: outcome.error_kind,
                        stored: outcome.stored.unwrap_or(false),
                    });
                }
            }
            outcome
        }

        async fn apply_inner(&mut self, op: &Op, seq: usize, at: DateTime<Utc>) -> OpOutcome {
            let id = Self::id_for(&self.tag, seq);
            match op.kind {
                OpKind::InsertLocal => self.local_write(op, id, false, at).await,
                OpKind::UpsertLocal => self.local_write(op, id, true, at).await,
                OpKind::UnsignedLocalWrite => self.unsigned_local_write(op, id, at).await,
                OpKind::Put => self.put(op, seq, id, op.tier, None, at).await,
                OpKind::Withdraw => {
                    self.revocation_put(op, seq, id, attestation_type::WITHDRAWS, at)
                        .await
                }
                OpKind::Supersede => {
                    self.revocation_put(op, seq, id, attestation_type::SUPERSEDES, at)
                        .await
                }
                OpKind::Recant => {
                    self.revocation_put(op, seq, id, attestation_type::RECANTS, at)
                        .await
                }
                OpKind::Deadmit => {
                    // Always FEDERATION tier: a sanction nobody can replicate
                    // is a sanction that dies with the node that issued it.
                    self.put(op, seq, id, Tier::Federation, None, at).await
                }
                OpKind::Promote => self.promote(op, seq, at).await,
                OpKind::ReadBack => self.read_back().await,
            }
        }

        // ── the individual surfaces ──────────────────────────────────

        async fn local_write(
            &mut self,
            op: &Op,
            id: String,
            replace: bool,
            at: DateTime<Utc>,
        ) -> OpOutcome {
            let input =
                self.local_input(op, id.clone(), op.attester, op.family, op.cohort_scope, at);
            let res = if replace {
                self.dir.attestation_upsert_local(input).await
            } else {
                self.dir.attestation_insert_local(input).await
            };
            self.record_local(res, id, op.attester.key_id(), op.family.dimension())
        }

        /// **The #541 shape.** An unsigned local write aimed at coordinates an
        /// EARLIER ADMITTED row already occupies — a different writer, the same
        /// `(attesting_key_id, dimension)` key, a later clock. When nothing is
        /// occupied yet it degrades to a plain local write on the op's own
        /// coordinates (still a legal sequence, just not yet a collision).
        ///
        /// `cohort_scope` is forced to `self` because the local tier REQUIRES
        /// it (CEG §10.1.5). That is deliberate: the point of this op is to be
        /// ADMITTED and actually do work next to a signed row, not to bounce off
        /// the scope gate — a refused collision proves nothing.
        async fn unsigned_local_write(
            &mut self,
            op: &Op,
            id: String,
            at: DateTime<Utc>,
        ) -> OpOutcome {
            let (attester_key, dimension) = self.pick_coordinates(op);
            let mut input =
                self.local_input(op, id.clone(), op.attester, op.family, Scope::SelfScope, at);
            input.attesting_key_id = attester_key.clone();
            input.attestation_envelope.dimension = Some(dimension.clone());
            let res = self.dir.attestation_upsert_local(input).await;
            self.record_local(res, id, &attester_key, &dimension)
        }

        /// The structural-revocation target for op slot `seq`, resolved ONCE
        /// and memoized — see [`Machine::resolved_targets`].
        fn target_for(&mut self, op: &Op, seq: usize) -> String {
            if let Some(t) = self.resolved_targets.get(&seq) {
                return t.clone();
            }
            let t = self
                .pick_minted(op.target)
                .unwrap_or_else(|| Machine::id_for(&self.tag, usize::from(op.target)));
            self.resolved_targets.insert(seq, t.clone());
            t
        }

        async fn put(
            &mut self,
            op: &Op,
            seq: usize,
            id: String,
            tier: Tier,
            structural: Option<&'static str>,
            at: DateTime<Utc>,
        ) -> OpOutcome {
            let target = self.target_for(op, seq);
            let row = self.row_for(op, id.clone(), tier, structural, at, &target);
            // Read the coordinate off the ROW rather than off `op.family`: a
            // `Deadmit` overrides both the attester and the dimension, and a
            // model that recomputed them from the op would be a second list
            // that can disagree with the row actually submitted — the exact
            // shape this harness exists to catch (CIRISPersist#541).
            let occupied = (
                row.attesting_key_id.clone(),
                crate::federation::admission::envelope_dimension(&row.attestation_envelope)
                    .unwrap_or_default()
                    .to_owned(),
            );
            let res = self
                .dir
                .put_attestation(SignedAttestation { attestation: row })
                .await;
            match res {
                Ok(()) => {
                    self.remember(&id);
                    self.occupy(occupied);
                    OpOutcome {
                        admitted: true,
                        error_kind: None,
                        row_id: Some(id),
                        stored: None,
                        referenced: None,
                        selector_note: None,
                    }
                }
                Err(e) => {
                    // METERED, not compared. `Error::kind()` for the
                    // de-admission refusal is the shared
                    // `federation_invalid_argument`, so the transcript's
                    // compared axes cannot tell "the AV-77 gate fired" from any
                    // other argument refusal. This counter can, and
                    // `generator_reaches_interesting_states` reads it to prove
                    // the gate is REACHED rather than merely wired.
                    //
                    // The needle is the DIMENSION CONSTANT, not the English word
                    // "de-admitted": a program constant cannot drift out from
                    // under the test when someone rewords the message.
                    if let crate::federation::Error::InvalidArgument(msg) = &e {
                        if msg.contains(crate::federation::admission::PEER_DEADMISSION_DIMENSION) {
                            self.deadmissions_enforced += 1;
                        }
                    }
                    OpOutcome {
                        admitted: false,
                        error_kind: Some(e.kind()),
                        row_id: Some(id),
                        stored: None,
                        referenced: None,
                        selector_note: None,
                    }
                }
            }
        }

        /// `withdraws` / `supersedes` / `recants` — the three structural
        /// revocation primitives. Always federation tier (a revocation that
        /// nobody can replicate is not a revocation), always referencing a
        /// previously-minted row via the envelope's `references_attestation_id`
        /// (the field [`crate::federation::admission::check_withdraws_admission`]
        /// resolves authority through).
        async fn revocation_put(
            &mut self,
            op: &Op,
            seq: usize,
            id: String,
            structural: &'static str,
            at: DateTime<Utc>,
        ) -> OpOutcome {
            self.put(op, seq, id, Tier::Federation, Some(structural), at)
                .await
        }

        /// The local→federation promotion write-back, driven at the DIRECTORY
        /// primitive (`set_attestation_cohort_scope` then `promote_attestation`)
        /// exactly as `Engine::attestation_promote` drives it. The harness
        /// deliberately replicates NO engine-level policy — including the
        /// engine's `cohort_scope = self` refusal — because the differential's
        /// subject is the BACKEND contract, and a policy copy in the test would
        /// be one more list that can disagree with the real one.
        async fn promote(&mut self, op: &Op, seq: usize, at: DateTime<Utc>) -> OpOutcome {
            let Some(target) = self.pick_minted(op.target) else {
                // Nothing to promote yet — a legal, inert sequence position.
                return OpOutcome {
                    admitted: false,
                    error_kind: Some("substrate_machine_no_target"),
                    row_id: None,
                    stored: None,
                    referenced: None,
                    selector_note: None,
                };
            };
            // Remember what we aimed at even if it turns out not to be there —
            // the whole point of provenance is that an ABSENT target names the
            // op that failed to create it.
            self.resolved_targets.insert(seq, target.clone());
            let row = match self.dir.get_attestation(&target).await {
                Ok(Some(r)) => r,
                Ok(None) => {
                    // NOT "the promote failed" — the TARGET is not here. The
                    // provenance map says which op was supposed to create it
                    // and what this backend did with that op; `assert_parity`
                    // prints it, so the reader is pointed at the originating
                    // op rather than at this one.
                    return OpOutcome {
                        admitted: false,
                        error_kind: Some("substrate_machine_target_absent"),
                        // `row_id` stays a BARE id: it is a lookup key (it
                        // feeds `get_attestation` and keys the provenance map),
                        // not a message. The selector arithmetic goes in
                        // `selector_note`, which is where diagnostics belong.
                        row_id: Some(target.clone()),
                        stored: Some(false),
                        referenced: Some(target),
                        selector_note: Some(self.target_provenance(op.target)),
                    };
                }
                Err(e) => {
                    return OpOutcome {
                        admitted: false,
                        error_kind: Some(e.kind()),
                        row_id: Some(target),
                        stored: None,
                        referenced: None,
                        selector_note: None,
                    }
                }
            };
            // Sign the row's CURRENT envelope with the row's OWN attesting key
            // — the produce-path contract (`Engine::attestation_promote` signs
            // canonical(envelope) with the node's signer and stamps its derived
            // key id). Using the row's attester keeps `scrub_key_id`'s FK and
            // the ingest gate's pubkey resolution coherent without an Engine.
            //
            // v26.0.0 (CIRISPersist#589 / AV-83) — the separate
            // `set_attestation_cohort_scope` call that used to precede this is
            // gone, because the primitive now CARRIES the placement. This
            // harness found the reason: once `promote_attestation` could refuse
            // on authority grounds, the old two-step left a refused promotion
            // having already rewritten `cohort_scope` + `persist_row_hash`, and
            // I2a ("a REFUSED op must leave every existing row byte-identical")
            // failed on `Promote{scope: Community}` and on
            // `Promote{scope: Family}` within one run. The harness mirrors the
            // primitive, so it mirrors the fix — one gated write.
            //
            // v31.0.0 (CIRISPersist#649) — and it RE-STAMPS the typed-column
            // mirror before signing, because the promotion changes
            // `cohort_scope` and #643 bound that column into the signed bytes.
            // Signing the pre-promotion envelope produced a row every peer
            // refused; the harness mirrors the primitive, so it mirrors that
            // fix too.
            let mut reseal =
                ts::reseal_for_scope(&row.attesting_key_id, &row, op.cohort_scope.as_str());
            reseal.scrub_timestamp = at;
            let res = self
                .dir
                .promote_attestation(&target, op.cohort_scope.as_str(), &reseal)
                .await;
            match res {
                Ok(_) => OpOutcome {
                    admitted: true,
                    error_kind: None,
                    row_id: Some(target),
                    stored: None,
                    referenced: None,
                    selector_note: None,
                },
                Err(e) => OpOutcome {
                    admitted: false,
                    error_kind: Some(e.kind()),
                    row_id: Some(target),
                    stored: None,
                    referenced: None,
                    selector_note: None,
                },
            }
        }

        /// Read the corpus back through the REAL replication surfaces and
        /// re-run the REAL ingest verifier on every federation-tier row (I1,
        /// mid-sequence). Panics on a verification failure — that IS the
        /// invariant.
        async fn read_back(&mut self) -> OpOutcome {
            self.assert_i1("mid-sequence ReadBack").await;
            OpOutcome {
                admitted: true,
                error_kind: None,
                row_id: None,
                stored: None,
                referenced: None,
                selector_note: None,
            }
        }

        // ── row / input builders ─────────────────────────────────────

        /// v31.0.0 (CIRISPersist#598) — `at` is the MODEL clock, and it is
        /// supplied in the envelope rather than left for the door to mint.
        ///
        /// [`local_row_instant`](crate::federation::admission::local_row_instant)
        /// honours a caller-supplied `asserted_at` and mints `Utc::now()` only
        /// when the envelope is silent. Both are real production shapes; the
        /// harness must take the caller-supplied one, because the local door now
        /// stamps whatever instant it settles on into the SIGNED envelope — and
        /// promotion re-signs those bytes. A minted instant would therefore make
        /// the promoted row's SIGNATURE differ between two runs of the same op
        /// sequence, and I3 (replay) and I5 (the memory/sqlite differential)
        /// would be comparing a clock. The only alternatives were to stop
        /// comparing signatures on promoted rows — blinding the differential to
        /// exactly the divergence class this module exists to catch — or this.
        ///
        /// Determinism here is a strict GAIN in what is compared: with the
        /// instant supplied, `asserted_at`, `scrub_timestamp` and
        /// `persist_row_hash` are all functions of the drawn sequence, so the
        /// normalization that used to elide all three is gone and local rows
        /// are compared byte-for-byte like every other row.
        fn local_input(
            &self,
            op: &Op,
            id: String,
            attester: Principal,
            family: Family,
            scope: Scope,
            at: DateTime<Utc>,
        ) -> LocalAttestationInput {
            let envelope = envelope_for(family, attester, op.subject);
            let mut core = crate::federation::envelope::EnvelopeCore::from_value(envelope)
                .expect("harness envelopes are objects");
            core.asserted_at = Some(at.to_rfc3339());
            LocalAttestationInput {
                attestation_id: Some(id),
                attesting_key_id: self.kid(attester),
                attested_key_id: Some(self.kid(op.subject)),
                attestation_type: op.att_type_str(),
                weight: None,
                expires_at: None,
                attestation_envelope: core,
                subject_key_ids: vec![self.kid(op.subject)],
                cohort_scope: scope.as_str().to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            }
        }

        fn row_for(
            &self,
            op: &Op,
            id: String,
            tier: Tier,
            structural: Option<&'static str>,
            at: DateTime<Utc>,
            target: &str,
        ) -> Attestation {
            // A `Deadmit` names its own author, type and dimension — the gate
            // folds over `list_attestations_by(self_key_id)` filtered on
            // `attestation_type == scores` and the de-admission dimension, so a
            // row missing any of the three is stored and INERT. Built here, in
            // the ONE row builder, so I4's narrowing probes narrow the same row
            // the sequence submitted rather than a lookalike.
            let attester = if op.kind == OpKind::Deadmit {
                SELF_PRINCIPAL
            } else {
                op.attester
            };
            let mut envelope = if op.kind == OpKind::Deadmit {
                deadmission_envelope()
            } else {
                envelope_for(op.family, attester, op.subject)
            };
            if structural.is_some() {
                // A structural revocation names its target in the envelope —
                // the field the §3.2.3 authority resolver reads. The target is
                // resolved by the CALLER and memoized per slot (see
                // `resolved_targets`) so a replay is byte-identical.
                let target = target.to_owned();
                envelope
                    .as_object_mut()
                    .expect("harness envelopes are objects")
                    .insert("references_attestation_id".into(), target.into());
            }
            // v31.0.0 (CIRISPersist#598) — THE SIGNED INSTANTS, stamped BEFORE
            // the signature, from the very expressions the struct literal below
            // assigns to the columns.
            //
            // This is a WELL-FORMEDNESS stamp, and stamping it does not blunt a
            // single property. `check_instant_binding` is a TIER-1 gate: an
            // unstamped row is refused there, BEFORE the hybrid verify, before
            // the §6.1 dedup short-circuit, before the AV-77 fold. Leaving the
            // instants off would therefore have made every one of this module's
            // properties measure the same trivial refusal — including
            // `dedup_short_circuit_never_accepts_an_unverified_row`, whose
            // whole subject is a row that reaches the CRYPTO gate. The
            // deliberately-broken axes stay exactly where they were and where
            // the generator can reason about them: [`SigState`] (the signature),
            // [`CoSign`] (the co-signature set), and [`Narrowing`] (the I4
            // probes). None of them is the instant binding, and none of them is
            // reached by a row this substrate refuses at the door.
            //
            // Neither instant needs truncating: the harness clock is a
            // whole-second walk from a fixed RFC-3339 constant and
            // [`harness_expires_at`] is another, so both already sit on the
            // microsecond substrate floor. That is asserted, not assumed —
            // `harness_instants_are_writable` pins it, so a future clock drawn
            // with sub-microsecond precision fails as a NAMED claim rather than
            // as every property at once.
            let expires_at = if op.kind == OpKind::Deadmit {
                // A de-admission carries NO expiry: the constant's contract is
                // "live unless the node `withdraws` it", and an expiring
                // sanction would be lifted by the calendar rather than by a
                // decision anybody made. Everything else gets
                // [`HARNESS_EXPIRES_AT`] — see there for why it is not a
                // relative offset.
                None
            } else {
                Some(harness_expires_at())
            };
            {
                let obj = envelope
                    .as_object_mut()
                    .expect("harness envelopes are objects");
                obj.insert(
                    crate::federation::envelope::paths::ASSERTED_AT.into(),
                    at.to_rfc3339().into(),
                );
                // Bound in BOTH directions, so the absent case is an ABSENT
                // key, not a null.
                match expires_at {
                    None => {
                        obj.remove(crate::federation::envelope::paths::EXPIRES_AT);
                    }
                    Some(t) => {
                        obj.insert(
                            crate::federation::envelope::paths::EXPIRES_AT.into(),
                            t.to_rfc3339().into(),
                        );
                    }
                }
            }
            // v31.0.0 (CIRISPersist#643) — THE TYPED-COLUMN MIRROR, stamped
            // into the envelope BEFORE it is signed. Built here for the same
            // reason everything else is: this is the ONE row builder, so the
            // mirror the harness signs is the mirror of the row the harness
            // submits — a mirror assembled anywhere else would drift from the
            // row and the differential would measure the drift, not the gate.
            //
            // v31.0.0 (CIRISPersist#658) — built as a `RowMirror`, not as a
            // `json!` literal with the same member names. `RowMirror` is
            // `deny_unknown_fields` over a CLOSED set, so a hand-written twin
            // is a second definition of the projection the gate checks — the
            // exact defect class the paragraph above argues against, one layer
            // down. As a struct literal an eighth member is a compile error
            // here; as a `json!` it was a mirror the gate silently refused.
            // (The same shape was found and fixed in `blobs.rs` this release.)
            crate::federation::envelope::RowMirror {
                attestation_id: id.clone(),
                attesting_key_id: self.kid(attester),
                attestation_type: structural
                    .map_or_else(|| op.att_type_str(), std::borrow::ToOwned::to_owned),
                attested_key_id: self.kid(op.subject),
                subject_key_ids: vec![self.kid(op.subject)],
                cohort_scope: op.cohort_scope.as_str().to_owned(),
                // Mirrors the `weight: None` this builder stamps on the row
                // below; absent ⇔ the column is NULL.
                weight: None,
            }
            .insert_into(&mut envelope, &id)
            .expect("harness envelopes are objects");
            let (hash, classical, pqc) =
                signature_for_key(op.signature, &self.kid(attester), &envelope);
            // v24.0.0 (CIRISPersist#556) — the co-signature set, over the SAME
            // canonical envelope bytes the base scrub signed. Built in the ONE
            // row builder so every signed-plane op can carry it and I1 re-runs
            // the real verifier over it.
            let additional_scrubs: Vec<crate::federation::types::ScrubSig> = op
                .cosign
                .co_signers(attester)
                .into_iter()
                .map(|p| {
                    let state = if op.cosign == CoSign::Corrupt {
                        SigState::Corrupt
                    } else {
                        SigState::Valid
                    };
                    let (_, c, q) = signature_for_key(state, &self.kid(p), &envelope);
                    crate::federation::types::ScrubSig {
                        scrub_key_id: self.kid(p),
                        scrub_signature_classical: c,
                        scrub_signature_pqc: q,
                    }
                })
                .collect();
            Attestation {
                attestation_id: id,
                attesting_key_id: self.kid(attester),
                attested_key_id: self.kid(op.subject),
                attestation_type: structural
                    .map_or_else(|| op.att_type_str(), std::borrow::ToOwned::to_owned),
                weight: None,
                asserted_at: at,
                // Decided ABOVE, where it is stamped into the signed envelope:
                // the column and its signed twin come from one expression, so
                // the #598 binding holds by construction rather than by two
                // sites agreeing.
                expires_at,
                attestation_envelope: envelope,
                original_content_hash: hash,
                scrub_signature_classical: classical,
                scrub_signature_pqc: pqc,
                scrub_key_id: self.kid(attester),
                scrub_timestamp: at,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: vec![self.kid(op.subject)],
                withdraws_admission_rule: None,
                cohort_scope: op.cohort_scope.as_str().to_owned(),
                tier: tier.as_str().to_owned(),
                promoted_at: None,
                additional_scrubs,
            }
        }

        // ── model bookkeeping ────────────────────────────────────────

        fn record_local(
            &mut self,
            res: Result<String, crate::federation::Error>,
            id: String,
            attester_key: &str,
            dimension: &str,
        ) -> OpOutcome {
            match res {
                Ok(minted) => {
                    self.remember(&minted);
                    self.server_clocked.insert(minted.clone());
                    self.occupy((attester_key.to_owned(), dimension.to_owned()));
                    OpOutcome {
                        admitted: true,
                        error_kind: None,
                        row_id: Some(minted),
                        stored: None,
                        referenced: None,
                        selector_note: None,
                    }
                }
                Err(e) => OpOutcome {
                    admitted: false,
                    error_kind: Some(e.kind()),
                    row_id: Some(id),
                    stored: None,
                    referenced: None,
                    selector_note: None,
                },
            }
        }

        fn remember(&mut self, id: &str) {
            if !self.minted.iter().any(|m| m == id) {
                self.minted.push(id.to_owned());
            }
        }

        /// How the `target` SELECTOR resolved on this backend.
        ///
        /// Complements [`Provenance`] rather than duplicating it: that answers
        /// "what happened to this row", this answers "why did the op aim at
        /// that row at all". The distinction matters because `pick_minted`
        /// indexes `minted` MODULO its length, so if the two backends' lists
        /// ever differ in length the SAME `target` selector resolves to
        /// DIFFERENT rows and a divergence surfaces with no sign of where it
        /// began.
        ///
        /// The mint op for each id is read back out of [`Self::provenance`] —
        /// the single source of truth. An earlier draft kept a `minted_at_op`
        /// array parallel to `minted`; that is the two-lists-that-disagree
        /// shape this whole harness exists to catch (CIRISPersist#541), and it
        /// has no business inside the instrument.
        fn target_provenance(&self, target: u8) -> String {
            if self.minted.is_empty() {
                return format!(
                    "minted=[] (nothing admitted yet on this backend; selector target={target})"
                );
            }
            let at = |id: &String| {
                self.provenance
                    .get(id)
                    .map_or("?".to_owned(), |p| p.minted_by_op.to_string())
            };
            let idx = usize::from(target) % self.minted.len();
            format!(
                "minted.len()={} selector target={target} → idx={idx} → id={} (minted at op {}); \
                 full mint history: {:?}",
                self.minted.len(),
                self.minted[idx],
                at(&self.minted[idx]),
                self.minted
                    .iter()
                    .map(|id| format!("op{}:{}", at(id), &id[..8.min(id.len())]))
                    .collect::<Vec<_>>()
            )
        }

        fn occupy(&mut self, coord: (String, String)) {
            if !self.occupied.contains(&coord) {
                self.occupied.push(coord);
            }
        }

        fn pick_minted(&self, target: u8) -> Option<String> {
            if self.minted.is_empty() {
                return None;
            }
            Some(self.minted[usize::from(target) % self.minted.len()].clone())
        }

        fn pick_coordinates(&self, op: &Op) -> (String, String) {
            if self.occupied.is_empty() {
                return (self.kid(op.attester), op.family.dimension().to_owned());
            }
            self.occupied[usize::from(op.target) % self.occupied.len()].clone()
        }

        // ── snapshots ────────────────────────────────────────────────

        /// Every attestation id the read surfaces currently REPORT. Model-free
        /// by construction — used by I2 to answer "did a refused op make a new
        /// row visible?" without the harness's own bookkeeping being part of
        /// the answer.
        pub async fn read_ids(&self) -> BTreeSet<String> {
            let mut ids = BTreeSet::new();
            for p in Principal::ALL {
                for row in self
                    .dir
                    .list_attestations_for(self.kid(p).as_str())
                    .await
                    .expect("list_attestations_for")
                {
                    ids.insert(row.attestation_id);
                }
                for row in self
                    .dir
                    .list_attestations_by(self.kid(p).as_str())
                    .await
                    .expect("list_attestations_by")
                {
                    ids.insert(row.attestation_id);
                }
            }
            ids
        }

        /// Every attestation id the corpus could plausibly hold: what the model
        /// asked for, UNIONED with what the real read surfaces report. The union
        /// matters — a row the model never asked for (a server-minted id, a
        /// backend that wrote more than it was told to) still lands in the
        /// snapshot and therefore still has to match.
        pub async fn corpus_ids(&self) -> BTreeSet<String> {
            let mut ids: BTreeSet<String> = self.minted.iter().cloned().collect();
            ids.extend(self.read_ids().await);
            ids
        }

        /// The EXACT corpus over an EXPLICIT id domain — every field, nothing
        /// elided.
        ///
        /// I2 supplies the domain rather than letting the snapshot derive one,
        /// and that is load-bearing: its two observations straddle the very
        /// `apply` that updates the model, so a self-derived domain would grow
        /// between them and the harness's own bookkeeping would read as a
        /// substrate write. A fixed domain (everything known before the op, plus
        /// the id the op would mint) compares like for like.
        pub async fn snapshot_over(&self, ids: &BTreeSet<String>) -> String {
            let mut out: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            for id in ids {
                let row = self
                    .dir
                    .get_attestation(id)
                    .await
                    .expect("get_attestation")
                    .map(|r| serde_json::to_value(&r).expect("Attestation serializes"));
                out.insert(id.clone(), row.unwrap_or(serde_json::Value::Null));
            }
            serde_json::to_string(&out).expect("snapshot serializes")
        }

        /// The NORMALIZED corpus, for comparisons across two independently
        /// executed runs (I3's replay, I5's differential).
        ///
        /// **Nothing is elided** — every field of every row is compared.
        ///
        /// It used to elide three, and ONLY on rows written through a local
        /// path: `asserted_at` and `scrub_timestamp` (minted from the server's
        /// own `Utc::now()`, so two runs legitimately differed) and
        /// `persist_row_hash` (a pure function of the row, hence of those two).
        ///
        /// v31.0.0 (CIRISPersist#598) removed the need. The local door now
        /// stamps its instant into the SIGNED envelope
        /// ([`crate::federation::envelope::stamp_signed_instants`]), and
        /// promotion re-signs those bytes — so a server-minted instant would
        /// have leaked into `original_content_hash` and both signature halves,
        /// where NO elision could reach it without blinding the differential to
        /// signature divergence. [`Machine::local_input`] therefore supplies the
        /// model clock in the envelope, which
        /// [`local_row_instant`](crate::federation::admission::local_row_instant)
        /// honours. Every local row is now a pure function of the drawn
        /// sequence, so the honest normalization is none at all.
        ///
        /// Deleting an elision is the direction this should always move: an
        /// elided field is a field no invariant is watching.
        pub async fn snapshot_normalized(&self) -> String {
            let mut out: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            for id in self.corpus_ids().await {
                let row = self
                    .dir
                    .get_attestation(&id)
                    .await
                    .expect("get_attestation")
                    .map(|r| serde_json::to_value(&r).expect("Attestation serializes"));
                out.insert(id, row.unwrap_or(serde_json::Value::Null));
            }
            // `serde_json::Map` is a `BTreeMap` here (no `preserve_order`
            // feature), so this string is key-order stable across backends.
            serde_json::to_string(&out).expect("snapshot serializes")
        }

        // ── invariants ───────────────────────────────────────────────

        /// **I1 — the #541 invariant.** No sequence of local writes may render a
        /// signed row unverifiable by a remote peer.
        ///
        /// Reads every federation-tier row back through the REAL replication
        /// surfaces (`list_attestations_for`, and `list_signed_records` — the
        /// path a peer actually pulls) and re-runs the REAL
        /// [`verify_federation_tier_ingest`](crate::federation::verify_federation_tier_ingest)
        /// on each. **Never a hand-rolled field comparison**: a field compare
        /// rebuilds the two-lists-that-disagree problem inside the test, which
        /// is the exact defect class this exists to catch. The verifier IS the
        /// list.
        pub async fn assert_i1(&self, at: &str) -> usize {
            let mut verified = 0usize;
            for p in Principal::ALL {
                // The bare read (what `list_signed_records` wraps for the
                // embedded-signature attestation kind).
                for row in self
                    .dir
                    .list_attestations_for(self.kid(p).as_str())
                    .await
                    .expect("list_attestations_for")
                {
                    if row.tier != attestation_tier::FEDERATION {
                        continue;
                    }
                    let id = row.attestation_id.clone();
                    crate::federation::verify_federation_tier_ingest(self.dir, &row)
                        .await
                        .unwrap_or_else(|e| {
                            panic!(
                                "I1 ({at}): a federation-tier row must remain verifiable by a \
                                 remote peer after ANY sequence of local writes — row {id} \
                                 (attester {attester}, dimension {dim:?}) no longer verifies: \
                                 {e} (CIRISPersist#541)",
                                attester = row.attesting_key_id,
                                dim = crate::federation::admission::envelope_dimension(
                                    &row.attestation_envelope
                                ),
                            )
                        });
                    verified += 1;
                }
                // And the replication surface itself, so the harness exercises
                // the wrapper a peer pulls through rather than only its callee.
                let replicated = self
                    .dir
                    .list_signed_records(
                        crate::federation::namespace::ReplicatedKind::Attestation,
                        p.key_id(),
                    )
                    .await
                    .expect("list_signed_records");
                for rec in replicated {
                    let row: Attestation = serde_json::from_value(rec.canonical_json)
                        .expect("a replicated attestation round-trips its own wire shape");
                    if row.tier != attestation_tier::FEDERATION {
                        continue;
                    }
                    let id = row.attestation_id.clone();
                    crate::federation::verify_federation_tier_ingest(self.dir, &row)
                        .await
                        .unwrap_or_else(|e| {
                            panic!(
                                "I1 ({at}): a row pulled through the REPLICATION surface \
                                 (list_signed_records) must verify at the receiving peer's \
                                 ingest gate — row {id} does not: {e} (CIRISPersist#541)"
                            )
                        });
                }
            }
            verified
        }

        /// How many federation-tier rows currently carry a real (non-empty)
        /// hybrid signature. The meta-coverage signal.
        pub async fn signed_federation_row_count(&self) -> usize {
            let mut n = 0;
            for id in self.corpus_ids().await {
                if let Ok(Some(row)) = self.dir.get_attestation(&id).await {
                    if row.tier == attestation_tier::FEDERATION
                        && !row.scrub_signature_classical.is_empty()
                        && row.scrub_signature_pqc.is_some()
                    {
                        n += 1;
                    }
                }
            }
            n
        }
    }

    // ── envelopes + signatures ───────────────────────────────────────

    /// The envelope for `family`, shaped so the family's REAL admission gate is
    /// the thing that decides — never a hand-encoded expectation. `Trace` in
    /// particular is built well-formed, so the ONLY axis that decides it is the
    /// self-emission polarity the generator controls (`subject == attester`).
    #[must_use]
    pub fn envelope_for(
        family: Family,
        attester: Principal,
        subject: Principal,
    ) -> serde_json::Value {
        match family {
            Family::Identity => serde_json::json!({
                "dimension": family.dimension(),
                "score": 1.0,
                "confidence": 0.9,
            }),
            Family::Reputation => serde_json::json!({
                "dimension": family.dimension(),
                "score": 0.5,
                "confidence": 0.8,
            }),
            Family::Capacity => serde_json::json!({
                "dimension": family.dimension(),
                "score": 0.7,
                "confidence": 0.6,
            }),
            Family::Trace => serde_json::json!({
                "dimension": family.dimension(),
                "trace_id": format!("sm-trace-{}", attester.key_id()),
                "agent_id_hash": format!("sha256:{}", "a".repeat(64)),
                "trace": { "thought": "substrate machine", "subject": subject.key_id() },
            }),
            Family::Reserved => serde_json::json!({
                "dimension": family.dimension(),
                "score": 1.0,
                "confidence": 1.0,
            }),
            // A payload the #510 closed grammar rejects (`deny_unknown_fields`)
            // — the always-refused probe.
            Family::ConsentGrant => serde_json::json!({
                "dimension": family.dimension(),
                "payload": { "not_a_grant_field": true },
            }),
        }
    }

    /// The `expires_at` every non-de-admission row the harness writes carries.
    ///
    /// **A FIXED FAR-FUTURE INSTANT, deliberately, and not `at + 30 days`.**
    /// This was `Some(at + Duration::days(30))` and it rotted, silently, on a
    /// date: the model clock is pinned to 2026-01-01 so two independently
    /// executed runs stamp byte-identical timestamps (I3's replay and I5's
    /// differential both compare `expires_at`), while gates evaluate liveness
    /// against **wall-clock `Utc::now()`**. From 2026-01-31 onward every row the
    /// harness wrote was therefore ALREADY EXPIRED at every such gate, and any
    /// fold with an `expires_at > now` term read the whole corpus as dead.
    ///
    /// [`OpKind::Deadmit`] is how that surfaced — a de-admission that landed and
    /// then refused nothing. It had been true of the harness for months and
    /// nothing failed, because no invariant in it depended on a row being LIVE.
    /// Coverage that decays with the calendar is worse than absent coverage: it
    /// was real once, so nobody looks again.
    ///
    /// A fixed future instant keeps both properties at once — deterministic
    /// across runs, and live for as long as anyone will run this.
    #[must_use]
    pub fn harness_expires_at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
            .expect("fixed instant")
            .with_timezone(&Utc)
    }

    /// The AV-77 peer de-admission envelope — [`OpKind::Deadmit`]'s payload.
    ///
    /// The de-admitted peer is named by the ROW's `attested_key_id`, not by the
    /// envelope: that is the column
    /// [`check_peer_deadmission`](crate::federation::admission::check_peer_deadmission)
    /// folds over, so putting the subject in the envelope as well would be a
    /// second copy that can disagree with the one that decides.
    ///
    /// `score` is negative because the constant's contract says so ("`score < 0`
    /// — the denial"), NOT because the gate reads it. The gate keys on
    /// `{attestation_type, attested_key_id, dimension, tombstone, expiry}` and
    /// never looks at the score. Emitting the documented shape is how the
    /// harness stays a witness for the contract rather than for the
    /// implementation: if a future validator starts enforcing the sign, this op
    /// already carries the value that must pass.
    #[must_use]
    pub fn deadmission_envelope() -> serde_json::Value {
        serde_json::json!({
            "dimension": crate::federation::admission::PEER_DEADMISSION_DIMENSION,
            "score": -1.0,
            "confidence": 0.9,
        })
    }

    /// `(original_content_hash, classical_b64, pqc_b64)` for `state`.
    ///
    /// [`SigState::Valid`] runs the REAL hybrid signer over the REAL canonical
    /// bytes; [`SigState::Corrupt`] flips one byte of that real signature (so
    /// the corruption is indistinguishable from a wire fault, not a shape
    /// error); [`SigState::Absent`] is the empty-sentinel shape a local row
    /// carries.
    #[must_use]
    pub fn signature_for(
        state: SigState,
        attester: Principal,
        envelope: &serde_json::Value,
    ) -> (String, String, Option<String>) {
        signature_for_key(state, attester.key_id(), envelope)
    }

    /// [`signature_for`] over an explicit signing key id.
    ///
    /// The machine signs with the TAGGED cast id ([`Principal::key_id_in`]),
    /// because that is the id `register_cast` registered and therefore the one
    /// whose pubkeys the ingest gate will resolve. The `Principal`-taking form
    /// above is kept for callers outside this module that use the untagged
    /// cast.
    #[must_use]
    pub fn signature_for_key(
        state: SigState,
        signing_key_id: &str,
        envelope: &serde_json::Value,
    ) -> (String, String, Option<String>) {
        match state {
            SigState::Valid => ts::sign_envelope(signing_key_id, envelope),
            SigState::Corrupt => {
                let (hash, classical, pqc) = ts::sign_envelope(signing_key_id, envelope);
                let mut bytes = B64.decode(&classical).expect("our own signature is base64");
                if let Some(b) = bytes.first_mut() {
                    *b ^= 0xff;
                }
                (hash, B64.encode(&bytes), pqc)
            }
            SigState::Absent => (String::new(), String::new(), None),
        }
    }

    impl Op {
        /// The wire `attestation_type` this op writes. The three structural
        /// revocation kinds override it in [`Machine::revocation_put`].
        #[must_use]
        pub fn att_type_str(&self) -> String {
            match self.kind {
                OpKind::Withdraw => attestation_type::WITHDRAWS.to_owned(),
                OpKind::Supersede => attestation_type::SUPERSEDES.to_owned(),
                OpKind::Recant => attestation_type::RECANTS.to_owned(),
                // A de-admission is `scores` BY DEFINITION: the gate's fold
                // filters on `attestation_type == scores`, so letting the
                // `target` selector hand this op a `delegates_to` would emit a
                // row that looks like a sanction, stores like a sanction, and
                // does nothing.
                OpKind::Deadmit => attestation_type::SCORES.to_owned(),
                _ => AttType::ALL[usize::from(self.target) % AttType::ALL.len()]
                    .as_str()
                    .to_owned(),
            }
        }
    }

    /// A STRICTLY-ADDITIVE transform on an op — I4's narrowings.
    ///
    /// "Additive" is the entire load-bearing word, and getting it wrong is easy:
    /// the harness's first attempt narrowed by **swapping the dimension** to a
    /// reserved (`system:*`) family, and I4 fired immediately. That was the
    /// TEST being wrong, not the substrate — and the reason is worth recording,
    /// because it is a fact about how this substrate gates:
    ///
    /// > **Dimension-keyed gates are per-family, not cumulative.** Swapping
    /// > `trace:complete:v1` for `system:machine:v1` does not ADD the
    /// > reserved-prefix rule on top of the trace validator; it REMOVES the
    /// > trace validator and adds the other. And the reserved-prefix emitter
    /// > rule is deliberately `scores`-ONLY — [`DimensionAdmissionPolicy::check`](crate::federation::admission::DimensionAdmissionPolicy::check)
    /// > returns `Ok` for every structural primitive — so on a `delegates_to`
    /// > the swap adds nothing at all and the op is correctly admitted.
    ///
    /// Each variant below therefore keeps EVERY field of the original op and
    /// only ADDS a precondition.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Narrowing {
        /// **+ a failing crypto check.** The identical row with one byte of its
        /// real signature flipped. Every gate the original faced is still
        /// faced, plus hybrid-verify.
        ///
        /// Applicable only where the signature is actually consulted: a
        /// federation-tier `Put` and the three structural revocations. A
        /// `tier = local` row is EXEMPT from the signature check by design
        /// (CC 5.3.2.2 deferred signature), so corrupting its signature adds
        /// nothing. That exemption is SAFE only because AV-78 made the stored
        /// tier equal the declared one; while `put_attestation` was dropping
        /// the `tier` column it was the hole itself, which is what
        /// `put_attestation_preserves_the_caller_declared_tier` now guards.
        CorruptSignature,
        /// **+ the attester-resolution precondition.** The identical row from
        /// [`UNREGISTERED_KEY_ID`]. Every write path resolves the attester
        /// against `federation_keys` (FK and/or pubkey lookup), so this adds a
        /// precondition and removes none.
        UnregisteredAttester,
        /// **+ the envelope-size cap.** The identical envelope plus a pad that
        /// pushes its canonical bytes past
        /// [`MAX_ATTESTATION_ENVELOPE_BYTES`](crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES).
        /// Runs FIRST at every attestation write chokepoint, so it is the one
        /// narrowing that applies to every write op on every path.
        OversizedEnvelope,
    }

    impl Narrowing {
        /// Every narrowing, in application order.
        pub const ALL: [Narrowing; 3] = [
            Narrowing::CorruptSignature,
            Narrowing::UnregisteredAttester,
            Narrowing::OversizedEnvelope,
        ];

        /// Whether this narrowing ADDS anything to `op`. A vacuous narrowing
        /// (one that changes nothing, or that would swap a gate rather than add
        /// one) must be skipped rather than asserted — an invariant that holds
        /// vacuously is an invariant nobody is checking.
        #[must_use]
        pub fn applies_to(self, op: &Op) -> bool {
            match self {
                Narrowing::CorruptSignature => {
                    op.signature == SigState::Valid
                        && matches!(
                            op.kind,
                            // `Deadmit` belongs here for the same reason the
                            // structural composers do: it is ALWAYS federation
                            // tier, so its signature is always consulted.
                            OpKind::Withdraw | OpKind::Supersede | OpKind::Recant | OpKind::Deadmit
                        )
                        || (op.kind == OpKind::Put
                            && op.tier == Tier::Federation
                            && op.signature == SigState::Valid)
                }
                Narrowing::UnregisteredAttester | Narrowing::OversizedEnvelope => matches!(
                    op.kind,
                    OpKind::InsertLocal
                        | OpKind::UpsertLocal
                        | OpKind::UnsignedLocalWrite
                        | OpKind::Put
                        | OpKind::Withdraw
                        | OpKind::Supersede
                        | OpKind::Recant
                        | OpKind::Deadmit
                ),
            }
        }
    }

    /// The pad that pushes an envelope past the 1 MiB canonical-bytes cap.
    fn oversize_pad() -> serde_json::Value {
        serde_json::Value::String(
            "x".repeat(crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES + 1024),
        )
    }

    /// Register the whole cast with REAL deterministic hybrid pubkeys, so every
    /// signature this harness produces verifies against a real registered key.
    pub async fn register_cast(dir: &dyn FederationDirectory, tag: &str) {
        for p in Principal::ALL {
            ts::register_hybrid_key(dir, &p.key_id_in(tag)).await;
        }
    }

    /// **The AV-77 lifecycle, as an op SEQUENCE.**
    ///
    /// The generator reaches de-admission-then-refusal on its own, but only in
    /// the minority of draws where the sanction lands, names a peer other than
    /// the node, and is followed by a write from exactly that peer — so the
    /// lifecycle is pinned deterministically as well. `#543`'s own
    /// `exercise_peer_deadmission` covers admit → sanction → refuse → scoped on
    /// a hand fixture; what only a SEQUENCE can express is the leg that makes
    /// the sanction legitimate rather than a one-way door:
    ///
    /// | op | act | expected |
    /// |---|---|---|
    /// | 0 | B writes | ADMITTED — before any judgement, a peer is a peer |
    /// | 1 | the node de-admits B | ADMITTED — a node may always author its own sanction |
    /// | 2 | B writes | REFUSED — the sanction is an ACT, not a note |
    /// | 3 | C writes | ADMITTED — de-admission is about ONE peer, never a lockdown |
    /// | 4 | the node WITHDRAWS its de-admission | ADMITTED — auditable, in-band |
    /// | 5 | B writes | ADMITTED AGAIN — revocable, so the door swings both ways |
    ///
    /// Op 4 is why this belongs in the state machine at all: it is an ordinary
    /// [`OpKind::Withdraw`] whose `target` selector resolves to the
    /// de-admission row minted at op 1. Nothing about the composer was
    /// specialised for AV-77 — the sanction is a CEG row like any other, which
    /// is precisely the design claim, and this sequence is what checks that the
    /// claim holds through the real target-selection path.
    #[must_use]
    pub fn deadmission_lifecycle_ops() -> Vec<Op> {
        let write_as = |who: Principal| Op {
            kind: OpKind::Put,
            family: Family::Identity,
            attester: who,
            subject: who,
            tier: Tier::Federation,
            cohort_scope: Scope::Federation,
            signature: SigState::Valid,
            cosign: CoSign::None,
            clock: ClockStep::Advance(1),
            // `target = 0` keeps `att_type_str` on `scores` (see
            // `AttType::ALL[target % 2]`); a `delegates_to` here would be a
            // different plane.
            target: 0,
        };
        vec![
            write_as(Principal::B),
            Op {
                kind: OpKind::Deadmit,
                // `attester` is IGNORED for a `Deadmit` (the row is authored by
                // `SELF_PRINCIPAL` whatever is drawn); written out here so the
                // sequence READS as what it is instead of relying on an override
                // the reader has to go and find.
                attester: SELF_PRINCIPAL,
                subject: Principal::B,
                ..write_as(Principal::B)
            },
            write_as(Principal::B),
            write_as(Principal::C),
            Op {
                kind: OpKind::Withdraw,
                attester: SELF_PRINCIPAL,
                subject: Principal::B,
                // `minted` is `[op0, op1]` when this op runs, so `1 % 2 = 1`
                // resolves to the DE-ADMISSION row. Asserted, not assumed —
                // `assert_deadmission_lifecycle` checks the resolved reference.
                target: 1,
                ..write_as(SELF_PRINCIPAL)
            },
            write_as(Principal::B),
        ]
    }

    /// Assert a [`deadmission_lifecycle_ops`] transcript shows the full AV-77
    /// lifecycle. Backend-agnostic, so the memory / sqlite / postgres arms all
    /// state the same six claims.
    pub fn assert_deadmission_lifecycle(name: &str, t: &Transcript) {
        let ops = deadmission_lifecycle_ops();
        assert_eq!(t.outcomes.len(), ops.len(), "({name}) transcript length");
        let expect = |i: usize, admitted: bool, why: &str| {
            assert_eq!(
                t.outcomes[i].admitted,
                admitted,
                "({name}) AV-77 lifecycle op {i} ({:?}): expected {}, got {} ({:?}) — {why}",
                ops[i].kind,
                if admitted { "ADMITTED" } else { "REFUSED" },
                if t.outcomes[i].admitted {
                    "ADMITTED"
                } else {
                    "REFUSED"
                },
                t.outcomes[i].error_kind,
            );
        };
        expect(
            0,
            true,
            "before any judgement, a peer's writes are a peer's writes",
        );
        expect(
            1,
            true,
            "a node may ALWAYS author its own de-admission, so it cannot lock itself out of \
             lifting one. v31.0.0 (#608): the exemption is AUTHORSHIP (attester == self), not \
             the dimension — the dimension arm let a de-admitted peer keep writing the sanction \
             dimension about third parties",
        );
        expect(
            2,
            false,
            "THE ACT — the leg that did not exist before v22.0.0. `moderation:*` records an \
             event, `consent:*` withdrawal is send-side; neither stops inbound injection",
        );
        expect(
            3,
            true,
            "SCOPED — de-admission is a judgement about ONE peer. A gate that widened to \
             everyone would be an outage dressed as a sanction",
        );
        expect(
            4,
            true,
            "the node can withdraw its own de-admission, in-band and auditably",
        );
        expect(
            5,
            true,
            "REVOCABLE — the de-admitted peer is admitted again. A sanction with no exit is the \
             censorship weapon the LOCAL scoping exists to avoid being",
        );

        // The withdraw must have pointed at the DE-ADMISSION row, not at
        // whatever the selector happened to land on. Without this the sequence
        // could pass by withdrawing something irrelevant while op 5 was admitted
        // for some unrelated reason — a green test proving nothing.
        assert_eq!(
            t.outcomes[4].referenced.as_deref(),
            t.outcomes[1].row_id.as_deref(),
            "({name}) AV-77 lifecycle: op 4's `withdraws` must reference the DE-ADMISSION row \
             minted at op 1 — if the target selector cannot reach a de-admission row then the \
             revocability leg is untested and op 5 is admitted for the wrong reason"
        );
        assert_eq!(
            t.deadmissions_enforced, 1,
            "({name}) AV-77 lifecycle: exactly ONE write must have been refused BY THE \
             DE-ADMISSION GATE (op 2). Zero means the gate never ran — the likeliest cause is a \
             driver that did not install `self_key_id_for(tag)`, which makes the gate dormant and \
             every `Deadmit` an inert write"
        );
    }

    /// Run `ops` against `dir`, asserting I1–I4 as it goes, and return the
    /// transcript the caller diffs for I5.
    ///
    /// The clock starts at a fixed instant and moves per
    /// [`Op::clock`] — so two backends running the same sequence see the same
    /// caller-supplied timestamps, and the only thing that can differ is the
    /// substrate.
    ///
    /// # The caller must install the node's own key id
    ///
    /// Before calling this, install [`self_key_id_for(tag)`](self_key_id_for) on
    /// the backend via its `set_self_key_id`. It is NOT done here because
    /// `set_self_key_id` is an inherent method on each concrete backend type and
    /// this function drives a `&dyn FederationDirectory` — the install needs the
    /// concrete type, so it belongs at the construction site.
    ///
    /// A driver that skips it runs a **strictly weaker machine**:
    /// [`check_peer_deadmission`](crate::federation::admission::check_peer_deadmission)
    /// is a no-op while the host has declared no identity, so every
    /// [`OpKind::Deadmit`] becomes an inert write and the AV-77 plane goes
    /// unexercised without anything saying so. That is not left to trust —
    /// [`generator_reaches_interesting_states`] asserts a de-admission actually
    /// REFUSED a later write, which fails if the install is missing.
    ///
    /// Installing it does not change how de-admission-free sequences are judged:
    /// with no de-admission row authored by the node, the gate's fold is empty
    /// and it returns `Ok`. What it changes is that the gate now RUNS — one
    /// `list_attestations_by(self)` per `put_attestation` — everywhere, which is
    /// the point.
    pub async fn run_sequence(dir: &dyn FederationDirectory, ops: &[Op], tag: &str) -> Transcript {
        register_cast(dir, tag).await;
        let mut m = Machine::new(dir, tag);
        let mut clock: DateTime<Utc> = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("fixed instant")
            .with_timezone(&Utc);
        let mut outcomes = Vec::with_capacity(ops.len());
        let mut states = Vec::with_capacity(ops.len());

        for (i, op) in ops.iter().enumerate() {
            // THE #541 LESSON, as code: the clock ADVANCES unless the op
            // deliberately asked not to. A reused timestamp is absorbed by the
            // monotonic guard, and a write that no-ops proves nothing.
            if let ClockStep::Advance(secs) = op.clock {
                clock += Duration::seconds(i64::from(secs.max(1)));
            }

            // I2's domain, FIXED across both observations: everything known
            // before the op, plus the id this op would mint. Fixed rather than
            // re-derived because the two observations straddle the `apply` that
            // updates the model — a growing domain would report the harness's
            // own bookkeeping as a substrate write.
            let mut i2_domain = m.corpus_ids().await;
            i2_domain.insert(Machine::id_for(tag, i));
            let before_exact = m.snapshot_over(&i2_domain).await;
            let read_ids_before = m.read_ids().await;
            let outcome = m.apply(op, i, clock).await;

            if outcome.admitted {
                // ── I3: replay idempotence ──────────────────────────
                // Re-apply the IDENTICAL op (same id, same instant) — what
                // anti-entropy does on every round. The state after two
                // applications must equal the state after one, whether the
                // replay is itself admitted (an idempotent write) or refused
                // (a conflict that wrote nothing).
                let after_once = m.snapshot_normalized().await;
                let _replay = m.apply(op, i, clock).await;
                let after_twice = m.snapshot_normalized().await;
                assert!(
                    after_once == after_twice,
                    "I3 (op {i} = {op:?}): replaying an ADMITTED op must leave the corpus \
                     exactly as one application did — an op that is not replay-idempotent \
                     diverges every peer that receives it twice.{diff}",
                    diff = diff_snapshots("once", &after_once, "twice", &after_twice)
                );
            } else {
                // ── I2: zero writes on refusal (AV-9) ───────────────
                // Two crisp claims: (a) every row that existed is byte-identical,
                // and (b) no NEW row became visible. A gate that writes before it
                // refuses has already admitted the row it is rejecting.
                let after_exact = m.snapshot_over(&i2_domain).await;
                assert!(
                    before_exact == after_exact,
                    "I2a (op {i} = {op:?}, refused with {kind:?}): a REFUSED op must leave every \
                     existing row byte-identical.{diff}",
                    kind = outcome.error_kind,
                    diff = diff_snapshots("before", &before_exact, "after", &after_exact)
                );
                let read_ids_after = m.read_ids().await;
                assert_eq!(
                    read_ids_before,
                    read_ids_after,
                    "I2b (op {i} = {op:?}, refused with {kind:?}): a REFUSED op must not make a \
                     new row VISIBLE — {new:?} appeared on the read surfaces",
                    kind = outcome.error_kind,
                    new = read_ids_after
                        .difference(&read_ids_before)
                        .collect::<Vec<_>>(),
                );

                // ── I4: monotone refusal ────────────────────────────
                // Per-narrowing applicability is decided by
                // `Narrowing::applies_to`, so a kind with nothing to narrow
                // (`Promote` / `ReadBack`) simply runs zero probes.
                assert_narrowings_still_refused(&mut m, op, i, clock).await;
            }
            // Pinned-ness is evaluated BEFORE this op's own triple is recorded:
            // the FIRST composer on a triple runs every gate on both backends
            // and stays fully compared; only a SUBSEQUENT one meets the
            // short-circuit.
            states.push(m.snapshot_normalized().await);
            outcomes.push(outcome);
        }

        // ── I1: the whole point ─────────────────────────────────────
        m.assert_i1("end of sequence").await;

        Transcript {
            outcomes,
            provenance: m.provenance.clone(),
            final_state: m.snapshot_normalized().await,
            states,
            signed_federation_rows: m.signed_federation_row_count().await,
            deadmissions_enforced: m.deadmissions_enforced,
        }
    }

    /// **I4 — monotone refusal.** If an op is refused, the same op carrying an
    /// ADDITIONAL constraint must still be refused. A gate whose refusal is not
    /// monotone has a hole reachable by making a request *more* restricted,
    /// which is the shape every privilege-escalation-by-narrowing bug takes.
    ///
    /// The narrowings are [`Narrowing::ALL`], each strictly ADDITIVE — see that
    /// type's doc for why "additive" is the load-bearing word, and for the
    /// substrate fact the harness learned by getting it wrong first (a
    /// dimension SWAP is not a narrowing).
    ///
    /// `cohort_scope` is deliberately NOT a narrowing axis, and that is a
    /// finding rather than an omission: `self` is the narrowest *visibility*,
    /// but it is the only scope the LOCAL tier ACCEPTS (CEG §10.1.5 requires
    /// it), so narrowing the scope makes a local-path op strictly MORE likely
    /// to be admitted. Visibility-narrowing and admission-narrowing point in
    /// opposite directions on that axis; asserting monotonicity over it would
    /// encode a false invariant.
    async fn assert_narrowings_still_refused(
        m: &mut Machine<'_>,
        op: &Op,
        i: usize,
        clock: DateTime<Utc>,
    ) {
        for (n_idx, narrowing) in Narrowing::ALL.iter().enumerate() {
            if !narrowing.applies_to(op) {
                continue;
            }
            let seq = I4_SEQ_BASE * (n_idx + 1) + i;
            let out = m.apply_narrowed(op, *narrowing, seq, i, clock).await;
            assert!(
                !out.admitted,
                "I4 (op {i} = {op:?}): the op was REFUSED, but the SAME op narrowed by \
                 {narrowing:?} was ADMITTED. Refusal is not monotone under adding that \
                 constraint — a request made strictly MORE restricted got strictly MORE \
                 access."
            );
        }
    }

    /// Sequence-slot base for I4's probe ops, so their deterministic ids can
    /// never collide with the sequence's own (or with each other's).
    const I4_SEQ_BASE: usize = 1_000_000;

    impl Machine<'_> {
        /// Apply `op` with `narrowing` applied — I4's probe.
        ///
        /// The narrowing is applied to the BUILT input/row rather than to the
        /// [`Op`], so the op alphabet stays a closed, shrinkable product of
        /// small enums: `Principal` has no "unregistered" member and `SigState`
        /// no "oversized" member by design, and adding them would pollute every
        /// ordinary generator draw with states that only I4 wants.
        async fn apply_narrowed(
            &mut self,
            op: &Op,
            narrowing: Narrowing,
            seq: usize,
            origin_seq: usize,
            at: DateTime<Utc>,
        ) -> OpOutcome {
            let id = Self::id_for(&self.tag, seq);
            match op.kind {
                OpKind::InsertLocal | OpKind::UpsertLocal | OpKind::UnsignedLocalWrite => {
                    let mut input = self.local_input(
                        op,
                        id.clone(),
                        op.attester,
                        op.family,
                        op.cohort_scope,
                        at,
                    );
                    match narrowing {
                        Narrowing::UnregisteredAttester => {
                            input.attesting_key_id = UNREGISTERED_KEY_ID.to_owned();
                        }
                        Narrowing::OversizedEnvelope => {
                            input
                                .attestation_envelope
                                .extra
                                .insert("sm_pad".into(), oversize_pad());
                        }
                        // The local tier defers its signature; nothing to
                        // corrupt. `applies_to` already filtered this out.
                        Narrowing::CorruptSignature => {}
                    }
                    let res = if op.kind == OpKind::InsertLocal {
                        self.dir.attestation_insert_local(input).await
                    } else {
                        self.dir.attestation_upsert_local(input).await
                    };
                    let attester = if narrowing == Narrowing::UnregisteredAttester {
                        UNREGISTERED_KEY_ID
                    } else {
                        op.attester.key_id()
                    };
                    self.record_local(res, id, attester, op.family.dimension())
                }
                OpKind::Put
                | OpKind::Withdraw
                | OpKind::Supersede
                | OpKind::Recant
                | OpKind::Deadmit => {
                    let structural = match op.kind {
                        OpKind::Withdraw => Some(attestation_type::WITHDRAWS),
                        OpKind::Supersede => Some(attestation_type::SUPERSEDES),
                        OpKind::Recant => Some(attestation_type::RECANTS),
                        _ => None,
                    };
                    let tier = if op.kind == OpKind::Put {
                        op.tier
                    } else {
                        Tier::Federation
                    };
                    // The ORIGINAL op's target, not a freshly-resolved one: the
                    // selector is `target % minted.len()` and `minted` has grown
                    // since, so re-resolving would give the probe a DIFFERENT
                    // `references_attestation_id` — a different envelope, a
                    // different §6.1 dedup triple, and therefore a different op.
                    // "The same op plus one constraint" has to mean it.
                    let target = self.target_for(op, origin_seq);
                    let mut row = self.row_for(op, id.clone(), tier, structural, at, &target);
                    match narrowing {
                        Narrowing::UnregisteredAttester => {
                            row.attesting_key_id = UNREGISTERED_KEY_ID.to_owned();
                            crate::federation::tier_ingest::test_support::reseal(&mut row);
                            row.scrub_key_id = UNREGISTERED_KEY_ID.to_owned();
                        }
                        Narrowing::CorruptSignature => {
                            // Re-sign CORRUPTLY over the row's own envelope with
                            // the ROW's own attester, so the only difference
                            // from the original is a failing crypto check — not
                            // a shape error and not a different signer.
                            // `row.attesting_key_id` rather than
                            // `op.attester`: a `Deadmit` row is authored by the
                            // NODE, so signing with the op's drawn attester
                            // would have swapped the signer as well and the
                            // probe would no longer be "the same op plus one
                            // constraint".
                            let (hash, classical, pqc) = signature_for_key(
                                SigState::Corrupt,
                                &row.attesting_key_id,
                                &row.attestation_envelope,
                            );
                            row.original_content_hash = hash;
                            row.scrub_signature_classical = classical;
                            row.scrub_signature_pqc = pqc;
                        }
                        Narrowing::OversizedEnvelope => {
                            if let Some(o) = row.attestation_envelope.as_object_mut() {
                                o.insert("sm_pad".into(), oversize_pad());
                            }
                        }
                    }
                    match self
                        .dir
                        .put_attestation(SignedAttestation { attestation: row })
                        .await
                    {
                        Ok(()) => {
                            self.remember(&id);
                            OpOutcome {
                                admitted: true,
                                error_kind: None,
                                row_id: Some(id),
                                stored: None,
                                referenced: None,
                                selector_note: None,
                            }
                        }
                        Err(e) => OpOutcome {
                            admitted: false,
                            error_kind: Some(e.kind()),
                            row_id: Some(id),
                            stored: None,
                            referenced: None,
                            selector_note: None,
                        },
                    }
                }
                // `Promote` / `ReadBack` carry no caller-supplied attester,
                // envelope, or signature; `Narrowing::applies_to` filters them
                // out before we get here.
                OpKind::Promote | OpKind::ReadBack => OpOutcome {
                    admitted: false,
                    error_kind: Some("substrate_machine_not_applicable"),
                    row_id: None,
                    stored: None,
                    referenced: None,
                    selector_note: None,
                },
            }
        }
    }

    /// **I5 — parity.** Assert two transcripts of the SAME sequence agree.
    ///
    /// No expected-value table exists or is wanted: the two backends ARE each
    /// other's oracle. "No backend is second-class" is this repo's standing
    /// invariant, and the #541 audit found memory silently accepting rows
    /// sqlite rejects — exactly the divergence this catches without anyone
    /// having had to predict it.
    /// A COMPACT diff of two snapshots: only the ids that differ, and within
    /// them only the fields that differ.
    ///
    /// Every invariant reports through this rather than dumping two multi-KiB
    /// JSON blobs. That is not cosmetic — a property test's whole value is the
    /// minimal counterexample it hands back, and a counterexample nobody can
    /// read is a counterexample nobody acts on. Each finding this harness
    /// produced was diagnosed from one line of this output.
    #[must_use]
    pub fn diff_snapshots(a_name: &str, a: &str, b_name: &str, b: &str) -> String {
        let pa: BTreeMap<String, serde_json::Value> = serde_json::from_str(a).unwrap_or_default();
        let pb: BTreeMap<String, serde_json::Value> = serde_json::from_str(b).unwrap_or_default();
        let mut out = String::new();
        let ids: BTreeSet<&String> = pa.keys().chain(pb.keys()).collect();
        for id in ids {
            let (x, y) = (pa.get(id), pb.get(id));
            if x == y {
                continue;
            }
            out.push_str(&format!("\n  row {id}:"));
            match (x, y) {
                (Some(serde_json::Value::Object(ox)), Some(serde_json::Value::Object(oy))) => {
                    let fields: BTreeSet<&String> = ox.keys().chain(oy.keys()).collect();
                    for f in fields {
                        if ox.get(f) == oy.get(f) {
                            continue;
                        }
                        let trim = |v: Option<&serde_json::Value>| {
                            let s = v.map_or("<absent>".to_owned(), ToString::to_string);
                            if s.len() > 120 {
                                format!("{}…", &s[..120])
                            } else {
                                s
                            }
                        };
                        out.push_str(&format!(
                            "\n    {f}: {a_name}={} | {b_name}={}",
                            trim(ox.get(f)),
                            trim(oy.get(f))
                        ));
                    }
                }
                _ => out.push_str(&format!(
                    "\n    {a_name}={} | {b_name}={}",
                    x.map_or("<no row>".to_owned(), ToString::to_string),
                    y.map_or("<no row>".to_owned(), ToString::to_string)
                )),
            }
        }
        if out.is_empty() {
            "\n  (no field-level difference — compare the raw snapshots)".to_owned()
        } else {
            out
        }
    }

    /// Explain WHERE a referenced row came from, on both backends.
    ///
    /// This is the instrumentation that turns "op 5 failed" into "op 5 failed
    /// BECAUSE op 2 diverged". A `Promote` (or a structural composer) points at
    /// a row minted several ops earlier; when that row is missing on one side,
    /// the useful sentence names the minting op and its per-backend fate — not
    /// the op that happened to trip over the consequence.
    #[must_use]
    pub fn explain_provenance(
        id: &str,
        a_name: &str,
        a: &Transcript,
        b_name: &str,
        b: &Transcript,
    ) -> String {
        match (a.provenance.get(id), b.provenance.get(id)) {
            (None, None) => format!(
                "\n  PROVENANCE of {id}: NEITHER backend has a record of minting it — the id \
                 came from the model's fallback, so no op ever created it. That is harness \
                 bookkeeping, not a substrate divergence."
            ),
            (x, y) => {
                let d = |p: Option<&Provenance>| {
                    p.map_or_else(|| "never minted".to_owned(), Provenance::describe)
                };
                let origin = x.or(y).map_or(usize::MAX, |p| p.minted_by_op);
                format!(
                    "\n  PROVENANCE of {id}: minted by op {origin}\n    {a_name}: {}\n    \
                     {b_name}: {}\n  ⇒ if those two lines differ, the divergence ORIGINATES at \
                     op {origin}, not at the op reported above.",
                    d(x),
                    d(y)
                )
            }
        }
    }

    /// Assert two transcripts of the same sequence agree, **op by op**, so the
    /// FIRST divergence is what fails.
    ///
    /// No expected-value table exists or is wanted: the two backends ARE each
    /// other's oracle. "No backend is second-class" is this repo's standing
    /// invariant, and the #541 audit found memory silently accepting rows
    /// sqlite rejects — exactly the divergence this catches without anyone
    /// having had to predict it.
    ///
    /// **I5 over THREE backends — with the odd one out NAMED.**
    ///
    /// The two-arm differential can only say "they disagree". With three arms a
    /// 2-1 split is real evidence about WHICH backend is wrong, and that is
    /// strictly more than twice as useful: it turns a divergence report into a
    /// bug report.
    ///
    /// Why this exists at all: both bugs this harness found in v22
    /// (`put_attestation` dropping `tier`, and the §6.1 short-circuit sitting
    /// ahead of the crypto gate) were present IDENTICALLY in postgres, and the
    /// two-arm oracle found NEITHER of them there — they were caught by reading
    /// postgres while porting the sqlite fix. A differential oracle is exactly
    /// as wide as its backend set, and ours was two-thirds of the parity trio.
    ///
    /// Reports per axis (admission / refusal kind / storedness / row state):
    /// - a 2-1 split names the minority backend as the suspect;
    /// - a 1-1-1 split says all three disagree, which is a different and worse
    ///   finding than any pair disagreeing.
    pub fn assert_three_way_parity(ops: &[Op], arms: &[(&str, &Transcript)]) {
        assert!(arms.len() >= 2, "a differential needs at least two arms");
        let n = arms[0].1.outcomes.len();
        for (name, t) in arms {
            assert_eq!(
                t.outcomes.len(),
                n,
                "I5: transcript length differs on {name}"
            );
        }

        /// The minority value in a 2-1 split, with the arm holding it.
        fn odd_one_out<T: PartialEq>(vals: &[(&str, T)]) -> String {
            if vals.len() < 3 {
                return String::new();
            }
            for i in 0..vals.len() {
                let others: Vec<usize> = (0..vals.len()).filter(|j| *j != i).collect();
                let all_others_agree = others.windows(2).all(|w| vals[w[0]].1 == vals[w[1]].1);
                if all_others_agree && vals[i].1 != vals[others[0]].1 {
                    return format!(
                        "\n  ⇒ ODD ONE OUT: {} disagrees with the other {} arms, which agree \
                         with each other. On a 2-1 split the minority is the suspect.",
                        vals[i].0,
                        others.len()
                    );
                }
            }
            "\n  ⇒ NO MAJORITY: all arms disagree with each other. That is a worse finding \
             than a 2-1 split — no backend can be treated as the reference."
                .to_owned()
        }

        for (i, op) in ops.iter().enumerate().take(n) {
            let admitted: Vec<(&str, bool)> = arms
                .iter()
                .map(|(nm, t)| (*nm, t.outcomes[i].admitted))
                .collect();
            let kinds: Vec<(&str, Option<&'static str>)> = arms
                .iter()
                .map(|(nm, t)| (*nm, t.outcomes[i].error_kind))
                .collect();
            let stored: Vec<(&str, Option<bool>)> = arms
                .iter()
                .map(|(nm, t)| (*nm, t.outcomes[i].stored))
                .collect();
            let states: Vec<(&str, &str)> = arms
                .iter()
                .map(|(nm, t)| (*nm, t.states[i].as_str()))
                .collect();

            assert!(
                admitted.windows(2).all(|w| w[0].1 == w[1].1),
                "I5 (op {i} = {op:?}): ADMISSION DIVERGES across the parity trio — {admitted:?}.\
                 {odd}",
                op = op,
                odd = odd_one_out(&admitted)
            );
            assert!(
                kinds.windows(2).all(|w| w[0].1 == w[1].1),
                "I5 (op {i} = {op:?}): REFUSAL KIND DIVERGES across the parity trio — \
                 {kinds:?}. All refused, but not at the same gate (AV-76).{odd}",
                op = op,
                odd = odd_one_out(&kinds)
            );
            assert!(
                stored.windows(2).all(|w| w[0].1 == w[1].1),
                "I5 (op {i} = {op:?}): STOREDNESS DIVERGES across the parity trio — \
                 {stored:?}.{odd}",
                op = op,
                odd = odd_one_out(&stored)
            );
            if !states.windows(2).all(|w| w[0].1 == w[1].1) {
                // Render the pairwise diff against the FIRST arm so the reader
                // sees fields, not two multi-KiB blobs.
                let mut detail = String::new();
                for (nm, st) in states.iter().skip(1) {
                    detail.push_str(&format!("\n  {} vs {nm}:", states[0].0));
                    detail.push_str(&diff_snapshots(states[0].0, states[0].1, nm, st));
                }
                panic!(
                    "I5 (op {i} = {op:?}): RESULTING ROW STATE DIVERGES across the parity trio \
                     — this is the FIRST op at which they differ.{odd}{detail}",
                    op = op,
                    odd = odd_one_out(&states)
                );
            }
        }
    }

    /// Four axes per op, each with the referenced row's provenance attached:
    /// admission, refusal kind, storedness (I6), and the resulting corpus.
    /// Nothing is skipped — every `KNOWN_DIVERGENCE_*` pin was retired once the
    /// bug behind it was fixed, which is what a pin is FOR.
    pub fn assert_parity(ops: &[Op], a_name: &str, a: &Transcript, b_name: &str, b: &Transcript) {
        assert_eq!(
            a.outcomes.len(),
            b.outcomes.len(),
            "I5: transcript lengths differ ({a_name} vs {b_name})"
        );
        for (i, (x, y)) in a.outcomes.iter().zip(b.outcomes.iter()).enumerate() {
            // The row this op POINTED AT (a promote target / a composer's
            // references_attestation_id), whose provenance explains a
            // divergence that originated upstream.
            let referenced = x
                .referenced
                .clone()
                .or_else(|| y.referenced.clone())
                .or_else(|| {
                    (ops[i].kind == OpKind::Promote)
                        .then(|| x.row_id.clone().or_else(|| y.row_id.clone()))
                        .flatten()
                });
            let why = referenced
                .as_deref()
                .map_or_else(String::new, |t| explain_provenance(t, a_name, a, b_name, b));

            assert!(
                x.admitted == y.admitted,
                "I5 (op {i} = {op:?}): ADMISSION DIVERGES — {a_name} {xa} ({xk:?}), \
                 {b_name} {ya} ({yk:?}). A row one backend accepts and another refuses is a \
                 mesh that cannot converge.{why}",
                op = ops[i],
                xa = if x.admitted { "ADMITTED" } else { "REFUSED" },
                xk = x.error_kind,
                ya = if y.admitted { "ADMITTED" } else { "REFUSED" },
                yk = y.error_kind,
            );
            // Refusal KIND — promoted back into the differential now that AV-76's
            // tiering has reached the memory backend (TIER 4b in `memory.rs`) and
            // the last gate-order divergence is gone. `Error::kind()` is the
            // machine-readable discriminator consumers branch on, so two backends
            // refusing the same row at DIFFERENT gates is a contract break even
            // though both correctly refused.
            assert!(
                x.error_kind == y.error_kind,
                "I5 (op {i} = {op:?}): REFUSAL KIND DIVERGES — {a_name} {xk:?} vs {b_name} \
                 {yk:?}. Both refused, so no row is at risk; what differs is WHICH GATE \
                 refused — the AV-76 gate-ordering contract.{why}",
                op = ops[i],
                xk = x.error_kind,
                yk = y.error_kind,
            );
            // I6 — ADMITTED IMPLIES STORED. Oracle-free, per backend: a
            // substrate that answers `Ok` must be able to show you the row
            // under the id you sent. Checked here (rather than in
            // `run_sequence`) so the message can name both backends at once.
            // Structural composers are EXEMPT: CEG §6.1 makes a replayed
            // composer a deliberate idempotent no-op — the backend returns
            // `Ok(())` and stores no new row, on every backend, by design. I6 is
            // about a backend that says yes and silently loses a row, not about
            // a documented dedup.
            let composer = matches!(
                ops[i].kind,
                OpKind::Withdraw | OpKind::Supersede | OpKind::Recant
            );
            for (name, o) in [(a_name, x), (b_name, y)] {
                if o.admitted && !composer {
                    if let (Some(id), Some(false)) = (o.row_id.as_deref(), o.stored) {
                        panic!(
                            "I6 (op {i} = {op:?}): {name} ADMITTED the write and then had no row \
                             under {id}. `Ok` and `stored` are different claims, and a peer that \
                             believes an accepted row landed will never retry it.{why}",
                            op = ops[i]
                        );
                    }
                }
            }
            assert!(
                x.stored == y.stored,
                "I5 (op {i} = {op:?}): STOREDNESS DIVERGES — {a_name} stored={xs:?}, \
                 {b_name} stored={ys:?}, though both reported admitted={adm}.{why}",
                op = ops[i],
                xs = x.stored,
                ys = y.stored,
                adm = x.admitted,
            );
            assert!(
                a.states[i] == b.states[i],
                "I5 (op {i} = {op:?}): RESULTING ROW STATE DIVERGES between {a_name} and \
                 {b_name} — this is the FIRST op at which they differ.{why}{diff}",
                op = ops[i],
                diff = diff_snapshots(a_name, &a.states[i], b_name, &b.states[i])
            );
        }
        assert!(
            a.final_state == b.final_state,
            "I5: FINAL row state diverges between {a_name} and {b_name} although every \
             individual op agreed — a convergence bug rather than an admission one.{diff}",
            diff = diff_snapshots(a_name, &a.final_state, b_name, &b.final_state)
        );
    }
}

/// The generators, the property bodies, and the meta-coverage assertion.
/// `proptest` is a dev-dependency, so this half cannot live in `test_support`.
#[cfg(all(test, feature = "sqlite"))]
mod proptests {
    use proptest::prelude::*;

    use super::test_support::{
        assert_deadmission_lifecycle, assert_parity, deadmission_lifecycle_ops, run_sequence,
        self_key_id_for, ClockStep, CoSign, Family, Op, OpKind, Principal, Scope, SigState, Tier,
        Transcript,
    };
    use crate::store::{Backend as _, MemoryBackend, SqliteBackend};

    /// The differential property's case budget. Every case pays a fresh sqlite
    /// `run_migrations`, up to 8 ops × (real ML-DSA-65 keygen + sign + verify),
    /// an I3 replay per admitted op, two I4 probes per refused op, and a full
    /// corpus snapshot on both sides of every op — on TWO backends. 64 keeps CI
    /// wall-clock in the low tens of seconds; raise `PROPTEST_CASES` in the
    /// environment to hunt.
    const PROPTEST_CASES: u32 = 64;

    /// Max ops per sequence. 8 is chosen so the shortest interesting #541-shaped
    /// sequence (signed put → different unsigned writer → read back → verify)
    /// fits with room for a promote and a revocation on either side.
    const MAX_OPS: usize = 8;

    fn arb_principal() -> impl Strategy<Value = Principal> {
        prop_oneof![Just(Principal::A), Just(Principal::B), Just(Principal::C),]
    }

    fn arb_family() -> impl Strategy<Value = Family> {
        prop_oneof![
            // The admitting families are weighted up: a generator that mostly
            // produces refusals passes every invariant vacuously (see
            // `generator_reaches_interesting_states`, which fails loudly if
            // this bias ever stops working).
            3 => Just(Family::Identity),
            3 => Just(Family::Reputation),
            2 => Just(Family::Capacity),
            2 => Just(Family::Trace),
            1 => Just(Family::Reserved),
            1 => Just(Family::ConsentGrant),
        ]
    }

    fn arb_scope() -> impl Strategy<Value = Scope> {
        prop_oneof![
            3 => Just(Scope::SelfScope),
            1 => Just(Scope::Family),
            1 => Just(Scope::Community),
            3 => Just(Scope::Federation),
        ]
    }

    fn arb_tier() -> impl Strategy<Value = Tier> {
        prop_oneof![1 => Just(Tier::Local), 3 => Just(Tier::Federation)]
    }

    fn arb_sig() -> impl Strategy<Value = SigState> {
        prop_oneof![
            6 => Just(SigState::Valid),
            1 => Just(SigState::Corrupt),
            1 => Just(SigState::Absent),
        ]
    }

    /// **The #541 lesson as a generator bias.** An ADVANCING clock is the
    /// default (9:1); an equal clock is the deliberate rare case. A harness
    /// that reuses timestamps cannot express a write the monotonic guard
    /// absorbs, and that is precisely why 1446 hand-written tests could not see
    /// #541.
    fn arb_clock() -> impl Strategy<Value = ClockStep> {
        prop_oneof![
            9 => (1u32..=3600).prop_map(ClockStep::Advance),
            1 => Just(ClockStep::Equal),
        ]
    }

    /// **The #556 axis.** `None` dominates so the ordinary single-scrub shape
    /// stays the common case (and the shrink target), while every sequence still
    /// has a real chance of putting a co-signed row through the storage
    /// round-trip, the differential and I1's real verifier. `Corrupt` is drawn
    /// as often as `Two` because "a co-signature the verifier does not check"
    /// is the failure this axis exists to make impossible.
    fn arb_cosign() -> impl Strategy<Value = CoSign> {
        prop_oneof![
            6 => Just(CoSign::None),
            2 => Just(CoSign::One),
            1 => Just(CoSign::Two),
            1 => Just(CoSign::Corrupt),
        ]
    }

    fn arb_kind() -> impl Strategy<Value = OpKind> {
        prop_oneof![
            2 => Just(OpKind::InsertLocal),
            2 => Just(OpKind::UpsertLocal),
            3 => Just(OpKind::Put),
            2 => Just(OpKind::Promote),
            1 => Just(OpKind::Withdraw),
            1 => Just(OpKind::Supersede),
            1 => Just(OpKind::Recant),
            3 => Just(OpKind::UnsignedLocalWrite),
            // Weighted level with `Put`, not down with the composers. A
            // `Deadmit` only becomes INTERESTING when a later op writes as the
            // peer it named, so the alphabet has to emit enough of them for that
            // conjunction to occur inside 8 ops — `deadmissions_enforced` in
            // `generator_reaches_interesting_states` is the measurement that
            // keeps this weight honest.
            3 => Just(OpKind::Deadmit),
            2 => Just(OpKind::ReadBack),
        ]
    }

    /// One op. Composed field-by-field (rather than as one opaque map) so
    /// proptest can shrink each axis INDEPENDENTLY — the difference between a
    /// failure report that says "this exact op" and one that says "somewhere in
    /// this pile".
    fn arb_op() -> impl Strategy<Value = Op> {
        (
            arb_kind(),
            arb_family(),
            arb_principal(),
            arb_principal(),
            arb_tier(),
            arb_scope(),
            arb_sig(),
            arb_cosign(),
            arb_clock(),
            any::<u8>(),
        )
            .prop_map(
                |(
                    kind,
                    family,
                    attester,
                    subject,
                    tier,
                    cohort_scope,
                    signature,
                    cosign,
                    clock,
                    target,
                )| {
                    Op {
                        kind,
                        family,
                        attester,
                        subject,
                        tier,
                        cohort_scope,
                        signature,
                        cosign,
                        clock,
                        target,
                    }
                },
            )
    }

    fn arb_sequence() -> impl Strategy<Value = Vec<Op>> {
        prop::collection::vec(arb_op(), 1..=MAX_OPS).prop_map(bias_deadmission_followups)
    }

    /// **Make the AV-77 conjunction actually occur.**
    ///
    /// A [`OpKind::Deadmit`] only proves anything when it LANDS and is then
    /// followed by a write from the very peer it named — that second write is
    /// the one [`check_peer_deadmission`](crate::federation::admission::check_peer_deadmission)
    /// refuses. A uniform generator reaches that conjunction rarely: the
    /// sanction needs a `Valid` signature (1 draw in 3), the follow-up needs a
    /// `Valid` signature too (or an earlier tier refuses it before the AV-77
    /// gate is ever consulted), and the follow-up's attester has to match the
    /// named subject (1 in 3). Measured on the unbiased generator: **7 of 240
    /// executed sequences, 2.9%** — re-measured after the expiry-horizon fix
    /// (limit 7), which is the number that matters, because under the broken
    /// clock the rate was **0 of 240**: the sanction could never be live, so no
    /// bias could have helped. The bias treats the sampling rate; the clock was
    /// the root cause, and a bias that had been tuned to work around it would
    /// have hidden it.
    ///
    /// At the meta-coverage test's 24-sequence budget that is an expected count
    /// of 0.7 — so observing zero is a coin flip. Asserting on it directly
    /// would be a flaky test reporting a real number, which this module already
    /// calls out as the worst of both (see the deterministic-RNG note in
    /// [`generator_reaches_interesting_states`]). **The fix belongs in the
    /// generator, not in the floor**: lowering a coverage floor to accommodate
    /// a newly-added op would defeat the reason the op was added.
    ///
    /// So: after a `Deadmit`, steer roughly half the following write ops onto
    /// the named peer with a `Valid` signature. The steering coin is
    /// `op.target`, a field the op ALREADY carries, so this stays a pure
    /// function of the drawn value — proptest shrinks the pre-transform vector
    /// and the transform re-applies deterministically at every shrink step. A
    /// transform that consulted fresh randomness would break shrinking, which
    /// is the whole reason this is a `prop_map` and not an RNG call.
    ///
    /// This biases WHERE the generator spends its budget; it does not narrow
    /// what it can express. Unbiased draws still occur — `Deadmit` still lands
    /// on the node itself (inert, and pinned separately by
    /// `third_party_deadmission_of_a_peer_is_inert`), still gets corrupt
    /// signatures, and still goes unfollowed.
    fn bias_deadmission_followups(mut ops: Vec<Op>) -> Vec<Op> {
        let mut sanctioned: Option<Principal> = None;
        for op in &mut ops {
            if op.kind == OpKind::Deadmit {
                // A node de-admitting ITSELF is inert by construction (the gate
                // always admits rows authored by the self key, else a node
                // could not lift its own denial), so it is not a follow-up
                // target worth steering toward.
                sanctioned = if op.subject == super::test_support::SELF_PRINCIPAL {
                    None
                } else {
                    // The sanction has to be admitted to exist at all.
                    op.signature = SigState::Valid;
                    op.tier = Tier::Federation;
                    Some(op.subject)
                };
                continue;
            }
            let Some(peer) = sanctioned else { continue };
            // Only steer ops that actually reach the gate: a write, carrying a
            // signature that will survive the tiers ahead of tier 4.
            if op.kind.dimension_is_caller_supplied() && op.target % 2 == 0 {
                op.attester = peer;
                op.signature = SigState::Valid;
                // ...and a scope that survives them too. MEASURED: with the
                // scope left to the draw this bias produced ONE enforced
                // de-admission across the meta-coverage slice, because
                // `arb_scope` puts only 3/8 of its weight on `federation` and
                // the de-admission gate sits at tier 4b — BEHIND the write-scope
                // gate. A steered write refused at tier 2 for having
                // `cohort_scope = self` at federation tier never reaches the
                // gate the steer exists to reach, and a bias that produces a
                // refusal at the wrong gate is not a bias, it is noise.
                op.cohort_scope = Scope::Federation;
            }
        }
        ops
    }

    /// A dedicated current-thread runtime per case. `proptest` bodies are
    /// synchronous, and the substrate is async; a per-case runtime also
    /// guarantees no state leaks between cases.
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(f)
    }

    /// A tag unique to this process AND this case, so the postgres arm — which
    /// runs against a SHARED database — never collides with another case or
    /// another concurrently-running test binary. All arms of one differential
    /// are handed the SAME tag; that is what keeps their rows comparable.
    fn fresh_tag() -> String {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        format!(
            "{:x}{:x}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// The three backend construction sites below are the ONLY places the
    /// node's own key id is installed, and they all install the same thing —
    /// [`self_key_id_for`]. It cannot happen inside `run_sequence` because
    /// `set_self_key_id` is an inherent method on each concrete backend and
    /// `run_sequence` drives a `&dyn FederationDirectory`; see that function's
    /// doc for what a driver that skips it silently loses.
    async fn run_on_memory(ops: &[Op], tag: &str) -> Transcript {
        let dir = MemoryBackend::new();
        dir.set_self_key_id(Some(self_key_id_for(tag)));
        run_sequence(&dir, ops, tag).await
    }

    async fn run_on_sqlite(ops: &[Op], tag: &str) -> Transcript {
        let dir = SqliteBackend::open_in_memory().await.expect("open sqlite");
        dir.run_migrations().await.expect("migrations");
        dir.set_self_key_id(Some(self_key_id_for(tag)));
        run_sequence(&dir, ops, tag).await
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: PROPTEST_CASES,
            // A failing sequence is the deliverable; spend the budget shrinking it.
            max_shrink_iters: 4096,
            .. ProptestConfig::default()
        })]

        /// **I1–I5 over arbitrary op sequences.**
        ///
        /// `run_sequence` asserts I1 (the real verifier still passes), I2 (a
        /// refused op wrote nothing), I3 (an admitted op replays to the same
        /// state) and I4 (refusal is monotone under narrowing) as it goes, on
        /// EACH backend independently. This body then asserts I5: memory and
        /// sqlite agreed, op for op and byte for byte.
        #[test]
        fn substrate_state_machine_holds_on_every_backend(ops in arb_sequence()) {
            let tag = fresh_tag();
            let (mem, sq) = block_on(async {
                let mem = run_on_memory(&ops, &tag).await;
                let sq = run_on_sqlite(&ops, &tag).await;
                (mem, sq)
            });
            assert_parity(&ops, "memory", &mem, "sqlite", &sq);
        }
    }

    /// The shared test database, or `None` when this run has no postgres.
    ///
    /// Same gate as every other pg test in the tree
    /// (`src/store/postgres.rs::pg_dsn`), so a developer or CI lane without a
    /// database SKIPS rather than fails.
    #[cfg(feature = "postgres")]
    fn pg_dsn() -> Option<String> {
        crate::test_pg::dsn()
    }

    #[cfg(feature = "postgres")]
    async fn run_on_postgres(ops: &[Op], tag: &str, dsn: &str) -> Transcript {
        use crate::store::PostgresBackend;
        let dir = PostgresBackend::connect(dsn)
            .await
            .expect("connect postgres");
        dir.run_migrations().await.expect("migrations");
        dir.set_self_key_id(Some(self_key_id_for(tag)));
        run_sequence(&dir, ops, tag).await
    }

    /// **THE FULL PARITY TRIO — memory ≡ sqlite ≡ postgres.**
    ///
    /// This exists because of a concrete miss. Both substrate bugs this harness
    /// found in v22 — `put_attestation` dropping the caller's `tier`, and the
    /// §6.1 replay short-circuit sitting ahead of the crypto gate — were
    /// present IDENTICALLY in postgres, and the two-arm oracle found NEITHER of
    /// them there. They were caught by hand while porting the sqlite fix. A
    /// differential oracle is exactly as wide as its backend set, and ours was
    /// two-thirds of the trio; postgres is the backend that actually runs in
    /// production.
    ///
    /// Postgres is a SHARED database, so every id this test writes is scoped by
    /// a per-case [`fresh_tag`]. The case count is deliberately much lower than
    /// the in-memory arms' — every op is a network round-trip, and the point of
    /// this arm is CROSS-BACKEND agreement, not depth of search; depth is the
    /// in-memory proptest's job. Raise `PROPTEST_CASES` to hunt harder against
    /// a real database.
    ///
    /// Skips cleanly when `CIRIS_PERSIST_TEST_PG_URL` is unset.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn substrate_state_machine_three_way_parity_postgres() {
        // Imported HERE, not at module scope: this helper has exactly one
        // caller and that caller is `postgres`-gated, so a module-scope import
        // is an unused-import error on a sqlite-only build — which is the
        // build CI runs (`--all-targets --features sqlite`).
        use super::test_support::assert_three_way_parity;
        use proptest::strategy::{Strategy as _, ValueTree};
        use proptest::test_runner::{Config, TestRng, TestRunner};

        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };

        /// Sequences run against the real database. Small on purpose — see the
        /// doc above.
        const PG_CASES: u32 = 48;

        // A DETERMINISTIC generator: this arm is a parity check, and a parity
        // check that explores a different corner every run cannot be bisected
        // when it fails. The in-memory proptest owns randomized search.
        let mut runner = TestRunner::new_with_rng(
            Config {
                cases: PG_CASES,
                ..Config::default()
            },
            TestRng::deterministic_rng(proptest::test_runner::RngAlgorithm::ChaCha),
        );

        // CASE 0 IS NOT RANDOM. The AV-77 lifecycle is the one sequence whose
        // reachability motivated `OpKind::Deadmit`, and postgres is the backend
        // that shipped the de-admission gate with nothing proving it — so the
        // trio runs it explicitly rather than hoping the generator lands on it
        // inside 48 draws.
        {
            let ops = deadmission_lifecycle_ops();
            let tag = fresh_tag();
            let mem = run_on_memory(&ops, &tag).await;
            let sq = run_on_sqlite(&ops, &tag).await;
            let pg = run_on_postgres(&ops, &tag, &dsn).await;
            for (name, t) in [("memory", &mem), ("sqlite", &sq), ("postgres", &pg)] {
                assert_deadmission_lifecycle(name, t);
            }
            assert_three_way_parity(
                &ops,
                &[("memory", &mem), ("sqlite", &sq), ("postgres", &pg)],
            );
            eprintln!("three-way parity: AV-77 de-admission lifecycle agreed on all three arms");
        }

        for case in 0..PG_CASES {
            let ops = arb_sequence()
                .new_tree(&mut runner)
                .expect("generator produces a value")
                .current();
            let tag = fresh_tag();
            let mem = run_on_memory(&ops, &tag).await;
            let sq = run_on_sqlite(&ops, &tag).await;
            let pg = run_on_postgres(&ops, &tag, &dsn).await;
            // memory first: on a 2-1 split the message names the minority arm,
            // and the ORDER here is what the reader sees, so keep the two
            // in-memory backends adjacent and postgres last.
            assert_parity(&ops, "memory", &mem, "sqlite", &sq);
            assert_three_way_parity(
                &ops,
                &[("memory", &mem), ("sqlite", &sq), ("postgres", &pg)],
            );
            eprintln!(
                "three-way parity: case {case} of {PG_CASES} agreed ({} ops)",
                ops.len()
            );
        }
    }

    /// A shared row builder for the direct (non-property) witnesses below.
    /// `tier`/`cohort_scope`/`attestation_type` are caller-chosen; everything
    /// else is the harness's deterministic cast.
    #[allow(clippy::too_many_arguments)]
    fn witness_row(
        tag: &str,
        id: &str,
        att_type: &str,
        tier: &str,
        cohort: &str,
        family: super::test_support::Family,
        sig: super::test_support::SigState,
        references: Option<&str>,
    ) -> crate::federation::Attestation {
        use super::test_support::{envelope_for, signature_for_key, Principal};
        let mut envelope = envelope_for(family, Principal::A, Principal::A);
        if let Some(r) = references {
            envelope
                .as_object_mut()
                .expect("harness envelopes are objects")
                .insert("references_attestation_id".into(), r.into());
        }
        // v31.0.0 (CIRISPersist#643) — the mirror rides the SIGNED bytes.
        //
        // v31.0.0 (CIRISPersist#658) — and it is a `RowMirror`, not a `json!`
        // twin of one. `Machine::row_for`'s comment argues that a mirror
        // assembled anywhere else drifts from the row; this builder WAS that
        // second assembly. Both now place the same closed-set type, so the
        // next member added to it is a compile error in both rather than a
        // silently short mirror in both.
        crate::federation::envelope::RowMirror {
            attestation_id: id.to_owned(),
            attesting_key_id: Principal::A.key_id_in(tag),
            attestation_type: att_type.to_owned(),
            attested_key_id: Principal::A.key_id_in(tag),
            subject_key_ids: Vec::new(),
            cohort_scope: cohort.to_owned(),
            // Mirrors the `weight: None` this builder stamps on the row below.
            weight: None,
        }
        .insert_into(&mut envelope, id)
        .expect("harness envelopes are objects");
        let now = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("fixed instant")
            .with_timezone(&chrono::Utc);
        // v31.0.0 (CIRISPersist#598) — the SIGNED INSTANTS, stamped before the
        // signature, exactly as `Machine::row_for` does for the generated
        // corpus. `expires_at` is `None` on every witness this builder makes,
        // and the gate binds that in both directions, so the key is REMOVED
        // rather than written as null.
        //
        // The teeth of every caller live on the [`SigState`] argument above,
        // not here: the binding is a TIER-1 gate, so an unstamped row never
        // reaches the crypto check that `dedup_short_circuit_never_accepts_an_
        // unverified_row` and the AV-78 tier witness are both about.
        {
            let obj = envelope
                .as_object_mut()
                .expect("harness envelopes are objects");
            obj.insert(
                crate::federation::envelope::paths::ASSERTED_AT.into(),
                now.to_rfc3339().into(),
            );
            obj.remove(crate::federation::envelope::paths::EXPIRES_AT);
        }
        let (original_content_hash, classical, pqc) =
            signature_for_key(sig, &Principal::A.key_id_in(tag), &envelope);
        crate::federation::Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: Principal::A.key_id_in(tag),
            attested_key_id: Principal::A.key_id_in(tag),
            attestation_type: att_type.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash,
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            scrub_key_id: Principal::A.key_id_in(tag),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: cohort.to_owned(),
            tier: tier.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// **AV-78 REGRESSION GUARD** — successor to the retired
    /// `KNOWN_DIVERGENCE_PUT_AT_LOCAL_TIER` pin.
    ///
    /// `put_attestation`'s INSERT listed 18 columns and neither `tier` nor
    /// `promoted_at` was among them, so the schema `DEFAULT 'federation'`
    /// silently overrode every `Tier::Local` row. The differential caught it as
    /// a parity break; the danger was one layer down. The ingest gate EXEMPTS a
    /// local-tier row from hybrid verify (CC 5.3.2.2 deferred signature), so a
    /// row admitted under that exemption and then stored as `federation` became
    /// federation-VISIBLE having never been verified — and every peer refused
    /// it. Accepted here, unverifiable there.
    ///
    /// Retiring the pin restored whole-row comparison across the differential.
    /// This states the property DIRECTLY as well, because a property that holds
    /// only incidentally is a property nobody is watching.
    #[tokio::test]
    async fn put_attestation_preserves_the_caller_declared_tier() {
        const TAG: &str = "put_attestat";
        use super::test_support::{register_cast, Family, Principal, SigState};
        use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};
        use crate::federation::{FederationDirectory, SignedAttestation};

        const VALID_ID: &str = "77777777-7777-5777-9777-777777777777";
        const CORRUPT_ID: &str = "88888888-8888-5888-9888-888888888888";
        let row = |id, sig| {
            witness_row(
                TAG,
                id,
                attestation_type::SCORES,
                attestation_tier::LOCAL,
                cohort_scope::SELF,
                Family::Identity,
                sig,
                None,
            )
        };

        let sq = SqliteBackend::open_in_memory().await.expect("open sqlite");
        sq.run_migrations().await.expect("migrations");
        register_cast(&sq, TAG).await;

        sq.put_attestation(SignedAttestation {
            attestation: row(VALID_ID, SigState::Valid),
        })
        .await
        .expect("a tier=local put is admitted");
        assert_eq!(
            sq.get_attestation(VALID_ID)
                .await
                .expect("get")
                .expect("row")
                .tier,
            attestation_tier::LOCAL,
            "AV-78: the STORED tier must equal the DECLARED tier — the INSERT must carry the \
             `tier` column rather than falling through to the schema default"
        );

        // The corrupt-signature row rides the SAME deferred-signature exemption.
        // That exemption is sound ONLY while the row genuinely stays local.
        sq.put_attestation(SignedAttestation {
            attestation: row(CORRUPT_ID, SigState::Corrupt),
        })
        .await
        .expect("the local tier defers its signature, so this is admitted by design");
        assert_eq!(
            sq.get_attestation(CORRUPT_ID)
                .await
                .expect("get")
                .expect("row")
                .tier,
            attestation_tier::LOCAL,
            "AV-78: a row admitted under the local-tier exemption must STAY local"
        );
        assert!(
            sq.list_attestations_for(Principal::A.key_id_in(TAG).as_str())
                .await
                .expect("list")
                .is_empty(),
            "AV-78: neither local row is federation-visible, so neither replicates. THIS is \
             what makes the CC 5.3.2.2 signature exemption safe — an unverified row that \
             becomes federation-visible is refused by every peer that receives it"
        );
    }

    /// **AV-76 tier-4b REGRESSION GUARD** — successor to the retired
    /// `KNOWN_DIVERGENCE_DEDUP_BEFORE_VERIFY` pin.
    ///
    /// The rule the finding produced, now substrate-wide: **a dedup
    /// short-circuit may return early to REFUSE, never to ACCEPT.** The §6.1
    /// replay short-circuit sat ahead of the crypto gate, where its bare
    /// `Ok(())` skipped hybrid verify AND the AV-45 write-scope gate, so a
    /// composer matching an existing `(type, attester, references_id)` triple
    /// was acknowledged without either gate running.
    ///
    /// BOTH legs are asserted, because a "fix" that simply deleted the dedup
    /// would pass the first one and silently destroy §6.1 idempotence.
    #[tokio::test]
    async fn dedup_short_circuit_never_accepts_an_unverified_row() {
        const TAG: &str = "dedup_short_";
        use super::test_support::{register_cast, Family, SigState};
        use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};
        use crate::federation::{FederationDirectory, SignedAttestation};

        const TARGET: &str = "99999999-9999-5999-9999-999999999999";
        const FIRST: &str = "aaaaaaaa-aaaa-5aaa-9aaa-aaaaaaaaaaaa";
        const FORGED: &str = "bbbbbbbb-bbbb-5bbb-9bbb-bbbbbbbbbbbb";
        const REPLAY: &str = "cccccccc-cccc-5ccc-9ccc-cccccccccccc";
        let composer = |id, sig| {
            witness_row(
                TAG,
                id,
                attestation_type::SUPERSEDES,
                attestation_tier::FEDERATION,
                cohort_scope::FEDERATION,
                Family::Identity,
                sig,
                Some(TARGET),
            )
        };

        let sq = SqliteBackend::open_in_memory().await.expect("open sqlite");
        sq.run_migrations().await.expect("migrations");
        register_cast(&sq, TAG).await;
        sq.put_attestation(SignedAttestation {
            attestation: composer(FIRST, SigState::Valid),
        })
        .await
        .expect("the genuine composer is admitted, populating the §6.1 dedup triple");

        // (1) THE RULE: early-return to REFUSE, never to ACCEPT.
        let err = sq
            .put_attestation(SignedAttestation {
                attestation: composer(FORGED, SigState::Corrupt),
            })
            .await
            .expect_err(
                "AV-76: a corrupt-signature composer matching an existing dedup triple must be \
                 REFUSED — the short-circuit must not return Ok ahead of the crypto gate",
            );
        assert_eq!(
            err.kind(),
            "federation_federation_tier_unverified",
            "and refused ON THE SIGNATURE — the gate the short-circuit used to outrun"
        );
        assert!(
            sq.get_attestation(FORGED).await.expect("get").is_none(),
            "and nothing is stored"
        );

        // (2) THE COUNTER-WITNESS: §6.1 idempotence still works. Dedup was
        // REORDERED, not removed.
        sq.put_attestation(SignedAttestation {
            attestation: composer(REPLAY, SigState::Valid),
        })
        .await
        .expect("a VALID replay on the same triple is still an idempotent no-op (§6.1)");
        assert!(
            sq.get_attestation(REPLAY).await.expect("get").is_none(),
            "the replay stores no new row"
        );
    }

    /// **ATTESTATION-ID UNIQUENESS REGRESSION GUARD** — successor to the
    /// retired `memory_admits_a_duplicate_attestation_id` witness.
    ///
    /// The memory backend had no primary-key uniqueness: a second
    /// `put_attestation` with the same `attestation_id` and DIFFERENT content
    /// was ACCEPTED and pushed as a second row, while sqlite refused it on the
    /// PK. `get_attestation` then kept answering with whichever landed FIRST,
    /// so the accepted write was silently shadowed — worse than a refusal,
    /// because the writer believes it landed — and `list_attestations_by`
    /// double-counted. The #541 audit's own class ("memory silently accepting
    /// rows sqlite rejects") on the identity axis.
    ///
    /// The differential could not catch it alone: `snapshot_normalized` keys
    /// the corpus BY id, so a duplicate collapses in the snapshot exactly as it
    /// does in `get_attestation`. It was witnessed directly, and is now
    /// asserted directly on BOTH backends.
    #[tokio::test]
    async fn attestation_id_uniqueness_is_enforced_on_every_backend() {
        const TAG: &str = "idunique";
        use super::test_support::{register_cast, Family, Principal, SigState};
        use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};
        use crate::federation::{FederationDirectory, SignedAttestation};

        const ID: &str = "22222222-2222-5222-9222-222222222222";
        let row = |family| {
            witness_row(
                TAG,
                ID,
                attestation_type::SCORES,
                attestation_tier::FEDERATION,
                cohort_scope::FEDERATION,
                family,
                SigState::Valid,
                None,
            )
        };
        // Two DIFFERENT rows sharing one id. `scores` is deliberately NOT a
        // structural composer, so §6.1 replay dedup does not apply and the only
        // thing standing between them is identity uniqueness.
        let first = row(Family::Identity);
        let second = row(Family::Reputation);
        assert_ne!(first.attestation_envelope, second.attestation_envelope);

        let sq = SqliteBackend::open_in_memory().await.expect("open sqlite");
        sq.run_migrations().await.expect("migrations");
        let mem = MemoryBackend::new();
        register_cast(&sq, TAG).await;
        register_cast(&mem, TAG).await;

        for (name, dir) in [
            ("sqlite", &sq as &dyn FederationDirectory),
            ("memory", &mem as &dyn FederationDirectory),
        ] {
            dir.put_attestation(SignedAttestation {
                attestation: first.clone(),
            })
            .await
            .unwrap_or_else(|e| panic!("({name}) the first row is admitted: {e}"));
            dir.put_attestation(SignedAttestation {
                attestation: second.clone(),
            })
            .await
            .expect_err(&format!(
                "({name}) a second row under the SAME attestation_id must be REFUSED. \
                 Accepting it is worse than refusing: the write is shadowed by the first row, \
                 so the writer believes it landed and never retries"
            ));
            // v31.0.0 (#647) — the stored envelope is the CANONICAL form of
            // what was submitted (`put_*` canonicalizes at ingest), so the
            // "intact" comparison is against that. The claim is unchanged:
            // the refused second write must not have overwritten the first.
            let mut expected_first = first.attestation_envelope.clone();
            crate::federation::canonical_at_rest::canonicalize_in_place(&mut expected_first)
                .expect("the fixture envelope canonicalizes");
            assert_eq!(
                dir.get_attestation(ID)
                    .await
                    .expect("get")
                    .expect("row")
                    .attestation_envelope,
                expected_first,
                "({name}) the original row is intact"
            );
            assert_eq!(
                dir.list_attestations_by(&Principal::A.key_id_in(TAG))
                    .await
                    .expect("list")
                    .len(),
                1,
                "({name}) and exactly ONE row exists under that id — a duplicate would also \
                 double-count on every read that does not go through `get_attestation`"
            );
        }
    }

    /// **AV-77 — THE FULL DE-ADMISSION LIFECYCLE, AS AN OP SEQUENCE**, on both
    /// in-memory backends.
    ///
    /// Motivated by a hole in this harness rather than in the substrate. v22.0.0
    /// closed three backend-parity defects a differential oracle should have
    /// caught instantly — memory ran no de-admission gate at all, memory ran no
    /// SCORES envelope-schema validation, and postgres ran the de-admission gate
    /// unproven. The oracle stayed silent because **no op could produce a row
    /// that reached those gates**. [`OpKind::Deadmit`] makes the first
    /// reachable; this pins the whole lifecycle deterministically so the
    /// coverage does not depend on a lucky draw.
    ///
    /// Both backends run the SAME six ops and are then diffed op-for-op: if one
    /// backend enforces the sanction and the other does not, I5 fails on
    /// admission before these six claims are even reached.
    #[tokio::test]
    async fn av77_deadmission_lifecycle_holds_and_agrees_across_backends() {
        const TAG: &str = "av77lifecyc";
        let ops = deadmission_lifecycle_ops();
        let mem = run_on_memory(&ops, TAG).await;
        let sq = run_on_sqlite(&ops, TAG).await;
        assert_deadmission_lifecycle("memory", &mem);
        assert_deadmission_lifecycle("sqlite", &sq);
        assert_parity(&ops, "memory", &mem, "sqlite", &sq);
    }

    /// **A PEER CANNOT DE-ADMIT ON THIS NODE'S BEHALF.**
    ///
    /// The other half of "de-admission is LOCAL". The gate folds only over
    /// `list_attestations_by(self_key_id)`, so a de-admission authored by
    /// anyone else is stored — deliberately; it replicates, and a receiving node
    /// may weigh it — and enforced by nobody. Without that, one admitted peer
    /// could evict another from every node it can reach, which is the
    /// federation-wide ban the design explicitly refuses to build.
    ///
    /// Asserted DIRECTLY rather than left to the generator: [`OpKind::Deadmit`]
    /// forces the author to the node itself (see its doc), so the third-party
    /// case is out of the alphabet by construction, and a property this sharp
    /// deserves better than a 1-in-3 draw anyway.
    #[tokio::test]
    async fn third_party_deadmission_of_a_peer_is_inert() {
        const TAG: &str = "av77inert";
        use super::test_support::register_cast;
        use crate::federation::admission::PEER_DEADMISSION_DIMENSION;
        use crate::federation::bootstrap_admission::test_support::scores_row;
        use crate::federation::{FederationDirectory, SignedAttestation};

        let sq = SqliteBackend::open_in_memory().await.expect("open sqlite");
        sq.run_migrations().await.expect("migrations");
        sq.set_self_key_id(Some(self_key_id_for(TAG)));
        let mem = MemoryBackend::new();
        mem.set_self_key_id(Some(self_key_id_for(TAG)));

        for (name, dir) in [
            ("sqlite", &sq as &dyn FederationDirectory),
            ("memory", &mem as &dyn FederationDirectory),
        ] {
            register_cast(dir, TAG).await;
            let me = self_key_id_for(TAG);
            let (b, c) = (Principal::B.key_id_in(TAG), Principal::C.key_id_in(TAG));
            let put = |row| dir.put_attestation(SignedAttestation { attestation: row });

            // B de-admits C. ADMITTED — the row is a legitimate CEG claim, and
            // refusing it would make the sanction unreplicable.
            put(scores_row(
                &uuid::Uuid::new_v4().to_string(),
                &b,
                &c,
                PEER_DEADMISSION_DIMENSION,
            ))
            .await
            .unwrap_or_else(|e| panic!("({name}) a peer's de-admission row is STORED: {e}"));

            // ...and INERT. C still writes here, because B does not decide what
            // this node accepts.
            put(scores_row(
                &uuid::Uuid::new_v4().to_string(),
                &c,
                &c,
                "identity:handle:v1",
            ))
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "({name}) AV-77: a de-admission authored by a PEER must not bind this node — \
                     one admitted peer evicting another from every node it can reach is the \
                     federation-wide ban this design refuses to build: {e}"
                )
            });

            // The node's OWN de-admission of C, by contrast, binds immediately.
            // This is the counter-witness: without it the test above would pass
            // just as well on a gate that never runs.
            put(scores_row(
                &uuid::Uuid::new_v4().to_string(),
                &me,
                &c,
                PEER_DEADMISSION_DIMENSION,
            ))
            .await
            .unwrap_or_else(|e| panic!("({name}) the node's own de-admission is admitted: {e}"));
            let err = put(scores_row(
                &uuid::Uuid::new_v4().to_string(),
                &c,
                &c,
                "identity:handle:v1",
            ))
            .await
            .expect_err(&format!(
                "({name}) AV-77: once THIS node de-admits C, C's writes are refused"
            ));
            assert!(
                format!("{err}").contains(PEER_DEADMISSION_DIMENSION),
                "({name}) and the refusal names the de-admission dimension: {err}"
            );
        }
    }

    /// **THE EXPIRY-HORIZON GUARD** — the model clock must stay inside the
    /// liveness window of every row the harness writes.
    ///
    /// This pins the invariant behind a defect that was live in this harness for
    /// roughly six months and failed **silently**, getting worse with age.
    /// `row_for` stamped `expires_at = at + 30 days` off a model clock pinned to
    /// 2026-01-01 (pinned deliberately — I3's replay and I5's differential both
    /// compare `expires_at`, so it cannot be `Utc::now()`). Substrate gates
    /// evaluate liveness against **wall-clock `Utc::now()`**. So on 2026-01-31
    /// every row the harness wrote silently became expired at every such gate,
    /// and no test noticed, because no invariant in this file depended on a row
    /// being LIVE. It surfaced only when [`OpKind::Deadmit`] arrived and a
    /// sanction landed and then refused nothing.
    ///
    /// The class is worth more than the instance: **a harness with a fixed model
    /// clock and gates that read wall-clock time has an expiry horizon.** A
    /// green run months from now proves less than a green run today unless
    /// something pins the horizon. This is that something, and it costs one
    /// comparison.
    #[test]
    fn every_row_the_harness_writes_is_live_at_wall_clock() {
        use super::test_support::harness_expires_at;
        let now = chrono::Utc::now();
        assert!(
            harness_expires_at() > now,
            "EXPIRY HORIZON: the harness stamps `expires_at = {}`, which is NOT in the future \
             relative to wall-clock now ({now}). Every row it writes is therefore already \
             expired at every gate that compares to `Utc::now()` — including \
             `check_peer_deadmission` — so those gates are unreachable and their coverage is \
             silently gone. This is the failure mode that hid for six months: fix the constant, \
             do not relax this test.",
            harness_expires_at()
        );
        // And the model clock must sit BEFORE that horizon, or a row would
        // declare an expiry earlier than its own assertion.
        let clock_start = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("fixed instant")
            .with_timezone(&chrono::Utc);
        assert!(
            clock_start < harness_expires_at(),
            "EXPIRY HORIZON: the model clock start must precede the declared expiry"
        );
    }

    /// **THE INSTANT-BINDING HORIZON GUARD** (v31.0.0, CIRISPersist#598) — the
    /// harness's own clock constants must be ones the binding gate ACCEPTS.
    ///
    /// [`Machine::row_for`] stamps `asserted_at` / `expires_at` into the signed
    /// envelope from the model clock and [`harness_expires_at`], and asserts in
    /// a comment that neither needs truncating. That comment is the whole
    /// argument, so it is pinned HERE rather than believed:
    /// [`check_instant_binding`](crate::federation::admission::check_instant_binding)
    /// refuses sub-microsecond precision outright, and refuses an `asserted_at`
    /// more than [`DEFAULT_MAX_TOUCH_SKEW`](crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW)
    /// in the future.
    ///
    /// This is `every_row_the_harness_writes_is_live_at_wall_clock`'s lesson on
    /// a second axis, and it is the same trap: a model clock and a gate reading
    /// wall-clock time. There the danger was drifting PAST the expiry; here it
    /// is drifting past `now` in the other direction. Either way the failure is
    /// silent in the sense that matters — every property in this module would go
    /// red at once, for a reason none of them names. This names it.
    ///
    /// Run over the REAL gate on a REAL row rather than by arithmetic on the
    /// constants: the arithmetic is what a future edit would get wrong.
    #[test]
    fn harness_instants_are_writable_by_the_binding_gate() {
        use super::test_support::harness_expires_at;
        use crate::federation::admission::{check_instant_binding, DEFAULT_MAX_TOUCH_SKEW};
        use crate::federation::envelope::paths;
        use crate::federation::types::{attestation_tier, attestation_type};

        // The LATEST instant any sequence can reach: the pinned clock start
        // plus the largest advance `arb_clock` can draw, at every op.
        let clock_start = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("fixed instant")
            .with_timezone(&chrono::Utc);
        let latest = clock_start + chrono::Duration::seconds(3600 * MAX_OPS as i64);

        for (label, at, expires) in [
            (
                "clock start, with an expiry",
                clock_start,
                Some(harness_expires_at()),
            ),
            // The `Deadmit` shape: no expiry at all, which the gate binds in
            // the other direction (envelope key ABSENT ⇔ column `None`).
            ("latest reachable clock, no expiry", latest, None),
        ] {
            let mut envelope = serde_json::json!({ "dimension": "identity:handle:v1" });
            let obj = envelope.as_object_mut().expect("object");
            obj.insert(paths::ASSERTED_AT.into(), at.to_rfc3339().into());
            if let Some(t) = expires {
                obj.insert(paths::EXPIRES_AT.into(), t.to_rfc3339().into());
            }
            let row = crate::federation::Attestation {
                attestation_id: format!("harness-instant-{label}"),
                attesting_key_id: "k".into(),
                attested_key_id: "k".into(),
                attestation_type: attestation_type::SCORES.into(),
                weight: None,
                asserted_at: at,
                expires_at: expires,
                attestation_envelope: envelope,
                original_content_hash: String::new(),
                scrub_signature_classical: String::new(),
                scrub_signature_pqc: None,
                scrub_key_id: "k".into(),
                scrub_timestamp: at,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: Vec::new(),
                withdraws_admission_rule: None,
                cohort_scope: Scope::SelfScope.as_str().into(),
                tier: attestation_tier::FEDERATION.into(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            };
            check_instant_binding(&row, chrono::Utc::now(), DEFAULT_MAX_TOUCH_SKEW).unwrap_or_else(
                |e| {
                    panic!(
                        "INSTANT HORIZON ({label}): the harness mints `asserted_at = {at}` / \
                         `expires_at = {expires:?}` into every row it signs, and the binding \
                         gate REFUSES them: {e}. Every property in this module would now be \
                         measuring this refusal instead of what it names. Fix the constant \
                         (truncate it, or move the model clock back before `Utc::now()`); do \
                         not relax this test and do not weaken the gate."
                    );
                },
            );
        }
    }

    /// **The provenance trail, proven on the case that motivated it.**
    ///
    /// A `Withdraw` referencing a row minted by an earlier op. The symptom, if
    /// anything diverges, lands at the withdraw; the cause is upstream. This
    /// pins the instrumentation that says so — instrumentation nobody exercises
    /// is instrumentation nobody can trust.
    #[tokio::test]
    async fn a_late_symptom_names_the_op_that_actually_diverged() {
        const TAG: &str = "a_late_sympt";
        use super::test_support::explain_provenance;

        let ops = vec![
            Op {
                kind: OpKind::Put,
                family: Family::Identity,
                attester: Principal::A,
                subject: Principal::A,
                tier: Tier::Federation,
                cohort_scope: Scope::Federation,
                signature: SigState::Valid,
                cosign: CoSign::None,
                clock: ClockStep::Advance(1),
                target: 0,
            },
            Op {
                kind: OpKind::Withdraw,
                family: Family::Identity,
                attester: Principal::A,
                subject: Principal::A,
                tier: Tier::Federation,
                cohort_scope: Scope::Federation,
                signature: SigState::Valid,
                cosign: CoSign::None,
                clock: ClockStep::Advance(1),
                target: 0,
            },
        ];

        // Through the shared runners, so this test sees the SAME node identity
        // the property tests do — a backend built inline here would run with the
        // de-admission gate dormant, which is a different machine.
        let mem_t = run_on_memory(&ops, TAG).await;
        let sq_t = run_on_sqlite(&ops, TAG).await;

        // The withdraw names the row it aimed at...
        let target = mem_t.outcomes[1]
            .referenced
            .clone()
            .expect("the withdraw records the row it referenced");
        // ...and that row's provenance names the op that minted it, on BOTH sides.
        let mem_p = mem_t.provenance.get(&target).expect("memory provenance");
        let sq_p = sq_t.provenance.get(&target).expect("sqlite provenance");
        assert_eq!(mem_p.minted_by_op, 0, "both name op 0 as the origin");
        assert_eq!(sq_p.minted_by_op, 0);
        assert_eq!(mem_p.kind, OpKind::Put);
        assert!(
            mem_p.admitted && mem_p.stored,
            "memory admitted op 0 AND stored the row: {}",
            mem_p.describe()
        );
        assert!(
            sq_p.admitted && sq_p.stored,
            "sqlite likewise — post-AV-78 the backends agree here: {}",
            sq_p.describe()
        );

        let msg = explain_provenance(&target, "memory", &mem_t, "sqlite", &sq_t);
        assert!(
            msg.contains("minted by op 0"),
            "the message must name the ORIGINATING op: {msg}"
        );
        assert!(
            msg.contains("ADMITTED stored=true"),
            "and show each backend's fate for that op: {msg}"
        );
        assert!(
            msg.contains("ORIGINATES at op 0"),
            "and say so in words, so the reader is not left to infer it: {msg}"
        );
    }

    /// **META-COVERAGE.** A generator that only ever produces refusals satisfies
    /// I1–I5 *vacuously*, and a harness that passes vacuously is worse than no
    /// harness: it reports safety it never checked. This test fails loudly if
    /// that ever becomes true.
    ///
    /// Four claims, each about the GENERATOR rather than the substrate:
    ///
    /// 1. every [`OpKind`] variant is emitted across a run (so adding a variant
    ///    without wiring it into `arb_kind` fails here, not silently);
    /// 2. both polarities are reached — some ops admitted AND some refused;
    /// 3. at least [`MIN_SIGNED_SEQUENCE_FRACTION`] of sequences leave behind a
    ///    real hybrid-signed FEDERATION-tier row, which is the precondition for
    ///    I1 to be testing anything at all;
    /// 4. the AV-77 de-admission gate actually REFUSED a write. Claim 1 only
    ///    proves the op is emitted; this proves it lands and then BITES, which
    ///    is a different and much rarer event — and it is the claim that fails
    ///    on a backend, or a driver, where the gate is dormant.
    ///
    /// Claim 4 is the one that would have caught what the v22.0.0 audit found by
    /// hand: memory shipped the AV-77 fix with no `self_key_id` field and so ran
    /// no de-admission gate at all, and the differential could not see it
    /// because no op in the alphabet reached the gate on ANY backend.
    #[test]
    fn generator_reaches_interesting_states() {
        use proptest::strategy::{Strategy as _, ValueTree};
        use proptest::test_runner::{Config, TestRunner};
        use std::collections::BTreeSet;

        /// Draws used for the cheap, no-execution variant-coverage claim.
        const DRAWS: u32 = 192;
        /// Sequences actually executed for the admitted/refused + signed-row
        /// claims. Kept well under the differential's budget — this test's job
        /// is to prove the generator is alive, not to re-run the properties.
        const EXECUTED: usize = 24;
        /// Floor for claim 3. Measured at ~0.7 on this generator; the floor is
        /// set well below the measurement so ordinary generator drift does not
        /// flap CI, while a generator that stops producing signed federation
        /// rows entirely still fails hard.
        const MIN_SIGNED_SEQUENCE_FRACTION: f64 = 0.35;

        // A DETERMINISTIC rng. Meta-coverage measures the GENERATOR, so it must
        // not depend on the luck of a draw: with a random seed this assertion
        // flapped 1-in-16 at 0.29 against a 0.35 floor, which is a flaky test
        // reporting a real number — the worst of both. Pinning the seed makes
        // the numbers in the module doc reproducible and makes any future
        // movement a real generator change.
        let mut runner = TestRunner::new_with_rng(
            Config {
                cases: DRAWS,
                ..Config::default()
            },
            proptest::test_runner::TestRng::deterministic_rng(
                proptest::test_runner::RngAlgorithm::ChaCha,
            ),
        );

        // Claim 1 — variant coverage, no execution needed.
        let mut seen_kinds: BTreeSet<OpKind> = BTreeSet::new();
        let mut seen_cosign: BTreeSet<CoSign> = BTreeSet::new();
        let mut sequences: Vec<Vec<Op>> = Vec::new();
        for _ in 0..DRAWS {
            let seq = arb_sequence()
                .new_tree(&mut runner)
                .expect("generator produces a value")
                .current();
            for op in &seq {
                seen_kinds.insert(op.kind);
                seen_cosign.insert(op.cosign);
            }
            sequences.push(seq);
        }
        for kind in OpKind::ALL {
            assert!(
                seen_kinds.contains(&kind),
                "META-COVERAGE: `{kind:?}` was never emitted in {DRAWS} draws — the op \
                 alphabet and the generator have drifted apart, so every invariant is being \
                 checked against a strictly smaller machine than the one documented"
            );
        }
        // v24.0.0 (CIRISPersist#556) — the co-signature axis, held to the same
        // standard. A field the generator never populates is a field I1 and the
        // differential never guard, which is precisely how `additional_scrubs`
        // could re-acquire the #541 shape without any test going red.
        for cs in CoSign::ALL {
            assert!(
                seen_cosign.contains(&cs),
                "META-COVERAGE: `CoSign::{cs:?}` was never emitted in {DRAWS} draws — signed \
                 rows are no longer reaching the substrate with that co-signature shape, so \
                 `additional_scrubs` is being carried by the type and guarded by nothing"
            );
        }

        // Claims 2 + 3 + 4 — execute a slice and measure.
        let (admitted, refused, with_signed, deadmitted, with_deadmit) = block_on(async {
            let mut admitted = 0usize;
            let mut refused = 0usize;
            let mut with_signed = 0usize;
            let mut deadmitted = 0usize;
            let mut with_deadmit = 0usize;
            for ops in sequences.iter().take(EXECUTED) {
                let t = run_on_sqlite(ops, &fresh_tag()).await;
                for o in &t.outcomes {
                    if o.admitted {
                        admitted += 1;
                    } else {
                        refused += 1;
                    }
                }
                if t.signed_federation_rows > 0 {
                    with_signed += 1;
                }
                deadmitted += t.deadmissions_enforced;
                // Counted PER SEQUENCE as well as per write, because the two
                // numbers answer different questions and only the per-sequence
                // one is comparable across budgets: "what fraction of sequences
                // reach the gate at all" is a property of the generator, while a
                // raw write count also moves with sequence length.
                if t.deadmissions_enforced > 0 {
                    with_deadmit += 1;
                }
            }
            (admitted, refused, with_signed, deadmitted, with_deadmit)
        });

        assert!(
            admitted > 0 && refused > 0,
            "META-COVERAGE: the generator reached only ONE polarity over {EXECUTED} \
             sequences ({admitted} admitted, {refused} refused). All-refused makes every \
             invariant vacuous; all-admitted means the refusal invariants (I2, I4) never ran."
        );

        let fraction = with_signed as f64 / EXECUTED as f64;
        // Printed so the ledger has real numbers rather than "it passed".
        eprintln!(
            "META-COVERAGE: {} op kinds over {DRAWS} draws; {EXECUTED} sequences executed \
             ({admitted} ops admitted / {refused} refused); {with_signed}/{EXECUTED} \
             ({fraction:.2}) left a hybrid-signed federation-tier row; {with_deadmit}/{EXECUTED} \
             ({dead_fraction:.3}) reached the AV-77 de-admission gate ({deadmitted} writes \
             refused by it)",
            seen_kinds.len(),
            dead_fraction = with_deadmit as f64 / EXECUTED as f64,
        );

        // Claim 4 — the AV-77 gate is REACHED, not merely wired. Emitting a
        // `Deadmit` is not coverage: the gate only runs against a LATER write
        // by the peer that was named, and that conjunction is exactly the kind
        // of thing an op alphabet can be one variant short of expressing. This
        // is the assertion that would have failed on the pre-v22 memory backend,
        // which had no `self_key_id` field and therefore no gate at all.
        //
        // MEASURED, at N=240 so the figure is not a small-sample artefact:
        // **18/240 sequences (7.5%)** reach the gate with the bias, 7/240 (2.9%)
        // without it — so the differential's 64 cases exercise it ~5 times per
        // run.
        //
        // BE HONEST ABOUT WHAT THIS SLICE PROVES: at the 24-sequence budget the
        // gate is reached in **1 sequence (3 refused writes)**. Expected is ~2,
        // so a single sequence carries the claim, and it does so only because the
        // RNG is pinned. That is enough to catch a DORMANT gate (the memory
        // backend, which would score 0) and it is NOT a rate estimate — 240 is.
        //
        // The floor is therefore the smallest meaningful one rather than a
        // fraction of the measurement: at 7.5% a fractional floor would encode
        // the current bias as a requirement and flap on any generator change.
        assert!(
            deadmitted > 0,
            "META-COVERAGE: across {EXECUTED} sequences the de-admission gate refused NOTHING. \
             `OpKind::Deadmit` is being emitted (claim 1 passed) but never lands and gets \
             followed by a write from the peer it named, so AV-77 is as unexercised as it was \
             before the op existed — the same hole that let three backend-parity defects ship \
             past this oracle in v22.0.0. Raise `Deadmit`'s weight in `arb_kind`, or check that \
             the runners still install `self_key_id_for(tag)`."
        );
        assert!(
            fraction >= MIN_SIGNED_SEQUENCE_FRACTION,
            "META-COVERAGE: only {with_signed}/{EXECUTED} sequences ({fraction:.2}) left a \
             hybrid-signed FEDERATION-tier row behind, below the {MIN_SIGNED_SEQUENCE_FRACTION} \
             floor. I1 — the CIRISPersist#541 invariant — has nothing to verify on a sequence \
             with no signed rows, so this harness would be reporting safety it never checked."
        );
    }
}
