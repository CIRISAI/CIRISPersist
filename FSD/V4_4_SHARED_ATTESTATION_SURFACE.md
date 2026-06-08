# FSD: CIRISPersist — Shared CEG Attestation Surface (local-tier write + query + promote)

**Status:** Draft — for review by the four CEG-RC1 implementations before any code. NOT yet accepted.
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.8
**Created:** 2026-06-08
**Repo:** `~/CIRISPersist`
**Target cut:** v4.4.0 (additive surface + one additive `federation_attestations` migration; no wire-format change, CEG §4 unchanged).
**Risk:** Additive at the grammar layer (CEG 1+4 lockdown holds). The one non-trivial change is a **tier model** on `federation_attestations` (a `local` tier with deferred signature) — additive column + a CHECK, but it relaxes the current "every attestation row is signed at write" invariant, so it is called out explicitly and gated on the threat-model review below.
**Driving issue:** CIRISPersist#171 (this ask) — gating dependency for **CIRISAgent#840** (CEG-native agent; `graph_nodes` ARE self-level CEG attestations; `CIRISAgent/FSD/CEG_NATIVE_AGENT.md`).
**Normative anchor:** CEG 0.15 **§10.1.3** (local-tier signature deferral + the consent-revocation non-eligibility rule), §7.0.1 (identity_type emitter gates), §10.1.4 (structural invisibility), §8.1.8.1 (tiered-scope promotion). `CIRISRegistry/FSD/CEG/`.
**Cross-refs:** CIRISAgent#840 / #866 (2.9.6 umbrella) / #842, CIRISNodeCore (`compose.rs` CEG-projection), CIRISLensCore#857 (CEG-native trace ingest), CIRISRegistry#45, CIRISPersist#161 (removal/revocation substrate — ask #4 is designed *with* it), **CIRISVerify#59** (JCS RFC 8785 canonicalizer + CEG-Contribution verify — the `attestation_promote` interop deliverable, OQ-4), CIRISConformance#9 (cross-impl JCS vector set).
**Review state (2026-06-08):** CIRISAgent ✅ nod (conditional, folded in) · CIRISVerify ✅ answered OQ-4 (+ filed #59) · CIRISRegistry 🟡 next (OQ-2) · #161 🟡 (OQ-3) · LensCore + NodeCore ⬜ not yet. See §11/§12.
**Builds on:** the v4.0 Data Access Surface (`FSD/V4_0_DATA_ACCESS_SURFACE.md`) — `CallerScope`/`CallerAdmission`, the target-membership `cohort_scope_sql_predicate`, the cache + `ReadEngine v2`. This FSD is the **write+promote** half of the same substrate; `attestation_query` is the DAS read shape extended with dimension/valid_at/confidence filters.

---

## 0. TL;DR for reviewers

`federation_attestations` is already the **single store** all four CEG-RC1 implementations (CIRISAgent, CIRISNodeCore, CIRISLensCore, CIRISRegistry) read from and write to. Persist v4.0 gave it a first-class **scope-aware read** surface (`ReadEngine v2`). It has **no agent-facing local-tier WRITE** — `put_attestation` demands a fully-signed `SignedAttestation`. This FSD adds the missing half as **one contract, four role-scoped views**:

1. **A tier model** — every attestation row is `local` (producer-only authority, signature deferred per CEG §10.1.3) or `federation` (hybrid-signed, federation-visible). A CHECK enforces `tier = federation ⟹ signature present`; the read gate hides `local` rows from every caller except the producing occurrence itself.
2. **`attestation_upsert_local(envelope)`** (+ batched `_many`) — the signature-deferred self-attestation write (`witness_relation: self`, empty `subject_key_ids`). ~JSON-row cost; the one-shot `graph_nodes → attestations` migration backlog rides `_many`.
3. **`attestation_query(dimensions[], valid_at, confidence_floor, subject_key_id?, scope)`** — the uniform read the agent's memory/config/consent/audit services become thin wrappers over; the SAME query NodeCore uses to read promoted agent-intent and LensCore/Registry use to read subjects. Built on the v4.0 DAS scope machinery.
4. **`attestation_promote(id) -> SignedAttestation`** — the local→federation transition: compute the hybrid Ed25519+ML-DSA-65 signature (via `Engine::sign_hybrid`) + flip federation-visible.
5. **Consent-revocation promotion obligation (CEG §10.1.3, normative)** — a Contribution with non-empty `subject_key_ids` whose subject revokes MUST promote to federation-tier within a bounded window (default 24h); the substrate emits `hard_case:consent_revocation_promotion_overdue` past it. Designed with CIRISPersist#161.

No CEG wire-format change. No dual-write path. Both backends implement everything in the cut (parity, MISSION §1.5).

---

## 1. Why this exists — the mission case

### 1.1 The driving observation

The CEG-native agent (#840) is a **hard cut-over**: `graph_nodes` (the agent's durable memory/config/consent/identity store) become self-level CEG attestations in `federation_attestations`. The agent's only node write today is `cirisgraph_upsert_node`; persist v4 has the federation **read** surface but the agent calls none of it, and **there is no agent-facing local-tier attestation WRITE**. Everything in the #840 `NodeType → dimension` map is inert until this lands.

Three things make this a substrate-shape ask, not an agent feature:

1. **The store is shared.** `federation_attestations` is the single table all four CEG-RC1 implementations read/write. CEG cannot reach RC1/1.0 until Agent, NodeCore, LensCore, and Registry all conform — *against this one table*. A surface forked per consumer would diverge the contract exactly where it must be coherent.
2. **The write is unsigned-by-design at local tier.** CEG §10.1.3 sanctions signature deferral for producer-only-authority self-attestations — but persist's current write demands a `SignedAttestation`. The substrate has no representation for "recorded, producer-authoritative, not-yet-federation-signed." That representation is the load-bearing new concept.
3. **One leak the substrate must close.** §10.1.3 carves out the *one* case deferral is unsafe: subject-side consent revocation. If a user revokes and the revocation sits unsigned/unpromoted, other peers keep propagating the user's data. The substrate — not the consumer — must enforce the bounded promotion window (it owns the rows + the clock).

### 1.2 Alignment against MISSION.md

- **§1.1 Justice + Integrity** — a Raspberry-Pi agent and a datacenter node write self-attestations through the same tier model + scope discipline. One shape across every tier (§1.5 parity).
- **§1.2 N_eff** — attestations ARE the corpus. The agent's identity/config/consent/memory become measurable CEG rows instead of an opaque graph. If the tier model silently leaked `local` rows to federation, or served unsigned rows as authoritative, the measurement is corrupted at the load-bearing layer.
- **§1.4 Apophatic bound** — this is a *fixed, named* surface (three methods + one obligation), not an OLAP/graph engine. `attestation_query` takes a closed `dimensions[]` set + bounded predicates; no ad-hoc SQL, no caller-composed projections.
- **§1.7 Relational fabric, not Cartesian gate** — `local` vs `federation` is *recorded tier*, not adjudicated trust. Promotion is a recorded transition the producer initiates; the substrate applies the §10.1.3 obligation the chain expresses, it does not decide who is "really" entitled.
- **§1.6 Fail-honest** — an overdue consent-revocation promotion is *labelled* (`hard_case:consent_revocation_promotion_overdue`), never silently tolerated. A `local` row is *labelled* local, never served as federation-authoritative.
- **§1.5 Parity** — both backends implement every primitive in the cut. **No sqlite NotImplemented** (`feedback_no_pg_only_no_deferral`).

---

## 2. Scope

### 2.1 In scope for v4.4 (the cut)
- The **tier column** + CHECK + read-gate change on `federation_attestations` (§3, §7).
- `attestation_upsert_local` + `attestation_upsert_local_many` (§4.1).
- `attestation_query(dimensions[], valid_at, confidence_floor, subject_key_id?, scope)` (§4.2).
- `attestation_promote(id) -> SignedAttestation` (§4.3).
- The consent-revocation promotion obligation + `hard_case:consent_revocation_promotion_overdue` emission + the overdue-scan query (§5).
- PyO3 surface for all of the above; both backends; the parity conformance suite.
- Coexistence migration concerns: bulk insert efficiency, `graph_nodes` read-only cold-backup tolerance (§9).

### 2.2 Out of scope for v4.4 (named, not deferred)
- **The 24h timer/sweeper runtime.** The substrate provides the *query* (`attestations_overdue_for_promotion(now)`) + the `hard_case` *emission primitive*; WHO runs the clock (a persist background task vs a consumer-driven scan vs edge) is an explicit open question (§11 OQ-3), to be resolved with #161 — not built blind in this cut.
- **The CEG wire format.** §4 unchanged. No new structural primitives. (Non-goal, per #171.)
- **graph_nodes ↔ attestations sync.** No shadow/dual-write path (§9). The agent cuts atomically per occurrence.
- **LensCore's `detection:consent:promotion_delay_pattern`** composition — that rides on top of the substrate's `hard_case` emission; it is LensCore's, not persist's.

### 2.3 Backend parity — both ship in the cut
Postgres + SQLite implement every primitive. SQLite binds `u64` epoch/window as `i64`, uses correlated subqueries where PG uses CTEs; the answer shape is byte-identical.

---

## 3. The tier model — `local` vs `federation`

The single load-bearing new concept. Today `federation_attestations` rows are written via `put_attestation(SignedAttestation)` — a signature is part of the write contract. This FSD adds a **tier**:

| Tier | `subject_key_ids` | Signature | Federation-visible | Written by |
|---|---|---|---|---|
| `local` | **empty OR non-empty** — any **producer-authority** row (incl. ones that *name* a subject) | **deferred** (NULL hybrid sig; `witness_relation: self`) | **No** — visible only to the producing occurrence | `attestation_upsert_local` / `attestation_insert_local` |
| `federation` | empty or non-empty | hybrid Ed25519 + ML-DSA-65 present | Yes | `put_attestation` (status quo) OR `attestation_promote` (local→federation) |

> **⚠️ Corrected per CIRISAgent review (was: "local ⟹ empty `subject_key_ids`").** Local-tier eligibility is **producer-only authority**, NOT empty subjects. CEG **§4.2.6** requires any dimension *naming* a subject to carry it in `subject_key_ids`, and large core classes of agent self-attestation are producer-authority **yet name a subject** — `observed:user:{hash}:*`, `consent:partnered:{user}` (CEG §10.1.3 says this MAY ride local-tier verbatim), `epistemic:about:{key}:*`, and the §4.2.3 self-consent `identity:current` with `subject_key_ids=[self]`. Forcing all non-empty-subject rows onto the signed path would defeat the deferral cost model for the majority of agent state and break the hard cut. **The discriminator is "who holds revocation authority," not "is the subject set empty"** — see §5 for the one carve-out (subject-side revocation).

**The invariant (a CHECK on the table):** `tier = 'federation' ⟹ scrub_signature_classical IS NOT NULL` (and PQC per the existing hybrid-pending rules). A `local` row MAY carry a NULL signature. This relaxes — but does not remove — the "signed at federation" guarantee: nothing crosses to federation-visible unsigned.

**The read gate (composes with v4.0 DAS).** `ReadEngine v2`'s `cohort_scope` target-membership predicate already hides `self`-scoped rows from non-owners. The tier adds an orthogonal axis: a `local` row is returned ONLY when the caller's `CallerAdmission.occurrence_key_id` equals the row's producing occurrence (self-read). Every other caller — including an otherwise-authorized family/community peer — sees nothing until promotion. AV-59 (§10) is the threat entry that nails this shut.

**Why a tier column and not a separate table.** The four-impl contract demands *one* read shape. NodeCore reads promoted agent-intent and LensCore reads subjects via the *same* `attestation_query`; splitting local rows into a second table would fork the read path and re-introduce the per-consumer divergence this FSD exists to prevent. One table, one tier axis, one query.

---

## 4. The three primitives

### 4.1 Local write — two classes (`upsert` + `insert`) + `_many`

Per CIRISAgent review, the #840 `NodeType → dimension` map splits into two write classes; `upsert` alone is insufficient. **The key is `(occurrence_key_id, dimension)`** — the CEG dimension string IS the identity (it already carries the scoped leaf: `config:filter_config`, `observed:user:{hash}:interaction_count`, `consent:partnered:{user}`). The §3 structural `attestation_type` (scores/supersedes/withdraws/…) is too coarse — keying on it would collapse every distinct dimension in a scope into one row. **OQ-1 resolved: `(occurrence_key_id, dimension)`.**

- **`attestation_upsert_local(envelope)`** — **singleton current-state** (`identity:current`, `config:{key}`, `consent:partnered:{user}`, `observed:user:{hash}:{metric}`): replace-on-`(occurrence_key_id, dimension)`; history via the `supersedes` composer.
- **`attestation_insert_local(envelope)`** — **multi-valued / event** (`epistemic:memory:topic={topic}` — many memories per topic; per-thought `dma:*`/`conscience:*` verdicts; observation events): **append**, each a distinct row with a server-assigned id, NOT collapsible by dimension. (An upsert keyed on dimension would collapse the agent's entire memory of a topic into one row.) The #840 map tags each dimension's write class.
- **`attestation_upsert_local_many(envelopes[])` / `attestation_insert_local_many`** — the boot-time `migrate_graph_nodes_to_attestations()` backlog. Must **chunk internally** (CONCEPT/OBSERVATION memory can be thousands of rows on a long-lived agent) — not one statement (§9).

All write at `local` tier (`witness_relation: self`, **no hybrid signature**, deferred per §10.1.3); `subject_key_ids` MAY be non-empty (producer-authority rows that name a subject — §3).

**Validation:** the local path is refused **only** for the §10.1.3 carve-out — a **subject-side revocation** (`attestation_type ∈ {withdraws}` or a `consent:state:revoked` dimension) whose `attesting_key_id` is a member of the *target* row's `subject_key_ids` (the subject exercising its own revocation right). Those MUST go through signed `put_attestation` / promotion (§5). Producer-authority rows are accepted regardless of whether they name a subject. Rejects a non-`self` `witness_relation`.

### 4.2 `attestation_query(dimensions[], valid_at, confidence_floor, subject_key_id?, scope)`

The uniform read. `dimensions[]` is a closed set of `attestation_type` prefixes (the #840 dimension vocabulary); `valid_at` filters on `asserted_at <= valid_at < COALESCE(expires_at, ∞)`; `confidence_floor` filters on `weight >= floor`; `subject_key_id?` narrows to attestations about a subject; `scope: CallerScope` applies the v4.0 target-membership gate AND the tier gate (§3). This is the DAS read shape — it reuses `cohort_scope_sql_predicate` and the cache substrate; it is NOT new query infra. The agent's memory/config/consent/audit services become thin wrappers; NodeCore/LensCore/Registry call the identical method with their role-scoped `CallerScope`.

### 4.3 `attestation_promote(id) -> SignedAttestation`

The local→federation transition: load the `local` row, compute the hybrid signature over its canonical bytes (`Engine::sign_hybrid`), write the signature + flip `tier = federation` (+ `promoted_at`). Idempotent: promoting an already-`federation` row returns it unchanged. At promotion, tiered-scope promotion semantics (§8.1.8.1) and `holds_bytes` emission (§10.1.2) fire exactly as for any federation write — promotion is the federation-emit moment.

**Canonical bytes — `JCS(envelope)`, NOT LP framing (OQ-4, resolved by CIRISVerify review).** A promoted row *is* a CEG Contribution four impls read + verify, so the signature MUST cover `JCS(contribution_envelope)` per CEG **§0.9 / RFC 8785** (`Engine::sign_hybrid(JCS(envelope))`); Verify recomputes the identical JCS bytes to verify. **Do NOT use Verify's internal length-prefixed `signing_bytes` framing** — that is correct only for verify-internal, verify-to-verify primitives (envelope framing, keyset rotation, doc integrity) that never cross the four-impl boundary as JSON; a promoted attestation is the opposite. Registry owns the exact envelope member set; Verify owns the matching recomputation.

**§0.9 omit-vs-materialize is load-bearing here.** Promotion MUST canonicalize the **exact member set the producer committed at local-write time** — a field *omitted* at `upsert_local`/`insert_local` MUST NOT be materialized at promote (and vice-versa), or the bytes diverge from what a peer recomputes and the hybrid sig fails to verify. Persist serializes the stored row → the committed envelope → JCS → sign; it does not re-default.

**Dependency — gates `promote` only.** No Rust impl has a JCS canonicalizer yet; **CIRISVerify#59** (JCS RFC 8785 + CEG-Contribution hybrid-sig verify path) is the deliverable that lets Verify verify the promotion signature as a CEG-Conforming Consumer, composing with CIRISConformance#9's vector set. Persist also needs JCS at promote time (shared impl from Verify, or its own conforming to #59's vectors). **This is why `promote` stages *after* the write+read half** (§2.1 / OQ-5): `upsert_local`/`insert_local`/`query` ship in v4.4.0 with no JCS dependency; `promote` lands once #59 is available.

---

## 5. Consent-revocation promotion obligation (CEG §10.1.3 — normative)

The one place deferral is unsafe, and the one place the *substrate* (not a consumer) must enforce, because it owns the rows and the clock.

**Rule (verbatim from §10.1.3):** a Contribution carrying non-empty `subject_key_ids` whose subject subsequently emits `consent:state:revoked` (or a `withdraws` admitted under §3.2.3 rule 2/3) MUST promote to federation-tier within a bounded window. **Default 24h, operator-tunable.** Past the window without promotion, the substrate MUST emit `hard_case:consent_revocation_promotion_overdue`.

**What "subject-side revocation" means (corrected per Agent review — it is NOT "non-empty subject_key_ids").** The carve-out is a row where a **subject exercises its own revocation right**: `attestation_type ∈ {withdraws}` or a `consent:state:revoked` dimension whose **`attesting_key_id` is a member of the target row's `subject_key_ids`**. That is the §10.1.3 "NOT local-tier-eligible" set. Producer-authority rows that merely *name* a subject (`observed:user:*`, `consent:partnered:*` stance, `epistemic:about:*`, self-consent `identity:current`) are **not** in it — they ride local-tier (§3, §4.1).

**Substrate surface:**
- `attestations_overdue_for_promotion(now, window) -> Vec<...>` — the scan that finds subject-side revocations still `local`/unpromoted past `now - window`. Indexed (partial index on `tier = 'local'` + the revocation-dimension/authority predicate).
- `emit_consent_revocation_overdue(id)` — writes the `hard_case:consent_revocation_promotion_overdue` attestation (the fail-honest signal; LensCore composes `detection:consent:promotion_delay_pattern` on top — not persist's concern).
- **Enforcement at the write gate:** `attestation_upsert_local` / `attestation_insert_local` *refuse* a subject-side revocation (per the authority test above) outright — these must go through signed `put_attestation` / promotion. The bounded-window obligation then guards the residual case where a prior producer-authority local row *acquires* a subject-side revocation against it; the scan catches those and emits the `hard_case` past the window.

**Designed with CIRISPersist#161** (removal/revocation substrate, Option-A forward secrecy). The window enforcement is the same forward-only-unsubscribe guarantee #161 enforces at the membership-row layer; OQ-3 settles whether the timer lives here or there.

---

## 6. One contract, four role-scoped views

The coherence requirement. `cohort_scope` (visibility), `subject_key_ids` (revocability), and `identity_type`-set emitter gates (§7.0.1) mean the same thing regardless of writer:

| Sibling | identity_type | Uses the surface as |
|---|---|---|
| **CIRISAgent** | `agent` | `attestation_upsert_local` for every internal state mutation (`witness_relation: self`, empty subjects, deferred sig); `attestation_query` to read its own state; `attestation_promote` at federation-emit. |
| **CIRISNodeCore** | governance / `witness` | Multi-party Contributions/Votes stay in `src/cirisnode/types.rs`; **projects** finalized governance into `federation_attestations` (federation tier, signed) and READS promoted agent-intent via `attestation_query`. |
| **CIRISLensCore** | `lenscore_detector` | Emits `detection:*` / `capacity:*` *about* agent subjects (federation tier, non-empty `subject_key_ids`); consumes the §10.5 delivery axis. The agent's §7.5 anti-Goodhart 𝒞 factors come FROM LensCore's rows here — its write + the agent's read are two ends of one flow. |
| **CIRISRegistry** | CEG authority | READS/verifies attestations for conformance + registry consensus (`attestation:registry_consensus`, `provenance:build_manifest:*`); owns `licensure:{authority}` emission. |

The emitter gate (§7.0.1) is enforced at write per `identity_type` of the `attesting_key_id`; the tier model + `subject_key_ids` rule are uniform across all four. This is why the contract is designed once, here, before any of the four builds against it.

---

## 7. Schema — additive migration (V0xx)

`federation_attestations` gains:
- `tier TEXT NOT NULL DEFAULT 'federation'` — `CHECK (tier IN ('local','federation'))`. Default `federation` so every existing row keeps its meaning (all current rows are signed/federation).
- `promoted_at TIMESTAMPTZ NULL` — set by `attestation_promote`.
- The signature columns (`scrub_signature_classical`) become nullable **only under** `tier = 'local'`, via a replaced CHECK: `tier = 'federation' ⟹ scrub_signature_classical IS NOT NULL`. (Postgres: DROP/ADD CONSTRAINT; SQLite: trigger rewrite per the V054/V056/V064 discipline — this is the one not-pure-additive constraint touch.)
- Partial index `WHERE tier = 'local'` (filtered further at query time by the revocation-dimension/authority predicate) for the overdue scan (§5). Note the index is NOT on `subject_key_ids <> '{}'` — producer-authority rows legitimately carry subjects (§3); the scan keys on revocation authority, not subject presence.

No data backfill — the default makes existing rows `federation`. No `graph_nodes` coupling (§9).

## 8. Backend parity

Both backends: the tier column + CHECK/trigger, all three primitives, the overdue scan, PyO3. The parity conformance suite (CIRISConformance) gets a tier-model adversarial pass: local-row-leak-to-non-self-caller, unsigned-federation-row rejection, promote idempotency, overdue-scan boundary.

## 9. Coexistence / hard-cut migration (persist's obligations to #840)

- **Bulk local insert** via `attestation_upsert_local_many` — one transaction for the boot-time backlog transform.
- **Coexistence window:** post-cut, legacy `cirisgraph`/`graph_nodes` is retained **read-only as a cold backup** for one release alongside `federation_attestations`. Persist must tolerate both tables resident with **no cross-coupling** — the v-next schema bump MUST NOT drop or FK-link `graph_nodes`.
- **No shadow/dual-write.** Persist builds no `graph_nodes ↔ attestations` sync. The agent cuts atomically per occurrence, validating the transform against production DB dumps offline (the 2.9.0 scoutdb playbook).

## 10. Threat model — new AV entries

- **AV-59 (local-tier read escalation)** — a non-self caller (even an authorized family/community peer, or an Unauthenticated caller) MUST NOT receive `local`-tier rows. Closed by the tier read-gate (§3): `local` returned iff `CallerAdmission.occurrence_key_id == row producer`. Adversary: a peer enumerating another occurrence's un-promoted self-state.
- **AV-60 (unsigned federation leak)** — a `local` row MUST NOT become federation-visible without a hybrid signature. Closed by the CHECK (`tier=federation ⟹ sig present`) + `attestation_promote` being the only transition that flips the tier (and it signs first). Adversary: a direct-SQL `UPDATE tier='federation'` — the CHECK rejects it without a signature.
- **AV-61 (consent-revocation deferral abuse)** — a subject revokes; the producer leaves it local to keep propagating the subject's data. Closed by §5: the upsert gate refuses subject-revocations at local tier, and the overdue scan + `hard_case` emission make any acquired-revocation delay observable (fail-honest, §1.6).

## 11. Open questions — status after the Agent + Verify review

- **OQ-1 — local-write key + classes. ✅ RESOLVED (CIRISAgent).** Key on `(occurrence_key_id, dimension)` (the dimension string is the identity; `attestation_type` is too coarse). Two write classes: `attestation_upsert_local` (replace-on-dimension, singleton state) + `attestation_insert_local` (append, server-assigned id, multi-valued/event). The #840 map tags each dimension's class. Also: the local-tier gate keys on **producer authority**, not empty subjects (§3/§4.1/§5). Folded into the design.
- **OQ-2 — query dimension vocabulary. 🟡 OPEN → CIRISRegistry.** Now *more* load-bearing: since `dimension` IS the upsert key (OQ-1), the dimension grammar is the row identity. Closed enum pinned in CEG vs open prefix persist validates structurally? Registry owns it (+ the §7.0.1 emitter-gate semantics).
- **OQ-3 — who runs the 24h clock. 🟡 OPEN → resolve with #161.** Persist sweeper vs consumer-driven `attestations_overdue_for_promotion` scan vs edge. Persist ships the query + `hard_case` emission either way; this decides the trigger. Gates only §5's trigger, not the primitives.
- **OQ-4 — promotion canonical bytes. ✅ RESOLVED on the spec (CIRISVerify); ⛓ new dependency.** `JCS(envelope)` per CEG §0.9 / RFC 8785 — NOT Verify's internal LP framing; canonicalize the exact committed member set (omit-vs-materialize). **New blocking dependency for `promote` only: CIRISVerify#59** (JCS canonicalizer + CEG-Contribution verify path; composes with CIRISConformance#9). Registry still owns the exact envelope member set the JCS runs over.
- **OQ-5 — version + staging. ✅ RESOLVED (CIRISAgent).** v4.4.0 confirmed. `promote` stages *after* the write+read half — `upsert_local`/`insert_local`/`query` ship first (no JCS dependency); `promote` lands once CIRISVerify#59 is available. (Agent: 2.9.7 can land the transform + CEG-native local operation against the surface before federation promotion exists.)

**Net after review:** the two signature-affecting blockers (OQ-1 + the producer-authority gate) are resolved and folded in. Remaining gates: **OQ-2 (Registry — the dimension grammar, now the upsert key)** and **OQ-3 (#161 — the clock, trigger-only)**. `promote` additionally waits on **CIRISVerify#59**. LensCore + NodeCore have not yet confirmed their views compose (non-blocking for the write+read half).

## 12. Who needs to nod / shake (the 4-impl RC1 gate)

This surface is a contract *between* implementations, so it can't be accepted on persist's say-so. Required reviewers, each on the hook for specific questions:

| Reviewer | Status | Must nod/shake on | OQs |
|---|---|---|---|
| **CIRISAgent** (#840) | **✅ NOD (conditional, met)** | Conditioned on (1) producer-authority gate not empty-subjects, (2) `(occurrence_key_id, dimension)` key + an append path. Both folded in. v4.4.0 + staging confirmed. | OQ-1 ✅, OQ-5 ✅ |
| **CIRISVerify** | **✅ ANSWERED** | Promotion bytes = `JCS(envelope)` §0.9, not LP framing; exact committed member set. Filed **CIRISVerify#59** (JCS + Contribution-verify) — the `promote` interop deliverable. | OQ-4 ✅ (spec) |
| **CIRISRegistry** (CEG authority) | **🟡 PENDING — next** | The `dimensions[]` grammar (now the upsert key — load-bearing); the exact promotion envelope member set the JCS runs over; tier-model + §10.1.3 CEG conformance. **Conformance gate.** | **OQ-2**, OQ-4 member-set |
| **CIRISPersist#161** | **🟡 PENDING** | OQ-3 — who runs the 24h promotion clock (sweeper vs consumer scan vs edge). Trigger-only; doesn't block the primitives. | **OQ-3** |
| **CIRISLensCore** (#857) | **⬜ NOT YET** | `detection:*`/`capacity:*` write + anti-Goodhart read flow compose through `attestation_query`; `promotion_delay_pattern` rides the substrate `hard_case`. Non-blocking for write+read. | — |
| **CIRISNodeCore** | **⬜ NOT YET** | governance-projection write + promoted-agent-intent read both ride this contract, not a forked path. Non-blocking for write+read. | — |

**Minimum to accept the write+read half (v4.4.0 phase 1):** Agent ✅ + **Registry on OQ-2** (the dimension grammar). LensCore + NodeCore confirm views compose. `promote` (phase 2) additionally needs **CIRISVerify#59** + the OQ-4 member set + OQ-3's clock decision with #161.

**Sequencing after review:** OQ-1 + the producer-authority gate (signature-affecting) are resolved. **OQ-2 (Registry) is now the sole code-blocker for the write+read half** — it fixes the dimension grammar that is the upsert key. OQ-3 (clock) gates only §5's trigger. OQ-4/CIRISVerify#59 gate only `promote`, which is explicitly staged second.
