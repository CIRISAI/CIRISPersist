# FSD: CIRISPersist — Shared CEG Attestation Surface (local-tier write + query + promote)

**Status:** Draft — for review by the four CEG-RC1 implementations before any code. NOT yet accepted.
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.8
**Created:** 2026-06-08
**Repo:** `~/CIRISPersist`
**Target cut:** v4.4.0 (additive surface + one additive `federation_attestations` migration; no wire-format change, CEG §4 unchanged).
**Risk:** Additive at the grammar layer (CEG 1+4 lockdown holds). The one non-trivial change is a **tier model** on `federation_attestations` (a `local` tier with deferred signature) — additive column + a CHECK, but it relaxes the current "every attestation row is signed at write" invariant, so it is called out explicitly and gated on the threat-model review below.
**Driving issue:** CIRISPersist#171 (this ask) — gating dependency for **CIRISAgent#840** (CEG-native agent; `graph_nodes` ARE self-level CEG attestations; `CIRISAgent/FSD/CEG_NATIVE_AGENT.md`).
**Normative anchor:** CEG 0.15 **§10.1.3** (local-tier signature deferral + the consent-revocation non-eligibility rule), §7.0.1 (identity_type emitter gates), §10.1.4 (structural invisibility), §8.1.8.1 (tiered-scope promotion). `CIRISRegistry/FSD/CEG/`.
**Cross-refs:** CIRISAgent#840 / #866 (2.9.6 umbrella) / #842, CIRISNodeCore (`compose.rs` CEG-projection), CIRISLensCore#857 (CEG-native trace ingest), CIRISRegistry#45, CIRISPersist#161 (removal/revocation substrate — ask #4 is designed *with* it).
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
| `local` | empty (producer-only authority) | **deferred** (NULL hybrid sig; `witness_relation: self`) | **No** — visible only to the producing occurrence | `attestation_upsert_local` |
| `federation` | empty or non-empty | hybrid Ed25519 + ML-DSA-65 present | Yes | `put_attestation` (status quo) OR `attestation_promote` (local→federation) |

**The invariant (a CHECK on the table):** `tier = 'federation' ⟹ scrub_signature_classical IS NOT NULL` (and PQC per the existing hybrid-pending rules). A `local` row MAY carry a NULL signature. This relaxes — but does not remove — the "signed at federation" guarantee: nothing crosses to federation-visible unsigned.

**The read gate (composes with v4.0 DAS).** `ReadEngine v2`'s `cohort_scope` target-membership predicate already hides `self`-scoped rows from non-owners. The tier adds an orthogonal axis: a `local` row is returned ONLY when the caller's `CallerAdmission.occurrence_key_id` equals the row's producing occurrence (self-read). Every other caller — including an otherwise-authorized family/community peer — sees nothing until promotion. AV-59 (§10) is the threat entry that nails this shut.

**Why a tier column and not a separate table.** The four-impl contract demands *one* read shape. NodeCore reads promoted agent-intent and LensCore reads subjects via the *same* `attestation_query`; splitting local rows into a second table would fork the read path and re-introduce the per-consumer divergence this FSD exists to prevent. One table, one tier axis, one query.

---

## 4. The three primitives

### 4.1 `attestation_upsert_local(envelope)` + `_many(envelopes[])`

Write a producer-only-authority self-attestation at `local` tier: `witness_relation: self`, empty `subject_key_ids`, **no hybrid signature** (deferred per §10.1.3). `upsert` semantics keyed on the producer's dimension identity (the #840 `NodeType → dimension` map decides the key; persist treats it as `(occurrence_key_id, attestation_type, scope_id)` unless review pins otherwise — OQ-1). `_many` is one transaction for the boot-time `migrate_graph_nodes_to_attestations()` backlog (identity/config/consent/memory) — bulk insert must be efficient (§9).

**Validation:** rejects a non-empty `subject_key_ids` on this path (that is NOT producer-only authority — it must go through the signed `put_attestation`, the §10.1.3 carve-out). Rejects a non-`self` `witness_relation`.

### 4.2 `attestation_query(dimensions[], valid_at, confidence_floor, subject_key_id?, scope)`

The uniform read. `dimensions[]` is a closed set of `attestation_type` prefixes (the #840 dimension vocabulary); `valid_at` filters on `asserted_at <= valid_at < COALESCE(expires_at, ∞)`; `confidence_floor` filters on `weight >= floor`; `subject_key_id?` narrows to attestations about a subject; `scope: CallerScope` applies the v4.0 target-membership gate AND the tier gate (§3). This is the DAS read shape — it reuses `cohort_scope_sql_predicate` and the cache substrate; it is NOT new query infra. The agent's memory/config/consent/audit services become thin wrappers; NodeCore/LensCore/Registry call the identical method with their role-scoped `CallerScope`.

### 4.3 `attestation_promote(id) -> SignedAttestation`

The local→federation transition: load the `local` row, compute the hybrid signature over its canonical bytes (`Engine::sign_hybrid` — already available), write the signature + flip `tier = federation` (+ `promoted_at`). Idempotent: promoting an already-`federation` row returns it unchanged. At promotion, tiered-scope promotion semantics (§8.1.8.1) and `holds_bytes` emission (§10.1.2) fire exactly as for any federation write — promotion is the federation-emit moment.

---

## 5. Consent-revocation promotion obligation (CEG §10.1.3 — normative)

The one place deferral is unsafe, and the one place the *substrate* (not a consumer) must enforce, because it owns the rows and the clock.

**Rule (verbatim from §10.1.3):** a Contribution carrying non-empty `subject_key_ids` whose subject subsequently emits `consent:state:revoked` (or a `withdraws` admitted under §3.2.3 rule 2/3) MUST promote to federation-tier within a bounded window. **Default 24h, operator-tunable.** Past the window without promotion, the substrate MUST emit `hard_case:consent_revocation_promotion_overdue`.

**Substrate surface:**
- `attestations_overdue_for_promotion(now, window) -> Vec<...>` — the scan that finds subject-revoked Contributions still `local`/unpromoted past `now - window`. Indexed (a partial index on `tier = 'local' AND subject_key_ids <> '{}'`).
- `emit_consent_revocation_overdue(id)` — writes the `hard_case:consent_revocation_promotion_overdue` attestation (the fail-honest signal; LensCore composes `detection:consent:promotion_delay_pattern` on top — not persist's concern).
- **Enforcement at the upsert gate:** `attestation_upsert_local` *refuses* a subject-side revocation (non-empty `subject_key_ids`) outright — per §10.1.3 these are "NOT local-tier-eligible." So the obligation primarily guards the case where a prior local self-attestation *acquires* a subject revocation against it; the scan catches those.

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
- Partial index `WHERE tier = 'local' AND subject_key_ids <> '{}'` for the overdue scan (§5).

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

## 11. Open questions — these gate acceptance

- **OQ-1 — upsert key.** Is the local-upsert identity `(occurrence_key_id, attestation_type, scope_id)`, or does the #840 `NodeType → dimension` map pin a different key? (Agent owns the answer.)
- **OQ-2 — query dimension vocabulary.** Is `dimensions[]` a closed enum pinned in CEG, or an open prefix set persist validates structurally? (Registry + the §7 emitter-gate semantics.)
- **OQ-3 — who runs the 24h clock.** Persist background sweeper vs consumer-driven `attestations_overdue_for_promotion` scan vs edge. Resolve with #161. (Persist ships the query + emission either way; this decides the trigger.)
- **OQ-4 — promotion canonical bytes.** Exact canonicalization the hybrid signature covers at promote time (must match what federation peers verify). (Registry + Verify.)
- **OQ-5 — version.** v4.4.0 (additive minor) confirmed, or fold into a larger CEG-RC1 cut?

## 12. Who needs to nod / shake (the 4-impl RC1 gate)

This surface is a contract *between* implementations, so it can't be accepted on persist's say-so. Required reviewers, each on the hook for specific questions:

| Reviewer | Must nod/shake on | Owns these OQs |
|---|---|---|
| **CIRISAgent** (#840, `FSD/CEG_NATIVE_AGENT.md`) | The `attestation_upsert_local` / `attestation_query` shapes match the `NodeType → dimension` map; `_many` bulk-insert + the `graph_nodes` cold-backup coexistence are sufficient for the hard cut; the local-upsert key. **Primary consumer — strongest veto.** | **OQ-1**, OQ-5 |
| **CIRISRegistry** (CEG authority) | The tier model + §10.1.3 enforcement conform to CEG; the `dimensions[]` vocabulary (closed-enum vs open-prefix); the promotion canonical bytes. **Conformance gate.** | OQ-2, **OQ-4** |
| **CIRISLensCore** (#857) | The `detection:*` / `capacity:*` write side (federation tier, non-empty `subject_key_ids`) + the anti-Goodhart read flow work through `attestation_query`; LensCore's `detection:consent:promotion_delay_pattern` composes cleanly on the substrate `hard_case` emission. | — |
| **CIRISNodeCore** | The governance-projection write into `federation_attestations` + reading promoted agent-intent both work through this contract (not a forked path); the `src/cirisnode` typed-table → projection boundary is unchanged. | — |
| **CIRISVerify** | The promotion-time hybrid signature + canonical bytes interop (what federation peers verify). | OQ-4 (jointly with Registry) |
| **CIRISPersist#161** (revocation substrate) | OQ-3 — who runs the 24h promotion clock (persist sweeper vs consumer scan vs edge); the window enforcement is the same forward-only-unsubscribe guarantee #161 owns. | **OQ-3** |

**Minimum to accept:** Agent + Registry nods on OQ-1/OQ-2/OQ-4 and an OQ-3 resolution with #161. LensCore + NodeCore confirm their views compose (no forked read/write path). Eric notifies the sisters + federation per the standing cut convention; downstream PRs land against the accepted surface.

**Sequencing:** OQ-1 (upsert key) and OQ-2 (dimension vocab) gate the method signatures, so they block code. OQ-3 (the clock) gates only §5's trigger, not the substrate primitives — persist can ship the scan + emission and wire the trigger once #161 resolves. OQ-4 (canonical bytes) gates `attestation_promote` but not `attestation_upsert_local` / `attestation_query`, so the write+read half can land ahead of promote if review wants to stage it.
