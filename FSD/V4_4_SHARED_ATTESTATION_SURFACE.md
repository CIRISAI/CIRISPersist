# FSD: CIRISPersist — Shared CEG Attestation Surface (local-tier write + query + promote)

**Status:** **Phase 1 ACCEPTED** (2026-06-08) — all four CEG-RC1 implementations nod (Agent ✅, Registry ✅, LensCore ✅, NodeCore ✅; Verify ✅ on OQ-4). The write+read half (tier model + `upsert_local`/`insert_local`/`query` + write gates + §5 scan/emission + migration) is cleared to build. **Phase 2 (`attestation_promote`)** stays Draft pending CIRISVerify#59 (JCS) + the OQ-4 envelope member set. **Phase-1 clock trigger (§5)** pending OQ-3 / CIRISPersist#161. Surface pinned in CEG §10.1.5 (`v-ceg-0.15`).
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
- **§1.4 Apophatic bound — open data, closed operators (per CIRISRegistry review).** This is a *fixed, named* surface (the methods below + one obligation), not an OLAP/graph engine. The apophatic bound is on the **operator set** — five fixed predicates, no caller-composed SQL/projections/JSONPath — NOT on the **vocabulary**. `dimensions[]` is an **open-vocabulary prefix set** (CEG §10.1.5.4 / §11.2.1): dimension families ship continuously (`consent:*`, `detection:community:*`, `settlement:*` across 0.6→0.15), so a closed enum would force a substrate redeploy per CEG namespace addition and is non-conformant. Open data, closed operators.
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

**Validation — two ineligible-for-local classes:**
1. **Subject-side revocation (§10.1.3 carve-out)** — `attestation_type ∈ {withdraws}` or a `consent:state:revoked` dimension whose `attesting_key_id` is a member of the *target* row's `subject_key_ids` (the subject exercising its own revocation right). Must go through signed `put_attestation` / promotion (§5).
2. **`capacity:*` anti-Goodhart (§7.5, per CIRISLensCore review — load-bearing).** `capacity:*` rejects self-emission: the local tier's self-write → self-read → deferred-sig shape is *exactly* the CEG §7.5 forbidden loop (the agent feeding its own capacity score back into its own context). So **`capacity:*` is ineligible for local tier outright** (rejected on `upsert_local`/`insert_local`), and on the federation path (`put_attestation`/`promote`) the substrate enforces **`attesting_key_id ≠ attested_key_id`** — capacity is inherently third-party-attested (that's what N_eff-as-independence means). The `attesting ≠ attested` rule per dimension-prefix is pinned in the OQ-2 grammar (§4.2) so it's a substrate-enforced property, not a consumer convention. (`detection:*` self-emission is closed by the §7.0.1 emitter gate restricting it to `identity_type: lenscore_detector`, which excludes `agent` — but `capacity:*` needs the explicit `attesting ≠ attested` check since a non-agent could satisfy the identity gate while self-attesting.) See AV-62.

Producer-authority rows are otherwise accepted regardless of whether they name a subject (§3). Rejects a non-`self` `witness_relation`.

### 4.2 `attestation_query(dimensions[], valid_at, confidence_floor, subject_key_id?, scope)`

The uniform read. **`dimensions[]` is an open-vocabulary prefix set, hierarchical-prefix-matched** (OQ-2, resolved by Registry; CEG §10.1.5.4) — persist validates the prefix *structurally* (well-formed CEG dimension syntax), it does NOT gate against a closed enum. So new CEG dimension families work without a persist redeploy, and every consumer's slice is covered by construction: the agent's `config:*`/`observed:user:*`/`epistemic:*`, NodeCore's governance slice (`goal:`/`approach:`/`method:`/`progress_measure:`/`moderation:`/`slashing:`/`reconsideration:`/`need:`/`deferral:aggregate:`/`weighted_aggregate:`), LensCore's `detection:*`/`capacity:*`. `valid_at` filters on `asserted_at <= valid_at < COALESCE(expires_at, ∞)`; `confidence_floor` filters on `weight >= floor`; `subject_key_id?` narrows to attestations about a subject; `scope: CallerScope` applies the v4.0 target-membership gate AND the tier gate (§3). The bounded surface (§1.4) is the **operator set** — these five predicates, no caller-composed SQL/projections. This is the DAS read shape — it reuses `cohort_scope_sql_predicate` + the cache substrate; NOT new query infra. The agent's memory/config/consent/audit services become thin wrappers; NodeCore/LensCore/Registry call the identical method with their role-scoped `CallerScope`.

### 4.3 `attestation_promote(id) -> SignedAttestation`

The local→federation transition: load the `local` row, compute the hybrid signature over its canonical bytes (`Engine::sign_hybrid`), write the signature + flip `tier = federation` (+ `promoted_at`). Idempotent: promoting an already-`federation` row returns it unchanged. At promotion, tiered-scope promotion semantics (§8.1.8.1) and `holds_bytes` emission (§10.1.2) fire exactly as for any federation write — promotion is the federation-emit moment.

**Canonical bytes — `JCS(envelope)`, NOT LP framing (OQ-4, resolved by CIRISVerify review).** A promoted row *is* a CEG Contribution four impls read + verify, so the signature MUST cover `JCS(contribution_envelope)` per CEG **§0.9 / RFC 8785** (`Engine::sign_hybrid(JCS(envelope))`); Verify recomputes the identical JCS bytes to verify. **Do NOT use Verify's internal length-prefixed `signing_bytes` framing** — that is correct only for verify-internal, verify-to-verify primitives (envelope framing, keyset rotation, doc integrity) that never cross the four-impl boundary as JSON; a promoted attestation is the opposite. Registry owns the exact envelope member set; Verify owns the matching recomputation.

**Three Registry musts (CIRISRegistry review, pinned CEG §10.1.5.3):**
1. **Byte-identical on the wire to a natively-federation attestation** — NO "was-promoted" marker in the signed bytes. A promoted row and a row born at `put_attestation` are indistinguishable to a verifying peer.
2. **Substrate columns are NOT canonicalized** — `tier`, `promoted_at` (and the local-tier bookkeeping) are persist-internal; only the §4 CEG envelope member set goes through JCS. (Registry owns that member set via the §0.9.3 catalog.)
3. **§0.9 omit-vs-materialize is load-bearing** — promotion MUST canonicalize the **exact member set the producer committed at local-write time**; a field *omitted* at `upsert_local`/`insert_local` MUST NOT be materialized at promote (and vice-versa), or the bytes diverge from what a peer recomputes and the hybrid sig fails. Persist serializes the stored committed envelope → JCS → sign; it does not re-default. (Same interop-trap class as the nonce/wrap encodings #63/#64.)

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
| **CIRISAgent** | `agent` | `attestation_upsert_local` (singleton state) / `attestation_insert_local` (multi-valued memory/verdicts) for internal state (`witness_relation: self`, deferred sig, subjects per §4.2.6); `attestation_query` to read its own state; `attestation_promote` at federation-emit. |
| **CIRISNodeCore** | governance / `witness` | **Two read surfaces (per NodeCore review).** Attestation reads (8 governance prefixes) migrate `persist_list_attestations` → `attestation_query` — a localized helper-swap, same shape as the v4.0 DAS absorption. The `local_feed`/`community_feed`/`global_feed` reads stay on `cirisnode.contributions` via `cirisnode_list_contributions` (Contribution **envelopes**, a different table — out of scope here). NodeCore needs **none** of the local-tier write primitives: multi-party governance stays in `src/cirisnode` → `cirisnode.contributions`; finalized governance outcomes **read, and MAY project** into `federation_attestations` via the existing `put_attestation` (federation-tier) — NodeCore does not project today; if it does, it's a v4.4-era deliverable, not a forked path. |
| **CIRISLensCore** | `lenscore_detector` | Emits `detection:*` / `capacity:*` *about* agent subjects (**federation tier, signed, `attesting ≠ attested`** — never local; §4.1/§7.5/AV-62); consumes the §10.5 delivery axis. The agent's §7.5 anti-Goodhart 𝒞 factors come FROM LensCore's rows here — its write + the agent's read are two ends of one flow. **`detection_events` vs `federation_attestations` (LensCore Q2):** the two are **parallel** for v4.4 — persist provides the attestation surface; whether LensCore migrates its `put_detection_event`/`cirislens_derived.detection_events` emission onto `federation_attestations` is **CIRISLensCore#857's** call (intersects #11), under the same `derived::*`-stability guarantee the v4.0 cut gave. Persist does not force the migration; no double-emit assumed. A `lenscore_detector` caller CAN read the `hard_case:consent_revocation_promotion_overdue` emission via `attestation_query` (the `promotion_delay_pattern` read path — confirmed, non-blocking). |
| **CIRISRegistry** | CEG authority | READS/verifies attestations for conformance + registry consensus (`attestation:registry_consensus`, `provenance:build_manifest:*`); owns `licensure:{authority}` emission + the OQ-2 dimension grammar + the OQ-4 envelope member set. Surface pinned in **CEG §10.1.5** (`v-ceg-0.15`). |

The emitter gate (§7.0.1) is enforced at write per `identity_type` of the `attesting_key_id`; the tier model + `subject_key_ids` (revocation-authority) rule + the `attesting ≠ attested` anti-Goodhart rule for `capacity:*` are uniform across all four. This is why the contract is designed once, here — and is now pinned in CEG §10.1.5 — before any of the four builds against it.

**Load model (CEG §10.1.5.5, Registry add).** The tier model is the cold-path-asymmetric-crypto dual of the streaming epoch-rekey: hot-path local write is O(1) unsigned; the lone hybrid-sign cost is on `promote` (federation-emit). A federation's attestation load models as *(local-write rate, promotion rate, query rate)*. Three measurable substrate signals: **local-row count, promotion rate, `hard_case:consent_revocation_promotion_overdue` count.**

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
- **AV-62 (capacity self-emission via local-tier deferral)** — an `agent` (or any caller satisfying the identity gate) writes a `capacity:*` row *about itself* via `attestation_upsert_local` (self-write, deferred sig) and reads it straight back (local rows are self-visible, §3) — the CEG §7.5 anti-Goodhart loop the agent's own capacity score must never close. Closed by §4.1: `capacity:*` is **ineligible for local tier outright**, and the federation path enforces **`attesting_key_id ≠ attested_key_id`**. The `attesting ≠ attested` rule is pinned per dimension-prefix in the OQ-2 grammar so it is substrate-enforced for every writer, not a consumer convention. (Raised by CIRISLensCore review as load-bearing — its §7.5 invariant; the write-side mirror of AV-61.)

## 11. Open questions — status after the Agent + Verify review

- **OQ-1 — local-write key + classes. ✅ RESOLVED (CIRISAgent).** Key on `(occurrence_key_id, dimension)` (the dimension string is the identity; `attestation_type` is too coarse). Two write classes: `attestation_upsert_local` (replace-on-dimension, singleton state) + `attestation_insert_local` (append, server-assigned id, multi-valued/event). The #840 map tags each dimension's class. Also: the local-tier gate keys on **producer authority**, not empty subjects (§3/§4.1/§5). Folded into the design.
- **OQ-2 — query/key dimension vocabulary. ✅ RESOLVED (CIRISRegistry; pinned CEG §10.1.5.4).** **Open-vocabulary prefix set, hierarchical-prefix-matched** — a closed enum is non-conformant (§11.2.1 axis discipline; families ship continuously). Persist validates the prefix structurally; the apophatic bound is on the *operator set* (five predicates), not the vocabulary — "open data, closed operators" (§1.4/§4.2). Satisfies NodeCore's governance-slice condition by construction. The OQ-2 grammar additionally pins the per-dimension-prefix `attesting ≠ attested` rule for `capacity:*` (LensCore §7.5/AV-62) + the §7.0.1 emitter-gate semantics, so those are substrate-enforced.
- **OQ-3 — who runs the 24h clock. 🟡 OPEN → resolve with #161.** Persist sweeper vs consumer-driven `attestations_overdue_for_promotion` scan vs edge. Persist ships the query + `hard_case` emission either way; this decides the trigger. Gates only §5's trigger, not the primitives.
- **OQ-4 — promotion canonical bytes. ✅ RESOLVED on the spec (CIRISVerify); ⛓ new dependency.** `JCS(envelope)` per CEG §0.9 / RFC 8785 — NOT Verify's internal LP framing; canonicalize the exact committed member set (omit-vs-materialize). **New blocking dependency for `promote` only: CIRISVerify#59** (JCS canonicalizer + CEG-Contribution verify path; composes with CIRISConformance#9). Registry still owns the exact envelope member set the JCS runs over.
- **OQ-5 — version + staging. ✅ RESOLVED (CIRISAgent).** v4.4.0 confirmed. `promote` stages *after* the write+read half — `upsert_local`/`insert_local`/`query` ship first (no JCS dependency); `promote` lands once CIRISVerify#59 is available. (Agent: 2.9.7 can land the transform + CEG-native local operation against the surface before federation promotion exists.)

**Net after the full four-impl review:** OQ-1, OQ-2, OQ-4, OQ-5 resolved; the producer-authority gate + the `capacity:*`/`attesting≠attested` anti-Goodhart gate folded in. **Phase 1 (write+read: tier model + `upsert_local`/`insert_local`(+`_many`) + `query` + the §4.1 write gates + the §5 scan/emission primitives + migration) has zero remaining blockers — it is accepted and ready to build.** Staged behind it: **`promote`** waits on **CIRISVerify#59** (JCS) + the OQ-4 member set (phase 2); the **§5 promotion-clock trigger** waits on **OQ-3 / #161** (persist ships the scan + `hard_case` emission regardless; #161 picks the trigger). LensCore Q2 (its own `detection_events` migration) is CIRISLensCore#857's, not a persist blocker.

## 12. Who needs to nod / shake (the 4-impl RC1 gate)

This surface is a contract *between* implementations, so it can't be accepted on persist's say-so. Required reviewers, each on the hook for specific questions:

| Reviewer | Status | Disposition |
|---|---|---|
| **CIRISAgent** (#840) | **✅ NOD** | Conditions met: producer-authority gate (not empty-subjects) + `(occurrence_key_id, dimension)` key + the `insert_local` append path. v4.4.0 + staging confirmed. OQ-1/OQ-5 ✅. |
| **CIRISRegistry** (CEG authority) | **✅ NOD** | OQ-2 = open prefix (§10.1.5.4); OQ-4 = JCS + 3 musts (§10.1.5.3); tier model conformant (Registry fixed CEG §10.1.3's over-narrow qualifier to match). **Surface pinned in CEG §10.1.5 / `v-ceg-0.15`.** |
| **CIRISVerify** | **✅ ANSWERED** | Promotion = `JCS(envelope)` §0.9, not LP framing. Filed **CIRISVerify#59** (JCS + Contribution-verify) — the phase-2 `promote` interop deliverable. OQ-4 ✅. |
| **CIRISLensCore** (#857) | **✅ NOD (condition folded)** | Read+tier compose. Condition: `capacity:*` ineligible-for-local + substrate `attesting ≠ attested` (§7.5/AV-62) — folded into §4.1/§4.2/§10. Q2 (`detection_events`) is #857's, parallel. |
| **CIRISNodeCore** | **✅ NOD (condition met)** | Composes, no forked path, needs no local-tier write primitive. Condition: OQ-2 covers the governance slice — **met** by the open-prefix answer. §6 two-read-surfaces + forward-looking-projection clarifications folded in. |
| **CIRISPersist#161** | **🟡 PENDING** | OQ-3 — who runs the 24h promotion clock. Trigger-only; doesn't block phase-1 primitives. |

**Phase 1 (write+read) is accepted — all four impls nod, zero remaining blockers.** Build it: tier model + `upsert_local`/`insert_local`(+`_many`) + `query` + §4.1 gates + §5 scan/emission + migration. **Phase 2 (`promote`)** stages behind **CIRISVerify#59** + the OQ-4 member set. **OQ-3 (#161)** picks the §5 clock trigger (persist ships scan+emission regardless).
