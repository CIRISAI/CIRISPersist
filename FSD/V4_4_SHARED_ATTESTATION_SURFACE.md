# FSD: CIRISPersist — Shared CEG Attestation Surface (local-tier write + query + promote)

**Status:** Implemented. Tier model (V066), local-tier writes (`attestation_upsert_local`, `attestation_insert_local`, `_many`), the scoped attestation read, the crossing into the federation tier, and the consent-revocation overdue scan, on both backends and the Python `Engine`. Surface pinned in CEG §10.1.5 (`v-ceg-0.15`).
**Driving issue:** CIRISPersist#171 — the CEG-native agent (CIRISAgent#840: `graph_nodes` are self-level CEG attestations; `CIRISAgent/FSD/CEG_NATIVE_AGENT.md`).
**Normative anchor:** CEG **§10.1.3** (local-tier signature deferral + the consent-revocation non-eligibility rule), §7.0.1 (identity_type emitter gates), §10.1.4 (structural invisibility), §8.1.8.1 (tiered-scope promotion). `CIRISRegistry/FSD/CEG/`.
**Cross-refs:** CIRISAgent#840 / #842, CIRISNodeCore (`compose.rs` CEG projection), CIRISLensCore#857 (CEG-native trace ingest), CIRISRegistry#45, CIRISPersist#161 (removal/revocation substrate), CIRISVerify#59 (JCS canonicalizer + CEG-Contribution verify), CIRISConformance#9 (cross-impl JCS vector set).
**Builds on:** the Data Access Surface (`FSD/V4_0_DATA_ACCESS_SURFACE.md`) — `CallerScope` / `CallerAdmission`, the target-membership `cohort_scope_sql_predicate`, the cache and `ReadEngine`. This FSD is the **write + promote** half of the same substrate.

---

## 0. Summary

`federation_attestations` is the **single store** all four CEG implementations (CIRISAgent, CIRISNodeCore, CIRISLensCore, CIRISRegistry) read from and write to. This surface gives it **one contract, four role-scoped views**:

1. **A tier model** — every attestation row is `local` (producer-only authority, signature deferred per CEG §10.1.3) or `federation` (hybrid-signed, federation-visible). A CHECK enforces `tier = federation ⟹ signature present`; the read gate hides `local` rows from every caller except the producing occurrence itself.
2. **`attestation_upsert_local` / `attestation_insert_local`** (+ batched `_many`) — the signature-deferred self-attestation writes (`witness_relation: self`).
3. **The scoped attestation read** — `ReadEngine::list_attestations` with an `AttestationFilter` (`dimension_prefixes`, `valid_at`, `confidence_floor`, `subject_key_id`, …) and a `CallerScope`: the uniform read the agent's memory/config/consent/audit services wrap, and the same read NodeCore, LensCore and Registry use for their slices.
4. **The crossing** — `local → federation`, signed over `JCS(envelope)`: `enter_mesh` (`FSD/PROMOTION_PRESERVES_THE_ACTOR_SIGNATURE.md`).
5. **Consent-revocation promotion obligation (CEG §10.1.3, normative)** — a subject-side revocation that rests local past a bounded window (default 24h) is reported as `hard_case:consent_revocation_promotion_overdue`.

No CEG wire-format change. No dual-write path. Both backends implement everything (parity, MISSION §1.5).

---

## 1. Why this exists — the mission case

### 1.1 The driving observation

The CEG-native agent (#840) stores its durable memory/config/consent/identity state as self-level CEG attestations in `federation_attestations`, which needs an agent-facing local-tier attestation **write** beside the federation read surface.

Three things make this a substrate concern, not an agent feature:

1. **The store is shared.** `federation_attestations` is the single table all four CEG-RC1 implementations read/write. CEG cannot reach RC1/1.0 until Agent, NodeCore, LensCore, and Registry all conform — *against this one table*. A surface forked per consumer would diverge the contract exactly where it must be coherent.
2. **The write is unsigned-by-design at local tier.** CEG §10.1.3 sanctions signature deferral for producer-only-authority self-attestations, while `put_attestation` takes a fully signed `SignedAttestation`. The substrate needs a representation for "recorded, producer-authoritative, not-yet-federation-signed" — the `local` tier.
3. **One leak the substrate must close.** §10.1.3 carves out the *one* case deferral is unsafe: subject-side consent revocation. If a user revokes and the revocation sits unsigned/unpromoted, other peers keep propagating the user's data. The substrate — not the consumer — must enforce the bounded promotion window (it owns the rows + the clock).

### 1.2 Alignment against MISSION.md

- **§1.1 Justice + Integrity** — a Raspberry-Pi agent and a datacenter node write self-attestations through the same tier model + scope discipline. One shape across every tier (§1.5 parity).
- **§1.2 N_eff** — attestations ARE the corpus. The agent's identity/config/consent/memory become measurable CEG rows instead of an opaque graph. If the tier model silently leaked `local` rows to federation, or served unsigned rows as authoritative, the measurement is corrupted at the load-bearing layer.
- **§1.4 Apophatic bound — open data, closed operators.** This is a *fixed, named* surface (the methods below + one obligation), not an OLAP/graph engine. The apophatic bound is on the **operator set** — five fixed predicates, no caller-composed SQL/projections/JSONPath — NOT on the **vocabulary**. `dimensions[]` is an **open-vocabulary prefix set** (CEG §10.1.5.4 / §11.2.1): dimension families ship continuously (`consent:*`, `detection:community:*`, `settlement:*` across 0.6→0.15), so a closed enum would force a substrate redeploy per CEG namespace addition and is non-conformant. Open data, closed operators.
- **§1.7 Relational fabric, not Cartesian gate** — `local` vs `federation` is *recorded tier*, not adjudicated trust. Promotion is a recorded transition the producer initiates; the substrate applies the §10.1.3 obligation the chain expresses, it does not decide who is "really" entitled.
- **§1.6 Fail-honest** — an overdue consent-revocation promotion is *labelled* (`hard_case:consent_revocation_promotion_overdue`), never silently tolerated. A `local` row is *labelled* local, never served as federation-authoritative.
- **§1.5 Parity** — both backends implement every primitive. No backend returns `NotImplemented`.

---

## 2. Scope

### 2.1 In scope
- The **tier column** + CHECK + read-gate on `federation_attestations` (§3, §7).
- `attestation_upsert_local` / `attestation_insert_local` and their `_many` forms (§4.1).
- The scoped attestation read (§4.2).
- The crossing into the federation tier (§4.3).
- The consent-revocation promotion obligation: the overdue scan and the `hard_case:consent_revocation_promotion_overdue` record (§5).
- The PyO3 surface for all of the above; both backends; the parity conformance suite.
- Coexistence with the agent's legacy `graph_nodes` (§9).

### 2.2 Out of scope
- **The CEG wire format.** §4 unchanged. No new structural primitives.
- **`graph_nodes` ↔ attestations sync.** No shadow/dual-write path (§9).
- **LensCore's `detection:consent:promotion_delay_pattern`** composition — it rides on top of the `hard_case` record and is LensCore's.

### 2.3 Backend parity
Postgres and SQLite implement every primitive. SQLite binds `u64` epoch/window as `i64` and uses correlated subqueries where PG uses CTEs; the answer shape is identical.

---

## 3. The tier model — `local` vs `federation`

The load-bearing concept. `put_attestation(SignedAttestation)` makes a signature part of the write contract; the **tier** says when it is not:

| Tier | `subject_key_ids` | Signature | Federation-visible | Written by |
|---|---|---|---|---|
| `local` | **empty OR non-empty** — any **producer-authority** row (incl. ones that *name* a subject) | **deferred** (NULL hybrid sig; `witness_relation: self`) | **No** — visible only to the producing occurrence | `attestation_upsert_local` / `attestation_insert_local` |
| `federation` | empty or non-empty | hybrid Ed25519 + ML-DSA-65 present | Yes | `put_attestation`, or the crossing (`enter_mesh`, local→federation) |

> **Local-tier eligibility is producer-only authority, NOT empty subjects.** CEG **§4.2.6** requires any dimension *naming* a subject to carry it in `subject_key_ids`, and large core classes of agent self-attestation are producer-authority **yet name a subject** — `observed:user:{hash}:*`, `consent:partnered:{user}` (CEG §10.1.3 says this MAY ride local-tier verbatim), `epistemic:about:{key}:*`, and the §4.2.3 self-consent `identity:current` with `subject_key_ids=[self]`. Forcing all non-empty-subject rows onto the signed path would defeat the deferral cost model for the majority of agent state. **The discriminator is "who holds revocation authority," not "is the subject set empty"** — see §5 for the one carve-out (subject-side revocation).

**The invariant (a CHECK on the table):** `tier = 'federation' ⟹ scrub_signature_classical IS NOT NULL` (and PQC per the existing hybrid-pending rules). A `local` row MAY carry a NULL signature. This relaxes — but does not remove — the "signed at federation" guarantee: nothing crosses to federation-visible unsigned.

**The read gate (composes with the DAS).** The `cohort_scope` target-membership predicate hides `self`-scoped rows from non-owners. The tier adds an orthogonal axis: a `local` row is returned ONLY when the caller's `CallerAdmission.occurrence_key_id` equals the row's producing occurrence (`CallerScope::admits_local_tier`; SQL twin `local_tier_sql_predicate`). Every other caller — including the rest of the caller's self-collective and an otherwise-authorized family/community peer, and every unauthenticated caller — sees nothing until the row crosses. AV-59 (§10).

**Why a tier column and not a separate table.** The four-impl contract demands *one* read shape. NodeCore reads promoted agent-intent and LensCore reads subjects through the *same* read; a second table would fork the read path. One table, one tier axis, one query.

---

## 4. The primitives

### 4.1 Local write — two classes (`upsert` + `insert`) + `_many`

The agent's `NodeType → dimension` map splits into two write classes. **The upsert key is `(occurrence_key_id, dimension)`** — the CEG dimension string IS the identity (it carries the scoped leaf: `config:filter_config`, `observed:user:{hash}:interaction_count`, `consent:partnered:{user}`). The structural `attestation_type` (scores/supersedes/withdraws/…) is too coarse — keying on it would collapse every distinct dimension in a scope into one row.

- **`attestation_upsert_local(envelope)`** — **singleton current-state** (`identity:current`, `config:{key}`, `consent:partnered:{user}`, `observed:user:{hash}:{metric}`): replace-on-`(occurrence_key_id, dimension)`; history via the `supersedes` composer.
- **`attestation_insert_local(envelope)`** — **multi-valued / event** (`epistemic:memory:topic={topic}` — many memories per topic; per-thought `dma:*`/`conscience:*` verdicts; observation events): **append**, each a distinct row with a server-assigned id, NOT collapsible by dimension. (An upsert keyed on dimension would collapse the agent's entire memory of a topic into one row.) The #840 map tags each dimension's write class.
- **`attestation_upsert_local_many(envelopes[])` / `attestation_insert_local_many`** — bulk forms for the agent's boot-time `graph_nodes → attestations` backlog. They **chunk internally** (CONCEPT/OBSERVATION memory can be thousands of rows on a long-lived agent) rather than issuing one statement (§9).

All write at `local` tier (`witness_relation: self`, **no hybrid signature**, deferred per §10.1.3); `subject_key_ids` MAY be non-empty (producer-authority rows that name a subject — §3).

**Validation — two ineligible-for-local classes:**
1. **Subject-side revocation (§10.1.3 carve-out)** — `attestation_type ∈ {withdraws}` or a `consent:state:revoked` dimension whose `attesting_key_id` is a member of the *target* row's `subject_key_ids` (the subject exercising its own revocation right). Must go through signed `put_attestation` / promotion (§5).
2. **`capacity:*` anti-Goodhart (§7.5 — load-bearing).** `capacity:*` rejects self-emission: the local tier's self-write → self-read → deferred-sig shape is *exactly* the CEG §7.5 forbidden loop (the agent feeding its own capacity score back into its own context). So **`capacity:*` is ineligible for local tier outright** (rejected on `upsert_local`/`insert_local`), and on the federation path (`put_attestation` / the crossing) the substrate enforces **`attesting_key_id ≠ attested_key_id`** — capacity is inherently third-party-attested (that's what N_eff-as-independence means). The `attesting ≠ attested` rule per dimension-prefix is pinned in the dimension grammar (§4.2, §11) so it is a substrate-enforced property, not a consumer convention. (`detection:*` self-emission is closed by the §7.0.1 emitter gate restricting it to `identity_type: lenscore_detector`, which excludes `agent` — but `capacity:*` needs the explicit `attesting ≠ attested` check since a non-agent could satisfy the identity gate while self-attesting.) See AV-62.

Producer-authority rows are otherwise accepted regardless of whether they name a subject (§3). Rejects a non-`self` `witness_relation`.

### 4.2 The scoped attestation read

`ReadEngine::list_attestations(AttestationFilter, …, CallerScope)` — the filter carries `dimension_prefixes`, `valid_at`, `confidence_floor` and `subject_key_id` among its fields. **`dimension_prefixes` is an open-vocabulary prefix set, hierarchical-prefix-matched** (CEG §10.1.5.4) — persist validates the prefix *structurally* (well-formed CEG dimension syntax), it does NOT gate against a closed enum. So new CEG dimension families work without a persist redeploy, and every consumer's slice is covered by construction: the agent's `config:*`/`observed:user:*`/`epistemic:*`, NodeCore's governance slice (`goal:`/`approach:`/`method:`/`progress_measure:`/`moderation:`/`slashing:`/`reconsideration:`/`need:`/`deferral:aggregate:`/`weighted_aggregate:`), LensCore's `detection:*`/`capacity:*`. `valid_at` filters on `asserted_at <= valid_at < COALESCE(expires_at, ∞)`; `confidence_floor` filters on `weight >= floor` (NULL weight excluded); `subject_key_id` narrows to attestations about a subject; the `CallerScope` applies the target-membership gate AND the tier gate (§3). The bounded surface (§1.4) is the **operator set** — fixed predicates, no caller-composed SQL/projections. It is the DAS read shape, reusing `cohort_scope_sql_predicate` and the cache substrate. The agent's memory/config/consent/audit services are thin wrappers; NodeCore/LensCore/Registry call the identical method with their role-scoped `CallerScope`.

Internal readers that pin an axis (`by` / `to`) use the typed bounded read `AttestationReads::query_attestations(AttestationQuery)` (`src/federation/attestation_query.rs`): a required page size, a cursor over the signed `(asserted_at, attestation_id)`, an optional `as_of` bound, and a `ReadOutcome` that distinguishes "served, empty" from "not served".

### 4.3 The crossing — `local → federation`

The transition is `enter_mesh` (`FSD/PROMOTION_PRESERVES_THE_ACTOR_SIGNATURE.md`): it signs the row's committed bytes, flips `tier = federation` and sets `promoted_at`, and never changes `cohort_scope` or replaces the actor's signature (a node participates as a co-scrub). Idempotent: an already-`federation` row returns `AlreadyInMesh`. At the crossing, tiered-scope semantics (§8.1.8.1) and `holds_bytes` emission (§10.1.2) fire exactly as for any federation write — the crossing is the federation-emit moment. Widening the audience is a separate `supersedes` row (`widen_audience`).

**Canonical bytes — `JCS(envelope)`, NOT LP framing.** A promoted row *is* a CEG Contribution four impls read + verify, so the signature MUST cover `JCS(contribution_envelope)` per CEG **§0.9 / RFC 8785** (`Engine::sign_hybrid(JCS(envelope))`); Verify recomputes the identical JCS bytes to verify. **Do NOT use Verify's internal length-prefixed `signing_bytes` framing** — that is correct only for verify-internal, verify-to-verify primitives (envelope framing, keyset rotation, doc integrity) that never cross the four-impl boundary as JSON; a promoted attestation is the opposite. Registry owns the exact envelope member set; Verify owns the matching recomputation.

**Three Registry musts (pinned CEG §10.1.5.3):**
1. **Byte-identical on the wire to a natively-federation attestation** — NO "was-promoted" marker in the signed bytes. A promoted row and a row born at `put_attestation` are indistinguishable to a verifying peer.
2. **Substrate columns are NOT canonicalized** — `tier`, `promoted_at` (and the local-tier bookkeeping) are persist-internal; only the §4 CEG envelope member set goes through JCS. (Registry owns that member set via the §0.9.3 catalog.)
3. **§0.9 omit-vs-materialize is load-bearing** — promotion MUST canonicalize the **exact member set the producer committed at local-write time**; a field *omitted* at `upsert_local`/`insert_local` MUST NOT be materialized at promote (and vice-versa), or the bytes diverge from what a peer recomputes and the hybrid sig fails. Persist serializes the stored committed envelope → JCS → sign; it does not re-default. (Same interop-trap class as the nonce/wrap encodings #63/#64.)

**JCS implementation.** The crossing-time bytes come from **`ciris_verify_core::jcs::canonicalize(&envelope)`** (RFC 8785, the shared cross-impl implementation — so persist's producer bytes are byte-identical to what a peer recomputes); verifying peers use `ciris_verify_core::jcs::verify_jcs_hybrid_signature` (CIRISVerify#59). No rolled crypto, no hand-rolled JCS (MISSION §1.4). Composes with CIRISConformance#9's RFC 8785 vector set (`FSD/V4_6_JCS_CANONICALIZATION.md`).

---

## 5. Consent-revocation promotion obligation (CEG §10.1.3 — normative)

The one place deferral is unsafe, and the one place the *substrate* (not a consumer) must enforce, because it owns the rows and the clock.

**Rule (verbatim from §10.1.3):** a Contribution carrying non-empty `subject_key_ids` whose subject subsequently emits `consent:state:revoked` (or a `withdraws` admitted under §3.2.3 rule 2/3) MUST promote to federation-tier within a bounded window. **Default 24h, operator-tunable.** Past the window without promotion, the substrate MUST emit `hard_case:consent_revocation_promotion_overdue`.

**What "subject-side revocation" means — it is NOT "non-empty subject_key_ids".** The carve-out is a row where a **subject exercises its own revocation right**: `attestation_type ∈ {withdraws}` or a `consent:state:revoked` dimension whose **`attesting_key_id` is a member of the target row's `subject_key_ids`**. That is the §10.1.3 "NOT local-tier-eligible" set. Producer-authority rows that merely *name* a subject (`observed:user:*`, `consent:partnered:*` stance, `epistemic:about:*`, self-consent `identity:current`) are **not** in it — they ride local-tier (§3, §4.1).

**Substrate surface:**
- `list_consent_revocation_promotion_overdue(now, sla)` — finds subject-side revocations still `local` with no `promoted_at` and resting longer than the window (`is_promotion_overdue`, one predicate shared with the non-emitting twin `list_consent_revocation_promotion_overdue_readonly`). Each overdue row is also recorded, idempotently, as `hard_case:consent_revocation_promotion_overdue` (deterministic event id, so a reader scan and a watcher tick never double-record one condition). LensCore composes `detection:consent:promotion_delay_pattern` on top.
- **The clock:** `run_consent_sla_watch` surfaces the same condition (its report counts `promotion_overdue`). Persist provides the scan and the record; the caller's maintenance loop drives the tick.
- **Enforcement at the write gate:** `attestation_upsert_local` / `attestation_insert_local` *refuse* a subject-side revocation (per the authority test above) outright — these go through signed `put_attestation` / the crossing. The bounded-window obligation guards the residual case where a prior producer-authority local row *acquires* a subject-side revocation against it.

The window enforcement is the same forward-only-unsubscribe guarantee CIRISPersist#161 enforces at the membership-row layer.

---

## 6. One contract, four role-scoped views

The coherence requirement. `cohort_scope` (visibility), `subject_key_ids` (revocability), and `identity_type`-set emitter gates (§7.0.1) mean the same thing regardless of writer:

| Sibling | identity_type | Uses the surface as |
|---|---|---|
| **CIRISAgent** | `agent` | `attestation_upsert_local` (singleton state) / `attestation_insert_local` (multi-valued memory/verdicts) for internal state (`witness_relation: self`, deferred sig, subjects per §4.2.6); the scoped read for its own state; the crossing at federation-emit. |
| **CIRISNodeCore** | governance / `witness` | Reads its governance prefixes through the scoped read. NodeCore needs **none** of the local-tier write primitives: its Contributions, votes and other classes are hybrid-signed `scores` rows on the federation tier (`FSD/CIRIS_PERSIST.md` Appendix A). |
| **CIRISLensCore** | `lenscore_detector` | Emits `detection:*` / `capacity:*` *about* agent subjects (**federation tier, signed, `attesting ≠ attested`** — never local; §4.1/§7.5/AV-62); consumes the §10.5 delivery axis. The agent's §7.5 anti-Goodhart 𝒞 factors come FROM LensCore's rows here — its write and the agent's read are two ends of one flow. `cirislens_derived.detection_events` is a parallel surface; whether LensCore moves its emission onto `federation_attestations` is CIRISLensCore#857's decision. A `lenscore_detector` caller can read the `hard_case:consent_revocation_promotion_overdue` records through the scoped read. |
| **CIRISRegistry** | CEG authority | READS/verifies attestations for conformance + registry consensus (`attestation:registry_consensus`, `provenance:build_manifest:*`); owns `licensure:{authority}` emission + the dimension grammar + the crossing's envelope member set. Surface pinned in **CEG §10.1.5** (`v-ceg-0.15`). |

The emitter gate (§7.0.1) is enforced at write per `identity_type` of the `attesting_key_id`; the tier model, the `subject_key_ids` (revocation-authority) rule and the `attesting ≠ attested` anti-Goodhart rule for `capacity:*` are uniform across all four. The contract is defined once, here, and pinned in CEG §10.1.5.

**Load model (CEG §10.1.5.5).** The tier model is the cold-path-asymmetric-crypto dual of the streaming epoch-rekey: hot-path local write is O(1) unsigned; the hybrid-sign cost falls on the crossing (federation-emit). A federation's attestation load models as *(local-write rate, promotion rate, query rate)*. Three measurable substrate signals: **local-row count, promotion rate, `hard_case:consent_revocation_promotion_overdue` count.**

---

## 7. Schema — V066 (`V066__federation_attestations_tier.sql`)

`federation_attestations` carries:
- `tier TEXT NOT NULL DEFAULT 'federation'` — `CHECK (tier IN ('local','federation'))`. The default keeps every row written before the column existed a signed federation row.
- `promoted_at TIMESTAMPTZ NULL` — set by the crossing.
- The signature columns (`scrub_signature_classical`) become nullable **only under** `tier = 'local'`, via a replaced CHECK: `tier = 'federation' ⟹ scrub_signature_classical IS NOT NULL`. (Postgres: DROP/ADD CONSTRAINT; SQLite: trigger rewrite per the V054/V056/V064 discipline — this is the one not-pure-additive constraint touch.)
- Partial index `WHERE tier = 'local'` (filtered further at query time by the revocation-dimension/authority predicate) for the overdue scan (§5). Note the index is NOT on `subject_key_ids <> '{}'` — producer-authority rows legitimately carry subjects (§3); the scan keys on revocation authority, not subject presence.

No data backfill. No `graph_nodes` coupling (§9).

## 8. Backend parity

Both backends: the tier column + CHECK/trigger, the write and read primitives, the crossing, the overdue scan, PyO3. The parity conformance suite (CIRISConformance) gets a tier-model adversarial pass: local-row-leak-to-non-self-caller, unsigned-federation-row rejection, promote idempotency, overdue-scan boundary.

## 9. Coexistence with `graph_nodes` (persist's obligations to #840)

- **Bulk local insert** via the `_many` forms for the agent's boot-time backlog transform.
- **Coexistence:** the legacy `cirisgraph` / `graph_nodes` tables can stay resident beside `federation_attestations` with **no cross-coupling** — no migration drops or FK-links `graph_nodes`.
- **No shadow/dual-write.** Persist has no `graph_nodes ↔ attestations` sync. The agent moves each occurrence atomically.

## 10. Threat model

- **AV-59 (local-tier read escalation)** — a non-self caller (even an authorized family/community peer, or an Unauthenticated caller) MUST NOT receive `local`-tier rows. Closed by the tier read-gate (§3): `local` returned iff `CallerAdmission.occurrence_key_id == row producer`. Adversary: a peer enumerating another occurrence's un-promoted self-state.
- **AV-60 (unsigned federation leak)** — a `local` row MUST NOT become federation-visible without a hybrid signature. Closed by the CHECK (`tier=federation ⟹ sig present`) + the crossing being the only transition that flips the tier (and it signs first). Adversary: a direct-SQL `UPDATE tier='federation'` — the CHECK rejects it without a signature.
- **AV-61 (consent-revocation deferral abuse)** — a subject revokes; the producer leaves it local to keep propagating the subject's data. Closed by §5: the upsert gate refuses subject-revocations at local tier, and the overdue scan + `hard_case` emission make any acquired-revocation delay observable (fail-honest, §1.6).
- **AV-62 (capacity self-emission via local-tier deferral)** — an `agent` (or any caller satisfying the identity gate) writes a `capacity:*` row *about itself* via `attestation_upsert_local` (self-write, deferred sig) and reads it straight back (local rows are self-visible, §3) — the CEG §7.5 anti-Goodhart loop the agent's own capacity score must never close. Closed by §4.1: `capacity:*` is **ineligible for local tier outright**, and the federation path enforces **`attesting_key_id ≠ attested_key_id`**. The `attesting ≠ attested` rule is pinned per dimension-prefix in the dimension grammar, so it is substrate-enforced for every writer, not a consumer convention (the write-side mirror of AV-61).

## 11. Decisions

- **Local-write key and classes.** Key on `(occurrence_key_id, dimension)`; two write classes, `attestation_upsert_local` (replace-on-dimension, singleton state) and `attestation_insert_local` (append, server-assigned id). The local-tier gate keys on **producer authority**, not empty subjects (§3/§4.1/§5).
- **Read vocabulary.** **Open-vocabulary prefix set, hierarchical-prefix-matched** (CEG §10.1.5.4 / §11.2.1): a closed enum would force a substrate redeploy per CEG namespace addition and is non-conformant. Persist validates prefix structure; the apophatic bound is on the *operator set*, not the vocabulary — "open data, closed operators". The grammar also pins the per-prefix `attesting ≠ attested` rule for `capacity:*` (AV-62) and the §7.0.1 emitter-gate semantics.
- **Who runs the 24h clock.** Persist ships the scan, the `hard_case` record and the `run_consent_sla_watch` branch that surfaces it; the caller's maintenance loop runs the tick (§5).
- **Crossing canonical bytes.** `JCS(envelope)` per CEG §0.9 / RFC 8785, with the three Registry musts (§4.3) — not CIRISVerify's internal length-prefixed framing.

## 12. Parties

This surface is a contract *between* implementations:

| Party | Role in the contract |
|---|---|
| **CIRISAgent** (#840) | Producer-authority local writes; the `(occurrence_key_id, dimension)` key; the `insert_local` append path. |
| **CIRISRegistry** (CEG authority) | Owns the open-prefix dimension grammar (§10.1.5.4), the crossing's envelope member set and the three musts (§10.1.5.3). |
| **CIRISVerify** | Owns `ciris_verify_core::jcs::{canonicalize, verify_jcs_hybrid_signature}` (CIRISVerify#59). |
| **CIRISLensCore** (#857) | `capacity:*` ineligible for local + substrate `attesting ≠ attested` (§7.5/AV-62); reads the overdue records. |
| **CIRISNodeCore** | Reads through the same scoped read; no local-tier writes. |
| **CIRISPersist#161** | The membership-row half of the forward-only-unsubscribe guarantee (§5). |
