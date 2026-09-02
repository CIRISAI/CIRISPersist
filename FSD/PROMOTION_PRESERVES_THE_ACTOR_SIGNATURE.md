# FSD: CIRISPersist — Promotion preserves the actor's signature (the fabric key never replaces the actor key)

**Status:** **SHIPPED in v39.0.0** (2026-09-02). The build followed this document with the deltas recorded in §11; read §11 before citing any earlier section as the shipped shape. Edge reviewed end-to-end and answered OQ-1/OQ-2 with corrections folded below (CIRISEdge `docs/FSD_REPLICATION_DX.md` §6 items 4–6, `786815c`). Written against CIRISConstitution **1.0-rc4** and persist **v38.8.0**.
**Author:** Eric Moore (CIRIS Team) with Claude Fable 5.1
**Created:** 2026-09-02
**Repo:** `~/CIRISPersist`
**Target cut:** v38.9.0 or v39.0.0 — see §8; the split of `promote_attestation` is a **behavioural break** for every caller that widens scope through it.
**Risk:** **High, and in the direction that matters.** This changes who signs a promoted row. Get it wrong one way and an agent's claims are signed by the fabric (today's defect); get it wrong the other way and rows never promote. Every load-bearing gate below has a named mutation.
**Normative anchors:** CC **5.3.2.4.2** (promotion signs `JCS(envelope)` over the *exact* member set the producer committed; a promoted row is **byte-indistinguishable** from one born federation-tier; **no was-promoted marker in the signed bytes**), CC **4.4.3.3.1 / 8.1.5** (scope widening is a `supersedes` chain, original preserved, lineage walkable), CC **2.6.1.1 / 2.6.1.5** (relay discipline: preserve what the producer signed exactly; forward the original signature unchanged), CC **2.6.7** (±5 min clock skew; `cosigned_at`; cosignatures >5 min from `signed_at` MUST be rejected), CC **2.6.2** (datetime canonical form `YYYY-MM-DDTHH:MM:SS.sssZ`), CC **5.3.2.4.3** (local tier: signature MAY be absent; `tier = federation ⟹ hybrid present AND verified`), CC **2.6.1.3** (the signed-discriminator redaction shape is **ruled out**, CIRISConstitution#78), CC **4.4** two granters / cohabitation (`agent = node + brain`, two delegations, `node`-only keys carry only `infra:*`).
**Driving question (operator, 2026-09-02):** *"We need to maintain any original signatures — we would be overwriting the actor's key with the fabric's key."* Confirmed against code: `promote_attestation` overwrites `scrub_key_id` / `scrub_signature_*` with the promoting node's reseal and clears `additional_scrubs`.
**Cross-refs:** CIRISPersist#649 (why `cohort_scope` was folded into the promote primitive), #643/#598 (what the signed mirror binds), #556 (every scrub verified over the same preimage), #589 (placement carried by the primitive), #750 (a bound member cannot be mutated after mint — the class this FSD must not recreate), #791 (a resolver over a gate-shaped verifier).

---

## 0. TL;DR for reviewers

**The question asked was whether an "envelope-in-envelope" promotion flows the same as a re-stamped envelope. The answer is no — and neither is the constitutional shape.** The constitution already defines the two operations persist's `promote_attestation` conflates, and defining them separately gives the operator exactly what was asked for with **no new envelope field, no new primitive, and no preimage change**:

1. **Tier promotion** (`local → federation`, CC 5.3.2.4.2) signs the **same bytes** the producer committed. It never changes `cohort_scope`. Because the bytes are unchanged, the actor's signature — if present — stays valid, and the node's participation is a **co-scrub** in `additional_scrubs` (CC-verified over identical bytes at every peer, #556). The original is included and flows the same *because it is byte-identical to a born-federation row*, which is what CC 5.3.2.4.2 demands.
2. **Scope widening** (CC 4.4.3.3.1 / 8.1.5) is a **`supersedes`** row authored and signed by the **actor**, referencing the original by `references_attestation_id`. The original row is never mutated; the lineage is walkable. This is where the operator's "re-stamp by the same key" lives, and it is the only place a re-sign is ever needed.
3. **`created` = `asserted_at`**, which is *already* a bound top-level envelope member (#598). **`modified` = `cosigned_at`** on each `ScrubSig`, the CC 2.6.7 name — signature metadata that lives *outside* the signed envelope (as the scrub set already does), so it costs no preimage. The ±5-minute rule is CC 2.6.7's own skew bound, already `CLOCK_SKEW_TOLERANCE` in persist.

**Envelope-in-envelope is ruled out on two independent grounds:** CC 5.3.2.4.2 forbids any was-promoted marker in the signed bytes (a nested original *is* one), and CC 2.6.1.3 explicitly rules out the signed-discriminator shape (#78: "a signed marker proves an authorized party changed the bytes — it does not prove that *only* the marked parts changed").

**What persist has to change:** split `promote_attestation` into its two constitutional halves, stop clearing `additional_scrubs` on tier promotion, stop re-signing with the fabric key, add `cosigned_at` to `ScrubSig`, implement the `supersedes` widening path (`differs_in` — not implemented today), and fix a **CC 2.6.2 conformance gap** found on the way: persist stamps `asserted_at` with `to_rfc3339()` (`+00:00`, microseconds) where the constitution requires `.sssZ` (milliseconds, `Z`).

---

## 1. Why this exists — what the code does today, measured

### 1.1 One signature slot, overwritten

`Attestation` carries exactly one signature: `scrub_signature_classical` / `scrub_signature_pqc` + `scrub_key_id` ("key_id that signed this row"). There is no separate actor-signature field. `attesting_key_id` is an *identifier*, not a signature.

`promote_attestation` on both SQL backends is one statement:

```sql
UPDATE federation_attestations
   SET attestation_envelope = ?, original_content_hash = ?,
       scrub_signature_classical = ?, scrub_signature_pqc = ?,
       scrub_key_id = ?,                       -- the PROMOTING NODE
       scrub_timestamp = ?, pqc_completed_at = ?, persist_row_hash = ?,
       tier = 'federation', promoted_at = ?,
       additional_scrubs = '[]',               -- the co-scrub set is CLEARED
       cohort_scope = ?,                       -- the placement is CHANGED
       admitted_at = ?
 WHERE attestation_id = ? AND tier = 'local'
```

`AttestationReseal.scrub_key_id` is documented as *"the DERIVED federation `key_id` of the re-signer"* — the promoting node. `envelope.rs` states the design outright: `scrub_key_id` / `scrub_timestamp` are *"signature metadata, legitimately REWRITTEN when a promoting node re-scrubs the row."* This FSD overrides that design.

### 1.2 Which rows actually carry an actor signature at local tier

Not all of them, and the distinction shapes everything below.

- **Producer-authority self-attestations** (the CC 5.3.2.2 deferral case) are written with the **empty-sentinel scrub** (`scrub_signature_classical = ""`). There is no actor signature to overwrite — promotion is the first signing. For these rows today's behaviour loses nothing *cryptographically*; it mis-attributes custody.
- **Transit revocations** (`LocalTierDisposition::TransitRevocation`) **are** caller-signed at the local write (`LocalAttestationInput::scrub_signature_classical`, verified at that door). Promotion then re-stamps the mirror from typed columns and re-signs with the node's key. **This is the case where an actor's signature is destroyed.**
- **Any future path where an agent or human signs at local write** — which is the operator's stated model (see §3) — is the transit-revocation shape generalised.

### 1.3 Why the conflation exists (#649), so we do not re-learn it

`#643` bound seven typed columns into the signed row mirror. Promotion changed one of them (`cohort_scope`) while re-signing the *pre*-promotion envelope, so every promoted row carried a mirror asserting its old scope beside a column saying otherwise — and every peer refused it. The fix (#649) folded the re-stamp into the promote primitive so tier flip, placement, and re-sign landed atomically. That fix was correct *for the operation it assumed* — a single "promote" that changes scope. The constitution never assumed that. It is two operations, and only one of them changes bytes.

### 1.4 The CC 2.6.2 gap found on the way

`stamp_signed_instants` and `attestation_emit::stamp_and_canonicalize` write `asserted_at` / `expires_at` with `chrono::to_rfc3339()` after truncating to `CONSENT_INSTANT_RESOLUTION_NANOS = 1_000` (microseconds). That emits `2026-09-02T10:00:00.123456+00:00`. CC 2.6.2 (normative) requires `2026-09-02T10:00:00.123Z` — exactly three fractional digits, literal `Z`, and *"consumers MUST reject any other form when verifying a signature."* Persist's own `check_instant_binding` parses (tolerantly), so persist-to-persist verifies; a strict CC consumer would not. This is a **signed-bytes** divergence and belongs in the same cut, because this FSD adds a second bound datetime.

---

## 2. Terms — the key model this FSD assumes

| Key | Held by | Constitutional plane |
|---|---|---|
| **nodeID** | the fabric node (≥1 at bootstrap) | `infra:*` only — CC 4.4 conformance: a key whose `identity_type` contains `node` MUST carry only `infra:*` scopes; a verifier MUST reject `agency:*` on it |
| **FedID** | the human owner (≥2 post-startup) | standing; the owner grants `infra:network_presence` / `infra:hold_*` to the node (CC 4.4 "two granters") |
| **AgentID** | the agent brain (≥3 for agents) | `agency:*` via a *separate* `delegates_to` (CC 4.4 cohabitation: `agent = node + brain`, two delegations, independently revocable) |

**The actor** is whichever of FedID / AgentID authored the claim (`attesting_key_id`). **The fabric** is nodeID. The constitution's two-granters rule is the reason the fabric key must never stand in for the actor: a `node`-only key **literally cannot carry agency**, so a fabric signature over an agent's claim is not a weaker attestation — it is a category error the wire is designed to make refusable.

---

## 3. The requirement, restated

From the operator (2026-09-02), restated so it can be checked:

1. Human- and agent-signed rows that get promoted are **re-stamped by the same key** that signed them — never by the fabric.
2. Two time fields: **`created`** (original creation, immutable) and **`modified`** (the re-stamp).
3. If promotion happens **more than 5 minutes** after creation, **do not re-stamp**; **co-scrub** instead — the co-scrub includes the original signature and flows identically.
4. The implied semantics of the 5-minute window: *is the original signer still reachable?* Inside it the actor can sign again; outside it the actor may be gone, so preserve what they signed and add the node's signature alongside.

Requirement 4 is the operator's, not the constitution's, but it lands squarely on CC 2.6.7: ±5 minutes is the constitutional skew bound, `cosigned_at` is the constitutional name for a cosignature instant, and *"cosignatures with `signed_at` farther than 5 minutes from the … published `signed_at` MUST be rejected"* is the constitutional precedent for a time-bounded co-signature window.

---

## 4. Validation against the constitution

### 4.1 Envelope-in-envelope — ruled out

**CC 5.3.2.4.2 (normative):** *"A promoted row is therefore byte-indistinguishable on the wire from one born federation-tier; there is no 'was-promoted' marker in the signed bytes."* A nested original envelope inside the signed bytes is precisely a was-promoted marker. Non-conformant.

**CC 2.6.1.3 (normative, CIRISConstitution#78):** the *signed-discriminator* shape — a signed marker saying "an authorized party changed this" — is ruled out as a dead end, with the reasoning kept in-clause: it proves an authorized party changed the bytes, not that *only* the marked parts changed. A wrapping signature over a nested original has the same property: the outer signer could alter anything outside the inner envelope and every reader reports the row as legitimately promoted.

**CC 2.6.1 (part_3:1267)** does use the phrase "inner envelope" — `envelope_hash = sha256(JCS(inner envelope))` for the org planes. That is a *hash basis* for a different plane, not a promotion wrapper, and should not be read as precedent.

**Verdict:** do not build it. What follows is what the constitution provides instead, and it is strictly better.

### 4.2 Tier promotion — same bytes, actor's signature preserved, node co-scrubs

CC 5.3.2.4.2: *"The signature MUST cover `JCS(contribution_envelope)` — the identical canonical bytes any natively-federation attestation signs … Promotion MUST canonicalize the exact member set the producer committed at local-write time."*

Consequences, each verified against persist:

- Tier promotion **must not** change `cohort_scope`. Today it does (`restamp_for_scope`, #649). That is the conflation.
- Because the bytes do not change, an actor signature made at local write **remains valid** over the promoted row. There is nothing to re-stamp.
- The node's participation is a **co-scrub**: an entry in `additional_scrubs` over the same `JCS(envelope)`. Persist already verifies every attestation co-scrub at ingest over the same preimage (`tier_ingest.rs:181`, #556: *"EVERY scrub, not just the first"*), and `ScrubSig`'s own doc states the rule: *"Every scrub on a record is over the **same** canonical bytes; the scrub set lives OUTSIDE the signed envelope."* So co-scrubbing is already a first-class, verified mechanism — persist just clears it at the wrong moment.
- CC 2.6.1.5 step 5 — *"Store/forward object O AS RECEIVED … Forward original signature S unchanged"* — is satisfied by construction.

This is what "the co-scrub should include the original and flow just the same" means constitutionally: the original *is* the base scrub, the node's is an additional scrub, and both verify at every peer over identical bytes. There is no second mechanism.

### 4.3 Scope widening — `supersedes`, authored by the actor

CC 4.4.3.3.1: *"A Contribution's `cohort_scope` MAY be widened (promoted) by emitting a `supersedes` against the prior attestation … `differs_in: ["cohort_scope", …]` … This pattern is wire-format-clean: it re-uses the structural primitive `supersedes` rather than introducing a `promote` primitive. The chain is walkable via `references_attestation_id` so the promotion lineage is preserved."*

CC 8.1.5's worked example has the **same** `attesting_key_id` on original and promoted rows (`user-alice-2026`), a fresh `asserted_at`, and `new_cohort_scope`.

Consequences:

- The original row is **never mutated**. Its signature, its `asserted_at`, its scope all stand. This is the operator's "maintain any original signatures" requirement, met by the primitive that already exists.
- The widening row is a **new claim by the actor**, signed by the actor's key. This is where "re-stamp by the same key" lives — and it is not a re-stamp of the old bytes, it is a new signature over a new row that *references* the old one.
- **Persist does not implement this.** `grep differs_in src/` returns nothing. Every widening today goes through the conflated `promote_attestation`. This FSD adds it.
- If the actor's signer is unavailable, the widening **waits**. A node cannot author a `supersedes` on an agent's behalf — the two-granters rule makes that a category error (§2). See OQ-1 for the delegated variant.

### 4.4 `created` and `modified` — already have constitutional names and homes

The constitution does not define `created` or `modified`. Its datetime vocabulary (CC 2.6.7) is `signed_at`, `asserted_at`, `valid_until`, `delegation_valid_from/until`, and `cosigned_at`.

| Operator term | Constitutional member | Where it lives | Signed? | Status in persist |
|---|---|---|---|---|
| `created` | **`asserted_at`** | top-level envelope key | **yes** — bound by #598, checked by `check_instant_binding` | **exists** |
| `modified` (base signer) | `scrub_timestamp` | signature metadata column | no — CC 5.3.2.4.2: substrate columns are never in canonical bytes | exists |
| `modified` (each co-signer) | **`cosigned_at`** | new field on `ScrubSig` | no — the scrub set lives outside the envelope by design | **add** |

This is the load-bearing design point: **`modified` must not enter the signed envelope.** If it did, adding it at promotion would change the bytes, the actor's local-tier signature would stop verifying, and the co-scrub path (§4.2) would become impossible — exactly the #649 shape. Putting it on the `ScrubSig` gives each signer its own instant, outside the preimage, which is what CC 2.6.7's `cosigned_at` already is.

(Correcting a claim made in conversation on 2026-09-02: `asserted_at` was described as an unsigned column. It is bound — as a top-level envelope key, not inside the seven-member `row` mirror. The seven-member mirror and the top-level instants are two different binding sites.)

### 4.5 The ±5-minute rule — CC 2.6.7, already in persist

`CLOCK_SKEW_TOLERANCE = Duration::minutes(5)` (`operational.rs:90`), cited to §0.7 / CC 2.6.7. The rule as this FSD states it:

> At tier promotion, if `now - asserted_at ≤ CLOCK_SKEW_TOLERANCE` **and** the actor's signer is reachable, the actor signs (or has already signed — same bytes). Otherwise the node **co-scrubs** the actor's existing signature. A row with **no** actor signature and no reachable actor signer **stays local** (fail-secure; see OQ-1 for the delegated alternative).

The input to the rule, `asserted_at`, is **signed** (§4.4), so it cannot be backdated to force the co-scrub path or forward-dated to force the re-stamp path. This matters: if the rule keyed on an unsigned column, the party choosing which key signs would be choosing by editing a column nothing binds.

### 4.6 What is *not* changing

- No new envelope member. No new primitive. CC 1.7's 1+4 surface is untouched.
- `check_row_column_binding` and the seven-member mirror are untouched.
- `tier = federation ⟹ hybrid present AND verified` (CC 5.3.2.4.3) holds — a co-scrubbed row has at least one verified hybrid scrub, and #556 verifies all of them.
- Deferred-signature local rows (CC 5.3.2.2) remain allowed. This FSD does not force actor-signing at local write; it makes actor signatures *survive* when present.

---

## 5. Design — the split

### 5.1 `enter_mesh` — tier-only, same bytes (replaces `promote_attestation`)

```rust
/// CC 5.3.2.4.2 — flip `local → federation` over the SAME bytes.
/// Never changes `cohort_scope`. Never replaces an existing scrub.
async fn enter_mesh(
    &self,
    attestation_id: &str,
    ci: ContextualIntegrity,          // §5.6 — all nine axes, no defaults
    custody: TierPromotionCustody,
) -> Result<MeshCrossing, Error>;

pub enum TierPromotionCustody {
    /// The actor's own hybrid signature over JCS(envelope), minted now or at
    /// local write. Becomes (or already is) the BASE scrub.
    ActorSigned(AttestationReseal),
    /// The node's hybrid signature over the same bytes, APPENDED to
    /// `additional_scrubs` with `cosigned_at = now`. Requires an existing
    /// verified base scrub; refused otherwise (see `NoActorSignature`).
    NodeCoScrub(ScrubSig),
}
```

Refusals (all typed, none collapse to `Ok`):

| Condition | Refusal |
|---|---|
| row is already `federation` | `Ok(AlreadyInMesh)` (idempotent, CC 5.3.2.4.2) |
| `NodeCoScrub` and base scrub is the empty sentinel | `Error::NoActorSignature` — the fabric cannot be the only signer of an actor's claim |
| `ActorSigned` and `reseal.scrub_key_id != row.attesting_key_id` | `Error::CustodyIsNotTheActor` |
| the reseal's bytes ≠ `JCS(stored envelope)` | `Error::PromotionMovedThePreimage` — the #649 class, refused at the primitive |
| `now - asserted_at > CLOCK_SKEW_TOLERANCE` and variant is `ActorSigned` | **admitted** — the window governs *which path the engine chooses*, not what the primitive accepts; an actor who is present after 5 minutes may still sign |

`additional_scrubs` is **never cleared** by tier promotion. The #557/#556 concern that motivated clearing — local-tier co-scrubs stored without verification — is answered differently: they are verified at *this* door before the flip, and refused if unverifiable, exactly as ingest already does.

### 5.2 `widen_audience` — scope widening via `supersedes` (new)

```rust
/// CC 4.4.3.3.1 — widen `cohort_scope` by a `supersedes` row the ACTOR signs.
/// The prior row is untouched.
async fn widen_audience(
    &self,
    prior_attestation_id: &str,
    ci: ContextualIntegrity,          // §5.6 — recipient_see is the NEW audience
    signed: SignedAttestation,   // attestation_type = supersedes,
                                 // references_attestation_id = prior,
                                 // differs_in = ["cohort_scope"],
                                 // attesting_key_id = prior.attesting_key_id
) -> Result<MeshCrossing, Error>;
```

Refused unless `signed.attesting_key_id == prior.attesting_key_id` (or a delegated signer per OQ-1), unless `new_cohort_scope` is strictly wider, and unless `references_attestation_id` resolves. The `content_sha256` / `evidence_refs` of the prior are reused (CC 8.1.5: "no body re-upload").

Readers that resolve "the current scope of claim X" must walk the `supersedes` chain — this is the projection work (see §7).

### 5.3 `ScrubSig` gains `cosigned_at`

```rust
pub struct ScrubSig {
    pub scrub_key_id: String,
    pub scrub_signature_classical: String,
    pub scrub_signature_pqc: Option<String>,
    /// CC 2.6.7 — when this co-signer signed. Signature METADATA: outside the
    /// envelope and outside the preimage, like the scrub set itself.
    /// CC 2.6.2 canonical form (`.sssZ`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cosigned_at: Option<String>,
}
```

Additive and serde-default; a pre-cut `ScrubSig` round-trips unchanged. `KeyRecord::additional_scrubs` shares the type and inherits the field harmlessly.

### 5.4 The engine's promotion motion

```
promote(row):
  if row.tier == federation: return AlreadyInMesh
  age = now - row.asserted_at                       # asserted_at is SIGNED
  has_actor_sig = row.scrub_signature_classical != ""

  if actor_signer_reachable(row.attesting_key_id):
      # the actor can sign; do so over the SAME bytes (re-stamp = same sig)
      enter_mesh(id, ci, ActorSigned(actor.sign(JCS(env))))
  elif has_actor_sig:
      # actor gone; preserve their signature, add custody
      enter_mesh(id, ci, NodeCoScrub(node.coscrub(JCS(env), now)))
  else:
      # deferred row, no actor, no signature: it WAITS — a typed outcome,
      # never a silent stay-local. There is nothing to co-scrub (W4).
      return MeshCrossing::AwaitingActor { attestation_id, age }
      emit hard_case: promotion_awaiting_actor        # see §7 — the CC 5.3.2.2
                                                      # overdue emission's sibling
```

`age` is reported so the CC 2.6.7 window is *observable*. `actor_signer_reachable` is **not an oracle**: it means "the caller handed over the actor's signer". The layer holding the key decides; persist never guesses at presence.

**Sign-at-write, per key class (OQ-2, answered by edge from this FSD's own gates).** The co-scrub path — the only thing in this FSD that *preserves* anything — is closed to a row with no signature (W4). So a deferred row's only road to the wire is the actor present at the crossing; otherwise it parks. Key rotation makes "actor gone" routine, not exotic: a row deferred under AgentID-v1 and promoted after rotation to v2 has no signer that can ever sign it as v1 (W5), whereas signed at write, v1's signature over the identical bytes stands and the node co-scrubs. And §4.5's guarantee that `asserted_at` is signed holds *exactly* for rows signed at write — a deferred row's `asserted_at` is an unsigned stamped column until the very promotion the rule governs. Therefore:

| key class | signs at | rationale |
|---|---|---|
| **software-held actor keys** (AgentID, in-process via keyring; cohabitation) | **local write** | prompt-free hybrid sign on a path that already canonicalises and fsyncs; measure before deferring (CC 5.3.2.2's cardinality win is real but must be shown, and if it matters it is self-witnessed telemetry, never a claim) |
| **ceremony-bound keys** (FedID on hardware) | **the crossing** | a signature that costs a presence ceremony cannot be paid per local write; for chat the crossing *is* the send, so the ceremony coincides with intent. A human row never signed, whose human is absent, correctly stays local — it is a draft nobody committed. Deferral-as-consent, not deferral-as-optimisation |

Edge's practice already agrees: every edge producer signs at write; `share*` takes the **actor's** signer — present → `ActorSigned`; absent + signed → `NodeCoScrub`; absent + unsigned → `Shared::AwaitingActor`.

### 5.6 The DX — two verbs, nine axes, and the consequence in the name

**Federation-tier crossing is the moment every contextual-integrity axis must be answered, because it is the moment edge starts replicating the row.** The constitution's CI vocabulary is closed and ratified (CC 4.5.1.1): `ci_axis ∈ {sender, data_subject, recipient_see, recipient_revoke, recipient_receive, information_type, transmission_principle, temporal_lifecycle, content}`. The namespace manifest already records which wire field answers which axis, per family (`families.*.round2.ci_axes`). Today `promote_attestation` takes an `attestation_id` and a `cohort_scope` and answers one axis by name. That is the DX defect: the crossing is silent about eight of the nine questions it is committing the row to.

**Naming.** Edge owns `share_clear_privately` / `share_encrypted_privately` / `share_publicly` — a *sharing* vocabulary, consumer-facing, keyed on how bytes travel. Persist's two verbs must be distinct from those, clearer than `promote` (which names neither operation), and must carry their consequence:

| Verb | Constitutional operation | What it changes | What edge sees afterwards |
|---|---|---|---|
| **`enter_mesh`** | tier crossing, CC 5.3.2.4.2 | `tier: local → federation`. Nothing in the signed bytes. | the row appears on the wire index and replicates to whoever `cohort_scope` already admits |
| **`widen_audience`** | scope widening, CC 4.4.3.3.1 | authors a new `supersedes` row with a wider `cohort_scope`; the prior row is untouched | a **new** row appears, addressed to the wider audience; the old one stays exactly where it was |

`promote_attestation` is removed, not aliased (this repo's clean-break rule).

**Both verbs take a `ContextualIntegrity` value that answers all nine axes by construction.** No field has a default; a caller that cannot state an axis cannot call the verb. This is the point — the type is the checklist, and the compiler is the reviewer:

```rust
/// The nine CC 4.5.1.1 axes, answered explicitly at the federation crossing.
/// Every field is required. A crossing that cannot name one of these is a
/// crossing whose consequences nobody stated.
pub struct ContextualIntegrity {
    /// `sender` — who is speaking. MUST equal the row's `attesting_key_id`;
    /// the verb refuses otherwise (the fabric is never the sender of an
    /// actor's claim).
    pub sender: KeyId,
    /// `data_subject` — who the claim is ABOUT. Mirrors `subject_key_ids`;
    /// `Nobody` is an explicit answer, not an omission.
    pub data_subject: DataSubject,             // Nobody | Keys(Vec<KeyId>)
    /// `recipient_see` — who may learn it exists. The `cohort_scope` plus,
    /// for family/community, the target id. This is the audience.
    pub recipient_see: Audience,               // SelfOnly | Family(id) | Community(id) | Global
    /// `recipient_revoke` — who may withdraw it (CC 2.4.1.1). Derived from
    /// `subject_key_ids` and stated back so the caller SEES the authority
    /// they are conferring by crossing.
    pub recipient_revoke: RevocationAuthority, // ProducerOnly | Subjects(Vec<KeyId>)
    /// `recipient_receive` — pull via the holds_bytes directory, or push.
    pub recipient_receive: DeliveryMode,
    /// `information_type` — the dimension family, resolved against the
    /// manifest so the per-family norm (`projection_for`) is the one applied.
    pub information_type: AttestationFamily,
    /// `transmission_principle` — the consent grant this crossing rides on
    /// (a `consent:scope:*` reference), or `ProducerAuthority` for a
    /// producer-only row. Stated, so a row never crosses "because the
    /// caller said so".
    pub transmission_principle: TransmissionPrinciple,
    /// `temporal_lifecycle` — `asserted_at` (signed; the row's own) and the
    /// bound the caller asserts (`valid_until` / retention class).
    pub temporal_lifecycle: Lifecycle,
    /// `content` — the content hash the crossing commits to. Byte-identical
    /// for `enter_mesh`; reused (no re-upload, CC 8.1.5) for
    /// `widen_audience`.
    pub content: ContentRef,
}
```

The verb **cross-checks every axis against the row** and refuses on any mismatch — `sender ≠ attesting_key_id`, `data_subject ≠ subject_key_ids`, `recipient_see` narrower than the row's current scope on `widen_audience`, a `transmission_principle` naming a consent grant that does not cover this `information_type`. Each refusal is typed and names the axis. A caller therefore cannot cross a row while misdescribing it, and a reader of the call site sees all nine answers at the point of the decision.

**Return shape says what edge will do:**

```rust
pub struct MeshCrossing {
    pub attestation_id: String,        // the row now on the wire (new id for widen_audience)
    pub audience: Audience,            // recipient_see, as applied
    pub custody: Custody,              // ActorSigned | ActorSignedNodeCoScrubbed
    pub age_at_crossing: Duration,     // now − asserted_at (the CC 2.6.7 window, observable)
    pub replicates: Replicates,        // { kinds, discoverable: bool }
}

/// The variant for a deferred row whose actor is absent. Typed, so "it did
/// not cross" is something a caller reads rather than infers from silence.
pub enum MeshCrossingOutcome { Crossed(MeshCrossing), AwaitingActor { attestation_id, age } }
```

`replicates` states what persist can state and no more. **`self` and `family` rows DO replicate** — to the owner's own node set and to the family's nodes respectively, by consent fan-out over resolved recipients rather than by `holds_bytes` discovery. CC 5.2 makes them *undiscoverable*, not un-replicated. (An earlier draft labelled them `InvisibleByScope`; edge corrected it from its side of the wire, `src/edge.rs` `CohortScope::SelfOnly`.) So persist reports `discoverable: false` for those scopes and `true` otherwise; **where the bytes go** (`routes_to`) is edge's to state, on edge's `Crossing`.

**One type, persist's.** `ContextualIntegrity` (nine axes, required, refused by axis name) subsumes edge's five-axis `Flow`. Edge deletes `Flow`, re-exports `ContextualIntegrity` + `MeshCrossing`, and keeps `With` (which maps onto `Audience`) and `Shared`.

**Why this is not ceremony.** The nine-axis struct is the manifest's own rubric turned into a call signature. Persist already derives `ci_axis` per field at manifest generation and gates axis fusion (CC 4.5.1.1). What it never did was ask the *caller* to answer the axes at the one moment they become irrevocable. `enter_mesh` is that moment, because edge picks the row up on the next round.

### 5.5 Timestamp conformance (CC 2.6.2)

`stamp_signed_instants`, `stamp_and_canonicalize`, and the new `cosigned_at` write `to_rfc3339_opts(SecondsFormat::Millis, true)` → `.sssZ`. `CONSENT_INSTANT_RESOLUTION_NANOS` moves from `1_000` (µs) to `1_000_000` (ms) so the truncation matches the wire form. `check_instant_binding` keeps parsing tolerantly for pre-cut rows (their bytes are already signed and cannot be re-rendered — every preimage field must be recoverable from the stored row).

---

## 6. Witnesses — what each mutation must kill

Every entry names the mutation that must fail it. A witness whose mutation survives is a claim about the witness (this repo's standing rule).

| # | Property | Mutation that must FAIL |
|---|---|---|
| W1 | `enter_mesh` leaves `JCS(envelope)` byte-identical | make it call `restamp_for_scope` |
| W2 | actor's base scrub survives tier promotion | overwrite `scrub_key_id` with the reseal's |
| W3 | `additional_scrubs` survives tier promotion | reinstate `additional_scrubs.clear()` |
| W4 | `NodeCoScrub` over an empty-sentinel base is refused | drop the `NoActorSignature` check |
| W5 | `ActorSigned` with a non-actor `scrub_key_id` is refused | drop the `CustodyIsNotTheActor` check |
| W6 | a co-scrubbed promoted row verifies at a **peer's** `put_attestation` with BOTH scrubs | verify only scrub #1 at ingest (re-open #556) |
| W7 | `widen_audience` leaves the prior row byte-identical | mutate the prior's `cohort_scope` in the widening path |
| W8 | `supersedes` by a non-actor key is refused | drop the `attesting_key_id` equality check |
| W9 | `cosigned_at` is outside the preimage | include it in `JCS(envelope)` — the actor's signature must still verify |
| W10 | `asserted_at` renders as `.sssZ` and a `+00:00` form is refused **on a new-epoch row** | keep `to_rfc3339()` |
| W11 | the age reported equals `now - asserted_at` and `asserted_at` is the SIGNED value | compute age from `scrub_timestamp` |
| W12 | a transit revocation's caller signature survives promotion (the case that is lost today) | route transit revocations through the old re-sign path |
| W13 | a `ContextualIntegrity` whose `sender ≠ attesting_key_id`, or whose `data_subject ≠ subject_key_ids`, is refused by name of the axis | drop the per-axis cross-check |
| W14 | `visible_to_edge` is `InvisibleByScope` for every `self`/`family` crossing and `Replicates` otherwise | report `Replicates` unconditionally |

All on three backends. The postgres leg must be confirmed **executing** (timing), not skipping on an unset DSN.

---

## 7. Projections and readers that must change

- **"Current scope of claim X"** now walks `supersedes`. `projection_for` and the retention/serve gates that read `cohort_scope` from a single row need a fold: newest non-tombstoned `supersedes` in the chain wins. This is the same fold shape as `precedence::retired_ids`; do not write a second one.
- **`hard_case:promotion_awaiting_actor`** — a deferred row whose actor is unreachable past the window. The sibling of CC 5.3.2.2's `consent_revocation_promotion_overdue` (already implemented, `hard_case.rs:36`): observability, not a slashing trigger.
- **`trace_events` projection** — unaffected; it already carries the pre-transform form.
- **Wire index** — a `supersedes` row is a new row and indexes normally; tier promotion no longer changes bytes so `signed_wire_index` no longer needs re-indexing on promote (it does today, because the hash moves).

---

## 8. Sequencing and version

Two behavioural breaks, one conformance fix:

1. **`promote_attestation` is removed** — every caller that flips tier migrates to `enter_mesh`; every caller that widens through it (`bootstrap_admission.rs` ×7, `engine.rs` ×4) migrates to `widen_audience`. This is a public-API break → **MAJOR (v39.0.0)** under this repo's clean-break rule (no aliases, rename + remove in one cut, flagged in CHANGELOG).
2. **Timestamp form** changes signed bytes for new rows. Not a break for stored rows (tolerant parse), a break for any external party byte-comparing persist's `asserted_at` — which CC 2.6.2 says they should have been refusing anyway.
3. Ship `ScrubSig.cosigned_at`, `ContextualIntegrity`, and `enter_mesh` **first**, `widen_audience` **second**, in the same release: a tier-only crossing with no widening path would strand every caller that needs to widen.

---

## 9. Open questions

**OQ-1 — Delegated widening. ANSWERED: no.** Subsidiarity (CC part 3 §308) and `check_node_agency_admission` make it cryptographic, not policy: a `node`-only key cannot carry agency, and widening an agent's claim is agency. The widening waits for the actor. Recorded by edge (`786815c`).

**OQ-2 — Sign at local write? ANSWERED: yes for software-held actor keys, at the crossing for ceremony-bound keys** — see §5.4's table and the four gates in this FSD that force it. **Correction to an earlier disposition:** "a human-authored row whose FedID lives elsewhere falls to the co-scrub path or waits" was half false under this FSD's own W4 — an unsigned row has nothing to co-scrub. It waits, as a typed `AwaitingActor`. The co-scrub path exists only for rows signed at write.

**OQ-3 — `cosigned_at` on the KeyRecord co-scrub plane.** The field is shared by type. The accord co-scrub ceremony could stamp it; nothing requires it to. Left optional; the key-plane quorum verifier ignores it.

**OQ-4 — Pre-cut promoted rows.** Rows already promoted by the fabric key exist in the corpus. They are valid signatures by the node over bytes the node minted; they are not forged. This FSD does not rewrite them (that would be the #649 shape). An operator report listing `scrub_key_id != attesting_key_id` federation rows is the honest disclosure.

---

## 10. What was checked, and how

Every constitutional claim above was read from `CIRISConstitution/constitution/part_{2,3,4,5,8}*.md` at 1.0-rc4 on 2026-09-02, and every persist claim from `src/` at v38.8.0 — by grep and by reading the cited lines, not from memory. The two places the conversation preceding this FSD was wrong are corrected in-line (§4.1 on "inner envelope" precedent; §4.4 on `asserted_at` being unsigned). The CC 2.6.2 gap (§1.4) was not being looked for.

---

## 11. What shipped differently from this document (v39.0.0)

Recorded here rather than rewritten into the sections above, so the reasoning
that led to each choice stays readable.

1. **Naming.** `enter_federation` shipped as **`enter_mesh`** (operator call: less confusing next to the `federation` tier). Types: `MeshCrossing`, `MeshCrossingOutcome` (`Crossed | AlreadyInMesh | AlreadyWidened | AwaitingActor`), `TierPromotionCustody`, `Custody`, `Replicates`.
2. **`Audience` carries the cohort id** for `family`/`community` (`Audience::Family { family_key_id }`, `Audience::Community { community_key_id }`). A widening into a cohort plane goes through the put door's AV-45 write-scope gate, which proves membership against the cohort the row NAMES; a targeted audience without its id is not an audience. The consent sweep therefore widens to `family`/`community` only when the grant names the cohort (a cohort-target alias on its envelope) and otherwise counts the row `skipped` with a warning. `enter_mesh` is unaffected (the placement is the row's own).
3. **CC 2.6.2 (§5.5) shipped as two constants, not one moved.** Minting renders `.sssZ` at millisecond resolution (`SIGNED_INSTANT_RESOLUTION_NANOS`); the ingest CHECK stays at microseconds (`CONSENT_INSTANT_RESOLUTION_NANOS`), because raising it would refuse every already-signed pre-v39 row. W10's "a `+00:00` form is refused on a new-epoch row" is not enforceable without an epoch marker and was not claimed; what is witnessed is that every minted instant renders `.sssZ`.
4. **`(federation, self)` is admitted at the crossing** — the placement arm of `check_promotion_admission` no longer refuses `self` (it was #315's dead plane only while nothing consumed it). The "not strictly wider" refusal lives at `widen_audience` (`AudienceNotWider`).
5. **`widen_audience` is a default trait method** over `get_attestation` + `put_attestation` (no per-backend body); it reports `AlreadyWidened` when the put door deduplicated the supersedes (CEG §6.1). To widen a claim twice, widen the LATEST row in its chain.
6. **`temporal_lifecycle` and `content` are cross-checked against the CLAIM** — the row itself for `enter_mesh`, the PRIOR for `widen_audience` — because a widening describes the claim being widened, whose instants and content hash the actor already signed; the new row's own do not exist until it is stamped and signed. The `transmission_principle` grant check requires the grant to name the audience only at a widening; at `enter_mesh` it must cover the dimension.
7. **`Engine::register_self`** emits the identity's `delegates_to` federation-tier directly, signed by `SelfAtLoginInput::identity_signer` (or by this node when the identity IS its composed signer); otherwise the delegation is staged local and waits. It is not widened, because a `supersedes` is not a `delegates_to` to a type-keyed reader — see §7 and the reader contract in the CHANGELOG.
8. **The consent sweep** (§5.4's engine motion) is two passes over one predicate: local rows (enter, then widen) and `list_widening_candidates` (undiscoverable federation rows with no widening yet — the sealed-before-grant case). `repair_stranded_scope_backlog` and the in-place re-scope are gone; `ConsentSweepReport` is `{promoted, widened, awaiting_actor, skipped}`.
9. **W14** reads `replicates.discoverable == false` for `self`/`family` and `true` otherwise (edge's correction, §5.6). **W12** rides W2's mechanism and is not fixtured separately.
10. **`register_hybrid_key_as`** in test support: a community member must be a human or steward-bound, so the B9 witness registers its producer as a USER before proving membership and then STANDING.

