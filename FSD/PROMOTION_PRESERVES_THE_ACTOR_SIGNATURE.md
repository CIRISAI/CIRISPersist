# FSD: CIRISPersist — Promotion preserves the actor's signature (the fabric key never replaces the actor key)

**Status:** Implemented. `src/federation/crossing.rs` is the map: it decides whether a row may cross into the federation tier, who signs it, and what the caller must state about it; the backends execute the plan it computes. Witnesses W1–W16 (§6) in `src/federation/bootstrap_admission.rs`, on both backends.
**Risk:** **High, and in the direction that matters.** This decides who signs a promoted row. Wrong one way and an agent's claims are signed by the fabric; wrong the other way and rows never promote. Every load-bearing gate has a named mutation (§6).
**Normative anchors:** CC **5.3.2.4.2** (promotion signs `JCS(envelope)` over the *exact* member set the producer committed; a promoted row is **byte-indistinguishable** from one born federation-tier; **no was-promoted marker in the signed bytes**), CC **4.4.3.3.1 / 8.1.5** (scope widening is a `supersedes` chain, original preserved, lineage walkable), CC **2.6.1.1 / 2.6.1.5** (relay discipline: preserve what the producer signed exactly; forward the original signature unchanged), CC **2.6.7** (±5 min clock skew; `cosigned_at`; cosignatures >5 min from `signed_at` MUST be rejected), CC **2.6.2** (datetime canonical form `YYYY-MM-DDTHH:MM:SS.sssZ`), CC **5.3.2.4.3** (local tier: signature MAY be absent; `tier = federation ⟹ hybrid present AND verified`), CC **2.6.1.3** (the signed-discriminator redaction shape is **ruled out**, CIRISConstitution#78), CC **4.4** two granters / cohabitation (`agent = node + brain`, two delegations, `node`-only keys carry only `infra:*`).
**Cross-refs:** CIRISPersist#649 (why tier and scope were once folded into one primitive), #643/#598 (what the signed mirror binds), #556 (every scrub verified over the same preimage), #589 (placement carried by the primitive), #750 (a bound member cannot be mutated after mint), #791 (a resolver over a gate-shaped verifier), #801 (the claim's instant crosses with the claim), #804 (local publication is not peer-metered). THREAT_MODEL.md AV-86 (the fabric signs an actor's claim).

---

## 0. Summary

**The governing requirement: original signatures are maintained; the fabric's key never overwrites an actor's key.** The constitution defines two operations, and keeping them separate meets that requirement with **no envelope-in-envelope wrapper and no preimage change**:

1. **Tier crossing** (`local → federation`, CC 5.3.2.4.2), `enter_mesh`, signs the **same bytes** the producer committed. It never changes `cohort_scope`. Because the bytes are unchanged, the actor's signature — if present — stays valid, and the node's participation is a **co-scrub** in `additional_scrubs` (verified over identical bytes at every peer, #556). The row is byte-identical to a born-federation row, which is what CC 5.3.2.4.2 demands.
2. **Scope widening** (CC 4.4.3.3.1 / 8.1.5), `widen_audience`, is a **`supersedes`** row authored and signed by the **actor**, referencing the original by `references_attestation_id`. The original row is never mutated; the lineage is walkable. This is the only place a new signature over new bytes is ever needed.
3. **`created` = `asserted_at`**, a bound top-level envelope member (#598). **`modified` = `cosigned_at`** on each `ScrubSig`, the CC 2.6.7 name — signature metadata outside the signed envelope (as the scrub set is), so it costs no preimage. The ±5-minute rule is CC 2.6.7's own skew bound, `CLOCK_SKEW_TOLERANCE` in persist.

**Envelope-in-envelope is ruled out on two independent grounds:** CC 5.3.2.4.2 forbids any was-promoted marker in the signed bytes (a nested original *is* one), and CC 2.6.1.3 rules out the signed-discriminator shape (#78: "a signed marker proves an authorized party changed the bytes — it does not prove that *only* the marked parts changed").

---

## 1. Why this exists — the defect class

### 1.1 One signature slot, and what overwriting it costs

`Attestation` carries one base signature: `scrub_signature_classical` / `scrub_signature_pqc` + `scrub_key_id`. There is no separate actor-signature field; `attesting_key_id` is an *identifier*, not a signature. Co-signatures live in `additional_scrubs`.

A single "promote" primitive that flips the tier, changes `cohort_scope` inside the signed bytes, re-signs with the promoting node's key into `scrub_key_id`, and clears `additional_scrubs` makes the fabric the author of an actor's claim (THREAT_MODEL.md AV-86). Because the wire verifier resolves the base signature against `attesting_key_id`, never `scrub_key_id`, every peer also refuses the result whenever the attester is not the node. `promote_attestation` had that shape and is removed; `enter_mesh` and `widen_audience` replace it (§5).

### 1.2 Which rows carry an actor signature at local tier

Not all of them, and the distinction shapes everything below.

- **Producer-authority self-attestations** (the CC 5.3.2.2 deferral case) are written with the **empty-sentinel scrub** (`scrub_signature_classical = ""`). There is no actor signature yet; the crossing is the first signing.
- **Transit revocations** (`LocalTierDisposition::TransitRevocation`) **are** caller-signed at the local write (`LocalAttestationInput::scrub_signature_classical`, verified at that door). Re-signing them at promotion would destroy an actor's signature (W12).
- **Any path where an agent or human signs at local write** is the transit-revocation shape generalised.

### 1.3 Why tier and scope must not be one operation (#649)

`#643` bound seven typed columns into the signed row mirror. Changing one of them (`cohort_scope`) while re-signing the *pre*-promotion envelope leaves a mirror asserting the old scope beside a column saying otherwise, and every peer refuses it. Folding the re-stamp into one primitive makes tier flip, placement and re-sign atomic — correct only for an operation that changes scope. The constitution defines two operations, and only one of them changes bytes.

### 1.4 CC 2.6.2 instant form

CC 2.6.2 (normative) requires signed instants as `2026-09-02T10:00:00.123Z` — exactly three fractional digits, literal `Z` — and *"consumers MUST reject any other form when verifying a signature."* `chrono::to_rfc3339()` emits `+00:00` with microseconds. Persist mints `.sssZ` (§5.5).

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

Restated so it can be checked:

1. Human- and agent-signed rows that get promoted are **signed by the same key** that signed them — never by the fabric.
2. Two time fields: **`created`** (original creation, immutable) and **`modified`** (each later signature).
3. If promotion happens **more than 5 minutes** after creation and the actor is not present, the node does not sign in the actor's place; it **co-scrubs** — the original signature is kept and the row flows identically.
4. The 5-minute window asks: *is the original signer still reachable?* Inside it the actor can sign again; outside it the actor may be gone, so persist preserves what they signed and adds the node's signature alongside.

Requirement 4 is not itself constitutional, but it lands on CC 2.6.7: ±5 minutes is the constitutional skew bound, `cosigned_at` is the constitutional name for a cosignature instant, and *"cosignatures with `signed_at` farther than 5 minutes from the … published `signed_at` MUST be rejected"* is the constitutional precedent for a time-bounded co-signature window.

---

## 4. Validation against the constitution

### 4.1 Envelope-in-envelope — ruled out

**CC 5.3.2.4.2 (normative):** *"A promoted row is therefore byte-indistinguishable on the wire from one born federation-tier; there is no 'was-promoted' marker in the signed bytes."* A nested original envelope inside the signed bytes is precisely a was-promoted marker. Non-conformant.

**CC 2.6.1.3 (normative, CIRISConstitution#78):** the *signed-discriminator* shape — a signed marker saying "an authorized party changed this" — is ruled out as a dead end, with the reasoning kept in-clause: it proves an authorized party changed the bytes, not that *only* the marked parts changed. A wrapping signature over a nested original has the same property: the outer signer could alter anything outside the inner envelope and every reader reports the row as legitimately promoted.

**CC 2.6.1 (part_3:1267)** does use the phrase "inner envelope" — `envelope_hash = sha256(JCS(inner envelope))` for the org planes. That is a *hash basis* for a different plane, not a promotion wrapper, and should not be read as precedent.

**Verdict:** not built. What follows is what the constitution provides instead, and it is strictly better.

### 4.2 Tier promotion — same bytes, actor's signature preserved, node co-scrubs

CC 5.3.2.4.2: *"The signature MUST cover `JCS(contribution_envelope)` — the identical canonical bytes any natively-federation attestation signs … Promotion MUST canonicalize the exact member set the producer committed at local-write time."*

Consequences:

- Tier promotion **does not** change `cohort_scope`.
- Because the bytes do not change, an actor signature made at local write **remains valid** over the promoted row. There is nothing to re-stamp.
- The node's participation is a **co-scrub**: an entry in `additional_scrubs` over the same `JCS(envelope)`. Persist verifies every attestation co-scrub at ingest over the same preimage (`tier_ingest.rs`, #556: *"EVERY scrub, not just the first"*), and `ScrubSig`'s own doc states the rule: *"Every scrub on a record is over the **same** canonical bytes; the scrub set lives OUTSIDE the signed envelope."* Co-scrubbing is a first-class, verified mechanism, and the crossing never clears it.
- CC 2.6.1.5 step 5 — *"Store/forward object O AS RECEIVED … Forward original signature S unchanged"* — is satisfied by construction.

This is what "the co-scrub should include the original and flow just the same" means constitutionally: the original *is* the base scrub, the node's is an additional scrub, and both verify at every peer over identical bytes. There is no second mechanism.

### 4.3 Scope widening — `supersedes`, authored by the actor

CC 4.4.3.3.1: *"A Contribution's `cohort_scope` MAY be widened (promoted) by emitting a `supersedes` against the prior attestation … `differs_in: ["cohort_scope", …]` … This pattern is wire-format-clean: it re-uses the structural primitive `supersedes` rather than introducing a `promote` primitive. The chain is walkable via `references_attestation_id` so the promotion lineage is preserved."*

CC 8.1.5's worked example has the **same** `attesting_key_id` on original and promoted rows (`user-alice-2026`), a fresh `asserted_at`, and `new_cohort_scope`.

Consequences:

- The original row is **never mutated**. Its signature, its `asserted_at`, its scope all stand. This is the "maintain any original signatures" requirement, met by an existing structural primitive.
- The widening row is a **new claim by the actor**, signed by the actor's key. It is not a re-stamp of the old bytes; it is a new signature over a new row that *references* the old one.
- If the actor's signer is unavailable, the widening **waits**. A node cannot author a `supersedes` on an agent's behalf — the two-granters rule makes that a category error (§2; OQ-1).

### 4.4 `created` and `modified` — their constitutional names and homes

The constitution does not define `created` or `modified`. Its datetime vocabulary (CC 2.6.7) is `signed_at`, `asserted_at`, `valid_until`, `delegation_valid_from/until`, and `cosigned_at`.

| Requirement term | Constitutional member | Where it lives | Signed? |
|---|---|---|---|
| `created` | **`asserted_at`** | top-level envelope key | **yes** — bound by #598, checked by `check_instant_binding` |
| `modified` (base signer) | `scrub_timestamp` | signature metadata column | no — CC 5.3.2.4.2: substrate columns are never in canonical bytes |
| `modified` (each co-signer) | **`cosigned_at`** | field on `ScrubSig` | no — the scrub set lives outside the envelope by design |
| the widening's own instant | **`widened_at`** | signed member of the `supersedes` row (§5.2) | **yes** |

This is the load-bearing design point: **`modified` must not enter the signed envelope of the crossing row.** If it did, adding it at promotion would change the bytes, the actor's local-tier signature would stop verifying, and the co-scrub path (§4.2) would become impossible — exactly the #649 shape. Putting it on the `ScrubSig` gives each signer its own instant, outside the preimage, which is what CC 2.6.7's `cosigned_at` is.

`asserted_at` is bound as a top-level envelope key, not inside the seven-member `row` mirror; the mirror and the top-level instants are two different binding sites.

### 4.5 The ±5-minute rule — CC 2.6.7

`CLOCK_SKEW_TOLERANCE = Duration::minutes(5)` (`operational.rs`), cited to §0.7 / CC 2.6.7. The rule:

> At tier promotion, if `now - asserted_at ≤ CLOCK_SKEW_TOLERANCE` **and** the actor's signer is reachable, the actor signs (or has already signed — same bytes). Otherwise the node **co-scrubs** the actor's existing signature. A row with **no** actor signature and no reachable actor signer **stays local** and is reported `AwaitingActor` (fail-secure; there is no delegated alternative, OQ-1).

The input to the rule, `asserted_at`, is **signed** (§4.4), so it cannot be backdated to force the co-scrub path or forward-dated to force the re-stamp path. This matters: if the rule keyed on an unsigned column, the party choosing which key signs would be choosing by editing a column nothing binds.

### 4.6 What the crossing does not change

- No new primitive; CC 1.7's 1+4 surface is untouched. The one signed member the design adds is `widened_at`, on the widening row only (§5.2).
- `check_row_column_binding` and the seven-member mirror are untouched.
- `tier = federation ⟹ hybrid present AND verified` (CC 5.3.2.4.3) holds — a co-scrubbed row has at least one verified hybrid scrub, and #556 verifies all of them.
- Deferred-signature local rows (CC 5.3.2.2) remain allowed. The design does not force actor-signing at local write; it makes actor signatures *survive* when present.

---

## 5. Design — the split

### 5.1 `enter_mesh` — tier-only, same bytes

```rust
/// CC 5.3.2.4.2 — flip `local → federation` over the SAME bytes.
/// Never changes `cohort_scope`. Never replaces an existing scrub.
async fn enter_mesh(
    &self,
    attestation_id: &str,
    ci: &ContextualIntegrity,         // §5.6 — all nine axes, no defaults
    custody: &TierPromotionCustody,
) -> Result<MeshCrossingOutcome, Error>;

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
| row is already `federation` | `Ok(MeshCrossingOutcome::AlreadyInMesh)` (idempotent, CC 5.3.2.4.2) |
| `NodeCoScrub` and base scrub is the empty sentinel | `Error::NoActorSignature` — the fabric cannot be the only signer of an actor's claim |
| `ActorSigned` and `reseal.scrub_key_id != row.attesting_key_id` | `Error::CustodyIsNotTheActor` |
| the reseal's bytes ≠ `JCS(stored envelope)` | `Error::PromotionMovedThePreimage` — the #649 class, refused at the primitive |
| `now - asserted_at > CLOCK_SKEW_TOLERANCE` and variant is `ActorSigned` | **admitted** — the window governs *which path the engine chooses*, not what the primitive accepts; an actor who is present after 5 minutes may still sign |

`additional_scrubs` is **never cleared** by tier promotion. Local-tier co-scrubs stored without verification (#557/#556) are verified at *this* door before the flip, and refused if unverifiable, exactly as ingest does.

### 5.2 `widen_audience` — scope widening via `supersedes`

```rust
/// CC 4.4.3.3.1 — widen `cohort_scope` by a `supersedes` row the ACTOR signs.
/// The prior row is untouched.
async fn widen_audience(
    &self,
    prior_attestation_id: &str,
    ci: &ContextualIntegrity,         // §5.6 — recipient_see is the NEW audience
    signed: SignedAttestation,   // attestation_type = supersedes,
                                 // references_attestation_id = prior,
                                 // differs_in = ["cohort_scope"],
                                 // attesting_key_id = prior.attesting_key_id
) -> Result<MeshCrossingOutcome, Error>;
```

These are the `FederationDirectory` primitives. `Engine::enter_mesh` / `Engine::widen_audience` wrap them, taking the actor's `LocalSigner` when the caller holds it and choosing the custody per §5.4.

Refused unless `signed.attesting_key_id == prior.attesting_key_id` (no delegated signer; OQ-1), unless `new_cohort_scope` is strictly wider (`AudienceNotWider`), and unless `references_attestation_id` resolves. The `content_sha256` / `evidence_refs` of the prior are reused (CC 8.1.5: "no body re-upload").

- **The widening carries the claim's `asserted_at` verbatim; its own instant is the signed member `widened_at`** (#801). A local row is `self`-scoped and `self` never becomes discoverable, so the widening is often the only row a peer sees; if it carried a fresh `asserted_at`, the claim's instant would be unrecoverable off-node, and `differs_in: ["cohort_scope"]` would be false. `widened_at` is in the agreed envelope vocabulary (`ENVELOPE_VOCABULARY_SHA256`), and `assemble` reads `scrub_timestamp` from it. The placement instant has to be a *signed member* rather than a column, or preserving `asserted_at` would erase it.
- `widen_audience` is a default trait method over `get_attestation` + `put_attestation` (no per-backend body). It reports `AlreadyWidened` when the put door deduplicates the `supersedes` (CEG §6.1); to widen a claim twice, widen the LATEST row in its chain.
- A widening into a cohort plane goes through the put door's AV-45 write-scope gate, which proves membership against the cohort the row NAMES, so `Audience` carries the cohort id (`Audience::Family { family_key_id }`, `Audience::Community { community_key_id }`).

Readers that resolve "the current scope of claim X" walk the `supersedes` chain (§7).

### 5.3 `ScrubSig.cosigned_at`

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

Serde-default: a `ScrubSig` without the field round-trips unchanged. `KeyRecord::additional_scrubs` shares the type and inherits the field harmlessly.

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
      return MeshCrossingOutcome::AwaitingActor { attestation_id, age }
```

The consent sweep runs this motion in two passes over one predicate: local rows (enter, then widen) and `list_widening_candidates` (undiscoverable federation rows with no widening yet — rows sealed before the grant). `ConsentSweepReport` counts `promoted`, `widened`, `awaiting_actor`, `awaiting_roster` and `skipped`. The sweep widens to `family`/`community` only when the grant names the cohort (a cohort-target alias on its envelope); otherwise it counts the row `skipped` with a warning.

`Engine::register_self` emits the identity's `delegates_to` federation-tier directly, signed by `SelfAtLoginInput::identity_signer` (or by this node when the identity IS its composed signer); otherwise the delegation is staged local and waits. It is never widened: a `supersedes` is not a `delegates_to` to a type-keyed reader.

`age` is reported so the CC 2.6.7 window is *observable*. `actor_signer_reachable` is **not an oracle**: it means "the caller handed over the actor's signer". The layer holding the key decides; persist never guesses at presence.

**Sign-at-write, per key class (OQ-2).** The co-scrub path — the only thing in this FSD that *preserves* anything — is closed to a row with no signature (W4). So a deferred row's only road to the wire is the actor present at the crossing; otherwise it parks. Key rotation makes "actor gone" routine, not exotic: a row deferred under AgentID-v1 and promoted after rotation to v2 has no signer that can ever sign it as v1 (W5), whereas signed at write, v1's signature over the identical bytes stands and the node co-scrubs. And §4.5's guarantee that `asserted_at` is signed holds *exactly* for rows signed at write — a deferred row's `asserted_at` is an unsigned stamped column until the very promotion the rule governs. Therefore:

| key class | signs at | rationale |
|---|---|---|
| **software-held actor keys** (AgentID, in-process via keyring; cohabitation) | **local write** | prompt-free hybrid sign on a path that already canonicalises and fsyncs; measure before deferring (CC 5.3.2.2's cardinality win is real but must be shown, and if it matters it is self-witnessed telemetry, never a claim) |
| **ceremony-bound keys** (FedID on hardware) | **the crossing** | a signature that costs a presence ceremony cannot be paid per local write; for chat the crossing *is* the send, so the ceremony coincides with intent. A human row never signed, whose human is absent, correctly stays local — it is a draft nobody committed. Deferral-as-consent, not deferral-as-optimisation |

CIRISEdge follows the same rule: every edge producer signs at write; `share*` takes the **actor's** signer — present → `ActorSigned`; absent + signed → `NodeCoScrub`; absent + unsigned → `Shared::AwaitingActor`.

### 5.6 The DX — two verbs, nine axes, and the consequence in the name

**Federation-tier crossing is the moment every contextual-integrity axis must be answered, because it is the moment edge starts replicating the row.** The constitution's CI vocabulary is closed and ratified (CC 4.5.1.1): `ci_axis ∈ {sender, data_subject, recipient_see, recipient_revoke, recipient_receive, information_type, transmission_principle, temporal_lifecycle, content}`. The namespace manifest records which wire field answers which axis, per family (`families.*.round2.ci_axes`). A crossing that takes only an `attestation_id` and a `cohort_scope` answers one axis by name and is silent about the other eight questions it commits the row to.

**Naming.** Edge owns `share_clear_privately` / `share_encrypted_privately` / `share_publicly` — a *sharing* vocabulary, consumer-facing, keyed on how bytes travel. Persist's two verbs must be distinct from those, clearer than `promote` (which names neither operation), and must carry their consequence:

| Verb | Constitutional operation | What it changes | What edge sees afterwards |
|---|---|---|---|
| **`enter_mesh`** | tier crossing, CC 5.3.2.4.2 | `tier: local → federation`. Nothing in the signed bytes. | the row appears on the wire index and replicates to whoever `cohort_scope` already admits |
| **`widen_audience`** | scope widening, CC 4.4.3.3.1 | authors a new `supersedes` row with a wider `cohort_scope`; the prior row is untouched | a **new** row appears, addressed to the wider audience; the old one stays exactly where it was |

There is no `promote_attestation`; the two verbs replace it.

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

`temporal_lifecycle` and `content` are cross-checked against the **claim** — the row itself for `enter_mesh`, the PRIOR for `widen_audience` — because a widening describes the claim being widened, whose instants and content hash the actor already signed; the new row's own do not exist until it is stamped and signed. The `transmission_principle` grant must name the audience at a widening; at `enter_mesh` it must cover the dimension.

**Return shape says what edge will do:**

```rust
pub struct MeshCrossing {
    pub attestation_id: String,        // the row now on the wire (new id for widen_audience)
    pub audience: Audience,            // recipient_see, as applied
    pub custody: Custody,              // ActorSigned | ActorSignedNodeCoScrubbed
    pub age_at_crossing: Duration,     // now − asserted_at (the CC 2.6.7 window, observable)
    pub replicates: Replicates,        // { kinds, discoverable: bool }
}

/// Typed, so "it did not cross" is something a caller reads rather than
/// infers from silence.
pub enum MeshCrossingOutcome { Crossed(MeshCrossing), AlreadyInMesh { .. }, AlreadyWidened { .. }, AwaitingActor { attestation_id, age } }
```

`replicates` states what persist can state and no more. **`self` and `family` rows DO replicate** — to the owner's own node set and to the family's nodes respectively, by consent fan-out over resolved recipients rather than by `holds_bytes` discovery. CC 5.2 makes them *not discoverable*, not un-replicated. So persist reports `discoverable: false` for those scopes and `true` otherwise; **where the bytes go** (`routes_to`) is CIRISEdge's to state, on its `Crossing`.

**One type, persist's.** `ContextualIntegrity` (nine axes, required, refused by axis name) is the one CI type; CIRISEdge re-exports `ContextualIntegrity` + `MeshCrossing` and keeps `With` (which maps onto `Audience`) and `Shared`.

**Why this is not ceremony.** The nine-axis struct is the manifest's own rubric turned into a call signature. Persist derives `ci_axis` per field at manifest generation and gates axis fusion (CC 4.5.1.1). `enter_mesh` asks the *caller* to answer the axes at the one moment they become irrevocable, because CIRISEdge picks the row up on the next round.

### 5.5 Timestamp conformance (CC 2.6.2)

`stamp_signed_instants`, `stamp_and_canonicalize` and `cosigned_at` write `to_rfc3339_opts(SecondsFormat::Millis, true)` → `.sssZ`, truncated at millisecond resolution (`SIGNED_INSTANT_RESOLUTION_NANOS`). The ingest CHECK stays at microseconds (`CONSENT_INSTANT_RESOLUTION_NANOS`), and `check_instant_binding` parses tolerantly: rows signed with the older `+00:00` form cannot be re-rendered (every preimage field must be recoverable from the stored row), so refusing them would refuse valid signatures.

**Limit:** without an epoch marker on the row, persist cannot refuse a `+00:00` form on new rows only; what is enforced is that every instant persist mints renders `.sssZ`.

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
| W10 | every instant persist mints renders as `.sssZ` (§5.5) | keep `to_rfc3339()` |
| W11 | the age reported equals `now - asserted_at` and `asserted_at` is the SIGNED value | compute age from `scrub_timestamp` |
| W12 | a transit revocation's caller signature survives promotion (rides W2's mechanism: no custody replaces the base scrub) | replace the base scrub on promotion |
| W13 | a `ContextualIntegrity` whose `sender ≠ attesting_key_id`, or whose `data_subject ≠ subject_key_ids`, is refused by name of the axis | drop the per-axis cross-check |
| W14 | `replicates.discoverable` is `false` for every `self`/`family` crossing and `true` otherwise | report `discoverable: true` unconditionally |
| W15 | a widening asserts the CLAIM's `asserted_at` verbatim, and a peer sees it (#801) | mint a fresh `asserted_at` on the widening |
| W16 | the widening's own instant is the signed `widened_at`, and `scrub_timestamp` reads from it (#801) | stamp `scrub_timestamp` from the wall clock |

All on both backends. The postgres leg must be confirmed **executing** (timing), not skipping on an unset DSN.

---

## 7. Projections and readers

- **"Current scope of claim X"** walks `supersedes`: the newest non-tombstoned `supersedes` in the chain wins. This is the same fold shape as `precedence::retired_ids`; there is no second one.
- **`trace_events` projection** — unaffected; it carries the pre-transform form.
- **Wire index** — a `supersedes` row is a new row and indexes normally; tier promotion does not change bytes, so `signed_wire_index` needs no re-indexing on promote.
- **Not implemented:** a `hard_case:promotion_awaiting_actor` emission for a deferred row whose actor stays unreachable past the window (the sibling of CC 5.3.2.2's `consent_revocation_promotion_overdue`). Waiting rows are visible as `awaiting_actor` in `ConsentSweepReport`.

---

## 8. Compatibility

1. **There is no `promote_attestation`.** A caller that flips tier uses `enter_mesh`; a caller that widens uses `widen_audience`. The two ship together: a tier-only crossing with no widening path would strand every caller that needs to widen.
2. **Timestamp form.** New rows sign `.sssZ` instants. Stored rows keep verifying (tolerant parse). An external party byte-comparing persist's `asserted_at` against the older `+00:00` form sees a difference — which CC 2.6.2 requires it to refuse anyway.

---

## 9. Decisions and open questions

**OQ-1 — Delegated widening: no.** Subsidiarity (CC part 3 §308) and `check_node_agency_admission` make it cryptographic, not policy: a `node`-only key cannot carry agency, and widening an agent's claim is agency. The widening waits for the actor (CIRISEdge `docs/FSD_REPLICATION_DX.md` §6).

**OQ-2 — Sign at local write: yes for software-held actor keys, at the crossing for ceremony-bound keys** — see §5.4's table. An unsigned row has nothing to co-scrub (W4), so a human-authored row whose FedID lives elsewhere waits as a typed `AwaitingActor`; the co-scrub path exists only for rows signed at write.

**OQ-3 — `cosigned_at` on the KeyRecord co-scrub plane (open).** The field is shared by type. The accord co-scrub ceremony may stamp it; nothing requires it to. It is optional, and the key-plane quorum verifier ignores it.

**OQ-4 — Rows promoted by the fabric key (limit).** Rows promoted under the removed primitive carry the node's signature over bytes the node minted. They are valid signatures, not forgeries, and persist does not rewrite them (that would be the #649 shape). Federation rows with `scrub_key_id != attesting_key_id` identify them.

---

## 10. Sources

Constitutional claims are read from `CIRISConstitution/constitution/part_{2,3,4,5,8}*.md`; persist claims from `src/federation/crossing.rs` and the code it cites.

---

## 11. Design notes

1. **Naming.** The verbs are `enter_mesh` (clearer next to the `federation` tier than `enter_federation`) and `widen_audience`. Types: `MeshCrossing`, `MeshCrossingOutcome` (`Crossed | AlreadyInMesh | AlreadyWidened | AwaitingActor`), `TierPromotionCustody`, `Custody`, `Replicates`.

2. **`(federation, self)` is admitted at the crossing.** The placement arm of `check_promotion_admission` does not refuse `self`; the "not strictly wider" refusal lives at `widen_audience` (`AudienceNotWider`).

3. **`register_hybrid_key_as`** in test support: a community member must be a human or steward-bound, so the B9 witness registers its producer as a USER before proving membership and then STANDING.

4. **Local publication is not peer-metered (#804).** `widen_audience` writes through `put_attestation`, which is where the AV-76 per-peer write quota lives. The quota runs at tier 0, before any signature check, so `attesting_key_id` there is a claim, and a quota keyed on it alone would meter the node's own owner as if it were a hostile remote peer. The missing axis is ORIGIN, which is not recoverable from the row, so it is a parameter: `put_attestation_with_origin` is the one required method, with `put_attestation` (wire) and `put_attestation_authored` (this node signed it — node ceiling only, no peer bucket) as defaults over it. `put_attestation_synced(row, authenticated_peer)` serves bulk cohort sync, which is legitimately bursty and carries rows authored by many parties; its privilege is bounded by a fact persist checks itself — the caller vouches only for which identity its transport authenticated, cohort membership comes from persist's own rosters, and an authenticated stranger falls back to ordinary metering.

   **Rule for crossing verbs:** a crossing that publishes through the ingest door inherits every control written for ingest, including resource controls that are not admission gates. Check each one against the axis the crossing changes.
