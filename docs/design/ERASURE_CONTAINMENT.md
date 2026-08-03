# Erasability is decided at mint, never at erasure

**Status:** the containment ruling CIRISVerify#241 and CIRISConstitution#78
both left to whoever owns the objects, plus the evidence for it.
**Answers:** CIRISPersist#573.
**Prerequisite read:** `docs/design/PAYLOAD_ENUMERATION.md`, especially §7.

Claims are marked **[TESTED]** with the test or command that produced them, or
**[BELIEVED]** with the basis. A heading carries no warrant.

---

## 0. The question, and the answer

CC 2.6 (rc3) ruled the signed-discriminator shape out, bound three substrate
constraints normatively, and kept one option open:

> **(d) the third option stays open** — a redacted row MAY simply be a
> *different object carrying a different kind*, relocating the work entirely

CIRISVerify#241 built the cryptography for it — `ciris_verify_core::redactable`,
SD-JWT/mDoc salted digests committing to member count and index ordering — and
deliberately did not answer (d), *"to keep the wire-break scope a separate
decision from the cryptography."* That decision is ours.

**The answer is neither of (d)'s two branches, because both presuppose a
redacted object exists. Persist should never produce one.**

What replaces it is a **mint-time distinction between two shapes**:

| | **SEALED** | **ERASABLE** |
|---|---|---|
| payload lives | inside the signed envelope | beside it, as salted disclosures |
| what the envelope carries | the values | per-member digests + the root |
| erasure | **impossible** | drop a disclosure |
| what erasure changes | `original_content_hash`, the hybrid signature, `persist_row_hash` | **nothing** |
| declared by | absence of the commitment | presence of the commitment — and the commitment is inside the signature |

The distinction is made **before** any erasure happens and does not change when
one does. An erased object keeps the kind it was minted with. `src/federation/erasable.rs`
is the shape; `ciris_verify_core::redactable` is the cryptography under it.

Today **[TESTED]** all 88 payload carriers are sealed — the enumeration in
`PAYLOAD_ENUMERATION.md` §6 reproduces exactly (88 carriers, 38 hashed), so
nothing has moved and nothing is erasable yet.

---

## 1. The evidence that decided it

### 1.1 "Which objects actually need erasure?" — the set is not bounded

CIRISVerify#241 asked for this to be the deciding question, reasoning that
*"a bounded set makes the distinct-kind answer obviously right."*

**[TESTED]** — the set is not bounded. Of the 38 payload carriers on hashed
rows, most take content a remote party influences: `attestation_envelope` on
every attestation of every dimension; `registration_envelope` and
`attestation_evidence` on the key plane; `policy_blob` on communities and peer
metadata; the `payload` columns on moderation / slashing / votes /
contributions / reconsideration; the `signed_envelope` columns on the org and
partner planes. There is no short list.

**This does not make distinct-kind wrong. It makes same-kind worse**, and that
is the load-bearing step:

> "Every object is redactable" is a **universal, fail-open partiality
> property**. Every consumer of every object would then have to remember to ask
> whether members were withheld, and the one that forgets silently accepts a
> partial object. Under the mint-time distinction nobody has to remember
> anything: an object either carries a commitment or it does not, and that
> presence is inside the signature.

`PAYLOAD_ENUMERATION.md` §4 already uses fail direction to keep #564, #573 and
#476 apart — #564 fails secure, #573 and #476 fail open. The same axis decides
this. A capability that makes *every* object partial-able is the wrong fail
direction on the plane whose failure mode is silent retention and silent
partiality.

### 1.2 What it costs, and where #573's premise does not hold

#573 argues:

> The mesh cannot know in advance which object will need nuking, so erasure has
> to be addressable the way objects are addressed.

The first clause is true. The conclusion does not follow, and the gap matters:

- **Erasure IS addressable by object here.** Any erasable object can be erased
  by name, at any time, with no foresight about *which* one.
- **Erasability is not retrofittable.** A payload already inside a signature
  cannot leave it. That is arithmetic. So the mesh does not have to predict
  which object will need erasing — but it does have to decide, per object,
  whether the payload goes inside the signature or beside it, and that decision
  is permanent.

The cost is real and should not be softened: an object minted sealed today can
never be erased, and every object is minted sealed today.

### 1.3 What a sealed erasure actually looks like to a peer — worse than §7.3 said

`PAYLOAD_ENUMERATION.md` §7.3 and #573 both expected the operator-facing
failure to be the ambiguous `original_content_hash mismatch` — *"envelope
canonicalizes to X, row declares Y"* — with the complaint that a reader cannot
tell redaction from tampering.

**[TESTED]** — `federation::erasable::ingest_gate_proof::{memory,sqlite}`, the
sealed control. The hybrid signature is verified **before** the hash
cross-check (`verify_envelope_hybrid_signature` runs `verify_hybrid`, then
compares the declared hash). So a sealed row that an authority lawfully
redacted never reaches the ambiguous message. It is refused as:

```
Classical signature verification failed: Ed25519 (verify_hybrid_crypto)
```

To an operator that is not ambiguous — it reads as a **forgery attempt against
the erasing authority's own key**. The problem CIRISVerify#241 describes is
therefore slightly understated in both issues, and it strengthens rather than
weakens the ruling.

---

## 2. The shape

An erasable envelope carries one additional member:

```json
{ "...header...":  "...",
  "_ciris_sd": {
    "scheme":  "ciris.redactable.v1",
    "root":    "<64 hex>",
    "digests": ["<64 hex>", "..."]
  }}
```

- `digests[i] = sha256(MEMBER_DOMAIN ‖ u32be(i) ‖ u32be(|salt|) ‖ salt ‖ bytes)`
  with a fresh 128-bit salt per member.
- `root = sha256(ROOT_DOMAIN ‖ u32be(count) ‖ digests…)` — the count is inside
  the root, so **redaction by omission is foreclosed**; the index is inside each
  digest, so members cannot be reordered or swapped.
- `root` and `digests` are inside `canonical(envelope)`, therefore inside
  `original_content_hash` and inside the hybrid signature. **A tamperer cannot
  add the commitment to a sealed object, remove it from an erasable one, or
  alter a digest.**
- The **disclosures** — `(index, salt, bytes)` — ride *beside* the envelope and
  are members of nothing hashed. **Erasure is dropping one.**

`digests` is carried in full rather than just `root` so a reader holding only
the envelope can see how many members existed and, against whatever disclosures
survive, exactly which are gone. #573's operator requirement is *which*, not
merely *that*.

---

## 3. What this does NOT require

### 3.1 No CIRISVerify change on the envelope plane

**[TESTED]** — `ingest_gate_proof` mints an erasable attestation, hybrid-signs
it with real deterministic keys, stores it through `put_attestation`, erases
**every** member, and then re-runs the real
`tier_ingest::verify_federation_tier_ingest` over the unchanged row. It is
admitted. On memory and sqlite it is then handed to a **second, independent
store that has never seen it** — the exact plane §7.3 says a redaction dies on
— and is admitted *and stored*.

The redacted-vs-tampered ambiguity CIRISVerify#241 exists to resolve **does not
arise**, because no signed bytes are ever rewritten. `redactable` is still the
primitive; it is used *above* the envelope by whoever reads the payload, never
*inside* the envelope verifier.

### 3.2 No second `consent_role`-shaped exclusion from `compute_persist_row_hash`

`PAYLOAD_ENUMERATION.md` §7.5 item 1 and CIRISVerify#241 both expected a
row-level marker outside the row hash, on the `consent_role` precedent (#365).

**[TESTED]** — none is needed. `ingest_gate_proof` asserts
`compute_persist_row_hash` is byte-identical before and after total erasure,
because the disclosures are not row members. The two-field exclusion list stays
at two.

### 3.3 No wire break — with one measured exception

**[TESTED]** — `put_attestation` runs a per-dimension JSON Schema check on all
three backends (`schema_resolver::validate_envelope_against_schema`, reached
from `memory.rs`, `sqlite.rs` and `postgres.rs`). `_ciris_sd` is an *additional
property*, so:

- a dimension with an **open** schema carries an erasable envelope today, with
  no schema change at all;
- a dimension whose schema sets `additionalProperties: false` **cannot** carry
  one until that schema is revised.

Both directions are asserted. This is the whole of the wire break: the
canonicalization and signature planes need nothing, and per-dimension closed
schemas are a per-dimension revision rather than a mesh flag day.

---

## 4. The tension inside #573 that salting forces

#573 asks for two properties. **They are not jointly satisfiable in general**,
and the reason is CC's own.

| | needs | why |
|---|---|---|
| **payload-only erasure** | a **salted** digest | an unsalted digest of a low-entropy member — a boolean, an enum, a date — is recoverable by dictionary, and erased content is exactly what an adversary searches for (CC 2.6, CIRISVerify#241) |
| **recognition without retention** | an **unsalted** hash | another node must be able to recompute it over the same bytes to decline them sight-unseen |

Publishing the unsalted hash re-opens the dictionary attack the salt exists to
close. So recognition is available only for content with enough entropy that
publishing its hash does not disclose it — and **persist cannot measure that**.

The resolution, in `RecognitionPolicy`:

- The **salted digest is always present**. It is the tombstone, it survives in
  the signed envelope forever, and it reveals nothing.
- An **unsalted recognition hash is opt-in per erasure**, never a default, and
  is an explicit *operator assertion* of high entropy.
- Persist enforces the one thing it can check — a length floor — and says
  plainly that a floor is a minimum, not a measurement. The v23.1.0 custody
  note's declared-depth discipline: never let the declared strength exceed the
  actual provenance.

**[TESTED]** — withheld is the default; below-floor content is refused; the
published hash is reproducible across calls and domain-separated from a member
commitment.

---

## 5. What is left

Named as asks rather than half-built, per the sequencing lesson this arc was
opened to avoid.

### 5.1 CIRISPersist — the disclosure store and `erase_object` (needs a migration)

Nothing stores disclosures today, so nothing can yet be erased. That needs a
table (`V121` is free) plus `put_disclosures` / `list_disclosures` /
`erase_disclosures` on all three backends, and `erase_object(target, authority,
reason) -> ErasureSummary` over them, with #573's five requirements — atomic,
tombstoning, `hard_case:*`-emitting, idempotent, authority-carrying.

Most of that machinery already exists and should be reused rather than
re-invented:

- `ErasureSummary` and the single-transaction / idempotent /
  audit-inside-the-transaction discipline from
  `delete_traces_for_agent_id_hash`;
- `hard_case::kind::ADMIN_ACTION` + `check_admin_action_attribution` (#570 ask
  3) for the attributed record — an erasure is an act, and the required
  `{delegation_id, reason}` shape is already gated;
- `admission::DELEGATION_SCOPE_SLASH` (#570 ask 2) for the authority, walked
  under `MODERATION_DUTY`, which is what `quarantine:` already gates on.

**The blocking sub-question, and why the table is not in this cut:** *does a
disclosure set replicate, and under which consent edge?* An erasable object's
envelope replicates today, unchanged. Its disclosures do not, because there is
no plane for them. That is a coherent degraded state and it fails in the right
direction — an unreplicated disclosure set is indistinguishable from a
fully-erased one, so the failure is *content unavailable*, never *content
leaked* and never *object rejected*. But committing a schema before answering
it would bake the wrong shape. It should be answered first.

### 5.2 CIRISVerify — the news is that nothing is required (#241)

CIRISVerify#241 is holding implementation pending exactly this ruling. What it
should hear:

1. **Nothing is required on the envelope plane.** Under the mint-time
   distinction no signed bytes are ever rewritten, so the redacted-vs-tampered
   discriminator #241 was opened for does not need to exist. `redactable`
   already shipped the part that was needed.
2. **The bounded-set heuristic did not survive contact** (§1.1), but the
   conclusion it was reaching for did, by a different route. Worth recording so
   the next reader inherits the corrected reasoning and not just the verdict.
3. **The signature is verified before the hash cross-check** (§1.3), so #241's
   description of the operator experience is understated. If verify ever adds
   an erasure-aware message, that ordering is where it has to land.
4. *Optional, not asked for:* a shared helper answering "is this envelope
   sealed or erasable, and which members are gone" would keep every
   verify-running peer reporting the same thing. Persist's `read_commitment` /
   `erased_indices` is that shape today, on persist's side of the fence.

### 5.3 CIRISConstitution — two refinements (#78)

1. **Constraint (d) as phrased presupposes a redacted object.** Both branches —
   same kind with redacted members, or a distinct redacted kind — describe an
   object whose bytes were rewritten. Persist's answer is that the object should
   not exist, and that the distinction belongs at **mint** (sealed vs erasable)
   rather than at **redaction**. Worth recording in-clause, because the phrasing
   is what a next drafter will inherit.
2. **CC 6.1.2's zero-descent carve-out is needed for *sealed* objects only.**
   #573 asked for a class where forced descent goes to zero because *"you cannot
   keep a blur of CSAM."* For an **erasable** object the carve-out is
   unnecessary: what survives is a salted digest, which is not a blur of the
   content and reveals nothing about it. For a **sealed** object the carve-out is
   still needed and is now the *only* remedy, because in-place erasure is
   arithmetically unavailable.
3. **The recognition-hash trade-off (§4) is above persist.** Whether an
   operator may publish an unsalted hash of erased illegal material — and
   whether doing so is itself a disclosure — is a ruling persist should
   implement, not author. The mechanism is built and defaults to withheld;
   the policy is not ours.

---

## 6. What this document does not establish

- **The 50 non-federation carriers are still unread** — inherited from
  `PAYLOAD_ENUMERATION.md` §5 and not closed here.
- **Whether disclosures should replicate, and under which consent edge**, is
  the open question in §5.1, not a gap in the ruling.
- **Only `put_attestation`'s gates were exercised.** The other write doors
  (`put_public_key`, `put_community`, …) run their own admission chains; an
  erasable envelope has not been put through them. The per-dimension schema
  gate (§3.3) is the one that generalizes structurally, but that is a belief,
  not a test. **[BELIEVED — basis: the schema check is invoked from the
  attestation write path on all three backends; the other doors were not
  read.]**
- **`federation_group_versions.snapshot` is unaffected but unaddressed.**
  `PAYLOAD_ENUMERATION.md` §1.2a's finding stands: a payload erased from a live
  row survives in every prior version's snapshot. An *erasable* payload never
  enters a snapshot in the first place (only its digests do), so the mint-time
  distinction happens to close this too — but that was not tested, and a
  snapshot of an erasable row was not built. **[BELIEVED — basis: `snapshot`
  holds the row's JSON, and an erasable row's JSON contains digests rather than
  values.]**
- **No timing or storage-size analysis.** A commitment adds 32 bytes per member
  to the envelope plus a salt per member beside it; whether that matters for
  any real dimension was not measured.
