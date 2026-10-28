# The minter is named, not inferred (CIRISPersist#876)

Status: normative for the community-DEK plane. Refines
`FSD/BLOB_REPLICATION.md` §11 (per-minter epochs). Tracking: CIRISPersist#876.

## 1. Author and minter are two different questions

`BLOB_REPLICATION.md` §11 keys community-DEK state, retention and grants by
`(community_key_id, minter_key_id, epoch)`. This FSD defines who the minter
is.

The **author** is the attester of the row the blob is a projection of. The
**minter** is the occurrence whose cascade minted the epoch and holds the
DEK. They coincide exactly when a node authors its own content. A chat row
is authored by a **person** (consent and authorship are by humans) and
sealed by their **node**: the seal path passes the signing key into
`resolve_minter`, so the DEK rows and the `key_grant` set are keyed by the
node. `authorize_viewer_by_tier` reads
`community_dek_blob_epoch(sha) -> (community, minter, epoch)` and then
`community_dek_has_member_grant(community, minter, epoch, viewer)`. If the
adopt keyed the binding by the person, the tuple would miss on the minter
member alone, and every cross-node community body would read `NotGranted`
with the viewer and its wrap both correct. So `BlobProvenance` names the
minter, and the adopt path takes it from §2, never from `author_key_id`.

**The class.** One key or gate answering "person or node?" from two axes
appears at write admission (CIRISPersist#765: the roster holds persons, the
writer is the node), at the audience plane (#873: `audience_memberships`
must ask the roster about the person, not the instrument), and at the DEK
plane (this FSD). §5's from-disk gate (I130) keeps the DEK-plane answer in
one function.

## 2. The rule (stated once)

**The minter of `(community, epoch)` is the occurrence whose cascade minted
it, and persist resolves it one way everywhere:**

1. the **explicitly named** `minter_key_id`, when the producer supplies one;
2. else the minter of the **one** admitted `key_grant` set that granted
   THIS node a wrap at that `(community, epoch)` — signed by the minter,
   already verified, so the two halves agree by construction;
3. else `author_key_id` — correct wherever author == sealer. A binding
   this arm gets wrong is repaired by `rebind_stranded_blob_epochs` when
   the naming set is admitted (§3, I129).

Ambiguity is not guessed: two admitted sets from different minters at one
`(community, epoch)` means only (1) can answer, and (3) is used if nobody
named it. That is exactly the state #848 made the key three-part for.

The bytes cannot arbitrate: `AtRestEnvelope` is `magic ‖ nonce ‖
ciphertext`, carrying no key id and no DEK fingerprint. Resolution is from
declaration or from verified state; there is no third source.

## 3. Surface

| symbol | meaning |
|---|---|
| `BlobProvenance.minter_key_id: Option<String>` | The key whose cascade minted the epoch — the key that signed the `key_grant` set. `author_key_id` is the row's attester |
| FFI provenance wire | optional `minter_key_id` member (`#[serde(default)]`) |
| `federation::epoch_minter::resolve(...)` | The ONE answer to §2, used by the adopt path, the repair sweep and the from-disk gate |
| `FederationDirectory::community_dek_minters_granting(community, epoch, viewer)` | The minters of every admitted set that granted `viewer` a wrap at `(community, epoch)`, sorted, deduped. The derivation input, on both backends |
| `rebind_stranded_blob_epochs(community, minter, epoch)` | On admitting a `key_grant` set, rebind every `federation_community_blob_epoch` row at that `(community, epoch)` whose recorded minter holds no DEK state and no grants — the bytes-before-key ordering (§3 of BLOB_REPLICATION) |
| `BlobProvenance::from_attestation(row, sha256, epoch, minter)` | PyO3 `blob_provenance_from_attestation_json`. The relation `BLOB_REPLICATION.md` §5 states in prose — provenance lives on the referencing attestation — as a constructor (the per-fact authority is the table below); refuses a row that neither cites the bytes in `evidence_refs[]` nor points at them. `epoch` / `minter_key_id` are arguments because they are key-plane facts carried by the `key_grant` set, not by the row |

**Which side answers what (CIRISPersist#878).** The referencing row and the
typed `BlobPointer` inside it are two axes, each authoritative for different
facts:

| fact | authority | why |
|---|---|---|
| `author_key_id` | the ROW's attester | authorship is the row's |
| `minter_key_id` | explicit, else the one admitted `key_grant` set | §2 |
| `tier` | the POINTER | the write door RESOLVED it and recorded it there; a chat row sits at `self` while its body is under the room's DEK |
| `community_key_id` | the POINTER | which key plane, not which row |
| `epoch` | the caller, else the POINTER | a key-plane fact; absent on a `CommunityDek` pointer means the adopt refuses rather than guesses |
| `cohort_scope` | the ROW, always | the attestation IS the access grant (`is_audience`, CC 5.2 / 4.4.3.3.1). A room message reaches a member's node only as a `community` row — crossed or born there; a `self` row pointing at community-DEK bytes is the owner's fan-out to their own node. The pointer never widens it |

A reference is an `evidence_refs[]` citation OR a pointer whose
`content_sha256` is the blob in hand; persist accepts either and refuses a
row that is neither. The tier taken from the pointer is still checked
against the placement it implies, through the one
`StorageFloor::check_scope` rule.

Three refusals keep the pointer from ever being a silent choice:

- **The pointer does not choose the audience.** A `community` /
  `affiliations` row is signed for one cohort (`envelope_cohort_target`);
  `would_hold` takes the audience from `provenance.community_key_id`, so a
  pointer naming a different community is refused by member. `self` /
  `family` rows carry no such target; their audience is the owner's and
  the pointer's community is the key plane only.
- **Pointer-shaped but unreadable is a refusal, not absence.** A member
  with a 64-hex `content_sha256` beside a `community_key_id` member IS a
  pointer; if its community is not a string, its tier is unknown or not a
  string, or its epoch is not an integer, `from_attestation` refuses by
  member. Treating it as "no pointer" would fall through to the citation
  path and derive a tier from the row's scope.
- **One blob, one key plane.** Two references to the same sha that
  disagree on tier, community or epoch are refused; identical duplicates
  (the same blob as `content` and as an attachment) are one reference.

The four minter-keyed tables carry `minter_key_id`.

## 4. Lifecycle, by door

| door | minter |
|---|---|
| `put_blob_scoped` (the seal) | the signing key, named THROUGH `epoch_minter` so one function answers everywhere |
| `adopt_sealed_blob{,_at}` | the binding's minter is `epoch_minter::resolve(...)`, not `author_key_id` |
| `apply_replicated_key_grant` (the set) | after projecting the wraps, `rebind_stranded_blob_epochs` for the set's `(community, minter, epoch)` |
| `authorize_viewer_by_tier` | reads the recorded `(community, minter, epoch)` binding |

## 5. Invariants

- **I126** — **the ladder, author ≠ sealer** (sqlite, postgres): a row
  attested by A's OWNER, sealed by A's NODE, its `key_grant` set carried to
  B, the blob adopted on B → `read_blob_as(B's node key)` OPENS, and the
  recorded binding names the NODE. The same ladder with the set NOT carried
  still refuses `NotGranted` (the fix admits nothing extra).
- **I127** — **explicit wins**: a provenance naming `minter_key_id` records
  that minter even where a different one could be derived; naming an empty
  string is refused by member.
- **I128** — **derivation, and its limit**: with exactly one admitted set
  for `(community, epoch)`, an unnamed provenance resolves to that set's
  minter; with two sets from different minters, an unnamed provenance falls
  back to `author_key_id` and does not guess (and I127's explicit member is
  the only way to disambiguate).
- **I129** — **repair**: a binding written under the wrong minter (bytes
  before the set) rebinds when the naming set is admitted, and the body
  then OPENS; a binding whose recorded minter DOES hold state is never
  rebound (the sweep touches only stranded rows).
- **I131** — **the row IS the provenance**: a person-attested row naming
  its community and citing the sealed bytes yields a provenance whose
  author is the attester, whose community is the named cohort and whose
  tier is resolved; a row citing other bytes is refused by member; and the
  adopt carried on that derived provenance OPENS on the peer.
- **I130** — from disk: every writer of a minter-keyed table takes its
  minter from `epoch_minter`; `adopt_cascade.rs` contains no
  `minter_key_id: provenance.author_key_id` spelling; the `author ≠ sealer`
  fixture is used by the DEK-plane witnesses.

Mutations: drop the explicit arm; drop the derivation arm; widen
derivation to pick the first of several minters; drop the rebind; let the
rebind touch a non-stranded row; restore the `author_key_id` spelling at
the adopt.

## 6. Not in scope

A DEK fingerprint in the at-rest envelope (it would let the bytes
arbitrate, at the cost of a format change and a re-seal of everything
already stored). The agreement-layer write lease (CIRISEdge#604, CC 5.4);
per-minter epochs remain the serialization discipline here.
