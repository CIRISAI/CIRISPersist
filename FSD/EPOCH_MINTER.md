# The minter is named, not inferred (CIRISPersist#876)

v46.0.0. Status: normative for the community-DEK plane. Corrects
`FSD/BLOB_REPLICATION.md` §11. Fixes CIRISPersist#876.

## 1. The premise that was false

`BLOB_REPLICATION.md` §11 ruled per-minter epochs — key state, retention
and grants keyed `(community_key_id, minter_key_id, epoch)` — and then, in
the same paragraph, said: *"a blob's key identity is `(community, author,
epoch)`, and the author is already on the row (`author_key_id`, §5)."*
That sentence is why no field was added, and `adopt_cascade.rs` wrote the
premise into code:

```rust
// #848 (§11) — the AUTHOR is the minter; `BlobProvenance` needs no new
// field: its `author_key_id` IS the epoch's minter, because the author's
// cascade minted the epoch the blob is sealed under.
minter_key_id: provenance.author_key_id.clone(),
```

**Author and minter are two different questions.** The author is the
attester of the row the blob is a projection of. The minter is the
occurrence whose cascade minted the epoch and holds the DEK. They coincide
exactly when a node authors its own content — which is every witness on
this plane, and not the product. A chat row is authored by a **person**
(consent and authorship are by humans, server 0.5.211) and sealed by their
**node**: the seal path passes the signing key into `resolve_minter`, so
the DEK rows and the `key_grant` set are keyed by the node, while the adopt
keyed the binding by the person. `authorize_viewer_by_tier` reads
`community_dek_blob_epoch(sha) -> (community, minter, epoch)` and then
`community_dek_has_member_grant(community, minter, epoch, viewer)`: the
tuple misses on the minter member alone, and every cross-node community
body reads `NotGranted` with the viewer and its wrap both correct.

**The class.** This is the third site where one key or gate answers
"person or node?" from two axes: CIRISPersist#765 at write admission (the
roster holds persons, the writer is the node), #873 at the audience plane
(`audience_memberships` asked the roster about the instrument), and this at
the DEK plane. Twice the fix was local and the next instance shipped. §5
closes it structurally instead.

## 2. The rule (stated once)

**The minter of `(community, epoch)` is the occurrence whose cascade minted
it, and persist resolves it one way everywhere:**

1. the **explicitly named** `minter_key_id`, when the producer supplies one;
2. else the minter of the **one** admitted `key_grant` set that granted
   THIS node a wrap at that `(community, epoch)` — signed by the minter,
   already verified, so the two halves agree by construction;
3. else `author_key_id` — the pre-v46 answer, kept so upgrading changes no
   behaviour a caller depends on, and correct wherever author == sealer.

Ambiguity is not guessed: two admitted sets from different minters at one
`(community, epoch)` means only (1) can answer, and (3) is used if nobody
named it. That is exactly the state #848 made the key three-part for.

The bytes cannot arbitrate: `AtRestEnvelope` is `magic ‖ nonce ‖
ciphertext`, carrying no key id and no DEK fingerprint. Resolution is from
declaration or from verified state; there is no third source.

## 3. Surface

| symbol | change |
|---|---|
| `BlobProvenance.minter_key_id: Option<String>` | NEW. The key whose cascade minted the epoch — the key that signed the `key_grant` set. `author_key_id` keeps its meaning (the row's attester). **Breaking**: the struct has no `#[non_exhaustive]`, so every Rust literal gains a member |
| FFI provenance wire | optional `minter_key_id` member (`#[serde(default)]`) — the JSON surface stays compatible |
| `federation::epoch_minter::resolve(...)` | NEW. The ONE answer to §2, used by the adopt path, the repair sweep and the from-disk gate |
| `FederationDirectory::community_dek_minters_granting(community, epoch, viewer)` | NEW read: the minters of every admitted set that granted `viewer` a wrap at `(community, epoch)`, sorted, deduped. The derivation input, on all three backends |
| `rebind_stranded_blob_epochs(community, minter, epoch)` | NEW. On admitting a `key_grant` set, rebind every `federation_community_blob_epoch` row at that `(community, epoch)` whose recorded minter holds no DEK state and no grants — the bytes-before-key ordering (§3 of BLOB_REPLICATION) and every row written under the v45 premise |
| `BlobProvenance::from_attestation(row, sha256, epoch, minter)` | NEW (PyO3 `blob_provenance_from_attestation_json`). The relation `BLOB_REPLICATION.md` §5 states in prose — provenance lives on the referencing attestation — as a constructor: author from the row's attester, cohort from the row, community from the cohort the SIGNED envelope names, tier resolved; refuses a row that does not cite the bytes in `evidence_refs[]`. `epoch` / `minter_key_id` are arguments because they are key-plane facts carried by the `key_grant` set, not by the row |
| `BLOB_REPLICATION.md` §11 | corrected: the key identity is `(community, MINTER, epoch)` |

**v46.1.0 (CIRISPersist#878) — which side answers what.** The referencing
row and the typed `BlobPointer` inside it are two axes, and v46.0.0 read one
where it needed the other:

| fact | authority | why |
|---|---|---|
| `author_key_id` | the ROW's attester | authorship is the row's, and it is the member #876 was written by transcribing |
| `minter_key_id` | explicit, else the one admitted `key_grant` set | §2, unchanged |
| `tier` | the POINTER | the write door RESOLVED it and recorded it there; a chat row sits at `self` while its body is under the room's DEK |
| `community_key_id` | the POINTER | which key plane, not which row |
| `epoch` | the caller, else the POINTER | a key-plane fact; absent on a `CommunityDek` pointer means the adopt refuses rather than guesses |
| `cohort_scope` | the POINTER's tier | community-DEK bytes are placed in the community whose DEK sealed them; otherwise the row's placement stands |

A reference is an `evidence_refs[]` citation OR a pointer whose
`content_sha256` is the blob in hand; persist accepts either and refuses a
row that is neither. The tier taken from the pointer is still checked
against the placement it implies, through the one
`StorageFloor::check_scope` rule.

No migration: the four tables already carry `minter_key_id`. No vocabulary
change. MAJOR for the struct member alone.

## 4. Lifecycle, by door

| door | what changes |
|---|---|
| `put_blob_scoped` (the seal) | unchanged — it already names the signing key as minter; it now does so THROUGH `epoch_minter` so one function answers everywhere |
| `adopt_sealed_blob{,_at}` | the binding's minter is `epoch_minter::resolve(...)`, not `author_key_id` |
| `apply_replicated_key_grant` (the set) | after projecting the wraps, `rebind_stranded_blob_epochs` for the set's `(community, minter, epoch)` |
| `authorize_viewer_by_tier` | unchanged — it was always right; it was being handed a wrong key |

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
