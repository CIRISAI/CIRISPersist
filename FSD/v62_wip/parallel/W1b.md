# W1b: a ROOTED edition-2 trust root

**Update 8 (2026-11-18, final): the pyi, and transit's positive control.**

- **pyi:** `python3 -I scripts/pyi_surface.py check` was read first (no cargo, no subprocess) and run: `OK type stub covers and classifies all 616 PyO3-exported symbols`, before and after the change. The verdict is surfaced as `trust_root_verdict_json` (a JSON string). Its member list is in the stub's docstring and in the matching `pyo3.rs` doc comment; both now list `not_rooted?` with one sentence. These are foreign hunks in `python/ciris_persist/ciris_persist.pyi` and `src/ffi/pyo3.rs`, docs only.
- **Transit (C), a production fix found while writing the control:** `transit_eligibility_walk`'s conjunct (C) "self-offers `infra:transport`" read `KeyRecord::claims_role`. An edition-2 key record carries no roles, so (C), and with it transit eligibility, could never hold on edition 2. Per CC 3.3.6.2 ("a node that relays carries one transit public key `transit_xwing_pubkey` on this `transport_destination` binding"), the offer is now a live transit key (`self_at_login::transit_xwing_pubkey_for(peer).is_some()`). The earlier role claim is read only while the earlier-form doors are open. The differential reference walk was changed identically.
- **New fixture helper:** `fixture_trust_root::put_acceptance(dir, &r, key, iss) -> RowId`, another party's `trust:accepts:v1` edge to the root signed by `key` (W1.api.md v1.5).
- **I3253 now has transit's own positive control.** Bundle seat 0 is a `node` with a live transit key (its bundle binding) and accepts the root (`put_acceptance` with the seat's key), so `resolve_transit_eligibility(node, seat)` is `eligible` while the root roots. After the later bundle leaves the count short, the SAME hop is not eligible. The old negative leg used a `user` subject, which (B) refuses whatever the root does; it is replaced.

**Update 7 (2026-11-18): no key-arm fallback for a community root (E9 finding 3, security ruling).**

- **`trust_root_valid_body`** (and its differential reference, identically): after the arm is resolved, an id still on the KEY arm that holds a trust-root-grade COMMUNITY record returns a not-valid verdict on the community arm (`community_not_rooted_verdict`): every leg false, `root_kind: Community`, and the new `not_rooted: Some(reason)`. The reason is the chain's own (`chain_standing_at`'s `NotRooted { reason }`, CC 2.7). Its validity comes only from its community chain, so a short founders' count can never read valid as the 1-of-1 key root at the same identity-ref.
- **`TrustRootVerdict` gains `not_rooted: Option<String>`** (`#[serde(default, skip_serializing_if = "Option::is_none")]`), so the JSON of every other verdict is unchanged. The four in-file struct literals add `not_rooted: None`. These were found with grep; there are no literals outside `trust_root.rs`.
- **Transit eligibility and the capability walk** both judge through `trust_root_valid`, so they inherit the rule. The ceremony arm is already behind the switch; the family-quorum plane judges family ids only.
- **Witness I3253 (sqlite + pg):**
  - a rooted root is valid and its conferral is reached (the positive control);
  - then a later bundle seats holders 1 and 4–7 (`later_v2`, signed by 1, 2 and the added 4–7), so the birth's voices {1,2,3} hold 1 of 5 against a required 3;
  - `chain_standing_at` is `NotRooted`, and `trust_root_valid` is not valid with `root_kind == Community` and `not_rooted` set;
  - the capability walk returns `None`, and `resolve_transit_eligibility(node, subject)` is not eligible.
- **Masking (E9's note):** with the guard removed, the key arm here reads `valid == false` anyway, because the root's own `user` key carries no custody evidence. So `!valid` alone would not catch a regression. I3253 therefore asserts `root_kind == Community` and `not_rooted.is_some()`, which only the guard produces; a mutation deleting the guard reds it whatever the hardware leg says.
- **Python surface:** `TrustRootVerdict` crosses to Python as JSON where it is serialized; the new member is absent unless set. Any `.pyi` TypedDict for the verdict may want `not_rooted: NotRequired[str]` (not edited; `scripts/pyi_surface.py check` not run against this tree).

E9 and E7 have been told.

**Update 6 (2026-11-18): the federation-scope duty-holders (E4's finding).**

`admission::duty_holders_for_federation` (signature unchanged) now reads the holders of the genesis bundle in force (C1's `genesis_in_force(dir).holders()`, common to every tip) as identity-refs.
- A genesis fork whose tips share no holder → `InvalidArgument`, never an empty set (#632's rule).
- No bundle held → the earlier accord-family roster only while the earlier-form doors are open; shut, it is `InvalidArgument`.
- The earlier sqlite witness `exercise_federation_duty_holders` (#632) runs on a backend with no bundle and the earlier family seeded, so it still takes the earlier path (doors open).

Witness I3252 (sqlite + pg):
- no bundle → `federation_invalid_argument`;
- after `install_v2` → exactly `bundle_v2().holder_identity_refs()`.

The gate leg (an accord holder's federation-scope `quarantine:*` row admitted by `check_delegated_duty_scores_admission`) is NOT re-witnessed in edition 2: it needs a holder-signed edition-2 scores row through the door. That flip is E4's, with the earlier `exercise_*` body.

E4 has been told.

**Update 5 (2026-11-18): E9's two causes, and `serve_tier`.**

- **E9 cause (1), the community arm reading the accord family:** fixed in update 3. `rooted_community_family` returns the root's OWN id for an edition-2 root, so `legs_ref` is the root itself and its `trust:charter:v1` self-edge is read. (E9 read a tree without update 3.)
- **E9 cause (2), the holder-hardware leg (CC 4.2.2.1):**
  - **Projection** (`edition2/projection.rs::attestation_evidence_of`): emits only the members the record states (`hardware_class`, `pq_custody` as text; `chain` as hex DER, leaf first, only when non-empty). A record with no `attestation_evidence` projects JSON `null`; there is no longer an object of nulls.
  - **Parse** (`hardware_attestation.rs`): a new untagged variant `AttestationEvidence::Edition2Custody(Edition2CustodyEvidence { hardware_class, pq_custody?, chain })`, LAST and `deny_unknown_fields`. Every earlier shape has required fields of its own, so there is no overlap.
  - **Check** (`check_structure`, new `check_edition2_custody`): the custody gate the genesis reader runs at seating.
    - The class must be `YubiKey_5_FIPS` with a chain; other classes are unattested, as Verify holds them.
    - The chain must verify to one of `edition2::genesis::attestation_roots()` (environment `YUBIKEY_PIV`) for the record's Ed25519 half, through Verify's `verify_yubikey_piv_attestation`, and attest that class.
    - A stated `pq_custody` must be `same_element` or `removable_offline`.
    - It returns `Ok(None)`, so Layer A passes and there is no Layer B.
  - **Whose evidence** (`trust_root_valid_body` and its differential reference, identically): for an edition-2 root (community arm, no family), the charter holders judged are the root's FOUNDERS (the holders it seats), not the root's own key that signs the charter.
  - `holder_hardware`: a holder with no `federation_keys` row that is a holder of the bundle in force passes Layer A. CC 4.2.2.1: custody is "checked where a holder is seated", and the bundle reader gated it.
  - **Fixture:** the founders are `bundle_v2`'s holders. Their records carry `YubiKey_5_FIPS`, `removable_offline` and C2's mock PIV chain. `install_v2` registers C2's mock root (`add_test_attestation_root`, test builds), which `attestation_roots()` then resolves. So the founders carry passing test-anchor evidence, and the new arm verifies it for real.
  - I3248 now also asserts `holders_hardware_attested`.
  - **Changed foreign test:** J0's I2000 (`projection_invariants.rs`) asserted the object-of-nulls (`chain: []`) for a record with no evidence. It now asserts that none is projected (`None` or `null`).
- **`serve_tier`'s canonical rung** (`resolve_serve_tier_over_roster_body`): `edition2::genesis::is_canonical_by_bundle(dir, subject)`, an identity-ref in `serve_nodes` of the bundle in force (ruling C). The ceremony-plane rung (accord co-scrub plus the walk) runs only while the earlier-form doors are open. Witness I3251 (sqlite + pg): bundle seat 0 is `Canonical`; an E0 node key the bundle does not list is not.
  - Risk: the rung sits after the subject's key-record checks (a `node` record, not expired). A bundle seat whose record is not projected into `federation_keys` (C1's single-transaction import, if it does not project) would read `None` before the rung.
- **Runtime risks:**
  - a stored `null` evidence read back as `Some(Value::Null)` makes `admit_key_record` run `check_structure` and refuse "null" on a door that re-admits a projected row. Believed not to happen: the projection is written by the edition-2 store, not by `put_public_key`.
  - the mock PIV chain must be inside its validity window: the genesis reader accepted it at install, through the same Verify function.

E9 and E7 have been told.

**Update 4 (2026-11-18): the confers path witnessed; the held root is returned.**
- **`rooted_trust_root` returns the held root on a second call.** The birth, charter and acceptance statements are built first (deterministic). If the root is held and its birth voices, charter and this node's acceptance are all held, they are returned and nothing is put. A root at `ROOT_SEED` founded otherwise is refused. Witnessed in I3248 (same ids).
- **`put_conferral(dir, &r, subject_seed, scope)`:** the root's `trust:confers:v1` grant, then the subject's own voice (`e2::voice_of`), which Verify's `delegate: sub` rule requires.
- **I3250 (sqlite + pg):** a conformant infrastructure room nothing reaches is not authorized. After `put_conferral(r → the room's key, infra:serve)`, with the room's key co-signing, it is authorized through `trust::infrastructure_reached_here`'s confers arm, and a node member of it needs no steward.
- **I3249** now uses `put_conferral` for the capability-walk grant.
- **Runtime risk:** a `user` key record at a community's own id (the room's key) must not conflict with the community row; the root fixture already relies on the same.

E5 and E7 have been told.

**Update 3 (2026-11-18): the readers, the walk, idempotency.** With update 2 (the infrastructure predicate), the lead's three open items are done.

- **`trust_root_valid` on edition 2.** `canonical_community::rooted_community_family` returns the root's OWN id for an edition-2 root whose chain verdict (`chain_standing_at`) is `Rooted` or `Stalled`. `trust_root_valid_body`'s community arm therefore reads every leg at the root:
  - the user's `trust:accepts:v1` edge (the kernel edge leg);
  - the root's self-charter (scope `infra:serve` + `infra:attest`) with a well-formed `pre_rotation_commitment`;
  - the charter holder's hardware leg (the root's own `user` key).

  It uses the chain verdict, not the read verdict, because the read verdict's acceptance is THIS node's, while `trust_root_valid` asks for its `user`. The earlier accord-family arm is reached only through `stored_standing`, so only while the earlier-form doors are open. The differential reference walk (`trust_root.rs` ~4855) calls the same function and stays equal.
- **The capability walk** (`capability_roots_to_trusted_root_over_roster`): the delegation plane reads the projected `trust:confers:v1` rows as it does any row, then `trust_root_valid`. The AccordCoScrub ceremony-plane fallback is now read only while the earlier-form doors are open (CC 2.6.1.12).
  - NOT changed: `serve_tier`'s canonical rung (~4155) still asks the ceremony plane. In v62, canonical standing is the bundle's `serve_nodes` (C1); that rung is C1's or F0's to retire.
- **Idempotent fixture:**
  - every instant is derived from the bundle in force (newest tip + 60 s), so a second call is a no-op with identical row ids (`RowId` is over the payload, not the signature);
  - new `confers_statement(r, subject, scope, at)`;
  - W1.api.md v1.3.
- **Witnesses I3248/I3249, sqlite and pg:**
  - a second `rooted_trust_root` returns the same ids;
  - `trust_root_valid(node, root)`: edge, charter and recovery all hold, `valid` is true, the arm is `Community`;
  - a `trust:confers:v1` grant root→subject (scope `infra:serve`, plus the subject's second voice) is found by `capability_roots_to_trusted_root(node, subject, infra:serve)` with `root_key_id == root` and `grant_attestation_id` = its row id;
  - after the node's `withdraws` of its acceptance, `valid` is false and the walk returns `None`.
- **Runtime risks added:**
  - the root's `user` key carries no hardware evidence. The holder-hardware leg must read it as attested under the default policy (`check_structure` → Layer A), else `valid` is false;
  - the confers row must be admitted with Verify's `delegate: sub` second-signer rule, the subject voicing second;
  - T2's `put_trust_statement` must not refuse a conferral.

E5 and E7 have been told.

**Update 2 (2026-11-18), the infrastructure predicate (E5's finding).**

The bug: `admission::infrastructure_rooted_here` compared `trusted_roots_of(node)` (accepted kids) with `rooted_community_family(room)`, which yields the accord FAMILY id only when the room itself is a rooted trust root. On edition 2 no room could pass `is_authorized_infrastructure_community`.

The fix (RULINGS: "a conformant infrastructure record rooted in THIS node's trust set"):
- An edition-2 room (its record has edition-2 roster voices) goes to the new `trust_root::infrastructure_reached_here(dir, &room, now)`. It is true when a root this node holds `Rooted` or `Stalled` (`stored_standing_at`: the chain, THIS node's acceptance edge and the root's charter) is any of:
  - the room itself;
  - the author of the `trust:charter:v1` self-edge the room's record cites (`charter_digest`, the roster's `refs.also.cites`);
  - the source of a live `trust:confers:v1` edge `delegates_to(root → room)`.
- No node key reaches nothing.
- The roots compared are the ones the chain reaches, never the accord family's name.
- The earlier-form body runs only while the earlier-form doors are open.
- `is_conformant_infrastructure_record`: a founder with no `federation_keys` row that is a holder of the bundle in force counts as a person (an `accord_holder`).

Witnesses I3245–I3247, sqlite and pg:
- the rooted root itself, and a room founded by holders 1–3 citing the root's charter, are authorized;
- a conformant room nothing reaches is not;
- in the authorized room a node member needs no steward, while an agent member is refused `UnstewardedCommunityMember{agent}`; in the unreached room a node member is refused too;
- after the node's `withdraws` of its acceptance, neither the root nor the cited room is authorized.

The `trust:confers` path is witnessed in update 4 (I3250).

Runtime risk: a roster citing a charter row (`refs.also.cites`) must pass T1's door, and any gate that reads `charter_digest`. Compile risk: none new beyond the earlier ones (the I3247 match binds `member_role: &'static str` by value).

E5 has been told.

**Base:** worktree `/home/emoore/CIRISPersist-wp-W1b`. Its index is T2's tree `6e7cf55f` (X2 @ `4239bde8` + `T2.patch`, read from T2's worktree index) + `W1.patch`, as tree `4807ee8c`. Two conflicts were resolved by keeping both sides: `edition2/ingest.rs` (W1's rebind branch, then T2's typed intercept) and `edition2/mod.rs` (both doc rows and module lists).

`W1b.patch` is `git diff` of the working tree over that index. To apply: X2 @ 4239bde8 → T2 → W1 (resolving the same two conflicts the same way) → W1b.

**Note for the coordinator:** `X2.patch` has drifted 48 files since T2's base (`4239bde8` vs today's `51f9d0da`). `W1.patch` was cut on the newer X2; T2 and W1b are on the older one.

Nothing is built; every claim is BELIEVED. "Read-checked" means confirmed by reading the base tree or CC rc20.

API: `W1.api.md` (v1.1). T2 and E7 were messaged when v1 was published; a second message goes out with this patch.

## What changed

### The read verdict (`canonical_community.rs`)

- **`chain_standing_at`** (pub) is the body that used to be `stored_standing_at`: the record's chain from its birth with every founder counting, plus the standing cache and the T7 liveness declarations.
  - The DOORS read it: `check_trust_root_community_admission`, `apply_trust_root_chain_counted`, `founders_link_is_the_quorum`, `prepare_trust_root_supersede`.
- **`stored_standing_at`** (same signature) is the READ verdict.
  - **Edition-2 roots** (a root whose stored version has edition-2 `group:roster` voices; W1's `trust_root_group::version_signers`): the chain verdict AND this node's own T3 chain. Without a live acceptance edge or a live charter it returns `NotRooted { reason }`, by name.
  - **Earlier-form chains:** returned as before only while `edition2::door::earlier_form_doors_shut()` is false. Once the doors shut they read as `NotRooted` (CC 2.6.1.12).
  - Readers unchanged in signature: `stored_standing`, `rooted_community_family`, `resolve_community`, `trust_root_bundle_response`, and T2's `trust_root_head` (purge).
- **The T3 overlay is not cached:** it is re-read on every call (two attestation slices). The chain verdict stays cached.

### This node's T3 chain (`trust_root.rs`)

`own_chain_to(dir, root, now) -> OwnChain { accepted, chartered }` and `struct OwnChain`.

- **The node is its own seed** (CC 4.4.3.34): `dir.node_key_id()`. With no node key nothing is accepted (CC: `None` means cannot verify).
- **Acceptance is the owner's** (CC 3.2 T3):
  - the owner's edge (`admission::owner_of`) governs once the owner has signed any `trust:accepts:v1` row;
  - until then the node's own edge is read;
  - an ambiguous owner reads as unowned.
- **The edge leg** is the existing `kernel_edge_leg` over the user's labelled slice with its composers (`with_slice_composers`), so a `withdraws` un-trusts.
- **The charter leg** is the root's own LABELLED `trust:charter:v1` self-edge (`attesting == attested == root`): not retired, not expired, counting in the capability walk, scope `infra:serve` + `infra:attest`, and a well-formed `pre_rotation_commitment`.
- **It never resolves a community arm:** `trust_root_valid` → `rooted_community_family` → `stored_standing` would recurse.

### Fixture (`edition2/fixture_trust_root.rs`, new; cfg `any(test, test-anchor)`)

`rooted_trust_root` / `try_rooted_trust_root` (`W1.api.md`):

1. install `bundle_v2` if no genesis is held;
2. put the root's `user` key `kid(ROOT_SEED)`;
3. found an infrastructure community at it, with the given holder seeds as FOUNDERS, through T1 roster voices;
4. put the charter self-edge, signed by the root's key, with `pre_rotation_commitment` = Verify's `recovery_commitment` over a successor key (bstr → 64-hex on the mapped envelope);
5. put the node's acceptance edge, signed by the node's E0 key, with `attached_head_digest` = the held head (bstr → hex).

Each edge is a `delegates_to` statement at family `trust:.job:.version`, routed by T2 to `typed::put_trust_statement` (the attestation door, kept).

### Foreign hunks

- `edition2/mod.rs`: `pub mod fixture_trust_root` (test-anchor gate).
- `edition2/fixture_switch.rs` (E0's file): re-export of the fixture.
- `canonical_community.rs`, `trust_root.rs`.

## Tests (block I3230–I3259; W1b uses I3242–I3244), sqlite + pg

| test | witnesses |
|---|---|
| I3242 | `rooted_trust_root(holders 1–3, quorum:2/3)` → `own_chain_to` reports both legs; `stored_standing` is `Rooted`; its founders are the bundle's holders |
| I3243 | an id never founded → `Absent`. With the node switched to another node key that accepted nothing: `chain_standing_at` is `Rooted` but `stored_standing` is `NotRooted`. Switched back → `Rooted`; the node's `withdraws` of its acceptance edge (T2's `trust_withdraws_statement`) → `NotRooted` (CC 3.2 T3, "un-trust is one deletion") |
| I3244 | end to end: a `takedown_notice:steward_purge` notice from the root over the empty `mock_llm_traces` selection. Founder 0's voice alone: `purge_rows_edition2` → `quorum_not_met`. With founder 1's voice: executes; `report.cosigners` = founders 0 and 1; `notice_id` = the row id |

**W1's I3235–I3237 now read `chain_standing_at`.** They witness T7, a property of the chain, and their test rooms have no acceptance edge.

The runners set the node key first: `set_node_key_id(e2::put_key(b, "w1b-node", &["node"]))`.

## For E7 / T2 (and every reader of `Rooted`)

- `Rooted` for an edition-2 root needs the backend's node key and this node's acceptance edge. Use the fixture, or put both edges yourself.
- The earlier-form canonical root (`cc::stand_up`) keeps working until the doors shut.
- A test that asserts `stored_standing == Rooted` on a T1-only room (no charter, no acceptance) must read `chain_standing_at` instead.

## Compile risks

1. `i3243_unrooted_without_this_nodes_acceptance` takes `&(dyn Fn(String) + Sync)`. The runners pass `&|k: String| b.set_node_key_id(k)`. The closure is believed `Sync`, because the backends hold `RwLock`s.
2. `own_chain_to` calls `pages.next(directory)` with a generic `F: ?Sized`, as `trust_root_valid_body` does in the same file.
3. `fixture_trust_root` and `fixture_switch` import each other: fine for `use`, but name collisions are checked at synthesis.
4. `takedown_payload(.., &r.founders, ..)` relies on `&Vec<String>` coercing to `&[String]`.

## Runtime risks (gates I could not read through)

- The charter self-edge must pass the attestation door's gates (`check_trust_charter_admission` read-checked: witness quorum absent, commitment well-formed, no recovery fields). It must also pass T2's `put_trust_statement` (a self edge is not projected).
- The acceptance edge to a held community root passes `check_attach_freshness` on the Replicated arm (head named). T2 flagged that trust-root gates on `delegates_to` at `trust:accepts:v1` might refuse.
- `count_over_trust_root` evaluates `quorum:2/3` over the head's three founder seats with two signers, `Direction::Add`, subkind infrastructure: admits, as I3176 shows.
- `resolve_selection(mock_llm_traces)` on an empty store must yield the empty selection digest (`selection_digest_bytes::<&str>(&[])`).

## Not done

- A root whose ACCEPTANCE is reached transitively (a node accepting a root that confers another root).
- The witnessed-mode attach freshness.
- Flipping E7's held trust-root bodies 536/557/561/548/686. They are E7's; the fixture is published for them.
