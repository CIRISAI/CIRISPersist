# FSD — `trust_root_valid`: the holder-hardware leg (CIRISPersist#901)

**Surface:** `TrustRootVerdict::holders_hardware` / `holders_hardware_attested`, `HardwareAttestationPolicy::check_structure`, and the structural check on every evidence-carrying key record at the key doors, replicated ones included.
**Rule (CIRISEdge#659):** *a valid root is defined by its holders' attested hardware property, evaluated where the root is judged.* Edge composes the mutual-root walk from persist's legs and re-derives nothing; this leg is what edge needs from persist for that walk.

## 1. The pieces this leg composes

- `trust_root_valid` (`trust_root.rs`) folds `valid = edge_exists && root_self_declares && charter_has_recovery && holders_hardware_attested`, with `bounded_until` as the consumer's re-check instant. `halt_latched` and `drill_freshness` are read and reported beside the verdict, not folded into it (a constitutional halt is an agent pause, gated at the agent's act gate — CC 4.2.1.1). It enumerates the holders: for `RootKind::Family` the seated holders whose `trust:charter:v1` scrubs reach the family's own threshold (the #557 fold — `charter_quorum` reports the counts; the holder key ids are the charter rows' scrub set); for `RootKind::Key` the self-charter's signer.
- `HardwareAttestationPolicy::check(key_id, evidence, now)` runs the structural legs — evidence present (`missing` / `null` refused), canonical shape (`AttestationEvidence` parses; `SoftwareOnly_TEST` only under a live test anchor; `GenerationCustody` through its own admissibility), class accepted (`platform_to_hardware_type ∈ accepted_hardware_types`), required fields present — and then **nonce freshness** (`now − nonce_captured_at ≤ max_nonce_age`, 24 h). Freshness is replay protection at registration. It is not a property a root's validity can depend on, or every real root would expire a day after its holders registered.
- The key doors are `put_public_key`, `adopt_scrub_upgrade` and `supersede_canonical_record` on each backend (`register.rs` §7.2 / §9.1). `apply_replicated_key_record` classifies through `plan_replicated_key_apply` (`Insert` / `Unchanged` / `Upgrade` / `Refused`) and then goes through `put_public_key`. A peer's directory may be weaker than the admitting node's, so a replicated record is checked where it lands (§3.5); otherwise the walk in §2 would be judging records nobody checked.
- verify-core (`accord_custody_attestation.rs`) has `verify_yubikey_piv_attestation(attest_9c_der, chain_ders, pinned_root_der, expected_ed) -> CustodyVerdict`: every link a real signature verification against a pinned Yubico root, asserting the attested key equals `expected_ed`. YubiKey PIV is the only class with a pinned root.

## 2. The rule

`R` is valid at node `N` iff, besides the existing legs, **every charter holder's key record passes Layer A, and passes Layer B for any hardware class `N` holds a pinned attestation root for.**

- **Layer A** = the policy's structural legs (present, canonical, class accepted, fields present) **without** freshness. A record with **no** evidence at all is software-class: the key doors admit it — but a charter holder with no evidence fails the leg, because validity is defined by the holders' attested hardware property. The leg judges a root's holders, not the directory.
- **Layer B** = the chain walk for classes with a pinned root: YubiKey PIV → `verify_yubikey_piv_attestation` with `expected_ed` = the record's Ed25519 pubkey. TPM / Secure Enclave / StrongBox are Layer-A-only until a root is pinned for them (`layer_b: None`, never `Some(false)`).
- **Evaluated where the root is judged**, from the records `N` holds. Not attacker-steerable: `N` verifies only holders of roots `N` pinned, and no one replaces a holder's record without that holder's key.

## 3. The structure

### 3.1 The policy split
```rust
impl HardwareAttestationPolicy {
    /// Layer A: present, canonical, class accepted, fields present. No clock.
    pub fn check_structure(&self, key_id, evidence) -> Result<HardwareType, Error>;
    /// Admission: check_structure + nonce freshness (the existing behaviour).
    pub fn check(&self, key_id, evidence, now) -> Result<(), Error>;  // unchanged contract
}
```
`check` is `check_structure` + the freshness leg, so the two cannot drift.

### 3.2 The verdict
```rust
pub struct HolderHardware {
    pub key_id: String,
    pub class: Option<HardwareType>,   // None: no evidence / unparseable
    pub layer_a: bool,
    pub layer_b: Option<bool>,          // None: no pinned root for this class
    pub refusal: Option<String>,        // the policy's own detail, when refused
}
// on TrustRootVerdict:
pub holders_hardware: Vec<HolderHardware>,   // one per charter holder, sorted by key_id
pub holders_hardware_attested: bool,         // all(layer_a && layer_b != Some(false))
// folded: valid = … && holders_hardware_attested
```
Per holder, so a consumer sees *which* leg failed. `bounded_until` is unchanged (hardware evidence does not expire on the clock).

The holder set is the one the charter fold already computes: on a KEY root the self-charter's signer; on a FAMILY root the union of the *verified seated scrubs* of every quorate charter (`family_quorum_holders_over` — the #557 count's own set, carried out beside the count, so "quorate" and "who" come from one fold). Not the roster (a seated holder who did not sign is not a holder of *this* charter) and not the `about_root` attesters (a co-signature that did not count is not a holder). When no charter reaches the bar the set is empty, `holders_hardware` is empty and `holders_hardware_attested` is vacuously true — `root_self_declares` is already false there, so nothing is claimed by it.

### 3.3 Layer B reuses the chain walk persist already has
Persist already walks a YubiKey PIV chain against the pinned Yubico root: `admission::verify_member_fips_custody(&KeyRecord)` (production, root pinned to `YUBICO_ATTESTATION_ROOT_1_DER`) with the root-parameterized twin `verify_member_fips_custody_against(&rec, root_der)` that the #513 witnesses drive with `MockYubicoCa`. It resolves the record's own `directory_member()` as the holder and asserts the attested key equals the record's Ed25519 pubkey, FIPS-certified, touch-always. The validity leg calls **that**, so there is one chain walk, not two. `GenerationCustody` evidence carries no nonce (it attests at generation), so Layer B has no freshness leg to drop. Classes with no pinned root (Android StrongBox, iOS Secure Enclave, TPM, external SE other than YubiKey) are Layer-A-only: `layer_b = None`, never `Some(false)`.

For the witnesses the pinned root is injectable: `HardwareAttestationPolicy` carries `yubico_root_der` (default: the pin; a `MockYubicoCa::root_der()` in tests, through the existing `set_hardware_attestation_policy`). Production never reads a caller-supplied root at admission (Registry-of-Record) — the field is the policy's, and the policy is the node's.

### 3.4 Cache
A memo of the pure function `(key record, policy) → HolderHardware`, keyed by the holder's key id and a fingerprint over exactly the inputs the verdict depends on: the record's Ed25519 / ML-DSA pubkeys, its `attestation_evidence`, and the policy (accepted classes, pinned root). Three holders, verified once per record version; invalidated by the record changing, never by time. (Not `persist_row_hash`: the row hash moves on fields the verdict does not read.) Bounded at 4096 entries (`HOLDER_HARDWARE_CACHE_CAP`).

### 3.5 Layer A on replicated key records, regardless of `identity_type`
At the three policy sites per backend (`put_public_key`, `adopt_scrub_upgrade`, `supersede_canonical_record`) the **structural** check is not conditioned on `claims_role(accord_holder)`: every row that carries evidence runs `check_structure` (a row with none is admitted, never downgraded). Freshness stays where it is: an `accord_holder` registering locally runs the full `check`; a record arriving by replication runs `check_structure` only (its nonce was fresh where it registered, days ago). Same policy, same door, every backend.

### 3.6 Test fixtures
Every key that can be a charter holder in a test fixture (the root, the seated family holders) carries Layer-A-valid evidence (the #543 pattern), so the gate is *satisfied* on sqlite and postgres rather than bypassed. A fixture that wants an unattested holder says so explicitly (I154's second leg).

## 4. Invariants (sqlite + postgres through one `&dyn FederationDirectory`)

A key record's evidence is **immutable for its key id**: the doors admit, upgrade scrubs (`adopt_scrub_upgrade`), supersede a canonical, or rebind (#864) — none rewrites `attestation_evidence` or the pubkeys (Registry-of-Record). So the witnesses vary the property across *holders* and across the *policy*, never across versions of one record; every shape is a fresh root whose holders were registered the way production registers them.

- **I154 — a root is as attested as its holders.** Root A: three seated charter holders, each carrying Layer-A-valid StrongBox evidence with a **month-old** nonce: `valid`, `holders_hardware_attested`, three entries sorted by key id, each `layer_a = true`, `layer_b = None` (no pinned root for StrongBox), no refusal. Root B: the same shape with holder 1 registered with **no** evidence: `valid = false`, that holder `layer_a = false`, `class = None`, refusal naming `missing`; the other two unchanged; `edge_exists` / `root_self_declares` / `charter_has_recovery` / `halt_latched` identical to A's; no `bounded_until` on a refusal. Then the **node's policy** stops accepting `AndroidStrongbox`: root A, judged now from the same records, is invalid with every holder refused by class — validity is evaluated where the root is judged, against the judging node's policy, not frozen at admission; restoring the default policy restores A's verdict byte-for-byte.
- **I155 — validity never re-checks freshness; admission always does.** The stale-nonce evidence is refused by `check` and accepted by `check_structure`; a fresh nonce passes both. Through the door on each backend: an `accord_holder` registering locally with the stale nonce is refused for freshness; a `NODE` row with the same evidence is admitted (structure only).
- **I156 — Layer B binds the record's key.** Root A's holder 0 is a YubiKey PIV member (`MockYubicoCa`, the policy's `yubico_root_der` swapped to the mock root) whose record carries the member's own pubkeys: `layer_a = true`, `layer_b = Some(true)`, `class = ExternalSecureElement`, valid; its StrongBox co-holders are Layer-A-only. Root B's holder 0 carries the same kind of chain but pubkeys the chain does **not** name (the door does not walk the chain — the leg does): `layer_b = Some(false)`, invalid, refusal names the mismatch.
- **I157 — replicated records are checked where they land.** A `NODE` record with **malformed** evidence through `apply_replicated_key_record` on every backend: refused *for the evidence* (`malformed` in the reason) and leaves no row. The same with no evidence: admitted. The same with stale-nonce valid evidence: admitted (structure only). An `accord_holder` registering locally with the stale nonce: refused.
- **I158 — verdicts are memoised by their inputs.** Evaluation counts per holder key id (a parallel suite judging other roots cannot move them): three holders, `trust_root_valid` twice → three evaluations, not six, and the two verdicts are equal. The policy is an input: swapping it for a different object that judges identically (`max_nonce_age` shortened — not a validity input) re-evaluates each holder exactly once more (six), with the same per-holder verdicts.

Mutants (§5.1): freshness re-added to `check_structure` (I154/I155 red); Layer B result ignored (I156 red); the holder set taken from the roster or the `about_root` attesters instead of the quorate charters' verified scrubs (I154 red through a non-signing seat); the `accord_holder` condition kept at the door for the structural check (I157 red); the memo keyed by key id alone (I158 red on the policy swap); `holders_hardware_attested` dropped from the `valid` fold (I154 red).

## 5. Verification

### 5.1 Mutation table (lane = I154–I158, each mutant reverted before the next)

| # | Mutant | Verdict | Killed by |
|---|--------|---------|-----------|
| M1 | validity re-checks nonce freshness (Layer A + age) | KILLED | I154, I156, I158 |
| M2 | `attested()` ignores Layer B | KILLED | I156 |
| M3a | holder set = every attester about the root | KILLED | I154, I156, I158 (the unattested user) |
| M3b | holder set = the seated roster, not the verified scrubs | KILLED | I154 (the seated non-signer) |
| M4 | door keeps the accord_holder-only condition | KILLED | I157 |
| M5 | memo fingerprint ignores the policy | KILLED | I154, I158 |
| M6 | `holders_hardware_attested` dropped from the `valid` fold | KILLED | I154, I156 |
| M7 | a Layer A refusal reports `layer_a = true` | KILLED | I154 |
| M9 | Layer B never runs (`is_custody` forced false) | KILLED | I156 |
| M10 | holders reported in reverse order | KILLED | I154 |
| M11 | door drops freshness for a local accord_holder | KILLED | I155, I157 |

Every mutant is killed on every backend. Not mutated: the "no key record for this holder" arm (`holder_hardware`'s `None` branch) — unreachable at read time, since a charter scrub only counts once it verified against a stored pubkey, so no witness can put a record-less holder into the set; it stays as the honest answer should that ever change. M8 is this arm, equivalent by construction.

## 6. Not in scope

- Pinning roots for TPM / Secure Enclave / StrongBox (each is a root-pinning decision with its own provenance; the hook takes them without a code path).
- Edge's composition of the mutual-root walk (CIRISEdge#659) and Server's replication ladder.
- Any change to what `HardwareAttestationPolicy::check` refuses at local `accord_holder` registration.
