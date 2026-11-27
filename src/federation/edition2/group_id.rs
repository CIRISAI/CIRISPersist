//! v62.0.0 (GID-prod; CIRISConstitution "THE DERIVED GROUP ID", rc22-pre4,
//! as Eric decided for v62.0) — **a group's id is derived from its own
//! founding.**
//!
//! `group-ref = "group-" ‖ base64url-nopad(SHA-256(CDE(["CEG-group/2",
//! group_kind, first_members, founded_at, nonce])))`: `group_kind` and
//! `founded_at` are the FIRST version's, `first_members` the `key` of EVERY
//! member that version lists (a set, CC 2.6.1.2 order), and `nonce` 32 fresh
//! bytes the first version alone carries. A first version (no `refs.head`)
//! whose `group` is not the id derived from its own members is Invalid
//! (`group_id_not_of_founding`), so nobody founds under an id without being
//! its founders, and no group id is a key's (the forms differ:
//! `group-` + 43 characters, never the `urn:…:ckt:` prefix).
//!
//! **To be replaced by Verify 23.5.1's export at the pin step: delete this
//! module and re-export `ciris_verify_core::edition2::group::{
//! derive_group_id, check_group_roster_founding, GROUP_ID_LABEL}`** (the
//! same two signatures; Verify's `Invalid::GroupIdNotOfFounding` and
//! `Invalid::Malformed { member: "nonce" }` in place of [`Invalid`]). The
//! known answers (`tests`) are Constitution's and Verify's; a swap that
//! changes one is a different rule.
//!
//! The deterministic encoding is Verify's [`cde::encode`] (map keys
//! bytewise, shortest integer heads); the set order is each element's
//! encoding, duplicates dropped, as `edition2::check_set` reads a set.

use base64::Engine as _;
use ciris_verify_core::cde::{self, Value};
use sha2::Digest as _;

/// The derivation's domain label (Verify 23.5.1 `GROUP_ID_LABEL`).
pub const GROUP_ID_LABEL: &str = "CEG-group/2";

/// The `group-ref` prefix: a group id is this plus 43 base64url characters
/// with zero trailing bits (the shape of a key segment).
pub const GROUP_REF_PREFIX: &str = "group-";

/// The refusal token of a first version whose `group` is not its derived id
/// (Verify 23.5.1 `Invalid::GroupIdNotOfFounding`).
pub const GROUP_ID_NOT_OF_FOUNDING: &str = "group_id_not_of_founding";

/// Why a `group:roster` payload fails the founding check (Verify 23.5.1's
/// `Invalid` arms, until the pin step re-exports them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// A member missing or not at its type, as the CDDL names it (`nonce`:
    /// absent or not 32 bytes on a first version, or present on a later
    /// one).
    Malformed {
        /// The member.
        member: &'static str,
    },
    /// The first version's `group` is not the id its own members derive.
    GroupIdNotOfFounding,
}

/// Is `s` a group-ref: [`GROUP_REF_PREFIX`] and one 43-character key-shaped
/// segment (zero trailing bits, one spelling per digest)?
#[must_use]
pub fn is_group_ref(s: &str) -> bool {
    s.strip_prefix(GROUP_REF_PREFIX)
        .is_some_and(crate::federation::namespace::key_segment::is_key_segment)
}

/// **The derived id** (Verify 23.5.1 `derive_group_id`). `founders` in any
/// order, repeated or not: they are encoded as a set.
#[must_use]
pub fn derive_group_id(
    group_kind: &str,
    founders: &[&str],
    founded_at: u64,
    nonce: &[u8; 32],
) -> String {
    let mut set: Vec<Value> = founders
        .iter()
        .map(|f| Value::Text((*f).to_owned()))
        .collect();
    set.sort_by_key(cde::encode);
    set.dedup();
    let input = Value::Array(vec![
        Value::Text(GROUP_ID_LABEL.to_owned()),
        Value::Text(group_kind.to_owned()),
        Value::Array(set),
        Value::Uint(founded_at),
        Value::Bytes(nonce.to_vec()),
    ]);
    let digest = sha2::Sha256::digest(cde::encode(&input));
    format!(
        "{GROUP_REF_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    )
}

/// **The founding check** (Verify 23.5.1 `check_group_roster_founding`),
/// over a `group:roster` payload. A first version (no `refs.head`) must carry
/// `group_kind` (text), `founded_at` (uint), `members` (each with an
/// identity-ref `key`), `group` (text) and a 32-byte `nonce`, and its
/// `group` must be the derived id; a later version must carry no `nonce` and
/// is otherwise judged as before (by `refs.head`). Pure.
///
/// # Errors
/// [`Invalid::Malformed`] naming the member; [`Invalid::GroupIdNotOfFounding`].
pub fn check_group_roster_founding(payload: &Value) -> Result<(), Invalid> {
    let malformed = |member: &'static str| Invalid::Malformed { member };
    let first = payload
        .get_text("refs")
        .and_then(|r| r.get_text("head"))
        .is_none();
    let nonce = payload.get_text("nonce");
    if !first {
        return match nonce {
            Some(_) => Err(malformed("nonce")),
            None => Ok(()),
        };
    }
    let kind = payload
        .get_text("group_kind")
        .and_then(Value::as_text)
        .ok_or(malformed("group_kind"))?;
    let founded_at = payload
        .get_text("founded_at")
        .and_then(Value::as_u64)
        .ok_or(malformed("founded_at"))?;
    let members = payload
        .get_text("members")
        .and_then(Value::as_array)
        .ok_or(malformed("members"))?;
    let founders = members
        .iter()
        .map(|m| {
            m.get_text("key")
                .and_then(Value::as_text)
                .filter(|k| ciris_verify_core::edition2::is_identity_ref(k))
                .ok_or(malformed("members"))
        })
        .collect::<Result<Vec<&str>, Invalid>>()?;
    let group = payload
        .get_text("group")
        .and_then(Value::as_text)
        .ok_or(malformed("group"))?;
    let nonce: [u8; 32] = nonce
        .and_then(Value::as_bytes)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or(malformed("nonce"))?;
    if derive_group_id(kind, &founders, founded_at, &nonce) == group {
        Ok(())
    } else {
        Err(Invalid::GroupIdNotOfFounding)
    }
}

/// **A fresh founding nonce** (GID-prod.fix1): 32 bytes straight from the OS
/// random source, `getrandom` 0.2 (the same copy `ring` already draws on; on
/// the wasm32 node build it is served by `ciris-host-abi`'s custom backend
/// over `ciris:node/random.fill`, CSPRNG bytes or a trap). This is the ONE
/// seam a founding draws through; a test replaces it for its own thread with
/// [`with_test_nonce`] (or passes a fixed nonce to
/// [`super::group::founding_payload`]).
///
/// # Errors
/// [`crate::federation::Error::Backend`] when the random source fails (no
/// weak fallback).
pub fn fresh_nonce() -> Result<[u8; 32], crate::federation::Error> {
    #[cfg(any(test, feature = "test-anchor"))]
    if let Some(n) = TEST_NONCE.with(std::cell::Cell::get) {
        return Ok(n);
    }
    let mut n = [0u8; 32];
    getrandom::getrandom(&mut n).map_err(|e| {
        crate::federation::Error::Backend(format!("group founding nonce: getrandom: {e}"))
    })?;
    Ok(n)
}

#[cfg(any(test, feature = "test-anchor"))]
thread_local! {
    static TEST_NONCE: std::cell::Cell<Option<[u8; 32]>> = const { std::cell::Cell::new(None) };
}

/// Test seam: run `f` with [`fresh_nonce`] answering `nonce` on THIS thread
/// (a current-thread runtime keeps the whole founding on it).
#[cfg(any(test, feature = "test-anchor"))]
pub fn with_test_nonce<R>(nonce: [u8; 32], f: impl FnOnce() -> R) -> R {
    TEST_NONCE.with(|c| c.set(Some(nonce)));
    let out = f();
    TEST_NONCE.with(|c| c.set(None));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "urn:ietf:params:oauth:ckt:sha-256:";

    fn known_founders() -> (String, String) {
        (
            format!("{P}{}", "A".repeat(43)),
            format!("{P}{}A", "B".repeat(42)),
        )
    }

    fn nonce() -> [u8; 32] {
        std::array::from_fn(|i| u8::try_from(i).expect("< 32"))
    }

    /// GID-prod — Constitution's, Verify's and the lead's known answer.
    #[test]
    fn the_known_group_ids() {
        let (a, b) = known_founders();
        let preimage = cde::encode(&Value::Array(vec![
            Value::Text(GROUP_ID_LABEL.into()),
            Value::Text("community".into()),
            Value::Array(vec![Value::Text(a.clone()), Value::Text(b.clone())]),
            Value::Uint(1_763_078_400_000),
            Value::Bytes(nonce().to_vec()),
        ]));
        assert_eq!(preimage.len(), 225);
        assert_eq!(hex::encode(&preimage[..13]), "856b4345472d67726f75702f32");
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&preimage)),
            "f1ecd4dd022aaab85345830078aa01c5d0cbde69af9809ca0b5ff0b2b9c9de12"
        );
        let community = derive_group_id("community", &[&a, &b], 1_763_078_400_000, &nonce());
        assert_eq!(
            community,
            "group-8ezU3QIqqrhTRYMAeKoBxdDL3mmvmAnKC1_wsrnJ3hI"
        );
        assert_eq!(
            derive_group_id("community", &[&b, &a, &b], 1_763_078_400_000, &nonce()),
            community,
            "founders are a set: order and repeats do not move the id"
        );
        assert_eq!(
            derive_group_id("family", &[&a, &b], 1_763_078_400_000, &nonce()),
            "group-ODjNYdkE6CL7viHGk4mFJRvuPtXGic_pxf-1iMrufE0"
        );
        assert!(is_group_ref(&community));
        assert!(!is_group_ref(&a), "a key's identity-ref is no group-ref");
        assert!(
            !is_group_ref("humanity-accord"),
            "a lineage name is no group-ref"
        );
    }

    fn member(k: &str) -> Value {
        Value::Map(vec![(Value::Text("key".into()), Value::Text(k.into()))])
    }

    fn first_version(group: &str, nonce: Option<Vec<u8>>, members: &[&str]) -> Value {
        let mut m = vec![
            (
                Value::Text("group_kind".into()),
                Value::Text("community".into()),
            ),
            (Value::Text("group".into()), Value::Text(group.into())),
            (
                Value::Text("founded_at".into()),
                Value::Uint(1_763_078_400_000),
            ),
            (
                Value::Text("members".into()),
                Value::Array(members.iter().map(|k| member(k)).collect()),
            ),
        ];
        if let Some(n) = nonce {
            m.push((Value::Text("nonce".into()), Value::Bytes(n)));
        }
        Value::Map(m)
    }

    /// GID-prod — the five known answers of the check (the `.md` carries
    /// their payload bytes as hex): valid; wrong id; missing nonce; a nonce
    /// on a later version; founders reordered → the same id.
    #[test]
    fn the_founding_check() {
        let (a, b) = known_founders();
        let id = derive_group_id("community", &[&a, &b], 1_763_078_400_000, &nonce());
        assert_eq!(
            check_group_roster_founding(&first_version(&id, Some(nonce().to_vec()), &[&a, &b])),
            Ok(())
        );
        let other = derive_group_id("family", &[&a, &b], 1_763_078_400_000, &nonce());
        assert_eq!(
            check_group_roster_founding(&first_version(&other, Some(nonce().to_vec()), &[&a, &b])),
            Err(Invalid::GroupIdNotOfFounding)
        );
        assert_eq!(
            check_group_roster_founding(&first_version(&id, None, &[&a, &b])),
            Err(Invalid::Malformed { member: "nonce" })
        );
        assert_eq!(
            check_group_roster_founding(&first_version(&id, Some(vec![0; 31]), &[&a, &b])),
            Err(Invalid::Malformed { member: "nonce" })
        );
        let Value::Map(mut later) = first_version(&id, Some(nonce().to_vec()), &[&a, &b]) else {
            unreachable!("a map")
        };
        later.push((
            Value::Text("refs".into()),
            Value::Map(vec![(
                Value::Text("head".into()),
                ciris_verify_core::edition2::row_ref(&[7; 32]),
            )]),
        ));
        assert_eq!(
            check_group_roster_founding(&Value::Map(later)),
            Err(Invalid::Malformed { member: "nonce" })
        );
        assert_eq!(
            check_group_roster_founding(&first_version(&id, Some(nonce().to_vec()), &[&b, &a])),
            Ok(()),
            "the members' order does not move the id"
        );
    }
}
