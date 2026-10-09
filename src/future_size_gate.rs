//! v54.0.0 (CIRISPersist#1017) — **I578: persist's public async doors stay
//! under `clippy::large_futures`' 16 KiB threshold.** CIRISEdge, gating
//! v53.1.8, found two futures over it at its own call sites: its inbound
//! dispatch awaiting the consent gate (~19 KB) and
//! `trust_root::resolve_serve_tier` (~29 KB). Every caller would otherwise
//! box them. The cause was the fold wrapper (`observe::fold`, #1014): each
//! nested fold kept its whole inner future inline, so serve tier →
//! trust_root_valid → owner_granted_scope stacked. `observe::fold` now boxes
//! the future it wraps, and the doors are measured here with
//! `std::mem::size_of_val` on the un-polled future, the size the caller's
//! state machine embeds. The lint itself runs in CI over the lib
//! (`-D clippy::large_futures`), which covers every await INSIDE persist; this
//! test covers the futures persist hands OUT, which the lint cannot see.

/// `clippy::large_futures`' default `future-size-threshold`, the one Edge hit.
#[cfg(test)]
pub(crate) const LARGE_FUTURE_BYTES: usize = 16 * 1024;

#[cfg(test)]
mod tests {
    use super::LARGE_FUTURE_BYTES;
    use crate::federation::admission::ConsentGatedFamily;
    use crate::federation::FederationDirectory;

    /// Every measured door, `(name, bytes)`, printed so a regression names
    /// itself and the CHANGELOG can quote the numbers.
    fn assert_all_under(sizes: &[(&str, usize)]) {
        for (name, n) in sizes {
            eprintln!("I578 {name}: {n} bytes");
        }
        let over: Vec<_> = sizes
            .iter()
            .filter(|(_, n)| *n >= LARGE_FUTURE_BYTES)
            .collect();
        assert!(
            over.is_empty(),
            "I578: public futures at or over {LARGE_FUTURE_BYTES} bytes (clippy::large_futures): \
             {over:?}"
        );
    }

    /// The free doors, over the memory backend (no I/O happens: the futures
    /// are built and measured, never polled).
    #[test]
    fn i578_free_doors_over_a_directory() {
        use crate::federation::{admission, consent_by_humans as cbh, trust_root};
        let m = crate::store::memory::MemoryBackend::new();
        let d: &dyn FederationDirectory = &m;
        let now = chrono::Utc::now();
        let row = crate::federation::tier_ingest::test_support::bare_attestation(
            "i578",
            "a",
            "b",
            &serde_json::json!({}),
        );
        let sizes = [
            (
                "trust_root::resolve_serve_tier<MemoryBackend>",
                std::mem::size_of_val(&trust_root::resolve_serve_tier(&m, "k", "k")),
            ),
            (
                "trust_root::resolve_serve_tier<dyn>",
                std::mem::size_of_val(&trust_root::resolve_serve_tier(d, "k", "k")),
            ),
            (
                "consent_by_humans::capacity_consent_stance",
                std::mem::size_of_val(&cbh::capacity_consent_stance(
                    d,
                    "a",
                    "b",
                    ConsentGatedFamily::Capacity,
                    now,
                )),
            ),
            (
                "consent_by_humans::resolve_scoped_stance_by_principals",
                std::mem::size_of_val(&cbh::resolve_scoped_stance_by_principals(
                    d, "a", "b", "analyze", None, now,
                )),
            ),
            (
                "consent_by_humans::retain_bound_by_principals",
                std::mem::size_of_val(&cbh::retain_bound_by_principals(d, "a", "b", now)),
            ),
            (
                "admission::check_capacity_consent_admission",
                std::mem::size_of_val(&admission::check_capacity_consent_admission(d, &row)),
            ),
            (
                "admission::steward_bindings_of",
                std::mem::size_of_val(&admission::steward_bindings_of(d, "k")),
            ),
            (
                "FederationDirectory::put_attestation",
                std::mem::size_of_val(&d.put_attestation(crate::federation::SignedAttestation {
                    attestation: row.clone(),
                })),
            ),
        ];
        assert_all_under(&sizes);
    }

    /// The Engine doors over the same folds (sqlite; built, never polled).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i578_engine_doors() {
        let e = crate::Engine::with_signer(
            crate::federation::tier_ingest::test_support::local_signer("i578-engine"),
            "sqlite::memory:",
        )
        .await
        .expect("engine");
        let now = chrono::Utc::now();
        let sizes = [
            (
                "Engine::hold_breadth",
                std::mem::size_of_val(&e.hold_breadth()),
            ),
            (
                "Engine::capacity_consent_stance",
                std::mem::size_of_val(&e.capacity_consent_stance(
                    "a",
                    "b",
                    ConsentGatedFamily::Capacity,
                    now,
                )),
            ),
            (
                "Engine::resolve_scoped_stance_by_principals",
                std::mem::size_of_val(
                    &e.resolve_scoped_stance_by_principals("a", "b", "analyze", None, now),
                ),
            ),
            (
                "Engine::steward_bindings_of",
                std::mem::size_of_val(&e.steward_bindings_of("k")),
            ),
        ];
        assert_all_under(&sizes);
    }
}
