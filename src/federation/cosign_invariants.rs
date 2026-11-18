//! v61.3.0 (CIRISPersist#1252; CC 3.3.4 step 2, CC 3.1.3 `cosign:{state}`,
//! CC 2.4, CC 4.5.13; `CLM-cosign-collection-held`) — **I1730–I1743: the
//! cosign hold**, on sqlite and postgres.
//!
//! Each witness names the hand-mutation that turns it red (run once, by hand,
//! against a committed checkpoint; the release notes carry the table).
//!
//! - **I1730** a short widening at the primary's local door is held: the
//!   roster is unchanged, the door returns `RosterChangeNotLanded`, the
//!   pending row is held under its quorum key with an open receipt.
//! - **I1731** a short event that ANOTHER check also refuses is refused
//!   exactly as before (the missing acceptance of a growth; the last-founder
//!   rule): `roster_consensus_insufficient`, and nothing held.
//! - **I1732** only the local door of the primary's node holds: the same
//!   short event at a non-primary node's local door, or arriving replicated,
//!   holds nothing.
//! - **I1733** one open hold per proposer per group.
//! - **I1734** a stranger cannot fill a hold; a self-roster assent is never
//!   read as a cosignature.
//! - **I1735** the audience of a cosign row: the group's active members at the
//!   event's instant, in a public room too; the invitee is not served it, the
//!   member a removal names is.
//! - **I1736** two nodes assemble one act from different subsets with
//!   different ML-DSA bytes: both land, carry equal wire hashes, and each
//!   other's offer settles `held_equivalent` (no refusal booked; a second diff
//!   round offers nothing).
//! - **I1737** expiry drops only the pending and signature rows; the assembled
//!   event still lands after expiry; a settled hold's re-offer is refused.
//! - **I1738** the proposer's `withdraws` of the pending row ends it; a
//!   `withdraws` of a signature row is refused.
//! - **I1739** (deleted v62.0.0, slice E6) witnessed the v61.2 -> v61.3
//!   re-key of a pre-cut cosigned row's JCS wire ref at open: an upgrade path
//!   of the earlier store, which v62 does not carry.
//! - **I1740** one hash derivation: the point read resolves the act's ref and
//!   not `sha256(bytes)`, and no attestation ref is taken anywhere else.
//! - **I1741** the executor lands once the protocol is met, through the
//!   admission hook and through the sweep alone; an `open:self_admit` removal's
//!   window is read against the hold's first receipt.
//! - **I1742** withdraws by id: a cosigned `withdraws` naming another node's
//!   row of the same act retracts the act here through the alias; before the
//!   alias it is the retryable `federation_withdraws_target_unheld`.
//! - **I1743** the window policy: under the floor refused, the default
//!   applies.
//! - **I1744** freshness W on cosign rows: a since-removed member's row
//!   signed more than W before receipt is `asserted_at_stale`; inside W it is
//!   judged as any member's; a member still standing signs at any age.
//! - **I1748** (v61.4.0, CIRISPersist#1250) a short refusal carries the
//!   door's count: `have`, `need` and the eligible signers, under
//!   `roster_consensus_insufficient` only.

//!
//! v62.0.0 (wave 3, slice E6) — **the store witnesses are deleted** (I1730–
//! I1738, I1740 round trip, I1741–I1744, I1748, I1751; I1739 earlier). They
//! witness the earlier form's cosign HOLD at the JSON group door: a short
//! roster change held as a JSON pending row under a quorum key, with a
//! receipt, a primary-node rule, one open hold per proposer, signature rows
//! carrying ML-DSA cosignature bytes, an expiry and window policy, a
//! withdraws-by-alias and the JCS wire ref of the assembled act. An edition-2
//! group change is counted voices at `put_statement` (T1): a short change is
//! `StatementOutcome::Pending` with its voices kept, and it lands the moment
//! the voices meet the protocol; `cosign::hold_if_short` holds no
//! earlier-form object any more (T1.md). The surviving properties are T1's
//! witnesses: the shortfall is kept and absent (I1730 → T1 I2994 v2 at 1/3,
//! I2998 a removal short of majority `Pending` and absent), the change lands
//! once the protocol is met (I1741 → I2993/I2994 Pending → Row, I2998 the
//! meeting voice through `apply_replicated_statement` → `Admitted(Row)`; I1736
//! two subsets, likewise), and another refusal still refuses (I1731 →
//! I2999, `membership_acceptance_unresolved`). NOT carried, flagged for the
//! group-plane owner: I1744's freshness W on a since-removed member's late
//! voice, and I1748's have/need count on a short change (`Pending` carries
//! none). I1740 from disk stays while the wire index keeps its derivation.
#[cfg(test)]
mod from_disk {
    //! **I1740 (from disk)** — one hash derivation: every attestation ref the
    //! wire index takes, and every backend's point-read self-check, goes
    //! through `attestation_wire_hash` / `reload_record_hashed`.

    fn read(rel: &str) -> String {
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
            .unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    fn code(src: &str) -> String {
        src.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Mutation: `all_kind_hash_keys` hashes `content_hash_of(&a.attestation)`
    /// again → red.
    #[test]
    fn i1740_one_hash_derivation_from_disk() {
        let wire = code(&read("src/federation/wire_index.rs"));
        let prod = wire.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "content_hash_of(&a)",
            "content_hash_of(&row)",
            "content_hash_of(&a.attestation)",
        ] {
            assert!(
                !prod.contains(forbidden),
                "I1740: wire_index.rs takes an attestation ref as {forbidden}"
            );
        }
        assert!(
            prod.matches("attestation_wire_hash_hex(&").count() >= 4,
            "I1740: the rebuild, the subject refs and the reload each use the one rule"
        );
        assert!(prod.contains("reload_record_hashed(dir, kind, record_key_json)"));
        for backend in ["src/store/sqlite.rs", "src/store/postgres.rs"] {
            let src = code(&read(backend));
            assert!(
                src.contains("wire_index::reload_record_hashed(self, kind, &record_key)"),
                "I1740: {backend}'s point-read self-check asks the one derivation"
            );
            assert!(
                !src.contains(
                    "let recomputed = crate::federation::wire_index::content_hash_of_bytes"
                ),
                "I1740: {backend} recomputes a ref of its own"
            );
        }
    }
}
