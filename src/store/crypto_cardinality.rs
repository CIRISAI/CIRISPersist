//! CIRISPersist#789 — **crypto material must declare what it is keyed by.**
//!
//! # The defect this exists to prevent recurring
//!
//! `trace_events` carried a key-scoped pubkey and a thought-scoped signature
//! once per EVENT row. On the live canonical that was **679 MB of an 898 MB
//! table** wrapped around 80 MB of actual trace payload — 99.7% and 93.2%
//! redundant respectively.
//!
//! Nothing noticed when the columns were added. It surfaced three releases
//! later as a read API going deaf after ~22h, a thread parked in `D` state on
//! `wait_on_page_bit_common`, because the working set stopped fitting page
//! cache (1,887 MB against ~1,500 MB available; 1,208 MB deduplicated). An
//! availability incident standing in for a schema-review comment.
//!
//! # The class, stated correctly
//!
//! It is **not** "crypto stored inline". `federation_attestations` holds
//! 16,010 distinct signatures over 16,471 rows — genuinely per-row, entirely
//! correct, and a gate phrased as "no inline crypto" would have swept it up
//! and made the real defect harder to see.
//!
//! The class is **material whose natural key differs from the row's, with
//! nothing that notices.**
//!
//! # Why a DECLARATION gate rather than a cardinality measurement
//!
//! Measuring `COUNT(DISTINCT col) / COUNT(*)` is the obvious gate and it is
//! the wrong one to rely on, because it only fires where there is production
//! data. On an empty CI database every ratio is `0/0`, so the check passes
//! vacuously in exactly the environment that gates a merge — a check that
//! cannot fail is a report.
//!
//! This gate instead makes the author answer *"keyed by what?"* at the moment
//! the column is added. Declaring `trace_events.signature_ml_dsa_65` as
//! per-row would have been visibly false to anyone writing it down, and
//! declaring it as `shared_by: thought_id` would have prompted the obvious
//! next question. The 679 MB existed because nobody was ever asked.
//!
//! # The per-row fact that must NOT be lost with the bytes
//!
//! Deduplicating by `thought_id` alone silently changes what a row MEANS. A
//! thought can contain both a hybrid-signed trace and a classical-only
//! `2.7.legacy` import — they share a `thought_id` — so a naive
//! `JOIN … USING (thought_id)` hands the legacy row the hybrid trace's
//! signature and it reads back as PQC-signed when it never was.
//!
//! That is information loss in the DANGEROUS direction: it makes unsigned
//! material look signed, which is precisely the distinction the #225
//! trace-tier hard cut exists to enforce and audit. The measurement in #789 —
//! 7,264 signatures over 7,264 thoughts, none spanning two — says the
//! signature is a total function of `thought_id`. It does NOT say every event
//! of a thought carried one.
//!
//! So the read is gated on the row's OWN `pqc_key_id`, which is retained
//! per-row and is exactly the "was this event PQC-signed" bit. The
//! deduplication removes the redundant BYTES and keeps the non-redundant
//! FACT. Caught by `trace_hybrid_hard_cut`, which had both traces on one
//! thought.
//!
//! # Known limitation (CIRISPersist#691)
//!
//! This reads the migration files from disk while it runs, so it is not
//! hermetic against the tree changing underneath it, and its failure
//! direction is toward a PASS. That is the standing weakness #691 tracks for
//! `parity.rs` and `schema_parity.rs`; this gate inherits it rather than
//! inventing a new one, and should move with them when that is fixed.

/// One crypto-bearing column, and the key its material actually belongs to.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CryptoColumn {
    /// The table the column is declared on.
    pub table: &'static str,
    /// The column carrying signature or key material.
    pub column: &'static str,
    /// `None` — genuinely one value per row.
    /// `Some(key)` — deliberately shared, and this names what by.
    pub shared_by: Option<&'static str>,
}

/// Substrings that mark a column as carrying crypto material.
///
/// Deliberately broad: a false positive costs one line of declaration, while
/// a false negative costs what #789 cost.
pub(crate) const CRYPTO_COLUMN_MARKERS: &[&str] = &[
    "signature_ml_dsa_65",
    "pubkey_ml_dsa_65",
    "scrub_signature_pqc",
];

/// Every crypto column this crate stores, with the key it is scoped to.
///
/// **APPEND when a table gains one.** The test below fails if a column
/// matching [`CRYPTO_COLUMN_MARKERS`] appears in a migration and is not
/// declared here, which is the whole mechanism: the gate is this list.
pub(crate) const CRYPTO_COLUMNS: &[CryptoColumn] = &[
    // ── PER-ROW by construction ──────────────────────────────────────
    //
    // `scrub_signature_pqc` is the scrub signature OF THAT ROW'S RECORD, so
    // its natural key IS the row's key — one signature per record, never
    // shared. `pubkey_ml_dsa_65` on a key/peer row is that row's OWN key, for
    // the same reason. Measured where it mattered:
    // `federation_attestations` carries 16,010 distinct signatures over
    // 16,471 rows, which is what a genuinely per-row crypto column looks
    // like, and is precisely why #789's root is cardinality MISMATCH rather
    // than "crypto stored inline" — the latter phrasing would have condemned
    // every row below.
    CryptoColumn {
        table: "_v114_stage_fa",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "_v117_stage_fa",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "announced_peers",
        column: "pubkey_ml_dsa_65",
        shared_by: None,
    },
    CryptoColumn {
        table: "cirisnode_contributions",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "cirisnode_moderation_events",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "cirisnode_promotion_attestations",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "cirisnode_reconsideration_attestations",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "cirisnode_reconsideration_requests",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "cirisnode_slashing_attestations",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "cirisnode_votes",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "content_manifest",
        column: "signature_ml_dsa_65",
        shared_by: None,
    },
    CryptoColumn {
        table: "federation_attestations",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "federation_attestations",
        column: "signature_ml_dsa_65",
        shared_by: None,
    },
    CryptoColumn {
        table: "federation_communities",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "federation_communities_new",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "federation_community_membership_revocations",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "federation_families",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "federation_family_membership_revocations",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "federation_keys",
        column: "pubkey_ml_dsa_65",
        shared_by: None,
    },
    CryptoColumn {
        table: "federation_keys",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "federation_location_proofs",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "federation_revocations",
        column: "scrub_signature_pqc",
        shared_by: None,
    },
    CryptoColumn {
        table: "wholeness_witness_corpus",
        column: "signature_ml_dsa_65",
        shared_by: None,
    },
    // ── DELIBERATELY SHARED, with the key it is shared by ────────────
    //
    // CIRISPersist#789 — signing is batched per THOUGHT, so this signature
    // covers a thought and belongs on a table keyed by one. It previously
    // rode every EVENT row of that thought: 447 MB stored for 30.5 MB of
    // unique material, 93.2% redundant.
    CryptoColumn {
        table: "trace_thought_signatures",
        column: "signature_ml_dsa_65",
        shared_by: Some("thought_id"),
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Every crypto column in the SQLite schema is declared in
    /// [`CRYPTO_COLUMNS`].
    ///
    /// The failure this catches is the one that produced #789: adding
    /// signature or key material to a table without stating what it is keyed
    /// by. The message names the column and asks the question directly,
    /// because the answer is the fix — if the honest answer is "shared with
    /// every row of a thought", the column belongs on a per-thought table, not
    /// on the event.
    #[test]
    fn every_crypto_column_declares_its_natural_key_789() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations/sqlite/lens");
        let mut found: BTreeSet<(String, String)> = BTreeSet::new();

        let mut files: Vec<_> = std::fs::read_dir(dir)
            .expect("migrations dir readable")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "sql"))
            .collect();
        files.sort();

        // Track the table each statement is talking about, so a marker column
        // is attributed to the right one. CREATE TABLE and ALTER TABLE … ADD
        // COLUMN are the two shapes that introduce a column here.
        for path in files {
            let sql = std::fs::read_to_string(&path).expect("migration readable");
            let mut current = String::new();
            for line in sql.lines() {
                let t = line.trim();
                if t.starts_with("--") {
                    continue;
                }
                if let Some(rest) = t.strip_prefix("CREATE TABLE IF NOT EXISTS ") {
                    current = rest.split_whitespace().next().unwrap_or("").to_owned();
                } else if let Some(rest) = t.strip_prefix("CREATE TABLE ") {
                    current = rest.split_whitespace().next().unwrap_or("").to_owned();
                } else if let Some(rest) = t.strip_prefix("ALTER TABLE ") {
                    current = rest.split_whitespace().next().unwrap_or("").to_owned();
                }
                for marker in CRYPTO_COLUMN_MARKERS {
                    if t.contains(marker) && !current.is_empty() {
                        // A DROP retires the column: the migrations are a
                        // HISTORY, and a gate that read only the adds would
                        // keep demanding a declaration for material no longer
                        // stored — and, worse, would report #789's own fix as
                        // an outstanding violation.
                        if t.contains("DROP COLUMN") {
                            found.remove(&(current.clone(), (*marker).to_owned()));
                        } else {
                            found.insert((current.clone(), (*marker).to_owned()));
                        }
                    }
                }
            }
        }

        let declared: BTreeSet<(String, String)> = CRYPTO_COLUMNS
            .iter()
            .map(|c| (c.table.to_owned(), c.column.to_owned()))
            .collect();

        let undeclared: Vec<&(String, String)> = found.difference(&declared).collect();
        assert!(
            undeclared.is_empty(),
            "CIRISPersist#789 — crypto column(s) with no declared natural key: \
             {undeclared:?}.\n\nAdd each to CRYPTO_COLUMNS saying what it is keyed \
             by. If the honest answer is that every row of some larger unit \
             carries the SAME value, the column belongs on a table keyed by that \
             unit — not on this row. That question going unasked is what put \
             679 MB of duplicated signatures and pubkeys into an 898 MB \
             trace_events, and it surfaced as a read API stalling three \
             releases later, not as a schema review comment."
        );
    }

    /// A column declared **shared** must name a key that is not the row's own
    /// identity — otherwise the declaration is decoration.
    ///
    /// `shared_by` exists to make the author answer *"shared with what?"*, and
    /// a gate that stored the answer without ever reading it would be exactly
    /// the kind of unchecked assertion this module was written to stop. Caught
    /// by `dead_code` on the field, which is the compiler making the same
    /// point.
    #[test]
    fn a_shared_declaration_names_a_real_grouping_key_789() {
        for c in CRYPTO_COLUMNS {
            let Some(key) = c.shared_by else { continue };
            assert!(
                !key.is_empty(),
                "#789: {}.{} is declared shared by an empty key",
                c.table,
                c.column
            );
            // The whole point of the declaration is that the material's
            // natural key is COARSER than the row. A column "shared by" the
            // thing that identifies its own row is per-row, and should say so
            // with `None` rather than dress it up.
            assert_ne!(
                key, c.column,
                "#789: {}.{} declares itself shared by its own column — if the \
                 material really is one value per row, declare `None`",
                c.table, c.column
            );
            assert!(
                key.ends_with("_id"),
                "#789: {}.{} is declared shared by {key:?}, which does not look \
                 like a grouping key. The declaration has to name the unit the \
                 material actually covers (a thought, a key, a record), because \
                 that name is what a reviewer checks against the table it sits on",
                c.table,
                c.column
            );
        }
    }

    /// The two #789 columns are GONE from `trace_events`.
    ///
    /// Asserted against the migration text rather than trusted from the
    /// changelog: the whole point of the cut is that they stopped being
    /// per-event, and a re-add would reintroduce 679 MB silently.
    #[test]
    fn trace_events_no_longer_carries_per_event_crypto_789() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations/sqlite/lens");
        let mut adds = 0usize;
        let mut drops = 0usize;
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .expect("dir")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "sql"))
            .collect();
        files.sort();
        for path in files {
            let sql = std::fs::read_to_string(&path).expect("readable");
            for line in sql.lines() {
                let t = line.trim();
                if t.starts_with("--") || !t.contains("trace_events") {
                    continue;
                }
                if t.contains("ADD COLUMN") && t.contains("_ml_dsa_65") {
                    adds += 1;
                }
                if t.contains("DROP COLUMN") && t.contains("_ml_dsa_65") {
                    drops += 1;
                }
            }
        }
        assert_eq!(
            adds, drops,
            "CIRISPersist#789: trace_events has {adds} per-event ML-DSA column \
             add(s) and {drops} drop(s). They must balance — a re-added \
             per-event signature or pubkey is 679 MB of duplication returning, \
             and it will present as an availability incident rather than a \
             schema question"
        );
    }
}
