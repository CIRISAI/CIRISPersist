//! MEASUREMENT ONLY (branch kg-burst-measure) — the cost of the CC "seat
//! door" burst: one minter minting a fresh community epoch and wrapping it to
//! 50 members x 3 occurrences = 150 recipients, plus emitting the
//! `key_grant:epoch:v1` rows; and the fill-in case (one newcomer, 3 devices).
//!
//! Every test is `#[ignore]`; run with `--ignored --nocapture`. Prints
//! `KGBURST` lines. Not a witness of anything.

#[cfg(test)]
mod measure {
    use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
    use crate::federation::key_grant::{
        emit_key_grant_axis_with, plan_key_grant_emission, KeyGrantAxis,
    };
    use crate::federation::key_grant_invariants::two_node::{node, Node};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::USER;
    use crate::federation::{BlobStorage, FederationDirectory};
    use std::cell::Cell;
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    const MEMBERS: usize = 50;
    const DEVICES: usize = 3;
    const RUNS: usize = 3;

    fn ms(d: Duration) -> f64 {
        d.as_secs_f64() * 1000.0
    }

    fn median(mut v: Vec<f64>) -> f64 {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[v.len() / 2]
    }

    async fn add_occurrence<B>(n: &Node<'_, B>, ident: &str, occ: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        // The occurrence key is registered so `lookup_public_key` finds it
        // (else the plan DEFERS the row). Every occurrence carries the node's
        // own content-KEM pubkeys: the hybrid encapsulation costs the same
        // for any recipient pubkey.
        if occ != n.key {
            ts::register_hybrid_key_as(n.backend, occ, occ, USER).await;
        }
        n.backend
            .put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                identity_key_id: ident.to_owned(),
                occurrence_key_id: occ.to_owned(),
                device_class: crate::federation::types::device_class::LAPTOP.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(n.kem.clone()),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap_or_else(|e| panic!("occurrence {occ} of {ident}: {e}"));
    }

    /// Seed a room: `members` identities x `devices` occurrences, member 0's
    /// first occurrence is the minter node. `extra_absent` adds roster
    /// members with no occurrence (the newcomer, seated later).
    async fn seed_room<B>(
        n: &Node<'_, B>,
        comm: &str,
        members: &[String],
        devices: usize,
        extra_absent: &[String],
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        ts::register_hybrid_key_as(n.backend, comm, comm, USER).await;
        for (i, ident) in members.iter().enumerate() {
            ts::register_hybrid_key_as(n.backend, ident, ident, USER).await;
            for d in 0..devices {
                let occ = if i == 0 && d == 0 {
                    n.key.clone()
                } else {
                    format!("{ident}-dev{d}")
                };
                add_occurrence(n, ident, &occ).await;
            }
        }
        for ident in extra_absent {
            ts::register_hybrid_key_as(n.backend, ident, ident, USER).await;
        }
        let roster = members
            .iter()
            .chain(extra_absent.iter())
            .map(|k| crate::federation::types::CommunityMember {
                key_id: k.clone(),
                joined_at: chrono::Utc::now(),
                role: None,
            })
            .collect();
        n.backend
            .put_community(ts::sign_community(
                comm,
                crate::federation::types::Community {
                    prev_head_digest: String::new(),
                    charter_digest: String::new(),
                    community_key_id: comm.to_owned(),
                    community_name: "burst room".into(),
                    members: roster,
                    founded_at: chrono::Utc::now(),
                    consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                        .to_owned(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .unwrap_or_else(|e| panic!("seed community {comm}: {e}"));
    }

    #[derive(Default, Debug, Clone)]
    struct Emit {
        plan: Duration,
        total: Duration,
        sign: Duration,
        put: Duration,
        rows: usize,
        row_bytes: Vec<usize>,
        env_bytes: Vec<usize>,
    }

    /// Plan (timed separately, read-only), then the real emission
    /// (`emit_key_grant_axis_with`, the Engine's door) with an `emit_one`
    /// that is `emit_with_local_signer` split into sign / assemble+put.
    async fn emit_timed<B>(n: &Node<'_, B>, comm: &str, epoch: u64) -> Emit
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let axis = KeyGrantAxis::Epoch {
            community_key_id: comm.to_owned(),
            minter_key_id: n.key.clone(),
            epoch,
        };
        let t = Instant::now();
        let plan = plan_key_grant_emission(n.backend, &n.key, &axis)
            .await
            .unwrap()
            .expect("plan");
        let plan_t = t.elapsed();
        assert!(plan.sealer_refused.is_none(), "{plan:?}");
        let sign = Rc::new(Cell::new(Duration::ZERO));
        let put = Rc::new(Cell::new(Duration::ZERO));
        let signer = n.signer.clone();
        let key = n.key.clone();
        let backend = n.backend;
        let t = Instant::now();
        let out = emit_key_grant_axis_with(backend, &key, &axis, |mut input| {
            let (sign, put, signer, key) = (sign.clone(), put.clone(), signer.clone(), key.clone());
            async move {
                let t0 = Instant::now();
                let canonical = crate::federation::attestation_emit::stamp_and_canonicalize(
                    &mut input,
                    &key,
                    chrono::Utc::now(),
                )?;
                let sig = signer
                    .sign_hybrid(&canonical)
                    .await
                    .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
                sign.set(sign.get() + t0.elapsed());
                let t1 = Instant::now();
                let e = crate::federation::attestation_emit::assemble_and_put(
                    backend, key, &canonical, sig, input,
                )
                .await?;
                put.set(put.get() + t1.elapsed());
                Ok(e.attestation_id)
            }
        })
        .await
        .unwrap()
        .expect("emission");
        let total = t.elapsed();
        assert!(
            out.deferred.is_empty() && out.withheld.is_empty(),
            "{out:?}"
        );
        let mut row_bytes = Vec::new();
        let mut env_bytes = Vec::new();
        for id in &out.attestation_ids {
            let row = n.backend.get_attestation(id).await.unwrap().unwrap();
            row_bytes.push(serde_json::to_vec(&row).unwrap().len());
            env_bytes.push(serde_json::to_vec(&row.attestation_envelope).unwrap().len());
        }
        Emit {
            plan: plan_t,
            total,
            sign: sign.get(),
            put: put.get(),
            rows: out.attestation_ids.len(),
            row_bytes,
            env_bytes,
        }
    }

    async fn one_run<B>(backend: &B, tag: &str, run: usize)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let rid = uuid::Uuid::new_v4().simple().to_string();
        let n = node(backend, &format!("kgb-minter-{rid}")).await;

        // ── baseline: first seal into a 1-member, 1-device room ─────────
        let base_comm = format!("kgb-base-{rid}");
        seed_room(&n, &base_comm, &[format!("kgb-solo-{rid}")], 1, &[]).await;
        let t = Instant::now();
        let r = encrypt_and_cascade_community(backend, &base_comm, b"x", None, Some(&n.key))
            .await
            .unwrap();
        let base_seal = t.elapsed();
        assert_eq!(r.granted.len(), 1);
        let base_emit = emit_timed(&n, &base_comm, r.epoch).await;
        assert_eq!(base_emit.rows, 1);

        // ── case 2: fresh epoch, 50 x 3 = 150 recipients ────────────────
        let comm = format!("kgb-room-{rid}");
        let members: Vec<String> = (0..MEMBERS).map(|i| format!("kgb-m{i}-{rid}")).collect();
        let newcomer = format!("kgb-new-{rid}");
        let t = Instant::now();
        seed_room(
            &n,
            &comm,
            &members,
            DEVICES,
            std::slice::from_ref(&newcomer),
        )
        .await;
        let seed_t = t.elapsed();
        let t = Instant::now();
        let r = encrypt_and_cascade_community(backend, &comm, b"x", None, Some(&n.key))
            .await
            .unwrap();
        let seal150 = t.elapsed();
        assert_eq!(r.granted.len(), MEMBERS * DEVICES, "granted");
        assert!(r.fanout_changed);
        let epoch = r.epoch;
        let e150 = emit_timed(&n, &comm, epoch).await;
        assert_eq!(e150.rows, MEMBERS * DEVICES, "rows");

        // A no-change seal in the same epoch (the content-seal floor).
        let t = Instant::now();
        let r = encrypt_and_cascade_community(backend, &comm, b"y", None, Some(&n.key))
            .await
            .unwrap();
        let seal_nochange = t.elapsed();
        assert!(!r.fanout_changed && r.epoch == epoch);

        // ── case 1: the newcomer's 3 devices appear; next seal fills in ─
        for d in 0..DEVICES {
            add_occurrence(&n, &newcomer, &format!("{newcomer}-dev{d}")).await;
        }
        let t = Instant::now();
        let r = encrypt_and_cascade_community(backend, &comm, b"z", None, Some(&n.key))
            .await
            .unwrap();
        let seal_fill = t.elapsed();
        assert!(
            r.fanout_changed && r.epoch == epoch,
            "fill-in stays in epoch"
        );
        let e_fill = emit_timed(&n, &comm, epoch).await;
        assert_eq!(e_fill.rows, DEVICES, "fill-in rows");

        // ── microbenches: 150 hybrid wraps, 150 member-grant inserts ────
        let dek = crate::federation::at_rest_cascade::fresh_dek().unwrap();
        let t = Instant::now();
        let mut wraps = Vec::with_capacity(150);
        for _ in 0..MEMBERS * DEVICES {
            wraps.push(
                crate::federation::at_rest_cascade::wrap_dek_v2(
                    &n.kem.x25519_base64,
                    &n.kem.ml_kem_768_base64,
                    &dek,
                )
                .unwrap(),
            );
        }
        let wrap150 = t.elapsed();
        let t = Instant::now();
        for (i, w) in wraps.iter().enumerate() {
            backend
                .community_dek_put_member_grant(
                    &format!("kgb-scratch-{rid}"),
                    &n.key,
                    0,
                    &format!("kgb-scratch-occ{i}"),
                    crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2,
                    w,
                )
                .await
                .unwrap();
        }
        let grant_put150 = t.elapsed();

        let row = median(e150.row_bytes.iter().map(|&b| b as f64).collect());
        let env = median(e150.env_bytes.iter().map(|&b| b as f64).collect());
        println!(
            "KGBURST {tag} run={run} seed_ms={:.1} base_seal_ms={:.2} base_emit_ms={:.2} \
             seal150_ms={:.2} emit150_ms={:.2} emit150_plan_ms={:.2} emit150_sign_ms={:.2} \
             emit150_put_ms={:.2} rows150={} seal_nochange_ms={:.2} seal_fill_ms={:.2} \
             emit_fill_ms={:.2} emit_fill_plan_ms={:.2} emit_fill_sign_ms={:.2} \
             emit_fill_put_ms={:.2} rows_fill={} wrap150_ms={:.2} grant_put150_ms={:.2} \
             row_bytes_median={row} row_bytes_min={} row_bytes_max={} env_bytes_median={env} \
             wrap_json_bytes={}",
            ms(seed_t),
            ms(base_seal),
            ms(base_emit.total),
            ms(seal150),
            ms(e150.total),
            ms(e150.plan),
            ms(e150.sign),
            ms(e150.put),
            e150.rows,
            ms(seal_nochange),
            ms(seal_fill),
            ms(e_fill.total),
            ms(e_fill.plan),
            ms(e_fill.sign),
            ms(e_fill.put),
            e_fill.rows,
            ms(wrap150),
            ms(grant_put150),
            e150.row_bytes.iter().min().unwrap(),
            e150.row_bytes.iter().max().unwrap(),
            wraps[0].len(),
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    #[ignore = "measurement"]
    async fn kg_burst_sqlite_file() {
        use crate::store::Backend as _;
        for run in 0..RUNS {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("kgb.db");
            let b = crate::store::sqlite::SqliteBackend::open(p.to_string_lossy().to_string())
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            one_run(&b, "sqlite-file", run).await;
        }
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[ignore = "measurement"]
    async fn kg_burst_postgres() {
        use crate::store::Backend as _;
        for run in 0..RUNS {
            let dsn = crate::test_pg::empty_dsn().expect("CIRIS_PERSIST_TEST_PG_URL");
            let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .unwrap();
            b.run_migrations().await.unwrap();
            one_run(&b, "postgres", run).await;
        }
    }
}
