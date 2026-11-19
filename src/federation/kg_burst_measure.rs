//! MEASUREMENT ONLY (branch kg-burst-measure) — the cost of the CC "seat
//! door" burst: one minter minting a fresh community epoch and wrapping it to
//! 50 members x 3 occurrences = 150 recipients, plus emitting the
//! `key_grant:epoch:v1` rows; and the fill-in case (one newcomer, 3 devices).
//!
//! Every test is `#[ignore]`; run with `--ignored --nocapture`. Prints
//! `KGBURST` lines. Not a witness of anything.
//!
//! v62.0.0 (E3b) — edition 2: kids everywhere, each room ONE `group:roster`
//! version (T1 voices), each row an edition-2 statement (`produce_row` is
//! the "sign" split, `admit_produced` the "put"), and the minter node
//! member 0's by the OWNER RELATION (his owner binding + the node's own
//! self-occurrence, [`own_node`]), never an occurrence of a person
//! (`occurrence_binds_machine_to_person`). Member 0 is the SAME identity in
//! both rooms, so the node has one owner. Device seeds lead with their
//! distinguishing part (a signer seeds from a key id's first 32 bytes).

#[cfg(test)]
mod measure {
    use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::key_grant::{
        emit_key_grant_axis_with, plan_key_grant_emission, KeyGrantAxis,
    };
    use crate::federation::key_grant_fold_invariants::{found_room, occurrence, own_node};
    use crate::federation::key_grant_invariants::two_node::{node_as, Node};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{NODE, USER};
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

    /// A device of `ident` (seeds): the occurrence key is registered so
    /// `lookup_public_key` finds it (else the plan DEFERS the row). Every
    /// occurrence carries the node's own content-KEM pubkeys: the hybrid
    /// encapsulation costs the same for any recipient pubkey.
    async fn add_occurrence<B>(n: &Node<'_, B>, ident: &str, occ: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        occurrence(n, ident, occ, true).await;
    }

    /// Seed a room (seeds; every `members` key already live, registered once
    /// in [`one_run`]): `members` identities x `devices` devices, where
    /// member 0's first device is the minter node (his by the owner relation,
    /// bound once in [`one_run`]; nothing is written for it here).
    /// `extra_absent` adds roster members with no occurrence (the newcomer,
    /// seated later).
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
            for d in 0..devices {
                if i == 0 && d == 0 {
                    continue; // the minter node: owned, not an occurrence
                }
                add_occurrence(n, ident, &format!("dev{d}-{ident}")).await;
            }
        }
        for ident in extra_absent {
            ts::register_hybrid_key_as(n.backend, ident, ident, USER).await;
        }
        let roster: Vec<&str> = members
            .iter()
            .chain(extra_absent.iter())
            .map(String::as_str)
            .collect();
        found_room(n, comm, "burst room", &roster, chrono::Utc::now()).await;
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
    /// that is `emit_with_local_signer` split into sign / put.
    async fn emit_timed<B>(n: &Node<'_, B>, comm: &str, epoch: u64) -> Emit
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let axis = KeyGrantAxis::Epoch {
            community_key_id: e2::kid(comm),
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
        // v62.0.0 (E3b) — `emit_with_local_signer` (cut B: `emit_statement`)
        // split into sign (`produce_row`: the edition-2 statement) and put
        // (`admit_produced`: the statement door).
        // v62.0.0 (v62 P8 triage 2) — sign (the typed `key_grant:{axis}`
        // payload through `sign_row`) and put (the statement door), timed apart.
        let out = emit_key_grant_axis_with(backend, &key, &axis, |row, at_ms| {
            let (sign, put, signer) = (sign.clone(), put.clone(), signer.clone());
            async move {
                let t0 = Instant::now();
                let iss = signer.federation_id().await;
                let payload =
                    crate::federation::edition2::typed::key_grant_payload(&iss, &row, at_ms)?;
                let statement = crate::federation::edition2::produce::sign_row(
                    &signer,
                    &row.wrap.recipient_key_id,
                    crate::federation::types::attestation_type::SCORES,
                    &ciris_verify_core::namespace_match::family_id(
                        crate::federation::edition2::typed::KEY_GRANT_PREFIX,
                    ),
                    &payload,
                )
                .await
                .map_err(|e| crate::federation::edition2::emit::produce_error("key_grant", e))?;
                sign.set(sign.get() + t0.elapsed());
                let t1 = Instant::now();
                let out = crate::federation::edition2::ingest::put_statement_with_origin(
                    backend,
                    &statement,
                    None,
                    crate::federation::types::attestation_tier::FEDERATION,
                    crate::federation::replication::admission::WriteOrigin::Authored,
                )
                .await?;
                put.set(put.get() + t1.elapsed());
                use crate::federation::edition2::ingest::StatementOutcome as O;
                Ok(match out {
                    O::Row { row_id, .. }
                    | O::Voice { row_id, .. }
                    | O::KeyPlane { row_id, .. }
                    | O::Pending { row_id, .. } => row_id.hex(),
                })
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
        let alias = format!("kgb-minter-{rid}");
        let n = node_as(backend, &alias, NODE).await;
        let members: Vec<String> = (0..MEMBERS).map(|i| format!("kgb-m{i}-{rid}")).collect();
        for m in &members {
            ts::register_hybrid_key_as(backend, m, m, USER).await;
        }
        // Member 0 owns the minter node (one owner binding for both rooms).
        own_node(&n, &alias, &members[0]).await;

        // ── baseline: first seal into a 1-member, 1-device room ─────────
        let base_comm = format!("kgb-base-{rid}");
        seed_room(&n, &base_comm, &members[..1], 1, &[]).await;
        let t = Instant::now();
        let r =
            encrypt_and_cascade_community(backend, &e2::kid(&base_comm), b"x", None, Some(&n.key))
                .await
                .unwrap();
        let base_seal = t.elapsed();
        assert_eq!(r.granted.len(), 1);
        let base_emit = emit_timed(&n, &base_comm, r.epoch).await;
        assert_eq!(base_emit.rows, 1);

        // ── case 2: fresh epoch, 50 x 3 = 150 recipients ────────────────
        let comm = format!("kgb-room-{rid}");
        let comm_id = e2::kid(&comm);
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
        let r = encrypt_and_cascade_community(backend, &comm_id, b"x", None, Some(&n.key))
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
        let r = encrypt_and_cascade_community(backend, &comm_id, b"y", None, Some(&n.key))
            .await
            .unwrap();
        let seal_nochange = t.elapsed();
        assert!(!r.fanout_changed && r.epoch == epoch);

        // ── case 1: the newcomer's 3 devices appear; next seal fills in ─
        for d in 0..DEVICES {
            add_occurrence(&n, &newcomer, &format!("dev{d}-{newcomer}")).await;
        }
        let t = Instant::now();
        let r = encrypt_and_cascade_community(backend, &comm_id, b"z", None, Some(&n.key))
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
