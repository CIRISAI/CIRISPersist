//! v62.0.0 (GB-fix1; CC 2.6.1.11, CC 5.3.4, CC 3.2 T3) — **the REAL genesis,
//! baked byte-for-byte, imports at the final pins.**
//!
//! The ceremony package `ciris-genesis-2026-11-21-public` (bundle
//! `cb9ada31…deb5`, `humanity-accord` v1, t0 1795302284535 ms, holders
//! A1/B1/C1 on YubiKey 5 FIPS, one serve seat `canonical-1`) is vendored
//! twice: its eight statement files as they are
//! (`baked/humanity-accord-v1/*.cose`), and ONE CDE array of them in put
//! order (`baked/humanity-accord-genesis-v1.cbor`, the `BAKED_BUNDLES`
//! entry). The pure legs are judged at a pinned instant ([`pinned_at`], an
//! hour after t0; standing two hours after). The import door's only clock
//! read is the seat binding's skew bound (not ahead of the node's clock), so
//! the import legs hold on any clock after t0. No leg reads the wall clock in
//! an assertion.
//!
//! - **I2468** (pure) the bytes are the ceremony's: each vendored file's
//!   SHA-256 is the recorded value (`BAKED_GENESIS_STATEMENTS`); the framed
//!   entry decodes to exactly those eight byte strings in that order, and
//!   framing them again gives the entry byte-for-byte (the framing is all
//!   persist added); the pinned anchor is the object id the voices name; the
//!   bake gate (`check_baked_bundle`, its seat-dialable rule included)
//!   places ONE bundle: `humanity-accord`, version 1, no prev, asserted at
//!   t0, the three holders of `terms.json`, one seat with a tcp hint. Server's
//!   anchor form (the holders' thumbprints) places the same bundle; no anchor
//!   places nothing.
//! - **I2469** (sqlite, postgres) a fresh store imports it through the real
//!   door (`import_baked_genesis` → `put_genesis_bundle`): one bundle placed,
//!   the three holders in force, one seat with a route, a root grant counted
//!   2 of 3; a second import offers nothing and changes nothing; a store
//!   that holds another bundle is left as it is.
//! - **I2470** (sqlite, postgres) the Engine's open leg on a fresh node, at
//!   pinned instants: imported, still ROOTLESS (baking is not accepting); a
//!   reopen places nothing; the node's acceptance of `humanity-accord`
//!   (`accept_root_draft`, the builder `accept_root` uses) lands and the
//!   node reads rooted through its own edge.
//! - **I2471** (sqlite, postgres) the open leg's failure: a CORRUPTED COPY
//!   (one byte of a voice's signature flipped; the baked bytes untouched) is
//!   refused by its token, loudly, and the store holds no bundle: the node
//!   opens rootless.

use super::genesis::{
    baked_genesis_anchor, baked_statements, check_baked_bundle, check_genesis_offer,
    genesis_in_force, import_baked_genesis, import_bundles_at_boot, BakedImport, BootImport,
    BAKED_BUNDLES, BAKED_GENESIS_ARRAY_SHA256, BAKED_GENESIS_OBJECT_ID, BAKED_GENESIS_STATEMENTS,
};
use crate::federation::FederationDirectory;
use ciris_verify_core::edition2::genesis::Anchor;

/// The real genesis's t0 (`terms.json` `asserted_at_ms`).
pub(crate) const T0_MS: u64 = 1_795_302_284_535;

/// The three holders (`terms.json`), A1, B1, C1.
const HOLDERS: [&str; 3] = [
    "urn:ietf:params:oauth:ckt:sha-256:mkABfy3E4WaNxm51g02c43ZODhR3EAxaPxpnZGSpMt0",
    "urn:ietf:params:oauth:ckt:sha-256:t22YNA-ICKYKWyyYJ8clnnufqynYg1KFoW0IVsTruAo",
    "urn:ietf:params:oauth:ckt:sha-256:lu4E9zfCraWxZAUp6akry3PzMJjGSAX9xvv-iktfqjk",
];

/// The serve seat `canonical-1` (`terms.json`).
const SEAT: &str = "urn:ietf:params:oauth:ckt:sha-256:IiG-eTvirkDbYiqa-tuv3MxShjEDJen7FQMkiItujzQ";

/// An hour after t0: the instant every pure leg is judged at.
pub(crate) fn pinned_at() -> chrono::DateTime<chrono::Utc> {
    chrono::TimeZone::timestamp_millis_opt(
        &chrono::Utc,
        i64::try_from(T0_MS + 3_600_000).expect("an instant"),
    )
    .single()
    .expect("an instant")
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(b))
}

fn sorted(v: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = v.into_iter().collect();
    v.sort();
    v
}

fn holders() -> Vec<String> {
    sorted(HOLDERS.iter().map(|h| (*h).to_owned()))
}

fn bytes() -> &'static [u8] {
    assert_eq!(BAKED_BUNDLES.len(), 1, "one baked bundle");
    assert_eq!(BAKED_BUNDLES[0].0, "humanity-accord-v1");
    BAKED_BUNDLES[0].1
}

fn frame(statements: &[Vec<u8>]) -> Vec<u8> {
    use ciris_verify_core::cde::Value;
    ciris_verify_core::cde::encode(&Value::Array(
        statements.iter().cloned().map(Value::Bytes).collect(),
    ))
}

/// The vendored originals, read from disk at test time (not included in the
/// build: the ONE bake is the framed entry, I2293).
fn vendored() -> Vec<Vec<u8>> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/federation/edition2/baked/humanity-accord-v1");
    BAKED_GENESIS_STATEMENTS
        .iter()
        .map(|(file, _)| {
            std::fs::read(dir.join(file)).unwrap_or_else(|e| panic!("I2468: {file}: {e}"))
        })
        .collect()
}

/// **I2468.**
#[test]
fn i2468_the_baked_bytes_are_the_ceremonys() {
    let b = bytes();
    let files = vendored();
    for (f, (file, sum)) in files.iter().zip(BAKED_GENESIS_STATEMENTS) {
        assert_eq!(sha256_hex(f), sum, "I2468: {file} is the ceremony's file");
    }
    assert_eq!(
        sha256_hex(b),
        BAKED_GENESIS_ARRAY_SHA256,
        "I2468: the array"
    );
    let st = baked_statements(b).expect("I2468: a CDE array of bstr");
    for (e, (file, sum)) in st.iter().zip(BAKED_GENESIS_STATEMENTS) {
        assert_eq!(sha256_hex(e), sum, "I2468: the decoded element {file}");
    }
    assert_eq!(
        st, files,
        "I2468: the entry is exactly the eight files, in order"
    );
    assert_eq!(frame(&files), b, "I2468: the framing is all persist added");

    // The anchor is a pinned constant, and it is the id the voices name.
    let Anchor::ObjectId(pinned) = baked_genesis_anchor() else {
        panic!("I2468: the production anchor is an object id");
    };
    let placed = check_baked_bundle(b, pinned_at())
        .unwrap_or_else(|e| panic!("I2468: the bake gate passes: {e:?}"));
    assert_eq!(placed.len(), 1, "I2468: one bundle");
    let p = &placed[0];
    assert_eq!(
        p.object_id, pinned,
        "I2468: the pinned anchor is the bundle"
    );
    assert_eq!(hex::encode(p.object_id), BAKED_GENESIS_OBJECT_ID);
    assert_eq!(p.family_key_id, "humanity-accord");
    assert_eq!(p.version, 1);
    assert_eq!(p.prev, None);
    assert_eq!(p.asserted_at, T0_MS);
    assert_eq!(
        sorted(p.holders.iter().map(|h| h.identity_ref.clone())),
        holders(),
        "I2468: A1, B1, C1"
    );
    assert_eq!(p.seats.len(), 1, "I2468: one seat");
    assert_eq!(p.seats[0].identity_ref, SEAT, "I2468: canonical-1");
    assert!(
        ciris_verify_core::edition2::has_tcp_hint(&p.seats[0].dial_hints),
        "I2468: the seat is dialable from a cold boot"
    );

    // Server's gate anchors by the holders' thumbprints: the same bundle.
    let thumbprints = HOLDERS
        .iter()
        .map(|h| ciris_verify_core::edition2::identity_ref_thumbprint(h).expect("a thumbprint"))
        .collect();
    let by_tp = check_genesis_offer(&st, Some(&Anchor::Thumbprints(thumbprints)), pinned_at())
        .unwrap_or_else(|e| panic!("I2468: the thumbprint anchor places it too: {e:?}"));
    assert_eq!(by_tp.len(), 1);
    assert_eq!(by_tp[0].object_id, pinned, "I2468: the same bundle");
    // No anchor: a first bundle is void (Verify's NotAnchored).
    assert!(
        check_genesis_offer(&st, None, pinned_at()).is_err(),
        "I2468: no anchor places nothing"
    );
}

/// **I2469.**
pub(crate) async fn i2469_a_fresh_store_imports_it(
    d: &dyn FederationDirectory,
    other: &dyn FederationDirectory,
    tag: &str,
) {
    let out = import_baked_genesis(d).await.unwrap_or_else(|e| {
        panic!("[{tag}] I2469: the import door places the baked genesis: {e:?}")
    });
    assert_eq!(
        out,
        BakedImport::Imported(vec![BAKED_GENESIS_OBJECT_ID.to_owned()]),
        "[{tag}] I2469: one bundle placed"
    );
    let g = genesis_in_force(d).await.expect("genesis reads");
    assert_eq!(
        (g.held, g.valid.len()),
        (1, 1),
        "[{tag}] I2469: one bundle held"
    );
    assert_eq!(
        g.head.as_ref().map(|h| hex::encode(h.object_id)).as_deref(),
        Some(BAKED_GENESIS_OBJECT_ID),
        "[{tag}] I2469: it is the head"
    );
    assert_eq!(
        sorted(super::trust_root_group::holders_in_force(&g)),
        holders(),
        "[{tag}] I2469: the three holders in force"
    );
    let hints = super::genesis::bootstrap_hints(&g);
    assert!(
        !hints.is_empty() && hints.iter().all(|(seat, _)| seat == SEAT),
        "[{tag}] I2469: the seat has a route: {hints:?}"
    );
    let oid = g.valid[0].object_id;
    let named = super::trust_root_group::bundle_holders(&g, &oid).expect("the named bundle");
    let count = super::trust_root_group::holders_count(&named, &std::collections::BTreeSet::new());
    assert_eq!(
        (count.required, count.roster_size),
        (2, 3),
        "[{tag}] I2469: a root grant counts 2 of the 3 holders"
    );
    // A reopen: nothing offered, nothing changed.
    let statements_before = super::genesis::genesis_statements(d).await.expect("reads");
    assert_eq!(
        import_baked_genesis(d).await.expect("a reopen reads"),
        BakedImport::AlreadyHeld,
        "[{tag}] I2469: idempotent"
    );
    assert_eq!(
        super::genesis::genesis_statements(d).await.expect("reads"),
        statements_before,
        "[{tag}] I2469: a reopen changes nothing"
    );
    // A store that already holds a bundle (here the test ceremony's) is left
    // as it is: no second lineage is offered.
    super::fixture_genesis::install_v2(other)
        .await
        .expect("the test ceremony installs");
    let before = genesis_in_force(other).await.expect("reads");
    assert_eq!(
        import_baked_genesis(other).await.expect("reads"),
        BakedImport::AlreadyHeld,
        "[{tag}] I2469: a store holding a bundle is not offered the bake"
    );
    let after = genesis_in_force(other).await.expect("reads");
    assert_eq!(
        (
            after.held,
            after.valid.iter().map(|p| p.object_id).collect::<Vec<_>>()
        ),
        (
            before.held,
            before.valid.iter().map(|p| p.object_id).collect::<Vec<_>>()
        ),
        "[{tag}] I2469: unchanged"
    );
}

/// **I2470.** Every instant is pinned: the node's key record from a day
/// before t0, the acceptance stated an hour after t0, standing read two
/// hours after t0. (`Engine::accept_root` stamps the host clock and has no
/// instant parameter, so the acceptance here is the Engine's own drafted row,
/// `accept_root_draft`, the same builder, signed with the node's key.)
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) async fn i2470_imported_is_not_accepted(dsn: &str, alias: &str) {
    use super::fixture_switch as e2;
    use crate::federation::tier_ingest::test_support as ts;
    let e = crate::Engine::with_signer_pre_genesis(ts::local_signer(alias), dsn)
        .await
        .expect("a fresh engine opens");
    let dir = e.federation_directory();
    let start = T0_MS - 86_400_000;
    let node = e2::put_key_with(
        dir.as_ref(),
        alias,
        &["node"],
        &e2::KeyRecordOptions {
            asserted_at_ms: Some(start),
            valid_until_ms: Some(start + e2::NODE_KEY_MAX_MS),
            ..e2::KeyRecordOptions::default()
        },
    )
    .await;
    // The open leg every production constructor runs.
    assert_eq!(
        e.import_baked_genesis_at_boot().await,
        BootImport::Done(BakedImport::Imported(vec![
            BAKED_GENESIS_OBJECT_ID.to_owned()
        ])),
        "I2470: the open leg imports the baked genesis"
    );
    let rooted_at = T0_MS + 2 * 3_600_000;
    assert_eq!(
        super::serve::rooted_under(dir.as_ref(), &node, rooted_at)
            .await
            .expect("reads"),
        None,
        "I2470: imported, not accepted: rootless"
    );
    assert_eq!(
        e.import_baked_genesis_at_boot().await,
        BootImport::Done(BakedImport::AlreadyHeld),
        "I2470: a reopen places nothing"
    );
    let draft = e
        .accept_root_draft(
            "humanity-accord",
            &node,
            &hex::encode(e2::kid_digest(alias)),
            T0_MS + 3_600_000,
        )
        .await
        .expect("I2470: the acceptance drafts");
    let st = draft.assemble(
        e2::signing_key(alias)
            .sign(&draft.sig_structure)
            .expect("the node signs"),
    );
    let out = e
        .put_edition2_statement(&st, None)
        .await
        .expect("I2470: the acceptance is admitted");
    assert!(
        matches!(out, super::ingest::StatementOutcome::Row { .. }),
        "I2470: it lands: {out:?}"
    );
    assert_eq!(
        super::serve::rooted_under(dir.as_ref(), &node, rooted_at)
            .await
            .expect("reads")
            .as_deref(),
        Some("humanity-accord"),
        "I2470: rooted under the baked lineage"
    );
    assert_eq!(
        crate::federation::trust_root::governing_acceptor(dir.as_ref(), &node)
            .await
            .expect("reads"),
        node,
        "I2470: through its own edge"
    );
}

/// **I2471.**
pub(crate) async fn i2471_a_corrupted_copy_is_refused_loudly(
    d: &dyn FederationDirectory,
    tag: &str,
) {
    let mut st = baked_statements(bytes()).expect("the bake decodes");
    let voice = st.len() - 1;
    if let Some(last) = st[voice].last_mut() {
        *last ^= 0x01;
    }
    let corrupted = frame(&st);
    assert_ne!(corrupted.as_slice(), bytes(), "a COPY was changed");
    let out = import_bundles_at_boot(
        d,
        &[("corrupted-copy", corrupted.as_slice())],
        &baked_genesis_anchor(),
    )
    .await;
    match &out {
        BootImport::Refused(token) => assert!(
            token.starts_with("genesis_"),
            "[{tag}] I2471: refused by a genesis token: {token}"
        ),
        other => panic!("[{tag}] I2471: a corrupted bake is refused, got {other:?}"),
    }
    assert_eq!(
        genesis_in_force(d).await.expect("reads").held,
        0,
        "[{tag}] I2471: nothing is held: the node opens rootless"
    );
}

#[cfg(feature = "sqlite")]
async fn sqlite_fresh() -> crate::store::sqlite::SqliteBackend {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b
}

#[cfg(feature = "postgres")]
async fn postgres_fresh() -> Option<crate::store::postgres::PostgresBackend> {
    use crate::store::Backend as _;
    let dsn = crate::test_pg::empty_dsn()?;
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2469_sqlite() {
    let (a, b) = (sqlite_fresh().await, sqlite_fresh().await);
    Box::pin(i2469_a_fresh_store_imports_it(&a, &b, "sqlite")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2469_postgres() {
    let (Some(a), Some(b)) = (postgres_fresh().await, postgres_fresh().await) else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    Box::pin(i2469_a_fresh_store_imports_it(&a, &b, "postgres")).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2470_sqlite() {
    Box::pin(i2470_imported_is_not_accepted(
        "sqlite::memory:",
        "gb1-node-sq",
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2470_postgres() {
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    Box::pin(i2470_imported_is_not_accepted(&dsn, "gb1-node-pg")).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2471_sqlite() {
    Box::pin(i2471_a_corrupted_copy_is_refused_loudly(
        &sqlite_fresh().await,
        "sqlite",
    ))
    .await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2471_postgres() {
    let Some(b) = postgres_fresh().await else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    Box::pin(i2471_a_corrupted_copy_is_refused_loudly(&b, "postgres")).await;
}
