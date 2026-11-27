//! CIRISPersist#848 (`FSD/BLOB_REPLICATION.md` §18) — **the
//! two-node witnesses, I59–I67.**
//!
//! "Two nodes" is two backends, each with its own signer and its own
//! content-KEM keyring, connected only by taking a statement from one and
//! handing it to the other's replicated statement door. No shared
//! directory: every node resolves every signer from its OWN key plane,
//! exactly as a peer would (CEG §0).
//!
//! Generic over the backend so the same drive runs on sqlite and postgres —
//! the `#[cfg(test)]` wrappers at the bottom instantiate two (or three)
//! in-memory sqlite backends, and two (or three) `test_pg::empty_dsn()`
//! databases when the postgres feature and a test cluster are present.
//!
//! v62.0.0 (wave E11) — **edition 2 throughout.** Keys are E0 `key:record`
//! statements named by kid; a community or family is its `group:roster`
//! voices (T1) and a removal its `membership:removal` voices; a key grant is
//! a `key_grant:{axis}` statement (T2) — the production emitters state it
//! since cut B — and it crosses to a peer as that statement, through
//! [`apply_replicated_statement`]; an owner binding is the owner's
//! `delegates_to` statement plus the node's own voice; a signed occurrence
//! is an O1 `identity:occurrence` bind (the identity authors it, the
//! occurrence key gives its own voice). Node/agent-signed rows are dated
//! now-relative (E0 v1.11).

/// The fixture and the exercises: [`Node`], the crossings
/// ([`carry_key_grant`](two_node::carry_key_grant),
/// [`carry_bytes`](two_node::carry_bytes)), and one `exercise_*` per
/// behavioural invariant.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub mod two_node {
    use crate::federation::adopt_cascade::{adopt_sealed_blob, AdoptDisposition};
    use crate::federation::at_rest_cascade::blob_invariants::{hold_ctx, node_signer};
    use crate::federation::at_rest_cascade::orchestrate::read_any_for_viewer;
    use crate::federation::attestation_apply::ReplicatedAttestationOutcome;
    use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::{
        apply_replicated_statement, ReplicatedStatementOutcome, StatementOutcome,
    };
    use crate::federation::edition2::names::RowId;
    use crate::federation::key_grant::{
        emit_content_key_grant_with_local_signer, emit_epoch_key_grant_with_local_signer,
        project_key_grant_row, publish_self_occurrence_with_local_signer, KeyGrantAdmission,
        KeyGrantAxis, KeyGrantEmission, KeyGrantProjection, KeyGrantRow, SignedKeyGrantRow,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY, SELF};
    use crate::federation::types::identity_type::USER;
    use crate::federation::{
        BlobBody, BlobError, BlobProvenance, BlobStorage, EncryptionPubkeys, Error,
        FederationDirectory,
    };
    use std::sync::Arc;

    /// One node: a backend, its signer, its derived federation key, and the
    /// content-KEM pubkeys its own keyring holds the private halves for.
    pub struct Node<'a, B> {
        /// The node's substrate.
        pub backend: &'a B,
        /// The node's hybrid signer (the minter / author on this node).
        pub signer: Arc<crate::signing::LocalSigner>,
        /// `signer.federation_id()` (v62.0.0: the identity-ref of the
        /// signer's composite key) — the node's occurrence key everywhere.
        pub key: String,
        /// This node's content-KEM identity: what a peer wraps to when it
        /// wraps to this node's occurrence, and what only this node can open.
        pub kem: EncryptionPubkeys,
    }

    /// Bring up a node on `backend`: register the alias and its derived key
    /// in the node's own directory, mint its content-KEM identity.
    pub async fn node<'a, B>(backend: &'a B, alias: &str) -> Node<'a, B>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let signer = node_signer(backend, alias).await;
        // v62.0.0 (cut B) — the node's federation id is its composite key's
        // identity-ref (`kid(alias)`), the key every edition-2 row it signs
        // names.
        let key = signer.federation_id().await;
        let id = backend
            .load_or_init_content_kem_identity()
            .await
            .expect("content-KEM identity");
        Node {
            backend,
            signer,
            key,
            kem: EncryptionPubkeys {
                x25519_base64: id.x25519_pubkey_b64,
                ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
            },
        }
    }

    /// A [`Node`] whose own key is registered on its backend under `role`
    /// (`identity_type::NODE` when an owner binding must target it — #851).
    /// The same construction as [`node`] (via `node_signer`), role aside.
    pub async fn node_as<'a, B>(backend: &'a B, alias: &str, role: &str) -> Node<'a, B>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        // v62.0.0 — the alias's edition-2 `key:record` (`kid(alias)`), the key
        // its LocalSigner signs as.
        ts::register_hybrid_key_as(backend, alias, alias, role).await;
        let signer = ts::local_signer(alias);
        let key = signer.federation_id().await;
        let id = backend
            .load_or_init_content_kem_identity()
            .await
            .expect("content-KEM identity");
        Node {
            backend,
            signer,
            key,
            kem: EncryptionPubkeys {
                x25519_base64: id.x25519_pubkey_b64,
                ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
            },
        }
    }

    /// v62.0.0 (HEAD-6; Constitution, head cases (3): "owned-but-rootless
    /// runs the mesh; unowned is only reachable") — **own `n`**: the person
    /// `owner_alias` binds the node `alias` (a [`node_as`] `NODE`) through the
    /// real owner-binding door (`fixture_switch::land_owner_binding`: the
    /// owner's statement, then the node's own voice), on the node's own
    /// backend. From then on its reports and holding claims name the binding.
    ///
    /// # Panics
    /// The binding does not land.
    pub async fn own<B>(n: &Node<'_, B>, alias: &str, owner_alias: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        e2::put_key(n.backend, owner_alias, &[USER]).await;
        let binding = ts::owner_binding_attestation(
            &format!("own-{alias}-{owner_alias}"),
            owner_alias,
            &n.key,
        );
        e2::land_owner_binding(n.backend, &binding, alias)
            .await
            .unwrap_or_else(|e| panic!("own({alias}): the owner binding lands: {e:?}"));
    }

    /// v62.0.0 (HEAD-7; Constitution, head cases (3)) — [`node_as`], then
    /// [`own`]: a `role` node OWNED by the person `{alias}-owner` through the
    /// real owner-binding door. The fixture for a node that is to sign reports
    /// and holding claims; [`node_as`] stays the fixture for a test about an
    /// unowned node, or one that binds the node itself.
    pub async fn node_owned_as<'a, B>(backend: &'a B, alias: &str, role: &str) -> Node<'a, B>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let n = node_as(backend, alias, role).await;
        own(&n, alias, &format!("{alias}-owner")).await;
        n
    }

    /// Every node learns every other node's key — the ONE piece of shared
    /// knowledge two real nodes have after a key-record exchange: each
    /// alias's edition-2 `key:record` (`kid(alias)`), registered as a USER
    /// (the historical fixture role). Use [`introduce_as`] with
    /// `identity_type::NODE` when an owner binding must target the key
    /// (#851).
    pub async fn introduce<B>(nodes: &[&Node<'_, B>], aliases: &[&str])
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        introduce_as(nodes, aliases, USER).await;
    }

    /// Register every node's key on every node under `role`.
    pub async fn introduce_as<B>(nodes: &[&Node<'_, B>], aliases: &[&str], role: &str)
    where
        B: FederationDirectory + Sync,
    {
        for (i, n) in nodes.iter().enumerate() {
            for (j, other) in nodes.iter().enumerate() {
                if i != j {
                    ts::register_hybrid_key_as(n.backend, &other.key, aliases[j], role).await;
                }
            }
        }
    }

    /// v62.0.0 (P1-fix4; CC rc21 3.3.6) — **`owner` OWNS `key`**: the owner
    /// binding row (`owner` a seed), landed by K2's
    /// `ts::put_sealed_owner_binding` with `key`'s voice (signed by
    /// `key_seed`, a seed or a seed-known kid, e.g. an engine's alias). The
    /// CC-correct way for a person to stand behind a machine key (a node or
    /// an agent), which is never an occurrence of the person. Published in
    /// P1.api.md.
    pub async fn own_key(
        d: &dyn crate::federation::FederationDirectory,
        owner: &str,
        key: &str,
        key_seed: &str,
    ) {
        // v62.0.0 (P1-fix10) — the bound key's own record FIRST: its voice
        // over the binding is checked against it.
        key_live(d, key_seed).await;
        // v62.0.0 (P1-fix5) — ONE voice path and one dating rule: K2's
        // `put_sealed_owner_binding` (the owner's statement through the
        // statement door, then the bound key's voice by `key_seed`; it asserts
        // the binding lands, and the builder dates it inside the bound key's
        // window). In the earlier form it is `put_attestation`, as before.
        let mut row = ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), owner, key);
        // v62.0.0 (E11-fix4) — dated from the bound key's record AS THIS
        // DIRECTORY HOLDS IT ([`owner_binding_instant`]), then re-sealed. The
        // builder dates from the process-wide default window of `key`'s seed,
        // which is not this directory's record when the key is an ENGINE's
        // own (`register_self_federation_key` starts the record at its
        // registration instant): the binding fell before the record began and
        // the key's voice waited `AttesterKeyUnknown` (86 reds, pass 4d).
        if e2::emit_edition2() {
            let at = owner_binding_instant(d, key_seed).await;
            row.asserted_at = at;
            row.scrub_timestamp = at;
            if let Some(m) = row.attestation_envelope.as_object_mut() {
                if m.contains_key("asserted_at") {
                    m.insert(
                        "asserted_at".to_owned(),
                        serde_json::Value::String(
                            crate::federation::admission::render_signed_instant(at),
                        ),
                    );
                }
            }
            ts::reseal(&mut row);
        }
        ts::put_sealed_owner_binding(d, &row, key_seed)
            .await
            .unwrap_or_else(|e| panic!("{owner} owns {key}: {e}"));
    }

    /// v62.0.0 (E11-fix4) — the offset past the bound key's record start at
    /// which [`own_key`] dates the owner binding.
    pub const OWNER_BINDING_RECORD_OFFSET_MS: i64 = 1;

    /// v62.0.0 (E11-fix4) — **the instant an owner binding of `key_seed`'s
    /// key is dated at on `d`**: the key's record as `d` holds it
    /// (`lookup_public_key`, its `valid_from`, at whole ms) plus
    /// [`OWNER_BINDING_RECORD_OFFSET_MS`]. Inside the record by construction,
    /// whenever and however the record was put (a default node window, an
    /// engine's registration instant). Call after [`key_live`].
    ///
    /// # Panics
    /// `d` holds no record for the key.
    pub async fn owner_binding_instant(
        d: &dyn crate::federation::FederationDirectory,
        key_seed: &str,
    ) -> chrono::DateTime<chrono::Utc> {
        let k = e2::kid(&e2::seed_of(key_seed));
        let rec = d
            .lookup_public_key(&k)
            .await
            .unwrap_or_else(|e| panic!("{k}'s record: {e}"))
            .unwrap_or_else(|| panic!("{k} is held before it is owned"));
        let ms = rec.valid_from.timestamp_millis() + OWNER_BINDING_RECORD_OFFSET_MS;
        chrono::TimeZone::timestamp_millis_opt(&chrono::Utc, ms)
            .single()
            .expect("an instant inside the key's record")
    }

    /// v62.0.0 (P1-fix10) — **make the bound key live before anything it
    /// voices**: under the switch, when `dir` holds no record for
    /// `kid(key_seed)`, put its default `node` `key:record` (window from
    /// [`NODE_DEFAULT_BACK_DAYS`](crate::federation::edition2::fixture_switch::NODE_DEFAULT_BACK_DAYS)
    /// before today, so a binding dated now sits inside it). A key the test
    /// already registered (any role, any window) is left as it is. Without
    /// this the node's voice met `AttesterKeyUnknown` ("an ordering gap"):
    /// 197 reds in pass 4b. The earlier form needs no record here.
    ///
    /// # Panics
    /// (P1-fix11) The key is held, but not as a `node` / `agent` key.
    pub async fn key_live(d: &dyn crate::federation::FederationDirectory, key_seed: &str) {
        use crate::federation::types::identity_type::{set_contains, AGENT, NODE};
        if !e2::emit_edition2() {
            return;
        }
        let seed = e2::seed_of(key_seed);
        let k = e2::kid(&seed);
        let held = d
            .lookup_public_key(&k)
            .await
            .unwrap_or_else(|e| panic!("{k}'s record: {e}"));
        let Some(rec) = held else {
            e2::put_key(d, &seed, &["node"]).await;
            return;
        };
        // v62.0.0 (P1-fix11; CC 2.7, CC rc21 3.3.6) — an owner binding binds
        // a MACHINE key: onto a `user` key it is held, never landed (a silent
        // `Pending` the caller then misreads). Named here instead.
        assert!(
            set_contains(&rec.identity_type, NODE) || set_contains(&rec.identity_type, AGENT),
            "owner binding onto {k} ({seed}): the key is held as `{}`, not a node or agent key; \
             register it as NODE (introduce_as(.., NODE) / node_as(.., NODE)) before owning it",
            rec.identity_type
        );
    }

    /// v62.0.0 (P1-fix4; CC rc21 3.3.6) — **THE shared fixture for "a
    /// person's device node"** (published in P1.api.md): `owner` (a seed)
    /// owns the node key `node` ([`own_key`], voiced by `node_seed`), and the
    /// node states its own class (`device_class`) and content-KEM keys on its
    /// SELF-occurrence (identity = occurrence = the node, which CC rc21
    /// allows). This replaces binding a `node` / `agent` key as an occurrence
    /// of a person, which the door refuses
    /// (`occurrence_mixes_person_and_machine`). The node then receives its
    /// owner's content by its class (`replication_audience::owned_device`)
    /// and is a wrap target through `nodes_owned_by`
    /// (`at_rest_cascade::member_holders`).
    pub async fn place_device(
        d: &dyn crate::federation::FederationDirectory,
        owner: &str,
        node: &str,
        node_seed: &str,
        device_class: &str,
        kem: Option<EncryptionPubkeys>,
    ) {
        // v62.0.0 (P1-fix10) — the node's record before its self-occurrence
        // and its owner binding.
        key_live(d, node_seed).await;
        d.test_seam_put_identity_occurrence(crate::federation::types::IdentityOccurrence {
            identity_key_id: node.to_owned(),
            occurrence_key_id: node.to_owned(),
            device_class: device_class.to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: kem,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("{node}'s self-occurrence: {e}"));
        own_key(d, owner, node, node_seed).await;
    }

    /// v62.0.0 (E11) — POSIX ms of an instant (`e2::ms`).
    pub fn ms(at: chrono::DateTime<chrono::Utc>) -> u64 {
        e2::ms(at)
    }

    /// v62.0.0 (E11) — **the community `comm`'s founding roster** as one
    /// `group:roster` version (T1): the authority's statement and each
    /// listed member's voice, built ONCE so every node holds the same
    /// version under the same row id (a later removal names it by
    /// `refs.head`). `comm` and every member are seeds or E0 kids.
    pub fn community_roster_voices<S: AsRef<str>>(
        comm: &str,
        name: &str,
        members: &[S],
    ) -> Vec<Vec<u8>> {
        let now = chrono::Utc::now();
        let signed = ts::sign_community(
            comm,
            crate::federation::types::Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: comm.to_owned(),
                community_name: name.to_owned(),
                members: members
                    .iter()
                    .map(|k| crate::federation::types::CommunityMember {
                        key_id: k.as_ref().to_owned(),
                        joined_at: now,
                        role: None,
                    })
                    .collect(),
                founded_at: now,
                consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                    .to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        );
        e2::community_voices(&signed, 1, None, ms(now))
    }

    /// v62.0.0 (E11) — **the family `fam`'s founding roster** (T1), as
    /// [`community_roster_voices`].
    pub fn family_roster_voices<S: AsRef<str>>(
        fam: &str,
        name: &str,
        members: &[S],
    ) -> Vec<Vec<u8>> {
        let now = chrono::Utc::now();
        let signed = ts::sign_family(
            fam,
            crate::federation::types::Family {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                family_key_id: fam.to_owned(),
                family_name: name.to_owned(),
                members: members
                    .iter()
                    .map(|k| crate::federation::types::FamilyMember {
                        key_id: k.as_ref().to_owned(),
                        joined_at: now,
                        role: None,
                    })
                    .collect(),
                founded_at: now,
                consensus_protocol: crate::federation::types::consensus_protocol::MAJORITY
                    .to_owned(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        );
        e2::family_voices(&signed, 1, None, ms(now))
    }

    /// v62.0.0 (E11) — **`member`'s removal from the community `comm`**: the
    /// `membership:removal` voices (T1) naming the version `dir` holds as the
    /// head, one per key in `signers` (seeds or kids; the departing member's
    /// own voice among them, #908). Give every member a voice when the
    /// protocol must be met outright.
    ///
    /// # Panics
    /// `dir` holds no version of `comm`.
    pub async fn community_removal_voices<D: FederationDirectory + ?Sized, S: AsRef<str>>(
        dir: &D,
        comm: &str,
        member: &str,
        removed_at: chrono::DateTime<chrono::Utc>,
        effective_at: chrono::DateTime<chrono::Utc>,
        signers: &[S],
    ) -> Vec<Vec<u8>> {
        let (head, _) = e2::held_head(dir, &e2::kid(comm))
            .await
            .unwrap_or_else(|| panic!("the community {comm} is held"));
        let record = crate::federation::edition2::group::MembershipRecord::CommunityRemoval(
            crate::federation::types::CommunityMembershipRevocation {
                community_key_id: e2::kid(comm),
                removed_identity_key_id: e2::kid(member),
                removed_at,
                effective_at,
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
                record_row_id: None,
            },
        );
        let keys: Vec<_> = signers
            .iter()
            .map(|s| e2::signing_key(s.as_ref()))
            .collect();
        let refs: Vec<&_> = keys.iter().collect();
        e2::membership_voices(&record, Some(&head), &refs)
    }

    /// v62.0.0 (E11) — **an owner binding, edition 2**: `owner`'s
    /// `delegates_to(owner → node)` statement (the flipped
    /// `owner_binding_attestation`, re-dated to `at` so a node-typed key's
    /// own record covers it, E0 v1.11) and then the node's own voice over
    /// the same payload. `owner` and `node` are seeds or E0 kids.
    pub fn owner_binding_voices(
        owner: &str,
        node: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Vec<Vec<u8>> {
        let id = format!("ob-{}", uuid::Uuid::new_v4().simple());
        // CP2 skeleton: the builder's unsigned shape, re-signed as edition 2
        // (`row_of`) before any door.
        let mut earlier = e2::with_earlier_form(|| ts::owner_binding_attestation(&id, owner, node));
        let at = crate::federation::admission::truncate_to_substrate_resolution(at);
        earlier.asserted_at = at;
        earlier.scrub_timestamp = at;
        let row = e2::row_of(&earlier, owner);
        let st = e2::carried_statement(&row).expect("an edition-2 owner binding");
        let node_voice = e2::voice_of(&st, node);
        vec![st, node_voice]
    }

    /// v62.0.0 (E11) — **statements cross to `to` as a peer delivers them**:
    /// each through the replicated statement door
    /// ([`apply_replicated_statement`]) under the row id its own bytes name.
    /// A statement that waits on another (a bind's author voice before the
    /// occurrence key's own; a voice before its key) is re-offered after the
    /// others, as a replication loop retries a held cursor; the last
    /// refusal of a statement that never lands is returned.
    ///
    /// # Errors
    /// The door's refusal of a statement that never landed.
    pub async fn deliver_statements<D: FederationDirectory + ?Sized>(
        to: &D,
        statements: &[Vec<u8>],
    ) -> Result<Vec<ReplicatedStatementOutcome>, Error> {
        let mut pending: Vec<&Vec<u8>> = statements.iter().collect();
        let mut out = Vec::with_capacity(statements.len());
        loop {
            let landed_before = out.len();
            let mut waiting = Vec::new();
            let mut last_err = None;
            for st in pending {
                let id = RowId::of_statement(st).ok_or_else(|| {
                    Error::InvalidArgument("key_grant_invariants: not a row statement".into())
                })?;
                match Box::pin(apply_replicated_statement(to, st, &id.0)).await {
                    Ok(o) => out.push(o),
                    Err(e) => {
                        waiting.push(st);
                        last_err = Some(e);
                    }
                }
            }
            if waiting.is_empty() {
                return Ok(out);
            }
            if out.len() == landed_before {
                // A pass that landed nothing: what still waits never will.
                return Err(last_err.expect("a waiting statement carries its refusal"));
            }
            pending = waiting;
        }
    }

    /// v62.0.0 (E11) — **the O1 `identity:occurrence` bind statements `dir`
    /// holds for `identity`**, as its signed listing serves them
    /// (`signed_envelope["ceg_statements"]`, every voice): what a peer
    /// pulls to learn the identity's occurrences.
    pub async fn bind_statements_for<D: FederationDirectory + ?Sized>(
        dir: &D,
        identity: &str,
    ) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for occ in dir
            .list_signed_identity_occurrences_for(identity)
            .await
            .expect("the signed occurrence listing")
        {
            if let Some(all) = occ
                .signed_envelope
                .get("ceg_statements")
                .and_then(serde_json::Value::as_array)
            {
                for h in all.iter().filter_map(serde_json::Value::as_str) {
                    out.push(hex::decode(h).expect("a statement is hex"));
                }
            }
        }
        out
    }

    /// The content-KEM pubkeys as an O1 bind's `encryption_pubkeys` member
    /// (`{x25519: bstr32, ml_kem_768: bstr1184}`).
    pub fn encryption_member(
        kem: &EncryptionPubkeys,
    ) -> (&'static str, ciris_verify_core::cde::Value) {
        use base64::Engine as _;
        use ciris_verify_core::cde::{self, Value};
        let b = |s: &str| {
            Value::Bytes(
                base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .expect("a base64 KEM pubkey"),
            )
        };
        let mut m = vec![
            (Value::Text("ml_kem_768".into()), b(&kem.ml_kem_768_base64)),
            (Value::Text("x25519".into()), b(&kem.x25519_base64)),
        ];
        m.sort_by_key(|(k, _)| cde::encode(k));
        ("encryption_pubkeys", Value::Map(m))
    }

    /// v62.0.0 (E11, round 3) — **`device` as one of `member`'s devices on
    /// `dir`, in the form CC rc21 allows** (way (d): "a node or agent key is
    /// never bound under a person's identity"; P5c's `devices_of`):
    /// - a person's device key (not `node`/`agent`-typed on `dir`): the
    ///   member's trusted-local occurrence, as before;
    /// - a NODE or AGENT key: the member's OWNER BINDING of it
    ///   ([`owner_binding_voices`]: the member's statement and the node's own
    ///   voice), plus the node's own self-occurrence carrying its content-KEM
    ///   pubkeys (`identity = occurrence`, the pair the rule allows), which
    ///   is where `devices_of` reads an owned node's keys from.
    ///
    /// # Panics
    /// A door refusal (a fixture mistake).
    pub async fn bind_member_device<D: FederationDirectory + ?Sized>(
        dir: &D,
        member: &str,
        device: &str,
        kem: &EncryptionPubkeys,
    ) {
        use crate::federation::types::identity_type::{set_contains, AGENT, NODE};
        let machine = dir
            .lookup_public_key(device)
            .await
            .expect("read the device's key record")
            .is_some_and(|r| {
                set_contains(&r.identity_type, NODE) || set_contains(&r.identity_type, AGENT)
            });
        let occurrence = |identity: &str| crate::federation::types::IdentityOccurrence {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: device.to_owned(),
            device_class: if machine {
                crate::federation::types::device_class::SERVER.into()
            } else {
                crate::federation::types::device_class::LAPTOP.into()
            },
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: Some(kem.clone()),
            transport_binding: None,
            persist_row_hash: String::new(),
        };
        if !machine {
            dir.test_seam_put_identity_occurrence(occurrence(member))
                .await
                .unwrap_or_else(|e| panic!("occurrence {device} of {member}: {e}"));
            return;
        }
        for v in owner_binding_voices(
            member,
            device,
            chrono::Utc::now() - chrono::Duration::minutes(1),
        ) {
            e2::put_statement(dir, &v)
                .await
                .unwrap_or_else(|e| panic!("{member}'s owner binding of the node {device}: {e}"));
        }
        dir.test_seam_put_identity_occurrence(occurrence(device))
            .await
            .unwrap_or_else(|e| panic!("the node {device}'s own occurrence: {e}"));
    }

    /// Seed the same community on every node: the community key, each
    /// member identity, and each member's device = the member's NODE (its
    /// key, with the node's content-KEM pubkeys), bound in the form CC rc21
    /// allows ([`bind_member_device`]: a trusted-local occurrence for a
    /// person's device key, an owner binding plus the node's own occurrence
    /// for a node-typed key). A member with `None` node is on the roster with
    /// no occurrence anywhere. v62.0.0: the roster is ONE `group:roster`
    /// version (T1) put on every node, so its row id is the same everywhere.
    pub async fn seed_community_everywhere<B>(
        nodes: &[&Node<'_, B>],
        comm: &str,
        members: &[(&str, Option<&Node<'_, B>>)],
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let names: Vec<&str> = members.iter().map(|(ident, _)| *ident).collect();
        let voices = community_roster_voices(comm, "Two-node Co-op", &names);
        for n in nodes {
            ts::register_hybrid_key_as(n.backend, comm, comm, USER).await;
            for (ident, occ) in members {
                ts::register_hybrid_key_as(n.backend, ident, ident, USER).await;
                if let Some(o) = occ {
                    // v62.0.0 (P1-fix4; CC rc21 3.3.6) — a node key is never
                    // an occurrence of a person: the member OWNS the node
                    // (owner binding, the node's voice), and the node states
                    // its class and content-KEM keys on its self-occurrence.
                    // It is a wrap target through `nodes_owned_by`
                    // (`at_rest_cascade::member_holders`).
                    place_device(
                        n.backend,
                        ident,
                        &o.key,
                        &o.key,
                        crate::federation::types::device_class::LAPTOP,
                        Some(o.kem.clone()),
                    )
                    .await;
                }
            }
            // v62.0.0 (T1) — the room is its `group:roster` voices (the
            // authority and every listed member), on every node.
            e2::put_voices(n.backend, &voices)
                .await
                .unwrap_or_else(|e| panic!("seed community {comm}: {e}"));
        }
    }

    /// The wire crossing for ONE row: take the row `attestation_id` stored on
    /// `from` and hand its statement to `to`'s replicated statement door,
    /// whoever it is for (a relay that forwards what it holds). Nothing else
    /// moves.
    pub async fn carry_key_grant<B>(
        from: &Node<'_, B>,
        to: &Node<'_, B>,
        attestation_id: &str,
    ) -> Result<KeyGrantAdmission, Error>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let row = from
            .backend
            .get_attestation(attestation_id)
            .await
            .expect("read the emitted row")
            .expect("the emitted row exists on the emitter");
        admit_replicated(to.backend, SignedKeyGrantRow { attestation: row }).await
    }

    /// v55.0.0 (#989) — **the wire crossing through the plane**: every row
    /// `emission` names that `from`'s serve gate
    /// ([`may_receive`](crate::federation::replication_audience::may_receive),
    /// on `from`'s own directory) would send to `to`, each as its statement
    /// through `to`'s replicated statement door. A row for another recipient
    /// does not cross: a key-grant row reaches its recipient's node and no
    /// other (CC 6.1.5.3).
    pub async fn carry_key_grants<B>(
        from: &Node<'_, B>,
        to: &Node<'_, B>,
        emission: &KeyGrantEmission,
    ) -> Result<Vec<KeyGrantAdmission>, Error>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let mut out = Vec::new();
        for id in &emission.attestation_ids {
            let row = from
                .backend
                .get_attestation(id)
                .await
                .expect("read the emitted row")
                .expect("the emitted row exists on the emitter");
            if !crate::federation::replication_audience::may_receive(from.backend, &to.key, &row)
                .await?
                .allowed()
            {
                continue;
            }
            out.push(admit_replicated(to.backend, SignedKeyGrantRow { attestation: row }).await?);
        }
        Ok(out)
    }

    /// v62.0.0 (E11) — **admit one replicated key-grant row as its
    /// statement**: the `key_grant:{axis}` statement the row carries
    /// (`ceg_statement`) through `to`'s replicated statement door
    /// ([`apply_replicated_statement`]), which runs the edition-2 door, the
    /// attestation plane's gates (the key-grant rule among them) and the
    /// grant projection (T2). Reported as the earlier door reported it: the
    /// plane's outcome, and whether the wrap is projected or pending
    /// ([`project_key_grant_row`] re-run over the stored row, a union). A
    /// store-conflict refusal is `attestation_refused`, typed.
    ///
    /// # Errors
    /// The door's and the gates' refusals.
    ///
    /// # Panics
    /// A row that carries no statement.
    pub async fn admit_replicated<B>(
        to: &B,
        signed: SignedKeyGrantRow,
    ) -> Result<KeyGrantAdmission, Error>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let row = signed.attestation;
        let parsed = KeyGrantRow::from_attestation(&row)?;
        let st = e2::carried_statement(&row).unwrap_or_else(|| {
            panic!(
                "an edition-2 key-grant row carries its statement: {}",
                row.attestation_id
            )
        });
        let offered = e2::rid_digest(&row);
        let attestation = match Box::pin(apply_replicated_statement(to, &st, &offered)).await? {
            // v62.0.0 (GC8; CC 2.7.3) — the key-grant rule's legs that read
            // other rows (the minter's delegation, the roster fold, the held
            // blob / stream owner, the audience) are fold conditions: the
            // statement is KEPT and its row concludes nothing. Witnessed here
            // as held (no typed row, a held reason) and reported as the
            // reason token, so a site that asserted the old refusal token now
            // asserts the hold ([`held_refusal`]).
            ReplicatedStatementOutcome::Admitted(StatementOutcome::Pending { row_id, .. })
            | ReplicatedStatementOutcome::Unchanged(StatementOutcome::Pending { row_id, .. }) => {
                return Err(held_refusal(to, &row_id).await);
            }
            ReplicatedStatementOutcome::Admitted(_) => ReplicatedAttestationOutcome::Inserted,
            ReplicatedStatementOutcome::Unchanged(_) => ReplicatedAttestationOutcome::Unchanged,
            ReplicatedStatementOutcome::Refused { reason } => {
                return Err(Error::KeyGrantRefused {
                    reason: "attestation_refused",
                    detail: format!("the statement door refused the row: {reason:?}"),
                    attestation_reason: Some(reason),
                });
            }
        };
        let stored = to
            .get_attestation(&e2::rid(&row))
            .await?
            .unwrap_or_else(|| panic!("the admitted key-grant row {} is stored", e2::rid(&row)));
        let projection = project_key_grant_row(to, &stored).await?;
        Ok(KeyGrantAdmission {
            recipient_key_id: parsed.wrap.recipient_key_id.clone(),
            axis: parsed.axis,
            attestation,
            projected: matches!(projection, KeyGrantProjection::Projected { .. }),
            pending: projection == KeyGrantProjection::Pending,
        })
    }

    /// v62.0.0 (GC8) — **a HELD key-grant row, as its reason token.** Asserts
    /// the row concludes nothing (no typed row under its id) and carries a
    /// registered `fold::reason`; answers it in the shape [`refusal_reason`]
    /// reads (`KeyGrantRefused { reason }`, or `SignerDoesNotActFor` for the
    /// self-scope leg), the detail marked `HELD`.
    pub async fn held_refusal<B>(to: &B, row_id: &RowId) -> Error
    where
        B: FederationDirectory + Sync + ?Sized,
    {
        use crate::federation::edition2::fold;
        assert!(
            to.get_attestation(&row_id.hex())
                .await
                .expect("read the typed table")
                .is_none(),
            "GC8: a held row concludes nothing: no typed row under {}",
            row_id.hex()
        );
        let held = fold::why_held(to, row_id)
            .await
            .expect("read the held reason")
            .unwrap_or_else(|| panic!("GC8: a Pending row {} has a held reason", row_id.hex()));
        let reason = fold::reason::registry()
            .into_iter()
            .find(|t| *t == held.reason)
            .unwrap_or_else(|| panic!("GC8: an unregistered held reason {:?}", held.reason));
        if reason == fold::reason::SIGNER_NOT_ACTING_FOR {
            return Error::SignerDoesNotActFor {
                attesting_key_id: String::new(),
                identity_key_id: String::new(),
                plane: crate::federation::key_grant::KEY_GRANT_PLANE,
                reason: crate::federation::SignerNotActingReason::NotBound,
            };
        }
        Error::KeyGrantRefused {
            reason,
            detail: format!("HELD (concludes nothing): {}", held.detail),
            attestation_reason: None,
        }
    }

    /// v55.0.0 (#989) — **the key-grant rows `signer` emitted that the plane
    /// delivers to `recipient`**, read off `dir`'s replication cursor and
    /// kept by its serve gate
    /// ([`may_receive`](crate::federation::replication_audience::may_receive)):
    /// what a host hands `recipient`'s apply door. v62.0.0: each row carries
    /// its `key_grant:{axis}` statement; [`admit_replicated`] delivers it.
    pub async fn key_grant_rows_for<D>(
        dir: &D,
        signer: &str,
        recipient: &str,
    ) -> Vec<SignedKeyGrantRow>
    where
        D: FederationDirectory + ?Sized,
    {
        let mut out = Vec::new();
        // v62.0.0 (RL-fix2c) — the fixture inspects its own store, not a serve.
        for served in crate::federation::edition2::serve::as_internal_read(
            dir.list_attestations_since(None, 100_000),
        )
        .await
        .unwrap()
        {
            let row = served.attestation;
            if row.attesting_key_id != signer
                || !crate::federation::key_grant::is_key_grant_row(&row)
            {
                continue;
            }
            if crate::federation::replication_audience::may_receive(dir, recipient, &row)
                .await
                .unwrap()
                .allowed()
            {
                out.push(SignedKeyGrantRow { attestation: row });
            }
        }
        out
    }

    /// The emitted row of `emission` whose recipient is `recipient`.
    pub async fn emitted_row_for<B>(
        from: &Node<'_, B>,
        emission: &KeyGrantEmission,
        recipient: &str,
    ) -> crate::federation::Attestation
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        for id in &emission.attestation_ids {
            let row = from
                .backend
                .get_attestation(id)
                .await
                .unwrap()
                .expect("the emitted row exists on the emitter");
            if row.attested_key_id == recipient {
                return row;
            }
        }
        panic!("no emitted row for {recipient}: {emission:?}")
    }

    /// The bytes crossing: `to` adopts the sealed bytes `from` holds, with
    /// the provenance the referencing attestation would declare. `family`
    /// is `to`'s operator predicate (#846 §4): for `self` / `family`
    /// content the holder is party to it exactly when the author is
    /// local-or-family — the owner's other device names the first one.
    #[allow(clippy::too_many_arguments)]
    pub async fn carry_bytes<B>(
        from: &Node<'_, B>,
        to: &Node<'_, B>,
        sha: &[u8; 32],
        cohort_scope: &str,
        community_or_owner: &str,
        epoch: Option<u64>,
        tier: CryptoTier,
        family: &[String],
    ) -> Result<[u8; 32], BlobError>
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let Some(BlobBody::Inline(bytes)) = from.backend.get_blob(sha).await? else {
            panic!("the sealed blob is inline on the author");
        };
        let ctx = hold_ctx(false, &to.key, family);
        let out = adopt_sealed_blob(
            to.backend,
            Some(&*to.signer),
            &ctx,
            &bytes,
            &BlobProvenance {
                author_key_id: from.key.clone(),
                cohort_scope: cohort_scope.to_owned(),
                community_key_id: Some(community_or_owner.to_owned()),
                epoch,
                tier,
                // #876 — this two-node fixture seals with the node's own
                // key, so author == minter here; the author != sealer
                // ladder lives in `epoch_minter_invariants`.
                minter_key_id: None,
            },
            None,
            AdoptDisposition::LocalOnly,
        )
        .await?;
        Ok(out.sha256)
    }

    /// Sign one key-grant row with `signer` WITHOUT storing it anywhere — a
    /// forger's row, or an honest row at a fresh signed instant built
    /// off-node (the emitter re-emits nothing it already holds as a row).
    pub async fn sign_row_unstored(
        signer: &crate::signing::LocalSigner,
        row: &KeyGrantRow,
    ) -> SignedKeyGrantRow {
        sign_row_unstored_at(signer, row, chrono::Utc::now()).await
    }

    /// v60.0.0 (#1049) — [`sign_row_unstored`] signed at `at` (a stamped
    /// instant belongs to the signer, so a witness may backdate one).
    pub async fn sign_row_unstored_at(
        signer: &crate::signing::LocalSigner,
        row: &KeyGrantRow,
        at: chrono::DateTime<chrono::Utc>,
    ) -> SignedKeyGrantRow {
        // v62.0.0 (T2) — an edition-2 `key_grant:{axis}` statement by the
        // signer's key (its identity-ref resolves to the E0 seed it was
        // minted from), mapped to the row a host carries.
        let (_, iref) = crate::federation::edition2::produce::signer_identity(signer)
            .await
            .expect("a composite signer");
        let at_ms = u64::try_from(
            crate::federation::admission::truncate_to_substrate_resolution(at).timestamp_millis(),
        )
        .expect("after the epoch");
        let st = e2::key_grant_statement(&e2::seed_of(&iref), row, at_ms);
        SignedKeyGrantRow {
            attestation: e2::row_of_statement(
                &st,
                crate::federation::types::attestation_tier::FEDERATION,
            ),
        }
    }

    /// The row this node holds for `axis` to `recipient`, as a [`KeyGrantRow`].
    pub async fn held_row<B>(n: &Node<'_, B>, axis: &KeyGrantAxis, recipient: &str) -> KeyGrantRow
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let set = crate::federation::key_grant::build_set_for_axis(n.backend, axis)
            .await
            .unwrap()
            .expect("the node holds wraps for the axis");
        set.rows()
            .into_iter()
            .find(|r| r.recipient() == recipient)
            .unwrap_or_else(|| panic!("no wrap for {recipient} on {axis:?}"))
    }

    fn refusal_reason(e: &Error) -> &'static str {
        match e {
            Error::KeyGrantRefused { reason, .. } => reason,
            // v55.0.0 (#989) — the self-axis sealer leg's retryable refusal.
            Error::SignerDoesNotActFor {
                plane: crate::federation::key_grant::KEY_GRANT_PLANE,
                ..
            } => "signer_not_acting_for",
            other => panic!("expected a typed key-grant refusal, got {other:?}"),
        }
    }

    /// v62.0.0 (E11, round 3) — **the key-grant rule's own verdict** on
    /// `row` at `dir` ([`check_key_grant_row_admission`], asked directly,
    /// outside any fold attempt), as [`refusal_reason`]'s token, or
    /// `"admitted"`. A delivered row meets the write-scope gate first, so a
    /// witness of the rule's own fold (membership at `asserted_at`) asks it
    /// here.
    ///
    /// [`check_key_grant_row_admission`]: crate::federation::key_grant::check_key_grant_row_admission
    async fn rule_reason<D>(dir: &D, row: &SignedKeyGrantRow) -> &'static str
    where
        D: FederationDirectory + Sync,
    {
        match crate::federation::key_grant::check_key_grant_row_admission(
            dir.as_dyn_directory(),
            &row.attestation,
        )
        .await
        {
            Ok(()) => "admitted",
            Err(e) => refusal_reason(&e),
        }
    }

    /// v62.0.0 (E11, round 3, fix2) — **a delivered row whose signer is no
    /// member is HELD by the write-scope gate**, the first fold gate that
    /// asks about the signer: `plan_put_attestation` runs
    /// `membership_acceptance::check_attestation_write_scope` (the cohort
    /// gate, at now) BEFORE `admission::check_reserved_prefix_admission`,
    /// which holds the key-grant rule (attestation_admit.rs). The rule's own
    /// verdict is pinned apart with [`rule_reason`].
    fn assert_held_by_write_scope(e: &Error, what: &str) {
        assert_eq!(
            refusal_reason(e),
            crate::federation::edition2::fold::reason::WRITE_SCOPE_REFUSED,
            "{what}: a non-member signer's row is held by the write-scope gate: {e}"
        );
    }

    /// v62.0.0 (E11) — a refusal's token: a malformed-row refusal's reason,
    /// else the error's kind.
    fn token_of(e: &Error) -> &'static str {
        match e {
            Error::MalformedRow { reason, .. } => reason,
            other => other.kind(),
        }
    }

    // ── I60 ──────────────────────────────────────────────────────────────
    /// **A `KeyGrant` whose signer is not the set's minter, or not an active
    /// member of the community at `asserted_at`, is refused at admission;
    /// the signer is resolved from the admitting node's directory.**
    pub async fn exercise_i60_forged_set_refused<B>(a: &Node<'_, B>, b: &Node<'_, B>, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = e2::kid(&format!("{tag}-comm-{run}"));
        let alice = e2::kid(&format!("{tag}-alice-{run}"));
        let bob = e2::kid(&format!("{tag}-bob-{run}"));
        seed_community_everywhere(&[a, b], &comm, &[(&alice, Some(a)), (&bob, Some(b))]).await;
        // GID-fixtures-sites — the room's DERIVED id, once founded (`room_id`
        // panics if it was not).
        let comm = crate::federation::edition2::fixture_switch::room_id(&comm);

        // Mallory: a registered key on BOTH nodes, a member of nothing.
        let mallory_alias = format!("{tag}-mallory-{run}");
        let mallory = node_signer(a.backend, &mallory_alias).await;
        let mallory_key = mallory.federation_id().await;
        ts::register_hybrid_key_as(b.backend, &mallory_key, &mallory_alias, USER).await;

        // A mints (C, A, 0) and wraps to both nodes' occurrences.
        let sealed =
            encrypt_and_cascade_community(a.backend, &comm, b"minutes", None, Some(&a.key))
                .await
                .unwrap_or_else(|e| panic!("{tag} I60: A seals: {e}"));
        assert_eq!(sealed.epoch, 0);
        let axis = KeyGrantAxis::Epoch {
            community_key_id: comm.clone(),
            minter_key_id: a.key.clone(),
            epoch: 0,
        };
        // A's genuine wrap to B — the row each forgery below is built from.
        let honest = held_row(a, &axis, &b.key).await;

        // (1) A member that is not the minter (B, bob's node) signs A's row,
        //     claiming A's counter. v62.0.0 (E11, round 3): the forger is a
        //     MEMBER so that only the minter rule is unmet — a non-member's
        //     row meets the write-scope gate first (legs 2 and 4).
        let forged = sign_row_unstored(&b.signer, &honest).await;
        let err = admit_replicated(b.backend, forged)
            .await
            .expect_err("a row signed by someone other than its minter must be refused");
        assert_eq!(
            refusal_reason(&err),
            "signer_not_minter",
            "{tag} I60: a member signing A's counter must be refused as not-the-minter, got {err}"
        );

        // (2) Mallory signs a row for Mallory's own counter — but Mallory is
        //     no member of C at asserted_at per B's roster fold.
        let own = KeyGrantRow {
            axis: KeyGrantAxis::Epoch {
                community_key_id: comm.clone(),
                minter_key_id: mallory_key.clone(),
                epoch: 0,
            },
            wrap: honest.wrap.clone(),
        };
        // v62.0.0 (E11, round 3) — delivered, the row meets the write-scope
        // gate (at now) before the key-grant rule and is HELD there; the
        // key-grant rule, asked of the same row on B, answers that the signer
        // is no active member at `asserted_at`.
        let own = sign_row_unstored(&mallory, &own).await;
        assert_eq!(
            rule_reason(b.backend, &own).await,
            "signer_not_active_member",
            "{tag} I60 (2): the key-grant rule's own verdict"
        );
        let err = admit_replicated(b.backend, own)
            .await
            .expect_err("a non-member's row must be refused");
        assert_eq!(
            refusal_reason(&err),
            crate::federation::edition2::fold::reason::WRITE_SCOPE_REFUSED,
            "{tag} I60: {err}"
        );

        // (3) A wrap that is not v2, signed by the honest minter.
        let mut v1 = honest.clone();
        v1.wrap.wrap_algorithm = "v1".into();
        let err = admit_replicated(b.backend, sign_row_unstored(&a.signer, &v1).await)
            .await
            .expect_err("a non-v2 wrap must be refused");
        assert_eq!(
            refusal_reason(&err),
            "wrap_algorithm_not_v2",
            "{tag} I60: {err}"
        );

        // (4) A community B has never heard of: the signer cannot be an
        //     active member of a roster B does not hold.
        let ghost = KeyGrantRow {
            axis: KeyGrantAxis::Epoch {
                community_key_id: format!("{tag}-ghost-{run}"),
                minter_key_id: a.key.clone(),
                epoch: 0,
            },
            wrap: honest.wrap.clone(),
        };
        let ghost = sign_row_unstored(&a.signer, &ghost).await;
        assert_eq!(
            rule_reason(b.backend, &ghost).await,
            "signer_not_active_member",
            "{tag} I60 (4): the key-grant rule's own verdict"
        );
        let err = admit_replicated(b.backend, ghost)
            .await
            .expect_err("a row for an unknown community must be refused");
        assert_eq!(
            refusal_reason(&err),
            crate::federation::edition2::fold::reason::WRITE_SCOPE_REFUSED,
            "{tag} I60: {err}"
        );

        // (5) v55.0.0 (#989) — the honest minter wrapping to a key that is no
        //     occurrence of any member: the recipient rule refuses it.
        let mut stranger = honest.clone();
        stranger.wrap.recipient_key_id = mallory_key.clone();
        let err = admit_replicated(b.backend, sign_row_unstored(&a.signer, &stranger).await)
            .await
            .expect_err("a wrap to a non-member must be refused");
        assert_eq!(
            refusal_reason(&err),
            "recipient_not_in_audience",
            "{tag} I60: {err}"
        );

        // Nothing was projected by any refusal.
        assert!(
            !b.backend
                .community_dek_has_member_grant(&comm, &a.key, 0, &b.key)
                .await
                .unwrap(),
            "{tag} I60: a refused row must project NOTHING"
        );
        assert!(
            !b.backend
                .community_dek_has_member_grant(&comm, &a.key, 0, &mallory_key)
                .await
                .unwrap(),
            "{tag} I60: a refused row must project NOTHING (the stranger)"
        );
        assert!(
            !b.backend
                .community_dek_has_member_grant(&comm, &mallory_key, 0, &b.key)
                .await
                .unwrap(),
            "{tag} I60: a refused row must project NOTHING (mallory's counter)"
        );
    }

    // ── I61 ──────────────────────────────────────────────────────────────
    /// **THE END TO END.** A seals a community blob under (C, A, E) and
    /// emits its set; B admits the set and adopts the bytes; B's member
    /// occurrence opens the blob; a non-member on B is `NotGranted`.
    pub async fn exercise_i61_end_to_end<B>(a: &Node<'_, B>, b: &Node<'_, B>, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = e2::kid(&format!("{tag}-comm-{run}"));
        let alice = e2::kid(&format!("{tag}-alice-{run}"));
        let bob = e2::kid(&format!("{tag}-bob-{run}"));
        seed_community_everywhere(&[a, b], &comm, &[(&alice, Some(a)), (&bob, Some(b))]).await;
        // GID-fixtures-sites — the room's DERIVED id, once founded (`room_id`
        // panics if it was not).
        let comm = crate::federation::edition2::fixture_switch::room_id(&comm);

        // A seals under (C, A, 0) — the fan-out wraps to B's occurrence
        // with B's OWN content-KEM pubkeys, which only B can open.
        let sealed =
            encrypt_and_cascade_community(a.backend, &comm, b"the minutes", None, Some(&a.key))
                .await
                .unwrap_or_else(|e| panic!("{tag} I61: A seals: {e}"));
        assert_eq!(sealed.minter_key_id, a.key, "{tag} I61: A is the minter");
        assert!(
            sealed.granted.contains(&b.key),
            "{tag} I61: precondition — A wrapped to B's occurrence; granted={:?}",
            sealed.granted
        );
        let sha = sealed.at_rest_sha256;

        // Before anything crosses: B holds the bytes? No. The key? No.
        let err = read_any_for_viewer(b.backend, &sha, &b.key, None)
            .await
            .expect_err("{tag} I61: nothing has crossed yet");
        assert!(
            matches!(err, BlobError::NotHeld { .. }),
            "{tag} I61: got {err:?}"
        );

        // A emits one row per wrap for (C, A, 0) through its attestation
        // store (v55.0.0, #989: the SET is retired).
        let emitted = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
            .await
            .unwrap_or_else(|e| panic!("{tag} I61: A emits: {e}"))
            .expect("A holds wraps to emit");
        assert!(
            emitted.attestation_ids.len() >= 2,
            "{tag} I61: one row per recipient (A's own and B's): {emitted:?}"
        );

        // Each row is what a PEER pulls: it rides the federation-tier
        // attestation cursor (§14 — "listable by the replication reader") as
        // a `scores` row on `key_grant:epoch:v1`, signed by the minter, to
        // ONE recipient.
        let served = a
            .backend
            .list_attestations_since(None, 1_000)
            .await
            .expect("the attestation cursor");
        let to_b = emitted_row_for(a, &emitted, &b.key).await;
        let row = served
            .iter()
            .find(|x| x.attestation.attestation_id == to_b.attestation_id)
            .unwrap_or_else(|| panic!("{tag} I61: the row to B is not on A's replication cursor"));
        assert_eq!(row.attestation.attestation_type, "scores");
        assert_eq!(
            crate::federation::admission::envelope_dimension(&row.attestation.attestation_envelope),
            Some(crate::federation::key_grant::KEY_GRANT_EPOCH_DIMENSION)
        );
        assert_eq!(
            row.attestation.attesting_key_id, a.key,
            "{tag} I61: signed by the minter"
        );
        assert_eq!(row.attestation.attested_key_id, b.key, "{tag} I61: to B");

        // The wire: through A's plane, then the bytes. Only B's own row
        // crosses (refers-to under the audience).
        let admissions = carry_key_grants(a, b, &emitted)
            .await
            .unwrap_or_else(|e| panic!("{tag} I61: B admits A's rows: {e}"));
        assert_eq!(
            admissions.len(),
            1,
            "{tag} I61: the plane delivers B exactly its own row: {admissions:?}"
        );
        assert!(
            admissions[0].projected && admissions[0].recipient_key_id == b.key,
            "{tag} I61: B projected its wrap: {admissions:?}"
        );
        assert!(
            b.backend
                .community_dek_has_member_grant(&comm, &a.key, 0, &b.key)
                .await
                .unwrap(),
            "{tag} I61: B's occurrence holds a grant on (C, A, 0) after admission"
        );
        let adopted = carry_bytes(
            a,
            b,
            &sha,
            COMMUNITY,
            &comm,
            Some(0),
            CryptoTier::CommunityDek,
            &[],
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I61: B adopts the bytes: {e}"));
        assert_eq!(adopted, sha);
        assert_eq!(
            b.backend.community_dek_blob_epoch(&sha).await.unwrap(),
            Some((comm.clone(), a.key.clone(), 0)),
            "{tag} I61: the binding on B names (C, A, 0) — the author is the minter"
        );

        // B's member occurrence OPENS it — with a DEK B recovered from the
        // wrap addressed to it, since B never minted (C, A, 0).
        assert!(
            b.backend
                .community_dek_get_self_retention(&comm, &a.key, 0)
                .await
                .unwrap()
                .is_none(),
            "{tag} I61: B holds no self-retention for A's epoch — the open must come from B's grant"
        );
        let got = read_any_for_viewer(b.backend, &sha, &b.key, None)
            .await
            .unwrap_or_else(|e| panic!("{tag} I61: B's member opens A's blob on B: {e}"));
        assert_eq!(
            got, b"the minutes",
            "{tag} I61: the plaintext, on the other node"
        );

        // A non-member on B is NotGranted, naming nothing.
        let stranger = format!("{tag}-stranger-{run}");
        let err = read_any_for_viewer(b.backend, &sha, &stranger, None)
            .await
            .expect_err("{tag} I61: a stranger must be refused");
        assert!(
            matches!(err, BlobError::NotGranted { .. }),
            "{tag} I61: expected NotGranted, got {err:?}"
        );
        // v55.0.0 (#989) — A's own wrap is a row to A: it does not reach B.
        // A wrap is useful to its recipient alone (CC 6.1.5.3).
        assert!(
            !b.backend
                .community_dek_has_member_grant(&comm, &a.key, 0, &a.key)
                .await
                .unwrap(),
            "{tag} I61: the row to A did not cross to B"
        );
        let to_a = emitted_row_for(a, &emitted, &a.key).await;
        assert!(
            !crate::federation::replication_audience::may_receive(a.backend, &b.key, &to_a)
                .await
                .unwrap()
                .allowed(),
            "{tag} I61: A's plane does not serve B the row for A"
        );
    }

    // ── I62 ──────────────────────────────────────────────────────────────
    /// **The projection is a union and order-independent**: re-applying a
    /// row, a later re-wrap with the same identity, a refused row, and a row
    /// applied before the bytes arrive all leave every prior grant in place
    /// (v55.0.0, #989: the union key is the row's identity).
    pub async fn exercise_i62_union_order_independent<B>(
        a: &Node<'_, B>,
        b: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = e2::kid(&format!("{tag}-comm-{run}"));
        let alice = e2::kid(&format!("{tag}-alice-{run}"));
        let bob = e2::kid(&format!("{tag}-bob-{run}"));
        seed_community_everywhere(&[a, b], &comm, &[(&alice, Some(a)), (&bob, Some(b))]).await;
        // GID-fixtures-sites — the room's DERIVED id, once founded (`room_id`
        // panics if it was not).
        let comm = crate::federation::edition2::fixture_switch::room_id(&comm);
        let sealed = encrypt_and_cascade_community(a.backend, &comm, b"v1", None, Some(&a.key))
            .await
            .unwrap();
        let sha = sealed.at_rest_sha256;
        let emitted = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
            .await
            .unwrap()
            .expect("wraps");
        let to_b = emitted_row_for(a, &emitted, &b.key).await;

        // (1) The row BEFORE the bytes: stored, projected, nothing lost.
        let first = carry_key_grant(a, b, &to_b.attestation_id).await.unwrap();
        assert!(
            first.projected,
            "{tag} I62: first admit projects: {first:?}"
        );
        let before: Vec<String> = b
            .backend
            .community_dek_member_grant_recipients(&comm, &a.key, 0)
            .await
            .unwrap();
        assert!(before.contains(&b.key), "{tag} I62: {before:?}");
        let wrap_before = b
            .backend
            .community_dek_member_grant_wrap(&comm, &a.key, 0, &b.key)
            .await
            .unwrap()
            .expect("B's wrap is held");

        // (2) Re-apply the SAME row: idempotent, nothing removed.
        let again = carry_key_grant(a, b, &to_b.attestation_id).await.unwrap();
        assert!(again.projected, "{tag} I62: {again:?}");
        assert_eq!(
            b.backend
                .community_dek_member_grant_recipients(&comm, &a.key, 0)
                .await
                .unwrap(),
            before,
            "{tag} I62: re-emission un-granted somebody"
        );

        // (3) v55.0.0 (#989, CC 3.3.2) — a later row with the SAME identity
        // and different wrap bytes (a re-wrap, at a fresh signed instant) is
        // admitted and changes nothing: the union key is the identity, and
        // CC 2's latest-wins over `(attester, dimension, attested)` does not
        // apply to the family.
        let mut rewrap = KeyGrantRow::from_attestation(&to_b).unwrap();
        rewrap.wrap.wrapped_dek =
            "{\"algorithm\":\"x25519_mlkem768_aes256_gcm_hkdf_sha256\"}".into();
        let later = admit_replicated(b.backend, sign_row_unstored(&a.signer, &rewrap).await)
            .await
            .unwrap_or_else(|e| panic!("{tag} I62: a re-wrap is admitted: {e}"));
        assert!(later.projected, "{tag} I62: {later:?}");
        assert_eq!(
            b.backend
                .community_dek_member_grant_wrap(&comm, &a.key, 0, &b.key)
                .await
                .unwrap()
                .expect("still held"),
            wrap_before,
            "{tag} I62: a wrap once admitted is never replaced by a later one"
        );

        // (4) A wrap to a key outside the audience adds nothing and removes
        // nothing: refused at the gate (`recipient_not_in_audience`).
        let mut outside = rewrap.clone();
        outside.wrap.recipient_key_id = format!("{tag}-late-occ-{run}");
        let err = admit_replicated(b.backend, sign_row_unstored(&a.signer, &outside).await)
            .await
            .expect_err("a wrap to a non-occurrence is refused");
        assert_eq!(refusal_reason(&err), "recipient_not_in_audience");
        assert_eq!(
            b.backend
                .community_dek_member_grant_recipients(&comm, &a.key, 0)
                .await
                .unwrap(),
            before,
            "{tag} I62: a refused row must remove NOTHING and add nothing (CC 3: cannot un-share)"
        );

        // (5) Now the bytes arrive — and open.
        carry_bytes(
            a,
            b,
            &sha,
            COMMUNITY,
            &comm,
            Some(0),
            CryptoTier::CommunityDek,
            &[],
        )
        .await
        .unwrap();
        assert_eq!(
            read_any_for_viewer(b.backend, &sha, &b.key, None)
                .await
                .unwrap(),
            b"v1",
            "{tag} I62: a row admitted before its bytes is read when they arrive"
        );
    }

    // ── I63 ──────────────────────────────────────────────────────────────
    /// **B admits A's revocation of X; B's next seal is under a new B-epoch;
    /// the old B-epoch is `disabled`; X is absent from B's new set.**
    pub async fn exercise_i63_rotation_on_admitted_removal<B>(
        a: &Node<'_, B>,
        b: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = e2::kid(&format!("{tag}-comm-{run}"));
        let alice = e2::kid(&format!("{tag}-alice-{run}"));
        let bob = e2::kid(&format!("{tag}-bob-{run}"));
        let xavier = e2::kid(&format!("{tag}-xavier-{run}"));
        // X has an occurrence on A's node (it is A's device that X uses);
        // what matters is X is on the roster and gets wrapped to.
        seed_community_everywhere(
            &[a, b],
            &comm,
            &[(&alice, Some(a)), (&bob, Some(b)), (&xavier, None)],
        )
        .await;
        // GID-fixtures-sites — the room's DERIVED id, once founded (`room_id`
        // panics if it was not).
        let comm = crate::federation::edition2::fixture_switch::room_id(&comm);
        // Give X an occurrence with keys on both nodes so B wraps to it.
        let x_occ = e2::kid(&format!("{tag}-x-occ-{run}"));
        for n in [a, b] {
            ts::register_hybrid_key_as(n.backend, &x_occ, &x_occ, USER).await;
            crate::federation::at_rest_cascade::blob_invariants::join_as_occurrence(
                n.backend, &xavier, &x_occ,
            )
            .await;
        }

        // B seals under (C, B, 0): X is granted.
        let first = encrypt_and_cascade_community(b.backend, &comm, b"before", None, Some(&b.key))
            .await
            .unwrap();
        assert_eq!(first.epoch, 0);
        assert!(
            first.granted.contains(&x_occ),
            "{tag} I63: X granted at B's e0"
        );
        let e0_minted = b
            .backend
            .community_dek_minted_at(&comm, &b.key, 0)
            .await
            .unwrap()
            .expect("minted_at recorded");

        // A revokes X (signed by the community key A holds); B ADMITS the
        // replicated revocation through its directory door — the only way a
        // removal reaches a non-revoker.
        let removed_at = chrono::Utc::now();
        assert!(
            removed_at >= e0_minted,
            "{tag} I63: the removal is newer than the mint"
        );
        // v62.0.0 (T1) — the removal is its `membership:removal` voices
        // naming the held roster version: X's own (v49.0.0, #908: the member
        // leaves on their own signature) and the other members', so the
        // community's majority is met outright. Put on A, then DELIVERED to B
        // through B's replicated statement door.
        let rev = community_removal_voices(
            a.backend,
            &comm,
            &xavier,
            removed_at,
            removed_at,
            &[&xavier, &alice, &bob],
        )
        .await;
        match e2::put_voices(a.backend, &rev).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("{tag} I63: A holds the removal: {other:?}"),
        }
        deliver_statements(b.backend, &rev)
            .await
            .unwrap_or_else(|e| panic!("{tag} I63: B admits A's revocation: {e}"));

        // B's next seal: a NEW B-epoch, the old one disabled, X absent.
        let second = encrypt_and_cascade_community(b.backend, &comm, b"after", None, Some(&b.key))
            .await
            .unwrap();
        assert!(
            second.epoch > first.epoch,
            "{tag} I63: B's next seal must be under a new B-epoch ({} -> {})",
            first.epoch,
            second.epoch
        );
        assert_eq!(
            b.backend
                .community_dek_key_state(&comm, &b.key, first.epoch)
                .await
                .unwrap(),
            Some(crate::federation::DekKeyState::Disabled),
            "{tag} I63: the old B-epoch is disabled"
        );
        assert!(
            !second.granted.contains(&x_occ),
            "{tag} I63: X is absent from B's new set: {:?}",
            second.granted
        );
        let new_set =
            crate::federation::key_grant::build_epoch_set(b.backend, &comm, &b.key, second.epoch)
                .await
                .unwrap()
                .expect("B holds wraps at the new epoch");
        assert!(
            new_set.wraps.iter().all(|w| w.recipient_key_id != x_occ),
            "{tag} I63: the new KeyGrant set carries no wrap for X"
        );
        // X keeps e0 (AV-70): forward-only.
        assert!(
            b.backend
                .community_dek_has_member_grant(&comm, &b.key, first.epoch, &x_occ)
                .await
                .unwrap(),
            "{tag} I63: X keeps its pre-rotation grant (AV-70)"
        );
    }

    // ── I64 ──────────────────────────────────────────────────────────────
    /// **Two minters at the same epoch number coexist**: B's viewer opens A's
    /// content at (C, A, 3) and C's content at (C, C, 3).
    pub async fn exercise_i64_two_minters_same_epoch<B>(
        a: &Node<'_, B>,
        b: &Node<'_, B>,
        c: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = e2::kid(&format!("{tag}-comm-{run}"));
        let alice = e2::kid(&format!("{tag}-alice-{run}"));
        let bob = e2::kid(&format!("{tag}-bob-{run}"));
        let carol = e2::kid(&format!("{tag}-carol-{run}"));
        seed_community_everywhere(
            &[a, b, c],
            &comm,
            &[(&alice, Some(a)), (&bob, Some(b)), (&carol, Some(c))],
        )
        .await;
        // GID-fixtures-sites — the room's DERIVED id, once founded (`room_id`
        // panics if it was not).
        let comm = crate::federation::edition2::fixture_switch::room_id(&comm);
        // Both A and C advance their OWN counters to 3.
        for n in [a, c] {
            for _ in 0..3 {
                n.backend
                    .community_dek_bump_epoch(&comm, &n.key)
                    .await
                    .unwrap();
            }
        }
        let from_a = encrypt_and_cascade_community(a.backend, &comm, b"from A", None, Some(&a.key))
            .await
            .unwrap();
        let from_c = encrypt_and_cascade_community(c.backend, &comm, b"from C", None, Some(&c.key))
            .await
            .unwrap();
        assert_eq!(
            (from_a.epoch, from_c.epoch),
            (3, 3),
            "{tag} I64: both at epoch 3"
        );
        assert_ne!(from_a.at_rest_sha256, from_c.at_rest_sha256);

        for (n, epoch_holder) in [(a, &from_a), (c, &from_c)] {
            let emitted = emit_epoch_key_grant_with_local_signer(n.backend, &n.signer, &comm, 3)
                .await
                .unwrap()
                .expect("wraps");
            carry_key_grants(n, b, &emitted)
                .await
                .unwrap_or_else(|e| panic!("{tag} I64: B admits {}'s rows: {e}", n.key));
            carry_bytes(
                n,
                b,
                &epoch_holder.at_rest_sha256,
                COMMUNITY,
                &comm,
                Some(3),
                CryptoTier::CommunityDek,
                &[],
            )
            .await
            .unwrap();
        }
        // Two grants, two DEKs, one epoch number — both open on B.
        assert!(b
            .backend
            .community_dek_has_member_grant(&comm, &a.key, 3, &b.key)
            .await
            .unwrap());
        assert!(b
            .backend
            .community_dek_has_member_grant(&comm, &c.key, 3, &b.key)
            .await
            .unwrap());
        assert_eq!(
            read_any_for_viewer(b.backend, &from_a.at_rest_sha256, &b.key, None)
                .await
                .unwrap(),
            b"from A",
            "{tag} I64: A's content at (C, A, 3)"
        );
        assert_eq!(
            read_any_for_viewer(b.backend, &from_c.at_rest_sha256, &b.key, None)
                .await
                .unwrap(),
            b"from C",
            "{tag} I64: C's content at (C, C, 3)"
        );
        assert_eq!(
            b.backend
                .community_dek_blob_epoch(&from_a.at_rest_sha256)
                .await
                .unwrap(),
            Some((comm.clone(), a.key.clone(), 3))
        );
        assert_eq!(
            b.backend
                .community_dek_blob_epoch(&from_c.at_rest_sha256)
                .await
                .unwrap(),
            Some((comm.clone(), c.key.clone(), 3))
        );
    }

    // ── I65 ──────────────────────────────────────────────────────────────
    /// **I1519** (v61 S2, the release lead's ruling on #1148) — a self-axis
    /// grant to a person's key reaches every node that hosts an occurrence
    /// of that key. The key-grant door's own audience rule
    /// (`recipient_not_in_audience`) is its gate, not the #1148 node-key
    /// comparison. `b` hosts an occurrence of `a.key` and admits A's row
    /// naming `a.key`; `c` hosts none and refuses it
    /// `recipient_not_in_audience`. Both receivers have declared their node
    /// key (the runner sets it), so the #1148 put-time gate is live on both.
    pub async fn exercise_i1519_a_self_grant_reaches_the_persons_occurrences<B>(
        a: &Node<'_, B>,
        b: &Node<'_, B>,
        c: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
        let occurrence = |_n: &Node<'_, B>| crate::federation::types::IdentityOccurrence {
            identity_key_id: a.key.clone(),
            occurrence_key_id: a.key.clone(),
            device_class: crate::federation::types::device_class::LAPTOP.into(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: Some(a.kem.clone()),
            transport_binding: None,
            persist_row_hash: String::new(),
        };
        for n in [a, b] {
            n.backend
                .test_seam_put_identity_occurrence(occurrence(n))
                .await
                .unwrap_or_else(|e| panic!("{tag} I1519: occurrence of A on a node: {e}"));
        }
        let sealed = encrypt_and_cascade(
            a.backend,
            SELF,
            &a.key,
            b"i1519 self",
            None,
            None,
            Some(&a.key),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I1519: A seals self: {e}"));
        let emitted = emit_content_key_grant_with_local_signer(
            a.backend,
            &a.signer,
            &sealed.at_rest_sha256,
            SELF,
            &a.key,
        )
        .await
        .unwrap()
        .expect("wraps");
        let mut row = None;
        for id in &emitted.attestation_ids {
            let r = a
                .backend
                .get_attestation(id)
                .await
                .unwrap()
                .expect("emitted");
            if r.attested_key_id == a.key {
                row = Some(r);
            }
        }
        let row = row.expect("A's self-axis row names A's key");
        let got = admit_replicated(
            b.backend,
            SignedKeyGrantRow {
                attestation: row.clone(),
            },
        )
        .await
        .unwrap_or_else(|e| {
            panic!("{tag} I1519: a node hosting an occurrence of the recipient admits: {e}")
        });
        assert_eq!(got.recipient_key_id, a.key, "{tag} I1519");
        let err = admit_replicated(
            c.backend,
            SignedKeyGrantRow {
                attestation: row.clone(),
            },
        )
        .await
        .expect_err("a node hosting no occurrence of the recipient");
        assert_eq!(
            refusal_reason(&err),
            "recipient_not_in_audience",
            "{tag} I1519: {err}"
        );
        // v61.0.1 (CIRISPersist#1184), v62.0.0 (E11) — a different row
        // offered under a HELD id is refused, typed, before anything is
        // stored. In edition 2 a row's id is the one this node computes from
        // the statement's bytes (CC 2.6.1.3): A's own re-signed wrap with its
        // ciphertext altered is a different statement, and a peer offering it
        // under the id of the row B holds is refused `row_id_mismatch`, so no
        // host reads the cause out of the message.
        let mut altered = KeyGrantRow::from_attestation(&row).expect("a key-grant row");
        let mut wrap: serde_json::Value =
            serde_json::from_str(&altered.wrap.wrapped_dek).expect("the wrap is JSON");
        wrap["ciphertext_b64"] = serde_json::json!(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [0u8; 48]
        ));
        altered.wrap.wrapped_dek = wrap.to_string();
        let altered = sign_row_unstored(&a.signer, &altered).await.attestation;
        let altered_st = e2::carried_statement(&altered).expect("an edition-2 row");
        assert_ne!(
            e2::rid(&altered),
            e2::rid(&row),
            "{tag} I1519: a different row"
        );
        let err = apply_replicated_statement(b.backend, &altered_st, &e2::rid_digest(&row))
            .await
            .expect_err("a different row under a held id");
        assert_eq!(
            token_of(&err),
            crate::federation::malformed_row::EDITION2_ROW_ID_MISMATCH,
            "{tag} I1519 (#1184): the refusal is typed: {err}"
        );
        assert!(
            b.backend
                .get_attestation(&e2::rid(&altered))
                .await
                .unwrap()
                .is_none(),
            "{tag} I1519: nothing is stored under the offered or the computed id"
        );
    }

    /// **Content axis**: the owner's second occurrence on B opens a self blob
    /// sealed on A once A's set is admitted on B.
    pub async fn exercise_i65_content_axis_second_device<B>(
        a: &Node<'_, B>,
        a2: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let owner = e2::kid(&format!("{tag}-owner-{run}"));
        // The owner's identity, with BOTH devices as active occurrences, on
        // both nodes' directories.
        for n in [a, a2] {
            ts::register_hybrid_key_as(n.backend, &owner, &owner, USER).await;
            for dev in [a, a2] {
                n.backend
                    .test_seam_put_identity_occurrence(
                        crate::federation::types::IdentityOccurrence {
                            identity_key_id: owner.clone(),
                            occurrence_key_id: dev.key.clone(),
                            device_class: crate::federation::types::device_class::LAPTOP.into(),
                            hardware_attestation: None,
                            asserted_at: chrono::Utc::now(),
                            valid_until: None,
                            encryption_pubkeys: Some(dev.kem.clone()),
                            transport_binding: None,
                            persist_row_hash: String::new(),
                        },
                    )
                    .await
                    .unwrap();
            }
        }
        // A seals a self blob: fresh DEK, wrapped to both devices.
        let sealed = encrypt_and_cascade(
            a.backend,
            SELF,
            &owner,
            b"my photo",
            None,
            None,
            Some(&a.key),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I65: A seals self: {e}"));
        assert!(
            sealed.granted.contains(&a2.key),
            "{tag} I65: the second device is granted"
        );
        let sha = sealed.at_rest_sha256;
        // (1) A FORGED content row from the owner's LOST device — its
        // occurrence revoked, no owner binding — which still knows the DEK,
        // naming an outsider, delivered BEFORE the bytes. v46.3.0 (#884,
        // §4.1): an ACTIVE occurrence of the owner speaks with the owner's
        // voice on the key plane (the sealing node is one); a revoked one
        // does not. v55.0.0 (#989): the sealer rule asks that at admission, on
        // the self axis, before the bytes name the author — refused
        // (retryable `SignerDoesNotActFor`, plane `key_grant`), nothing stored.
        // Revoked NOW: `IdentityOccurrenceRevocation::revokes` treats an
        // occurrence asserted after its revocation as re-established.
        let lost = node_signer(a2.backend, &format!("{tag}-lost-{run}")).await;
        let lost_key = lost.federation_id().await;
        a2.backend
            .test_seam_put_identity_occurrence(crate::federation::types::IdentityOccurrence {
                identity_key_id: owner.clone(),
                occurrence_key_id: lost_key.clone(),
                device_class: crate::federation::types::device_class::LAPTOP.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now() - chrono::Duration::seconds(5),
                valid_until: None,
                encryption_pubkeys: Some(a.kem.clone()),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap();
        let revoked_at = chrono::Utc::now();
        a2.backend
            .put_identity_occurrence_revocation_edition2(
                crate::federation::types::IdentityOccurrenceRevocation {
                    identity_key_id: owner.clone(),
                    occurrence_key_id: lost_key.clone(),
                    revoked_at,
                    effective_at: revoked_at,
                    reason: Some("lost device (I65)".into()),
                    witness_set: vec![],
                    persist_row_hash: String::new(),
                },
                crate::federation::DoorToken::new(),
            )
            .await
            .unwrap_or_else(|e| panic!("{tag} I65: the lost device's occurrence is revoked: {e}"));
        let outsider = e2::kid(&format!("{tag}-outsider-{run}"));
        let forged = KeyGrantRow {
            axis: KeyGrantAxis::Content {
                at_rest_sha256: hex::encode(sha),
                cohort_scope: SELF.into(),
                owner_key_id: owner.clone(),
            },
            wrap: crate::federation::GrantWrap {
                recipient_key_id: outsider.clone(),
                wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2.into(),
                wrapped_dek: "{}".into(),
            },
        };
        let forged_row = sign_row_unstored(&lost, &forged).await;
        let forged_id = forged_row.attestation.attestation_id.clone();
        let err = admit_replicated(a2.backend, forged_row)
            .await
            .expect_err("a revoked device does not speak for the owner");
        assert_eq!(
            refusal_reason(&err),
            "signer_not_acting_for",
            "{tag} I65: {err}"
        );
        assert!(
            a2.backend
                .get_attestation(&forged_id)
                .await
                .unwrap()
                .is_none(),
            "{tag} I65: the forged row is not stored"
        );
        assert!(
            a2.backend
                .get_at_rest_grant(&sha, &outsider)
                .await
                .unwrap()
                .is_none(),
            "{tag} I65: the outsider has no grant row"
        );
        // (2) The AUTHOR's rows, also before the bytes: the plane delivers
        // the second device its own, pending, nothing projected yet.
        let emitted =
            emit_content_key_grant_with_local_signer(a.backend, &a.signer, &sha, SELF, &owner)
                .await
                .unwrap()
                .expect("wraps");
        let admissions = carry_key_grants(a, a2, &emitted)
            .await
            .unwrap_or_else(|e| panic!("{tag} I65: the second device admits its row: {e}"));
        assert_eq!(admissions.len(), 1, "{tag} I65: {admissions:?}");
        let admission = &admissions[0];
        assert_eq!(
            match &admission.axis {
                KeyGrantAxis::Content { at_rest_sha256, .. } => at_rest_sha256.clone(),
                other => panic!("{other:?}"),
            },
            hex::encode(sha)
        );
        assert!(
            admission.pending && !admission.projected,
            "{tag} I65: the author's row is pending until the bytes name the author: {admission:?}"
        );
        assert!(
            a2.backend
                .get_at_rest_grant(&sha, &a2.key)
                .await
                .unwrap()
                .is_none(),
            "{tag} I65: nothing projects before the author is known"
        );
        // The second device's operator names the first as family (#846 §4):
        // that is what makes it party to the owner's own content.
        carry_bytes(
            a,
            a2,
            &sha,
            SELF,
            &owner,
            None,
            CryptoTier::InvisibleEncrypted,
            std::slice::from_ref(&a.key),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I65: the second device adopts: {e}"));
        // (3) The adopt named the author: the author's set projected, the
        // forged one did not and never will (order independence, kept).
        assert!(
            a2.backend
                .get_at_rest_grant(&sha, &a2.key)
                .await
                .unwrap()
                .is_some(),
            "{tag} I65: the second device's grant row landed with the bytes"
        );
        assert!(
            a2.backend
                .get_at_rest_grant(&sha, &outsider)
                .await
                .unwrap()
                .is_none(),
            "{tag} I65: a row the author did not sign never projects"
        );
        // The pending index (V146) was TAKEN by the adopt: nothing left.
        assert!(
            a2.backend
                .key_grant_pending_list(&sha, SELF)
                .await
                .unwrap()
                .is_empty(),
            "{tag} I65: the adopt retired every pending row for the blob"
        );
        // (4) A re-delivered author row after the bytes projects directly —
        // the row is present, the author is checked, the wrap already held.
        let to_a2 = emitted_row_for(a, &emitted, &a2.key).await;
        let again = carry_key_grant(a, a2, &to_a2.attestation_id)
            .await
            .unwrap_or_else(|e| panic!("{tag} I65: re-delivery: {e}"));
        assert!(!again.pending && again.projected, "{tag} I65: {again:?}");
        assert!(
            a2.backend
                .get_at_rest_grant(&sha, crate::federation::at_rest_cascade::PERSIST_SELF_RECIPIENT)
                .await
                .unwrap()
                .is_none(),
            "{tag} I65: no persist self-retention on the second device — the open comes from its grant"
        );
        assert_eq!(
            read_any_for_viewer(a2.backend, &sha, &a2.key, None)
                .await
                .unwrap_or_else(|e| panic!("{tag} I65: the second device opens: {e}")),
            b"my photo"
        );
        // Order independence on the content axis: a stranger stays refused.
        let err = read_any_for_viewer(a2.backend, &sha, &format!("{tag}-stranger-{run}"), None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, BlobError::NotGranted { .. }),
            "{tag} I65: {err:?}"
        );
        let err = read_any_for_viewer(a2.backend, &sha, &outsider, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, BlobError::NotGranted { .. }),
            "{tag} I65: the outsider the forged row named stays refused: {err:?}"
        );
        // (5) A retroactive ADD on the ADOPTING node (PR #850, round three):
        // the owner admits a third device on a2. The peer-authored blob is
        // not this node's to re-wrap (no self-retention here) — the walk
        // skips it rather than aborting, and grants it nothing.
        let dev3 = e2::kid(&format!("{tag}-dev3-{run}"));
        ts::register_hybrid_key_as(a2.backend, &dev3, &dev3, USER).await;
        a2.backend
            .test_seam_put_identity_occurrence(crate::federation::types::IdentityOccurrence {
                identity_key_id: owner.clone(),
                occurrence_key_id: dev3.clone(),
                device_class: crate::federation::types::device_class::SERVER.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(a.kem.clone()),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap();
        let rk = crate::federation::at_rest_cascade::orchestrate::rekey_self_occurrence_add(
            a2.backend,
            &owner,
            std::slice::from_ref(&dev3),
            chrono::Utc::now(),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I65: a rekey on the adopting node must not abort: {e}"));
        assert!(
            !rk.changed_blobs.contains(&sha),
            "{tag} I65: the peer-authored blob is not re-wrapped here"
        );
        assert!(
            a2.backend
                .get_at_rest_grant(&sha, &dev3)
                .await
                .unwrap()
                .is_none(),
            "{tag} I65: only the author's node can grant the third device"
        );
    }

    // ── I800 ─────────────────────────────────────────────────────────────
    /// **I800 (Codex r3 on #1065) — the blob-arrival race.** An unrelated
    /// signer's content row, admitted while the bytes were absent, reaches
    /// the DIRECT projection after the blob arrived (the author now held):
    /// it projects nothing (`NotAuthor`) and occupies no grant row, and the
    /// author's own row then lands and the device opens the blob.
    pub async fn exercise_i800_the_blob_arrival_race<B>(
        a: &Node<'_, B>,
        a2: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
        use crate::federation::key_grant::{project_key_grant_row, KeyGrantProjection};
        let run = uuid::Uuid::new_v4().simple().to_string();
        let owner = e2::kid(&format!("{tag}-owner-{run}"));
        for n in [a, a2] {
            ts::register_hybrid_key_as(n.backend, &owner, &owner, USER).await;
            for dev in [a, a2] {
                n.backend
                    .test_seam_put_identity_occurrence(
                        crate::federation::types::IdentityOccurrence {
                            identity_key_id: owner.clone(),
                            occurrence_key_id: dev.key.clone(),
                            device_class: crate::federation::types::device_class::LAPTOP.into(),
                            hardware_attestation: None,
                            asserted_at: chrono::Utc::now(),
                            valid_until: None,
                            encryption_pubkeys: Some(dev.kem.clone()),
                            transport_binding: None,
                            persist_row_hash: String::new(),
                        },
                    )
                    .await
                    .unwrap();
            }
        }
        let sealed = encrypt_and_cascade(
            a.backend,
            SELF,
            &owner,
            b"race photo",
            None,
            None,
            Some(&a.key),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I800: A seals: {e}"));
        let sha = sealed.at_rest_sha256;
        // The unrelated signer's row, built off-node.
        let stranger = node_signer(a2.backend, &format!("{tag}-x-{run}")).await;
        let forged = sign_row_unstored(
            &stranger,
            &KeyGrantRow {
                axis: KeyGrantAxis::Content {
                    at_rest_sha256: hex::encode(sha),
                    cohort_scope: SELF.into(),
                    owner_key_id: owner.clone(),
                },
                wrap: crate::federation::GrantWrap {
                    recipient_key_id: a2.key.clone(),
                    wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2.into(),
                    wrapped_dek: "{}".into(),
                },
            },
        )
        .await;
        // The bytes arrive (the author is named), THEN the projection runs.
        carry_bytes(
            a,
            a2,
            &sha,
            SELF,
            &owner,
            None,
            CryptoTier::InvisibleEncrypted,
            std::slice::from_ref(&a.key),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I800: the device adopts: {e}"));
        assert_eq!(
            project_key_grant_row(a2.backend, &forged.attestation)
                .await
                .unwrap(),
            KeyGrantProjection::NotAuthor,
            "{tag} I800: the stranger's row projects nothing"
        );
        assert!(
            a2.backend
                .get_at_rest_grant(&sha, &a2.key)
                .await
                .unwrap()
                .is_none(),
            "{tag} I800: the device's grant row is not occupied"
        );
        // The author's row lands and opens.
        let emitted =
            emit_content_key_grant_with_local_signer(a.backend, &a.signer, &sha, SELF, &owner)
                .await
                .unwrap()
                .expect("wraps");
        carry_key_grants(a, a2, &emitted)
            .await
            .unwrap_or_else(|e| panic!("{tag} I800: the author's row: {e}"));
        assert_eq!(
            read_any_for_viewer(a2.backend, &sha, &a2.key, None)
                .await
                .unwrap_or_else(|e| panic!("{tag} I800: the device opens: {e}")),
            b"race photo"
        );
    }

    // ── I199 ─────────────────────────────────────────────────────────────
    /// **I199 (CIRISPersist#953) — a family member publishes a family blob
    /// and another member's node opens it.** The content-axis set names its
    /// family as the cohort target the write gate reads (`family_key_id`), so
    /// the author's own door stores it and the peer's apply door admits it.
    /// Before #953 the set carried the family only as `owner_key_id`, and
    /// both doors refused it `scope_no_family_membership`.
    pub async fn exercise_i199_family_member_publishes_and_another_opens<B>(
        a: &Node<'_, B>,
        b: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
        use crate::federation::types::cohort_scope::FAMILY;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let fam = e2::kid(&format!("{tag}-fam-{run}"));
        let alice = e2::kid(&format!("{tag}-alice-{run}"));
        let bob = e2::kid(&format!("{tag}-bob-{run}"));
        let household =
            family_roster_voices(&fam, "I199 Household", &[alice.as_str(), bob.as_str()]);
        for n in [a, b] {
            ts::register_hybrid_key_as(n.backend, &fam, &fam, USER).await;
            for (ident, dev) in [(&alice, a), (&bob, b)] {
                ts::register_hybrid_key_as(n.backend, ident, ident, USER).await;
                // v53.0.0 (#963, CC 3.3.7) — a member's PERSONAL device: a
                // server-class occurrence holds no family content by default.
                n.backend
                    .test_seam_put_identity_occurrence(
                        crate::federation::types::IdentityOccurrence {
                            identity_key_id: ident.clone(),
                            occurrence_key_id: dev.key.clone(),
                            device_class: crate::federation::types::device_class::LAPTOP.into(),
                            hardware_attestation: None,
                            asserted_at: chrono::Utc::now(),
                            valid_until: None,
                            encryption_pubkeys: Some(dev.kem.clone()),
                            transport_binding: None,
                            persist_row_hash: String::new(),
                        },
                    )
                    .await
                    .unwrap_or_else(|e| panic!("{tag} I199: occurrence of {ident}: {e}"));
            }
            // v62.0.0 (T1) — the family is ONE `group:roster` version (the
            // authority and both members' voices), the same on every node.
            e2::put_voices(n.backend, &household)
                .await
                .unwrap_or_else(|e| panic!("{tag} I199: seed family: {e}"));
        }
        // GID-fixtures-sites — the room's DERIVED id, once founded (`room_id`
        // panics if it was not).
        let fam = crate::federation::edition2::fixture_switch::room_id(&fam);
        let sealed = encrypt_and_cascade(
            a.backend,
            FAMILY,
            &fam,
            b"the household budget",
            None,
            None,
            Some(&a.key),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I199: alice's node seals the family blob: {e}"));
        assert!(
            sealed.granted.contains(&b.key),
            "{tag} I199: bob's occurrence is granted at the seal: {:?}",
            sealed.granted
        );
        let sha = sealed.at_rest_sha256;
        let emitted =
            emit_content_key_grant_with_local_signer(a.backend, &a.signer, &sha, FAMILY, &fam)
                .await
                .unwrap_or_else(|e| {
                    panic!("{tag} I199: the author's own door stores the family rows: {e}")
                })
                .expect("the family blob has wraps");
        let row = emitted_row_for(a, &emitted, &b.key).await;
        assert_eq!(
            crate::federation::admission::envelope_cohort_target(&row.attestation_envelope)
                .unwrap(),
            Some(fam.as_str()),
            "{tag} I199: the row names its family where the write gate reads the target"
        );
        let admitted = carry_key_grants(a, b, &emitted)
            .await
            .unwrap_or_else(|e| panic!("{tag} I199: bob's node admits the family row: {e}"));
        assert_eq!(admitted.len(), 1, "{tag} I199: {admitted:?}");
        carry_bytes(
            a,
            b,
            &sha,
            FAMILY,
            &fam,
            None,
            CryptoTier::InvisibleEncrypted,
            // #960 — NO operator family predicate: production never installs
            // one, so bob's node must find its party-ness in the family
            // roster, not in a predicate the test supplies.
            &[],
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I199: bob's node adopts the family bytes: {e}"));
        // #960 — and a node none of whose principals is in the family is
        // still not party to it, on the same directory.
        let stranger_node = format!("{tag}-stranger-node-{run}");
        assert!(
            !crate::federation::replication::hold::is_audience(
                b.backend,
                FAMILY,
                Some(&fam),
                &a.key,
                |_| false,
                &stranger_node,
            )
            .await
            .unwrap(),
            "{tag} I199: a non-member node is not audience of family content"
        );
        assert!(
            crate::federation::replication::hold::is_audience(
                b.backend,
                FAMILY,
                Some(&fam),
                &a.key,
                |_| false,
                &b.key,
            )
            .await
            .unwrap(),
            "{tag} I199: bob's node is audience by the family roster alone"
        );
        assert_eq!(
            read_any_for_viewer(b.backend, &sha, &b.key, None)
                .await
                .unwrap_or_else(|e| panic!("{tag} I199: bob's node opens the family blob: {e}")),
            b"the household budget"
        );
        let err = read_any_for_viewer(b.backend, &sha, &format!("{tag}-stranger-{run}"), None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, BlobError::NotGranted { .. }),
            "{tag} I199: a non-member stays refused: {err:?}"
        );
    }

    /// **I71 — rotation is keyed on the removal's EFFECTIVE instant** (PR
    /// #850 review). A removal admitted with a future `effective_at` (inside
    /// the skew window) and a bump-and-seal in between mint an epoch NEWER
    /// than `removed_at` that still grants the member. Once the removal takes
    /// effect, the next seal must rotate that epoch too: compared against
    /// `removed_at` it never would.
    pub async fn exercise_i71_rotation_keys_on_effective_at<B>(
        a: &Node<'_, B>,
        b: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = e2::kid(&format!("{tag}-comm-{run}"));
        let alice = e2::kid(&format!("{tag}-alice-{run}"));
        let bob = e2::kid(&format!("{tag}-bob-{run}"));
        let xavier = e2::kid(&format!("{tag}-xavier-{run}"));
        seed_community_everywhere(
            &[a, b],
            &comm,
            &[(&alice, Some(a)), (&bob, Some(b)), (&xavier, None)],
        )
        .await;
        // GID-fixtures-sites — the room's DERIVED id, once founded (`room_id`
        // panics if it was not).
        let comm = crate::federation::edition2::fixture_switch::room_id(&comm);
        let x_occ = e2::kid(&format!("{tag}-x-occ-{run}"));
        for n in [a, b] {
            ts::register_hybrid_key_as(n.backend, &x_occ, &x_occ, USER).await;
            crate::federation::at_rest_cascade::blob_invariants::join_as_occurrence(
                n.backend, &xavier, &x_occ,
            )
            .await;
        }
        let first = encrypt_and_cascade_community(a.backend, &comm, b"e0", None, Some(&a.key))
            .await
            .unwrap();
        assert!(first.granted.contains(&x_occ), "{tag} I71: X granted at e0");
        // The removal is RECORDED now and takes EFFECT shortly (skew window).
        // The window was 400 ms until 61.2.2; under certify's co-tenant load
        // the admit + bump + seal below outran it, so `between` was minted
        // AFTER `effective_at` and the premise assertion went red. 3 s sits
        // well inside COMMUNITY_REVOCATION_MAX_FUTURE_SKEW_SECS (60 s); the
        // sleep below waits for this instant, not a fixed duration.
        let removed_at = chrono::Utc::now();
        let effective_at = removed_at + chrono::Duration::seconds(3);
        // v62.0.0 (T1) — the removal's `membership:removal` voices: X's own
        // (v49.0.0, #908) and the other members', meeting the majority.
        let rev = community_removal_voices(
            a.backend,
            &comm,
            &xavier,
            removed_at,
            effective_at,
            &[&xavier, &alice, &bob],
        )
        .await;
        match e2::put_voices(a.backend, &rev).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("{tag} I71: a future-effective removal is admitted: {other:?}"),
        }
        // Between admission and effect: the revoker's bump, then a seal —
        // an epoch minted AFTER `removed_at` that still grants X.
        a.backend
            .community_dek_bump_epoch(&comm, &a.key)
            .await
            .unwrap();
        let between =
            encrypt_and_cascade_community(a.backend, &comm, b"between", None, Some(&a.key))
                .await
                .unwrap();
        assert!(
            between.epoch > first.epoch,
            "{tag} I71: the bump minted a new epoch"
        );
        assert!(
            between.granted.contains(&x_occ),
            "{tag} I71: before the removal takes effect X is still granted (by design)"
        );
        let between_minted = a
            .backend
            .community_dek_minted_at(&comm, &a.key, between.epoch)
            .await
            .unwrap()
            .expect("minted_at");
        assert!(
            between_minted > removed_at && between_minted < effective_at,
            "{tag} I71: the in-between epoch is minted inside the window \
             ({removed_at} < {between_minted} < {effective_at})"
        );
        let until_effect = (effective_at - chrono::Utc::now())
            .to_std()
            .unwrap_or_default()
            + std::time::Duration::from_millis(200);
        tokio::time::sleep(until_effect).await;
        // The removal is in effect: the next seal must rotate the in-between
        // epoch (its mint predates `effective_at`), disable it, and exclude X.
        let after = encrypt_and_cascade_community(a.backend, &comm, b"after", None, Some(&a.key))
            .await
            .unwrap();
        assert!(
            after.epoch > between.epoch,
            "{tag} I71: the epoch minted before the removal took EFFECT rotates ({} -> {})",
            between.epoch,
            after.epoch
        );
        assert_eq!(
            a.backend
                .community_dek_key_state(&comm, &a.key, between.epoch)
                .await
                .unwrap(),
            Some(crate::federation::DekKeyState::Disabled),
            "{tag} I71: the in-between epoch is disabled"
        );
        assert!(
            !after.granted.contains(&x_occ),
            "{tag} I71: X is absent after the removal takes effect: {:?}",
            after.granted
        );
    }

    /// **I77 (#851 §20.1) — admission asks about the PRINCIPAL.** The
    /// minter is an owned node with NO occurrence row on the admitting node:
    /// refused while no live owner binding lifts it; admitted once the
    /// owner's binding (a replicated statement) is on B and the owner is an
    /// active member; refused again once the owner is removed at
    /// `asserted_at`.
    ///
    /// v62.0.0 (E11) — the owner binding is the owner's `delegates_to`
    /// statement plus the node's own voice, delivered through the replicated
    /// statement door; the rosters and the removal are T1 voices. Leg (7)'s
    /// attack (carol binding A's key under herself) is now refused at the
    /// signed door (`occurrence_mixes_person_and_machine`: a node key is never
    /// a person's occurrence, O1), so its row exists only as a trusted-local
    /// write, which is where the revocation rule is still asked.
    pub async fn exercise_i77_owned_node_minter_admitted_by_principal<B>(
        a: &Node<'_, B>,
        b: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = e2::kid(&format!("{tag}-comm-{run}"));
        let alice = e2::kid(&format!("{tag}-alice-{run}"));
        let bob = e2::kid(&format!("{tag}-bob-{run}"));
        // The seeds the nodes' keys were minted from (their runner aliases).
        let (a_seed, b_seed) = (e2::seed_of(&a.key), e2::seed_of(&b.key));
        // alice is a deterministic-keyed USER on both nodes (the owner binding
        // is her statement); bob likewise; the community on both, as ONE
        // roster version.
        let roster =
            community_roster_voices(&comm, "Principal Co-op", &[alice.as_str(), bob.as_str()]);
        for n in [a, b] {
            ts::register_identity_key(n.backend, &alice, USER).await;
            ts::register_identity_key(n.backend, &bob, USER).await;
            ts::register_hybrid_key_as(n.backend, &comm, &comm, USER).await;
            e2::put_voices(n.backend, &roster)
                .await
                .unwrap_or_else(|e| panic!("{tag} I77: seed community: {e}"));
        }
        // GID-fixtures-sites — the room's DERIVED id, once founded (`room_id`
        // panics if it was not).
        let comm = crate::federation::edition2::fixture_switch::room_id(&comm);
        let local_occurrence =
            |identity: &str,
             occurrence: &str,
             kem: &EncryptionPubkeys,
             asserted_at: chrono::DateTime<chrono::Utc>| {
                crate::federation::types::IdentityOccurrence {
                    identity_key_id: identity.to_owned(),
                    occurrence_key_id: occurrence.to_owned(),
                    device_class: crate::federation::types::device_class::SERVER.into(),
                    hardware_attestation: None,
                    asserted_at,
                    valid_until: None,
                    encryption_pubkeys: Some(kem.clone()),
                    transport_binding: None,
                    persist_row_hash: String::new(),
                }
            };
        // On A only: A's own occurrence under alice (the local decrypt target,
        // trusted-local — exactly what does NOT replicate) and B as bob's
        // device, so A's fan-out has a far recipient. v62.0.0 (E11, round 3):
        // B's key is a NODE on A (the runner introduces it so), and a node key
        // is never bound under a person (CC rc21 way (d)), so B is bob's device
        // by bob's OWNER BINDING plus B's own occurrence ([`bind_member_device`]).
        for (ident, o) in [(&alice, a), (&bob, b)] {
            bind_member_device(a.backend, ident, &o.key, &o.kem).await;
        }
        // On B: bob's own occurrence (B's decrypt target), NOTHING for A.
        bind_member_device(b.backend, &bob, &b.key, &b.kem).await;
        let sealed =
            encrypt_and_cascade_community(a.backend, &comm, b"principal", None, Some(&a.key))
                .await
                .unwrap_or_else(|e| panic!("{tag} I77: A seals: {e}"));
        assert!(
            sealed.granted.contains(&b.key),
            "{tag} I77: A wrapped to B's occurrence"
        );
        let emitted = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
            .await
            .unwrap()
            .expect("A holds wraps");
        let axis = KeyGrantAxis::Epoch {
            community_key_id: comm.clone(),
            minter_key_id: a.key.clone(),
            epoch: 0,
        };
        let to_b = emitted_row_for(a, &emitted, &b.key).await;
        let to_b_signed = SignedKeyGrantRow {
            attestation: to_b.clone(),
        };
        // (1) No occurrence for A on B, no binding: the key-grant rule finds
        // no principal; delivered, the row is held by the write-scope gate,
        // the first fold gate that asks about the signer (CC 2.7), and
        // concludes nothing.
        assert_eq!(
            rule_reason(b.backend, &to_b_signed).await,
            "signer_not_active_member",
            "{tag} I77 (1): the key-grant rule's own verdict"
        );
        let err = carry_key_grant(a, b, &to_b.attestation_id)
            .await
            .expect_err("{tag} I77: an unbound node is nobody's instrument");
        assert_held_by_write_scope(&err, &format!("{tag} I77 (1)"));
        // (2) alice's owner binding for A lands on B (her statement and A's
        // own voice, delivered — what the mesh already carries): admitted.
        let bound_at = chrono::Utc::now() - chrono::Duration::minutes(1);
        deliver_statements(b.backend, &owner_binding_voices(&alice, &a.key, bound_at))
            .await
            .unwrap_or_else(|e| panic!("{tag} I77: B admits alice's owner binding for A: {e}"));
        let admission = carry_key_grant(a, b, &to_b.attestation_id)
            .await
            .unwrap_or_else(|e| panic!("{tag} I77: an owned node lifts to its owner: {e}"));
        assert!(admission.projected, "{tag} I77: {admission:?}");
        assert!(
            b.backend
                .community_dek_has_member_grant(&comm, &a.key, 0, &b.key)
                .await
                .unwrap(),
            "{tag} I77: B's own wrap projected"
        );
        // (3) alice removed, effective before a later row's asserted_at: the
        // principal is no longer a member — refused. v49.0.0 (#908): alice
        // leaves on her own signature; bob's voice meets the majority.
        let removed_at = chrono::Utc::now();
        let rev = community_removal_voices(
            b.backend,
            &comm,
            &alice,
            removed_at,
            removed_at,
            &[&alice, &bob],
        )
        .await;
        match e2::put_voices(b.backend, &rev).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("{tag} I77: B holds alice's removal: {other:?}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        // A later row: A re-signs its wrap to B at a fresh instant (the
        // emitter re-emits nothing it already holds as a row).
        let wrap_to_b = held_row(a, &axis, &b.key).await;
        let later = sign_row_unstored(&a.signer, &wrap_to_b).await;
        assert_eq!(
            rule_reason(b.backend, &later).await,
            "signer_not_active_member",
            "{tag} I77 (3): the key-grant rule's own verdict"
        );
        let err = admit_replicated(b.backend, later)
            .await
            .expect_err("{tag} I77: the removed owner's instrument is refused");
        assert_held_by_write_scope(&err, &format!("{tag} I77 (3)"));
        // A fresh sqlite peer seeded like B was: A's key as a NODE, alice and
        // bob, the same roster version, bob's occurrence B as the recipient
        // (v55.0.0, #989 — the recipient rule asks that the wrap's recipient
        // may hold the key).
        #[cfg(feature = "sqlite")]
        async fn peer(
            a_seed: &str,
            b_seed: &str,
            identities: &[&str],
            roster: &[Vec<u8>],
        ) -> crate::store::sqlite::SqliteBackend {
            let p = crate::store::sqlite::SqliteBackend::open_in_memory()
                .await
                .unwrap();
            crate::store::Backend::run_migrations(&p).await.unwrap();
            ts::register_hybrid_key_as(
                &p,
                a_seed,
                a_seed,
                crate::federation::types::identity_type::NODE,
            )
            .await;
            ts::register_hybrid_key_as(&p, b_seed, b_seed, USER).await;
            for ident in identities {
                ts::register_identity_key(&p, ident, USER).await;
            }
            e2::put_voices(&p, roster)
                .await
                .unwrap_or_else(|e| panic!("I77: seed community on a peer: {e}"));
            p
        }
        // (4) PR #852 round two — a NODE minter lifts only through the live
        // owner binding. v62.0.0 (E11, round 3): the node's occurrence row
        // under alice the earlier leg planted cannot be written at all (the
        // trusted-local door refuses a node key under a person, CC rc21), so
        // the peer holds bob's device B, no binding: no principal; with
        // alice's binding: admitted.
        #[cfg(feature = "sqlite")]
        {
            let c = peer(
                &a_seed,
                &b_seed,
                &[alice.as_str(), bob.as_str(), comm.as_str()],
                &roster,
            )
            .await;
            let err = c
                .test_seam_put_identity_occurrence(local_occurrence(
                    &alice,
                    &a.key,
                    &a.kem,
                    chrono::Utc::now(),
                ))
                .await
                .expect_err("{tag} I77 (4): a node key is never a person's occurrence");
            assert_eq!(
                token_of(&err),
                crate::federation::malformed_row::OCCURRENCE_MIXES_PERSON_AND_MACHINE,
                "{tag} I77 (4): {err}"
            );
            bind_member_device(&c, &bob, &b.key, &b.kem).await;
            assert_eq!(
                rule_reason(&c, &to_b_signed).await,
                "signer_not_active_member",
                "{tag} I77 (4): no binding, no principal"
            );
            deliver_statements(&c, &owner_binding_voices(&alice, &a.key, bound_at))
                .await
                .unwrap_or_else(|e| panic!("{tag} I77 (4): alice's binding on the peer: {e}"));
            admit_replicated(&c, to_b_signed.clone())
                .await
                .unwrap_or_else(|e| panic!("{tag} I77 (4): with the live binding: {e}"));
        }
        // (7) PR #852 round four — an attacker cannot make A's key HER
        // occurrence: carol (a member) is refused at the signed door and at
        // the trusted-local door alike (v62.0.0, CC rc21: a node key is never
        // a person's occurrence), and with alice's binding live A's row is
        // still admitted.
        #[cfg(feature = "sqlite")]
        {
            let carol = e2::kid(&format!("{tag}-carol-{run}"));
            let carol_roster = community_roster_voices(
                &comm,
                "Principal Co-op",
                &[alice.as_str(), bob.as_str(), carol.as_str()],
            );
            let e = peer(
                &a_seed,
                &b_seed,
                &[alice.as_str(), bob.as_str(), carol.as_str(), comm.as_str()],
                &carol_roster,
            )
            .await;
            let err = e2::put_bind(
                &e,
                &carol,
                &carol,
                &a.key,
                crate::federation::types::device_class::SERVER,
                &e2::BindOptions::default(),
            )
            .await
            .expect_err("{tag} I77 (7): a person cannot bind a node's key as her occurrence");
            assert_eq!(
                token_of(&err),
                crate::federation::malformed_row::OCCURRENCE_MIXES_PERSON_AND_MACHINE,
                "{tag} I77 (7): {err}"
            );
            let err = e
                .test_seam_put_identity_occurrence(local_occurrence(
                    &carol,
                    &a.key,
                    &a.kem,
                    chrono::Utc::now(),
                ))
                .await
                .expect_err("{tag} I77 (7): nor as a trusted-local row");
            assert_eq!(
                token_of(&err),
                crate::federation::malformed_row::OCCURRENCE_MIXES_PERSON_AND_MACHINE,
                "{tag} I77 (7): {err}"
            );
            deliver_statements(&e, &owner_binding_voices(&alice, &a.key, bound_at))
                .await
                .unwrap_or_else(|e| panic!("{tag} I77 (7): alice's binding on the peer: {e}"));
            bind_member_device(&e, &bob, &b.key, &b.kem).await;
            let row4 = sign_row_unstored(&a.signer, &wrap_to_b).await;
            admit_replicated(&e, row4).await.unwrap_or_else(|err| {
                panic!("{tag} I77 (7): carol's failed claims must not disable A: {err}")
            });
        }
        // (8) PR #852 round five — ownership moved alice → dave: the live
        // binding is dave's, who is NOT on the roster. A NODE minter has
        // exactly one principal — its live owner — so the row is refused.
        #[cfg(feature = "sqlite")]
        {
            let dave = e2::kid(&format!("{tag}-dave-{run}"));
            let f = peer(
                &a_seed,
                &b_seed,
                &[alice.as_str(), bob.as_str(), dave.as_str(), comm.as_str()],
                &roster,
            )
            .await;
            bind_member_device(&f, &bob, &b.key, &b.kem).await;
            deliver_statements(&f, &owner_binding_voices(&dave, &a.key, bound_at))
                .await
                .unwrap_or_else(|e| panic!("{tag} I77 (8): dave's binding on the peer: {e}"));
            assert_eq!(
                rule_reason(&f, &to_b_signed).await,
                "signer_not_active_member",
                "{tag} I77 (8): the owner off the roster is no principal"
            );
            let err = admit_replicated(&f, to_b_signed.clone())
                .await
                .expect_err("{tag} I77 (8): a node owned off the roster is not a member");
            assert_held_by_write_scope(&err, &format!("{tag} I77 (8)"));
        }
    }

    /// **I76 (#851 §20.2) — the content-only signed occurrence.** The
    /// identity binds its device with KEM pubkeys and no transport
    /// destination; the bind is admitted and advertised; a trusted-local
    /// row is not (I78).
    ///
    /// v62.0.0 (E11, O1) — an occurrence is an `identity:occurrence` bind:
    /// the occurrence key's own statement, then the identity's (the author).
    /// A node no longer vouches for itself through its owner binding: the
    /// identity authors, and a node's key is never a person's occurrence
    /// (`occurrence_mixes_person_and_machine`, whatever binding is live). The
    /// legs map:
    /// - (1) unbound → P8's producer with no author pen states the device's
    ///   own voice, drafts the author's, and lands nothing;
    /// - (2) admitted, advertised → with the identity's pen the bind lands,
    ///   and the signed listing serves it with its statements;
    /// - (3)/(6) another identity / a diverging attester → a bind whose
    ///   author is not its identity is refused `edition2_payload_invalid`;
    /// - (8) future-dated → the skew bound refuses the author's voice;
    /// - (9) a node vouching for a sibling key → the node's own key under
    ///   its owner is refused, and an agent's occurrence binds the AGENT's
    ///   identity, authored by its owner (CC 3.3.6).
    pub async fn exercise_i76_content_only_occurrence<B>(n: &Node<'_, B>, alias: &str, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::malformed_row;
        use crate::federation::types::device_class::{AGENT, PHONE, SERVER};
        let _ = alias;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let alice = e2::kid(&format!("{tag}-alice-{run}"));
        let carol = e2::kid(&format!("{tag}-carol-{run}"));
        ts::register_identity_key(n.backend, &alice, USER).await;
        ts::register_identity_key(n.backend, &carol, USER).await;
        // alice's personal device: a USER key (a person's occurrence key),
        // and the two pens of the producer (P8): the device's own signer and
        // alice's.
        let phone_seed = format!("{tag}-phone-{run}");
        let phone = e2::put_key(n.backend, &phone_seed, &[USER]).await;
        let phone_signer = ts::local_signer(&phone_seed);
        let alice_signer = ts::local_signer(&e2::seed_of(&alice));
        let opts = |at: chrono::DateTime<chrono::Utc>| e2::BindOptions {
            asserted_at_ms: ms(at),
            valid_until_ms: None,
            extra: vec![encryption_member(&n.kem)],
            head: None,
            further_heads: vec![],
        };
        // (1) The device publishes with no author in hand: its own voice is
        // stated, alice's is drafted for her pen, and nothing lands.
        let drafted = publish_self_occurrence_with_local_signer(
            n.backend,
            &phone_signer,
            &alice,
            PHONE,
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I76: the device states its own voice: {e}"));
        assert!(
            !drafted.landed
                && drafted.own_voice.is_some()
                && drafted.author_voice.is_none()
                && drafted.author_draft.is_some(),
            "{tag} I76: the device's word alone lands nothing; the author's voice is a draft"
        );
        assert!(
            n.backend
                .lookup_identity_for_occurrence(&phone)
                .await
                .unwrap()
                .is_none(),
            "{tag} I76: nothing binds on the device's word alone"
        );
        // (2) With alice's pen the bind lands: content-only, advertised.
        let published = publish_self_occurrence_with_local_signer(
            n.backend,
            &phone_signer,
            &alice,
            PHONE,
            None,
            Some(alice_signer.as_ref()),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I76: the identity's voice lands the bind: {e}"));
        assert!(published.landed, "{tag} I76: the bind landed");
        let voices: Vec<Vec<u8>> = [published.own_voice.clone(), published.author_voice.clone()]
            .into_iter()
            .flatten()
            .collect();
        assert_eq!(voices.len(), 2, "{tag} I76: the own voice and the author's");
        let row = n
            .backend
            .lookup_identity_for_occurrence(&phone)
            .await
            .unwrap()
            .expect("the occurrence exists");
        assert_eq!(row.identity_key_id, alice);
        assert!(row.encryption_pubkeys.is_some() && row.transport_binding.is_none());
        assert!(
            n.backend
                .list_signed_identity_occurrences_for(&alice)
                .await
                .unwrap()
                .iter()
                .any(|s| s.identity_occurrence.occurrence_key_id == phone),
            "{tag} I78: the bind is advertised by the signed listing"
        );
        let served = bind_statements_for(n.backend, &alice).await;
        assert!(
            voices.iter().all(|v| served.contains(v)),
            "{tag} I78: the listing serves every voice of the bind"
        );
        // I78: a trusted-local row is never advertised.
        let local_occ = e2::put_key(n.backend, &format!("{tag}-local-{run}"), &[USER]).await;
        n.backend
            .test_seam_put_identity_occurrence(crate::federation::types::IdentityOccurrence {
                identity_key_id: alice.clone(),
                occurrence_key_id: local_occ.clone(),
                device_class: SERVER.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(n.kem.clone()),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap();
        assert!(
            !n.backend
                .list_signed_identity_occurrences_for(&alice)
                .await
                .unwrap()
                .iter()
                .any(|s| s.identity_occurrence.occurrence_key_id == local_occ),
            "{tag} I78: a trusted-local row is not on the plane"
        );
        // (3)/(6) A bind of alice's device under carol that carol did not
        // author (alice's statement naming carol's identity): refused.
        let err = e2::put_bind(
            n.backend,
            &alice,
            &carol,
            &phone,
            PHONE,
            &opts(chrono::Utc::now()),
        )
        .await
        .expect_err("{tag} I76: an identity is bound only by its own statement");
        assert_eq!(
            token_of(&err),
            malformed_row::EDITION2_PAYLOAD_INVALID,
            "{tag} I76: the author is the identity: {err}"
        );
        // (8) PR #852 round five — a future-dated bind is refused by the
        // write-gate skew bound: a compromised key must not out-rank
        // authentic replacements or escape a later revocation.
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        let err = e2::put_bind(n.backend, &alice, &alice, &phone, PHONE, &opts(future))
            .await
            .expect_err("{tag} I76 (8): a future-dated occurrence is refused");
        assert!(
            err.to_string().to_lowercase().contains("skew")
                || err.to_string().to_lowercase().contains("future"),
            "{tag} I76 (8): the refusal is the skew bound: {err}"
        );
        // (9) The node's own key under its owner: refused, a live owner
        // binding notwithstanding — a node is owned, never a person's device.
        for v in owner_binding_voices(
            &alice,
            &n.key,
            chrono::Utc::now() - chrono::Duration::minutes(1),
        ) {
            e2::put_statement(n.backend, &v).await.unwrap_or_else(|e| {
                panic!("{tag} I76 (9): alice's owner binding of the node: {e}")
            });
        }
        // P8's producer: the node's own voice is the door's refusal, alice's
        // pen notwithstanding (never a machine under a person).
        let err = match publish_self_occurrence_with_local_signer(
            n.backend,
            &n.signer,
            &alice,
            SERVER,
            None,
            Some(alice_signer.as_ref()),
        )
        .await
        {
            Ok(_) => panic!("{tag} I76 (9): a node key is no person's occurrence"),
            Err(e) => e,
        };
        assert_eq!(
            token_of(&err),
            malformed_row::OCCURRENCE_MIXES_PERSON_AND_MACHINE,
            "{tag} I76 (9): {err}"
        );
        // …and an AGENT's occurrence binds the agent's own identity, authored
        // by its owner (v59.0.0, #1099: an agent key is no roster key of a
        // person; CC 3.3.6).
        let agent = e2::put_key(n.backend, &format!("{tag}-agent-{run}"), &[AGENT]).await;
        let agent_key = e2::put_key(n.backend, &format!("{tag}-agent-key-{run}"), &[AGENT]).await;
        let err = e2::put_bind(
            n.backend,
            &alice,
            &alice,
            &agent_key,
            AGENT,
            &opts(chrono::Utc::now()),
        )
        .await
        .expect_err("{tag} I76 (9): an agent key under a person is refused");
        assert_eq!(
            token_of(&err),
            malformed_row::OCCURRENCE_MIXES_PERSON_AND_MACHINE,
            "{tag} I76 (9): {err}"
        );
        e2::put_agent_owner_binding(n.backend, &alice, &agent, ms(chrono::Utc::now()) - 60_000)
            .await;
        match e2::put_bind(
            n.backend,
            &alice,
            &agent,
            &agent_key,
            AGENT,
            &opts(chrono::Utc::now()),
        )
        .await
        {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("{tag} I76 (9): the owner binds its agent's occurrence: {other:?}"),
        }
        assert_eq!(
            n.backend
                .lookup_identity_for_occurrence(&agent_key)
                .await
                .unwrap()
                .map(|o| o.identity_key_id),
            Some(agent.clone()),
            "{tag} I76 (9): the agent's occurrence is the agent's"
        );
    }

    /// **I91 (§21.2, #855) — `valid_until` is one more bound member.**
    /// Stored at millisecond precision, carried in the statement, admitted
    /// by the door; `None` stores NULL; and a re-bind carrying the expiry
    /// KEEPS it — the republish that dropped an operator's expiry is the
    /// defect.
    ///
    /// v62.0.0 (E11) — through P8's producer
    /// (`publish_self_occurrence_with_local_signer`): the device states its
    /// own voice and the identity (`alice`'s pen in hand) authors the O1
    /// `identity:occurrence` bind. The instant is POSIX ms in the signed
    /// payload, so a sub-millisecond expiry is stored at ms.
    pub async fn exercise_i91_a_bind_carries_valid_until<B>(n: &Node<'_, B>, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::types::device_class::PHONE;
        async fn valid_until_of<D: FederationDirectory + ?Sized>(
            d: &D,
            identity: &str,
            occurrence: &str,
        ) -> Option<chrono::DateTime<chrono::Utc>> {
            d.list_identity_occurrences_for(identity)
                .await
                .unwrap()
                .into_iter()
                .find(|o| o.occurrence_key_id == occurrence)
                .expect("I91: the device's occurrence is stored")
                .valid_until
        }
        let run = uuid::Uuid::new_v4().simple().to_string();
        let alice_seed = format!("{tag}-i91-alice-{run}");
        let phone_seed = format!("{tag}-i91-phone-{run}");
        let alice = e2::put_key(n.backend, &alice_seed, &[USER]).await;
        let phone = e2::put_key(n.backend, &phone_seed, &[USER]).await;
        let (alice_signer, phone_signer) =
            (ts::local_signer(&alice_seed), ts::local_signer(&phone_seed));
        // A sub-millisecond instant: the producer states it at the payload's
        // ms resolution, so what is signed is what is stored.
        let until: chrono::DateTime<chrono::Utc> = "2031-06-01T12:00:00.123456Z".parse().unwrap();
        let until_ms =
            chrono::DateTime::<chrono::Utc>::from_timestamp_millis(until.timestamp_millis())
                .unwrap();
        let publish = |valid_until: Option<chrono::DateTime<chrono::Utc>>| {
            let (phone_signer, alice_signer, alice) =
                (phone_signer.clone(), alice_signer.clone(), alice.clone());
            async move {
                // Each publish at its own millisecond: a re-bind supersedes.
                tokio::time::sleep(std::time::Duration::from_millis(3)).await;
                publish_self_occurrence_with_local_signer(
                    n.backend,
                    &phone_signer,
                    &alice,
                    PHONE,
                    valid_until,
                    Some(alice_signer.as_ref()),
                )
                .await
            }
        };
        let landed =
            |o: Result<crate::federation::edition2::occurrence::OccurrenceBindOutcome, Error>,
             what: &str| match o {
                Ok(out) if out.landed => {}
                Ok(_) => panic!("{tag} I91: {what}: the bind did not land"),
                Err(e) => panic!("{tag} I91: {what}: {e}"),
            };
        landed(publish(Some(until)).await, "publish with an expiry");
        assert_eq!(
            valid_until_of(n.backend, &alice, &phone).await,
            Some(until_ms),
            "{tag} I91: stored, at ms precision"
        );
        // It is on the plane — the door admitted the bound member.
        assert!(
            n.backend
                .list_signed_identity_occurrences_for(&alice)
                .await
                .unwrap()
                .iter()
                .any(|x| x.identity_occurrence.occurrence_key_id == phone
                    && x.identity_occurrence.valid_until == Some(until_ms)),
            "{tag} I91: the signed listing serves the bind with its expiry"
        );
        // Republish WITH the expiry: it stays. This is the heal Edge needs.
        landed(
            publish(Some(until_ms)).await,
            "republish with the same expiry",
        );
        assert_eq!(
            valid_until_of(n.backend, &alice, &phone).await,
            Some(until_ms),
            "{tag} I91: a republish keeps the expiry"
        );
        // And `None` stores NULL — the producer does not invent an expiry.
        landed(publish(None).await, "publish without an expiry");
        assert_eq!(
            valid_until_of(n.backend, &alice, &phone).await,
            None,
            "{tag} I91: None stores NULL"
        );
    }

    /// **I60b — a set from a minter occurrence that is no longer active is
    /// refused, even one asserted before the revocation — and by the RIGHT
    /// gate.** The KeyGrant check folds membership at the row's
    /// `asserted_at` (consistent with the community-removal fold, §13): a set
    /// asserted while the occurrence was active passes it. The attestation
    /// plane's cohort gate then asks about the signer NOW and refuses — and
    /// that gate must stay at now: `asserted_at` is signer-chosen, so a
    /// revoked occurrence must never regain admission by back-dating. The
    /// two legs give different typed reasons, which is what makes the fold
    /// observable: early → the plane's own refusal (the fold passed); late →
    /// `signer_not_active_member` (the fold refused first).
    /// Ruled on PR #850's review.
    ///
    /// v62.0.0 (E11-fix4) — the minter node is its owner's device by owner
    /// binding (CC rc21 3.3.6), so its standing ends when its OWNER leaves the
    /// room; the removal stands in for the earlier occurrence revocation.
    pub async fn exercise_i60b_delayed_set_survives_a_later_occurrence_revocation<B>(
        a: &Node<'_, B>,
        b: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = e2::kid(&format!("{tag}-comm-{run}"));
        let alice = e2::kid(&format!("{tag}-alice-{run}"));
        let bob = e2::kid(&format!("{tag}-bob-{run}"));
        seed_community_everywhere(&[a, b], &comm, &[(&alice, Some(a)), (&bob, Some(b))]).await;
        // GID-fixtures-sites — the room's DERIVED id, once founded (`room_id`
        // panics if it was not).
        let comm = crate::federation::edition2::fixture_switch::room_id(&comm);
        encrypt_and_cascade_community(a.backend, &comm, b"while active", None, Some(&a.key))
            .await
            .unwrap_or_else(|e| panic!("{tag} I60b: A seals: {e}"));
        let early = emit_epoch_key_grant_with_local_signer(a.backend, &a.signer, &comm, 0)
            .await
            .unwrap()
            .expect("A holds wraps");
        let early_row = emitted_row_for(a, &early, &b.key).await;
        // B learns that A's principal stopped standing AFTER the early set was
        // asserted (and before now). v62.0.0 (E11-fix4; CC rc21 3.3.6): A is
        // alice's device by her OWNER BINDING (`place_device`), never an
        // occurrence of hers, so the earlier "A's occurrence revoked" has no
        // row to revoke; what ends A's standing is alice leaving the room.
        // Her removal is effective NOW, after the early row's `asserted_at`
        // (its own signed instant, never re-dated): v49.0.0 (#908), her own
        // voice, and bob's to meet the majority.
        let removed_at = chrono::Utc::now();
        assert!(
            removed_at > early_row.asserted_at,
            "{tag} I60b: the removal follows the early row"
        );
        let rev = community_removal_voices(
            b.backend,
            &comm,
            &alice,
            removed_at,
            removed_at,
            &[&alice, &bob],
        )
        .await;
        match e2::put_voices(b.backend, &rev).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("{tag} I60b: B holds alice's removal: {other:?}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        // v62.0.0 (E11, round 3) — the two gates are asked apart. The
        // key-grant rule folds membership at the row's `asserted_at`, so it
        // PASSES a row asserted while the occurrence was active; the plane's
        // write-scope gate asks about the signer NOW and HOLDS the delivered
        // row (CC 2.7: a fold condition, kept and concluding nothing).
        let early_signed = SignedKeyGrantRow {
            attestation: early_row.clone(),
        };
        assert_eq!(
            rule_reason(b.backend, &early_signed).await,
            "admitted",
            "{tag} I60b: the fold at asserted_at must pass a set asserted while active"
        );
        let err = carry_key_grant(a, b, &early_row.attestation_id)
            .await
            .expect_err("{tag} I60b: the plane's cohort gate refuses a revoked occurrence");
        assert_eq!(
            refusal_reason(&err),
            crate::federation::edition2::fold::reason::WRITE_SCOPE_REFUSED,
            "{tag} I60b: the plane's cohort gate (at now) is what holds it: {err}"
        );
        assert!(
            !b.backend
                .community_dek_has_member_grant(&comm, &a.key, 0, &b.key)
                .await
                .unwrap(),
            "{tag} I60b: nothing projected"
        );
        // The same minter, speaking AFTER the revocation: the fold itself
        // refuses, before the plane is asked.
        let axis = KeyGrantAxis::Epoch {
            community_key_id: comm.clone(),
            minter_key_id: a.key.clone(),
            epoch: 0,
        };
        let late = sign_row_unstored(&a.signer, &held_row(a, &axis, &b.key).await).await;
        assert_ne!(late.attestation.attestation_id, early_row.attestation_id);
        // The key-grant rule's own fold refuses it (membership at its
        // `asserted_at`); delivered, the write-scope gate holds it first.
        assert_eq!(
            rule_reason(b.backend, &late).await,
            "signer_not_active_member",
            "{tag} I60b: the fold at asserted_at refuses a row asserted after the revocation"
        );
        let err = admit_replicated(b.backend, late)
            .await
            .expect_err("{tag} I60b: a row asserted after the revocation is refused");
        assert_eq!(
            refusal_reason(&err),
            crate::federation::edition2::fold::reason::WRITE_SCOPE_REFUSED,
            "{tag} I60b: {err}"
        );
    }
}

#[cfg(test)]
mod tests {
    // ── I59 ──────────────────────────────────────────────────────────────
    /// `KeyGrant` is the sixteenth kind with a policy row exactly as §12
    /// states; the manifest witness holds (`replication_policy_hash_is_pinned`
    /// beside it); the wire table documents it.
    #[test]
    fn i59_key_grant_is_the_sixteenth_kind_with_the_stated_policy_row() {
        use crate::federation::replication_policy::*;
        // v48.0.0 appended the 17th (`CommunityMembershipWidening`, #860),
        // v49.0.0 the 18th (`FamilyMembershipWidening`, #910) and the 19th
        // (`CommunityMembershipListing`, #912); KeyGrant stays at index 15.
        assert_eq!(EnvelopeKind::ALL.len(), 19);
        assert_eq!(
            EnvelopeKind::ALL[16],
            EnvelopeKind::CommunityMembershipWidening,
            "the 17th kind is appended after KeyGrant"
        );
        assert_eq!(
            EnvelopeKind::ALL[17],
            EnvelopeKind::FamilyMembershipWidening,
            "the 18th kind is appended after CommunityMembershipWidening"
        );
        assert_eq!(
            EnvelopeKind::ALL[18],
            EnvelopeKind::CommunityMembershipListing,
            "the 19th kind is appended after FamilyMembershipWidening"
        );
        assert_eq!(
            EnvelopeKind::ALL[15],
            EnvelopeKind::KeyGrant,
            "appended, never inserted"
        );
        assert_eq!(EnvelopeKind::KeyGrant.as_str(), "KeyGrant");
        // v61 (CIRISPersist#991): the framed kind is retired; the rows ride
        // the attestation kind. Its position above does not move.
        assert!(
            crate::federation::replication_policy::RETIRED_FRAMED.contains(&EnvelopeKind::KeyGrant),
            "KeyGrant is a retired framed kind"
        );
        let p = policy_for(EnvelopeKind::KeyGrant);
        assert_eq!(p.signer, SignerSource::RegisteredSigner);
        assert_eq!(p.binding, SignerBinding::SelfOwn);
        assert_eq!(p.pop_on_insert, PopOnInsert::NotApplicable);
        assert_eq!(p.tier, WireTier::FederationOnly);
        assert_eq!(p.projections, &[Projection::KeyGrants]);
        assert_eq!(
            replication_policy_sha256(),
            REPLICATION_POLICY_HASH,
            "the re-pin must be deliberate and recorded"
        );
        assert_eq!(
            REPLICATION_POLICY_HASH,
            "1860451cf166879431dadf433422f6fdb43a911b5c889b0f55ca491262393869"
        );
        let doc = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("WIRE_VOCABULARY_KINDS.md"),
        )
        .expect("WIRE_VOCABULARY_KINDS.md");
        assert!(
            doc.contains("KeyGrant") && doc.contains("key_grant:epoch:v1"),
            "I59: the wire table must document the sixteenth kind and its row types"
        );
    }

    // ── I67 ──────────────────────────────────────────────────────────────
    /// No production path removes a grant within an epoch: the only `DELETE`
    /// on the member-grant table is the epoch destroy, and the only deletes
    /// on the at-rest grant table ride blob deletion (the row goes with the
    /// blob it grants).
    #[test]
    fn i67_no_production_delete_on_the_grant_tables_outside_destroy() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for (file, table) in [
            (
                "src/store/sqlite.rs",
                "federation_community_dek_member_grants",
            ),
            (
                "src/store/postgres.rs",
                "cirislens.federation_community_dek_member_grants",
            ),
        ] {
            let text = std::fs::read_to_string(root.join(file)).unwrap();
            let prod = production_only(&text);
            let needle = format!("DELETE FROM {table}");
            let sites: Vec<usize> = prod.match_indices(&needle).map(|(i, _)| i).collect();
            assert_eq!(
                sites.len(),
                1,
                "I67: {file} must delete member grants in exactly ONE place (destroy), found {}",
                sites.len()
            );
            let fn_name = enclosing_fn(&prod, sites[0]);
            assert_eq!(
                fn_name, "community_dek_set_key_state",
                "I67: {file}: the one member-grant DELETE must be the destroy path"
            );
        }
        for (file, table) in [
            ("src/store/sqlite.rs", "federation_blob_key_grants"),
            (
                "src/store/postgres.rs",
                "cirislens.federation_blob_key_grants",
            ),
        ] {
            let text = std::fs::read_to_string(root.join(file)).unwrap();
            let prod = production_only(&text);
            let needle = format!("DELETE FROM {table}");
            let fns: std::collections::BTreeSet<String> = prod
                .match_indices(&needle)
                .map(|(i, _)| enclosing_fn(&prod, i))
                .collect();
            // v52.0.0 (#954) — `abandon_stream_floor` evicts an abandoned
            // stream's sealed chunk rows; each grant delete rides the delete
            // of its own blob row in the same transaction (blob deletion).
            let allowed: std::collections::BTreeSet<String> = [
                "delete_blob",
                "community_dek_evict_epoch_objects",
                "abandon_stream_floor",
            ]
            .into_iter()
            .map(String::from)
            .collect();
            assert!(
                fns.is_subset(&allowed),
                "I67: {file}: at-rest grant deletes may ride only blob deletion, found in {fns:?}"
            );
        }
        // And no cascade / door module un-grants through a floor: there is
        // no such floor.
        let blobs = std::fs::read_to_string(root.join("src/federation/blobs.rs")).unwrap();
        assert!(
            !blobs.contains("fn community_dek_remove_member_grant")
                && !blobs.contains("fn remove_at_rest_grant")
                && !blobs.contains("fn community_dek_delete_member_grant"),
            "I67: the trait must offer no un-grant floor"
        );
    }

    /// Strip `#[cfg(test)] mod` regions from a source file.
    /// The body of `fn NAME(` in `text`, up to the next method at the same
    /// indentation (its doc comment included, which is harmless).
    fn method_body<'t>(text: &'t str, name: &str) -> &'t str {
        let start = text
            .find(&format!("fn {name}("))
            .unwrap_or_else(|| panic!("{name} is defined"));
        let rest = &text[start + 1..];
        let end = [
            "\n    pub async fn ",
            "\n    pub fn ",
            "\n    async fn ",
            "\n    fn ",
            "\n}\n",
        ]
        .iter()
        .filter_map(|m| rest.find(m))
        .min()
        .map(|i| start + 1 + i)
        .unwrap_or(text.len());
        &text[start..end]
    }

    /// **I69 (from disk) — every Python write door emits** (PR #850
    /// review: the two specialized doors did not). Each `#[pymethods]` door
    /// calls the one emission helper.
    #[test]
    fn i69_every_python_write_door_emits_the_key_grant_set() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(root.join("src/ffi/pyo3.rs")).unwrap();
        let prod = production_only(&text);
        for door in [
            "put_blob_scoped",
            "put_blob_encrypted_community",
            "put_blob_encrypted_self_family",
            "put_blob_chunk_scoped",
            "seal_stream_scoped",
            // v55.0.0 (#981) — a kept supplied epoch's rows.
            "register_stream_epoch_dek",
        ] {
            assert!(
                method_body(&prod, door).contains("emit_key_grant_axis_async"),
                "I69: PyEngine::{door} must emit the KeyGrant set after its cascade (§14)"
            );
        }
    }

    /// **I72 (from disk) — both adopt doors reconcile pending content sets**
    /// (PR #850, round three): a self/family chunk has its own DEK and its
    /// own set, so the chunk adopt projects exactly as `adopt_sealed_blob`.
    /// v52.0.0 (#957): the chunk door that stores is the batched
    /// `adopt_sealed_chunks`; the single `adopt_sealed_chunk` is a batch of
    /// one and must delegate to it, never store around it.
    #[test]
    fn i72_both_adopt_doors_project_pending_content_grants() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(root.join("src/federation/adopt_cascade.rs")).unwrap();
        let prod = production_only(&text);
        let body = |door: &str| {
            let start = prod.find(&format!("pub async fn {door}<")).unwrap();
            let end = prod[start + 1..]
                .find("\npub ")
                .map(|i| start + 1 + i)
                .unwrap_or(prod.len());
            prod[start..end].to_owned()
        };
        for door in ["adopt_sealed_blob", "adopt_sealed_chunks"] {
            assert!(
                body(door).contains("project_pending_content_grants("),
                "I72: {door} must project the pending content sets once the row names its author"
            );
        }
        let single = body("adopt_sealed_chunk");
        assert!(
            single.contains("adopt_sealed_chunks(") && !single.contains("adopt_sealed_chunk_at("),
            "I72: adopt_sealed_chunk must be a batch of one through adopt_sealed_chunks, never a \
             second path to the floor that could skip the projection"
        );
    }

    /// **I66e (from disk) — every DEK-plane door of the Engine resolves the
    /// sentinel first**, so an `Engine` built by `from_shared*` (which cannot
    /// repair synchronously) is repaired at its first such door. And **I68's
    /// carrier**: both retroactive-ADD doors consume `changed_blobs`.
    #[test]
    fn i66e_every_dek_plane_door_resolves_the_sentinel_first() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(root.join("src/engine.rs")).unwrap();
        let prod = production_only(&text);
        for door in [
            "put_blob_scoped",
            "put_blob_encrypted_community",
            "put_blob_encrypted_self_family",
            "put_blob_chunk_scoped",
            "seal_stream_scoped",
            "read_blob_as",
            "read_blob_range_as",
            "read_stream_chunk_as",
            "read_blob_for_community_viewer",
            "adopt_sealed_blob",
            "adopt_sealed_chunk",
            "apply_replicated_key_grant",
            "emit_key_grant",
            "community_dek_set_key_state",
            "community_dek_set_retain_past_epochs",
            "rekey_community_member_revoke",
        ] {
            assert!(
                method_body(&prod, door).contains("ensure_minter_sentinels_resolved()"),
                "I66e: Engine::{door} must resolve V145's sentinel before touching the DEK plane"
            );
        }
        for door in ["rekey_family_member_add", "rekey_self_occurrence_add"] {
            let body = method_body(&prod, door);
            assert!(
                body.contains("changed_blobs") && body.contains("emit_key_grant("),
                "I68: Engine::{door} must emit each changed blob's content set (§14)"
            );
        }
    }

    fn production_only(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut depth = 0i32;
        let mut in_tests = false;
        for line in text.lines() {
            // v54.1.0 (#1026): `#[cfg(all(test, …))]` is test-only too.
            if !in_tests && crate::test_cfg::is_test_only_cfg(line) {
                in_tests = true;
                depth = 0;
                continue;
            }
            if in_tests {
                depth += line.matches('{').count() as i32;
                depth -= line.matches('}').count() as i32;
                if depth <= 0 && line.contains('}') {
                    in_tests = false;
                }
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// The name of the `fn` whose body contains byte offset `at`.
    fn enclosing_fn(text: &str, at: usize) -> String {
        let head = &text[..at];
        let idx = head.rfind("fn ").expect("a fn precedes the site");
        let rest = &head[idx + 3..];
        rest.split(|c: char| c == '(' || c == '<' || c.is_whitespace())
            .next()
            .unwrap_or("")
            .to_owned()
    }

    #[cfg(feature = "sqlite")]
    mod sqlite {
        use super::super::two_node::*;
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::store::sqlite::SqliteBackend;
        use crate::store::Backend as _;

        async fn fresh() -> SqliteBackend {
            let b = SqliteBackend::open_in_memory().await.unwrap();
            b.run_migrations().await.unwrap();
            b
        }

        #[tokio::test]
        async fn i76_content_only_occurrence_sqlite() {
            let bn = fresh().await;
            let n = node_as(&bn, "i76-n", crate::federation::types::identity_type::NODE).await;
            exercise_i76_content_only_occurrence(&n, "i76-n", "sqlite").await;
        }

        #[tokio::test]
        async fn i60_forged_set_refused_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node_as(&ba, "i60-a", crate::federation::types::identity_type::NODE).await;
            let b = node_as(&bb, "i60-b", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b],
                &["i60-a", "i60-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i60_forged_set_refused(&a, &b, "sqlite").await;
        }

        #[tokio::test]
        async fn i60b_delayed_set_survives_a_later_occurrence_revocation_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node_as(&ba, "i60b-a", crate::federation::types::identity_type::NODE).await;
            let b = node_as(&bb, "i60b-b", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b],
                &["i60b-a", "i60b-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i60b_delayed_set_survives_a_later_occurrence_revocation(&a, &b, "sqlite")
                .await;
        }

        #[tokio::test]
        async fn i77_owned_node_minter_admitted_by_principal_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node(&ba, "i77-a").await;
            let b = node(&bb, "i77-b").await;
            introduce_as(
                &[&a, &b],
                &["i77-a", "i77-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            Box::pin(exercise_i77_owned_node_minter_admitted_by_principal(
                &a, &b, "sqlite",
            ))
            .await;
        }

        #[tokio::test]
        async fn i71_rotation_keys_on_effective_at_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node_as(&ba, "i71-a", crate::federation::types::identity_type::NODE).await;
            let b = node_as(&bb, "i71-b", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b],
                &["i71-a", "i71-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i71_rotation_keys_on_effective_at(&a, &b, "sqlite").await;
        }

        #[tokio::test]
        async fn i61_end_to_end_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node_as(&ba, "i61-a", crate::federation::types::identity_type::NODE).await;
            let b = node_as(&bb, "i61-b", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b],
                &["i61-a", "i61-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i61_end_to_end(&a, &b, "sqlite").await;
        }

        #[tokio::test]
        async fn i62_union_order_independent_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node_as(&ba, "i62-a", crate::federation::types::identity_type::NODE).await;
            let b = node_as(&bb, "i62-b", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b],
                &["i62-a", "i62-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i62_union_order_independent(&a, &b, "sqlite").await;
        }

        #[tokio::test]
        async fn i63_rotation_on_admitted_removal_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node_as(&ba, "i63-a", crate::federation::types::identity_type::NODE).await;
            let b = node_as(&bb, "i63-b", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b],
                &["i63-a", "i63-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i63_rotation_on_admitted_removal(&a, &b, "sqlite").await;
        }

        #[tokio::test]
        async fn i64_two_minters_same_epoch_sqlite() {
            let (ba, bb, bc) = (fresh().await, fresh().await, fresh().await);
            let a = node_as(&ba, "i64-a", crate::federation::types::identity_type::NODE).await;
            let b = node_as(&bb, "i64-b", crate::federation::types::identity_type::NODE).await;
            let c = node_as(&bc, "i64-c", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b, &c],
                &["i64-a", "i64-b", "i64-c"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i64_two_minters_same_epoch(&a, &b, &c, "sqlite").await;
        }

        #[tokio::test]
        async fn i199_family_member_publishes_and_another_opens_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node(&ba, "i199-a").await;
            let b = node(&bb, "i199-b").await;
            introduce(&[&a, &b], &["i199-a", "i199-b"]).await;
            exercise_i199_family_member_publishes_and_another_opens(&a, &b, "sqlite").await;
        }

        #[tokio::test]
        async fn i800_the_blob_arrival_race_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node(&ba, "i800-a").await;
            let a2 = node(&bb, "i800-a2").await;
            introduce(&[&a, &a2], &["i800-a", "i800-a2"]).await;
            exercise_i800_the_blob_arrival_race(&a, &a2, "sqlite").await;
        }

        #[tokio::test]
        async fn i1519_a_self_grant_reaches_the_persons_occurrences_sqlite() {
            let (ba, bb, bc) = (fresh().await, fresh().await, fresh().await);
            let a = node(&ba, "i1519-a").await;
            let b = node(&bb, "i1519-b").await;
            let c = node(&bc, "i1519-c").await;
            introduce(&[&a, &b, &c], &["i1519-a", "i1519-b", "i1519-c"]).await;
            bb.set_node_key_id(b.key.clone());
            bc.set_node_key_id(c.key.clone());
            exercise_i1519_a_self_grant_reaches_the_persons_occurrences(&a, &b, &c, "sqlite").await;
        }

        #[tokio::test]
        async fn i65_content_axis_second_device_sqlite() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node(&ba, "i65-a").await;
            let a2 = node(&bb, "i65-a2").await;
            introduce(&[&a, &a2], &["i65-a", "i65-a2"]).await;
            exercise_i65_content_axis_second_device(&a, &a2, "sqlite").await;
        }

        /// **I68 — a retroactive ADD emits each changed blob's content rows**
        /// (PR #850 review). `rekey_self_occurrence_add` writes new per-blob
        /// wraps for a newcomer device; the Engine door emits a row for every
        /// wrap of every blob it changed not yet held as a row, so the newcomer's
        /// remote node receives the key for historical bytes through the
        /// same path a fresh write uses. Idempotent: a second walk changes
        /// nothing and emits nothing.
        #[tokio::test]
        async fn i68_rekey_for_a_newcomer_emits_each_changed_blobs_content_set_sqlite() {
            use crate::federation::attestation_query::test_support::AllAttestations as _;
            use crate::federation::key_grant::{KeyGrantAxis, KeyGrantRow};
            use crate::federation::tier_ingest::test_support as ts;
            use crate::federation::types::cohort_scope::SELF;
            use crate::federation::types::identity_type::USER;
            use crate::federation::{BlobStorage, EncryptionPubkeys, FederationDirectory};
            let run = uuid::Uuid::new_v4().simple().to_string();
            let alias = format!("i68-node-{run}");
            let engine =
                crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), "sqlite::memory:")
                    .await
                    .unwrap();
            engine
                .register_self_federation_key(USER, None, None)
                .await
                .unwrap();
            let sq = engine.sqlite_backend().unwrap().clone();
            let me = engine.local_derived_key_id().await.unwrap();
            let kem =
                |id: crate::federation::identity_aggregate::ContentKemIdentity| EncryptionPubkeys {
                    x25519_base64: id.x25519_pubkey_b64,
                    ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
                };
            let owner = e2::kid(&format!("i68-owner-{run}"));
            ts::register_hybrid_key_as(sq.as_ref(), &owner, &owner, USER).await;
            let occurrence =
                |occ: &str, pk: EncryptionPubkeys| crate::federation::types::IdentityOccurrence {
                    identity_key_id: owner.clone(),
                    occurrence_key_id: occ.to_owned(),
                    device_class: crate::federation::types::device_class::LAPTOP.into(),
                    hardware_attestation: None,
                    asserted_at: chrono::Utc::now(),
                    valid_until: None,
                    encryption_pubkeys: Some(pk),
                    transport_binding: None,
                    persist_row_hash: String::new(),
                };
            sq.test_seam_put_identity_occurrence(occurrence(
                &me,
                kem(sq.load_or_init_content_kem_identity().await.unwrap()),
            ))
            .await
            .unwrap();
            let r = engine
                .put_blob_encrypted_self_family(SELF, &owner, b"photo", None)
                .await
                .expect("I68: the owner's first device seals");
            let sha = r.at_rest_sha256;
            // v55.0.0 (#989) — the content-axis ROWS this node signed for the
            // blob, one per recipient.
            let rows_for = |sq: std::sync::Arc<SqliteBackend>, me: String| async move {
                let mut out: Vec<KeyGrantRow> = Vec::new();
                for row in sq.all_attestations_by(&me).await.unwrap() {
                    if !crate::federation::key_grant::is_key_grant_row(&row) {
                        continue;
                    }
                    let r = KeyGrantRow::from_attestation(&row).unwrap();
                    if matches!(&r.axis, KeyGrantAxis::Content { at_rest_sha256, .. } if *at_rest_sha256 == hex::encode(sha))
                    {
                        out.push(r);
                    }
                }
                out
            };
            let before = rows_for(sq.clone(), me.clone()).await;
            assert_eq!(
                before
                    .iter()
                    .map(|r| r.recipient().to_owned())
                    .collect::<Vec<_>>(),
                vec![me.clone()],
                "I68: the write emitted one row, to the first device"
            );
            // A NEW device of the owner, with its own content-KEM identity.
            let other = fresh().await;
            let dev2 = e2::kid(&format!("i68-dev2-{run}"));
            ts::register_hybrid_key_as(sq.as_ref(), &dev2, &dev2, USER).await;
            sq.test_seam_put_identity_occurrence(occurrence(
                &dev2,
                kem(other.load_or_init_content_kem_identity().await.unwrap()),
            ))
            .await
            .unwrap();
            let rk = engine
                .rekey_self_occurrence_add(&owner, std::slice::from_ref(&dev2))
                .await
                .expect("I68: the retroactive add");
            assert_eq!(
                rk.changed_blobs,
                vec![sha],
                "I68: the walk names the blob it changed"
            );
            assert!(sq.get_at_rest_grant(&sha, &dev2).await.unwrap().is_some());
            let after = rows_for(sq.clone(), me.clone()).await;
            let mut recipients: Vec<String> =
                after.iter().map(|r| r.recipient().to_owned()).collect();
            recipients.sort();
            let mut want = vec![me.clone(), dev2.clone()];
            want.sort();
            assert_eq!(
                recipients, want,
                "I68: the rekey emitted the new device's row, and the first device's row was not \
                 emitted twice (a wrap already held as a row is skipped)"
            );
            // Idempotent: nothing changed, nothing emitted.
            let rk2 = engine
                .rekey_self_occurrence_add(&owner, std::slice::from_ref(&dev2))
                .await
                .unwrap();
            assert!(rk2.changed_blobs.is_empty(), "I68: {rk2:?}");
            assert_eq!(rows_for(sq.clone(), me.clone()).await.len(), 2);
        }

        /// v62.0.0 (E11) — **the key plane crossing**: every `key:record`
        /// statement `from` serves an anonymous reader
        /// ([`statements_served_to`](crate::federation::edition2::serve::statements_served_to)),
        /// delivered through `to`'s replicated statement door. Returns how
        /// many were new on `to`.
        async fn deliver_keys(from: &SqliteBackend, to: &SqliteBackend) -> usize {
            use crate::federation::edition2::emit::{family_of_statement, KEY_RECORD_FAMILY};
            use crate::federation::edition2::ingest::ReplicatedStatementOutcome;
            let page =
                crate::federation::edition2::serve::statements_served_to(from, None, 1_000, None)
                    .await
                    .unwrap();
            let keys: Vec<Vec<u8>> = page
                .statements
                .into_iter()
                .map(|s| s.bytes)
                .filter(|b| family_of_statement(b).is_some_and(|(f, _)| f == KEY_RECORD_FAMILY))
                .collect();
            deliver_statements(to, &keys)
                .await
                .unwrap_or_else(|e| panic!("the far node admits the key records: {e}"))
                .iter()
                .filter(|o| matches!(o, ReplicatedStatementOutcome::Admitted(_)))
                .count()
        }

        /// v62.0.0 (E11) — **the key-grant crossing through the plane**:
        /// every key-grant row `from` serves on its cursor that its serve gate
        /// (`may_receive`, on `from`'s own directory) sends to `to_key`, each
        /// as its statement through `to`'s replicated statement door. Returns
        /// how many crossed.
        async fn deliver_key_grants(
            from: &SqliteBackend,
            to: &SqliteBackend,
            to_key: &str,
        ) -> usize {
            use crate::federation::FederationDirectory;
            let mut n = 0;
            for served in from.list_attestations_since(None, 1_000).await.unwrap() {
                let row = served.attestation;
                if !crate::federation::key_grant::is_key_grant_row(&row)
                    || !crate::federation::replication_audience::may_receive(from, to_key, &row)
                        .await
                        .unwrap()
                        .allowed()
                    || to
                        .get_attestation(&row.attestation_id)
                        .await
                        .unwrap()
                        .is_some()
                {
                    continue;
                }
                let signer = row.attesting_key_id.clone();
                admit_replicated(
                    to,
                    crate::federation::key_grant::SignedKeyGrantRow { attestation: row },
                )
                .await
                .unwrap_or_else(|e| {
                    panic!("the far node admits the key-grant row by {signer}: {e}")
                });
                n += 1;
            }
            n
        }

        /// **I75 (#851 §20.4) — THE END TO END, DELIVERED.** Two Engines. Every
        /// row crosses only through a since-read and the gated door on the
        /// other side: keys through the key plane, occurrences through the
        /// signed occurrence listing, the key-grant row through the cursor and
        /// the sender's serve gate. Nothing is copied by hand — the plane I61
        /// could not run.
        ///
        /// v62.0.0 (E11) — every crossing is a statement through the
        /// replicated statement door. Each node publishes its own occurrence
        /// through `Engine::publish_self_occurrence` (P8): the node states its
        /// own voice and the identity, its pen handed in, authors the O1
        /// `identity:occurrence` bind. The nodes are USER-typed device keys (a
        /// node key is never a person's occurrence) and no owner binding is
        /// needed: the identity's own voice is the authority.
        #[tokio::test]
        async fn i75_end_to_end_delivered_by_the_planes_sqlite() {
            use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY};
            use crate::federation::types::device_class::SERVER;
            use crate::federation::types::identity_type::USER;
            use crate::federation::{
                AdoptDisposition, BlobBody, BlobProvenance, BlobStorage, FederationDirectory,
            };
            let run = uuid::Uuid::new_v4().simple().to_string();
            let (alias_a, alias_b) = (format!("i75-a-{run}"), format!("i75-b-{run}"));
            let engine_a = crate::Engine::with_signer_pre_genesis(
                ts::local_signer(&alias_a),
                "sqlite::memory:",
            )
            .await
            .unwrap();
            let engine_b = crate::Engine::with_signer_pre_genesis(
                ts::local_signer(&alias_b),
                "sqlite::memory:",
            )
            .await
            .unwrap();
            for e in [&engine_a, &engine_b] {
                e.register_self_federation_key(USER, None, None)
                    .await
                    .unwrap();
            }
            let (sa, sb) = (
                engine_a.sqlite_backend().unwrap().clone(),
                engine_b.sqlite_backend().unwrap().clone(),
            );
            let (a_key, b_key) = (
                engine_a.local_derived_key_id().await.unwrap(),
                engine_b.local_derived_key_id().await.unwrap(),
            );
            // The fixtures sign as the engines' own composites.
            assert_eq!(
                e2::kid(&alias_a),
                a_key,
                "I75: the engine signs as kid(alias)"
            );
            assert_eq!(
                e2::kid(&alias_b),
                b_key,
                "I75: the engine signs as kid(alias)"
            );
            // ── identities and the community, each born on ONE node ───
            let (alice, bob, comm) = (
                e2::kid(&format!("i75-alice-{run}")),
                e2::kid(&format!("i75-bob-{run}")),
                e2::kid(&format!("i75-comm-{run}")),
            );
            ts::register_identity_key(sa.as_ref(), &alice, USER).await;
            ts::register_identity_key(sb.as_ref(), &bob, USER).await;
            ts::register_identity_key(sa.as_ref(), &comm, USER).await;
            // Keys cross (both ways) so each side can verify the other's rows.
            assert!(deliver_keys(&sa, &sb).await >= 3, "I75: A's keys reach B");
            assert!(deliver_keys(&sb, &sa).await >= 2, "I75: B's keys reach A");
            let a_on_b = FederationDirectory::lookup_public_key(sb.as_ref(), &a_key)
                .await
                .unwrap()
                .expect("A's key on B");
            assert!(
                a_on_b.pubkey_ml_dsa_65_base64.is_some(),
                "I75: A's key record on B carries the ML-DSA-65 pubkey (composite rows verify)"
            );
            // The community (roster plane: the same version, both sides).
            let roster = community_roster_voices(&comm, "Delivered Co-op", &[&alice, &bob]);
            for s in [&sa, &sb] {
                e2::put_voices(s.as_ref(), &roster)
                    .await
                    .unwrap_or_else(|e| panic!("I75: the community: {e}"));
            }
            // ── each node publishes its OWN occurrence (§20.3) ────────
            // v62.0.0 (P8) — the node states its own voice; the identity (its
            // pen in hand) authors the O1 bind.
            for (engine, ident) in [(&engine_a, &alice), (&engine_b, &bob)] {
                let pen = ts::local_signer(&e2::seed_of(ident));
                let out = engine
                    .publish_self_occurrence(ident, SERVER, None, Some(pen.as_ref()))
                    .await
                    .unwrap_or_else(|e| {
                        panic!("I75: the node publishes its occurrence under {ident}: {e}")
                    });
                assert!(out.landed, "I75: {ident}'s bind of its node landed");
            }
            // Occurrences cross through the signed listing and the gated door.
            deliver_statements(sb.as_ref(), &bind_statements_for(sa.as_ref(), &alice).await)
                .await
                .unwrap_or_else(|e| panic!("I75: A's occurrence reaches B: {e}"));
            deliver_statements(sa.as_ref(), &bind_statements_for(sb.as_ref(), &bob).await)
                .await
                .unwrap_or_else(|e| panic!("I75: B's occurrence reaches A: {e}"));
            assert_eq!(
                sb.lookup_identity_for_occurrence(&a_key)
                    .await
                    .unwrap()
                    .map(|o| o.identity_key_id),
                Some(alice.clone()),
                "I75: A's occurrence reaches B"
            );
            assert_eq!(
                sa.lookup_identity_for_occurrence(&b_key)
                    .await
                    .unwrap()
                    .map(|o| o.identity_key_id),
                Some(bob.clone()),
                "I75: B's occurrence reaches A"
            );
            // ── A seals; B's node is IN the set ───────────────────────
            let r = engine_a
                .put_blob_scoped(COMMUNITY, Some(&comm), b"delivered minutes", None, None)
                .await
                .expect("A seals through the door");
            assert!(
                r.granted.contains(&b_key),
                "I75: the far member's node is in A's fan-out: {:?}",
                r.granted
            );
            assert!(r.key_grant_emission.is_some());
            let sha = r.at_rest_sha256;
            // B's row crosses through the cursor and the serve gate.
            assert!(
                deliver_key_grants(&sa, &sb, &b_key).await >= 1,
                "I75: the row reaches B"
            );
            assert!(
                sb.community_dek_has_member_grant(&comm, &a_key, r.epoch.unwrap_or(0), &b_key)
                    .await
                    .unwrap(),
                "I75: B's own wrap is projected on B"
            );
            // The bytes cross (CIRISEdge#601's hook is the fetch; here the adopt).
            let Some(BlobBody::Inline(bytes)) = sa.get_blob(&sha).await.unwrap() else {
                panic!("inline")
            };
            engine_b
                .adopt_sealed_blob(
                    &bytes,
                    BlobProvenance {
                        author_key_id: a_key.clone(),
                        cohort_scope: COMMUNITY.into(),
                        community_key_id: Some(comm.clone()),
                        epoch: r.epoch,
                        tier: CryptoTier::CommunityDek,
                        minter_key_id: None,
                    },
                    None,
                    AdoptDisposition::LocalOnly,
                )
                .await
                .expect("B adopts");
            assert_eq!(
                engine_b
                    .read_blob_as(&sha, &b_key, None)
                    .await
                    .expect("I75: B's member opens — the mesh's red leg"),
                b"delivered minutes"
            );
        }

        /// **I82 (PR #852 round five) — `publish_self_occurrence` publishes
        /// only THIS node's key.** An Engine over a shared backend whose
        /// composed signer is one identity and whose LocalSigner is another
        /// (`from_shared_with_local`) is refused: the occurrence would name a
        /// key that is not the node.
        #[tokio::test]
        async fn i82_publish_self_occurrence_refuses_a_foreign_local_signer_sqlite() {
            use crate::federation::tier_ingest::test_support as ts;
            use std::sync::Arc;
            let backend = Arc::new(fresh().await);
            let node_local = ts::local_signer("i82-node");
            let foreign_local = ts::local_signer("i82-foreign");
            let signer: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
                crate::signing::LocalSignerHardwareAdapter::new(node_local.clone()),
            );
            let engine = crate::Engine::try_from_shared_with_local(
                crate::engine::BackendDispatch::Sqlite(backend.clone()),
                signer,
                Some(foreign_local),
            )
            .expect("a shared engine view: no node_key_conflict");
            // v62.0.0 (P8) — the fourth argument is the author's pen (none).
            let err = match engine
                .publish_self_occurrence(
                    "i82-owner",
                    crate::federation::types::device_class::SERVER,
                    None,
                    None,
                )
                .await
            {
                Ok(_) => panic!("I82: a LocalSigner that is not the node's identity is refused"),
                Err(e) => e,
            };
            assert!(
                err.to_string().contains("not this node's identity"),
                "I82: the refusal names the mismatch: {err}"
            );
        }

        /// **I91 (§21.2, #855) — `valid_until` is one more bound member.**
        /// v62.0.0 (E11): through P8's producer ([`exercise_i91_a_bind_carries_valid_until`]).
        #[tokio::test]
        async fn i91_a_bind_carries_valid_until_sqlite() {
            let bn = fresh().await;
            let n = node(&bn, "i91-n").await;
            exercise_i91_a_bind_carries_valid_until(&n, "sqlite").await;
        }

        /// **I92 (§21.3, #856) — the device occurrence's producer is
        /// `self_at_login`, and what it produces crosses the plane.** With
        /// the identity's signer, each pubkey-bearing occurrence is admitted
        /// through the GATED door: the stored row is signed-put, the plane
        /// advertises it, and a second node admits it through the same gate.
        /// Without the signer the rows are trusted-local and the plane does
        /// not list them — today's behaviour, unchanged.
        #[tokio::test]
        async fn i92_self_at_login_publishes_device_occurrences_through_the_gated_door_sqlite() {
            use crate::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
            use crate::federation::tier_ingest::test_support as ts;
            use crate::federation::types::identity_type::{AGENT, USER};
            use crate::federation::FederationDirectory;
            let run = uuid::Uuid::new_v4().simple().to_string();
            // v62.0.0 (P8) — the bind carries `hardware_attestation` as bytes,
            // so the producer takes it base64 (STANDARD) and the far row reads it
            // back the same way.
            let hw_attest = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"hw-attest-i92",
            );
            let (alias_a, alias_b) = (format!("i92-a-{run}"), format!("i92-b-{run}"));
            let engine_a = crate::Engine::with_signer_pre_genesis(
                ts::local_signer(&alias_a),
                "sqlite::memory:",
            )
            .await
            .unwrap();
            let engine_b = crate::Engine::with_signer_pre_genesis(
                ts::local_signer(&alias_b),
                "sqlite::memory:",
            )
            .await
            .unwrap();
            for e in [&engine_a, &engine_b] {
                e.register_self_federation_key(
                    crate::federation::types::identity_type::NODE,
                    None,
                    None,
                )
                .await
                .unwrap();
            }
            let (sa, sb) = (
                engine_a.sqlite_backend().unwrap().clone(),
                engine_b.sqlite_backend().unwrap().clone(),
            );
            // The identity: registered on BOTH nodes under its DERIVED id with
            // the label's real pubkeys, because the far node verifies the
            // identity's signature over the occurrence.
            let identity_label = format!("i92-alice-{run}");
            let identity_signer = ts::local_signer(&identity_label);
            let identity = identity_signer.federation_id().await;
            for s in [&sa, &sb] {
                ts::register_hybrid_key_as(s.as_ref(), &identity, &identity_label, USER).await;
            }
            // The device keys, on both nodes (the occurrence names them).
            let (app_key, agent_key) = (
                e2::kid(&format!("i92-app-{run}")),
                e2::kid(&format!("i92-agent-{run}")),
            );
            for s in [&sa, &sb] {
                ts::register_hybrid_key_as(s.as_ref(), &app_key, &app_key, USER).await;
                ts::register_hybrid_key_as(s.as_ref(), &agent_key, &agent_key, AGENT).await;
            }
            let mk_keys = || {
                use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
                let (_xp, x_pub, _mp, ml_pub) =
                    crate::federation::identity_aggregate::mint_content_kem_keypair().unwrap();
                crate::federation::EncryptionPubkeys {
                    x25519_base64: B64.encode(x_pub),
                    ml_kem_768_base64: B64.encode(ml_pub),
                }
            };
            let input = |signer: Option<std::sync::Arc<crate::signing::LocalSigner>>| {
                SelfAtLoginInput {
                    identity_key_id: identity.clone(),
                    identity_signer: signer,
                    app: SelfAtLoginOccurrence {
                        occurrence_key_id: app_key.clone(),
                        device_class: crate::federation::types::device_class::PHONE.to_owned(),
                        // The producer's Some(..) path: a bound member the
                        // node's own occurrence never exercises.
                        hardware_attestation: Some(hw_attest.clone()),
                        encryption_pubkeys: Some(mk_keys()),
                        transport_destinations: vec![],
                        // v62.0.0 (P8 §3) — the identity it binds under (None: the
                        // login identity for the app, the agent key itself for the
                        // agent), its own pen, and no transport members.
                        identity_key_id: None,
                        occurrence_signer: Some(ts::local_signer(&e2::seed_of(&app_key))),
                        transport: None,
                    },
                    agent: SelfAtLoginOccurrence {
                        occurrence_key_id: agent_key.clone(),
                        device_class: crate::federation::types::device_class::AGENT.to_owned(),
                        hardware_attestation: None,
                        encryption_pubkeys: Some(mk_keys()),
                        transport_destinations: vec![],
                        // v62.0.0 (P8 §3) — the identity it binds under (None: the
                        // login identity for the app, the agent key itself for the
                        // agent), its own pen, and no transport members.
                        identity_key_id: None,
                        occurrence_signer: Some(ts::local_signer(&e2::seed_of(&agent_key))),
                        transport: None,
                    },
                    bilateral_pair_id: uuid::Uuid::new_v4().to_string(),
                    delegation_scope: None,
                }
            };

            // ── leg 1: with the signer, the rows are ON THE PLANE ─────────
            let outcome = engine_a
                .self_at_login(input(Some(identity_signer.clone())))
                .await
                .expect("I92: self_at_login with the identity's signer");
            // v62.0.0 (E11, O1) — the person's DEVICE (the app) is an
            // `identity:occurrence` bind the identity authors; an AGENT key is
            // never a person's occurrence (`occurrence_mixes_person_and_machine`:
            // an agent's occurrence binds the agent's own identity), so it is
            // not on the person's plane. DEPENDS ON P8's edition-2
            // `self_at_login` (its producer and its outcome's agent leg).
            assert!(
                outcome.occurrences_published.contains(&app_key),
                "I92: the pubkey-bearing app occurrence was published: {outcome:?}"
            );
            let on_plane: Vec<String> =
                FederationDirectory::list_signed_identity_occurrences_for(sa.as_ref(), &identity)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|s| s.identity_occurrence.occurrence_key_id)
                    .collect();
            assert!(
                on_plane.contains(&app_key),
                "I92: the plane advertises the device occurrence: {on_plane:?}"
            );
            assert!(
                !on_plane.contains(&agent_key),
                "I92: an agent key is no person's occurrence: {on_plane:?}"
            );
            assert!(
                FederationDirectory::list_identity_occurrences_for(sa.as_ref(), &agent_key)
                    .await
                    .unwrap()
                    .iter()
                    .any(|o| o.occurrence_key_id == agent_key),
                "I92: the agent's occurrence binds the agent's own identity (P8 §3)"
            );
            // The far node admits the bind through the SAME door — the
            // identity's statement verifies against the identity's key and the
            // device's own voice against the device's, no lift needed.
            deliver_statements(
                sb.as_ref(),
                &bind_statements_for(sa.as_ref(), &identity).await,
            )
            .await
            .unwrap_or_else(|e| panic!("I92: B admits the bind through the door: {e}"));
            let far: Vec<String> =
                FederationDirectory::list_identity_occurrences_for(sb.as_ref(), &identity)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|o| o.occurrence_key_id)
                    .collect();
            assert!(far.contains(&app_key), "I92: on B: {far:?}");
            // The hardware attestation crossed as a BOUND member: the far row
            // carries what the producer stated in the bind's payload.
            let far_app =
                FederationDirectory::list_identity_occurrences_for(sb.as_ref(), &identity)
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|o| o.occurrence_key_id == app_key)
                    .expect("I92: the app row on B");
            assert_eq!(
                far_app.hardware_attestation.as_deref(),
                Some(hw_attest.as_str()),
                "I92: hardware_attestation is bound into the envelope and crosses intact"
            );

            // ── leg 2: WITHOUT the signer, trusted-local, not on the plane ──
            let engine_c = crate::Engine::with_signer_pre_genesis(
                ts::local_signer(&format!("i92-c-{run}")),
                "sqlite::memory:",
            )
            .await
            .unwrap();
            engine_c
                .register_self_federation_key(
                    crate::federation::types::identity_type::NODE,
                    None,
                    None,
                )
                .await
                .unwrap();
            let sc = engine_c.sqlite_backend().unwrap().clone();
            ts::register_hybrid_key_as(sc.as_ref(), &identity, &identity_label, USER).await;
            ts::register_hybrid_key_as(sc.as_ref(), &app_key, &app_key, USER).await;
            ts::register_hybrid_key_as(sc.as_ref(), &agent_key, &agent_key, AGENT).await;
            let outcome_c = engine_c
                .self_at_login(input(None))
                .await
                .expect("I92: self_at_login without the identity's signer still completes");
            // v62.0.0 (WD-fix9; the lead's ruling) — no unsigned occurrence
            // is written. WD-fix9b (the Constitution's ruling of 2026-11-22,
            // CC 3.3.6: "an UNOWNED agent has no occurrence") — the AGENT is
            // unowned here (no owner pen, no binding held), so NOTHING is
            // stated for it: it is pending with no draft. The APP's bind
            // needs the login identity's voice: its own voice is kept and the
            // identity's is DRAFTED.
            assert!(
                outcome_c.occurrences_published.is_empty(),
                "I92: nothing concludes without the identity's pen: {outcome_c:?}"
            );
            let mut pending = outcome_c.occurrences_pending.clone();
            pending.sort();
            let mut expected = vec![app_key.clone(), agent_key.clone()];
            expected.sort();
            assert_eq!(
                pending, expected,
                "I92: the app waits for the identity's voice, the unowned agent for an owner: \
                 {outcome_c:?}"
            );
            assert!(
                outcome_c.bind_drafts.iter().any(|(k, _)| k == &app_key),
                "I92: the identity's part of the app's bind is returned as a draft: {outcome_c:?}"
            );
            assert!(
                !outcome_c.bind_drafts.iter().any(|(k, _)| k == &agent_key),
                "I92: the unowned agent's bind is not drafted (there is no author): {outcome_c:?}"
            );
            // First login leaves NO unsigned occurrence row: nothing under the
            // login identity until the identity's voice lands.
            assert!(
                FederationDirectory::list_identity_occurrences_for(sc.as_ref(), &identity)
                    .await
                    .unwrap()
                    .is_empty(),
                "I92: no unsigned occurrence row under the identity"
            );
            // And none for the unowned agent: no row, signed or not.
            assert!(
                FederationDirectory::list_identity_occurrences_for(sc.as_ref(), &agent_key)
                    .await
                    .unwrap()
                    .is_empty()
                    && FederationDirectory::list_signed_identity_occurrences_for(
                        sc.as_ref(),
                        &agent_key
                    )
                    .await
                    .unwrap()
                    .is_empty(),
                "I92: an unowned agent has no occurrence"
            );
        }

        /// **I92 (b) — an occurrence with no `encryption_pubkeys` has no
        /// replicable form.** It is written trusted-local even when the signer
        /// is present, login does NOT fail for it, and the outcome names it.
        #[tokio::test]
        async fn i92b_a_pubkey_less_occurrence_stays_local_and_is_named_sqlite() {
            use crate::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
            use crate::federation::tier_ingest::test_support as ts;
            use crate::federation::types::identity_type::{AGENT, USER};
            use crate::federation::FederationDirectory;
            let run = uuid::Uuid::new_v4().simple().to_string();
            let alias = format!("i92b-{run}");
            let engine =
                crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), "sqlite::memory:")
                    .await
                    .unwrap();
            engine
                .register_self_federation_key(
                    crate::federation::types::identity_type::NODE,
                    None,
                    None,
                )
                .await
                .unwrap();
            let s = engine.sqlite_backend().unwrap().clone();
            let identity_label = format!("i92b-alice-{run}");
            let identity_signer = ts::local_signer(&identity_label);
            let identity = identity_signer.federation_id().await;
            ts::register_hybrid_key_as(s.as_ref(), &identity, &identity_label, USER).await;
            let (app_key, agent_key) = (
                e2::kid(&format!("i92b-app-{run}")),
                e2::kid(&format!("i92b-agent-{run}")),
            );
            ts::register_hybrid_key_as(s.as_ref(), &app_key, &app_key, USER).await;
            ts::register_hybrid_key_as(s.as_ref(), &agent_key, &agent_key, AGENT).await;
            let keys = {
                use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
                let (_xp, x_pub, _mp, ml_pub) =
                    crate::federation::identity_aggregate::mint_content_kem_keypair().unwrap();
                crate::federation::EncryptionPubkeys {
                    x25519_base64: B64.encode(x_pub),
                    ml_kem_768_base64: B64.encode(ml_pub),
                }
            };
            let outcome = engine
                .self_at_login(SelfAtLoginInput {
                    identity_key_id: identity.clone(),
                    identity_signer: Some(identity_signer),
                    app: SelfAtLoginOccurrence {
                        occurrence_key_id: app_key.clone(),
                        device_class: crate::federation::types::device_class::PHONE.to_owned(),
                        hardware_attestation: None,
                        encryption_pubkeys: Some(keys),
                        transport_destinations: vec![],
                        // v62.0.0 (P8 §3) — the identity it binds under (None: the
                        // login identity for the app, the agent key itself for the
                        // agent), its own pen, and no transport members.
                        identity_key_id: None,
                        occurrence_signer: Some(ts::local_signer(&e2::seed_of(&app_key))),
                        transport: None,
                    },
                    agent: SelfAtLoginOccurrence {
                        occurrence_key_id: agent_key.clone(),
                        device_class: crate::federation::types::device_class::AGENT.to_owned(),
                        hardware_attestation: None,
                        encryption_pubkeys: None, // ← no replicable form
                        transport_destinations: vec![],
                        // v62.0.0 (P8 §3) — the identity it binds under (None: the
                        // login identity for the app, the agent key itself for the
                        // agent), its own pen, and no transport members.
                        identity_key_id: None,
                        occurrence_signer: None,
                        transport: None,
                    },
                    bilateral_pair_id: uuid::Uuid::new_v4().to_string(),
                    delegation_scope: None,
                })
                .await
                .expect("I92 (b): login does not fail for a row that cannot replicate");
            assert_eq!(
                outcome.occurrences_published,
                vec![app_key.clone()],
                "{outcome:?}"
            );
            // v62.0.0 (WD-fix9) — the agent's bind did not land (no pen of its
            // own here): pending, drafted, and nothing unsigned written.
            assert_eq!(
                outcome.occurrences_pending,
                vec![agent_key.clone()],
                "{outcome:?}"
            );
            let plane: Vec<String> =
                FederationDirectory::list_signed_identity_occurrences_for(s.as_ref(), &identity)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|x| x.identity_occurrence.occurrence_key_id)
                    .collect();
            assert!(plane.contains(&app_key), "I92 (b): the app is on the plane");
            assert!(
                !plane.contains(&agent_key),
                "I92 (b): the pubkey-less agent is NOT"
            );
        }

        /// **I93 — a signer that is not the identity refuses BEFORE any
        /// occurrence is written.** The check existed (step 5); step 1 now
        /// signs with the signer, so the check moves ahead of it.
        #[tokio::test]
        async fn i93_a_foreign_identity_signer_refuses_before_any_occurrence_is_written_sqlite() {
            use crate::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
            use crate::federation::tier_ingest::test_support as ts;
            use crate::federation::types::identity_type::{AGENT, USER};
            use crate::federation::FederationDirectory;
            let run = uuid::Uuid::new_v4().simple().to_string();
            let alias = format!("i93-{run}");
            let engine =
                crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), "sqlite::memory:")
                    .await
                    .unwrap();
            engine
                .register_self_federation_key(
                    crate::federation::types::identity_type::NODE,
                    None,
                    None,
                )
                .await
                .unwrap();
            let s = engine.sqlite_backend().unwrap().clone();
            let identity_label = format!("i93-alice-{run}");
            let identity = ts::local_signer(&identity_label).federation_id().await;
            ts::register_hybrid_key_as(s.as_ref(), &identity, &identity_label, USER).await;
            let (app_key, agent_key) = (
                e2::kid(&format!("i93-app-{run}")),
                e2::kid(&format!("i93-agent-{run}")),
            );
            ts::register_hybrid_key_as(s.as_ref(), &app_key, &app_key, USER).await;
            ts::register_hybrid_key_as(s.as_ref(), &agent_key, &agent_key, AGENT).await;
            let foreign = ts::local_signer(&format!("i93-mallory-{run}"));
            let err = engine
                .self_at_login(SelfAtLoginInput {
                    identity_key_id: identity.clone(),
                    identity_signer: Some(foreign),
                    app: SelfAtLoginOccurrence {
                        occurrence_key_id: app_key.clone(),
                        device_class: crate::federation::types::device_class::PHONE.to_owned(),
                        hardware_attestation: None,
                        encryption_pubkeys: None,
                        transport_destinations: vec![],
                        // v62.0.0 (P8 §3) — the identity it binds under (None: the
                        // login identity for the app, the agent key itself for the
                        // agent), its own pen, and no transport members.
                        identity_key_id: None,
                        occurrence_signer: None,
                        transport: None,
                    },
                    agent: SelfAtLoginOccurrence {
                        occurrence_key_id: agent_key.clone(),
                        device_class: crate::federation::types::device_class::AGENT.to_owned(),
                        hardware_attestation: None,
                        encryption_pubkeys: None,
                        transport_destinations: vec![],
                        // v62.0.0 (P8 §3) — the identity it binds under (None: the
                        // login identity for the app, the agent key itself for the
                        // agent), its own pen, and no transport members.
                        identity_key_id: None,
                        occurrence_signer: None,
                        transport: None,
                    },
                    bilateral_pair_id: uuid::Uuid::new_v4().to_string(),
                    delegation_scope: None,
                })
                .await
                .expect_err("I93: a foreign signer is refused");
            assert!(
                matches!(err, crate::federation::Error::CustodyIsNotTheActor { .. }),
                "I93: the existing refusal, now first: {err:?}"
            );
            // NOTHING was written — the refusal precedes step 1.
            let rows = FederationDirectory::list_identity_occurrences_for(s.as_ref(), &identity)
                .await
                .unwrap();
            assert!(
                rows.is_empty(),
                "I93: no occurrence written before the refusal: {rows:?}"
            );
        }

        /// **I74 — the ledger stamps the WATERMARK, never the clock** (PR
        /// #850, round three). A grant that lands after the emitted set was
        /// built is newer than the mark and keeps the axis dirty; a mark at
        /// the newest grant cleans it; the mark never moves backwards.
        #[tokio::test]
        async fn i74_ledger_mark_is_the_snapshot_watermark_sqlite() {
            use crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2;
            use crate::federation::{BlobStorage, GrantWrap};
            let sq = fresh().await;
            let (comm, me) = ("i74-comm", "i74-me");
            sq.community_dek_put_self_retention(comm, me, 0, "{}")
                .await
                .unwrap();
            let wrap = |r: &str| GrantWrap {
                recipient_key_id: r.into(),
                wrap_algorithm: WRAP_ALGORITHM_V2.into(),
                wrapped_dek: "{}".into(),
            };
            sq.community_dek_put_member_grants(comm, me, 0, &[wrap("r1")])
                .await
                .unwrap();
            let w1 = sq
                .community_dek_key_grant_watermark(comm, me, 0)
                .await
                .unwrap()
                .expect("a grant exists");
            assert!(sq.community_dek_key_grant_dirty(comm, me, 0).await.unwrap());
            // The concurrent grant: lands AFTER the snapshot's watermark.
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            sq.community_dek_put_member_grants(comm, me, 0, &[wrap("r2")])
                .await
                .unwrap();
            // Mark at the SNAPSHOT's watermark (what the emitter read): still
            // dirty — r2 was not in the emitted set.
            sq.community_dek_mark_key_grant_emitted(comm, me, 0, w1)
                .await
                .unwrap();
            assert!(
                sq.community_dek_key_grant_dirty(comm, me, 0).await.unwrap(),
                "I74: a grant newer than the emitted snapshot keeps the axis dirty"
            );
            // Mark at the NEW watermark (a later emission that carried r2): clean.
            let w2 = sq
                .community_dek_key_grant_watermark(comm, me, 0)
                .await
                .unwrap()
                .unwrap();
            assert!(w2 > w1);
            sq.community_dek_mark_key_grant_emitted(comm, me, 0, w2)
                .await
                .unwrap();
            assert!(!sq.community_dek_key_grant_dirty(comm, me, 0).await.unwrap());
            // Never backwards: an older mark does not re-dirty.
            sq.community_dek_mark_key_grant_emitted(comm, me, 0, w1)
                .await
                .unwrap();
            assert!(!sq.community_dek_key_grant_dirty(comm, me, 0).await.unwrap());
        }

        /// **I70 — the emission ledger (V146): a door that died between its
        /// cascade and its emission is repaired by the next door, and by the
        /// boot sweep** (PR #850 review). The cascade is driven directly on the
        /// engine's backend — the exact state a crash leaves: DEK and wraps
        /// durable, no set on the cursor.
        #[tokio::test]
        async fn i70_emission_ledger_repairs_a_missed_emission_sqlite() {
            use crate::federation::attestation_query::test_support::AllAttestations as _;
            use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
            use crate::federation::tier_ingest::test_support as ts;
            use crate::federation::types::cohort_scope::COMMUNITY;
            use crate::federation::types::identity_type::USER;
            use crate::federation::{BlobStorage, EncryptionPubkeys, FederationDirectory};
            let run = uuid::Uuid::new_v4().simple().to_string();
            let alias = format!("i70-node-{run}");
            let engine =
                crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), "sqlite::memory:")
                    .await
                    .unwrap();
            // v62.0.0 (E11-fix4; CC rc21 3.3.6) — the engine is a MACHINE: a
            // member's device node (`place_device`: an owner binding onto a NODE
            // key), so it registers (and is introduced) as a NODE.
            engine
                .register_self_federation_key(
                    crate::federation::types::identity_type::NODE,
                    None,
                    None,
                )
                .await
                .unwrap();
            let sq = engine.sqlite_backend().unwrap().clone();
            let me = engine.local_derived_key_id().await.unwrap();
            let kem =
                |id: crate::federation::identity_aggregate::ContentKemIdentity| EncryptionPubkeys {
                    x25519_base64: id.x25519_pubkey_b64,
                    ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
                };
            // A community of me (occurrence: this node) and a member whose
            // occurrence lives elsewhere (a second in-memory identity).
            let other = fresh().await;
            let member_occ = e2::kid(&format!("i70-member-occ-{run}"));
            ts::register_hybrid_key_as(sq.as_ref(), &member_occ, &member_occ, USER).await;
            let node = Node {
                backend: sq.as_ref(),
                signer: ts::local_signer(&alias),
                key: me.clone(),
                kem: kem(sq.load_or_init_content_kem_identity().await.unwrap()),
            };
            let comm = e2::kid(&format!("i70-comm-{run}"));
            let (alice, bob) = (
                e2::kid(&format!("i70-alice-{run}")),
                e2::kid(&format!("i70-bob-{run}")),
            );
            seed_community_everywhere(&[&node], &comm, &[(&alice, Some(&node)), (&bob, None)])
                .await;
            // GID-fixtures-sites — the room's DERIVED id, once founded (`room_id`
            // panics if it was not).
            let comm = crate::federation::edition2::fixture_switch::room_id(&comm);
            sq.test_seam_put_identity_occurrence(crate::federation::types::IdentityOccurrence {
                identity_key_id: bob.clone(),
                occurrence_key_id: member_occ.clone(),
                device_class: crate::federation::types::device_class::SERVER.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(kem(other
                    .load_or_init_content_kem_identity()
                    .await
                    .unwrap())),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap();
            // v55.0.0 (#989) — the epoch-axis ROWS this node signed (one per
            // recipient: this node's occurrence and the member's).
            let epoch_sets = |sq: std::sync::Arc<SqliteBackend>, me: String| async move {
                sq.all_attestations_by(&me)
                    .await
                    .unwrap()
                    .into_iter()
                    .filter(|r| {
                        crate::federation::admission::envelope_dimension(&r.attestation_envelope)
                            == Some(crate::federation::key_grant::KEY_GRANT_EPOCH_DIMENSION)
                    })
                    .count()
            };
            // (1) The crash shape: the cascade ran, no door emitted.
            let sealed =
                encrypt_and_cascade_community(sq.as_ref(), &comm, b"minutes", None, Some(&me))
                    .await
                    .unwrap();
            assert!(sealed.granted.contains(&member_occ));
            assert_eq!(
                epoch_sets(sq.clone(), me.clone()).await,
                0,
                "I70: nothing carried"
            );
            assert!(
                sq.community_dek_key_grant_dirty(&comm, &me, sealed.epoch)
                    .await
                    .unwrap(),
                "I70: the epoch's set is DIRTY"
            );
            // (2) The next door — fan-out unchanged — emits anyway.
            let r = engine
                .put_blob_scoped(COMMUNITY, Some(&comm), b"next", None, None)
                .await
                .unwrap();
            assert!(
                r.key_grant_emission.is_some(),
                "I70: the dirty epoch reports an emission"
            );
            assert_eq!(
                epoch_sets(sq.clone(), me.clone()).await,
                2,
                "I70: the rows are on the cursor, one per recipient"
            );
            assert!(!sq
                .community_dek_key_grant_dirty(&comm, &me, sealed.epoch)
                .await
                .unwrap());
            // (3) Clean: a further unchanged write emits nothing more.
            let r2 = engine
                .put_blob_scoped(COMMUNITY, Some(&comm), b"again", None, None)
                .await
                .unwrap();
            assert!(
                r2.key_grant_emission.is_none(),
                "I70: clean epoch, no emission"
            );
            assert_eq!(epoch_sets(sq.clone(), me.clone()).await, 2);
            // (4) The boot sweep on a fresh community left dirty by a "crash".
            let comm2 = e2::kid(&format!("i70-comm2-{run}"));
            // Seeded by hand: alice (this node's identity) is already
            // registered — one occurrence, one identity — and joins a second
            // community with bob2.
            let bob2 = e2::kid(&format!("i70-bob2-{run}"));
            let member_occ2 = e2::kid(&format!("i70-member-occ2-{run}"));
            for k in [&comm2, &bob2, &member_occ2] {
                ts::register_hybrid_key_as(sq.as_ref(), k, k, USER).await;
            }
            sq.test_seam_put_identity_occurrence(crate::federation::types::IdentityOccurrence {
                identity_key_id: bob2.clone(),
                occurrence_key_id: member_occ2.clone(),
                device_class: crate::federation::types::device_class::SERVER.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(kem(other
                    .load_or_init_content_kem_identity()
                    .await
                    .unwrap())),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap();
            e2::put_voices(
                sq.as_ref(),
                &community_roster_voices(&comm2, "Second Co-op", &[&alice, &bob2]),
            )
            .await
            .unwrap();
            // GID-fixtures-sites — the room's DERIVED id, once founded (`room_id`
            // panics if it was not).
            let comm2 = crate::federation::edition2::fixture_switch::room_id(&comm2);
            encrypt_and_cascade_community(sq.as_ref(), &comm2, b"crashed", None, Some(&me))
                .await
                .unwrap();
            assert_eq!(
                engine.emit_pending_key_grants().await.unwrap(),
                2,
                "I70: the sweep emits the dirty epoch's rows"
            );
            assert_eq!(epoch_sets(sq.clone(), me.clone()).await, 4);
            assert_eq!(
                engine.emit_pending_key_grants().await.unwrap(),
                0,
                "I70: nothing left to emit"
            );
        }

        /// I61 through the CONSUMER-HELD doors: two `Engine`s, each its own
        /// in-memory sqlite. `put_blob_scoped` on A emits the set through
        /// `emit_attestation_self`; B admits its statement through the
        /// replicated statement door (v62.0.0), adopts the bytes through
        /// `Engine::adopt_sealed_blob`, and opens them through
        /// `Engine::read_blob_as`. `Engine::emit_key_grant` re-emits on demand.
        #[tokio::test]
        async fn i61_end_to_end_through_the_engine_doors_sqlite() {
            use crate::federation::attestation_query::test_support::AllAttestations as _;
            use crate::federation::key_grant::{KeyGrantAxis, SignedKeyGrantRow};
            use crate::federation::tier_ingest::test_support as ts;
            use crate::federation::types::cohort_scope::{CryptoTier, COMMUNITY};
            use crate::federation::types::identity_type::NODE;
            use crate::federation::{
                AdoptDisposition, BlobBody, BlobProvenance, BlobStorage, EncryptionPubkeys,
            };
            let run = uuid::Uuid::new_v4().simple().to_string();
            let (alias_a, alias_b) = (format!("eng-a-{run}"), format!("eng-b-{run}"));
            let engine_a = crate::Engine::with_signer_pre_genesis(
                ts::local_signer(&alias_a),
                "sqlite::memory:",
            )
            .await
            .unwrap();
            let engine_b = crate::Engine::with_signer_pre_genesis(
                ts::local_signer(&alias_b),
                "sqlite::memory:",
            )
            .await
            .unwrap();
            // v62.0.0 (E11-fix4; CC rc21 3.3.6) — the engine is a MACHINE: a
            // member's device node (`place_device`: an owner binding onto a NODE
            // key), so it registers (and is introduced) as a NODE.
            for e in [&engine_a, &engine_b] {
                e.register_self_federation_key(
                    crate::federation::types::identity_type::NODE,
                    None,
                    None,
                )
                .await
                .expect("register the engine's own key");
            }
            let (sa, sb) = (
                engine_a.sqlite_backend().unwrap().clone(),
                engine_b.sqlite_backend().unwrap().clone(),
            );
            let kem =
                |id: crate::federation::identity_aggregate::ContentKemIdentity| EncryptionPubkeys {
                    x25519_base64: id.x25519_pubkey_b64,
                    ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
                };
            let a = Node {
                backend: sa.as_ref(),
                signer: ts::local_signer(&alias_a),
                key: engine_a.local_derived_key_id().await.unwrap(),
                kem: kem(sa.load_or_init_content_kem_identity().await.unwrap()),
            };
            let b = Node {
                backend: sb.as_ref(),
                signer: ts::local_signer(&alias_b),
                key: engine_b.local_derived_key_id().await.unwrap(),
                kem: kem(sb.load_or_init_content_kem_identity().await.unwrap()),
            };
            introduce_as(&[&a, &b], &[&alias_a, &alias_b], NODE).await;
            let comm = e2::kid(&format!("eng-comm-{run}"));
            let (alice, bob) = (
                e2::kid(&format!("eng-alice-{run}")),
                e2::kid(&format!("eng-bob-{run}")),
            );
            seed_community_everywhere(&[&a, &b], &comm, &[(&alice, Some(&a)), (&bob, Some(&b))])
                .await;
            // GID-fixtures-sites — the room's DERIVED id, once founded (`room_id`
            // panics if it was not).
            let comm = crate::federation::edition2::fixture_switch::room_id(&comm);

            // A writes through THE door; the set is emitted by the door.
            let r = engine_a
                .put_blob_scoped(COMMUNITY, Some(&comm), b"engine minutes", None, None)
                .await
                .expect("A's scoped put");
            assert_eq!(r.tier, CryptoTier::CommunityDek);
            assert!(
                r.key_grant_emission.is_some(),
                "the first seal minted: a set was reported"
            );
            let sha = r.at_rest_sha256;
            let emitted: Vec<_> = sa
                .all_attestations_by(&a.key)
                .await
                .unwrap()
                .into_iter()
                .filter(|x| {
                    crate::federation::admission::envelope_dimension(&x.attestation_envelope)
                        == Some(crate::federation::key_grant::KEY_GRANT_EPOCH_DIMENSION)
                })
                .collect();
            assert_eq!(
                emitted.len(),
                2,
                "one epoch-axis row per recipient emitted by the door (A's own, B's)"
            );
            let to_b = emitted
                .iter()
                .find(|x| x.attested_key_id == b.key)
                .expect("a row to B");

            // B admits the row's statement through the replicated statement
            // door (v62.0.0, E11: `Engine::apply_replicated_key_grant` is the
            // earlier form's door, shut at CP2; the Engine exposes no
            // statement door, so the substrate's is the one a host calls),
            // and adopts through the Engine door.
            let admission = admit_replicated(
                sb.as_ref(),
                SignedKeyGrantRow {
                    attestation: to_b.clone(),
                },
            )
            .await
            .expect("B admits A's row through the replicated statement door");
            assert!(admission.projected, "{admission:?}");
            let Some(BlobBody::Inline(bytes)) = sa.get_blob(&sha).await.unwrap() else {
                panic!("inline")
            };
            engine_b
                .adopt_sealed_blob(
                    &bytes,
                    BlobProvenance {
                        author_key_id: a.key.clone(),
                        cohort_scope: COMMUNITY.into(),
                        community_key_id: Some(comm.clone()),
                        epoch: Some(0),
                        tier: CryptoTier::CommunityDek,
                        minter_key_id: None,
                    },
                    None,
                    AdoptDisposition::LocalOnly,
                )
                .await
                .expect("B adopts through the Engine door");
            assert_eq!(
                engine_b
                    .read_blob_as(&sha, &b.key, None)
                    .await
                    .expect("B reads through the Engine door"),
                b"engine minutes"
            );
            // Re-emission on demand is idempotent: every wrap is held as a row
            // already, so nothing new is emitted (v55.0.0, #989).
            let again = engine_a
                .emit_key_grant(&KeyGrantAxis::Epoch {
                    community_key_id: comm.clone(),
                    minter_key_id: a.key.clone(),
                    epoch: 0,
                })
                .await
                .expect("re-emit")
                .expect("A holds wraps");
            assert!(again.attestation_ids.is_empty(), "{again:?}");
            assert_eq!(again.already_emitted.len(), 2, "{again:?}");
            // A second seal in the same epoch changes no grant: no new set.
            let r2 = engine_a
                .put_blob_scoped(COMMUNITY, Some(&comm), b"more minutes", None, None)
                .await
                .unwrap();
            assert!(
                r2.key_grant_emission.is_none(),
                "an unchanged fan-out emits nothing (§14)"
            );
        }
    }

    #[cfg(feature = "postgres")]
    mod postgres {
        use super::super::two_node::*;
        use crate::store::postgres::PostgresBackend;
        use crate::store::Backend as _;

        async fn fresh() -> Option<PostgresBackend> {
            let dsn = crate::test_pg::empty_dsn()?;
            let b = PostgresBackend::connect(&dsn).await.unwrap();
            b.run_migrations().await.unwrap();
            Some(b)
        }

        #[tokio::test]
        async fn i61_end_to_end_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node_as(&ba, "i61-a", crate::federation::types::identity_type::NODE).await;
            let b = node_as(&bb, "i61-b", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b],
                &["i61-a", "i61-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i61_end_to_end(&a, &b, "postgres").await;
        }

        #[tokio::test]
        async fn i76_content_only_occurrence_postgres() {
            let Some(bn) = fresh().await else {
                eprintln!("no postgres — skipped");
                return;
            };
            let n = node_as(&bn, "i76-n", crate::federation::types::identity_type::NODE).await;
            exercise_i76_content_only_occurrence(&n, "i76-n", "postgres").await;
        }

        #[tokio::test]
        async fn i60_forged_set_refused_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node_as(&ba, "i60-a", crate::federation::types::identity_type::NODE).await;
            let b = node_as(&bb, "i60-b", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b],
                &["i60-a", "i60-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i60_forged_set_refused(&a, &b, "postgres").await;
        }

        #[tokio::test]
        async fn i60b_delayed_set_survives_a_later_occurrence_revocation_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node_as(&ba, "i60b-a", crate::federation::types::identity_type::NODE).await;
            let b = node_as(&bb, "i60b-b", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b],
                &["i60b-a", "i60b-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i60b_delayed_set_survives_a_later_occurrence_revocation(&a, &b, "postgres")
                .await;
        }

        #[tokio::test]
        async fn i77_owned_node_minter_admitted_by_principal_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i77-a").await;
            let b = node(&bb, "i77-b").await;
            introduce_as(
                &[&a, &b],
                &["i77-a", "i77-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            Box::pin(exercise_i77_owned_node_minter_admitted_by_principal(
                &a, &b, "postgres",
            ))
            .await;
        }

        #[tokio::test]
        async fn i71_rotation_keys_on_effective_at_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node_as(&ba, "i71-a", crate::federation::types::identity_type::NODE).await;
            let b = node_as(&bb, "i71-b", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b],
                &["i71-a", "i71-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i71_rotation_keys_on_effective_at(&a, &b, "postgres").await;
        }

        #[tokio::test]
        async fn i62_union_order_independent_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node_as(&ba, "i62-a", crate::federation::types::identity_type::NODE).await;
            let b = node_as(&bb, "i62-b", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b],
                &["i62-a", "i62-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i62_union_order_independent(&a, &b, "postgres").await;
        }

        #[tokio::test]
        async fn i63_rotation_on_admitted_removal_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node_as(&ba, "i63-a", crate::federation::types::identity_type::NODE).await;
            let b = node_as(&bb, "i63-b", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b],
                &["i63-a", "i63-b"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i63_rotation_on_admitted_removal(&a, &b, "postgres").await;
        }

        #[tokio::test]
        async fn i64_two_minters_same_epoch_postgres() {
            let (Some(ba), Some(bb), Some(bc)) = (fresh().await, fresh().await, fresh().await)
            else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node_as(&ba, "i64-a", crate::federation::types::identity_type::NODE).await;
            let b = node_as(&bb, "i64-b", crate::federation::types::identity_type::NODE).await;
            let c = node_as(&bc, "i64-c", crate::federation::types::identity_type::NODE).await;
            introduce_as(
                &[&a, &b, &c],
                &["i64-a", "i64-b", "i64-c"],
                crate::federation::types::identity_type::NODE,
            )
            .await;
            exercise_i64_two_minters_same_epoch(&a, &b, &c, "postgres").await;
        }

        #[tokio::test]
        async fn i199_family_member_publishes_and_another_opens_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i199-a").await;
            let b = node(&bb, "i199-b").await;
            introduce(&[&a, &b], &["i199-a", "i199-b"]).await;
            exercise_i199_family_member_publishes_and_another_opens(&a, &b, "postgres").await;
        }

        #[tokio::test]
        async fn i800_the_blob_arrival_race_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i800-a").await;
            let a2 = node(&bb, "i800-a2").await;
            introduce(&[&a, &a2], &["i800-a", "i800-a2"]).await;
            exercise_i800_the_blob_arrival_race(&a, &a2, "postgres").await;
        }

        #[tokio::test]
        async fn i1519_a_self_grant_reaches_the_persons_occurrences_postgres() {
            let (Some(ba), Some(bb), Some(bc)) = (fresh().await, fresh().await, fresh().await)
            else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i1519-a").await;
            let b = node(&bb, "i1519-b").await;
            let c = node(&bc, "i1519-c").await;
            introduce(&[&a, &b, &c], &["i1519-a", "i1519-b", "i1519-c"]).await;
            bb.set_node_key_id(b.key.clone());
            bc.set_node_key_id(c.key.clone());
            exercise_i1519_a_self_grant_reaches_the_persons_occurrences(&a, &b, &c, "postgres")
                .await;
            eprintln!("i1519 postgres: RAN");
        }

        #[tokio::test]
        async fn i91_a_bind_carries_valid_until_postgres() {
            let Some(bn) = fresh().await else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let n = node(&bn, "i91-n").await;
            exercise_i91_a_bind_carries_valid_until(&n, "postgres").await;
        }

        #[tokio::test]
        async fn i65_content_axis_second_device_postgres() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let a = node(&ba, "i65-a").await;
            let a2 = node(&bb, "i65-a2").await;
            introduce(&[&a, &a2], &["i65-a", "i65-a2"]).await;
            exercise_i65_content_axis_second_device(&a, &a2, "postgres").await;
        }
    }
}
