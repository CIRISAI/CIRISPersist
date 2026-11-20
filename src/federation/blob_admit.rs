//! v61 (CIRISPersist#934, S4a) — **the blob plane's gated doors, decided
//! once.**
//!
//! Each `BlobStorage` door the parity scan reported `identical x2` is one
//! function here, and a backend implements [`BlobFloorStore`]: the SQL, the
//! transaction, the savepoints, the locks. It decides nothing.
//!
//! - the chunk floor (`put_blob_chunk_with_scope`, `adopt_sealed_chunk_at`,
//!   `adopt_sealed_chunks_at`): the scope, reserved-name, batch and
//!   stream-key gates, each item's floor check and tombstone pre-read, then
//!   ONE executor transaction. The stream claim (#837 / I41, #954) is judged
//!   inside it by [`stream_claim_verdict`], a shared plan the executor
//!   re-asks; each item's answer is [`item_answer`];
//! - the stream plane's records (`stream_dek_insert`,
//!   `stream_dek_put_grants`, `put_stream_sth`, `put_delivery_receipt`): the gates, then a write that reports what it
//!   found under the key for the plan to judge.
//!
//! # Which instant each plan reads
//!
//! A delivery receipt is stamped `received_at` with the door's one clock
//! read. The others read no instant (a stream row's `created_at` is the
//! executor's column default).

use super::blobs::{
    self, BlobStorage, ChunkFloorItem, EpochBinding, StorageFloor, StreamClaim, StreamDekRecord,
};
use super::steward_purge::{self, ReversedTakedowns, TombstoneFloor};
use super::{BlobError, FederationDirectory};

// ── the chunk floor ─────────────────────────────────────────────────────

/// One chunk the floor admitted: its `federation_blobs` row and its index
/// row's binds, at `slot` in the caller's batch.
#[derive(Debug, Clone)]
pub(crate) struct ChunkFloorRow {
    /// The item's position in the caller's batch.
    pub(crate) slot: usize,
    /// Its stream position.
    pub(crate) seq: u64,
    /// `seq`, as stored.
    pub(crate) seq_i64: i64,
    /// Its plaintext length, as stored.
    pub(crate) plaintext_i64: i64,
    /// Its content address.
    pub(crate) sha256: [u8; 32],
    /// `storage_kind`.
    pub(crate) storage_kind: &'static str,
    /// `bytes_inline`.
    pub(crate) bytes_inline: Option<Vec<u8>>,
    /// `external_ref`.
    pub(crate) external_ref: Option<String>,
    /// `size_bytes`.
    pub(crate) size_bytes: i64,
}

/// What one item's savepoint did. Anything but `Ok` rolls it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ItemAppended {
    /// Stored.
    Ok,
    /// The stream already holds this `seq`.
    SeqConflict,
    /// The (stream, epoch) counter is at `MAX_CHUNKS_PER_EPOCH`.
    CapReached,
    /// The binding's epoch is no longer the community's current one.
    EpochMoved,
    /// #969 — the V165 count is not the counter the chunk was sealed at.
    StreamCounterMoved,
    /// #969 — the stream epoch is closed / terminated / has no DEK row.
    StreamEpochClosed,
    /// v60.1.0 (#1070) — a tombstone committed after the pre-read: the
    /// notice naming the chunk's address.
    Purged(String),
}

/// A chunk batch the floor admitted: the stream's claim and every item's
/// row, for ONE executor transaction.
#[derive(Debug, Clone)]
pub(crate) struct PlannedChunkBatch {
    /// The stream.
    pub(crate) stream_id: String,
    /// The epoch every item was sealed under, as stored.
    pub(crate) epoch_i64: i64,
    /// The batch's cohort scope.
    pub(crate) cohort_scope: String,
    /// The floor's crypto tier.
    pub(crate) tier: String,
    /// The epoch binding, if any.
    pub(crate) binding: Option<EpochBinding>,
    /// `false`: the write rule (the binding's epoch must be the community's
    /// CURRENT one, I17); `true`: the adopt rule (bound as declared).
    pub(crate) bind_as_declared: bool,
    /// Whose stream this append claims.
    pub(crate) claim: StreamClaim,
    /// The in-transaction tombstone look's inputs (#1070, #1113).
    pub(crate) tombstones: TombstoneFloor,
    /// The admitted items.
    pub(crate) rows: Vec<ChunkFloorRow>,
}

/// The stream's row as the executor found it, after its insert-if-absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldStream {
    /// `cohort_scope`.
    pub(crate) cohort_scope: String,
    /// `community_key_id`.
    pub(crate) community_key_id: Option<String>,
    /// `owner_key_id`.
    pub(crate) owner_key_id: Option<String>,
    /// Whether `abandoned_at` is set.
    pub(crate) abandoned: bool,
}

/// What the executor does with the stream row the claim may proceed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamClaimWrite {
    /// The claim matches the row: append.
    Proceed,
    /// The row is unclaimed and the append names an owner: adopt it
    /// (`… WHERE owner_key_id IS NULL`); a lost adopt is a foreign stream.
    Adopt,
}

/// The stream executor. Storage only.
#[async_trait::async_trait]
pub(crate) trait BlobFloorStore: BlobStorage + FederationDirectory + Sized {
    /// Does the bytes-plane tombstone table exist (#1070)?
    fn tombstone_plane_present(&self) -> bool;

    /// Test-only: the witnesses' seam between the tombstone pre-read and the
    /// write (`BYTES_AFTER_TOMBSTONE_PRECHECK`).
    #[cfg(test)]
    async fn pause_after_tombstone_precheck(&self);

    /// In ONE transaction: insert the stream row if absent, read it back,
    /// ask [`stream_claim_verdict`] (adopting an unclaimed row when it says
    /// so), then append each row inside its own savepoint, rolled back
    /// unless `Ok`. Nothing landed ⇒ nothing commits (a refused first append
    /// does not claim the stream).
    async fn store_planned_chunk_batch(
        &self,
        batch: PlannedChunkBatch,
    ) -> Result<Vec<(usize, ItemAppended)>, BlobError>;

    /// The stream's chunk hashes in `seq` order.
    async fn read_stream_chunk_hashes(&self, stream_id: &str) -> Result<Vec<[u8; 32]>, BlobError>;

    /// Insert the STH at `(stream_id, tree_size)` unless one is held;
    /// `Some(root)`: the held row's root, and nothing was written.
    async fn store_stream_sth(&self, sth: PlannedSth<'_>) -> Result<Option<Vec<u8>>, BlobError>;

    /// In ONE transaction: the published-root JOIN, then the receipt at
    /// `(stream_id, subscriber_key_id, k)` unless one is held.
    async fn store_delivery_receipt(
        &self,
        receipt: PlannedReceipt<'_>,
    ) -> Result<ReceiptWrite, BlobError>;

    /// Insert the stream DEK row if absent, and read back the stored one.
    async fn store_stream_dek(
        &self,
        record: &StreamDekRecord,
        epoch_i64: i64,
    ) -> Result<StreamDekRecord, BlobError>;

    /// In ONE transaction: each wrap, `DO NOTHING` per row (§13). The count
    /// inserted.
    async fn store_stream_dek_grants(
        &self,
        stream_id: &str,
        epoch: u64,
        sealer_key_id: &str,
        cohort_scope: &str,
        wraps: &[super::GrantWrap],
    ) -> Result<usize, BlobError>;
}

/// v62.0.0 (wave GC7; CC 2.7.3) — the reason tokens of the byte doors'
/// fold conditions, and the one marker every one of them uses: a refusal
/// that read ANOTHER row (a held stream, a held chunk at the slot, an epoch
/// row, a tombstone, a published STH, a held receipt, this node's own blob
/// row) marks the running fold attempt held with `reason` and declares the
/// stream / content it read; outside an attempt it is the refusal it was.
/// The byte checks (cap, hash, scope, name, arity) and the epoch CAP (a
/// resource limit) stay refusals.
fn held_on(reason: &'static str, read: &str, err: BlobError) -> BlobError {
    super::edition2::fold::reads(super::edition2::fold::Dep::key(read));
    super::edition2::fold::hold_detail(reason, err.to_string());
    err
}

/// **The stream claim's verdict** (#837 §12.9 / I41, #954), asked by the
/// executor inside its transaction against the row it just read: a stream
/// belongs to its first append; an abandoned one takes nothing; one in
/// another cohort or community, or owned by another key, is refused.
pub(crate) fn stream_claim_verdict(
    batch: &PlannedChunkBatch,
    held: &HeldStream,
) -> Result<StreamClaimWrite, BlobError> {
    refuse_held_stream(batch, held)?;
    Ok(match (&held.owner_key_id, &batch.claim.owner_key_id) {
        (None, Some(_)) => StreamClaimWrite::Adopt,
        _ => StreamClaimWrite::Proceed,
    })
}

/// The held stream rows an append may not land on.
fn refuse_held_stream(batch: &PlannedChunkBatch, held: &HeldStream) -> Result<(), BlobError> {
    let stream_id = batch.stream_id.as_str();
    // v62.0.0 (T2-fix8; lead's GC7 ruling, T2-fix7.md §2) — NOT a fold hold.
    // No production path ever clears this blocker (an abandoned stream, the
    // first append's cohort / owner, a held slot, a moved epoch), so no held
    // bytes could ever be released: this arm is a terminal REFUSAL, and v62
    // keeps no held chunk store. (These doors also run outside any fold
    // attempt, where a mark was inert.) Same-author `seq_held` equivocation
    // ("both kept, neither concludes") is a post-v62 CC policy question.
    if held.abandoned {
        return Err(blobs::stream_abandoned_refusal(stream_id));
    }
    if held.cohort_scope != batch.cohort_scope
        || held.community_key_id != batch.claim.community_key_id
    {
        return Err(blobs::stream_elsewhere_refusal(
            stream_id,
            &held.cohort_scope,
            held.community_key_id.as_deref(),
            &batch.cohort_scope,
            batch.claim.community_key_id.as_deref(),
        ));
    }
    match (&held.owner_key_id, &batch.claim.owner_key_id) {
        (None, _) => Ok(()),
        (Some(owner), Some(mine)) if owner == mine => Ok(()),
        _ => Err(foreign_stream(batch, held)),
    }
}

/// The refusal of a stream another key owns (never disclosing whose).
pub(crate) fn foreign_stream(batch: &PlannedChunkBatch, held: &HeldStream) -> BlobError {
    blobs::stream_foreign_refusal(
        &batch.stream_id,
        &held.cohort_scope,
        held.community_key_id.as_deref(),
    )
}

/// One item's answer from what its savepoint did.
fn item_answer(
    batch_stream: &str,
    epoch: u64,
    binding: Option<&EpochBinding>,
    claim: &StreamClaim,
    (seq, sha): (u64, [u8; 32]),
    got: ItemAppended,
) -> Result<[u8; 32], BlobError> {
    use super::edition2::fold::reason;
    // v62.0.0 (T2-fix8; lead's GC7 ruling, T2-fix7.md §2) — NOT a fold hold.
    // No production path ever clears this blocker (an abandoned stream, the
    // first append's cohort / owner, a held slot, a moved epoch), so no held
    // bytes could ever be released: this arm is a terminal REFUSAL, and v62
    // keeps no held chunk store. (These doors also run outside any fold
    // attempt, where a mark was inert.) Same-author `seq_held` equivocation
    // ("both kept, neither concludes") is a post-v62 CC policy question.
    // The epoch cap is a resource limit. Only the tombstone arm keeps its
    // mark (GC2's reversal item; a purge order, not a slot conflict).
    Err(match got {
        ItemAppended::Ok => return Ok(sha),
        ItemAppended::SeqConflict => {
            BlobError::InvalidArgument(format!("stream {batch_stream} seq {seq} already exists"))
        }
        ItemAppended::CapReached => blobs::epoch_cap_refusal(batch_stream, epoch),
        ItemAppended::EpochMoved => {
            let b = binding.expect("EpochMoved only arises with a binding");
            BlobError::EpochNotCurrent {
                community_key_id: b.community_key_id.clone(),
                epoch: b.epoch,
            }
        }
        ItemAppended::StreamCounterMoved => blobs::stream_counter_moved_refusal(
            batch_stream,
            epoch,
            claim.stream_key.map_or(0, |k| k.counter),
        ),
        ItemAppended::StreamEpochClosed => blobs::stream_epoch_closed_refusal(batch_stream, epoch),
        ItemAppended::Purged(notice_id) => held_on(
            reason::BLOB_PURGED,
            &hex::encode(sha),
            BlobError::Purged {
                sha256_hex: hex::encode(sha),
                notice_id,
            },
        ),
    })
}

/// An item's floor check and hash-on-write (`prepare_stream_chunk_row`) and
/// its u64 → i64 binds, outside the transaction.
fn prepare_chunk_item(
    slot: usize,
    item: &ChunkFloorItem,
    cap: usize,
    floor: StorageFloor,
) -> Result<ChunkFloorRow, BlobError> {
    let row = blobs::prepare_stream_chunk_row(&item.body, cap, floor, item.plaintext_size)?;
    let seq_i64 = i64::try_from(item.seq)
        .map_err(|_| BlobError::InvalidArgument("put_blob_chunk: seq exceeds i64".into()))?;
    let plaintext_i64 = i64::try_from(item.plaintext_size).map_err(|_| {
        BlobError::InvalidArgument("put_blob_chunk: plaintext_size exceeds i64".into())
    })?;
    Ok(ChunkFloorRow {
        slot,
        seq: item.seq,
        seq_i64,
        plaintext_i64,
        sha256: row.sha256,
        storage_kind: row.storage_kind,
        bytes_inline: row.bytes_inline,
        external_ref: row.external_ref,
        size_bytes: row.size_bytes,
    })
}

/// #832 (§12.3) / #846 (§6.2) / #957 — **the chunk floor**, shared by the
/// write door and the adopt doors, batched. A refusal of the batch's own
/// shape (scope, name, bounds, stream-key arity) or of the stream refuses
/// the whole batch; an item refused by its floor check, its tombstone or its
/// savepoint answers `Err` in its slot and the rest commit.
#[allow(clippy::too_many_arguments)]
async fn chunk_floor_planned<D: BlobFloorStore>(
    dir: &D,
    stream_id: &str,
    items: Vec<ChunkFloorItem>,
    epoch: u64,
    cohort_scope: &str,
    floor: StorageFloor,
    binding: Option<EpochBinding>,
    claim: StreamClaim,
    bind_as_declared: bool,
) -> Result<Vec<Result<[u8; 32], BlobError>>, BlobError> {
    floor.check_scope(cohort_scope)?;
    super::stream_sth::refuse_reserved_stream_id(stream_id)?;
    blobs::check_chunk_batch_bounds(&items)?;
    blobs::check_stream_key_batch(&claim, items.len())?;
    let epoch_i64 = i64::try_from(epoch)
        .map_err(|_| BlobError::InvalidArgument("put_blob_chunk: epoch exceeds i64".into()))?;
    let cap = dir.inline_bytes_cap();
    let mut results: Vec<Option<Result<[u8; 32], BlobError>>> = Vec::with_capacity(items.len());
    let mut ready = Vec::with_capacity(items.len());
    for (slot, item) in items.iter().enumerate() {
        match prepare_chunk_item(slot, item, cap, floor) {
            Ok(row) => {
                results.push(None);
                ready.push(row);
            }
            Err(e) => results.push(Some(Err(e))),
        }
    }
    // v55.0.0 (#1007) — taken-down bytes never come back: that item's answer
    // is the refusal, as for any other per-item refusal.
    let mut rows = Vec::with_capacity(ready.len());
    let mut reversed = ReversedTakedowns::default();
    for row in ready {
        match steward_purge::refuse_tombstoned_bytes(dir, &row.sha256).await {
            Ok(r) => {
                reversed.absorb(r);
                rows.push(row);
            }
            Err(e) => results[row.slot] = Some(Err(e)),
        }
    }
    // v60.1.0 (#1070) — the in-transaction second look's inputs, and the
    // witnesses' seam between the pre-read and the write.
    let tombstones = TombstoneFloor::new(dir.tombstone_plane_present(), reversed);
    #[cfg(test)]
    dir.pause_after_tombstone_precheck().await;
    let meta: Vec<(usize, u64, [u8; 32])> =
        rows.iter().map(|r| (r.slot, r.seq, r.sha256)).collect();
    let batch = PlannedChunkBatch {
        stream_id: stream_id.to_owned(),
        epoch_i64,
        cohort_scope: cohort_scope.to_owned(),
        tier: floor.tier().as_str().to_owned(),
        binding: binding.clone(),
        bind_as_declared,
        claim: claim.clone(),
        tombstones,
        rows,
    };
    // The stream is judged even when every item was refused before the
    // transaction: a refused stream refuses the whole batch.
    let appended = dir.store_planned_chunk_batch(batch).await?;
    for (slot, got) in appended {
        let &(_, seq, sha) = meta
            .iter()
            .find(|(s, _, _)| *s == slot)
            .expect("the executor answers the planned slots");
        results[slot] = Some(item_answer(
            stream_id,
            epoch,
            binding.as_ref(),
            &claim,
            (seq, sha),
            got,
        ));
    }
    Ok(results
        .into_iter()
        .map(|r| r.expect("every slot answered"))
        .collect())
}

/// The adopt doors' claim (#846 §6.2, I50): the AUTHOR is the claimed owner,
/// so the adopter can never append to the stream as its own (I41 carried
/// across nodes); the provenance's community, bound or not (#977).
fn adopt_claim(
    author_key_id: &str,
    binding: Option<&EpochBinding>,
    community_key_id: Option<&str>,
) -> StreamClaim {
    StreamClaim {
        community_key_id: community_key_id
            .map(str::to_owned)
            .or_else(|| binding.map(|b| b.community_key_id.clone())),
        owner_key_id: Some(author_key_id.to_owned()),
        stream_key: None,
    }
}

/// The one answer of a batch of one.
fn only(mut out: Vec<Result<[u8; 32], BlobError>>) -> Result<[u8; 32], BlobError> {
    out.pop().expect("a batch of one answers with one result")
}

/// The door: every backend's `put_blob_chunk_with_scope`. #832 (§12.3 /
/// I17) — a WRITE binds the current epoch.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn put_blob_chunk_planned<D: BlobFloorStore>(
    dir: &D,
    stream_id: &str,
    seq: u64,
    body: super::BlobBody,
    epoch: u64,
    plaintext_size: u64,
    cohort_scope: &str,
    floor: StorageFloor,
    binding: Option<EpochBinding>,
    claim: StreamClaim,
) -> Result<[u8; 32], BlobError> {
    let item = ChunkFloorItem {
        seq,
        body,
        plaintext_size,
    };
    only(
        chunk_floor_planned(
            dir,
            stream_id,
            vec![item],
            epoch,
            cohort_scope,
            floor,
            binding,
            claim,
            false,
        )
        .await?,
    )
}

/// The door: every backend's `adopt_sealed_chunk_at`. The binding is
/// written AS DECLARED (no current-epoch check).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn adopt_sealed_chunk_planned<D: BlobFloorStore>(
    dir: &D,
    stream_id: &str,
    seq: u64,
    envelope_bytes: Vec<u8>,
    epoch: u64,
    plaintext_size: u64,
    cohort_scope: &str,
    author_key_id: &str,
    floor: StorageFloor,
    binding: Option<EpochBinding>,
    community_key_id: Option<&str>,
) -> Result<[u8; 32], BlobError> {
    let claim = adopt_claim(author_key_id, binding.as_ref(), community_key_id);
    let item = ChunkFloorItem {
        seq,
        body: super::BlobBody::Inline(envelope_bytes),
        plaintext_size,
    };
    only(
        chunk_floor_planned(
            dir,
            stream_id,
            vec![item],
            epoch,
            cohort_scope,
            floor,
            binding,
            claim,
            true,
        )
        .await?,
    )
}

/// The door: every backend's `adopt_sealed_chunks_at`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn adopt_sealed_chunks_planned<D: BlobFloorStore>(
    dir: &D,
    stream_id: &str,
    items: Vec<(u64, Vec<u8>, u64)>,
    epoch: u64,
    cohort_scope: &str,
    author_key_id: &str,
    floor: StorageFloor,
    binding: Option<EpochBinding>,
    community_key_id: Option<&str>,
) -> Result<Vec<Result<[u8; 32], BlobError>>, BlobError> {
    let claim = adopt_claim(author_key_id, binding.as_ref(), community_key_id);
    let items = items
        .into_iter()
        .map(|(seq, envelope, plaintext_size)| ChunkFloorItem {
            seq,
            body: super::BlobBody::Inline(envelope),
            plaintext_size,
        })
        .collect();
    chunk_floor_planned(
        dir,
        stream_id,
        items,
        epoch,
        cohort_scope,
        floor,
        binding,
        claim,
        true,
    )
    .await
}

// ── the stream plane's records ──────────────────────────────────────────

/// An STH the plan admitted, its columns encoded.
#[derive(Debug, Clone)]
pub(crate) struct PlannedSth<'a> {
    /// The stream (`log_id` without its `stream:` prefix).
    pub(crate) stream_id: &'a str,
    /// `tree_size`, as stored.
    pub(crate) tree_size_i64: i64,
    /// The admitted head.
    pub(crate) sth: &'a ciris_verify_core::transparency::SignedTreeHead,
    /// Its producer.
    pub(crate) producer_key_id: &'a str,
    /// The producer signature, serialized.
    pub(crate) signature_blob: Vec<u8>,
    /// The witness cosignatures, JSON text.
    pub(crate) witness_json: String,
}

/// A delivery receipt the plan admitted, its columns encoded.
#[derive(Debug, Clone)]
pub(crate) struct PlannedReceipt<'a> {
    /// The admitted receipt.
    pub(crate) receipt: &'a super::stream_receipt::DeliveryReceipt,
    /// `k`, as stored.
    pub(crate) k_i64: i64,
    /// `epoch`, as stored.
    pub(crate) epoch_i64: i64,
    /// The subscriber signature, serialized.
    pub(crate) signature_blob: Vec<u8>,
    /// The door's receipt instant.
    pub(crate) received_at: chrono::DateTime<chrono::Utc>,
}

/// What the receipt write found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReceiptWrite {
    /// No STH this node published for the stream has the acknowledged root
    /// at `tree_size >= k`; nothing written.
    Unpublished,
    /// Stored.
    Inserted,
    /// A receipt was held under the key, with this root; nothing written.
    Held(Vec<u8>),
}

/// The door: every backend's `put_stream_sth`.
pub(crate) async fn put_stream_sth_planned<D: BlobFloorStore>(
    dir: &D,
    sth: ciris_verify_core::transparency::SignedTreeHead,
    producer_key_id: &str,
) -> Result<(), BlobError> {
    use super::stream_sth;
    // Step 1: the stream (`log_id` must be `stream:<id>`).
    let stream_id = stream_sth::parse_stream_id(&sth.log_id)?.to_string();
    // Steps 2–4: recompute the RFC 6962 root from persist's own chunks and
    // assert equality (the anti-equivocation gate; it also refuses an
    // over-claimed tree_size).
    let chunk_hashes = dir.read_stream_chunk_hashes(&stream_id).await?;
    // v62.0.0 (wave GC7; CC 2.7.3) — the root is recomputed over this node's
    // own chunks (other rows): a disagreement holds under a fold attempt
    // and re-folds when the stream's chunks change.
    stream_sth::recompute_and_assert_root(&sth, &chunk_hashes).map_err(|e| {
        held_on(
            super::edition2::fold::reason::STH_ROOT_DISAGREES,
            &stream_id,
            e,
        )
    })?;
    // Step 5: the producer's hybrid signature, and (v31.0.0, #657) every
    // witness cosignature, verified the same way.
    blobs::verify_stream_sth_signature(dir, &sth, producer_key_id).await?;
    blobs::verify_stream_sth_witnesses(dir, &sth).await?;
    let tree_size_i64 = i64::try_from(sth.tree_size)
        .map_err(|_| BlobError::InvalidArgument("put_stream_sth: tree_size exceeds i64".into()))?;
    let planned = PlannedSth {
        stream_id: &stream_id,
        tree_size_i64,
        sth: &sth,
        producer_key_id,
        signature_blob: stream_sth::serialize_signature(&sth.signature)?,
        witness_json: stream_sth::serialize_witness_signatures(&sth.witness_signatures)?,
    };
    // Step 6: a held (stream_id, tree_size) with a DIFFERENT root is an
    // equivocation; an identical one an idempotent re-put.
    match dir.store_stream_sth(planned).await? {
        // v62.0.0 (wave GC7) — first-seen-wins reads the held STH: a fold
        // condition (CC 2.7.7 rule 2 makes the slot both-or-neither).
        Some(held) if held != sth.root_hash.to_vec() => Err(held_on(
            super::edition2::fold::reason::STH_ROOT_DISAGREES,
            &stream_id,
            BlobError::InvalidArgument(format!(
                "put_stream_sth: equivocation — an STH at stream={stream_id} tree_size={} \
                 already exists with a different root",
                sth.tree_size
            )),
        )),
        _ => Ok(()),
    }
}

/// The door: every backend's `put_delivery_receipt`.
pub(crate) async fn put_delivery_receipt_planned<D: BlobFloorStore>(
    dir: &D,
    receipt: super::stream_receipt::DeliveryReceipt,
) -> Result<(), BlobError> {
    super::edition2::door::refuse_earlier_form("delivery_receipt")
        .map_err(|e| BlobError::InvalidArgument(e.to_string()))?;
    // v62.0.0 (F0-cp5) — the earlier receipt's bound-hybrid verify is
    // deleted, so this door admits nothing whatever the switch says: it
    // never stores a receipt it has not verified.
    let _ = (dir, receipt);
    Err(BlobError::InvalidArgument(
        "put_delivery_receipt: the earlier-form receipt (a bound-hybrid \
         signature) admits nothing; send a delivery_receipt:{stream_id} statement \
         (v62.0.0)"
            .into(),
    ))
}

/// v62.0.0 (wave T2) — **the receipt door for an edition-2
/// `delivery_receipt:{stream_id}` statement** (`edition2::typed`). The
/// edition-2 door verified the subscriber's composite statement (its step
/// 1); the JOIN and equivocation steps are this door's own
/// ([`store_receipt_checked`]), the same ones the earlier form meets.
pub(crate) async fn put_delivery_receipt_edition2_planned<D: BlobFloorStore>(
    dir: &D,
    receipt: super::stream_receipt::DeliveryReceipt,
) -> Result<(), BlobError> {
    store_receipt_checked(dir, receipt).await
}

/// The receipt door's steps after the signature: the JOIN against a
/// published STH and the equivocation check. Shared by both forms.
async fn store_receipt_checked<D: BlobFloorStore>(
    dir: &D,
    receipt: super::stream_receipt::DeliveryReceipt,
) -> Result<(), BlobError> {
    let k_i64 = i64::try_from(receipt.k)
        .map_err(|_| BlobError::InvalidArgument("put_delivery_receipt: k exceeds i64".into()))?;
    let epoch_i64 = i64::try_from(receipt.epoch).map_err(|_| {
        BlobError::InvalidArgument("put_delivery_receipt: epoch exceeds i64".into())
    })?;
    let planned = PlannedReceipt {
        receipt: &receipt,
        k_i64,
        epoch_i64,
        signature_blob: serde_json::to_vec(&receipt.signature).map_err(|e| {
            BlobError::Backend(format!("delivery receipt signature serialize: {e}"))
        })?,
        received_at: crate::host::clock::now(),
    };
    match dir.store_delivery_receipt(planned).await? {
        // Step 2: the JOIN gate. The signature proved WHO; a root this node
        // published at tree_size >= k proves the root is REAL.
        // v62.0.0 (wave GC7; CC 2.7.3) — the publication is another row: the
        // receipt WAITS for it (held, re-folded when the STH lands).
        ReceiptWrite::Unpublished => Err(held_on(
            super::edition2::fold::reason::RECEIPT_ROOT_UNPUBLISHED,
            &receipt.stream_id,
            BlobError::InvalidArgument(format!(
                "put_delivery_receipt: no published STH for stream={} matches the acknowledged \
                 chunk_root at tree_size >= {} (a subscriber cannot acknowledge an unpublished \
                 root)",
                receipt.stream_id, receipt.k
            )),
        )),
        // Step 3: a held receipt with a DIFFERENT root is a subscriber
        // equivocation; an identical one an idempotent re-put.
        ReceiptWrite::Held(root) if root != receipt.chunk_root.to_vec() => Err(held_on(
            super::edition2::fold::reason::RECEIPT_EQUIVOCATION,
            &receipt.stream_id,
            BlobError::InvalidArgument(format!(
                "put_delivery_receipt: subscriber equivocation — a receipt for stream={} \
                 subscriber={} k={} already exists with a different chunk_root",
                receipt.stream_id, receipt.subscriber_key_id, receipt.k
            )),
        )),
        ReceiptWrite::Held(_) | ReceiptWrite::Inserted => Ok(()),
    }
}

/// The door: every backend's `stream_dek_insert`. v55.0.0 — the chunk
/// floor's stream-name rule (#953): no stream row under a name reserved for
/// an inline blob's log.
pub(crate) async fn stream_dek_insert_planned<D: BlobFloorStore>(
    dir: &D,
    record: &StreamDekRecord,
) -> Result<StreamDekRecord, BlobError> {
    super::stream_sth::refuse_reserved_stream_id(&record.stream_id)?;
    let epoch_i64 = i64::try_from(record.epoch)
        .map_err(|_| BlobError::InvalidArgument("stream epoch exceeds i64".into()))?;
    dir.store_stream_dek(record, epoch_i64).await
}

/// The door: every backend's `stream_dek_put_grants` (the same name rule).
pub(crate) async fn stream_dek_put_grants_planned<D: BlobFloorStore>(
    dir: &D,
    stream_id: &str,
    epoch: u64,
    sealer_key_id: &str,
    cohort_scope: &str,
    wraps: &[super::GrantWrap],
) -> Result<usize, BlobError> {
    super::stream_sth::refuse_reserved_stream_id(stream_id)?;
    dir.store_stream_dek_grants(stream_id, epoch, sealer_key_id, cohort_scope, wraps)
        .await
}

// ── the blob writes ─────────────────────────────────────────────────────

/// The blob writes' executor (the bytes doors). Storage only.
#[async_trait::async_trait]
pub(crate) trait BlobWriteStore: BlobFloorStore {
    /// The blob-admission gate the host installed, if any.
    fn blob_admission_gate(&self) -> Option<super::AdmissionGate>;

    /// In ONE transaction: re-ask the tombstone (#1070), insert the row
    /// (first write wins on the address), the plaintext room association
    /// when [`PlannedBlob::associate`], the binding AS DECLARED when there is
    /// one, and the holding claim when there is one; after the commit, index
    /// the claim.
    async fn store_planned_blob(&self, planned: PlannedBlob) -> Result<(), BlobError>;

    /// v62.0.0 (wave T2) — delete the blob row (as `BlobStorage::delete_blob`)
    /// UNLESS a `custody:ack:v1` `here` row cites it, judged in the same
    /// transaction as the delete. `false`: kept (claimed, or absent).
    async fn delete_blob_unless_claimed(&self, sha256: &[u8; 32]) -> Result<bool, BlobError>;

    /// §11.5 / I28 — an announcement never stores. In ONE transaction:
    /// re-ask that the row is held (and bound, for a community-DEK token),
    /// name the announcer as the author of a row the cascade could not
    /// attribute, insert the holding claim; after the commit, index it.
    /// `false`: not held, nothing written.
    async fn store_planned_announcement(
        &self,
        planned: PlannedAnnouncement,
    ) -> Result<bool, BlobError>;

    /// In ONE transaction: re-ask the tombstone of every prepared row, insert
    /// them (chunks first, the manifest last) and the manifest's chunk
    /// relation.
    async fn store_planned_dag(&self, planned: PlannedDag) -> Result<(), BlobError>;

    /// In ONE transaction: ask [`held_dag_chunk_verdict`] of every chunk the
    /// manifest names as stored, re-ask the manifest's and every chunk's
    /// tombstone, then insert the manifest row and its chunk relation.
    async fn store_planned_dag_over_held(&self, planned: PlannedDag) -> Result<(), BlobError>;

    /// In ONE transaction: refuse an abandoned stream, refuse a stream that
    /// moved under the seal, insert the root (and its binding, current and
    /// enabled), the v3 children, the chunk relation; stamp the stream
    /// sealed.
    async fn store_planned_seal(&self, planned: PlannedSeal) -> Result<SealWrite, BlobError>;
}

/// One `federation_blobs` row a write door admitted.
#[derive(Debug, Clone)]
pub(crate) struct PlannedBlobRow {
    /// The address.
    pub(crate) sha256: [u8; 32],
    /// `storage_kind`.
    pub(crate) storage_kind: String,
    /// `bytes_inline`.
    pub(crate) bytes_inline: Option<Vec<u8>>,
    /// `external_ref`.
    pub(crate) external_ref: Option<String>,
    /// `size_bytes`.
    pub(crate) size_bytes: i64,
    /// `media_type`.
    pub(crate) media_type: Option<String>,
    /// `cohort_scope`.
    pub(crate) cohort_scope: String,
    /// `crypto_tier`.
    pub(crate) tier: String,
    /// `author_key_id`.
    pub(crate) author_key_id: Option<String>,
    /// `group_key_id` (V177).
    pub(crate) group_key_id: Option<String>,
}

/// A blob write the plan admitted (`put_blob_with_scope` at the plaintext
/// tier, `store_blob_local`, `adopt_sealed_blob_at`).
#[derive(Debug, Clone)]
pub(crate) struct PlannedBlob {
    /// The row.
    pub(crate) row: PlannedBlobRow,
    /// v54.0.0 (#995 row 4, V184) — record THIS write's room (a plaintext
    /// row keeps every room); the adopt floor records none.
    pub(crate) associate: bool,
    /// The binding AS DECLARED (#846 §3, the adopt floor's): the epoch the
    /// author sealed under, with no key-state check.
    pub(crate) binding: Option<EpochBinding>,
    /// The in-transaction tombstone look's inputs.
    pub(crate) tombstones: TombstoneFloor,
    /// The door, for an error's text.
    pub(crate) door: &'static str,
}

/// A sealed-tier holding announcement the plan admitted.
#[derive(Debug, Clone)]
pub(crate) struct PlannedAnnouncement {
    /// The announced address.
    pub(crate) sha256: [u8; 32],
    /// The announcer, named as the author of a row the cascade could not
    /// attribute.
    pub(crate) author_key_id: String,
    /// A community-DEK token: the row must also be bound (an evicted binding
    /// is an eviction RECORD, not a bound row).
    pub(crate) needs_binding: bool,
}

/// A chunk DAG the plan admitted: its prepared rows (chunks first, the
/// manifest last) and the manifest's chunk relation.
#[derive(Debug)]
pub(crate) struct PlannedDag {
    /// The rows to insert (for a finalize over held chunks, the manifest's
    /// alone).
    pub(crate) rows: Vec<blobs::PreparedBlobRow>,
    /// The chunks the manifest names, `(sha, size)`, that must already be
    /// held (a finalize over held chunks; empty otherwise).
    pub(crate) held_chunks: Vec<([u8; 32], u64)>,
    /// `(seq, chunk sha)` for `federation_dag_chunks`.
    pub(crate) links: Vec<(i64, Vec<u8>)>,
    /// The relation's `stream_id`.
    pub(crate) link_stream: String,
    /// The in-transaction tombstone look's inputs.
    pub(crate) tombstones: TombstoneFloor,
}

impl PlannedDag {
    /// The manifest row's address (the last prepared row).
    #[must_use]
    pub(crate) fn manifest_sha(&self) -> Option<[u8; 32]> {
        self.rows.last().map(|r| r.sha256)
    }
}

/// A stream seal the plan admitted.
#[derive(Debug, Clone)]
pub(crate) struct PlannedSeal {
    /// The stream.
    pub(crate) stream_id: String,
    /// The root manifest row.
    pub(crate) spec: blobs::ManifestRowSpec,
    /// Its `size_bytes`.
    pub(crate) size_bytes: i64,
    /// The chunk count the manifest was built over.
    pub(crate) expected_chunks: i64,
    /// `media_type`.
    pub(crate) media_type: Option<String>,
    /// `cohort_scope`.
    pub(crate) cohort_scope: String,
    /// `crypto_tier`.
    pub(crate) tier: String,
    /// The binding (current and enabled, the minter's own state).
    pub(crate) binding: Option<EpochBinding>,
}

/// What the seal's transaction found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealWrite {
    /// Sealed.
    Sealed,
    /// #954 — the stream was abandoned.
    Abandoned,
    /// §12.3 — the stream holds this many chunks, not the manifest's.
    StreamMoved(i64),
    /// The binding's epoch is no longer the minter's current enabled one.
    EpochMoved,
}

/// v55.0.0 (#1007) / v60.1.0 (#1070) — a byte write's tombstone pre-read
/// (every address it stores), the floor its transaction re-asks with, and
/// the witnesses' seam between the two.
async fn tombstone_floor<D: BlobFloorStore>(
    dir: &D,
    shas: &[[u8; 32]],
) -> Result<TombstoneFloor, BlobError> {
    let mut reversed = ReversedTakedowns::default();
    for sha in shas {
        // v62.0.0 (wave GC7; CC 2.7.3) — the tombstone / reversal / manifest
        // rows are other rows: a purged address holds under a fold attempt
        // (re-folded when a reversal lands).
        reversed.absorb(
            steward_purge::refuse_tombstoned_bytes(dir, sha)
                .await
                .map_err(|e| match e {
                    e @ BlobError::Purged { .. } => held_on(
                        super::edition2::fold::reason::BLOB_PURGED,
                        &hex::encode(sha),
                        e,
                    ),
                    e => e,
                })?,
        );
    }
    let floor = TombstoneFloor::new(dir.tombstone_plane_present(), reversed);
    #[cfg(test)]
    dir.pause_after_tombstone_precheck().await;
    Ok(floor)
}

/// A single-row body's stored columns: `(storage_kind, bytes_inline,
/// external_ref, size_bytes)`.
type BodyColumns = (String, Option<Vec<u8>>, Option<String>, i64);

/// A single-row body's checks: inline within the cap and hashing to its
/// address; a ChunkDag body is refused (it only goes through
/// `put_blob_chunks`, which writes its rows together).
fn plan_blob_body(
    door: &'static str,
    sha256: &[u8; 32],
    body: &super::BlobBody,
    cap: usize,
) -> Result<BodyColumns, BlobError> {
    let (inline, external) = match body {
        super::BlobBody::Inline(bytes) => {
            if bytes.len() > cap {
                return Err(BlobError::InlineSizeExceeded {
                    size: bytes.len(),
                    cap,
                });
            }
            blobs::verify_inline_hash(sha256, bytes)?;
            (Some(bytes.clone()), None)
        }
        super::BlobBody::External(e) => (None, Some(e.uri.clone())),
        super::BlobBody::ChunkDag(_) => {
            return Err(BlobError::InvalidArgument(format!(
                "{door} does not accept a ChunkDag body — use put_blob_chunks"
            )))
        }
    };
    let size = i64::try_from(body.size_bytes())
        .map_err(|_| BlobError::InvalidArgument("size_bytes exceeds i64".into()))?;
    Ok((body.storage_kind().to_owned(), inline, external, size))
}

/// AV-89 (v45.0.0, #871) — the claim's declared size is the length of the
/// bytes this door stores.
fn check_claim_size(declared: u64, stored: u64, what: &str) -> Result<(), BlobError> {
    if declared == stored {
        Ok(())
    } else {
        Err(BlobError::InvalidArgument(format!(
            "holding claim declares size {declared} but the {what} bytes are {stored} \
             (CC 5.3.2.5 / AV-89: a holder announces exactly what it holds)"
        )))
    }
}

/// v62.0.0 (wave T2; T2-fix11, CC 6.1.3) — **the blob put doors, with an
/// edition-2 holding claim**: `put_blob` (the commons form: `federation`,
/// plaintext) and `put_blob_with_scope` (any scope and floor). `claim` is the
/// holder's `custody:{kind}` `here` statement: ONE composite signature (a
/// holding claim is a CC 6.1 object), admitted through the one statement
/// door. The earlier form (`PutBlobAttestation`, a bound-hybrid scrub pair
/// over a JCS row) is deleted (ruling 4).
///
/// The pure checks run first, before anything is written:
/// - the claim names THIS blob, at THIS scope (and group, for a targeted
///   scope) and THIS size (AV-89);
/// - the floor's scope rule, the tombstone, the hash-on-write and size cap;
/// - the admission gate on the holder;
/// - the holder is in the claim's cohort (CC 3.1.3.3 rule 2).
///
/// Plaintext: the bytes are stored, then the claim goes through the
/// statement door; a claim refused after the bytes landed reaps the bytes
/// THIS call stored (`delete_blob_unless_claimed`), so a refused claim
/// leaves no bytes; bytes held before the call stay; an admitted claim finds
/// its bytes held (it re-stores them after a concurrent reap).
///
/// A sealed floor is an ANNOUNCEMENT (§11.5 / I28: it never stores): the row
/// a cascade stored is read for the content's scope (absent: `NotHeld`,
/// waiting), the announce step records the author and asks the binding
/// (`announce_held_blob_planned`'s executor), then the claim goes through the
/// statement door. Never a claim without bytes.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn put_blob_planned<D: BlobWriteStore>(
    dir: &D,
    author_key_id: Option<&str>,
    sha256: &[u8; 32],
    body: super::BlobBody,
    media_type: Option<&str>,
    claim: &[u8],
    cohort_scope: &str,
    floor: StorageFloor,
    group_key_id: Option<&str>,
) -> Result<(), BlobError> {
    use super::types::cohort_scope::CryptoTier;
    let read = super::edition2::typed::holding_claim_of(claim)
        .map_err(|e| BlobError::InvalidArgument(e.to_string()))?;
    if read.sha256 != *sha256 {
        return Err(BlobError::InvalidArgument(format!(
            "put_blob: the holding claim names blob {}, not {}",
            hex::encode(read.sha256),
            hex::encode(sha256)
        )));
    }
    floor.check_scope(cohort_scope)?;
    let tombstones = tombstone_floor(dir, &[*sha256]).await?;
    if let Some(gate) = dir.blob_admission_gate() {
        gate.check_blob(&read.holder).await?;
    }
    let (storage_kind, bytes_inline, external_ref, size_bytes) =
        plan_blob_body("put_blob", sha256, &body, dir.inline_bytes_cap())?;
    check_claim_size(read.size, body.size_bytes(), "stored")?;
    // v55.0.0 (#989, CC 3.1.3.3 rule 1) — the claim is placed at the content's
    // scope: this write's for plaintext; for a sealed floor, read off the row
    // a cascade already stored, and an absent row is NotHeld (§11.5 / I28).
    let plaintext = floor.tier() == CryptoTier::Plaintext;
    let want = if plaintext {
        super::holding_claim::ClaimScope::of_content(floor.tier(), cohort_scope, group_key_id)?
    } else {
        super::holding_claim::content_claim_scope(dir, sha256)
            .await?
            .ok_or_else(|| {
                held_on(
                    super::edition2::fold::reason::BLOB_NOT_HELD,
                    &hex::encode(sha256),
                    BlobError::NotHeld {
                        sha256_hex: hex::encode(sha256),
                    },
                )
            })?
    };
    let agrees = read.cohort_scope == want.cohort_scope()
        && (want.cohort_scope() == super::types::cohort_scope::SELF
            || read.target.as_deref() == want.target());
    if !agrees {
        return Err(BlobError::InvalidArgument(format!(
            "{}: the holding claim about {} is placed at {} {:?}, but the content is at {} {:?} \
             (CC 3.1.3.3 rule 1: a claim is placed at its content's scope)",
            super::holding_claim::CUSTODY_ACK_SCOPE_MISMATCH,
            hex::encode(sha256),
            read.cohort_scope,
            read.target,
            want.cohort_scope(),
            want.target()
        )));
    }
    // CC 3.1.3.3 rule 2 — the holder is in the claim's cohort (the audience
    // half of the custody gate), asked before anything is written.
    if !want.is_directory()
        && !super::custody_ack::holder_in_cohort(
            dir,
            &read.holder,
            want.cohort_scope(),
            want.target(),
        )
        .await
        .map_err(|e| BlobError::Backend(format!("holding claim audience: {e}")))?
    {
        return Err(BlobError::InvalidArgument(format!(
            "custody_ack_outside_cohort: the holder {} is not in the {} cohort {:?} of the \
             claim it states (CC 3.1.3.3 rule 2)",
            read.holder,
            want.cohort_scope(),
            want.target()
        )));
    }
    // §20.5 (PR #852 review) — the ROW's author is the supplied one (a proxy
    // write's peer); absent that, the claim's holder.
    let author = author_key_id
        .map(str::to_owned)
        .unwrap_or_else(|| read.holder.clone());
    let refused = |e: super::Error| match e {
        super::Error::Backend(m) => BlobError::Backend(m),
        other => BlobError::InvalidArgument(other.to_string()),
    };
    if !plaintext {
        let held = dir
            .store_planned_announcement(PlannedAnnouncement {
                sha256: *sha256,
                author_key_id: author,
                needs_binding: floor.tier() == CryptoTier::CommunityDek,
            })
            .await?;
        if !held {
            return Err(held_on(
                super::edition2::fold::reason::BLOB_NOT_HELD,
                &hex::encode(sha256),
                BlobError::NotHeld {
                    sha256_hex: hex::encode(sha256),
                },
            ));
        }
        super::edition2::ingest::put_statement(
            dir,
            claim,
            None,
            super::edition2::ingest::INGEST_TIER,
        )
        .await
        .map_err(refused)?;
        return Ok(());
    }
    // Held before this call? Then a refused claim leaves the held row as it
    // was; otherwise the bytes this call stored are reaped (below).
    let held_before = dir.blob_head(sha256).await?.is_some();
    let planned = PlannedBlob {
        row: PlannedBlobRow {
            sha256: *sha256,
            storage_kind,
            bytes_inline,
            external_ref,
            size_bytes,
            media_type: media_type.map(str::to_owned),
            cohort_scope: cohort_scope.to_owned(),
            tier: floor.tier().as_str().to_owned(),
            author_key_id: Some(author),
            group_key_id: group_key_id.map(str::to_owned),
        },
        associate: true,
        binding: None,
        tombstones,
        door: "put_blob",
    };
    dir.store_planned_blob(planned.clone()).await?;
    let admitted = super::edition2::ingest::put_statement(
        dir,
        claim,
        None,
        super::edition2::ingest::INGEST_TIER,
    )
    .await;
    if let Err(e) = admitted {
        // The claim was refused: no holding stands for these bytes. Bytes
        // this call stored are reaped here, in the same call (no sweep reaps
        // unclaimed local bytes); bytes held before it are left as they were.
        if !held_before {
            // Conditional: a concurrent writer whose claim landed first keeps
            // the bytes (the guard and the delete are one transaction).
            dir.delete_blob_unless_claimed(sha256).await?;
        }
        return Err(refused(e));
    }
    // The other side of the race: a concurrent refused writer's reap may
    // have run between this call's store and its claim. The claim stands, so
    // its bytes are put back (first write wins; idempotent when held).
    if dir.blob_head(sha256).await?.is_none() {
        dir.store_planned_blob(planned).await?;
    }
    // v62.0.0 (T2-fix7) — the bytes landed: the bytes plane's touch, so a
    // row that waited on this node's holding of them (an own `here` claim
    // held `blob_not_held`, a claim at the wrong scope) re-folds now.
    super::holding_claim::refold_on_blob(dir, sha256)
        .await
        .map_err(|e| BlobError::Backend(format!("put_blob re-fold: {e}")))?;
    Ok(())
}

/// v62.0.0 (E8-fix2) — an announce is of SEALED content a cascade already
/// stored: a plaintext floor stores its bytes and claims them in one write
/// (`store_blob_local` + the claim), never through the announce.
///
/// # Errors
/// [`BlobError::InvalidArgument`] for a plaintext floor.
fn refuse_plaintext_announce(floor: StorageFloor) -> Result<(), BlobError> {
    if floor.tier() == super::types::cohort_scope::CryptoTier::Plaintext {
        return Err(BlobError::InvalidArgument(
            "announce_held_blob: a plaintext floor stores its bytes; only sealed content a \
             cascade already stored is announced (§11.5 / I28)"
                .into(),
        ));
    }
    Ok(())
}

/// v62.0.0 (E8-fix2; the I27 / I28 regression of d5b39133, cut B) — **the
/// sealed-floor announce, edition 2**: every backend's
/// `BlobStorage::announce_held_blob`. §11.5 / I28: an announcement never
/// stores; I27: a community-DEK announce takes the community's
/// serialization boundary. In ONE transaction (the backend's
/// [`BlobWriteStore::store_planned_announcement`], no claim row): re-ask that
/// the row is held, and for a community-DEK floor that it is bound (an
/// evicted binding is an eviction record, #833), under the bound community's
/// lock on postgres (sqlite: the connection mutex, §11.4); name the
/// announcer as the author of a row the cascade could not attribute. The
/// claim itself is the caller's edition-2 `custody` statement, emitted after
/// this commits (`holding_claim::emit_holding_claim`).
///
/// # Errors
/// `NotHeld` (a hold on the row, CC 2.7.3: the cascade's row is another
/// row) when the row is not held, or a community-DEK row is not bound;
/// storage faults.
pub(crate) async fn announce_held_blob_planned<D: BlobWriteStore>(
    dir: &D,
    sha256: &[u8; 32],
    author_key_id: &str,
    floor: StorageFloor,
) -> Result<(), BlobError> {
    use super::types::cohort_scope::CryptoTier;
    refuse_plaintext_announce(floor)?;
    let held = dir
        .store_planned_announcement(PlannedAnnouncement {
            sha256: *sha256,
            author_key_id: author_key_id.to_owned(),
            needs_binding: floor.tier() == CryptoTier::CommunityDek,
        })
        .await?;
    if held {
        Ok(())
    } else {
        Err(held_on(
            super::edition2::fold::reason::BLOB_NOT_HELD,
            &hex::encode(sha256),
            BlobError::NotHeld {
                sha256_hex: hex::encode(sha256),
            },
        ))
    }
}

/// The door: every backend's `store_blob_local`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn store_blob_local_planned<D: BlobWriteStore>(
    dir: &D,
    sha256: &[u8; 32],
    body: super::BlobBody,
    media_type: Option<&str>,
    cohort_scope: &str,
    floor: StorageFloor,
    author_key_id: Option<&str>,
    group_key_id: Option<&str>,
) -> Result<(), BlobError> {
    floor.check_scope(cohort_scope)?;
    let tombstones = tombstone_floor(dir, &[*sha256]).await?;
    let (storage_kind, bytes_inline, external_ref, size_bytes) =
        plan_blob_body("store_blob_local", sha256, &body, dir.inline_bytes_cap())?;
    let tier = floor.tier();
    dir.store_planned_blob(PlannedBlob {
        row: PlannedBlobRow {
            sha256: *sha256,
            storage_kind,
            bytes_inline,
            external_ref,
            size_bytes,
            media_type: media_type.map(str::to_owned),
            cohort_scope: cohort_scope.to_owned(),
            tier: tier.as_str().to_owned(),
            author_key_id: author_key_id.map(str::to_owned),
            group_key_id: group_key_id.map(str::to_owned),
        },
        associate: tier == super::types::cohort_scope::CryptoTier::Plaintext,
        binding: None,
        tombstones,
        door: "store_blob_local",
    })
    .await
}

/// The door: every backend's `adopt_sealed_blob_at` (#846 §6.1). The
/// address is the SHA-256 of the CIPHERTEXT, computed here from the bytes
/// stored, never trusted from the sender; the row, the binding and the
/// author are recorded AS DECLARED.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn adopt_sealed_blob_planned<D: BlobWriteStore>(
    dir: &D,
    envelope_bytes: Vec<u8>,
    media_type: Option<&str>,
    cohort_scope: &str,
    author_key_id: &str,
    floor: StorageFloor,
    binding: Option<EpochBinding>,
    group_key_id: Option<&str>,
) -> Result<[u8; 32], BlobError> {
    use sha2::Digest as _;
    // v62.0.0 (T2-fix10/fix11; CC 6.1.3) — the adopt floor stores bytes
    // only: the holding claim is the composite edition-2 statement
    // `holding_claim::emit_holding_claim` states after the bytes are held.
    floor.check_scope(cohort_scope)?;
    let cap = dir.inline_bytes_cap();
    if envelope_bytes.len() > cap {
        return Err(BlobError::InlineSizeExceeded {
            size: envelope_bytes.len(),
            cap,
        });
    }
    let sha256: [u8; 32] = sha2::Sha256::digest(&envelope_bytes).into();
    let tombstones = tombstone_floor(dir, &[sha256]).await?;
    let size_bytes = i64::try_from(envelope_bytes.len()).map_err(|_| {
        BlobError::InvalidArgument("adopt_sealed_blob_at: size_bytes exceeds i64".into())
    })?;
    // v55.0.0 (#989, CC 3.1.3.3 rule 1) — the group a sealed room row names
    // is its binding's community: a group that disagrees is refused.
    if let (Some(b), Some(g)) = (&binding, group_key_id) {
        if b.community_key_id != g {
            return Err(BlobError::InvalidArgument(format!(
                "adopt_sealed_blob_at: group {g:?} is not the binding's community {:?}",
                b.community_key_id
            )));
        }
    }
    let group = group_key_id
        .map(str::to_owned)
        .or_else(|| binding.as_ref().map(|b| b.community_key_id.clone()));
    dir.store_planned_blob(PlannedBlob {
        row: PlannedBlobRow {
            sha256,
            storage_kind: "inline".to_owned(),
            bytes_inline: Some(envelope_bytes),
            external_ref: None,
            size_bytes,
            media_type: media_type.map(str::to_owned),
            cohort_scope: cohort_scope.to_owned(),
            tier: floor.tier().as_str().to_owned(),
            author_key_id: Some(author_key_id.to_owned()),
            group_key_id: group,
        },
        associate: false,
        binding,
        tombstones,
        door: "adopt_sealed_blob_at",
    })
    .await?;
    Ok(sha256)
}

/// The door: every backend's `put_blob_chunks`. Validation and row
/// preparation (chunks first, the manifest last); no chunk and not the
/// manifest when taken down.
pub(crate) async fn put_blob_chunks_planned<D: BlobWriteStore>(
    dir: &D,
    manifest: super::ChunkManifest,
    chunks: Vec<([u8; 32], super::BlobBody)>,
) -> Result<(), BlobError> {
    let rows = blobs::prepare_chunk_rows(&manifest, &chunks, dir.inline_bytes_cap())?;
    let shas: Vec<[u8; 32]> = rows.iter().map(|r| r.sha256).collect();
    let tombstones = tombstone_floor(dir, &shas).await?;
    // Codex r2 on #1065 — the manifest's chunk relation, in the same
    // transaction.
    let (links, link_stream) = blobs::manifest_chunk_links(&manifest);
    dir.store_planned_dag(PlannedDag {
        rows,
        held_chunks: Vec::new(),
        links,
        link_stream,
        tombstones,
    })
    .await
}

/// The door: every backend's `put_dag_manifest_over_held` (v55.0.0, #952):
/// the incremental plaintext DAG's finalize. Every chunk the manifest names
/// is read in the transaction that writes the manifest row, so the row lands
/// only over a whole DAG.
pub(crate) async fn put_dag_manifest_over_held_planned<D: BlobWriteStore>(
    dir: &D,
    manifest: super::ChunkManifest,
) -> Result<[u8; 32], BlobError> {
    let row = blobs::prepare_manifest_row(&manifest, dir.inline_bytes_cap())?;
    let sha = row.sha256;
    // Neither the manifest nor a withheld chunk becomes a DAG.
    let shas: Vec<[u8; 32]> = std::iter::once(row.sha256)
        .chain(manifest.chunks.iter().map(|c| c.sha))
        .collect();
    let tombstones = tombstone_floor(dir, &shas).await?;
    let held_chunks = manifest
        .chunks
        .iter()
        .map(|c| (c.sha, u64::from(c.size)))
        .collect();
    let (links, link_stream) = blobs::manifest_chunk_links(&manifest);
    dir.store_planned_dag_over_held(PlannedDag {
        rows: vec![row],
        held_chunks,
        links,
        link_stream,
        tombstones,
    })
    .await?;
    Ok(sha)
}

/// **The finalize's held-chunk verdict**, asked by the executor inside its
/// transaction for each chunk the manifest names, as stored.
pub(crate) fn held_dag_chunk_verdict(
    idx: usize,
    chunk_sha: &[u8; 32],
    size: u64,
    held: Option<(String, String, i64)>,
) -> Result<(), BlobError> {
    blobs::check_held_dag_chunk(idx, chunk_sha, size, held)?;
    Ok(())
}

/// The door: every backend's `seal_stream_with_scope`. The root and every v3
/// child within the cap and hashing to its address, before the transaction.
pub(crate) async fn seal_stream_planned<D: BlobWriteStore>(
    dir: &D,
    stream_id: &str,
    spec: blobs::ManifestRowSpec,
    media_type: Option<&str>,
    cohort_scope: &str,
    floor: StorageFloor,
    binding: Option<EpochBinding>,
) -> Result<(), BlobError> {
    floor.check_scope(cohort_scope)?;
    let cap = dir.inline_bytes_cap();
    let fits = |sha: &[u8; 32], body: &[u8]| -> Result<(), BlobError> {
        if body.len() > cap {
            return Err(BlobError::InlineSizeExceeded {
                size: body.len(),
                cap,
            });
        }
        blobs::verify_inline_hash(sha, body)
    };
    fits(&spec.sha256, &spec.body)?;
    let size_bytes = i64::try_from(spec.size_bytes).map_err(|_| {
        BlobError::InvalidArgument("seal_stream_with_scope: size_bytes exceeds i64".into())
    })?;
    for c in &spec.children {
        fits(&c.sha256, &c.body)?;
    }
    let expected_chunks = i64::try_from(spec.expected_chunk_count).unwrap_or(i64::MAX);
    let expected_count = spec.expected_chunk_count;
    let written = dir
        .store_planned_seal(PlannedSeal {
            stream_id: stream_id.to_owned(),
            spec,
            size_bytes,
            expected_chunks,
            media_type: media_type.map(str::to_owned),
            cohort_scope: cohort_scope.to_owned(),
            tier: floor.tier().as_str().to_owned(),
            binding: binding.clone(),
        })
        .await?;
    // v62.0.0 (T2-fix8; lead's GC7 ruling) — this node's OWN seal of its
    // own stream (LOCAL: the producer re-seals). Every arm is a refusal, not
    // a fold hold: the seal runs outside any fold attempt, and no blocker
    // here is released by another row's arrival.
    match written {
        SealWrite::Sealed => Ok(()),
        SealWrite::Abandoned => Err(blobs::stream_abandoned_refusal(stream_id)),
        // §12.3 — the manifest describes a stream that no longer exists:
        // refused, never truncated.
        SealWrite::StreamMoved(count) => Err(BlobError::InvalidArgument(format!(
            "seal_stream_with_scope: stream {stream_id} has {count} chunk(s) but the manifest \
             was built over {expected_count}; the stream moved under the seal — list it again \
             (BLOB_ENCRYPTION_AT_REST.md §12.3)"
        ))),
        SealWrite::EpochMoved => {
            let b = binding.expect("EpochMoved only arises with a binding");
            Err(BlobError::EpochNotCurrent {
                community_key_id: b.community_key_id.clone(),
                epoch: b.epoch,
            })
        }
    }
}

/// **I3916** (wave GC7; T2-fix8 per the lead's GC7 ruling): the chunk
/// savepoint's slot answers (a held seq, a moved epoch / counter, a closed
/// epoch) are terminal REFUSALS that mark nothing, even inside a fold
/// attempt (no held chunk store; no blocker clears); the tombstone answer
/// keeps its `blob_purged` mark; the epoch CAP (a resource limit) marks
/// nothing; outside an attempt every one is the refusal it was.
#[cfg(test)]
mod gc7_fold_marks {
    use super::*;
    use crate::federation::edition2::fold::{self, reason, Dep};
    use crate::federation::edition2::names::RowId;

    async fn marked(got: ItemAppended) -> Option<String> {
        let (out, att) = fold::attempt(RowId([0x79; 32]), None, async {
            item_answer("s1", 0, None, &StreamClaim::default(), (3, [7; 32]), got)
        })
        .await;
        assert!(out.is_err(), "I3916: still an Err inside the attempt");
        if att.held.is_some() {
            assert!(
                att.reads.contains(&Dep::key("s1").read_key())
                    || att
                        .reads
                        .contains(&Dep::key(&hex::encode([7u8; 32])).read_key()),
                "I3916: the slot's input is declared: {:?}",
                att.reads
            );
        }
        att.held.map(|(r, _)| r)
    }

    #[tokio::test]
    async fn i3916_chunk_slot_answers_hold_and_the_cap_refuses() {
        for got in [
            ItemAppended::SeqConflict,
            ItemAppended::StreamCounterMoved,
            ItemAppended::StreamEpochClosed,
        ] {
            assert_eq!(
                marked(got).await,
                None,
                "I3916: a slot conflict is a terminal refusal, never a hold (GC7 ruling)"
            );
        }
        assert_eq!(
            marked(ItemAppended::Purged("n1".into())).await.as_deref(),
            Some(reason::BLOB_PURGED)
        );
        assert_eq!(
            marked(ItemAppended::CapReached).await,
            None,
            "I3916: the epoch cap is a resource limit: refused, not held"
        );
        // Outside an attempt: the same refusal, nothing marked.
        assert!(!fold::in_attempt());
        assert!(item_answer(
            "s1",
            0,
            None,
            &StreamClaim::default(),
            (3, [7; 32]),
            ItemAppended::SeqConflict
        )
        .is_err());
    }
}
