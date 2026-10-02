//! v51.1.0 (CIRISPersist#942) — **the custody view**: for one blob, who can open
//! it and how many copies are known — the recovery question ("is this the only
//! copy of the baby photos?") a Server can render per file.
//!
//! Authorized exactly as the bytes read ([`read_any_for_viewer`]): the row's
//! recorded tier, then the withdrawn check. A viewer who may not open the bytes
//! learns nothing — not even the access list.
//!
//! **What is knowable, and the one thing that is not.** Access is exact: the
//! at-rest grant recipients (`self`/`family`) or the member grants on the epoch
//! the blob was sealed under (`community`), each device resolved to its person
//! by persist's own principal fold. Copies are exact for `community` and the
//! commons (announced holders). For `self`/`family` they are NOT countable:
//! those bytes are never announced (CC 5.2 structural invisibility; I52), so
//! the view reports `copies_observable: false` with the reason rather than a
//! false "1 copy". Within-cohort custody acknowledgements (v52,
//! CIRISConstitution#130) close that.
//!
//! v53.0.0 (CIRISPersist#942 part 2, CC 3.1.3.3) — they have landed. Every
//! tier's view now carries `device_custody`, each device's own
//! [`custody:ack:v1`](super::custody_ack) report folded at the reader's clock,
//! and the copies a node can count are this node's copy, the announced
//! holders, and every device whose verdict is `here`. A `self`/`family` view
//! is now observable: a device with no live report is `unknown`, which is
//! never a copy and never `none`.
//!
//! [`read_any_for_viewer`]: crate::federation::at_rest_cascade::orchestrate::read_any_for_viewer

use crate::federation::types::cohort_scope::CryptoTier;
use crate::federation::{BlobError, BlobStorage, FederationDirectory};
use serde::{Deserialize, Serialize};

/// One person who can open the blob, and the devices through which they can.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyAccess {
    /// The person (the principal persist's fold resolves each device to).
    pub person_key_id: String,
    /// The devices (grant recipients) that hold a key to the blob, sorted.
    pub devices: Vec<String>,
    /// `at_rest_grant` (self/family) or `community_epoch_grant` (community).
    pub via: String,
}

/// A node that has announced holding the bytes (community / commons).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyHolder {
    /// The announcing node.
    pub node_key_id: String,
    /// The byte length its claim carries.
    pub size_bytes: u64,
}

/// The custody view of one blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobCustody {
    /// Lowercase hex of the at-rest sha256.
    pub sha256_hex: String,
    /// `plaintext` | `invisible_encrypted` | `community_dek`.
    pub tier: String,
    /// The cohort the write named.
    pub cohort_scope: String,
    /// The stored length.
    pub size_bytes: u64,
    /// This node stores the bytes.
    pub held_here: bool,
    /// Who can open it, per person (sorted by person).
    pub access: Vec<CustodyAccess>,
    /// Announced holders (community / commons), sorted by node.
    pub announced_holders: Vec<CustodyHolder>,
    /// Copies this node can count: this node's copy, the distinct announced
    /// holders, and (v53.0.0) every device whose custody verdict is `here`,
    /// each node once.
    pub copies_known: u32,
    /// False when copies elsewhere were unknowable by design (`self`/`family`
    /// before v53.0.0). Always true since custody reports (CC 3.1.3.3): a
    /// device with no live report is `unknown` in `device_custody`, never a
    /// copy. Kept on the wire so a reader that branched on it still reads.
    pub copies_observable: bool,
    /// Why the view is partial, when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// v53.0.0 (CIRISPersist#942 part 2, CC 3.1.3.3) — each device's custody
    /// report, folded at the reader's clock (sorted by device). Delivery
    /// receipts are not consulted here; [`custody_view`](super::custody_ack::custody_view)
    /// takes the stream that names them.
    #[serde(default)]
    pub device_custody: Vec<super::custody_ack::DeviceCustody>,
}

fn tier_token(t: CryptoTier) -> &'static str {
    match t {
        CryptoTier::Plaintext => "plaintext",
        CryptoTier::InvisibleEncrypted => "invisible_encrypted",
        CryptoTier::CommunityDek => "community_dek",
    }
}

/// Group device key ids by the person each resolves to. A device whose fold
/// errors (an ambiguous owner) is listed as its own principal — the view never
/// hides a device that holds a key.
async fn group_by_person<B>(
    backend: &B,
    devices: Vec<String>,
    via: &str,
) -> Result<Vec<CustodyAccess>, BlobError>
where
    B: FederationDirectory + Sync + ?Sized,
{
    let mut by: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        std::collections::BTreeMap::new();
    for d in devices {
        let person = crate::federation::admission::admission_identity_for_writer(backend, &d)
            .await
            .unwrap_or_else(|_| d.clone());
        by.entry(person).or_default().insert(d);
    }
    Ok(by
        .into_iter()
        .map(|(person_key_id, devs)| CustodyAccess {
            person_key_id,
            devices: devs.into_iter().collect(),
            via: via.to_owned(),
        })
        .collect())
}

/// **The custody view** — see the module doc. `NotHeld` when this node has no
/// row for the blob; `NotGranted` when `viewer_key_id` may not open it.
pub async fn blob_custody<B>(
    backend: &B,
    at_rest_sha256: &[u8; 32],
    viewer_key_id: &str,
) -> Result<BlobCustody, BlobError>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    blob_custody_at(backend, at_rest_sha256, viewer_key_id, chrono::Utc::now()).await
}

/// [`blob_custody`] with the reader's clock injected (custody reports are live
/// for 72 h from their signed instant, judged at `now`).
pub async fn blob_custody_at<B>(
    backend: &B,
    at_rest_sha256: &[u8; 32],
    viewer_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<BlobCustody, BlobError>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    use crate::federation::at_rest_cascade::orchestrate::{
        authorize_viewer_by_tier, refuse_missing_row,
    };
    let Some(head) = backend.blob_head(at_rest_sha256).await? else {
        return Err(refuse_missing_row(backend, at_rest_sha256, viewer_key_id).await?);
    };
    authorize_viewer_by_tier(backend, at_rest_sha256, head.crypto_tier, viewer_key_id).await?;
    let held_here = backend.has_blob(at_rest_sha256).await?;
    let self_node = backend.node_key_id();
    let (access, observable_elsewhere, why) = match head.crypto_tier {
        CryptoTier::InvisibleEncrypted => {
            let devices: Vec<String> = backend
                .list_at_rest_grants(at_rest_sha256)
                .await?
                .into_iter()
                .map(|g| g.recipient_key_id)
                .filter(|r| r != crate::federation::at_rest_cascade::PERSIST_SELF_RECIPIENT)
                .collect();
            (
                group_by_person(backend, devices, "at_rest_grant").await?,
                false,
                Some(
                    "self/family bytes are never announced (CC 5.2 structural invisibility): \
                     copies on other devices are counted from their custody reports (CC \
                     3.1.3.3); a device with no live report is unknown, not none"
                        .to_owned(),
                ),
            )
        }
        CryptoTier::CommunityDek => {
            let devices = match backend.community_dek_blob_epoch(at_rest_sha256).await? {
                Some((community, minter, epoch)) => {
                    backend
                        .community_dek_member_grant_recipients(&community, &minter, epoch)
                        .await?
                }
                None => Vec::new(),
            };
            (
                group_by_person(backend, devices, "community_epoch_grant").await?,
                true,
                None,
            )
        }
        CryptoTier::Plaintext => (
            Vec::new(),
            true,
            Some("plaintext (commons): anyone who holds the bytes can read them".to_owned()),
        ),
    };
    let mut announced: Vec<CustodyHolder> = if observable_elsewhere {
        match backend.list_holders_sized(at_rest_sha256).await {
            Ok(h) => h
                .into_iter()
                .map(|c| CustodyHolder {
                    node_key_id: c.key_id,
                    size_bytes: c.size,
                })
                .collect(),
            Err(crate::federation::Error::Unsupported { .. }) => Vec::new(),
            Err(e) => return Err(BlobError::Backend(format!("list_holders_sized: {e}"))),
        }
    } else {
        Vec::new()
    };
    announced.sort_by(|a, b| a.node_key_id.cmp(&b.node_key_id));
    announced.dedup_by(|a, b| a.node_key_id == b.node_key_id);
    // v53.0.0 (CIRISPersist#942 part 2) — the same fold `custody_view` runs,
    // over the same candidate devices, without receipts.
    let device_custody =
        super::custody_ack::custody_view(backend, at_rest_sha256, viewer_key_id, None, now)
            .await?
            .devices;
    // The copies this node can count, as one set of nodes so a device that both
    // announced and reported is counted once: this node's copy, the announced
    // holders, and every device whose verdict is `here`.
    let mut copies: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    if held_here {
        if let Some(me) = self_node.as_deref() {
            copies.insert(me);
        }
    }
    copies.extend(announced.iter().map(|h| h.node_key_id.as_str()));
    copies.extend(
        device_custody
            .iter()
            .filter(|d| d.state == super::custody_ack::CustodyVerdict::Here)
            .map(|d| d.device_key_id.as_str()),
    );
    // A node that holds the bytes but whose key id is unknown still counts.
    let copies_known = copies.len() as u32 + u32::from(held_here && self_node.is_none());
    Ok(BlobCustody {
        sha256_hex: hex::encode(at_rest_sha256),
        tier: tier_token(head.crypto_tier).to_owned(),
        cohort_scope: head.cohort_scope,
        size_bytes: head.size_bytes,
        held_here,
        access,
        announced_holders: announced,
        copies_known,
        // v53.0.0 — every tier is observable now: self/family copies are
        // counted from their custody reports.
        copies_observable: true,
        why,
        device_custody,
    })
}
