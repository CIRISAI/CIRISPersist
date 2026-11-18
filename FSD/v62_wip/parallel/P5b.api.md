# P5b API: the node-local touch write (for E2 and every touch-claim caller)

Status: IMPLEMENTED in `P5b.patch` (base `v62-syn0`). BELIEVED: nothing was built. If a signature changes, this line says so.

## The write (on `FederationDirectory`; sqlite + postgres override; the double delegates)

```rust
/// Unsigned: the node is the only author of its own floor, and the floor
/// never crosses the mesh.
/// Rules (the signed door's, unchanged):
/// - monotonic max (an equal or older fresh_as_of is NotFresher and writes nothing);
/// - future skew: fresh_as_of > now + admission::DEFAULT_MAX_TOUCH_SKEW (5 min)
///   -> Error::InvalidArgument("touch_claim: fresh_as_of … ahead of now …");
/// - cohort_scope outside the closed set -> Error::CohortScopeRejected { cohort_scope };
/// - an empty target_key_id or target_kind -> Error::InvalidArgument.
async fn put_touch_claim_local(
    &self,
    target_key_id: &str,
    target_kind: &str,
    fresh_as_of: chrono::DateTime<chrono::Utc>,
    cohort_scope: &str,
) -> Result<crate::federation::TouchApplyOutcome, crate::federation::Error>;
```

## The read (the floor as the node holds it, whichever write set it)

```rust
async fn freshness_floor(
    &self,
    target_key_id: &str,
    target_kind: &str,
) -> Result<Option<crate::federation::types::FreshnessFloor>, crate::federation::Error>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessFloor {          // crate::federation::types
    pub target_key_id: String,
    pub target_kind: String,
    pub fresh_as_of: DateTime<Utc>,
    pub cohort_scope: String,
}

pub const NODE_LOCAL_TOUCH_FORM: &str = "node_local"; // crate::federation::types
```

## Also new

`pub fn admission::check_touch_fresh_as_of_skew(fresh_as_of, now, max_skew) -> Result<(), Error>`. `verify_touch_claim_admission` now delegates to it. Its message prefix changed from `signed touch_claim:` to `touch_claim:`; no test matched the old prefix (read-checked by grep).

## The earlier form (left for F to remove)

`put_touch_claim(&SignedTouchClaim)` and `lookup_freshness_floor` are unchanged in signature.
- `lookup_freshness_floor` now SKIPS a node-local row (`signer_form <> 'node_local'`): it returns `None` for a floor a node-local touch holds.
- Both writes merge into the one row per `(target_key_id, target_kind)`, monotonic max across both.

**For callers:** read the floor with `freshness_floor`, not `lookup_freshness_floor`. `ownership_reclaim`'s abandonment fold already does.

**Storage:** no schema change. V300 must reproduce edition 1's `freshness_floor` DDL byte for byte (I1950), so the NOT NULL signed columns stay. A node-local row is stored as `signer_form = 'node_local'`, `attesting_key_id` = the node's own key id (or empty), `signed_envelope = '{}'` and `signature = ''`.
