//! v62.0.0 (FS-step1; Eric 11-21: "move to config driven") — **the one
//! family table**: CIRISConstitution `manifests/family_model.json` at the
//! vendored tag (`v1.0-rc22-pre3`), read once into a typed table.
//!
//! Persist's knowledge of a family (who may sign, who cosigns, the subject
//! rule, polarity, shape, what descends on withdrawal, the per-family refs)
//! is read from here, not kept in hand-written lists and matches. This first
//! cut carries the two columns the withdrawn-content descent reads, `shape`
//! and `descends_on_withdrawal`. They replace WD-fix1's hand-derived
//! `FAMILY_SHAPES` table, which equalled pre3's columns for all 189
//! families. Later steps add the signer, cosign, subject and polarity cells
//! to the same row.
//!
//! A column a later tag adds (`names_head`, at the tag after pre3) is one
//! field and one accessor. The field is `None` while the vendored tag does
//! not carry the column; the accessor then answers `None`, never a default.
//! Once the tag carries it (any row has it, or `_meta.columns` declares it),
//! every row must, and a row without it refuses the table.
//!
//! The bytes are the vendored file (`cc_manifests::VENDORED_FAMILY_MODEL_FILE_SHA256`,
//! checked by I1300 and, against a Constitution checkout, I1302). The parse
//! is closed: a shape or descent token outside the vocabulary below is a
//! malformed table, and building it panics (I5701 shows the parser refuses
//! one).

use std::collections::BTreeMap;
use std::sync::OnceLock;

/// The vendored table (CC `manifests/family_model.json`).
pub const FAMILY_MODEL_JSON: &str = include_str!("family_model.json");

/// A family's shape (CC 6.1.5; `family_model.json` `shape`, from Constitution
/// `formal/derivation/family_shapes.tsv`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// A score or attestation about something (`claim`).
    Claim,
    /// Words, bytes, a trace, a goal, a listing (`content`).
    Content,
    /// A consent: a grant, an acceptance (`consent`).
    Consent,
    /// A door: a delegation, a seat, a proposal (`door`).
    Door,
    /// Both a consent and a door (`consent+door`).
    ConsentDoor,
    /// No shape takes it (`null` in the table).
    NoneFits,
}

/// What an admitted withdrawal takes from other holders (CC 6.1.5;
/// `family_model.json` `descends_on_withdrawal`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawalDescent {
    /// The row itself goes; its id is kept as a tombstone (`row`).
    Row,
    /// The row's words and the bytes it bound go (`bytes_and_words`).
    BytesAndWords,
    /// Nothing goes: the row is kept and read retracted (`nothing`).
    Nothing,
}

/// Who a family's row names as its head (`family_model.json` `names_head`,
/// added at the tag after pre3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamesHead {
    /// The roster (`roster`).
    Roster,
    /// The standing (`standing`).
    Standing,
    /// No head (`none`).
    NoHead,
    /// The row's placement decides (`by_placement`).
    ByPlacement,
}

/// A `names_head` cell: one value for the family, or one per leaf where the
/// leaves differ (the table's per-leaf form: `value` is an object keyed by
/// leaf, as `signer_rule` is for `cosign:{state}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamesHeadCell {
    /// Every leaf alike.
    Every(NamesHead),
    /// By leaf.
    PerLeaf(BTreeMap<String, NamesHead>),
}

/// One family of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyRow {
    /// The registry prefix (`chat:*`, `membership:{stage}`).
    pub prefix: String,
    /// Its family id (header -70002; Verify's `namespace_match::family_id`).
    pub family_id: String,
    /// The `shape` cell.
    pub shape: Shape,
    /// The `descends_on_withdrawal` cell.
    pub descends_on_withdrawal: WithdrawalDescent,
    /// The `names_head` cell; `None` while the vendored tag has no such
    /// column.
    pub names_head: Option<NamesHeadCell>,
}

/// The table: every row, by family id.
#[derive(Debug)]
pub struct FamilyTable {
    rows: Vec<FamilyRow>,
    by_id: BTreeMap<String, usize>,
}

impl FamilyTable {
    /// Every row, in the manifest's order.
    #[must_use]
    pub fn rows(&self) -> &[FamilyRow] {
        &self.rows
    }

    /// The row of the family whose family id is `family_id`.
    #[must_use]
    pub fn by_family_id(&self, family_id: &str) -> Option<&FamilyRow> {
        self.by_id.get(family_id).map(|&i| &self.rows[i])
    }

    /// Who the family's row names as its head, at `leaf` when the cell is
    /// per leaf. `None` when the vendored tag has no `names_head` column,
    /// the family is unknown, or the cell is per leaf and `leaf` is not one
    /// of its leaves: never a default.
    #[must_use]
    pub fn names_head(&self, family_id: &str, leaf: Option<&str>) -> Option<NamesHead> {
        match self.by_family_id(family_id)?.names_head.as_ref()? {
            NamesHeadCell::Every(h) => Some(*h),
            NamesHeadCell::PerLeaf(m) => m.get(leaf?).copied(),
        }
    }
}

/// A cell's `value` (the table states every cell as `{value, source, …}`).
fn cell<'a>(row: &'a serde_json::Value, column: &str) -> &'a serde_json::Value {
    match &row[column] {
        serde_json::Value::Object(m) => m.get("value").unwrap_or(&serde_json::Value::Null),
        other => other,
    }
}

fn shape_of(v: &serde_json::Value, family: &str) -> Result<Shape, String> {
    match v {
        serde_json::Value::Null => Ok(Shape::NoneFits),
        serde_json::Value::String(s) => match s.as_str() {
            "claim" => Ok(Shape::Claim),
            "content" => Ok(Shape::Content),
            "consent" => Ok(Shape::Consent),
            "door" => Ok(Shape::Door),
            "consent+door" => Ok(Shape::ConsentDoor),
            other => Err(format!(
                "{family}: shape {other:?} is outside the vocabulary"
            )),
        },
        other => Err(format!("{family}: shape {other} is not text")),
    }
}

fn names_head_token(v: &serde_json::Value, family: &str) -> Result<NamesHead, String> {
    match v.as_str() {
        Some("roster") => Ok(NamesHead::Roster),
        Some("standing") => Ok(NamesHead::Standing),
        Some("none") => Ok(NamesHead::NoHead),
        Some("by_placement") => Ok(NamesHead::ByPlacement),
        _ => Err(format!(
            "{family}: names_head {v} is outside the vocabulary"
        )),
    }
}

fn names_head_of(v: &serde_json::Value, family: &str) -> Result<NamesHeadCell, String> {
    match v {
        serde_json::Value::Object(m) => m
            .iter()
            .map(|(leaf, t)| Ok((leaf.clone(), names_head_token(t, family)?)))
            .collect::<Result<BTreeMap<_, _>, String>>()
            .map(NamesHeadCell::PerLeaf),
        other => names_head_token(other, family).map(NamesHeadCell::Every),
    }
}

/// Whether the table carries `column`, a column a later tag adds: some row
/// has it, or `_meta.columns` declares it.
fn carries_column(doc: &serde_json::Value, rows: &[serde_json::Value], column: &str) -> bool {
    doc["_meta"]["columns"].get(column).is_some() || rows.iter().any(|r| r.get(column).is_some())
}

/// A later-tag column's cell: `None` when the table does not carry the
/// column; once it does, a row without the cell is malformed.
fn later_cell<'a>(
    carried: bool,
    row: &'a serde_json::Value,
    column: &str,
    family: &str,
) -> Result<Option<&'a serde_json::Value>, String> {
    match (carried, row.get(column)) {
        (false, _) => Ok(None),
        (true, Some(_)) => Ok(Some(cell(row, column))),
        (true, None) => Err(format!(
            "{family}: no {column} cell, but the table carries the column"
        )),
    }
}

fn descent_of(v: &serde_json::Value, family: &str) -> Result<WithdrawalDescent, String> {
    match v.as_str() {
        Some("row") => Ok(WithdrawalDescent::Row),
        Some("bytes_and_words") => Ok(WithdrawalDescent::BytesAndWords),
        Some("nothing") => Ok(WithdrawalDescent::Nothing),
        _ => Err(format!(
            "{family}: descends_on_withdrawal {v} is outside the vocabulary"
        )),
    }
}

/// Parse a family model (the vendored bytes, or a planted copy in a test).
///
/// # Errors
/// A malformed table: no `rows`, a row with no `family`, a token outside the
/// vocabulary, a duplicated family id, a row count other than
/// `_meta.families`, or a row without a later-tag column the table carries.
pub fn parse(json: &str) -> Result<FamilyTable, String> {
    let doc: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("family_model.json: {e}"))?;
    let raw = doc["rows"]
        .as_array()
        .ok_or("family_model.json carries no rows[]")?;
    let mut rows = Vec::with_capacity(raw.len());
    let mut by_id = BTreeMap::new();
    let has_names_head = carries_column(&doc, raw, "names_head");
    for r in raw {
        let prefix = r["family"]
            .as_str()
            .ok_or("a family_model.json row names no family")?
            .to_owned();
        let family_id = ciris_verify_core::namespace_match::family_id(&prefix);
        let shape = shape_of(cell(r, "shape"), &prefix)?;
        let descends_on_withdrawal = descent_of(cell(r, "descends_on_withdrawal"), &prefix)?;
        let names_head = later_cell(has_names_head, r, "names_head", &prefix)?
            .map(|v| names_head_of(v, &prefix))
            .transpose()?;
        if by_id.insert(family_id.clone(), rows.len()).is_some() {
            return Err(format!("{prefix}: family id {family_id} twice"));
        }
        rows.push(FamilyRow {
            prefix,
            family_id,
            shape,
            descends_on_withdrawal,
            names_head,
        });
    }
    if doc["_meta"]["families"].as_u64() != Some(rows.len() as u64) {
        return Err(format!(
            "{} rows, but _meta.families says {}",
            rows.len(),
            doc["_meta"]["families"]
        ));
    }
    Ok(FamilyTable { rows, by_id })
}

/// The vendored table, built once.
///
/// # Panics
/// The vendored bytes do not parse ([`parse`]); I5700 holds that they do.
#[must_use]
pub fn table() -> &'static FamilyTable {
    static TABLE: OnceLock<FamilyTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        parse(FAMILY_MODEL_JSON).unwrap_or_else(|e| panic!("vendored family_model.json: {e}"))
    })
}

#[cfg(test)]
mod tests {
    //! **I5700–I5702** (v62.0.0, FS-step1) — the one family table.
    use super::*;

    /// The vendored bytes' own `_meta.families`: the row count is read from
    /// the tag, not pinned here (pre3 states 189; the next tag, 190).
    fn stated_families() -> u64 {
        let doc: serde_json::Value = serde_json::from_str(FAMILY_MODEL_JSON).expect("I5700: json");
        doc["_meta"]["families"]
            .as_u64()
            .expect("I5700: _meta.families")
    }

    /// **I5700** — the vendored table parses: the row count `_meta.families`
    /// states, every family id once, every shape present, and the two
    /// columns agree (a claim descends as a row, content as its bytes and
    /// words, structure not at all). No count is a literal: a re-vendor
    /// re-pins nothing here.
    #[test]
    fn i5700_the_vendored_family_table() {
        let t = table();
        assert_eq!(
            t.rows().len() as u64,
            stated_families(),
            "I5700: the stated count"
        );
        for s in [
            Shape::Claim,
            Shape::Content,
            Shape::Consent,
            Shape::Door,
            Shape::ConsentDoor,
            Shape::NoneFits,
        ] {
            assert!(t.rows().iter().any(|r| r.shape == s), "I5700: some {s:?}");
        }
        for r in t.rows() {
            let want = match r.shape {
                Shape::Claim => WithdrawalDescent::Row,
                Shape::Content => WithdrawalDescent::BytesAndWords,
                _ => WithdrawalDescent::Nothing,
            };
            assert_eq!(r.descends_on_withdrawal, want, "I5700: {}", r.prefix);
            assert_eq!(
                t.by_family_id(&r.family_id).map(|x| &x.prefix),
                Some(&r.prefix),
                "I5700: {} by its id",
                r.prefix
            );
        }
    }

    /// **I5701** — the parse is closed: a planted shape or descent token
    /// outside the vocabulary, or a row count `_meta.families` does not
    /// state, refuses the table.
    #[test]
    fn i5701_a_malformed_table_is_refused() {
        let bad_shape =
            FAMILY_MODEL_JSON.replacen("\"value\": \"claim\"", "\"value\": \"clam\"", 1);
        assert_ne!(bad_shape, FAMILY_MODEL_JSON, "I5701: the plant landed");
        assert!(
            parse(&bad_shape).is_err_and(|e| e.contains("clam")),
            "I5701: an unknown shape"
        );
        let bad_descent =
            FAMILY_MODEL_JSON.replacen("\"value\": \"bytes_and_words\"", "\"value\": \"bytes\"", 1);
        assert_ne!(bad_descent, FAMILY_MODEL_JSON, "I5701: the plant landed");
        assert!(parse(&bad_descent).is_err(), "I5701: an unknown descent");
        let n = stated_families();
        let bad_count = FAMILY_MODEL_JSON.replacen(
            &format!("\"families\": {n}"),
            &format!("\"families\": {}", n - 1),
            1,
        );
        assert_ne!(bad_count, FAMILY_MODEL_JSON, "I5701: the plant landed");
        assert!(
            parse(&bad_count).is_err(),
            "I5701: a row count the meta does not state"
        );
    }

    /// **I5702** — the two composer predicates, one place each
    /// (`edition2::emit`): `names_a_target` is withdraws, recants and
    /// supersedes; `carries_no_dimension` (Verify's `is_composer`) is the two
    /// retractions; they differ by exactly `supersedes`.
    #[test]
    fn i5702_the_two_composer_predicates() {
        use crate::federation::edition2::emit::{carries_no_dimension, names_a_target};
        use crate::federation::types::attestation_type;
        let names: Vec<&str> = attestation_type::ALL
            .iter()
            .copied()
            .filter(|t| names_a_target(t))
            .collect();
        let no_dim: Vec<&str> = attestation_type::ALL
            .iter()
            .copied()
            .filter(|t| carries_no_dimension(t))
            .collect();
        assert_eq!(
            names,
            [
                attestation_type::SUPERSEDES,
                attestation_type::WITHDRAWS,
                attestation_type::RECANTS
            ],
            "I5702: the rows that name a target"
        );
        assert_eq!(
            no_dim,
            [attestation_type::WITHDRAWS, attestation_type::RECANTS],
            "I5702: the rows that carry no dimension"
        );
        assert!(!names_a_target(attestation_type::SCORES));
        assert!(!names_a_target(attestation_type::DELEGATES_TO));
    }

    /// **I5703** — a later-tag column (`names_head`) is one field and one
    /// accessor. While the vendored tag lacks the column every answer is
    /// `None` (this holds at pre3 and after: when the tag carries the column,
    /// every row has the cell). A planted column is read whole and per
    /// leaf; a leaf the cell does not list answers `None`, not a default; a
    /// row without the cell, or a token outside the vocabulary, refuses the
    /// table.
    #[test]
    fn i5703_a_later_column_is_none_until_the_tag_carries_it() {
        let t = table();
        let doc: serde_json::Value = serde_json::from_str(FAMILY_MODEL_JSON).expect("I5703: json");
        let carried = carries_column(&doc, doc["rows"].as_array().expect("rows"), "names_head");
        for r in t.rows() {
            assert_eq!(r.names_head.is_some(), carried, "I5703: {}", r.prefix);
            if !carried {
                assert_eq!(
                    t.names_head(&r.family_id, None),
                    None,
                    "I5703: {}",
                    r.prefix
                );
            }
        }
        let plant = |f: &dyn Fn(usize, &mut serde_json::Value)| {
            let mut d = doc.clone();
            for (i, r) in d["rows"]
                .as_array_mut()
                .expect("rows")
                .iter_mut()
                .enumerate()
            {
                f(i, r);
            }
            serde_json::to_string(&d).expect("I5703: plant")
        };
        let planted = parse(&plant(&|i, r| {
            r["names_head"] = match i {
                0 => serde_json::json!({"value": "roster", "source": "planted"}),
                1 => serde_json::json!({
                    "value": {"a": "standing", "b": "by_placement"},
                    "source": "planted"
                }),
                _ => serde_json::json!({"value": "none", "source": "planted"}),
            };
        }))
        .expect("I5703: the planted column parses");
        let id = |i: usize| planted.rows()[i].family_id.clone();
        assert_eq!(planted.names_head(&id(0), None), Some(NamesHead::Roster));
        assert_eq!(
            planted.names_head(&id(0), Some("x")),
            Some(NamesHead::Roster)
        );
        assert_eq!(
            planted.names_head(&id(1), Some("a")),
            Some(NamesHead::Standing)
        );
        assert_eq!(
            planted.names_head(&id(1), Some("b")),
            Some(NamesHead::ByPlacement)
        );
        assert_eq!(
            planted.names_head(&id(1), Some("c")),
            None,
            "I5703: an unlisted leaf"
        );
        assert_eq!(
            planted.names_head(&id(1), None),
            None,
            "I5703: per leaf, no leaf"
        );
        assert_eq!(planted.names_head(&id(2), None), Some(NamesHead::NoHead));
        assert_eq!(
            planted.names_head("zz:.probe", None),
            None,
            "I5703: an unknown family"
        );
        let one_row = plant(&|i, r| {
            if i == 0 {
                r["names_head"] = serde_json::json!({"value": "roster", "source": "planted"});
            }
        });
        assert!(
            parse(&one_row).is_err_and(|e| e.contains("no names_head cell")),
            "I5703: a row without the carried column"
        );
        let bad = plant(&|_, r| {
            r["names_head"] = serde_json::json!({"value": "head", "source": "planted"});
        });
        assert!(parse(&bad).is_err(), "I5703: an unknown names_head token");
    }
}
