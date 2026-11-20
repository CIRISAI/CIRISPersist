//! v62.0.0 (P1-fix8; the lead's ruling, CC 2.6.1.5 "no float anywhere") —
//! **the ledgers' exact decimal.**
//!
//! A credits `balance` and an `expertise` are money-like: they are stored,
//! read, compared and multiplied EXACTLY, never through `f64`. One value has
//! one spelling, the **canonical decimal text**, and it is the same text on
//! every backend (sqlite stores it as `TEXT`, postgres as `numeric` and reads
//! it back as `::text`) and on every public surface (Rust, FFI, Python):
//!
//! - an integral value is plain digits: `0`, `12`, `-3` (never `-0`, never
//!   `12.0`, never `1e2`);
//! - any other value is `[-]I.F` with `I` the integer digits (`0` when the
//!   magnitude is below one) and `F` the fractional digits, the last one not
//!   `0`: `12.5`, `0.30000000000000004`, `-0.05`.
//!
//! It is exactly the text [`crate::federation::edition2::payloads::body_number`]
//! states on the wire (an integer, or a normalised tag-4 decimal) rendered
//! back by `json_number_of_decimal`, so a balance read from a row, stored, and
//! read back is the row's own number. The arithmetic here (`+`, `×`, order)
//! is schoolbook decimal on digit vectors: no rounding happens anywhere but
//! [`Decimal::round_half_away_to`], which the expertise row's fixed6 `score`
//! names explicitly.

use std::cmp::Ordering;

/// An exact decimal: `(-1)^negative × digits × 10^-scale`.
///
/// Invariants (every constructor normalises): `digits` holds the magnitude's
/// decimal digits, most significant first, with no leading `0` (empty for
/// zero); when `scale > 0` the last digit is not `0`; zero has `scale == 0`
/// and is never negative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decimal {
    negative: bool,
    digits: Vec<u8>,
    scale: usize,
}

impl Decimal {
    /// Zero.
    #[must_use]
    pub fn zero() -> Self {
        Self {
            negative: false,
            digits: Vec::new(),
            scale: 0,
        }
    }

    fn normalised(negative: bool, mut digits: Vec<u8>, mut scale: usize) -> Self {
        while scale > 0 && digits.last() == Some(&0) {
            digits.pop();
            scale -= 1;
        }
        let lead = digits.iter().take_while(|d| **d == 0).count();
        digits.drain(..lead);
        if digits.is_empty() {
            return Self::zero();
        }
        Self {
            negative,
            digits,
            scale,
        }
    }

    /// Parse decimal text `-?D+(.D+)?` (no exponent, no `+`), any spelling of
    /// it (`1.50`, `007`, `-0`), normalised. `None` for anything else.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (negative, rest) = match text.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, text),
        };
        let (int, frac) = match rest.split_once('.') {
            Some((i, f)) => {
                if f.is_empty() {
                    return None;
                }
                (i, f)
            }
            None => (rest, ""),
        };
        if int.is_empty() || !int.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit()) {
            return None;
        }
        let digits = int.bytes().chain(frac.bytes()).map(|b| b - b'0').collect();
        Some(Self::normalised(negative, digits, frac.len()))
    }

    /// Parse the CANONICAL text only: `text` must be exactly what
    /// [`Decimal::canonical`] renders for its value. `1.50`, `-0`, `+1`,
    /// `1e2` and `.5` are `None` — one value, one spelling.
    #[must_use]
    pub fn parse_canonical(text: &str) -> Option<Self> {
        Self::parse(text).filter(|d| d.canonical() == text)
    }

    /// The exact value of a JSON number, read through the one body-number
    /// reader ([`crate::federation::edition2::payloads::body_number`]); its
    /// source token under `arbitrary_precision`, never `f64`. `None` for a
    /// number that reader refuses (`body_number_unrepresentable`).
    #[must_use]
    pub fn of_number(n: &serde_json::Number) -> Option<Self> {
        use ciris_verify_core::cde::Value;
        match crate::federation::edition2::payloads::body_number(n).ok()? {
            Value::Uint(u) => Self::parse(&u.to_string()),
            // A CBOR negative integer `Nint(k)` is `-1 - k`.
            Value::Nint(k) => Self::parse(&format!("-{}", u128::from(k) + 1)),
            v @ Value::Tag(4, _) => {
                let n = crate::federation::edition2::payloads::json_number_of_decimal(&v)?;
                Self::parse(&n.to_string())
            }
            _ => None,
        }
    }

    /// The canonical decimal text (module docs).
    #[must_use]
    pub fn canonical(&self) -> String {
        if self.digits.is_empty() {
            return "0".to_owned();
        }
        let d: String = self.digits.iter().map(|d| char::from(b'0' + d)).collect();
        let body = if self.scale == 0 {
            d
        } else if d.len() > self.scale {
            let (i, f) = d.split_at(d.len() - self.scale);
            format!("{i}.{f}")
        } else {
            format!("0.{}{d}", "0".repeat(self.scale - d.len()))
        };
        if self.negative {
            format!("-{body}")
        } else {
            body
        }
    }

    /// A JSON number with exactly this value (its token the canonical text).
    ///
    /// # Panics
    /// Never: the canonical text is always a JSON number.
    #[must_use]
    pub fn json_number(&self) -> serde_json::Number {
        serde_json::from_str(&self.canonical()).expect("a canonical decimal is a JSON number")
    }

    /// Is this zero?
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.digits.is_empty()
    }

    /// Is this below zero?
    #[must_use]
    pub fn is_negative(&self) -> bool {
        self.negative
    }

    /// Is this within `[0, 1]`?
    #[must_use]
    pub fn in_unit(&self) -> bool {
        !self.negative && self.cmp(&Self::from_u64(1)) != Ordering::Greater
    }

    /// An integer.
    #[must_use]
    pub fn from_u64(v: u64) -> Self {
        Self::parse(&v.to_string()).unwrap_or_else(Self::zero)
    }

    /// The magnitude's digits at `scale` places (`scale >= self.scale`).
    fn magnitude_at(&self, scale: usize) -> Vec<u8> {
        let mut d = self.digits.clone();
        d.resize(d.len() + (scale - self.scale), 0);
        d
    }

    /// Exact sum.
    #[must_use]
    pub fn plus(&self, other: &Self) -> Self {
        let scale = self.scale.max(other.scale);
        let (a, b) = (self.magnitude_at(scale), other.magnitude_at(scale));
        if self.negative == other.negative {
            return Self::normalised(self.negative, add_mag(&a, &b), scale);
        }
        match cmp_mag(&a, &b) {
            Ordering::Equal => Self::zero(),
            Ordering::Greater => Self::normalised(self.negative, sub_mag(&a, &b), scale),
            Ordering::Less => Self::normalised(other.negative, sub_mag(&b, &a), scale),
        }
    }

    /// Exact product.
    #[must_use]
    pub fn times(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let (a, b) = (&self.digits, &other.digits);
        let mut acc = vec![0u32; a.len() + b.len()];
        for (i, x) in a.iter().enumerate().rev() {
            for (j, y) in b.iter().enumerate().rev() {
                acc[i + j + 1] += u32::from(*x) * u32::from(*y);
            }
        }
        for k in (1..acc.len()).rev() {
            let carry = acc[k] / 10;
            acc[k] %= 10;
            acc[k - 1] += carry;
        }
        #[allow(clippy::cast_possible_truncation)] // every cell is < 10 after the carry pass
        let digits = acc.into_iter().map(|d| d as u8).collect();
        Self::normalised(
            self.negative != other.negative,
            digits,
            self.scale + other.scale,
        )
    }

    /// Round to `places` fractional digits, half away from zero — the ONE
    /// rounding in this module, for a fixed-scale member (the expertise
    /// row's fixed6 `score`, CC 2.6.1.5). Exact otherwise.
    #[must_use]
    pub fn round_half_away_to(&self, places: usize) -> Self {
        if self.scale <= places {
            return self.clone();
        }
        let drop = self.scale - places;
        let mut d = self.digits.clone();
        // Left-pad so at least one digit stays above the cut.
        if d.len() <= drop {
            let mut padded = vec![0u8; drop + 1 - d.len()];
            padded.extend(d);
            d = padded;
        }
        let first_dropped = d[d.len() - drop];
        d.truncate(d.len() - drop);
        let kept = if first_dropped >= 5 {
            add_mag(&d, &[1])
        } else {
            d
        };
        Self::normalised(self.negative, kept, places)
    }
}

impl Ord for Decimal {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (false, true) => return Ordering::Greater,
            (true, false) => return Ordering::Less,
            _ => {}
        }
        let scale = self.scale.max(other.scale);
        let m = cmp_mag(&self.magnitude_at(scale), &other.magnitude_at(scale));
        if self.negative {
            m.reverse()
        } else {
            m
        }
    }
}

impl PartialOrd for Decimal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for Decimal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.canonical())
    }
}

/// Compare two digit vectors as unsigned integers (leading zeros allowed).
fn cmp_mag(a: &[u8], b: &[u8]) -> Ordering {
    let strip = |x: &[u8]| -> Vec<u8> { x.iter().copied().skip_while(|d| *d == 0).collect() };
    let (a, b) = (strip(a), strip(b));
    a.len().cmp(&b.len()).then_with(|| a.cmp(&b))
}

/// `a + b` on digit vectors.
fn add_mag(a: &[u8], b: &[u8]) -> Vec<u8> {
    let n = a.len().max(b.len());
    let mut out = Vec::with_capacity(n + 1);
    let mut carry = 0u8;
    for k in 0..n {
        let x = if k < a.len() { a[a.len() - 1 - k] } else { 0 };
        let y = if k < b.len() { b[b.len() - 1 - k] } else { 0 };
        let s = x + y + carry;
        out.push(s % 10);
        carry = s / 10;
    }
    if carry > 0 {
        out.push(carry);
    }
    out.reverse();
    out
}

/// `a - b` on digit vectors, `a >= b`.
fn sub_mag(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(a.len());
    let mut borrow = 0i8;
    for k in 0..a.len() {
        let x = i8::try_from(a[a.len() - 1 - k]).unwrap_or(0);
        let y = if k < b.len() {
            i8::try_from(b[b.len() - 1 - k]).unwrap_or(0)
        } else {
            0
        };
        let mut s = x - y - borrow;
        borrow = 0;
        if s < 0 {
            s += 10;
            borrow = 1;
        }
        out.push(u8::try_from(s).unwrap_or(0));
    }
    out.reverse();
    out
}

/// v62.0.0 (P1-fix8) — **the vote weight, exactly** (`SCHEMA.md` §5.2):
/// `expertise_multiplier = 1 + 4 × expertise` (`[1, 5]`),
/// `active_tier_multiplier = 1.5` if active else `0.5`, and
/// `weight = credits × expertise_multiplier × active_tier_multiplier`.
/// Returns `(expertise_multiplier, active_tier_multiplier, weight)`.
#[must_use]
pub fn vote_weight(
    credits: &Decimal,
    expertise: &Decimal,
    is_active: bool,
) -> (Decimal, Decimal, Decimal) {
    let expertise_multiplier = Decimal::from_u64(1).plus(&Decimal::from_u64(4).times(expertise));
    let active_tier_multiplier = if is_active {
        Decimal::parse("1.5").unwrap_or_else(Decimal::zero)
    } else {
        Decimal::parse("0.5").unwrap_or_else(Decimal::zero)
    };
    let weight = credits
        .times(&expertise_multiplier)
        .times(&active_tier_multiplier);
    (expertise_multiplier, active_tier_multiplier, weight)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        Decimal::parse(s).unwrap()
    }

    /// **I4005 — one value, one spelling, exact.** Every spelling of a value
    /// renders the one canonical text; only that text parses canonically;
    /// a JSON number's source token is read exactly (20 significant digits
    /// survive); sums, products and order are exact.
    #[test]
    fn i4005_the_canonical_decimal_is_exact() {
        for (any, canon) in [
            ("1.50", "1.5"),
            ("007", "7"),
            ("-0", "0"),
            ("-0.000", "0"),
            ("0.30000000000000004", "0.30000000000000004"),
            ("0.12345678901234567890", "0.1234567890123456789"),
            ("-12.50", "-12.5"),
            ("0.05", "0.05"),
            ("100", "100"),
        ] {
            assert_eq!(d(any).canonical(), canon, "I4005: {any}");
            assert!(Decimal::parse_canonical(canon).is_some(), "I4005: {canon}");
        }
        for bad in [
            "1.50", "-0", "+1", "1e2", ".5", "5.", "", "-", "0x1", "1.0", "01",
        ] {
            assert!(Decimal::parse_canonical(bad).is_none(), "I4005: {bad:?}");
        }
        for (token, canon) in [
            ("0.12345678901234567890", "0.1234567890123456789"),
            ("0.30000000000000004", "0.30000000000000004"),
            ("12.5", "12.5"),
            ("2.0", "2"),
            ("1e2", "100"),
            ("-3", "-3"),
            ("-0.050", "-0.05"),
            // P1-fix9 — tag-4 mantissas past i64, inside CBOR's range.
            ("92233720368547758.08", "92233720368547758.08"),
            ("-184467440737095516.16", "-184467440737095516.16"),
        ] {
            let n: serde_json::Number = serde_json::from_str(token).unwrap();
            assert_eq!(
                Decimal::of_number(&n).unwrap().canonical(),
                canon,
                "I4005: {token}"
            );
            assert_eq!(d(canon).json_number().to_string(), canon, "I4005: {canon}");
        }
        assert_eq!(
            d("0.1").plus(&d("0.2")).canonical(),
            "0.3",
            "I4005: no 0.30000000000000004"
        );
        assert_eq!(d("-1.25").plus(&d("1.25")).canonical(), "0");
        assert_eq!(d("1").plus(&d("-1.5")).canonical(), "-0.5");
        assert_eq!(d("1.5").times(&d("-0.5")).canonical(), "-0.75");
        assert_eq!(d("0.1").times(&d("0.1")).canonical(), "0.01");
        assert!(d("0.30000000000000004") > d("0.3"));
        assert!(d("-2") < d("-1.9"));
        assert!(d("1").in_unit() && d("0").in_unit() && d("0.999").in_unit());
        assert!(!d("1.00000000000000001").in_unit() && !d("-0.0000000000000001").in_unit());
        assert_eq!(d("0.0000005").round_half_away_to(6).canonical(), "0.000001");
        assert_eq!(d("0.0000004999").round_half_away_to(6).canonical(), "0");
        assert_eq!(d("0.9999995").round_half_away_to(6).canonical(), "1");
        assert_eq!(d("0.25").round_half_away_to(6).canonical(), "0.25");
    }

    /// **I4006 — the vote weight is exact** (`SCHEMA.md` §5.2): no float
    /// step, so `0.1`-scale inputs give the decimal answer, not its `f64`
    /// neighbour.
    #[test]
    fn i4006_the_vote_weight_is_exact() {
        let (em, am, w) = vote_weight(&d("10"), &d("0.5"), true);
        assert_eq!(
            (em.canonical(), am.canonical(), w.canonical()),
            ("3".into(), "1.5".into(), "45".into())
        );
        let (em, am, w) = vote_weight(&d("0.1"), &d("0.3"), false);
        assert_eq!(
            (em.canonical(), am.canonical(), w.canonical()),
            ("2.2".into(), "0.5".into(), "0.11".into()),
            "I4006: 0.1 × 2.2 × 0.5 is 0.11 exactly"
        );
        let (_, _, w) = vote_weight(&d("-3.5"), &d("0"), true);
        assert_eq!(w.canonical(), "-5.25");
        let (em, _, w) = vote_weight(&d("0.12345678901234567890"), &d("1"), true);
        assert_eq!(
            (em.canonical(), w.canonical()),
            ("5".into(), "0.92592591759259259175".into())
        );
    }
}
