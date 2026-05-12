//! Regex pass — structured-PII patterns and historical-year residue check.
//!
//! Lifted verbatim from CIRISLens `cirislens-core/src/scrubber/regex.rs`
//! (sole behavioral change: `lazy_static` → `std::sync::OnceLock`).
//! Every pattern + helper here is bytewise-identical to the upstream
//! reference; the regression tests at the bottom of this file
//! (originally added in lens-core after observed production-corpus
//! false positives) port verbatim too.
//!
//! The regex pass runs on every string in the trace — in or out of
//! `SCRUB_FIELDS` scope — so the year-residue invariant holds
//! globally. NER (when enabled) only runs on `SCRUB_FIELDS`-scoped
//! strings; the regex pass is the universal sweep behind it.

use ::regex::Regex;
use serde_json::Value;
use std::env;
use std::sync::OnceLock;

use super::ScrubStats;

/// Lazy regex slot. Compiled on first call; the unwrap below is a
/// `panic!` on the literal pattern — which would mean the literal is
/// invalid Rust regex syntax, a compile-time bug worth surfacing
/// loudly via panic at first use.
fn email() -> &'static Regex {
    static C: OnceLock<Regex> = OnceLock::new();
    C.get_or_init(|| Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap())
}

/// US-style phone numbers. The crucial discipline here is to require
/// at least one structural marker (separator, parens, or `+1` prefix)
/// somewhere in the match — otherwise the regex collapses to "any 10
/// consecutive digits", which false-positives on every embedded
/// timestamp / sequence number / batch counter in the corpus
/// (e.g. `20260322030441` → `[PHONE]0441` was real production data).
/// Real phone numbers in the wild basically always have a separator
/// or parens or `+1`; bare 10-digit strings are almost never phones.
fn phone() -> &'static Regex {
    static C: OnceLock<Regex> = OnceLock::new();
    C.get_or_init(|| {
        Regex::new(
            // Three accepted shapes (each must carry at least one
            // structural marker — `+`, parens, or two separators):
            //   1. `+1 NNN NNN NNNN` — literal `+` required
            //   2. `(NNN) NNN-NNNN`  — parens required
            //   3. `NNN-NNN-NNNN`    — two separators required
            //
            // The optional-`+` form (`1-NNN-NNN-NNNN`) is intentionally
            // NOT accepted: without the literal `+`, any digit `1`
            // followed by a separator and 10 further digits matches —
            // including substrings of long numeric IDs like
            // `151-20260328091840` where the `1` is a coincidence.
            r"(?x)
            \+1[-.\s]+\(?[0-9]{3}\)?[-.\s]*[0-9]{3}[-.\s]*[0-9]{4}
            | \([0-9]{3}\)[-.\s]*[0-9]{3}[-.\s]*[0-9]{4}
            | \b[0-9]{3}[-.\s]+[0-9]{3}[-.\s]+[0-9]{4}\b
            ",
        )
        .unwrap()
    })
}

fn ipv4() -> &'static Regex {
    static C: OnceLock<Regex> = OnceLock::new();
    C.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap())
}

fn url() -> &'static Regex {
    static C: OnceLock<Regex> = OnceLock::new();
    C.get_or_init(|| Regex::new(r"https?://[^\s<>]+").unwrap())
}

fn ssn() -> &'static Regex {
    static C: OnceLock<Regex> = OnceLock::new();
    C.get_or_init(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap())
}

fn credit_card() -> &'static Regex {
    static C: OnceLock<Regex> = OnceLock::new();
    C.get_or_init(|| Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{4}\b").unwrap())
}

/// Historical years (1700-2023). Excludes 2024+ to preserve current
/// timestamps in conversation. The cutoff bumps each year via the
/// release process — see FSD §10 for the operational note.
fn historical_year() -> &'static Regex {
    static C: OnceLock<Regex> = OnceLock::new();
    C.get_or_init(|| Regex::new(r"\b(?:1[7-9]\d{2}|20[0-1]\d|202[0-3])\b").unwrap())
}

/// Year-bearing programmatic identifiers — `foo_1989_bar`, etc. NER
/// doesn't tokenize these as natural language; the year regex alone
/// would only strip the year, leaving the topic-revealing flanking
/// tokens. This pattern eats the whole compound identifier.
///
/// Discipline:
///
/// 1. At least one flanking character on at least one side (so a
///    bare year falls through to `historical_year` and produces
///    `[YEAR]`, not `[IDENTIFIER]`).
/// 2. The flanking text must contain at least one alphabetic
///    character or underscore — otherwise long all-digit runs like
///    a 14-digit timestamp `20260322021153` (where the substring
///    `2021` falls in the historical range) would be eaten as an
///    identifier. Pure-digit context = structural data, not a
///    topic-revealing identifier.
fn year_identifier() -> &'static Regex {
    static C: OnceLock<Regex> = OnceLock::new();
    C.get_or_init(|| {
        Regex::new(
            r"(?x)
            \b
            (?:
                # at least one letter/underscore in the SAME hyphen-less
                # chunk on the left (any script — `\p{L}` catches CJK
                # so `1989年的事件` still collapses to `[IDENTIFIER]`)
                \w{0,40}[\p{L}_]\w{0,40}
                    (?:1[7-9]\d{2}|20[0-1]\d|202[0-3])
                    \w{0,40}
              |
                # alpha/underscore on the right
                \w{0,40}
                    (?:1[7-9]\d{2}|20[0-1]\d|202[0-3])
                    \w{0,40}[\p{L}_]\w{0,40}
            )
            \b
            ",
        )
        .unwrap()
    })
}

/// Apply all regex patterns to a string in the order: identifier →
/// year → structured PII. Identifier first because year is a
/// substring of identifier.
pub(super) fn scrub_string(s: &str, stats: &mut ScrubStats) -> String {
    let mut out = s.to_string();

    let mut count = |pat: &Regex, replacement: &str, text: String| -> String {
        let n = pat.find_iter(&text).count();
        if n > 0 {
            stats.regex_redactions += n;
            pat.replace_all(&text, replacement).to_string()
        } else {
            text
        }
    };

    out = count(year_identifier(), "[IDENTIFIER]", out);
    out = count(historical_year(), "[YEAR]", out);
    out = count(email(), "[EMAIL]", out);
    out = count(phone(), "[PHONE]", out);
    out = count(ipv4(), "[IP_ADDRESS]", out);
    out = count(url(), "[URL]", out);
    out = count(ssn(), "[SSN]", out);
    out = count(credit_card(), "[CREDIT_CARD]", out);

    out
}

/// Count residual historical-year matches in scrubbed output. Any
/// nonzero count means the regex pass missed something — caller
/// rejects the trace.
pub fn count_year_residue(value: &Value) -> usize {
    let mut total = 0usize;
    walk_strings(value, &mut |s| {
        total += historical_year().find_iter(s).count();
    });
    total
}

/// Check whether any operator-supplied probe term
/// (`CIRISLENS_LEAK_PROBES`, newline-separated) appears in the
/// scrubbed output. Returns `true` if any probe matched — caller
/// rejects.
///
/// The probe list is read from the env at call time; intentionally
/// not cached so operators can update the list without restarting
/// the service.
pub fn probe_match(value: &Value) -> bool {
    let probes_env = match env::var("CIRISLENS_LEAK_PROBES") {
        Ok(s) if !s.is_empty() => s,
        _ => return false,
    };
    let probes: Vec<String> = probes_env
        .split('\n')
        .filter(|p| !p.trim().is_empty())
        .map(|p| p.to_lowercase())
        .collect();

    let mut hit = false;
    walk_strings(value, &mut |s| {
        if hit {
            return;
        }
        let s_lower = s.to_lowercase();
        if probes.iter().any(|p| s_lower.contains(p)) {
            hit = true;
        }
    });
    hit
}

/// Visit every string leaf in a JSON value.
fn walk_strings<F: FnMut(&str)>(value: &Value, f: &mut F) {
    match value {
        Value::String(s) => f(s),
        Value::Array(arr) => arr.iter().for_each(|v| walk_strings(v, f)),
        Value::Object(obj) => obj.values().for_each(|v| walk_strings(v, f)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_year_redacts() {
        let mut s = ScrubStats::default();
        let out = scrub_string("Event in 1989", &mut s);
        assert_eq!(out, "Event in [YEAR]");
    }

    #[test]
    fn current_year_preserved() {
        let mut s = ScrubStats::default();
        let out = scrub_string("Today is 2026-04-25", &mut s);
        assert!(out.contains("2026"));
    }

    #[test]
    fn year_identifier_eats_topic_tokens() {
        let mut s = ScrubStats::default();
        let out = scrub_string("source: foo_1989_bar", &mut s);
        assert_eq!(out, "source: [IDENTIFIER]");
        assert!(!out.contains("foo"));
        assert!(!out.contains("bar"));
    }

    #[test]
    fn email_phone_ip() {
        let mut s = ScrubStats::default();
        let out = scrub_string("alice@example.com 555-123-4567 192.168.1.1", &mut s);
        assert!(out.contains("[EMAIL]"));
        assert!(out.contains("[PHONE]"));
        assert!(out.contains("[IP_ADDRESS]"));
        assert_eq!(s.regex_redactions, 3);
    }

    #[test]
    fn year_residue_check_finds_misses() {
        use serde_json::json;
        let v = json!({"escaped": "text with 1989 in it"});
        assert_eq!(count_year_residue(&v), 1);
    }

    // ── Regression cases: long-digit-string false positives observed in
    //    the production HF release corpus rescrub.

    #[test]
    fn phone_requires_separator_not_just_ten_digits() {
        let mut s = ScrubStats::default();
        let out = scrub_string("trace-th_seed_b11243fb-7d8-20260322030441", &mut s);
        assert!(
            !out.contains("[PHONE]"),
            "phone over-fired on timestamp: {out}",
        );
    }

    #[test]
    fn phone_with_separator_still_matches() {
        for p in [
            "(555) 123-4567",
            "555-123-4567",
            "555.123.4567",
            "+1-555-123-4567",
            "+1 555 123 4567",
            "+1 (555) 123-4567",
        ] {
            let mut s = ScrubStats::default();
            let out = scrub_string(p, &mut s);
            assert!(
                out.contains("[PHONE]"),
                "phone shape `{p}` was missed: {out}"
            );
        }
    }

    #[test]
    fn phone_skips_embedded_one_separator_digit_run() {
        let mut s = ScrubStats::default();
        let out = scrub_string(
            "trace-th_followup_th_follo_ffd15263-151-20260328091840",
            &mut s,
        );
        assert!(!out.contains("[PHONE]"), "phone over-fired: {out}");
        assert!(
            out.contains("20260328091840"),
            "structural id mangled: {out}"
        );
    }

    #[test]
    fn year_identifier_skips_pure_digit_runs() {
        let mut s = ScrubStats::default();
        let out = scrub_string("trace-th_seed_c633c320-36b-20260322021153", &mut s);
        assert!(
            !out.contains("[IDENTIFIER]"),
            "year-id over-fired on timestamp: {out}",
        );
        assert!(
            out.contains("20260322021153"),
            "structural id was mangled: {out}",
        );
    }

    #[test]
    fn year_identifier_still_eats_alpha_flanked_year() {
        let mut s = ScrubStats::default();
        let out = scrub_string("source: user_query_1989_topic", &mut s);
        assert_eq!(out, "source: [IDENTIFIER]");
    }

    #[test]
    fn year_identifier_eats_year_with_alpha_only_on_left() {
        let mut s = ScrubStats::default();
        let out = scrub_string("see article_1989", &mut s);
        assert_eq!(out, "see [IDENTIFIER]");
    }

    #[test]
    fn year_identifier_eats_year_with_alpha_only_on_right() {
        let mut s = ScrubStats::default();
        let out = scrub_string("see 1989_archive", &mut s);
        assert_eq!(out, "see [IDENTIFIER]");
    }
}
