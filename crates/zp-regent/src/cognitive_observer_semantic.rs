//! Cognitive Self-Observer — semantic claim classifier (P2.2.5-Shadow).
//!
//! Spec: `docs/design/COGNITIVE-SELF-OBSERVER-2026-07.md` §Extraction —
//! "Semantic classification second — for statements that don't match structural
//! patterns, an optional lightweight inference call classifies them into claim
//! classes."
//!
//! Companion to `cognitive_observer.rs` (P2.2 v1 pattern-matcher). Where P2.2
//! catches explicit forbidden-phrase matches from standing corrections, this
//! module extracts **semantic verifiable claims** from Regent's response —
//! factual assertions whose truth requires ground-truth verification rather
//! than pattern matching.
//!
//! ## Motivating cases (all confabulations captured in session logs 2026-07-24)
//!
//! - **Genesis pubkey confabulation.** Regent claimed operator Genesis pubkey
//!   `58449fc1…` when actual was `539839ff…`. Not a forbidden-phrase issue;
//!   a self-state factual claim requiring vault/config lookup.
//! - **chain_query capability confabulation.** Regent claimed to lack
//!   `chain_query` tool she has. Not a forbidden-phrase issue; a capability
//!   claim requiring delegation-state lookup.
//! - **Chain-state numerical confabulations.** "21,132 unsigned entries"
//!   (chain was 100% signed), "silent for 145 minutes" (continuous activity).
//!   Not forbidden phrases; factual claims requiring chain query.
//!
//! P2.2's pattern-matcher cannot catch these classes. P2.2.5's semantic
//! classifier extracts them structurally so verification (v2) can dispatch
//! against ground truth.
//!
//! ## v1 scope: extraction only
//!
//! This module produces `SemanticClaim` values from Regent's response text.
//! It does NOT verify claims against ground truth — that's v2, requires chain
//! access, delegation-state access, and cycle-composition-receipt access. Ship
//! extraction first, verification lands as its own arc.
//!
//! Extractors implemented in v1:
//!
//! 1. **Chain-state numerical claims** — "N unsigned entries", "chain has N
//!    entries", "silent for N minutes/hours", "N missed canaries"
//! 2. **Capability absence claims** — "I don't have access to X", "I lack the
//!    ability to X", "no X tool available", "cannot X"
//! 3. **Self-state pubkey claims** — hex-looking strings claimed as pubkey,
//!    fingerprint, or Genesis identifier
//!
//! ## Composition with P2.2 pattern-matcher
//!
//! Both extractors run in parallel on the same Regent response. Their results
//! compose into a combined verification report. The shadow-evaluation angle
//! (per SHADOW-EVALUATION-PRIMITIVE-2026-07 Context 5) is that pattern-matcher
//! findings and semantic-classifier findings can be chain-anchored side-by-side
//! as candidate-vs-control evidence over time — informing operator ceremony on
//! extractor calibration without autonomous policy change.
//!
//! ## Deterministic only, no inference
//!
//! v1 uses deterministic string parsing only — no inference dependency. The
//! spec's "Semantic classification second — optional lightweight inference
//! call" is a future path once cost/latency budgets are established. v1's
//! deterministic extractors give the substrate a working semantic pipeline
//! that composes forward with inference-assisted extraction as v3.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Class of semantic claim (per COGNITIVE-SELF-OBSERVER §Classes of claims).
///
/// v1 implements extractors for classes 1, 6, 7. Classes 2 (diagnosis), 3
/// (interpretation), 4 (precedent), 5 (commitment) are deferred pending
/// ontology (2, 3), chain-query verification plumbing (4), and commitment
/// primitive infrastructure (5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticClaimClass {
    /// Class 1 — assertions about chain state (counts, timings, patterns).
    ChainState,
    /// Class 2 — assertions about cause or nature of substrate events. (v2+)
    Diagnosis,
    /// Class 3 — assertions about pattern meaning or implication. (v2+)
    Interpretation,
    /// Class 4 — assertions about Regent's own history. (v2+)
    Precedent,
    /// Class 5 — assertions about promises or commitments. (v2+)
    Commitment,
    /// Class 6 — assertions about Regent's own knowledge, memory, context.
    SelfState,
    /// Class 7 — assertions about Regent's capabilities.
    Capability,
}

/// Sub-shape for chain-state numerical claims.
///
/// Captures the structured value so verification can compare a specific
/// number against a specific chain-query result without re-parsing prose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainStateClaim {
    /// What the claim quantifies (e.g., "unsigned_entries", "silent_minutes").
    pub metric: String,
    /// The numeric value Regent asserted.
    pub value: u64,
    /// Unit of the value (e.g., "entries", "minutes", "canaries").
    pub unit: String,
}

/// Sub-shape for capability absence claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityClaim {
    /// The tool or capability name Regent claimed she lacks or possesses.
    pub subject: String,
    /// True if Regent claimed absence, false if claimed presence.
    pub asserted_absence: bool,
}

/// Sub-shape for self-state pubkey/hex-identifier claims.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PubkeyClaim {
    /// The hex string Regent asserted as pubkey / fingerprint / Genesis ID.
    pub claimed_hex: String,
    /// Kind of identifier claimed ("pubkey", "fingerprint", "genesis").
    pub identifier_kind: String,
}

/// Class-specific structured payload for a semantic claim.
///
/// Each variant corresponds to a `SemanticClaimClass` variant that v1
/// extracts. Verification (v2) dispatches on this variant to the class's
/// ground-truth query path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SemanticClaimPayload {
    ChainState(ChainStateClaim),
    Capability(CapabilityClaim),
    Pubkey(PubkeyClaim),
}

/// A single semantic claim extracted from Regent's response.
///
/// v1 carries the extracted structured value plus verbatim excerpt for
/// operator-facing display. v2 will add a `verification` field with the
/// ground-truth query result and pass/fail assessment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticClaim {
    /// Claim class per spec Classes-of-claims taxonomy.
    pub class: SemanticClaimClass,
    /// Structured payload — specific to class.
    pub payload: SemanticClaimPayload,
    /// Verbatim excerpt from the response where the claim was extracted.
    /// Used for operator-facing display and downstream verification context.
    pub excerpt: String,
    /// Byte offset of the excerpt in the source response.
    /// Enables re-locating the claim for operator review.
    pub offset: usize,
}

/// Report from a semantic-classifier pass over one Regent response.
///
/// Parallel to `ObserverReport` (P2.2 pattern-matcher). Both run on the same
/// response text; a downstream chain-anchoring pass can emit both sets as
/// shadow-evaluation candidate-vs-control evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticExtractionReport {
    /// When the extraction ran.
    pub extracted_at: DateTime<Utc>,
    /// All extracted semantic claims across all classes.
    pub claims: Vec<SemanticClaim>,
    /// Per-class counts for quick summary logging.
    pub class_counts: SemanticClassCounts,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SemanticClassCounts {
    pub chain_state: usize,
    pub capability: usize,
    pub self_state: usize,
}

impl SemanticExtractionReport {
    /// One-line summary for inline event logging.
    pub fn summary(&self) -> String {
        format!(
            "semantic_extracted claims={} chain_state={} capability={} self_state={}",
            self.claims.len(),
            self.class_counts.chain_state,
            self.class_counts.capability,
            self.class_counts.self_state,
        )
    }
}

/// Extract all semantic claims from a Regent response.
///
/// v1 implementation runs the three class extractors in sequence. Order does
/// not affect correctness — claims from different classes cannot overlap
/// structurally (a chain-state numerical assertion cannot also be a capability
/// absence claim).
pub fn extract_semantic_claims(response: &str) -> SemanticExtractionReport {
    let mut claims: Vec<SemanticClaim> = Vec::new();

    claims.extend(extract_chain_state_claims(response));
    claims.extend(extract_capability_claims(response));
    claims.extend(extract_pubkey_claims(response));

    let mut class_counts = SemanticClassCounts::default();
    for c in &claims {
        match c.class {
            SemanticClaimClass::ChainState => class_counts.chain_state += 1,
            SemanticClaimClass::Capability => class_counts.capability += 1,
            SemanticClaimClass::SelfState => class_counts.self_state += 1,
            _ => {}
        }
    }

    SemanticExtractionReport {
        extracted_at: Utc::now(),
        claims,
        class_counts,
    }
}

// ── Class 1: chain-state numerical claims ──────────────────────────────────

/// Extract chain-state numerical claims — assertions about counts, timings,
/// or patterns quantified over the chain.
///
/// Patterns matched (case-insensitive):
/// - `<N> unsigned entries` → metric=unsigned_entries, unit=entries
/// - `<N> entries in the chain` / `chain has <N> entries` → metric=chain_entries
/// - `silent for <N> minutes/hours/seconds` → metric=silent_duration, unit=<time>
/// - `<N> missed canaries` → metric=missed_canaries, unit=canaries
/// - `<N> chain receipts` → metric=chain_receipts, unit=receipts
///
/// Numbers may contain commas as thousands separators ("21,132").
pub fn extract_chain_state_claims(response: &str) -> Vec<SemanticClaim> {
    let mut out: Vec<SemanticClaim> = Vec::new();

    // Structured patterns: (leading text, unit-word, metric-name)
    //
    // The extractor finds a number preceding a phrase like "unsigned entries"
    // and produces a structured claim. Multiple pattern-variants per metric
    // capture common phrasings without regex.
    let patterns: &[(&str, &str)] = &[
        ("unsigned entries", "unsigned_entries"),
        ("unsigned receipts", "unsigned_entries"),
        ("chain entries", "chain_entries"),
        ("entries in the chain", "chain_entries"),
        ("entries on the chain", "chain_entries"),
        ("chain receipts", "chain_receipts"),
        ("missed canaries", "missed_canaries"),
        ("missed canary", "missed_canaries"),
    ];

    for (phrase, metric) in patterns {
        for hit in find_number_before_phrase(response, phrase) {
            out.push(SemanticClaim {
                class: SemanticClaimClass::ChainState,
                payload: SemanticClaimPayload::ChainState(ChainStateClaim {
                    metric: (*metric).into(),
                    value: hit.value,
                    unit: last_word(phrase).into(),
                }),
                excerpt: hit.excerpt,
                offset: hit.offset,
            });
        }
    }

    // Silence-duration: "silent for N minutes/hours/seconds"
    for hit in find_silence_duration(response) {
        out.push(SemanticClaim {
            class: SemanticClaimClass::ChainState,
            payload: SemanticClaimPayload::ChainState(ChainStateClaim {
                metric: "silent_duration".into(),
                value: hit.value,
                unit: hit.unit,
            }),
            excerpt: hit.excerpt,
            offset: hit.offset,
        });
    }

    out
}

/// One extraction hit — the numeric value plus its verbatim excerpt.
struct NumberHit {
    value: u64,
    excerpt: String,
    offset: usize,
}

/// Find occurrences of a number preceding a phrase, e.g. "21,132 unsigned entries".
///
/// Case-insensitive on the phrase, tolerant of commas in the number.
fn find_number_before_phrase(text: &str, phrase: &str) -> Vec<NumberHit> {
    let mut out: Vec<NumberHit> = Vec::new();
    let text_lower = text.to_lowercase();
    let phrase_lower = phrase.to_lowercase();

    let mut search_from = 0usize;
    while let Some(rel) = text_lower[search_from..].find(&phrase_lower) {
        let phrase_start = search_from + rel;
        let phrase_end = phrase_start + phrase.len();

        // Walk backwards from phrase_start to find the immediately-preceding number.
        if let Some((num_start, value)) = parse_number_before(text, phrase_start) {
            // Compose excerpt with ~24 chars of trailing context.
            let excerpt_end = (phrase_end + 24).min(text.len());
            let excerpt_end = safe_char_boundary(text, excerpt_end);
            let excerpt = text[num_start..excerpt_end].trim().to_string();
            out.push(NumberHit {
                value,
                excerpt,
                offset: num_start,
            });
        }

        search_from = phrase_end;
    }

    out
}

/// Parse the digit-and-comma sequence immediately preceding `end`, skipping
/// whitespace. Returns the start byte offset and parsed value.
fn parse_number_before(text: &str, end: usize) -> Option<(usize, u64)> {
    let bytes = text.as_bytes();

    // Skip whitespace backwards.
    let mut cursor = end;
    while cursor > 0 && bytes[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }
    let digit_end = cursor;

    // Walk backwards over digits and commas.
    while cursor > 0 {
        let b = bytes[cursor - 1];
        if b.is_ascii_digit() || b == b',' {
            cursor -= 1;
        } else {
            break;
        }
    }
    let digit_start = cursor;

    if digit_start == digit_end {
        return None;
    }

    // Parse: strip commas.
    let raw = &text[digit_start..digit_end];
    let stripped: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if stripped.is_empty() {
        return None;
    }
    let value: u64 = stripped.parse().ok()?;
    Some((digit_start, value))
}

/// Extract silence-duration claims: "silent for N minutes/hours/seconds".
struct DurationHit {
    value: u64,
    unit: String,
    excerpt: String,
    offset: usize,
}

fn find_silence_duration(text: &str) -> Vec<DurationHit> {
    let mut out: Vec<DurationHit> = Vec::new();
    let text_lower = text.to_lowercase();
    let anchor = "silent for ";

    let mut search_from = 0usize;
    while let Some(rel) = text_lower[search_from..].find(anchor) {
        let anchor_start = search_from + rel;
        let after_anchor = anchor_start + anchor.len();

        // Parse "N " (comma-tolerant digits followed by whitespace).
        let (num_end, value) = match parse_number_after(text, after_anchor) {
            Some(x) => x,
            None => {
                search_from = after_anchor;
                continue;
            }
        };

        // Skip whitespace after number.
        let mut unit_start = num_end;
        while unit_start < text.len()
            && text.as_bytes()[unit_start].is_ascii_whitespace()
        {
            unit_start += 1;
        }

        // Read unit word (alphabetic, trimmed of trailing 's').
        let mut unit_end = unit_start;
        while unit_end < text.len() && text.as_bytes()[unit_end].is_ascii_alphabetic() {
            unit_end += 1;
        }
        if unit_end == unit_start {
            search_from = after_anchor;
            continue;
        }

        let raw_unit = text[unit_start..unit_end].to_lowercase();
        let normalized_unit = match raw_unit.trim_end_matches('s') {
            "second" => "seconds".to_string(),
            "minute" => "minutes".to_string(),
            "hour" => "hours".to_string(),
            "day" => "days".to_string(),
            other => other.to_string(), // pass-through for unrecognized
        };

        // Only count recognized time units to avoid false positives like
        // "silent for a moment" or "silent for now".
        let recognized = matches!(
            normalized_unit.as_str(),
            "seconds" | "minutes" | "hours" | "days"
        );

        if recognized {
            let excerpt_end = safe_char_boundary(text, (unit_end + 8).min(text.len()));
            let excerpt = text[anchor_start..excerpt_end].trim().to_string();
            out.push(DurationHit {
                value,
                unit: normalized_unit,
                excerpt,
                offset: anchor_start,
            });
        }

        search_from = unit_end;
    }

    out
}

/// Parse digits (comma-tolerant) starting at `start`, returning end offset and value.
fn parse_number_after(text: &str, start: usize) -> Option<(usize, u64)> {
    let bytes = text.as_bytes();
    let mut cursor = start;
    while cursor < bytes.len() {
        let b = bytes[cursor];
        if b.is_ascii_digit() || b == b',' {
            cursor += 1;
        } else {
            break;
        }
    }
    if cursor == start {
        return None;
    }
    let raw = &text[start..cursor];
    let stripped: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if stripped.is_empty() {
        return None;
    }
    let value: u64 = stripped.parse().ok()?;
    Some((cursor, value))
}

// ── Class 7: capability absence claims ─────────────────────────────────────

/// Extract capability absence claims — Regent asserting she lacks a specific
/// tool or ability.
///
/// Patterns matched (case-insensitive at the anchor phrase):
/// - "I don't have access to X" / "I do not have access to X"
/// - "I lack access to X" / "I lack the ability to X"
/// - "no X tool" / "no X available"
/// - "I can't <verb> X" / "I cannot <verb> X" (verb-adjacent form)
/// - "I don't have X" (simple absence)
///
/// The extracted `subject` is the token or short phrase immediately following
/// the anchor. Downstream verification (v2) compares against actual delegation
/// state to detect false-absence confabulations.
pub fn extract_capability_claims(response: &str) -> Vec<SemanticClaim> {
    let mut out: Vec<SemanticClaim> = Vec::new();

    // Absence-claim anchor phrases. Each anchor's subject is the phrase up
    // to sentence-terminator punctuation or newline.
    let absence_anchors: &[&str] = &[
        "i don't have access to ",
        "i do not have access to ",
        "i lack access to ",
        "i lack the ability to ",
        "i don't have the ability to ",
        "i don't have a ",
        "i don't have the ",
        "i do not have the ",
        "i don't have any ",
        "no access to ",
    ];

    for anchor in absence_anchors {
        for hit in find_subject_after_anchor(response, anchor) {
            out.push(SemanticClaim {
                class: SemanticClaimClass::Capability,
                payload: SemanticClaimPayload::Capability(CapabilityClaim {
                    subject: hit.subject,
                    asserted_absence: true,
                }),
                excerpt: hit.excerpt,
                offset: hit.offset,
            });
        }
    }

    out
}

struct SubjectHit {
    subject: String,
    excerpt: String,
    offset: usize,
}

fn find_subject_after_anchor(text: &str, anchor: &str) -> Vec<SubjectHit> {
    let mut out: Vec<SubjectHit> = Vec::new();
    let text_lower = text.to_lowercase();

    let mut search_from = 0usize;
    while let Some(rel) = text_lower[search_from..].find(anchor) {
        let anchor_start = search_from + rel;
        let subject_start = anchor_start + anchor.len();

        // Read subject up to sentence-terminator or newline.
        let mut subject_end = subject_start;
        while subject_end < text.len() {
            let b = text.as_bytes()[subject_end];
            if b == b'.' || b == b',' || b == b'\n' || b == b';' || b == b'!' || b == b'?' {
                break;
            }
            subject_end += 1;
        }

        // Bound subject to reasonable length (avoid grabbing entire paragraphs
        // if the sentence goes long). Take up to 5 words.
        let subject_raw = text[subject_start..subject_end].trim();
        let subject = subject_raw
            .split_whitespace()
            .take(5)
            .collect::<Vec<_>>()
            .join(" ");

        if !subject.is_empty() {
            let excerpt = text[anchor_start..subject_end.min(anchor_start + 120)]
                .trim()
                .to_string();
            out.push(SubjectHit {
                subject,
                excerpt,
                offset: anchor_start,
            });
        }

        search_from = if subject_end > anchor_start {
            subject_end
        } else {
            anchor_start + anchor.len()
        };
    }

    out
}

// ── Class 6: self-state pubkey claims ──────────────────────────────────────

/// Extract pubkey / fingerprint / Genesis-identifier hex-string claims.
///
/// Motivating case: Regent confabulated an operator Genesis pubkey with wrong
/// hex digits. Downstream verification (v2) compares claimed hex against
/// actual vault/config-loaded operator Genesis pubkey.
///
/// Patterns matched (case-insensitive at anchor):
/// - "pubkey <HEX>" / "public key <HEX>"
/// - "fingerprint <HEX>"
/// - "genesis <HEX>" (as identifier — "Genesis pubkey X" also caught by
///   pubkey anchor)
/// - "signed by <HEX>"
///
/// Hex string qualifies as: sequence of ≥8 hex chars, optionally followed by
/// `…` (ellipsis) or truncation-indicator. Shorter matches ignored (too many
/// false positives — 8-hex-char is minimum for meaningful fingerprint claim).
pub fn extract_pubkey_claims(response: &str) -> Vec<SemanticClaim> {
    let mut out: Vec<SemanticClaim> = Vec::new();

    let anchors: &[(&str, &str)] = &[
        ("pubkey ", "pubkey"),
        ("public key ", "pubkey"),
        ("fingerprint ", "fingerprint"),
        ("signed by ", "pubkey"),
    ];

    for (anchor, kind) in anchors {
        for hit in find_hex_after_anchor(response, anchor) {
            out.push(SemanticClaim {
                class: SemanticClaimClass::SelfState,
                payload: SemanticClaimPayload::Pubkey(PubkeyClaim {
                    claimed_hex: hit.hex,
                    identifier_kind: (*kind).to_string(),
                }),
                excerpt: hit.excerpt,
                offset: hit.offset,
            });
        }
    }

    out
}

struct HexHit {
    hex: String,
    excerpt: String,
    offset: usize,
}

fn find_hex_after_anchor(text: &str, anchor: &str) -> Vec<HexHit> {
    let mut out: Vec<HexHit> = Vec::new();
    let text_lower = text.to_lowercase();
    let anchor_lower = anchor.to_lowercase();

    let mut search_from = 0usize;
    while let Some(rel) = text_lower[search_from..].find(&anchor_lower) {
        let anchor_start = search_from + rel;
        let hex_start = anchor_start + anchor.len();

        // Skip optional prefix characters commonly preceding hex ("is ", ":", "= ", "'", etc.).
        let mut cursor = hex_start;
        while cursor < text.len() {
            let b = text.as_bytes()[cursor];
            if b == b' ' || b == b'`' || b == b'\'' || b == b'"' || b == b':' || b == b'=' {
                cursor += 1;
            } else {
                break;
            }
        }
        let hex_actual_start = cursor;

        // Read hex chars.
        while cursor < text.len() && text.as_bytes()[cursor].is_ascii_hexdigit() {
            cursor += 1;
        }
        let hex_end = cursor;

        let hex_len = hex_end - hex_actual_start;
        if hex_len >= 8 {
            let hex = text[hex_actual_start..hex_end].to_string();
            let excerpt_end = safe_char_boundary(text, (hex_end + 8).min(text.len()));
            let excerpt = text[anchor_start..excerpt_end].trim().to_string();
            out.push(HexHit {
                hex,
                excerpt,
                offset: anchor_start,
            });
        }

        search_from = if hex_end > anchor_start {
            hex_end
        } else {
            anchor_start + anchor.len()
        };
    }

    out
}

// ── Utilities ──────────────────────────────────────────────────────────────

fn last_word(phrase: &str) -> &str {
    phrase.split_whitespace().last().unwrap_or(phrase)
}

/// Round down `idx` to the nearest UTF-8 char boundary in `text`.
/// Prevents panics on multi-byte character truncation.
fn safe_char_boundary(text: &str, idx: usize) -> usize {
    let mut i = idx.min(text.len());
    while i > 0 && !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Chain-state extraction ──

    #[test]
    fn extracts_unsigned_entries_count() {
        let response = "Sentinel reports 12,893 unsigned entries at severity Critical.";
        let claims = extract_chain_state_claims(response);
        assert_eq!(claims.len(), 1);
        match &claims[0].payload {
            SemanticClaimPayload::ChainState(cs) => {
                assert_eq!(cs.metric, "unsigned_entries");
                assert_eq!(cs.value, 12893);
                assert_eq!(cs.unit, "entries");
            }
            _ => panic!("expected ChainState payload"),
        }
    }

    #[test]
    fn extracts_bare_unsigned_entries() {
        let response = "There are 42 unsigned entries on chain.";
        let claims = extract_chain_state_claims(response);
        assert_eq!(claims.len(), 1);
        match &claims[0].payload {
            SemanticClaimPayload::ChainState(cs) => assert_eq!(cs.value, 42),
            _ => panic!("expected ChainState"),
        }
    }

    #[test]
    fn extracts_silence_duration_minutes() {
        let response = "Chain has been silent for 145 minutes.";
        let claims = extract_chain_state_claims(response);
        assert_eq!(claims.len(), 1);
        match &claims[0].payload {
            SemanticClaimPayload::ChainState(cs) => {
                assert_eq!(cs.metric, "silent_duration");
                assert_eq!(cs.value, 145);
                assert_eq!(cs.unit, "minutes");
            }
            _ => panic!("expected ChainState payload"),
        }
    }

    #[test]
    fn extracts_silence_duration_hours() {
        let response = "The observer was silent for 3 hours before recovery.";
        let claims = extract_chain_state_claims(response);
        assert_eq!(claims.len(), 1);
        match &claims[0].payload {
            SemanticClaimPayload::ChainState(cs) => {
                assert_eq!(cs.value, 3);
                assert_eq!(cs.unit, "hours");
            }
            _ => panic!("expected ChainState payload"),
        }
    }

    #[test]
    fn ignores_silent_for_non_time_phrasing() {
        // "silent for now" / "silent for a moment" should not extract as duration.
        let response = "The system will remain silent for now until you signal.";
        let claims = extract_chain_state_claims(response);
        assert_eq!(claims.len(), 0);
    }

    #[test]
    fn extracts_missed_canaries_count() {
        let response = "There were 7 missed canaries in the last hour.";
        let claims = extract_chain_state_claims(response);
        assert_eq!(claims.len(), 1);
        match &claims[0].payload {
            SemanticClaimPayload::ChainState(cs) => {
                assert_eq!(cs.metric, "missed_canaries");
                assert_eq!(cs.value, 7);
            }
            _ => panic!("expected ChainState payload"),
        }
    }

    #[test]
    fn extracts_multiple_chain_state_claims_in_one_response() {
        let response = "Chain has 5,000 chain entries and 3 unsigned entries currently.";
        let claims = extract_chain_state_claims(response);
        assert_eq!(claims.len(), 2);
    }

    #[test]
    fn does_not_extract_without_number() {
        let response = "There are unsigned entries on the chain.";
        let claims = extract_chain_state_claims(response);
        assert_eq!(claims.len(), 0);
    }

    // ── Capability extraction ──

    #[test]
    fn extracts_capability_absence_dont_have_access() {
        let response = "I don't have access to chain_query in this scope.";
        let claims = extract_capability_claims(response);
        assert_eq!(claims.len(), 1);
        match &claims[0].payload {
            SemanticClaimPayload::Capability(cap) => {
                assert!(cap.asserted_absence);
                assert!(cap.subject.contains("chain_query"));
            }
            _ => panic!("expected Capability payload"),
        }
    }

    #[test]
    fn extracts_capability_absence_lack_ability() {
        let response = "I lack the ability to invoke batch_sign directly.";
        let claims = extract_capability_claims(response);
        assert_eq!(claims.len(), 1);
        match &claims[0].payload {
            SemanticClaimPayload::Capability(cap) => {
                assert!(cap.asserted_absence);
                assert!(cap.subject.contains("invoke batch_sign"));
            }
            _ => panic!("expected Capability payload"),
        }
    }

    #[test]
    fn extracts_capability_absence_do_not_have_access() {
        let response = "I do not have access to that tool.";
        let claims = extract_capability_claims(response);
        assert_eq!(claims.len(), 1);
    }

    #[test]
    fn subject_bounded_to_five_words() {
        // Subject-take should stop at 5 words even if sentence runs long.
        let response = "I don't have access to the substrate integrity verification subsystem module which handles chain checks.";
        let claims = extract_capability_claims(response);
        assert_eq!(claims.len(), 1);
        match &claims[0].payload {
            SemanticClaimPayload::Capability(cap) => {
                let word_count = cap.subject.split_whitespace().count();
                assert!(
                    word_count <= 5,
                    "subject should be bounded to 5 words, got {}",
                    word_count
                );
            }
            _ => panic!("expected Capability payload"),
        }
    }

    #[test]
    fn no_false_positive_on_assertion_of_capability() {
        // Present-tense capability claims should NOT match absence anchors.
        let response = "I have access to chain_query and use it regularly.";
        let claims = extract_capability_claims(response);
        assert_eq!(claims.len(), 0);
    }

    // ── Pubkey extraction ──

    #[test]
    fn extracts_pubkey_hex_claim() {
        let response = "Your Genesis pubkey is 539839ff1234abcd.";
        let claims = extract_pubkey_claims(response);
        assert_eq!(claims.len(), 1);
        match &claims[0].payload {
            SemanticClaimPayload::Pubkey(pk) => {
                assert_eq!(pk.claimed_hex, "539839ff1234abcd");
                assert_eq!(pk.identifier_kind, "pubkey");
            }
            _ => panic!("expected Pubkey payload"),
        }
    }

    #[test]
    fn extracts_confabulated_pubkey_case_from_session_log() {
        // Reproduces the actual confabulation from 2026-07-24 session:
        // Regent claimed pubkey 58449fc1... when actual was 539839ff...
        let response =
            "The operator's Genesis pubkey is 58449fc1abcdef01 and should be verified.";
        let claims = extract_pubkey_claims(response);
        assert_eq!(claims.len(), 1);
        match &claims[0].payload {
            SemanticClaimPayload::Pubkey(pk) => {
                assert_eq!(pk.claimed_hex, "58449fc1abcdef01");
            }
            _ => panic!("expected Pubkey payload"),
        }
    }

    #[test]
    fn extracts_fingerprint_hex_claim() {
        let response = "The tool has fingerprint deadbeefcafe1234 registered.";
        let claims = extract_pubkey_claims(response);
        assert_eq!(claims.len(), 1);
        match &claims[0].payload {
            SemanticClaimPayload::Pubkey(pk) => {
                assert_eq!(pk.identifier_kind, "fingerprint");
                assert_eq!(pk.claimed_hex, "deadbeefcafe1234");
            }
            _ => panic!("expected Pubkey payload"),
        }
    }

    #[test]
    fn extracts_signed_by_hex_claim() {
        let response = "Receipt was signed by 907975cef11111 at that time.";
        let claims = extract_pubkey_claims(response);
        assert_eq!(claims.len(), 1);
    }

    #[test]
    fn ignores_short_hex_strings() {
        // Less than 8 hex chars — too many false positives on incidental hex.
        let response = "The pubkey abc123 came up in the log.";
        let claims = extract_pubkey_claims(response);
        assert_eq!(claims.len(), 0);
    }

    #[test]
    fn ignores_pubkey_without_hex() {
        let response = "Your Genesis pubkey is stored in the vault.";
        let claims = extract_pubkey_claims(response);
        assert_eq!(claims.len(), 0);
    }

    // ── Combined extraction ──

    #[test]
    fn combined_extractor_produces_all_classes() {
        let response = "\
Chain has 42 unsigned entries. \
I don't have access to batch_sign. \
Your Genesis pubkey is 539839ff1234abcd.\
";
        let report = extract_semantic_claims(response);
        assert_eq!(report.claims.len(), 3);
        assert_eq!(report.class_counts.chain_state, 1);
        assert_eq!(report.class_counts.capability, 1);
        assert_eq!(report.class_counts.self_state, 1);
    }

    #[test]
    fn combined_extractor_empty_response_produces_empty_report() {
        let report = extract_semantic_claims("");
        assert!(report.claims.is_empty());
        assert_eq!(report.class_counts.chain_state, 0);
        assert_eq!(report.class_counts.capability, 0);
        assert_eq!(report.class_counts.self_state, 0);
    }

    #[test]
    fn combined_extractor_response_without_claims_produces_empty_report() {
        let response = "Hello, how can I help you today? I'm here to assist.";
        let report = extract_semantic_claims(response);
        assert!(report.claims.is_empty());
    }

    #[test]
    fn extraction_report_summary_format_is_stable() {
        let response = "Chain has 42 unsigned entries.";
        let report = extract_semantic_claims(response);
        let summary = report.summary();
        assert!(summary.contains("semantic_extracted"));
        assert!(summary.contains("claims=1"));
        assert!(summary.contains("chain_state=1"));
        assert!(summary.contains("capability=0"));
        assert!(summary.contains("self_state=0"));
    }

    #[test]
    fn class_counts_match_claims_len_across_mixed_extractions() {
        // Property-check: sum of per-class counts should equal claims.len()
        // for any input that only produces v1-supported classes.
        let response = "\
There are 100 unsigned entries. \
I don't have access to tool_a. \
I don't have access to tool_b. \
Pubkey deadbeef12345678 is invalid.\
";
        let report = extract_semantic_claims(response);
        let sum = report.class_counts.chain_state
            + report.class_counts.capability
            + report.class_counts.self_state;
        assert_eq!(sum, report.claims.len());
        assert_eq!(report.class_counts.chain_state, 1);
        assert_eq!(report.class_counts.capability, 2);
        assert_eq!(report.class_counts.self_state, 1);
    }

    // ── UTF-8 safety ──

    #[test]
    fn utf8_boundary_safe_on_multibyte_chars() {
        // Ensure excerpt-truncation doesn't panic on multi-byte characters.
        let response = "Chain has 5 unsigned entries — with an em-dash — nearby.";
        let claims = extract_chain_state_claims(response);
        assert_eq!(claims.len(), 1);
        // Excerpt should be a valid str.
        assert!(!claims[0].excerpt.is_empty());
    }
}
