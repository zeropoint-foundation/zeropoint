//! Cognitive Self-Observer — post-emission verification of Regent's outputs
//! against active standing corrections.
//!
//! Spec: `docs/design/COGNITIVE-SELF-OBSERVER-2026-07.md`
//! Companion to P2.1's standing correction pipeline. Where P2.1 puts corrections
//! into Regent's context, P2.2 verifies she respected them post-emission.
//!
//! ## Scope (v1)
//!
//! Pattern-based violation detection against active standing corrections. This
//! is the minimum viable observer — it catches explicit forbidden-phrase
//! violations (proper nouns, quoted phrases from a correction's negation field)
//! without requiring semantic understanding or ontology cross-reference.
//!
//! Deferred to later Phase 2 items:
//!   - Class 2 diagnosis verification (needs Cartographer ontology)
//!   - Class 5 commitment verification, *fulfillment* half — did a promise
//!     come true (needs P2.4 commitment primitives). The *enactment* half
//!     — "I have done X" emitted by a cycle that dispatched nothing — is
//!     implemented below and needs no new primitive: the cycle's own
//!     record is the authoritative source.
//!   - Class 7 capability verification (P2.3 Claim Verifier)
//!   - Semantic-assisted extraction via inference
//!   - Circuit breaker integration (L1-L4 escalation)
//!   - Auto-proposal of standing corrections from confabulation patterns
//!
//! ## Extraction heuristics
//!
//! From a correction's `content.negation` field, the observer extracts two
//! classes of pattern:
//!
//! 1. **Quoted phrases** (single or double quotes) — high-confidence markers.
//!    A prohibition correction with negation `Do not open with 'good morning'`
//!    yields the pattern `good morning` for case-insensitive substring matching.
//! 2. **Proper-noun tokens** — capitalized identifiers, version numbers, and
//!    hyphenated compounds. `Do not claim to be running GLM 5.2` yields the
//!    pattern `GLM 5.2` for case-sensitive substring matching.
//!
//! Neither heuristic is complete; both are fast, deterministic, and produce
//! meaningful signal for the initial correction corpus. The Layer B pattern
//! specifications per class in the spec are the natural evolution path.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::corrections::{ActiveStandingCorrection, CorrectionType, StandingCorrection};

/// A single extracted pattern from a correction's negation field.
///
/// Patterns are used to substring-match against Regent's response text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverPattern {
    /// The correction this pattern derives from.
    pub correction_id: String,
    /// Correction type — determines severity of matches.
    pub correction_type: CorrectionType,
    /// Extraction class — quoted phrase or proper-noun-like token.
    pub extraction: PatternExtraction,
    /// The pattern text to match.
    pub pattern: String,
    /// Whether to match case-sensitively.
    pub case_sensitive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternExtraction {
    /// Phrase extracted from single or double quotes in the negation.
    QuotedPhrase,
    /// Capitalized identifier / version / hyphenated proper-noun token.
    ProperNoun,
}

/// A detected violation of a standing correction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Correction whose negation was matched.
    pub correction_id: String,
    /// Correction type at issue.
    pub correction_type: CorrectionType,
    /// Correction domain for context.
    pub domain: String,
    /// The pattern that matched.
    pub matched_pattern: String,
    /// Extraction class of the matched pattern.
    pub extraction: PatternExtraction,
    /// Severity — derived from correction_type and priority.
    pub severity: ViolationSeverity,
    /// Short excerpt (with byte offset context) of where the match occurred.
    pub excerpt: String,
}

/// Violation severity ordering.
///
/// Maps to spec §"Comparison" severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ViolationSeverity {
    Informational,
    Warning,
    Critical,
}

/// The observer's per-response report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverReport {
    /// When the verification ran.
    pub verified_at: DateTime<Utc>,
    /// How many corrections were checked.
    pub corrections_checked: usize,
    /// How many patterns were extracted across all corrections.
    pub patterns_checked: usize,
    /// Detected violations (empty when Regent output is clean).
    pub violations: Vec<Violation>,
    /// Highest severity across all violations (Informational when clean).
    pub max_severity: ViolationSeverity,
}

impl ObserverReport {
    /// True if the response passed all verification checks.
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }

    /// Cheap one-line summary for inline event logging.
    pub fn summary(&self) -> String {
        if self.violations.is_empty() {
            format!(
                "clean corrections={} patterns={}",
                self.corrections_checked, self.patterns_checked
            )
        } else {
            format!(
                "VIOLATIONS={} corrections={} patterns={} max={:?}",
                self.violations.len(),
                self.corrections_checked,
                self.patterns_checked,
                self.max_severity
            )
        }
    }
}

/// Verify Regent's response text against a set of active standing corrections.
///
/// The primary entry point for the observer. Extracts patterns from each
/// active correction, substring-matches against the response, produces an
/// `ObserverReport`.
pub fn verify_against_corrections(
    response: &str,
    corrections: &[ActiveStandingCorrection],
) -> ObserverReport {
    let mut all_patterns: Vec<ObserverPattern> = Vec::new();
    for active in corrections {
        all_patterns.extend(extract_patterns(&active.correction));
    }

    let mut violations: Vec<Violation> = Vec::new();
    for pattern in &all_patterns {
        if let Some(excerpt) = match_pattern(response, pattern) {
            // Find the correction so we can capture its domain.
            let (domain, priority) = corrections
                .iter()
                .find(|c| c.correction.correction_id == pattern.correction_id)
                .map(|c| (c.correction.domain.clone(), c.correction.priority))
                .unwrap_or_default();

            violations.push(Violation {
                correction_id: pattern.correction_id.clone(),
                correction_type: pattern.correction_type,
                domain,
                matched_pattern: pattern.pattern.clone(),
                extraction: pattern.extraction,
                severity: severity_for(pattern.correction_type, priority, pattern.extraction),
                excerpt,
            });
        }
    }

    let max_severity = violations
        .iter()
        .map(|v| v.severity)
        .max()
        .unwrap_or(ViolationSeverity::Informational);

    ObserverReport {
        verified_at: Utc::now(),
        corrections_checked: corrections.len(),
        patterns_checked: all_patterns.len(),
        violations,
        max_severity,
    }
}

/// Extract observation patterns from a single standing correction.
///
/// v1 heuristic: pull quoted phrases (single or double quotes) and
/// proper-noun-like tokens from the negation field. Corrections without a
/// negation return an empty pattern set.
pub fn extract_patterns(correction: &StandingCorrection) -> Vec<ObserverPattern> {
    let negation = match &correction.content.negation {
        Some(n) => n,
        None => return Vec::new(),
    };

    let mut patterns: Vec<ObserverPattern> = Vec::new();

    for phrase in extract_quoted_phrases(negation) {
        patterns.push(ObserverPattern {
            correction_id: correction.correction_id.clone(),
            correction_type: correction.correction_type,
            extraction: PatternExtraction::QuotedPhrase,
            pattern: phrase,
            case_sensitive: false,
        });
    }

    for token in extract_proper_noun_tokens(negation) {
        patterns.push(ObserverPattern {
            correction_id: correction.correction_id.clone(),
            correction_type: correction.correction_type,
            extraction: PatternExtraction::ProperNoun,
            pattern: token,
            case_sensitive: true,
        });
    }

    patterns
}

/// Extract quoted phrases (single or double quotes) from text.
/// Deduplicated. Empty phrases dropped.
fn extract_quoted_phrases(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for quote_char in ['\'', '"'] {
        let mut chars = text.char_indices().peekable();
        while let Some((start, c)) = chars.next() {
            if c != quote_char {
                continue;
            }
            let phrase_start = start + c.len_utf8();
            let mut phrase_end = None;
            for (i, ch) in text[phrase_start..].char_indices() {
                if ch == quote_char {
                    phrase_end = Some(phrase_start + i);
                    break;
                }
            }
            if let Some(end) = phrase_end {
                let phrase = text[phrase_start..end].trim().to_string();
                if !phrase.is_empty() && seen.insert(phrase.clone()) {
                    out.push(phrase);
                }
                // Advance past the closing quote.
                while let Some(&(next_idx, _)) = chars.peek() {
                    if next_idx > end {
                        break;
                    }
                    chars.next();
                }
            }
        }
    }

    out
}

/// Extract proper-noun-like tokens: capitalized identifiers, version numbers,
/// hyphenated compounds. Filters out short generic tokens ("Do", "Not", "Regent"
/// alone) so the pattern set doesn't fire on incidental capitalization.
fn extract_proper_noun_tokens(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Sentence-starter capitalization (`Do not...`, `Regent may...`) is not
    // signal — filter tokens that appear at sentence starts alone.
    // Sentence-starter capitalized English words that should NOT be extracted
    // as proper-noun-like markers. Extended 2026-07-24 after empirical
    // false-positive observed 2026-07-16: "Findings" extracted as a proper
    // noun from a standing correction's negation, triggering spurious
    // Critical-severity violations. Semantic classifier (task #14
    // P2.2.5-Shadow) is the structural fix; this list is the narrow tactical
    // remediation for the most common false-positive class.
    //
    // Discipline: any capitalized English word likely to appear as a
    // sentence-starter in prose negations should be here. Common categories:
    // (a) sentence-starter modals and auxiliaries, (b) nouns that appear at
    // start of imperative or declarative sentences ("Findings that require
    // action escalate..."), (c) common verbs used to start sentences.
    let stopwords: std::collections::HashSet<&str> = [
        // Modals / auxiliaries at sentence start
        "Do", "Not", "May", "Should", "Must", "Will", "Would", "Could",
        "Can", "Cannot", "Might", "Shall", "Have", "Has", "Had",
        // Pronouns and determiners
        "The", "This", "That", "These", "Those", "It", "Its", "Their",
        "Any", "All", "Some", "Every", "Each", "No", "None",
        // Conjunctions / connectors
        "If", "When", "But", "And", "Or", "So", "For", "To", "Because",
        "Since", "While", "Although", "However", "Therefore", "Thus",
        "Also", "Yet", "Still", "Then",
        // Substrate-specific proper nouns that appear at sentence starts
        // in corrections' negation fields — extracting them would produce
        // false positives against Regent's normal narration about her role
        // and the substrate she governs.
        "Vault", "Regent", "Operator", "Substrate", "Chain",
        // Common sentence-starter nouns in prose negations
        "Findings", "Findings.", "Actions", "Reports", "Errors", "Warnings",
        "Results", "Outputs", "Events", "Signals", "Patterns", "Content",
        // Common sentence-starter verbs (imperative style)
        "Verify", "Ensure", "Confirm", "Check", "Consider", "Note",
        "Observe", "Watch", "Track", "Assume", "Recall", "Remember",
    ]
    .iter()
    .copied()
    .collect();

    // Split on whitespace and iterate.
    let words: Vec<&str> = text.split_whitespace().collect();

    let mut i = 0;
    while i < words.len() {
        // Strip trailing punctuation (periods, commas, semicolons) so
        // "GLM 5.2." → "GLM 5.2" and "Bananas." → "Bananas".
        // Internal punctuation (hyphens in "current-substrate", dots in "5.2")
        // is preserved because trim_end_matches only touches the tail.
        let w = words[i].trim_end_matches(|c: char| c.is_ascii_punctuation());
        let is_cap =
            w.chars().next().map_or(false, |c| c.is_ascii_uppercase()) && w.len() >= 3;
        let has_version = w.contains(|c: char| c.is_ascii_digit());
        let has_hyphen = w.contains('-');

        // Capitalized-then-alphanumeric-version-adjacent gets merged.
        // Example: "GLM 5.2" — "GLM" (capitalized) + "5.2" (version) → merge.
        if is_cap && !stopwords.contains(w) {
            let mut token = w.to_string();
            if i + 1 < words.len() {
                let next = words[i + 1]
                    .trim_end_matches(|c: char| c.is_ascii_punctuation());
                let next_is_version = next
                    .chars()
                    .next()
                    .map_or(false, |c| c.is_ascii_digit())
                    && next.chars().all(|c| c.is_ascii_digit() || c == '.');
                if next_is_version {
                    token.push(' ');
                    token.push_str(next);
                    i += 1;
                }
            }
            if seen.insert(token.clone()) {
                out.push(token);
            }
        } else if has_version && !w.chars().all(|c| c.is_ascii_digit() || c == '.') {
            // Standalone versioned identifier like "IronClaw-2.0".
            if seen.insert(w.to_string()) {
                out.push(w.to_string());
            }
        } else if has_hyphen && is_cap {
            // Hyphenated proper-noun compounds.
            if seen.insert(w.to_string()) {
                out.push(w.to_string());
            }
        }

        i += 1;
    }

    out
}

/// Substring match a pattern against Regent's response.
/// Returns the excerpt around the match, or None if no match.
fn match_pattern(response: &str, pattern: &ObserverPattern) -> Option<String> {
    let match_idx = if pattern.case_sensitive {
        response.find(&pattern.pattern)
    } else {
        response
            .to_lowercase()
            .find(&pattern.pattern.to_lowercase())
    };

    let idx = match_idx?;
    let start = idx.saturating_sub(24);
    let end = (idx + pattern.pattern.len() + 24).min(response.len());
    let mut excerpt = String::new();
    if start > 0 {
        excerpt.push_str("…");
    }
    // Snap to char boundaries to avoid slicing multi-byte codepoints.
    let start = snap_to_char_boundary(response, start);
    let end = snap_to_char_boundary(response, end);
    excerpt.push_str(&response[start..end]);
    if end < response.len() {
        excerpt.push_str("…");
    }
    Some(excerpt)
}

fn snap_to_char_boundary(s: &str, mut idx: usize) -> usize {
    idx = idx.min(s.len());
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

/// Map correction type + priority + extraction confidence to violation severity.
///
/// Rough heuristic:
///   - Boundary + high priority → Critical
///   - Prohibition + high priority → Warning
///   - Factual → Warning
///   - Preference → Informational
///   - Proper-noun matches carry higher confidence than long quoted phrases
///     (fewer false positives), so Factual/Prohibition proper-noun matches
///     upgrade one level when priority >= 90.
fn severity_for(
    correction_type: CorrectionType,
    priority: u32,
    extraction: PatternExtraction,
) -> ViolationSeverity {
    let base = match correction_type {
        CorrectionType::Boundary if priority >= 90 => ViolationSeverity::Critical,
        CorrectionType::Boundary => ViolationSeverity::Warning,
        CorrectionType::Prohibition if priority >= 90 => ViolationSeverity::Critical,
        CorrectionType::Prohibition => ViolationSeverity::Warning,
        CorrectionType::Factual => ViolationSeverity::Warning,
        CorrectionType::Preference => ViolationSeverity::Informational,
    };
    match (base, extraction, priority) {
        (ViolationSeverity::Warning, PatternExtraction::ProperNoun, p) if p >= 90 => {
            ViolationSeverity::Critical
        }
        _ => base,
    }
}

// ── Chain event encoding for violation + summary receipts ───────────────────

/// Event prefix for a chain-anchored violation receipt.
pub const EVENT_PREFIX_VIOLATED: &str = "cognitive:correction:violated";

/// Event prefix for a chain-anchored per-response observer summary.
pub const EVENT_PREFIX_VERIFIED: &str = "cognitive:observer:verified";

/// Encode a violation as its chain-event string.
/// Format: `cognitive:correction:violated {json}` — same encoding pattern as
/// standing correction receipts, so the search-by-keyword infrastructure works.
pub fn violation_event_string(v: &Violation) -> String {
    let payload = serde_json::to_string(v)
        .expect("Violation JSON serialization cannot fail");
    format!("{} {}", EVENT_PREFIX_VIOLATED, payload)
}

/// Encode an observer report summary as an inline event string.
///
/// Structural only — counts + severity, not full violation content (violations
/// have their own receipts). Emitted every response so the chain has evidence
/// the observer ran, even when there are no violations.
pub fn summary_event_string(report: &ObserverReport) -> String {
    format!(
        "{} corrections={} patterns={} violations={} max_severity={:?}",
        EVENT_PREFIX_VERIFIED,
        report.corrections_checked,
        report.patterns_checked,
        report.violations.len(),
        report.max_severity,
    )
}

// ── Class 5 (enactment subset) — unbacked act claims ─────────────────────────
//
// Spec: `COGNITIVE-SELF-OBSERVER-2026-07.md` §"Class 5 — Commitment claims",
// whose own example is *"I have addressed this concern" (verifiable against
// action receipts)*. The spec routes Class 5 verification through commitment
// receipts (Task #41), which do not exist. This implements the subset that
// needs no new primitive, because the ground truth is already in hand:
//
//   **If the cycle enacted nothing, no claim of enactment can be true.**
//
// That check requires no chain query, no ontology, and no second inference.
// The cycle knows exactly which tools ran and which intent it produced. A
// response asserting a completed substrate act while `tools_run` is empty is
// false by construction, not by judgement.
//
// # Why this is the failure worth catching first
//
// Observed 2026-07-31. The operator said "Please call me Kenrom." The router
// returned `{"intent":"respond","tool":"none"}`; the cycle closed with
// `intent="respond"` and zero tool dispatches. The composer replied:
//
//   > I have drafted the preference: "Call me Kenrom." It needs your
//   > signature to persist.
//
// No draft existed. No `RequestApproval` was constructed, no proposal receipt
// emitted, and `zp approval list` had nothing to show. The operator was
// directed to perform a signing ceremony on an artifact that was never
// created.
//
// This is worse than a wrong answer. Per P9 (*the system acts; the operator
// signs*), the signature is the substrate's load-bearing act. A response that
// manufactures a pending signature corrupts the one ceremony the whole
// authority model rests on — and does it in language indistinguishable from
// the real thing. An operator who signs nothing twice stops trusting the
// prompt; an operator who trusts the prompt signs nothing.
//
// The structural cause is the two-tier split. A 1.7b classifier decides
// whether a turn is a proposal; once it answers `respond`, the composing tier
// can only write prose. But the composer is handed the action menu by
// `build_available_actions` — added precisely so it would stop inventing
// *offers* it could not honour. It stopped inventing offers and began
// inventing completions instead, which is the worse trade: an offer invites a
// correction, a completion does not.
//
// # Precision over recall
//
// The marker lists below are deliberately narrow. Ambiguous first-person
// verbs — "I checked", "I ran", "I looked", "I found" — are excluded, because
// they carry an innocent conversational reading ("I ran through the options")
// as often as an enactment reading. A false positive here is expensive in a
// way a false negative is not: findings the operator learns to ignore are
// worse than findings that arrive late. Recall grows as the corpus of
// observed confabulations grows; it should not be guessed at up front.

/// Event prefix for a claim the cycle's own enactment record contradicts.
pub const EVENT_PREFIX_UNBACKED: &str = "cognitive:claim:unbacked";

/// What the cycle actually did, as the claim verifier's ground truth.
///
/// Assembled by the caller from the cycle's own state — never inferred, never
/// re-derived from the chain. This is the whole reason the check is sound.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnactedActs {
    /// Receipt event of the intent this cycle produced (`respond`, `observe`…).
    pub intent: String,
    /// Tools that actually executed this cycle, in dispatch order. Empty means
    /// the cycle performed no substrate act at all.
    pub tools_run: Vec<String>,
    /// Whether this cycle produced a signable proposal.
    pub proposal_emitted: bool,
}

/// Which kind of unbacked claim was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    /// Asserts a completed substrate act in a cycle that dispatched no tool.
    Enactment,
    /// Asserts an artifact is waiting on operator signature or approval when
    /// no proposal was emitted — there is nothing for the operator to sign.
    PendingArtifact,
}

/// A claim contradicted by the cycle's own enactment record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnbackedClaim {
    pub kind: ClaimKind,
    /// The marker phrase that matched.
    pub matched_phrase: String,
    /// Surrounding text, for the operator and for later pattern mining.
    pub excerpt: String,
    /// Intent the cycle actually produced.
    pub intent: String,
    /// Tools that actually ran (empty for every Enactment finding).
    pub tools_run: Vec<String>,
    pub severity: ViolationSeverity,
}

/// First-person assertions of a completed substrate act.
const ENACTMENT_MARKERS: &[&str] = &[
    "i have drafted", "i've drafted", "i drafted",
    "i have saved", "i've saved", "i saved",
    "i have stored", "i've stored", "i stored",
    "i have created", "i've created", "i created",
    "i have updated", "i've updated", "i updated",
    "i have recorded", "i've recorded", "i recorded",
    "i have registered", "i've registered", "i registered",
    "i have signed", "i've signed", "i signed",
    "i have configured", "i've configured", "i configured",
    "i have scheduled", "i've scheduled", "i scheduled",
    "i have queued", "i've queued", "i queued",
    "i have pinned", "i've pinned", "i pinned",
    "i have granted", "i've granted", "i granted",
    "i have revoked", "i've revoked", "i revoked",
    "i have emitted", "i've emitted", "i emitted",
    "i have dispatched", "i've dispatched", "i dispatched",
    "i have executed", "i've executed", "i executed",
    "i have invoked", "i've invoked", "i invoked",
];

/// Assertions that an artifact awaits an operator ceremony.
const PENDING_ARTIFACT_MARKERS: &[&str] = &[
    "needs your signature",
    "need your signature",
    "requires your signature",
    "awaiting your signature",
    "ready for your signature",
    "for you to sign",
    "once you sign",
    "when you sign",
    "needs your approval",
    "requires your approval",
    "awaiting your approval",
    "pending your approval",
    "submitted for approval",
];

/// Verify the response's act claims against what the cycle actually enacted.
///
/// Returns one finding per matched marker. An empty vector means every claim
/// the response makes about its own acts is consistent with the record — not
/// that the response is true, only that it did not claim to have done
/// something while doing nothing.
pub fn verify_claims(response: &str, enacted: &EnactedActs) -> Vec<UnbackedClaim> {
    let mut found = Vec::new();
    let lower = response.to_lowercase();

    // An enactment claim is only false if nothing was enacted. When a tool did
    // run, narrating it is exactly what the cycle asked for.
    if enacted.tools_run.is_empty() {
        for marker in ENACTMENT_MARKERS {
            if let Some(excerpt) = excerpt_around(response, &lower, marker) {
                found.push(UnbackedClaim {
                    kind: ClaimKind::Enactment,
                    matched_phrase: (*marker).to_string(),
                    excerpt,
                    intent: enacted.intent.clone(),
                    tools_run: enacted.tools_run.clone(),
                    severity: ViolationSeverity::Warning,
                });
            }
        }
    }

    // A pending-artifact claim is false whenever no proposal was emitted,
    // regardless of tool activity — running a tool does not create something
    // to sign.
    if !enacted.proposal_emitted {
        for marker in PENDING_ARTIFACT_MARKERS {
            if let Some(excerpt) = excerpt_around(response, &lower, marker) {
                found.push(UnbackedClaim {
                    kind: ClaimKind::PendingArtifact,
                    matched_phrase: (*marker).to_string(),
                    excerpt,
                    intent: enacted.intent.clone(),
                    tools_run: enacted.tools_run.clone(),
                    // Critical: this one sends the operator to a ceremony that
                    // cannot be completed. See the module note on P9.
                    severity: ViolationSeverity::Critical,
                });
            }
        }
    }

    found
}

/// Locate `needle` in the lowercased text and cut an excerpt from the original.
///
/// Indices come from the lowercased copy, which can differ in byte length from
/// the original for a handful of exotic codepoints. Both ends are snapped to
/// char boundaries of the *original*, so a drifted index yields a slightly
/// ragged excerpt rather than a panic — the same trade `match_pattern` makes.
fn excerpt_around(original: &str, lowered: &str, needle: &str) -> Option<String> {
    let idx = lowered.find(needle)?;
    let start = snap_to_char_boundary(original, idx.saturating_sub(32));
    let end = snap_to_char_boundary(original, (idx + needle.len() + 48).min(original.len()));
    let mut excerpt = String::new();
    if start > 0 {
        excerpt.push('…');
    }
    excerpt.push_str(&original[start..end]);
    if end < original.len() {
        excerpt.push('…');
    }
    Some(excerpt)
}

/// Encode an unbacked claim as its chain-event string.
///
/// Same `prefix {json}` encoding as violation receipts, so search-by-keyword
/// finds it without new infrastructure.
pub fn unbacked_claim_event_string(c: &UnbackedClaim) -> String {
    let payload =
        serde_json::to_string(c).expect("UnbackedClaim JSON serialization cannot fail");
    format!("{} {}", EVENT_PREFIX_UNBACKED, payload)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corrections::{
        ActiveStandingCorrection, CorrectionContent, CorrectionScope, CorrectionType,
        StandingCorrection,
    };

    fn correction_with(
        id: &str,
        correction_type: CorrectionType,
        domain: &str,
        assertion: &str,
        negation: Option<&str>,
        priority: u32,
    ) -> ActiveStandingCorrection {
        ActiveStandingCorrection {
            correction: StandingCorrection {
                correction_id: id.to_string(),
                issued_at: Utc::now(),
                issued_by: "operator".to_string(),
                correction_type,
                domain: domain.to_string(),
                scope: CorrectionScope::broad(),
                content: CorrectionContent {
                    assertion: assertion.to_string(),
                    negation: negation.map(String::from),
                    context: None,
                },
                priority,
                expiry: None,
                supersedes: Vec::new(),
            },
            entry_hash: format!("hash-{}", id),
        }
    }

    #[test]
    fn extracts_quoted_phrases_from_negation() {
        let phrases = extract_quoted_phrases(
            "Do not open with 'good morning'; do not close with 'rest up'; avoid \"end of a long day\".",
        );
        assert!(phrases.iter().any(|p| p == "good morning"));
        assert!(phrases.iter().any(|p| p == "rest up"));
        assert!(phrases.iter().any(|p| p == "end of a long day"));
    }

    #[test]
    fn extracts_proper_noun_with_version() {
        let tokens = extract_proper_noun_tokens(
            "Do not claim to be running GLM 5.2. Do not conflate stated destination with current state.",
        );
        assert!(tokens.iter().any(|t| t == "GLM 5.2"));
    }

    #[test]
    fn extracts_ironclaw_as_proper_noun() {
        let tokens = extract_proper_noun_tokens(
            "Do not treat IronClaw as current-substrate reference. Do not carry IronClaw framing into current design.",
        );
        assert!(tokens.iter().any(|t| t == "IronClaw"));
    }

    #[test]
    fn stopwords_filter_out_incidental_capitalization() {
        let tokens = extract_proper_noun_tokens("Do not claim this. Regent may narrate.");
        assert!(
            !tokens.iter().any(|t| t == "Do" || t == "Regent"),
            "sentence-starter capitalization must not fire"
        );
    }

    #[test]
    fn findings_regression_2026_07_16_does_not_extract_as_proper_noun() {
        // Empirical false-positive from substrate_validation correction negation:
        // "Regent may not autonomously modify substrate structure, dispatch
        //  builder agents, or sign new delegations. Findings that require
        //  action escalate to operator ceremony."
        // Pre-fix: "Findings" extracted as proper noun (starts second sentence,
        // capitalized, not in stopwords). Any response mentioning "findings"
        // triggered spurious Critical violation.
        // Post-fix (extended stopwords 2026-07-24): "Findings" is stopworded.
        let negation = "Regent may not autonomously modify substrate structure, \
                        dispatch builder agents, or sign new delegations. Findings \
                        that require action escalate to operator ceremony.";
        let tokens = extract_proper_noun_tokens(negation);
        assert!(
            !tokens.iter().any(|t| t == "Findings"),
            "'Findings' sentence-starter must be stopworded per 2026-07-16 empirical case, got tokens: {:?}",
            tokens
        );
    }

    #[test]
    fn common_sentence_starter_verbs_are_stopworded() {
        // Imperative-style sentence starters in prose negations shouldn't
        // extract as proper nouns.
        let negation = "Do not do X. Verify Y before proceeding. Ensure Z. \
                        Consider the implications. Note the pattern.";
        let tokens = extract_proper_noun_tokens(negation);
        for word in ["Verify", "Ensure", "Consider", "Note"] {
            assert!(
                !tokens.iter().any(|t| t == word),
                "'{}' should be stopworded (imperative sentence starter), got tokens: {:?}",
                word,
                tokens
            );
        }
    }

    #[test]
    fn factual_violation_detected_against_response_containing_glm() {
        let c = correction_with(
            "c-model",
            CorrectionType::Factual,
            "cognitive.self_reference.model_state",
            "Regent's inference is currently Sonnet 4.6.",
            Some("Do not claim to be running GLM 5.2. Do not conflate stated destination with current state."),
            90,
        );
        let response = "I'm running GLM 5.2 via Abacus";
        let report = verify_against_corrections(response, &[c]);
        assert!(!report.is_clean());
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].matched_pattern, "GLM 5.2");
        assert_eq!(report.max_severity, ViolationSeverity::Critical);
    }

    #[test]
    fn clean_response_produces_clean_report() {
        let c = correction_with(
            "c-model",
            CorrectionType::Factual,
            "cognitive.self_reference.model_state",
            "Regent's inference is currently Sonnet 4.6.",
            Some("Do not claim to be running GLM 5.2."),
            90,
        );
        let response = "I'm running Sonnet 4.6 via Abacus RouteLLM.";
        let report = verify_against_corrections(response, &[c]);
        assert!(report.is_clean());
        assert_eq!(report.violations.len(), 0);
        assert_eq!(report.max_severity, ViolationSeverity::Informational);
    }

    #[test]
    fn quoted_phrase_prohibition_violation_detected() {
        let c = correction_with(
            "c-day-shape",
            CorrectionType::Prohibition,
            "cognitive.narration.tone.day_shape",
            "Regent may mirror operator's day-shape framing when operator sets frame.",
            Some("Do not open with 'good morning'; do not close with 'rest up'."),
            70,
        );
        let response = "Good morning, kenrom. Here's the status.";
        let report = verify_against_corrections(response, &[c]);
        assert!(!report.is_clean());
        assert!(report
            .violations
            .iter()
            .any(|v| v.matched_pattern == "good morning"));
    }

    #[test]
    fn ironclaw_detected_in_current_context_response() {
        let c = correction_with(
            "c-ironclaw",
            CorrectionType::Factual,
            "substrate.factual.corpus_state",
            "IronClaw purged from Tier 1 corpus.",
            Some("Do not treat IronClaw as current-substrate reference."),
            60,
        );
        let response = "Consulting the IronClaw architecture for current substrate design...";
        let report = verify_against_corrections(response, &[c]);
        assert!(!report.is_clean());
        assert!(report
            .violations
            .iter()
            .any(|v| v.matched_pattern == "IronClaw"));
    }

    #[test]
    fn no_negation_produces_no_patterns() {
        let c = correction_with(
            "c-no-neg",
            CorrectionType::Preference,
            "test.no_negation",
            "Some assertion.",
            None,
            30,
        );
        let patterns = extract_patterns(&c.correction);
        assert!(patterns.is_empty());
    }

    #[test]
    fn empty_correction_set_produces_clean_report() {
        let report = verify_against_corrections("Some response text", &[]);
        assert!(report.is_clean());
        assert_eq!(report.corrections_checked, 0);
        assert_eq!(report.patterns_checked, 0);
    }

    #[test]
    fn boundary_correction_with_high_priority_is_critical() {
        let c = correction_with(
            "c-boundary",
            CorrectionType::Boundary,
            "cognitive.boundary.something",
            "Some boundary assertion.",
            Some("Do not invoke ForbiddenTool-v2 or reference SecretVault-Alpha."),
            100,
        );
        let response = "I'll invoke ForbiddenTool-v2 now.";
        let report = verify_against_corrections(response, &[c]);
        assert!(!report.is_clean());
        assert!(report
            .violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Critical));
    }

    #[test]
    fn preference_violation_is_informational_only() {
        let c = correction_with(
            "c-pref",
            CorrectionType::Preference,
            "cognitive.narration.style",
            "Prefer terse framing.",
            Some("Do not use 'MarketingLingo'"),
            40,
        );
        let response = "Deploying via MarketingLingo...";
        let report = verify_against_corrections(response, &[c]);
        assert!(!report.is_clean());
        assert!(report
            .violations
            .iter()
            .all(|v| v.severity == ViolationSeverity::Informational));
    }

    #[test]
    fn violation_event_string_roundtrip_encodes_correctly() {
        let c = correction_with(
            "c-encode",
            CorrectionType::Factual,
            "test.encode",
            "assertion",
            Some("Do not say Bananas."),
            50,
        );
        let response = "Actually Bananas are involved.";
        let report = verify_against_corrections(response, &[c]);
        assert_eq!(report.violations.len(), 1);
        let event = violation_event_string(&report.violations[0]);
        assert!(event.starts_with(EVENT_PREFIX_VIOLATED));
    }

    #[test]
    fn summary_event_string_includes_counts() {
        let report = ObserverReport {
            verified_at: Utc::now(),
            corrections_checked: 5,
            patterns_checked: 12,
            violations: Vec::new(),
            max_severity: ViolationSeverity::Informational,
        };
        let s = summary_event_string(&report);
        assert!(s.starts_with(EVENT_PREFIX_VERIFIED));
        assert!(s.contains("corrections=5"));
        assert!(s.contains("patterns=12"));
        assert!(s.contains("violations=0"));
    }

    #[test]
    fn multi_byte_response_boundary_handling_does_not_panic() {
        let c = correction_with(
            "c-mb",
            CorrectionType::Factual,
            "test.multibyte",
            "assertion",
            Some("Do not say Bananas."),
            50,
        );
        // Response contains multi-byte characters near the match position.
        let response = "The 面 substrate reports Bananas 🎯 today.";
        let report = verify_against_corrections(response, &[c]);
        assert_eq!(report.violations.len(), 1);
        // Excerpt must be a valid UTF-8 string.
        assert!(!report.violations[0].excerpt.is_empty());
    }
}

#[cfg(test)]
mod claim_tests {
    use super::*;

    fn nothing_enacted() -> EnactedActs {
        EnactedActs {
            intent: "respond".to_string(),
            tools_run: Vec::new(),
            proposal_emitted: false,
        }
    }

    /// The exact response observed 2026-07-31, against the exact cycle record
    /// that produced it. Both claims are false; both must be caught.
    #[test]
    fn catches_the_kenrom_confabulation() {
        let response = "I have drafted the preference: \"Call me Kenrom.\" \
                        It needs your signature to persist.";
        let claims = verify_claims(response, &nothing_enacted());

        assert_eq!(claims.len(), 2, "expected both claim kinds: {claims:?}");
        assert!(claims.iter().any(|c| c.kind == ClaimKind::Enactment));
        assert!(claims.iter().any(|c| c.kind == ClaimKind::PendingArtifact));
        // The signature claim is the load-bearing one.
        assert_eq!(
            claims
                .iter()
                .find(|c| c.kind == ClaimKind::PendingArtifact)
                .unwrap()
                .severity,
            ViolationSeverity::Critical
        );
    }

    /// Narrating a tool that actually ran is the cycle working as designed.
    #[test]
    fn narration_after_a_real_dispatch_is_clean() {
        let enacted = EnactedActs {
            intent: "respond".to_string(),
            tools_run: vec!["remember".to_string()],
            proposal_emitted: true,
        };
        let claims = verify_claims("I have saved that preference for you.", &enacted);
        assert!(claims.is_empty(), "false positive: {claims:?}");
    }

    /// A real proposal makes the signature claim true.
    #[test]
    fn emitted_proposal_backs_the_signature_claim() {
        let enacted = EnactedActs {
            intent: "request_approval".to_string(),
            tools_run: Vec::new(),
            proposal_emitted: true,
        };
        let claims = verify_claims("This needs your signature to persist.", &enacted);
        assert!(claims.is_empty(), "false positive: {claims:?}");
    }

    /// An enactment claim with no dispatch is still caught even when a
    /// proposal was emitted — the proposal backs the signature, not the act.
    #[test]
    fn proposal_does_not_excuse_an_enactment_claim() {
        let enacted = EnactedActs {
            intent: "request_approval".to_string(),
            tools_run: Vec::new(),
            proposal_emitted: true,
        };
        let claims = verify_claims("I have configured the endpoint.", &enacted);
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].kind, ClaimKind::Enactment);
    }

    #[test]
    fn ordinary_conversation_is_clean() {
        let claims = verify_claims(
            "The chain has 85,136 entries. Would you like me to check the \
             routing configuration?",
            &nothing_enacted(),
        );
        assert!(claims.is_empty(), "false positive: {claims:?}");
    }

    /// Deliberately excluded ambiguous verbs stay excluded — this test exists
    /// so that widening the marker list is a conscious act with a failing test
    /// attached, not a silent drift in precision.
    #[test]
    fn ambiguous_verbs_are_not_markers() {
        for s in [
            "I ran through the options with you.",
            "I checked in on that earlier.",
            "I looked at three approaches.",
            "I found that surprising.",
        ] {
            assert!(
                verify_claims(s, &nothing_enacted()).is_empty(),
                "unexpectedly flagged: {s}"
            );
        }
    }

    /// Excerpting must survive multi-byte text around the match — the same
    /// class of bug that panicked the evaluation sweep 54 times.
    #[test]
    fn excerpt_survives_multibyte_neighbours() {
        let response = "Considered — weighed — decided: I have drafted the \
                        preference “Call me Kenrom” — it needs your signature.";
        let claims = verify_claims(response, &nothing_enacted());
        assert!(!claims.is_empty());
        for c in &claims {
            assert!(!c.excerpt.is_empty());
        }
    }

    #[test]
    fn event_string_round_trips() {
        let claims = verify_claims("I have drafted it.", &nothing_enacted());
        let s = unbacked_claim_event_string(&claims[0]);
        assert!(s.starts_with(EVENT_PREFIX_UNBACKED));
        let json = s.trim_start_matches(EVENT_PREFIX_UNBACKED).trim();
        let back: UnbackedClaim = serde_json::from_str(json).unwrap();
        assert_eq!(back.kind, ClaimKind::Enactment);
    }
}
