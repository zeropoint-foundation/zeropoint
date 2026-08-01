//! H1 — N-gram repetition density.
//!
//! Per REGENT-DOOM-LOOP-DETECTION-2026-07.md §Heuristic 1:
//! for a response of L word-tokens:
//! - any 3-gram appears more than `max(4, L/20)` times → flag
//! - any 5-gram appears more than `max(2, L/40)` times → flag
//! - any 8-gram appears more than `1` time → flag
//!
//! We check both text-word-grams (whitespace-split lowercase) and
//! token-id-grams. Text grams catch natural-language repetition; token
//! grams catch sub-word repetition below the tokenizer's word boundary.

use std::collections::HashMap;

use crate::{Finding, HeuristicName, Severity};

/// Returns Some(Finding) if the response trips H1, else None.
pub fn ngram_repetition_density(text: &str, token_ids: &[u32]) -> Option<Finding> {
    // Word-tokens over text.
    let words: Vec<String> = text
        .split_whitespace()
        .map(|w| {
            w.trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase()
        })
        .filter(|w| !w.is_empty())
        .collect();
    let l_words = words.len();

    // Token-ids (already integer, no normalization).
    let l_tokens = token_ids.len();

    // Threshold formulas per the doc.
    let word_thresholds = ngram_thresholds(l_words);
    let token_thresholds = ngram_thresholds(l_tokens);

    let mut worst: Option<(usize, String, usize, usize)> = None; // (n, gram-as-string, count, threshold)

    for &n in &[3usize, 5, 8] {
        let thr_word = word_thresholds[&n];
        if l_words >= n {
            let counts = count_word_ngrams(&words, n);
            for (gram, count) in counts {
                if count > thr_word {
                    let joined = gram.join(" ");
                    let hit_worse = worst
                        .as_ref()
                        .map(|(pn, _, _, _)| n > *pn || (n == *pn && count > worst.as_ref().unwrap().2))
                        .unwrap_or(true);
                    if hit_worse {
                        worst = Some((n, joined, count, thr_word));
                    }
                }
            }
        }
        let thr_token = token_thresholds[&n];
        if l_tokens >= n {
            let counts = count_token_ngrams(token_ids, n);
            for (gram, count) in counts {
                if count > thr_token {
                    let joined = gram
                        .iter()
                        .map(|t| t.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    let repr = format!("[tokens: {joined}]");
                    let hit_worse = worst
                        .as_ref()
                        .map(|(pn, _, pcount, _)| n > *pn || (n == *pn && count > *pcount))
                        .unwrap_or(true);
                    if hit_worse {
                        worst = Some((n, repr, count, thr_token));
                    }
                }
            }
        }
    }

    let (n, gram_repr, count, threshold) = worst?;

    // Severity: 8-gram repetition or huge margin → Critical; else Warning.
    let severity = if n == 8 || count >= threshold * 3 {
        Severity::Critical
    } else {
        Severity::Warning
    };

    Some(Finding {
        name: HeuristicName::NgramRepetitionDensity,
        severity,
        evidence: serde_json::json!({
            "worst_gram_n": n,
            "worst_gram": gram_repr,
            "count": count,
            "threshold": threshold,
            "response_word_length": l_words,
            "response_token_length": l_tokens,
        }),
    })
}

fn ngram_thresholds(length: usize) -> HashMap<usize, usize> {
    let mut m = HashMap::new();
    // Per doc: 3-gram > max(4, L/20); 5-gram > max(2, L/40); 8-gram > 1.
    m.insert(3, std::cmp::max(4, length / 20));
    m.insert(5, std::cmp::max(2, length / 40));
    m.insert(8, 1);
    m
}

fn count_word_ngrams(words: &[String], n: usize) -> HashMap<Vec<String>, usize> {
    let mut counts = HashMap::new();
    for window in words.windows(n) {
        *counts.entry(window.to_vec()).or_insert(0) += 1;
    }
    counts
}

fn count_token_ngrams(tokens: &[u32], n: usize) -> HashMap<Vec<u32>, usize> {
    let mut counts = HashMap::new();
    for window in tokens.windows(n) {
        *counts.entry(window.to_vec()).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_text_no_finding() {
        let text = "The morning fog obscured the shape of the ships in the harbor as they moved slowly toward the open sea.";
        let tokens: Vec<u32> = (1..=25).collect();
        assert!(ngram_repetition_density(text, &tokens).is_none());
    }

    #[test]
    fn repeated_8gram_trips() {
        // Same 8-gram twice → threshold=1, count=2 → flag.
        let piece = "the quick brown fox jumps over the lazy dog and ";
        let text = format!("{piece} {piece}");
        let tokens: Vec<u32> = (1..=100).collect();
        let f = ngram_repetition_density(&text, &tokens).unwrap();
        assert_eq!(f.name, HeuristicName::NgramRepetitionDensity);
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn repeated_token_pattern_trips() {
        // Repeated token 8-gram — text is arbitrary.
        let text = "content is not analyzed here for word grams if text is short";
        let base = [1u32, 2, 3, 4, 5, 6, 7, 8];
        let mut tokens = Vec::new();
        for _ in 0..3 {
            tokens.extend_from_slice(&base);
        }
        let f = ngram_repetition_density(text, &tokens).unwrap();
        assert_eq!(f.name, HeuristicName::NgramRepetitionDensity);
    }
}
