//! Byte-safe previews of text the substrate did not author.
//!
//! # Why this module exists
//!
//! `&s[..n]` panics when byte `n` falls inside a multi-byte UTF-8
//! character. For hex digests and byte arrays that can never happen, so
//! the raw form is correct there. For *model output*, *operator input*,
//! and *remote response bodies* it happens routinely: an en dash is
//! three bytes, a curly quote three, an emoji four, and a language model
//! emits all of them without being asked.
//!
//! This is not hypothetical. `evaluation.rs:790` truncated a model reply
//! at byte 300, landed inside `'–'` (bytes 299..302), and panicked the
//! `tokio-runtime-worker` carrying the background evaluation sweep. It
//! did so **54 times over three days** on the instance observed
//! 2026-07-31, each panic silently aborting one sweep — the task dies,
//! the loop keeps ticking, and nothing in the operator-visible log says
//! a subsystem just stopped.
//!
//! That is the shape of the defect worth naming: not the crash, but the
//! crash that presents as health. A panic inside a spawned task is
//! swallowed by the runtime, so the substrate reports a running
//! evaluation sweep while producing no evaluations.
//!
//! # The rule
//!
//! Slicing a string by byte index is correct only when the alphabet is
//! known to be single-byte — hex, base32, a validated identifier. For
//! anything that crossed a network boundary, came from an operator, or
//! came out of a model, truncate through [`preview`].
//!
//! Violates *the system acts; the operator signs* (P9) only indirectly,
//! but it violates the plainer commitment underneath it: a substrate
//! that reports its own state must not have subsystems that fail
//! invisibly.

/// Truncate `s` to at most `max_bytes`, never splitting a character.
///
/// Returns `s` unchanged when it already fits. Otherwise walks back from
/// `max_bytes` to the nearest character boundary, so the result is at
/// most `max_bytes` long and always valid UTF-8.
///
/// This truncates by *bytes*, not characters, because every caller is
/// bounding log or context size — the budget being protected is the byte
/// budget. `preview(s, 200)` is the safe spelling of `&s[..200]`.
pub fn preview(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    // `is_char_boundary` is O(1) and true at 0, so this terminates.
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::preview;

    #[test]
    fn shorter_than_limit_is_unchanged() {
        assert_eq!(preview("hello", 200), "hello");
        assert_eq!(preview("", 10), "");
    }

    #[test]
    fn exact_length_is_unchanged() {
        assert_eq!(preview("abcde", 5), "abcde");
    }

    #[test]
    fn ascii_truncates_at_the_limit() {
        assert_eq!(preview("abcdefgh", 3), "abc");
    }

    /// The observed panic: an en dash straddling the cut.
    #[test]
    fn does_not_split_an_en_dash() {
        // 'x' * 299 then '–' (3 bytes) — byte 300 is inside the dash.
        let s = format!("{}{}", "x".repeat(299), '–');
        let out = preview(&s, 300);
        assert_eq!(out.len(), 299);
        assert!(out.chars().all(|c| c == 'x'));
    }

    #[test]
    fn handles_every_boundary_offset_of_a_four_byte_char() {
        // '🙂' is 4 bytes; cutting at 1..=3 bytes into it must back off.
        let s = "🙂🙂";
        for n in 0..=8 {
            let out = preview(s, n);
            assert!(out.len() <= n);
            // The only proof that matters: it is still valid UTF-8, and
            // taking the slice did not panic.
            assert!(s.starts_with(out));
        }
    }

    #[test]
    fn multibyte_shorter_than_limit_survives_whole() {
        assert_eq!(preview("a–b", 100), "a–b");
    }
}
