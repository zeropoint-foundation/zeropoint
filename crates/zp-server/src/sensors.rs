//! HARNESS-SEAM-2026-08 §4 boot-time sensors (W7).
//!
//! Small, pure decision logic pulled out of `AppState::init`'s boot sequence
//! so each sensor's classification can be unit-tested without a live
//! backend, a running process, or a `std::process::exit` side effect.
//! `lib.rs` performs the actual I/O (HTTP probes, config reads) and the
//! actual boot-fatal action (`eprintln!` + `std::process::exit`); this
//! module only decides what a given observation *means*.
//!
//! See `docs/design/HARNESS-SEAM-2026-08.md` §4 for the sensor catalog and
//! §6 for the "boot-failing in production, no warn-only tier" ratification.

/// S2 ("model installed") classification.
///
/// `model_available()` (`zp-regent::inference::InferenceBackend`, the
/// W5-3c-extended probe) can answer three different things, and conflating
/// any two of them is exactly the kind of ambiguity a sensor exists to
/// remove:
///
/// - The model is confirmed present → [`S2Outcome::Verified`].
/// - The backend answered and the model is confirmed absent →
///   [`S2Outcome::Violated`] (boot-fatal per §6 — the operator configured a
///   model that does not exist).
/// - The backend could not be asked at all (network error, backend down) →
///   [`S2Outcome::Skipped`]. This is a reachability problem, not a "model
///   does not exist" finding, and treating it as either Verified (false
///   green) or Violated (false alarm on the wrong invariant) would make the
///   sensor lie about what it actually observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S2Outcome {
    Verified,
    Violated,
    Skipped,
}

/// Classify a single `model_available()` probe result.
///
/// `Err` is carried as its rendered message rather than the original error
/// type so this stays a plain, dependency-free function — the caller in
/// `lib.rs` already has the real error for logging; this function only
/// needs to know "did the probe itself fail".
pub fn classify_model_probe(result: &Result<bool, String>) -> S2Outcome {
    match result {
        Ok(true) => S2Outcome::Verified,
        Ok(false) => S2Outcome::Violated,
        Err(_) => S2Outcome::Skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HARNESS-SEAM-2026-08 S2 ("model installed"), W7. Prove the sensor is
    /// not lying: a synthetic "model absent" result must classify as
    /// Violated, and "fixing" it (the model now present) must classify
    /// clean, in the same test. The probe-failure case is checked
    /// separately since it is a distinct outcome, not a pass/fail toggle of
    /// the same condition.
    #[test]
    fn s2_classify_catches_synthetic_violation_and_clears_on_fix() {
        // Synthetic violation: backend answered, model is not in its list.
        assert_eq!(
            classify_model_probe(&Ok(false)),
            S2Outcome::Violated,
            "S2 must flag a confirmed-absent model"
        );

        // "Fix": the model is now present. Same predicate, clean result.
        assert_eq!(
            classify_model_probe(&Ok(true)),
            S2Outcome::Verified,
            "S2 must pass clean once the model is confirmed present"
        );
    }

    /// A probe that never got an answer is neither a pass nor a violation —
    /// collapsing it into either would make the sensor report something it
    /// did not actually observe.
    #[test]
    fn s2_classify_distinguishes_unreachable_from_violated() {
        let outcome = classify_model_probe(&Err("connection refused".to_string()));
        assert_eq!(outcome, S2Outcome::Skipped);
        assert_ne!(
            outcome,
            S2Outcome::Violated,
            "an unreachable backend must not be reported as a confirmed-absent model"
        );
    }
}
