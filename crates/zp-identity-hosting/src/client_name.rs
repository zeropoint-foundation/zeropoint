//! `client_name` derivation — design decision 4, first half. Fully settled;
//! this file is a real implementation, not a stub.
//!
//! Source states per `REGENT-NAMING-CEREMONY-2026-07.md`: a Regent is
//! either named (a committed `regent:named:v1`/`regent:renamed:v1` state,
//! not since superseded by `regent:name_retracted:v1`) or pre-named. See
//! design doc §4 for why the marker string below was chosen.

/// Local placeholder for "what the naming ceremony's chain state currently
/// is." The real implementation session should replace this with whatever
/// type the naming ceremony's `RegentIdentity` ontology read (per
/// `REGENT-NAMING-CEREMONY-2026-07.md` §"Chain-visible identity graph")
/// actually materializes as — this scaffold does not have that type
/// in scope and does not want to guess its real shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegentNameState {
    /// The committed name from the latest un-superseded naming/renaming
    /// receipt, e.g. `"Astra"`.
    Named(String),
    /// No naming ceremony has completed, or the identity was retracted
    /// back to pre-named per the naming ceremony's "Retraction to
    /// pre-named" ceremony.
    PreNamed,
}

/// The fixed `client_name` string for a pre-named Regent. Deliberately:
///
/// - Stable across every pre-named operator — must not leak any
///   per-operator identifying detail before naming has happened (mirrors
///   the naming ceremony's own discipline: pre-named substrate-generated
///   language says "the Regent," never anything operator-specific).
/// - Textually distinct from any plausible committed name, so a real named
///   Regent could never collide with it by coincidence.
pub const PRE_NAMED_CLIENT_NAME: &str = "ZeroPoint Substrate (Regent pre-named)";

/// `client_name` per design doc §4: the committed name verbatim if named,
/// undecorated (client_name is cosmetic per the CIMD spec — the AS does not
/// key anything off it; `client_id`, the hosted URL, is the actual
/// identifier), else the fixed marker.
pub fn derive_client_name(state: &RegentNameState) -> String {
    match state {
        RegentNameState::Named(name) => name.clone(),
        RegentNameState::PreNamed => PRE_NAMED_CLIENT_NAME.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_regent_uses_committed_name_undecorated() {
        assert_eq!(
            derive_client_name(&RegentNameState::Named("Astra".into())),
            "Astra"
        );
    }

    #[test]
    fn pre_named_regent_uses_fixed_marker() {
        assert_eq!(
            derive_client_name(&RegentNameState::PreNamed),
            PRE_NAMED_CLIENT_NAME
        );
    }

    #[test]
    fn marker_does_not_look_like_a_plausible_operator_chosen_name() {
        // Cheap guard against the marker drifting into something that
        // could plausibly collide with a real committed name later.
        assert!(PRE_NAMED_CLIENT_NAME.contains("pre-named"));
    }
}
