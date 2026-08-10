//! Bedrock invariants — the substrate noticing when something existential is missing.
//!
//! # Why this exists
//!
//! On 2026-08-06 `~/ZeroPoint/vault.json` was found not to exist on a substrate
//! that had been running for months. The credential vault — ChaCha20-Poly1305,
//! tier-derived keys, master key from the sovereign root — was complete,
//! correct, and empty. Roughly two dozen live credentials sat in plaintext
//! `.env.pre-vault` files while the mechanism built to hold them held nothing.
//!
//! The substrate did not notice. Not once, across every boot in that period.
//! Its only signal was Steward's `vault_empty` finding at **Info** severity,
//! which — until that same afternoon — was computed and then discarded by an
//! emission filter before ever reaching the chain.
//!
//! The operator's summary of the requirement is the clearest statement of it:
//!
//! > The system needs to know "hey, where is my vault?"
//!
//! # What makes these different from the checks that already exist
//!
//! `substrate_validate` reports health. Officers report findings. Both stream
//! into a posture score that has read `degraded` continuously for long enough
//! that it carries no information — which is how a missing vault hid inside it.
//!
//! Bedrock invariants are not health. They ask whether the substrate **is what
//! it claims to be**. A ZeroPoint substrate with no vault is not a degraded
//! ZeroPoint substrate; it is something else wearing the name. So these are:
//!
//! - **Few.** A list of five is read. A list of forty is skimmed, and skimming
//!   is how this class of failure survives.
//! - **Existential, not graded.** Each is a yes/no about a load-bearing
//!   premise, not a measurement.
//! - **Loud at the boundary.** Violations print to the operator's terminal at
//!   boot, where the sovereignty ceremony already has their attention — not
//!   into a logfile, and not into a stream that has trained them to look away.
//! - **Chain-anchored.** `invariant:<name>:verified|violated`, so "the vault
//!   was already empty three months ago" becomes a question the chain can
//!   answer.
//!
//! # Relationship to the specified ceremony
//!
//! `docs/design/SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md` specifies five
//! bootstrap phases and an invariant catalog. It was written 2026-07-18 in
//! response to a near-identical incident — *"Nothing in the substrate noticed
//! until the operator hit each surface manually… `zp doctor` reported healthy
//! (4 warnings)"* — and has zero implementation.
//!
//! This is a first slice of it, with one correction. That spec's vault
//! invariant, `vault_key_composes_with_provider`, asserts `resolve_vault_key()`
//! returns `Ok` with `source = SovereigntyProvider`. **The 2026-08-06 defect
//! satisfies it** — the key resolved with exactly that source, and simply
//! arrived after its consumer had given up. The invariant tested capability
//! where the failure was delivery. The checks below test delivery and custody:
//! not *can the substrate produce this*, but *does it actually have it*.
//!
//! Custody tiers per `docs/design/INFORMATION-CUSTODY-TIERS-2026-08.md`.

use std::path::PathBuf;
use std::sync::Arc;

use tracing::{error, info, warn};
use zp_audit::AuditStore;

use crate::tool_chain;

/// Chain-event prefix for bedrock results.
pub const EVENT_PREFIX_INVARIANT: &str = "invariant:";

/// A substrate is "young" below this many chain entries — plausibly a fresh
/// install where an empty vault is the correct state rather than a lost one.
///
/// Deliberately generous. The cost of a false Critical here is an operator
/// learning to ignore the loudest signal the substrate has, which is the exact
/// failure being fixed. The cost of a false Info is one boot's delay in
/// noticing, and the check runs every boot.
/// `pub` because the caller sizes its chain read against it — reading exactly
/// one entry past the threshold is enough to answer "mature or not" without
/// pulling an unbounded history into memory to count it.
pub const YOUNG_SUBSTRATE_ENTRIES: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Ok,
    Warning,
    Critical,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Severity::Ok => "ok",
            Severity::Warning => "warning",
            Severity::Critical => "CRITICAL",
        }
    }
}

pub struct Finding {
    pub invariant: &'static str,
    pub severity: Severity,
    pub detail: String,
    /// What the operator should do. Present on every non-`Ok` finding — a
    /// bedrock alarm with no remedy is a complaint.
    pub remedy: Option<String>,
}

impl Finding {
    fn ok(invariant: &'static str, detail: impl Into<String>) -> Self {
        Self { invariant, severity: Severity::Ok, detail: detail.into(), remedy: None }
    }
    fn warn(invariant: &'static str, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            invariant,
            severity: Severity::Warning,
            detail: detail.into(),
            remedy: Some(remedy.into()),
        }
    }
    fn critical(
        invariant: &'static str,
        detail: impl Into<String>,
        remedy: impl Into<String>,
    ) -> Self {
        Self {
            invariant,
            severity: Severity::Critical,
            detail: detail.into(),
            remedy: Some(remedy.into()),
        }
    }
}

/// Inputs the check needs, gathered by the caller so this stays testable.
pub struct BedrockInputs {
    /// Does `genesis.json` exist?
    pub genesis_present: bool,
    /// Did the vault master key resolve? `None` means resolution completed and
    /// failed; this is distinct from never having run.
    pub vault_key_resolved: bool,
    /// Path the vault is expected at.
    pub vault_path: PathBuf,
    /// Vault file present on disk.
    pub vault_file_exists: bool,
    /// Key names held. `None` when the vault could not be opened at all —
    /// which is a different condition from an empty vault, and the conflation
    /// of the two is what made this failure invisible for months.
    pub vault_keys: Option<usize>,
    /// Whether the chain has grown past [`YOUNG_SUBSTRATE_ENTRIES`] — the proxy
    /// for distinguishing a fresh install, where an empty vault is correct,
    /// from a substrate that has lost custody.
    ///
    /// A boolean rather than a count on purpose. The caller determines this by
    /// reading one entry past the threshold, so any number it could pass would
    /// be the capped read rather than the chain length — 501 on a chain of
    /// 10,000. Correct for the decision and wrong in the finding text an
    /// operator reads. The check only needs the comparison, so it only takes
    /// the comparison.
    pub substrate_is_mature: bool,
}

/// Evaluate the bedrock invariants.
pub fn check(inputs: &BedrockInputs) -> Vec<Finding> {
    let mut out = Vec::new();

    // ── genesis_present ────────────────────────────────────────────────
    // Without Genesis there is no sovereign root, so no vault key, no signing
    // identity, and nothing downstream means what it claims to.
    out.push(if inputs.genesis_present {
        Finding::ok("genesis_present", "genesis.json found")
    } else {
        Finding::critical(
            "genesis_present",
            "genesis.json is absent — the substrate has no sovereign identity",
            "Run `zp init` for a new substrate, or `zp recover` with your 24-word mnemonic",
        )
    });

    // ── sovereign_root_delivers ────────────────────────────────────────
    // Delivery, not capability. The specified ceremony asks whether the key
    // *can* be derived; this asks whether it *was*, by the time anything
    // needed it. The 2026-08-06 race passed the former and failed the latter.
    out.push(if inputs.vault_key_resolved {
        Finding::ok("sovereign_root_delivers", "vault master key resolved before consumers ran")
    } else if inputs.genesis_present {
        Finding::critical(
            "sovereign_root_delivers",
            "Genesis exists but the vault master key did not resolve — every \
             secret-dependent surface is running without vault access",
            "Check the sovereignty provider (`zp vault test`) and that the boot ceremony completed",
        )
    } else {
        // Already reported by genesis_present; do not double-alarm.
        Finding::ok("sovereign_root_delivers", "no Genesis — not applicable")
    });

    // ── vault_readable ─────────────────────────────────────────────────
    // "Cannot open" and "opens and is empty" are different failures with
    // different repairs. Steward's finding reported both as "contains no
    // entries", at Info, which is how a lost vault reads as a quiet one.
    match inputs.vault_keys {
        None if inputs.vault_key_resolved => out.push(Finding::critical(
            "vault_readable",
            format!("vault at {} could not be opened", inputs.vault_path.display()),
            "The file may be corrupt or encrypted under a different root. Do not \
             delete it — move it aside and inspect before replacing",
        )),
        None => out.push(Finding::ok("vault_readable", "no vault key — not applicable")),
        Some(_) => out.push(Finding::ok(
            "vault_readable",
            format!("vault opens at {}", inputs.vault_path.display()),
        )),
    }

    // ── vault_custody ──────────────────────────────────────────────────
    // The question the operator actually asked. An empty vault on a fresh
    // substrate is correct. An empty vault on one with thousands of chain
    // entries means custody was established and then lost, and the substrate
    // should say so at the top of its voice.
    if let Some(n) = inputs.vault_keys {
        out.push(match (n, inputs.substrate_is_mature) {
            (0, true) => Finding::critical(
                "vault_custody",
                "the vault holds nothing, on an established substrate — custody was \
                 set up and has been lost, or was never completed",
                "Check for plaintext credentials outside the vault \
                 (`tools/migrate-envs-to-vault.sh`), then `zp vault list` to confirm",
            ),
            (0, false) => Finding::warn(
                "vault_custody",
                "the vault holds nothing, on a substrate young enough that this is \
                 plausibly a fresh install",
                "Expected on a new substrate. Store credentials with `zp vault put`",
            ),
            (n, _) => Finding::ok("vault_custody", format!("vault holds {} secrets", n)),
        });

        // A populated vault with no file on disk would mean the save path is
        // silently failing — secrets alive in memory and gone at restart.
        if n > 0 && !inputs.vault_file_exists {
            out.push(Finding::critical(
                "vault_persisted",
                format!(
                    "{} secrets in memory but no file at {} — they will not survive restart",
                    n,
                    inputs.vault_path.display()
                ),
                "The vault save path is failing. Check filesystem permissions on ~/ZeroPoint/",
            ));
        } else {
            out.push(Finding::ok("vault_persisted", "vault state matches disk"));
        }
    }

    out
}

/// Print the bedrock block to the operator's terminal.
///
/// Silent when everything holds — a boot banner that always fires is furniture,
/// and furniture is not read. On violation it prints where the sovereignty
/// ceremony has just had the operator's attention, rather than into a log they
/// would have to think to check.
pub fn report(findings: &[Finding]) {
    let worst = findings.iter().map(|f| f.severity).max_by_key(|s| match s {
        Severity::Ok => 0,
        Severity::Warning => 1,
        Severity::Critical => 2,
    });
    if worst == Some(Severity::Ok) || worst.is_none() {
        info!(checks = findings.len(), "bedrock invariants hold");
        return;
    }

    let red = "\x1b[1;31m";
    let yellow = "\x1b[1;33m";
    let reset = "\x1b[0m";
    let accent = if worst == Some(Severity::Critical) { red } else { yellow };

    eprintln!();
    eprintln!("{accent}   ── BEDROCK ──────────────────────────────────────────{reset}");
    eprintln!();
    for f in findings.iter().filter(|f| f.severity != Severity::Ok) {
        let mark = if f.severity == Severity::Critical { "✗" } else { "⚠" };
        eprintln!("{accent}   {mark}  {}{reset}", f.invariant);
        eprintln!("      {}", f.detail);
        if let Some(r) = &f.remedy {
            eprintln!("      → {}", r);
        }
        eprintln!();
    }
    eprintln!("{accent}   ─────────────────────────────────────────────────────{reset}");
    eprintln!();

    for f in findings.iter().filter(|f| f.severity == Severity::Critical) {
        error!(invariant = f.invariant, detail = %f.detail, "bedrock invariant violated");
    }
    for f in findings.iter().filter(|f| f.severity == Severity::Warning) {
        warn!(invariant = f.invariant, detail = %f.detail, "bedrock invariant degraded");
    }
}

/// Chain-anchor each result.
///
/// Emitted on every boot including clean ones. The absence of a violation is
/// itself the record — "the vault was already empty three months ago" should be
/// a question the chain can answer, and it can only answer it if the healthy
/// boots are on there too.
pub fn anchor(audit_store: &Arc<std::sync::Mutex<AuditStore>>, findings: &[Finding]) {
    for f in findings {
        let verb = if f.severity == Severity::Ok { "verified" } else { "violated" };
        tool_chain::emit_tool_receipt(
            audit_store,
            &format!("{}{}:{}", EVENT_PREFIX_INVARIANT, f.invariant, verb),
            Some(&format!("severity={} {}", f.severity.label(), f.detail)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> BedrockInputs {
        BedrockInputs {
            genesis_present: true,
            vault_key_resolved: true,
            vault_path: PathBuf::from("/tmp/vault.json"),
            vault_file_exists: true,
            vault_keys: Some(3),
            substrate_is_mature: true,
        }
    }

    fn find<'a>(fs: &'a [Finding], name: &str) -> &'a Finding {
        fs.iter().find(|f| f.invariant == name).expect("invariant present")
    }

    #[test]
    fn healthy_substrate_reports_all_ok() {
        let fs = check(&base());
        assert!(fs.iter().all(|f| f.severity == Severity::Ok), "expected all ok");
    }

    /// The 2026-08-06 condition: a mature substrate, key resolving, vault empty.
    /// This is the case that went unnoticed for months.
    #[test]
    fn empty_vault_on_mature_substrate_is_critical() {
        let mut i = base();
        i.vault_keys = Some(0);
        let fs = check(&i);
        let f = find(&fs, "vault_custody");
        assert_eq!(f.severity, Severity::Critical, "detail: {}", f.detail);
        assert!(f.remedy.is_some(), "a bedrock alarm must carry a remedy");
    }

    /// The same emptiness on a new substrate is correct, and must not cry wolf.
    #[test]
    fn empty_vault_on_fresh_substrate_is_only_a_warning() {
        let mut i = base();
        i.vault_keys = Some(0);
        i.substrate_is_mature = false;
        assert_eq!(find(&check(&i), "vault_custody").severity, Severity::Warning);
    }

    /// Unreadable is not empty. Conflating them is what hid the original defect.
    #[test]
    fn unreadable_vault_is_distinct_from_empty() {
        let mut i = base();
        i.vault_keys = None;
        let fs = check(&i);
        assert_eq!(find(&fs, "vault_readable").severity, Severity::Critical);
        // And must not also be reported as a custody problem — one fault, one alarm.
        assert!(fs.iter().all(|f| f.invariant != "vault_custody"));
    }

    /// Delivery, not capability — the distinction the specified ceremony misses.
    #[test]
    fn genesis_without_key_delivery_is_critical() {
        let mut i = base();
        i.vault_key_resolved = false;
        i.vault_keys = None;
        assert_eq!(find(&check(&i), "sovereign_root_delivers").severity, Severity::Critical);
    }

    /// Absent Genesis reports once, not three times.
    #[test]
    fn missing_genesis_does_not_cascade() {
        let mut i = base();
        i.genesis_present = false;
        i.vault_key_resolved = false;
        i.vault_keys = None;
        let fs = check(&i);
        let criticals: Vec<_> =
            fs.iter().filter(|f| f.severity == Severity::Critical).map(|f| f.invariant).collect();
        assert_eq!(criticals, vec!["genesis_present"], "one root cause, one alarm");
    }

    /// Secrets in memory with no file means they vanish at restart.
    #[test]
    fn populated_vault_without_a_file_is_critical() {
        let mut i = base();
        i.vault_file_exists = false;
        assert_eq!(find(&check(&i), "vault_persisted").severity, Severity::Critical);
    }
}
