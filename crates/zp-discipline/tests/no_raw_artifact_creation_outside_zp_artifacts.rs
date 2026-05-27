//! Discipline pin: artifact creation must go through zp-artifacts.
//!
//! The `Artifact` struct must only be constructed inside `zp-artifacts` itself.
//! External crates receive `ArtifactId`s and fetch `Artifact`s via the `Library`
//! trait — they never construct the struct directly. This prevents the lifecycle
//! state machine and signing protocol from being bypassed.
//!
//! Forbidden outside zp-artifacts/:
//!   - `Artifact {` (struct literal construction)
//!   - `LifecycleState::Candidate` (direct state assignment)
//!
//! zp-server is an allowlisted consumer — it calls Library methods, never
//! constructs Artifact literals. zp-artifacts/src/ is the only allowed site
//! for direct construction.

use std::path::Path;

const WORKSPACE_ROOT: &str = env!("CARGO_MANIFEST_DIR");

/// Crates that may construct Artifact literals directly.
const ALLOWED_CRATES: &[&str] = &[
    "crates/zp-artifacts/src",
    "crates/zp-artifacts/tests",
];

/// Patterns that indicate raw artifact construction.
const FORBIDDEN_PATTERNS: &[&str] = &[
    "Artifact {",
    "LifecycleState::Candidate",
    "LifecycleState::Signed",
    "LifecycleState::Rejected",
    "LifecycleState::Superseded",
];

#[test]
fn no_raw_artifact_construction_outside_zp_artifacts() {
    let root = Path::new(WORKSPACE_ROOT)
        .parent()
        .expect("workspace root");

    let mut violations: Vec<String> = Vec::new();

    scan_dir(root, &mut violations);

    if !violations.is_empty() {
        panic!(
            "Raw artifact construction detected outside zp-artifacts.\n\
             Use Library::store_candidate() or generate_candidate() instead.\n\
             Violations:\n{}",
            violations.join("\n")
        );
    }
}

fn scan_dir(dir: &Path, violations: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();

        // Skip non-Rust source directories
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if matches!(name, "target" | ".git" | "node_modules" | ".understand-anything") {
                continue;
            }
            scan_dir(&path, violations);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            check_file(&path, violations);
        }
    }
}

fn check_file(path: &Path, violations: &mut Vec<String>) {
    let path_str = path.to_string_lossy();

    // Allowed: anything inside zp-artifacts itself (src + tests)
    if ALLOWED_CRATES.iter().any(|allowed| path_str.contains(allowed)) {
        return;
    }

    // Also allow this discipline pin file itself
    if path_str.contains("zp-discipline") {
        return;
    }

    let Ok(content) = std::fs::read_to_string(path) else { return };

    for pattern in FORBIDDEN_PATTERNS {
        if content.contains(pattern) {
            // Only flag if the file also imports zp_artifacts — avoids false
            // positives from unrelated enums named LifecycleState.
            if content.contains("zp_artifacts") || content.contains("zp-artifacts") {
                violations.push(format!(
                    "  {} — contains '{}'",
                    path_str, pattern
                ));
                break; // one violation per file is enough
            }
        }
    }
}
