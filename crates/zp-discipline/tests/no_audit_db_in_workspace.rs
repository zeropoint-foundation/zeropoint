//! Discipline (SEAM-001, resolved 2026-08-12): no file named `audit.db` may
//! exist inside the workspace.
//!
//! # Why
//!
//! The chain is not a repository artifact. `zp_core::paths::audit_db_path()`
//! resolves to `$ZP_HOME/data/audit.db` — by default `~/ZeroPoint/data/audit.db`,
//! outside the source tree entirely. Any `audit.db` found under the workspace is
//! therefore a stray copy by construction, and the only question is how badly it
//! will mislead whoever opens it.
//!
//! Three had accumulated by 2026-08-12:
//!
//! | path | schema | rows |
//! |---|---|---|
//! | `audit.db` (repo root) | `audit_log` (pre-migration) | 28, from February |
//! | `data/zeropoint/audit.db` | `audit_entries` (**current**) | 0 |
//! | `zeropoint-server/audit.db` | `audit_log` (pre-migration) | 0 |
//!
//! The middle one is the dangerous shape and the reason this pin exists rather
//! than a naming convention. It carries the *current* schema and no rows, so a
//! reader using today's code opens it, finds exactly the table it expects, and
//! receives a confident, well-formed, entirely false answer: the chain is empty.
//! Nothing about that read looks wrong. SEAM-001 records the cost as already
//! paid once — a tool built during a session picked the 28-row February copy and
//! would have reported on it as the chain.
//!
//! # Why a pin and not a marker
//!
//! SEAM-001's own design-out proposed marking live files, or naming dead ones so
//! they cannot be mistaken. Both put the burden on the reader at the moment of
//! reading, which is exactly when the reader is least equipped — they are
//! looking for the chain, they found something called the chain, and the marker
//! is one more thing to check. Absence needs no checking. If the file cannot be
//! here, no reader can pick it up.
//!
//! It also avoids the second mechanism SEAM-001 warns about: ironing this out
//! by having every reader replicate `zp_core::paths::home()` is the duplication
//! P8 exists to prevent.
//!
//! # Why the self-test matters more than the pin
//!
//! An absence assertion passes trivially when it has gone blind — a broken
//! exclusion, a renamed directory, a walk that visits nothing. Two tests answer
//! that: [`the_scan_finds_a_planted_database`] runs the same matcher over a
//! synthetic tree containing a planted `audit.db` and requires a hit, and
//! [`the_scan_actually_walks_the_workspace`] requires the real walk to visit a
//! plausible number of directories. That is PIN-002 applied to a pin whose
//! healthy state and whose blind state look identical.

use std::path::{Path, PathBuf};

use walkdir::WalkDir;

/// Directories never walked.
///
/// `_to_delete` is a staging area for files awaiting the operator's `rm` —
/// `device_bash` and other remote tooling cannot delete, so removals land there
/// first. Scanning it would leave this pin red for work that is already done,
/// and a pin that stays red for a known reason stops being read.
const SKIPPED_DIRS: &[&str] = &[
    "target",
    "node_modules",
    ".git",
    "_to_delete",
    "archive",
    ".venvs",
    ".pnpm-store",
];

/// Filenames that are a chain database or its SQLite sidecars.
fn is_chain_db(name: &str) -> bool {
    name == "audit.db" || name == "audit.db-wal" || name == "audit.db-shm"
}

fn skipped(name: &str) -> bool {
    SKIPPED_DIRS.contains(&name)
}

/// Walk `root`, returning every path whose filename [`is_chain_db`], plus the
/// number of directories visited. The count is what the self-test reads to tell
/// "found nothing" apart from "looked nowhere".
fn scan(root: &Path) -> (Vec<PathBuf>, usize) {
    let mut hits = Vec::new();
    let mut dirs = 0usize;

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            !e.file_type().is_dir() || !skipped(&e.file_name().to_string_lossy())
        })
        .filter_map(Result::ok)
    {
        if entry.file_type().is_dir() {
            dirs += 1;
        } else if is_chain_db(&entry.file_name().to_string_lossy()) {
            hits.push(entry.path().to_path_buf());
        }
    }
    (hits, dirs)
}

fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut cur: &Path = &manifest_dir;
    loop {
        let candidate = cur.join("Cargo.toml");
        if candidate.exists() {
            if let Ok(s) = std::fs::read_to_string(&candidate) {
                if s.contains("[workspace]") {
                    return cur.to_path_buf();
                }
            }
        }
        match cur.parent() {
            Some(p) => cur = p,
            None => panic!("no workspace Cargo.toml above {}", manifest_dir.display()),
        }
    }
}

#[test]
fn no_chain_database_inside_the_workspace() {
    let root = workspace_root();
    let (hits, _) = scan(&root);

    assert!(
        hits.is_empty(),
        "\nA chain database is sitting inside the workspace.\n\n\
         The chain lives at `zp_core::paths::audit_db_path()` —\n\
         `$ZP_HOME/data/audit.db`, outside this tree. Anything named `audit.db`\n\
         here is a stray copy, and the worst case is not an obviously broken one:\n\
         a copy carrying the current `audit_entries` schema with zero rows reads\n\
         as a healthy, empty chain to code that is working correctly.\n\n{}\n\n\
         Move it out of the tree. If it is evidence worth keeping, name it\n\
         something that is not `audit.db` and record what it is.\n\
         See SEAM-001 in docs/DELIBERATION-LOG-2026-08.md.\n",
        hits.iter()
            .map(|p| format!(
                "  {}",
                p.strip_prefix(&root).unwrap_or(p).display()
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn the_scan_finds_a_planted_database() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let nested = tmp.path().join("a").join("b");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("audit.db"), b"not really sqlite").unwrap();
    std::fs::write(nested.join("unrelated.txt"), b"x").unwrap();

    // And one inside a skipped directory, which must NOT be found.
    let skipped_dir = tmp.path().join("target");
    std::fs::create_dir_all(&skipped_dir).unwrap();
    std::fs::write(skipped_dir.join("audit.db"), b"ignored").unwrap();

    let (hits, _) = scan(tmp.path());

    assert_eq!(
        hits.len(),
        1,
        "matcher found {} databases in the synthetic tree, expected exactly the \
         one outside `target/`. If this is 0 the matcher is broken and the pin \
         above passes blind; if it is 2 the skip list is not being applied. \
         Hits: {hits:?}",
        hits.len()
    );
    assert!(hits[0].ends_with("a/b/audit.db"));
}

#[test]
fn the_scan_actually_walks_the_workspace() {
    let root = workspace_root();
    let (_, dirs) = scan(&root);

    assert!(
        dirs > 50,
        "the workspace walk visited only {dirs} directories. Either the skip \
         list is swallowing the tree or the root resolved somewhere unexpected \
         ({}). An absence assertion over an empty walk is not a check.",
        root.display()
    );
}
